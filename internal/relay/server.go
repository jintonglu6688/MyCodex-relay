package relay

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"

	"github.com/coder/websocket"
	"github.com/mycodex/mycodex-relay/internal/config"
	"github.com/mycodex/mycodex-relay/internal/pairing"
	"github.com/mycodex/mycodex-relay/internal/protocol"
	"github.com/mycodex/mycodex-relay/internal/session"
	"github.com/mycodex/mycodex-relay/internal/store"
	"github.com/mycodex/mycodex-relay/internal/tenant"
)

type Server struct {
	config config.Config
	mux    *http.ServeMux
	store  *store.Store

	mu      sync.RWMutex
	hosts   map[string]*webSocketSession
	devices map[string]*webSocketSession
}

func NewServer(cfg config.Config) *Server {
	server := &Server{
		config:  cfg,
		mux:     http.NewServeMux(),
		hosts:   make(map[string]*webSocketSession),
		devices: make(map[string]*webSocketSession),
	}
	server.mux.HandleFunc("/health", server.handleHealth)
	server.mux.HandleFunc("/v1/ws", server.handleWebSocket)
	return server
}

func NewServerWithStore(cfg config.Config, st *store.Store) *Server {
	server := NewServer(cfg)
	server.store = st
	return server
}

func (s *Server) Handler() http.Handler {
	return s.mux
}

func (s *Server) Serve(ctx context.Context) error {
	address := net.JoinHostPort(s.config.ListenHost, fmt.Sprintf("%d", s.config.ListenPort))
	httpServer := &http.Server{Addr: address, Handler: s.Handler()}
	go func() {
		<-ctx.Done()
		httpServer.Shutdown(context.Background())
	}()
	err := httpServer.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("{\"status\":\"ok\"}\n"))
}

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	activeSession, err := sessionFromRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !s.authenticateSession(r, activeSession) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
	if err != nil {
		return
	}
	ws := &webSocketSession{session: activeSession, conn: conn}
	s.addSession(ws)
	defer func() {
		s.removeSession(ws)
		conn.Close(websocket.StatusNormalClosure, "")
	}()
	for {
		messageType, data, err := conn.Read(r.Context())
		if err != nil {
			return
		}
		if messageType != websocket.MessageText {
			s.writeError(ws, protocol.Envelope{TenantID: activeSession.TenantID, HostID: activeSession.HostID, DeviceID: activeSession.DeviceID}, "invalid_envelope")
			continue
		}
		var envelope protocol.Envelope
		if err := json.Unmarshal(data, &envelope); err != nil {
			s.writeError(ws, protocol.Envelope{TenantID: activeSession.TenantID, HostID: activeSession.HostID, DeviceID: activeSession.DeviceID}, "invalid_envelope")
			continue
		}
		if err := envelope.Validate(s.config.DefaultQuota.MaxMessageBytes); err != nil {
			s.writeError(ws, envelope, errorCode(err))
			continue
		}
		if code := validateSenderEnvelope(ws.session, envelope); code != "" {
			s.writeError(ws, envelope, code)
			continue
		}
		s.routeEnvelope(ws, envelope)
	}
}

func (s *Server) authenticateSession(r *http.Request, activeSession session.Session) bool {
	if s.store == nil {
		return true
	}
	token, ok := bearerToken(r.Header.Get("Authorization"))
	if !ok {
		return false
	}
	switch activeSession.ConnectionType {
	case session.ConnectionHost:
		tenantService := tenant.NewService(s.store)
		item, err := tenantService.Get(activeSession.TenantID)
		if err != nil || !item.Enabled {
			return false
		}
		return tenant.VerifySecretHash(item.SecretHash, token)
	case session.ConnectionDevice:
		pairingService := pairing.NewService(s.store)
		return pairingService.VerifyDeviceToken(activeSession.TenantID, activeSession.HostID, activeSession.DeviceID, token)
	default:
		return false
	}
}

type webSocketSession struct {
	session session.Session
	conn    *websocket.Conn
	writeMu sync.Mutex
}

func (s *Server) addSession(ws *webSocketSession) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ws.session.ConnectionType == session.ConnectionHost {
		s.hosts[hostKey(ws.session.TenantID, ws.session.HostID)] = ws
	}
	if ws.session.ConnectionType == session.ConnectionDevice {
		s.devices[deviceKey(ws.session.TenantID, ws.session.HostID, ws.session.DeviceID)] = ws
	}
}

func (s *Server) removeSession(ws *webSocketSession) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ws.session.ConnectionType == session.ConnectionHost {
		key := hostKey(ws.session.TenantID, ws.session.HostID)
		if s.hosts[key] == ws {
			delete(s.hosts, key)
		}
	}
	if ws.session.ConnectionType == session.ConnectionDevice {
		key := deviceKey(ws.session.TenantID, ws.session.HostID, ws.session.DeviceID)
		if s.devices[key] == ws {
			delete(s.devices, key)
		}
	}
}

func (s *Server) routeEnvelope(sender *webSocketSession, envelope protocol.Envelope) {
	var target *webSocketSession
	s.mu.RLock()
	switch envelope.Direction {
	case protocol.DirectionMobileToWindows:
		target = s.hosts[hostKey(envelope.TenantID, envelope.HostID)]
	case protocol.DirectionWindowsToMobile:
		target = s.devices[deviceKey(envelope.TenantID, envelope.HostID, envelope.DeviceID)]
	default:
		target = nil
	}
	s.mu.RUnlock()
	if target == nil {
		s.writeError(sender, envelope, "route_not_found")
		return
	}
	if err := target.writeEnvelope(envelope); err != nil {
		s.writeError(sender, envelope, "route_not_found")
	}
}

func (s *Server) writeError(target *webSocketSession, source protocol.Envelope, code string) {
	correlationID := source.MessageID
	payload, err := json.Marshal(protocol.ErrorPayload{Code: code})
	if err != nil {
		payload = []byte("{\"code\":\"internal_error\"}")
	}
	errorEnvelope := protocol.Envelope{
		ProtocolVersion: 1,
		MessageID:       "error-" + source.MessageID,
		CorrelationID:   &correlationID,
		TenantID:        source.TenantID,
		HostID:          source.HostID,
		DeviceID:        source.DeviceID,
		SessionID:       target.session.SessionID,
		Direction:       protocol.DirectionSystem,
		Kind:            "system.error",
		PayloadEncoding: protocol.PayloadEncodingPlainJSON,
		Payload:         string(payload),
	}
	if errorEnvelope.MessageID == "error-" {
		errorEnvelope.MessageID = "error"
	}
	target.writeEnvelope(errorEnvelope)
}

func (ws *webSocketSession) writeEnvelope(envelope protocol.Envelope) error {
	data, err := json.Marshal(envelope)
	if err != nil {
		return err
	}
	ws.writeMu.Lock()
	defer ws.writeMu.Unlock()
	return ws.conn.Write(context.Background(), websocket.MessageText, data)
}

func sessionFromRequest(r *http.Request) (session.Session, error) {
	query := r.URL.Query()
	connection := query.Get("connection")
	result := session.Session{
		TenantID:  query.Get("tenantId"),
		HostID:    query.Get("hostId"),
		DeviceID:  query.Get("deviceId"),
		SessionID: query.Get("sessionId"),
	}
	if result.SessionID == "" {
		result.SessionID = "session"
	}
	if result.TenantID == "" || result.HostID == "" {
		return session.Session{}, fmt.Errorf("tenantId and hostId are required")
	}
	switch connection {
	case "host":
		result.ConnectionType = session.ConnectionHost
	case "device":
		if result.DeviceID == "" {
			return session.Session{}, fmt.Errorf("deviceId is required")
		}
		result.ConnectionType = session.ConnectionDevice
	default:
		return session.Session{}, fmt.Errorf("connection must be host or device")
	}
	return result, nil
}

func bearerToken(header string) (string, bool) {
	const prefix = "Bearer "
	if len(header) <= len(prefix) || header[:len(prefix)] != prefix {
		return "", false
	}
	return header[len(prefix):], true
}

func hostKey(tenantID string, hostID string) string {
	return tenantID + "/" + hostID
}

func deviceKey(tenantID string, hostID string, deviceID string) string {
	return tenantID + "/" + hostID + "/" + deviceID
}

func validateSenderEnvelope(sender session.Session, envelope protocol.Envelope) string {
	switch sender.ConnectionType {
	case session.ConnectionHost:
		if envelope.TenantID != sender.TenantID || envelope.HostID != sender.HostID {
			return "identity_mismatch"
		}
		if envelope.Direction != protocol.DirectionWindowsToMobile {
			return "direction_not_allowed"
		}
	case session.ConnectionDevice:
		if envelope.TenantID != sender.TenantID || envelope.HostID != sender.HostID || envelope.DeviceID != sender.DeviceID {
			return "identity_mismatch"
		}
		if envelope.Direction != protocol.DirectionMobileToWindows {
			return "direction_not_allowed"
		}
	default:
		return "identity_mismatch"
	}
	return ""
}

func errorCode(err error) string {
	text := err.Error()
	for i := 0; i < len(text); i++ {
		if text[i] == ':' {
			return text[:i]
		}
	}
	return text
}
