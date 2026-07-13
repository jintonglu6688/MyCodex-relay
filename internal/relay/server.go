package relay

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/mycodex/mycodex-relay/internal/config"
	hostsvc "github.com/mycodex/mycodex-relay/internal/host"
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
	server.mux.HandleFunc("/v1/hosts/register", server.handleRegisterHost)
	server.mux.HandleFunc("/v1/pairing/invites", server.handleCreateInvite)
	server.mux.HandleFunc("/v1/pairing/claim", server.handleClaimInvite)
	server.mux.HandleFunc("/v1/pairing/bind", server.handleBindPairing)
	server.mux.HandleFunc("/v1/pairing/approve", server.handleApprovePairing)
	server.mux.HandleFunc("/v1/devices", server.handleListDevices)
	server.mux.HandleFunc("/v1/devices/revoke", server.handleRevokeDevice)
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
	tlsConfig, err := s.buildTLSConfig()
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", net.JoinHostPort(s.config.ListenHost, strconv.Itoa(s.config.ListenPort)))
	if err != nil {
		return err
	}
	return s.serve(ctx, listener, tlsConfig)
}

func (s *Server) buildTLSConfig() (*tls.Config, error) {
	if !s.config.TLS.Enabled {
		return nil, nil
	}
	certificate, err := tls.LoadX509KeyPair(s.config.TLS.CertFile, s.config.TLS.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load TLS certificate: %w", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS12,
	}, nil
}

func (s *Server) serve(ctx context.Context, listener net.Listener, tlsConfig *tls.Config) error {
	httpServer := &http.Server{Handler: s.Handler(), TLSConfig: tlsConfig}
	go func() {
		<-ctx.Done()
		_ = httpServer.Shutdown(context.Background())
	}()
	var err error
	if tlsConfig != nil {
		err = httpServer.ServeTLS(listener, "", "")
	} else {
		err = httpServer.Serve(listener)
	}
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

func (s *Server) handleRegisterHost(w http.ResponseWriter, r *http.Request) {
	if !s.requireMethod(w, r, http.MethodPost) {
		return
	}
	var request struct {
		TenantID      string `json:"tenantId"`
		HostID        string `json:"hostId"`
		DisplayName   string `json:"displayName"`
		HostPublicKey string `json:"hostPublicKey"`
	}
	if !s.readJSON(w, r, &request) {
		return
	}
	if !s.authorizeTenant(w, r, request.TenantID) {
		return
	}
	service := hostsvc.NewService(s.store)
	if err := service.RegisterHost(request.TenantID, request.HostID, request.DisplayName, request.HostPublicKey); err != nil {
		writeJSON(w, http.StatusBadRequest, protocol.ErrorPayload{Code: errorCode(err)})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"tenantId": request.TenantID, "hostId": request.HostID})
}

func (s *Server) handleCreateInvite(w http.ResponseWriter, r *http.Request) {
	if !s.requireMethod(w, r, http.MethodPost) {
		return
	}
	var request struct {
		TenantID   string `json:"tenantId"`
		HostID     string `json:"hostId"`
		TTLSeconds int    `json:"ttlSeconds"`
	}
	if !s.readJSON(w, r, &request) {
		return
	}
	if !s.authorizeTenant(w, r, request.TenantID) {
		return
	}
	ttl := request.TTLSeconds
	if ttl <= 0 {
		ttl = 600
	}
	service := pairing.NewService(s.store)
	invite, token, err := service.CreateInvite(request.TenantID, request.HostID, time.Now().UTC().Add(time.Duration(ttl)*time.Second))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, protocol.ErrorPayload{Code: errorCode(err)})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"tenantId":            invite.TenantID,
		"hostId":              invite.HostID,
		"inviteId":            invite.InviteID,
		"oneTimePairingToken": token,
		"expiresAt":           invite.ExpiresAt.Format(time.RFC3339Nano),
	})
}

func (s *Server) handleClaimInvite(w http.ResponseWriter, r *http.Request) {
	if !s.requireMethod(w, r, http.MethodPost) {
		return
	}
	var request struct {
		TenantID            string `json:"tenantId"`
		HostID              string `json:"hostId"`
		InviteID            string `json:"inviteId"`
		OneTimePairingToken string `json:"oneTimePairingToken"`
		DeviceID            string `json:"deviceId"`
		DeviceDisplayName   string `json:"deviceDisplayName"`
		DevicePublicKey     string `json:"devicePublicKey"`
		Platform            string `json:"platform"`
	}
	if !s.readJSON(w, r, &request) {
		return
	}
	service := pairing.NewService(s.store)
	claim, err := service.ClaimInvite(pairing.ClaimRequest{
		TenantID:          request.TenantID,
		HostID:            request.HostID,
		InviteID:          request.InviteID,
		Token:             request.OneTimePairingToken,
		DeviceID:          request.DeviceID,
		DeviceDisplayName: request.DeviceDisplayName,
		DevicePublicKey:   request.DevicePublicKey,
		Platform:          request.Platform,
	})
	if err != nil {
		writeJSON(w, http.StatusBadRequest, protocol.ErrorPayload{Code: errorCode(err)})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"tenantId":          claim.TenantID,
		"hostId":            claim.HostID,
		"inviteId":          claim.InviteID,
		"deviceId":          claim.DeviceID,
		"deviceDisplayName": claim.DeviceDisplayName,
		"devicePublicKey":   claim.DevicePublicKey,
		"platform":          claim.Platform,
	})
}

func (s *Server) handleApprovePairing(w http.ResponseWriter, r *http.Request) {
	if !s.requireMethod(w, r, http.MethodPost) {
		return
	}
	var request struct {
		TenantID          string `json:"tenantId"`
		HostID            string `json:"hostId"`
		DeviceID          string `json:"deviceId"`
		DeviceDisplayName string `json:"deviceDisplayName"`
		DevicePublicKey   string `json:"devicePublicKey"`
		Platform          string `json:"platform"`
	}
	if !s.readJSON(w, r, &request) {
		return
	}
	if !s.authorizeTenant(w, r, request.TenantID) {
		return
	}
	service := pairing.NewService(s.store)
	token, err := service.ApproveClaimWithToken(pairing.Claim{
		TenantID:          request.TenantID,
		HostID:            request.HostID,
		DeviceID:          request.DeviceID,
		DeviceDisplayName: request.DeviceDisplayName,
		DevicePublicKey:   request.DevicePublicKey,
		Platform:          request.Platform,
	})
	if err != nil {
		writeJSON(w, http.StatusBadRequest, protocol.ErrorPayload{Code: errorCode(err)})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"tenantId": request.TenantID, "hostId": request.HostID, "deviceId": request.DeviceID, "deviceToken": token})
}

func (s *Server) handleBindPairing(w http.ResponseWriter, r *http.Request) {
	if !s.requireMethod(w, r, http.MethodPost) {
		return
	}
	var request struct {
		TenantID            string `json:"tenantId"`
		HostID              string `json:"hostId"`
		InviteID            string `json:"inviteId"`
		OneTimePairingToken string `json:"oneTimePairingToken"`
		DeviceID            string `json:"deviceId"`
		DeviceDisplayName   string `json:"deviceDisplayName"`
		DevicePublicKey     string `json:"devicePublicKey"`
		Platform            string `json:"platform"`
	}
	if !s.readJSON(w, r, &request) {
		return
	}
	service := pairing.NewService(s.store)
	result, err := service.BindInvite(pairing.ClaimRequest{
		TenantID:          request.TenantID,
		HostID:            request.HostID,
		InviteID:          request.InviteID,
		Token:             request.OneTimePairingToken,
		DeviceID:          request.DeviceID,
		DeviceDisplayName: request.DeviceDisplayName,
		DevicePublicKey:   request.DevicePublicKey,
		Platform:          request.Platform,
	})
	if err != nil {
		writeJSON(w, http.StatusBadRequest, protocol.ErrorPayload{Code: errorCode(err)})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"tenantId":          result.Claim.TenantID,
		"hostId":            result.Claim.HostID,
		"deviceId":          result.Claim.DeviceID,
		"deviceDisplayName": result.Claim.DeviceDisplayName,
		"platform":          result.Claim.Platform,
		"deviceToken":       result.DeviceToken,
	})
}

func (s *Server) handleListDevices(w http.ResponseWriter, r *http.Request) {
	if !s.requireMethod(w, r, http.MethodGet) {
		return
	}
	tenantID := r.URL.Query().Get("tenantId")
	hostID := r.URL.Query().Get("hostId")
	if !s.authorizeTenant(w, r, tenantID) {
		return
	}
	service := pairing.NewService(s.store)
	devices, err := service.ListDevices(tenantID, hostID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, protocol.ErrorPayload{Code: errorCode(err)})
		return
	}
	type deviceResponse struct {
		TenantID    string `json:"tenantId"`
		HostID      string `json:"hostId"`
		DeviceID    string `json:"deviceId"`
		DisplayName string `json:"displayName"`
		Platform    string `json:"platform"`
		BoundAt     string `json:"boundAt"`
		Online      bool   `json:"online"`
	}
	response := make([]deviceResponse, 0, len(devices))
	for _, device := range devices {
		response = append(response, deviceResponse{
			TenantID:    device.TenantID,
			HostID:      device.HostID,
			DeviceID:    device.DeviceID,
			DisplayName: device.DisplayName,
			Platform:    device.Platform,
			BoundAt:     device.BoundAt.Format(time.RFC3339Nano),
			Online:      s.isDeviceOnline(device.TenantID, device.HostID, device.DeviceID),
		})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"devices": response})
}

func (s *Server) handleRevokeDevice(w http.ResponseWriter, r *http.Request) {
	if !s.requireMethod(w, r, http.MethodPost) {
		return
	}
	var request struct {
		TenantID string `json:"tenantId"`
		HostID   string `json:"hostId"`
		DeviceID string `json:"deviceId"`
	}
	if !s.readJSON(w, r, &request) {
		return
	}
	if !s.authorizeTenant(w, r, request.TenantID) {
		return
	}
	service := pairing.NewService(s.store)
	if err := service.RevokeDevice(request.TenantID, request.HostID, request.DeviceID); err != nil {
		writeJSON(w, http.StatusBadRequest, protocol.ErrorPayload{Code: errorCode(err)})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"tenantId": request.TenantID, "hostId": request.HostID, "deviceId": request.DeviceID, "revoked": true})
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
	conn.SetReadLimit(webSocketReadLimit(s.config.DefaultQuota.MaxMessageBytes))
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

func (s *Server) authorizeTenant(w http.ResponseWriter, r *http.Request, tenantID string) bool {
	if s.store == nil {
		writeJSON(w, http.StatusServiceUnavailable, protocol.ErrorPayload{Code: "store_required"})
		return false
	}
	token, ok := bearerToken(r.Header.Get("Authorization"))
	if !ok {
		writeJSON(w, http.StatusUnauthorized, protocol.ErrorPayload{Code: "unauthorized"})
		return false
	}
	tenantService := tenant.NewService(s.store)
	item, err := tenantService.Get(tenantID)
	if err != nil || !item.Enabled || !tenant.VerifySecretHash(item.SecretHash, token) {
		writeJSON(w, http.StatusUnauthorized, protocol.ErrorPayload{Code: "unauthorized"})
		return false
	}
	return true
}

func (s *Server) requireMethod(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method != method {
		w.Header().Set("Allow", method)
		writeJSON(w, http.StatusMethodNotAllowed, protocol.ErrorPayload{Code: "method_not_allowed"})
		return false
	}
	return true
}

func (s *Server) readJSON(w http.ResponseWriter, r *http.Request, target interface{}) bool {
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeJSON(w, http.StatusBadRequest, protocol.ErrorPayload{Code: "invalid_json"})
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, value interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	encoder := json.NewEncoder(w)
	encoder.Encode(value)
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

func (s *Server) isDeviceOnline(tenantID string, hostID string, deviceID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.devices[deviceKey(tenantID, hostID, deviceID)]
	return ok
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

func webSocketReadLimit(maxPayloadBytes int) int64 {
	if maxPayloadBytes < 0 {
		return -1
	}
	return int64(maxPayloadBytes)*2 + 64*1024
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
