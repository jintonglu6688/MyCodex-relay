package relay

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/coder/websocket"
	authsvc "github.com/mycodex/mycodex-relay/internal/auth"
	"github.com/mycodex/mycodex-relay/internal/config"
	"github.com/mycodex/mycodex-relay/internal/pairing"
	"github.com/mycodex/mycodex-relay/internal/protocol"
	"github.com/mycodex/mycodex-relay/internal/security"
	"github.com/mycodex/mycodex-relay/internal/session"
	"github.com/mycodex/mycodex-relay/internal/store"
	"github.com/mycodex/mycodex-relay/internal/tenant"
)

const (
	closeInvalidFrame = websocket.StatusCode(4001)
	closeRouteMissing = websocket.StatusCode(4004)
	closeIdentity     = websocket.StatusCode(4008)
	closeReplaced     = websocket.StatusCode(4009)
	relayWriteTimeout = 15 * time.Second
	shutdownTimeout   = 15 * time.Second
)

type Server struct {
	config            config.Config
	mux               *http.ServeMux
	store             *store.Store
	authOnce          sync.Once
	identity          *security.RelayIdentitySigner
	authService       *authsvc.Service
	authErr           error
	challengeMu       sync.Mutex
	challengeAttempts map[string]challengeAttempt
	mu                sync.RWMutex
	hosts             map[string]*webSocketSession
	devices           map[string]*webSocketSession
	shuttingDown      bool
	webSocketWG       sync.WaitGroup
	shutdownOnce      sync.Once
	webSocketsDone    chan struct{}
}

func NewServer(cfg config.Config) *Server {
	s := &Server{config: cfg, mux: http.NewServeMux(), hosts: map[string]*webSocketSession{}, devices: map[string]*webSocketSession{}, challengeAttempts: map[string]challengeAttempt{}, webSocketsDone: make(chan struct{})}
	s.mux.HandleFunc("/health", s.handleHealth)
	s.mux.HandleFunc("/.well-known/mycodex-relay", s.handleMetadata)
	s.mux.HandleFunc("/v1/ws", s.handleWebSocket)
	s.mux.HandleFunc("/v1/hosts/enroll", s.handleEnrollHost)
	s.mux.HandleFunc("/v1/auth/challenges", s.handleCreateChallenge)
	s.mux.HandleFunc("/v1/auth/prove", s.handleProve)
	s.registerPairingRoutes()
	return s
}
func NewServerWithStore(cfg config.Config, st *store.Store) *Server {
	s := NewServer(cfg)
	s.store = st
	return s
}
func (s *Server) Handler() http.Handler { return s.mux }
func (s *Server) Serve(ctx context.Context) error {
	if err := s.ensureAuth(); err != nil {
		return fmt.Errorf("initialize Relay identity: %w", err)
	}
	tlsConfig, err := s.buildTLSConfig()
	if err != nil {
		return err
	}
	if err := config.ValidateInternalListener(s.config); err != nil {
		return err
	}
	if s.config.InternalListenHost != "" && !s.config.TLS.Enabled {
		return fmt.Errorf("internal listener requires public TLS")
	}
	publicListener, err := net.Listen("tcp", net.JoinHostPort(s.config.ListenHost, strconv.Itoa(s.config.ListenPort)))
	if err != nil {
		return fmt.Errorf("public listener: %w", err)
	}
	if s.config.InternalListenHost == "" || s.config.InternalListenPort == 0 {
		return s.serve(ctx, publicListener, tlsConfig)
	}
	internalListener, err := net.Listen("tcp", net.JoinHostPort(s.config.InternalListenHost, strconv.Itoa(s.config.InternalListenPort)))
	if err != nil {
		_ = publicListener.Close()
		return fmt.Errorf("internal listener: %w", err)
	}
	return s.serveBoth(ctx, publicListener, internalListener, tlsConfig)
}
func (s *Server) serveBoth(ctx context.Context, publicListener, internalListener net.Listener, tlsConfig *tls.Config) error {
	serveCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan error, 2)
	go func() { results <- s.serve(serveCtx, publicListener, tlsConfig) }()
	go func() { results <- s.serve(serveCtx, internalListener, nil) }()
	first := <-results
	cancel()
	second := <-results
	if first != nil {
		return first
	}
	return second
}
func (s *Server) buildTLSConfig() (*tls.Config, error) {
	if !s.config.TLS.Enabled {
		return nil, nil
	}
	certificate, err := tls.LoadX509KeyPair(s.config.TLS.CertFile, s.config.TLS.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load TLS certificate: %w", err)
	}
	return &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}, nil
}
func (s *Server) serve(ctx context.Context, listener net.Listener, tlsConfig *tls.Config) error {
	httpServer := &http.Server{Handler: s.Handler(), TLSConfig: tlsConfig}
	serveCtx, cancel := context.WithCancel(ctx)
	shutdownDone := make(chan error, 1)
	go func() {
		<-serveCtx.Done()
		shutdownDone <- s.shutdown(httpServer)
	}()
	var err error
	if tlsConfig != nil {
		err = httpServer.ServeTLS(listener, "", "")
	} else {
		err = httpServer.Serve(listener)
	}
	cancel()
	shutdownErr := <-shutdownDone
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return shutdownErr
}
func (s *Server) shutdown(httpServer *http.Server) error {
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	webSocketsDone := s.beginShutdown()
	if err := httpServer.Shutdown(ctx); err != nil {
		return fmt.Errorf("shutdown HTTP server: %w", err)
	}
	select {
	case <-webSocketsDone:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("wait for WebSocket handlers: %w", ctx.Err())
	}
}
func (s *Server) beginShutdown() <-chan struct{} {
	s.shutdownOnce.Do(func() {
		unique := make(map[*webSocketSession]struct{})
		s.mu.Lock()
		s.shuttingDown = true
		for _, active := range s.hosts {
			unique[active] = struct{}{}
		}
		for _, active := range s.devices {
			unique[active] = struct{}{}
		}
		clear(s.hosts)
		clear(s.devices)
		s.mu.Unlock()

		active := make([]*webSocketSession, 0, len(unique))
		for item := range unique {
			active = append(active, item)
		}
		closeSessions(active, websocket.StatusGoingAway, "server_shutdown")
		go func() {
			s.webSocketWG.Wait()
			close(s.webSocketsDone)
		}()
	})
	return s.webSocketsDone
}
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("{\"status\":\"ok\"}\n"))
}

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	active, err := sessionFromRequest(r)
	if err != nil {
		http.Error(w, "bad websocket request", http.StatusBadRequest)
		return
	}
	if !s.authenticateSession(r, active) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
	if err != nil {
		return
	}
	conn.SetReadLimit(protocol.WireFrameLimit(s.config.DefaultQuota.MaxMessageBytes))
	ws := &webSocketSession{session: active, conn: conn}
	if !s.beginWebSocket(ws) {
		closeSocket(conn, closeIdentity, "identity_or_direction_mismatch")
		return
	}
	defer func() {
		s.removeSession(ws)
		closeSocket(conn, websocket.StatusNormalClosure, "")
		s.webSocketWG.Done()
	}()
	for {
		messageType, data, err := conn.Read(r.Context())
		if err != nil {
			return
		}
		if messageType != websocket.MessageText {
			closeSocket(conn, closeInvalidFrame, "invalid_frame")
			return
		}
		frame, err := protocol.ParseRelayFrame(data, s.config.DefaultQuota.MaxMessageBytes)
		if err != nil {
			closeSocket(conn, closeInvalidFrame, "invalid_frame")
			return
		}
		if code := validateSenderFrame(ws.session, frame); code != 0 {
			closeSocket(conn, code, "identity_or_direction_mismatch")
			return
		}
		if !s.routeFrame(ws, frame, data) {
			return
		}
	}
}

func (s *Server) authenticateSession(r *http.Request, active session.Session) bool {
	if s.store == nil {
		return true
	}
	token, ok := bearerToken(r.Header.Get("Authorization"))
	if !ok {
		return false
	}
	var scope authsvc.TicketScope
	switch active.ConnectionType {
	case session.ConnectionHost:
		scope = authsvc.TicketScope{SubjectType: authsvc.SubjectHost, SubjectID: active.HostID, TenantID: active.TenantID, HostID: active.HostID, DeviceID: active.DeviceID, Purpose: authsvc.PurposeWebSocketHost}
	case session.ConnectionDevice:
		scope = authsvc.TicketScope{SubjectType: authsvc.SubjectDevice, SubjectID: active.DeviceID, TenantID: active.TenantID, HostID: active.HostID, DeviceID: active.DeviceID, Purpose: authsvc.PurposeWebSocketDevice}
	default:
		return false
	}
	return s.ensureAuth() == nil && s.authService != nil && s.authService.ConsumeTicket(token, scope) == nil
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
	item, err := tenant.NewService(s.store).Get(tenantID)
	if err != nil || !item.Enabled || !tenant.VerifySecretHash(item.SecretHash, token) {
		writeJSON(w, http.StatusUnauthorized, protocol.ErrorPayload{Code: "unauthorized"})
		return false
	}
	return true
}
func (s *Server) requireMethod(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method == method {
		return true
	}
	w.Header().Set("Allow", method)
	writeJSON(w, http.StatusMethodNotAllowed, protocol.ErrorPayload{Code: "method_not_allowed"})
	return false
}
func (s *Server) readJSON(w http.ResponseWriter, r *http.Request, target interface{}) bool {
	r.Body = http.MaxBytesReader(w, r.Body, int64(protocol.EffectiveMessageBytes(s.config.DefaultQuota.MaxMessageBytes)))
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeJSON(w, http.StatusRequestEntityTooLarge, protocol.ErrorPayload{Code: "request_too_large"})
			return false
		}
		writeJSON(w, http.StatusBadRequest, protocol.ErrorPayload{Code: "invalid_json"})
		return false
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		writeJSON(w, http.StatusBadRequest, protocol.ErrorPayload{Code: "invalid_json"})
		return false
	}
	return true
}
func writeJSON(w http.ResponseWriter, status int, value interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

type webSocketSession struct {
	session session.Session
	conn    *websocket.Conn
	writeMu sync.Mutex
}

func (s *Server) addSession(ws *webSocketSession) bool {
	return s.addSessionWithLifecycle(ws, false)
}
func (s *Server) beginWebSocket(ws *webSocketSession) bool {
	return s.addSessionWithLifecycle(ws, true)
}
func (s *Server) addSessionWithLifecycle(ws *webSocketSession, trackLifecycle bool) bool {
	var closeList []*webSocketSession
	key := deviceKey(ws.session.TenantID, ws.session.HostID, ws.session.DeviceID)
	s.mu.Lock()
	if s.shuttingDown || !s.routeActiveLocked(ws.session) {
		s.mu.Unlock()
		return false
	}
	switch ws.session.ConnectionType {
	case session.ConnectionHost:
		if old := s.hosts[key]; old != nil {
			delete(s.hosts, key)
			closeList = append(closeList, old)
		}
		if old := s.devices[key]; old != nil {
			delete(s.devices, key)
			closeList = append(closeList, old)
		}
		s.hosts[key] = ws
	case session.ConnectionDevice:
		if old := s.devices[key]; old != nil {
			delete(s.devices, key)
			closeList = append(closeList, old)
		}
		s.devices[key] = ws
	default:
		s.mu.Unlock()
		return false
	}
	if trackLifecycle {
		s.webSocketWG.Add(1)
	}
	s.mu.Unlock()
	closeSessions(closeList, closeReplaced, "peer_replaced")
	return true
}
func (s *Server) routeActiveLocked(active session.Session) bool {
	if s.store == nil {
		return true
	}
	_, err := pairing.NewService(s.store).GetDevice(active.TenantID, active.HostID, active.DeviceID)
	return err == nil
}
func (s *Server) removeSession(ws *webSocketSession) {
	var closeList []*webSocketSession
	key := deviceKey(ws.session.TenantID, ws.session.HostID, ws.session.DeviceID)
	s.mu.Lock()
	switch ws.session.ConnectionType {
	case session.ConnectionHost:
		if s.hosts[key] == ws {
			delete(s.hosts, key)
			if peer := s.devices[key]; peer != nil {
				delete(s.devices, key)
				closeList = append(closeList, peer)
			}
		}
	case session.ConnectionDevice:
		if s.devices[key] == ws {
			delete(s.devices, key)
			if peer := s.hosts[key]; peer != nil {
				delete(s.hosts, key)
				closeList = append(closeList, peer)
			}
		}
	}
	s.mu.Unlock()
	closeSessions(closeList, closeRouteMissing, "route_unavailable")
}
func (s *Server) isDeviceOnline(tenantID, hostID, deviceID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.devices[deviceKey(tenantID, hostID, deviceID)] != nil
}
func (s *Server) revokeDevice(tenantID, hostID, deviceID string) error {
	key := deviceKey(tenantID, hostID, deviceID)
	var closeList []*webSocketSession
	s.mu.Lock()
	if err := pairing.NewService(s.store).RevokeDevice(tenantID, hostID, deviceID); err != nil {
		s.mu.Unlock()
		return err
	}
	if host := s.hosts[key]; host != nil {
		delete(s.hosts, key)
		closeList = append(closeList, host)
	}
	if device := s.devices[key]; device != nil {
		delete(s.devices, key)
		closeList = append(closeList, device)
	}
	s.mu.Unlock()
	closeSessions(closeList, closeIdentity, "identity_or_direction_mismatch")
	return nil
}
func (s *Server) routeFrame(sender *webSocketSession, frame protocol.RelayFrame, data []byte) bool {
	key := deviceKey(frame.TenantID, frame.HostID, frame.DeviceID)
	s.mu.RLock()
	current := s.hosts[key]
	if sender.session.ConnectionType == session.ConnectionDevice {
		current = s.devices[key]
	}
	if current != sender {
		s.mu.RUnlock()
		closeSocket(sender.conn, closeReplaced, "peer_replaced")
		return false
	}
	target := s.hosts[key]
	if frame.Direction == protocol.DirectionWindowsToMobile {
		target = s.devices[key]
	}
	s.mu.RUnlock()
	if target == nil {
		closeSocket(sender.conn, closeRouteMissing, "route_unavailable")
		return false
	}
	if err := target.writeRaw(data); err != nil {
		closeSocket(sender.conn, closeRouteMissing, "route_unavailable")
		return false
	}
	return true
}
func (ws *webSocketSession) writeRaw(data []byte) error {
	ws.writeMu.Lock()
	defer ws.writeMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), relayWriteTimeout)
	defer cancel()
	return ws.conn.Write(ctx, websocket.MessageText, data)
}
func closeSocket(conn *websocket.Conn, code websocket.StatusCode, reason string) {
	_ = conn.Close(code, reason)
}

func closeSessions(sessions []*webSocketSession, code websocket.StatusCode, reason string) {
	for _, item := range sessions {
		go closeSocket(item.conn, code, reason)
	}
}
func sessionFromRequest(r *http.Request) (session.Session, error) {
	query := r.URL.Query()
	if len(query) != 4 {
		return session.Session{}, fmt.Errorf("invalid query")
	}
	required := []string{"connection", "tenantId", "hostId", "deviceId"}
	for _, key := range required {
		values, ok := query[key]
		if !ok || len(values) != 1 || values[0] == "" {
			return session.Session{}, fmt.Errorf("invalid query")
		}
	}
	for key := range query {
		if key != "connection" && key != "tenantId" && key != "hostId" && key != "deviceId" {
			return session.Session{}, fmt.Errorf("invalid query")
		}
	}
	result := session.Session{TenantID: query.Get("tenantId"), HostID: query.Get("hostId"), DeviceID: query.Get("deviceId")}
	if len([]byte(result.TenantID)) > 128 || len([]byte(result.HostID)) > 128 || len([]byte(result.DeviceID)) > 128 {
		return session.Session{}, fmt.Errorf("invalid query")
	}
	switch query.Get("connection") {
	case "host":
		result.ConnectionType = session.ConnectionHost
	case "device":
		result.ConnectionType = session.ConnectionDevice
	default:
		return session.Session{}, fmt.Errorf("invalid query")
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
func deviceKey(tenantID, hostID, deviceID string) string {
	return tenantID + "/" + hostID + "/" + deviceID
}
func validateSenderFrame(sender session.Session, frame protocol.RelayFrame) websocket.StatusCode {
	if frame.TenantID != sender.TenantID || frame.HostID != sender.HostID || frame.DeviceID != sender.DeviceID {
		return closeIdentity
	}
	if sender.ConnectionType == session.ConnectionHost && frame.Direction != protocol.DirectionWindowsToMobile {
		return closeIdentity
	}
	if sender.ConnectionType == session.ConnectionDevice && frame.Direction != protocol.DirectionMobileToWindows {
		return closeIdentity
	}
	return 0
}
