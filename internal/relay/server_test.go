package relay

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	authsvc "github.com/mycodex/mycodex-relay/internal/auth"
	"github.com/mycodex/mycodex-relay/internal/config"
	"github.com/mycodex/mycodex-relay/internal/protocol"
	"github.com/mycodex/mycodex-relay/internal/security"
)

func TestHealthEndpoint(t *testing.T) {
	server := NewServer(config.Default())
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest("GET", "/health", nil)

	server.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}
	if recorder.Body.String() != "{\"status\":\"ok\"}\n" {
		t.Fatalf("unexpected body: %q", recorder.Body.String())
	}
}

func TestServeUsesTLSForHealthEndpoint(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "embedded-relay-cert.pem")
	keyPath := filepath.Join(dir, "embedded-relay-key.pem")
	if _, err := security.EnsureEmbeddedCertificate(certPath, keyPath, "192.0.2.42"); err != nil {
		t.Fatalf("create embedded TLS identity: %v", err)
	}
	certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("load embedded TLS identity: %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	server := NewServer(config.Default())
	done := make(chan error, 1)
	go func() {
		done <- server.serve(ctx, listener, &tls.Config{
			Certificates: []tls.Certificate{certificate},
			MinVersion:   tls.VersionTLS12,
		})
	}()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("serve returned error: %v", err)
		}
	}()

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read embedded certificate: %v", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		t.Fatal("append embedded certificate to test roots")
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs:    roots,
		MinVersion: tls.VersionTLS12,
	}}}
	response, err := client.Get("https://" + listener.Addr().String() + "/health")
	if err != nil {
		t.Fatalf("GET TLS health endpoint: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", response.StatusCode)
	}
}

func TestServeRejectsInvalidTLSCertificateBeforeBinding(t *testing.T) {
	reserved, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	host, rawPort, err := net.SplitHostPort(reserved.Addr().String())
	if err != nil {
		t.Fatalf("split address: %v", err)
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	if err := reserved.Close(); err != nil {
		t.Fatalf("release port: %v", err)
	}
	cfg := config.Default()
	cfg.StatePath = filepath.Join(t.TempDir(), "relay-state.db")
	cfg.ListenHost = host
	cfg.ListenPort = port
	cfg.TLS = config.TLSConfig{
		Enabled:  true,
		CertFile: filepath.Join(t.TempDir(), "missing-cert.pem"),
		KeyFile:  filepath.Join(t.TempDir(), "missing-key.pem"),
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := NewServer(cfg).Serve(ctx); err == nil || !strings.Contains(err.Error(), "TLS certificate") {
		t.Fatalf("expected TLS certificate error, got %v", err)
	}
	available, err := net.Listen("tcp", net.JoinHostPort(host, rawPort))
	if err != nil {
		t.Fatalf("port was bound before TLS validation: %v", err)
	}
	available.Close()
}

func TestWebSocketRoutesPingPongBetweenDeviceAndHost(t *testing.T) {
	cfg := config.Default()
	cfg.DefaultQuota.MaxMessageBytes = 1024
	server := NewServer(cfg)
	httpServer := httptest.NewServer(server.Handler())
	defer httpServer.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	host := dialRelay(t, ctx, httpServer.URL, "connection=host&tenantId=tenant_a&hostId=host_a&deviceId=device_a&sessionId=host_session")
	defer host.Close(websocket.StatusNormalClosure, "")
	device := dialRelay(t, ctx, httpServer.URL, "connection=device&tenantId=tenant_a&hostId=host_a&deviceId=device_a&sessionId=device_session")
	defer device.Close(websocket.StatusNormalClosure, "")

	ping := protocol.Envelope{
		ProtocolVersion: 1,
		MessageID:       "ping-1",
		TenantID:        "tenant_a",
		HostID:          "host_a",
		DeviceID:        "device_a",
		SessionID:       "device_session",
		Direction:       protocol.DirectionMobileToWindows,
		Kind:            "rpc.request",
		Sequence:        1,
		PayloadEncoding: protocol.PayloadEncodingPlainJSON,
		Payload:         "{\"type\":\"remote/ping\",\"value\":\"hello\"}",
	}
	writeEnvelope(t, ctx, device, ping)
	received := readEnvelope(t, ctx, host)
	if received.MessageID != "ping-1" || received.Payload != ping.Payload {
		t.Fatalf("unexpected routed ping: %+v", received)
	}

	pong := protocol.Envelope{
		ProtocolVersion: 1,
		MessageID:       "pong-1",
		CorrelationID:   &ping.MessageID,
		TenantID:        "tenant_a",
		HostID:          "host_a",
		DeviceID:        "device_a",
		SessionID:       "host_session",
		Direction:       protocol.DirectionWindowsToMobile,
		Kind:            "rpc.response",
		Sequence:        2,
		PayloadEncoding: protocol.PayloadEncodingPlainJSON,
		Payload:         "{\"type\":\"remote/pong\",\"value\":\"hello\"}",
	}
	writeEnvelope(t, ctx, host, pong)
	response := readEnvelope(t, ctx, device)
	if response.MessageID != "pong-1" || response.Payload != pong.Payload {
		t.Fatalf("unexpected routed pong: %+v", response)
	}
}

func TestWebSocketRoutesLargeResponseWithinConfiguredMessageLimit(t *testing.T) {
	cfg := config.Default()
	cfg.DefaultQuota.MaxMessageBytes = 128 * 1024
	server := NewServer(cfg)
	httpServer := httptest.NewServer(server.Handler())
	defer httpServer.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	host := dialRelay(t, ctx, httpServer.URL, "connection=host&tenantId=tenant_a&hostId=host_a&deviceId=device_a&sessionId=host_session")
	defer host.Close(websocket.StatusNormalClosure, "")
	device := dialRelay(t, ctx, httpServer.URL, "connection=device&tenantId=tenant_a&hostId=host_a&deviceId=device_a&sessionId=device_session")
	defer device.Close(websocket.StatusNormalClosure, "")
	device.SetReadLimit(256 * 1024)

	payload := `{"type":"remote.response","value":"` + strings.Repeat("x", 40*1024) + `"}`
	response := protocol.Envelope{
		ProtocolVersion: 1,
		MessageID:       "large-response",
		TenantID:        "tenant_a",
		HostID:          "host_a",
		DeviceID:        "device_a",
		SessionID:       "host_session",
		Direction:       protocol.DirectionWindowsToMobile,
		Kind:            "rpc.response",
		Sequence:        1,
		PayloadEncoding: protocol.PayloadEncodingPlainJSON,
		Payload:         payload,
	}

	writeEnvelope(t, ctx, host, response)
	readCtx, readCancel := context.WithTimeout(context.Background(), time.Second)
	defer readCancel()
	received := readEnvelope(t, readCtx, device)
	if received.MessageID != "large-response" || received.Payload != payload {
		t.Fatalf("unexpected large response: messageId=%s payloadBytes=%d", received.MessageID, len([]byte(received.Payload)))
	}
}

func TestWebSocketRoutesRemoteHistoryResponseOverOneMegabyte(t *testing.T) {
	cfg := config.Default()
	server := NewServer(cfg)
	httpServer := httptest.NewServer(server.Handler())
	defer httpServer.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	host := dialRelay(t, ctx, httpServer.URL, "connection=host&tenantId=tenant_a&hostId=host_a&deviceId=device_a&sessionId=host_session")
	defer host.Close(websocket.StatusNormalClosure, "")
	device := dialRelay(t, ctx, httpServer.URL, "connection=device&tenantId=tenant_a&hostId=host_a&deviceId=device_a&sessionId=device_session")
	defer device.Close(websocket.StatusNormalClosure, "")
	device.SetReadLimit(2 * 1024 * 1024)

	payload := `{"type":"remote.event","eventType":"coding.messages.list.result","messages":"` + strings.Repeat("x", 1250*1024) + `"}`
	response := protocol.Envelope{
		ProtocolVersion: 1,
		MessageID:       "large-history-response",
		TenantID:        "tenant_a",
		HostID:          "host_a",
		DeviceID:        "device_a",
		SessionID:       "host_session",
		Direction:       protocol.DirectionWindowsToMobile,
		Kind:            "rpc.response",
		Sequence:        1,
		PayloadEncoding: protocol.PayloadEncodingPlainJSON,
		Payload:         payload,
	}

	writeEnvelope(t, ctx, host, response)
	readCtx, readCancel := context.WithTimeout(context.Background(), time.Second)
	defer readCancel()
	received := readEnvelope(t, readCtx, device)
	if received.MessageID != "large-history-response" || received.Payload != payload {
		t.Fatalf("unexpected large history response: messageId=%s payloadBytes=%d", received.MessageID, len([]byte(received.Payload)))
	}
}

func TestWebSocketForwardsRemoteCodingPayloadUntouched(t *testing.T) {
	server := NewServer(config.Default())
	httpServer := httptest.NewServer(server.Handler())
	defer httpServer.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	host := dialRelay(t, ctx, httpServer.URL, "connection=host&tenantId=tenant_a&hostId=host_a&deviceId=device_a&sessionId=host_session")
	defer host.Close(websocket.StatusNormalClosure, "")
	device := dialRelay(t, ctx, httpServer.URL, "connection=device&tenantId=tenant_a&hostId=host_a&deviceId=device_a&sessionId=device_session")
	defer device.Close(websocket.StatusNormalClosure, "")

	payload := "{\"schemaVersion\":1,\"payloadType\":\"remote.command\",\"requestId\":\"request_a\",\"deviceId\":\"device_a\",\"commandType\":\"coding.workspaces.list\",\"payload\":{}}"
	message := protocol.Envelope{
		ProtocolVersion: 1,
		MessageID:       "coding-request",
		TenantID:        "tenant_a",
		HostID:          "host_a",
		DeviceID:        "device_a",
		SessionID:       "device_session",
		Direction:       protocol.DirectionMobileToWindows,
		Kind:            "rpc.request",
		Sequence:        1,
		PayloadEncoding: protocol.PayloadEncodingPlainJSON,
		Payload:         payload,
	}

	writeEnvelope(t, ctx, device, message)
	received := readEnvelope(t, ctx, host)
	if received.Payload != payload {
		t.Fatalf("payload changed during relay route: %s", received.Payload)
	}
}

func TestWebSocketRejectsCrossTenantRoute(t *testing.T) {
	server := NewServer(config.Default())
	httpServer := httptest.NewServer(server.Handler())
	defer httpServer.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	host := dialRelay(t, ctx, httpServer.URL, "connection=host&tenantId=tenant_a&hostId=host_a&deviceId=device_a&sessionId=host_session")
	defer host.Close(websocket.StatusNormalClosure, "")
	device := dialRelay(t, ctx, httpServer.URL, "connection=device&tenantId=tenant_b&hostId=host_a&deviceId=device_a&sessionId=device_session")
	defer device.Close(websocket.StatusNormalClosure, "")

	message := protocol.Envelope{
		ProtocolVersion: 1,
		MessageID:       "cross-tenant",
		TenantID:        "tenant_b",
		HostID:          "host_a",
		DeviceID:        "device_a",
		SessionID:       "device_session",
		Direction:       protocol.DirectionMobileToWindows,
		Kind:            "rpc.request",
		Sequence:        1,
		PayloadEncoding: protocol.PayloadEncodingPlainJSON,
		Payload:         "{}",
	}
	writeEnvelope(t, ctx, device, message)
	response := readEnvelope(t, ctx, device)
	if response.Kind != "system.error" || response.Payload != "{\"code\":\"route_not_found\"}" {
		t.Fatalf("expected route_not_found error envelope, got %+v", response)
	}
}

func TestWebSocketRejectsDeviceEnvelopeTenantMismatchBeforeRouting(t *testing.T) {
	server := NewServer(config.Default())
	httpServer := httptest.NewServer(server.Handler())
	defer httpServer.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tenantBHost := dialRelay(t, ctx, httpServer.URL, "connection=host&tenantId=tenant_b&hostId=host_b&deviceId=device_a&sessionId=host_b_session")
	defer tenantBHost.Close(websocket.StatusNormalClosure, "")
	device := dialRelay(t, ctx, httpServer.URL, "connection=device&tenantId=tenant_a&hostId=host_a&deviceId=device_a&sessionId=device_a_session")
	defer device.Close(websocket.StatusNormalClosure, "")

	message := protocol.Envelope{
		ProtocolVersion: 1,
		MessageID:       "spoof-tenant",
		TenantID:        "tenant_b",
		HostID:          "host_b",
		DeviceID:        "device_a",
		SessionID:       "device_a_session",
		Direction:       protocol.DirectionMobileToWindows,
		Kind:            "rpc.request",
		Sequence:        1,
		PayloadEncoding: protocol.PayloadEncodingPlainJSON,
		Payload:         "{}",
	}
	writeEnvelope(t, ctx, device, message)
	response := readEnvelope(t, ctx, device)
	if response.Kind != "system.error" || response.Payload != "{\"code\":\"identity_mismatch\"}" {
		t.Fatalf("expected identity_mismatch error envelope, got %+v", response)
	}

	readCtx, readCancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer readCancel()
	if _, _, err := tenantBHost.Read(readCtx); err == nil {
		t.Fatalf("tenant_b host should not receive spoofed device message")
	}
}

func TestWebSocketRejectsDeviceSendingWindowsToMobile(t *testing.T) {
	server := NewServer(config.Default())
	httpServer := httptest.NewServer(server.Handler())
	defer httpServer.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	device := dialRelay(t, ctx, httpServer.URL, "connection=device&tenantId=tenant_a&hostId=host_a&deviceId=device_a&sessionId=device_a_session")
	defer device.Close(websocket.StatusNormalClosure, "")

	message := protocol.Envelope{
		ProtocolVersion: 1,
		MessageID:       "device-wrong-direction",
		TenantID:        "tenant_a",
		HostID:          "host_a",
		DeviceID:        "device_a",
		SessionID:       "device_a_session",
		Direction:       protocol.DirectionWindowsToMobile,
		Kind:            "rpc.response",
		Sequence:        1,
		PayloadEncoding: protocol.PayloadEncodingPlainJSON,
		Payload:         "{}",
	}
	writeEnvelope(t, ctx, device, message)
	response := readEnvelope(t, ctx, device)
	if response.Kind != "system.error" || response.Payload != "{\"code\":\"direction_not_allowed\"}" {
		t.Fatalf("expected direction_not_allowed error envelope, got %+v", response)
	}
}

func TestWebSocketRejectsHostSendingMobileToWindows(t *testing.T) {
	server := NewServer(config.Default())
	httpServer := httptest.NewServer(server.Handler())
	defer httpServer.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	host := dialRelay(t, ctx, httpServer.URL, "connection=host&tenantId=tenant_a&hostId=host_a&deviceId=device_a&sessionId=host_a_session")
	defer host.Close(websocket.StatusNormalClosure, "")

	message := protocol.Envelope{
		ProtocolVersion: 1,
		MessageID:       "host-wrong-direction",
		TenantID:        "tenant_a",
		HostID:          "host_a",
		DeviceID:        "device_a",
		SessionID:       "host_a_session",
		Direction:       protocol.DirectionMobileToWindows,
		Kind:            "rpc.request",
		Sequence:        1,
		PayloadEncoding: protocol.PayloadEncodingPlainJSON,
		Payload:         "{}",
	}
	writeEnvelope(t, ctx, host, message)
	response := readEnvelope(t, ctx, host)
	if response.Kind != "system.error" || response.Payload != "{\"code\":\"direction_not_allowed\"}" {
		t.Fatalf("expected direction_not_allowed error envelope, got %+v", response)
	}
}

func TestWebSocketAuthenticatedHostAndDeviceRoutePingPong(t *testing.T) {
	fixture := newHTTPAuthFixture(t)
	hostPrivate, _ := enrollHTTPHost(t, fixture)
	devicePrivate := newHTTPPrivateKey(t)
	devicePublic := encodeHTTPPublicKey(&devicePrivate.PublicKey)
	agreementPublic := encodeHTTPPublicKey(&newHTTPPrivateKey(t).PublicKey)
	if _, err := fixture.store.DB().Exec(
		`insert into devices
(tenant_id, host_id, device_id, signing_public_key, agreement_public_key,
 key_version, binding_version, revoked, approved_at)
values (?, ?, ?, ?, ?, ?, ?, 0, ?)`,
		fixture.tenantID, fixture.hostID, fixture.deviceID,
		devicePublic, agreementPublic, 1, 1,
		time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("insert device identity: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	hostTicket := issueHTTPAuthTicket(t, fixture.server.URL, hostPrivate, authsvc.TicketScope{
		SubjectType: authsvc.SubjectHost,
		SubjectID:   fixture.hostID,
		TenantID:    fixture.tenantID,
		HostID:      fixture.hostID,
		DeviceID:    fixture.deviceID,
		Purpose:     authsvc.PurposeWebSocketHost,
	})
	deviceTicket := issueHTTPAuthTicket(t, fixture.server.URL, devicePrivate, authsvc.TicketScope{
		SubjectType: authsvc.SubjectDevice,
		SubjectID:   fixture.deviceID,
		TenantID:    fixture.tenantID,
		HostID:      fixture.hostID,
		DeviceID:    fixture.deviceID,
		Purpose:     authsvc.PurposeWebSocketDevice,
	})
	host := dialRelayWithAuth(t, ctx, fixture.server.URL, "connection=host&tenantId="+fixture.tenantID+"&hostId="+fixture.hostID+"&deviceId="+fixture.deviceID+"&sessionId=host_session", hostTicket.Ticket)
	defer host.Close(websocket.StatusNormalClosure, "")
	device := dialRelayWithAuth(t, ctx, fixture.server.URL, "connection=device&tenantId="+fixture.tenantID+"&hostId="+fixture.hostID+"&deviceId="+fixture.deviceID+"&sessionId=device_session", deviceTicket.Ticket)
	defer device.Close(websocket.StatusNormalClosure, "")

	ping := protocol.Envelope{ProtocolVersion: 1, MessageID: "auth-ping", TenantID: fixture.tenantID, HostID: fixture.hostID, DeviceID: fixture.deviceID, SessionID: "device_session", Direction: protocol.DirectionMobileToWindows, Kind: "rpc.request", Sequence: 1, PayloadEncoding: protocol.PayloadEncodingPlainJSON, Payload: "{}"}
	writeEnvelope(t, ctx, device, ping)
	if received := readEnvelope(t, ctx, host); received.MessageID != "auth-ping" {
		t.Fatalf("unexpected routed ping: %+v", received)
	}
}

func TestWebSocketRejectsMissingHostAuthorization(t *testing.T) {
	fixture := newHTTPAuthFixture(t)
	enrollHTTPHost(t, fixture)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	wsURL := "ws" + strings.TrimPrefix(fixture.server.URL, "http") +
		"/v1/ws?connection=host&tenantId=" + fixture.tenantID +
		"&hostId=" + fixture.hostID + "&deviceId=" + fixture.deviceID
	_, response, err := websocket.Dial(ctx, wsURL, nil)
	if err == nil {
		t.Fatalf("expected missing authorization to fail")
	}
	if response == nil || response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got response=%v err=%v", response, err)
	}
}

func TestWebSocketRejectsInvalidDeviceAuthorization(t *testing.T) {
	fixture := newHTTPAuthFixture(t)
	enrollHTTPHost(t, fixture)
	insertHTTPDeviceIdentity(t, fixture)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	wsURL := "ws" + strings.TrimPrefix(fixture.server.URL, "http") +
		"/v1/ws?connection=device&tenantId=" + fixture.tenantID +
		"&hostId=" + fixture.hostID + "&deviceId=" + fixture.deviceID
	_, response, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": []string{"Bearer wrong"}}})
	if err == nil {
		t.Fatalf("expected invalid device authorization to fail")
	}
	if response == nil || response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got response=%v err=%v", response, err)
	}
}

func TestWebSocketRejectsRevokedDeviceAuthorization(t *testing.T) {
	fixture := newHTTPAuthFixture(t)
	enrollHTTPHost(t, fixture)
	devicePrivate := insertHTTPDeviceIdentity(t, fixture)
	ticket := issueHTTPAuthTicket(t, fixture.server.URL, devicePrivate, authsvc.TicketScope{
		SubjectType: authsvc.SubjectDevice,
		SubjectID:   fixture.deviceID,
		TenantID:    fixture.tenantID,
		HostID:      fixture.hostID,
		DeviceID:    fixture.deviceID,
		Purpose:     authsvc.PurposeWebSocketDevice,
	})
	if _, err := fixture.store.DB().Exec(
		"update devices set revoked = 1 where tenant_id = ? and host_id = ? and device_id = ?",
		fixture.tenantID, fixture.hostID, fixture.deviceID); err != nil {
		t.Fatalf("revoke device: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	wsURL := "ws" + strings.TrimPrefix(fixture.server.URL, "http") +
		"/v1/ws?connection=device&tenantId=" + fixture.tenantID +
		"&hostId=" + fixture.hostID + "&deviceId=" + fixture.deviceID
	_, response, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": []string{"Bearer " + ticket.Ticket}},
	})
	if err == nil {
		t.Fatalf("expected revoked device authorization to fail")
	}
	if response == nil || response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got response=%v err=%v", response, err)
	}
}

func dialRelay(t *testing.T, ctx context.Context, serverURL string, query string) *websocket.Conn {
	t.Helper()
	wsURL := "ws" + strings.TrimPrefix(serverURL, "http") + "/v1/ws?" + query
	conn, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("websocket dial failed: %v", err)
	}
	return conn
}

func dialRelayWithAuth(t *testing.T, ctx context.Context, serverURL string, query string, token string) *websocket.Conn {
	t.Helper()
	wsURL := "ws" + strings.TrimPrefix(serverURL, "http") + "/v1/ws?" + query
	conn, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": []string{"Bearer " + token}}})
	if err != nil {
		t.Fatalf("websocket dial failed: %v", err)
	}
	return conn
}

func writeEnvelope(t *testing.T, ctx context.Context, conn *websocket.Conn, envelope protocol.Envelope) {
	t.Helper()
	data, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	if err := conn.Write(ctx, websocket.MessageText, data); err != nil {
		t.Fatalf("write envelope: %v", err)
	}
}

func readEnvelope(t *testing.T, ctx context.Context, conn *websocket.Conn) protocol.Envelope {
	t.Helper()
	messageType, data, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("read envelope: %v", err)
	}
	if messageType != websocket.MessageText {
		t.Fatalf("expected text message, got %v", messageType)
	}
	var envelope protocol.Envelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		t.Fatalf("unmarshal envelope: %v; data=%s", err, string(data))
	}
	return envelope
}

func insertHTTPDeviceIdentity(t *testing.T, fixture httpAuthFixture) *ecdsa.PrivateKey {
	t.Helper()
	signingPrivate := newHTTPPrivateKey(t)
	if _, err := fixture.store.DB().Exec(
		`insert into devices
(tenant_id, host_id, device_id, signing_public_key, agreement_public_key,
 key_version, binding_version, revoked, approved_at)
values (?, ?, ?, ?, ?, ?, ?, 0, ?)`,
		fixture.tenantID,
		fixture.hostID,
		fixture.deviceID,
		encodeHTTPPublicKey(&signingPrivate.PublicKey),
		encodeHTTPPublicKey(&newHTTPPrivateKey(t).PublicKey),
		1,
		1,
		time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("insert device identity: %v", err)
	}
	return signingPrivate
}
