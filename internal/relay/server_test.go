package relay

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/mycodex/mycodex-relay/internal/config"
	"github.com/mycodex/mycodex-relay/internal/protocol"
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

func TestWebSocketRoutesPingPongBetweenDeviceAndHost(t *testing.T) {
	cfg := config.Default()
	cfg.DefaultQuota.MaxMessageBytes = 1024
	server := NewServer(cfg)
	httpServer := httptest.NewServer(server.Handler())
	defer httpServer.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	host := dialRelay(t, ctx, httpServer.URL, "connection=host&tenantId=tenant_a&hostId=host_a&sessionId=host_session")
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

func TestWebSocketRejectsCrossTenantRoute(t *testing.T) {
	server := NewServer(config.Default())
	httpServer := httptest.NewServer(server.Handler())
	defer httpServer.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	host := dialRelay(t, ctx, httpServer.URL, "connection=host&tenantId=tenant_a&hostId=host_a&sessionId=host_session")
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

func dialRelay(t *testing.T, ctx context.Context, serverURL string, query string) *websocket.Conn {
	t.Helper()
	wsURL := "ws" + strings.TrimPrefix(serverURL, "http") + "/v1/ws?" + query
	conn, _, err := websocket.Dial(ctx, wsURL, nil)
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
