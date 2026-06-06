package integration

import (
	"testing"

	"github.com/mycodex/mycodex-relay/internal/debug"
	"github.com/mycodex/mycodex-relay/internal/protocol"
	"github.com/mycodex/mycodex-relay/internal/session"
)

func TestTenantIsolatedPingPongRoute(t *testing.T) {
	registry := session.NewRegistry()
	registry.Add(session.Session{TenantID: "tenant_a", HostID: "host_a", SessionID: "host_session", ConnectionType: session.ConnectionHost})
	registry.Add(session.Session{TenantID: "tenant_a", HostID: "host_a", DeviceID: "device_a", SessionID: "device_session", ConnectionType: session.ConnectionDevice})

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
		Payload:         debug.BuildPingPayload("hello"),
	}

	if err := ping.Validate(1024); err != nil {
		t.Fatalf("ping envelope invalid: %v", err)
	}
	host, ok := registry.FindHost(ping.TenantID, ping.HostID)
	if !ok || host.SessionID != "host_session" {
		t.Fatalf("host route not found: %+v", host)
	}
	if _, ok := registry.FindHost("tenant_b", ping.HostID); ok {
		t.Fatalf("cross-tenant host route should not resolve")
	}
}
