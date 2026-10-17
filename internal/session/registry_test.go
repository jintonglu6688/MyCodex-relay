package session

import "testing"

func TestRegistryRoutesWithinTenant(t *testing.T) {
	registry := NewRegistry()
	host := Session{TenantID: "tenant_a", HostID: "host_a", SessionID: "host_session", ConnectionType: ConnectionHost}
	device := Session{TenantID: "tenant_a", HostID: "host_a", DeviceID: "device_a", SessionID: "device_session", ConnectionType: ConnectionDevice}

	registry.Add(host)
	registry.Add(device)

	found, ok := registry.FindDevice("tenant_a", "host_a", "device_a")
	if !ok || found.SessionID != "device_session" {
		t.Fatalf("device route not found: %+v %v", found, ok)
	}
}

func TestRegistryRejectsCrossTenantRoute(t *testing.T) {
	registry := NewRegistry()
	registry.Add(Session{TenantID: "tenant_a", HostID: "host_a", DeviceID: "device_a", SessionID: "device_session", ConnectionType: ConnectionDevice})

	if _, ok := registry.FindDevice("tenant_b", "host_a", "device_a"); ok {
		t.Fatalf("cross-tenant route should not resolve")
	}
}
