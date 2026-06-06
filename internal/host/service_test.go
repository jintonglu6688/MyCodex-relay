package host

import (
	"path/filepath"
	"testing"

	"github.com/mycodex/mycodex-relay/internal/store"
)

func TestRegisterAndGetHostIsTenantScoped(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "relay-state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()

	service := NewService(st)
	if err := service.RegisterHost("tenant_a", "host_same", "Windows A", "public-a"); err != nil {
		t.Fatalf("RegisterHost tenant_a failed: %v", err)
	}
	if err := service.RegisterHost("tenant_b", "host_same", "Windows B", "public-b"); err != nil {
		t.Fatalf("RegisterHost tenant_b failed: %v", err)
	}

	host, err := service.GetHost("tenant_a", "host_same")
	if err != nil {
		t.Fatalf("GetHost failed: %v", err)
	}
	if host.DisplayName != "Windows A" || host.HostPublicKey != "public-a" {
		t.Fatalf("unexpected tenant_a host: %+v", host)
	}
	other, err := service.GetHost("tenant_b", "host_same")
	if err != nil {
		t.Fatalf("GetHost tenant_b failed: %v", err)
	}
	if other.DisplayName != "Windows B" || other.HostPublicKey != "public-b" {
		t.Fatalf("unexpected tenant_b host: %+v", other)
	}
}
