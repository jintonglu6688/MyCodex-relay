package tenant

import (
	"path/filepath"
	"testing"

	"github.com/mycodex/mycodex-relay/internal/store"
)

func TestCreateAndGetTenant(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "relay-state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()

	service := NewService(st)
	created, secret, err := service.Create("Alice")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	if created.TenantID == "" || secret == "" {
		t.Fatalf("expected tenant id and secret")
	}

	loaded, err := service.Get(created.TenantID)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if loaded.DisplayName != "Alice" || !loaded.Enabled {
		t.Fatalf("unexpected tenant: %+v", loaded)
	}
}
