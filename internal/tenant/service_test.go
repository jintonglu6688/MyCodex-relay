package tenant

import (
	"encoding/hex"
	"path/filepath"
	"strings"
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
	assertCanonicalTenantUUID(t, created.TenantID)

	loaded, err := service.Get(created.TenantID)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if loaded.DisplayName != "Alice" || !loaded.Enabled {
		t.Fatalf("unexpected tenant: %+v", loaded)
	}
}

func assertCanonicalTenantUUID(t *testing.T, value string) {
	t.Helper()
	if len(value) != 36 ||
		value[8] != '-' ||
		value[13] != '-' ||
		value[18] != '-' ||
		value[23] != '-' {
		t.Fatalf("tenant ID %q is not lowercase UUID D format", value)
	}
	if value != strings.ToLower(value) {
		t.Fatalf("tenant ID %q is not lowercase", value)
	}
	raw, err := hex.DecodeString(strings.ReplaceAll(value, "-", ""))
	if err != nil || len(raw) != 16 {
		t.Fatalf("tenant ID %q is not hexadecimal UUID: bytes=%x err=%v", value, raw, err)
	}
	if version := raw[6] >> 4; version != 4 {
		t.Fatalf("tenant ID %q version=%d, want 4", value, version)
	}
	if variant := raw[8] >> 6; variant != 2 {
		t.Fatalf("tenant ID %q variant=%02b, want RFC 4122 10", value, variant)
	}
}
