package store

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenAppliesSecurePairingSchema(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "relay-state.db"))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer st.Close()

	expectedTables := []string{
		"tenants",
		"hosts",
		"devices",
		"pairing_invites",
		"pairing_claims",
		"auth_challenges",
		"auth_tickets",
		"audit_events",
	}
	for _, table := range expectedTables {
		var count int
		if err := st.DB().QueryRow(
			"select count(*) from sqlite_master where type = 'table' and name = ?",
			table).Scan(&count); err != nil {
			t.Fatalf("query table %s: %v", table, err)
		}
		if count != 1 {
			t.Fatalf("table %s count = %d, want 1", table, count)
		}
	}
}

func TestSchemaHasNoDeviceTokenHashOrInviteSecret(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "relay-state.db"))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer st.Close()

	for table, forbidden := range map[string][]string{
		"devices":         {"device_token_hash", "device_public_key"},
		"pairing_invites": {"invite_secret", "token_hash", "max_uses"},
	} {
		rows, err := st.DB().Query("pragma table_info(" + table + ")")
		if err != nil {
			t.Fatalf("query %s columns: %v", table, err)
		}
		var names []string
		for rows.Next() {
			var columnID int
			var name string
			var columnType string
			var notNull int
			var defaultValue interface{}
			var primaryKey int
			if err := rows.Scan(
				&columnID, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
				rows.Close()
				t.Fatalf("scan %s columns: %v", table, err)
			}
			names = append(names, name)
		}
		rows.Close()
		joined := strings.Join(names, ",")
		for _, column := range forbidden {
			if strings.Contains(joined, column) {
				t.Fatalf("%s contains forbidden column %s: %s", table, column, joined)
			}
		}
	}
	if strings.Contains(strings.ToLower(SchemaSQL), "invite_secret") {
		t.Fatal("schema contains invite_secret")
	}
}

func TestOpenEnablesForeignKeys(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "relay-state.db"))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer st.Close()
	var enabled int
	if err := st.DB().QueryRow("pragma foreign_keys").Scan(&enabled); err != nil {
		t.Fatalf("query foreign_keys: %v", err)
	}
	if enabled != 1 {
		t.Fatalf("foreign_keys = %d, want 1", enabled)
	}
}
