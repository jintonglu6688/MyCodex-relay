package store

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func TestOpenAppliesSchema(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "relay-state.db")
	store, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer store.Close()

	rows, err := store.DB().Query("select name from sqlite_master where type = 'table' and name = 'tenants'")
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	defer rows.Close()
	if !rows.Next() {
		t.Fatalf("expected tenants table")
	}
}

func TestOpenMigratesExistingIdentityColumns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "relay-state.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open legacy database: %v", err)
	}
	if _, err := db.Exec(`
create table hosts (
  tenant_id text not null,
  host_id text not null,
  display_name text not null,
  host_public_key text not null,
  enabled integer not null,
  registered_at text not null,
  last_seen_at text,
  primary key (tenant_id, host_id)
);
create table devices (
  tenant_id text not null,
  host_id text not null,
  device_id text not null,
  display_name text not null,
  platform text not null,
  device_public_key text not null,
  revoked integer not null,
  bound_at text not null,
  last_seen_at text,
  primary key (tenant_id, host_id, device_id)
);`); err != nil {
		db.Close()
		t.Fatalf("create legacy schema: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close legacy database: %v", err)
	}

	st, err := Open(path)
	if err != nil {
		t.Fatalf("Open legacy database: %v", err)
	}
	defer st.Close()
	for table, columns := range map[string][]string{
		"hosts":   {"signing_public_key", "agreement_public_key", "key_version", "revoked"},
		"devices": {"signing_public_key", "agreement_public_key", "key_version", "binding_version", "device_token_hash"},
	} {
		existing := make(map[string]bool)
		rows, err := st.DB().Query("pragma table_info(" + table + ")")
		if err != nil {
			t.Fatalf("query %s columns: %v", table, err)
		}
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
			existing[name] = true
		}
		rows.Close()
		for _, column := range columns {
			if !existing[column] {
				t.Fatalf("%s.%s was not migrated", table, column)
			}
		}
	}
}
