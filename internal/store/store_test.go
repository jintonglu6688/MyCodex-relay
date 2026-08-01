package store

import (
	"database/sql"
	"os"
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

func TestOpenMigratesLegacySecurePairingSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "relay-state.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open legacy database: %v", err)
	}
	if _, err := db.Exec(`
create table tenants (
  tenant_id text primary key, display_name text not null, enabled integer not null,
  secret_hash text not null, created_at text not null
);
create table hosts (
  tenant_id text not null, host_id text not null, display_name text not null,
  host_public_key text not null, signing_public_key text not null default '',
  agreement_public_key text not null default '', key_version integer not null default 0,
  enabled integer not null, revoked integer not null default 0,
  registered_at text not null, last_seen_at text,
  primary key (tenant_id, host_id)
);
create table devices (
  tenant_id text not null, host_id text not null, device_id text not null,
  display_name text not null, platform text not null, device_public_key text not null,
  revoked integer not null, bound_at text not null,
  primary key (tenant_id, host_id, device_id)
);
create table pairing_invites (
  tenant_id text not null, host_id text not null, invite_id text not null,
  token_hash text not null, expires_at text not null, consumed_at text,
  max_uses integer not null, primary key (tenant_id, host_id, invite_id)
);
create table audit_events (
  id integer primary key autoincrement, tenant_id text, event_type text not null,
  message text not null, created_at text not null
);
insert into tenants values ('tenant_a', 'Local', 1, 'preserved_hash', '2026-01-01T00:00:00Z');
insert into hosts values ('tenant_a', 'host_a', 'PC', 'old', '', '', 0, 1, 0, 'now', null);
insert into pairing_invites values ('tenant_a', 'host_a', 'invite_a', 'old', 'later', null, 1);
insert into audit_events (tenant_id, event_type, message, created_at)
values ('tenant_a', 'legacy', 'preserve', '2026-01-01T00:00:00Z');
`); err != nil {
		db.Close()
		t.Fatalf("create legacy database: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close legacy database: %v", err)
	}

	st, err := Open(path)
	if err != nil {
		t.Fatalf("Open legacy database failed: %v", err)
	}

	var secretHash string
	if err := st.DB().QueryRow(
		"select secret_hash from tenants where tenant_id = 'tenant_a'").Scan(&secretHash); err != nil {
		t.Fatalf("query preserved tenant: %v", err)
	}
	if secretHash != "preserved_hash" {
		t.Fatalf("tenant secret hash = %q, want preserved_hash", secretHash)
	}
	backupPath := path + legacySecureSchemaBackupSuffix
	if _, err := os.Stat(backupPath); err != nil {
		t.Fatalf("legacy backup was not created: %v", err)
	}
	backup, err := sql.Open("sqlite", backupPath)
	if err != nil {
		t.Fatalf("open legacy backup: %v", err)
	}
	var legacyHostCount int
	if err := backup.QueryRow("select count(*) from hosts").Scan(&legacyHostCount); err != nil {
		backup.Close()
		t.Fatalf("query legacy backup: %v", err)
	}
	if err := backup.Close(); err != nil {
		t.Fatalf("close legacy backup: %v", err)
	}
	if legacyHostCount != 1 {
		t.Fatalf("legacy backup host count = %d, want 1", legacyHostCount)
	}
	for _, table := range []string{"hosts", "devices", "pairing_invites", "auth_challenges", "auth_tickets"} {
		var count int
		if err := st.DB().QueryRow("select count(*) from " + table).Scan(&count); err != nil {
			t.Fatalf("query migrated %s: %v", table, err)
		}
		if count != 0 {
			t.Fatalf("migrated %s count = %d, want 0", table, count)
		}
	}
	var auditCount int
	if err := st.DB().QueryRow("select count(*) from audit_events").Scan(&auditCount); err != nil || auditCount != 1 {
		t.Fatalf("preserved audit count = %d, err = %v", auditCount, err)
	}
	if _, err := st.DB().Exec(`insert into hosts
(tenant_id, host_id, display_name, signing_public_key, agreement_public_key,
 key_version, enabled, revoked, registered_at, last_seen_at)
values ('tenant_a', 'host_a', 'PC', 'signing', 'agreement', 1, 1, 0, 'now', 'now')`); err != nil {
		t.Fatalf("insert current host after migration: %v", err)
	}
	if _, err := st.DB().Exec(`insert into pairing_invites
(tenant_id, host_id, invite_id, status, created_at, expires_at, consumed_at)
values ('tenant_a', 'host_a', 'invite_a', 'pending', 1, 2, null)`); err != nil {
		t.Fatalf("insert current invite after migration: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("close migrated database: %v", err)
	}
	st, err = Open(path)
	if err != nil {
		t.Fatalf("reopen migrated database: %v", err)
	}
	defer st.Close()
	for _, table := range []string{"hosts", "pairing_invites"} {
		var count int
		if err := st.DB().QueryRow("select count(*) from " + table).Scan(&count); err != nil || count != 1 {
			t.Fatalf("reopened %s count = %d, err = %v", table, count, err)
		}
	}
}
