package store

import (
	"database/sql"
	"os"

	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if _, err := db.Exec("pragma busy_timeout = 5000"); err != nil {
		db.Close()
		return nil, err
	}
	if err := migrateLegacySecureSchema(db, path); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.Exec("pragma foreign_keys = on"); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.Exec(SchemaSQL); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) DB() *sql.DB {
	return s.db
}

func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

const legacySecureSchemaBackupSuffix = ".pre-secure-pairing.bak"

func migrateLegacySecureSchema(db *sql.DB, path string) error {
	legacy, err := hasLegacySecureSchema(db)
	if err != nil || !legacy {
		return err
	}
	if err := backupLegacySecureSchema(db, path); err != nil {
		return err
	}
	if _, err := db.Exec("pragma foreign_keys = off"); err != nil {
		return err
	}
	transaction, err := db.Begin()
	if err != nil {
		return err
	}
	defer transaction.Rollback()

	// Legacy pairing and device rows use the retired token-based trust model.
	// Keep tenants so their access secrets remain valid, then re-enroll hosts.
	if _, err := transaction.Exec(`
drop table if exists pairing_claims;
drop table if exists auth_tickets;
drop table if exists auth_challenges;
drop table if exists pairing_invites;
drop table if exists devices;
drop table if exists hosts;
`); err != nil {
		return err
	}
	if _, err := transaction.Exec(SchemaSQL); err != nil {
		return err
	}
	return transaction.Commit()
}

func backupLegacySecureSchema(db *sql.DB, path string) error {
	backupPath := path + legacySecureSchemaBackupSuffix
	if _, err := os.Stat(backupPath); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	_, err := db.Exec("vacuum into ?", backupPath)
	return err
}

func hasLegacySecureSchema(db *sql.DB) (bool, error) {
	checks := []struct {
		table  string
		column string
	}{
		{"hosts", "host_public_key"},
		{"devices", "device_public_key"},
		{"pairing_invites", "token_hash"},
		{"pairing_invites", "max_uses"},
	}
	for _, check := range checks {
		found, err := tableHasColumn(db, check.table, check.column)
		if err != nil {
			return false, err
		}
		if found {
			return true, nil
		}
	}
	return false, nil
}

func tableHasColumn(db *sql.DB, table string, column string) (bool, error) {
	rows, err := db.Query("pragma table_info(" + table + ")")
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var columnID int
		var name string
		var columnType string
		var notNull int
		var defaultValue interface{}
		var primaryKey int
		if err := rows.Scan(
			&columnID, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			return false, err
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}
