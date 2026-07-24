package store

import (
	"database/sql"
	"strings"

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
	if _, err := db.Exec(SchemaSQL); err != nil {
		db.Close()
		return nil, err
	}
	migrations := []string{
		"alter table hosts add column signing_public_key text not null default ''",
		"alter table hosts add column agreement_public_key text not null default ''",
		"alter table hosts add column key_version integer not null default 0",
		"alter table hosts add column revoked integer not null default 0",
		"alter table devices add column signing_public_key text not null default ''",
		"alter table devices add column agreement_public_key text not null default ''",
		"alter table devices add column key_version integer not null default 0",
		"alter table devices add column binding_version integer not null default 0",
		"alter table devices add column device_token_hash text",
	}
	for _, migration := range migrations {
		if _, err := db.Exec(migration); err != nil && !isDuplicateColumnError(err) {
			db.Close()
			return nil, err
		}
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

func isDuplicateColumnError(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "duplicate column name")
}
