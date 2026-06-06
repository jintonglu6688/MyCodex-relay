package host

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/mycodex/mycodex-relay/internal/store"
)

type Host struct {
	TenantID      string
	HostID        string
	DisplayName   string
	HostPublicKey string
	Enabled       bool
	RegisteredAt  time.Time
	LastSeenAt    *time.Time
}

type Service struct {
	store *store.Store
}

func NewService(store *store.Store) *Service {
	return &Service{store: store}
}

func (s *Service) RegisterHost(tenantID string, hostID string, displayName string, hostPublicKey string) error {
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(hostID) == "" {
		return fmt.Errorf("tenantId and hostId are required")
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.store.DB().Exec(
		`insert into hosts (tenant_id, host_id, display_name, host_public_key, enabled, registered_at, last_seen_at)
values (?, ?, ?, ?, 1, ?, ?)
on conflict(tenant_id, host_id) do update set
  display_name = excluded.display_name,
  host_public_key = excluded.host_public_key,
  enabled = 1,
  last_seen_at = excluded.last_seen_at`,
		tenantID, hostID, strings.TrimSpace(displayName), hostPublicKey, now, now)
	return err
}

func (s *Service) GetHost(tenantID string, hostID string) (Host, error) {
	row := s.store.DB().QueryRow(
		"select tenant_id, host_id, display_name, host_public_key, enabled, registered_at, last_seen_at from hosts where tenant_id = ? and host_id = ?",
		tenantID, hostID)
	var result Host
	var enabled int
	var registered string
	var lastSeen sql.NullString
	if err := row.Scan(&result.TenantID, &result.HostID, &result.DisplayName, &result.HostPublicKey, &enabled, &registered, &lastSeen); err != nil {
		if err == sql.ErrNoRows {
			return Host{}, fmt.Errorf("host_not_found")
		}
		return Host{}, err
	}
	result.Enabled = enabled != 0
	result.RegisteredAt, _ = time.Parse(time.RFC3339Nano, registered)
	if lastSeen.Valid {
		parsed, _ := time.Parse(time.RFC3339Nano, lastSeen.String)
		result.LastSeenAt = &parsed
	}
	return result, nil
}

func (s *Service) UpdateLastSeen(tenantID string, hostID string) error {
	result, err := s.store.DB().Exec(
		"update hosts set last_seen_at = ? where tenant_id = ? and host_id = ?",
		time.Now().UTC().Format(time.RFC3339Nano), tenantID, hostID)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("host_not_found")
	}
	return nil
}
