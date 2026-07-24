package host

import (
	"database/sql"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/mycodex/mycodex-relay/internal/protocol"
	"github.com/mycodex/mycodex-relay/internal/store"
)

type Host struct {
	TenantID           string
	HostID             string
	DisplayName        string
	HostPublicKey      string
	SigningPublicKey   string
	AgreementPublicKey string
	KeyVersion         int64
	Enabled            bool
	Revoked            bool
	RegisteredAt       time.Time
	LastSeenAt         *time.Time
}

type Enrollment struct {
	TenantID           string
	HostID             string
	DisplayName        string
	SigningPublicKey   string
	AgreementPublicKey string
	KeyVersion         int64
}

type Service struct {
	store *store.Store
}

func NewService(store *store.Store) *Service {
	return &Service{store: store}
}

func (s *Service) EnrollHost(request Enrollment) (Host, error) {
	request.TenantID = strings.TrimSpace(request.TenantID)
	request.HostID = strings.TrimSpace(request.HostID)
	request.DisplayName = strings.TrimSpace(request.DisplayName)
	if request.TenantID == "" || request.HostID == "" || request.DisplayName == "" {
		return Host{}, fmt.Errorf("invalid_host_enrollment")
	}
	if request.KeyVersion <= 0 ||
		request.SigningPublicKey == request.AgreementPublicKey ||
		!validStrictSEC1(request.SigningPublicKey) ||
		!validStrictSEC1(request.AgreementPublicKey) {
		return Host{}, fmt.Errorf("invalid_host_identity")
	}
	var tenantEnabled int
	if err := s.store.DB().QueryRow(
		"select enabled from tenants where tenant_id = ?",
		request.TenantID).Scan(&tenantEnabled); err != nil || tenantEnabled == 0 {
		return Host{}, fmt.Errorf("tenant_not_found")
	}

	transaction, err := s.store.DB().Begin()
	if err != nil {
		return Host{}, fmt.Errorf("internal_error")
	}
	defer transaction.Rollback()

	now := time.Now().UTC().Format(time.RFC3339Nano)
	result, err := transaction.Exec(
		`insert into hosts
(tenant_id, host_id, display_name, host_public_key, signing_public_key,
 agreement_public_key, key_version, enabled, revoked, registered_at, last_seen_at)
values (?, ?, ?, ?, ?, ?, ?, 1, 0, ?, ?)
on conflict(tenant_id, host_id) do nothing`,
		request.TenantID, request.HostID, request.DisplayName,
		request.SigningPublicKey, request.SigningPublicKey,
		request.AgreementPublicKey, request.KeyVersion,
		now, now)
	if err != nil {
		return Host{}, fmt.Errorf("internal_error")
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return Host{}, fmt.Errorf("internal_error")
	}
	if inserted == 0 {
		var signingPublicKey string
		var agreementPublicKey string
		var keyVersion int64
		var enabled int
		var revoked int
		if err := transaction.QueryRow(
			`select signing_public_key, agreement_public_key, key_version, enabled, revoked
from hosts where tenant_id = ? and host_id = ?`,
			request.TenantID, request.HostID).Scan(
			&signingPublicKey, &agreementPublicKey, &keyVersion, &enabled, &revoked); err != nil {
			return Host{}, fmt.Errorf("internal_error")
		}
		if signingPublicKey != request.SigningPublicKey ||
			agreementPublicKey != request.AgreementPublicKey ||
			keyVersion != request.KeyVersion ||
			enabled == 0 ||
			revoked != 0 {
			return Host{}, fmt.Errorf("host_identity_conflict_reset_required")
		}
		if _, err := transaction.Exec(
			`update hosts set display_name = ?, last_seen_at = ?
where tenant_id = ? and host_id = ?
  and signing_public_key = ? and agreement_public_key = ?
  and key_version = ? and enabled = 1 and revoked = 0`,
			request.DisplayName, now, request.TenantID, request.HostID,
			request.SigningPublicKey, request.AgreementPublicKey, request.KeyVersion); err != nil {
			return Host{}, fmt.Errorf("internal_error")
		}
	}
	if err := transaction.Commit(); err != nil {
		return Host{}, fmt.Errorf("internal_error")
	}
	return s.GetHost(request.TenantID, request.HostID)
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
		`select tenant_id, host_id, display_name, host_public_key,
signing_public_key, agreement_public_key, key_version, enabled, revoked,
registered_at, last_seen_at
from hosts where tenant_id = ? and host_id = ?`,
		tenantID, hostID)
	var result Host
	var enabled int
	var revoked int
	var registered string
	var lastSeen sql.NullString
	if err := row.Scan(
		&result.TenantID,
		&result.HostID,
		&result.DisplayName,
		&result.HostPublicKey,
		&result.SigningPublicKey,
		&result.AgreementPublicKey,
		&result.KeyVersion,
		&enabled,
		&revoked,
		&registered,
		&lastSeen); err != nil {
		if err == sql.ErrNoRows {
			return Host{}, fmt.Errorf("host_not_found")
		}
		return Host{}, err
	}
	result.Enabled = enabled != 0
	result.Revoked = revoked != 0
	result.RegisteredAt, _ = time.Parse(time.RFC3339Nano, registered)
	if lastSeen.Valid {
		parsed, _ := time.Parse(time.RFC3339Nano, lastSeen.String)
		result.LastSeenAt = &parsed
	}
	return result, nil
}

func validStrictSEC1(value string) bool {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) != 65 {
		return false
	}
	_, err = protocol.DecodeSEC1PublicKey(value)
	return err == nil
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
