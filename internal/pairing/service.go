package pairing

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/mycodex/mycodex-relay/internal/security"
	"github.com/mycodex/mycodex-relay/internal/store"
)

type Invite struct {
	TenantID  string
	HostID    string
	InviteID  string
	ExpiresAt time.Time
}

type ClaimRequest struct {
	TenantID          string
	HostID            string
	InviteID          string
	Token             string
	DeviceID          string
	DeviceDisplayName string
	DevicePublicKey   string
	Platform          string
}

type Claim struct {
	TenantID          string
	HostID            string
	InviteID          string
	DeviceID          string
	DeviceDisplayName string
	DevicePublicKey   string
	Platform          string
}

type Device struct {
	TenantID        string
	HostID          string
	DeviceID        string
	DisplayName     string
	Platform        string
	DevicePublicKey string
	Revoked         bool
	BoundAt         time.Time
	LastSeenAt      *time.Time
}

type Service struct {
	store *store.Store
}

func NewService(store *store.Store) *Service {
	return &Service{store: store}
}

func (s *Service) CreateInvite(tenantID string, hostID string, expiresAt time.Time) (Invite, string, error) {
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(hostID) == "" {
		return Invite{}, "", fmt.Errorf("tenantId and hostId are required")
	}
	inviteID, err := security.GenerateToken(18)
	if err != nil {
		return Invite{}, "", err
	}
	token, err := security.GenerateToken(32)
	if err != nil {
		return Invite{}, "", err
	}
	hash, err := security.HashSecret(token)
	if err != nil {
		return Invite{}, "", err
	}
	_, err = s.store.DB().Exec(
		"insert into pairing_invites (tenant_id, host_id, invite_id, token_hash, expires_at, consumed_at, max_uses) values (?, ?, ?, ?, ?, null, 1)",
		tenantID, hostID, inviteID, hash, expiresAt.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return Invite{}, "", err
	}
	return Invite{TenantID: tenantID, HostID: hostID, InviteID: inviteID, ExpiresAt: expiresAt.UTC()}, token, nil
}

func (s *Service) ClaimInvite(request ClaimRequest) (Claim, error) {
	row := s.store.DB().QueryRow(
		"select token_hash, expires_at, consumed_at from pairing_invites where tenant_id = ? and host_id = ? and invite_id = ?",
		request.TenantID, request.HostID, request.InviteID)
	var tokenHash string
	var expiresAtText string
	var consumedAt sql.NullString
	if err := row.Scan(&tokenHash, &expiresAtText, &consumedAt); err != nil {
		if err == sql.ErrNoRows {
			return Claim{}, fmt.Errorf("invite_not_found")
		}
		return Claim{}, err
	}
	if consumedAt.Valid {
		return Claim{}, fmt.Errorf("invite_consumed")
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, expiresAtText)
	if err != nil {
		return Claim{}, err
	}
	if time.Now().UTC().After(expiresAt) {
		return Claim{}, fmt.Errorf("invite_expired")
	}
	if !security.VerifySecret(tokenHash, request.Token) {
		return Claim{}, fmt.Errorf("auth_failed")
	}
	result, err := s.store.DB().Exec(
		"update pairing_invites set consumed_at = ? where tenant_id = ? and host_id = ? and invite_id = ? and consumed_at is null",
		time.Now().UTC().Format(time.RFC3339Nano), request.TenantID, request.HostID, request.InviteID)
	if err != nil {
		return Claim{}, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return Claim{}, err
	}
	if rows == 0 {
		return Claim{}, fmt.Errorf("invite_consumed")
	}
	return Claim{
		TenantID:          request.TenantID,
		HostID:            request.HostID,
		InviteID:          request.InviteID,
		DeviceID:          request.DeviceID,
		DeviceDisplayName: request.DeviceDisplayName,
		DevicePublicKey:   request.DevicePublicKey,
		Platform:          request.Platform,
	}, nil
}

func (s *Service) ApproveClaim(claim Claim) error {
	if strings.TrimSpace(claim.TenantID) == "" || strings.TrimSpace(claim.HostID) == "" || strings.TrimSpace(claim.DeviceID) == "" {
		return fmt.Errorf("tenantId, hostId, and deviceId are required")
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.store.DB().Exec(
		`insert into devices (tenant_id, host_id, device_id, display_name, platform, device_public_key, revoked, bound_at, last_seen_at)
values (?, ?, ?, ?, ?, ?, 0, ?, null)
on conflict(tenant_id, host_id, device_id) do update set
  display_name = excluded.display_name,
  platform = excluded.platform,
  device_public_key = excluded.device_public_key,
  revoked = 0`,
		claim.TenantID, claim.HostID, claim.DeviceID, claim.DeviceDisplayName, claim.Platform, claim.DevicePublicKey, now)
	return err
}

func (s *Service) GetDevice(tenantID string, hostID string, deviceID string) (Device, error) {
	row := s.store.DB().QueryRow(
		"select tenant_id, host_id, device_id, display_name, platform, device_public_key, revoked, bound_at, last_seen_at from devices where tenant_id = ? and host_id = ? and device_id = ?",
		tenantID, hostID, deviceID)
	device, err := scanDevice(row)
	if err != nil {
		return Device{}, err
	}
	if device.Revoked {
		return Device{}, fmt.Errorf("device_revoked")
	}
	return device, nil
}

func (s *Service) ListDevices(tenantID string, hostID string) ([]Device, error) {
	rows, err := s.store.DB().Query(
		"select tenant_id, host_id, device_id, display_name, platform, device_public_key, revoked, bound_at, last_seen_at from devices where tenant_id = ? and host_id = ? and revoked = 0 order by bound_at, device_id",
		tenantID, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var devices []Device
	for rows.Next() {
		device, err := scanDevice(rows)
		if err != nil {
			return nil, err
		}
		devices = append(devices, device)
	}
	return devices, rows.Err()
}

func (s *Service) RevokeDevice(tenantID string, hostID string, deviceID string) error {
	result, err := s.store.DB().Exec(
		"update devices set revoked = 1 where tenant_id = ? and host_id = ? and device_id = ?",
		tenantID, hostID, deviceID)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("device_not_found")
	}
	return nil
}

type deviceScanner interface {
	Scan(dest ...interface{}) error
}

func scanDevice(scanner deviceScanner) (Device, error) {
	var device Device
	var revoked int
	var boundAt string
	var lastSeen sql.NullString
	if err := scanner.Scan(&device.TenantID, &device.HostID, &device.DeviceID, &device.DisplayName, &device.Platform, &device.DevicePublicKey, &revoked, &boundAt, &lastSeen); err != nil {
		if err == sql.ErrNoRows {
			return Device{}, fmt.Errorf("device_not_found")
		}
		return Device{}, err
	}
	device.Revoked = revoked != 0
	device.BoundAt, _ = time.Parse(time.RFC3339Nano, boundAt)
	if lastSeen.Valid {
		parsed, _ := time.Parse(time.RFC3339Nano, lastSeen.String)
		device.LastSeenAt = &parsed
	}
	return device, nil
}
