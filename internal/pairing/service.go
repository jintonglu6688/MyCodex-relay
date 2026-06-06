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
	_, err = s.store.DB().Exec(
		"update pairing_invites set consumed_at = ? where tenant_id = ? and host_id = ? and invite_id = ? and consumed_at is null",
		time.Now().UTC().Format(time.RFC3339Nano), request.TenantID, request.HostID, request.InviteID)
	if err != nil {
		return Claim{}, err
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
