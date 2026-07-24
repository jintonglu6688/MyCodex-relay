package pairing

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/mycodex/mycodex-relay/internal/protocol"
	"github.com/mycodex/mycodex-relay/internal/store"
)

const (
	ClaimPending   ClaimStatus = "pending"
	ClaimApproved  ClaimStatus = "approved"
	ClaimRejected  ClaimStatus = "rejected"
	ClaimExpired   ClaimStatus = "expired"
	ClaimCancelled ClaimStatus = "cancelled"
	ClaimConsumed  ClaimStatus = "consumed"

	claimAccessTokenBytes    = 32
	claimNonceBytes          = 12
	clientNonceBytes         = 32
	maxInviteLifetime        = 10 * time.Minute
	maxIdentifierBytes       = 128
	maxOpaqueHeaderBytes     = 8 * 1024
	maxOpaqueCiphertextBytes = 256 * 1024
)

type ClaimStatus string

type Invite struct {
	TenantID  string      `json:"tenantId"`
	HostID    string      `json:"hostId"`
	InviteID  string      `json:"inviteId"`
	Status    ClaimStatus `json:"status"`
	ExpiresAt int64       `json:"expiresAt"`
}

type PairingClaimHeader struct {
	InviteID                 string `json:"inviteId"`
	TenantID                 string `json:"tenantId"`
	HostID                   string `json:"hostId"`
	ClaimID                  string `json:"claimId"`
	DeviceID                 string `json:"deviceId"`
	DeviceAgreementPublicKey string `json:"deviceAgreementPublicKey"`
	DeviceKeyVersion         int64  `json:"deviceKeyVersion"`
	ClientNonce              string `json:"clientNonce"`
	CiphertextLength         int64  `json:"ciphertextLength"`
}

type SubmitClaimRequest struct {
	Header     PairingClaimHeader `json:"header"`
	Nonce      string             `json:"nonce"`
	Ciphertext string             `json:"ciphertext"`
}

type CreatedClaim struct {
	ClaimID          string      `json:"claimId"`
	ClaimAccessToken string      `json:"claimAccessToken"`
	Status           ClaimStatus `json:"status"`
	ExpiresAt        int64       `json:"expiresAt"`
}

type OpaqueClaim struct {
	Header     PairingClaimHeader `json:"header"`
	Nonce      string             `json:"nonce"`
	Ciphertext string             `json:"ciphertext"`
	Status     ClaimStatus        `json:"status"`
	CreatedAt  int64              `json:"createdAt"`
	ExpiresAt  int64              `json:"expiresAt"`
}

type ClaimStatusView struct {
	ClaimID            string      `json:"claimId"`
	Status             ClaimStatus `json:"status"`
	UpdatedAt          int64       `json:"updatedAt"`
	ApprovalHeader     string      `json:"approvalHeader"`
	ApprovalNonce      string      `json:"approvalNonce"`
	ApprovalCiphertext string      `json:"approvalCiphertext"`
}

type ApproveClaimRequest struct {
	TenantID                 string `json:"-"`
	HostID                   string `json:"-"`
	ClaimID                  string `json:"-"`
	DeviceSigningPublicKey   string `json:"deviceSigningPublicKey"`
	DeviceAgreementPublicKey string `json:"deviceAgreementPublicKey"`
	DeviceKeyVersion         int64  `json:"deviceKeyVersion"`
	BindingVersion           int64  `json:"bindingVersion"`
	ApprovalHeader           string `json:"approvalHeader"`
	ApprovalNonce            string `json:"approvalNonce"`
	ApprovalCiphertext       string `json:"approvalCiphertext"`
}

type Device struct {
	TenantID           string
	HostID             string
	DeviceID           string
	SigningPublicKey   string
	AgreementPublicKey string
	KeyVersion         int64
	BindingVersion     int64
	Revoked            bool
	ApprovedAt         time.Time
	LastSeenAt         *time.Time
}

type Service struct {
	store *store.Store
}

func NewService(st *store.Store) *Service {
	return &Service{store: st}
}

func (s *Service) CreateInvite(
	tenantID string,
	hostID string,
	inviteID string,
	expiresAt time.Time,
) error {
	tenantID = strings.TrimSpace(tenantID)
	hostID = strings.TrimSpace(hostID)
	inviteID = strings.TrimSpace(inviteID)
	now := time.Now().UTC()
	expiresAt = expiresAt.UTC()
	if !validIdentifier(tenantID) ||
		!validIdentifier(hostID) ||
		!validIdentifier(inviteID) ||
		expiresAt.UnixMilli() <= now.UnixMilli() ||
		expiresAt.Sub(now) > maxInviteLifetime {
		return codeError("invalid_invite")
	}
	var active int
	if err := s.store.DB().QueryRow(
		`select count(*)
from hosts h join tenants t on t.tenant_id = h.tenant_id
where h.tenant_id = ? and h.host_id = ?
  and h.enabled = 1 and h.revoked = 0 and t.enabled = 1`,
		tenantID, hostID).Scan(&active); err != nil {
		return codeError("internal_error")
	}
	if active != 1 {
		return codeError("host_not_found")
	}
	if _, err := s.store.DB().Exec(
		`insert into pairing_invites
(tenant_id, host_id, invite_id, status, created_at, expires_at, consumed_at)
values (?, ?, ?, ?, ?, ?, null)`,
		tenantID,
		hostID,
		inviteID,
		ClaimPending,
		now.UnixMilli(),
		expiresAt.UnixMilli()); err != nil {
		if s.inviteExists(tenantID, hostID, inviteID) {
			return codeError("invite_exists")
		}
		return codeError("internal_error")
	}
	return nil
}

func (s *Service) SubmitClaim(request SubmitClaimRequest) (CreatedClaim, error) {
	if err := validateClaimSubmission(request); err != nil {
		return CreatedClaim{}, err
	}
	headerJSON, err := json.Marshal(request.Header)
	if err != nil {
		return CreatedClaim{}, codeError("internal_error")
	}
	if len(headerJSON) > maxOpaqueHeaderBytes {
		return CreatedClaim{}, codeError("invalid_claim")
	}
	rawToken := make([]byte, claimAccessTokenBytes)
	if _, err := rand.Read(rawToken); err != nil {
		return CreatedClaim{}, codeError("internal_error")
	}
	defer clearBytes(rawToken)
	token := base64.RawURLEncoding.EncodeToString(rawToken)
	tokenHash := sha256.Sum256(rawToken)
	now := time.Now().UTC().UnixMilli()

	transaction, err := s.store.DB().BeginTx(context.Background(), nil)
	if err != nil {
		return CreatedClaim{}, codeError("internal_error")
	}
	defer transaction.Rollback()
	if err := expirePending(transaction, now); err != nil {
		return CreatedClaim{}, err
	}
	var inviteStatus string
	var expiresAt int64
	if err := transaction.QueryRow(
		`select i.status, i.expires_at
from pairing_invites i
join hosts h on h.tenant_id = i.tenant_id and h.host_id = i.host_id
join tenants t on t.tenant_id = i.tenant_id
where i.tenant_id = ? and i.host_id = ? and i.invite_id = ?
  and h.enabled = 1 and h.revoked = 0 and t.enabled = 1`,
		request.Header.TenantID,
		request.Header.HostID,
		request.Header.InviteID).Scan(&inviteStatus, &expiresAt); err != nil {
		if err == sql.ErrNoRows {
			return CreatedClaim{}, codeError("invite_not_found")
		}
		return CreatedClaim{}, codeError("internal_error")
	}
	if ClaimStatus(inviteStatus) != ClaimPending {
		return CreatedClaim{}, codeError("invite_not_pending")
	}
	var existing int
	if err := transaction.QueryRow(
		"select count(*) from pairing_claims where claim_id = ?",
		request.Header.ClaimID).Scan(&existing); err != nil {
		return CreatedClaim{}, codeError("internal_error")
	}
	if existing != 0 {
		return CreatedClaim{}, codeError("claim_exists")
	}
	if _, err := transaction.Exec(
		`insert into pairing_claims
(claim_id, invite_id, tenant_id, host_id, device_id, header_json,
 nonce, ciphertext, access_token_hash, status, created_at, updated_at,
 expires_at, consumed_at)
values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, null)`,
		request.Header.ClaimID,
		request.Header.InviteID,
		request.Header.TenantID,
		request.Header.HostID,
		request.Header.DeviceID,
		string(headerJSON),
		request.Nonce,
		request.Ciphertext,
		tokenHash[:],
		ClaimPending,
		now,
		now,
		expiresAt); err != nil {
		return CreatedClaim{}, codeError("internal_error")
	}
	if err := transaction.Commit(); err != nil {
		return CreatedClaim{}, codeError("internal_error")
	}
	return CreatedClaim{
		ClaimID:          request.Header.ClaimID,
		ClaimAccessToken: token,
		Status:           ClaimPending,
		ExpiresAt:        expiresAt,
	}, nil
}

func (s *Service) GetClaimWithToken(
	claimID string,
	accessToken string,
) (ClaimStatusView, error) {
	tokenHash, err := hashAccessToken(accessToken)
	if err != nil {
		return ClaimStatusView{}, err
	}
	now := time.Now().UTC().UnixMilli()
	transaction, err := s.store.DB().BeginTx(context.Background(), nil)
	if err != nil {
		return ClaimStatusView{}, codeError("internal_error")
	}
	defer transaction.Rollback()
	if err := expirePending(transaction, now); err != nil {
		return ClaimStatusView{}, err
	}
	var result ClaimStatusView
	var status string
	var approvalHeader sql.NullString
	var approvalNonce sql.NullString
	var approvalCiphertext sql.NullString
	if err := transaction.QueryRow(
		`select claim_id, status, updated_at,
 approval_header, approval_nonce, approval_ciphertext
from pairing_claims
where claim_id = ? and access_token_hash = ?`,
		strings.TrimSpace(claimID), tokenHash).Scan(
		&result.ClaimID,
		&status,
		&result.UpdatedAt,
		&approvalHeader,
		&approvalNonce,
		&approvalCiphertext); err != nil {
		if err == sql.ErrNoRows {
			return ClaimStatusView{}, codeError("unauthorized")
		}
		return ClaimStatusView{}, codeError("internal_error")
	}
	result.Status = ClaimStatus(status)
	result.ApprovalHeader = approvalHeader.String
	result.ApprovalNonce = approvalNonce.String
	result.ApprovalCiphertext = approvalCiphertext.String
	if err := transaction.Commit(); err != nil {
		return ClaimStatusView{}, codeError("internal_error")
	}
	return result, nil
}

func (s *Service) ListPendingClaims(
	tenantID string,
	hostID string,
) ([]OpaqueClaim, error) {
	now := time.Now().UTC().UnixMilli()
	transaction, err := s.store.DB().BeginTx(context.Background(), nil)
	if err != nil {
		return nil, codeError("internal_error")
	}
	defer transaction.Rollback()
	if err := expirePending(transaction, now); err != nil {
		return nil, err
	}
	rows, err := transaction.Query(
		`select header_json, nonce, ciphertext, status, created_at, expires_at
from pairing_claims
where tenant_id = ? and host_id = ? and status = ?
order by created_at, claim_id`,
		strings.TrimSpace(tenantID),
		strings.TrimSpace(hostID),
		ClaimPending)
	if err != nil {
		return nil, codeError("internal_error")
	}
	var result []OpaqueClaim
	for rows.Next() {
		var item OpaqueClaim
		var headerJSON string
		var status string
		if err := rows.Scan(
			&headerJSON,
			&item.Nonce,
			&item.Ciphertext,
			&status,
			&item.CreatedAt,
			&item.ExpiresAt); err != nil {
			rows.Close()
			return nil, codeError("internal_error")
		}
		if err := json.Unmarshal([]byte(headerJSON), &item.Header); err != nil {
			rows.Close()
			return nil, codeError("internal_error")
		}
		item.Status = ClaimStatus(status)
		result = append(result, item)
	}
	if err := rows.Close(); err != nil {
		return nil, codeError("internal_error")
	}
	if err := transaction.Commit(); err != nil {
		return nil, codeError("internal_error")
	}
	return result, nil
}

func (s *Service) ClaimDeviceID(tenantID string, hostID string, claimID string) (string, error) {
	var deviceID string
	if err := s.store.DB().QueryRow(
		`select device_id from pairing_claims
where tenant_id = ? and host_id = ? and claim_id = ?`,
		strings.TrimSpace(tenantID),
		strings.TrimSpace(hostID),
		strings.TrimSpace(claimID)).Scan(&deviceID); err != nil {
		if err == sql.ErrNoRows {
			return "", codeError("claim_not_found")
		}
		return "", codeError("internal_error")
	}
	return deviceID, nil
}

func (s *Service) ApproveClaim(request ApproveClaimRequest) error {
	if err := validateApproval(request); err != nil {
		return err
	}
	now := time.Now().UTC().UnixMilli()
	transaction, err := s.store.DB().BeginTx(context.Background(), nil)
	if err != nil {
		return codeError("internal_error")
	}
	defer transaction.Rollback()
	if err := expirePending(transaction, now); err != nil {
		return err
	}

	var inviteID string
	var deviceID string
	var headerJSON string
	var status string
	var storedSigning sql.NullString
	var storedAgreement sql.NullString
	var storedKeyVersion sql.NullInt64
	var storedBindingVersion sql.NullInt64
	var storedHeader sql.NullString
	var storedNonce sql.NullString
	var storedCiphertext sql.NullString
	if err := transaction.QueryRow(
		`select invite_id, device_id, header_json, status,
 device_signing_public_key, device_agreement_public_key,
 device_key_version, binding_version,
 approval_header, approval_nonce, approval_ciphertext
from pairing_claims
where tenant_id = ? and host_id = ? and claim_id = ?`,
		strings.TrimSpace(request.TenantID),
		strings.TrimSpace(request.HostID),
		strings.TrimSpace(request.ClaimID)).Scan(
		&inviteID,
		&deviceID,
		&headerJSON,
		&status,
		&storedSigning,
		&storedAgreement,
		&storedKeyVersion,
		&storedBindingVersion,
		&storedHeader,
		&storedNonce,
		&storedCiphertext); err != nil {
		if err == sql.ErrNoRows {
			return codeError("claim_not_found")
		}
		return codeError("internal_error")
	}
	if ClaimStatus(status) == ClaimApproved {
		if approvalMatches(
			request,
			storedSigning,
			storedAgreement,
			storedKeyVersion,
			storedBindingVersion,
			storedHeader,
			storedNonce,
			storedCiphertext) {
			if err := transaction.Commit(); err != nil {
				return codeError("internal_error")
			}
			return nil
		}
		return codeError("approval_conflict")
	}
	if ClaimStatus(status) != ClaimPending {
		return codeError("claim_not_pending")
	}
	var claimHeader PairingClaimHeader
	if err := json.Unmarshal([]byte(headerJSON), &claimHeader); err != nil {
		return codeError("internal_error")
	}
	if claimHeader.DeviceAgreementPublicKey != request.DeviceAgreementPublicKey ||
		claimHeader.DeviceKeyVersion != request.DeviceKeyVersion {
		return codeError("invalid_device_identity")
	}
	var inviteStatus string
	if err := transaction.QueryRow(
		`select status from pairing_invites
where tenant_id = ? and host_id = ? and invite_id = ?`,
		request.TenantID, request.HostID, inviteID).Scan(&inviteStatus); err != nil {
		return codeError("internal_error")
	}
	if ClaimStatus(inviteStatus) != ClaimPending {
		return codeError("invite_not_pending")
	}
	approvedAt := time.UnixMilli(now).UTC().Format(time.RFC3339Nano)
	deviceResult, err := transaction.Exec(
		`insert into devices
(tenant_id, host_id, device_id, signing_public_key, agreement_public_key,
 key_version, binding_version, revoked, approved_at, last_seen_at)
values (?, ?, ?, ?, ?, ?, ?, 0, ?, null)
on conflict(tenant_id, host_id, device_id) do update set
  binding_version = excluded.binding_version,
  revoked = 0,
  approved_at = excluded.approved_at
where devices.signing_public_key = excluded.signing_public_key
  and devices.agreement_public_key = excluded.agreement_public_key
  and devices.key_version = excluded.key_version
  and devices.binding_version < excluded.binding_version`,
		request.TenantID,
		request.HostID,
		deviceID,
		request.DeviceSigningPublicKey,
		request.DeviceAgreementPublicKey,
		request.DeviceKeyVersion,
		request.BindingVersion,
		approvedAt)
	if err != nil {
		return codeError("internal_error")
	}
	deviceAffected, err := deviceResult.RowsAffected()
	if err != nil {
		return codeError("internal_error")
	}
	if deviceAffected != 1 {
		return codeError("device_binding_conflict")
	}
	result, err := transaction.Exec(
		`update pairing_claims set
 status = ?, device_signing_public_key = ?, device_agreement_public_key = ?,
 device_key_version = ?, binding_version = ?,
 approval_header = ?, approval_nonce = ?, approval_ciphertext = ?,
 updated_at = ?
where tenant_id = ? and host_id = ? and claim_id = ? and status = ?`,
		ClaimApproved,
		request.DeviceSigningPublicKey,
		request.DeviceAgreementPublicKey,
		request.DeviceKeyVersion,
		request.BindingVersion,
		request.ApprovalHeader,
		request.ApprovalNonce,
		request.ApprovalCiphertext,
		now,
		request.TenantID,
		request.HostID,
		request.ClaimID,
		ClaimPending)
	if err != nil {
		return codeError("internal_error")
	}
	affected, err := result.RowsAffected()
	if err != nil || affected != 1 {
		return codeError("claim_not_pending")
	}
	if _, err := transaction.Exec(
		`update pairing_claims set status = ?, updated_at = ?, consumed_at = ?
where tenant_id = ? and host_id = ? and invite_id = ?
  and claim_id <> ? and status = ?`,
		ClaimConsumed,
		now,
		now,
		request.TenantID,
		request.HostID,
		inviteID,
		request.ClaimID,
		ClaimPending); err != nil {
		return codeError("internal_error")
	}
	inviteResult, err := transaction.Exec(
		`update pairing_invites set status = ?, consumed_at = ?
where tenant_id = ? and host_id = ? and invite_id = ? and status = ?`,
		ClaimConsumed,
		now,
		request.TenantID,
		request.HostID,
		inviteID,
		ClaimPending)
	if err != nil {
		return codeError("internal_error")
	}
	inviteAffected, err := inviteResult.RowsAffected()
	if err != nil || inviteAffected != 1 {
		return codeError("invite_not_pending")
	}
	if err := transaction.Commit(); err != nil {
		return codeError("internal_error")
	}
	return nil
}

func (s *Service) RejectClaim(tenantID string, hostID string, claimID string) error {
	now := time.Now().UTC().UnixMilli()
	transaction, err := s.store.DB().BeginTx(context.Background(), nil)
	if err != nil {
		return codeError("internal_error")
	}
	defer transaction.Rollback()
	if err := expirePending(transaction, now); err != nil {
		return err
	}
	result, err := transaction.Exec(
		`update pairing_claims set status = ?, updated_at = ?
where tenant_id = ? and host_id = ? and claim_id = ? and status = ?`,
		ClaimRejected,
		now,
		strings.TrimSpace(tenantID),
		strings.TrimSpace(hostID),
		strings.TrimSpace(claimID),
		ClaimPending)
	if err != nil {
		return codeError("internal_error")
	}
	affected, err := result.RowsAffected()
	if err != nil || affected != 1 {
		return codeError("claim_not_pending")
	}
	if err := transaction.Commit(); err != nil {
		return codeError("internal_error")
	}
	return nil
}

func (s *Service) CancelClaim(claimID string, accessToken string) error {
	tokenHash, err := hashAccessToken(accessToken)
	if err != nil {
		return err
	}
	now := time.Now().UTC().UnixMilli()
	transaction, err := s.store.DB().BeginTx(context.Background(), nil)
	if err != nil {
		return codeError("internal_error")
	}
	defer transaction.Rollback()
	if err := expirePending(transaction, now); err != nil {
		return err
	}
	var status string
	if err := transaction.QueryRow(
		`select status from pairing_claims
where claim_id = ? and access_token_hash = ?`,
		strings.TrimSpace(claimID),
		tokenHash).Scan(&status); err != nil {
		if err == sql.ErrNoRows {
			return codeError("unauthorized")
		}
		return codeError("internal_error")
	}
	if ClaimStatus(status) != ClaimPending {
		return codeError("claim_not_pending")
	}
	result, err := transaction.Exec(
		`update pairing_claims set status = ?, updated_at = ?
where claim_id = ? and access_token_hash = ? and status = ?`,
		ClaimCancelled,
		now,
		strings.TrimSpace(claimID),
		tokenHash,
		ClaimPending)
	if err != nil {
		return codeError("internal_error")
	}
	affected, err := result.RowsAffected()
	if err != nil || affected != 1 {
		return codeError("claim_not_pending")
	}
	if err := transaction.Commit(); err != nil {
		return codeError("internal_error")
	}
	return nil
}

func (s *Service) CancelInvite(tenantID string, hostID string, inviteID string) error {
	now := time.Now().UTC().UnixMilli()
	transaction, err := s.store.DB().BeginTx(context.Background(), nil)
	if err != nil {
		return codeError("internal_error")
	}
	defer transaction.Rollback()
	if err := expirePending(transaction, now); err != nil {
		return err
	}
	result, err := transaction.Exec(
		`update pairing_invites set status = ?, consumed_at = ?
where tenant_id = ? and host_id = ? and invite_id = ? and status = ?`,
		ClaimCancelled,
		now,
		strings.TrimSpace(tenantID),
		strings.TrimSpace(hostID),
		strings.TrimSpace(inviteID),
		ClaimPending)
	if err != nil {
		return codeError("internal_error")
	}
	affected, err := result.RowsAffected()
	if err != nil || affected != 1 {
		return codeError("invite_not_pending")
	}
	if _, err := transaction.Exec(
		`update pairing_claims set status = ?, updated_at = ?
where tenant_id = ? and host_id = ? and invite_id = ? and status = ?`,
		ClaimCancelled,
		now,
		tenantID,
		hostID,
		inviteID,
		ClaimPending); err != nil {
		return codeError("internal_error")
	}
	if err := transaction.Commit(); err != nil {
		return codeError("internal_error")
	}
	return nil
}

func (s *Service) GetDevice(tenantID string, hostID string, deviceID string) (Device, error) {
	row := s.store.DB().QueryRow(
		`select tenant_id, host_id, device_id, signing_public_key,
agreement_public_key, key_version, binding_version, revoked,
approved_at, last_seen_at
from devices where tenant_id = ? and host_id = ? and device_id = ?`,
		tenantID, hostID, deviceID)
	device, err := scanDevice(row)
	if err != nil {
		return Device{}, err
	}
	if device.Revoked {
		return Device{}, codeError("device_revoked")
	}
	return device, nil
}

func (s *Service) ListDevices(tenantID string, hostID string) ([]Device, error) {
	rows, err := s.store.DB().Query(
		`select tenant_id, host_id, device_id, signing_public_key,
agreement_public_key, key_version, binding_version, revoked,
approved_at, last_seen_at
from devices
where tenant_id = ? and host_id = ? and revoked = 0
order by approved_at, device_id`,
		tenantID, hostID)
	if err != nil {
		return nil, codeError("internal_error")
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
	if err := rows.Err(); err != nil {
		return nil, codeError("internal_error")
	}
	return devices, nil
}

func (s *Service) RevokeDevice(tenantID string, hostID string, deviceID string) error {
	result, err := s.store.DB().Exec(
		`update devices set revoked = 1
where tenant_id = ? and host_id = ? and device_id = ? and revoked = 0`,
		tenantID, hostID, deviceID)
	if err != nil {
		return codeError("internal_error")
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return codeError("internal_error")
	}
	if affected != 1 {
		return codeError("device_not_found")
	}
	return nil
}

func validateClaimSubmission(request SubmitClaimRequest) error {
	header := request.Header
	if !validIdentifier(header.InviteID) ||
		!validIdentifier(header.TenantID) ||
		!validIdentifier(header.HostID) ||
		!validIdentifier(header.ClaimID) ||
		!validIdentifier(header.DeviceID) {
		return codeError("invalid_claim")
	}
	if header.DeviceKeyVersion <= 0 || !validStrictSEC1(header.DeviceAgreementPublicKey) {
		return codeError("invalid_device_identity")
	}
	if _, err := decodeExact(header.ClientNonce, clientNonceBytes); err != nil {
		return codeError("invalid_claim")
	}
	if _, err := decodeExact(request.Nonce, claimNonceBytes); err != nil {
		return codeError("invalid_claim")
	}
	ciphertext, err := decodeStrict(request.Ciphertext)
	if err != nil ||
		len(ciphertext) < 16 ||
		len(ciphertext) > maxOpaqueCiphertextBytes ||
		int64(len(ciphertext)) != header.CiphertextLength {
		return codeError("invalid_claim")
	}
	return nil
}

func validateApproval(request ApproveClaimRequest) error {
	if !validIdentifier(request.TenantID) ||
		!validIdentifier(request.HostID) ||
		!validIdentifier(request.ClaimID) ||
		request.DeviceKeyVersion <= 0 ||
		request.BindingVersion <= 0 ||
		request.DeviceSigningPublicKey == request.DeviceAgreementPublicKey ||
		!validStrictSEC1(request.DeviceSigningPublicKey) ||
		!validStrictSEC1(request.DeviceAgreementPublicKey) {
		return codeError("invalid_device_identity")
	}
	header, err := decodeStrict(request.ApprovalHeader)
	if err != nil || len(header) == 0 || len(header) > maxOpaqueHeaderBytes {
		return codeError("invalid_approval")
	}
	if _, err := decodeExact(request.ApprovalNonce, claimNonceBytes); err != nil {
		return codeError("invalid_approval")
	}
	ciphertext, err := decodeStrict(request.ApprovalCiphertext)
	if err != nil || len(ciphertext) < 16 || len(ciphertext) > maxOpaqueCiphertextBytes {
		return codeError("invalid_approval")
	}
	return nil
}

func expirePending(transaction *sql.Tx, now int64) error {
	if _, err := transaction.Exec(
		`update pairing_claims set status = ?, updated_at = ?
where status = ? and expires_at <= ?`,
		ClaimExpired, now, ClaimPending, now); err != nil {
		return codeError("internal_error")
	}
	if _, err := transaction.Exec(
		`update pairing_invites set status = ?, consumed_at = ?
where status = ? and expires_at <= ?`,
		ClaimExpired, now, ClaimPending, now); err != nil {
		return codeError("internal_error")
	}
	return nil
}

func approvalMatches(
	request ApproveClaimRequest,
	signing sql.NullString,
	agreement sql.NullString,
	keyVersion sql.NullInt64,
	bindingVersion sql.NullInt64,
	header sql.NullString,
	nonce sql.NullString,
	ciphertext sql.NullString,
) bool {
	return signing.Valid &&
		agreement.Valid &&
		keyVersion.Valid &&
		bindingVersion.Valid &&
		header.Valid &&
		nonce.Valid &&
		ciphertext.Valid &&
		secureEqual(signing.String, request.DeviceSigningPublicKey) &&
		secureEqual(agreement.String, request.DeviceAgreementPublicKey) &&
		keyVersion.Int64 == request.DeviceKeyVersion &&
		bindingVersion.Int64 == request.BindingVersion &&
		secureEqual(header.String, request.ApprovalHeader) &&
		secureEqual(nonce.String, request.ApprovalNonce) &&
		secureEqual(ciphertext.String, request.ApprovalCiphertext)
}

func secureEqual(left string, right string) bool {
	leftHash := sha256.Sum256([]byte(left))
	rightHash := sha256.Sum256([]byte(right))
	return subtle.ConstantTimeCompare(leftHash[:], rightHash[:]) == 1
}

func (s *Service) inviteExists(tenantID string, hostID string, inviteID string) bool {
	var count int
	return s.store.DB().QueryRow(
		`select count(*) from pairing_invites
where tenant_id = ? and host_id = ? and invite_id = ?`,
		tenantID, hostID, inviteID).Scan(&count) == nil && count != 0
}

func hashAccessToken(value string) ([]byte, error) {
	raw, err := decodeExact(value, claimAccessTokenBytes)
	if err != nil {
		return nil, codeError("unauthorized")
	}
	defer clearBytes(raw)
	digest := sha256.Sum256(raw)
	return digest[:], nil
}

func validStrictSEC1(value string) bool {
	decoded, err := decodeExact(value, 65)
	if err != nil || decoded[0] != 0x04 {
		return false
	}
	_, err = protocol.DecodeSEC1PublicKey(value)
	return err == nil
}

func decodeExact(value string, length int) ([]byte, error) {
	decoded, err := decodeStrict(value)
	if err != nil || len(decoded) != length {
		return nil, fmt.Errorf("invalid Base64Url")
	}
	return decoded, nil
}

func decodeStrict(value string) ([]byte, error) {
	if value == "" || value != strings.TrimSpace(value) {
		return nil, fmt.Errorf("invalid Base64Url")
	}
	return base64.RawURLEncoding.Strict().DecodeString(value)
}

func validIdentifier(value string) bool {
	return value != "" &&
		len(value) <= maxIdentifierBytes &&
		value == strings.TrimSpace(value) &&
		strings.IndexFunc(value, unicode.IsSpace) < 0
}

func clearBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func codeError(code string) error {
	return fmt.Errorf("%s", code)
}

type deviceScanner interface {
	Scan(dest ...interface{}) error
}

func scanDevice(scanner deviceScanner) (Device, error) {
	var device Device
	var revoked int
	var approvedAt string
	var lastSeen sql.NullString
	if err := scanner.Scan(
		&device.TenantID,
		&device.HostID,
		&device.DeviceID,
		&device.SigningPublicKey,
		&device.AgreementPublicKey,
		&device.KeyVersion,
		&device.BindingVersion,
		&revoked,
		&approvedAt,
		&lastSeen); err != nil {
		if err == sql.ErrNoRows {
			return Device{}, codeError("device_not_found")
		}
		return Device{}, codeError("internal_error")
	}
	device.Revoked = revoked != 0
	device.ApprovedAt, _ = time.Parse(time.RFC3339Nano, approvedAt)
	if lastSeen.Valid {
		parsed, _ := time.Parse(time.RFC3339Nano, lastSeen.String)
		device.LastSeenAt = &parsed
	}
	return device, nil
}
