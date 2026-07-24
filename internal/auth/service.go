package auth

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/mycodex/mycodex-relay/internal/protocol"
	"github.com/mycodex/mycodex-relay/internal/security"
	"github.com/mycodex/mycodex-relay/internal/store"
)

const (
	ProtocolVersion = 1

	SubjectHost   = "host"
	SubjectDevice = "device"

	PurposePairingInviteCreate = "pairing_invite_create"
	PurposePairingInviteCancel = "pairing_invite_cancel"
	PurposePairingClaimList    = "pairing_claim_list"
	PurposePairingClaimApprove = "pairing_claim_approve"
	PurposePairingClaimReject  = "pairing_claim_reject"
	PurposeDeviceList          = "device_list"
	PurposeDeviceRevoke        = "device_revoke"
	PurposeWebSocketHost       = "websocket_host"
	PurposeWebSocketDevice     = "websocket_device"

	credentialBytes = 32
	maxLifetime     = 60 * time.Second
)

type TicketScope struct {
	SubjectType string `json:"subjectType"`
	SubjectID   string `json:"subjectId"`
	TenantID    string `json:"tenantId"`
	HostID      string `json:"hostId"`
	DeviceID    string `json:"deviceId"`
	Purpose     string `json:"purpose"`
}

type ChallengeRequest TicketScope

type SignedChallenge struct {
	ProtocolVersion  int    `json:"protocolVersion"`
	RelayFingerprint string `json:"relayFingerprint"`
	ChallengeID      string `json:"challengeId"`
	Challenge        string `json:"challenge"`
	SubjectType      string `json:"subjectType"`
	SubjectID        string `json:"subjectId"`
	TenantID         string `json:"tenantId"`
	HostID           string `json:"hostId"`
	DeviceID         string `json:"deviceId"`
	Purpose          string `json:"purpose"`
	IssuedAt         int64  `json:"issuedAt"`
	ExpiresAt        int64  `json:"expiresAt"`
	RelaySignature   string `json:"relaySignature"`
}

type ProofRequest struct {
	Challenge        SignedChallenge `json:"challenge"`
	SubjectSignature string          `json:"subjectSignature"`
}

type Ticket struct {
	Ticket    string `json:"ticket"`
	Purpose   string `json:"purpose"`
	ExpiresAt int64  `json:"expiresAt"`
}

type Service struct {
	store  *store.Store
	signer *security.RelayIdentitySigner
}

func NewService(st *store.Store, signer *security.RelayIdentitySigner) *Service {
	return &Service{store: st, signer: signer}
}

func (s *Service) CreateChallenge(request ChallengeRequest) (SignedChallenge, error) {
	if s == nil || s.store == nil || s.signer == nil {
		return SignedChallenge{}, codeError("auth_unavailable")
	}
	scope := TicketScope(request)
	if err := validateScope(scope); err != nil {
		return SignedChallenge{}, err
	}
	if _, err := s.subjectSigningKey(scope); err != nil {
		return SignedChallenge{}, err
	}
	challengeID, _, err := randomBase64URL(18)
	if err != nil {
		return SignedChallenge{}, codeError("internal_error")
	}
	challengeText, challengeValue, err := randomBase64URL(credentialBytes)
	if err != nil {
		return SignedChallenge{}, codeError("internal_error")
	}
	defer clearBytes(challengeValue)
	now := time.Now().UTC()
	public := s.signer.Public()
	challenge := SignedChallenge{
		ProtocolVersion:  ProtocolVersion,
		RelayFingerprint: public.FingerprintBase64URL,
		ChallengeID:      challengeID,
		Challenge:        challengeText,
		SubjectType:      scope.SubjectType,
		SubjectID:        scope.SubjectID,
		TenantID:         scope.TenantID,
		HostID:           scope.HostID,
		DeviceID:         scope.DeviceID,
		Purpose:          scope.Purpose,
		IssuedAt:         now.UnixMilli(),
		ExpiresAt:        now.Add(maxLifetime).UnixMilli(),
	}
	transcript, err := challengeTranscript(challenge)
	if err != nil {
		return SignedChallenge{}, err
	}
	challenge.RelaySignature, err = s.signer.Sign(transcript)
	if err != nil {
		return SignedChallenge{}, codeError("internal_error")
	}
	challengeHash := sha256.Sum256(challengeValue)
	if _, err := s.store.DB().Exec(
		`insert into auth_challenges
(challenge_id, challenge_hash, protocol_version, relay_fingerprint,
 relay_signature, subject_type, subject_id, tenant_id, host_id, device_id,
 purpose, issued_at, expires_at, consumed_at)
values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, null)`,
		challenge.ChallengeID,
		challengeHash[:],
		challenge.ProtocolVersion,
		challenge.RelayFingerprint,
		challenge.RelaySignature,
		challenge.SubjectType,
		challenge.SubjectID,
		challenge.TenantID,
		challenge.HostID,
		challenge.DeviceID,
		challenge.Purpose,
		challenge.IssuedAt,
		challenge.ExpiresAt); err != nil {
		return SignedChallenge{}, codeError("internal_error")
	}
	return challenge, nil
}

func (s *Service) Prove(request ProofRequest) (Ticket, error) {
	if s == nil || s.store == nil || s.signer == nil {
		return Ticket{}, codeError("auth_unavailable")
	}
	challenge := request.Challenge
	scope := challenge.scope()
	if challenge.ProtocolVersion != ProtocolVersion ||
		challenge.RelayFingerprint != s.signer.Public().FingerprintBase64URL {
		return Ticket{}, codeError("invalid_challenge")
	}
	if err := validateScope(scope); err != nil {
		return Ticket{}, err
	}
	now := time.Now().UTC().UnixMilli()
	if challenge.IssuedAt > now || challenge.ExpiresAt <= now ||
		challenge.ExpiresAt-challenge.IssuedAt > maxLifetime.Milliseconds() {
		return Ticket{}, codeError("challenge_expired")
	}
	challengeValue, err := decodeExact(challenge.Challenge, credentialBytes)
	if err != nil {
		return Ticket{}, codeError("invalid_challenge")
	}
	defer clearBytes(challengeValue)
	if _, err := decodeExact(challenge.RelaySignature, 64); err != nil {
		return Ticket{}, codeError("invalid_challenge")
	}
	challengeBytes, err := challengeTranscript(challenge)
	if err != nil {
		return Ticket{}, err
	}
	relayKey, err := protocol.DecodeSEC1PublicKey(s.signer.Public().PublicKeyBase64URL)
	if err != nil || !protocol.VerifyRawSignature(relayKey, challengeBytes, challenge.RelaySignature) {
		return Ticket{}, codeError("invalid_challenge")
	}
	if _, err := decodeExact(request.SubjectSignature, 64); err != nil {
		return Ticket{}, codeError("invalid_proof")
	}
	subjectKey, err := s.subjectSigningKey(scope)
	if err != nil {
		return Ticket{}, err
	}
	proofBytes, err := proofTranscript(challenge, challengeBytes)
	if err != nil || !protocol.VerifyRawSignature(subjectKey, proofBytes, request.SubjectSignature) {
		return Ticket{}, codeError("invalid_proof")
	}
	challengeHash := sha256.Sum256(challengeValue)
	if err := s.consumeChallenge(challenge, challengeHash[:], now); err != nil {
		return Ticket{}, err
	}

	ticketText, ticketValue, err := randomBase64URL(credentialBytes)
	if err != nil {
		return Ticket{}, codeError("internal_error")
	}
	defer clearBytes(ticketValue)
	ticketHash := sha256.Sum256(ticketValue)
	expiresAt := now + maxLifetime.Milliseconds()
	if _, err := s.store.DB().Exec(
		`insert into auth_tickets
(ticket_hash, subject_type, subject_id, tenant_id, host_id, device_id,
 purpose, issued_at, expires_at, consumed_at)
values (?, ?, ?, ?, ?, ?, ?, ?, ?, null)`,
		ticketHash[:],
		scope.SubjectType,
		scope.SubjectID,
		scope.TenantID,
		scope.HostID,
		scope.DeviceID,
		scope.Purpose,
		now,
		expiresAt); err != nil {
		return Ticket{}, codeError("internal_error")
	}
	return Ticket{Ticket: ticketText, Purpose: scope.Purpose, ExpiresAt: expiresAt}, nil
}

func (s *Service) ConsumeTicket(rawTicket string, expected TicketScope) error {
	if s == nil || s.store == nil {
		return codeError("auth_unavailable")
	}
	if err := validateScope(expected); err != nil {
		return err
	}
	ticketValue, err := decodeExact(rawTicket, credentialBytes)
	if err != nil {
		return codeError("invalid_ticket")
	}
	defer clearBytes(ticketValue)
	ticketHash := sha256.Sum256(ticketValue)
	now := time.Now().UTC().UnixMilli()
	result, err := s.store.DB().Exec(
		`update auth_tickets set consumed_at = ?
where ticket_hash = ?
  and subject_type = ? and subject_id = ?
  and tenant_id = ? and host_id = ? and device_id = ? and purpose = ?
  and consumed_at is null and expires_at > ?
  and exists (
    select 1 from tenants t
    where t.tenant_id = auth_tickets.tenant_id and t.enabled = 1
  )
  and (
    (subject_type = 'host' and exists (
      select 1 from hosts h
      where h.tenant_id = auth_tickets.tenant_id
        and h.host_id = auth_tickets.subject_id
        and h.enabled = 1 and h.revoked = 0
        and h.signing_public_key <> ''
    ))
    or
    (subject_type = 'device' and exists (
      select 1 from devices d join hosts h
        on h.tenant_id = d.tenant_id and h.host_id = d.host_id
      where d.tenant_id = auth_tickets.tenant_id
        and d.host_id = auth_tickets.host_id
        and d.device_id = auth_tickets.subject_id
        and d.revoked = 0 and d.signing_public_key <> ''
        and h.enabled = 1 and h.revoked = 0
    ))
  )`,
		now,
		ticketHash[:],
		expected.SubjectType,
		expected.SubjectID,
		expected.TenantID,
		expected.HostID,
		expected.DeviceID,
		expected.Purpose,
		now)
	if err != nil {
		return codeError("internal_error")
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return codeError("internal_error")
	}
	if affected != 1 {
		return codeError("invalid_ticket")
	}
	return nil
}

func (s *Service) consumeChallenge(challenge SignedChallenge, challengeHash []byte, now int64) error {
	result, err := s.store.DB().Exec(
		`update auth_challenges set consumed_at = ?
where challenge_id = ? and challenge_hash = ?
  and protocol_version = ? and relay_fingerprint = ? and relay_signature = ?
  and subject_type = ? and subject_id = ?
  and tenant_id = ? and host_id = ? and device_id = ? and purpose = ?
  and issued_at = ? and expires_at = ?
  and consumed_at is null and expires_at > ?
  and exists (
    select 1 from tenants t
    where t.tenant_id = auth_challenges.tenant_id and t.enabled = 1
  )
  and (
    (subject_type = 'host' and exists (
      select 1 from hosts h
      where h.tenant_id = auth_challenges.tenant_id
        and h.host_id = auth_challenges.subject_id
        and h.enabled = 1 and h.revoked = 0
        and h.signing_public_key <> ''
    ))
    or
    (subject_type = 'device' and exists (
      select 1 from devices d join hosts h
        on h.tenant_id = d.tenant_id and h.host_id = d.host_id
      where d.tenant_id = auth_challenges.tenant_id
        and d.host_id = auth_challenges.host_id
        and d.device_id = auth_challenges.subject_id
        and d.revoked = 0 and d.signing_public_key <> ''
        and h.enabled = 1 and h.revoked = 0
    ))
  )`,
		now,
		challenge.ChallengeID,
		challengeHash,
		challenge.ProtocolVersion,
		challenge.RelayFingerprint,
		challenge.RelaySignature,
		challenge.SubjectType,
		challenge.SubjectID,
		challenge.TenantID,
		challenge.HostID,
		challenge.DeviceID,
		challenge.Purpose,
		challenge.IssuedAt,
		challenge.ExpiresAt,
		now)
	if err != nil {
		return codeError("internal_error")
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return codeError("internal_error")
	}
	if affected != 1 {
		return codeError("challenge_consumed")
	}
	return nil
}

func (s *Service) subjectSigningKey(scope TicketScope) (*ecdsa.PublicKey, error) {
	var encoded string
	switch scope.SubjectType {
	case SubjectHost:
		err := s.store.DB().QueryRow(
			`select h.signing_public_key
from hosts h join tenants t on t.tenant_id = h.tenant_id
where h.tenant_id = ? and h.host_id = ?
  and h.enabled = 1 and h.revoked = 0 and t.enabled = 1`,
			scope.TenantID, scope.SubjectID).Scan(&encoded)
		if err != nil {
			return nil, codeError("subject_not_found")
		}
	case SubjectDevice:
		err := s.store.DB().QueryRow(
			`select d.signing_public_key
from devices d
join hosts h on h.tenant_id = d.tenant_id and h.host_id = d.host_id
join tenants t on t.tenant_id = d.tenant_id
where d.tenant_id = ? and d.host_id = ? and d.device_id = ?
  and d.revoked = 0 and h.enabled = 1 and h.revoked = 0 and t.enabled = 1`,
			scope.TenantID, scope.HostID, scope.SubjectID).Scan(&encoded)
		if err != nil {
			return nil, codeError("subject_not_found")
		}
	default:
		return nil, codeError("invalid_scope")
	}
	if _, err := decodeExact(encoded, 65); err != nil {
		return nil, codeError("invalid_subject_key")
	}
	key, err := protocol.DecodeSEC1PublicKey(encoded)
	if err != nil {
		return nil, codeError("invalid_subject_key")
	}
	return key, nil
}

func challengeTranscript(challenge SignedChallenge) ([]byte, error) {
	fingerprint, err := decodeExact(challenge.RelayFingerprint, 32)
	if err != nil {
		return nil, codeError("invalid_challenge")
	}
	value, err := decodeExact(challenge.Challenge, credentialBytes)
	if err != nil {
		return nil, codeError("invalid_challenge")
	}
	var transcript []byte
	transcript = protocol.AppendString(transcript, "MYCODEX-RELAY-CHALLENGE-V1")
	transcript = protocol.AppendInt64(transcript, int64(challenge.ProtocolVersion))
	transcript = protocol.AppendField(transcript, fingerprint)
	transcript = protocol.AppendString(transcript, challenge.ChallengeID)
	transcript = protocol.AppendField(transcript, value)
	transcript = protocol.AppendString(transcript, challenge.SubjectType)
	transcript = protocol.AppendString(transcript, challenge.SubjectID)
	transcript = protocol.AppendString(transcript, challenge.TenantID)
	transcript = protocol.AppendString(transcript, challenge.HostID)
	transcript = protocol.AppendString(transcript, challenge.DeviceID)
	transcript = protocol.AppendString(transcript, challenge.Purpose)
	transcript = protocol.AppendInt64(transcript, challenge.IssuedAt)
	return protocol.AppendInt64(transcript, challenge.ExpiresAt), nil
}

func proofTranscript(challenge SignedChallenge, challengeBytes []byte) ([]byte, error) {
	relaySignature, err := decodeExact(challenge.RelaySignature, 64)
	if err != nil {
		return nil, codeError("invalid_challenge")
	}
	var transcript []byte
	transcript = protocol.AppendString(transcript, "MYCODEX-RELAY-PROOF-V1")
	transcript = protocol.AppendInt64(transcript, ProtocolVersion)
	transcript = protocol.AppendField(transcript, challengeBytes)
	transcript = protocol.AppendField(transcript, relaySignature)
	transcript = protocol.AppendString(transcript, challenge.SubjectType)
	return protocol.AppendString(transcript, challenge.SubjectID), nil
}

func (challenge SignedChallenge) scope() TicketScope {
	return TicketScope{
		SubjectType: challenge.SubjectType,
		SubjectID:   challenge.SubjectID,
		TenantID:    challenge.TenantID,
		HostID:      challenge.HostID,
		DeviceID:    challenge.DeviceID,
		Purpose:     challenge.Purpose,
	}
}

func validateScope(scope TicketScope) error {
	if strings.TrimSpace(scope.SubjectID) == "" ||
		strings.TrimSpace(scope.TenantID) == "" ||
		strings.TrimSpace(scope.HostID) == "" ||
		scope.SubjectID != strings.TrimSpace(scope.SubjectID) ||
		scope.TenantID != strings.TrimSpace(scope.TenantID) ||
		scope.HostID != strings.TrimSpace(scope.HostID) ||
		scope.DeviceID != strings.TrimSpace(scope.DeviceID) {
		return codeError("invalid_scope")
	}
	if !validPurpose(scope.Purpose) {
		return codeError("invalid_purpose")
	}
	switch scope.SubjectType {
	case SubjectHost:
		if scope.SubjectID != scope.HostID || scope.Purpose == PurposeWebSocketDevice {
			return codeError("invalid_scope")
		}
		switch scope.Purpose {
		case PurposePairingClaimApprove,
			PurposePairingClaimReject,
			PurposeDeviceRevoke,
			PurposeWebSocketHost:
			if scope.DeviceID == "" {
				return codeError("invalid_scope")
			}
		default:
			if scope.DeviceID != "" {
				return codeError("invalid_scope")
			}
		}
	case SubjectDevice:
		if scope.DeviceID == "" || scope.SubjectID != scope.DeviceID ||
			scope.Purpose != PurposeWebSocketDevice {
			return codeError("invalid_scope")
		}
	default:
		return codeError("invalid_subject_type")
	}
	return nil
}

func validPurpose(value string) bool {
	switch value {
	case PurposePairingInviteCreate,
		PurposePairingInviteCancel,
		PurposePairingClaimList,
		PurposePairingClaimApprove,
		PurposePairingClaimReject,
		PurposeDeviceList,
		PurposeDeviceRevoke,
		PurposeWebSocketHost,
		PurposeWebSocketDevice:
		return true
	default:
		return false
	}
}

func decodeExact(value string, length int) ([]byte, error) {
	if value == "" || value != strings.TrimSpace(value) {
		return nil, fmt.Errorf("invalid Base64Url")
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) != length {
		return nil, fmt.Errorf("invalid Base64Url")
	}
	return decoded, nil
}

func randomBase64URL(length int) (string, []byte, error) {
	value := make([]byte, length)
	if _, err := rand.Read(value); err != nil {
		return "", nil, err
	}
	return base64.RawURLEncoding.EncodeToString(value), value, nil
}

func clearBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func codeError(code string) error {
	return fmt.Errorf("%s", code)
}
