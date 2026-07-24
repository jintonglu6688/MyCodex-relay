package auth

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	hostsvc "github.com/mycodex/mycodex-relay/internal/host"
	"github.com/mycodex/mycodex-relay/internal/protocol"
	"github.com/mycodex/mycodex-relay/internal/security"
	"github.com/mycodex/mycodex-relay/internal/store"
	"github.com/mycodex/mycodex-relay/internal/tenant"
)

func TestChallengeIs32BytesSignedAndExpires(t *testing.T) {
	fixture := newHostAuthFixture(t)
	challenge, err := fixture.service.CreateChallenge(ChallengeRequest(fixture.scope))
	if err != nil {
		t.Fatalf("CreateChallenge failed: %v", err)
	}

	raw := decodeRawBase64(t, challenge.Challenge)
	if len(raw) != 32 {
		t.Fatalf("challenge length = %d, want 32", len(raw))
	}
	if challenge.ProtocolVersion != 1 || challenge.RelayFingerprint != fixture.relay.Public().FingerprintBase64URL {
		t.Fatalf("unexpected signed challenge identity: %+v", challenge)
	}
	now := time.Now().UTC().UnixMilli()
	if challenge.IssuedAt > now || challenge.ExpiresAt <= now || challenge.ExpiresAt-challenge.IssuedAt > 60_000 {
		t.Fatalf("unexpected challenge lifetime: issued=%d expires=%d now=%d", challenge.IssuedAt, challenge.ExpiresAt, now)
	}
	publicKey, err := protocol.DecodeSEC1PublicKey(fixture.relay.Public().PublicKeyBase64URL)
	if err != nil {
		t.Fatalf("decode Relay public key: %v", err)
	}
	if !protocol.VerifyRawSignature(publicKey, challengeTranscriptForTest(t, challenge), challenge.RelaySignature) {
		t.Fatal("Relay challenge signature did not verify")
	}

	var storedHash []byte
	if err := fixture.store.DB().QueryRow(
		"select challenge_hash from auth_challenges where challenge_id = ?",
		challenge.ChallengeID).Scan(&storedHash); err != nil {
		t.Fatalf("query challenge hash: %v", err)
	}
	digest := sha256.Sum256(raw)
	if !bytes.Equal(storedHash, digest[:]) || bytes.Equal(storedHash, raw) {
		t.Fatalf("challenge was not stored only as SHA-256: stored=%x", storedHash)
	}
}

func TestProofUsesRegisteredSubjectKey(t *testing.T) {
	fixture := newHostAuthFixture(t)
	challenge := fixture.createChallenge(t)
	attacker, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate attacker key: %v", err)
	}

	if _, err := fixture.service.Prove(ProofRequest{
		Challenge:        challenge,
		SubjectSignature: signProofForTest(t, attacker, challenge),
	}); err == nil {
		t.Fatal("proof signed by an unregistered key succeeded")
	}
	if _, err := fixture.service.Prove(ProofRequest{
		Challenge:        challenge,
		SubjectSignature: signProofForTest(t, fixture.hostPrivate, challenge),
	}); err != nil {
		t.Fatalf("registered key could not prove after rejected attacker proof: %v", err)
	}
}

func TestTicketIs32BytesHashedAndAtMost60Seconds(t *testing.T) {
	fixture := newHostAuthFixture(t)
	ticket := fixture.createTicket(t)
	raw := decodeRawBase64(t, ticket.Ticket)
	if len(raw) != 32 {
		t.Fatalf("ticket length = %d, want 32", len(raw))
	}
	now := time.Now().UTC().UnixMilli()
	if ticket.ExpiresAt <= now || ticket.ExpiresAt-now > 60_000 || ticket.Purpose != fixture.scope.Purpose {
		t.Fatalf("unexpected ticket: %+v now=%d", ticket, now)
	}

	var storedHash []byte
	var issuedAt int64
	var expiresAt int64
	if err := fixture.store.DB().QueryRow(
		"select ticket_hash, issued_at, expires_at from auth_tickets").Scan(
		&storedHash, &issuedAt, &expiresAt); err != nil {
		t.Fatalf("query ticket hash: %v", err)
	}
	if expiresAt-issuedAt > 60_000 {
		t.Fatalf("persisted ticket lifetime = %dms, want <= 60000ms", expiresAt-issuedAt)
	}
	digest := sha256.Sum256(raw)
	if !bytes.Equal(storedHash, digest[:]) || bytes.Equal(storedHash, raw) {
		t.Fatalf("ticket was not stored only as SHA-256: stored=%x", storedHash)
	}
}

func TestTicketCanBeConsumedExactlyOnce(t *testing.T) {
	fixture := newHostAuthFixture(t)
	ticket := fixture.createTicket(t)
	if err := fixture.service.ConsumeTicket(ticket.Ticket, fixture.scope); err != nil {
		t.Fatalf("first ConsumeTicket failed: %v", err)
	}
	if err := fixture.service.ConsumeTicket(ticket.Ticket, fixture.scope); err == nil {
		t.Fatal("second ConsumeTicket succeeded")
	}
}

func TestWrongPurposeSubjectTargetOrExpiryFails(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*TicketScope)
	}{
		{"subjectType", func(scope *TicketScope) { scope.SubjectType = "device" }},
		{"subjectId", func(scope *TicketScope) { scope.SubjectID = "other-host" }},
		{"tenantId", func(scope *TicketScope) { scope.TenantID = "other-tenant" }},
		{"hostId", func(scope *TicketScope) { scope.HostID = "other-host" }},
		{"deviceId", func(scope *TicketScope) { scope.DeviceID = "other-device" }},
		{"purpose", func(scope *TicketScope) { scope.Purpose = "device_list" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newHostAuthFixture(t)
			ticket := fixture.createTicket(t)
			wrong := fixture.scope
			test.mutate(&wrong)
			if err := fixture.service.ConsumeTicket(ticket.Ticket, wrong); err == nil {
				t.Fatalf("ticket accepted wrong %s", test.name)
			}
			if err := fixture.service.ConsumeTicket(ticket.Ticket, fixture.scope); err != nil {
				t.Fatalf("wrong-scope attempt consumed ticket: %v", err)
			}
		})
	}

	fixture := newHostAuthFixture(t)
	ticket := fixture.createTicket(t)
	if _, err := fixture.store.DB().Exec("update auth_tickets set expires_at = ?", time.Now().UTC().Add(-time.Second).UnixMilli()); err != nil {
		t.Fatalf("expire ticket: %v", err)
	}
	if err := fixture.service.ConsumeTicket(ticket.Ticket, fixture.scope); err == nil {
		t.Fatal("expired ticket succeeded")
	}
}

func TestProofReplayAndChallengeConcurrentConsumption(t *testing.T) {
	fixture := newHostAuthFixture(t)
	challenge := fixture.createChallenge(t)
	request := ProofRequest{
		Challenge:        challenge,
		SubjectSignature: signProofForTest(t, fixture.hostPrivate, challenge),
	}

	var successes atomic.Int32
	var wait sync.WaitGroup
	for i := 0; i < 8; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if _, err := fixture.service.Prove(request); err == nil {
				successes.Add(1)
			}
		}()
	}
	wait.Wait()
	if successes.Load() != 1 {
		t.Fatalf("successful proof consumers = %d, want 1", successes.Load())
	}
	if _, err := fixture.service.Prove(request); err == nil {
		t.Fatal("proof replay succeeded")
	}
}

func TestTicketConcurrentConsumption(t *testing.T) {
	fixture := newHostAuthFixture(t)
	ticket := fixture.createTicket(t)
	var successes atomic.Int32
	var wait sync.WaitGroup
	for i := 0; i < 8; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if err := fixture.service.ConsumeTicket(ticket.Ticket, fixture.scope); err == nil {
				successes.Add(1)
			}
		}()
	}
	wait.Wait()
	if successes.Load() != 1 {
		t.Fatalf("successful ticket consumers = %d, want 1", successes.Load())
	}
}

func TestRevokedDeviceCannotProveOrConsumeTicket(t *testing.T) {
	fixture := newHostAuthFixture(t)
	devicePrivate, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate device key: %v", err)
	}
	devicePublic := encodePublicKey(&devicePrivate.PublicKey)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := fixture.store.DB().Exec(
		`insert into devices
(tenant_id, host_id, device_id, signing_public_key, agreement_public_key,
 key_version, binding_version, revoked, approved_at)
values (?, ?, ?, ?, ?, ?, ?, 0, ?)`,
		fixture.scope.TenantID, fixture.scope.HostID, fixture.scope.DeviceID,
		devicePublic, encodePublicKey(&mustGeneratePrivateKey(t).PublicKey), 1, 1, now); err != nil {
		t.Fatalf("insert device: %v", err)
	}
	deviceScope := fixture.scope
	deviceScope.SubjectType = "device"
	deviceScope.SubjectID = fixture.scope.DeviceID
	deviceScope.Purpose = "websocket_device"

	challenge, err := fixture.service.CreateChallenge(ChallengeRequest(deviceScope))
	if err != nil {
		t.Fatalf("create device challenge: %v", err)
	}
	if _, err := fixture.store.DB().Exec(
		"update devices set revoked = 1 where tenant_id = ? and host_id = ? and device_id = ?",
		deviceScope.TenantID, deviceScope.HostID, deviceScope.DeviceID); err != nil {
		t.Fatalf("revoke device: %v", err)
	}
	if _, err := fixture.service.Prove(ProofRequest{
		Challenge:        challenge,
		SubjectSignature: signProofForTest(t, devicePrivate, challenge),
	}); err == nil {
		t.Fatal("revoked device proved a challenge")
	}

	if _, err := fixture.store.DB().Exec(
		"update devices set revoked = 0 where tenant_id = ? and host_id = ? and device_id = ?",
		deviceScope.TenantID, deviceScope.HostID, deviceScope.DeviceID); err != nil {
		t.Fatalf("restore device for ticket setup: %v", err)
	}
	challenge, err = fixture.service.CreateChallenge(ChallengeRequest(deviceScope))
	if err != nil {
		t.Fatalf("create second device challenge: %v", err)
	}
	ticket, err := fixture.service.Prove(ProofRequest{
		Challenge:        challenge,
		SubjectSignature: signProofForTest(t, devicePrivate, challenge),
	})
	if err != nil {
		t.Fatalf("issue device ticket: %v", err)
	}
	if _, err := fixture.store.DB().Exec(
		"update devices set revoked = 1 where tenant_id = ? and host_id = ? and device_id = ?",
		deviceScope.TenantID, deviceScope.HostID, deviceScope.DeviceID); err != nil {
		t.Fatalf("revoke device before consume: %v", err)
	}
	if err := fixture.service.ConsumeTicket(ticket.Ticket, deviceScope); err == nil {
		t.Fatal("revoked device consumed a ticket")
	}
}

func mustGeneratePrivateKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-256 key: %v", err)
	}
	return privateKey
}

func TestInvalidProtocolVersionAndLockedStringsFailClosed(t *testing.T) {
	fixture := newHostAuthFixture(t)
	invalidSubject := fixture.scope
	invalidSubject.SubjectType = "mobile"
	if _, err := fixture.service.CreateChallenge(ChallengeRequest(invalidSubject)); err == nil {
		t.Fatal("invalid subject type accepted")
	}
	invalidPurpose := fixture.scope
	invalidPurpose.Purpose = "websocket"
	if _, err := fixture.service.CreateChallenge(ChallengeRequest(invalidPurpose)); err == nil {
		t.Fatal("generic websocket purpose accepted")
	}

	challenge := fixture.createChallenge(t)
	challenge.ProtocolVersion = 2
	if _, err := fixture.service.Prove(ProofRequest{
		Challenge:        challenge,
		SubjectSignature: signProofForTest(t, fixture.hostPrivate, challenge),
	}); err == nil {
		t.Fatal("invalid protocol version accepted")
	}

	challenge = fixture.createChallenge(t)
	challenge.Challenge += "="
	if _, err := fixture.service.Prove(ProofRequest{
		Challenge:        challenge,
		SubjectSignature: base64.RawURLEncoding.EncodeToString(make([]byte, 64)),
	}); err == nil {
		t.Fatal("non-canonical Base64Url challenge accepted")
	}
}

func TestPurposeRequiresExactDeviceTargetShape(t *testing.T) {
	fixture := newHostAuthFixture(t)
	for _, purpose := range []string{
		PurposePairingClaimApprove,
		PurposePairingClaimReject,
		PurposeDeviceRevoke,
		PurposeWebSocketHost,
	} {
		scope := fixture.scope
		scope.Purpose = purpose
		scope.DeviceID = ""
		if _, err := fixture.service.CreateChallenge(ChallengeRequest(scope)); err == nil {
			t.Fatalf("%s accepted without deviceId", purpose)
		}
	}
	for _, purpose := range []string{
		PurposePairingInviteCreate,
		PurposePairingInviteCancel,
		PurposePairingClaimList,
		PurposeDeviceList,
	} {
		scope := fixture.scope
		scope.Purpose = purpose
		if _, err := fixture.service.CreateChallenge(ChallengeRequest(scope)); err == nil {
			t.Fatalf("%s accepted unexpected deviceId", purpose)
		}
		scope.DeviceID = ""
		if _, err := fixture.service.CreateChallenge(ChallengeRequest(scope)); err != nil {
			t.Fatalf("%s rejected empty deviceId: %v", purpose, err)
		}
	}
}

type authFixture struct {
	store       *store.Store
	service     *Service
	relay       *security.RelayIdentitySigner
	hostPrivate *ecdsa.PrivateKey
	scope       TicketScope
}

func newHostAuthFixture(t *testing.T) authFixture {
	t.Helper()
	directory := t.TempDir()
	st, err := store.Open(filepath.Join(directory, "relay-state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	tenantService := tenant.NewService(st)
	created, _, err := tenantService.Create("Test tenant")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	signingPrivate, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate host signing key: %v", err)
	}
	agreementPrivate, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate host agreement key: %v", err)
	}
	hostID := "22222222-2222-2222-2222-222222222222"
	if _, err := hostsvc.NewService(st).EnrollHost(hostsvc.Enrollment{
		TenantID:           created.TenantID,
		HostID:             hostID,
		DisplayName:        "Windows",
		SigningPublicKey:   encodePublicKey(&signingPrivate.PublicKey),
		AgreementPublicKey: encodePublicKey(&agreementPrivate.PublicKey),
		KeyVersion:         1,
	}); err != nil {
		t.Fatalf("enroll host: %v", err)
	}
	relayIdentity, err := security.LoadOrCreateRelayIdentity(filepath.Join(directory, "relay-state.db.identity.pk8"))
	if err != nil {
		t.Fatalf("create Relay identity: %v", err)
	}
	return authFixture{
		store:       st,
		service:     NewService(st, relayIdentity),
		relay:       relayIdentity,
		hostPrivate: signingPrivate,
		scope: TicketScope{
			SubjectType: "host",
			SubjectID:   hostID,
			TenantID:    created.TenantID,
			HostID:      hostID,
			DeviceID:    "33333333-3333-3333-3333-333333333333",
			Purpose:     "websocket_host",
		},
	}
}

func (fixture authFixture) createChallenge(t *testing.T) SignedChallenge {
	t.Helper()
	challenge, err := fixture.service.CreateChallenge(ChallengeRequest(fixture.scope))
	if err != nil {
		t.Fatalf("CreateChallenge failed: %v", err)
	}
	return challenge
}

func (fixture authFixture) createTicket(t *testing.T) Ticket {
	t.Helper()
	challenge := fixture.createChallenge(t)
	ticket, err := fixture.service.Prove(ProofRequest{
		Challenge:        challenge,
		SubjectSignature: signProofForTest(t, fixture.hostPrivate, challenge),
	})
	if err != nil {
		t.Fatalf("Prove failed: %v", err)
	}
	return ticket
}

func challengeTranscriptForTest(t *testing.T, challenge SignedChallenge) []byte {
	t.Helper()
	fingerprint := decodeRawBase64(t, challenge.RelayFingerprint)
	value := decodeRawBase64(t, challenge.Challenge)
	var result []byte
	result = protocol.AppendString(result, "MYCODEX-RELAY-CHALLENGE-V1")
	result = protocol.AppendInt64(result, int64(challenge.ProtocolVersion))
	result = protocol.AppendField(result, fingerprint)
	result = protocol.AppendString(result, challenge.ChallengeID)
	result = protocol.AppendField(result, value)
	result = protocol.AppendString(result, challenge.SubjectType)
	result = protocol.AppendString(result, challenge.SubjectID)
	result = protocol.AppendString(result, challenge.TenantID)
	result = protocol.AppendString(result, challenge.HostID)
	result = protocol.AppendString(result, challenge.DeviceID)
	result = protocol.AppendString(result, challenge.Purpose)
	result = protocol.AppendInt64(result, challenge.IssuedAt)
	return protocol.AppendInt64(result, challenge.ExpiresAt)
}

func proofTranscriptForTest(t *testing.T, challenge SignedChallenge) []byte {
	t.Helper()
	challengeTranscript := challengeTranscriptForTest(t, challenge)
	relaySignature := decodeRawBase64(t, challenge.RelaySignature)
	var result []byte
	result = protocol.AppendString(result, "MYCODEX-RELAY-PROOF-V1")
	result = protocol.AppendInt64(result, 1)
	result = protocol.AppendField(result, challengeTranscript)
	result = protocol.AppendField(result, relaySignature)
	result = protocol.AppendString(result, challenge.SubjectType)
	return protocol.AppendString(result, challenge.SubjectID)
}

func signProofForTest(t *testing.T, privateKey *ecdsa.PrivateKey, challenge SignedChallenge) string {
	t.Helper()
	digest := sha256.Sum256(proofTranscriptForTest(t, challenge))
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, digest[:])
	if err != nil {
		t.Fatalf("sign proof: %v", err)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return base64.RawURLEncoding.EncodeToString(signature)
}

func encodePublicKey(key *ecdsa.PublicKey) string {
	return base64.RawURLEncoding.EncodeToString(elliptic.Marshal(elliptic.P256(), key.X, key.Y))
}

func decodeRawBase64(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil {
		t.Fatalf("decode Base64Url: %v", err)
	}
	return decoded
}
