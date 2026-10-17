package pairing

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	hostsvc "github.com/mycodex/mycodex-relay/internal/host"
	"github.com/mycodex/mycodex-relay/internal/store"
	"github.com/mycodex/mycodex-relay/internal/tenant"
)

func TestSubmitClaimStoresOnlyCiphertextAndAccessTokenHash(t *testing.T) {
	fixture := newPairingFixture(t)
	request := fixture.claimRequest("55555555-5555-5555-5555-555555555555", "device_a")
	created, err := fixture.service.SubmitClaim(request)
	if err != nil {
		t.Fatalf("SubmitClaim failed: %v", err)
	}
	rawToken := decodePairingBase64(t, created.ClaimAccessToken)
	if len(rawToken) != 32 {
		t.Fatalf("claim access token length = %d, want 32", len(rawToken))
	}
	var headerJSON string
	var storedNonce string
	var storedCiphertext string
	var tokenHash []byte
	if err := fixture.store.DB().QueryRow(
		`select header_json, nonce, ciphertext, access_token_hash
from pairing_claims where claim_id = ?`,
		created.ClaimID).Scan(
		&headerJSON, &storedNonce, &storedCiphertext, &tokenHash); err != nil {
		t.Fatalf("query stored claim: %v", err)
	}
	var storedHeader PairingClaimHeader
	if err := json.Unmarshal([]byte(headerJSON), &storedHeader); err != nil {
		t.Fatalf("unmarshal stored header: %v", err)
	}
	if storedHeader != request.Header ||
		storedNonce != request.Nonce ||
		storedCiphertext != request.Ciphertext {
		t.Fatalf("stored opaque claim changed: header=%+v nonce=%q ciphertext=%q", storedHeader, storedNonce, storedCiphertext)
	}
	digest := sha256.Sum256(rawToken)
	if !bytes.Equal(tokenHash, digest[:]) || bytes.Equal(tokenHash, rawToken) {
		t.Fatalf("claim token was not stored only as SHA-256: %x", tokenHash)
	}
}

func TestInviteAcceptsMultiplePendingClaims(t *testing.T) {
	fixture := newPairingFixture(t)
	first := fixture.submitClaim(t, "55555555-5555-5555-5555-555555555551", "device_a")
	second := fixture.submitClaim(t, "55555555-5555-5555-5555-555555555552", "device_b")
	if first.ClaimID == second.ClaimID {
		t.Fatal("two pending claims have the same ID")
	}
	claims, err := fixture.service.ListPendingClaims(fixture.tenantID, fixture.hostID)
	if err != nil {
		t.Fatalf("ListPendingClaims failed: %v", err)
	}
	if len(claims) != 2 ||
		claims[0].Status != ClaimPending ||
		claims[1].Status != ClaimPending {
		t.Fatalf("pending claims = %+v, want two", claims)
	}
}

func TestApproveAtomicallyApprovesOneAndConsumesSiblings(t *testing.T) {
	fixture := newPairingFixture(t)
	first := fixture.submitClaim(t, "55555555-5555-5555-5555-555555555551", "device_a")
	second := fixture.submitClaim(t, "55555555-5555-5555-5555-555555555552", "device_b")
	approvals := []ApproveClaimRequest{
		fixture.approval(t, first.ClaimID),
		fixture.approval(t, second.ClaimID),
	}
	var successes atomic.Int32
	var wait sync.WaitGroup
	start := make(chan struct{})
	for index := range approvals {
		wait.Add(1)
		go func(request ApproveClaimRequest) {
			defer wait.Done()
			<-start
			if err := fixture.service.ApproveClaim(request); err == nil {
				successes.Add(1)
			}
		}(approvals[index])
	}
	close(start)
	wait.Wait()
	if successes.Load() != 1 {
		t.Fatalf("successful competing approvals = %d, want 1", successes.Load())
	}
	var approved int
	var consumed int
	rows, err := fixture.store.DB().Query(
		"select status from pairing_claims where invite_id = ?",
		fixture.inviteID)
	if err != nil {
		t.Fatalf("query claim statuses: %v", err)
	}
	for rows.Next() {
		var status string
		if err := rows.Scan(&status); err != nil {
			rows.Close()
			t.Fatalf("scan claim status: %v", err)
		}
		switch ClaimStatus(status) {
		case ClaimApproved:
			approved++
		case ClaimConsumed:
			consumed++
		}
	}
	rows.Close()
	if approved != 1 || consumed != 1 {
		t.Fatalf("approved=%d consumed=%d, want 1/1", approved, consumed)
	}
	var inviteStatus string
	if err := fixture.store.DB().QueryRow(
		"select status from pairing_invites where invite_id = ?",
		fixture.inviteID).Scan(&inviteStatus); err != nil {
		t.Fatalf("query invite status: %v", err)
	}
	if inviteStatus != string(ClaimConsumed) {
		t.Fatalf("invite status = %q, want consumed", inviteStatus)
	}
	var devices int
	if err := fixture.store.DB().QueryRow("select count(*) from devices").Scan(&devices); err != nil {
		t.Fatalf("count devices: %v", err)
	}
	if devices != 1 {
		t.Fatalf("device rows = %d, want 1", devices)
	}
}

func TestIdenticalApproveIsIdempotent(t *testing.T) {
	fixture := newPairingFixture(t)
	claim := fixture.submitClaim(t, "55555555-5555-5555-5555-555555555555", "device_a")
	request := fixture.approval(t, claim.ClaimID)
	if err := fixture.service.ApproveClaim(request); err != nil {
		t.Fatalf("first ApproveClaim failed: %v", err)
	}
	if err := fixture.service.ApproveClaim(request); err != nil {
		t.Fatalf("identical ApproveClaim retry failed: %v", err)
	}
}

func TestDifferentSecondApproveIsRejectedWithoutMutation(t *testing.T) {
	fixture := newPairingFixture(t)
	claim := fixture.submitClaim(t, "55555555-5555-5555-5555-555555555555", "device_a")
	request := fixture.approval(t, claim.ClaimID)
	if err := fixture.service.ApproveClaim(request); err != nil {
		t.Fatalf("first ApproveClaim failed: %v", err)
	}
	changed := request
	changed.ApprovalCiphertext = pairingBase64([]byte("different immutable approval ciphertext"))
	if err := fixture.service.ApproveClaim(changed); err == nil || err.Error() != "approval_conflict" {
		t.Fatalf("changed ApproveClaim error = %v, want approval_conflict", err)
	}
	view, err := fixture.service.GetClaimWithToken(claim.ClaimID, claim.ClaimAccessToken)
	if err != nil {
		t.Fatalf("GetClaimWithToken failed: %v", err)
	}
	if view.ApprovalCiphertext != request.ApprovalCiphertext {
		t.Fatalf("changed retry mutated approval: %+v", view)
	}
}

func TestClaimTokenCannotReadAnotherClaim(t *testing.T) {
	fixture := newPairingFixture(t)
	first := fixture.submitClaim(t, "55555555-5555-5555-5555-555555555551", "device_a")
	second := fixture.submitClaim(t, "55555555-5555-5555-5555-555555555552", "device_b")
	if _, err := fixture.service.GetClaimWithToken(second.ClaimID, first.ClaimAccessToken); err == nil {
		t.Fatal("one claim token read another claim")
	}
	if _, err := fixture.service.GetClaimWithToken(first.ClaimID, first.ClaimAccessToken); err != nil {
		t.Fatalf("correct claim token failed: %v", err)
	}
	if err := fixture.service.CancelClaim(second.ClaimID, first.ClaimAccessToken); err == nil ||
		err.Error() != "unauthorized" {
		t.Fatalf("one claim token cancelled another claim: %v", err)
	}
	view, err := fixture.service.GetClaimWithToken(second.ClaimID, second.ClaimAccessToken)
	if err != nil || view.Status != ClaimPending {
		t.Fatalf("cross-claim cancel changed claim: view=%+v err=%v", view, err)
	}
}

func TestCancelRejectExpireAndConsumeAreTerminal(t *testing.T) {
	t.Run("cancelled", func(t *testing.T) {
		fixture := newPairingFixture(t)
		claim := fixture.submitClaim(t, "55555555-5555-5555-5555-555555555555", "device_a")
		if err := fixture.service.CancelClaim(claim.ClaimID, claim.ClaimAccessToken); err != nil {
			t.Fatalf("CancelClaim failed: %v", err)
		}
		assertTerminalClaim(t, fixture, claim, ClaimCancelled)
	})
	t.Run("rejected", func(t *testing.T) {
		fixture := newPairingFixture(t)
		claim := fixture.submitClaim(t, "55555555-5555-5555-5555-555555555555", "device_a")
		if err := fixture.service.RejectClaim(fixture.tenantID, fixture.hostID, claim.ClaimID); err != nil {
			t.Fatalf("RejectClaim failed: %v", err)
		}
		assertTerminalClaim(t, fixture, claim, ClaimRejected)
	})
	t.Run("expired", func(t *testing.T) {
		fixture := newPairingFixture(t)
		claim := fixture.submitClaim(t, "55555555-5555-5555-5555-555555555555", "device_a")
		if _, err := fixture.store.DB().Exec(
			"update pairing_claims set expires_at = ? where claim_id = ?",
			time.Now().UTC().Add(-time.Second).UnixMilli(), claim.ClaimID); err != nil {
			t.Fatalf("expire claim: %v", err)
		}
		assertTerminalClaim(t, fixture, claim, ClaimExpired)
	})
	t.Run("consumed", func(t *testing.T) {
		fixture := newPairingFixture(t)
		winner := fixture.submitClaim(t, "55555555-5555-5555-5555-555555555551", "device_a")
		loser := fixture.submitClaim(t, "55555555-5555-5555-5555-555555555552", "device_b")
		if err := fixture.service.ApproveClaim(fixture.approval(t, winner.ClaimID)); err != nil {
			t.Fatalf("ApproveClaim failed: %v", err)
		}
		assertTerminalClaim(t, fixture, loser, ClaimConsumed)
	})
}

func TestApprovedDeviceStoresBothPublicKeysAndBindingVersion(t *testing.T) {
	fixture := newPairingFixture(t)
	claim := fixture.submitClaim(t, "55555555-5555-5555-5555-555555555555", "device_a")
	request := fixture.approval(t, claim.ClaimID)
	if err := fixture.service.ApproveClaim(request); err != nil {
		t.Fatalf("ApproveClaim failed: %v", err)
	}
	device, err := fixture.service.GetDevice(fixture.tenantID, fixture.hostID, "device_a")
	if err != nil {
		t.Fatalf("GetDevice failed: %v", err)
	}
	if device.SigningPublicKey != request.DeviceSigningPublicKey ||
		device.AgreementPublicKey != request.DeviceAgreementPublicKey ||
		device.KeyVersion != request.DeviceKeyVersion ||
		device.BindingVersion != request.BindingVersion ||
		device.Revoked {
		t.Fatalf("unexpected approved device: %+v", device)
	}
}

func TestExistingDeviceIdentityIsImmutableAndBindingVersionOnlyAdvances(t *testing.T) {
	t.Run("active device advances with identical keys", func(t *testing.T) {
		fixture, firstApproval := approveInitialDevice(t)
		claim := fixture.submitRepairClaim(
			t,
			"44444444-4444-4444-4444-444444444445",
			"55555555-5555-5555-5555-555555555556",
			"device_a",
			firstApproval.DeviceAgreementPublicKey)
		request := fixture.approval(t, claim.ClaimID)
		request.DeviceSigningPublicKey = firstApproval.DeviceSigningPublicKey
		request.BindingVersion = firstApproval.BindingVersion + 1
		if err := fixture.service.ApproveClaim(request); err != nil {
			t.Fatalf("higher-version re-pair failed: %v", err)
		}
		device, err := fixture.service.GetDevice(fixture.tenantID, fixture.hostID, "device_a")
		if err != nil || device.BindingVersion != request.BindingVersion {
			t.Fatalf("advanced device=%+v err=%v", device, err)
		}
	})

	t.Run("revoked device advances and becomes active", func(t *testing.T) {
		fixture, firstApproval := approveInitialDevice(t)
		if err := fixture.service.RevokeDevice(fixture.tenantID, fixture.hostID, "device_a"); err != nil {
			t.Fatalf("RevokeDevice failed: %v", err)
		}
		claim := fixture.submitRepairClaim(
			t,
			"44444444-4444-4444-4444-444444444445",
			"55555555-5555-5555-5555-555555555556",
			"device_a",
			firstApproval.DeviceAgreementPublicKey)
		request := fixture.approval(t, claim.ClaimID)
		request.DeviceSigningPublicKey = firstApproval.DeviceSigningPublicKey
		request.BindingVersion = firstApproval.BindingVersion + 1
		if err := fixture.service.ApproveClaim(request); err != nil {
			t.Fatalf("revoked higher-version re-pair failed: %v", err)
		}
		device, err := fixture.service.GetDevice(fixture.tenantID, fixture.hostID, "device_a")
		if err != nil || device.Revoked || device.BindingVersion != request.BindingVersion {
			t.Fatalf("reactivated device=%+v err=%v", device, err)
		}
	})

	for _, test := range []struct {
		name   string
		mutate func(*ApproveClaimRequest)
	}{
		{
			name: "signing key mismatch",
			mutate: func(request *ApproveClaimRequest) {
				request.DeviceSigningPublicKey = pairingPublicKeyNoTestFailure()
			},
		},
		{
			name:   "agreement key mismatch",
			mutate: func(request *ApproveClaimRequest) {},
		},
		{
			name: "binding version rollback",
			mutate: func(request *ApproveClaimRequest) {
				request.BindingVersion = 3
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture, firstApproval := approveInitialDevice(t)
			agreement := firstApproval.DeviceAgreementPublicKey
			if test.name == "agreement key mismatch" {
				agreement = pairingPublicKeyNoTestFailure()
			}
			claim := fixture.submitRepairClaim(
				t,
				"44444444-4444-4444-4444-444444444445",
				"55555555-5555-5555-5555-555555555556",
				"device_a",
				agreement)
			request := fixture.approval(t, claim.ClaimID)
			request.DeviceSigningPublicKey = firstApproval.DeviceSigningPublicKey
			request.BindingVersion = firstApproval.BindingVersion + 1
			test.mutate(&request)
			if err := fixture.service.ApproveClaim(request); err == nil ||
				err.Error() != "device_binding_conflict" {
				t.Fatalf("conflicting re-pair error=%v, want device_binding_conflict", err)
			}
			assertClaimAndInvitePending(t, fixture, claim, "44444444-4444-4444-4444-444444444445")
			device, err := fixture.service.GetDevice(fixture.tenantID, fixture.hostID, "device_a")
			if err != nil ||
				device.SigningPublicKey != firstApproval.DeviceSigningPublicKey ||
				device.AgreementPublicKey != firstApproval.DeviceAgreementPublicKey ||
				device.BindingVersion != firstApproval.BindingVersion {
				t.Fatalf("conflict mutated device=%+v err=%v", device, err)
			}
		})
	}
}

func TestConcurrentDeviceRepairAllowsExactlyOneBindingAdvance(t *testing.T) {
	fixture, firstApproval := approveInitialDevice(t)
	first := fixture.submitRepairClaim(
		t,
		"44444444-4444-4444-4444-444444444445",
		"55555555-5555-5555-5555-555555555556",
		"device_a",
		firstApproval.DeviceAgreementPublicKey)
	second := fixture.submitRepairClaim(
		t,
		"44444444-4444-4444-4444-444444444446",
		"55555555-5555-5555-5555-555555555557",
		"device_a",
		firstApproval.DeviceAgreementPublicKey)
	requests := []ApproveClaimRequest{
		fixture.approval(t, first.ClaimID),
		fixture.approval(t, second.ClaimID),
	}
	for index := range requests {
		requests[index].DeviceSigningPublicKey = firstApproval.DeviceSigningPublicKey
		requests[index].BindingVersion = firstApproval.BindingVersion + 1
	}
	var successes atomic.Int32
	var conflicts atomic.Int32
	var wait sync.WaitGroup
	start := make(chan struct{})
	for index := range requests {
		wait.Add(1)
		go func(request ApproveClaimRequest) {
			defer wait.Done()
			<-start
			err := fixture.service.ApproveClaim(request)
			if err == nil {
				successes.Add(1)
			} else if err.Error() == "device_binding_conflict" {
				conflicts.Add(1)
			}
		}(requests[index])
	}
	close(start)
	wait.Wait()
	if successes.Load() != 1 || conflicts.Load() != 1 {
		t.Fatalf("concurrent re-pair successes=%d conflicts=%d, want 1/1",
			successes.Load(), conflicts.Load())
	}
}

func TestPairingOpaqueInputsHaveSmallFixedBounds(t *testing.T) {
	fixture := newPairingFixture(t)
	for _, test := range []struct {
		name   string
		mutate func(*SubmitClaimRequest)
	}{
		{
			name: "identifier whitespace",
			mutate: func(request *SubmitClaimRequest) {
				request.Header.DeviceID = "device a"
			},
		},
		{
			name: "identifier too long",
			mutate: func(request *SubmitClaimRequest) {
				request.Header.DeviceID = strings.Repeat("a", maxIdentifierBytes+1)
			},
		},
		{
			name: "ciphertext too large",
			mutate: func(request *SubmitClaimRequest) {
				ciphertext := make([]byte, maxOpaqueCiphertextBytes+1)
				request.Ciphertext = pairingBase64(ciphertext)
				request.Header.CiphertextLength = int64(len(ciphertext))
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := fixture.claimRequest(
				"55555555-5555-5555-5555-555555555555",
				"device_a")
			test.mutate(&request)
			if _, err := fixture.service.SubmitClaim(request); err == nil {
				t.Fatalf("%s claim succeeded", test.name)
			}
		})
	}

	claim := fixture.submitClaim(t, "55555555-5555-5555-5555-555555555556", "device_b")
	for _, test := range []struct {
		name   string
		mutate func(*ApproveClaimRequest)
	}{
		{
			name: "approval header too large",
			mutate: func(request *ApproveClaimRequest) {
				request.ApprovalHeader = pairingBase64(make([]byte, maxOpaqueHeaderBytes+1))
			},
		},
		{
			name: "approval ciphertext too large",
			mutate: func(request *ApproveClaimRequest) {
				request.ApprovalCiphertext = pairingBase64(make([]byte, maxOpaqueCiphertextBytes+1))
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := fixture.approval(t, claim.ClaimID)
			test.mutate(&request)
			if err := fixture.service.ApproveClaim(request); err == nil {
				t.Fatalf("%s approval succeeded", test.name)
			}
		})
	}
}

func TestCrossTenantAndWrongScopeTransitionsFail(t *testing.T) {
	fixture := newPairingFixture(t)
	claim := fixture.submitClaim(t, "55555555-5555-5555-5555-555555555555", "device_a")
	if err := fixture.service.RejectClaim("other_tenant", fixture.hostID, claim.ClaimID); err == nil {
		t.Fatal("cross-tenant reject succeeded")
	}
	request := fixture.approval(t, claim.ClaimID)
	request.HostID = "other_host"
	if err := fixture.service.ApproveClaim(request); err == nil {
		t.Fatal("wrong-host approval succeeded")
	}
	view, err := fixture.service.GetClaimWithToken(claim.ClaimID, claim.ClaimAccessToken)
	if err != nil || view.Status != ClaimPending {
		t.Fatalf("wrong-scope operation changed claim: view=%+v err=%v", view, err)
	}
}

func TestClaimReplayAndMalformedOpaqueFieldsFailClosed(t *testing.T) {
	fixture := newPairingFixture(t)
	request := fixture.claimRequest("55555555-5555-5555-5555-555555555555", "device_a")
	if _, err := fixture.service.SubmitClaim(request); err != nil {
		t.Fatalf("first SubmitClaim failed: %v", err)
	}
	if _, err := fixture.service.SubmitClaim(request); err == nil || err.Error() != "claim_exists" {
		t.Fatalf("claim replay error = %v, want claim_exists", err)
	}

	tests := []struct {
		name   string
		mutate func(*SubmitClaimRequest)
	}{
		{"wrong tenant", func(value *SubmitClaimRequest) { value.Header.TenantID = "other_tenant" }},
		{"padded nonce", func(value *SubmitClaimRequest) { value.Nonce += "=" }},
		{"short nonce", func(value *SubmitClaimRequest) { value.Nonce = pairingBase64(make([]byte, 11)) }},
		{"short client nonce", func(value *SubmitClaimRequest) { value.Header.ClientNonce = pairingBase64(make([]byte, 31)) }},
		{"invalid agreement key", func(value *SubmitClaimRequest) { value.Header.DeviceAgreementPublicKey = "invalid" }},
		{"wrong ciphertext length", func(value *SubmitClaimRequest) { value.Header.CiphertextLength++ }},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := fixture.claimRequest(
				fmt.Sprintf("55555555-5555-5555-5555-%012d", index+100),
				fmt.Sprintf("device_%d", index))
			test.mutate(&changed)
			if _, err := fixture.service.SubmitClaim(changed); err == nil {
				t.Fatalf("malformed %s claim succeeded", test.name)
			}
		})
	}
}

func TestApprovalRejectsSharedSigningAndAgreementKey(t *testing.T) {
	fixture := newPairingFixture(t)
	claim := fixture.submitClaim(t, "55555555-5555-5555-5555-555555555555", "device_a")
	request := fixture.approval(t, claim.ClaimID)
	request.DeviceAgreementPublicKey = request.DeviceSigningPublicKey
	if err := fixture.service.ApproveClaim(request); err == nil || err.Error() != "invalid_device_identity" {
		t.Fatalf("ApproveClaim error = %v, want invalid_device_identity", err)
	}
	view, err := fixture.service.GetClaimWithToken(claim.ClaimID, claim.ClaimAccessToken)
	if err != nil || view.Status != ClaimPending {
		t.Fatalf("invalid approval changed claim: view=%+v err=%v", view, err)
	}
}

func TestCancelInviteAtomicallyCancelsPendingClaims(t *testing.T) {
	fixture := newPairingFixture(t)
	first := fixture.submitClaim(t, "55555555-5555-5555-5555-555555555551", "device_a")
	second := fixture.submitClaim(t, "55555555-5555-5555-5555-555555555552", "device_b")
	if err := fixture.service.CancelInvite(fixture.tenantID, fixture.hostID, fixture.inviteID); err != nil {
		t.Fatalf("CancelInvite failed: %v", err)
	}
	for _, claim := range []CreatedClaim{first, second} {
		view, err := fixture.service.GetClaimWithToken(claim.ClaimID, claim.ClaimAccessToken)
		if err != nil || view.Status != ClaimCancelled {
			t.Fatalf("cancelled invite claim view=%+v err=%v", view, err)
		}
	}
}

func assertTerminalClaim(
	t *testing.T,
	fixture pairingFixture,
	claim CreatedClaim,
	status ClaimStatus,
) {
	t.Helper()
	view, err := fixture.service.GetClaimWithToken(claim.ClaimID, claim.ClaimAccessToken)
	if err != nil {
		t.Fatalf("GetClaimWithToken failed: %v", err)
	}
	if view.Status != status {
		t.Fatalf("claim status = %q, want %q", view.Status, status)
	}
	if err := fixture.service.CancelClaim(claim.ClaimID, claim.ClaimAccessToken); err == nil {
		t.Fatalf("terminal %s claim was cancelled again", status)
	}
	if err := fixture.service.RejectClaim(fixture.tenantID, fixture.hostID, claim.ClaimID); err == nil {
		t.Fatalf("terminal %s claim was rejected", status)
	}
	if err := fixture.service.ApproveClaim(fixture.approval(t, claim.ClaimID)); err == nil {
		t.Fatalf("terminal %s claim was approved", status)
	}
}

type pairingFixture struct {
	store    *store.Store
	service  *Service
	tenantID string
	hostID   string
	inviteID string
}

func approveInitialDevice(t *testing.T) (pairingFixture, ApproveClaimRequest) {
	t.Helper()
	fixture := newPairingFixture(t)
	claim := fixture.submitClaim(
		t,
		"55555555-5555-5555-5555-555555555555",
		"device_a")
	request := fixture.approval(t, claim.ClaimID)
	if err := fixture.service.ApproveClaim(request); err != nil {
		t.Fatalf("initial ApproveClaim failed: %v", err)
	}
	return fixture, request
}

func (fixture pairingFixture) submitRepairClaim(
	t *testing.T,
	inviteID string,
	claimID string,
	deviceID string,
	agreementPublicKey string,
) CreatedClaim {
	t.Helper()
	if err := fixture.service.CreateInvite(
		fixture.tenantID,
		fixture.hostID,
		inviteID,
		time.Now().UTC().Add(9*time.Minute)); err != nil {
		t.Fatalf("CreateInvite for re-pair failed: %v", err)
	}
	request := fixture.claimRequest(claimID, deviceID)
	request.Header.InviteID = inviteID
	request.Header.DeviceAgreementPublicKey = agreementPublicKey
	created, err := fixture.service.SubmitClaim(request)
	if err != nil {
		t.Fatalf("SubmitClaim for re-pair failed: %v", err)
	}
	return created
}

func assertClaimAndInvitePending(
	t *testing.T,
	fixture pairingFixture,
	claim CreatedClaim,
	inviteID string,
) {
	t.Helper()
	view, err := fixture.service.GetClaimWithToken(claim.ClaimID, claim.ClaimAccessToken)
	if err != nil || view.Status != ClaimPending {
		t.Fatalf("conflict mutated claim=%+v err=%v", view, err)
	}
	var status string
	if err := fixture.store.DB().QueryRow(
		"select status from pairing_invites where invite_id = ?",
		inviteID).Scan(&status); err != nil || status != string(ClaimPending) {
		t.Fatalf("conflict mutated invite status=%q err=%v", status, err)
	}
}

func newPairingFixture(t *testing.T) pairingFixture {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "relay-state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	created, _, err := tenant.NewService(st).Create("Pairing tenant")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	hostID := "22222222-2222-2222-2222-222222222222"
	if _, err := hostsvc.NewService(st).EnrollHost(hostsvc.Enrollment{
		TenantID:           created.TenantID,
		HostID:             hostID,
		DisplayName:        "Windows",
		SigningPublicKey:   pairingPublicKey(t),
		AgreementPublicKey: pairingPublicKey(t),
		KeyVersion:         1,
	}); err != nil {
		t.Fatalf("enroll host: %v", err)
	}
	service := NewService(st)
	inviteID := "44444444-4444-4444-4444-444444444444"
	if err := service.CreateInvite(
		created.TenantID,
		hostID,
		inviteID,
		time.Now().UTC().Add(10*time.Minute)); err != nil {
		t.Fatalf("CreateInvite failed: %v", err)
	}
	return pairingFixture{
		store:    st,
		service:  service,
		tenantID: created.TenantID,
		hostID:   hostID,
		inviteID: inviteID,
	}
}

func (fixture pairingFixture) claimRequest(claimID string, deviceID string) SubmitClaimRequest {
	ciphertext := []byte("opaque encrypted claim bytes plus tag")
	return SubmitClaimRequest{
		Header: PairingClaimHeader{
			InviteID:                 fixture.inviteID,
			TenantID:                 fixture.tenantID,
			HostID:                   fixture.hostID,
			ClaimID:                  claimID,
			DeviceID:                 deviceID,
			DeviceAgreementPublicKey: pairingPublicKeyNoTestFailure(),
			DeviceKeyVersion:         1,
			ClientNonce:              pairingBase64(bytes.Repeat([]byte{0x23}, 32)),
			CiphertextLength:         int64(len(ciphertext)),
		},
		Nonce:      pairingBase64(bytes.Repeat([]byte{0x42}, 12)),
		Ciphertext: pairingBase64(ciphertext),
	}
}

func (fixture pairingFixture) submitClaim(t *testing.T, claimID string, deviceID string) CreatedClaim {
	t.Helper()
	created, err := fixture.service.SubmitClaim(fixture.claimRequest(claimID, deviceID))
	if err != nil {
		t.Fatalf("SubmitClaim failed: %v", err)
	}
	return created
}

func (fixture pairingFixture) approval(t *testing.T, claimID string) ApproveClaimRequest {
	t.Helper()
	var headerJSON string
	if err := fixture.store.DB().QueryRow(
		"select header_json from pairing_claims where claim_id = ?",
		claimID).Scan(&headerJSON); err != nil {
		t.Fatalf("query claim header: %v", err)
	}
	var header PairingClaimHeader
	if err := json.Unmarshal([]byte(headerJSON), &header); err != nil {
		t.Fatalf("unmarshal claim header: %v", err)
	}
	return ApproveClaimRequest{
		TenantID:                 fixture.tenantID,
		HostID:                   fixture.hostID,
		ClaimID:                  claimID,
		DeviceSigningPublicKey:   pairingPublicKeyNoTestFailure(),
		DeviceAgreementPublicKey: header.DeviceAgreementPublicKey,
		DeviceKeyVersion:         header.DeviceKeyVersion,
		BindingVersion:           3,
		ApprovalHeader:           pairingBase64([]byte("opaque canonical approval header")),
		ApprovalNonce:            pairingBase64(bytes.Repeat([]byte{0x51}, 12)),
		ApprovalCiphertext:       pairingBase64([]byte("opaque encrypted approval bytes plus tag")),
	}
}

func pairingPublicKey(t *testing.T) string {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-256 key: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(
		elliptic.Marshal(elliptic.P256(), privateKey.X, privateKey.Y))
}

func pairingPublicKeyNoTestFailure() string {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("generate test P-256 key: %v", err))
	}
	return base64.RawURLEncoding.EncodeToString(
		elliptic.Marshal(elliptic.P256(), privateKey.X, privateKey.Y))
}

func pairingBase64(value []byte) string {
	return base64.RawURLEncoding.EncodeToString(value)
}

func decodePairingBase64(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil {
		t.Fatalf("decode Base64Url: %v", err)
	}
	return decoded
}
