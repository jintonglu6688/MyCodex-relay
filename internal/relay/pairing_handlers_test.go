package relay

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	authsvc "github.com/mycodex/mycodex-relay/internal/auth"
	"github.com/mycodex/mycodex-relay/internal/pairing"
)

func TestSecurePairingHTTPFlowUsesLockedRoutesAndTickets(t *testing.T) {
	fixture := newHTTPAuthFixture(t)
	hostPrivate, _ := enrollHTTPHost(t, fixture)
	scope := func(purpose string, deviceID string) authsvc.TicketScope {
		return authsvc.TicketScope{
			SubjectType: authsvc.SubjectHost,
			SubjectID:   fixture.hostID,
			TenantID:    fixture.tenantID,
			HostID:      fixture.hostID,
			DeviceID:    deviceID,
			Purpose:     purpose,
		}
	}
	inviteID := "44444444-4444-4444-4444-444444444444"
	inviteTicket := issueHTTPAuthTicket(
		t, fixture.server.URL, hostPrivate,
		scope(authsvc.PurposePairingInviteCreate, ""))
	status, body := postJSON(t, fixture.server.URL+"/v1/pairing/invites", inviteTicket.Ticket, map[string]interface{}{
		"tenantId": fixture.tenantID,
		"hostId":   fixture.hostID,
		"inviteId": inviteID,
		"expiresAt": time.Now().UTC().
			Add(10 * time.Minute).
			UnixMilli(),
	})
	if status != http.StatusOK || !strings.Contains(body, `"status":"pending"`) {
		t.Fatalf("create invite status=%d body=%s", status, body)
	}
	if strings.Contains(body, "secret") || strings.Contains(body, "token") {
		t.Fatalf("invite response exposed a secret/token field: %s", body)
	}

	firstRequest := httpClaimRequest(fixture, inviteID, "55555555-5555-5555-5555-555555555551", fixture.deviceID)
	secondRequest := httpClaimRequest(fixture, inviteID, "55555555-5555-5555-5555-555555555552", "device_b")
	first := submitHTTPClaim(t, fixture.server.URL, firstRequest)
	second := submitHTTPClaim(t, fixture.server.URL, secondRequest)

	listTicket := issueHTTPAuthTicket(
		t, fixture.server.URL, hostPrivate,
		scope(authsvc.PurposePairingClaimList, ""))
	var headers http.Header
	status, body, headers = getJSONResponse(
		t,
		fixture.server.URL+"/v1/hosts/"+fixture.hostID+"/pairing/claims?tenantId="+fixture.tenantID,
		listTicket.Ticket)
	if status != http.StatusOK ||
		!strings.Contains(body, first.ClaimID) ||
		!strings.Contains(body, second.ClaimID) ||
		!strings.Contains(body, firstRequest.Ciphertext) {
		t.Fatalf("list claims status=%d body=%s", status, body)
	}
	if headers.Get("Cache-Control") != "no-store" {
		t.Fatalf("list claims Cache-Control=%q, want no-store", headers.Get("Cache-Control"))
	}

	approveTicket := issueHTTPAuthTicket(
		t, fixture.server.URL, hostPrivate,
		scope(authsvc.PurposePairingClaimApprove, fixture.deviceID))
	approval := pairing.ApproveClaimRequest{
		DeviceSigningPublicKey:   testHTTPPublicKey(t),
		DeviceAgreementPublicKey: firstRequest.Header.DeviceAgreementPublicKey,
		DeviceKeyVersion:         firstRequest.Header.DeviceKeyVersion,
		BindingVersion:           3,
		ApprovalHeader:           pairingHTTPBase64([]byte("opaque approval header")),
		ApprovalNonce:            pairingHTTPBase64(bytes.Repeat([]byte{0x51}, 12)),
		ApprovalCiphertext:       pairingHTTPBase64([]byte("opaque encrypted approval bytes plus tag")),
	}
	status, body = postJSON(
		t,
		fixture.server.URL+"/v1/hosts/"+fixture.hostID+"/pairing/claims/"+first.ClaimID+"/approve?tenantId="+fixture.tenantID,
		approveTicket.Ticket,
		approval)
	if status != http.StatusOK {
		t.Fatalf("approve status=%d body=%s", status, body)
	}

	status, body = getJSON(
		t,
		fixture.server.URL+"/v1/pairing/claims/"+first.ClaimID,
		first.ClaimAccessToken)
	if status != http.StatusOK ||
		!strings.Contains(body, `"status":"approved"`) ||
		!strings.Contains(body, approval.ApprovalCiphertext) {
		t.Fatalf("approved poll status=%d body=%s", status, body)
	}
	status, body = getJSON(
		t,
		fixture.server.URL+"/v1/pairing/claims/"+second.ClaimID,
		second.ClaimAccessToken)
	if status != http.StatusOK || !strings.Contains(body, `"status":"consumed"`) {
		t.Fatalf("sibling poll status=%d body=%s", status, body)
	}
}

func TestClaimPollAndCancelUseOnlyClaimAccessBearer(t *testing.T) {
	fixture := newHTTPAuthFixture(t)
	hostPrivate, _ := enrollHTTPHost(t, fixture)
	inviteID := "44444444-4444-4444-4444-444444444444"
	ticket := issueHTTPAuthTicket(t, fixture.server.URL, hostPrivate, authsvc.TicketScope{
		SubjectType: authsvc.SubjectHost,
		SubjectID:   fixture.hostID,
		TenantID:    fixture.tenantID,
		HostID:      fixture.hostID,
		Purpose:     authsvc.PurposePairingInviteCreate,
	})
	status, body := postJSON(t, fixture.server.URL+"/v1/pairing/invites", ticket.Ticket, map[string]interface{}{
		"tenantId": fixture.tenantID,
		"hostId":   fixture.hostID,
		"inviteId": inviteID,
		"expiresAt": time.Now().UTC().
			Add(10 * time.Minute).
			UnixMilli(),
	})
	if status != http.StatusOK {
		t.Fatalf("create invite status=%d body=%s", status, body)
	}
	created := submitHTTPClaim(
		t,
		fixture.server.URL,
		httpClaimRequest(fixture, inviteID, "55555555-5555-5555-5555-555555555555", fixture.deviceID))

	status, _ = getJSON(
		t,
		fixture.server.URL+"/v1/pairing/claims/"+created.ClaimID,
		fixture.tenantSecret)
	if status != http.StatusUnauthorized {
		t.Fatalf("tenant bearer polled claim: status=%d", status)
	}
	status, _ = getJSON(
		t,
		fixture.server.URL+"/v1/pairing/claims/"+created.ClaimID+
			"?claimAccessToken="+created.ClaimAccessToken,
		"")
	if status != http.StatusUnauthorized {
		t.Fatalf("query token polled claim: status=%d", status)
	}
	status, _ = postJSON(
		t,
		fixture.server.URL+"/v1/pairing/claims/"+created.ClaimID+"/cancel",
		"",
		map[string]string{"claimAccessToken": created.ClaimAccessToken})
	if status != http.StatusUnauthorized {
		t.Fatalf("body token cancelled claim: status=%d", status)
	}
	status, body = postJSON(
		t,
		fixture.server.URL+"/v1/pairing/claims/"+created.ClaimID+"/cancel",
		created.ClaimAccessToken,
		struct{}{})
	if status != http.StatusOK {
		t.Fatalf("cancel claim status=%d body=%s", status, body)
	}
	status, body = getJSON(
		t,
		fixture.server.URL+"/v1/pairing/claims/"+created.ClaimID,
		created.ClaimAccessToken)
	if status != http.StatusOK || !strings.Contains(body, `"status":"cancelled"`) {
		t.Fatalf("cancelled poll status=%d body=%s", status, body)
	}
}

func TestLegacyPairingRoutesAreAbsent(t *testing.T) {
	fixture := newHTTPAuthFixture(t)
	for _, path := range []string{
		"/v1/pairing/claim",
		"/v1/pairing/bind",
		"/v1/pairing/approve",
		"/v1/devices",
		"/v1/devices/revoke",
	} {
		status, body := postJSON(t, fixture.server.URL+path, "", struct{}{})
		if status != http.StatusNotFound {
			t.Fatalf("%s status=%d body=%s, want 404", path, status, body)
		}
	}
}

func TestClaimResponsesAreNotCacheableAndErrorsDoNotReflectTokens(t *testing.T) {
	fixture := newHTTPAuthFixture(t)
	const marker = "secret-claim-access-token-marker"
	request, err := http.NewRequest(
		http.MethodGet,
		fixture.server.URL+"/v1/pairing/claims/missing",
		nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	request.Header.Set("Authorization", "Bearer "+marker)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("poll claim: %v", err)
	}
	defer response.Body.Close()
	var body bytes.Buffer
	body.ReadFrom(response.Body)
	if response.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", response.Header.Get("Cache-Control"))
	}
	if strings.Contains(body.String(), marker) {
		t.Fatalf("claim error reflected bearer: %s", body.String())
	}
}

func TestHostPairingManagementRoutesUsePurposeBoundTickets(t *testing.T) {
	fixture := newHTTPAuthFixture(t)
	hostPrivate, _ := enrollHTTPHost(t, fixture)
	service := pairing.NewService(fixture.store)
	scope := func(purpose string, deviceID string) authsvc.TicketScope {
		return authsvc.TicketScope{
			SubjectType: authsvc.SubjectHost,
			SubjectID:   fixture.hostID,
			TenantID:    fixture.tenantID,
			HostID:      fixture.hostID,
			DeviceID:    deviceID,
			Purpose:     purpose,
		}
	}

	cancelledInviteID := "44444444-4444-4444-4444-444444444445"
	if err := service.CreateInvite(
		fixture.tenantID,
		fixture.hostID,
		cancelledInviteID,
		time.Now().UTC().Add(9*time.Minute)); err != nil {
		t.Fatalf("create cancelled invite: %v", err)
	}
	cancelTicket := issueHTTPAuthTicket(
		t,
		fixture.server.URL,
		hostPrivate,
		scope(authsvc.PurposePairingInviteCancel, ""))
	status, body := postJSON(
		t,
		fixture.server.URL+"/v1/pairing/invites/"+cancelledInviteID+
			"/cancel?tenantId="+fixture.tenantID+"&hostId="+fixture.hostID,
		cancelTicket.Ticket,
		struct{}{})
	if status != http.StatusOK || !strings.Contains(body, `"status":"cancelled"`) {
		t.Fatalf("cancel invite status=%d body=%s", status, body)
	}

	rejectedInviteID := "44444444-4444-4444-4444-444444444446"
	if err := service.CreateInvite(
		fixture.tenantID,
		fixture.hostID,
		rejectedInviteID,
		time.Now().UTC().Add(9*time.Minute)); err != nil {
		t.Fatalf("create rejected invite: %v", err)
	}
	rejectedRequest := httpClaimRequest(
		fixture,
		rejectedInviteID,
		"55555555-5555-5555-5555-555555555556",
		"device_rejected")
	rejected := submitHTTPClaim(t, fixture.server.URL, rejectedRequest)
	rejectTicket := issueHTTPAuthTicket(
		t,
		fixture.server.URL,
		hostPrivate,
		scope(authsvc.PurposePairingClaimReject, rejectedRequest.Header.DeviceID))
	status, body = postJSON(
		t,
		fixture.server.URL+"/v1/hosts/"+fixture.hostID+"/pairing/claims/"+
			rejected.ClaimID+"/reject?tenantId="+fixture.tenantID,
		rejectTicket.Ticket,
		struct{}{})
	if status != http.StatusOK || !strings.Contains(body, `"status":"rejected"`) {
		t.Fatalf("reject claim status=%d body=%s", status, body)
	}

	approvedInviteID := "44444444-4444-4444-4444-444444444447"
	if err := service.CreateInvite(
		fixture.tenantID,
		fixture.hostID,
		approvedInviteID,
		time.Now().UTC().Add(9*time.Minute)); err != nil {
		t.Fatalf("create approved invite: %v", err)
	}
	approvedRequest := httpClaimRequest(
		fixture,
		approvedInviteID,
		"55555555-5555-5555-5555-555555555557",
		fixture.deviceID)
	approved := submitHTTPClaim(t, fixture.server.URL, approvedRequest)
	approval := pairing.ApproveClaimRequest{
		TenantID:                 fixture.tenantID,
		HostID:                   fixture.hostID,
		ClaimID:                  approved.ClaimID,
		DeviceSigningPublicKey:   testHTTPPublicKey(t),
		DeviceAgreementPublicKey: approvedRequest.Header.DeviceAgreementPublicKey,
		DeviceKeyVersion:         approvedRequest.Header.DeviceKeyVersion,
		BindingVersion:           1,
		ApprovalHeader:           pairingHTTPBase64([]byte("opaque approval header")),
		ApprovalNonce:            pairingHTTPBase64(bytes.Repeat([]byte{0x51}, 12)),
		ApprovalCiphertext: pairingHTTPBase64(
			[]byte("opaque encrypted approval bytes plus tag")),
	}
	if err := service.ApproveClaim(approval); err != nil {
		t.Fatalf("approve device for management routes: %v", err)
	}

	listTicket := issueHTTPAuthTicket(
		t,
		fixture.server.URL,
		hostPrivate,
		scope(authsvc.PurposeDeviceList, ""))
	status, body = getJSON(
		t,
		fixture.server.URL+"/v1/hosts/"+fixture.hostID+
			"/devices?tenantId="+fixture.tenantID,
		listTicket.Ticket)
	if status != http.StatusOK ||
		!strings.Contains(body, `"deviceSigningPublicKey"`) ||
		!strings.Contains(body, fixture.deviceID) {
		t.Fatalf("list devices status=%d body=%s", status, body)
	}

	revokeTicket := issueHTTPAuthTicket(
		t,
		fixture.server.URL,
		hostPrivate,
		scope(authsvc.PurposeDeviceRevoke, fixture.deviceID))
	status, body = postJSON(
		t,
		fixture.server.URL+"/v1/hosts/"+fixture.hostID+"/devices/"+
			fixture.deviceID+"/revoke?tenantId="+fixture.tenantID,
		revokeTicket.Ticket,
		struct{}{})
	if status != http.StatusOK || !strings.Contains(body, `"revoked":true`) {
		t.Fatalf("revoke device status=%d body=%s", status, body)
	}
}

func submitHTTPClaim(
	t *testing.T,
	serverURL string,
	request pairing.SubmitClaimRequest,
) pairing.CreatedClaim {
	t.Helper()
	status, body := postJSON(t, serverURL+"/v1/pairing/claims", "", request)
	if status != http.StatusOK {
		t.Fatalf("submit claim status=%d body=%s", status, body)
	}
	var created pairing.CreatedClaim
	if err := json.Unmarshal([]byte(body), &created); err != nil {
		t.Fatalf("unmarshal created claim: %v", err)
	}
	if created.ClaimID == "" || created.ClaimAccessToken == "" || created.Status != pairing.ClaimPending {
		t.Fatalf("unexpected created claim: %+v", created)
	}
	return created
}

func httpClaimRequest(
	fixture httpAuthFixture,
	inviteID string,
	claimID string,
	deviceID string,
) pairing.SubmitClaimRequest {
	ciphertext := []byte("opaque encrypted claim bytes plus tag")
	return pairing.SubmitClaimRequest{
		Header: pairing.PairingClaimHeader{
			InviteID:                 inviteID,
			TenantID:                 fixture.tenantID,
			HostID:                   fixture.hostID,
			ClaimID:                  claimID,
			DeviceID:                 deviceID,
			DeviceAgreementPublicKey: pairingHTTPPublicKey(),
			DeviceKeyVersion:         1,
			ClientNonce:              pairingHTTPBase64(bytes.Repeat([]byte{0x23}, 32)),
			CiphertextLength:         int64(len(ciphertext)),
		},
		Nonce:      pairingHTTPBase64(bytes.Repeat([]byte{0x42}, 12)),
		Ciphertext: pairingHTTPBase64(ciphertext),
	}
}

func pairingHTTPPublicKey() string {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(
		elliptic.Marshal(elliptic.P256(), privateKey.X, privateKey.Y))
}

func pairingHTTPBase64(value []byte) string {
	return base64.RawURLEncoding.EncodeToString(value)
}
