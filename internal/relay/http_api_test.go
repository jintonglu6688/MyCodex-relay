package relay

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	authsvc "github.com/mycodex/mycodex-relay/internal/auth"
	"github.com/mycodex/mycodex-relay/internal/config"
	"github.com/mycodex/mycodex-relay/internal/store"
)

func TestHTTPHostPairingAndDeviceLifecycle(t *testing.T) {
	fixture := newHTTPAuthFixture(t)
	hostPrivate, _ := enrollHTTPHost(t, fixture)
	hostScope := func(purpose string, deviceID string) authsvc.TicketScope {
		return authsvc.TicketScope{
			SubjectType: authsvc.SubjectHost,
			SubjectID:   fixture.hostID,
			TenantID:    fixture.tenantID,
			HostID:      fixture.hostID,
			DeviceID:    deviceID,
			Purpose:     purpose,
		}
	}

	inviteTicket := issueHTTPAuthTicket(
		t, fixture.server.URL, hostPrivate,
		hostScope(authsvc.PurposePairingInviteCreate, ""))
	inviteStatus, inviteBody := postJSON(t, fixture.server.URL+"/v1/pairing/invites", inviteTicket.Ticket, map[string]interface{}{
		"tenantId":   fixture.tenantID,
		"hostId":     fixture.hostID,
		"ttlSeconds": 3600,
	})
	if inviteStatus != http.StatusOK {
		t.Fatalf("unexpected invite status=%d body=%s", inviteStatus, inviteBody)
	}
	var invite struct {
		InviteID            string `json:"inviteId"`
		OneTimePairingToken string `json:"oneTimePairingToken"`
		ExpiresAt           string `json:"expiresAt"`
	}
	if err := json.Unmarshal([]byte(inviteBody), &invite); err != nil {
		t.Fatalf("unmarshal invite: %v", err)
	}
	if invite.InviteID == "" || invite.OneTimePairingToken == "" {
		t.Fatalf("missing invite fields: %+v", invite)
	}
	if _, err := time.Parse(time.RFC3339Nano, invite.ExpiresAt); err != nil {
		t.Fatalf("invalid expiresAt: %v", err)
	}

	claimStatus, claimBody := postJSON(t, fixture.server.URL+"/v1/pairing/claim", "", map[string]string{
		"tenantId":            fixture.tenantID,
		"hostId":              fixture.hostID,
		"inviteId":            invite.InviteID,
		"oneTimePairingToken": invite.OneTimePairingToken,
		"deviceId":            fixture.deviceID,
		"deviceDisplayName":   "Android",
		"devicePublicKey":     "device-key",
		"platform":            "android",
	})
	if claimStatus != http.StatusOK || !strings.Contains(claimBody, `"deviceId":"`+fixture.deviceID+`"`) {
		t.Fatalf("unexpected claim response: status=%d body=%s", claimStatus, claimBody)
	}

	approveTicket := issueHTTPAuthTicket(
		t, fixture.server.URL, hostPrivate,
		hostScope(authsvc.PurposePairingClaimApprove, fixture.deviceID))
	approveStatus, approveBody := postJSON(t, fixture.server.URL+"/v1/pairing/approve", approveTicket.Ticket, map[string]string{
		"tenantId":          fixture.tenantID,
		"hostId":            fixture.hostID,
		"deviceId":          fixture.deviceID,
		"deviceDisplayName": "Android",
		"devicePublicKey":   "device-key",
		"platform":          "android",
	})
	if approveStatus != http.StatusOK {
		t.Fatalf("unexpected approve status=%d body=%s", approveStatus, approveBody)
	}
	var approved struct {
		DeviceID    string `json:"deviceId"`
		DeviceToken string `json:"deviceToken"`
	}
	if err := json.Unmarshal([]byte(approveBody), &approved); err != nil {
		t.Fatalf("unmarshal approve: %v", err)
	}
	if approved.DeviceID != fixture.deviceID || approved.DeviceToken == "" {
		t.Fatalf("unexpected approve body: %+v", approved)
	}

	inviteTicket = issueHTTPAuthTicket(
		t, fixture.server.URL, hostPrivate,
		hostScope(authsvc.PurposePairingInviteCreate, ""))
	inviteStatus, inviteBody = postJSON(t, fixture.server.URL+"/v1/pairing/invites", inviteTicket.Ticket, map[string]interface{}{
		"tenantId":   fixture.tenantID,
		"hostId":     fixture.hostID,
		"ttlSeconds": 3600,
	})
	if inviteStatus != http.StatusOK {
		t.Fatalf("unexpected second invite status=%d body=%s", inviteStatus, inviteBody)
	}
	var bindInvite struct {
		InviteID            string `json:"inviteId"`
		OneTimePairingToken string `json:"oneTimePairingToken"`
	}
	if err := json.Unmarshal([]byte(inviteBody), &bindInvite); err != nil {
		t.Fatalf("unmarshal bind invite: %v", err)
	}
	bindStatus, bindBody := postJSON(t, fixture.server.URL+"/v1/pairing/bind", "", map[string]string{
		"tenantId":            fixture.tenantID,
		"hostId":              fixture.hostID,
		"inviteId":            bindInvite.InviteID,
		"oneTimePairingToken": bindInvite.OneTimePairingToken,
		"deviceId":            "device_b",
		"deviceDisplayName":   "Android 2",
		"devicePublicKey":     "device-key-2",
		"platform":            "android",
	})
	if bindStatus != http.StatusOK || !strings.Contains(bindBody, `"deviceToken"`) || !strings.Contains(bindBody, `"deviceId":"device_b"`) {
		t.Fatalf("unexpected bind response: status=%d body=%s", bindStatus, bindBody)
	}
	var bound struct {
		DeviceID    string `json:"deviceId"`
		DeviceToken string `json:"deviceToken"`
	}
	if err := json.Unmarshal([]byte(bindBody), &bound); err != nil {
		t.Fatalf("unmarshal bind response: %v", err)
	}

	listTicket := issueHTTPAuthTicket(
		t, fixture.server.URL, hostPrivate,
		hostScope(authsvc.PurposeDeviceList, ""))
	listStatus, listBody := getJSON(
		t,
		fixture.server.URL+"/v1/devices?tenantId="+fixture.tenantID+"&hostId="+fixture.hostID,
		listTicket.Ticket)
	if listStatus != http.StatusOK || !strings.Contains(listBody, `"deviceId":"`+fixture.deviceID+`"`) || !strings.Contains(listBody, `"deviceId":"device_b"`) || strings.Contains(listBody, approved.DeviceToken) {
		t.Fatalf("unexpected device list: status=%d body=%s", listStatus, listBody)
	}
	if !strings.Contains(listBody, `"online":false`) {
		t.Fatalf("expected offline device list, got %s", listBody)
	}

	revokeTicket := issueHTTPAuthTicket(
		t, fixture.server.URL, hostPrivate,
		hostScope(authsvc.PurposeDeviceRevoke, "device_b"))
	revokeStatus, revokeBody := postJSON(t, fixture.server.URL+"/v1/devices/revoke", revokeTicket.Ticket, map[string]string{
		"tenantId": fixture.tenantID,
		"hostId":   fixture.hostID,
		"deviceId": "device_b",
	})
	if revokeStatus != http.StatusOK || !strings.Contains(revokeBody, `"revoked":true`) {
		t.Fatalf("unexpected revoke: status=%d body=%s", revokeStatus, revokeBody)
	}
}

func TestHTTPHostEndpointRejectsMissingAuth(t *testing.T) {
	cfg := config.Default()
	cfg.StatePath = filepath.Join(t.TempDir(), "relay-state.db")
	st, err := store.Open(cfg.StatePath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()
	server := httptest.NewServer(NewServerWithStore(cfg, st).Handler())
	defer server.Close()

	status, _ := postJSON(t, server.URL+"/v1/hosts/enroll", "", map[string]interface{}{
		"tenantId":           "tenant_a",
		"hostId":             "host_a",
		"displayName":        "Windows",
		"signingPublicKey":   testHTTPPublicKey(t),
		"agreementPublicKey": testHTTPPublicKey(t),
		"keyVersion":         1,
	})
	if status != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", status)
	}
}

func testHTTPPublicKey(t *testing.T) string {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(
		elliptic.Marshal(elliptic.P256(), privateKey.X, privateKey.Y))
}

func postJSON(t *testing.T, url string, token string, body interface{}) (int, string) {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	request, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	request.Header.Set("Content-Type", "application/json")
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("post %s: %v", url, err)
	}
	defer response.Body.Close()
	buffer := new(bytes.Buffer)
	buffer.ReadFrom(response.Body)
	return response.StatusCode, buffer.String()
}

func getJSON(t *testing.T, url string, token string) (int, string) {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("get %s: %v", url, err)
	}
	defer response.Body.Close()
	buffer := new(bytes.Buffer)
	buffer.ReadFrom(response.Body)
	return response.StatusCode, buffer.String()
}
