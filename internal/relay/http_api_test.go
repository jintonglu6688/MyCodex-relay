package relay

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/mycodex/mycodex-relay/internal/config"
	"github.com/mycodex/mycodex-relay/internal/store"
	"github.com/mycodex/mycodex-relay/internal/tenant"
)

func TestHTTPHostPairingAndDeviceLifecycle(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "relay-state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()
	tenantService := tenant.NewService(st)
	created, tenantSecret, err := tenantService.Create("Alice")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	server := httptest.NewServer(NewServerWithStore(config.Default(), st).Handler())
	defer server.Close()

	registerStatus, registerBody := postJSON(t, server.URL+"/v1/hosts/register", tenantSecret, map[string]string{
		"tenantId":      created.TenantID,
		"hostId":        "host_a",
		"displayName":   "Windows",
		"hostPublicKey": "host-key",
	})
	if registerStatus != http.StatusOK || !strings.Contains(registerBody, `"hostId":"host_a"`) {
		t.Fatalf("unexpected register response: status=%d body=%s", registerStatus, registerBody)
	}

	inviteStatus, inviteBody := postJSON(t, server.URL+"/v1/pairing/invites", tenantSecret, map[string]interface{}{
		"tenantId":   created.TenantID,
		"hostId":     "host_a",
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

	claimStatus, claimBody := postJSON(t, server.URL+"/v1/pairing/claim", "", map[string]string{
		"tenantId":            created.TenantID,
		"hostId":              "host_a",
		"inviteId":            invite.InviteID,
		"oneTimePairingToken": invite.OneTimePairingToken,
		"deviceId":            "device_a",
		"deviceDisplayName":   "Android",
		"devicePublicKey":     "device-key",
		"platform":            "android",
	})
	if claimStatus != http.StatusOK || !strings.Contains(claimBody, `"deviceId":"device_a"`) {
		t.Fatalf("unexpected claim response: status=%d body=%s", claimStatus, claimBody)
	}

	approveStatus, approveBody := postJSON(t, server.URL+"/v1/pairing/approve", tenantSecret, map[string]string{
		"tenantId":          created.TenantID,
		"hostId":            "host_a",
		"deviceId":          "device_a",
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
	if approved.DeviceID != "device_a" || approved.DeviceToken == "" {
		t.Fatalf("unexpected approve body: %+v", approved)
	}

	inviteStatus, inviteBody = postJSON(t, server.URL+"/v1/pairing/invites", tenantSecret, map[string]interface{}{
		"tenantId":   created.TenantID,
		"hostId":     "host_a",
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
	bindStatus, bindBody := postJSON(t, server.URL+"/v1/pairing/bind", "", map[string]string{
		"tenantId":            created.TenantID,
		"hostId":              "host_a",
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

	listStatus, listBody := getJSON(t, server.URL+"/v1/devices?tenantId="+created.TenantID+"&hostId=host_a", tenantSecret)
	if listStatus != http.StatusOK || !strings.Contains(listBody, `"deviceId":"device_a"`) || !strings.Contains(listBody, `"deviceId":"device_b"`) || strings.Contains(listBody, approved.DeviceToken) {
		t.Fatalf("unexpected device list: status=%d body=%s", listStatus, listBody)
	}
	if !strings.Contains(listBody, `"online":false`) {
		t.Fatalf("expected offline device list before websocket connection, got %s", listBody)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	deviceConn := dialRelayWithAuth(t, ctx, server.URL, "connection=device&tenantId="+created.TenantID+"&hostId=host_a&deviceId=device_b&sessionId=device_b_session", bound.DeviceToken)
	defer deviceConn.Close(websocket.StatusNormalClosure, "")

	listStatus, listBody = getJSON(t, server.URL+"/v1/devices?tenantId="+created.TenantID+"&hostId=host_a", tenantSecret)
	if listStatus != http.StatusOK || !strings.Contains(listBody, `"deviceId":"device_b"`) || !strings.Contains(listBody, `"online":true`) {
		t.Fatalf("expected online device after websocket connection: status=%d body=%s", listStatus, listBody)
	}

	revokeStatus, revokeBody := postJSON(t, server.URL+"/v1/devices/revoke", tenantSecret, map[string]string{
		"tenantId": created.TenantID,
		"hostId":   "host_a",
		"deviceId": "device_a",
	})
	if revokeStatus != http.StatusOK || !strings.Contains(revokeBody, `"revoked":true`) {
		t.Fatalf("unexpected revoke: status=%d body=%s", revokeStatus, revokeBody)
	}
}

func TestHTTPHostEndpointRejectsMissingAuth(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "relay-state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()
	server := httptest.NewServer(NewServerWithStore(config.Default(), st).Handler())
	defer server.Close()

	status, _ := postJSON(t, server.URL+"/v1/hosts/register", "", map[string]string{
		"tenantId": "tenant_a",
		"hostId":   "host_a",
	})
	if status != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", status)
	}
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
