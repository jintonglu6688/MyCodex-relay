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
	"testing"

	"github.com/mycodex/mycodex-relay/internal/config"
	"github.com/mycodex/mycodex-relay/internal/store"
)

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
	status, body, _ := getJSONResponse(t, url, token)
	return status, body
}

func getJSONResponse(
	t *testing.T,
	url string,
	token string,
) (int, string, http.Header) {
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
	return response.StatusCode, buffer.String(), response.Header.Clone()
}
