package relay

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	authsvc "github.com/mycodex/mycodex-relay/internal/auth"
	"github.com/mycodex/mycodex-relay/internal/config"
	hostsvc "github.com/mycodex/mycodex-relay/internal/host"
	"github.com/mycodex/mycodex-relay/internal/protocol"
	"github.com/mycodex/mycodex-relay/internal/store"
	"github.com/mycodex/mycodex-relay/internal/tenant"
)

func TestMetadataUsesStableRelayIdentityAndConfiguredLimits(t *testing.T) {
	directory := t.TempDir()
	cfg := config.Default()
	cfg.StatePath = filepath.Join(directory, "relay-state.db")
	cfg.DefaultQuota.MaxMessageBytes = 7654321
	st, err := store.Open(cfg.StatePath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	var activeStore = st
	t.Cleanup(func() {
		if activeStore != nil {
			_ = activeStore.Close()
		}
	})

	first := httptest.NewServer(NewServerWithStore(cfg, st).Handler())
	status, body := getJSON(t, first.URL+"/.well-known/mycodex-relay", "")
	first.Close()
	if status != http.StatusOK {
		t.Fatalf("metadata status=%d body=%s", status, body)
	}
	var firstMetadata struct {
		ProtocolVersion       int    `json:"protocolVersion"`
		SigningPublicKey      string `json:"signingPublicKey"`
		SigningKeyFingerprint string `json:"signingKeyFingerprint"`
		ServerTime            int64  `json:"serverTime"`
		MaxRequestBytes       int    `json:"maxRequestBytes"`
		MaxMessageBytes       int    `json:"maxMessageBytes"`
	}
	if err := json.Unmarshal([]byte(body), &firstMetadata); err != nil {
		t.Fatalf("unmarshal metadata: %v", err)
	}
	if firstMetadata.ProtocolVersion != 1 ||
		firstMetadata.SigningPublicKey == "" ||
		firstMetadata.SigningKeyFingerprint == "" ||
		firstMetadata.ServerTime <= 0 ||
		firstMetadata.MaxRequestBytes != cfg.DefaultQuota.MaxMessageBytes ||
		firstMetadata.MaxMessageBytes != cfg.DefaultQuota.MaxMessageBytes {
		t.Fatalf("unexpected metadata: %+v", firstMetadata)
	}
	if _, err := os.Stat(cfg.StatePath + ".identity.pk8"); err != nil {
		t.Fatalf("Relay identity path is not Config.StatePath+.identity.pk8: %v", err)
	}

	if err := st.Close(); err != nil {
		t.Fatalf("close first store: %v", err)
	}
	activeStore = nil
	st, err = store.Open(cfg.StatePath)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	activeStore = st
	second := httptest.NewServer(NewServerWithStore(cfg, st).Handler())
	defer second.Close()
	status, body = getJSON(t, second.URL+"/.well-known/mycodex-relay", "")
	if status != http.StatusOK {
		t.Fatalf("second metadata status=%d body=%s", status, body)
	}
	var secondMetadata struct {
		SigningPublicKey      string `json:"signingPublicKey"`
		SigningKeyFingerprint string `json:"signingKeyFingerprint"`
	}
	if err := json.Unmarshal([]byte(body), &secondMetadata); err != nil {
		t.Fatalf("unmarshal second metadata: %v", err)
	}
	if secondMetadata.SigningPublicKey != firstMetadata.SigningPublicKey ||
		secondMetadata.SigningKeyFingerprint != firstMetadata.SigningKeyFingerprint {
		t.Fatalf("Relay identity changed across restart: first=%+v second=%+v", firstMetadata, secondMetadata)
	}
}

func TestMetadataCapsConfiguredMessageLimitAtSecureProtocolMaximum(t *testing.T) {
	cfg := config.Default()
	cfg.StatePath = filepath.Join(t.TempDir(), "relay-state.db")
	cfg.DefaultQuota.MaxMessageBytes = 32 * 1024 * 1024
	server := httptest.NewServer(NewServer(cfg).Handler())
	defer server.Close()
	status, body := getJSON(t, server.URL+"/.well-known/mycodex-relay", "")
	if status != http.StatusOK || !strings.Contains(body, `"maxMessageBytes":11534336`) {
		t.Fatalf("metadata did not publish protocol cap: status=%d body=%s", status, body)
	}
}

func TestHTTPHostEnrollmentAndSignedTicketFlow(t *testing.T) {
	fixture := newHTTPAuthFixture(t)
	signingPrivate, agreementPrivate := enrollHTTPHost(t, fixture)

	host, err := hostsvc.NewService(fixture.store).GetHost(fixture.tenantID, fixture.hostID)
	if err != nil {
		t.Fatalf("GetHost failed: %v", err)
	}
	if host.SigningPublicKey != encodeHTTPPublicKey(&signingPrivate.PublicKey) ||
		host.AgreementPublicKey != encodeHTTPPublicKey(&agreementPrivate.PublicKey) ||
		host.KeyVersion != 3 {
		t.Fatalf("host enrollment did not persist identity keys: %+v", host)
	}

	challengeStatus, challengeBody := postJSON(t, fixture.server.URL+"/v1/auth/challenges", "", map[string]string{
		"subjectType": "host",
		"subjectId":   fixture.hostID,
		"tenantId":    fixture.tenantID,
		"hostId":      fixture.hostID,
		"deviceId":    fixture.deviceID,
		"purpose":     "websocket_host",
	})
	if challengeStatus != http.StatusOK {
		t.Fatalf("challenge status=%d body=%s", challengeStatus, challengeBody)
	}
	var challenge authsvc.SignedChallenge
	if err := json.Unmarshal([]byte(challengeBody), &challenge); err != nil {
		t.Fatalf("unmarshal challenge: %v", err)
	}
	proofStatus, proofBody := postJSON(t, fixture.server.URL+"/v1/auth/prove", "", map[string]interface{}{
		"challenge":        challenge,
		"subjectSignature": signHTTPProof(t, signingPrivate, challenge),
	})
	if proofStatus != http.StatusOK {
		t.Fatalf("proof status=%d body=%s", proofStatus, proofBody)
	}
	var ticket authsvc.Ticket
	if err := json.Unmarshal([]byte(proofBody), &ticket); err != nil {
		t.Fatalf("unmarshal ticket: %v", err)
	}
	if len(decodeHTTPBase64(t, ticket.Ticket)) != 32 || ticket.Purpose != "websocket_host" {
		t.Fatalf("unexpected ticket: %+v", ticket)
	}
}

func issueHTTPAuthTicket(
	t *testing.T,
	serverURL string,
	privateKey *ecdsa.PrivateKey,
	scope authsvc.TicketScope,
) authsvc.Ticket {
	t.Helper()
	status, body := postJSON(t, serverURL+"/v1/auth/challenges", "", scope)
	if status != http.StatusOK {
		t.Fatalf("challenge status=%d body=%s scope=%+v", status, body, scope)
	}
	var challenge authsvc.SignedChallenge
	if err := json.Unmarshal([]byte(body), &challenge); err != nil {
		t.Fatalf("unmarshal challenge: %v", err)
	}
	status, body = postJSON(t, serverURL+"/v1/auth/prove", "", map[string]interface{}{
		"challenge":        challenge,
		"subjectSignature": signHTTPProof(t, privateKey, challenge),
	})
	if status != http.StatusOK {
		t.Fatalf("proof status=%d body=%s scope=%+v", status, body, scope)
	}
	var ticket authsvc.Ticket
	if err := json.Unmarshal([]byte(body), &ticket); err != nil {
		t.Fatalf("unmarshal ticket: %v", err)
	}
	return ticket
}

func TestTenantSecretCannotCallRuntimeEndpoint(t *testing.T) {
	fixture := newHTTPAuthFixture(t)
	enrollHTTPHost(t, fixture)

	status, body := postJSON(t, fixture.server.URL+"/v1/pairing/invites", fixture.tenantSecret, map[string]interface{}{
		"tenantId": fixture.tenantID,
		"hostId":   fixture.hostID,
	})
	if status != http.StatusUnauthorized || !strings.Contains(body, `"code":"unauthorized"`) {
		t.Fatalf("tenant bearer authorized pairing runtime call: status=%d body=%s", status, body)
	}

	wsURL := "ws" + strings.TrimPrefix(fixture.server.URL, "http") +
		"/v1/ws?connection=host&tenantId=" + fixture.tenantID +
		"&hostId=" + fixture.hostID + "&deviceId=" + fixture.deviceID
	_, response, err := websocket.Dial(t.Context(), wsURL, &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": []string{"Bearer " + fixture.tenantSecret}},
	})
	if err == nil {
		t.Fatal("tenant bearer established runtime WebSocket")
	}
	if response == nil || response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("runtime WebSocket response=%v err=%v", response, err)
	}
}

func TestAuthHTTPErrorDoesNotReflectSecretInput(t *testing.T) {
	fixture := newHTTPAuthFixture(t)
	const secretMarker = "super-secret-bearer-and-signature"
	status, body := postJSON(t, fixture.server.URL+"/v1/auth/challenges", secretMarker, map[string]string{
		"subjectType": "device",
		"subjectId":   secretMarker,
		"tenantId":    secretMarker,
		"hostId":      secretMarker,
		"deviceId":    secretMarker,
		"purpose":     "websocket",
	})
	if status == http.StatusOK {
		t.Fatalf("invalid challenge unexpectedly succeeded: %s", body)
	}
	if strings.Contains(body, secretMarker) || strings.Contains(body, "Bearer") {
		t.Fatalf("safe error reflected secret input: %s", body)
	}
}

func TestChallengeEndpointUsesConfiguredAttemptLimit(t *testing.T) {
	cfg := config.Default()
	cfg.StatePath = filepath.Join(t.TempDir(), "relay-state.db")
	cfg.DefaultQuota.PairingAttemptsPerMinute = 2
	st, err := store.Open(cfg.StatePath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()
	server := httptest.NewServer(NewServerWithStore(cfg, st).Handler())
	defer server.Close()
	request := map[string]string{
		"subjectType": "host",
		"subjectId":   "missing-host",
		"tenantId":    "missing-tenant",
		"hostId":      "missing-host",
		"deviceId":    "target-device",
		"purpose":     "websocket_host",
	}
	for attempt := 1; attempt <= 3; attempt++ {
		status, body := postJSON(t, server.URL+"/v1/auth/challenges", "", request)
		if attempt < 3 && status == http.StatusTooManyRequests {
			t.Fatalf("attempt %d was limited early: %s", attempt, body)
		}
		if attempt == 3 && (status != http.StatusTooManyRequests || !strings.Contains(body, `"code":"rate_limited"`)) {
			t.Fatalf("attempt limit not enforced: status=%d body=%s", status, body)
		}
	}
}

func TestDefaultChallengeLimitSupportsAllHostsPollingWithActionHeadroom(t *testing.T) {
	cfg := config.Default()
	server := NewServer(cfg)
	request := httptest.NewRequest(http.MethodPost, "/v1/auth/challenges", nil)
	request.RemoteAddr = "127.0.0.1:12345"
	required := cfg.DefaultQuota.MaxWindowsHosts * 60
	for attempt := 1; attempt <= required; attempt++ {
		if !server.allowChallenge(request) {
			t.Fatalf(
				"default challenge limit rejected attempt %d of %d",
				attempt,
				required,
			)
		}
	}
}

func TestReadJSONRejectsConfiguredMaxRequestBytes(t *testing.T) {
	cfg := config.Default()
	cfg.StatePath = filepath.Join(t.TempDir(), "relay-state.db")
	cfg.DefaultQuota.MaxMessageBytes = 128
	st, err := store.Open(cfg.StatePath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()
	server := httptest.NewServer(NewServerWithStore(cfg, st).Handler())
	defer server.Close()
	status, body := postJSON(t, server.URL+"/v1/auth/challenges", "", map[string]string{
		"subjectType": "host",
		"subjectId":   strings.Repeat("x", 256),
		"tenantId":    "tenant",
		"hostId":      "host",
		"deviceId":    "device",
		"purpose":     "websocket_host",
	})
	if status != http.StatusRequestEntityTooLarge || !strings.Contains(body, `"code":"request_too_large"`) {
		t.Fatalf("request limit not enforced: status=%d body=%s", status, body)
	}
}

func TestChallengeAndProofResponsesAreNotCacheable(t *testing.T) {
	cfg := config.Default()
	cfg.StatePath = filepath.Join(t.TempDir(), "relay-state.db")
	server := NewServer(cfg)
	for _, path := range []string{"/v1/auth/challenges", "/v1/auth/prove"} {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, path, strings.NewReader("{}"))
		server.Handler().ServeHTTP(recorder, request)
		if value := recorder.Header().Get("Cache-Control"); value != "no-store" {
			t.Fatalf("%s Cache-Control = %q, want no-store", path, value)
		}
	}
}

func TestChallengeLimiterBoundsTrackedSourcesAndCleansExpiredEntries(t *testing.T) {
	cfg := config.Default()
	server := NewServer(cfg)
	now := time.Now().UTC()
	for index := 0; index < maxChallengeSources; index++ {
		server.challengeAttempts[fmt.Sprintf("198.51.100.%d", index)] = challengeAttempt{
			windowStart: now,
			count:       1,
		}
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/auth/challenges", nil)
	request.RemoteAddr = "203.0.113.1:1234"
	if server.allowChallenge(request) {
		t.Fatal("new source was accepted after source cap")
	}
	server.challengeAttempts["198.51.100.0"] = challengeAttempt{
		windowStart: now.Add(-time.Minute),
		count:       1,
	}
	if !server.allowChallenge(request) {
		t.Fatal("new source was rejected after an expired source was cleaned")
	}
	if len(server.challengeAttempts) != maxChallengeSources {
		t.Fatalf("tracked sources = %d, want %d", len(server.challengeAttempts), maxChallengeSources)
	}
}

type httpAuthFixture struct {
	store        *store.Store
	relay        *Server
	server       *httptest.Server
	tenantID     string
	tenantSecret string
	hostID       string
	deviceID     string
}

func newHTTPAuthFixture(t *testing.T) httpAuthFixture {
	t.Helper()
	cfg := config.Default()
	cfg.StatePath = filepath.Join(t.TempDir(), "relay-state.db")
	st, err := store.Open(cfg.StatePath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	created, tenantSecret, err := tenant.NewService(st).Create("HTTP tenant")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	relay := NewServerWithStore(cfg, st)
	server := httptest.NewServer(relay.Handler())
	t.Cleanup(server.Close)
	return httpAuthFixture{
		store:        st,
		relay:        relay,
		server:       server,
		tenantID:     created.TenantID,
		tenantSecret: tenantSecret,
		hostID:       "22222222-2222-2222-2222-222222222222",
		deviceID:     "33333333-3333-3333-3333-333333333333",
	}
}

func enrollHTTPHost(t *testing.T, fixture httpAuthFixture) (*ecdsa.PrivateKey, *ecdsa.PrivateKey) {
	t.Helper()
	signingPrivate, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	agreementPrivate, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate agreement key: %v", err)
	}
	status, body := postJSON(t, fixture.server.URL+"/v1/hosts/enroll", fixture.tenantSecret, map[string]interface{}{
		"tenantId":           fixture.tenantID,
		"hostId":             fixture.hostID,
		"displayName":        "Windows",
		"signingPublicKey":   encodeHTTPPublicKey(&signingPrivate.PublicKey),
		"agreementPublicKey": encodeHTTPPublicKey(&agreementPrivate.PublicKey),
		"keyVersion":         3,
	})
	if status != http.StatusOK {
		t.Fatalf("enroll status=%d body=%s", status, body)
	}
	return signingPrivate, agreementPrivate
}

func signHTTPProof(t *testing.T, privateKey *ecdsa.PrivateKey, challenge authsvc.SignedChallenge) string {
	t.Helper()
	challengeTranscript := httpChallengeTranscript(t, challenge)
	relaySignature := decodeHTTPBase64(t, challenge.RelaySignature)
	var transcript []byte
	transcript = protocol.AppendString(transcript, "MYCODEX-RELAY-PROOF-V1")
	transcript = protocol.AppendInt64(transcript, 1)
	transcript = protocol.AppendField(transcript, challengeTranscript)
	transcript = protocol.AppendField(transcript, relaySignature)
	transcript = protocol.AppendString(transcript, challenge.SubjectType)
	transcript = protocol.AppendString(transcript, challenge.SubjectID)
	digest := sha256.Sum256(transcript)
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, digest[:])
	if err != nil {
		t.Fatalf("sign proof: %v", err)
	}
	raw := make([]byte, 64)
	r.FillBytes(raw[:32])
	s.FillBytes(raw[32:])
	return base64.RawURLEncoding.EncodeToString(raw)
}

func httpChallengeTranscript(t *testing.T, challenge authsvc.SignedChallenge) []byte {
	t.Helper()
	var transcript []byte
	transcript = protocol.AppendString(transcript, "MYCODEX-RELAY-CHALLENGE-V1")
	transcript = protocol.AppendInt64(transcript, int64(challenge.ProtocolVersion))
	transcript = protocol.AppendField(transcript, decodeHTTPBase64(t, challenge.RelayFingerprint))
	transcript = protocol.AppendString(transcript, challenge.ChallengeID)
	transcript = protocol.AppendField(transcript, decodeHTTPBase64(t, challenge.Challenge))
	transcript = protocol.AppendString(transcript, challenge.SubjectType)
	transcript = protocol.AppendString(transcript, challenge.SubjectID)
	transcript = protocol.AppendString(transcript, challenge.TenantID)
	transcript = protocol.AppendString(transcript, challenge.HostID)
	transcript = protocol.AppendString(transcript, challenge.DeviceID)
	transcript = protocol.AppendString(transcript, challenge.Purpose)
	transcript = protocol.AppendInt64(transcript, challenge.IssuedAt)
	return protocol.AppendInt64(transcript, challenge.ExpiresAt)
}

func encodeHTTPPublicKey(key *ecdsa.PublicKey) string {
	return base64.RawURLEncoding.EncodeToString(elliptic.Marshal(elliptic.P256(), key.X, key.Y))
}

func decodeHTTPBase64(t *testing.T, value string) []byte {
	t.Helper()
	result, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil {
		t.Fatalf("decode Base64Url: %v", err)
	}
	return result
}

func newHTTPPrivateKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}
	return privateKey
}
