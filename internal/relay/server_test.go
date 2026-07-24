package relay

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	authsvc "github.com/mycodex/mycodex-relay/internal/auth"
	"github.com/mycodex/mycodex-relay/internal/config"
	"github.com/mycodex/mycodex-relay/internal/session"
)

func TestHealthEndpoint(t *testing.T) {
	recorder := httptest.NewRecorder()
	NewServer(config.Default()).Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/health", nil))
	if recorder.Code != http.StatusOK || recorder.Body.String() != "{\"status\":\"ok\"}\n" {
		t.Fatalf("health=%d %q", recorder.Code, recorder.Body.String())
	}
}

func TestWebSocketForwardsValidatedRawUTF8Unchanged(t *testing.T) {
	server := httptest.NewServer(NewServer(config.Default()).Handler())
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	host := dialRelay(t, ctx, server.URL, "connection=host&tenantId=tenant&hostId=host&deviceId=device")
	defer host.Close(websocket.StatusNormalClosure, "")
	device := dialRelay(t, ctx, server.URL, "connection=device&tenantId=tenant&hostId=host&deviceId=device")
	defer device.Close(websocket.StatusNormalClosure, "")
	raw := secureEnvelope("tenant", "host", "device", "mobile_to_windows", "rpc.request", "opaque-message")
	if err := device.Write(ctx, websocket.MessageText, raw); err != nil {
		t.Fatal(err)
	}
	typeID, got, err := host.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if typeID != websocket.MessageText || string(got) != string(raw) {
		t.Fatalf("relay changed raw frame: %s", got)
	}
}

func TestWebSocketClosesInvalidPlaintextAndRouteUnavailable(t *testing.T) {
	server := httptest.NewServer(NewServer(config.Default()).Handler())
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	device := dialRelay(t, ctx, server.URL, "connection=device&tenantId=tenant&hostId=host&deviceId=device")
	defer device.Close(websocket.StatusNormalClosure, "")
	if err := device.Write(ctx, websocket.MessageText, []byte(`{"protocolVersion":1,"payloadEncoding":"plain-json"}`)); err != nil {
		t.Fatal(err)
	}
	_, _, err := device.Read(ctx)
	if websocket.CloseStatus(err) != closeInvalidFrame {
		t.Fatalf("plaintext close=%v", err)
	}
	device = dialRelay(t, ctx, server.URL, "connection=device&tenantId=tenant&hostId=host&deviceId=device")
	defer device.Close(websocket.StatusNormalClosure, "")
	if err := device.Write(ctx, websocket.MessageText, secureEnvelope("tenant", "host", "device", "mobile_to_windows", "rpc.request", "missing-route")); err != nil {
		t.Fatal(err)
	}
	_, _, err = device.Read(ctx)
	if websocket.CloseStatus(err) != closeRouteMissing {
		t.Fatalf("route close=%v", err)
	}
}

func TestWebSocketRejectsLegacyAndAmbiguousQuery(t *testing.T) {
	server := httptest.NewServer(NewServer(config.Default()).Handler())
	defer server.Close()
	base := "ws" + strings.TrimPrefix(server.URL, "http") + "/v1/ws?connection=device&tenantId=tenant&hostId=host&deviceId=device"
	for _, suffix := range []string{"&sessionId=legacy", "&deviceId=duplicate", "&unknown=value"} {
		_, response, err := websocket.Dial(t.Context(), base+suffix, nil)
		if err == nil || response == nil || response.StatusCode != http.StatusBadRequest {
			t.Fatalf("query %q response=%v err=%v", suffix, response, err)
		}
	}
}

func TestSameRoleReplacementCannotLeaveOldReaderCurrent(t *testing.T) {
	server := httptest.NewServer(NewServer(config.Default()).Handler())
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	host := dialRelay(t, ctx, server.URL, "connection=host&tenantId=tenant&hostId=host&deviceId=device")
	defer host.Close(websocket.StatusNormalClosure, "")
	first := dialRelay(t, ctx, server.URL, "connection=device&tenantId=tenant&hostId=host&deviceId=device")
	defer first.Close(websocket.StatusNormalClosure, "")
	second := dialRelay(t, ctx, server.URL, "connection=device&tenantId=tenant&hostId=host&deviceId=device")
	defer second.Close(websocket.StatusNormalClosure, "")
	_, _, err := first.Read(ctx)
	if websocket.CloseStatus(err) != closeReplaced {
		t.Fatalf("first replacement close=%v", err)
	}
	raw := secureEnvelope("tenant", "host", "device", "mobile_to_windows", "rpc.request", "new-generation")
	if err := second.Write(ctx, websocket.MessageText, raw); err != nil {
		t.Fatal(err)
	}
	_, got, err := host.Read(ctx)
	if err != nil || string(got) != string(raw) {
		t.Fatalf("new generation route: %v %s", err, got)
	}
}

func TestWebSocketRejectsBinaryAndRoleMismatch(t *testing.T) {
	server := httptest.NewServer(NewServer(config.Default()).Handler())
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	device := dialRelay(t, ctx, server.URL, "connection=device&tenantId=tenant&hostId=host&deviceId=device")
	defer device.Close(websocket.StatusNormalClosure, "")
	if err := device.Write(ctx, websocket.MessageBinary, []byte("x")); err != nil {
		t.Fatal(err)
	}
	_, _, err := device.Read(ctx)
	if websocket.CloseStatus(err) != closeInvalidFrame {
		t.Fatalf("binary close=%v", err)
	}
	device = dialRelay(t, ctx, server.URL, "connection=device&tenantId=tenant&hostId=host&deviceId=device")
	defer device.Close(websocket.StatusNormalClosure, "")
	if err := device.Write(ctx, websocket.MessageText, secureEnvelope("tenant", "host", "device", "windows_to_mobile", "rpc.response", "wrong-role")); err != nil {
		t.Fatal(err)
	}
	_, _, err = device.Read(ctx)
	if websocket.CloseStatus(err) != closeIdentity {
		t.Fatalf("role close=%v", err)
	}
}

func TestRevokeDetachesBothPeersAndBlocksLateRegistration(t *testing.T) {
	fixture := newHTTPAuthFixture(t)
	hostPrivate, _ := enrollHTTPHost(t, fixture)
	devicePrivate := insertSecureTestDevice(t, fixture)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	host := dialRelayWithTicket(t, ctx, fixture.server.URL, "host", fixture, hostPrivate)
	defer host.Close(websocket.StatusNormalClosure, "")
	device := dialRelayWithTicket(t, ctx, fixture.server.URL, "device", fixture, devicePrivate)
	defer device.Close(websocket.StatusNormalClosure, "")
	server := fixture.relay
	if err := server.revokeDevice(fixture.tenantID, fixture.hostID, fixture.deviceID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	key := deviceKey(fixture.tenantID, fixture.hostID, fixture.deviceID)
	server.mu.RLock()
	removed := server.hosts[key] == nil && server.devices[key] == nil
	server.mu.RUnlock()
	if !removed {
		t.Fatal("revoke left an active route")
	}
	if server.addSession(&webSocketSession{session: sessionForFixture(fixture, "device")}) {
		t.Fatal("revoked route registered after ticket consumption window")
	}
}

func dialRelayWithTicket(t *testing.T, ctx context.Context, serverURL, connection string, fixture httpAuthFixture, private *ecdsa.PrivateKey) *websocket.Conn {
	t.Helper()
	subjectType, subjectID, purpose := authsvc.SubjectHost, fixture.hostID, authsvc.PurposeWebSocketHost
	if connection == "device" {
		subjectType, subjectID, purpose = authsvc.SubjectDevice, fixture.deviceID, authsvc.PurposeWebSocketDevice
	}
	ticket := issueHTTPAuthTicket(t, serverURL, private, authsvc.TicketScope{SubjectType: subjectType, SubjectID: subjectID, TenantID: fixture.tenantID, HostID: fixture.hostID, DeviceID: fixture.deviceID, Purpose: purpose})
	url := "ws" + strings.TrimPrefix(serverURL, "http") + "/v1/ws?connection=" + connection + "&tenantId=" + fixture.tenantID + "&hostId=" + fixture.hostID + "&deviceId=" + fixture.deviceID
	conn, _, err := websocket.Dial(ctx, url, &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": []string{"Bearer " + ticket.Ticket}}})
	if err != nil {
		t.Fatalf("authenticated dial: %v", err)
	}
	return conn
}

func sessionForFixture(fixture httpAuthFixture, connection string) session.Session {
	role := session.ConnectionHost
	if connection == "device" {
		role = session.ConnectionDevice
	}
	return session.Session{TenantID: fixture.tenantID, HostID: fixture.hostID, DeviceID: fixture.deviceID, ConnectionType: role}
}

func insertSecureTestDevice(t *testing.T, fixture httpAuthFixture) *ecdsa.PrivateKey {
	t.Helper()
	private := newHTTPPrivateKey(t)
	_, err := fixture.store.DB().Exec(
		`insert into devices (tenant_id, host_id, device_id, signing_public_key, agreement_public_key, key_version, binding_version, revoked, approved_at) values (?, ?, ?, ?, ?, 1, 1, 0, ?)`,
		fixture.tenantID, fixture.hostID, fixture.deviceID, encodeHTTPPublicKey(&private.PublicKey), encodeHTTPPublicKey(&newHTTPPrivateKey(t).PublicKey), time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		t.Fatalf("insert device: %v", err)
	}
	return private
}

func dialRelay(t *testing.T, ctx context.Context, serverURL, query string) *websocket.Conn {
	t.Helper()
	conn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(serverURL, "http")+"/v1/ws?"+query, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	return conn
}
func secureEnvelope(tenant, host, device, direction, kind, messageID string) []byte {
	b64 := func(n int) string { return base64.RawURLEncoding.EncodeToString(make([]byte, n)) }
	return []byte(fmt.Sprintf(`{"protocolVersion":1,"frameType":"session.envelope","sessionId":"%s","tenantId":"%s","hostId":"%s","deviceId":"%s","direction":"%s","kind":"%s","messageId":"%s","sequence":1,"createdAt":1,"payloadEncoding":"encrypted-json","nonce":"%s","ciphertext":"%s"}`, b64(32), tenant, host, device, direction, kind, messageID, b64(12), b64(16)))
}
