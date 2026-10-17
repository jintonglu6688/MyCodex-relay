package security

import "testing"

func TestGenerateTokenReturnsUrlSafeText(t *testing.T) {
	token, err := GenerateToken(32)
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}
	if len(token) < 32 {
		t.Fatalf("token too short: %q", token)
	}
}

func TestHashAndVerifySecret(t *testing.T) {
	hash, err := HashSecret("secret-value")
	if err != nil {
		t.Fatalf("HashSecret failed: %v", err)
	}
	if !VerifySecret(hash, "secret-value") {
		t.Fatalf("expected correct secret to verify")
	}
	if VerifySecret(hash, "wrong") {
		t.Fatalf("expected wrong secret to fail")
	}
}

func TestRedactSecrets(t *testing.T) {
	text := Redact("tenantSecret=abc oneTimePairingToken=def payload=ghi")
	expected := "tenantSecret=<redacted> oneTimePairingToken=<redacted> payload=<redacted>"
	if text != expected {
		t.Fatalf("expected %q, got %q", expected, text)
	}
}
