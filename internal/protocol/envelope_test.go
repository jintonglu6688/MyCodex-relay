package protocol

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestParseRelayFrameAcceptsOnlyStrictEncryptedEnvelope(t *testing.T) {
	frame, err := ParseRelayFrame(validEnvelope(), MaxBusinessPlaintextBytes)
	if err != nil {
		t.Fatalf("ParseRelayFrame: %v", err)
	}
	if frame.FrameType != FrameEnvelope || frame.Kind != "rpc.request" || frame.Sequence != 1 {
		t.Fatalf("unexpected frame: %+v", frame)
	}
}

func TestParseRelayFrameRejectsPlaintextAndDuplicateFields(t *testing.T) {
	plain := strings.Replace(string(validEnvelope()), `"ciphertext":"`, `"payload":"{}","ciphertext":"`, 1)
	if _, err := ParseRelayFrame([]byte(plain), MaxBusinessPlaintextBytes); err == nil {
		t.Fatal("plaintext field accepted")
	}
	duplicate := strings.Replace(string(validEnvelope()), `"frameType":`, `"frameType":"session.envelope","frameType":`, 1)
	if _, err := ParseRelayFrame([]byte(duplicate), MaxBusinessPlaintextBytes); err == nil {
		t.Fatal("duplicate field accepted")
	}
}

func TestParseRelayFrameRejectsNonCanonicalAndOversizedCiphertext(t *testing.T) {
	badSequence := strings.Replace(string(validEnvelope()), `"sequence":1`, `"sequence":01`, 1)
	if _, err := ParseRelayFrame([]byte(badSequence), MaxBusinessPlaintextBytes); err == nil {
		t.Fatal("noncanonical integer accepted")
	}
	overse := strings.Replace(string(validEnvelope()), `"ciphertext":"`+base64.RawURLEncoding.EncodeToString(make([]byte, 16))+`"`, `"ciphertext":"`+base64.RawURLEncoding.EncodeToString(make([]byte, 17))+`"`, 1)
	if _, err := ParseRelayFrame([]byte(overse), 0); err == nil {
		t.Fatal("configured ciphertext cap ignored")
	}
}

func TestWireFrameLimitUsesProtocolCap(t *testing.T) {
	if got := WireFrameLimit(32 * 1024 * 1024); got != MaxWireFrameBytes {
		t.Fatalf("limit=%d want %d", got, MaxWireFrameBytes)
	}
	if got := EffectiveMessageBytes(123); got != 123 {
		t.Fatalf("configured lower limit=%d", got)
	}
}

func validEnvelope() []byte {
	encoded := func(size int) string { return base64.RawURLEncoding.EncodeToString(make([]byte, size)) }
	return []byte(`{"protocolVersion":1,"frameType":"session.envelope","sessionId":"` + encoded(32) + `","tenantId":"tenant","hostId":"host","deviceId":"device","direction":"mobile_to_windows","kind":"rpc.request","messageId":"message","sequence":1,"createdAt":1,"payloadEncoding":"encrypted-json","nonce":"` + encoded(12) + `","ciphertext":"` + encoded(16) + `"}`)
}
