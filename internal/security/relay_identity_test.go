package security

import (
	"crypto/sha256"
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/mycodex/mycodex-relay/internal/protocol"
)

func TestRawECDSASignatureIsExactly64Bytes(t *testing.T) {
	signer, err := LoadOrCreateRelayIdentity(filepath.Join(t.TempDir(), "relay.identity.pk8"))
	if err != nil {
		t.Fatalf("LoadOrCreateRelayIdentity failed: %v", err)
	}

	transcript := []byte("canonical transcript")
	signature, err := signer.Sign(transcript)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		t.Fatalf("signature is not unpadded Base64Url: %v", err)
	}
	if len(raw) != 64 {
		t.Fatalf("signature length = %d, want 64", len(raw))
	}

	publicKey, err := protocol.DecodeSEC1PublicKey(signer.Public().PublicKeyBase64URL)
	if err != nil {
		t.Fatalf("DecodeSEC1PublicKey failed: %v", err)
	}
	if !protocol.VerifyRawSignature(publicKey, transcript, signature) {
		t.Fatal("signature did not verify")
	}
}

func TestRelayIdentityPersistsAcrossReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "relay.identity.pk8")
	first, err := LoadOrCreateRelayIdentity(path)
	if err != nil {
		t.Fatalf("first LoadOrCreateRelayIdentity failed: %v", err)
	}
	second, err := LoadOrCreateRelayIdentity(path)
	if err != nil {
		t.Fatalf("second LoadOrCreateRelayIdentity failed: %v", err)
	}

	if first.Public() != second.Public() {
		t.Fatalf("identity changed across reload: first=%+v second=%+v", first.Public(), second.Public())
	}

	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("Stat failed: %v", err)
		}
		if got := info.Mode().Perm(); got != 0600 {
			t.Fatalf("identity mode = %04o, want 0600", got)
		}
	}
}

func TestRelayFingerprintIsSHA256OfSEC1PublicKey(t *testing.T) {
	signer, err := LoadOrCreateRelayIdentity(filepath.Join(t.TempDir(), "relay.identity.pk8"))
	if err != nil {
		t.Fatalf("LoadOrCreateRelayIdentity failed: %v", err)
	}
	public := signer.Public()
	publicKey, err := base64.RawURLEncoding.DecodeString(public.PublicKeyBase64URL)
	if err != nil {
		t.Fatalf("public key is not unpadded Base64Url: %v", err)
	}
	digest := sha256.Sum256(publicKey)
	want := base64.RawURLEncoding.EncodeToString(digest[:])
	if public.FingerprintBase64URL != want {
		t.Fatalf("fingerprint = %q, want %q", public.FingerprintBase64URL, want)
	}
}
