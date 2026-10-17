package security

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
)

type RelayIdentity struct {
	PublicKeyBase64URL   string
	FingerprintBase64URL string
}

type RelayIdentitySigner struct {
	privateKey *ecdsa.PrivateKey
}

func LoadOrCreateRelayIdentity(path string) (*RelayIdentitySigner, error) {
	encoded, err := os.ReadFile(path)
	if err == nil {
		return parseRelayIdentity(encoded)
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read relay identity: %w", err)
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate relay identity: %w", err)
	}
	encoded, err = x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("encode relay identity: %w", err)
	}
	if err := writeIdentityAtomically(path, encoded); err != nil {
		return nil, err
	}
	return &RelayIdentitySigner{privateKey: privateKey}, nil
}

func (s *RelayIdentitySigner) Public() RelayIdentity {
	publicKey := elliptic.Marshal(elliptic.P256(), s.privateKey.X, s.privateKey.Y)
	fingerprint := sha256.Sum256(publicKey)
	return RelayIdentity{
		PublicKeyBase64URL:   base64.RawURLEncoding.EncodeToString(publicKey),
		FingerprintBase64URL: base64.RawURLEncoding.EncodeToString(fingerprint[:]),
	}
}

func (s *RelayIdentitySigner) Sign(transcript []byte) (string, error) {
	digest := sha256.Sum256(transcript)
	r, signatureS, err := ecdsa.Sign(rand.Reader, s.privateKey, digest[:])
	if err != nil {
		return "", fmt.Errorf("sign relay transcript: %w", err)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	signatureS.FillBytes(signature[32:])
	return base64.RawURLEncoding.EncodeToString(signature), nil
}

func parseRelayIdentity(encoded []byte) (*RelayIdentitySigner, error) {
	value, err := x509.ParsePKCS8PrivateKey(encoded)
	if err != nil {
		return nil, fmt.Errorf("parse relay identity: %w", err)
	}
	privateKey, ok := value.(*ecdsa.PrivateKey)
	if !ok || privateKey.Curve != elliptic.P256() {
		return nil, fmt.Errorf("relay identity must be an ECDSA P-256 private key")
	}
	return &RelayIdentitySigner{privateKey: privateKey}, nil
}

func writeIdentityAtomically(path string, encoded []byte) (resultErr error) {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create relay identity temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() {
		temporary.Close()
		if resultErr != nil {
			os.Remove(temporaryPath)
		}
	}()

	if err := temporary.Chmod(0600); err != nil {
		return fmt.Errorf("set relay identity permissions: %w", err)
	}
	if _, err := temporary.Write(encoded); err != nil {
		return fmt.Errorf("write relay identity: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync relay identity: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close relay identity: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("publish relay identity: %w", err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		return fmt.Errorf("set published relay identity permissions: %w", err)
	}
	return nil
}
