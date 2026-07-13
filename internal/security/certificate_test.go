package security

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

func TestEnsureEmbeddedCertificateCreatesAndReusesIdentity(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "embedded-relay-cert.pem")
	keyPath := filepath.Join(dir, "embedded-relay-key.pem")

	first, err := EnsureEmbeddedCertificate(certPath, keyPath, "192.0.2.42")
	if err != nil {
		t.Fatalf("create embedded certificate: %v", err)
	}
	second, err := EnsureEmbeddedCertificate(certPath, keyPath, "192.0.2.43")
	if err != nil {
		t.Fatalf("reuse embedded certificate: %v", err)
	}
	if first != second || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(first) {
		t.Fatalf("unexpected fingerprints: first=%q second=%q", first, second)
	}

	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("load generated key pair: %v", err)
	}
	certificate, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatalf("parse generated certificate: %v", err)
	}
	if certificate.IsCA {
		t.Fatal("embedded certificate must not be a CA")
	}
	if !containsExtKeyUsage(certificate.ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
		t.Fatalf("expected ServerAuth EKU, got %v", certificate.ExtKeyUsage)
	}
	if err := certificate.VerifyHostname("localhost"); err != nil {
		t.Fatalf("localhost SAN missing: %v", err)
	}
	if err := certificate.VerifyHostname("127.0.0.1"); err != nil {
		t.Fatalf("IPv4 loopback SAN missing: %v", err)
	}
	if err := certificate.VerifyHostname("::1"); err != nil {
		t.Fatalf("IPv6 loopback SAN missing: %v", err)
	}
}

func TestEnsureEmbeddedCertificateRejectsPartialIdentity(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "embedded-relay-cert.pem")
	keyPath := filepath.Join(dir, "embedded-relay-key.pem")
	if err := os.WriteFile(certPath, []byte("certificate only"), 0600); err != nil {
		t.Fatalf("write partial certificate: %v", err)
	}

	if _, err := EnsureEmbeddedCertificate(certPath, keyPath, "192.0.2.42"); err == nil {
		t.Fatal("expected partial identity to fail")
	}
	if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
		t.Fatalf("partial identity must not create key, stat err=%v", err)
	}
}

func TestEnsureEmbeddedCertificateRejectsCorruptIdentity(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "embedded-relay-cert.pem")
	keyPath := filepath.Join(dir, "embedded-relay-key.pem")
	if err := os.WriteFile(certPath, []byte("not a certificate"), 0600); err != nil {
		t.Fatalf("write corrupt certificate: %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not a key")}), 0600); err != nil {
		t.Fatalf("write corrupt key: %v", err)
	}

	if _, err := EnsureEmbeddedCertificate(certPath, keyPath, "192.0.2.42"); err == nil {
		t.Fatal("expected corrupt identity to fail")
	}
}

func TestEnsureEmbeddedCertificateRejectsMismatchedKey(t *testing.T) {
	firstDir := t.TempDir()
	firstCert := filepath.Join(firstDir, "embedded-relay-cert.pem")
	firstKey := filepath.Join(firstDir, "embedded-relay-key.pem")
	if _, err := EnsureEmbeddedCertificate(firstCert, firstKey, "192.0.2.42"); err != nil {
		t.Fatalf("create first identity: %v", err)
	}
	secondDir := t.TempDir()
	secondCert := filepath.Join(secondDir, "embedded-relay-cert.pem")
	secondKey := filepath.Join(secondDir, "embedded-relay-key.pem")
	if _, err := EnsureEmbeddedCertificate(secondCert, secondKey, "192.0.2.43"); err != nil {
		t.Fatalf("create second identity: %v", err)
	}
	keyData, err := os.ReadFile(secondKey)
	if err != nil {
		t.Fatalf("read second key: %v", err)
	}
	if err := os.WriteFile(firstKey, keyData, 0600); err != nil {
		t.Fatalf("replace first key: %v", err)
	}

	if _, err := EnsureEmbeddedCertificate(firstCert, firstKey, "192.0.2.42"); err == nil {
		t.Fatal("expected mismatched key to fail")
	}
}

func containsExtKeyUsage(values []x509.ExtKeyUsage, expected x509.ExtKeyUsage) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
