package security

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

func EnsureEmbeddedCertificate(certPath, keyPath, publicHost string) (string, error) {
	certExists := fileExists(certPath)
	keyExists := fileExists(keyPath)
	if certExists != keyExists {
		return "", errors.New("embedded TLS certificate and key must both exist or both be absent")
	}
	if certExists {
		return ValidateTLSCertificatePair(certPath, keyPath)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", fmt.Errorf("generate embedded TLS key: %w", err)
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return "", fmt.Errorf("generate certificate serial: %w", err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "MyCodex Embedded Relay"},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	if address := net.ParseIP(publicHost); address != nil {
		template.IPAddresses = append(template.IPAddresses, address)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return "", fmt.Errorf("create embedded TLS certificate: %w", err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", fmt.Errorf("encode embedded TLS key: %w", err)
	}
	if err := writeExclusive(keyPath, 0600, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})); err != nil {
		return "", err
	}
	if err := writeExclusive(certPath, 0644, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})); err != nil {
		_ = os.Remove(keyPath)
		return "", err
	}
	return ValidateTLSCertificatePair(certPath, keyPath)
}

func ValidateTLSCertificatePair(certPath, keyPath string) (string, error) {
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return "", fmt.Errorf("validate embedded TLS identity: %w", err)
	}
	if len(pair.Certificate) == 0 {
		return "", errors.New("validate embedded TLS identity: certificate chain is empty")
	}
	sum := sha256.Sum256(pair.Certificate[0])
	return hex.EncodeToString(sum[:]), nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func writeExclusive(path string, mode os.FileMode, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create embedded TLS identity directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("create embedded TLS identity file: %w", err)
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return fmt.Errorf("write embedded TLS identity file: %w", err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("close embedded TLS identity file: %w", err)
	}
	return nil
}
