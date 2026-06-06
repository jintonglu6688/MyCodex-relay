package security

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
)

func GenerateToken(byteCount int) (string, error) {
	if byteCount < 16 {
		byteCount = 16
	}
	buffer := make([]byte, byteCount)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

func HashSecret(secret string) (string, error) {
	if strings.TrimSpace(secret) == "" {
		return "", fmt.Errorf("secret cannot be empty")
	}
	salt, err := GenerateToken(16)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(salt + ":" + secret))
	return "sha256:" + salt + ":" + base64.RawURLEncoding.EncodeToString(digest[:]), nil
}

func VerifySecret(hash string, secret string) bool {
	parts := strings.Split(hash, ":")
	if len(parts) != 3 || parts[0] != "sha256" {
		return false
	}
	digest := sha256.Sum256([]byte(parts[1] + ":" + secret))
	actual := base64.RawURLEncoding.EncodeToString(digest[:])
	return subtle.ConstantTimeCompare([]byte(parts[2]), []byte(actual)) == 1
}

var redactionPattern = regexp.MustCompile(`(?i)(tenantSecret|oneTimePairingToken|deviceToken|payload)=\S+`)

func Redact(text string) string {
	return redactionPattern.ReplaceAllStringFunc(text, func(match string) string {
		key := strings.SplitN(match, "=", 2)[0]
		return key + "=<redacted>"
	})
}
