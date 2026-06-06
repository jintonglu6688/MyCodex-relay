package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"strings"
)

type Challenge struct {
	TenantID    string
	ClientNonce string
	ServerNonce string
	ChallengeID string
}

func ComputeResponse(secret string, challenge Challenge) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(challenge.TenantID))
	mac.Write([]byte("\n"))
	mac.Write([]byte(challenge.ClientNonce))
	mac.Write([]byte("\n"))
	mac.Write([]byte(challenge.ServerNonce))
	mac.Write([]byte("\n"))
	mac.Write([]byte(challenge.ChallengeID))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func VerifyResponse(secret string, challenge Challenge, response string) bool {
	expected := ComputeResponse(secret, challenge)
	return subtle.ConstantTimeCompare([]byte(expected), []byte(strings.TrimSpace(response))) == 1
}
