package auth

import "testing"

func TestChallengeResponseVerifies(t *testing.T) {
	challenge := Challenge{
		TenantID:    "tenant_demo",
		ClientNonce: "client",
		ServerNonce: "server",
		ChallengeID: "challenge",
	}
	response := ComputeResponse("secret", challenge)

	if !VerifyResponse("secret", challenge, response) {
		t.Fatalf("expected response to verify")
	}
	if VerifyResponse("wrong", challenge, response) {
		t.Fatalf("expected wrong secret to fail")
	}
}
