package debug

import "testing"

func TestBuildPingPayload(t *testing.T) {
	payload := BuildPingPayload("hello")
	expected := "{\"type\":\"remote/ping\",\"value\":\"hello\"}"
	if payload != expected {
		t.Fatalf("expected %q, got %q", expected, payload)
	}
}

func TestBuildPongPayload(t *testing.T) {
	payload := BuildPongPayload("hello")
	expected := "{\"type\":\"remote/pong\",\"value\":\"hello\"}"
	if payload != expected {
		t.Fatalf("expected %q, got %q", expected, payload)
	}
}
