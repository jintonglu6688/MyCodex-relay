package protocol

import "testing"

func TestEnvelopeValidateAcceptsPingVector(t *testing.T) {
	envelope := Envelope{
		ProtocolVersion: 1,
		MessageID:       "msg_demo_ping",
		TenantID:        "tenant_demo",
		HostID:          "host_demo",
		DeviceID:        "device_demo",
		SessionID:       "session_demo",
		Direction:       DirectionMobileToWindows,
		Kind:            "rpc.request",
		Sequence:        1,
		PayloadEncoding: PayloadEncodingPlainJSON,
		Payload:         "{\"type\":\"remote/ping\",\"value\":\"hello\"}",
	}

	if err := envelope.Validate(1024); err != nil {
		t.Fatalf("expected valid envelope, got %v", err)
	}
}

func TestEnvelopeValidateRejectsWrongProtocolVersion(t *testing.T) {
	envelope := Envelope{
		ProtocolVersion: 2,
		MessageID:       "msg",
		TenantID:        "tenant_demo",
		Direction:       DirectionSystem,
		Kind:            "system.hello",
		PayloadEncoding: PayloadEncodingPlainJSON,
		Payload:         "{}",
	}

	err := envelope.Validate(1024)
	if err == nil || err.Error() != "invalid_envelope: protocolVersion must be 1" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEnvelopeValidateRejectsOversizedPayload(t *testing.T) {
	envelope := Envelope{
		ProtocolVersion: 1,
		MessageID:       "msg",
		TenantID:        "tenant_demo",
		Direction:       DirectionSystem,
		Kind:            "system.hello",
		PayloadEncoding: PayloadEncodingPlainJSON,
		Payload:         "12345",
	}

	err := envelope.Validate(4)
	if err == nil || err.Error() != "message_too_large: payload exceeds limit" {
		t.Fatalf("unexpected error: %v", err)
	}
}
