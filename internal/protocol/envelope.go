package protocol

import "fmt"

const (
	DirectionWindowsToMobile = "windows_to_mobile"
	DirectionMobileToWindows = "mobile_to_windows"
	DirectionSystem          = "system"

	PayloadEncodingPlainJSON     = "plain-json"
	PayloadEncodingEncryptedJSON = "encrypted-json"
)

type Envelope struct {
	ProtocolVersion int     `json:"protocolVersion"`
	MessageID       string  `json:"messageId"`
	CorrelationID   *string `json:"correlationId"`
	TenantID        string  `json:"tenantId"`
	HostID          string  `json:"hostId"`
	DeviceID        string  `json:"deviceId"`
	SessionID       string  `json:"sessionId"`
	Direction       string  `json:"direction"`
	Kind            string  `json:"kind"`
	Sequence        uint64  `json:"sequence"`
	PayloadEncoding string  `json:"payloadEncoding"`
	Payload         string  `json:"payload"`
}

func (e Envelope) Validate(maxPayloadBytes int) error {
	if e.ProtocolVersion != 1 {
		return fmt.Errorf("invalid_envelope: protocolVersion must be 1")
	}
	if e.MessageID == "" {
		return fmt.Errorf("invalid_envelope: messageId is required")
	}
	if e.TenantID == "" {
		return fmt.Errorf("invalid_envelope: tenantId is required")
	}
	if e.Direction != DirectionWindowsToMobile &&
		e.Direction != DirectionMobileToWindows &&
		e.Direction != DirectionSystem {
		return fmt.Errorf("invalid_envelope: direction is invalid")
	}
	if e.Kind == "" {
		return fmt.Errorf("invalid_envelope: kind is required")
	}
	if e.PayloadEncoding != PayloadEncodingPlainJSON &&
		e.PayloadEncoding != PayloadEncodingEncryptedJSON {
		return fmt.Errorf("invalid_envelope: payloadEncoding is invalid")
	}
	if maxPayloadBytes >= 0 && len([]byte(e.Payload)) > maxPayloadBytes {
		return fmt.Errorf("message_too_large: payload exceeds limit")
	}
	return nil
}
