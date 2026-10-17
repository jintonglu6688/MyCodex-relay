package protocol

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	DirectionWindowsToMobile = "windows_to_mobile"
	DirectionMobileToWindows = "mobile_to_windows"

	FrameClientHello  = "session.client_hello"
	FrameServerHello  = "session.server_hello"
	FrameConfirmation = "session.confirmation"
	FrameEnvelope     = "session.envelope"

	PayloadEncodingEncryptedJSON = "encrypted-json"

	MaxBusinessPlaintextBytes = 11 * 1024 * 1024
	GCMTagBytes               = 16
	MaxCiphertextBytes        = MaxBusinessPlaintextBytes + GCMTagBytes
	MaxWireFrameBytes         = 15444672
	MaxEncryptedSequence      = uint64(math.MaxUint32)
)

var canonicalInteger = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)

// RelayFrame is the relay-visible tagged union. Ciphertext remains opaque.
type RelayFrame struct {
	ProtocolVersion int64
	FrameType       string
	SessionID       string
	TenantID        string
	HostID          string
	DeviceID        string
	Direction       string
	BindingVersion  int64
	KeyVersion      int64
	EphemeralKey    string
	Nonce           string
	CreatedAt       int64
	Signature       string
	SenderRole      string
	Confirmation    string
	Kind            string
	MessageID       string
	Sequence        uint64
	PayloadEncoding string
	Ciphertext      string
}

func EffectiveMessageBytes(configured int) int {
	if configured < 0 {
		return MaxBusinessPlaintextBytes
	}
	if configured > MaxBusinessPlaintextBytes {
		return MaxBusinessPlaintextBytes
	}
	return configured
}

func EncodedLength(size int) int {
	return 4*(size/3) + map[bool]int{true: 0, false: size%3 + 1}[size%3 == 0]
}

func WireFrameLimit(configured int) int64 {
	limit := EncodedLength(EffectiveMessageBytes(configured)+GCMTagBytes) + 64*1024
	if limit > MaxWireFrameBytes {
		return MaxWireFrameBytes
	}
	return int64(limit)
}

func ParseRelayFrame(data []byte, configuredMax int) (RelayFrame, error) {
	if len(data) == 0 || !utf8.Valid(data) {
		return RelayFrame{}, fmt.Errorf("invalid_frame")
	}
	raw, err := strictObject(data)
	if err != nil {
		return RelayFrame{}, err
	}
	frameType, err := requiredString(raw, "frameType")
	if err != nil {
		return RelayFrame{}, err
	}
	var frame RelayFrame
	frame.FrameType = frameType
	switch frameType {
	case FrameClientHello, FrameServerHello:
		err = parseHello(raw, &frame)
	case FrameConfirmation:
		err = parseConfirmation(raw, &frame)
	case FrameEnvelope:
		err = parseEnvelope(raw, configuredMax, &frame)
	default:
		err = fmt.Errorf("invalid_frame")
	}
	if err != nil {
		return RelayFrame{}, err
	}
	return frame, nil
}

func strictObject(data []byte) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	first, err := decoder.Token()
	if err != nil {
		return nil, fmt.Errorf("invalid_frame")
	}
	if delimiter, ok := first.(json.Delim); !ok || delimiter != '{' {
		return nil, fmt.Errorf("invalid_frame")
	}
	values := make(map[string]json.RawMessage)
	for decoder.More() {
		name, err := decoder.Token()
		if err != nil {
			return nil, fmt.Errorf("invalid_frame")
		}
		key, ok := name.(string)
		if !ok || values[key] != nil {
			return nil, fmt.Errorf("invalid_frame")
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, fmt.Errorf("invalid_frame")
		}
		values[key] = value
	}
	if end, err := decoder.Token(); err != nil || end != json.Delim('}') {
		return nil, fmt.Errorf("invalid_frame")
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, fmt.Errorf("invalid_frame")
	}
	return values, nil
}

func requireKeys(values map[string]json.RawMessage, keys ...string) error {
	if len(values) != len(keys) {
		return fmt.Errorf("invalid_frame")
	}
	for _, key := range keys {
		if values[key] == nil {
			return fmt.Errorf("invalid_frame")
		}
	}
	return nil
}

func parseHello(values map[string]json.RawMessage, frame *RelayFrame) error {
	if err := requireKeys(values, "protocolVersion", "frameType", "sessionId", "tenantId", "hostId", "deviceId", "direction", "bindingVersion", "keyVersion", "ephemeralPublicKey", "nonce", "createdAt", "signature"); err != nil {
		return err
	}
	if err := parseRoute(values, frame); err != nil {
		return err
	}
	var err error
	if frame.BindingVersion, err = positiveInt(values, "bindingVersion"); err != nil {
		return err
	}
	if frame.KeyVersion, err = positiveInt(values, "keyVersion"); err != nil {
		return err
	}
	if frame.EphemeralKey, err = requiredString(values, "ephemeralPublicKey"); err != nil {
		return err
	}
	if frame.Nonce, err = requiredString(values, "nonce"); err != nil {
		return err
	}
	if frame.CreatedAt, err = nonnegativeInt(values, "createdAt"); err != nil {
		return err
	}
	if frame.Signature, err = requiredString(values, "signature"); err != nil {
		return err
	}
	if !validBase64(frame.EphemeralKey, 65) {
		return fmt.Errorf("invalid_frame")
	}
	if _, err := DecodeSEC1PublicKey(frame.EphemeralKey); err != nil {
		return fmt.Errorf("invalid_frame")
	}
	if !validBase64(frame.Nonce, 32) || !validBase64(frame.Signature, 64) {
		return fmt.Errorf("invalid_frame")
	}
	if (frame.FrameType == FrameClientHello && frame.Direction != DirectionMobileToWindows) ||
		(frame.FrameType == FrameServerHello && frame.Direction != DirectionWindowsToMobile) {
		return fmt.Errorf("invalid_frame")
	}
	return nil
}

func parseConfirmation(values map[string]json.RawMessage, frame *RelayFrame) error {
	if err := requireKeys(values, "protocolVersion", "frameType", "sessionId", "tenantId", "hostId", "deviceId", "direction", "senderRole", "confirmation"); err != nil {
		return err
	}
	if err := parseRoute(values, frame); err != nil {
		return err
	}
	var err error
	if frame.SenderRole, err = requiredString(values, "senderRole"); err != nil {
		return err
	}
	if frame.Confirmation, err = requiredString(values, "confirmation"); err != nil {
		return err
	}
	if !validBase64(frame.Confirmation, 32) ||
		(frame.SenderRole == "android" && frame.Direction != DirectionMobileToWindows) ||
		(frame.SenderRole == "windows" && frame.Direction != DirectionWindowsToMobile) ||
		(frame.SenderRole != "android" && frame.SenderRole != "windows") {
		return fmt.Errorf("invalid_frame")
	}
	return nil
}

func parseEnvelope(values map[string]json.RawMessage, configuredMax int, frame *RelayFrame) error {
	if err := requireKeys(values, "protocolVersion", "frameType", "sessionId", "tenantId", "hostId", "deviceId", "direction", "kind", "messageId", "sequence", "createdAt", "payloadEncoding", "nonce", "ciphertext"); err != nil {
		return err
	}
	if err := parseRoute(values, frame); err != nil {
		return err
	}
	var err error
	if frame.Kind, err = requiredString(values, "kind"); err != nil {
		return err
	}
	if frame.MessageID, err = identifier(values, "messageId"); err != nil {
		return err
	}
	if frame.Sequence, err = boundedUint(values, "sequence", 1, MaxEncryptedSequence); err != nil {
		return err
	}
	if frame.CreatedAt, err = nonnegativeInt(values, "createdAt"); err != nil {
		return err
	}
	if frame.PayloadEncoding, err = requiredString(values, "payloadEncoding"); err != nil {
		return err
	}
	if frame.Nonce, err = requiredString(values, "nonce"); err != nil {
		return err
	}
	if frame.Ciphertext, err = requiredString(values, "ciphertext"); err != nil {
		return err
	}
	if frame.PayloadEncoding != PayloadEncodingEncryptedJSON || !validBase64(frame.Nonce, 12) {
		return fmt.Errorf("invalid_frame")
	}
	ciphertext, ok := decodeBase64(frame.Ciphertext)
	if !ok || len(ciphertext) < GCMTagBytes || len(ciphertext) > EffectiveMessageBytes(configuredMax)+GCMTagBytes {
		return fmt.Errorf("invalid_frame")
	}
	if (frame.Direction == DirectionMobileToWindows && frame.Kind != "rpc.request") ||
		(frame.Direction == DirectionWindowsToMobile && frame.Kind != "rpc.response" && frame.Kind != "event") {
		return fmt.Errorf("invalid_frame")
	}
	return nil
}

func parseRoute(values map[string]json.RawMessage, frame *RelayFrame) error {
	var err error
	if frame.ProtocolVersion, err = positiveInt(values, "protocolVersion"); err != nil || frame.ProtocolVersion != 1 {
		return fmt.Errorf("invalid_frame")
	}
	if frame.SessionID, err = requiredString(values, "sessionId"); err != nil {
		return err
	}
	if frame.TenantID, err = identifier(values, "tenantId"); err != nil {
		return err
	}
	if frame.HostID, err = identifier(values, "hostId"); err != nil {
		return err
	}
	if frame.DeviceID, err = identifier(values, "deviceId"); err != nil {
		return err
	}
	if frame.Direction, err = requiredString(values, "direction"); err != nil {
		return err
	}
	if !validBase64(frame.SessionID, 32) || (frame.Direction != DirectionMobileToWindows && frame.Direction != DirectionWindowsToMobile) {
		return fmt.Errorf("invalid_frame")
	}
	return nil
}

func requiredString(values map[string]json.RawMessage, key string) (string, error) {
	raw := values[key]
	var value string
	if len(raw) == 0 || json.Unmarshal(raw, &value) != nil || !utf8.ValidString(value) || value == "" {
		return "", fmt.Errorf("invalid_frame")
	}
	return value, nil
}

func identifier(values map[string]json.RawMessage, key string) (string, error) {
	value, err := requiredString(values, key)
	if err != nil || len([]byte(value)) > 128 || strings.TrimSpace(value) != value {
		return "", fmt.Errorf("invalid_frame")
	}
	return value, nil
}

func positiveInt(values map[string]json.RawMessage, key string) (int64, error) {
	return boundedInt(values, key, 1, math.MaxInt64)
}
func nonnegativeInt(values map[string]json.RawMessage, key string) (int64, error) {
	return boundedInt(values, key, 0, math.MaxInt64)
}
func boundedInt(values map[string]json.RawMessage, key string, minimum int64, maximum int64) (int64, error) {
	raw := string(values[key])
	if !canonicalInteger.MatchString(raw) {
		return 0, fmt.Errorf("invalid_frame")
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value < minimum || value > maximum {
		return 0, fmt.Errorf("invalid_frame")
	}
	return value, nil
}
func boundedUint(values map[string]json.RawMessage, key string, minimum uint64, maximum uint64) (uint64, error) {
	raw := string(values[key])
	if !canonicalInteger.MatchString(raw) {
		return 0, fmt.Errorf("invalid_frame")
	}
	value, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || value < minimum || value > maximum {
		return 0, fmt.Errorf("invalid_frame")
	}
	return value, nil
}
func decodeBase64(value string) ([]byte, bool) {
	if strings.Contains(value, "=") {
		return nil, false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	return decoded, err == nil && base64.RawURLEncoding.EncodeToString(decoded) == value
}
func validBase64(value string, length int) bool {
	decoded, ok := decodeBase64(value)
	return ok && len(decoded) == length
}
