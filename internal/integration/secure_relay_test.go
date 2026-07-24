package integration

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestSecureRelayVectorContainsBothEncryptedDirections(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "docs", "protocol", "test-vectors", "secure-remote-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Envelopes map[string]struct {
			FrameType  string `json:"frameType"`
			Ciphertext string `json:"ciphertext"`
		} `json:"envelopes"`
	}
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	for _, direction := range []string{"androidToWindows", "windowsToAndroid"} {
		frame, ok := vector.Envelopes[direction]
		if !ok || frame.FrameType != "session.envelope" || frame.Ciphertext == "" {
			t.Fatalf("missing encrypted %s vector", direction)
		}
	}
}
