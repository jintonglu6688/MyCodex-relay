package protocol

import (
	"encoding/json"
	"testing"
)

func TestErrorPayloadMarshalsStableJSON(t *testing.T) {
	data, err := json.Marshal(ErrorPayload{Code: "route_not_found"})
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	if string(data) != "{\"code\":\"route_not_found\"}" {
		t.Fatalf("unexpected JSON: %s", string(data))
	}
}
