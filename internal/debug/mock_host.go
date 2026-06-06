package debug

import "encoding/json"

type DebugPayload struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

func BuildPingPayload(value string) string {
	data, _ := json.Marshal(DebugPayload{Type: "remote/ping", Value: value})
	return string(data)
}
