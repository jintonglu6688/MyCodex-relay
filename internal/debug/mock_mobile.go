package debug

import "encoding/json"

func BuildPongPayload(value string) string {
	data, _ := json.Marshal(DebugPayload{Type: "remote/pong", Value: value})
	return string(data)
}
