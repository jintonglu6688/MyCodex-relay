package relay

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mycodex/mycodex-relay/internal/config"
)

func TestHealthEndpoint(t *testing.T) {
	server := NewServer(config.Default())
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest("GET", "/health", nil)

	server.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}
	if recorder.Body.String() != "{\"status\":\"ok\"}\n" {
		t.Fatalf("unexpected body: %q", recorder.Body.String())
	}
}
