package relay

import (
	"context"
	"net"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/mycodex/mycodex-relay/internal/config"
)

func TestServeCancellationClosesActiveWebSocketsBeforeReturning(t *testing.T) {
	host, port := reserveEndpoint(t)
	cfg := config.Default()
	cfg.StatePath = filepath.Join(t.TempDir(), "relay-state.db")
	cfg.ListenHost = host
	cfg.ListenPort = port

	ctx, cancel := context.WithCancel(context.Background())
	server := NewServer(cfg)
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	waitForEndpoint(t, net.JoinHostPort(host, strconv.Itoa(port)))

	clientCtx, clientCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer clientCancel()
	conn := dialRelay(t, clientCtx, "http://"+net.JoinHostPort(host, strconv.Itoa(port)), "connection=device&tenantId=tenant&hostId=host&deviceId=device")
	defer conn.CloseNow()
	waitForActiveWebSocket(t, server)
	readDone := make(chan error, 1)
	go func() {
		_, _, err := conn.Read(clientCtx)
		readDone <- err
	}()

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve returned error during shutdown: %v", err)
		}
	case <-clientCtx.Done():
		t.Fatal("Serve did not return before the shutdown deadline")
	}

	err := <-readDone
	if websocket.CloseStatus(err) != websocket.StatusGoingAway {
		t.Fatalf("active WebSocket was not closed for server shutdown: %v", err)
	}

	server.mu.RLock()
	activeSessions := len(server.hosts) + len(server.devices)
	server.mu.RUnlock()
	if activeSessions != 0 {
		t.Fatalf("server returned with %d active WebSocket sessions", activeSessions)
	}
}

func waitForActiveWebSocket(t *testing.T, server *Server) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		server.mu.RLock()
		active := len(server.hosts) + len(server.devices)
		server.mu.RUnlock()
		if active != 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("WebSocket session did not become active")
}
