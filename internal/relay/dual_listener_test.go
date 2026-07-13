package relay

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mycodex/mycodex-relay/internal/config"
	"github.com/mycodex/mycodex-relay/internal/security"
)

func TestServeExposesTLSAndLoopbackInternalHealth(t *testing.T) {
	publicHost, publicPort := reserveEndpoint(t)
	internalHost, internalPort := reserveEndpoint(t)
	certPath, keyPath := testTLSIdentity(t)
	cfg := config.Default()
	cfg.ListenHost = publicHost
	cfg.ListenPort = publicPort
	cfg.PublicHost = publicHost
	cfg.PublicPort = publicPort
	cfg.InternalListenHost = internalHost
	cfg.InternalListenPort = internalPort
	cfg.TLS = config.TLSConfig{Enabled: true, CertFile: certPath, KeyFile: keyPath}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- NewServer(cfg).Serve(ctx) }()
	stopped := false
	t.Cleanup(func() {
		if !stopped {
			cancel()
			if err := <-done; err != nil {
				t.Errorf("Serve returned error: %v", err)
			}
		}
	})
	waitForEndpoint(t, net.JoinHostPort(publicHost, strconv.Itoa(publicPort)))
	waitForEndpoint(t, net.JoinHostPort(internalHost, strconv.Itoa(internalPort)))

	roots := x509.NewCertPool()
	certPEM, err := os.ReadFile(certPath)
	if err != nil || !roots.AppendCertsFromPEM(certPEM) {
		t.Fatalf("load test root: %v", err)
	}
	tlsClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs:    roots,
		MinVersion: tls.VersionTLS12,
	}}}
	assertHealth(t, tlsClient, "https://"+net.JoinHostPort(publicHost, strconv.Itoa(publicPort))+"/health")
	assertHealth(t, http.DefaultClient, "http://"+net.JoinHostPort(internalHost, strconv.Itoa(internalPort))+"/health")

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Serve returned error during shutdown: %v", err)
	}
	stopped = true
	assertEndpointAvailable(t, publicHost, publicPort)
	assertEndpointAvailable(t, internalHost, internalPort)
}

func TestServeRejectsNonLoopbackInternalListenerBeforeBinding(t *testing.T) {
	publicHost, publicPort := reserveEndpoint(t)
	certPath, keyPath := testTLSIdentity(t)
	cfg := config.Default()
	cfg.ListenHost = publicHost
	cfg.ListenPort = publicPort
	cfg.InternalListenHost = "0.0.0.0"
	cfg.InternalListenPort = publicPort + 1
	cfg.TLS = config.TLSConfig{Enabled: true, CertFile: certPath, KeyFile: keyPath}

	err := NewServer(cfg).Serve(context.Background())
	if err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("expected loopback error, got %v", err)
	}
	assertEndpointAvailable(t, publicHost, publicPort)
}

func TestServeRejectsInternalPortCollisionBeforeBinding(t *testing.T) {
	publicHost, publicPort := reserveEndpoint(t)
	certPath, keyPath := testTLSIdentity(t)
	cfg := config.Default()
	cfg.ListenHost = publicHost
	cfg.ListenPort = publicPort
	cfg.InternalListenHost = "127.0.0.1"
	cfg.InternalListenPort = publicPort
	cfg.TLS = config.TLSConfig{Enabled: true, CertFile: certPath, KeyFile: keyPath}

	err := NewServer(cfg).Serve(context.Background())
	if err == nil || !strings.Contains(err.Error(), "distinct") {
		t.Fatalf("expected distinct-port error, got %v", err)
	}
	assertEndpointAvailable(t, publicHost, publicPort)
}

func TestServeRejectsInternalListenerWithoutPublicTLSBeforeBinding(t *testing.T) {
	publicHost, publicPort := reserveEndpoint(t)
	_, internalPort := reserveEndpoint(t)
	cfg := config.Default()
	cfg.ListenHost = publicHost
	cfg.ListenPort = publicPort
	cfg.InternalListenHost = "127.0.0.1"
	cfg.InternalListenPort = internalPort
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := NewServer(cfg).Serve(ctx)
	if err == nil || !strings.Contains(err.Error(), "requires public TLS") {
		t.Fatalf("expected public TLS requirement, got %v", err)
	}
	assertEndpointAvailable(t, publicHost, publicPort)
}

func TestServeClosesPublicListenerWhenInternalBindFails(t *testing.T) {
	publicHost, publicPort := reserveEndpoint(t)
	internalListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve internal endpoint: %v", err)
	}
	defer internalListener.Close()
	_, rawInternalPort, _ := net.SplitHostPort(internalListener.Addr().String())
	internalPort, _ := strconv.Atoi(rawInternalPort)
	certPath, keyPath := testTLSIdentity(t)
	cfg := config.Default()
	cfg.ListenHost = publicHost
	cfg.ListenPort = publicPort
	cfg.InternalListenHost = "127.0.0.1"
	cfg.InternalListenPort = internalPort
	cfg.TLS = config.TLSConfig{Enabled: true, CertFile: certPath, KeyFile: keyPath}

	err = NewServer(cfg).Serve(context.Background())
	if err == nil || !strings.Contains(err.Error(), "internal listener") {
		t.Fatalf("expected internal bind error, got %v", err)
	}
	assertEndpointAvailable(t, publicHost, publicPort)
}

func reserveEndpoint(t *testing.T) (string, int) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve endpoint: %v", err)
	}
	host, rawPort, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		listener.Close()
		t.Fatalf("split endpoint: %v", err)
	}
	port, err := strconv.Atoi(rawPort)
	listener.Close()
	if err != nil {
		t.Fatalf("parse endpoint port: %v", err)
	}
	return host, port
}

func testTLSIdentity(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if _, err := security.EnsureEmbeddedCertificate(certPath, keyPath, "127.0.0.1"); err != nil {
		t.Fatalf("create TLS identity: %v", err)
	}
	return certPath, keyPath
}

func waitForEndpoint(t *testing.T, address string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		connection, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			connection.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("endpoint did not listen: %s", address)
}

func assertHealth(t *testing.T, client *http.Client, url string) {
	t.Helper()
	response, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK || string(body) != "{\"status\":\"ok\"}\n" {
		t.Fatalf("unexpected health response from %s: status=%d body=%q", url, response.StatusCode, body)
	}
}

func assertEndpointAvailable(t *testing.T, host string, port int) {
	t.Helper()
	listener, err := net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("endpoint remained bound after failure: %v", err)
	}
	listener.Close()
}
