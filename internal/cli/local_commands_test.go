package cli

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mycodex/mycodex-relay/internal/config"
)

func TestRunHelpListsLocalCommand(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"help"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("help failed: code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "local") {
		t.Fatalf("expected local in help output, got %q", stdout.String())
	}
}

func TestRunLocalInitWritesConfigAndPrintsJson(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "relay-config.json")
	statePath := filepath.Join(dir, "state.db")
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{
		"local", "init",
		"--config", configPath,
		"--state", statePath,
		"--listen-host", "0.0.0.0",
		"--listen-port", "38443",
		"--public-host", "192.0.2.42",
		"--public-port", "38443",
		"--json",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("local init failed: code=%d stderr=%s", code, stderr.String())
	}
	loaded, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if loaded.StatePath != statePath || loaded.ListenHost != "0.0.0.0" || loaded.ListenPort != 38443 || loaded.PublicHost != "192.0.2.42" || loaded.PublicPort != 38443 {
		t.Fatalf("unexpected config: %+v", loaded)
	}
	output := decodeLocalInfoOutput(t, stdout.String())
	if output.Version != Version ||
		output.ConfigPath != configPath ||
		output.StatePath != statePath ||
		output.ListenHost != "0.0.0.0" ||
		output.ListenPort != 38443 ||
		output.PublicHost != "192.0.2.42" ||
		output.PublicPort != 38443 ||
		output.TLSRequired ||
		output.RelayHost != "192.0.2.42" ||
		output.RelayPort != 38443 ||
		output.RelayURL != "http://192.0.2.42:38443" ||
		output.HealthURL != "http://192.0.2.42:38443/health" {
		t.Fatalf("unexpected JSON output: %+v", output)
	}
	if output.Tenants == nil || len(output.Tenants) != 0 {
		t.Fatalf("expected empty tenants array, got %#v", output.Tenants)
	}
	if output.Secret != nil {
		t.Fatalf("init should not output a secret, got %#v", output.Secret)
	}
}

func TestRunLocalInitEmbeddedTLSCreatesAndReportsStableCertificate(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "relay-config.json")
	statePath := filepath.Join(dir, "state.db")
	args := []string{
		"local", "init",
		"--config", configPath,
		"--state", statePath,
		"--listen-host", "0.0.0.0",
		"--listen-port", "38443",
		"--public-host", "192.0.2.42",
		"--public-port", "38443",
		"--internal-listen-host", "127.0.0.1",
		"--internal-listen-port", "39221",
		"--embedded-tls",
		"--json",
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	if code := Run(args, &stdout, &stderr); code != 0 {
		t.Fatalf("first embedded TLS init failed: code=%d stderr=%s", code, stderr.String())
	}
	first := decodeLocalInfoOutput(t, stdout.String())
	if !first.TLSRequired || first.RelayURL != "https://192.0.2.42:38443" {
		t.Fatalf("unexpected embedded TLS output: %+v", first)
	}
	if first.InternalListenHost != "127.0.0.1" ||
		first.InternalListenPort != 39221 ||
		first.InternalTLSRequired ||
		first.InternalRelayURL != "http://127.0.0.1:39221" ||
		first.InternalHealthURL != "http://127.0.0.1:39221/health" {
		t.Fatalf("unexpected embedded internal endpoint: %+v", first)
	}
	if !filepath.IsAbs(first.CertificatePath) || len(first.CertificateSHA256) != 64 {
		t.Fatalf("expected absolute certificate identity, got %+v", first)
	}
	loaded, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("load embedded TLS config: %v", err)
	}
	if !loaded.TLS.Enabled || loaded.TLS.CertFile != first.CertificatePath || loaded.TLS.KeyFile == "" {
		t.Fatalf("unexpected TLS config: %+v", loaded.TLS)
	}
	if loaded.InternalListenHost != "127.0.0.1" || loaded.InternalListenPort != 39221 {
		t.Fatalf("unexpected internal listener config: %+v", loaded)
	}

	stdout.Reset()
	stderr.Reset()
	if code := Run(args, &stdout, &stderr); code != 0 {
		t.Fatalf("second embedded TLS init failed: code=%d stderr=%s", code, stderr.String())
	}
	second := decodeLocalInfoOutput(t, stdout.String())
	if second.CertificatePath != first.CertificatePath || second.CertificateSHA256 != first.CertificateSHA256 {
		t.Fatalf("embedded identity changed: first=%+v second=%+v", first, second)
	}
}

func TestRunLocalInitRejectsNonLoopbackInternalListener(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"local", "init",
		"--config", filepath.Join(t.TempDir(), "relay-config.json"),
		"--internal-listen-host", "0.0.0.0",
		"--internal-listen-port", "39221",
		"--embedded-tls",
		"--json",
	}, &stdout, &stderr)

	if code != 2 || !strings.Contains(stderr.String(), "loopback") {
		t.Fatalf("expected loopback validation error, code=%d stderr=%q", code, stderr.String())
	}
}

func TestRunLocalInitRejectsIncompleteInternalListener(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"local", "init",
		"--config", filepath.Join(t.TempDir(), "relay-config.json"),
		"--internal-listen-host", "127.0.0.1",
		"--embedded-tls",
		"--json",
	}, &stdout, &stderr)

	if code != 2 || !strings.Contains(stderr.String(), "internal listener") {
		t.Fatalf("expected complete internal listener error, code=%d stderr=%q", code, stderr.String())
	}
}

func TestRunLocalInfoAndEnsureTenantReportCertificateWithoutPrivateKey(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "relay-config.json")
	statePath := filepath.Join(dir, "state.db")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := Run([]string{
		"local", "init", "--config", configPath, "--state", statePath,
		"--public-host", "192.0.2.42", "--embedded-tls", "--json",
	}, &stdout, &stderr); code != 0 {
		t.Fatalf("embedded TLS init failed: code=%d stderr=%s", code, stderr.String())
	}
	identity := decodeLocalInfoOutput(t, stdout.String())
	keyPath := filepath.Join(filepath.Dir(identity.CertificatePath), "embedded-relay-key.pem")

	for _, command := range [][]string{
		{"local", "info", "--config", configPath, "--json"},
		{"local", "ensure-tenant", "--config", configPath, "--json"},
	} {
		stdout.Reset()
		stderr.Reset()
		if code := Run(command, &stdout, &stderr); code != 0 {
			t.Fatalf("%v failed: code=%d stderr=%s", command, code, stderr.String())
		}
		output := decodeLocalInfoOutput(t, stdout.String())
		if output.CertificatePath != identity.CertificatePath || output.CertificateSHA256 != identity.CertificateSHA256 {
			t.Fatalf("%v reported a different identity: %+v", command, output)
		}
		if strings.Contains(stdout.String(), keyPath) || strings.Contains(stdout.String(), "PRIVATE KEY") {
			t.Fatalf("%v leaked private-key data: %s", command, stdout.String())
		}
	}
}

func TestRunLocalEnsureTenantCreatesOnceAndDoesNotRevealStoredSecret(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "relay-config.json")
	statePath := filepath.Join(dir, "state.db")
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	if code := Run([]string{"local", "init", "--config", configPath, "--state", statePath, "--json"}, &stdout, &stderr); code != 0 {
		t.Fatalf("local init failed: code=%d stderr=%s", code, stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"local", "ensure-tenant", "--config", configPath, "--name", "Local", "--json"}, &stdout, &stderr); code != 0 {
		t.Fatalf("local ensure-tenant failed: code=%d stderr=%s", code, stderr.String())
	}
	first := decodeLocalInfoOutput(t, stdout.String())
	if len(first.Tenants) != 1 {
		t.Fatalf("expected one tenant, got %#v", first.Tenants)
	}
	if first.Tenants[0].DisplayName != "Local" || !first.Tenants[0].Enabled {
		t.Fatalf("unexpected tenant: %#v", first.Tenants[0])
	}
	if first.Secret == nil || first.Secret.TenantID != first.Tenants[0].TenantID || first.Secret.Value == "" || first.Secret.Source != "created" {
		t.Fatalf("expected created secret in first output, got %#v", first.Secret)
	}
	firstSecret := first.Secret.Value

	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"local", "ensure-tenant", "--config", configPath, "--name", "Local", "--json"}, &stdout, &stderr); code != 0 {
		t.Fatalf("second local ensure-tenant failed: code=%d stderr=%s", code, stderr.String())
	}
	secondText := stdout.String()
	second := decodeLocalInfoOutput(t, secondText)
	if len(second.Tenants) != 1 || second.Tenants[0].TenantID != first.Tenants[0].TenantID {
		t.Fatalf("expected existing tenant only, got %#v", second.Tenants)
	}
	if second.Secret != nil {
		t.Fatalf("second run should not output old secret, got %#v", second.Secret)
	}
	if strings.Contains(secondText, firstSecret) || strings.Contains(secondText, "secretHash") || strings.Contains(secondText, "tenantSecret") {
		t.Fatalf("second run leaked stored secret data: %s", secondText)
	}

	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"local", "info", "--config", configPath, "--json"}, &stdout, &stderr); code != 0 {
		t.Fatalf("local info failed: code=%d stderr=%s", code, stderr.String())
	}
	infoText := stdout.String()
	info := decodeLocalInfoOutput(t, infoText)
	if len(info.Tenants) != 1 || info.Secret != nil || strings.Contains(infoText, firstSecret) || strings.Contains(infoText, "secretHash") {
		t.Fatalf("local info leaked secret data: %+v text=%s", info, infoText)
	}
}

func decodeLocalInfoOutput(t *testing.T, value string) localInfoOutput {
	t.Helper()
	var output localInfoOutput
	if err := json.Unmarshal([]byte(value), &output); err != nil {
		t.Fatalf("decode JSON %q: %v", value, err)
	}
	return output
}
