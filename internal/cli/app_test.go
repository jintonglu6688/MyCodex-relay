package cli

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mycodex/mycodex-relay/internal/config"
)

func TestRunVersionPrintsName(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := Run([]string{"version"}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d; stderr=%s", exitCode, stderr.String())
	}
	if stdout.String() != "mycodex-relay dev\n" {
		t.Fatalf("unexpected stdout: %q", stdout.String())
	}
}

func TestRunUnknownCommandFails(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := Run([]string{"unknown"}, &stdout, &stderr)

	if exitCode != 2 {
		t.Fatalf("expected exit code 2, got %d", exitCode)
	}
	if stderr.String() != "unknown command: unknown\n" {
		t.Fatalf("unexpected stderr: %q", stderr.String())
	}
}

func TestRunHelpListsCoreCommands(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := Run([]string{"help"}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d; stderr=%s", exitCode, stderr.String())
	}
	expected := "commands: help, version, configure, serve, info, local, tenant, debug\n"
	if stdout.String() != expected {
		t.Fatalf("expected %q, got %q", expected, stdout.String())
	}
}

func TestRunConfigureWritesConfigWithOverrides(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "relay-config.json")
	statePath := filepath.Join(dir, "state.db")
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := Run([]string{
		"configure",
		"--config", configPath,
		"--state", statePath,
		"--listen-host", "0.0.0.0",
		"--listen-port", "39000",
		"--public-host", "relay.example.com",
		"--public-port", "443",
	}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d; stderr=%s", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "configPath="+configPath) {
		t.Fatalf("expected config path in stdout, got %q", stdout.String())
	}
	loaded, err := loadConfigForTest(configPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if loaded.ListenHost != "0.0.0.0" || loaded.ListenPort != 39000 || loaded.PublicHost != "relay.example.com" || loaded.PublicPort != 443 || loaded.StatePath != statePath {
		t.Fatalf("unexpected config: %+v", loaded)
	}
}

func TestRunTenantLifecycleDoesNotPrintStoredSecrets(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "relay-config.json")
	statePath := filepath.Join(dir, "state.db")
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	if code := Run([]string{"configure", "--config", configPath, "--state", statePath, "--public-host", "relay.example.com"}, &stdout, &stderr); code != 0 {
		t.Fatalf("configure failed: code=%d stderr=%s", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"tenant", "create", "--config", configPath, "--name", "Alice"}, &stdout, &stderr); code != 0 {
		t.Fatalf("tenant create failed: code=%d stderr=%s", code, stderr.String())
	}
	createOutput := stdout.String()
	tenantID := valueFromOutput(createOutput, "tenantId")
	tenantSecret := valueFromOutput(createOutput, "tenantSecret")
	if tenantID == "" || tenantSecret == "" {
		t.Fatalf("expected tenant id and secret once, got %q", createOutput)
	}
	if strings.Count(createOutput, "tenantSecret=") != 1 {
		t.Fatalf("tenant secret should be printed exactly once, got %q", createOutput)
	}

	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"tenant", "list", "--config", configPath}, &stdout, &stderr); code != 0 {
		t.Fatalf("tenant list failed: code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), tenantID+"\tAlice\tenabled") || strings.Contains(stdout.String(), tenantSecret) {
		t.Fatalf("unexpected list output: %q", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"tenant", "show", "--config", configPath, "--tenant", tenantID}, &stdout, &stderr); code != 0 {
		t.Fatalf("tenant show failed: code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "displayName=Alice") || strings.Contains(stdout.String(), tenantSecret) || strings.Contains(stdout.String(), "secretHash") {
		t.Fatalf("unexpected show output: %q", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"tenant", "disable", "--config", configPath, "--tenant", tenantID}, &stdout, &stderr); code != 0 {
		t.Fatalf("tenant disable failed: code=%d stderr=%s", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"tenant", "enable", "--config", configPath, "--tenant", tenantID}, &stdout, &stderr); code != 0 {
		t.Fatalf("tenant enable failed: code=%d stderr=%s", code, stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"tenant", "print-connection", "--config", configPath, "--tenant", tenantID}, &stdout, &stderr); code != 0 {
		t.Fatalf("tenant print-connection failed: code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "tenantId="+tenantID) || !strings.Contains(stdout.String(), "relayHost=relay.example.com") || strings.Contains(stdout.String(), tenantSecret) || strings.Contains(stdout.String(), "tenantSecret") {
		t.Fatalf("unexpected connection output: %q", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"tenant", "rotate-secret", "--config", configPath, "--tenant", tenantID}, &stdout, &stderr); code != 0 {
		t.Fatalf("tenant rotate-secret failed: code=%d stderr=%s", code, stderr.String())
	}
	rotated := valueFromOutput(stdout.String(), "tenantSecret")
	if rotated == "" || rotated == tenantSecret || strings.Count(stdout.String(), "tenantSecret=") != 1 {
		t.Fatalf("unexpected rotate output: %q", stdout.String())
	}
}

func TestRunInfoPrintsServerAndTenantsWithoutSecrets(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "relay-config.json")
	statePath := filepath.Join(dir, "state.db")
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	if code := Run([]string{
		"configure",
		"--config", configPath,
		"--state", statePath,
		"--listen-host", "0.0.0.0",
		"--listen-port", "39000",
		"--public-host", "relay.example.com",
		"--public-port", "443",
	}, &stdout, &stderr); code != 0 {
		t.Fatalf("configure failed: code=%d stderr=%s", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"tenant", "create", "--config", configPath, "--name", "Alice"}, &stdout, &stderr); code != 0 {
		t.Fatalf("tenant create failed: code=%d stderr=%s", code, stderr.String())
	}
	createOutput := stdout.String()
	tenantID := valueFromOutput(createOutput, "tenantId")
	tenantSecret := valueFromOutput(createOutput, "tenantSecret")
	if tenantID == "" || tenantSecret == "" {
		t.Fatalf("expected tenant id and secret, got %q", createOutput)
	}

	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"info", "--config", configPath}, &stdout, &stderr); code != 0 {
		t.Fatalf("info failed: code=%d stderr=%s", code, stderr.String())
	}
	output := stdout.String()
	for _, expected := range []string{
		"MyCodex Relay\n",
		"configPath=" + configPath,
		"statePath=" + statePath,
		"listenHost=0.0.0.0",
		"listenPort=39000",
		"publicHost=relay.example.com",
		"publicPort=443",
		"tlsRequired=false",
		"relayHost=relay.example.com",
		"relayPort=443",
		"relayUrl=http://relay.example.com:443",
		"healthUrl=http://relay.example.com:443/health",
		"tenants=1",
		"tenantId=" + tenantID,
		"displayName=Alice",
		"enabled=true",
		"connectionRelayHost=relay.example.com",
		"connectionRelayPort=443",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("expected info output to contain %q, got %q", expected, output)
		}
	}
	if strings.Contains(output, tenantSecret) || strings.Contains(output, "tenantSecret") || strings.Contains(output, "secretHash") {
		t.Fatalf("info output should not print secrets, got %q", output)
	}
}

func TestRunInfoEnsureTenantCreatesDefaultTenantAndPrintsSecretOnce(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "relay-config.json")
	statePath := filepath.Join(dir, "state.db")
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	if code := Run([]string{"configure", "--config", configPath, "--state", statePath}, &stdout, &stderr); code != 0 {
		t.Fatalf("configure failed: code=%d stderr=%s", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"info", "--config", configPath, "--ensure-tenant", "--tenant-name", "Local"}, &stdout, &stderr); code != 0 {
		t.Fatalf("info failed: code=%d stderr=%s", code, stderr.String())
	}
	output := stdout.String()
	tenantID := valueFromOutput(output, "tenantId")
	tenantSecret := valueFromOutput(output, "tenantSecret")
	if tenantID == "" || tenantSecret == "" {
		t.Fatalf("expected created tenant id and secret, got %q", output)
	}
	if !strings.Contains(output, "tenants=1") || !strings.Contains(output, "displayName=Local") || !strings.Contains(output, "tenantSecretSource=created") {
		t.Fatalf("unexpected ensure tenant output: %q", output)
	}

	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"info", "--config", configPath, "--ensure-tenant", "--tenant-name", "Local"}, &stdout, &stderr); code != 0 {
		t.Fatalf("second info failed: code=%d stderr=%s", code, stderr.String())
	}
	secondOutput := stdout.String()
	if strings.Contains(secondOutput, "tenantSecret=") || strings.Contains(secondOutput, tenantSecret) || strings.Count(secondOutput, "tenantId=") != 1 {
		t.Fatalf("second info should not print or create another secret, got %q", secondOutput)
	}
}

func TestRunServeWithCanceledContextConstructsServer(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "relay-config.json")
	statePath := filepath.Join(dir, "state.db")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := Run([]string{"configure", "--config", configPath, "--state", statePath, "--listen-port", "0"}, &stdout, &stderr); code != 0 {
		t.Fatalf("configure failed: %d %s", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	ctx, cancel := canceledContextForTest()
	cancel()

	code := RunWithContext(ctx, []string{"serve", "--config", configPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("serve failed: code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "serve initialized") {
		t.Fatalf("expected serve initialized output, got %q", stdout.String())
	}
}

func TestRunDebugRejectsRemovedPlaintextPayloadCommands(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := Run([]string{"debug", "mobile"}, &stdout, &stderr); code == 0 || !strings.Contains(stderr.String(), "auth-header") {
		t.Fatalf("plaintext debug command was retained: code=%d stderr=%q", code, stderr.String())
	}
}

func TestRunDebugAuthHeaderFormatsBearerToken(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{"debug", "auth-header", "--token", "secret-value"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("debug auth-header failed: code=%d stderr=%s", code, stderr.String())
	}
	if stdout.String() != "Authorization=Bearer secret-value\n" {
		t.Fatalf("unexpected auth header output: %q", stdout.String())
	}
}

func loadConfigForTest(path string) (config.Config, error) {
	return config.Load(path)
}

func valueFromOutput(output string, key string) string {
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, key+"=") {
			return strings.TrimPrefix(line, key+"=")
		}
	}
	return ""
}

func canceledContextForTest() (context.Context, context.CancelFunc) {
	return context.WithCancel(context.Background())
}
