package cli

import (
	"bytes"
	"testing"
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
