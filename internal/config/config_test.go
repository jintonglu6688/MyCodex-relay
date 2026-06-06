package config

import (
	"path/filepath"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := Default()
	if cfg.ListenHost != "127.0.0.1" {
		t.Fatalf("unexpected listen host: %s", cfg.ListenHost)
	}
	if cfg.ListenPort != 38443 {
		t.Fatalf("unexpected listen port: %d", cfg.ListenPort)
	}
	if cfg.DefaultQuota.MaxDevicesPerHost != 8 {
		t.Fatalf("unexpected max devices: %d", cfg.DefaultQuota.MaxDevicesPerHost)
	}
}

func TestSaveAndLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "relay-config.json")
	cfg := Default()
	cfg.PublicHost = "relay.example.com"

	if err := Save(path, cfg); err != nil {
		t.Fatalf("Save failed: %v", err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if loaded.PublicHost != "relay.example.com" {
		t.Fatalf("unexpected public host: %s", loaded.PublicHost)
	}
}
