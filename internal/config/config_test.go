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
	if cfg.DefaultQuota.MaxMessageBytes != 11*1024*1024 {
		t.Fatalf("unexpected secure message limit: %d", cfg.DefaultQuota.MaxMessageBytes)
	}
}

func TestSaveAndLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "relay-config.json")
	cfg := Default()
	cfg.PublicHost = "relay.example.com"
	cfg.PublicTLS = true

	if err := Save(path, cfg); err != nil {
		t.Fatalf("Save failed: %v", err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if loaded.PublicHost != "relay.example.com" || !loaded.PublicTLS {
		t.Fatalf("unexpected public endpoint: %+v", loaded)
	}
}
