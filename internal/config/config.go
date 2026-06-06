package config

import (
	"encoding/json"
	"os"
)

type TLSConfig struct {
	Enabled  bool   `json:"enabled"`
	CertFile string `json:"certFile"`
	KeyFile  string `json:"keyFile"`
}

type Quota struct {
	MaxWindowsHosts          int `json:"maxWindowsHosts"`
	MaxDevicesPerHost        int `json:"maxDevicesPerHost"`
	MaxConcurrentSessions    int `json:"maxConcurrentSessions"`
	MaxMessageBytes          int `json:"maxMessageBytes"`
	MaxFileBytes             int `json:"maxFileBytes"`
	MaxFileTransfers         int `json:"maxFileTransfers"`
	PairingInvitesPerHour    int `json:"pairingInvitesPerHour"`
	PairingAttemptsPerMinute int `json:"pairingAttemptsPerMinute"`
	IdleTimeoutSeconds       int `json:"idleTimeoutSeconds"`
	SessionResumeSeconds     int `json:"sessionResumeSeconds"`
}

type Config struct {
	ListenHost   string    `json:"listenHost"`
	ListenPort   int       `json:"listenPort"`
	PublicHost   string    `json:"publicHost"`
	PublicPort   int       `json:"publicPort"`
	StatePath    string    `json:"statePath"`
	TLS          TLSConfig `json:"tls"`
	DefaultQuota Quota     `json:"defaultQuota"`
}

func Default() Config {
	return Config{
		ListenHost: "127.0.0.1",
		ListenPort: 38443,
		PublicPort: 38443,
		StatePath:  "relay-state.db",
		DefaultQuota: Quota{
			MaxWindowsHosts:          4,
			MaxDevicesPerHost:        8,
			MaxConcurrentSessions:    16,
			MaxMessageBytes:          1048576,
			MaxFileBytes:             104857600,
			MaxFileTransfers:         2,
			PairingInvitesPerHour:    30,
			PairingAttemptsPerMinute: 10,
			IdleTimeoutSeconds:       120,
			SessionResumeSeconds:     60,
		},
	}
}

func Load(path string) (Config, error) {
	cfg := Default()
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func Save(path string, cfg Config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}
