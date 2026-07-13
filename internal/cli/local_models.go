package cli

type localInfoOutput struct {
	Version           string              `json:"version"`
	ConfigPath        string              `json:"configPath"`
	StatePath         string              `json:"statePath"`
	ListenHost        string              `json:"listenHost"`
	ListenPort        int                 `json:"listenPort"`
	PublicHost        string              `json:"publicHost"`
	PublicPort        int                 `json:"publicPort"`
	TLSRequired       bool                `json:"tlsRequired"`
	CertificatePath   string              `json:"certificatePath,omitempty"`
	CertificateSHA256 string              `json:"certificateSha256,omitempty"`
	RelayHost         string              `json:"relayHost"`
	RelayPort         int                 `json:"relayPort"`
	RelayURL          string              `json:"relayUrl"`
	HealthURL         string              `json:"healthUrl"`
	Tenants           []localTenantOutput `json:"tenants"`
	Secret            *localSecretOutput  `json:"secret,omitempty"`
}

type localTenantOutput struct {
	TenantID    string `json:"tenantId"`
	DisplayName string `json:"displayName"`
	Enabled     bool   `json:"enabled"`
}

type localSecretOutput struct {
	TenantID string `json:"tenantId"`
	Value    string `json:"value"`
	Source   string `json:"source"`
}
