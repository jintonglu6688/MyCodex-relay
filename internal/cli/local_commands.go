package cli

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/mycodex/mycodex-relay/internal/config"
	"github.com/mycodex/mycodex-relay/internal/tenant"
)

func runLocal(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stdout, "local commands: init, info, ensure-tenant")
		return 0
	}

	switch args[0] {
	case "init":
		return runLocalInit(args[1:], stdout, stderr)
	case "info":
		return runLocalInfo(args[1:], stdout, stderr)
	case "ensure-tenant":
		return runLocalEnsureTenant(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown local command: %s\n", args[0])
		return 2
	}
}

func runLocalInit(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := newFlagSet("local init", stderr)
	configPath := flags.String("config", "relay-config.json", "config path")
	statePath := flags.String("state", "", "state path")
	listenHost := flags.String("listen-host", "", "listen host")
	listenPort := flags.String("listen-port", "", "listen port")
	publicHost := flags.String("public-host", "", "public host")
	publicPort := flags.String("public-port", "", "public port")
	jsonOutput := flags.Bool("json", false, "write machine-readable JSON")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if !*jsonOutput {
		fmt.Fprintln(stderr, "--json is required")
		return 2
	}

	cfg := config.Default()
	if *statePath != "" {
		cfg.StatePath = *statePath
	}
	if *listenHost != "" {
		cfg.ListenHost = *listenHost
	}
	if *listenPort != "" {
		port, err := parsePort(*listenPort)
		if err != nil {
			fmt.Fprintf(stderr, "invalid listen port: %v\n", err)
			return 2
		}
		cfg.ListenPort = port
	}
	if *publicHost != "" {
		cfg.PublicHost = *publicHost
	}
	if *publicPort != "" {
		port, err := parsePort(*publicPort)
		if err != nil {
			fmt.Fprintf(stderr, "invalid public port: %v\n", err)
			return 2
		}
		cfg.PublicPort = port
	}
	if err := ensureParentDir(*configPath); err != nil {
		fmt.Fprintf(stderr, "create config directory: %v\n", err)
		return 1
	}
	if err := ensureParentDir(cfg.StatePath); err != nil {
		fmt.Fprintf(stderr, "create state directory: %v\n", err)
		return 1
	}
	if err := config.Save(*configPath, cfg); err != nil {
		fmt.Fprintf(stderr, "write config: %v\n", err)
		return 1
	}

	return writeLocalInfoJSON(stdout, localInfoFromConfig(*configPath, cfg, nil, nil))
}

func runLocalInfo(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := newFlagSet("local info", stderr)
	configPath := flags.String("config", "relay-config.json", "config path")
	jsonOutput := flags.Bool("json", false, "write machine-readable JSON")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if !*jsonOutput {
		fmt.Fprintln(stderr, "--json is required")
		return 2
	}

	cfg, service, closeStore, code := openTenantService(*configPath, stderr)
	if code != 0 {
		return code
	}
	defer closeStore()
	tenants, err := service.List()
	if err != nil {
		fmt.Fprintf(stderr, "list tenants: %v\n", err)
		return 1
	}
	return writeLocalInfoJSON(stdout, localInfoFromConfig(*configPath, cfg, tenants, nil))
}

func runLocalEnsureTenant(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := newFlagSet("local ensure-tenant", stderr)
	configPath := flags.String("config", "relay-config.json", "config path")
	name := flags.String("name", "Local", "tenant display name")
	jsonOutput := flags.Bool("json", false, "write machine-readable JSON")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if !*jsonOutput {
		fmt.Fprintln(stderr, "--json is required")
		return 2
	}

	cfg, service, closeStore, code := openTenantService(*configPath, stderr)
	if code != 0 {
		return code
	}
	defer closeStore()
	tenants, err := service.List()
	if err != nil {
		fmt.Fprintf(stderr, "list tenants: %v\n", err)
		return 1
	}
	var secret *localSecretOutput
	if len(tenants) == 0 {
		created, value, err := service.Create(*name)
		if err != nil {
			fmt.Fprintf(stderr, "create tenant: %v\n", err)
			return 1
		}
		tenants = append(tenants, created)
		secret = &localSecretOutput{
			TenantID: created.TenantID,
			Value:    value,
			Source:   "created",
		}
	}
	return writeLocalInfoJSON(stdout, localInfoFromConfig(*configPath, cfg, tenants, secret))
}

func localInfoFromConfig(configPath string, cfg config.Config, tenants []tenant.Tenant, secret *localSecretOutput) localInfoOutput {
	host, port := publicEndpoint(cfg)
	output := localInfoOutput{
		Version:     Version,
		ConfigPath:  configPath,
		StatePath:   cfg.StatePath,
		ListenHost:  cfg.ListenHost,
		ListenPort:  cfg.ListenPort,
		PublicHost:  cfg.PublicHost,
		PublicPort:  cfg.PublicPort,
		TLSRequired: cfg.TLS.Enabled,
		RelayHost:   host,
		RelayPort:   port,
		RelayURL:    relayURL(cfg, host, port),
		Tenants:     make([]localTenantOutput, 0, len(tenants)),
		Secret:      secret,
	}
	output.HealthURL = output.RelayURL + "/health"
	for _, item := range tenants {
		output.Tenants = append(output.Tenants, localTenantOutput{
			TenantID:    item.TenantID,
			DisplayName: item.DisplayName,
			Enabled:     item.Enabled,
		})
	}
	return output
}

func writeLocalInfoJSON(stdout io.Writer, output localInfoOutput) int {
	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		fmt.Fprintf(stdout, "{}\n")
		return 1
	}
	fmt.Fprintln(stdout, string(data))
	return 0
}
