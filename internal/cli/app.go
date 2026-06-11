package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"

	"github.com/mycodex/mycodex-relay/internal/config"
	"github.com/mycodex/mycodex-relay/internal/debug"
	"github.com/mycodex/mycodex-relay/internal/protocol"
	"github.com/mycodex/mycodex-relay/internal/relay"
	"github.com/mycodex/mycodex-relay/internal/store"
	"github.com/mycodex/mycodex-relay/internal/tenant"
)

var Version = "dev"

func Run(args []string, stdout io.Writer, stderr io.Writer) int {
	return RunWithContext(context.Background(), args, stdout, stderr)
}

func RunWithContext(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "command required")
		return 2
	}

	switch args[0] {
	case "help":
		fmt.Fprintln(stdout, "commands: help, version, configure, serve, info, local, tenant, debug")
		return 0
	case "version":
		fmt.Fprintf(stdout, "mycodex-relay %s\n", Version)
		return 0
	case "configure":
		return runConfigure(args[1:], stdout, stderr)
	case "serve":
		return runServe(ctx, args[1:], stdout, stderr)
	case "info":
		return runInfo(args[1:], stdout, stderr)
	case "local":
		return runLocal(args[1:], stdout, stderr)
	case "tenant":
		return runTenant(args[1:], stdout, stderr)
	case "debug":
		return runDebug(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown command: %s\n", args[0])
		return 2
	}
}

func runConfigure(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := newFlagSet("configure", stderr)
	configPath := flags.String("config", "relay-config.json", "config path")
	statePath := flags.String("state", "", "state path")
	listenHost := flags.String("listen-host", "", "listen host")
	listenPort := flags.String("listen-port", "", "listen port")
	publicHost := flags.String("public-host", "", "public host")
	publicPort := flags.String("public-port", "", "public port")
	if err := flags.Parse(args); err != nil {
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
	if err := config.Save(*configPath, cfg); err != nil {
		fmt.Fprintf(stderr, "write config: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "configPath=%s\n", *configPath)
	return 0
}

func runServe(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) int {
	flags := newFlagSet("serve", stderr)
	configPath := flags.String("config", "relay-config.json", "config path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "load config: %v\n", err)
		return 1
	}
	st, err := store.Open(cfg.StatePath)
	if err != nil {
		fmt.Fprintf(stderr, "open state: %v\n", err)
		return 1
	}
	defer st.Close()
	server := relay.NewServerWithStore(cfg, st)
	fmt.Fprintf(stdout, "serve initialized configPath=%s statePath=%s\n", *configPath, cfg.StatePath)
	if ctx.Err() != nil {
		return 0
	}
	if err := server.Serve(ctx); err != nil {
		fmt.Fprintf(stderr, "serve failed: %v\n", err)
		return 1
	}
	return 0
}

func runInfo(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := newFlagSet("info", stderr)
	configPath := flags.String("config", "relay-config.json", "config path")
	ensureTenant := flags.Bool("ensure-tenant", false, "create a default tenant when none exists")
	tenantName := flags.String("tenant-name", "Local", "default tenant display name for --ensure-tenant")
	if err := flags.Parse(args); err != nil {
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
	createdTenantID := ""
	createdTenantSecret := ""
	if *ensureTenant && len(tenants) == 0 {
		created, secret, err := service.Create(*tenantName)
		if err != nil {
			fmt.Fprintf(stderr, "create tenant: %v\n", err)
			return 1
		}
		createdTenantID = created.TenantID
		createdTenantSecret = secret
		tenants = append(tenants, created)
	}
	host, port := publicEndpoint(cfg)
	relayURL := relayURL(cfg, host, port)
	fmt.Fprintln(stdout, "MyCodex Relay")
	fmt.Fprintf(stdout, "version=%s\n", Version)
	fmt.Fprintf(stdout, "configPath=%s\n", *configPath)
	fmt.Fprintf(stdout, "statePath=%s\n", cfg.StatePath)
	fmt.Fprintf(stdout, "listenHost=%s\n", cfg.ListenHost)
	fmt.Fprintf(stdout, "listenPort=%d\n", cfg.ListenPort)
	fmt.Fprintf(stdout, "publicHost=%s\n", cfg.PublicHost)
	fmt.Fprintf(stdout, "publicPort=%d\n", cfg.PublicPort)
	fmt.Fprintf(stdout, "tlsRequired=%t\n", cfg.TLS.Enabled)
	fmt.Fprintf(stdout, "relayHost=%s\n", host)
	fmt.Fprintf(stdout, "relayPort=%d\n", port)
	fmt.Fprintf(stdout, "relayUrl=%s\n", relayURL)
	fmt.Fprintf(stdout, "healthUrl=%s/health\n", relayURL)
	fmt.Fprintf(stdout, "tenants=%d\n", len(tenants))
	for _, item := range tenants {
		fmt.Fprintln(stdout)
		fmt.Fprintf(stdout, "tenantId=%s\n", item.TenantID)
		fmt.Fprintf(stdout, "displayName=%s\n", item.DisplayName)
		fmt.Fprintf(stdout, "enabled=%t\n", item.Enabled)
		fmt.Fprintf(stdout, "connectionRelayHost=%s\n", host)
		fmt.Fprintf(stdout, "connectionRelayPort=%d\n", port)
		if item.TenantID == createdTenantID {
			fmt.Fprintf(stdout, "tenantSecret=%s\n", createdTenantSecret)
			fmt.Fprintln(stdout, "tenantSecretSource=created")
		}
	}
	return 0
}

func runTenant(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stdout, "tenant commands: create, list, show, disable, enable, rotate-secret, print-connection")
		return 0
	}
	switch args[0] {
	case "create":
		return runTenantCreate(args[1:], stdout, stderr)
	case "list":
		return runTenantList(args[1:], stdout, stderr)
	case "show":
		return runTenantShow(args[1:], stdout, stderr)
	case "disable":
		return runTenantSetEnabled(args[1:], stdout, stderr, false)
	case "enable":
		return runTenantSetEnabled(args[1:], stdout, stderr, true)
	case "rotate-secret":
		return runTenantRotateSecret(args[1:], stdout, stderr)
	case "print-connection":
		return runTenantPrintConnection(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown tenant command: %s\n", args[0])
		return 2
	}
}

func runTenantCreate(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := tenantFlagSet("tenant create", stderr)
	name := flags.String("name", "", "tenant display name")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *name == "" {
		fmt.Fprintln(stderr, "tenant name is required")
		return 2
	}
	cfg, service, closeStore, code := openTenantService(*flags.configPath, stderr)
	_ = cfg
	if code != 0 {
		return code
	}
	defer closeStore()
	created, secret, err := service.Create(*name)
	if err != nil {
		fmt.Fprintf(stderr, "create tenant: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "tenantId=%s\n", created.TenantID)
	fmt.Fprintf(stdout, "tenantSecret=%s\n", secret)
	return 0
}

func runTenantList(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := tenantFlagSet("tenant list", stderr)
	if err := flags.Parse(args); err != nil {
		return 2
	}
	_, service, closeStore, code := openTenantService(*flags.configPath, stderr)
	if code != 0 {
		return code
	}
	defer closeStore()
	tenants, err := service.List()
	if err != nil {
		fmt.Fprintf(stderr, "list tenants: %v\n", err)
		return 1
	}
	for _, item := range tenants {
		state := "disabled"
		if item.Enabled {
			state = "enabled"
		}
		fmt.Fprintf(stdout, "%s\t%s\t%s\n", item.TenantID, item.DisplayName, state)
	}
	return 0
}

func runTenantShow(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := tenantFlagSet("tenant show", stderr)
	tenantID := flags.String("tenant", "", "tenant id")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *tenantID == "" {
		fmt.Fprintln(stderr, "tenant id is required")
		return 2
	}
	_, service, closeStore, code := openTenantService(*flags.configPath, stderr)
	if code != 0 {
		return code
	}
	defer closeStore()
	item, err := service.Get(*tenantID)
	if err != nil {
		fmt.Fprintf(stderr, "show tenant: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "tenantId=%s\n", item.TenantID)
	fmt.Fprintf(stdout, "displayName=%s\n", item.DisplayName)
	fmt.Fprintf(stdout, "enabled=%t\n", item.Enabled)
	fmt.Fprintf(stdout, "createdAt=%s\n", item.CreatedAt.Format("2006-01-02T15:04:05Z07:00"))
	return 0
}

func runTenantSetEnabled(args []string, stdout io.Writer, stderr io.Writer, enabled bool) int {
	flags := tenantFlagSet("tenant set-enabled", stderr)
	tenantID := flags.String("tenant", "", "tenant id")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *tenantID == "" {
		fmt.Fprintln(stderr, "tenant id is required")
		return 2
	}
	_, service, closeStore, code := openTenantService(*flags.configPath, stderr)
	if code != 0 {
		return code
	}
	defer closeStore()
	if err := service.SetEnabled(*tenantID, enabled); err != nil {
		fmt.Fprintf(stderr, "update tenant: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "tenantId=%s\n", *tenantID)
	fmt.Fprintf(stdout, "enabled=%t\n", enabled)
	return 0
}

func runTenantRotateSecret(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := tenantFlagSet("tenant rotate-secret", stderr)
	tenantID := flags.String("tenant", "", "tenant id")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *tenantID == "" {
		fmt.Fprintln(stderr, "tenant id is required")
		return 2
	}
	_, service, closeStore, code := openTenantService(*flags.configPath, stderr)
	if code != 0 {
		return code
	}
	defer closeStore()
	secret, err := service.RotateSecret(*tenantID)
	if err != nil {
		fmt.Fprintf(stderr, "rotate secret: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "tenantId=%s\n", *tenantID)
	fmt.Fprintf(stdout, "tenantSecret=%s\n", secret)
	return 0
}

func runTenantPrintConnection(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := tenantFlagSet("tenant print-connection", stderr)
	tenantID := flags.String("tenant", "", "tenant id")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *tenantID == "" {
		fmt.Fprintln(stderr, "tenant id is required")
		return 2
	}
	cfg, service, closeStore, code := openTenantService(*flags.configPath, stderr)
	if code != 0 {
		return code
	}
	defer closeStore()
	if _, err := service.Get(*tenantID); err != nil {
		fmt.Fprintf(stderr, "load tenant: %v\n", err)
		return 1
	}
	host, port := publicEndpoint(cfg)
	fmt.Fprintf(stdout, "relayHost=%s\n", host)
	fmt.Fprintf(stdout, "relayPort=%d\n", port)
	fmt.Fprintf(stdout, "tlsRequired=%t\n", cfg.TLS.Enabled)
	fmt.Fprintf(stdout, "tenantId=%s\n", *tenantID)
	return 0
}

func runDebug(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stdout, "debug commands: host, mobile, auth-header")
		return 0
	}
	if args[0] == "auth-header" {
		flags := newFlagSet("debug auth-header", stderr)
		token := flags.String("token", "", "bearer token")
		if err := flags.Parse(args[1:]); err != nil {
			return 2
		}
		if *token == "" {
			fmt.Fprintln(stderr, "token is required")
			return 2
		}
		fmt.Fprintf(stdout, "Authorization=Bearer %s\n", *token)
		return 0
	}
	flags := newFlagSet("debug "+args[0], stderr)
	tenantID := flags.String("tenant", "tenant_demo", "tenant id")
	hostID := flags.String("host", "host_demo", "host id")
	deviceID := flags.String("device", "device_demo", "device id")
	value := flags.String("value", "hello", "debug value")
	if err := flags.Parse(args[1:]); err != nil {
		return 2
	}
	envelope := protocol.Envelope{
		ProtocolVersion: 1,
		TenantID:        *tenantID,
		HostID:          *hostID,
		DeviceID:        *deviceID,
		SessionID:       "debug_session",
		Sequence:        1,
		PayloadEncoding: protocol.PayloadEncodingPlainJSON,
	}
	switch args[0] {
	case "host":
		envelope.MessageID = "debug-host-pong"
		envelope.Direction = protocol.DirectionWindowsToMobile
		envelope.Kind = "rpc.response"
		envelope.Payload = debug.BuildPongPayload(*value)
	case "mobile":
		envelope.MessageID = "debug-mobile-ping"
		envelope.Direction = protocol.DirectionMobileToWindows
		envelope.Kind = "rpc.request"
		envelope.Payload = debug.BuildPingPayload(*value)
	default:
		fmt.Fprintf(stderr, "unknown debug command: %s\n", args[0])
		return 2
	}
	data, err := json.Marshal(envelope)
	if err != nil {
		fmt.Fprintf(stderr, "debug envelope: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, string(data))
	return 0
}

type tenantFlags struct {
	*flag.FlagSet
	configPath *string
}

func tenantFlagSet(name string, stderr io.Writer) tenantFlags {
	flags := newFlagSet(name, stderr)
	return tenantFlags{FlagSet: flags, configPath: flags.String("config", "relay-config.json", "config path")}
}

func publicEndpoint(cfg config.Config) (string, int) {
	if cfg.PublicHost == "" {
		return cfg.ListenHost, cfg.ListenPort
	}
	port := cfg.PublicPort
	if port == 0 {
		port = cfg.ListenPort
	}
	return cfg.PublicHost, port
}

func relayURL(cfg config.Config, host string, port int) string {
	scheme := "http"
	if cfg.TLS.Enabled {
		scheme = "https"
	}
	return scheme + "://" + net.JoinHostPort(host, strconv.Itoa(port))
}

func openTenantService(configPath string, stderr io.Writer) (config.Config, *tenant.Service, func(), int) {
	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(stderr, "load config: %v\n", err)
		return config.Config{}, nil, func() {}, 1
	}
	st, err := store.Open(cfg.StatePath)
	if err != nil {
		fmt.Fprintf(stderr, "open state: %v\n", err)
		return config.Config{}, nil, func() {}, 1
	}
	return cfg, tenant.NewService(st), func() { st.Close() }, 0
}

func newFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(stderr)
	return flags
}

func parsePort(value string) (int, error) {
	port, err := strconv.Atoi(value)
	if err != nil {
		return 0, err
	}
	if port < 0 || port > 65535 {
		return 0, fmt.Errorf("port out of range")
	}
	return port, nil
}

func ensureParentDir(path string) error {
	dir := filepath.Dir(path)
	if dir == "." || dir == "" {
		return nil
	}
	return os.MkdirAll(dir, 0700)
}
