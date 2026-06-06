# Relay MVP Verification

Date: 2026-06-06

Verified commands:

```text
go test ./...
Get-ChildItem docs\protocol\test-vectors\*.json | ForEach-Object { Get-Content $_.FullName -Raw | ConvertFrom-Json | Out-Null; $_.Name }
scripts\build.ps1 -Version 0.1.0-dev
go run ./cmd/mycodex-relay version
go run ./cmd/mycodex-relay help
go run ./cmd/mycodex-relay configure --config <temp>\relay-config.json --state <temp>\relay-state.db --public-host relay.example.com
go run ./cmd/mycodex-relay tenant create --config <temp>\relay-config.json --name Alice
go run ./cmd/mycodex-relay tenant list --config <temp>\relay-config.json
go run ./cmd/mycodex-relay tenant show --config <temp>\relay-config.json --tenant <tenantId>
go run ./cmd/mycodex-relay tenant print-connection --config <temp>\relay-config.json --tenant <tenantId>
```

MVP result:

- Tenant-aware protocol docs exist.
- Configure, serve construction, tenant lifecycle, and debug CLI command tests pass.
- Host registration, tenant-isolated device binding, invite consumption, envelope, session, and debug payload tests pass.
- `/v1/ws` accepts query-parameter host/device sessions and routes tenant-isolated envelopes.
- Cross-platform build artifacts are generated.
- Windows and Android integration can begin against protocol v1.
