# MyCodex Relay

Cross-platform relay service for MyCodex mobile remote connections.

This repository will host the Go implementation of the multi-tenant relay service used by:

- MyCodex Windows remote host
- MyCodex Android remote client
- future MyCodex iOS remote client

Initial scope:

- Multi-tenant relay server
- Windows host registration
- Mobile pairing invites
- WebSocket message routing
- Tenant and device isolation
- Lightweight cross-platform deployment

## Development

```powershell
go test ./...
go run ./cmd/mycodex-relay version
```

The first milestone is a multi-tenant relay MVP with mock Windows host and mock mobile commands.

## CLI

```powershell
go run ./cmd/mycodex-relay configure --config relay-config.json --state relay-state.db --public-host relay.example.com
go run ./cmd/mycodex-relay tenant create --config relay-config.json --name Alice
go run ./cmd/mycodex-relay tenant list --config relay-config.json
go run ./cmd/mycodex-relay tenant show --config relay-config.json --tenant <tenantId>
go run ./cmd/mycodex-relay tenant disable --config relay-config.json --tenant <tenantId>
go run ./cmd/mycodex-relay tenant enable --config relay-config.json --tenant <tenantId>
go run ./cmd/mycodex-relay tenant rotate-secret --config relay-config.json --tenant <tenantId>
go run ./cmd/mycodex-relay tenant print-connection --config relay-config.json --tenant <tenantId>
go run ./cmd/mycodex-relay serve --config relay-config.json
go run ./cmd/mycodex-relay debug mobile --tenant tenant_demo --host host_demo --device device_demo --value hello
go run ./cmd/mycodex-relay debug host --tenant tenant_demo --host host_demo --device device_demo --value hello
go run ./cmd/mycodex-relay debug auth-header --token <tenant-or-device-token>
```

Tenant secrets are printed only by `tenant create` and `tenant rotate-secret`.

Authenticated WebSocket sessions use an HTTP header:

```text
Authorization: Bearer <tenant-or-device-token>
```

Host sessions use the tenant secret. Device sessions use the token returned by pairing approval.

## CI

GitHub Actions runs `go test ./... -count=1` on Windows and Linux. The Windows job also runs `scripts\build.ps1 -Version 0.1.0-ci`.

## Build

Windows:

```powershell
scripts\build.ps1 -Version 0.1.0-dev
```

Linux/macOS:

```bash
sh scripts/build.sh 0.1.0-dev
```
