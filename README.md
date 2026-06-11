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
go run ./cmd/mycodex-relay info --config relay-config.json --ensure-tenant --tenant-name Local
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

## HTTP API

Store-backed relay servers expose the server-side integration API:

- `POST /v1/hosts/register`
- `POST /v1/pairing/invites`
- `POST /v1/pairing/claim`
- `POST /v1/pairing/bind`
- `POST /v1/pairing/approve`
- `GET /v1/devices?tenantId=<tenantId>&hostId=<hostId>`
- `POST /v1/devices/revoke`

Host management endpoints require `Authorization: Bearer <tenantSecret>`. Device tokens are returned only by pairing approval and are never included in device list responses.

## CI

GitHub Actions runs `go test ./... -count=1` on Windows and Linux. The Windows job also runs `scripts\build.ps1 -Version 0.1.0-ci`.

## Build

Windows:

```powershell
scripts\build.ps1 -Version 0.1.0-dev
```

or:

```bat
build_all.bat 0.1.0-dev
```

Linux/macOS:

```bash
sh scripts/build.sh 0.1.0-dev
```

Build outputs are grouped by platform:

```text
dist/
  windows-x64/
    mycodex-relay.exe
    show-relay-info.bat
    start-relay.bat
    start-relay-silent.vbs
    stop-relay.bat
  darwin-x64/
    mycodex-relay
    show-relay-info.command
    start-relay.command
    stop-relay.command
  darwin-arm64/
    mycodex-relay
    show-relay-info.command
    start-relay.command
    stop-relay.command
  linux-x64/
    mycodex-relay
  linux-arm64/
    mycodex-relay
```

The Windows and macOS start scripts run `serve` from the platform directory. With no argument they prefer `relay-config.local.json` when it exists, otherwise they use `relay-config.json`. If the selected config does not exist, the script creates a default local config with `relay-state.db` as the state file before starting the relay. Logs are written to `relay.out.log` and `relay.err.log`.

Use `show-relay-info.bat` on Windows or `show-relay-info.command` on macOS to display the local registration information, including listen/public ports, relay URL, health URL, and tenant IDs. If no tenant exists, the script creates a `Local` tenant and prints the newly generated tenant secret once. Existing tenant secrets are not recoverable; use `tenant rotate-secret` to explicitly generate a replacement secret.
