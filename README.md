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
go run ./cmd/mycodex-relay configure --config relay-config.json --state relay-state.db --public-host relay.example.com --public-port 443 --public-tls
go run ./cmd/mycodex-relay info --config relay-config.json --ensure-tenant --tenant-name Local --json
go run ./cmd/mycodex-relay tenant create --config relay-config.json --name Alice
go run ./cmd/mycodex-relay tenant list --config relay-config.json
go run ./cmd/mycodex-relay tenant show --config relay-config.json --tenant <tenantId>
go run ./cmd/mycodex-relay tenant disable --config relay-config.json --tenant <tenantId>
go run ./cmd/mycodex-relay tenant enable --config relay-config.json --tenant <tenantId>
go run ./cmd/mycodex-relay tenant rotate-secret --config relay-config.json --tenant <tenantId>
go run ./cmd/mycodex-relay tenant print-connection --config relay-config.json --tenant <tenantId>
go run ./cmd/mycodex-relay serve --config relay-config.json
go run ./cmd/mycodex-relay debug auth-header --token <tenant-or-device-token>
```

Tenant secrets are printed only by `tenant create` and `tenant rotate-secret`.

Authenticated WebSocket sessions use an HTTP header:

```text
Authorization: Bearer <tenant-or-device-token>
```

Both host and device sessions use the one-time, purpose-bound ticket returned by
the challenge/proof flow. Bearer values never appear in the WebSocket query.

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

GitHub Actions runs `go test ./... -count=1` on Windows and Linux. The Windows
job runs `scripts\build.ps1 -Version 0.1.0-ci`; the Linux job runs
`sh scripts/build.sh 0.1.0-ci`.

## Build

End-user release resources are under [`resources/release`](resources/release).
Linux production deployment instructions are in
[`resources/release/linux/DEPLOYMENT.md`](resources/release/linux/DEPLOYMENT.md).
The release version is defined once in [`VERSION`](VERSION). Build scripts use
that value when no explicit development or CI version is supplied.

### Windows embedded mode

普通用户不需要手动运行本仓库脚本。正式产品中，Windows 端 MyCodex 会内置 Relay，并在“远程服务”页面完成启动、诊断和配对。

本仓库脚本仍用于开发、自托管和问题诊断：

- `start-relay.bat`: start Relay in the foreground.
- `start-relay-silent.vbs`: start Relay without a console window.
- `show-relay-info.bat`: display the local Relay URL, health URL, and tenant ID.

Windows:

```powershell
scripts\build.ps1
```

or:

```bat
build_all.bat
```

Linux/macOS:

```bash
sh scripts/build.sh
```

Build outputs are grouped by platform and packaged as self-contained release
archives:

```text
dist/
  mycodex-relay-0.1.0-docker-linux-amd64.tar.gz
  mycodex-relay-0.1.0-docker-linux-arm64.tar.gz
  DOCKER-SHA256SUMS.txt
  mycodex-relay-0.1.0-windows-x64.zip
  mycodex-relay-0.1.0-linux-x64.tar.gz
  mycodex-relay-0.1.0-linux-arm64.tar.gz
  mycodex-relay-0.1.0-macos-intel.tar.gz
  mycodex-relay-0.1.0-macos-apple-silicon.tar.gz
  SHA256SUMS.txt
  windows-x64/
    mycodex-relay.exe
    README.md
    DEPLOYMENT.md
    VERSION.txt
    show-relay-info.bat
    start-relay.bat
    start-relay-silent.vbs
    stop-relay.bat
  macos-intel/
    mycodex-relay
    show-relay-info.command
    start-relay.command
    stop-relay.command
  macos-apple-silicon/
    mycodex-relay
    show-relay-info.command
    start-relay.command
    stop-relay.command
  linux-x64/
    mycodex-relay
    deploy-relay.sh
  linux-arm64/
    mycodex-relay
    deploy-relay.sh
```

Windows is distributed as ZIP; Linux and macOS are distributed as `tar.gz`.
Every archive contains the matching binary, platform scripts, `README.md`,
`DEPLOYMENT.md`, and `VERSION.txt`. Verify a downloaded archive against
`SHA256SUMS.txt` before deployment.

## Docker

Docker uses a multi-stage image and supports `linux/amd64` and `linux/arm64`.
The default Compose deployment runs one non-root Relay instance, publishes its
plain HTTP/WebSocket listener only on host loopback, and persists the database,
Relay identity, and migration backups in one named volume.

See [`docker/README.md`](docker/README.md) for configuration, first-tenant
creation, reverse proxy, upgrade, and backup instructions.

Build the two loadable Docker release bundles on a machine with Docker Buildx:

```powershell
scripts\docker\Build-DockerRelease.ps1
```

The same script can use a remote Docker builder over SSH. The remote Docker
executable must be given as an absolute path when it is not on the SSH login
PATH:

```powershell
scripts\docker\Build-DockerRelease.ps1 `
  -DockerHost "user@docker-builder" `
  -RemoteDockerCommand "/usr/local/bin/docker"
```

After extracting on Linux, run `chmod +x mycodex-relay *.sh`; on macOS, run
`chmod +x mycodex-relay *.command`.

The Windows and macOS start scripts run `serve` from the platform directory. With no argument they prefer `relay-config.local.json` when it exists, otherwise they use `relay-config.json`. If the selected config does not exist, the script creates a default local config with `relay-state.db` as the state file before starting the relay. Logs are written to `relay.out.log` and `relay.err.log`.

Use `show-relay-info.bat` on Windows or `show-relay-info.command` on macOS to display the local registration information, including listen/public ports, relay URL, health URL, and tenant IDs. If no tenant exists, the script creates a `Local` tenant and prints the newly generated tenant secret once. Existing tenant secrets are not recoverable; use `tenant rotate-secret` to explicitly generate a replacement secret.

## GitCode binary release

Relay releases use immutable GitCode tags named `relay-v<version>`. A release
contains the five native platform archives, two loadable Docker bundles, and
their checksum files; the Relay source repository is never pushed to GitCode.

Prepare and validate all release assets without publishing:

```powershell
scripts\gitcode\Publish-GitCodeRelayRelease.ps1 `
  -PrepareOnly `
  -DockerHost "user@docker-builder"
```

Publish after committing the version and release changes so the source working
tree is clean:

```powershell
scripts\gitcode\Publish-GitCodeRelayRelease.ps1 `
  -DockerHost "user@docker-builder" `
  -ReleaseNotesZhCn "MyCodex Relay 0.1.0"
```

The token is read from `GITCODE_TOKEN` or Git Credential Manager. If the
version tag already exists, the script verifies every public asset against the
local candidate and refuses to replace different content. Increase `VERSION`
for every new binary release.

Every attachment has a versioned direct URL with this fixed rule:

```text
https://api.gitcode.com/api/v5/repos/<owner>/<repo>/releases/relay-v<version>/attach_files/<file-name>/download
```

The default public distribution repository is `gcw_SpGZ48lW/mycodex-updates`.
The versioned tag and file names are immutable, so these URLs are suitable for
the desktop client's download list. They intentionally do not pretend that a
GitCode Release attachment is an OCI registry.
