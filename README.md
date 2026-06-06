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

## Build

Windows:

```powershell
scripts\build.ps1 -Version 0.1.0-dev
```

Linux/macOS:

```bash
sh scripts/build.sh 0.1.0-dev
```
