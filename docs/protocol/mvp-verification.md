# Relay MVP Verification

Date: 2026-06-06

Verified commands:

```text
go test ./...
scripts\build.ps1 -Version 0.1.0-dev
go run ./cmd/mycodex-relay version
go run ./cmd/mycodex-relay help
```

MVP result:

- Tenant-aware protocol docs exist.
- Tenant, invite, envelope, session, and debug payload tests pass.
- Cross-platform build artifacts are generated.
- Windows and Android integration can begin against protocol v1.
