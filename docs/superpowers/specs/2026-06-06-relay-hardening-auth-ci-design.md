# Superseded — Relay Hardening Auth CI Design

> Superseded by `E:\MyCodex\docs\superpowers\plans\2026-07-24-encrypted-remote-business-channel.md`. This historical document describes a plaintext Relay protocol and is not an implementation reference.

## Goal

Harden the Relay MVP so real clients cannot connect only by claiming query-parameter identity, errors use a structured payload, and every push is protected by GitHub CI.

## Scope

This design covers the next relay-only slice:

- Structured relay error payloads.
- WebSocket authentication before session registration.
- Host authentication with the tenant secret.
- Device authentication with a generated device token stored as a hash.
- CLI/debug helpers for local signed/authenticated WebSocket testing.
- GitHub Actions CI for tests and Windows build.

It does not implement Windows or Android clients, public-key device signatures, TLS automation, push notifications, or file transfer.

## Authentication Approach

The current tenant secret is stored as a salted hash, which is correct for persistence but prevents server-side HMAC verification without storing plaintext. For this hardening slice, WebSocket authentication uses bearer-style credentials in the HTTP `Authorization` header:

- Host sessions send `Authorization: Bearer <tenantSecret>`.
- Device sessions send `Authorization: Bearer <deviceToken>`.

The relay verifies these values with `security.VerifySecret` against stored hashes and never logs or echoes them. Query parameters continue to identify the requested session, but they are not trusted until the matching credential verifies.

Device tokens are generated when a pairing claim is approved. They are returned once from `ApproveClaimWithToken`, stored only as a hash, and can be used by future device WebSocket sessions. Existing `ApproveClaim` remains available and discards the generated token for callers that do not need it.

## Structured Errors

Relay error envelopes keep `kind=system.error` and `payloadEncoding=plain-json`, but the payload is produced from a `protocol.ErrorPayload` DTO:

```json
{"code":"route_not_found"}
```

This keeps existing wire output stable while removing ad hoc string concatenation from relay code.

## WebSocket Flow

1. Client connects to `/v1/ws` with existing query fields.
2. Relay parses the requested session identity.
3. If the server was created with a store, relay requires `Authorization: Bearer <credential>`.
4. Host credentials verify against the tenant secret hash.
5. Device credentials verify against the active, non-revoked device token hash.
6. Only authenticated sessions are registered.
7. Each envelope is still validated for protocol fields, sender identity, allowed direction, payload size, and tenant-isolated route.

Servers created without a store remain allowed for narrow protocol/unit tests, but `serve --config` always opens the store and creates an authenticated server.

## CLI And Debug Helpers

CLI keeps existing tenant commands. Debug command scope expands to help local WebSocket tests:

- `debug auth-header --token <token>` prints an `Authorization` header value.

This intentionally does not print tokens from stores. It formats a token the operator already has.

## CI

Add `.github/workflows/ci.yml`:

- Windows job: `go test ./... -count=1` and `scripts\build.ps1 -Version 0.1.0-ci`.
- Linux job: `go test ./... -count=1`.

Windows is the primary build target because the local packaging script is PowerShell and the relay is used by MyCodex Windows integration.

## Tests

Tests must prove:

- Error payload JSON is stable.
- Authenticated host/device WebSocket sessions can route ping-pong.
- Missing/invalid host authorization is rejected before WebSocket upgrade.
- Missing/invalid device authorization is rejected before WebSocket upgrade.
- Revoked devices cannot authenticate.
- Existing unauthenticated `NewServer` tests still cover pure routing behavior.
- CLI debug can format an auth header without storing or exposing secrets.
