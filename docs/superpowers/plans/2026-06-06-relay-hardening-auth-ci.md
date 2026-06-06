# Relay Hardening Auth CI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Harden Relay MVP WebSocket access with structured errors, store-backed authentication, debug auth helpers, and CI.

**Architecture:** Add a protocol DTO for error payloads, extend pairing device bindings with a hashed device token, and let `relay.Server` optionally authenticate WebSocket upgrades with a `store.Store`. Keep unauthenticated `NewServer` behavior for narrow in-memory protocol tests while `NewServerWithStore` and CLI `serve` use authenticated mode.

**Tech Stack:** Go 1.25, `net/http`, `database/sql`, `github.com/coder/websocket`, `modernc.org/sqlite`, GitHub Actions.

---

## File Structure

- `internal/protocol/error.go`: structured error payload DTO.
- `internal/protocol/error_test.go`: stable error JSON tests.
- `internal/pairing/service.go`: device token hash persistence and token-returning approval method.
- `internal/pairing/device_test.go`: device token and revoked auth tests.
- `internal/store/schema.go`: add nullable `device_token_hash` to devices schema.
- `internal/store/store.go`: run lightweight migration for existing DBs.
- `internal/relay/server.go`: authenticate WebSocket upgrades when store-backed.
- `internal/relay/server_test.go`: authenticated WebSocket tests.
- `internal/cli/app.go`: `serve` uses `NewServerWithStore`, add `debug auth-header`.
- `internal/cli/app_test.go`: debug auth header test.
- `.github/workflows/ci.yml`: Windows and Linux CI.
- `docs/protocol/relay-v1.md`: document authenticated WebSocket header.
- `docs/protocol/pairing-v1.md`: document device token.
- `docs/protocol/error-codes-v1.md`: add auth error codes.
- `README.md`: update development/CI notes.

## Tasks

### Task 1: Structured Error Payload

- [ ] Write `internal/protocol/error_test.go` proving `ErrorPayload{Code:"route_not_found"}` marshals to `{"code":"route_not_found"}`.
- [ ] Run `go test ./internal/protocol -run ErrorPayload -count=1` and verify it fails because the type is missing.
- [ ] Add `internal/protocol/error.go`.
- [ ] Update `relay.writeError` to marshal `protocol.ErrorPayload`.
- [ ] Run `go test ./internal/protocol ./internal/relay -count=1`.

### Task 2: Device Token Persistence

- [ ] Add pairing tests for `ApproveClaimWithToken`, `VerifyDeviceToken`, wrong token failure, and revoked-device failure.
- [ ] Run `go test ./internal/pairing -count=1` and verify missing methods fail.
- [ ] Add `device_token_hash` to schema and migration.
- [ ] Implement token generation/hash storage and verification.
- [ ] Run `go test ./internal/store ./internal/pairing -count=1`.

### Task 3: WebSocket Upgrade Authentication

- [ ] Add relay tests for authenticated host/device ping-pong, missing host auth rejection, invalid device auth rejection, and revoked device auth rejection.
- [ ] Run `go test ./internal/relay -run Auth -count=1` and verify failures.
- [ ] Add `NewServerWithStore` and Authorization header verification.
- [ ] Update CLI `serve` to call `NewServerWithStore`.
- [ ] Run `go test ./internal/relay ./internal/cli -count=1`.

### Task 4: CLI Debug Auth Header

- [ ] Add CLI test for `debug auth-header --token secret`.
- [ ] Run `go test ./internal/cli -run AuthHeader -count=1` and verify failure.
- [ ] Implement `debug auth-header`.
- [ ] Run `go test ./internal/cli -count=1`.

### Task 5: CI And Documentation

- [ ] Add `.github/workflows/ci.yml`.
- [ ] Update protocol docs and README.
- [ ] Run `go test ./... -count=1`.
- [ ] Run `scripts\build.ps1 -Version 0.1.0-dev`.
- [ ] Commit and push.
