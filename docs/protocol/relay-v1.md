# MyCodex Relay Protocol v1

Relay Protocol v1 is a tenant-aware WebSocket relay protocol.

Relay-visible fields are used only for authentication, routing, quota enforcement, and diagnostics. Business payloads are opaque to the relay.

## Envelope

```json
{
  "protocolVersion": 1,
  "messageId": "018f51d1-1cc3-74e2-9b75-df9a9987a101",
  "correlationId": null,
  "tenantId": "tenant_demo",
  "hostId": "host_demo",
  "deviceId": "device_demo",
  "sessionId": "session_demo",
  "direction": "mobile_to_windows",
  "kind": "rpc.request",
  "sequence": 1,
  "payloadEncoding": "plain-json",
  "payload": "{\"type\":\"remote/ping\",\"value\":\"hello\"}"
}
```

## Required Validation

- `protocolVersion` must be `1`.
- `messageId` must be non-empty.
- `tenantId` must be non-empty.
- `hostId` must be non-empty for host/device routes.
- `direction` must be `windows_to_mobile`, `mobile_to_windows`, or `system`.
- `kind` must be non-empty.
- `payloadEncoding` must be `plain-json` for debug traffic or `encrypted-json` for production traffic.
- `payload` must not exceed the configured message size limit.

## WebSocket Session Handshake

Relay MVP WebSocket sessions connect to `/v1/ws` with query parameters. This is the MVP handshake; future clients may negotiate a signed hello message after the socket is accepted.

Windows host session:

```text
/v1/ws?connection=host&tenantId=tenant_demo&hostId=host_demo&sessionId=host_session
```

Mobile device session:

```text
/v1/ws?connection=device&tenantId=tenant_demo&hostId=host_demo&deviceId=device_demo&sessionId=device_session
```

Required query fields:

- `connection` must be `host` or `device`.
- `tenantId` and `hostId` are required for every session.
- `deviceId` is required for device sessions.
- `sessionId` is optional; the relay assigns a fallback session ID when omitted.

Authenticated relay servers require an HTTP authorization header during the WebSocket upgrade:

```text
Authorization: Bearer <credential>
```

Credential rules:

- Host sessions use the tenant secret returned by `tenant create` or `tenant rotate-secret`.
- Device sessions use the device token returned when Windows approves a pairing claim.
- The relay verifies credentials against stored hashes before the socket is accepted.
- Credentials must not be placed in query parameters.

After the socket is accepted, each text WebSocket message is one JSON `Envelope`. The relay validates each envelope, then routes:

- `mobile_to_windows` to the active host session keyed by `tenantId + hostId`.
- `windows_to_mobile` to the active device session keyed by `tenantId + hostId + deviceId`.

Before route lookup, the relay validates envelope identity against the connected session identity:

- Host sessions may send only `windows_to_mobile`.
- Host envelopes must use the connected session's `tenantId` and `hostId`.
- Host envelopes may target any `deviceId` under that connected tenant and host.
- Device sessions may send only `mobile_to_windows`.
- Device envelopes must use the connected session's `tenantId`, `hostId`, and `deviceId`.

If the envelope identity does not match the connected session, the sender receives `identity_mismatch`. If the session type is not allowed to send the envelope direction, the sender receives `direction_not_allowed`. Neither error is routed to another session.

When a route is missing, the sender receives a `system.error` envelope with payload:

```json
{"code":"route_not_found"}
```

## Tenant Isolation

Every route lookup uses `tenantId` together with `hostId`, `deviceId`, or `sessionId`. A route that exists under another tenant must be treated as missing.

## HTTP API

All authenticated host management endpoints use:

```text
Authorization: Bearer <tenantSecret>
```

The relay verifies the tenant secret against the stored tenant hash. Responses are JSON and error responses use:

```json
{"code":"unauthorized"}
```

### Register Host

```text
POST /v1/hosts/register
```

Request:

```json
{
  "tenantId": "tenant_demo",
  "hostId": "host_demo",
  "displayName": "MyCodex on Windows",
  "hostPublicKey": "debug-host-public-key"
}
```

Response:

```json
{
  "tenantId": "tenant_demo",
  "hostId": "host_demo"
}
```

### Create Pairing Invite

```text
POST /v1/pairing/invites
```

Request:

```json
{
  "tenantId": "tenant_demo",
  "hostId": "host_demo",
  "ttlSeconds": 600
}
```

Response includes `inviteId`, `oneTimePairingToken`, and `expiresAt`. The pairing token is returned once.

### Claim Pairing Invite

```text
POST /v1/pairing/claim
```

This endpoint is called by mobile with the invite token. It validates and consumes the invite, then returns the claimed device fields for host approval.

### Approve Pairing

```text
POST /v1/pairing/approve
```

This endpoint is called by the host with the tenant secret. It persists the device binding and returns `deviceToken` once. Mobile uses that device token as the WebSocket bearer credential.

### Device List And Revoke

```text
GET /v1/devices?tenantId=tenant_demo&hostId=host_demo
POST /v1/devices/revoke
```

Device list responses never include device tokens or token hashes. Revoke marks a device unusable for future WebSocket authentication.
