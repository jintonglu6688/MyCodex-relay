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

## Tenant Isolation

Every route lookup uses `tenantId` together with `hostId`, `deviceId`, or `sessionId`. A route that exists under another tenant must be treated as missing.
