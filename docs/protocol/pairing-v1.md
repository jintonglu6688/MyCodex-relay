# MyCodex Pairing Protocol v1

Pairing connects one mobile device to one Windows host under one tenant.

## Secret Ownership

- Relay stores tenant secret hashes.
- Windows stores relay endpoint, tenant ID, and tenant secret.
- Mobile stores pairing invite fields and later device credentials.
- Mobile never stores tenant secret.

## Invite Fields

```json
{
  "relayHost": "relay.example.com",
  "relayPort": 38443,
  "tlsRequired": true,
  "tenantId": "tenant_demo",
  "hostId": "host_demo",
  "inviteId": "invite_demo",
  "oneTimePairingToken": "pairing-token-demo",
  "expiresAt": "2026-06-06T12:30:00Z",
  "protocolVersion": 1,
  "windowsHostDisplayName": "MyCodex on Windows",
  "keyAgreementMaterial": "debug-key-material"
}
```

## Lifecycle

1. Windows authenticates with tenant secret.
2. Windows registers a host.
3. Windows creates a one-time invite.
4. Mobile claims the invite.
5. Relay validates tenant, host, invite token, expiry, and consumption state.
6. Relay forwards the claim to Windows.
7. Windows approves or rejects the claim.
8. Approval persists a device binding under `tenantId + hostId + deviceId` and returns a device token once.
9. Approved, non-revoked devices use the device token as the WebSocket bearer credential for future sessions.

Invite consumption is atomic. If two claim attempts race for the same invite, only one can consume it and the other receives `invite_consumed`.

## Device Binding

Approved devices are stored with:

- tenant ID
- host ID
- device ID
- display name
- platform
- device public key
- hashed device token
- revoked state
- bind timestamp

Device lookup is tenant and host scoped. A device ID bound under one tenant or host must not resolve under another tenant or host. Revoked devices are retained for auditability but fail active lookup.

Device tokens are shown only at approval time. The relay stores only a hash and verifies future WebSocket sessions with constant-time secret verification.
