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
8. Approved devices can open future sessions without the invite token.
