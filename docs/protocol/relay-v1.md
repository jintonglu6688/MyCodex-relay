# MyCodex Relay Protocol v1

The Relay is an untrusted, authenticated router for encrypted MyCodex remote
sessions. Its current wire contract is
[`secure-remote-v1.md`](secure-remote-v1.md); that document and its known-answer
vector are authoritative.

`/v1/ws` accepts exactly these query keys, once each and with non-empty values:

```text
connection=host|device
tenantId
hostId
deviceId
```

`sessionId` is deliberately not a WebSocket query parameter. It is a signed,
32-byte Base64Url value inside the endpoint handshake.

After a ticket-authenticated upgrade, only text frames with one of these exact
tagged-union records are accepted:

- `session.client_hello`
- `session.server_hello`
- `session.confirmation`
- `session.envelope`

The Relay validates the visible route, type, canonical integer spelling,
Base64Url shape and configured size bounds. It does not validate endpoint
signatures, confirmations or ciphertext, and forwards a validated UTF-8 frame
as its original bytes. It never emits a business error frame: malformed frames,
identity/direction mismatches and unavailable routes close the socket.

| Close code | Short reason |
| --- | --- |
| 4001 | `invalid_frame` |
| 4004 | `route_unavailable` |
| 4008 | `identity_or_direction_mismatch` |
| 4009 | `peer_replaced` |
| 1009 | `message_too_large` |

The effective business plaintext quota is
`min(config.maxMessageBytes, 11 * 1024 * 1024)`. The Relay's read limit is the
Base64Url encoded ciphertext bound plus 64 KiB, capped by the protocol maximum
of 15,444,672 bytes.
