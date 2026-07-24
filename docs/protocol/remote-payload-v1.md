# MyCodex Remote Payload Protocol v1

Business JSON is end-to-end encrypted. The Relay neither accepts nor produces
plaintext business payloads, and does not parse ciphertext after validating the
outer `session.envelope` shape.

The endpoint-visible outer `kind` matrix is fixed:

| Direction | Allowed kind |
| --- | --- |
| `mobile_to_windows` | `rpc.request` |
| `windows_to_mobile` | `rpc.response`, `event` |

Request correlation lives in the encrypted business DTO (`requestId`), not in
the Relay envelope.
