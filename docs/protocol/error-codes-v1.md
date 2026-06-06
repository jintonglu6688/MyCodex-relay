# MyCodex Relay Error Codes v1

| Code | Meaning |
| --- | --- |
| `tenant_not_found` | Tenant ID does not exist. |
| `tenant_disabled` | Tenant is disabled. |
| `auth_failed` | Tenant authentication failed. |
| `host_not_found` | Host ID is not registered under the tenant. |
| `device_not_found` | Device ID is not bound under the host. |
| `device_revoked` | Device binding exists but is revoked and cannot be used. |
| `invite_not_found` | Invite ID does not exist under the tenant and host. |
| `invite_expired` | Invite expiry time has passed. |
| `invite_consumed` | Invite has already been used. |
| `route_not_found` | Target session is not connected. |
| `quota_exceeded` | Tenant or global quota rejected the action. |
| `message_too_large` | Envelope payload exceeds the configured limit. |
| `invalid_envelope` | Envelope failed protocol validation. |
