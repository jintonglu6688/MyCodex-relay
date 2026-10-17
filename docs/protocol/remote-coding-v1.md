# Remote Coding Payload Protocol v1

Remote Coding Payload Protocol v1 defines the JSON payload carried inside Relay Protocol v1 envelopes for Android programming-mode remote sessions.

The relay treats these payloads as opaque strings. Only Windows MyCodex and the Android client interpret this document.

## Command Payload

Android sends commands to Windows as:

```json
{
  "schemaVersion": 1,
  "payloadType": "remote.command",
  "requestId": "request_demo",
  "operationId": "operation_demo",
  "deviceId": "device_demo",
  "commandType": "coding.message.send",
  "payload": {}
}
```

`operationId` is present only for long-running chat operations.

## Event Payload

Windows sends events to Android as:

```json
{
  "schemaVersion": 1,
  "payloadType": "remote.event",
  "requestId": "request_demo",
  "operationId": "operation_demo",
  "eventType": "coding.message.delta",
  "payload": {}
}
```

## Commands

- `coding.workspaces.list`
- `coding.sessions.list`
- `coding.messages.list`
- `coding.session.create`
- `coding.message.send`
- `approval.respond`
- `remote.writeLock.acquire`
- `remote.writeLock.release`
- `remote.writeLock.heartbeat`

## Events

- `coding.workspaces.list.result`
- `coding.sessions.list.result`
- `coding.messages.list.result`
- `coding.session.created`
- `coding.message.accepted`
- `coding.message.delta`
- `coding.message.completed`
- `coding.message.failed`
- `coding.session.updated`
- `approval.requested`
- `approval.completed`
- `remote.writeLock.granted`
- `remote.writeLock.denied`
- `remote.error`

## Error Payload

```json
{
  "code": "session_busy",
  "message": "This session is already processing a request.",
  "details": {}
}
```

Error payloads must not include tenant secrets, device tokens, authorization headers, model API keys, or sensitive filesystem details.
