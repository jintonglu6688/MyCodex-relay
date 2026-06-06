# MyCodex Remote Payload Protocol v1

The relay treats payloads as opaque strings. Debug traffic uses `plain-json`; production traffic uses `encrypted-json`.

## Debug Ping

```json
{
  "type": "remote/ping",
  "value": "hello"
}
```

## Debug Pong

```json
{
  "type": "remote/pong",
  "value": "hello"
}
```
