# Contributing

Issues and pull requests are welcome.

- For larger changes, open an issue first to agree on the direction. Protocol changes must update the specifications in [`docs/protocol`](docs/protocol) and stay compatible with the Windows and Android clients.
- Run `go test ./... -count=1` before submitting, and add tests for new behavior and fixes.
- Do not commit tenant secrets, device tokens, relay identities, state databases, or personal data.
- Contributions are licensed under this repository's [MIT License](LICENSE).
