# rustgate

Rust-native secure message router with pluggable protocol support. Built for tactical edge deployment.

## Why

Existing tactical messaging servers are Java monoliths requiring 8GB+ RAM, multiple JVM processes, and complex module stacks. They work in garrison but fall apart at the edge where resources are constrained and reliability matters most. Federation-only alternatives exist but don't handle client connections.

rustgate is a lightweight alternative that handles mTLS client connections, routes messages by group membership derived from client certificates, and exposes a pluggable protocol interface for future adapters. Pure Rust, single binary, minimal footprint.

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                      rustgate-server                          │
│                        (binary)                               │
├──────────────────┬──────────────────┬────────────────────────┤
│ rustgate-transport│   rustgate-nats  │  rustgate-enrollment   │
│ TLS · sessions ·  │  NATS pub/sub · │  HTTPS · CSR signing · │
│ codec · router    │  JetStream · SA  │  Basic Auth · Marti v2 │
├──────────────────┴──────────────────┴────────────────────────┤
│                       rustgate-core                           │
│       Identity · RoutableMessage · framing strategy           │
└──────────────────────────────────────────────────────────────┘
```

**rustgate-core** — Shared types: `Identity` (CN + groups + fingerprint), `RoutableMessage`, `Destination` (Broadcast / Group / Direct), framing strategies.

**rustgate-transport** — mTLS listener with client certificate verification, X.509 identity extraction (CN → identity, OU → groups, SHA-256 → fingerprint), length-prefixed / XML stream / line-delimited codecs, and a routing engine that delivers messages by broadcast, group, or direct address. Sessions are managed with atomic IDs to prevent stale task eviction on reconnect.

**rustgate-nats** — Optional NATS bridge for stateless horizontal scaling. Publishes position updates to NATS subjects, subscribes for cross-instance delivery, and replays JetStream history on startup for situational awareness bootstrap. Two-layer echo prevention ensures messages are never re-published to their origin. Feature-gated behind `--features nats`.

**rustgate-enrollment** — Optional HTTPS enrollment server for TAK client certificate self-provisioning. Implements the Marti v2 certificate signing protocol: clients authenticate with HTTP Basic Auth, submit a PKCS#10 CSR, and receive a signed client certificate + CA cert in JSON or XML. Server-only TLS (no client cert required). Subject DN is enforced from the authenticated username to prevent impersonation. Feature-gated behind `--features enrollment`.

**rustgate-server** — Binary entry point. Accepts mTLS connections, spawns per-session read/write tasks, routes all traffic through the shared `Router`. Optionally bridges to NATS when `--nats-url` is provided. Optionally runs enrollment when `--enrollment-bind` is set.

## Status

Core transport and routing are functional. The server accepts mTLS connections, extracts identity from client certificates, and routes messages between authenticated sessions.

**What works:**
- mTLS handshake with client certificate authentication
- Identity extraction from X.509 (CN, OU groups, SHA-256 fingerprint)
- Broadcast, group, and direct message routing
- Session lifecycle with reconnect handling
- Length-prefixed codec with overflow protection (16MB max frame)
- XML stream codec for TAK client connections
- Cursor on Target (CoT) message parsing
- Position cache with replay on connect
- NATS bridge for cross-instance message delivery (feature-gated)
- JetStream history replay for situational awareness bootstrap
- Two-layer echo prevention (protocol tag + instance header)
- Certificate enrollment (Marti v2 CSR signing, feature-gated)
- Subject DN enforcement from authenticated username (anti-impersonation)
- TLS handshake + HTTP request timeouts on enrollment server
- Streaming body size limits (pre-read rejection, not post-buffer)

**What's next:**
- Real TAK client compatibility testing (ATAK/iTAK/WinTAK)
- Protocol translation layer (XML ↔ binary ↔ JSON)
- Integration testing with embedded NATS

## Building

```
cargo build --release
```

With NATS bridge support:
```
cargo build --release --features nats
```

With enrollment support:
```
cargo build --release --features enrollment
```

All optional features:
```
cargo build --release --features nats,enrollment
```

Requires Rust 1.85+ (edition 2024).

## Running

```
rustgate --cert server.pem --key server-key.pem --ca ca.pem
```

With NATS bridge (requires `--features nats`):
```
rustgate --cert server.pem --key server-key.pem --ca ca.pem \
    --nats-url nats://nats:4222
```

With enrollment (requires `--features enrollment`):
```
rustgate --cert server.pem --key server-key.pem --ca ca.pem \
    --ca-key ca-key.pem \
    --enrollment-bind 0.0.0.0:8446 \
    --enrollment-user admin --enrollment-password changeme
```

Options:
- `--bind` — Listen address (default: `0.0.0.0:4433`)
- `--cert` — Server certificate PEM
- `--key` — Server private key PEM
- `--ca` — Client CA certificate PEM (for mTLS verification)
- `--nats-url` — NATS server URL (enables cross-instance bridge)
- `--nats-credentials` — Path to NATS credentials file for JWT/NKey auth
- `--enrollment-bind` — Enrollment HTTPS listen address (e.g. `0.0.0.0:8446`)
- `--ca-key` — CA private key PEM (for signing client CSRs)
- `--enrollment-user` — Enrollment Basic Auth username
- `--enrollment-password` — Enrollment Basic Auth password
- `--ca-organization` — Organization name for issued certs (default: `rustgate`)

## Testing

```
cargo test
```

81 tests covering mTLS handshake, identity extraction, broadcast/group/direct routing, session lifecycle, codec edge cases, frame size limits, NATS wire format serialization, subject sanitization, group extraction, echo prevention, CSR signing round-trips, subject DN enforcement, Basic Auth validation, response formatting, and XML/JSON enrollment responses. Tests use ephemeral certificates generated at runtime — no fixture files.

## License

Proprietary. See [LICENSE](LICENSE) for details.
