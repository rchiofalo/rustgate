# rustgate

Rust-native secure message router with pluggable protocol support. Built for tactical edge deployment.

## Why

Existing tactical messaging servers are Java monoliths requiring 8GB+ RAM, multiple JVM processes, and complex module stacks. They work in garrison but fall apart at the edge where resources are constrained and reliability matters most. Federation-only alternatives exist but don't handle client connections.

rustgate is a lightweight alternative that handles mTLS client connections, routes messages by group membership derived from client certificates, and exposes a pluggable protocol interface for future adapters. Pure Rust, single binary, minimal footprint.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   rustgate-server                    │
│                     (binary)                         │
├──────────────────────┬──────────────────────────────┤
│  rustgate-transport  │       rustgate-nats           │
│  TLS · sessions ·    │  NATS pub/sub · JetStream    │
│  codec · router      │  SA replay · echo prevention │
├──────────────────────┴──────────────────────────────┤
│                    rustgate-core                     │
│  Identity · RoutableMessage · framing strategy       │
└─────────────────────────────────────────────────────┘
```

**rustgate-core** — Shared types: `Identity` (CN + groups + fingerprint), `RoutableMessage`, `Destination` (Broadcast / Group / Direct), framing strategies.

**rustgate-transport** — mTLS listener with client certificate verification, X.509 identity extraction (CN → identity, OU → groups, SHA-256 → fingerprint), length-prefixed / XML stream / line-delimited codecs, and a routing engine that delivers messages by broadcast, group, or direct address. Sessions are managed with atomic IDs to prevent stale task eviction on reconnect.

**rustgate-nats** — Optional NATS bridge for stateless horizontal scaling. Publishes position updates to NATS subjects, subscribes for cross-instance delivery, and replays JetStream history on startup for situational awareness bootstrap. Two-layer echo prevention ensures messages are never re-published to their origin. Feature-gated behind `--features nats`.

**rustgate-server** — Binary entry point. Accepts mTLS connections, spawns per-session read/write tasks, routes all traffic through the shared `Router`. Optionally bridges to NATS when `--nats-url` is provided.

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

Options:
- `--bind` — Listen address (default: `0.0.0.0:4433`)
- `--cert` — Server certificate PEM
- `--key` — Server private key PEM
- `--ca` — Client CA certificate PEM (for mTLS verification)
- `--nats-url` — NATS server URL (enables cross-instance bridge)
- `--nats-credentials` — Path to NATS credentials file for JWT/NKey auth

## Testing

```
cargo test
```

57 tests covering mTLS handshake, identity extraction, broadcast/group/direct routing, session lifecycle, codec edge cases, frame size limits, NATS wire format serialization, subject sanitization, group extraction, and echo prevention. Tests use ephemeral certificates generated at runtime — no fixture files.

## License

Proprietary. See [LICENSE](LICENSE) for details.
