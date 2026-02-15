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
├─────────────────────────────────────────────────────┤
│                  rustgate-transport                  │
│  TLS listener · session mgmt · codec · router       │
├─────────────────────────────────────────────────────┤
│                    rustgate-core                     │
│  Identity · RoutableMessage · framing strategy       │
└─────────────────────────────────────────────────────┘
```

**rustgate-core** — Shared types: `Identity` (CN + groups + fingerprint), `RoutableMessage`, `Destination` (Broadcast / Group / Direct), framing strategies.

**rustgate-transport** — mTLS listener with client certificate verification, X.509 identity extraction (CN → identity, OU → groups, SHA-256 → fingerprint), length-prefixed / XML stream / line-delimited codecs, and a routing engine that delivers messages by broadcast, group, or direct address. Sessions are managed with atomic IDs to prevent stale task eviction on reconnect.

**rustgate-server** — Binary entry point. Accepts mTLS connections, spawns per-session read/write tasks, routes all traffic through the shared `Router`.

## Status

Core transport and routing are functional. The server accepts mTLS connections, extracts identity from client certificates, and routes messages between authenticated sessions.

**What works:**
- mTLS handshake with client certificate authentication
- Identity extraction from X.509 (CN, OU groups, SHA-256 fingerprint)
- Broadcast, group, and direct message routing
- Session lifecycle with reconnect handling
- Length-prefixed codec with overflow protection (16MB max frame)
- XML stream and line-delimited codecs (built, not yet wired to server)

**What's next:**
- Wire XML codec for TAK client connections
- Cursor on Target (CoT) message parsing
- Protocol translation layer (XML ↔ binary ↔ JSON)
- Latest-state cache for position replay on connect
- Real TAK client compatibility testing (ATAK/iTAK/WinTAK)

## Building

```
cargo build --release
```

Requires Rust 1.85+ (edition 2024).

## Running

```
rustgate --cert server.pem --key server-key.pem --ca ca.pem
```

Options:
- `--bind` — Listen address (default: `0.0.0.0:4433`)
- `--cert` — Server certificate PEM
- `--key` — Server private key PEM
- `--ca` — Client CA certificate PEM (for mTLS verification)

## Testing

```
cargo test
```

23 integration tests covering mTLS handshake, identity extraction, broadcast/group/direct routing, session lifecycle, codec edge cases, and frame size limits. Tests use ephemeral certificates generated at runtime — no fixture files.

## License

Proprietary. See [LICENSE](LICENSE) for details.
