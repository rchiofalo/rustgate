# Architecture

rustgate is a Rust-native secure message router built for tactical edge deployment. It handles mTLS client connections, routes messages by group membership derived from client certificates, and federates with remote servers for cross-network situational awareness sharing.

## Crate Structure

```
crates/
  rustgate-core/          Shared types (Identity, RoutableMessage, Destination, framing)
  rustgate-cot/           Cursor on Target XML parsing, MessageBuilder
  rustgate-authz/         Authorization engine (RBAC/ABAC policy evaluation, Cedar backend)
  rustgate-transport/     mTLS listener, codecs, session management, message router
  rustgate-websocket/     WebSocket (wss://) listener with mTLS, router integration
  rustgate-mqtt/          MQTT 5.0/3.1.1 transport with mTLS, dynamic group subscriptions
  rustgate-nats/          NATS pub/sub bridge with JetStream history replay
  rustgate-http/          HTTP/webhook egress bridge (auth, retry, circuit breaking)
  rustgate-enrollment/    HTTPS certificate enrollment (Marti v2 CSR signing)
  rustgate-proto/         Protobuf translation (XML / proto) and negotiation
  rustgate-federation/    Server-to-server federation (V1 XML, V2 gRPC)
  rustgate-client/        Lightweight client library for integration testing
  rustgate-server/        Binary entry point wiring all crates together
  rustgate-test-utils/    Ephemeral certificate generation for tests
```

## Data Flow

```
Clients
  │                        │                      │
  │ mTLS (port 4433)       │ wss:// (port 8443)   │ mqtts:// (port 8883)
  ▼                        ▼                      ▼
┌──────────────────────────────────────────────────────────────────┐
│                         rustgate-server                          │
│                                                                  │
│  ┌─────────────┐   ┌────────────┐   ┌─────────────────────┐      │
│  │ TLS Listener│──>│   Router   │──>│  Session Write Loop │      │
│  │ (transport) │   │ broadcast/ │   │  (per-client sender)│      │
│  └─────────────┘   │ group/     │   └─────────────────────┘      │
│                     │ direct     │                               │
│  ┌─────────────┐   │            │   ┌─────────────────────┐      │
│  │ WS Listener │──>│   Authz    │   │ Federation Manager  │      │
│  │ (websocket) │   │    PEP     │<->│ (V1 XML / V2 gRPC)  │      │
│  └─────────────┘   │            │   └─────────────────────┘      │
│                    │            │                                │
│  ┌──────────────┐  │            │   ┌─────────────────────┐      │
│  │MQTT Listener │─>│            │   │  Position Cache     │      │
│  │ (mqtts://)   │  │            │   │  (replay on connect)│      │
│  └──────────────┘  │            │   └─────────────────────┘      │
│                    │            │                                │
│  ┌─────────────┐   │            │                                │
│  │ NATS Bridge │<->│            │                                │
│  │ (pub/sub)   │   │            │                                │
│  └─────────────┘   └────────────┘                                │
│                                                                  │
│  ┌─────────────┐   ┌────────────┐   ┌─────────────────────┐      │
│  │ Enrollment  │   │  Metrics   │   │  HTTP Egress        │      │
│  │ (HTTPS CSR) │   │ Prometheus │   │  (webhook/REST)     │      │
│  └─────────────┘   └────────────┘   └─────────────────────┘      │
└──────────────────────────────────────────────────────────────────┘
  │                     │                    │                  │
  │ NATS (4222)         │ HTTP (9090)        │ mTLS (9000/9001)│ HTTPS (targets)
  ▼                     ▼                    ▼                 ▼
Other rustgate       Prometheus/         Remote            SIEM, dashboards,
instances            monitoring          servers (peers)   webhook receivers
```

## Core Types

### Identity

Extracted from X.509 client certificates during the mTLS handshake:

| Field | Source | Example |
|-------|--------|---------|
| `cn` | Certificate Common Name | `ALPHA-BRAVO-1` |
| `groups` | Certificate OU fields | `{"Team-Alpha", "HQ"}` |
| `fingerprint` | SHA-256 of DER cert | `a3b2c1...` |

### RoutableMessage

The internal message envelope used by the router:

| Field | Type | Description |
|-------|------|-------------|
| `source` | `Identity` | Sender identity from their certificate |
| `destination` | `Destination` | Broadcast, Group(name), or Direct(callsign) |
| `payload` | `Bytes` | Raw message bytes (typically CoT XML) |
| `metadata` | `Metadata` | Timestamp, source protocol, protocol detail |

### Destination

Three routing modes:

- **Broadcast** — deliver to all connected sessions
- **Group(name)** — deliver only to sessions whose certificate OU includes the group
- **Direct(callsign)** — deliver to the session whose certificate CN matches

## Feature Gates

All optional features are compile-time feature gates, keeping the base binary minimal:

| Feature | Crate | What It Adds |
|---------|-------|--------------|
| `websocket` | rustgate-websocket | WebSocket (wss://) listener with mTLS, router integration |
| `mqtt` | rustgate-mqtt | MQTT 5.0/3.1.1 transport with mTLS, dynamic group subscriptions |
| `nats` | rustgate-nats | NATS pub/sub bridge, JetStream SA replay |
| `enrollment` | rustgate-enrollment | HTTPS certificate enrollment server |
| `proto` | rustgate-proto | TAK protobuf translation, protocol negotiation |
| `metrics` | prometheus, hyper | Prometheus metrics, health endpoints |
| `federation` | rustgate-federation | Server-to-server federation (V1/V2) |
| `federation-ha` | rustgate-federation | High-availability federation with JWT and NATS KV |
| `est` | rustgate-enrollment | EST (RFC 7030) enrollment endpoints |
| `full-detail` | rustgate-nats | Extended CoT parsing for NATS bridge |
| `fips` | rustgate-transport | FIPS 140-3 crypto via aws-lc-rs (requires Go + cmake) |
| `post-quantum` | rustgate-transport | Post-quantum key exchange X25519MLKEM768 (requires Go + cmake) |
| `otel` | opentelemetry | OpenTelemetry distributed tracing (OTLP export, requires protoc) |
| `ocsp` | rustgate-transport | OCSP stapling and client OCSP checking |
| `spiffe` | rustgate-transport | SPIFFE/SPIRE workload identity for server TLS |
| `cedar` | rustgate-authz | Cedar policy language backend for authorization |
| `peer-discovery` | rustgate-federation | Peer discovery backends (DNS-SD, Consul, etcd) |
| `jemalloc` | tikv-jemallocator | jemalloc allocator for musl builds |

Build with specific features:
```
cargo build --release --features nats,proto,metrics,federation
```

Or all features:
```
cargo build --release --all-features
```

## Protobuf Conversion Semantics

When the `proto` feature is enabled, messages can be translated between CoT XML and TAK protobuf. This conversion is **lossy by design**:

- **Mapped fields** (uid, type, how, time, start, stale, point attributes, contact, group, status, takv, track, precisionlocation) are preserved in both directions.
- **Unknown `<event>` attributes** not in the proto schema are silently discarded.
- **Unknown `<detail>` children** are serialized into `Detail.xmlDetail` as raw XML — attribute ordering and whitespace may change.

See the [`xml_to_proto` module documentation](../crates/rustgate-proto/src/convert/xml_to_proto.rs) for the complete field mapping table.

## Session Lifecycle

### TCP Sessions (port 4433)

1. Client connects over TCP to the listener port (default 4433)
2. TLS handshake with mutual authentication (client must present a certificate)
3. Server extracts `Identity` from the client certificate
4. Server assigns an atomic session ID and registers a `SessionHandle` with the Router
5. Spawns a read loop (client -> router) and write loop (router -> client)
6. On disconnect: unregisters from Router, cleans up session resources
7. If the same CN reconnects, the old session is evicted (new session ID wins)

### WebSocket Sessions (requires `--features websocket`)

1. Client connects over TCP, completes mTLS handshake (same cert requirements as TCP)
2. WebSocket upgrade handshake over the TLS connection (10s timeout)
3. Server extracts `Identity` from the client certificate (same as TCP)
4. Session registers with the shared `Router` and receives cached positions
5. Read/write loops over split WebSocket stream (Binary/Text frames, 5min read timeout, 30s write timeout)
6. On disconnect or Close frame: unregisters from Router, releases semaphore permit
7. WebSocket and TCP sessions are fully interoperable — same router, same groups, same position cache

## Codec Pipeline

Messages pass through a codec pipeline based on the configured framing mode:

| Framing | Codec | Wire Format |
|---------|-------|-------------|
| `xml` | `XmlStreamCodec` | Raw XML stream with depth tracking |
| `length-prefixed` | `LengthPrefixedCodec(Four)` | 4-byte big-endian length header |
| `line` | `LineCodec` | Newline-delimited |
| `tak-protobuf` | `TakFrameCodec` | 0xBF magic + varint length |
| `tak-negotiate` | Negotiation then `TakFrameCodec` or `XmlStreamCodec` | Server advertises, client opts in |

## Message Routing

The `Router` maintains a map of session ID -> `SessionHandle` (mpsc sender). On each message:

1. Parse destination from CoT XML `<event>` attributes
2. Match destination type (broadcast/group/direct)
3. For each candidate session, check group membership
4. Send message bytes through the session's mpsc channel
5. Write loop picks up bytes and writes to the TLS stream

Position cache stores the latest position per (group, callsign) pair. New sessions receive cached positions on connect for immediate situational awareness.

## NATS Bridge

When `--nats-url` is provided, the NATS bridge:

1. Subscribes to NATS subjects for messages from other rustgate instances
2. Publishes local messages to NATS for cross-instance delivery
3. Uses JetStream for SA history replay on new subscriber connect
4. Two-layer echo prevention: protocol tag (`source_protocol`) + instance UUID header

## Security Model

- `unsafe_code = "forbid"` across all crates
- `unwrap_used = "deny"` and `panic = "deny"` in clippy lints
- Client certificate authentication (mTLS) — no password-based auth
- Subject DN enforcement in enrollment (CSR subject ignored, CN set from authenticated username)
- CSR SAN and custom extension stripping to prevent subject injection
- 16MB maximum frame size to prevent memory exhaustion
- Connection limits via semaphore (`--max-connections`)
- Read-only root filesystem in Docker/K8s
- Non-root container (UID 10001) with all capabilities dropped
- Pod Security Standards (restricted profile) in Helm chart
