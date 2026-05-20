# Architecture

rustgate is a Rust-native secure message router built for tactical edge deployment. It handles mTLS client connections, routes messages by group membership derived from client certificates, and federates with remote servers for cross-network situational awareness sharing.

## Crate Structure

The workspace ships **39 crates** under `crates/`. The full table — kept in
sync with `cargo metadata` via the `cargo-toml-drift` CI check — is in the
top-level [`README.md`](https://github.com/rchiofalo/rustgate/blob/main/README.md#architecture). The architectural
groupings are:

### Foundation

| Crate | Purpose |
|---|---|
| `rustgate-core` | Shared types: `Identity`, `RoutableMessage`, `Destination`, framing strategies |
| `rustgate-cot` | Cursor on Target XML parsing, MessageBuilder |
| `rustgate-tls` | TLS/mTLS configuration, X.509 identity extraction, OCSP, SPIFFE, TCP listeners |
| `rustgate-authz` | RBAC/ABAC policy evaluation (Cedar backend) |
| `rustgate-router` | Routing engine: Router, ACL, dedup, store-and-forward, position cache, replay |
| `rustgate-transport` | Codec / framing primitives, hardware identity, UDP / multicast |
| `rustgate-resilience` | Circuit breakers, backoff, rate limiters, token buckets |
| `rustgate-metrics` | Prometheus scaffolding: OnceLock fallbacks, init() orchestration |
| `rustgate-archive` | Encrypted hash-chained archives for tamper-evident audit |
| `rustgate-codec-schema` | Declarative schema format + generic codec runtime |

### Client-facing transports

| Crate | Purpose |
|---|---|
| `rustgate-websocket` | wss:// listener with mTLS |
| `rustgate-mqtt` | MQTT 5.0/3.1.1 transport adapter with mTLS |
| `rustgate-nats` | NATS pub/sub bridge with JetStream history replay |
| `rustgate-http` | HTTP/webhook egress (auth, retry, circuit breaking) |
| `rustgate-enrollment` | HTTPS certificate enrollment (Marti v2 CSR signing) |
| `rustgate-federation` | V1 (length-prefixed XML) and V2 (gRPC) federation |
| `rustgate-proto` | TAK protobuf translation (XML ↔ proto) |

### Tactical protocol codecs

| Crate | Protocol |
|---|---|
| `rustgate-mavlink` | MAVLink v1/v2 frame codec |
| `rustgate-meshtastic` | Meshtastic / LoRa TAKPacket compact-protobuf codec |
| `rustgate-vmf` | VMF / MIL-STD-6017 bit-level codec (K05.1 Position Reports) |
| `rustgate-sapient` | SAPIENT (BSI Flex 335) autonomous-sensor / counter-UAS protobuf |
| `rustgate-nffi` | NFFI (STANAG 5527) NATO Friendly Force Information XML |
| `rustgate-dis` | DIS (IEEE 1278.1) Entity State PDU codec |
| `rustgate-link16` | Link 16 / JREAP-C (STANAG 5518) frame codec |
| `rustgate-stanag4586` | STANAG 4586 LOI 2-3 telemetry codec (NATO UAS interop) |
| `rustgate-asterix` | ASTERIX (Eurocontrol surveillance) binary codec |

### Partner / platform integrations

| Crate | Backend |
|---|---|
| `rustgate-lattice` | Anduril Lattice bidirectional adapter (partner-gated SDK) |
| `rustgate-foundry` | Palantir Foundry / Gotham REST/WebSocket bridge (partner-gated) |
| `rustgate-dds` | DDS Pub/Sub bridge for NGVA (STANAG 4754) / VICTORY |
| `rustgate-ogc-sensorthings` | OGC SensorThings v1.0 HTTP polling client |

### Higher-order pipeline

| Crate | Purpose |
|---|---|
| `rustgate-correlation` | Multi-sensor track correlation (CoT / Link 16 / MAVLink / DIS / SAPIENT) |
| `rustgate-inference` | Edge ML inference pipeline (pluggable backends) |
| `rustgate-guard` | Cross-domain content inspection guard: rate limit, marking, dedicated egress |
| `rustgate-missions` | TAK Data Packages — content-addressed package store |

### Server + client + ops

| Crate | Purpose |
|---|---|
| `rustgate-server` | Binary entry point, CLI, orchestration |
| `rustgate-client` | Reference client library for integration tests |
| `rustgate-admin` | HTTP management server: metrics, health, federation/ACL/missions APIs |
| `rustgate-operator` | Kubernetes operator for the `RustgateCluster` CRD |
| `rustgate-test-utils` | TestCa, CRL, and certificate generation helpers |

The README has the same table with per-crate links to source. **The crate
table here should match `README.md`'s.** When adding or renaming a crate,
update both — the workspace pre-commit hook flags drift.

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
| `http` | rustgate-http | HTTP/webhook egress with auth, retry, circuit breaking |
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

## Schema-Driven Tactical Codecs

Beyond the transport framing pipeline above, every tactical-protocol crate
(`rustgate-stanag4586`, `rustgate-dis`, `rustgate-mavlink`, `rustgate-vmf`,
`rustgate-link16`, `rustgate-asterix`, …) ships a hand-rolled byte-level codec
**plus** a YAML schema that declares the same wire layout in the codec-schema
vocabulary. The schema runtime (`rustgate-codec-schema::SchemaCodec`) is a
generic decode/encode driver that reads any schema and produces / consumes the
declared bytes — one runtime, N protocols.

### Why two implementations

The hand-rolled codec stays the production code path. The schema is **a
declarative pin** of the wire layout, validated by a per-crate `schema-parity`
proptest:

```text
Generate arbitrary inputs (proptest)
        │
        ▼
  reference_encoder()    SchemaCodec::from_entity()
        │                         │
        └────── byte-equal ───────┘  ← assertion
```

When the test passes for every arbitrary input proptest generates, the schema
and the hand-rolled codec agree on every wire byte. Any drift between the two
implementations (an offset change in the schema, a byte-ordering bug in the
hand-rolled codec) lights up the test the moment it lands.

### When to add a new grammar feature

The schema grammar is intentionally narrow — it covers what tactical wire
formats actually need:

| Grammar version | Feature | Real-world protocol that needed it |
|---|---|---|
| v1 | Fixed offsets, primitives, calibration, range, `entity-path` | STANAG 4586 vehicle position |
| v2 | Multi-message dispatch, `value-mapping` | DIS PDU header (72 PDU types) |
| v3 | `present-if` sparse-projection, `repeat` (`count-from`), single-byte bit-packing | DIS Entity State articulation tail, Entity Appearance bits |
| v4 | Cross-byte bit spans, bit-packed u16/u32/u64 | VMF 24-bit URN, 25/26-bit lat/lon |
| v4.1 | Signed bit-packed (i8/i16/i32/i64) with sign-extension | VMF signed latitude/longitude |
| v5 | Variable-shift `present-if` (`shift-mode: collapse-when-absent`) | VMF FPI cascade, ASTERIX FX-continuation chain |

Adding a new feature is a deliberate decision. The bar:

1. **At least one real protocol needs it** that we ship a codec for.
2. **Existing grammar genuinely cannot express it** — checked by trying to
   write the schema first and surfacing the validator error.
3. **Backward-compatible** — a v3 schema must validate and produce byte-identical
   wire output after the grammar grows to v4+.

Issues tracking deferred grammar work that doesn't yet have a forcing function:

- **#1411 v6 schema chaining** — header + body composition across separate
  schemas. Needed for VMF K05.1 production migration (the body's bit position
  depends on the variable-length header).
- **Protobuf / XML support** — would need an entirely different grammar
  vocabulary; codec-schema is binary-fixed-offset by design.

### What the schema does NOT do

- **Replace production codecs.** The schema-parity test is a pin, not a
  drop-in. Migrating a production codec to a SchemaCodec-driven runtime is a
  separate refactor (the only one that landed and stuck is STANAG 4586
  vehicle_position decode in #1390/#1393).
- **Handle XML / JSON / Protobuf.** The grammar targets fixed-offset binary.
  CoT (XML), SAPIENT (protobuf), Meshtastic (protobuf), NFFI (XML) have
  hand-rolled codecs and no schema-parity test.
- **Carry runtime semantics** beyond wire layout. Range guards, NaN rejection,
  ASCII sanitization on string fields, calibration into physical units — those
  stay in the wrapper layer above the SchemaCodec call.

For the full grammar reference (every YAML key, every validator constraint,
every backward-compat rule), see [`codec-schema-grammar.md`](https://github.com/rchiofalo/rustgate/blob/main/docs/codec-schema-grammar.md).

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
