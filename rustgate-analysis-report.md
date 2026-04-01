# rustgate Codebase Analysis Report

**Date:** March 26, 2026
**Scope:** Message flow tracing, feature flag audit, dependency review, refactor candidates, test gap analysis

---

## 1. Message Flow Trace

### Inbound Path: TLS → Parse → Route → Fanout

A message enters rustgate through one of four transports (TCP/TLS, WebSocket, Federation, NATS) and follows this path:

**Step 1 — TLS Handshake & Identity Extraction**
`rustgate-transport/src/listener.rs` accepts TCP connections, performs TLS handshake via `TlsAcceptor`, then extracts the client's `Identity` (CN, OU groups, SHA-256 fingerprint) from the X.509 certificate in `extract.rs`.

**Step 2 — Session Registration**
`rustgate-server/src/main.rs` creates a bounded `mpsc::channel(64)` per session, registers a `SessionHandle` with the `Router`, and replays cached position messages filtered by group overlap.

**Step 3 — Codec Framing**
`rustgate-transport/src/codec.rs` decodes raw bytes using one of four strategies: `LengthPrefixed` (1/2/4-byte header), `XmlStream` (tag-depth tracking), `LineDelimited`, or `TakProtobuf` (0xBF magic + varint). Protobuf frames are converted to XML via `rustgate-proto`.

**Step 4 — Message Construction**
`rustgate-cot/src/lib.rs` parses CoT XML to extract uid, event type, destination (Direct/Group/Broadcast), message type (Position/Chat/Alert), and TTL. The result is a `RoutableMessage` with `Identity`, `Destination`, `Bytes` payload, and `Metadata`.

**Step 5 — Rate Limiting & Archival**
Per-client token-bucket throttling drops excess messages. If `--archive-dir` is configured, messages are written to JSONL files via `CotArchiver`.

**Step 6 — Routing**
`rustgate-transport/src/router.rs` dispatches by destination: `Direct` → lookup by CN, `Group` → send to all group members (excluding sender, enforcing membership), `Broadcast` → send to all sessions except sender. Position messages are cached for SA replay.

**Step 7 — Encoding & Transmission**
The write loop receives messages from the channel, encodes via `RawEncoder` or `CotEncoder`, frames with the selected codec, and sends over TLS with a 30s write timeout.

### NATS Bridge

Outbound: After routing, `NatsPublisher` publishes to `{prefix}.{group}.update` subjects (echo-prevented via `X-Rustgate-Instance` header). JetStream history keyed by UID.

Inbound: `NatsSubscriber` listens on `{prefix}.>`, deserializes `WireEvent` JSON, converts to `RoutableMessage` with `source_protocol: "nats"` and `Destination::Broadcast`, then routes locally.

### Federation (Server-to-Server)

V1 uses TAK binary protocol over TLS. V2 uses gRPC with protobuf. Both share reconnection logic with exponential backoff and circuit breakers. Outbound forwarding injects flow tags for traceability, filters by group overlap, and enforces hop limits via provenance tracking. Dedup caches prevent message loops.

### WebSocket

Identical to TCP/TLS flow — same router, same session registration, same group enforcement. Only difference is the framing layer (WebSocket Binary/Text frames via `tokio-tungstenite`).

### Key Types

| Type | Location | Purpose |
|------|----------|---------|
| `Identity` | rustgate-core | CN + fingerprint + groups from X.509 |
| `RoutableMessage` | rustgate-core | Message envelope (source, destination, payload, metadata) |
| `Destination` | rustgate-core | Group / Direct / Broadcast enum |
| `FramingStrategy` | rustgate-core | LengthPrefixed / XmlStream / LineDelimited / TakProtobuf |
| `SessionHandle` | rustgate-transport | Per-client channel sender + identity |
| `Router` | rustgate-transport | Session registry + group index + position cache |
| `OnInbound` | rustgate-federation | `Arc<dyn Fn(String, Bytes) + Send + Sync>` callback |

---

## 2. Feature Flag Audit

### Summary

10 features defined across 6 crates, all properly used and propagated. No dead features or undefined references found.

### Issues Found

**ISSUE 1 (Medium): Missing server-level feature tests**
9 features in rustgate-server have `cfg` gates but no dedicated integration tests: `nats`, `enrollment`, `proto`, `full-detail`, `metrics`, `federation`, `federation-ha`, `websocket`, `jemalloc`.

**ISSUE 2 (Medium): Missing federation/api feature test**
The `api` feature in rustgate-federation has no dedicated test file (implicitly tested when `rustgate-server/federation` enables it).

**ISSUE 3 (Low): Incomplete FIPS testing**
FIPS tests only cover `rustgate-transport`. The federation and enrollment crates with FIPS enabled are untested.

### Feature Interaction Map

```
server/federation → federation/v2 + federation/api + serde_json
server/federation-ha → server/federation + federation/ha (async-nats)
server/full-detail → server/nats + nats/full-detail (rustgate-proto)
server/fips → transport/fips + federation?/fips + enrollment?/fips
```

All interactions are correctly wired with proper optional propagation (`?` operator).

---

## 3. Dependency Review

### Critical Issues

**socket2 not using workspace inheritance in rustgate-federation**
`crates/rustgate-federation/Cargo.toml` declares `socket2 = "0.6"` inline instead of `socket2 = { workspace = true }`. This breaks the workspace dependency contract and risks version drift.

**prost-build not using workspace inheritance in rustgate-proto**
`crates/rustgate-proto/Cargo.toml` declares `prost-build = "0.14"` inline in build-dependencies instead of using workspace inheritance.

### Security Advisories (3 active ignores)

| Advisory | Package | Status | Risk |
|----------|---------|--------|------|
| RUSTSEC-2025-0134 | rustls-pemfile 2.x | Unmaintained; transitive via async-nats | Low — no direct usage |
| RUSTSEC-2026-0042 | aws-lc-sys | CRL dist point scope error | Low — FIPS-only |
| RUSTSEC-2026-0049 | rustls-webpki | CRL dist point matching error | Low — no upstream fix |

All three are reasonable ignores. Recommend quarterly review for upstream fixes.

### Dependency Health

No redundancy detected. 41 workspace dependencies, all actively used. TLS stack is exclusively rustls (openssl/native-tls explicitly banned in deny.toml). License policy is well-configured with appropriate exceptions for aws-lc OpenSSL license.

---

## 4. Refactor Candidates

### High Priority (Low Effort)

**TCP keepalive duplication** — Identical `configure_tcp_keepalive()` code and constants in 4 locations (transport, federation, websocket, plaintext). Extract to `rustgate-core` as a shared utility.

**PEM parsing duplication** — `parse_certs`, `parse_key`, `parse_ca_store` reimplemented in transport and federation with near-identical error handling. Consolidate into a shared module (~150 lines saved).

**Test helper duplication** — WebSocket tests reimplement TLS client setup that should come from `rustgate-test-utils`.

### Medium Priority

**V1/V2 reconnection loop duplication** — Both federation client versions implement exponential backoff, reconnection limits, shutdown handling, and state transitions independently (~200+ duplicated lines). Extract a generic `ConnectionManager` or `PeerConnectionDriver` trait.

**FederationManager::adopt_peer() complexity** — Monolithic ~200-line function handling address parsing, circuit breaker setup, protocol-specific client creation, dedup wrapping, and peer registration. Break into composable helpers.

**V2 convert module size** — `federation/src/v2/convert.rs` at 1,279 lines. Split into `cot_to_event.rs`, `routable_message.rs`, and `timestamps.rs` submodules.

**main.rs size** — 1,783 lines. Extract into `config.rs`, `session_handler.rs`, `setup.rs`, and `api_routes.rs`.

### Architecture Improvements

**Missing Transport trait** — TCP, WebSocket, and UDP are implemented separately with no shared abstraction. A `Transport` trait would enable pluggable backends and mock testing.

**Stringly-typed peer IDs** — Peer IDs and server names are raw `String` throughout federation. Newtypes (`PeerId`, `ServerName`) would add compile-time safety.

**RustgateError uses raw strings** — Error variants hold `String` instead of structured types, making pattern matching and metrics difficult. Structured variants would improve error handling.

**Duplicated constants** — Timeouts (`WRITE_TIMEOUT`, `READ_TIMEOUT`, `TCP_KEEPALIVE_*`) repeated across crates. Centralize in `rustgate-core/src/constants.rs`.

---

## 5. Test Gap Analysis

### Current Coverage

729+ unit tests across the workspace, with integration tests in 7/10 crates. Three crates have zero integration tests.

### Proposed Test Strategy

**rustgate-core** — 41 tests in `tests/types.rs`
Coverage: Identity creation/membership/equality, RoutableMessage construction with all destination types, Metadata fields, MessageType variants, FramingStrategy/HeaderSize behaviors, Destination cloning/matching. Infrastructure: TestCa, standard lib only.

**rustgate-proto** — 35 tests in `tests/codec_integration.rs`
Coverage: TakFrameCodec encode/decode round-trips, partial frame buffering, magic byte validation, varint overflow, 16MB boundary, TakProtobufEncoder XML→proto conversion, protocol negotiation handshake (build_protocol_support_xml, parse_tak_request, build_tak_response), version rejection. Infrastructure: tokio, prost, BytesMut.

**rustgate-server** — 28+ tests across 4 files
`tests/cli_parsing.rs` (18 tests): All CLI argument combinations, env var overrides, framing/encoding enum parsing, defaults, bounds checking.
`tests/tls_config.rs` (12 tests): PEM validation, CRL handling, TlsListener binding, address reuse rejection.
`tests/archive_integration.rs` (8 tests): JSONL output, daily rotation, base64 encoding, JSON escaping, destination formatting.
`tests/startup_integration.rs` (4 tests): Audit events, metrics init, bounds checking.
Infrastructure: TestCa, tokio, tempfile.

**Total: ~104 new integration tests across 3 crates.**

---

## 6. Actionable Next Steps

| # | Action | Type | Effort |
|---|--------|------|--------|
| 1 | Fix socket2 workspace inheritance in rustgate-federation | Bug fix | 5 min |
| 2 | Fix prost-build workspace inheritance in rustgate-proto | Bug fix | 5 min |
| 3 | Extract TCP keepalive to rustgate-core | Refactor | 1 hr |
| 4 | Extract PEM parsing to shared module | Refactor | 2 hr |
| 5 | Add rustgate-core integration tests (41 tests) | Testing | 3 hr |
| 6 | Add rustgate-proto integration tests (35 tests) | Testing | 4 hr |
| 7 | Add rustgate-server CLI/config tests (28+ tests) | Testing | 5 hr |
| 8 | Extract V1/V2 reconnection logic | Refactor | 4 hr |
| 9 | Split v2/convert.rs into submodules | Refactor | 2 hr |
| 10 | Split main.rs into modules | Refactor | 6 hr |
