# Planned GitHub Issues

Generated from codebase analysis (March 2026). Each section is one issue. Branch prefix and conventional commit type are noted for each.

---

## 1. fix(deps): use workspace inheritance for socket2 in rustgate-federation

**Labels:** bug, dependencies
**Branch:** `fix/socket2-workspace-inheritance`
**Effort:** 5 min

### Description

`crates/rustgate-federation/Cargo.toml` declares `socket2 = "0.6"` inline instead of using `socket2 = { workspace = true }`. This breaks the workspace dependency inheritance pattern and creates risk of version drift.

All other crates using socket2 (rustgate-transport, rustgate-websocket) correctly reference the workspace version.

### Acceptance Criteria

- [ ] Change `socket2 = "0.6"` to `socket2 = { workspace = true }` in `crates/rustgate-federation/Cargo.toml`
- [ ] Verify `cargo check --workspace` passes
- [ ] Verify no duplicate socket2 versions in `Cargo.lock`

---

## 2. fix(deps): use workspace inheritance for prost-build in rustgate-proto

**Labels:** bug, dependencies
**Branch:** `fix/prost-build-workspace-inheritance`
**Effort:** 5 min

### Description

`crates/rustgate-proto/Cargo.toml` declares `prost-build = "0.14"` inline in `[build-dependencies]` instead of using `prost-build = { workspace = true }`. The workspace already defines `prost-build = "0.14"` in root `Cargo.toml`.

### Acceptance Criteria

- [ ] Change `prost-build = "0.14"` to `prost-build = { workspace = true }` in `crates/rustgate-proto/Cargo.toml` under `[build-dependencies]`
- [ ] Verify `cargo check -p rustgate-proto` passes
- [ ] Verify no duplicate prost-build versions in `Cargo.lock`

---

## 3. refactor(core): extract shared TCP keepalive utility

**Labels:** refactor, code-quality
**Branch:** `refactor/shared-tcp-keepalive`
**Effort:** 1 hr

### Description

Identical TCP keepalive configuration code (constants + `configure_tcp_keepalive()` function) is duplicated in 4 locations:

- `crates/rustgate-transport/src/listener.rs` (lines 17-25)
- `crates/rustgate-transport/src/plaintext.rs`
- `crates/rustgate-federation/src/connector.rs` (lines 20-24)
- `crates/rustgate-websocket/src/lib.rs` (lines 24-31)

Each copy uses the same constants (30s idle, 10s interval) and the same socket2 setup logic.

### Acceptance Criteria

- [ ] Add `rustgate-core/src/net.rs` module with `configure_tcp_keepalive(socket: &socket2::Socket) -> io::Result<()>` and keepalive constants
- [ ] Add `socket2` as a dependency of `rustgate-core`
- [ ] Replace all 4 inline implementations with calls to the shared function
- [ ] All existing tests pass
- [ ] Add a unit test in rustgate-core that verifies socket options are set correctly

---

## 4. refactor(transport): extract shared PEM parsing utilities

**Labels:** refactor, code-quality
**Branch:** `refactor/shared-pem-parsing`
**Effort:** 2 hr

### Description

PEM parsing functions (`parse_certs`, `parse_key`, `parse_ca_store`) are reimplemented with near-identical logic in 7 locations:

**Production code (3 files):**
- `crates/rustgate-transport/src/config.rs` (lines 86-130) — uses `RustgateError::Config`
- `crates/rustgate-federation/src/connector.rs` (lines 171-209) — uses `anyhow::Result`
- `crates/rustgate-federation/src/trust_store.rs` (lines 142-154, 281-290) — inline cert parsing with `anyhow::Context`

**Test code (4 files):**
- `crates/rustgate-websocket/tests/ws_listener.rs` (lines 18-43)
- `crates/rustgate-websocket/tests/ws_server.rs` (lines 19-44) — identical to ws_listener
- `crates/rustgate-transport/tests/tls_listener.rs`
- `crates/rustgate-transport/tests/crl.rs`, `fips.rs`, `e2e_routing.rs`

The core logic is identical across all 7 locations — only error handling differs (RustgateError vs anyhow vs `.expect()` panics).

### Acceptance Criteria

- [ ] Create shared PEM parsing module (either `rustgate-transport::pem` or `rustgate-core::pem`)
- [ ] Provide `parse_certs(pem: &str) -> Result<Vec<CertificateDer>>`, `parse_key(pem: &str) -> Result<PrivateKeyDer>`, `parse_ca_store(pem: &str) -> Result<RootCertStore>`
- [ ] Update rustgate-transport `TlsConfig::from_pem()` to use shared functions
- [ ] Update rustgate-federation `PeerConnector` and `TrustStore` to use shared functions
- [ ] Move test PEM helpers to `rustgate-test-utils` and update all 4 test files
- [ ] All existing tests pass

---

## 5. refactor(federation): extract generic reconnection manager

**Labels:** refactor, code-quality
**Branch:** `refactor/connection-manager`
**Effort:** 4 hr

### Description

V1 and V2 federation clients implement nearly identical reconnection loops with:

- Exponential backoff logic
- Reconnection attempt limits and counting
- Shutdown signal handling
- State transitions (Connecting → Connected/Disconnected → Reconnecting)
- Error logging and audit trail calls

**Files:**
- `crates/rustgate-federation/src/v1/client.rs` (lines 126-260+)
- `crates/rustgate-federation/src/v2/client.rs` (lines 170-350+)

This duplicates ~200+ lines and makes it harder to keep reconnection behavior consistent.

### Proposed Design

```rust
pub trait PeerConnectionDriver: Send + Sync {
    async fn connect(&self) -> Result<()>;
    async fn run_session(&self) -> Result<()>;
    fn peer_id(&self) -> &str;
}
```

A generic `ConnectionManager` wraps any driver with shared backoff, retry, shutdown, and state logic.

### Acceptance Criteria

- [ ] Create `ConnectionManager` or `ReconnectLoop` abstraction in rustgate-federation
- [ ] Implement `PeerConnectionDriver` for V1 and V2 clients
- [ ] Reconnection behavior is identical to current implementation
- [ ] All federation integration tests pass
- [ ] Add unit test for backoff timing and retry limits

---

## 6. refactor(federation): split v2/convert.rs into submodules

**Labels:** refactor, code-quality
**Branch:** `refactor/split-v2-convert`
**Effort:** 2 hr

### Description

`crates/rustgate-federation/src/v2/convert.rs` is 1,279 lines and combines multiple concerns:

- CoT XML → FederatedEvent (proto) conversion
- RoutableMessage ↔ FederatedEvent conversions
- Timestamp parsing and formatting
- Group extraction and field mapping

### Acceptance Criteria

- [ ] Split into submodules: `cot_to_event.rs`, `routable_message.rs`, `timestamps.rs`
- [ ] Re-export public items from `convert/mod.rs` to maintain API compatibility
- [ ] No file exceeds ~400 lines
- [ ] All existing tests pass without modification

---

## 7. refactor(server): split main.rs into modules

**Labels:** refactor, code-quality
**Branch:** `refactor/split-server-main`
**Effort:** 6 hr

### Description

`crates/rustgate-server/src/main.rs` is 1,783 lines. The `run()` function alone is 723 lines (lines 321-1043), handling TLS config, metrics init, WebSocket setup, HTTP metrics server, TCP listener, plaintext listener, signal handlers, and nested task spawning. Other large functions: `handle_session()` (109 lines), `read_loop()` (106 lines).

The file also has 3 `#[allow(clippy::too_many_arguments)]` attributes (lines 1256, 1377, 1457), indicating functions that have accumulated too many parameters — a sign they need restructuring.

### Proposed Structure

```
crates/rustgate-server/src/
├── main.rs          (~200 lines — entrypoint, orchestration)
├── cli.rs           (CLI arg definitions and parsing)
├── config.rs        (config building from CLI + env)
├── session.rs       (handle_session, read_loop, write_loop)
├── setup.rs         (TLS, listener, NATS, federation init)
└── metrics.rs       (already exists — expand if needed)
```

### Acceptance Criteria

- [ ] main.rs reduced to <300 lines
- [ ] `run()` broken into focused setup functions (<100 lines each)
- [ ] Functions with `too_many_arguments` refactored to use config structs
- [ ] Each extracted module has clear `pub` interface
- [ ] No behavior changes — pure refactor
- [ ] All existing tests pass
- [ ] Feature gates preserved correctly in each module

---

## 8. test(core): add integration tests for rustgate-core types

**Labels:** testing
**Branch:** `test/core-integration-tests`
**Effort:** 3 hr

### Description

rustgate-core has 0 integration tests. It defines the foundational types used by every other crate: `Identity`, `RoutableMessage`, `Destination`, `MessageType`, `Metadata`, `FramingStrategy`, `HeaderSize`, and the `MessageEncoder` trait.

### Test File: `crates/rustgate-core/tests/types.rs`

**Identity tests (8):**
- Creation with CN, fingerprint, groups
- `is_member_of()` for existing and nonexistent groups
- Empty groups behavior
- Display impl shows CN
- Equality and hash consistency
- BTreeSet ordering of groups

**RoutableMessage tests (18):**
- Construction with each Destination variant (Group, Direct, Broadcast)
- Payload preservation as Bytes
- All Metadata fields (received_at, source_protocol, ttl)
- All MessageType variants including `Other(String)`
- MessageType equality and inequality
- Large payload handling (10MB)

**Destination tests (5):**
- Group name preservation
- Direct identity equality
- Pattern matching all variants
- Clone semantics

**FramingStrategy & HeaderSize tests (10):**
- `byte_count()` for each HeaderSize variant
- Equality comparisons
- Each FramingStrategy variant identity
- Clone and Debug impls

### Acceptance Criteria

- [ ] `crates/rustgate-core/tests/types.rs` created with ~41 tests
- [ ] All tests pass with `cargo nextest run -p rustgate-core`
- [ ] Test file uses `#![allow(clippy::panic, clippy::unwrap_used)]`

---

## 9. test(proto): add integration tests for rustgate-proto codec and negotiation

**Labels:** testing
**Branch:** `test/proto-integration-tests`
**Effort:** 4 hr

### Description

rustgate-proto has inline unit tests for XML↔protobuf conversion and varint codec, but no integration tests covering the `TakFrameCodec` async codec, `TakProtobufEncoder`, or protocol negotiation flow.

### Test File: `crates/rustgate-proto/tests/codec_integration.rs`

**TakFrameCodec tests (15):**
- Encode/decode round-trip for minimal proto message
- Multiple frames in a single stream
- Partial frame buffering (returns None until complete)
- Incomplete varint returns None
- Invalid magic byte (0x00 instead of 0xBF) → error
- Varint exceeding max bytes → error
- Oversized frame (>16MB) → rejection
- Empty payload (valid)
- 16MB boundary test (exactly at limit)
- State reset after successful decode
- Payload byte-for-byte preservation (including null bytes)

**TakProtobufEncoder tests (8):**
- XML → protobuf encoding round-trip
- Invalid XML → io::Error
- Complex CoT event with contact, group, precision, track
- Verify encoder is Send + Sync

**Protocol negotiation tests (12):**
- `build_protocol_support_xml()` output structure validation
- `build_tak_response()` framing and protobuf validity
- `parse_tak_request()` accepts version 1, rejects version 2
- Missing TakControl → error
- Happy-path negotiation scenario

### Acceptance Criteria

- [ ] `crates/rustgate-proto/tests/codec_integration.rs` created with ~35 tests
- [ ] All tests pass with `cargo nextest run -p rustgate-proto`
- [ ] Test file uses `#![allow(clippy::panic, clippy::unwrap_used)]`

---

## 10. test(server): add integration tests for CLI parsing and TLS config

**Labels:** testing
**Branch:** `test/server-integration-tests`
**Effort:** 5 hr

### Description

rustgate-server has 0 integration tests. The binary entrypoint handles CLI parsing, TLS config building, archive management, and startup orchestration.

### Test Files

**`crates/rustgate-server/tests/cli_parsing.rs` (18 tests):**
- Default values for all CLI args (bind, max_connections, framing, encoding)
- `--bind` from arg and from `RUSTGATE_BIND` env var
- Arg overrides env var
- `--cert`, `--key`, `--ca` required trio
- `--crl` optional from arg and env
- `--fips-required` flag
- All `--framing` variants (xml, length-prefixed, line, tak-protobuf)
- All `--encoding` variants (raw, cot, tak-protobuf)
- `--max-connections` custom value, default, and bounds

**`crates/rustgate-server/tests/tls_config.rs` (12 tests):**
- Valid PEM → Ok(config)
- Invalid cert/key/CA PEM → descriptive error
- Mismatched key → error
- CRL from valid PEM and from invalid PEM
- TlsListener bind to localhost:0, IPv6, invalid address, already-in-use

**`crates/rustgate-server/tests/archive_integration.rs` (8 tests):**
- Archive directory creation
- JSONL line format validation
- Daily file rotation
- Append behavior
- Base64 payload encoding
- JSON escaping in CN field
- Destination formatting (broadcast, group:X, direct:X)

### Acceptance Criteria

- [ ] 3 test files created under `crates/rustgate-server/tests/`
- [ ] All tests pass with `cargo nextest run -p rustgate-server`
- [ ] Tests use TestCa from rustgate-test-utils for TLS fixtures
- [ ] Archive tests use tempfile for cleanup
- [ ] Test files use `#![allow(clippy::panic, clippy::unwrap_used)]`

---

## 11. test(federation): add integration tests for server-level feature gates

**Labels:** testing, feature-flags
**Branch:** `test/feature-gate-coverage`
**Effort:** 3 hr

### Description

9 features in rustgate-server have `cfg` gates but no dedicated integration tests. Additionally, the `api` feature in rustgate-federation has no dedicated test file.

**Untested feature gates in rustgate-server:**
- `nats` (1 cfg gate in main.rs)
- `enrollment` (1 cfg gate)
- `proto` (6 cfg gates)
- `full-detail` (depends on nats + rustgate-nats/full-detail)
- `metrics` (9 cfg gates in main.rs, 5 in metrics.rs)
- `federation` (2 cfg gates in main.rs)
- `federation-ha` (depends on federation + rustgate-federation/ha)
- `websocket` (1 cfg gate)
- `jemalloc` (1 cfg gate)

**Untested feature in rustgate-federation:**
- `api` (2 cfg gates in lib.rs)

### Acceptance Criteria

- [ ] Add feature-gated compilation tests that verify each feature compiles in isolation
- [ ] Add `rustgate-federation/tests/api_integration.rs` gated behind `#[cfg(feature = "api")]`
- [ ] Verify with `cargo hack check --feature-powerset --depth 2 --exclude-features jemalloc,fips --no-dev-deps`
- [ ] Document any feature combinations that require special handling

---

## 12. refactor(federation): break down FederationManager::adopt_peer()

**Labels:** refactor, code-quality
**Branch:** `refactor/adopt-peer-decompose`
**Effort:** 2 hr

### Description

`FederationManager::adopt_peer()` in `crates/rustgate-federation/src/manager.rs` (lines ~350-550+) is a ~200-line monolithic function handling:

- Address parsing and validation
- Circuit breaker initialization
- Protocol-specific (V1 vs V2) client setup with callbacks
- Dedup cache wrapping for V1
- Event conversion and filtering for V2
- Peer state registration

### Proposed Decomposition

```rust
fn create_v1_client_config(...) -> V1ClientConfig { }
fn create_v2_client_config(...) -> V2ClientConfig { }
fn create_dedup_wrapper(dedup: Arc<Mutex<MessageDedup>>) -> OnMessage { }
fn create_v2_event_handler(...) -> OnEvent { }
```

### Acceptance Criteria

- [ ] `adopt_peer()` reduced to ~40-50 lines of orchestration
- [ ] Each helper function has a clear, testable interface
- [ ] All federation integration tests pass
- [ ] No behavior changes

---

## 13. refactor(core): introduce newtypes for PeerId and ServerName

**Labels:** refactor, type-safety
**Branch:** `refactor/peer-id-newtype`
**Effort:** 2 hr

### Description

Peer IDs and server names are raw `String` throughout rustgate-federation with no type distinction. This allows accidental misuse (e.g., passing a server name where a peer ID is expected).

**Affected files:**
- `rustgate-federation/src/peer.rs` — `pub id: String`
- `rustgate-federation/src/manager.rs` — HashMap keys, comparisons
- `rustgate-federation/src/connector.rs` — `server_name: &str`

### Acceptance Criteria

- [ ] Create `PeerId` and `ServerName` newtypes in rustgate-federation
- [ ] Derive `Clone`, `Debug`, `PartialEq`, `Eq`, `Hash`, `Display` on both
- [ ] Add `fn new(s: impl Into<String>) -> Self` constructors
- [ ] Update all usages across federation crate
- [ ] All existing tests pass

---

## 14. refactor(core): use structured error variants in RustgateError

**Labels:** refactor, code-quality
**Branch:** `refactor/structured-errors`
**Effort:** 3 hr

### Description

`RustgateError` variants hold raw `String` (e.g., `Transport(String)`) making it difficult to pattern-match on specific error kinds, count errors by category in metrics, or produce structured log fields.

### Proposed Design

```rust
pub enum RustgateError {
    Transport(TransportError),
    Protocol(ProtocolError),
    Routing(RoutingError),
}

pub enum TransportError {
    TlsHandshakeFailed { addr: SocketAddr, reason: String },
    ConnectionTimeout { addr: SocketAddr, duration: Duration },
    // ...
}
```

### Acceptance Criteria

- [ ] Define structured sub-enums with `thiserror::Error`
- [ ] Migrate all `RustgateError::Transport(String)` call sites
- [ ] Verify error messages remain human-readable
- [ ] All tests pass
- [ ] Metrics can count by error category (if metrics feature enabled)

---

## 15. refactor(core): centralize timeout and buffer constants

**Labels:** refactor, code-quality
**Branch:** `refactor/centralize-constants`
**Effort:** 1 hr

### Description

Timeout and buffer constants are scattered across crates:

- `WRITE_TIMEOUT` — defined in server, websocket, enrollment
- `READ_TIMEOUT` — defined in server, websocket
- `TCP_KEEPALIVE_IDLE` / `TCP_KEEPALIVE_INTERVAL` — defined in 4 places
- `MAX_FRAME_SIZE` — codec level

### Acceptance Criteria

- [ ] Add `rustgate-core/src/constants.rs` with all shared constants
- [ ] Document the rationale for each value
- [ ] Update all crates to import from rustgate-core
- [ ] All tests pass

---

## 16. chore(deps): quarterly security advisory review

**Labels:** security, maintenance
**Branch:** n/a (process issue)
**Effort:** recurring

### Description

Three security advisories are currently ignored in `deny.toml`:

| Advisory | Package | Reason |
|----------|---------|--------|
| RUSTSEC-2025-0134 | rustls-pemfile 2.x | Unmaintained; transitive via async-nats |
| RUSTSEC-2026-0042 | aws-lc-sys | CRL distribution point scope check error |
| RUSTSEC-2026-0049 | rustls-webpki | CRL distribution point matching error |

All three are blocked on upstream fixes.

### Acceptance Criteria

- [ ] Review each advisory quarterly for upstream resolution
- [ ] Remove ignores from deny.toml when upstream fixes land
- [ ] Update async-nats when rustls-pemfile dependency is dropped
- [ ] Consider adding a scheduled CI job or reminder

---

## 17. fix(federation): replace expect() calls in metrics accessors

**Labels:** bug, code-quality
**Branch:** `fix/federation-metrics-expect`
**Effort:** 1 hr

### Description

`crates/rustgate-federation/src/metrics.rs` has 9+ public functions (lines 113-167) that call `.get().expect("federation metrics not initialized")` on `OnceLock` getters. These violate the workspace `clippy::unwrap_used = "deny"` policy and will panic at runtime if metrics are accessed before initialization.

**Affected lines:** 113, 120, 127, 134, 141, 146, 153, 160, 167

### Acceptance Criteria

- [ ] Replace all `.expect()` calls with fallible accessors (return `Option<&T>` or use `?`)
- [ ] Ensure callers handle the `None`/`Err` case gracefully
- [ ] Verify no panics possible from uninitialized metrics
- [ ] All existing tests pass

---

## 18. fix(server): replace expect() calls in production code paths

**Labels:** bug, code-quality
**Branch:** `fix/server-expect-calls`
**Effort:** 30 min

### Description

`crates/rustgate-server/src/main.rs` has 2 `.expect()` calls in production code:

- Line 548: `.parse().expect()` — address parsing
- Line 1054: `signal().expect()` — signal handler setup

Additionally, `crates/rustgate-federation/src/config.rs` has 2 `.expect()` calls for default address parsing (lines 138, 140).

While these are arguably infallible (parsing known-valid strings, or setting up OS signals), they still violate the `clippy::unwrap_used = "deny"` policy and should use `?` propagation for consistency.

### Acceptance Criteria

- [ ] Replace `.expect()` with `?` or `.map_err()` in all production code paths
- [ ] Verify no remaining `.expect()` or `.unwrap()` in non-test code
- [ ] All existing tests pass

---

## 19. fix(deps): add tikv-jemallocator to workspace dependencies

**Labels:** bug, dependencies
**Branch:** `fix/jemallocator-workspace-inheritance`
**Effort:** 5 min

### Description

`crates/rustgate-server/Cargo.toml` (line 42) declares `tikv-jemallocator = { version = "0.6", optional = true }` inline. While it's only used by one crate, the workspace convention is to declare all dependencies in root `Cargo.toml` `[workspace.dependencies]`.

### Acceptance Criteria

- [ ] Add `tikv-jemallocator = { version = "0.6" }` to root `Cargo.toml` `[workspace.dependencies]`
- [ ] Change rustgate-server to `tikv-jemallocator = { workspace = true, optional = true }`
- [ ] Verify `cargo check --workspace` passes

---

## 20. refactor(federation): split api.rs into submodules

**Labels:** refactor, code-quality
**Branch:** `refactor/split-federation-api`
**Effort:** 2 hr

### Description

`crates/rustgate-federation/src/api.rs` is 1,206 lines — the 4th largest file in the codebase. This was not flagged in the initial analysis. It handles federation HTTP API endpoints and should be split similarly to v2/convert.rs.

### Acceptance Criteria

- [ ] Split into logical submodules (routes, handlers, types)
- [ ] Re-export public items to maintain API compatibility
- [ ] No file exceeds ~400 lines
- [ ] All existing tests pass

---

## 21. chore(test-utils): consolidate duplicated test helpers

**Labels:** testing, code-quality
**Branch:** `chore/consolidate-test-helpers`
**Effort:** 2 hr

### Description

Integration tests across multiple crates duplicate common setup patterns that should be in `rustgate-test-utils`:

- **PEM parsing helpers** (`parse_certs`, `parse_key`, `build_client_tls_config`) — duplicated in ws_listener.rs, ws_server.rs, tls_listener.rs, crl.rs, fips.rs, e2e_routing.rs
- **Certificate setup boilerplate** — repeated TestCa initialization patterns across federation v2, HA, and enrollment tests
- **Tempdir management** — each test creates its own temp directory handling

### Acceptance Criteria

- [ ] Add `rustgate-test-utils::tls` module with shared PEM parsing and TLS client config helpers
- [ ] Add `rustgate-test-utils::fixtures` module with common certificate pair generators
- [ ] Update all integration test files to import from test-utils
- [ ] Verify no duplicated helper functions remain across test files
- [ ] All existing tests pass

---

## 22. fix(server): remove or wire dead_code metrics functions

**Labels:** bug, code-quality
**Branch:** `fix/dead-metrics-functions`
**Effort:** 30 min

### Description

`crates/rustgate-server/src/metrics.rs` has 4 functions marked `#[allow(dead_code)]` (lines 238-253):

- `pings_received()`
- `nats_publish_errors()`
- `nats_received()`
- `negotiations()`

These are either incomplete feature integration or leftover stubs. Additionally, `crates/rustgate-core/src/audit.rs` (line 21) has `federation_config_changed()` marked dead with comment "Wired when federation config API is added".

### Acceptance Criteria

- [ ] Either wire the dead functions into their intended call sites, or remove them
- [ ] If keeping for future use, add tracking issues and clear doc comments explaining the plan
- [ ] Remove `#[allow(dead_code)]` attributes
- [ ] All existing tests pass

---

---

# Security Hardening (from deep audit + TLS research)

---

## 23. fix(security): bound JWT revocation cache to prevent memory exhaustion

**Labels:** security, bug
**Branch:** `fix/bound-jwt-revocation-cache`
**Effort:** 2 hr
**Ref:** CWE-770 (Allocation of Resources Without Limits)

### Description

`crates/rustgate-federation/src/jwt.rs` (lines 44-45) maintains an unbounded `HashSet<String>` of revoked JWT token IDs. The `revoke()` method (line 151) inserts without any size check. An attacker can trigger revocation of many tokens, causing unbounded memory consumption.

Combined with the 3600-second default TTL, a federation server under attack could accumulate millions of revoked JTI entries.

### Acceptance Criteria

- [ ] Implement bounded LRU cache for revoked JTIs (max 10,000 or configurable)
- [ ] Auto-expire revoked JTI entries after their token's expiration time
- [ ] Add metric for revocation cache size
- [ ] Add warning log when cache exceeds 80% capacity

---

## 24. fix(security): bound position cache to prevent memory exhaustion

**Labels:** security, bug
**Branch:** `fix/bound-position-cache`
**Effort:** 2 hr
**Ref:** CWE-770

### Description

`crates/rustgate-transport/src/cache.rs` (line 23) uses an unbounded `HashMap<String, RoutableMessage>` for the position cache. An attacker with a compromised CA can generate valid client certificates with unique CNs and send position updates, growing the cache without limit. Each entry includes a full payload (up to 16 MB).

The cache does have TTL-based expiration and a periodic sweep (60s interval), but no max entry count.

### Acceptance Criteria

- [ ] Add configurable max cache size (default 100,000 entries)
- [ ] Implement LRU eviction when limit is exceeded
- [ ] Add metric for cache size and eviction count
- [ ] Add CLI flag `--position-cache-max-entries`
- [ ] Document the limit in operational runbooks

---

## 25. fix(security): replace custom HMAC-SHA256 with hmac crate

**Labels:** security, code-quality
**Branch:** `fix/replace-custom-hmac`
**Effort:** 1 hr
**Ref:** CWE-327 (Use of Broken or Risky Cryptographic Algorithm)

### Description

`crates/rustgate-federation/src/jwt.rs` (lines 247-288) implements HMAC-SHA256 manually with custom ipad/opad XOR logic instead of using the peer-reviewed `hmac` crate from RustCrypto. While the implementation appears correct (including constant-time comparison at lines 290-299), custom crypto is error-prone and unaudited.

### Acceptance Criteria

- [ ] Replace custom `hmac_sha256()` with `hmac` crate: `use hmac::{Hmac, Mac}; type HmacSha256 = Hmac<Sha256>;`
- [ ] Add `hmac = "0.12"` to workspace dependencies
- [ ] Verify existing JWT tests pass with the library implementation
- [ ] Remove ~50 lines of custom crypto code

---

## 26. feat(security): add TLS handshake rate limiting

**Labels:** security, enhancement
**Branch:** `feat/handshake-rate-limit`
**Effort:** 4 hr
**Ref:** NIST 800-53 SC-5 (DoS Protection)

### Description

`crates/rustgate-transport/src/listener.rs` accepts TLS connections in an unbounded loop with no rate limiting on handshake attempts per IP. An attacker can flood the listener with incomplete handshakes, consuming CPU on certificate chain validation and TLS crypto.

### Acceptance Criteria

- [ ] Implement per-IP handshake failure tracking in listener.rs
- [ ] After N consecutive failures in Y seconds, block IP for Z seconds
- [ ] Add CLI flags: `--handshake-fail-threshold`, `--handshake-fail-window`, `--handshake-block-duration`
- [ ] Log blocked IPs with structured tracing
- [ ] Add metric for blocked handshakes

---

## 27. feat(security): add configurable TLS version minimum

**Labels:** security, enhancement
**Branch:** `feat/tls-version-min`
**Effort:** 2 hr
**Ref:** NIST SP 1800-37, NSA/CISA Joint Guidance (2025)

### Description

rustgate enables TLS 1.2 via `features = ["tls12"]` in rustls with no option to enforce TLS 1.3 only. For tactical systems, NIST SP 1800-37 (2025) recommends TLS 1.3 for new deployments.

### Acceptance Criteria

- [ ] Add CLI flag `--tls-version-min` (values: `1.2`, `1.3`, default: `1.2`)
- [ ] When set to `1.3`, configure rustls to reject TLS 1.2 handshakes
- [ ] Document in README and tls-certificates.md that TLS 1.3-only is recommended
- [ ] Add integration test verifying TLS 1.2 rejection when min is 1.3

---

## 28. feat(security): validate X.509 key usage extensions

**Labels:** security, enhancement
**Branch:** `feat/key-usage-validation`
**Effort:** 3 hr
**Ref:** RFC 5280 §4.2.1.3, NIST 800-53 SC-12

### Description

`crates/rustgate-transport/src/extract.rs` extracts CN, OU, and fingerprint from client certificates but does not validate X.509 key usage extensions. A certificate intended for code signing could authenticate as a TLS client.

### Acceptance Criteria

- [ ] Parse keyUsage extension in `extract_identity()` (client certs: require digitalSignature)
- [ ] Add CLI flag `--validate-key-usage` (default: false for backward compat)
- [ ] Log key usage fields on connection
- [ ] Add integration test with cert that has wrong key usage

---

## 29. fix(security): sanitize certificate CN/OU before logging

**Labels:** security, code-quality
**Branch:** `fix/sanitize-cert-fields-logging`
**Effort:** 1 hr
**Ref:** CWE-117 (Log Injection)

### Description

`crates/rustgate-transport/src/listener.rs` (lines 100-105) logs client certificate CN and OU fields directly. An attacker controlling a client certificate can inject control characters, ANSI escape codes, or newlines into log output, corrupting structured logs or SIEM parsing.

### Acceptance Criteria

- [ ] Add `sanitize_log_field()` utility that escapes control chars and newlines
- [ ] Apply to all certificate field logging (listener.rs, audit events, federation peer logging)
- [ ] Add test with CN containing `\n`, `\r`, ANSI escape sequences

---

## 30. feat(security): add CRL freshness validation

**Labels:** security, enhancement
**Branch:** `feat/crl-freshness-check`
**Effort:** 2 hr
**Ref:** RFC 5280 §5.1.2.5

### Description

`crates/rustgate-transport/src/config.rs` loads CRL files via `with_crls()` but does not validate the CRL's `nextUpdate` field. Stale CRLs allow revoked certificates to authenticate without detection. The FIPS docs explicitly note: "CRL nextUpdate timestamps are not validated."

### Acceptance Criteria

- [ ] Parse CRL `nextUpdate` field after loading
- [ ] Add CLI flag `--crl-max-age` (seconds, default: 86400)
- [ ] Warn if CRL is stale; optionally reject connections
- [ ] Add CRL reload interval option `--crl-check-interval`
- [ ] Update docs/tls-certificates.md with CRL rotation guidance

---

## 31. feat(security): bound federation peer groups

**Labels:** security, enhancement
**Branch:** `feat/bound-peer-groups`
**Effort:** 1 hr
**Ref:** CWE-770

### Description

`crates/rustgate-federation/src/v2/server.rs` (lines 37-40) maintains a `HashMap<String, Vec<String>>` of peer-advertised groups with no bounds. A malicious federation peer could advertise millions of group strings, causing unbounded memory growth.

### Acceptance Criteria

- [ ] Limit groups per peer (max 1,000)
- [ ] Limit group name length (max 256 bytes)
- [ ] Reject peers that exceed limits with structured error log
- [ ] Add metric tracking group count per peer

---

## 32. fix(security): add NATS subject token length limit

**Labels:** security, bug
**Branch:** `fix/nats-subject-length-limit`
**Effort:** 30 min
**Ref:** CWE-400

### Description

`crates/rustgate-nats/src/publisher.rs` (lines 50-52) sanitizes NATS group tokens but does not enforce a length limit. An attacker controlling the `source.groups` field could inject extremely long group names creating oversized NATS subjects.

### Acceptance Criteria

- [ ] Enforce max 256-byte limit on sanitized NATS tokens in `sanitize_nats_token()`
- [ ] Return None for tokens exceeding the limit
- [ ] Add test with oversized group name

---

## 33. docs(security): add unauthenticated metrics endpoint warning

**Labels:** security, documentation
**Branch:** `docs/metrics-auth-warning`
**Effort:** 30 min
**Ref:** CWE-306

### Description

The `/metrics` endpoint (`crates/rustgate-server/src/metrics.rs` lines 330-396) is served on an unauthenticated HTTP server. It exposes session counts, routing patterns, protocol stats, and NATS status — useful for attacker reconnaissance.

### Acceptance Criteria

- [ ] Document in README that operators must firewall the metrics port in hostile environments
- [ ] Add note in docs/deployment.md about binding metrics to localhost/private interface
- [ ] Consider future work: optional HTTP Basic Auth for metrics endpoint

---

# Performance & Async Correctness

---

## 34. fix(perf): move archive file I/O off async read loop

**Labels:** bug, performance
**Branch:** `fix/archive-async-io`
**Effort:** 3 hr

### Description

`crates/rustgate-server/src/archive.rs` (lines 46-105) performs blocking file I/O (`std::fs::File::write_all()`) while holding a `std::sync::Mutex`, called directly from the async read loop at main.rs line 1329. This blocks the tokio worker thread on every message when archiving is enabled.

### Acceptance Criteria

- [ ] Move archive writes to `tokio::task::spawn_blocking` or use `tokio::fs`
- [ ] Replace `std::sync::Mutex` with `tokio::sync::Mutex` if holding across `.await`
- [ ] Or: buffer archive writes and flush via a dedicated background task with a channel
- [ ] Benchmark: verify no latency impact on message routing when archiving is enabled

---

## 35. fix(perf): remove block_on in federation API handler

**Labels:** bug, performance
**Branch:** `fix/federation-api-block-on`
**Effort:** 1 hr

### Description

`crates/rustgate-federation/src/api.rs` uses `rt.block_on(async { ... })` inside an async HTTP request handler to collect the request body. This blocks the entire handler task.

### Acceptance Criteria

- [ ] Replace `block_on()` with direct `.await` on body collection
- [ ] Verify federation API integration tests pass
- [ ] No blocking calls remain in async context

---

## 36. fix(perf): bound federation HA channels

**Labels:** bug, performance
**Branch:** `fix/bound-ha-channels`
**Effort:** 30 min

### Description

`crates/rustgate-federation/src/manager.rs` (lines 76-82) uses `mpsc::unbounded_channel()` for HA adopt/lost events. Under rapid failover conditions, these can grow without bound.

### Acceptance Criteria

- [ ] Replace `unbounded_channel()` with bounded `mpsc::channel(256)` (or similar)
- [ ] Handle full channel gracefully (drop old events or log warning)
- [ ] All HA integration tests pass

---

# Code Quality & Documentation

---

## 37. refactor(enrollment): split enrollment/server.rs into modules

**Labels:** refactor, code-quality
**Branch:** `refactor/split-enrollment-server`
**Effort:** 3 hr

### Description

`crates/rustgate-enrollment/src/server.rs` is 1,030 lines combining HTTP server setup, CSR signing (v1 + v2), PKCS#12 packaging, multipart parsing, data package handling, and rate limiting.

### Acceptance Criteria

- [ ] Split into: `server.rs` (HTTP setup), `sign.rs` (CSR signing), `pkcs12.rs` (packaging), `datapackage.rs` (data package serving)
- [ ] No file exceeds ~400 lines
- [ ] All enrollment integration tests pass

---

## 38. docs: add module-level documentation across all crates

**Labels:** documentation
**Branch:** `docs/module-level-docs`
**Effort:** 3 hr

### Description

15+ source files across rustgate-core, rustgate-proto, rustgate-nats, rustgate-websocket, and rustgate-test-utils lack `//!` module-level documentation. Public types in core, cot, proto, and federation lack field-level `///` doc comments.

### Acceptance Criteria

- [ ] Add `//!` module docs to all .rs files explaining the module's purpose
- [ ] Add `///` field docs to all public struct fields in rustgate-core
- [ ] Run `cargo doc --workspace --no-deps` and verify no missing doc warnings

---

## 39. feat(security): add error context throughout error propagation chains

**Labels:** code-quality, security
**Branch:** `feat/error-context`
**Effort:** 4 hr

### Description

Multiple crates use bare `?` operators without `.context()` or `.with_context()`, making production debugging harder when errors propagate through multiple layers. Affected crates: rustgate-transport (codec, config, filter), rustgate-proto (codec), rustgate-federation (connector), rustgate-enrollment (server).

### Acceptance Criteria

- [ ] Audit all `?` operators in production code
- [ ] Add `.context()` to all error propagation points where the caller's context is lost
- [ ] Ensure error messages form readable chains (e.g., "failed to accept connection: TLS handshake failed: certificate expired")
- [ ] All tests pass

---

## 40. feat(security): document post-quantum TLS migration roadmap

**Labels:** security, documentation
**Branch:** `docs/post-quantum-roadmap`
**Effort:** 1 hr
**Ref:** NIST PQC Standards (2024), Rustls PQ Support

### Description

Rustls 0.23.22+ supports ML-KEM (Kyber) hybrid key exchange, but rustgate does not enable it or document a migration path. For a tactical system, a post-quantum roadmap is important for long-term confidentiality.

### Acceptance Criteria

- [ ] Create `docs/post-quantum.md` documenting current PQ status and migration plan
- [ ] Target hybrid PQ key exchange (X25519 + ML-KEM 768) for v0.5.0 or v0.6.0
- [ ] Reference NIST PQC standards and Rustls PQ blog post

---

## 41. feat(security): enforce mTLS for NATS broker connections

**Labels:** security, enhancement
**Branch:** `feat/nats-mtls`
**Effort:** 3 hr
**Ref:** NATS Security Audit (Trail of Bits, April 2025)

### Description

`crates/rustgate-nats/src/lib.rs` connects to NATS with optional JWT/NKey auth but no explicit mTLS enforcement. The NATS broker connection is a sensitive path carrying all routed messages. Per the Trail of Bits audit (April 2025), NATS supports full mTLS with client certificate verification.

### Acceptance Criteria

- [ ] Add `--nats-tls-cert`, `--nats-tls-key`, `--nats-tls-ca` CLI flags
- [ ] Configure async-nats TLS with client certificate when provided
- [ ] Document in docs/deployment.md that NATS mTLS is recommended for production
- [ ] Add integration test with TLS-enabled NATS server

---

## 42. ci(security): add cargo-auditable for binary SBOM

**Labels:** ci, security
**Branch:** `ci/cargo-auditable`
**Effort:** 1 hr

### Description

`cargo-auditable` embeds dependency information directly into compiled binaries, enabling post-build SBOM extraction and vulnerability scanning of deployed artifacts. This complements the existing cargo-deny and cargo-audit CI checks.

### Acceptance Criteria

- [ ] Add `cargo install cargo-auditable` to release workflow
- [ ] Build release binaries with `cargo auditable build --release`
- [ ] Verify SBOM can be extracted from built binary with `cargo audit bin`
- [ ] Document in CONTRIBUTING.md

---

---

# Fuzzing & Attack Surface Coverage

---

## 43. test(fuzz): add JWT parsing fuzz target

**Labels:** testing, security, fuzzing
**Branch:** `test/fuzz-jwt-parsing`
**Effort:** 2 hr
**Ref:** CWE-20 (Improper Input Validation)

### Description

`crates/rustgate-federation/src/jwt.rs` parses JWT tokens with manual base64 decoding, JSON deserialization, and HMAC verification. There is no fuzz target for this path. Malformed JWTs (truncated base64, invalid JSON, oversized headers) could trigger panics or unexpected behavior.

Existing fuzz targets cover codecs and CoT parsing but none of the 5 remaining attack surfaces: JWT, CSR, NATS JSON, WebSocket framing, CRL parsing.

### Acceptance Criteria

- [ ] Add `fuzz/fuzz_targets/jwt_parse.rs` targeting `jwt::verify()` and `jwt::decode()`
- [ ] Seed corpus with valid JWT, expired JWT, truncated JWT, oversized claims
- [ ] Run for 1M+ iterations with no crashes
- [ ] Add to CI fuzz regression suite

---

## 44. test(fuzz): add CSR parsing fuzz target

**Labels:** testing, security, fuzzing
**Branch:** `test/fuzz-csr-parsing`
**Effort:** 2 hr

### Description

`crates/rustgate-enrollment/src/server.rs` accepts Certificate Signing Requests from clients. CSR parsing involves ASN.1 DER decoding which is a historically rich attack surface. No fuzz target exists.

### Acceptance Criteria

- [ ] Add `fuzz/fuzz_targets/csr_parse.rs` targeting CSR decoding path
- [ ] Seed corpus with valid CSR, truncated DER, oversized fields
- [ ] Run for 1M+ iterations with no crashes

---

## 45. test(fuzz): add NATS WireEvent JSON fuzz target

**Labels:** testing, security, fuzzing
**Branch:** `test/fuzz-nats-json`
**Effort:** 1 hr

### Description

`crates/rustgate-nats/src/subscriber.rs` deserializes `WireEvent` JSON from NATS subjects. Malformed JSON payloads from a compromised NATS broker could trigger unexpected behavior.

### Acceptance Criteria

- [ ] Add `fuzz/fuzz_targets/nats_wire_event.rs` targeting JSON deserialization
- [ ] Seed corpus with valid WireEvent, nested objects, oversized strings, unicode edge cases
- [ ] Run for 1M+ iterations with no crashes

---

## 46. test(fuzz): add WebSocket frame fuzz target

**Labels:** testing, security, fuzzing
**Branch:** `test/fuzz-websocket-frame`
**Effort:** 2 hr

### Description

`crates/rustgate-websocket/` handles WebSocket binary/text frames via `tokio-tungstenite`. While the library itself is well-tested, the integration layer (frame → codec → RoutableMessage) is not fuzzed. Malformed frames at the application layer could trigger panics in codec dispatch.

### Acceptance Criteria

- [ ] Add `fuzz/fuzz_targets/websocket_frame.rs` targeting the WebSocket → codec pipeline
- [ ] Test both binary and text frame paths
- [ ] Run for 1M+ iterations with no crashes

---

## 47. test(fuzz): add CRL parsing fuzz target

**Labels:** testing, security, fuzzing
**Branch:** `test/fuzz-crl-parse`
**Effort:** 1 hr

### Description

`crates/rustgate-transport/src/config.rs` loads CRL files (DER-encoded X.509 CRLs). CRL parsing involves ASN.1 and is a common attack vector for certificate infrastructure. No fuzz target exists.

### Acceptance Criteria

- [ ] Add `fuzz/fuzz_targets/crl_parse.rs` targeting CRL loading path
- [ ] Seed corpus with valid CRL, truncated DER, oversized revocation lists
- [ ] Run for 1M+ iterations with no crashes

---

## 48. test(fuzz): add protobuf roundtrip fuzz target

**Labels:** testing, security, fuzzing
**Branch:** `test/fuzz-protobuf-roundtrip`
**Effort:** 2 hr

### Description

`crates/rustgate-proto/` converts between XML and protobuf formats. The existing `tak_frame_codec` fuzz target covers framing but not the XML↔protobuf conversion roundtrip. Asymmetric encode/decode behavior could silently corrupt messages.

### Acceptance Criteria

- [ ] Add `fuzz/fuzz_targets/protobuf_roundtrip.rs` testing XML → proto → XML roundtrip
- [ ] Verify byte-level equality or semantic equivalence after roundtrip
- [ ] Seed corpus with complex CoT events including all optional fields
- [ ] Run for 1M+ iterations with no crashes

---

## 49. test(fuzz): implement structured fuzzing with Arbitrary trait

**Labels:** testing, fuzzing, enhancement
**Branch:** `test/structured-fuzzing`
**Effort:** 4 hr

### Description

Current fuzz targets use raw byte inputs. Implementing the `arbitrary::Arbitrary` trait for key types (`Identity`, `RoutableMessage`, `Destination`, `FramingStrategy`) would enable structure-aware fuzzing, dramatically improving coverage depth.

### Acceptance Criteria

- [ ] Derive or implement `Arbitrary` for core types in rustgate-core
- [ ] Add `arbitrary` as optional dev-dependency with feature gate
- [ ] Update existing fuzz targets to use structured inputs where applicable
- [ ] Add corpus seeds for each target

---

# Helm & Kubernetes Hardening

---

## 50. fix(helm): pin container image by SHA256 digest

**Labels:** security, helm
**Branch:** `fix/helm-image-digest`
**Effort:** 30 min
**Ref:** CIS Kubernetes Benchmark 5.5.1

### Description

`helm/values.yaml` (line 8) pins the container image by tag (`tag: "0.3.0"`) but not by digest. Tags are mutable — a compromised registry could serve a different image for the same tag. The deployment template at `helm/templates/deployment.yaml` (line 34) uses `image: "{{ .Values.image.repository }}:{{ .Values.image.tag }}"`.

### Acceptance Criteria

- [ ] Add `digest` field to `values.yaml` image section
- [ ] Update deployment.yaml template to use `image: "{{ .Values.image.repository }}:{{ .Values.image.tag }}@{{ .Values.image.digest }}"` when digest is provided
- [ ] Document digest pinning in helm/README.md
- [ ] Update CI to output image digest after build

---

## 51. fix(helm): enable NetworkPolicy by default in production values

**Labels:** security, helm
**Branch:** `fix/helm-networkpolicy-default`
**Effort:** 30 min

### Description

`helm/templates/networkpolicy.yaml` exists with proper ingress/egress rules but is disabled by default (`networkPolicy.enabled: false` in values.yaml line 111). The production values file `helm/values-production.yaml` should enable this.

### Acceptance Criteria

- [ ] Set `networkPolicy.enabled: true` in `helm/values-production.yaml`
- [ ] Verify NetworkPolicy renders correctly with `helm template`
- [ ] Document required network policies in deployment docs

---

## 52. feat(helm): add external secrets operator support

**Labels:** security, helm, enhancement
**Branch:** `feat/helm-external-secrets`
**Effort:** 3 hr

### Description

`helm/values.yaml` supports both inline credentials (plaintext in values) and `existingSecret` references for NATS credentials (line 31-34), enrollment credentials (lines 41-46), and federation peers (lines 72-75). However, there is no integration with External Secrets Operator or Sealed Secrets for GitOps-safe secret management.

### Acceptance Criteria

- [ ] Add optional ExternalSecret template for NATS, enrollment, and federation secrets
- [ ] Support `secretStoreRef` configuration in values.yaml
- [ ] Document recommended secret management patterns in docs/deployment.md
- [ ] Add warning comment in values.yaml discouraging plaintext credentials

---

# CI/CD Hardening

---

## 53. ci(security): add dependency-review action for PRs

**Labels:** ci, security
**Branch:** `ci/dependency-review`
**Effort:** 30 min

### Description

No `dependency-review-action` is configured in `.github/workflows/ci.yml`. This GitHub Action flags known-vulnerable or license-violating dependencies introduced by PRs before they merge, complementing the existing `cargo deny` and `cargo audit` checks.

### Acceptance Criteria

- [ ] Add `actions/dependency-review-action` step to CI workflow on `pull_request` events
- [ ] Pin to SHA per existing convention
- [ ] Configure to fail on high-severity vulnerabilities
- [ ] Verify it runs on a test PR

---

## 54. ci(security): add harden-runner for self-hosted jobs

**Labels:** ci, security
**Branch:** `ci/harden-runner`
**Effort:** 1 hr
**Ref:** StepSecurity harden-runner

### Description

All 9 CI jobs run on `self-hosted` runners with no network or process egress monitoring. `step-security/harden-runner` restricts outbound network calls and detects credential exfiltration on GitHub Actions runners. This is especially important for self-hosted runners which lack GitHub's built-in isolation.

### Acceptance Criteria

- [ ] Add `step-security/harden-runner` as first step in all workflow jobs
- [ ] Pin to SHA per existing convention
- [ ] Start with `egress-policy: audit` mode, review logs, then switch to `block`
- [ ] Document allowed egress endpoints

---

## 55. fix(ci): harden PR title validation against injection

**Labels:** ci, security
**Branch:** `fix/ci-pr-title-validation`
**Effort:** 30 min

### Description

`.github/workflows/ci.yml` (line 30) sets `PR_TITLE: ${{ github.event.pull_request.title }}` as an environment variable. While the current usage (piped through `grep -qE`) is safe since the variable is quoted in the shell context, best practice for self-hosted runners is to pass untrusted input via file rather than environment variable, or use an intermediate variable with explicit sanitization.

### Acceptance Criteria

- [ ] Pass PR title through `$GITHUB_OUTPUT` file mechanism instead of env var
- [ ] Or: add explicit input sanitization before shell evaluation
- [ ] Add comment explaining the security consideration
- [ ] Existing commit-lint job behavior unchanged

---

# NIST 800-53 & Compliance

---

## 56. docs(security): expand NIST 800-53 control mapping

**Labels:** security, documentation, compliance
**Branch:** `docs/nist-800-53-expansion`
**Effort:** 3 hr

### Description

The existing NIST 800-53 security posture document maps 21 controls but is missing 5 control families that apply to a tactical message routing system:

- **CP (Contingency Planning)** — no documented backup/restore procedures or failover testing
- **IR (Incident Response)** — no incident response playbooks or audit trail correlation guidance
- **RA (Risk Assessment)** — no formal threat model document
- **CA (Security Assessment)** — no penetration testing schedule or security assessment procedures
- **OM (Organization and Management)** — no operational security procedures for key rotation, certificate lifecycle

### Acceptance Criteria

- [ ] Add CP control family mapping with backup/restore procedures for position cache, federation state
- [ ] Add IR control family with incident response runbook template
- [ ] Add RA control family with formal threat model (see issue #57)
- [ ] Add CA control family with penetration testing schedule
- [ ] Update docs/nist-800-53.md with all 5 new families

---

## 57. docs(security): create formal threat model document

**Labels:** security, documentation
**Branch:** `docs/threat-model`
**Effort:** 4 hr

### Description

rustgate lacks a formal threat model document. For a tactical mTLS router, key threat actors include: compromised client certificates, rogue federation peers, NATS broker compromise, insider threats, and DoS attacks. A STRIDE-based threat model would identify gaps systematically.

### Acceptance Criteria

- [ ] Create `docs/threat-model.md` using STRIDE methodology
- [ ] Cover all 4 transport paths (TCP/TLS, WebSocket, Federation, NATS)
- [ ] Identify trust boundaries (client ↔ server, server ↔ federation peer, server ↔ NATS)
- [ ] Map existing mitigations to each threat
- [ ] Identify residual risks and link to remediation issues
- [ ] Include data flow diagrams

---

# Operational Security & Observability

---

## 58. feat(observability): add OpenTelemetry distributed tracing

**Labels:** enhancement, observability
**Branch:** `feat/otel-tracing`
**Effort:** 6 hr

### Description

rustgate uses `tracing` for structured logging but has no distributed tracing support. For federation deployments spanning multiple servers, correlating message flow across federation peers and NATS bridges requires trace context propagation (W3C Trace Context or B3).

### Acceptance Criteria

- [ ] Add `tracing-opentelemetry` and `opentelemetry-otlp` as optional dependencies behind `otel` feature
- [ ] Instrument key spans: TLS handshake, message routing, federation forwarding, NATS publish/subscribe
- [ ] Propagate trace context through federation protocol (add trace headers to V2 gRPC metadata)
- [ ] Add `--otel-endpoint` CLI flag
- [ ] Document setup with Jaeger/Tempo in docs/observability.md

---

## 59. feat(security): add sensitive data masking in logs

**Labels:** security, enhancement
**Branch:** `feat/log-data-masking`
**Effort:** 2 hr
**Ref:** CWE-532 (Information Exposure Through Log Files)

### Description

rustgate logs certificate fingerprints, client identities, and message metadata. In environments subject to data retention regulations, sensitive fields (certificate fingerprints, client CNs, message UIDs) should be maskable in logs.

### Acceptance Criteria

- [ ] Add `--log-mask-fields` CLI flag accepting comma-separated field names
- [ ] Implement a `tracing` layer that redacts specified fields (replace with `***`)
- [ ] Default: no masking (backward compatible)
- [ ] Document masking configuration in operational runbooks

---

## 60. feat(audit): add missing audit events for security-critical operations

**Labels:** security, enhancement
**Branch:** `feat/audit-events-expansion`
**Effort:** 3 hr

### Description

`rustgate-core/src/audit.rs` defines audit events but several security-critical operations lack audit logging:

- CRL reload/update events
- Certificate revocation check results (pass/fail)
- Rate limit threshold breaches
- Federation circuit breaker state changes
- Position cache eviction events
- JWT token revocation

### Acceptance Criteria

- [ ] Add audit events for all 6 missing categories
- [ ] Each event includes timestamp, source, severity, and structured fields
- [ ] Events are emitted via `tracing` at `info!` or `warn!` level
- [ ] Add tests verifying audit events are emitted for each category

---

## 61. feat(security): add anti-replay mechanism for messages

**Labels:** security, enhancement
**Branch:** `feat/message-anti-replay`
**Effort:** 4 hr
**Ref:** CWE-294 (Authentication Bypass by Capture-replay)

### Description

rustgate routes messages without replay detection. An attacker who captures a valid message can replay it later. While the mTLS layer prevents external injection, a compromised client or federation peer could replay captured messages.

The federation layer has dedup caches for loop prevention, but the client-facing transport layer has no message-level replay protection.

### Acceptance Criteria

- [ ] Add sliding-window replay detection based on message UID + timestamp
- [ ] Configurable window size via `--replay-window` (default: 300 seconds)
- [ ] Drop replayed messages with structured warning log
- [ ] Add metric for replayed message count
- [ ] Document in operational runbooks

---

## 62. feat(security): enforce minimum JWT secret length

**Labels:** security, enhancement
**Branch:** `feat/jwt-min-secret-length`
**Effort:** 30 min
**Ref:** NIST SP 800-107

### Description

`crates/rustgate-federation/src/jwt.rs` accepts HMAC-SHA256 secrets of any length. NIST SP 800-107 recommends HMAC keys be at least as long as the hash output (32 bytes for SHA-256). A short secret weakens the HMAC and enables brute-force attacks.

### Acceptance Criteria

- [ ] Add minimum secret length check (32 bytes) when initializing JWT validator
- [ ] Warn at startup if secret is shorter than recommended
- [ ] Reject secrets shorter than 16 bytes as insecure
- [ ] Add test for short secret rejection

---

## 63. feat(websocket): add per-connection rate limiting

**Labels:** security, enhancement
**Branch:** `feat/websocket-rate-limit`
**Effort:** 2 hr

### Description

`crates/rustgate-websocket/` has bounded channels (capacity 64) and frame size limits (16 MiB per frame, 64 MiB per message) but no per-connection message rate limiting. A client sending many small valid messages at high frequency could overwhelm the router without triggering any existing limits.

The TCP/TLS transport path has per-client token-bucket throttling (Step 5 in the message flow), but this is not applied to WebSocket connections.

### Acceptance Criteria

- [ ] Apply the same token-bucket rate limiter used by TCP/TLS to WebSocket sessions
- [ ] Add `--ws-rate-limit` CLI flag (messages per second per connection)
- [ ] Log rate-limited connections with structured tracing
- [ ] Add integration test verifying rate limiting kicks in

---

# Dependencies & Migration

---

## 64. deps: migrate from rustls-pemfile to rustls-pki-types

**Labels:** dependencies, security
**Branch:** `deps/migrate-rustls-pemfile`
**Effort:** 3 hr

### Description

`rustls-pemfile` 2.x is marked unmaintained (RUSTSEC-2025-0134) and is currently an ignored advisory in `deny.toml`. The replacement is `rustls-pki-types` which provides PEM parsing as part of the core rustls ecosystem. rustgate directly depends on `rustls-pemfile` in 4 production crates (rustgate-transport, rustgate-federation, rustgate-enrollment, rustgate-test-utils) with usage in config.rs, connector.rs, trust_store.rs, server.rs, and signing.rs.

### Acceptance Criteria

- [ ] Replace `rustls-pemfile` with `rustls-pki-types` PEM parsing across all 4 crates
- [ ] Remove `rustls-pemfile` from workspace dependencies
- [ ] Remove RUSTSEC-2025-0134 ignore from `deny.toml`
- [ ] All existing TLS tests pass
- [ ] Coordinate with issue #4 (PEM parsing consolidation) to avoid duplicate work

---

## 65. deps: resolve dual thiserror versions (1.0 + 2.0)

**Labels:** dependencies
**Branch:** `deps/unify-thiserror`
**Effort:** 2 hr

### Description

`Cargo.lock` contains both `thiserror 1.0.69` and `thiserror 2.0.18`. Dual versions increase compile times and binary size. The workspace should standardize on one version.

### Acceptance Criteria

- [ ] Identify which crates use thiserror 1.x vs 2.x (check direct and transitive deps)
- [ ] Migrate all direct usage to thiserror 2.x
- [ ] If transitive deps hold back thiserror 1.x, document which and track upstream migration
- [ ] Verify single thiserror version in Cargo.lock after migration

---

## 66. feat(federation): add circuit breaker state machine

**Labels:** enhancement, reliability
**Branch:** `feat/federation-circuit-breaker`
**Effort:** 4 hr

### Description

Federation connections use basic reconnection with exponential backoff but lack a formal circuit breaker pattern. A proper circuit breaker (Closed → Open → Half-Open) would prevent thundering herd on federation peer recovery and provide observable state for operators.

### Acceptance Criteria

- [ ] Implement circuit breaker with Closed/Open/Half-Open states
- [ ] Configurable thresholds: failure count, recovery timeout, half-open probe interval
- [ ] Add metrics for circuit breaker state transitions
- [ ] Add audit events for state changes (see issue #60)
- [ ] Add unit tests for state machine transitions

---

## 67. docs: create graceful degradation policy document

**Labels:** documentation, reliability
**Branch:** `docs/graceful-degradation`
**Effort:** 2 hr

### Description

rustgate has no documented behavior for partial system failures: NATS broker disconnection, federation peer failure, certificate enrollment CA unavailability. Operators need clear documentation of degradation behavior and recovery procedures.

### Acceptance Criteria

- [ ] Create `docs/graceful-degradation.md` documenting behavior when each subsystem fails
- [ ] Cover: NATS bridge failure (messages still route locally), federation peer failure (circuit breaker behavior), enrollment CA failure (existing connections unaffected)
- [ ] Document automatic recovery mechanisms and manual intervention steps
- [ ] Add to operational runbook index

---

## 68. feat(security): add certificate rotation automation support

**Labels:** security, enhancement
**Branch:** `feat/cert-rotation`
**Effort:** 4 hr

### Description

rustgate loads TLS certificates at startup and does not support runtime certificate rotation. In long-running deployments, certificates expire and require server restart to reload. This creates a window of downtime.

### Acceptance Criteria

- [ ] Watch certificate files for changes (via `notify` crate or periodic poll)
- [ ] Reload TLS `ServerConfig` atomically using `Arc::swap` pattern
- [ ] Add `--cert-reload-interval` CLI flag (default: disabled, values in seconds)
- [ ] Log certificate rotation events as audit events
- [ ] Add integration test verifying live rotation with new cert

---

# Transport Layer Hardening (from deep code review)

---

## 69. fix(security): prevent integer overflow in ClientThrottle token refill

**Labels:** security, bug
**Branch:** `fix/throttle-overflow`
**Effort:** 30 min
**Ref:** CWE-190 (Integer Overflow)

### Description

`crates/rustgate-transport/src/throttle.rs` (line 72) performs `refill * 100` where both values are `u32`. If `refill > 42,949,672` (u32::MAX / 100), this silently wraps to zero, bypassing the rate limiter entirely.

```rust
let refill = (self.refill_rate * f64::from(elapsed_ms) / 1000.0) as u32;
let max_x100 = self.capacity * 100;
let available = (tokens_x100 + refill * 100).min(max_x100);  // ← overflow
```

### Acceptance Criteria

- [ ] Use `u64` for intermediate arithmetic or `saturating_mul()` for the `refill * 100` calculation
- [ ] Add bounds validation in `ClientThrottle::new()` for `capacity` and `refill_rate`
- [ ] Add test with pathologically large refill rate to confirm no overflow
- [ ] Add test verifying throttle actually limits after overflow-range values

---

## 70. fix(security): bound router group membership per CN

**Labels:** security, bug
**Branch:** `fix/bound-router-groups`
**Effort:** 1 hr
**Ref:** CWE-770 (Allocation Without Limits)

### Description

`crates/rustgate-transport/src/router.rs` (line 42) stores `groups: HashMap<GroupId, HashSet<String>>` with no limit on group count per CN or total group count. A client presenting a certificate with many OUs (groups) can grow this structure without bound.

### Acceptance Criteria

- [ ] Add configurable max groups per CN (default: 100)
- [ ] Add configurable max total groups (default: 10,000)
- [ ] Reject or truncate group lists exceeding the limit with structured warning
- [ ] Add metric for group count

---

## 71. fix(transport): eliminate hot-path heap allocation in filter extract_attr

**Labels:** performance, bug
**Branch:** `fix/filter-extract-attr-alloc`
**Effort:** 30 min

### Description

`crates/rustgate-transport/src/filter.rs` (line 162) calls `format!("{name}=\"")` on every invocation of `extract_attr()`, which is called twice per position message for geo filtering. This allocates a new `String` on the heap in the hot path.

### Acceptance Criteria

- [ ] Replace `format!()` with direct byte-level search (e.g., find `name` bytes then check for `="` suffix)
- [ ] Or: pre-compute needle strings once and pass as parameters
- [ ] Benchmark with `criterion` to confirm improvement
- [ ] All filter tests pass

---

## 72. docs(transport): document position cache TTL semantics and edge cases

**Labels:** documentation, code-quality
**Branch:** `docs/cache-ttl-semantics`
**Effort:** 15 min

### Description

`crates/rustgate-transport/src/cache.rs` — the `is_expired()` check uses `elapsed > ttl`, which correctly handles zero-TTL (expires immediately since any elapsed time > 0). However, the TTL behavior for edge cases (`Duration::ZERO`, `None`, very large values) is undocumented. Add module-level docs clarifying:

- `ttl: None` → entry never expires by TTL (only by sweep interval)
- `ttl: Some(Duration::ZERO)` → entry expires on next sweep
- Sweep interval is 60 seconds regardless of individual TTLs

### Acceptance Criteria

- [ ] Add `//!` module docs to `cache.rs` explaining TTL semantics
- [ ] Document sweep interval and its interaction with TTL
- [ ] Add unit test confirming zero-TTL expires on next check

---

## 73. fix(security): prevent silent message loss in router channel overflow

**Labels:** security, observability
**Branch:** `fix/router-channel-backpressure`
**Effort:** 2 hr

### Description

`crates/rustgate-transport/src/router.rs` (line 168) silently discards messages when a session's outbound channel is full: `let _ = handle.send(msg).await;`. No metric, no log, no indication to sender or receiver. Clients silently miss updates with no way to detect or recover.

### Acceptance Criteria

- [ ] Log dropped messages at `warn!` level with structured fields (source CN, destination, channel capacity)
- [ ] Add `messages_dropped` counter metric per session
- [ ] Add `messages_dropped_total` gauge to server metrics endpoint
- [ ] Consider: optional slow-consumer disconnect after N drops

---

## 74. fix(transport): add HashMap capacity hints for router state

**Labels:** performance
**Branch:** `fix/router-capacity-hints`
**Effort:** 15 min

### Description

`crates/rustgate-transport/src/router.rs` (lines 41-42) initializes `sessions` and `groups` HashMaps with `HashMap::new()` (default capacity 0). Under load with hundreds of clients, this causes repeated reallocations.

### Acceptance Criteria

- [ ] Use `HashMap::with_capacity()` with sensible defaults (e.g., 256 for sessions, 64 for groups)
- [ ] Or: accept capacity hints from server config via CLI flags
- [ ] All existing tests pass

---

# Federation Layer Hardening (from deep code review)

---

## 75. fix(security): add logging for silently dropped federation messages

**Labels:** security, observability
**Branch:** `fix/federation-silent-drops`
**Effort:** 1 hr

### Description

`crates/rustgate-federation/src/manager.rs` (lines 609-627) silently drops messages when source groups and peer groups don't overlap. No log is emitted, making it impossible for operators to diagnose missing message delivery across federation peers.

### Acceptance Criteria

- [ ] Add `debug!` log when messages are filtered by group mismatch
- [ ] Include source CN, source groups, peer ID, peer outbound groups in structured fields
- [ ] Add `federation_messages_filtered` counter metric
- [ ] No behavior change — messages still filtered, just observable now

---

## 76. fix(federation): protect forward() against concurrent peer modification

**Labels:** bug, correctness
**Branch:** `fix/federation-forward-sync`
**Effort:** 3 hr

### Description

`crates/rustgate-federation/src/manager.rs` (lines 604-653) — `forward()` iterates over `&self.clients` without synchronization against concurrent `adopt_peer()` and `disconnect_peer()` calls. If a peer is added or removed during iteration, messages may be lost or sent to stale handles.

### Acceptance Criteria

- [ ] Snapshot client list under lock before iterating for sends
- [ ] Or: wrap `clients` in `Arc<RwLock<>>` and take read lock during forward
- [ ] Add integration test simulating concurrent peer churn during message forwarding
- [ ] All existing federation tests pass

---

# Enrollment & Server Hardening

---

## 77. fix(security): escape all fields in archive JSONL output

**Labels:** security, bug
**Branch:** `fix/archive-jsonl-injection`
**Effort:** 30 min
**Ref:** CWE-117 (Log Injection)

### Description

`crates/rustgate-server/src/archive.rs` (lines 95-100) escapes CN and fingerprint via `escape_json()`, but `msg_type` (formatted via `{:?}` Debug) and `dest` are interpolated without escaping. If `MessageType::Other(s)` contains quotes or control characters, the JSONL output is corrupted.

### Acceptance Criteria

- [ ] Apply `escape_json()` to all interpolated fields in JSONL output (msg_type, dest, proto)
- [ ] Or: switch to `serde_json::to_string()` for the entire record to guarantee valid JSON
- [ ] Add test with `MessageType::Other("has\"quotes\n")` confirming valid JSONL output

---

## 78. fix(enrollment): call rate limiter prune() periodically

**Labels:** bug, performance
**Branch:** `fix/enrollment-ratelimit-prune`
**Effort:** 30 min

### Description

`crates/rustgate-enrollment/src/ratelimit.rs` has a `prune()` method (lines 62-74) that removes stale entries from the per-IP rate limiter HashMap, but it is never called from production code. The per-IP `check()` method prunes only the current IP's timestamps, not other IPs. Over days/weeks with many unique client IPs, the HashMap grows without bound.

### Acceptance Criteria

- [ ] Add periodic prune call (e.g., every 10 minutes) via a background tokio task in enrollment server
- [ ] Or: call `prune()` every N requests (e.g., every 1000 `check()` calls)
- [ ] Add metric for rate limiter entry count

---

## 79. fix(enrollment): URL-decode query parameters

**Labels:** bug, security
**Branch:** `fix/enrollment-urldecode`
**Effort:** 30 min

### Description

`crates/rustgate-enrollment/src/server.rs` (lines 828-834) `extract_param()` returns raw query values without URL decoding. Parameters like `clientUID` containing `%20` or `%3D` are stored/logged with encoding artifacts.

### Acceptance Criteria

- [ ] URL-decode extracted parameter values (use `percent_encoding` crate or `urlencoding`)
- [ ] Add test with URL-encoded clientUID
- [ ] Ensure truncation (128 char limit) applies after decoding

---

# Build & CI Hardening

---

## 80. ci(build): add --locked flag to all cargo build commands

**Labels:** ci, security
**Branch:** `ci/cargo-locked`
**Effort:** 30 min

### Description

`Dockerfile` (lines 33, 39) and `.github/workflows/release-binary.yml` (line 60) run `cargo build` without `--locked`. CI workflows (`ci.yml`) also run `cargo nextest`, `cargo clippy`, `cargo hack` without `--locked`. Only tool installations use `--locked`. This allows dependency version drift between Cargo.lock and actual builds.

### Acceptance Criteria

- [ ] Add `--locked` to all `cargo build` commands in Dockerfile
- [ ] Add `--locked` to all `cargo` commands in CI workflows (nextest, clippy, hack, etc.)
- [ ] Verify CI fails if Cargo.lock is out of sync with Cargo.toml

---

## 81. ci(perf): add cargo target caching for CI jobs

**Labels:** ci, performance
**Branch:** `ci/cargo-cache`
**Effort:** 1 hr

### Description

All 9 CI jobs on self-hosted runners rebuild the entire dependency tree from scratch. No `actions/cache` for `~/.cargo/registry`, `~/.cargo/git`, or `target/` directories. This wastes significant CI time on every push.

### Acceptance Criteria

- [ ] Add `actions/cache` step with key based on `Cargo.lock` hash and toolchain version
- [ ] Cache `~/.cargo/registry/index`, `~/.cargo/registry/cache`, `~/.cargo/git/db`, and `target/`
- [ ] Pin cache action to SHA per existing convention
- [ ] Measure before/after CI job duration

---

## 82. ci(fuzz): commit seed corpus and persist crash findings

**Labels:** ci, testing
**Branch:** `ci/fuzz-corpus`
**Effort:** 1 hr

### Description

No `fuzz/corpus/` directory is committed to the repository. All 5 fuzz targets in `.github/workflows/nightly.yml` run for 5 minutes each but crash findings are not persisted. Each nightly run starts from scratch with no seed corpus, reducing fuzzing effectiveness.

### Acceptance Criteria

- [ ] Create `fuzz/corpus/<target_name>/` directories for each fuzz target
- [ ] Add seed inputs (valid CoT XML, valid frames, edge cases) to each corpus
- [ ] Persist crash artifacts as CI workflow artifacts (upload-artifact)
- [ ] Document corpus maintenance in CONTRIBUTING.md

---

# Code Quality (from deep review)

---

## 83. feat(core): add Display impl for MessageType and Destination

**Labels:** enhancement, code-quality
**Branch:** `feat/core-display-impls`
**Effort:** 30 min

### Description

`rustgate-core/src/message.rs` — `MessageType` and `Destination` lack `Display` implementations. Code throughout the codebase uses `{:?}` (Debug format) for logging these types, producing verbose output like `Other("custom-type")` instead of `other:custom-type`.

### Acceptance Criteria

- [ ] Implement `Display` for `MessageType` with concise human-readable output
- [ ] Implement `Display` for `Destination` with concise output (e.g., `broadcast`, `group:teamA`, `direct:alice`)
- [ ] Update archive.rs and any logging sites to use `{}` instead of `{:?}`
- [ ] Add tests for Display output

---

## 84. feat(core): add validation on Identity construction

**Labels:** enhancement, type-safety
**Branch:** `feat/identity-validation`
**Effort:** 1 hr

### Description

`rustgate-core/src/identity.rs` — `Identity` can be constructed with empty `cn` or `fingerprint` strings. While production code always creates identities from TLS certificate extraction (which validates), test code and potential future callers have no guardrails.

### Acceptance Criteria

- [ ] Add `Identity::new()` constructor that validates `cn` is non-empty
- [ ] Add `Identity::builder()` or validate in `new()` that fingerprint is non-empty for TLS sessions
- [ ] Allow empty fingerprint only for plaintext sessions (explicit `Identity::plaintext(cn, groups)` constructor)
- [ ] Update all call sites to use validated constructors

---

## 85. docs(proto): document field loss behavior in XML↔protobuf conversion

**Labels:** documentation
**Branch:** `docs/proto-field-loss`
**Effort:** 30 min

### Description

`crates/rustgate-proto/src/convert/xml_to_proto.rs` silently drops unknown XML event attributes and detail elements not in the protobuf schema. Only unmapped detail children are preserved in `xmlDetail`. This is by design but undocumented — operators and integrators need to know which fields survive conversion.

### Acceptance Criteria

- [ ] Add module-level doc comment to `xml_to_proto.rs` listing explicitly mapped fields
- [ ] Document that unknown `<event>` attributes are discarded
- [ ] Document that unmapped `<detail>` children go to `xmlDetail`
- [ ] Add note to docs/architecture.md about proto conversion semantics

---

# Release Hygiene & Documentation Gaps (final sweep)

---

## 86. fix(helm): update image tag to match current release version

**Labels:** bug, helm
**Branch:** `fix/helm-image-tag`
**Effort:** 5 min

### Description

`helm/values.yaml` (line 8) pins `tag: "0.3.0"` but the workspace is at version `0.4.0` (per root `Cargo.toml`). Users deploying with default Helm values get an outdated image.

### Acceptance Criteria

- [ ] Update `helm/values.yaml` image tag to `"0.4.0"`
- [ ] Add CI check that Helm image tag matches `Cargo.toml` workspace version

---

## 87. fix(docs): update SECURITY.md supported versions table

**Labels:** bug, documentation
**Branch:** `fix/security-md-versions`
**Effort:** 5 min

### Description

`SECURITY.md` (lines 5-8) lists 0.3.x and 0.2.x as supported versions but does not include the current 0.4.x release.

### Acceptance Criteria

- [ ] Add `| 0.4.x | Yes |` to supported versions table
- [ ] Mark 0.2.x as unsupported if appropriate

---

## 88. docs(config): add missing sections to configuration reference

**Labels:** documentation
**Branch:** `docs/configuration-completeness`
**Effort:** 2 hr

### Description

`docs/configuration.md` is missing documentation for several CLI flags and environment variables that exist in the binary and are referenced in README.md:

- **Plaintext transport**: `--tcp-bind`, `--udp-bind`, `--plaintext-cn`, `--plaintext-group` (security-critical — needs warning about unencrypted traffic)
- **Rate limiting**: `--client-message-rate`, `--client-burst`
- **Data packages / archive**: `--data-package-dir`, `--archive-dir`, `--package-max-age-hours`
- **CRL**: `--crl` (critical security feature, only documented in TLS/FIPS docs)
- **Federation V2**: `--federation-v2-bind` (V1 documented but V2 missing)

### Acceptance Criteria

- [ ] Add "Plaintext Transport" section with security warning matching Helm chart text
- [ ] Add "Rate Limiting" section documenting client-message-rate and client-burst
- [ ] Add "Data Packages & Archive" section
- [ ] Add CRL option to TLS section or create "Certificate Revocation" section
- [ ] Add V2 bind to federation section
- [ ] Cross-reference federation REST API docs

---

## 89. fix(config): correct .env.example encoding modes and add missing variables

**Labels:** bug, documentation
**Branch:** `fix/env-example`
**Effort:** 30 min

### Description

`.env.example` (line 16) lists `cot` as a valid encoding mode (`raw, cot, tak-protobuf`) but `cot` is not a valid encoding mode — only `raw` and `tak-protobuf` are supported. Additionally, the file is missing environment variables for WebSocket, federation, rate limiting, CRL, plaintext, data packages, and FIPS features.

### Acceptance Criteria

- [ ] Remove `cot` from encoding mode comment
- [ ] Add commented examples for all missing environment variables
- [ ] Group by feature with section headers

---

## 90. refactor(enrollment): replace pointer arithmetic with safe indexing in datapackage.rs

**Labels:** refactor, code-quality
**Branch:** `refactor/datapackage-safe-indexing`
**Effort:** 30 min

### Description

`crates/rustgate-enrollment/src/datapackage.rs` (lines 203-205) derives byte offsets via raw pointer subtraction:

```rust
let start = body_str.as_ptr() as usize;
let content_ptr = content.as_ptr() as usize;
let offset = content_ptr - start;
return Some(&body[offset..offset + content.len()]);
```

While currently safe (content is guaranteed to be a substring from `.split()`), this pattern is brittle — if a future refactor changes the source of `content`, this becomes undefined behavior without any compiler warning.

### Acceptance Criteria

- [ ] Replace with `str::find()` + direct byte indexing, or `subslice_offset` pattern
- [ ] Add a comment explaining the substring guarantee if pointer math is retained
- [ ] All enrollment tests pass

---

## 91. fix(test-utils): use incrementing CRL serial numbers

**Labels:** bug, testing
**Branch:** `fix/test-crl-serial`
**Effort:** 15 min

### Description

`crates/rustgate-test-utils/src/certs.rs` (line 180) always uses `crl_number: SerialNumber::from(1u64)` for generated CRLs, regardless of how many are created. Tests generating multiple CRLs per `TestCa` instance will have conflicting serial numbers, violating RFC 5280 §5.2.3 which requires monotonically increasing CRL numbers.

### Acceptance Criteria

- [ ] Add `AtomicU64` counter to `TestCa` for CRL serial numbers
- [ ] Each `generate_crl()` call increments the counter
- [ ] Existing CRL tests pass

---

## Issue Summary

| # | Title | Type | Effort | Priority |
|---|-------|------|--------|----------|

### Code Quality & Refactoring (Issues 1-22)

| # | Title | Type | Effort | Priority |
|---|-------|------|--------|----------|
| 1 | socket2 workspace inheritance | fix | 5 min | High |
| 2 | prost-build workspace inheritance | fix | 5 min | High |
| 3 | Extract TCP keepalive utility | refactor | 1 hr | High |
| 4 | Extract PEM parsing utilities (7 locations) | refactor | 2 hr | High |
| 5 | Extract reconnection manager | refactor | 4 hr | Medium |
| 6 | Split v2/convert.rs (1,279 lines) | refactor | 2 hr | Medium |
| 7 | Split server main.rs (1,783 lines, 723-line run()) | refactor | 6 hr | Medium |
| 8 | rustgate-core integration tests (~41 tests) | test | 3 hr | High |
| 9 | rustgate-proto integration tests (~35 tests) | test | 4 hr | High |
| 10 | rustgate-server integration tests (~38 tests) | test | 5 hr | High |
| 11 | Feature gate test coverage | test | 3 hr | Medium |
| 12 | Decompose adopt_peer() | refactor | 2 hr | Medium |
| 13 | PeerId/ServerName newtypes | refactor | 2 hr | Low |
| 14 | Structured error variants | refactor | 3 hr | Low |
| 15 | Centralize constants | refactor | 1 hr | High |
| 16 | Quarterly advisory review | chore | recurring | Medium |
| 17 | Federation metrics expect() violations | fix | 1 hr | High |
| 18 | Server production expect() calls | fix | 30 min | High |
| 19 | tikv-jemallocator workspace inheritance | fix | 5 min | High |
| 20 | Split federation api.rs (1,206 lines) | refactor | 2 hr | Medium |
| 21 | Consolidate test helpers into test-utils | chore | 2 hr | High |
| 22 | Dead code metrics functions | fix | 30 min | Medium |

### Security Hardening (Issues 23-33)

| # | Title | Type | Effort | Priority |
|---|-------|------|--------|----------|
| 23 | Bound JWT revocation cache (CWE-770) | security | 2 hr | Critical |
| 24 | Bound position cache (CWE-770) | security | 2 hr | Critical |
| 25 | Replace custom HMAC with hmac crate (CWE-327) | security | 1 hr | High |
| 26 | TLS handshake rate limiting (NIST SC-5) | security | 4 hr | High |
| 27 | Configurable TLS version minimum (NIST 1800-37) | security | 2 hr | High |
| 28 | X.509 key usage validation (RFC 5280) | security | 3 hr | Medium |
| 29 | Sanitize cert CN/OU in logs (CWE-117) | security | 1 hr | Medium |
| 30 | CRL freshness validation (RFC 5280) | security | 2 hr | Medium |
| 31 | Bound federation peer groups (CWE-770) | security | 1 hr | Medium |
| 32 | NATS subject token length limit (CWE-400) | security | 30 min | Medium |
| 33 | Document unauthenticated metrics endpoint | docs | 30 min | Medium |

### Performance & Async (Issues 34-36)

| # | Title | Type | Effort | Priority |
|---|-------|------|--------|----------|
| 34 | Archive blocking I/O in async read loop | fix | 3 hr | Critical |
| 35 | Remove block_on in federation API handler | fix | 1 hr | High |
| 36 | Bound federation HA channels | fix | 30 min | Medium |

### Code Quality & Docs (Issues 37-42)

| # | Title | Type | Effort | Priority |
|---|-------|------|--------|----------|
| 37 | Split enrollment/server.rs (1,030 lines) | refactor | 3 hr | Medium |
| 38 | Module-level documentation sweep | docs | 3 hr | Medium |
| 39 | Error context throughout propagation chains | quality | 4 hr | Medium |
| 40 | Post-quantum TLS migration roadmap | docs | 1 hr | Low |
| 41 | NATS mTLS enforcement | security | 3 hr | Medium |
| 42 | cargo-auditable for binary SBOM | ci | 1 hr | Low |

### Fuzzing & Attack Surface (Issues 43-49)

| # | Title | Type | Effort | Priority |
|---|-------|------|--------|----------|
| 43 | JWT parsing fuzz target | fuzz | 2 hr | High |
| 44 | CSR parsing fuzz target | fuzz | 2 hr | High |
| 45 | NATS WireEvent JSON fuzz target | fuzz | 1 hr | Medium |
| 46 | WebSocket frame fuzz target | fuzz | 2 hr | Medium |
| 47 | CRL parsing fuzz target | fuzz | 1 hr | Medium |
| 48 | Protobuf roundtrip fuzz target | fuzz | 2 hr | Medium |
| 49 | Structured fuzzing with Arbitrary trait | fuzz | 4 hr | Low |

### Helm & Kubernetes (Issues 50-52)

| # | Title | Type | Effort | Priority |
|---|-------|------|--------|----------|
| 50 | Pin container image by SHA256 digest | helm | 30 min | High |
| 51 | Enable NetworkPolicy in production values | helm | 30 min | Medium |
| 52 | External secrets operator support | helm | 3 hr | Medium |

### CI/CD Hardening (Issues 53-55)

| # | Title | Type | Effort | Priority |
|---|-------|------|--------|----------|
| 53 | Add dependency-review action | ci | 30 min | High |
| 54 | Add harden-runner for self-hosted jobs | ci | 1 hr | High |
| 55 | Harden PR title validation | ci | 30 min | Low |

### Compliance & Threat Modeling (Issues 56-57)

| # | Title | Type | Effort | Priority |
|---|-------|------|--------|----------|
| 56 | Expand NIST 800-53 control mapping (5 families) | docs | 3 hr | Medium |
| 57 | Create formal STRIDE threat model | docs | 4 hr | Medium |

### Observability & Operational Security (Issues 58-63)

| # | Title | Type | Effort | Priority |
|---|-------|------|--------|----------|
| 58 | OpenTelemetry distributed tracing | feat | 6 hr | Medium |
| 59 | Sensitive data masking in logs | security | 2 hr | Medium |
| 60 | Expand audit events (6 missing categories) | security | 3 hr | High |
| 61 | Anti-replay mechanism for messages | security | 4 hr | Medium |
| 62 | Enforce minimum JWT secret length | security | 30 min | High |
| 63 | WebSocket per-connection rate limiting | security | 2 hr | High |

### Dependencies & Migration (Issues 64-65)

| # | Title | Type | Effort | Priority |
|---|-------|------|--------|----------|
| 64 | Migrate rustls-pemfile → rustls-pki-types | deps | 3 hr | High |
| 65 | Resolve dual thiserror versions (1.0 + 2.0) | deps | 2 hr | Medium |

### Reliability & Resilience (Issues 66-68)

| # | Title | Type | Effort | Priority |
|---|-------|------|--------|----------|
| 66 | Federation circuit breaker state machine | feat | 4 hr | Medium |
| 67 | Graceful degradation policy document | docs | 2 hr | Medium |
| 68 | Certificate rotation automation | feat | 4 hr | Medium |

### Transport Layer Hardening (Issues 69-74)

| # | Title | Type | Effort | Priority |
|---|-------|------|--------|----------|
| 69 | Throttle integer overflow (CWE-190) | security | 30 min | Critical |
| 70 | Bound router group membership per CN | security | 1 hr | High |
| 71 | Hot-path heap allocation in filter | perf | 30 min | Medium |
| 72 | Document cache TTL semantics | docs | 15 min | Low |
| 73 | Silent message loss in router channels | observability | 2 hr | High |
| 74 | Router HashMap capacity hints | perf | 15 min | Low |

### Federation Layer Hardening (Issues 75-76)

| # | Title | Type | Effort | Priority |
|---|-------|------|--------|----------|
| 75 | Log silently dropped federation messages | observability | 1 hr | High |
| 76 | Protect forward() against concurrent peer modification | bug | 3 hr | High |

### Enrollment & Server Hardening (Issues 77-79)

| # | Title | Type | Effort | Priority |
|---|-------|------|--------|----------|
| 77 | Archive JSONL field injection (CWE-117) | security | 30 min | High |
| 78 | Rate limiter prune() never called | bug | 30 min | Medium |
| 79 | URL-decode enrollment query parameters | bug | 30 min | Medium |

### Build & CI Hardening (Issues 80-82)

| # | Title | Type | Effort | Priority |
|---|-------|------|--------|----------|
| 80 | Add --locked to all cargo builds | ci | 30 min | High |
| 81 | Add cargo target caching for CI | ci | 1 hr | Medium |
| 82 | Commit fuzz corpus and persist crashes | ci | 1 hr | Medium |

### Code Quality (Issues 83-85)

| # | Title | Type | Effort | Priority |
|---|-------|------|--------|----------|
| 83 | Display impl for MessageType & Destination | quality | 30 min | Low |
| 84 | Identity construction validation | type-safety | 1 hr | Low |
| 85 | Document proto conversion field loss | docs | 30 min | Low |

### Release Hygiene & Docs (Issues 86-91)

| # | Title | Type | Effort | Priority |
|---|-------|------|--------|----------|
| 86 | Helm image tag version mismatch (0.3.0 vs 0.4.0) | fix | 5 min | Critical |
| 87 | SECURITY.md missing 0.4.x in supported versions | fix | 5 min | High |
| 88 | Configuration docs missing 5+ feature sections | docs | 2 hr | High |
| 89 | .env.example incorrect encoding mode + missing vars | fix | 30 min | Medium |
| 90 | Pointer arithmetic in datapackage.rs | refactor | 30 min | Medium |
| 91 | CRL serial numbers always 1 in test-utils | fix | 15 min | Low |

---

**Total: 91 issues | ~161 hours estimated + recurring maintenance**

---

### Suggested Execution Order

**Phase 0 — Critical security + perf (2-3 days):**
Issues 23, 24 (bound caches), 34 (archive async I/O), 35 (remove block_on), 25 (replace custom HMAC), 62 (JWT min secret length), 69 (throttle overflow), 76 (federation forward sync), 86 (Helm image tag)

**Phase 1 — Quick wins (< 1 day):**
Issues 1, 2, 19 (dep fixes), 17, 18 (expect violations), 22 (dead code), 32 (NATS token limit), 36 (bound HA channels), 50 (image digest), 55 (CI PR title), 74 (capacity hints), 77 (archive JSONL), 80 (--locked), 87 (SECURITY.md), 89 (.env.example)

**Phase 2 — Security hardening (3-4 days):**
Issues 26 (handshake rate limiting), 27 (TLS version min), 29 (log sanitization), 31 (bound peer groups), 33 (metrics docs), 60 (audit events), 63 (WebSocket rate limit), 70 (bound router groups), 73 (channel drop logging), 75 (federation drop logging)

**Phase 3 — CI/CD & compliance (1-2 days):**
Issues 53 (dependency-review), 54 (harden-runner), 42 (cargo-auditable), 51 (NetworkPolicy), 81 (cargo cache), 82 (fuzz corpus)

**Phase 4 — Code consolidation (2-3 days):**
Issues 3, 4, 15 (extract shared utilities), 21 (test helpers), 64 (rustls-pemfile migration), 65 (thiserror unification), 71 (filter alloc), 78 (ratelimit prune), 79 (urldecode), 90 (datapackage pointer math)

**Phase 5 — Fuzzing campaign (3-4 days):**
Issues 43, 44 (critical: JWT + CSR), 45, 46, 47, 48 (remaining targets), 49 (structured fuzzing)

**Phase 6 — Test coverage (3-4 days):**
Issues 8, 9, 10 (integration tests), 11 (feature gate tests)

**Phase 7 — Structural refactors (1-2 weeks):**
Issues 5, 6, 7, 12, 20, 37 (split large files, extract abstractions)

**Phase 8 — Hardening & type safety (ongoing):**
Issues 13, 14 (newtypes, structured errors), 28 (key usage), 30 (CRL freshness), 38, 39 (docs + error context), 41 (NATS mTLS), 59 (log masking), 61 (anti-replay), 83 (Display impls), 84 (Identity validation)

**Phase 9 — Resilience & observability:**
Issues 58 (OpenTelemetry), 66 (circuit breaker), 67 (degradation docs), 68 (cert rotation), 52 (external secrets)

**Phase 10 — Documentation & compliance:**
Issues 56 (NIST expansion), 57 (threat model), 40 (post-quantum roadmap), 72 (cache TTL docs), 85 (proto field loss docs), 88 (configuration docs), 91 (CRL serial)

**Ongoing:**
Issue 16 (quarterly advisory review)
