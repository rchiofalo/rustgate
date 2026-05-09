# Open Systems Management Plan (OSMP)

| Field | Value |
|---|---|
| **Project** | rustgate — Tactical mTLS Message Router |
| **Version** | 0.8.0 |
| **Document Date** | 2026-05-08 |
| **Document Owner** | Roberto Chiofalo (`<point-of-contact-placeholder>`) |
| **MOSA Reference** | DoD Modular Open Systems Approach (MOSA) — 10 USC §2446a, OMB MOSA guidance |
| **Issue** | Closes #875 |

This Open Systems Management Plan (OSMP) documents how rustgate satisfies the
Modular Open Systems Approach (MOSA) principles required for tactical
data-link integration. It pairs the technical architecture of the project
(workspace crate map, public extension traits, conformance gates) with the
external standards rustgate implements, the ADRs that govern key design
decisions, and the operational lifecycle (configuration, versioning,
deprecation, security advisories).

---

## 1. MOSA Principles

rustgate is designed against the four MOSA pillars defined in DoD MOSA
guidance:

1. **Modular Design** — the system decomposes into self-contained units
   that can be independently built, tested, deprecated, and replaced. In
   rustgate this is realized as a **39-crate workspace** under `crates/`,
   each crate with a single responsibility, an explicit public API, and
   a CI-enforced workspace-dependency-inheritance rule (ADR-0017) so a
   downstream consumer never sees a hidden version skew.

2. **Use of Major Interfaces** — extension points are exposed as Rust
   traits with stable public signatures and conformance test suites.
   See §4 below for the seven MOSA-load-bearing trait surfaces.

3. **Open Standards** — every protocol rustgate speaks is a published
   open standard (CoT, MAVLink, MQTT, NATS, gRPC + Protobuf, mTLS,
   SPIFFE, Cedar, JREAP-C/Link 16, VMF, DIS, STANAG 4586, ASTERIX,
   SAPIENT, NFFI, OGC SensorThings, FIPS 140-3, GeoJSON). See §5 for
   the full standards inventory. rustgate adds no proprietary wire
   formats.

4. **Certified Conformance** — every standard implementation has
   conformance evidence: integration tests against published vectors
   where available, fuzzing harnesses at the parser boundary, and CI
   gates that fail the build on regression. See §6.

The OSMP supplements rustgate's existing technical documentation rather
than replacing it. Architecture details live in `docs/architecture.md`,
configuration in `docs/configuration.md`, deployment in
`docs/deployment.md`, and the federation contract in `docs/federation.md`.

---

## 2. Project Scope

rustgate is a tactical mTLS message router that ingests, deduplicates,
authorizes, and routes messages between heterogeneous tactical clients
and federation peers. The project is vendor-neutral and protocol-agnostic
— no client identity, branding, or wire format is privileged in the
codebase. The router is engineered for forward-deployed environments
where bandwidth, latency, and identity assurance matter, and where
fail-open is the wrong default for security-relevant decisions.

Out-of-scope for the MVP: client GUIs, mission-planning workflow tools,
content-creation suites. rustgate is the data-plane substrate; the
mission-applications layer is the consumer.

---

## 3. Modular Architecture

rustgate is a Cargo workspace with 39 crates under `crates/`, each crate
mapping 1:1 to a MOSA-aligned bounded context. The table below mirrors
the README architecture map and is the load-bearing reference for
identifying where new functionality belongs.

| Crate | Responsibility |
|---|---|
| `rustgate-core` | Shared types: `Identity`, `RoutableMessage`, error hierarchy, audit, masking, sanitization, tactical socket helpers |
| `rustgate-cot` | Cursor-on-Target XML parsing, validation, delta encoding |
| `rustgate-authz` | Authorization engine (RBAC/ABAC, Cedar backend, dual-hash subject cache) |
| `rustgate-enrollment` | PKCS#12 cert enrollment, EST (RFC 7030), CSR validation, rate limiting |
| `rustgate-federation` | Server-to-server federation (gRPC/mTLS, JWT, mesh routing, peer discovery) |
| `rustgate-http` | HTTP/webhook egress bridge, DLQ, circuit breaker |
| `rustgate-mavlink` | MAVLink v1/v2 frame codec and transport primitives |
| `rustgate-nats` | NATS/JetStream bridge, subject sanitization |
| `rustgate-proto` | Protobuf message definitions (prost/tonic) |
| `rustgate-resilience` | Shared circuit breaker, backoff, rate limiters, token bucket |
| `rustgate-transport` | TLS listener, mTLS, CRL/OCSP, codec, ACL, backpressure, store-forward |
| `rustgate-router` | Central message dispatcher (ACL, authz, dedup, fanout) |
| `rustgate-tls` | rustls integration, cert reloader, SPIFFE workload identity |
| `rustgate-websocket` | WebSocket transport layer |
| `rustgate-mqtt` | MQTT 5.0/3.1.1 transport adapter |
| `rustgate-asterix` | EUROCONTROL ASTERIX radar / surveillance codec |
| `rustgate-dis` | IEEE 1278.1 Distributed Interactive Simulation codec |
| `rustgate-stanag4586` | STANAG 4586 unmanned-systems control adapter |
| `rustgate-sapient` | BSI Flex 335 (SAPIENT) sensor-fusion codec |
| `rustgate-nffi` | STANAG 5527 NATO Friendly-Force-Information XML codec |
| `rustgate-vmf` | MIL-STD-6017 VMF K05.1 Position-Report codec |
| `rustgate-link16` | JREAP-C / Link 16 (STANAG 5518) JSON-tunnel codec |
| `rustgate-meshtastic` | Meshtastic / LoRa TAKPacket codec |
| `rustgate-dds` | DDS Pub/Sub bridge for NGVA / VICTORY in-vehicle data buses |
| `rustgate-foundry` | Palantir Foundry / Gotham bridge (partner-gated) |
| `rustgate-lattice` | Anduril Lattice bidirectional adapter (partner-gated) |
| `rustgate-ogc-sensorthings` | OGC SensorThings v1.0 client (REST + JSON + MQTT) |
| `rustgate-missions` | Lightweight TAK Data-Packages REST API + on-disk store |
| `rustgate-archive` | Hash-chained audit log writer + verifier; ChaCha20-Poly1305 archives |
| `rustgate-admin` | HTTP management server: Prometheus, health probes, federation/ACL/management APIs |
| `rustgate-metrics` | Prometheus init ladder + histograms |
| `rustgate-guard` | Cross-domain guard / data-diode adapter |
| `rustgate-client` | Lightweight client library for integration testing |
| `rustgate-server` | Binary entrypoint, CLI, orchestration |
| `rustgate-test-utils` | Test certificate generation (TestCa, CRL, expired/revoked) |

Each crate forbids `unsafe_code` workspace-wide
(`unsafe_code = "forbid"` in the workspace `[lints]` table). All public
panics are denied by lint policy (`clippy::panic = "deny"`,
`clippy::unwrap_used = "deny"`).

---

## 4. Key Interfaces (Major Interfaces in MOSA terms)

The MOSA "major interface" concept covers the public extension points
that govern how downstream consumers and partner integrators plug in.
rustgate exposes the following load-bearing traits. Each trait has a
documented intent, stable signature, and a conformance test location.

| Trait | Crate | Intent | Conformance evidence |
|---|---|---|---|
| `Codec` | `rustgate-core::codec` | Frame-level wire-format adapter for a transport (CoT, length-prefix, line-delimited, TAK protobuf). `decode` / `encode` / `framing` / `detect` form the four-method contract. | `crates/rustgate-cot/tests/`, `crates/rustgate-mavlink/tests/`, `crates/rustgate-mqtt/tests/`, plus per-crate unit tests |
| `EntityCodec` | `rustgate-core::entity` | Entity-level codec — projects an external wire format (CoT, NFFI, VMF, Link 16, STANAG 5527) to/from the canonical `Entity` type. | `crates/rustgate-nffi/tests/roundtrip.rs`, `crates/rustgate-vmf/tests/`, `crates/rustgate-link16/tests/`, plus integration tests in `crates/rustgate-cot/tests/` |
| `PolicyEngine` | `rustgate-authz::engine` | Async authorization PEP — ingest a `Subject` + `Resource` + `Action`, return `Decision` (Allow/Deny + obligations). Cedar is the reference backend; a custom engine plugs in via this trait. | `crates/rustgate-authz/tests/cedar_engine.rs`, `crates/rustgate-authz/tests/cache.rs` |
| `PeerDiscovery` | `rustgate-federation::discovery` | `async fn discover() -> Result<Vec<PeerConfig>>`. Three reference backends: DNS-SD, Consul, etcd. A new backend implements the trait and registers via `--peer-discovery-backend`. | `crates/rustgate-federation/tests/discovery_*` |
| `LatticeBridge` | `rustgate-lattice` | Anduril Lattice bidirectional-bridge adapter. Mock backend ships under `lattice-mock`; the real Lattice gRPC SDK is partner-NDA gated and lives behind `lattice-real`. | `crates/rustgate-lattice/tests/` |
| `FoundryBridge` | `rustgate-foundry` | Palantir Foundry / Gotham bridge. Mock backend ships under `foundry-mock`; the real REST/WebSocket SDK is partner-gated. | `crates/rustgate-foundry/tests/` |
| `DdsBridge` | `rustgate-dds` | DDS Pub/Sub bridge for NGVA / VICTORY. Mock backend ships under `dds-mock`; the real DDS SDK is partner-gated and `dds-real` ships as a placeholder feature. | `crates/rustgate-dds/tests/wiring.rs` |
| OGC SensorThings client | `rustgate-ogc-sensorthings::client` | OGC SensorThings v1.0 polling + MQTT-push client. Implementation is concrete (no plug-in trait); wire-format conformance is the certification surface. | `crates/rustgate-ogc-sensorthings/tests/polling.rs` |

The trait surface is deliberately narrow. New protocol adapters
generally extend an existing trait (e.g. add a new `Codec`
implementation) rather than introducing a new top-level extension
point — that discipline is what keeps the crate count bounded.

---

## 5. Open Standards Inventory

rustgate implements the following published standards. Every entry
below names the standard, the rustgate crate that implements it, and
the conformance / version pin where applicable. The list is exhaustive
as of v0.8.0.

| Standard | rustgate crate | Notes |
|---|---|---|
| **Cursor-on-Target (CoT)** XML schema | `rustgate-cot` | Full event support including `b-i-v` video streams, delta encoding, `<detail>` extension passthrough |
| **MAVLink v1 / v2** frame format | `rustgate-mavlink` | Full v1+v2 codec; common-message dialect coverage |
| **MQTT 5.0 / 3.1.1** | `rustgate-mqtt` | Both protocol versions; properties, retained messages, QoS 0/1/2 |
| **NATS** core protocol + JetStream | `rustgate-nats` | Subject sanitization with NFC normalization defense |
| **gRPC + Protobuf** | `rustgate-proto`, `rustgate-federation` | tonic + prost; federation v2 contract |
| **mTLS (RFC 8446 — TLS 1.3)** | `rustgate-tls`, `rustgate-transport` | rustls 0.23; optional aws-lc-rs FIPS provider |
| **X.509 PKI (RFC 5280)** | `rustgate-tls`, `rustgate-enrollment` | CRL, OCSP stapling, certificate hot-reload, EST |
| **EST (RFC 7030)** | `rustgate-enrollment` | `cacerts` / `simpleenroll` endpoints |
| **SPIFFE / SVID** | `rustgate-tls::spiffe` | Workload API SVID rotation |
| **Cedar policy language** | `rustgate-authz` | Full Cedar engine; dual-hash subject cache |
| **JREAP-C / Link 16 (STANAG 5518)** | `rustgate-link16` | JSON-tunnel codec for J-series messages |
| **VMF (MIL-STD-6017) K05.1** | `rustgate-vmf` | Position-Report subset; bit-level layout pinned by tests |
| **DIS (IEEE 1278.1)** | `rustgate-dis` | Entity State PDUs and supporting telemetry |
| **STANAG 4586** unmanned-systems control | `rustgate-stanag4586` | UAS C2 wire format |
| **ASTERIX** EUROCONTROL surveillance | `rustgate-asterix` | Cat-021/048 ADS-B + radar tracks |
| **SAPIENT (BSI Flex 335)** | `rustgate-sapient` | Sensor-fusion XML schema |
| **STANAG 5527 (NFFI)** Friendly-Force Info | `rustgate-nffi` | Blue-Force-Tracking XML codec; APP-6A SIDC parser |
| **OGC SensorThings v1.0** | `rustgate-ogc-sensorthings` | REST + JSON polling; MQTT half deferred |
| **NGVA / VICTORY DDS** | `rustgate-dds` | DDS Pub/Sub trait + mock backend; real SDK partner-gated |
| **FIPS 140-3** validated cryptography | `rustgate-tls` (`fips` feature) | aws-lc-rs FIPS module; CI gate |
| **CNSA 2.0** post-quantum (planned) | `rustgate-tls` (`post-quantum` feature) | Hybrid X25519+ML-KEM key exchange |
| **GeoJSON (RFC 7946)** | `rustgate-core::geo`, `rustgate-foundry`, others | Position projection + GeoJSON output |
| **TAK Data-Packages** | `rustgate-missions` | Lightweight package store + REST API |

The codebase contains **zero proprietary wire formats**. Every
serialization surface is either a published standard, a thin
projection of one (e.g. JSON envelope around CoT), or an explicitly
internal type whose serialization shape is pinned by integration
tests so a refactor is forced to update the wire-shape contract
in lockstep.

---

## 6. Conformance Evidence

### 6.1 CI Gates (11 jobs on `ubuntu-latest`)

| Job | Purpose |
|---|---|
| `commit-lint` | Conventional-commits enforcement on every PR |
| `lint` | `cargo +nightly fmt --all` + `cargo machete` (unused deps) |
| `clippy` | `cargo clippy --locked --workspace --all-targets --features <full set>` with `-Dwarnings` |
| `check-features` | `cargo hack check --feature-powerset --depth 2` so every feature combination compiles |
| `test` | `cargo nextest run` workspace-wide |
| `coverage` | `cargo tarpaulin` line-coverage gate |
| `fips` | Build + test under `--features fips` (aws-lc-rs FIPS provider) |
| `post-quantum` | Build + test under `--features post-quantum` |
| `audit` | `cargo deny check` (advisories, bans, licenses, sources) + `cargo audit` |
| `helm` | Helm chart lint + template validation |
| `docker` | Multi-arch container build |

### 6.2 Architecture Decision Records

Each load-bearing engineering decision is captured as a numbered ADR
under `docs/adr/`. The MVP MOSA-relevant set:

| ADR | Topic | MOSA relevance |
|---|---|---|
| [0001](adr/0001-parking-lot-mutexes-for-sync-paths.md) | `parking_lot::Mutex` for sync paths | Concurrency discipline — no `.unwrap()` on lock |
| [0002](adr/0002-tokio-rwlock-across-await.md) | `tokio::sync::RwLock` across `.await` | Prevents the most-common async deadlock footgun |
| [0003](adr/0003-arcswap-hot-reload.md) | `ArcSwap` for hot-reload | Lock-free config reload — load-bearing for SIGHUP |
| [0007](adr/0007-thiserror-everywhere-no-anyhow-in-libs.md) | `thiserror` everywhere; `anyhow` only in binaries | Typed error surface across library boundaries |
| [0009](adr/0009-zeroizing-and-subtle-for-secrets.md) | `zeroize::Zeroizing` + `subtle::ConstantTimeEq` for secrets | Memory-safety + timing-attack defense |
| [0013](adr/0013-tactical-tcp-socket-hardening.md) | Tactical TCP socket hardening | `TCP_NODELAY` + keepalive on every accepted stream |
| [0014](adr/0014-hash-chained-audit-log.md) | Hash-chained audit log | Tamper-evident audit trail for forensic compliance |
| [0015](adr/0015-encrypted-archives-chacha20-poly1305.md) | ChaCha20-Poly1305 encrypted archives | At-rest encryption for store-and-forward + audit archives |
| [0017](adr/0017-workspace-dependency-inheritance.md) | Workspace dependency inheritance | Single source of truth for every dep version |

The full set of 18+ ADRs lives in `docs/adr/`. New architectural
decisions land as new ADR files; existing ADRs are updated
in-place only via a follow-on ADR that supersedes them.

### 6.3 Test Counts

As of v0.8.0:
- **Workspace-wide unit + integration tests:** ~3000 (run via
  `cargo nextest run`).
- **Fuzzing harnesses:** present at the CoT, MAVLink, ASTERIX, DIS,
  VMF, NFFI, and TAK-protobuf parser boundaries.
- **Conformance vectors:** every standard with public test vectors
  (CoT, MAVLink, MQTT, ASTERIX) is exercised against those vectors;
  partner-gated standards (Lattice, Foundry) ship mock backends
  with integration tests.

### 6.4 Threat Model and Security Posture

`docs/threat-model.md` and `docs/security-posture.md` are the
load-bearing security documents. Cross-cutting controls:

- **Secrets handling.** All secret material wraps in
  `zeroize::Zeroizing<T>` (ADR-0009).
- **Constant-time comparison.** Every credential check uses
  `subtle::ConstantTimeEq`.
- **Custom Debug redaction.** Types holding secrets implement
  custom `Debug` that prints `[REDACTED]`.
- **No-panic in production.** `clippy::panic = "deny"`,
  `clippy::unwrap_used = "deny"` workspace-wide.
- **`unsafe_code = "forbid"`.** No exceptions.
- **TCP socket hardening.** Every accepted stream calls
  `configure_tactical_socket` (keepalive + `TCP_NODELAY`) per
  ADR-0013.
- **Hash-chained audit log.** Per ADR-0014, audit records
  are SHA-256 chained so tampering is detectable.
- **Encrypted archives.** Store-and-forward queues and audit-log
  archives ride ChaCha20-Poly1305 with per-chunk AAD per
  ADR-0015.

---

## 7. Configuration Management

rustgate configuration is layered: defaults → TOML config file →
environment variables → CLI flags. CLI flags always win.

- **Schema source of truth:** the CLI struct in
  `crates/rustgate-server/src/cli.rs`. The struct derives `Serialize`
  with redaction attributes (`#[serde(skip_serializing)]`,
  `#[serde(serialize_with = "redact_optional_secret")]`) so the
  same surface that governs `--print-config-toml` and
  `GET /api/config` controls every path that emits config to the
  outside world.
- **Schema export.** A JSON schema export test
  (`crates/rustgate-server/tests/schema_export.rs`) regenerates the
  config schema in CI; a config-shape regression fails the build.
- **Hot reload.** SIGHUP triggers reload of: server cert/key, ACL
  policy, CRL, OCSP responses (when `ocsp` feature on), and
  federation peer list (via `peer-discovery` backends). The
  expanded management API exposes the same trigger as
  `POST /api/config/reload` returning `202 Accepted`.
- **Operator-facing reference.** `docs/configuration.md` is the
  human-readable reference. Every CLI flag has a `///` doc comment
  on the struct field that doubles as the `--help` text.

---

## 8. Lifecycle Management

### 8.1 Versioning Policy

rustgate follows [Semantic Versioning](https://semver.org/). The
public API surface includes:

- The CLI (`rustgate` binary) flag set.
- Every `pub` item on every workspace crate.
- The wire-format-level shape of every protocol rustgate speaks
  (CoT, MAVLink, etc. — though those are governed by the upstream
  standards body, not rustgate).
- The metrics names exposed at `/metrics` and the JSON shape of
  every endpoint under `/api/`.

### 8.2 Deprecation Process

Public-API removals are gated by a one-minor-release deprecation
window:

1. The deprecated item is annotated with `#[deprecated(note = "...")]`
   pointing at the replacement.
2. CHANGELOG.md `### Deprecated` notes the user-facing impact in the
   release the deprecation lands.
3. Removal lands no earlier than the next minor release (or the next
   major if the surface is large enough that a deprecation cycle on a
   minor would be insufficient).
4. The release that removes the item documents the removal under
   `### Removed`.

### 8.3 Security Advisory Handling

- **Dependency advisories.** `cargo deny check` is a CI gate. The
  `deny.toml` policy is split into a `sources` policy (no
  unauthorized registries), a `bans` policy (no banned crates), an
  `advisories` policy (no unmaintained / vulnerable transitive deps),
  and a `licenses` policy. Each advisory ignore is justified inline
  with a tracking issue and a removal trigger (closes #776 introduced
  the split-gate `deny.toml`).
- **Project-side CVEs.** When a vulnerability is discovered in
  rustgate itself, the project follows standard coordinated
  disclosure: a private GitHub Security Advisory is opened, a fix is
  prepared on a security branch, the advisory is published in
  lockstep with the fix release, and CHANGELOG.md `### Security`
  notes the impact.
- **No `unsafe_code`.** The workspace-wide `unsafe_code = "forbid"`
  removes an entire class of memory-safety vulnerability from the
  attack surface.
- **FIPS / PQ readiness.** `fips` and `post-quantum` features are
  built and tested in CI on every PR so a regression in either
  surface fails the build before merge.

### 8.4 Release Cadence

- **Minor releases:** as features are ready and an integration window
  closes. No fixed cadence — rustgate is feature-driven, not
  calendar-driven.
- **Patch releases:** ad hoc, when a bug-fix or security advisory
  needs to ship without waiting for the next minor.
- **CHANGELOG.md:** every release lists the user-facing impact under
  `Added` / `Changed` / `Fixed` / `Deprecated` / `Removed` /
  `Security`. The unreleased section accumulates entries on `main`
  and rolls forward at release time.

---

## 9. References

- [docs/architecture.md](architecture.md) — system architecture
- [docs/configuration.md](configuration.md) — CLI / config reference
- [docs/rest-api.md](rest-api.md) — full REST API reference (incl.
  the expanded management API closed by #875)
- [docs/federation.md](federation.md) — federation contract
- [docs/threat-model.md](threat-model.md) — threat model
- [docs/security-posture.md](security-posture.md) — security posture
- [docs/observability.md](observability.md) — Prometheus / OTel
  exposition
- [docs/disaster-recovery.md](disaster-recovery.md) — DR procedures
- [docs/adr/](adr/) — architecture decision records
- [CHANGELOG.md](../CHANGELOG.md) — release notes
- [CLAUDE.md](../CLAUDE.md) — repository rules
- [.claude/rules/shared-infrastructure.md](../.claude/rules/shared-infrastructure.md)
  — workspace-wide reusable infrastructure
