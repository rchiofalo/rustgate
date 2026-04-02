# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **External Secrets Operator support** — optional ExternalSecret templates for NATS, enrollment, and federation secrets with configurable `secretStoreRef` and `refreshInterval` (#275)

## [0.5.0] - 2026-04-01

### Added

- **TLS handshake concurrency limiting** — configurable semaphore to bound concurrent TLS handshakes and prevent resource exhaustion (#345)
- **CRL freshness validation** — warn on stale CRLs whose `nextUpdate` has passed; configurable via `--crl-warn-stale` (#347)
- **Configurable TLS version minimum** — `--tls-min-version` flag to enforce TLS 1.3-only mode; key usage validation on client certificates (#348)
- **Per-connection WebSocket rate limiting** — reuses `--client-message-rate` and `--client-burst` config for WebSocket sessions (#346)
- **NATS mTLS support** — client certificate authentication for NATS broker connections via `NatsTlsConfig` (#342)
- **Sensitive data masking** — `mask_cert_serial`, `mask_ip`, `mask_credential` utilities for structured log fields (#343)
- **Security audit events** — CRL reload, enrollment certificate issued, rate limit triggered, TLS handshake failed audit events (#343)
- **Identity validation** — `Identity::new()` returns `Result` with validation errors for empty CN/fingerprint (#334)
- **Structured fuzzing** — `Arbitrary` trait implementations behind `fuzz` feature flag for `RoutableMessage` and `CotEvent` (#341)
- **Fuzz targets** — JWT parse, CSR parse, NATS wire event, WebSocket frame, CRL parse, and protobuf roundtrip fuzz targets (#344)
- **Image digest pinning** — Helm deployment supports `image.digest` for immutable container references (#340)
- **NetworkPolicy** — Helm template for network-level pod isolation, enabled in production values (#340)
- **Integration tests** — 150+ new tests across core types, proto codec, server CLI/TLS, and feature gates (#359, #361, #362, #363)
- **1100+ tests** — up from 887 in v0.4.0

### Fixed

- **Position cache memory exhaustion** — bounded cache size prevents unbounded growth (#316)
- **JWT revocation cache memory exhaustion** — bounded cache with LRU eviction (#315)
- **ClientThrottle integer overflow** — prevent token refill overflow on long-running connections (#317)
- **Federation forward lock contention** — snapshot client list to reduce hold time during message forwarding (#318)
- **Helm image tag** — corrected to match workspace version (#319)
- **Workspace dependency inheritance** — enforced for socket2, prost-build, tikv-jemallocator (#320)
- **Certificate field sanitization** — escape JSONL output and bound NATS token length (#322)
- **Enrollment rate limiter pruning** — periodic cleanup of expired entries; URL-decode query parameters (#321)
- **JWT HMAC implementation** — replaced custom HMAC with `hmac` crate; enforce minimum secret length (#323)
- **Silent message drops** — added structured logging for dropped messages in router and federation (#324)
- **Async archive I/O** — moved archive writes off the async event loop; removed `block_on` from federation tests (#325)
- **Dead metrics code** — removed unreachable metrics paths; added `Display` impls; fixed CRL serial number formatting (#330)
- **Group membership bounds** — limit groups per CN and federation peer to prevent resource abuse (#332)
- **Hot-path heap allocation** — eliminated per-message allocations in routing; added HashMap capacity hints (#333)
- **`expect()` calls** — replaced remaining `expect()` in federation and server with fallible alternatives (#339)
- **Bounded HA channels** — federation HA peer event channels capped at 256 to prevent unbounded queue growth (#338)

### Changed

- **Structured error types** — `RustgateError::Transport(String)` and `Config(String)` replaced with `TransportError` and `ConfigError` sub-enums for precise error matching (#350)
- **PeerId and ServerName newtypes** — strongly-typed identifiers replace loose `String` usage across federation, server, and audit code (#351)
- **Centralized constants** — duplicated timeout and buffer constants extracted to `rustgate_core::constants` (#349)
- **Shared TCP keepalive** — `configure_tcp_keepalive()` extracted to `rustgate_core::net`, replacing 4 identical implementations (#354)
- **Shared PEM parsing** — `parse_certs`, `parse_key`, `parse_ca_store` extracted to `rustgate_transport::pem` module (#353)
- **Reconnection utilities** — `backoff_delay` and `should_stop_reconnecting` consolidated into `rustgate_federation::reconnect` (#352)
- **Federation module splits** — `v2/convert.rs` split into `cot_to_event`, `routable_message`, `timestamps` submodules (#358); `api.rs` split into `handlers`, `helpers`, `types` submodules (#357); callback creation extracted to helpers (#355)
- **Enrollment module split** — `server.rs` split into `handlers/sign`, `handlers/api`, `handlers/packages`, `handlers/util` (#356)
- **Test helper consolidation** — shared TLS helpers in `rustgate_test_utils::tls` replace duplicated code across 6 test files (#360)
- **Safe indexing** — replaced pointer arithmetic in enrollment with safe slice indexing (#336)
- **Dependency migration** — migrated from `rustls-pemfile` to `rustls-pki-types` PEM parsing (#335)

### Security

- **CI workflow hardening** — minimal token permissions, credential isolation, harden-runner, dependency-review, cargo-auditable (#206, #331)
- **CodeQL SAST** — static analysis scanning with pinned Trivy download (#214)
- **Nightly security scanning** — auto-create issues for dependency vulnerabilities; container image scanning (#210, #212)
- **aws-lc-rs vulnerability fix** — updated aws-lc-rs to resolve 3 HIGH severity CVEs (#208)
- **SECURITY.md** — updated supported versions and environment variable references (#337)

## [0.4.0] - 2026-03-06

### Added

- **Federation TrustStore integration** — dynamic CA trust for federation TLS handshakes; new CAs take effect on the next connection without restart (#191)
- **Federation HA claim manager wiring** — distributed peer ownership via NATS KV atomic claims integrated into the federation manager (#193)
- **Per-peer circuit breaker** — automatic backoff on repeated federation connection failures with configurable thresholds (#182)
- **V1 loop detection** — message deduplication prevents routing loops in V1 federation protocol (#190)
- **V2 provenance checking** — inbound and outbound provenance validation for V2 federation messages (#189)
- **887 tests** — up from 818 in v0.3.0

### Fixed

- **NATS test server startup flakiness** — shared `TestNatsServer` in `rustgate-test-utils` with retry logic and fast-fail on port conflicts (#195)
- **Release docker workflow cascading failures** — best-effort guards on post-push steps prevent attestation/Trivy failures from failing the entire job (#194)
- **Cross-compilation FIPS builds** — install Go 1.22.12 from go.dev in `Cross.toml` (distro `golang` was 1.10.4, `aws-lc-fips-sys` requires >= 1.17.13)
- **Nightly fuzz rustup** — fix cross-device rename error in fuzz CI (#181)
- **Scorecard workflow** — skip on private repos where `persist-credentials: false` blocks cloning
- **Test timeouts** — increase timeouts for coverage instrumentation overhead (#183)

### Changed

- **Project branding** — add project logo, OpenSSF Scorecard badge, and NIST 800-53 security posture to documentation (#180)

## [0.3.0] - 2026-03-05

### Changed

- **CI pipeline** — 10 parallel jobs: commit-lint, lint, clippy, check-features (cargo-hack powerset), test (nextest), coverage (tarpaulin), fips, audit, helm, docker
- **Branch protection** — `main` requires all CI status checks to pass before merge

### Added

- **CRL revocation** — PEM-encoded Certificate Revocation List support via `--crl`; revoked certificates are rejected at the TLS handshake before reaching the application layer
- **FIPS 140-3 crypto** (feature-gated: `fips`) — aws-lc-rs crypto provider for FIPS-validated TLS, certificate signing (rcgen), and PKCS#12 salt generation; runtime enforcement via `--fips-required`
- **TLS session resumption disabled** — forces full handshake with certificate verification on every connection, ensuring CRL checks cannot be bypassed via cached sessions
- **Plaintext input** — TCP (`--tcp-bind`) and UDP (`--udp-bind`) listeners for trusted-network scenarios with configurable default CN and group
- **Per-client rate limiting** — `--client-message-rate` and `--client-burst` for per-connection message throttling
- **CoT event archival** — structured JSONL logging of all received events to date-stamped files via `--archive-dir`
- **Data package expiration** — `--package-max-age-hours` for automatic cleanup of uploaded data packages
- **Audit logging** — structured event logging for connection lifecycle and federation events
- **Marti contact API** — `/Marti/api/contacts/all` and `/Marti/api/clientEndPoints` endpoints for client contact discovery
- **Data package support** — upload, download, and keyword search for data packages via `/Marti/sync/` endpoints
- **Directional group routing** — group-aware message filtering for federation peers
- **Fuzz targets** — cargo-fuzz targets for XML stream codec, CoT parser, TAK frame codec, length-prefixed codec, and federation converter
- **Criterion benchmarks** — throughput benchmarks for CoT parsing, codec encode/decode, and federation XML conversion
- **Container security scanning** — Trivy vulnerability scanning with SARIF upload in release workflow; cargo-audit in CI
- **Binary release artifacts** — cross-compiled static binaries for x86_64 and aarch64 linux-musl via GitHub Release
- **818 tests** — up from 639 in v0.2.0

## [0.2.0] - 2026-03-01

### Added

- **Server-to-server federation** (feature-gated: `federation`) — share situational awareness between independent server networks via the federation protocol
- **V1 federation protocol** — length-prefixed XML over mTLS for legacy server compatibility, with CoT heartbeat monitoring (30s interval, 90s timeout) and automatic reconnection with exponential backoff
- **V2 federation protocol** — gRPC FederatedChannel service over mTLS with 5-stream handshake, group exchange, health checks (5s interval, 15s timeout), and bidirectional event streaming
- **Provenance-based loop detection** — federation messages carry a server chain and hop counter; messages are dropped when a loop is detected or the configurable hop limit (default 10) is exceeded
- **Federation manager** — orchestrates all inbound and outbound peer connections, protocol selection (V1/V2 per-peer), group-aware forwarding, and NATS ↔ federation bridging with echo prevention
- **Dynamic CA trust store** — add and remove trusted CA certificates at runtime without restart; new CAs take effect on the next TLS handshake
- **Persistent peer storage** — JSON file backend for single-pod deployments; NATS KV backend with cross-pod sync for multi-pod clusters
- **HA mode** — distributed peer ownership via NATS KV atomic claims with 30s TTL and 10s refresh; automatic adoption of orphaned peers after pod failure with configurable delay
- **Federation REST API** — peer CRUD, certificate management, connection status, and aggregated statistics endpoints mounted under `/api/federation/`
- **Federation Prometheus metrics** — `federation_connections` gauge, `federation_messages_in_total` / `federation_messages_out_total` / `federation_errors_total` / `federation_heartbeats_total` counters
- **Federation CLI flags** — `--federation-v1-bind`, `--federation-id`, `--federation-peers-file`, `--federation-skip-hostname-verify`, `--federation-max-hops`, `--federation-store-path` with corresponding `FEDERATION_*` environment variables
- **Helm chart federation support** — `federation.enabled` toggle, peer config via Secret or values, federation port (9000) in Service and NetworkPolicy
- **639 tests** — up from 198 in v0.1.0, adding comprehensive coverage for federation config, provenance, heartbeat, store, V1/V2 protocols, gRPC service, trust store, HA claims, REST API, and metrics

## [0.1.0] - 2026-03-01

Initial release of rustgate — a Rust-native secure tactical message router.

### Added

- **mTLS transport** — TLS listener with client certificate verification, X.509 identity extraction (CN, OU groups, SHA-256 fingerprint), and TCP keepalive with read/write timeouts
- **Message routing** — broadcast, group-based, and direct (callsign) message delivery with session lifecycle management and atomic session IDs for reconnect handling
- **Framing codecs** — length-prefixed (4-byte header, 16MB max), XML stream, and line-delimited codecs with overflow protection
- **Cursor on Target parsing** — full CoT XML parser with typed detail field extraction (`<contact>`, `<__group>`, `<precisionlocation>`, `<status>`, `<takv>`, `<track>`)
- **Position cache** — per-group position replay on client connect for situational awareness bootstrap
- **NATS bridge** (feature-gated: `nats`) — cross-instance message delivery via NATS pub/sub, JetStream history replay on startup, two-layer echo prevention (protocol tag + instance header)
- **Certificate enrollment** (feature-gated: `enrollment`) — Marti v2 CSR signing protocol over HTTPS with HTTP Basic Auth, subject DN enforcement from authenticated username, TLS handshake + request timeouts, streaming body size limits
- **TAK protobuf translation** (feature-gated: `proto`) — bidirectional XML ↔ protobuf conversion via prost, TAK binary framing codec (0xBF + varint), protocol negotiation handshake (server advertises, client opts in or stays XML), xmlDetail residual preservation
- **Prometheus metrics** (feature-gated: `metrics`) — connection lifecycle, message routing, NATS bridge, and protocol negotiation counters; `/healthz`, `/readyz`, and `/metrics` HTTP endpoints with hardened server (128 connection limit, 15s timeout)
- **Graceful shutdown** — SIGTERM + SIGINT handling, readiness probe returns 503, connection draining with 110s timeout inside K8s terminationGracePeriodSeconds
- **Environment variable configuration** — all CLI flags available as `RUSTGATE_*`, `NATS_*`, `ENROLLMENT_*`, and `METRICS_*` env vars (CLI takes precedence)
- **Configurable connection limits** — `--max-connections` / `RUSTGATE_MAX_CONNECTIONS` with semaphore-based enforcement
- **jemalloc allocator** (feature-gated: `jemalloc`) — avoids musl malloc contention for Alpine/musl production builds
- **Helm chart** — Deployment with Pod Security Standards (restricted), PDB, HPA, startup/liveness/readiness probes, pre-stop hook, configurable NATS and enrollment, TLS secret mounting
- **Docker** — multi-stage Dockerfile with OCI labels, HEALTHCHECK, STOPSIGNAL SIGTERM, non-root UID 10001, read-only root filesystem; docker-compose for local development
- **CI pipeline** — GitHub Actions with fmt, clippy, feature matrix testing, cargo-deny (licenses, advisories, bans, sources), Helm lint, Docker build validation
- **Release pipeline** — Docker image build and push to ghcr.io on GitHub Release, cosign signing, SBOM embedding
- **Dependency management** — Dependabot with grouped minor/patch updates and individual major version PRs; cargo-deny with advisory ignore for transitive rustls-pemfile dep
- **198 tests** — unit tests covering mTLS, identity extraction, routing, codecs (XML stream, line-delimited), NATS wire format, CSR signing, enrollment HTTP integration, protobuf conversion, metrics, and CLI configuration; NATS integration tests with embedded nats-server

### Security

- `unsafe_code = "forbid"` across all crates
- `unwrap_used = "deny"` and `panic = "deny"` in clippy lints
- Client certificate subject DN enforced from authenticated username (CSR subject ignored)
- CSR SAN and custom extension stripping to prevent subject injection
- Streaming body size limits (pre-read rejection, not post-buffer)
- SHA-pinned GitHub Actions in CI and release workflows
- `cargo-deny` for license compliance and vulnerability scanning
- Cosign-signed container images with embedded SBOM
- Pod Security Standards (restricted profile) in Helm chart
- Non-root container (UID 10001) with read-only root filesystem and dropped capabilities
