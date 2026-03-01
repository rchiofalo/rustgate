# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - Unreleased

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
- **CI pipeline** — GitHub Actions with fmt, clippy, test (default + all features), cargo-deny (licenses, advisories, bans, sources), Helm lint, Docker build validation
- **Release pipeline** — Docker image build and push to ghcr.io on GitHub Release, cosign signing, SBOM embedding
- **Dependency management** — Dependabot with grouped minor/patch updates and individual major version PRs; cargo-deny with advisory ignore for transitive rustls-pemfile dep
- **169 tests** — unit tests covering mTLS, identity extraction, routing, codecs, NATS wire format, CSR signing, enrollment, protobuf conversion, metrics, and CLI configuration; NATS integration tests with embedded nats-server

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
