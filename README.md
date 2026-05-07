<p align="center">
  <img src="assets/logo.svg" alt="rustgate logo" width="600">
</p>

<p align="center">
  <a href="https://github.com/rchiofalo/rustgate/actions/workflows/ci.yml"><img src="https://github.com/rchiofalo/rustgate/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/rchiofalo/rustgate/releases/latest"><img src="https://img.shields.io/github/v/release/rchiofalo/rustgate?color=green" alt="Release"></a>
  <a href="https://ghcr.io/rchiofalo/rustgate"><img src="https://img.shields.io/badge/docker-ghcr.io-blue?logo=docker" alt="Docker"></a>
  <a href="https://securityscorecards.dev/viewer/?uri=github.com/rchiofalo/rustgate"><img src="https://api.securityscorecards.dev/projects/github.com/rchiofalo/rustgate/badge" alt="OpenSSF Scorecard"></a>
  <img src="https://img.shields.io/badge/rust-1.94%2B-orange.svg?logo=rust" alt="Rust 1.94+">
  <img src="https://img.shields.io/badge/license-Proprietary-blue.svg" alt="License">
</p>

<p align="center">
  <em>Secure mTLS message router in Rust — group-based routing, WebSocket, server federation, NATS scaling, certificate enrollment, CRL and FIPS support. Single binary, edge-ready.</em>
</p>

## Table of Contents

- [Why](#why)
- [Quick Start](#quick-start)
- [Architecture](#architecture)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Building](#building)
- [Running](#running)
- [Docker](#docker)
- [Kubernetes](#kubernetes)
- [Security](#security)
- [Testing](#testing)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [License](#license)

## Why

Existing messaging servers are Java monoliths requiring 8 GB+ RAM, multiple JVM processes, and complex module stacks. They work in fixed infrastructure but fall apart at the edge where resources are constrained and reliability matters most. Federation-only alternatives exist but don't handle client connections.

rustgate is a lightweight alternative that handles mTLS client connections, routes messages by group membership derived from client certificates, and exposes a pluggable protocol interface. Pure Rust, single binary, minimal footprint.

## Quick Start

Generate test certificates and run with Docker Compose:

```bash
# Generate CA
openssl req -x509 -newkey rsa:4096 -keyout ca-key.pem -out ca.pem \
  -days 365 -nodes -subj "/CN=rustgate-ca"

# Generate server cert
openssl req -newkey rsa:4096 -keyout server-key.pem -out server.csr \
  -nodes -subj "/CN=rustgate-server"
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca-key.pem \
  -CAcreateserial -out server.pem -days 365

# Place certs where Docker Compose expects them
mkdir -p certs
cp ca.pem certs/ca.crt && cp server.pem certs/server.crt && cp server-key.pem certs/server.key

# Start
docker compose up -d

# Verify
curl http://localhost:9090/health/live
```

For production certificate management see [docs/tls-certificates.md](docs/tls-certificates.md).

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                                     rustgate-server                                     │
│                                        (binary)                                         │
├────────────┬────────────┬────────────┬────────────┬────────────┬────────────┬───────────┤
│ rustgate-  │ rustgate-  │ rustgate-  │ rustgate-  │ rustgate-  │ rustgate-  │ rustgate- │
│ transport  │ websocket  │ mqtt       │ nats       │ http       │ enrollment │ federation│
│ TLS·codec  │ wss://     │ MQTT 5.0   │ NATS pub   │ HTTP/REST  │ HTTPS·CSR  │ V1·V2·gRPC│
│ router     │ mTLS WS    │ 3.1.1      │ JetStream  │ egress     │ Auth       │ peer mgmt │
├────────────┴────────────┴────────────┼────────────┴────────────┴────────────┴───────────┤
│             rustgate-cot             │                  rustgate-core                   │
│   CoT XML parsing · MessageBuilder   │     Codec trait · Identity · RoutableMessage     │
└──────────────────────────────────────┴──────────────────────────────────────────────────┘
```

| Crate | Purpose |
|-------|---------|
| [`rustgate-core`](crates/rustgate-core/README.md) | Codec trait, shared types: Identity, RoutableMessage, Destination, framing strategies |
| [`rustgate-cot`](crates/rustgate-cot/README.md) | Cursor on Target XML parsing and message building |
| [`rustgate-tls`](crates/rustgate-tls/README.md) | TLS/mTLS configuration, X.509 identity extraction, OCSP, SPIFFE, TCP listeners |
| [`rustgate-router`](crates/rustgate-router/README.md) | Routing engine: Router, ACL, dedup, store-and-forward, position cache, throttling, quota, obligations, egress |
| [`rustgate-transport`](crates/rustgate-transport/README.md) | Codec / framing primitives, hardware identity, UDP / multicast — pure post-handshake |
| [`rustgate-websocket`](crates/rustgate-websocket/README.md) | WebSocket (wss://) listener with mTLS client authentication |
| [`rustgate-mqtt`](crates/rustgate-mqtt/README.md) | MQTT 5.0/3.1.1 transport adapter with mTLS and dynamic subscriptions |
| [`rustgate-mavlink`](crates/rustgate-mavlink/README.md) | MAVLink v1/v2 wire-frame codec (listeners and signing land in follow-up PRs) |
| [`rustgate-meshtastic`](crates/rustgate-meshtastic/README.md) | Meshtastic / LoRa TAKPacket compact-protobuf codec (237-byte cap; transport binding in follow-up PRs) |
| [`rustgate-nats`](crates/rustgate-nats/README.md) | NATS/JetStream bridge for cross-instance message delivery |
| [`rustgate-enrollment`](crates/rustgate-enrollment/README.md) | HTTPS certificate enrollment server (CSR signing, PKCS#12) |
| [`rustgate-proto`](crates/rustgate-proto/README.md) | Protobuf message translation (XML ↔ proto) |
| [`rustgate-authz`](crates/rustgate-authz/README.md) | Authorization engine (RBAC/ABAC, Cedar backend) |
| [`rustgate-http`](crates/rustgate-http/README.md) | HTTP/webhook egress bridge with auth, retry, circuit breaking |
| [`rustgate-federation`](crates/rustgate-federation/README.md) | Server-to-server federation: V1 (XML), V2 (gRPC), HA, REST API |
| [`rustgate-client`](crates/rustgate-client/README.md) | Lightweight client library for integration testing |
| [`rustgate-server`](crates/rustgate-server/README.md) | Binary entry point, CLI, orchestration |
| [`rustgate-admin`](crates/rustgate-admin/README.md) | HTTP management server: Prometheus exposition, health/readiness probes, federation/mgmt/ACL APIs |
| [`rustgate-archive`](crates/rustgate-archive/README.md) | Encrypted hash-chained archives (ChaCha20-Poly1305 + SHA-256 chain) |
| [`rustgate-metrics`](crates/rustgate-metrics/README.md) | Shared Prometheus scaffolding: OnceLock fallbacks, init() orchestration, standard buckets |
| [`rustgate-test-utils`](crates/rustgate-test-utils/README.md) | Test CA and certificate generation helpers |

For detailed architecture documentation see [docs/architecture.md](docs/architecture.md).

## Features

### Transport & Routing

| Feature | Description |
|---------|-------------|
| mTLS | Mutual TLS with client certificate authentication |
| Identity extraction | CN → callsign, OU → groups, SHA-256 → fingerprint |
| Group routing | Broadcast, group, and direct message delivery |
| Codecs | Length-prefixed, XML stream, and line-delimited codecs |
| Position cache | Replay cached positions on client connect |
| Rate limiting | Per-client message rate and burst controls |
| MQTT transport | MQTT 5.0/3.1.1 sessions over mTLS with dynamic group subscriptions |
| Plaintext input | TCP and UDP listeners for trusted-network scenarios |

### Protocols & Codecs

| Feature | Description |
|---------|-------------|
| WebSocket | wss:// listener with mTLS, interoperable with TCP clients |
| Protobuf | Bidirectional XML ↔ protobuf translation |
| Protocol negotiation | Automatic upgrade from XML to protobuf framing |
| MAVLink v1/v2 | Wire-frame codec with resync (listeners and v2 signing in follow-up PRs) |
| CoT delta encoding | Opt-in per-UID delta + epsilon suppression on XML sessions ([details](docs/cot-delta-encoding.md)) |
| CoT archival | Structured JSONL logging of all received events |
| Data packages | Upload, download, and search via Marti sync API |

### Security

| Feature | Description |
|---------|-------------|
| CRL revocation | PEM-encoded CRL loaded via `--crl`, enforced at TLS handshake |
| FIPS 140-3 | aws-lc-rs crypto provider via `--features fips` ([details](docs/fips.md)) |
| RBAC/ABAC authorization | Hot-reloadable policies and sub-microsecond evaluation ([details](docs/authorization.md)) |
| Subject DN enforcement | Enrollment certs carry the authenticated username — prevents impersonation |
| No unsafe code | `unsafe_code = "forbid"` workspace-wide |
| Container hardening | Non-root UID, read-only filesystem, STOPSIGNAL SIGTERM |

### Federation & Scaling

| Feature | Description |
|---------|-------------|
| Federation V1 | Length-prefixed XML over mTLS |
| Federation V2 | gRPC over mTLS with FederatedChannel service |
| Loop detection | Provenance-based with configurable hop limits |
| HA mode | NATS KV distributed claims for multi-pod peer ownership |
| NATS bridge | Publish/subscribe for stateless horizontal scaling with JetStream replay |
| HTTP egress | Webhook/REST forwarding with Bearer/Basic/HMAC auth, retry, circuit breaking ([details](docs/http-egress.md)) |
| REST API | Peer CRUD and certificate management endpoints |

### Operations

| Feature | Description |
|---------|-------------|
| Prometheus metrics | Connection lifecycle, message routing, NATS, federation ([unauthenticated](docs/deployment.md#ports) — firewall in hostile environments) |
| OpenTelemetry tracing | Distributed trace export via OTLP (Jaeger, Tempo, etc.) |
| OpenTelemetry metrics | Optional OTLP metrics push alongside the Prometheus `/metrics` scrape endpoint (shares the OTLP collector URL with traces) |
| Health endpoints | `/health/live`, `/health/ready`, `/health/startup` (plus deprecated `/healthz`, `/readyz` aliases) |
| Graceful shutdown | SIGTERM handling, readiness 503, connection draining |
| Helm chart | Pod Security Standards, PDB, HPA, probes, NetworkPolicy |
| Docker Compose | Local development stack with NATS and JetStream |
| jemalloc | Optional allocator for musl/Alpine production builds |

## Prerequisites

| Dependency | Required | Notes |
|------------|----------|-------|
| Rust 1.94+ | Yes | Pinned in `rust-toolchain.toml` (edition 2024) |
| Rust nightly | Yes | For `cargo +nightly fmt` (CI enforces nightly formatting) |
| protoc | For `proto` / `federation` features | Protocol Buffers compiler |
| Go 1.20+, cmake | For `fips` feature | Required by aws-lc-rs build system |
| nats-server | For NATS integration tests | Install from [nats.io](https://nats.io/download/) |

Optional tooling:

| Tool | Purpose |
|------|---------|
| [cargo-nextest](https://nexte.st/) | CI test runner |
| [cargo-hack](https://github.com/taiki-e/cargo-hack) | Feature powerset checking |
| [cargo-deny](https://github.com/EmbarkStudios/cargo-deny) | License and advisory auditing |
| [cargo-machete](https://github.com/bnjbvr/cargo-machete) | Unused dependency detection |
| Helm | Chart linting |

## Building

```bash
# Default (core transport + routing)
cargo build --release

# With individual features
cargo build --release --features nats           # NATS bridge
cargo build --release --features enrollment     # Certificate enrollment
cargo build --release --features proto          # Protobuf translation (needs protoc)
cargo build --release --features federation     # Server federation (needs protoc)
cargo build --release --features websocket      # WebSocket listener
cargo build --release --features metrics        # Prometheus + health endpoints
cargo build --release --features jemalloc       # jemalloc allocator (musl)
cargo build --release --features fips           # FIPS 140-3 crypto (needs Go + cmake)
cargo build --release --features post-quantum  # PQ key exchange (needs Go + cmake)
cargo build --release --features http            # HTTP/webhook egress
cargo build --release --features otel           # OpenTelemetry tracing (needs protoc)

# All features
cargo build --release --all-features
```

### Feature Flags

| Feature | Purpose | Extra build deps |
|---------|---------|-----------------|
| `nats` | NATS/JetStream bridge | — |
| `enrollment` | PKCS#12 enrollment server | — |
| `est` | EST (RFC 7030) enrollment endpoints | — |
| `proto` | Protobuf message support | `protoc` |
| `federation` | Server-to-server federation | `protoc` |
| `federation-ha` | HA federation with JWT | `protoc` |
| `websocket` | WebSocket transport | — |
| `mqtt` | MQTT 5.0/3.1.1 transport | — |
| `mavlink` | MAVLink v1/v2 framing (rustgate-transport dep, listeners in follow-up) | — |
| `metrics` | Prometheus metrics | — |
| `full-detail` | Extended CoT parsing | — |
| `fips` | FIPS 140-3 crypto (aws-lc-rs) | Go 1.20+, cmake |
| `post-quantum` | Post-quantum key exchange (X25519MLKEM768) | Go 1.20+, cmake |
| `otel` | OpenTelemetry distributed tracing | `protoc` |
| `http` | HTTP/webhook egress bridge | — |
| `cedar` | Cedar policy backend for authorization | — |
| `ocsp` | OCSP stapling for server certificates | — |
| `spiffe` | SPIFFE / SPIRE workload identity (server cert + trust bundle from the Workload API) | `protoc` |
| `peer-discovery` | DNS-SD, Consul, etcd federation peer discovery | — |
| `jemalloc` | jemalloc allocator | — |

#### SPIFFE workload identity

When the `spiffe` feature is compiled in, rustgate can obtain its server
TLS identity from a SPIRE agent via the SPIFFE Workload API instead of
from static `--cert` / `--key` / `--ca` files. Enable it by passing
`--spiffe` on the command line (or `RUSTGATE_SPIFFE=true`) alongside an
optional `--spiffe-workload-api-socket`:

```
rustgate \
  --bind 0.0.0.0:4433 \
  --spiffe \
  --spiffe-workload-api-socket unix:///tmp/spire-agent/public/api.sock \
  --spiffe-trust-domain example.org
```

The X.509-SVID and trust bundle are fetched at startup, installed as the
active rustls server certificate and client-cert verifier CA bundle, and
then re-fetched on the interval set by `--spiffe-refresh-interval`
(default 300 s). Rotations reuse the existing zero-downtime hot-reload
path used by file-based certs. `--spiffe` is mutually exclusive with
`--cert`/`--key`/`--ca` and `--enrollment-bind`. Refresh outcomes are
exposed via the `rustgate_spiffe_svid_refresh_total{outcome="success|failure"}`
counter and the `rustgate_spiffe_svid_expiry_seconds` gauge when the
`metrics` feature is also enabled, and via
`target="audit", event_type="spiffe.svid_refresh"` audit events.

## Running

### Configuration file

In addition to CLI flags and environment variables, all server settings can be
loaded from a TOML file. Pass `--config <path>` (or set `RUSTGATE_CONFIG`) to
the binary; keys mirror the CLI flag names in kebab-case:

```toml
# /etc/rustgate/rustgate.toml
bind = "0.0.0.0:4433"
cert = "/etc/rustgate/server.pem"
key  = "/etc/rustgate/server-key.pem"
ca   = "/etc/rustgate/ca.pem"

tls-min-version  = "1.3"
max-connections  = 4096
metrics-bind     = "0.0.0.0:9090"
audit-log        = "/var/log/rustgate/audit.jsonl"

federation-id        = "rustgate-east-1"
federation-v1-bind   = "0.0.0.0:9000"
federation-v2-bind   = "0.0.0.0:9001"
federation-max-hops  = 8

framing  = "tak-negotiate"
encoding = "raw"
```

Settings are merged in this order, with later sources overriding earlier ones:

1. **Built-in defaults** (the same defaults shown in the flag table below)
2. **Configuration file** (when `--config` is set)
3. **Environment variables** (`RUSTGATE_*` and friends)
4. **Command-line flags**

In other words: command-line flags always win, environment variables override
the file, and the file overrides defaults. Unknown keys in the file are
rejected.

Two helper subcommands ship alongside the flag:

```bash
# Print the effective merged configuration as TOML, then exit.
rustgate --config /etc/rustgate/rustgate.toml print-config

# Parse and validate a configuration file (cross-field checks). Exits 0 on
# success, non-zero with a descriptive error on failure.
rustgate --config /etc/rustgate/rustgate.toml validate-config

# Verify the integrity of a hash-chained audit log.
rustgate verify-audit --file /var/log/rustgate/audit.jsonl
```

#### Editor autocomplete via JSON Schema

A JSON Schema describing the `rustgate.toml` surface ships at
[`schemas/rustgate-v0.8.json`](schemas/rustgate-v0.8.json). Wire it into any
JSON-Schema-aware editor for autocomplete and inline validation while editing
your config.

For VS Code with the **Even Better TOML** extension, add this to your
`.vscode/settings.json`:

```json
{
  "evenBetterToml.schema.associations": {
    "**/rustgate.toml": "https://raw.githubusercontent.com/rchiofalo/rustgate/main/schemas/rustgate-v0.8.json"
  }
}
```

Operators building from source can regenerate the schema from the live `Cli`
type:

```bash
cargo run -p rustgate-server --features schema -- emit-schema \
  > schemas/rustgate-v0.8.json
```

The `emit-schema` subcommand is gated behind the `schema` feature so the
default release build does not pull `schemars` into the runtime image.

Running `rustgate` with no subcommand starts the server as before.

Minimal:

```bash
rustgate --cert server.pem --key server-key.pem --ca ca.pem
```

Full setup:

```bash
rustgate \
  --cert server.pem --key server-key.pem --ca ca.pem \
  --crl revoked.pem --fips-required \
  --websocket-bind 0.0.0.0:8443 \
  --nats-url nats://localhost:4222 \
  --metrics-bind 0.0.0.0:9090 \
  --federation-v1-bind 0.0.0.0:9000 \
  --federation-v2-bind 0.0.0.0:9001 \
  --framing tak-negotiate
```

<details>
<summary>All configuration flags</summary>

All flags support environment variables (CLI takes precedence):

| Flag | Env Var | Default |
|------|---------|---------|
| `--config` | `RUSTGATE_CONFIG` | — (TOML file; merged under env/CLI) |
| `--bind` | `RUSTGATE_BIND` | `0.0.0.0:4433` |
| `--cert` | `RUSTGATE_CERT` | — |
| `--key` | `RUSTGATE_KEY` | — |
| `--ca` | `RUSTGATE_CA` | — |
| `--crl` | `RUSTGATE_CRL` | — |
| `--crl-warn-stale` | `RUSTGATE_CRL_WARN_STALE` | `true` |
| `--tls-min-version` | `RUSTGATE_TLS_MIN_VERSION` | `1.2` |
| `--cert-reload-interval` | `RUSTGATE_CERT_RELOAD_INTERVAL` | `0` (disabled) |
| `--max-concurrent-handshakes` | `RUSTGATE_MAX_HANDSHAKES` | `100` |
| `--fips-required` | `RUSTGATE_FIPS_REQUIRED` | `false` |
| `--prefer-post-quantum` | `RUSTGATE_PREFER_POST_QUANTUM` | `false` |
| `--kx-groups` | `RUSTGATE_KX_GROUPS` | — (provider default) |
| `--framing` | `RUSTGATE_FRAMING` | `xml` |
| `--encoding` | `RUSTGATE_ENCODING` | `raw` |
| `--max-connections` | `RUSTGATE_MAX_CONNECTIONS` | `1024` |
| `--max-queued-bytes` | `RUSTGATE_MAX_QUEUED_BYTES` | `536870912` (512 MiB) |
| `--max-queued-bytes-low-water` | `RUSTGATE_MAX_QUEUED_BYTES_LOW_WATER` | 90% of high-water |
| `--tcp-bind` | `RUSTGATE_TCP_BIND` | — |
| `--udp-bind` | `RUSTGATE_UDP_BIND` | — |
| `--plaintext-cn` | `RUSTGATE_PLAINTEXT_CN` | `anonymous` |
| `--plaintext-group` | `RUSTGATE_PLAINTEXT_GROUP` | `__plaintext__` |
| `--metrics-bind` | `RUSTGATE_METRICS_BIND` | — |
| `--metrics-per-identity` | `RUSTGATE_METRICS_PER_IDENTITY` | `false` |
| `--metrics-identity-allowlist` | `RUSTGATE_METRICS_IDENTITY_ALLOWLIST` | — |
| `--nats-url` | `RUSTGATE_NATS_URL` | — |
| `--nats-credentials` | `RUSTGATE_NATS_CREDENTIALS` | — |
| `--nats-tls-cert` | `RUSTGATE_NATS_TLS_CERT` | — |
| `--nats-tls-key` | `RUSTGATE_NATS_TLS_KEY` | — |
| `--nats-tls-ca` | `RUSTGATE_NATS_TLS_CA` | — |
| `--nats-tls-required` | `RUSTGATE_NATS_TLS_REQUIRED` | `false` |
| `--nats-subscription-capacity` | `RUSTGATE_NATS_SUBSCRIPTION_CAPACITY` | `1024` |
| `--nats-live-stream` | `RUSTGATE_NATS_LIVE_STREAM` | `RUSTGATE_LIVE` |
| `--nats-max-ack-pending` | `RUSTGATE_NATS_MAX_ACK_PENDING` | `1000` |
| `--nats-checkpoint-path` | `RUSTGATE_NATS_CHECKPOINT_PATH` | — |
| `--http-config-file` | `RUSTGATE_HTTP_CONFIG` | — |
| `--websocket-bind` | `RUSTGATE_WEBSOCKET_BIND` | — |
| `--ws-max-frames-per-sec` | `RUSTGATE_WS_MAX_FRAMES_PER_SEC` | `0` (disabled) |
| `--ws-max-bytes-per-sec` | `RUSTGATE_WS_MAX_BYTES_PER_SEC` | `0` (disabled) |
| `--ws-max-violations` | `RUSTGATE_WS_MAX_VIOLATIONS` | `10` |
| `--enrollment-bind` | `RUSTGATE_ENROLLMENT_BIND` | — |
| `--ca-key` | `RUSTGATE_CA_KEY` | — |
| `--enrollment-user` | `RUSTGATE_ENROLLMENT_USER` | — |
| `--enrollment-password` | `RUSTGATE_ENROLLMENT_PASSWORD` | — |
| `--ca-organization` | `RUSTGATE_CA_ORG` | `rustgate` |
| `--enrollment-rate-limit` | `RUSTGATE_ENROLLMENT_RATE_LIMIT` | `10` (per IP per minute, 0 = unlimited) |
| `--data-package-dir` | `RUSTGATE_DATA_PACKAGE_DIR` | — |
| `--package-signature-ca` | `RUSTGATE_PACKAGE_SIGNATURE_CA` | — |
| `--package-strict-signatures` | `RUSTGATE_PACKAGE_STRICT_SIGNATURES` | `false` |
| `--revocation-db` | `RUSTGATE_REVOCATION_DB` | — |
| `--crl-validity-days` | `RUSTGATE_CRL_VALIDITY_DAYS` | `7` |
| `--est-enabled` | `RUSTGATE_EST_ENABLED` | `false` |
| `--federation-v1-bind` | `RUSTGATE_FEDERATION_V1_BIND` | — |
| `--federation-v2-bind` | `RUSTGATE_FEDERATION_V2_BIND` | — |
| `--federation-id` | `RUSTGATE_FEDERATION_ID` | `rustgate-federation-1` |
| `--federation-peers-file` | `RUSTGATE_FEDERATION_PEERS_FILE` | — |
| `--federation-peers-reload-interval` | `RUSTGATE_FEDERATION_PEERS_RELOAD_INTERVAL` | `0` |
| `--federation-peer-discovery` | `RUSTGATE_FEDERATION_PEER_DISCOVERY` | `none` (one of `none`, `dns-sd`, `consul`, `etcd`) |
| `--federation-peer-discovery-interval` | `RUSTGATE_FEDERATION_PEER_DISCOVERY_INTERVAL` | `30` (seconds) |
| `--federation-peer-discovery-dns-sd-service` | `RUSTGATE_FEDERATION_PEER_DISCOVERY_DNS_SD_SERVICE` | `_rustgate._tcp.local.` |
| `--federation-peer-discovery-consul-addr` | `RUSTGATE_FEDERATION_PEER_DISCOVERY_CONSUL_ADDR` | `http://127.0.0.1:8500` |
| `--federation-peer-discovery-consul-service` | `RUSTGATE_FEDERATION_PEER_DISCOVERY_CONSUL_SERVICE` | `rustgate` |
| `--federation-peer-discovery-etcd-endpoints` | `RUSTGATE_FEDERATION_PEER_DISCOVERY_ETCD_ENDPOINTS` | `http://127.0.0.1:2379` (comma-separated) |
| `--federation-peer-discovery-etcd-prefix` | `RUSTGATE_FEDERATION_PEER_DISCOVERY_ETCD_PREFIX` | `rustgate/peers/` |
| `--federation-skip-hostname-verify` | `RUSTGATE_FEDERATION_SKIP_HOSTNAME_VERIFY` | `false` |
| `--federation-max-hops` | `RUSTGATE_FEDERATION_MAX_HOPS` | `10` |
| `--federation-store-path` | `RUSTGATE_FEDERATION_STORE_PATH` | — |
| `--federation-trust-store-dir` | `RUSTGATE_FEDERATION_TRUST_STORE_DIR` | — |
| `--federation-circuit-breaker-threshold` | `RUSTGATE_FEDERATION_CIRCUIT_BREAKER_THRESHOLD` | `5` |
| `--federation-circuit-breaker-timeout` | `RUSTGATE_FEDERATION_CIRCUIT_BREAKER_TIMEOUT` | `60` |
| `--federation-replay-buffer-size` | `RUSTGATE_FEDERATION_REPLAY_BUFFER_SIZE` | `1000` |
| `--federation-replay-dir` | `RUSTGATE_FEDERATION_REPLAY_DIR` | — |
| `--federation-replay-max-bytes` | `RUSTGATE_FEDERATION_REPLAY_MAX_BYTES` | `67108864` (64 MiB) |
| `--federation-ha-nats-url` | `RUSTGATE_FEDERATION_HA_NATS_URL` | — |
| `--federation-pod-id` | `RUSTGATE_FEDERATION_POD_ID` | — |
| `--replay-window` | `RUSTGATE_REPLAY_WINDOW` | `300` |
| `--dedup-window-secs` | `RUSTGATE_DEDUP_WINDOW_SECS` | `0` (disabled) |
| `--dedup-cache-size` | `RUSTGATE_DEDUP_CACHE_SIZE` | `100000` |
| `--client-msg-rate` | `RUSTGATE_CLIENT_MSG_RATE` | `0` (disabled) |
| `--client-burst` | `RUSTGATE_CLIENT_BURST` | `200` |
| `--circuit-breaker-threshold` | `RUSTGATE_CIRCUIT_BREAKER_THRESHOLD` | `10` |
| `--group-acl-file` | `RUSTGATE_GROUP_ACL_FILE` | — |
| `--archive-dir` | `RUSTGATE_ARCHIVE_DIR` | — |
| `--archive-key-file` | `RUSTGATE_ARCHIVE_KEY_FILE` | — |
| `--archive-max-size` | `RUSTGATE_ARCHIVE_MAX_SIZE` | `0` (unlimited) |
| `--archive-max-age` | `RUSTGATE_ARCHIVE_MAX_AGE` | `0` (unlimited, seconds) |
| `--archive-rotate-interval` | `RUSTGATE_ARCHIVE_ROTATE_INTERVAL` | `60` (seconds) |
| `--package-max-age-hours` | `RUSTGATE_PACKAGE_MAX_AGE_HOURS` | `0` (no expiration) |
| `--audit-log` | `RUSTGATE_AUDIT_LOG` | — |
| `--access-log` | `RUSTGATE_ACCESS_LOG` | — |
| `--client-queue-dir` | `RUSTGATE_CLIENT_QUEUE_DIR` | — (disabled) |
| `--client-queue-max-bytes` | `RUSTGATE_CLIENT_QUEUE_MAX_BYTES` | `104857600` (100 MiB) |
| `--otel-endpoint` | `OTEL_EXPORTER_OTLP_ENDPOINT` | — |
| `--otel-service-name` | `OTEL_SERVICE_NAME` | `rustgate` |
| `--otlp-metrics` | `RUSTGATE_OTLP_METRICS` | `false` |
| `--otlp-metrics-interval` | `RUSTGATE_OTLP_METRICS_INTERVAL` | `60` (seconds, min 1) |
| `--authz-policy-file` | `RUSTGATE_AUTHZ_POLICY_FILE` | — |
| `--authz-policy-format` | `RUSTGATE_AUTHZ_POLICY_FORMAT` | `native` |
| `--authz-fail-open` | `RUSTGATE_AUTHZ_FAIL_OPEN` | `false` |
| `--position-replay-rate-per-sec` | `RUSTGATE_POSITION_REPLAY_RATE_PER_SEC` | `100` |
| `--position-replay-burst` | `RUSTGATE_POSITION_REPLAY_BURST` | `200` |
| `--tenant-quota-file` | `RUSTGATE_TENANT_QUOTA_FILE` | — |
| `--federation-region` | `RUSTGATE_FEDERATION_REGION` | — |
| `--mqtt-bind` | `RUSTGATE_MQTT_BIND` | — |
| `--mqtt-max-packet-size` | `RUSTGATE_MQTT_MAX_PACKET_SIZE` | `16777216` (16 MiB) |
| `--spiffe` | `RUSTGATE_SPIFFE` | `false` |
| `--spiffe-workload-api-socket` | `RUSTGATE_SPIFFE_WORKLOAD_API_SOCKET` | — |
| `--ocsp-stapling` | `RUSTGATE_OCSP_STAPLING` | `false` |
| `--client-ocsp` | `RUSTGATE_CLIENT_OCSP` | `false` |
| `--metrics-token-file` | `RUSTGATE_METRICS_TOKEN_FILE` | — |
| `--shutdown-drain-timeout` | `RUSTGATE_SHUTDOWN_DRAIN_TIMEOUT` | `10` (seconds) |
| `--acl-reload-interval` | `RUSTGATE_ACL_RELOAD_INTERVAL` | `0` (disabled) |
| `--udp-rate-limit` | `RUSTGATE_UDP_RATE_LIMIT` | `0` (disabled) |
| `--udp-allowed-cidrs` | `RUSTGATE_UDP_ALLOWED_CIDRS` | — |
| `--udp-max-identities` | `RUSTGATE_UDP_MAX_IDENTITIES` | `1024` |
| `--ws-max-write-buffer-bytes` | `RUSTGATE_WS_MAX_WRITE_BUFFER_BYTES` | `4194304` (4 MiB) |
| `--cot-delta-encoding` | `RUSTGATE_COT_DELTA_ENCODING` | `false` |
| `--cot-delta-cache-size` | `RUSTGATE_COT_DELTA_CACHE_SIZE` | `512` |
| `--cot-delta-epsilon-meters` | `RUSTGATE_COT_DELTA_EPSILON_METERS` | `1.0` |
| `--acl-api-token-file` | `RUSTGATE_ACL_API_TOKEN_FILE` | — |

</details>

### Encrypted-at-rest archive and audit log

When `--archive-key-file <path>` is supplied, the CoT archive
(`--archive-dir`) and the audit log (`--audit-log`) are written through
a streaming ChaCha20-Poly1305 sink instead of plaintext JSONL. The key
file is a small JSON document:

```json
{
  "active_key_id": "k1",
  "keys": {
    "k1": "1111111111111111111111111111111111111111111111111111111111111111"
  }
}
```

Each key is a 32-byte (64-character) lowercase hex string. The `active_key_id`
is used for new writes; rotating keys is as simple as adding a new entry
and updating `active_key_id` — historical files written under the prior
key remain readable as long as that key is still listed. Encrypted files
gain an `.enc` suffix and start with an authenticated header that records
the key id used.

To inspect or export an encrypted file:

```bash
rustgate decrypt-archive \
  --in  /var/log/rustgate/cot-2026-04-06.jsonl.enc \
  --out /tmp/cot-2026-04-06.jsonl \
  --key-file /etc/rustgate/archive-keys.json
```

Tampering with any byte of the on-disk ciphertext fails AEAD verification
on read. Key bytes are held in `zeroize::Zeroizing` buffers and wiped on
drop.

### Cross-path deduplication

When the same logical message reaches the server via more than one
ingress path — for example, a directly-connected client and a federation
peer that forwarded the same event — subscribers would normally receive
two copies. Setting `--dedup-window-secs` to a non-zero value enables a
router-level LRU cache keyed by
`SHA-256(uid || 0x00 || time_le || 0x00 || payload)`. For CoT XML the
`uid` attribute is extracted from the payload; for non-CoT payloads
(protobuf, raw binary) `uid` is empty and the key degenerates to a
pure content hash so byte-identical payloads are still deduped. The
router consults the cache before dispatching a message; if the same
key was already seen within the window, the duplicate is dropped before
it reaches any subscriber and the `rustgate_dedup_hits_total` counter is
incremented. The current cache occupancy is exposed as
`rustgate_dedup_cache_size`. Use `--dedup-cache-size` to bound the cache
(default 100 000 entries, oldest evicted in LRU order). Disabled by
default.

### NATS JetStream consumer lag metrics

When built with `--features metrics,nats` and `--nats-url` is configured,
the NATS pull-consumer subscriber polls `consumer.info()` every five
seconds and exports three gauges so operators can alert on cross-instance
bridge lag and redelivery storms:

- `rustgate_nats_consumer_pending` — messages pending delivery to this
  instance's pull consumer (`num_pending`).
- `rustgate_nats_consumer_num_redelivered` — current count of messages in
  a redelivered state (`num_redelivered`).
- `rustgate_nats_consumer_ack_floor_stream_seq` — stream sequence of the
  highest contiguous ACK (`ack_floor.stream_seq`); a flat value while
  `pending` grows indicates the consumer is stuck.

### Per-identity metrics (bounded cardinality)

`messages_routed_total` and `messages_dropped_total` carry an
`identity_cn` label so operators can attribute routing volume and rate-limit
drops to individual clients. To prevent unbounded label growth from large
or untrusted client populations, the label is bucketed against an optional
allowlist (`--metrics-identity-allowlist`, one CN per line, `#` comments
allowed). CNs that are not in the allowlist — or **all** CNs when the
allowlist is unset — collapse into the literal `"other"` bucket, capping
per-identity cardinality at 1 by default.

Set `--metrics-per-identity` (or `RUSTGATE_METRICS_PER_IDENTITY=true`) to
additionally register the Tier 2 per-identity metrics:
`rustgate_per_identity_handshake_failures_total`,
`rustgate_per_identity_session_duration_seconds`,
`rustgate_per_identity_bytes_sent_total`, and
`rustgate_per_identity_bytes_received_total`. When the flag is disabled
(the default), these metrics are not registered at all and impose zero
overhead.

**Scope:** per-identity labels currently cover the TLS and plaintext TCP
transports only. WebSocket sessions are not yet labelled and will not appear
in `identity_cn`-labelled series. Byte counters report **application payload
bytes** (post-decode / pre-encode), not wire bytes — they exclude TLS,
framing, and codec overhead.

### Federation peer discovery (DNS-SD, Consul, etcd)

Static peer lists via `--federation-peers-file` remain the recommended
source of truth for production meshes, but rustgate can also pull its
peer set from an external service registry so nodes joining or leaving a
cluster are reflected automatically. Set `--federation-peer-discovery` to
one of `dns-sd`, `consul`, or `etcd` (it is mutually exclusive with
`--federation-peers-file`), and a background reconciler will poll the
selected backend every `--federation-peer-discovery-interval` seconds
(default 30) and pipe the result into the same `swap_peers` machinery
used by the file reloader. Adds, removes, and unchanged peers take the
usual zero-downtime path: unchanged peers keep their existing connection,
removed peers are disconnected cleanly, and new peers are connected.

Each backend ships behind its own cargo sub-feature so minimal images
only pay for the registry they actually use:

- **DNS-SD / mDNS** (`--features peer-discovery-dns-sd`) — browses an
  mDNS service type on the local link (default
  `--federation-peer-discovery-dns-sd-service=_rustgate._tcp.local.`).
  Each resolved service instance becomes an outbound peer whose address
  is the instance's advertised host and port. Useful for self-forming
  edge clusters on a flat L2 network; requires multicast between nodes.
- **Consul** (`--features peer-discovery-consul`) — queries
  `GET /v1/catalog/service/<name>` on the agent or server endpoint given
  by `--federation-peer-discovery-consul-addr` (default
  `http://127.0.0.1:8500`). Service instances with a non-empty
  `ServiceAddress` use that field; otherwise the fallback is the node's
  `Address`. The service name is configurable via
  `--federation-peer-discovery-consul-service` (default `rustgate`).
- **etcd** (`--features peer-discovery-etcd`) — performs a prefix scan
  against the gRPC endpoints listed in
  `--federation-peer-discovery-etcd-endpoints` (comma-separated) under
  `--federation-peer-discovery-etcd-prefix` (default `rustgate/peers/`).
  Values may be either a plain `host:port` string or a serialized
  `PeerConfig` JSON object for full control over groups and routing.

The umbrella feature `peer-discovery` enables all three backends. Mixing
backends is not supported — a single reconciler runs at a time — but the
`PeerDiscovery` trait is public so operators can provide their own.

Selecting a backend whose sub-feature was not compiled in fails fast at
startup with a clear error instead of silently ignoring the setting. See
[docs/runbooks/federation-reconnect.md](docs/runbooks/federation-reconnect.md)
for troubleshooting guidance on each backend.

### Per-peer federation lag

When the `federation` and `metrics` features are both enabled, two
gauges expose how far behind each federation peer is, so operators can
spot cascading backpressure:

- `rustgate_federation_peer_queue_bytes{peer="..."}` — bytes currently
  queued on the peer's outbound channel.
- `rustgate_federation_peer_oldest_seconds{peer="..."}` — age in seconds
  of the oldest message still waiting for delivery (`0` when the queue
  is empty).

Both gauges are refreshed once per second by a background task that
snapshots the federation manager. Labels for peers that disappear are
removed on the following tick.

## Docker

```bash
docker compose up -d
```

This starts NATS with JetStream, a one-shot stream setup container, and rustgate on port 4433 with metrics on 9090.

The Dockerfile builds all features (including jemalloc) in a multi-stage Alpine build. The final image runs as UID 10001 with a read-only root filesystem. Health is checked via `/health/live` on port 9090.

To build the image standalone:

```bash
docker build -t rustgate .
```

## Kubernetes

A Helm chart is provided in `helm/`:

```bash
helm install rustgate helm/ --set tls.secretName=my-tls-secret
```

The chart includes Pod Security Standards (restricted profile), startup/liveness/readiness probes, PodDisruptionBudget, HorizontalPodAutoscaler, graceful shutdown with connection draining, optional federation, and NetworkPolicy.

For full deployment documentation see [docs/deployment.md](docs/deployment.md).

## Security

- **mTLS everywhere** — all client and federation connections require mutual TLS with certificate verification
- **CRL revocation** — revoked certificates are rejected at the TLS handshake via `--crl`
- **OCSP stapling** — optional `ocsp` feature staples OCSP responses to the server certificate (see below)
- **FIPS 140-3** — optional aws-lc-rs crypto provider for FIPS-validated TLS ([details](docs/fips.md))
- **No unsafe code** — `unsafe_code = "forbid"` enforced workspace-wide
- **No panics** — `clippy::panic = "deny"` and `clippy::unwrap_used = "deny"` in production code
- **Subject DN enforcement** — enrollment certificates carry the authenticated username to prevent impersonation
- **Container hardening** — non-root UID (10001), read-only filesystem, STOPSIGNAL SIGTERM
- **TLS session resumption disabled** — forces full handshake with CRL check on every connection

### OCSP stapling

Build with `--features ocsp` and pass `--ocsp-stapling` (env `RUSTGATE_OCSP_STAPLING`) to wrap the
server certificate resolver with [`ocsp-stapler`](https://crates.io/crates/ocsp-stapler). The
stapler runs a background tokio task that periodically fetches an OCSP response for the active
certificate from the issuing CA's OCSP responder and attaches it to the TLS handshake, so clients
can verify revocation status without contacting the CA themselves.

Notes:

- **Best with private / enterprise CAs.** Let's Encrypt stopped serving OCSP responses in 2025.
  OCSP stapling is most valuable for internal PKIs that operate their own OCSP responder.
- **First handshakes after startup may be unstapled** until the background fetcher completes its
  initial cycle (~60s). The server preloads the active certificate into the stapler at startup so
  the fetch is queued immediately, but the very first handshakes can still arrive before the
  response lands. This is the same fallback path clients already use when stapling is off.
- **After a certificate rotation (SIGHUP or polling), there is a brief window — typically under
  one minute — during which handshakes may be served unstapled until the background fetcher
  refreshes.** The SIGHUP path also re-preloads the rotated certificate into the stapler to
  shorten this window.
- **Requires outbound network access to the issuing CA's OCSP responder**; air-gapped deployments
  should leave this flag off.
- **Responder failures degrade gracefully** — handshakes continue without a stapled response.
- **CRL and OCSP can be enabled together.** OCSP stapling lives on the *server certificate*
  resolver path; CRL revocation lives on the *client certificate* verifier path. They are
  independent layers and may be combined freely.
- **SHA-1 OCSP requests.** The upstream `ocsp-stapler` crate currently issues OCSP requests with
  SHA-1 issuer hashes. Most CAs accept this — verify compatibility with strict modern responders.

### Client certificate OCSP verification

Build with `--features ocsp` and pass `--client-ocsp` (env `RUSTGATE_CLIENT_OCSP`) to wrap the
client certificate verifier with a SKI-keyed OCSP cache. On a cache miss the inner verifier's
decision still stands (Tier 1, fail-open) and a background task fetches an OCSP response so the
*next* handshake for the same client certificate can be answered from the cache; cached
`Revoked` responses cause the handshake to be rejected before the session is established.

This complements CRL-based revocation (which only refreshes on a schedule) with near-real-time
revocation for the incoming client cert. Two Prometheus counters track cache effectiveness when
`--features metrics` is enabled:

- `rustgate_client_ocsp_cache_hits_total`
- `rustgate_client_ocsp_cache_misses_total`

For security policy and vulnerability reporting see [SECURITY.md](SECURITY.md).

## Testing

```bash
cargo nextest run                              # All tests (default features)
cargo nextest run --features fips              # FIPS-gated tests
cargo nextest run -p rustgate-nats --test integration  # NATS integration (needs nats-server)
```

| Crate | Test files | Covers |
|-------|-----------|--------|
| `rustgate-transport` | `tls_listener`, `e2e_routing`, `encoder`, `crl`, `fips`, `cert_rotation` | mTLS, routing, codecs, CRL, FIPS, certificate hot-reload |
| `rustgate-cot` | `parser` | CoT XML parsing |
| `rustgate-core` | `types` | Core type invariants |
| `rustgate-enrollment` | `server_integration`, `est_integration` | PKCS#12 enrollment, CSR signing, EST (RFC 7030) |
| `rustgate-federation` | `v2_integration`, `api_integration`, `ha_integration` | Federation V2 protocol, REST API, HA coordination |
| `rustgate-nats` | `integration` | NATS bridge, echo prevention, JetStream replay |
| `rustgate-proto` | `codec_integration` | XML ↔ protobuf conversion |
| `rustgate-server` | `cli_parsing`, `tls_config`, `feature_gates`, `archive_integration` | CLI validation, TLS setup, feature gating, CoT archival |
| `rustgate-websocket` | `ws_listener`, `ws_server` | WebSocket mTLS, session routing |
| `rustgate-authz` | `policy_engine`, `cedar_backend` | RBAC/ABAC policy evaluation, Cedar integration |
| `rustgate-mqtt` | `session`, `codec` | MQTT transport, protocol negotiation, group subscriptions |

All tests use ephemeral certificates generated at runtime via `rustgate-test-utils` — no fixture files.

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](docs/architecture.md) | System design and crate responsibilities |
| [Protocol Specification](docs/protocol.md) | Wire format, framing, codecs, routing, federation, HA |
| [TLS Certificates](docs/tls-certificates.md) | Certificate requirements, generation, and management |
| [Deployment](docs/deployment.md) | Binary, Docker Compose, and Kubernetes deployment |
| [FIPS 140-3](docs/fips.md) | FIPS crypto provider setup and known limitations |
| [Configuration](docs/configuration.md) | All CLI flags, env vars, and runtime options |
| [Security Posture](docs/security-posture.md) | NIST 800-53 control mapping and compliance overview |
| [Threat Model](docs/threat-model.md) | STRIDE methodology threats, mitigations, and residual risks |
| [Graceful Degradation](docs/graceful-degradation.md) | Subsystem failure modes and recovery behavior |
| [Post-Quantum Roadmap](docs/post-quantum.md) | Path to post-quantum cryptographic protection |
| [Observability](docs/observability.md) | Structured logging, metrics, and distributed tracing |
| [Federation](docs/federation.md) | Federation architecture, peer management, and HA mode |
| [REST API](docs/rest-api.md) | Health, metrics, federation, ACL, and enrollment endpoints |
| [Disaster Recovery](docs/disaster-recovery.md) | Backup, restore, and failover procedures |
| [Performance Tuning](docs/performance-tuning.md) | Tuning guides for throughput, latency, and memory |
| [Troubleshooting](docs/troubleshooting.md) | Common issues, diagnostics, and resolution steps |
| [Crypto Agility](docs/crypto-agility.md) | Cryptographic algorithm selection and migration |
| [Architecture Decision Records](docs/adr/README.md) | Non-obvious workspace decisions (locking, dependency choices, secret handling) |
| [Runbooks](docs/runbooks/) | Operational runbooks for federation, memory, NATS |
| [CONTRIBUTING](CONTRIBUTING.md) | Build prerequisites, code quality, and PR guidelines |
| [CHANGELOG](CHANGELOG.md) | Release history in Keep a Changelog format |
| [SECURITY](SECURITY.md) | Security policy and vulnerability reporting |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for prerequisites, building, testing, code quality standards, and pull request guidelines.

## License

Proprietary. See [LICENSE](LICENSE) for details.
