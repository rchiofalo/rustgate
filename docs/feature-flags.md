# Feature Flags Reference

Every Cargo feature flag across the rustgate workspace. **53 unique
feature names across 24 crates**, with 111 total definitions (the
delta is from features that propagate by the same name across multiple
crates — `metrics`, `fips`, `post-quantum`, etc.).

This file is the operational answer to "which features should I enable
on the rustgate binary?". For the architectural rationale behind a
specific feature, see the corresponding ADR in `docs/adr/`. For the
build-time and runtime cost of each, see `docs/performance-tuning.md`.

## How feature flags work

- **Top-level surface**: 41 features are declared on `rustgate-server`
  (the binary). These are what an operator selects with `--features`
  at `cargo build` time, or what a Helm chart sets via
  `image.build.features`.
- **Propagation**: most server-level features turn into dependency
  features on workspace crates (e.g. `--features fips` on the server
  flips `rustls/aws_lc_rs` + `rustls/fips` on `rustgate-tls`,
  `rustgate-federation`, `rustgate-enrollment`, and `rustgate-http`).
  Per-crate features are listed in the [Per-crate reference](#per-crate-reference)
  below.
- **Default features**: rustgate-server has **no default features**.
  Every capability is opt-in. The default release binary in
  `dockerfiles/` enables the canonical operator bundle: `nats,
  enrollment, est, proto, full-detail, metrics, federation,
  federation-ha, websocket, mqtt, otel, http`.
- **Special-build features**: a handful of features change the
  toolchain or build matrix (Go required for FIPS / PQ; protoc
  required for proto / OTel). Marked with **(special build)** below.
- **CI coverage**: `cargo hack check --feature-powerset --depth 2` runs
  on every PR, excluding `jemalloc, fips, otel, post-quantum,
  mavlink-pq` (which require special builds). Independent CI jobs cover
  those — `mavlink-pq` is clippy-checked and tested in the
  `post-quantum` lane (it shares the aws-lc-rs build dependency).

### Quick-start bundles

| Bundle | `--features …` | Purpose |
|---|---|---|
| **Default release binary** | `nats,enrollment,est,proto,full-detail,metrics,federation,federation-ha,websocket,mqtt,otel,http` | Canonical operator build — what `docker pull rustgate:latest` ships. |
| **Tactical edge** | `metrics,websocket,mqtt,proto,full-detail` | Minimal binary for resource-constrained edge nodes (no federation, no NATS). |
| **Federated hub** | `nats,enrollment,est,metrics,federation,federation-ha,otel,http,management-api,peer-discovery` | Central federation hub with auto-discovery, observability, and a management plane. |
| **CNSA-2 compliant** | `fips,enrollment,est,metrics,federation,websocket,otel,jemalloc` | NSA CNSA 2.0 alignment; FIPS provider with PQ-ready posture. |
| **Post-quantum experimental** | `post-quantum,metrics,federation,websocket` | ML-KEM-768 hybrid KEX (ADR 0011 / 0019). Not for production yet. |

---

## Top-level features (`rustgate-server`)

### Default features

`rustgate-server` declares **no defaults** — every feature is opt-in.
This is deliberate so consumers can build a minimal binary by setting
`--no-default-features` and then explicitly listing what they need
(useful for FIPS, air-gap, and SBOM-restricted builds).

### Transport & protocol features

| Feature | Adds | Special build? | Notes |
|---|---|---|---|
| `nats` | NATS/JetStream bridge (publisher + JetStream pull-consumer) | No | Brings in `rustgate-nats` and admin glue. |
| `enrollment` | PKCS#12 certificate enrollment HTTP endpoint | No | Required by EST. |
| `est` | EST (RFC 7030) endpoints | No | Implies `enrollment`. Brings `cms` / `der` / `x509-cert`. |
| `proto` | Protobuf message support (Federation V2, TAK proto wire) | **protoc required** | Implies `rustgate-transport/proto` and downstream HTTP target proto. |
| `websocket` | WebSocket transport adapter (mTLS-authenticated) | No | RFC 6455; RFC 7692 `permessage-deflate` available at runtime. |
| `mqtt` | MQTT 5.0 + 3.1.1 broker adapter | No | mTLS-authenticated. Includes retained-message store and LWT. |
| `http` | HTTP/webhook egress publishers | No | Per-target circuit breaker + dead-letter queue. |
| `full-detail` | Extended CoT parsing (delta encoding, full attribute set) | No | Implies `nats`. Slightly larger binary; needed for production CoT. |

### Federation features

| Feature | Adds | Notes |
|---|---|---|
| `federation` | Server-to-server federation, V2 gRPC, API | Implies `rustgate-federation/v2` + `/api`. |
| `federation-ha` | HA federation via shared NATS-backed state | Implies `federation`. |
| `mesh-routing` | DSR-style multi-hop mesh routing across federation peers | Implies `federation`. |
| `peer-discovery` | All three peer discovery backends (umbrella) | Implies the three below. |
| `peer-discovery-dns-sd` | DNS-SD / mDNS peer discovery | RFC 6762 / 6763. |
| `peer-discovery-consul` | HashiCorp Consul service-catalogue discovery | HTTP-based; respects ACL token. |
| `peer-discovery-etcd` | etcd-backed peer discovery | gRPC; respects TLS + auth. |

### Crypto & security features

| Feature | Adds | Special build? | Notes |
|---|---|---|---|
| `fips` | aws-lc-rs FIPS 140-3 provider; PQ-ready posture | **Go + cmake required** | Replaces ring with aws-lc-rs across TLS stack. |
| `post-quantum` | ML-KEM-768 hybrid KEX (X25519 + Kyber) | **Go + cmake required** | Experimental; co-exists with FIPS or alone. See ADR 0011 / 0019. |
| `ocsp` | OCSP stapling for served certificates | No | Background fetcher with cached good/revoked. |
| `spiffe` | SPIFFE Workload API integration | No | Auto-rotating SVIDs; trust-bundle refresh. |
| `cedar` | Cedar policy backend for authorization | No | Default backend is built-in; Cedar is opt-in. |

### Observability features

| Feature | Adds | Special build? | Notes |
|---|---|---|---|
| `metrics` | Prometheus instrumentation (154 metrics) | No | Endpoint `/metrics` on `--metrics-bind`. See `docs/metrics-reference.md`. |
| `otel` | OpenTelemetry OTLP gRPC trace export | **protoc required** | Configure via `--otel-endpoint` (or `OTEL_EXPORTER_OTLP_ENDPOINT`). |
| `jemalloc` | jemalloc allocator replacement | Platform-specific (Linux x86_64 + aarch64 only) | Adds 4 RSS-attribution gauges. |
| `management-api` | REST admin endpoints (clients, drain, archive) | No | Bearer-token authenticated; emits `mgmt.api_accessed` audit events. |

### Higher-order integrations

These features wire rustgate into larger ecosystems. Most are
mock-able (`*-mock`) for local development without external infra.

| Feature | Adds | Companion `-mock` / `-real` | Notes |
|---|---|---|---|
| `marti-compat` | Marti-flavour CoT compatibility shim | — | Implies `enrollment`, `video`, `rustgate-admin/marti-compat`. |
| `lattice` | Anduril Lattice SDK integration umbrella | `lattice-mock`, `lattice-real` | Use `lattice-mock` for dev/CI; `lattice-real` requires an SDK token. |
| `foundry` | Palantir Foundry data-egress integration umbrella | `foundry-mock` | Mock-only in workspace (real path is enterprise). |
| `dds` | OMG DDS / ROS 2 bridge umbrella | `dds-mock` | Mock-only in workspace; `dds-real` enables `rustdds` + `ros2-client`. |
| `inference` | ML-inference adapter (rustgate-inference) | `inference-mock` | Mock-only in workspace. |
| `correlation` | Cross-domain entity-correlation engine | — | Implies `rustgate-correlation`. |
| `missions` | TAK data-package REST API (`/api/packages`) | — | Implies `rustgate-missions` + `rustgate-admin/missions`. Needs `metrics` + `--packages-dir`; reuses `--metrics-token-file` for auth. |
| `ogc-sensorthings` | OGC SensorThings API ingest | — | OGC standard for IoT sensor data. |
| `meshtastic` | Meshtastic LoRa mesh bridge | — | LoRaWAN-adjacent low-bandwidth bridge. |
| `sapient` | UK MOD SAPIENT ASE/ASM bridge | — | Sensor data over publish/subscribe. |
| `video` | Video metadata processing | — | Brings `quick-xml`. |

### Schema & utility features

| Feature | Adds | Notes |
|---|---|---|
| `schema` | JSON Schema export for the config surface | Brings `schemars`. Used by the operator and `--print-schema`. |

---

## Per-crate reference

The same feature name can mean different things on different crates;
the table below is the source of truth.

### `rustgate-core` (foundation, no transport)

| Feature | Pulls in |
|---|---|
| `fuzz` | `arbitrary` (for fuzz harnesses only) |
| `pem` | `rustls`, `rustls-pki-types` (PEM parsing helpers reused by tests) |

### `rustgate-tls`

| Feature | Pulls in |
|---|---|
| `fips` | `rustls/aws_lc_rs`, `rustls/fips` |
| `post-quantum` | `rustls/aws_lc_rs`, `rustls/prefer-post-quantum` |
| `ocsp` | `ocsp-stapler` |
| `spiffe` | `spiffe` SDK |

### `rustgate-transport`

| Feature | Pulls in |
|---|---|
| `proto` | `rustgate-proto` |
| `mavlink` | `rustgate-mavlink` (v1/v2 framing) |
| `fips` | `rustgate-tls/fips` |
| `post-quantum` | `rustgate-tls/post-quantum` |
| `ocsp` | `rustgate-tls/ocsp` |
| `spiffe` | `rustgate-tls/spiffe` |

### `rustgate-federation`

| Feature | Pulls in |
|---|---|
| `v2` | gRPC stack (`tonic`, `tonic-prost`, `prost-build`, `rustgate-proto`) |
| `ha` | `async-nats` for shared HA state |
| `api` | REST API (`hyper`, `prometheus`, `rustgate-metrics`) |
| `fips` | `rustls/{aws_lc_rs,fips}`, `tonic?/tls-aws-lc` |
| `post-quantum` | `rustls/{aws_lc_rs,prefer-post-quantum}`, `tonic?/tls-aws-lc` |
| `peer-discovery` | All three backends |
| `peer-discovery-dns-sd` | `mdns-sd`, `async-trait` |
| `peer-discovery-consul` | `reqwest`, `async-trait` |
| `peer-discovery-etcd` | `etcd-client`, `async-trait` |
| `jwks` | `reqwest` (for JWKS HTTP fetcher) |
| `otel` | `opentelemetry`, `tracing-opentelemetry` |
| `mesh-routing` | (no extra deps; gates the mesh router module) |

### `rustgate-enrollment`

| Feature | Pulls in |
|---|---|
| `est` | `cms`, `der`, `x509-cert` |
| `fips` | `rcgen/fips` (test cert generation under FIPS) |

### `rustgate-authz`

| Feature | Pulls in |
|---|---|
| `cedar` | `cedar-policy` backend |
| `metrics` | `prometheus`, `rustgate-metrics` |
| `cjadc2` | (gates CJADC2 obligation enforcement) |

### `rustgate-http`

| Feature | Pulls in |
|---|---|
| `metrics` | `prometheus`, `rustgate-metrics`, `rustgate-resilience/metrics` |
| `proto` | `prost`, `rustgate-proto` |
| `otel` | `opentelemetry`, `tracing-opentelemetry` |
| `fips` | `rustls/{aws_lc_rs,fips}` |
| `post-quantum` | `rustls/{aws_lc_rs,prefer-post-quantum}` |

### `rustgate-mavlink`

| Feature | Pulls in |
|---|---|
| `mavlink-pq` *(special build)* | `aws-lc-rs` (ML-KEM-768), `ciborium`, `hkdf`, `chacha20poly1305`, `serde` — the post-quantum signing-key rekey channel (ADR 0020). Needs Go + cmake; off by default. |

### `rustgate-mqtt`, `rustgate-websocket`, `rustgate-cot`, `rustgate-proto`, `rustgate-guard`

Each of these has a single `metrics` feature pulling in `prometheus`
+ `rustgate-metrics`. `rustgate-cot` also has a `fuzz` feature for
its CoT-XML parsing fuzz targets.

### `rustgate-nats`

| Feature | Pulls in |
|---|---|
| `full-detail` | `rustgate-proto` (TAK protobuf decoding alongside XML) |

### `rustgate-resilience`

| Feature | Pulls in |
|---|---|
| `metrics` | (no extra deps; exposes `CircuitBreaker::state_value()` for gauge wiring) |

### `rustgate-router`

| Feature | Pulls in |
|---|---|
| `cjadc2` | `rustgate-authz/cjadc2` |

### `rustgate-archive`

| Feature | Pulls in |
|---|---|
| `metrics` | (no extra deps; exposes archive metrics) |

### `rustgate-admin`

The admin crate is the glue layer between the server binary and
optional subsystems. Most of its features only re-export crate deps.

| Feature | Pulls in |
|---|---|
| `nats` | `rustgate-nats` |
| `federation` | `rustgate-federation` |
| `http` | `rustgate-http` |
| `missions` | `rustgate-missions` |
| `video` | `quick-xml` |
| `correlation` | `rustgate-correlation` |
| `marti-compat` | `rustgate-enrollment`, `missions`, `video` |
| `management-api` | `rustgate-archive` |

### `rustgate-operator`

| Feature | Pulls in |
|---|---|
| `controller` | Full Kubernetes controller stack (`kube`, `k8s-openapi`, `tokio`, `axum`, `prometheus`, `chrono`, `futures`, `fastrand`, `schemars`) |

### `rustgate-ogc-sensorthings`

| Feature | Pulls in |
|---|---|
| `mqtt-push` | `rumqttc` (`default-features = false`, no TLS features — MVP accepts only `mqtt://` URIs and rejects `mqtts://` at startup, so the rustls / native-tls feature flags stay off until a follow-up adds CA-pin / mTLS / SNI knobs). Enables the SensorThings v1.0 §10 MQTT push subscriber. |

### Mock-able integrations

`rustgate-dds`, `rustgate-foundry`, `rustgate-inference`,
`rustgate-lattice` each ship a `-mock` feature for local development
plus (where applicable) a `-real` feature requiring the upstream SDK.
Pick the mock variant in CI; the real variant in production:

| Crate | Features |
|---|---|
| `rustgate-dds` | `default`, `dds-mock`, `dds-real` (`rustdds` + `ros2-client`) |
| `rustgate-foundry` | `default`, `foundry-mock`, `foundry-real` |
| `rustgate-inference` | `default`, `inference-mock` |
| `rustgate-lattice` | `default`, `lattice-mock`, `lattice-real` |

### `rustgate-test-utils`

| Feature | Pulls in |
|---|---|
| `nats` | `tempfile`, `tokio`, `async-nats` (for `TestNatsServer`) |

---

## Special-build prerequisites

These features change the build toolchain. Plan CI accordingly.

| Feature | Why | Required tools | Linker / sysroot |
|---|---|---|---|
| `fips` | aws-lc-rs is partly built from `aws-lc` (C + Go) | Go ≥ 1.21, cmake, gcc | `musl` for static-FIPS images; `glibc` ≥ 2.31 for dynamic. |
| `post-quantum` | aws-lc-rs's Kyber backend reuses the aws-lc build | Go ≥ 1.21, cmake, gcc | Same as `fips`. |
| `proto` | `prost-build` invokes `protoc` for proto codegen | protoc ≥ 3.20 | Bundled into the Docker build image. |
| `otel` | Pulls `opentelemetry-proto` via prost | protoc ≥ 3.20 | Same as `proto`. |
| `jemalloc` | `tikv-jemallocator` is Linux-only (x86_64, aarch64) | None beyond `cargo` | Skipped on macOS / Windows. |

The default `Dockerfile` (UBI Iron Bank base) installs all four toolchains so the canonical operator build doesn't need extra steps. Local builds can omit them by dropping the corresponding features.

---

## Feature combinations and conflicts

A handful of combinations are technically valid but operationally
unwise. The compiler doesn't refuse them — these are advisory:

| Combination | Why it's surprising |
|---|---|
| `fips` + `post-quantum` | Both supported; PQ Kyber is FIPS-pending. Use both together for the CNSA-2 bundle. |
| `default` (none) + every observability flag | Builds the smallest possible binary with full instrumentation hooks; useful for benchmarks where you want the metrics path but no transports. |
| `federation` without `proto` | Federation V2 needs `proto`. Cargo errors out at link time; pair them. |
| `est` without `enrollment` | Cargo resolves this automatically (`est` declares `enrollment`), but it's a useful mental model that `est` is "enrollment with EST RFC 7030 on top". |
| `mesh-routing` without `federation-ha` | Allowed. Mesh routing works in non-HA federation; HA only adds NATS-backed shared state. |
| `peer-discovery-consul` + air-gap mode | Allowed at compile time; runtime rejects with `air_gap.violation` audit event. |
| `*-real` integration features in CI | Almost always wrong — these need external SDKs or production tokens. Use `*-mock`. |

---

## Recommended starter sets

For a fresh deployment, pick from these:

```bash
# Minimal demo (single-node, no federation)
cargo build --release --features metrics,websocket,mqtt

# Tactical edge node (resource-constrained, no federation)
cargo build --release --features metrics,websocket,mqtt,proto,full-detail

# Federated production hub
cargo build --release --features nats,enrollment,est,proto,full-detail,metrics,federation,federation-ha,websocket,mqtt,otel,http,management-api

# CNSA 2.0 compliant (FIPS + PQ-ready)
cargo build --release --features fips,enrollment,est,proto,metrics,federation,websocket,otel,jemalloc

# Post-quantum experimental
cargo build --release --features post-quantum,metrics,federation,websocket
```

The Helm chart's `values.yaml` exposes the canonical operator build
via `image.tag` selection. Custom feature combinations require
rebuilding the image; see `docs/deployment.md` for the multi-stage
Dockerfile that consumes `--build-arg FEATURES=…`.

---

## Keeping this catalogue in sync

When a new feature is added to any crate, add a row here in the same
PR. Regenerate the master list from source:

```bash
python3 - <<'PY'
import re
from pathlib import Path
seen = set()
for cargo in sorted(Path("crates").glob("*/Cargo.toml")):
    text = cargo.read_text()
    m = re.search(r'^\[features\]\s*$', text, re.MULTILINE)
    if not m:
        continue
    rest = text[m.end():]
    end_m = re.search(r'^\[', rest, re.MULTILINE)
    body = rest[:end_m.start()] if end_m else rest
    for fm in re.finditer(r'^([a-z][a-z0-9_-]*)\s*=\s*\[', body, re.MULTILINE):
        seen.add(fm.group(1))
print(f"{len(seen)} unique features")
for f in sorted(seen):
    print(f"  {f}")
PY
```

— diff against the row count above (53 unique feature names).
