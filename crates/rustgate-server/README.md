# rustgate-server

Binary crate that orchestrates every other rustgate workspace component
into the `rustgate` executable.

## Role in the workspace

`rustgate-server` is the only binary crate in the workspace. It owns the
CLI parser, the figment-backed configuration merge (defaults < TOML file <
env vars < CLI flags), the subsystem startup / graceful-shutdown sequence,
the Prometheus metrics endpoint, the management API, the audit-log writer,
the OpenTelemetry tracing setup, and the SIGHUP reloaders for ACL / authz /
federation / certificates. It directly depends on
[rustgate-core](../rustgate-core/README.md),
[rustgate-cot](../rustgate-cot/README.md),
[rustgate-authz](../rustgate-authz/README.md), and
[rustgate-transport](../rustgate-transport/README.md), and pulls in every
other crate in the workspace conditionally behind cargo features.

## Public API surface

The crate ships a single binary entrypoint — `rustgate` — and does not
export a library API. Internal modules visible at the binary level:

- `main` — async runtime bring-up, signal handling, and the
  graceful-shutdown sequence
- `cli` — clap-derived `Cli` and `Command` (the subcommands are
  `print-config`, `validate-config`, `verify-audit`, `decrypt-archive`)
- `setup` — subsystem factories (TLS listener, federation manager,
  enrollment server, NATS adapter, HTTP egress publisher, MQTT/WebSocket
  listeners) wired into the router
- `session` — per-client session driver bridging the TLS listener to the
  router fan-out
- `metrics`, `mgmt_api`, `acl_api` — Prometheus exposition and management
  endpoints (under `--features metrics`)
- `acl_reloader`, `authz_reloader`, `federation_reloader` — SIGHUP and
  interval-based reloaders for hot configuration
- `archive`, `archive_rotation`, `audit` — CoT archive and audit-log
  writers, optionally streaming through the `rustgate-core::encrypted`
  AEAD sink
- `otel`, `otel_metrics` — OTLP exporter setup (under `--features otel`)
- `diagnostics` — startup self-checks and feature-gate validation

## Feature flags

| Name | Purpose | Default-on? |
|---|---|---|
| `nats` | Pulls in [rustgate-nats](../rustgate-nats/README.md) | No |
| `enrollment` | Pulls in [rustgate-enrollment](../rustgate-enrollment/README.md) | No |
| `est` | EST RFC 7030 endpoints (implies `enrollment`) | No |
| `proto` | Pulls in [rustgate-proto](../rustgate-proto/README.md) and enables the transport `proto` feature | No |
| `full-detail` | Extended CoT field set in the NATS bridge (implies `nats`) | No |
| `metrics` | Prometheus `/metrics` endpoint, health endpoints, and management API | No |
| `federation` | Pulls in [rustgate-federation](../rustgate-federation/README.md) with the V2 + REST API features | No |
| `federation-ha` | NATS-KV claim manager for multi-pod federation (implies `federation`) | No |
| `peer-discovery-dns-sd` / `peer-discovery-consul` / `peer-discovery-etcd` / `peer-discovery` | Selects which peer-discovery backends ship with the binary | No |
| `websocket` | Pulls in [rustgate-websocket](../rustgate-websocket/README.md) | No |
| `mqtt` | Pulls in [rustgate-mqtt](../rustgate-mqtt/README.md) | No |
| `http` | Pulls in [rustgate-http](../rustgate-http/README.md) for webhook egress | No |
| `otel` | OpenTelemetry tracing + metrics export over OTLP | No |
| `fips` | Forwards `fips` to transport / federation / enrollment / http | No |
| `post-quantum` | Forwards `post-quantum` (X25519MLKEM768) to transport / federation / http | No |
| `cedar` | Cedar policy backend (`--authz-policy-format cedar`) | No |
| `ocsp` / `spiffe` | Forwards to transport for OCSP and SPIFFE workload identity | No |
| `jemalloc` | Switches the global allocator to jemalloc (musl / Alpine builds) | No |

## Topology / deployment notes

The binary listens on a configurable mTLS bind, optionally adds plaintext
TCP / UDP inputs, WebSocket and MQTT listeners, federation V1 and V2
listeners, an enrollment HTTPS endpoint, and an unauthenticated metrics +
management HTTP endpoint. SIGTERM triggers readiness 503 and a bounded
graceful-shutdown drain (default 10s). See the workspace README for the
full CLI / TOML / env-var matrix.

## Where to look first

- `crates/rustgate-server/src/main.rs` — runtime bring-up and shutdown
  sequence
- `crates/rustgate-server/src/setup.rs` — subsystem factories that wire
  every feature-gated dependency into the router
