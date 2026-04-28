# rustgate-http

HTTP/webhook egress bridge for routable messages.

## Role in the workspace

`rustgate-http` forwards routed messages to configured HTTP endpoints
(webhooks, REST APIs, SIEM collectors) with per-target authentication, TLS
posture, filtering, retry, and circuit breaking. It depends on
[rustgate-core](../rustgate-core/README.md) and
[rustgate-resilience](../rustgate-resilience/README.md) (circuit breaker,
backoff with jitter, token bucket). Wired into
[rustgate-server](../rustgate-server/README.md) under `--features http`.

## Public API surface

- `HttpPublisher` — primary entry point; accepts `RoutableMessage`s through
  `publish()` and dispatches via a bounded internal channel to a worker
  task that fans out to all matching targets
- `HttpConfig` — top-level configuration loaded from a TOML file (per-target
  list, auth, TLS, filtering, retry, circuit breaker, DLQ)
- `TriggerDrainError` — signal type returned when the publisher's drain
  trigger cannot be wired (e.g., DLQ disk full)
- `HttpError` — typed error enum covering serialization, transport, auth,
  TLS, circuit-open, and DLQ failures
- `dlq_reader::*` — admin tooling for inspecting and replaying the
  encrypted dead-letter queue

## Feature flags

| Name | Purpose | Default-on? |
|---|---|---|
| `metrics` | Prometheus counters/histograms for publishes, errors, latency, circuit state, DLQ depth | No |
| `proto` | Protobuf payload serialization via [rustgate-proto](../rustgate-proto/README.md) | No |
| `otel` | OpenTelemetry trace context propagation (`traceparent` / `tracestate` headers on outbound requests) | No |
| `fips` | aws-lc-rs in FIPS mode for outbound TLS | No |
| `post-quantum` | X25519MLKEM768 hybrid key exchange for outbound TLS | No |

## Topology / deployment notes

The publisher is opinionated about security:

- **Authentication** — Bearer token, HTTP Basic, or HMAC-SHA256 request
  signing (with timestamp binding to defeat replay). All secrets are
  loaded via `rustgate_core::secrets::read_secret_file` (size cap, mode
  `0o077` permissions gate, `Zeroizing` return).
- **TLS** — per-target custom CA, optional mTLS client certificate, and
  optional SHA-256 SPKI pinning for defense against CA compromise.
- **SSRF protection** — private/loopback IPs are rejected at config-validation
  time AND at DNS-resolution time (rebinding defense).
- **Rate limiting** — per-target token-bucket limiter prevents upstream
  flooding from a runaway broadcast.
- **Dead-letter queue** — undeliverable messages are encrypted with
  ChaCha20-Poly1305 and persisted for forensic recovery.

## Where to look first

- `crates/rustgate-http/src/publisher.rs` — accept loop, fan-out, retry
  state machine, and circuit-breaker interactions
- `crates/rustgate-http/src/config.rs` — the TOML schema operators target
