# rustgate-resilience

Shared circuit breakers, backoff, rate limiters, and the global backpressure
gate.

## Role in the workspace

`rustgate-resilience` consolidates the resilience primitives that previously
lived (and drifted) inside individual transport / publisher crates. Every
primitive here is transport-agnostic — no `reqwest`, `tonic`, or `rustls`
leaks in — so it can be safely consumed by every egress in the workspace.
Depends only on [rustgate-core](../rustgate-core/README.md) (for audit
emission and shared callback shapes). Consumed by
[rustgate-transport](../rustgate-transport/README.md),
[rustgate-http](../rustgate-http/README.md),
[rustgate-federation](../rustgate-federation/README.md),
[rustgate-mqtt](../rustgate-mqtt/README.md),
[rustgate-websocket](../rustgate-websocket/README.md),
[rustgate-nats](../rustgate-nats/README.md), and
[rustgate-enrollment](../rustgate-enrollment/README.md).

## Public API surface

- `circuit::CircuitBreaker` — three-state breaker (Closed → Open →
  HalfOpen) with probe limiting and a configurable success threshold;
  atomic hot path, lock-free reads
- `backpressure::{BackpressureGate, BackpressurePermit, OnBytesChanged,
  OnDeferred, DEFAULT_MAX_QUEUED_BYTES}` — global byte-count admission gate
  with high/low water marks; RAII permit decrements on drop
- `retry::{backoff_with_jitter, is_retryable_status}` — exponential backoff
  with 0–25% jitter for request-level retries against multiple concurrent
  targets
- `reconnect::{backoff_delay, should_stop_reconnecting}` — deterministic
  exponential backoff (no jitter) for long-lived client reconnection loops
- `token_bucket::TokenBucket` — per-target rate limiter with lazy refill;
  fail-open on mutex poisoning
- `sliding_window::SlidingWindowLimiter` — generic per-key sliding-window
  limiter with configurable audit category; used by every plaintext
  listener (MQTT, WebSocket, UDP) keyed on IP, and by enrollment keyed on
  IP for request admission
- `conn_rate_limiter::ConnRateLimiter` — DEPRECATED thin shim around
  `SlidingWindowLimiter` retained for one PR cycle while callers migrate
- `SlidingWindowLimiter` re-export at the crate root

## Feature flags

| Name | Purpose | Default-on? |
|---|---|---|
| `metrics` | Exposes internal-state accessors (e.g. `CircuitBreaker::state_value()` as `u8`) so downstream Prometheus gauges can sample the breaker without taking a `metrics` dep on this crate | No |

## Topology / deployment notes

The breaker callbacks (`OnStateChange`) are
`Arc<dyn Fn(u8, u8) + Send + Sync>` so they slot into the workspace-wide
callback discipline. Every limiter rejection emits
`rustgate_core::audit::security_rate_limited()` with a category label so
SIEM dashboards can distinguish enforcement cadences (`connection`,
`request`) without losing the unified counter.

## Where to look first

- `crates/rustgate-resilience/src/circuit.rs` — the three-state breaker that
  HTTP egress and federation peer handles share
- `crates/rustgate-resilience/src/sliding_window.rs` — the canonical
  per-IP / per-key admission gate used across plaintext listeners
