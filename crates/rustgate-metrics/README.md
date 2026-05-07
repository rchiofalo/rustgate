# rustgate-metrics

Shared Prometheus scaffolding for the rustgate workspace.

## Role in the workspace

Every crate that exposes Prometheus metrics follows the same
`OnceLock` + `init()` + accessor pattern documented in
`.claude/rules/shared-infrastructure.md`. The pattern depends on a
small set of fallback constructors (`fallback_counter`,
`fallback_gauge`, `fallback_counter_vec`, `fallback_gauge_vec`,
`fallback_histogram`, `fallback_histogram_vec`) that build an
unregistered metric for the `OnceLock::get_or_init` fallback path.
Pre-this-crate the constructors were copied independently into
`rustgate-server`, `rustgate-federation`, and `rustgate-http`, then
partially consolidated under `rustgate_core::metrics_util` by #794.
This crate is the dedicated home that #894 carved out, leaving
`rustgate-core` free of the `prometheus` dep.

The metric instances themselves stay in their domain crate —
`rustgate_federation::metrics::peer_latency` is still federation-domain
code. Only the cross-cutting scaffolding moved.

## Public API surface

- `fallback_counter`, `fallback_gauge`, `fallback_counter_vec`,
  `fallback_gauge_vec`, `fallback_histogram`, `fallback_histogram_vec`
  — six unregistered-metric constructors keyed off Prometheus's
  `with_opts` builder. Each one is the body of an
  `OnceLock::get_or_init(...)` closure on the accessor side; if
  `init()` has not been called the accessor still returns a usable
  `&'static` reference so increments are absorbed without effect.
- `standard_duration_buckets()` — `[1ms, 5ms, 10ms, 25ms, 50ms, 100ms,
  250ms, 500ms, 1s, 2.5s, 5s, 10s]`. Matches the Prometheus
  client-library defaults plus the 25ms/250ms/2.5s mid-points that
  tactical dashboards rely on for SLO percentiles.
- `standard_byte_size_buckets()` — `[64B, 256B, 1KiB, 4KiB, 16KiB,
  64KiB, 256KiB, 1MiB, 4MiB, 16MiB]`. Power-of-four spacing covers the
  full payload-size range tactical traffic exhibits in practice; the
  16 MiB ceiling matches the workspace `MAX_FRAME_SIZE`.
- `MetricsRegistry` — thin orchestration helper that aggregates each
  domain crate's `init()` callback into one ordered list. Insertion
  order is preserved and `init_all` short-circuits on the first error,
  matching the historical hardcoded `init_a()?; init_b()?;` sequence.

## Usage

```rust,ignore
use std::sync::OnceLock;
use prometheus::IntCounter;
use rustgate_metrics::fallback_counter;

static MY_COUNTER: OnceLock<IntCounter> = OnceLock::new();

pub fn my_counter() -> &'static IntCounter {
    MY_COUNTER.get_or_init(|| fallback_counter("my_metric_total", "fallback"))
}

pub fn init() -> prometheus::Result<()> {
    let counter = IntCounter::with_opts(prometheus::Opts::new(
        "my_metric_total",
        "Documented help string",
    ))?;
    prometheus::default_registry().register(Box::new(counter.clone()))?;
    let _ = MY_COUNTER.set(counter);
    Ok(())
}
```

## Wire format

The `/metrics` text-exposition output is byte-identical before and
after the extraction. Every metric name, help string, label set, and
bucket boundary is preserved; the `init()` ordering inside each
consumer crate is unchanged. This is a pure Rust-side reorganisation.

## Feature flags

This crate has no feature flags. It is the metrics scaffolding crate;
consumers add it as a regular optional dep behind their own `metrics`
feature.

## Where to look first

- `crates/rustgate-metrics/src/lib.rs` — the six `fallback_*` helpers
  and the two standard-bucket helpers
- `crates/rustgate-metrics/src/registry.rs` — the `MetricsRegistry`
  aggregator and its insertion-order / short-circuit semantics
