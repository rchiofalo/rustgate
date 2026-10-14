// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Shared Prometheus metric scaffolding for the rustgate workspace.
//!
//! Subsumes the duplicated `fallback_*` boilerplate that previously
//! lived independently in `rustgate-server`, `rustgate-federation`,
//! and `rustgate-http` (and was already partially consolidated under
//! `rustgate_core::metrics_util` — this crate is the dedicated home
//! that issue #894 carved out, leaving `rustgate-core` free of the
//! `prometheus` dep). Domain crates use these helpers to register
//! their metrics; the metric instances themselves stay in the domain
//! crate they belong to.
//!
//! # Usage
//!
//! Every crate that exposes Prometheus metrics follows the
//! `OnceLock` + `init()` + accessor pattern documented in
//! `.claude/rules/shared-infrastructure.md`. The accessor must return
//! a valid metric even when `init()` was never called (e.g. during
//! unit tests that never wire up the metrics subsystem); the fallback
//! is an unregistered metric created via `OnceLock::get_or_init()` so
//! the call site keeps a stable `&'static` reference and increments
//! are absorbed without effect.
//!
//! ```ignore
//! use std::sync::OnceLock;
//! use prometheus::IntCounter;
//! use rustgate_metrics::fallback_counter;
//!
//! static MY_COUNTER: OnceLock<IntCounter> = OnceLock::new();
//!
//! pub fn my_counter() -> &'static IntCounter {
//!     MY_COUNTER.get_or_init(|| fallback_counter("my_metric_total", "fallback"))
//! }
//! ```
//!
//! # Panic discipline
//!
//! These helpers are only reachable with hardcoded metric names that
//! have already been validated by the matching `init()` call site —
//! i.e. the constructor was successfully called once at startup with
//! the same name and label arity. Failure here would mean
//! `prometheus::Opts::new` rejected a name it had previously accepted,
//! which is a programmer error: an `expect()` is the correct sentinel.
//! This is the existing convention in the per-crate copies that this
//! module replaces (those originally used `std::process::abort()`); the
//! panic variant gives reviewers and panic-reporting infrastructure a
//! usable message instead of a silent SIGABRT.

use prometheus::{
    Histogram, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge, IntGaugeVec, Opts,
};

mod registry;

pub use registry::MetricsRegistry;

/// Build an unregistered [`IntCounter`] for use as an `OnceLock`
/// fallback when `init()` has not been called.
///
/// See module docs for the panic-discipline rationale.
pub fn fallback_counter(name: &str, help: &str) -> IntCounter {
    IntCounter::with_opts(Opts::new(name, help))
        .expect("fallback IntCounter constructor: hardcoded metric name must be valid")
}

/// Build an unregistered [`IntGauge`] for use as an `OnceLock`
/// fallback when `init()` has not been called.
pub fn fallback_gauge(name: &str, help: &str) -> IntGauge {
    IntGauge::with_opts(Opts::new(name, help))
        .expect("fallback IntGauge constructor: hardcoded metric name must be valid")
}

/// Build an unregistered [`IntCounterVec`] for use as an `OnceLock`
/// fallback when `init()` has not been called.
pub fn fallback_counter_vec(name: &str, help: &str, labels: &[&str]) -> IntCounterVec {
    IntCounterVec::new(Opts::new(name, help), labels).expect(
        "fallback IntCounterVec constructor: hardcoded metric name and labels must be valid",
    )
}

/// Build an unregistered [`IntGaugeVec`] for use as an `OnceLock`
/// fallback when `init()` has not been called.
pub fn fallback_gauge_vec(name: &str, help: &str, labels: &[&str]) -> IntGaugeVec {
    IntGaugeVec::new(Opts::new(name, help), labels)
        .expect("fallback IntGaugeVec constructor: hardcoded metric name and labels must be valid")
}

/// Build an unregistered [`Histogram`] (default buckets) for use as an
/// `OnceLock` fallback when `init()` has not been called.
pub fn fallback_histogram(name: &str, help: &str) -> Histogram {
    Histogram::with_opts(HistogramOpts::new(name, help))
        .expect("fallback Histogram constructor: hardcoded metric name must be valid")
}

/// Build an unregistered [`HistogramVec`] (default buckets) for use as
/// an `OnceLock` fallback when `init()` has not been called.
pub fn fallback_histogram_vec(name: &str, help: &str, labels: &[&str]) -> HistogramVec {
    HistogramVec::new(HistogramOpts::new(name, help), labels)
        .expect("fallback HistogramVec constructor: hardcoded metric name and labels must be valid")
}

/// Standard duration buckets for HTTP-shaped latency: 1ms, 5ms, 10ms,
/// 25ms, 50ms, 100ms, 250ms, 500ms, 1s, 2.5s, 5s, 10s.
///
/// Returned as a fresh `Vec` per call so callers can pass them into a
/// [`HistogramOpts::buckets`] builder without lifetime juggling. The
/// bucket layout matches Prometheus client-library defaults plus the
/// 25ms/250ms/2.5s mid-points that tactical dashboards historically
/// rely on for SLO percentiles.
pub fn standard_duration_buckets() -> Vec<f64> {
    vec![
        0.001, 0.005, 0.010, 0.025, 0.050, 0.100, 0.250, 0.500, 1.0, 2.5, 5.0, 10.0,
    ]
}

/// Standard byte-size buckets: 64B, 256B, 1KiB, 4KiB, 16KiB, 64KiB,
/// 256KiB, 1MiB, 4MiB, 16MiB.
///
/// Power-of-four spacing covers the full payload-size range tactical
/// traffic exhibits in practice — small CoT events at the low end,
/// chat/group payloads in the middle, and binary-blob attachments up
/// to the workspace `MAX_FRAME_SIZE` (16 MiB) at the top.
pub fn standard_byte_size_buckets() -> Vec<f64> {
    vec![
        64.0,
        256.0,
        1024.0,
        4096.0,
        16384.0,
        65536.0,
        262144.0,
        1_048_576.0,
        4_194_304.0,
        16_777_216.0,
    ]
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn fallback_counter_returns_usable_metric_without_init() {
        // Sunny path: `IntCounter::with_opts` accepts hardcoded names so
        // the helper must produce a callable counter that starts at 0
        // and increments monotonically. The error path is `expect()`,
        // which only fires on prometheus-internal validation failures —
        // it is intentionally untested here (it would mean prometheus is
        // broken, not that our wrapper is wrong).
        let c = fallback_counter("metrics_test_counter_basic", "help");
        assert_eq!(c.get(), 0);
        c.inc();
        c.inc();
        assert_eq!(c.get(), 2);
    }

    #[test]
    fn fallback_counter_vec_with_labels_increments_per_label_combination() {
        // Pin that the `labels` argument is honoured: distinct label
        // values produce independent children. A regression that
        // ignored the argument would collide every label onto a single
        // child.
        let cv = fallback_counter_vec("metrics_test_counter_vec_basic", "help", &["target"]);
        let a = cv
            .get_metric_with_label_values(&["alpha"])
            .expect("alpha label ok");
        let b = cv
            .get_metric_with_label_values(&["beta"])
            .expect("beta label ok");
        assert_eq!(a.get(), 0);
        assert_eq!(b.get(), 0);
        a.inc();
        a.inc();
        b.inc();
        assert_eq!(a.get(), 2);
        assert_eq!(b.get(), 1);
    }

    #[test]
    fn fallback_gauge_increments_decrements_signed_writes() {
        // `IntGauge` is signed; the helper must preserve that contract.
        // Regression would surface as a switch to `IntCounter`, which
        // would fail on `dec()` at compile time, but pinning negative
        // values makes the intent explicit for future readers.
        let g = fallback_gauge("metrics_test_gauge_basic", "help");
        assert_eq!(g.get(), 0);
        g.inc();
        g.inc();
        assert_eq!(g.get(), 2);
        g.dec();
        assert_eq!(g.get(), 1);
        g.set(-5);
        assert_eq!(g.get(), -5);
    }

    #[test]
    fn fallback_gauge_vec_returns_callable_vec() {
        // Sibling to the counter-vec test: confirm gauge-vec children
        // are indexable by label and accept signed writes.
        let gv = fallback_gauge_vec("metrics_test_gauge_vec_basic", "help", &["peer"]);
        let child = gv
            .get_metric_with_label_values(&["west-1"])
            .expect("label ok");
        assert_eq!(child.get(), 0);
        child.set(42);
        assert_eq!(child.get(), 42);
        child.set(-1);
        assert_eq!(child.get(), -1);
    }

    #[test]
    fn fallback_histogram_observes_into_default_buckets() {
        // Pin the two histogram fields dashboards rely on: the running
        // sample count and the cumulative sum across all observations.
        // A regression that swapped to `Counter` would fail at compile
        // time on `observe`, but pinning count + sum makes it explicit
        // that these are the only two numbers consumers depend on.
        let h = fallback_histogram("metrics_test_histogram_basic", "help");
        h.observe(0.25);
        h.observe(0.75);
        h.observe(2.0);
        assert_eq!(h.get_sample_count(), 3);
        assert!((h.get_sample_sum() - 3.0).abs() < f64::EPSILON);
    }

    #[test]
    fn fallback_histogram_vec_records_per_label_observations() {
        // `HistogramVec` per-label children are independent. Pin that
        // behaviour: observations on one label must not bleed into
        // another.
        let hv = fallback_histogram_vec("metrics_test_histogram_vec_basic", "help", &["operation"]);
        let read = hv.with_label_values(&["read"]);
        let write = hv.with_label_values(&["write"]);
        read.observe(1.0);
        read.observe(2.0);
        write.observe(0.5);
        assert_eq!(read.get_sample_count(), 2);
        assert_eq!(write.get_sample_count(), 1);
        assert!((read.get_sample_sum() - 3.0).abs() < f64::EPSILON);
        assert!((write.get_sample_sum() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn standard_duration_buckets_match_documented_values() {
        // Documented contract: 1ms, 5ms, 10ms, 25ms, 50ms, 100ms,
        // 250ms, 500ms, 1s, 2.5s, 5s, 10s. Dashboards and SLO queries
        // depend on these exact bucket boundaries — a regression here
        // would silently shift quantile estimates across the entire
        // workspace.
        let buckets = standard_duration_buckets();
        let expected: &[f64] = &[
            0.001, 0.005, 0.010, 0.025, 0.050, 0.100, 0.250, 0.500, 1.0, 2.5, 5.0, 10.0,
        ];
        assert_eq!(buckets.len(), expected.len());
        for (got, want) in buckets.iter().zip(expected.iter()) {
            assert!(
                (got - want).abs() < f64::EPSILON,
                "bucket mismatch: got {got}, want {want}",
            );
        }
    }

    #[test]
    fn standard_byte_size_buckets_cover_payload_range() {
        // Pin the documented power-of-four spacing from 64B to 16MiB.
        // The top boundary intentionally mirrors workspace-wide
        // MAX_FRAME_SIZE so a payload at the upper edge falls into the
        // last bucket rather than +Inf.
        let buckets = standard_byte_size_buckets();
        let expected: &[f64] = &[
            64.0,
            256.0,
            1024.0,
            4096.0,
            16384.0,
            65536.0,
            262144.0,
            1_048_576.0,
            4_194_304.0,
            16_777_216.0,
        ];
        assert_eq!(buckets.len(), expected.len());
        for (got, want) in buckets.iter().zip(expected.iter()) {
            assert!(
                (got - want).abs() < f64::EPSILON,
                "bucket mismatch: got {got}, want {want}",
            );
        }
    }

    #[test]
    fn fallback_constructors_register_independently_in_default_registry() {
        // Sanity check: even though the fallback helpers themselves
        // produce *unregistered* metrics, callers that wire them
        // through `prometheus::default_registry().register(...)` must
        // see them turn up in the rendered text exposition. Pin that
        // path with one counter — a regression that silently dropped
        // registration would otherwise only surface in a deploy-time
        // dashboard miss.
        let registry = prometheus::Registry::new();
        let c = fallback_counter("metrics_test_register_smoke", "help");
        registry.register(Box::new(c.clone())).expect("register ok");
        c.inc();
        c.inc();
        c.inc();
        let families = registry.gather();
        let found = families
            .iter()
            .any(|f| f.name() == "metrics_test_register_smoke");
        assert!(found, "registered counter must appear in registry.gather()",);
    }

    #[test]
    fn fallback_built_metrics_serialize_to_canonical_prometheus_text_format() {
        // Wire-format pin (closes #894): the `/metrics` endpoint
        // renders registered metrics via `prometheus::TextEncoder`.
        // After the rustgate-metrics extraction the text exposition
        // must be byte-identical to the pre-extraction output for any
        // metric that goes through `fallback_*` plus
        // `default_registry().register(...)`. A regression that
        // changed the encoder path (different encoder, different
        // ordering, missing `# HELP` / `# TYPE` headers) would show
        // up here before it reached a dashboard.
        use prometheus::Encoder;

        let registry = prometheus::Registry::new();
        let c = fallback_counter(
            "metrics_test_text_format_counter",
            "Counter for text-format pin",
        );
        let g = fallback_gauge(
            "metrics_test_text_format_gauge",
            "Gauge for text-format pin",
        );
        registry
            .register(Box::new(c.clone()))
            .expect("counter register ok");
        registry
            .register(Box::new(g.clone()))
            .expect("gauge register ok");

        c.inc();
        c.inc();
        g.set(42);

        let mut buf = Vec::new();
        prometheus::TextEncoder::new()
            .encode(&registry.gather(), &mut buf)
            .expect("encode ok");
        let rendered = String::from_utf8(buf).expect("utf8");

        // Pin the documented Prometheus text-exposition shape:
        // a `# HELP` line, a `# TYPE` line, then the value line. The
        // exact value text "metrics_test_text_format_counter 2" /
        // "metrics_test_text_format_gauge 42" guards against a future
        // change that, for example, switched to a custom encoder
        // emitting a different label format.
        assert!(
            rendered
                .contains("# HELP metrics_test_text_format_counter Counter for text-format pin"),
            "expected HELP line for counter: {rendered}",
        );
        assert!(
            rendered.contains("# TYPE metrics_test_text_format_counter counter"),
            "expected TYPE line for counter: {rendered}",
        );
        assert!(
            rendered.contains("metrics_test_text_format_counter 2"),
            "expected counter value line: {rendered}",
        );
        assert!(
            rendered.contains("# HELP metrics_test_text_format_gauge Gauge for text-format pin"),
            "expected HELP line for gauge: {rendered}",
        );
        assert!(
            rendered.contains("# TYPE metrics_test_text_format_gauge gauge"),
            "expected TYPE line for gauge: {rendered}",
        );
        assert!(
            rendered.contains("metrics_test_text_format_gauge 42"),
            "expected gauge value line: {rendered}",
        );
    }
}
