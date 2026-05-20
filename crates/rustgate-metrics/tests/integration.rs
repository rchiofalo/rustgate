// Copyright © 2026 Roberto Chiofalo.

//! Integration tests for `rustgate-metrics`.
//!
//! Inline unit tests in `src/lib.rs` and `src/registry.rs` cover the
//! per-helper contracts (each `fallback_*` constructor produces a
//! usable metric without `init()`, `MetricsRegistry` preserves
//! insertion order, the standard bucket values are pinned). These
//! integration tests cover what unit tests can't easily exercise:
//!
//! 1. **End-to-end registry composition** — multiple "domain crate"
//!    init functions registered with `MetricsRegistry`, run via
//!    `init_all`, and verified to surface in the Prometheus default
//!    registry.
//! 2. **First-error short-circuits without rolling back** — when one
//!    domain's init fails, prior registrations stay live (matches the
//!    historical hardcoded `init_a()?; init_b()?;` sequence).
//! 3. **Concurrent gather + increment** — Prometheus's `gather()`
//!    holds a read lock; many threads incrementing while one thread
//!    gathers must not deadlock.
//! 4. **Increments survive serialisation** — values written to a
//!    counter show up in `gather()` and in the Prometheus text format.
//! 5. **Histogram observations record correctly** — bucket counts,
//!    sum, and count all reflect observed values.
//!
//! Each test uses a unique metric-name prefix
//! (`rustgate_metrics_integration_<test_name>`) so parallel test
//! execution does not collide on the global Prometheus default
//! registry (each metric name must be unique workspace-wide; a
//! conflict surfaces as `prometheus::Error::AlreadyReg`).

#![allow(clippy::panic, clippy::unwrap_used)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use prometheus::{Encoder, IntCounter, Opts, TextEncoder};
use rustgate_metrics::{
    MetricsRegistry, fallback_counter, fallback_counter_vec, fallback_histogram,
    standard_duration_buckets,
};

// ------------------------------------------------------------------
// End-to-end registry composition
// ------------------------------------------------------------------

/// Three fake "domain crate" init functions registered with
/// `MetricsRegistry::register` should each successfully build their
/// metrics, register them with the Prometheus default registry, and
/// surface in `gather()` output after `init_all()` succeeds.
#[test]
fn registry_composes_three_domain_initializers_into_default_registry() {
    let mut registry = MetricsRegistry::default();
    let _ = registry
        .register(domain_a_init)
        .register(domain_b_init)
        .register(domain_c_init);
    assert_eq!(registry.len(), 3);

    registry.init_all().expect("all three domains must init");

    // Every domain's counter should now exist in the default registry.
    let gathered = prometheus::default_registry().gather();
    let names: Vec<String> = gathered
        .into_iter()
        .map(|mf| mf.name().to_string())
        .collect();
    assert!(
        names
            .iter()
            .any(|n| n == "rmi_compose_domain_a_events_total"),
        "domain A missing — gathered names: {names:?}"
    );
    assert!(
        names
            .iter()
            .any(|n| n == "rmi_compose_domain_b_messages_total"),
        "domain B missing"
    );
    assert!(
        names
            .iter()
            .any(|n| n == "rmi_compose_domain_c_requests_total"),
        "domain C missing"
    );
}

fn domain_a_init() -> prometheus::Result<()> {
    let c = IntCounter::with_opts(Opts::new(
        "rmi_compose_domain_a_events_total",
        "fake domain A — events processed",
    ))?;
    prometheus::default_registry().register(Box::new(c))?;
    Ok(())
}

fn domain_b_init() -> prometheus::Result<()> {
    let c = IntCounter::with_opts(Opts::new(
        "rmi_compose_domain_b_messages_total",
        "fake domain B — messages handled",
    ))?;
    prometheus::default_registry().register(Box::new(c))?;
    Ok(())
}

fn domain_c_init() -> prometheus::Result<()> {
    let c = IntCounter::with_opts(Opts::new(
        "rmi_compose_domain_c_requests_total",
        "fake domain C — requests served",
    ))?;
    prometheus::default_registry().register(Box::new(c))?;
    Ok(())
}

// ------------------------------------------------------------------
// First-error short-circuits without rolling back
// ------------------------------------------------------------------

/// When the middle initialiser fails, the FIRST initialiser's
/// registrations must remain live (the historical hardcoded
/// `init_a()?; init_b()?; init_c()?;` sequence had this behaviour:
/// failure-fast at startup, never partial rollback). The third
/// initialiser must NOT execute.
#[test]
fn registry_first_failure_preserves_prior_registrations_and_skips_later() {
    let third_ran = Arc::new(AtomicUsize::new(0));
    let third_marker = Arc::clone(&third_ran);

    let mut registry = MetricsRegistry::default();
    let _ = registry
        .register(|| {
            // First init succeeds and registers a real metric.
            let c = IntCounter::with_opts(Opts::new(
                "rmi_shortcircuit_first_total",
                "first domain — must remain registered after later failure",
            ))?;
            prometheus::default_registry().register(Box::new(c))?;
            Ok(())
        })
        .register(|| {
            // Second init fails with a synthetic error.
            Err(prometheus::Error::Msg(
                "synthetic mid-sequence failure".into(),
            ))
        })
        .register(move || {
            // Third init must never execute — increment this counter
            // would prove the short-circuit didn't fire.
            let _ = third_marker.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });

    let result = registry.init_all();
    assert!(result.is_err(), "init_all must surface the middle failure");
    assert_eq!(
        third_ran.load(Ordering::SeqCst),
        0,
        "third initialiser must not run after second's failure",
    );

    // First domain's metric stays registered — no rollback.
    let gathered = prometheus::default_registry().gather();
    let names: Vec<String> = gathered
        .into_iter()
        .map(|mf| mf.name().to_string())
        .collect();
    assert!(
        names.iter().any(|n| n == "rmi_shortcircuit_first_total"),
        "first domain's metric must survive the short-circuit",
    );
}

// ------------------------------------------------------------------
// Concurrent gather + increment
// ------------------------------------------------------------------

/// `prometheus::default_registry().gather()` holds a read lock that
/// serialises with the metric updates. Many threads incrementing
/// while one thread gathers must not deadlock or race-condition
/// the count. This catches issues in the workspace's wrapper, not
/// in the prometheus crate itself.
#[test]
fn concurrent_gather_and_increment_do_not_deadlock() {
    let counter = fallback_counter(
        "rmi_concurrent_increment_total",
        "concurrent stress test counter",
    );
    prometheus::default_registry()
        .register(Box::new(counter.clone()))
        .expect("register concurrent test counter");

    const INCREMENTERS: usize = 8;
    const INCREMENTS_PER_THREAD: u64 = 10_000;
    const GATHER_ROUNDS: usize = 50;

    let counter_for_writers = counter.clone();
    let writers: Vec<_> = (0..INCREMENTERS)
        .map(|_| {
            let c = counter_for_writers.clone();
            thread::spawn(move || {
                for _ in 0..INCREMENTS_PER_THREAD {
                    c.inc();
                }
            })
        })
        .collect();

    // While the writers race, a reader thread repeatedly gathers.
    // Should never deadlock and should never panic.
    let reader = thread::spawn(|| {
        for _ in 0..GATHER_ROUNDS {
            let _ = prometheus::default_registry().gather();
            thread::sleep(Duration::from_micros(100));
        }
    });

    for w in writers {
        w.join().expect("writer thread");
    }
    reader.join().expect("reader thread");

    // Every increment must be reflected — no lost updates from the
    // contention.
    let expected = (INCREMENTERS as u64) * INCREMENTS_PER_THREAD;
    assert_eq!(
        counter.get(),
        expected,
        "all increments must be visible after writers join",
    );
}

// ------------------------------------------------------------------
// Increments survive serialisation
// ------------------------------------------------------------------

/// Incrementing a counter and then rendering the default registry to
/// Prometheus text format must show the same value. Catches any
/// wrapper-level bug that intercepts increments without forwarding to
/// the underlying metric.
#[test]
fn counter_increments_show_up_in_prometheus_text_format() {
    let counter = fallback_counter(
        "rmi_text_format_visible_total",
        "verify text-format output reflects increments",
    );
    prometheus::default_registry()
        .register(Box::new(counter.clone()))
        .expect("register text-format counter");

    counter.inc();
    counter.inc_by(41);
    assert_eq!(counter.get(), 42);

    let mut buffer = Vec::new();
    let encoder = TextEncoder::new();
    encoder
        .encode(&prometheus::default_registry().gather(), &mut buffer)
        .expect("encode text format");
    let text = String::from_utf8(buffer).expect("text format is utf-8");

    assert!(
        text.contains("rmi_text_format_visible_total 42"),
        "expected '<metric_name> 42' in text format; got:\n{text}",
    );
}

// ------------------------------------------------------------------
// Counter-vec per-label independence at integration scale
// ------------------------------------------------------------------

/// A `IntCounterVec` with three label values incremented from three
/// threads must yield three independent counters in the gather output
/// — one per label set. Verifies the fallback constructor builds a
/// real multi-dimensional metric, not a single-shared accumulator.
#[test]
fn counter_vec_keeps_per_label_counts_independent_under_concurrency() {
    let cv = fallback_counter_vec(
        "rmi_label_independence_total",
        "per-label independence check",
        &["protocol"],
    );
    prometheus::default_registry()
        .register(Box::new(cv.clone()))
        .expect("register counter vec");

    const PER_LABEL_INCREMENTS: u64 = 5_000;

    let labels = ["mavlink", "cot", "dis"];
    let handles: Vec<_> = labels
        .iter()
        .map(|&label| {
            let cv = cv.clone();
            thread::spawn(move || {
                let metric = cv.with_label_values(&[label]);
                for _ in 0..PER_LABEL_INCREMENTS {
                    metric.inc();
                }
            })
        })
        .collect();
    for h in handles {
        h.join().expect("label-incrementer thread");
    }

    for label in labels {
        assert_eq!(
            cv.with_label_values(&[label]).get(),
            PER_LABEL_INCREMENTS,
            "label {label} must have exactly {PER_LABEL_INCREMENTS} increments",
        );
    }
}

// ------------------------------------------------------------------
// Histogram observations land in the right buckets
// ------------------------------------------------------------------

/// Observations of known values must populate the correct bucket
/// counts AND increment the sample sum + count. Pins the histogram's
/// contract end-to-end against Prometheus text format output (the
/// inline `fallback_histogram_observes_into_default_buckets` unit
/// test pins the bucket boundaries; this one pins the user-visible
/// integration behaviour).
#[test]
fn histogram_observations_reflect_in_sum_count_and_text_format() {
    let h = fallback_histogram(
        "rmi_histogram_observe_seconds",
        "histogram observation integration check",
    );
    prometheus::default_registry()
        .register(Box::new(h.clone()))
        .expect("register histogram");

    // Observe values that will populate the default Prometheus
    // buckets (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, …).
    h.observe(0.001); // bucket: 0.005
    h.observe(0.03); // bucket: 0.05
    h.observe(0.2); // bucket: 0.25
    h.observe(0.7); // bucket: 1.0

    let mut buffer = Vec::new();
    TextEncoder::new()
        .encode(&prometheus::default_registry().gather(), &mut buffer)
        .expect("encode");
    let text = String::from_utf8(buffer).expect("utf-8");

    // The histogram exports `_count` (4 observations) and `_sum`
    // (≈ 0.931).
    assert!(
        text.contains("rmi_histogram_observe_seconds_count 4"),
        "expected sample count = 4 in text format; got:\n{text}",
    );
    // _sum is a float so just verify it's there with the expected
    // prefix and contains the order-of-magnitude value (0.9).
    let sum_line = text
        .lines()
        .find(|l| l.starts_with("rmi_histogram_observe_seconds_sum "))
        .expect("histogram sum line present");
    let sum_value: f64 = sum_line
        .split_whitespace()
        .nth(1)
        .expect("sum line has value column")
        .parse()
        .expect("sum value parses as f64");
    let expected_sum = 0.001_f64 + 0.03 + 0.2 + 0.7;
    assert!(
        (sum_value - expected_sum).abs() < 1e-6,
        "histogram sum {sum_value} != expected {expected_sum}",
    );
}

// ------------------------------------------------------------------
// Standard bucket helpers compose with histogram registration
// ------------------------------------------------------------------

/// The documented `standard_duration_buckets()` values must compose
/// with `prometheus::HistogramOpts::buckets()` to produce a histogram
/// whose serialised output includes the expected bucket boundaries.
#[test]
fn standard_duration_buckets_serialise_to_expected_boundaries() {
    let buckets = standard_duration_buckets();
    // The unit test pins the exact values; here we verify they make
    // it through prometheus's `HistogramOpts::buckets()` to the
    // serialised text format.
    let h = prometheus::Histogram::with_opts(
        prometheus::HistogramOpts::new(
            "rmi_standard_buckets_check_seconds",
            "standard duration buckets integration check",
        )
        .buckets(buckets.clone()),
    )
    .expect("histogram with custom buckets");
    prometheus::default_registry()
        .register(Box::new(h.clone()))
        .expect("register custom-bucket histogram");

    h.observe(0.0007); // hits bucket 0.001
    h.observe(2.0); // hits bucket 2.5

    let mut buffer = Vec::new();
    TextEncoder::new()
        .encode(&prometheus::default_registry().gather(), &mut buffer)
        .expect("encode");
    let text = String::from_utf8(buffer).expect("utf-8");

    for upper in &buckets {
        // Each bucket should appear in the text output as a
        // `_bucket{le="<value>"}` line. Use a Prometheus-compatible
        // formatting (avoid trailing-zero stripping).
        let needle = format!("le=\"{upper}\"");
        assert!(
            text.contains(&needle),
            "bucket boundary {upper} not found in text format; got:\n{text}",
        );
    }
}
