// Copyright © 2026 Roberto Chiofalo.

//! Prometheus metrics for the HTTP egress subsystem.
//!
//! Follows the server's `OnceLock` + `init()` + accessor pattern.
//! All metrics are registered centrally via [`init`] at startup.
//! Accessor functions return a `&'static` reference, falling back to
//! an unregistered metric if `init()` was not called.

use std::sync::OnceLock;

use prometheus::{Histogram, HistogramOpts, IntCounterVec, IntGauge, IntGaugeVec, Opts};

// ── Static Cells ───────────────────────────────────────────────────

static PUBLISHES: OnceLock<IntCounterVec> = OnceLock::new();
static ERRORS: OnceLock<IntCounterVec> = OnceLock::new();
static REQUEST_DURATION: OnceLock<Histogram> = OnceLock::new();
static CIRCUIT_STATE: OnceLock<IntGaugeVec> = OnceLock::new();
static RETRIES: OnceLock<IntCounterVec> = OnceLock::new();
static FILTERED: OnceLock<IntCounterVec> = OnceLock::new();
static QUEUE_DEPTH: OnceLock<IntGauge> = OnceLock::new();
static DROPPED: OnceLock<IntCounterVec> = OnceLock::new();
static DLQ_EVICTED: OnceLock<IntCounterVec> = OnceLock::new();
static RESPONSE_BODIES_CAPTURED: OnceLock<IntCounterVec> = OnceLock::new();

// ── Fallback constructors ──────────────────────────────────────────

fn fallback_counter_vec(name: &str, help: &str, labels: &[&str]) -> IntCounterVec {
    match IntCounterVec::new(Opts::new(name, help), labels) {
        Ok(cv) => cv,
        Err(_) => std::process::abort(),
    }
}

fn fallback_gauge(name: &str, help: &str) -> IntGauge {
    match IntGauge::with_opts(Opts::new(name, help)) {
        Ok(g) => g,
        Err(_) => std::process::abort(),
    }
}

fn fallback_gauge_vec(name: &str, help: &str, labels: &[&str]) -> IntGaugeVec {
    match IntGaugeVec::new(Opts::new(name, help), labels) {
        Ok(gv) => gv,
        Err(_) => std::process::abort(),
    }
}

fn fallback_histogram(name: &str, help: &str) -> Histogram {
    match Histogram::with_opts(HistogramOpts::new(name, help)) {
        Ok(h) => h,
        Err(_) => std::process::abort(),
    }
}

// ── Registration ───────────────────────────────────────────────────

/// Register all HTTP egress metrics with the default Prometheus registry.
///
/// Must be called once at startup. If called multiple times, subsequent
/// calls will succeed but metrics may not be re-registered.
pub fn init() -> prometheus::Result<()> {
    let registry = prometheus::default_registry();

    let publishes = IntCounterVec::new(
        Opts::new(
            "rustgate_http_publishes_total",
            "Successful HTTP egress deliveries",
        ),
        &["target"],
    )?;
    registry.register(Box::new(publishes.clone()))?;
    let _ = PUBLISHES.set(publishes);

    let errors = IntCounterVec::new(
        Opts::new(
            "rustgate_http_errors_total",
            "Failed HTTP egress deliveries",
        ),
        &["target", "reason"],
    )?;
    registry.register(Box::new(errors.clone()))?;
    let _ = ERRORS.set(errors);

    let request_duration = Histogram::with_opts(HistogramOpts::new(
        "rustgate_http_request_duration_seconds",
        "End-to-end HTTP request latency",
    ))?;
    registry.register(Box::new(request_duration.clone()))?;
    let _ = REQUEST_DURATION.set(request_duration);

    let circuit_state = IntGaugeVec::new(
        Opts::new(
            "rustgate_http_circuit_state",
            "Circuit breaker state per target (0=closed, 1=open, 2=half-open)",
        ),
        &["target"],
    )?;
    registry.register(Box::new(circuit_state.clone()))?;
    let _ = CIRCUIT_STATE.set(circuit_state);

    let retries = IntCounterVec::new(
        Opts::new(
            "rustgate_http_retries_total",
            "HTTP egress retry attempts (not initial attempts)",
        ),
        &["target"],
    )?;
    registry.register(Box::new(retries.clone()))?;
    let _ = RETRIES.set(retries);

    let filtered = IntCounterVec::new(
        Opts::new(
            "rustgate_http_filtered_total",
            "Messages filtered out before HTTP dispatch",
        ),
        &["target"],
    )?;
    registry.register(Box::new(filtered.clone()))?;
    let _ = FILTERED.set(filtered);

    let queue_depth = IntGauge::with_opts(Opts::new(
        "rustgate_http_queue_depth",
        "Current HTTP dispatch channel occupancy",
    ))?;
    registry.register(Box::new(queue_depth.clone()))?;
    let _ = QUEUE_DEPTH.set(queue_depth);

    let dropped = IntCounterVec::new(
        Opts::new(
            "rustgate_http_dropped_total",
            "Messages dropped before per-target dispatch (admission-queue \
             shed). Labelled by reason (`channel_full`, `channel_closed`).",
        ),
        &["reason"],
    )?;
    registry.register(Box::new(dropped.clone()))?;
    let _ = DROPPED.set(dropped);

    let dlq_evicted = IntCounterVec::new(
        Opts::new(
            "rustgate_http_dlq_evicted_total",
            "Dead-letter queue files evicted by the per-target total-bytes \
             sweep. Each increment represents one sealed `.dlq.enc` segment \
             deleted because the target's on-disk DLQ footprint exceeded \
             `dlq-max-target-bytes`. Labelled by target name.",
        ),
        &["target"],
    )?;
    registry.register(Box::new(dlq_evicted.clone()))?;
    let _ = DLQ_EVICTED.set(dlq_evicted);

    let response_bodies_captured = IntCounterVec::new(
        Opts::new(
            "rustgate_http_response_bodies_captured_total",
            "2xx HTTP responses whose body was captured and surfaced in a \
             structured debug log alongside the per-request `delivery_id`. \
             Only counted for targets with `capture-response-body = true` \
             and when the server returned a non-empty body. Operators use \
             this to confirm that downstream acknowledgement IDs (Splunk \
             HEC `ackId`, Elastic `_id`, Loki `traceID`) are being \
             recorded; a flat-lining rate against a climbing \
             `publishes_total` suggests the target is returning empty \
             acknowledgement bodies. Labelled by target name.",
        ),
        &["target"],
    )?;
    registry.register(Box::new(response_bodies_captured.clone()))?;
    let _ = RESPONSE_BODIES_CAPTURED.set(response_bodies_captured);

    Ok(())
}

// ── Accessors ──────────────────────────────────────────────────────

/// Successful HTTP deliveries counter, labelled by target name.
pub fn publishes() -> &'static IntCounterVec {
    PUBLISHES.get_or_init(|| {
        fallback_counter_vec("rustgate_http_publishes_total", "fallback", &["target"])
    })
}

/// Failed HTTP deliveries counter, labelled by target and reason.
pub fn errors() -> &'static IntCounterVec {
    ERRORS.get_or_init(|| {
        fallback_counter_vec(
            "rustgate_http_errors_total",
            "fallback",
            &["target", "reason"],
        )
    })
}

/// HTTP request latency histogram.
pub fn request_duration() -> &'static Histogram {
    REQUEST_DURATION
        .get_or_init(|| fallback_histogram("rustgate_http_request_duration_seconds", "fallback"))
}

/// Circuit breaker state gauge, labelled by target.
pub fn circuit_state() -> &'static IntGaugeVec {
    CIRCUIT_STATE
        .get_or_init(|| fallback_gauge_vec("rustgate_http_circuit_state", "fallback", &["target"]))
}

/// Retry attempts counter, labelled by target.
pub fn retries() -> &'static IntCounterVec {
    RETRIES.get_or_init(|| {
        fallback_counter_vec("rustgate_http_retries_total", "fallback", &["target"])
    })
}

/// Filtered messages counter, labelled by target.
pub fn filtered() -> &'static IntCounterVec {
    FILTERED.get_or_init(|| {
        fallback_counter_vec("rustgate_http_filtered_total", "fallback", &["target"])
    })
}

/// Current dispatch channel occupancy gauge.
pub fn queue_depth() -> &'static IntGauge {
    QUEUE_DEPTH.get_or_init(|| fallback_gauge("rustgate_http_queue_depth", "fallback"))
}

/// Pre-dispatch admission-queue drops counter, labelled by reason.
///
/// Increments when a message is shed before reaching per-target
/// dispatch (e.g. the internal bounded channel is full or closed).
/// Paired with a DLQ entry under the synthetic `admission` target
/// when the DLQ is configured, so no drop is silent.
pub fn dropped() -> &'static IntCounterVec {
    DROPPED.get_or_init(|| {
        fallback_counter_vec("rustgate_http_dropped_total", "fallback", &["reason"])
    })
}

/// DLQ file-eviction counter, labelled by target.
///
/// Increments once per sealed `.dlq.enc` segment deleted by the
/// per-target total-bytes sweep (`dlq-max-target-bytes`). A rising
/// rate here indicates a target has been persistently unreachable
/// long enough for its DLQ footprint to exceed the operator's disk
/// budget — use it in alerting to complement the circuit-state gauge.
pub fn dlq_evicted() -> &'static IntCounterVec {
    DLQ_EVICTED.get_or_init(|| {
        fallback_counter_vec("rustgate_http_dlq_evicted_total", "fallback", &["target"])
    })
}

/// 2xx responses whose body was captured for acknowledgement tracking,
/// labelled by target name.
///
/// Only counted for targets with `capture-response-body = true` and
/// when the server returned a non-empty body. A flat-lining rate
/// against a climbing `publishes_total` is the operator signal that
/// the target is returning empty acknowledgement bodies.
pub fn response_bodies_captured() -> &'static IntCounterVec {
    RESPONSE_BODIES_CAPTURED.get_or_init(|| {
        fallback_counter_vec(
            "rustgate_http_response_bodies_captured_total",
            "fallback",
            &["target"],
        )
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn accessors_return_without_init() {
        // Fallback metrics should work without init()
        let _ = publishes();
        let _ = errors();
        let _ = request_duration();
        let _ = circuit_state();
        let _ = retries();
        let _ = filtered();
        let _ = queue_depth();
        let _ = response_bodies_captured();
    }

    #[test]
    fn publishes_can_increment() {
        let counter = publishes();
        if let Ok(child) = counter.get_metric_with_label_values(&["test-target"]) {
            child.inc();
            assert_eq!(child.get(), 1);
        }
    }

    #[test]
    fn errors_can_increment_with_reason() {
        let counter = errors();
        if let Ok(child) = counter.get_metric_with_label_values(&["test-target", "network"]) {
            child.inc();
            assert_eq!(child.get(), 1);
        }
    }

    #[test]
    fn circuit_state_can_set() {
        let gauge = circuit_state();
        if let Ok(child) = gauge.get_metric_with_label_values(&["test-target"]) {
            child.set(1); // open
            assert_eq!(child.get(), 1);
        }
    }

    #[test]
    fn queue_depth_can_set() {
        queue_depth().set(42);
        assert_eq!(queue_depth().get(), 42);
    }

    #[test]
    fn dropped_can_increment_with_reason() {
        let counter = dropped();
        if let Ok(child) = counter.get_metric_with_label_values(&["channel_full"]) {
            child.inc();
            assert!(child.get() >= 1);
        }
    }

    // ── Defensive regression pins ──────────────────────────────────

    #[test]
    fn metric_names_match_documented_schema() {
        // Regression sentinel: the fully-qualified metric names are
        // contracts with Grafana dashboards, alerting rules, and
        // external scrape-aware tooling. A silent rename here would
        // break dashboards without any in-tree compile failure. Pin
        // each `fq_name` exactly.
        use prometheus::core::Collector;

        assert_eq!(
            publishes().desc()[0].fq_name,
            "rustgate_http_publishes_total"
        );
        assert_eq!(errors().desc()[0].fq_name, "rustgate_http_errors_total");
        assert_eq!(
            request_duration().desc()[0].fq_name,
            "rustgate_http_request_duration_seconds"
        );
        assert_eq!(
            circuit_state().desc()[0].fq_name,
            "rustgate_http_circuit_state"
        );
        assert_eq!(retries().desc()[0].fq_name, "rustgate_http_retries_total");
        assert_eq!(filtered().desc()[0].fq_name, "rustgate_http_filtered_total");
        assert_eq!(queue_depth().desc()[0].fq_name, "rustgate_http_queue_depth");
        assert_eq!(dropped().desc()[0].fq_name, "rustgate_http_dropped_total");
        assert_eq!(
            response_bodies_captured().desc()[0].fq_name,
            "rustgate_http_response_bodies_captured_total"
        );
    }

    #[test]
    fn label_schema_is_stable_per_metric() {
        // The Prometheus timeseries identity is `(metric_name, label_set)`.
        // Changing the label name — even keeping the semantic meaning —
        // creates a new timeseries and breaks the rate() continuity on
        // every dashboard. Pin the exact variable-label ordering and
        // membership for every label-bearing metric.
        use prometheus::core::Collector;

        let labels_of = |d: &prometheus::core::Desc| -> Vec<String> {
            d.variable_labels.iter().map(|s| s.to_string()).collect()
        };

        assert_eq!(labels_of(publishes().desc()[0]), vec!["target".to_string()]);
        assert_eq!(
            labels_of(errors().desc()[0]),
            vec!["target".to_string(), "reason".to_string()]
        );
        assert_eq!(
            labels_of(circuit_state().desc()[0]),
            vec!["target".to_string()]
        );
        assert_eq!(labels_of(retries().desc()[0]), vec!["target".to_string()]);
        assert_eq!(labels_of(filtered().desc()[0]), vec!["target".to_string()]);
        assert_eq!(labels_of(dropped().desc()[0]), vec!["reason".to_string()]);
        assert_eq!(
            labels_of(response_bodies_captured().desc()[0]),
            vec!["target".to_string()]
        );
        // Non-vector metrics carry no variable labels.
        assert!(labels_of(queue_depth().desc()[0]).is_empty());
        assert!(labels_of(request_duration().desc()[0]).is_empty());
    }

    #[test]
    fn wrong_label_arity_returns_error_not_panic() {
        // `get_metric_with_label_values` must return `Err` on arity
        // mismatch rather than panicking. The production code threads
        // these through `if let Ok(child)` — if prometheus ever changed
        // the behaviour to panic, those guards would stop being enough.
        // Pin the `Result` contract on a two-label vector (`errors`) and
        // a zero-label metric is skipped (the zero-label case has no
        // `get_metric_with_label_values`).
        assert!(
            errors()
                .get_metric_with_label_values(&[] as &[&str])
                .is_err()
        );
        assert!(
            errors()
                .get_metric_with_label_values(&["only-one"])
                .is_err()
        );
        assert!(
            errors()
                .get_metric_with_label_values(&["too", "many", "labels"])
                .is_err()
        );
        assert!(errors().get_metric_with_label_values(&["t", "r"]).is_ok());
    }

    #[test]
    fn fresh_label_pair_starts_at_zero() {
        // A never-before-seen label combination must report `0` before
        // the first `inc()`. This is the Prometheus baseline invariant
        // — dashboards use `rate(counter[5m])` which silently shifts if
        // a fresh label starts at any non-zero value.
        let counter = publishes();
        // Use a distinctive label so parallel tests cannot collide on it.
        let label = "fresh-label-start-zero-0x7d4e";
        let child = counter
            .get_metric_with_label_values(&[label])
            .expect("label ok");
        assert_eq!(child.get(), 0);
    }

    #[test]
    fn fallback_counter_vec_produces_callable_counter() {
        // Direct exercise of the `fallback_counter_vec` helper. Its
        // error path is `std::process::abort()`, which cannot be
        // tested — but the sunny path must yield a counter vec that
        // accepts `with_label_values` and increments normally.
        let cv = fallback_counter_vec("fallback_test_counter_a", "help", &["k"]);
        let child = cv.get_metric_with_label_values(&["v"]).expect("label ok");
        assert_eq!(child.get(), 0);
        child.inc();
        assert_eq!(child.get(), 1);
    }

    #[test]
    fn fallback_gauge_starts_at_zero_and_is_signed() {
        // `fallback_gauge` builds an `IntGauge`. Pin the documented
        // prometheus behaviour: fresh gauge reads zero; gauges accept
        // negative values (this differs from counters, which must be
        // monotonically non-decreasing). If the helper ever swapped to
        // an `IntCounter` variant, this test would fail.
        let g = fallback_gauge("fallback_test_gauge_a", "help");
        assert_eq!(g.get(), 0);
        g.set(-1);
        assert_eq!(g.get(), -1);
        g.set(42);
        assert_eq!(g.get(), 42);
    }

    #[test]
    fn fallback_gauge_vec_returns_callable_vec() {
        // Same shape as the counter-vec fallback test: exercise the
        // sunny path and confirm per-label children are indexable and
        // writable. Regression guard for the helper used by the circuit
        // state accessor.
        let gv = fallback_gauge_vec("fallback_test_gauge_vec_a", "help", &["label"]);
        let child = gv.get_metric_with_label_values(&["x"]).expect("label ok");
        assert_eq!(child.get(), 0);
        child.set(7);
        assert_eq!(child.get(), 7);
    }

    #[test]
    fn fallback_histogram_observes_count_and_sum() {
        // `fallback_histogram` produces a default-bucket `Histogram`.
        // Pin the two observable fields that dashboards use: total
        // sample count and cumulative sum. A regression that switched
        // to a `Counter` would fail on `observe` (not present) at
        // compile time, but a regression that switched bucket bounds
        // would not — still, pinning count + sum makes intent explicit.
        let h = fallback_histogram("fallback_test_hist_a", "help");
        h.observe(0.5);
        h.observe(1.5);
        assert_eq!(h.get_sample_count(), 2);
        assert!((h.get_sample_sum() - 2.0).abs() < f64::EPSILON);
    }

    #[test]
    fn accessors_are_idempotent_reference_same_static_instance() {
        // `OnceLock::get_or_init` must return the same underlying
        // `&'static` on every call. Prometheus uses pointer-equal
        // comparison when iterating registered collectors; a regression
        // that created a fresh metric on every access would duplicate
        // timeseries in the scrape output.
        assert!(std::ptr::eq(publishes(), publishes()));
        assert!(std::ptr::eq(errors(), errors()));
        assert!(std::ptr::eq(circuit_state(), circuit_state()));
        assert!(std::ptr::eq(retries(), retries()));
        assert!(std::ptr::eq(filtered(), filtered()));
        assert!(std::ptr::eq(dropped(), dropped()));
        assert!(std::ptr::eq(queue_depth(), queue_depth()));
        assert!(std::ptr::eq(request_duration(), request_duration()));
        assert!(std::ptr::eq(
            response_bodies_captured(),
            response_bodies_captured()
        ));
    }

    #[test]
    fn request_duration_observes_sample_count_and_sum() {
        // Pin the end-to-end histogram plumbing for the request-
        // duration metric via the accessor. This complements the
        // helper-level test by verifying the production accessor
        // returns something observable.
        let h = request_duration();
        let before_count = h.get_sample_count();
        let before_sum = h.get_sample_sum();
        h.observe(0.25);
        assert_eq!(h.get_sample_count(), before_count + 1);
        assert!((h.get_sample_sum() - before_sum - 0.25).abs() < 1e-9);
    }

    #[test]
    fn metric_help_text_is_non_empty_for_every_accessor() {
        // Prometheus `HELP` lines drive the descriptions in the
        // `/metrics` exposition and in Grafana tooltips. Empty help
        // strings would render as blank rows. Pin non-empty for every
        // registered metric.
        use prometheus::core::Collector;

        for d in [
            publishes().desc()[0],
            errors().desc()[0],
            circuit_state().desc()[0],
            retries().desc()[0],
            filtered().desc()[0],
            dropped().desc()[0],
            queue_depth().desc()[0],
            request_duration().desc()[0],
            response_bodies_captured().desc()[0],
        ] {
            assert!(
                !d.help.is_empty(),
                "help must be non-empty for {}",
                d.fq_name
            );
        }
    }
}
