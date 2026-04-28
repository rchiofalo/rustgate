// Copyright © 2026 Roberto Chiofalo.

//! Prometheus metrics for the CoT parser (issue #771).
//!
//! Adds parse-result counters and a parse-latency histogram on top of
//! the pre-existing delta-compression metrics that already live in
//! [`rustgate-server`'s metrics module]. This module owns ONLY the new
//! parse-side metrics; the delta-compression family
//! (`rustgate_cot_delta_*`) stays where it is so its established
//! dashboards do not break.
//!
//! Follows the workspace `OnceLock` + `init()` + accessor pattern
//! documented in `rules/shared-infrastructure.md`. Accessors return a
//! `&'static` reference and lazily build an unregistered fallback when
//! [`init`] has not been called, so unit tests outside the server
//! orchestration path can still increment the metric without panicking.
//!
//! Gated behind the `metrics` feature; the no-features build of
//! `rustgate-cot` does not pull in `prometheus`.
//!
//! [`rustgate-server`'s metrics module]: ../../rustgate_server/metrics/index.html

use std::sync::OnceLock;

use prometheus::{Histogram, HistogramOpts, IntCounterVec, Opts};
use rustgate_core::metrics_util::{fallback_counter_vec, fallback_histogram};

// ── Static slots ────────────────────────────────────────────────────

static PARSE_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();
static PARSE_SECONDS: OnceLock<Histogram> = OnceLock::new();

// ── Registration ────────────────────────────────────────────────────

/// Register CoT-parse metrics with the default Prometheus registry.
///
/// Must be called once at startup. Returns the underlying registry
/// error if a metric is already registered (e.g. on a double-init).
pub fn init() -> prometheus::Result<()> {
    let registry = prometheus::default_registry();

    let parse_total = IntCounterVec::new(
        Opts::new(
            "rustgate_cot_parse_total",
            "CoT XML parse attempts, labelled by `result` (`ok` for a \
             successful parse, `err` for any `ParseError` variant). \
             Operators graph the err/total ratio to detect a misbehaving \
             producer or a wire-format regression on a tactical client.",
        ),
        &["result"],
    )?;
    registry.register(Box::new(parse_total.clone()))?;
    let _ = PARSE_TOTAL.set(parse_total);

    // Buckets cover the operationally meaningful CoT parse range. P50
    // for a small position event is sub-microsecond; pathological
    // payloads (deeply nested detail elements, oversized attributes)
    // can reach the 100 ms bucket. The 1s ceiling catches a parser
    // pathology before it monopolises a thread.
    let parse_seconds = Histogram::with_opts(
        HistogramOpts::new(
            "rustgate_cot_parse_seconds",
            "CoT XML parse latency in seconds. Observed for every parse \
             attempt — both successful and failed parses contribute to \
             the histogram so a slowdown caused by malformed input is \
             still visible.",
        )
        .buckets(vec![
            0.000_001, 0.000_010, 0.000_100, 0.001, 0.010, 0.100, 1.0,
        ]),
    )?;
    registry.register(Box::new(parse_seconds.clone()))?;
    let _ = PARSE_SECONDS.set(parse_seconds);

    Ok(())
}

// ── Accessors ───────────────────────────────────────────────────────

/// CoT parse counter, labelled by `result` (`ok` | `err`).
pub fn parse_total() -> &'static IntCounterVec {
    PARSE_TOTAL
        .get_or_init(|| fallback_counter_vec("rustgate_cot_parse_total", "fallback", &["result"]))
}

/// CoT parse latency histogram in seconds.
pub fn parse_seconds() -> &'static Histogram {
    PARSE_SECONDS.get_or_init(|| fallback_histogram("rustgate_cot_parse_seconds", "fallback"))
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn accessors_work_without_init() {
        // The fallback path must work — unit tests that exercise the
        // parser in isolation never call `init()`.
        let _ = parse_total();
        let _ = parse_seconds();
    }

    #[test]
    fn parse_total_increment_with_label_does_not_panic() {
        let counter = parse_total();
        if let Ok(child) = counter.get_metric_with_label_values(&["ok"]) {
            child.inc();
            assert!(child.get() >= 1);
        }
    }

    #[test]
    fn parse_total_err_label_is_independent_of_ok_label() {
        let counter = parse_total();
        let ok = counter
            .get_metric_with_label_values(&["ok"])
            .expect("ok label");
        let err = counter
            .get_metric_with_label_values(&["err"])
            .expect("err label");
        let ok_before = ok.get();
        let err_before = err.get();
        err.inc();
        assert_eq!(err.get(), err_before + 1);
        // ok label must not move when err increments.
        assert_eq!(ok.get(), ok_before);
    }

    #[test]
    fn parse_seconds_observe_is_recorded() {
        let h = parse_seconds();
        let count_before = h.get_sample_count();
        h.observe(0.000_5);
        assert_eq!(h.get_sample_count(), count_before + 1);
    }

    #[test]
    fn accessors_return_same_static_instance() {
        assert!(std::ptr::eq(parse_total(), parse_total()));
        assert!(std::ptr::eq(parse_seconds(), parse_seconds()));
    }
}
