// Copyright © 2026 Roberto Chiofalo.

//! Prometheus metrics for the TAK protobuf <-> XML translation layer
//! (issue #771).
//!
//! Every cross-encoding decode (protobuf -> XML or XML -> protobuf)
//! increments [`decode_total`] with the `kind` and `result` labels and
//! observes its wall-clock duration into [`decode_seconds`] under the
//! same `kind` label. The label vocabulary is `&'static str` at every
//! call site so cardinality is fixed at compile time:
//!
//! - `kind = "proto_to_xml" | "xml_to_proto"`
//! - `result = "ok" | "err"`
//!
//! Follows the workspace `OnceLock` + `init()` + accessor pattern
//! documented in `rules/shared-infrastructure.md`. Accessors return a
//! `&'static` reference and lazily build an unregistered fallback when
//! [`init`] has not been called.
//!
//! Gated behind the `metrics` feature; the no-features build does not
//! pull in `prometheus`.

use std::sync::OnceLock;

use prometheus::{HistogramOpts, HistogramVec, IntCounterVec, Opts};
use rustgate_core::metrics_util::{fallback_counter_vec, fallback_histogram_vec};

// ── Static slots ────────────────────────────────────────────────────

static DECODE_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();
static DECODE_SECONDS: OnceLock<HistogramVec> = OnceLock::new();

// ── Registration ────────────────────────────────────────────────────

/// Register protobuf<->XML translation metrics with the default
/// Prometheus registry.
///
/// Must be called once at startup. Returns the underlying registry
/// error on duplicate registration.
pub fn init() -> prometheus::Result<()> {
    let registry = prometheus::default_registry();

    let decode_total = IntCounterVec::new(
        Opts::new(
            "rustgate_proto_decode_total",
            "TAK protobuf <-> CoT XML decode attempts. Labels: \
             `kind = proto_to_xml | xml_to_proto`, \
             `result = ok | err`. The err/total ratio per `kind` \
             surfaces wire-format regressions (e.g. a peer emitting \
             malformed protobuf or oversized XML detail blocks).",
        ),
        &["kind", "result"],
    )?;
    registry.register(Box::new(decode_total.clone()))?;
    let _ = DECODE_TOTAL.set(decode_total);

    // Buckets cover the operationally meaningful translation range.
    // Healthy P50 for a small position event sits in the
    // sub-microsecond bucket; the 100 ms bucket catches a pathological
    // payload before it monopolises a thread, and the 1s ceiling acts
    // as a parser-runaway guard.
    let decode_seconds = HistogramVec::new(
        HistogramOpts::new(
            "rustgate_proto_decode_seconds",
            "TAK protobuf <-> CoT XML decode latency in seconds, \
             labelled by `kind`. Observed for every attempt — both \
             successful and failed decodes contribute, so a slowdown \
             caused by malformed input is still visible.",
        )
        .buckets(vec![
            0.000_001, 0.000_010, 0.000_100, 0.001, 0.010, 0.100, 1.0,
        ]),
        &["kind"],
    )?;
    registry.register(Box::new(decode_seconds.clone()))?;
    let _ = DECODE_SECONDS.set(decode_seconds);

    Ok(())
}

// ── Accessors ───────────────────────────────────────────────────────

/// Decode-attempt counter, labelled by `kind` and `result`.
pub fn decode_total() -> &'static IntCounterVec {
    DECODE_TOTAL.get_or_init(|| {
        fallback_counter_vec(
            "rustgate_proto_decode_total",
            "fallback",
            &["kind", "result"],
        )
    })
}

/// Decode-latency histogram (seconds), labelled by `kind`.
pub fn decode_seconds() -> &'static HistogramVec {
    DECODE_SECONDS.get_or_init(|| {
        fallback_histogram_vec("rustgate_proto_decode_seconds", "fallback", &["kind"])
    })
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn accessors_work_without_init() {
        let _ = decode_total();
        let _ = decode_seconds();
    }

    #[test]
    fn decode_total_increment_with_known_labels_does_not_panic() {
        let counter = decode_total();
        if let Ok(child) = counter.get_metric_with_label_values(&["proto_to_xml", "ok"]) {
            child.inc();
            assert!(child.get() >= 1);
        }
    }

    #[test]
    fn decode_seconds_observe_per_kind_is_independent() {
        let h = decode_seconds();
        let p2x = h.with_label_values(&["proto_to_xml"]);
        let x2p = h.with_label_values(&["xml_to_proto"]);
        let p2x_before = p2x.get_sample_count();
        let x2p_before = x2p.get_sample_count();
        p2x.observe(0.000_5);
        // p2x sample count must increment but x2p must not.
        assert_eq!(p2x.get_sample_count(), p2x_before + 1);
        assert_eq!(x2p.get_sample_count(), x2p_before);
    }

    #[test]
    fn err_label_independent_of_ok_label() {
        let counter = decode_total();
        let ok = counter
            .get_metric_with_label_values(&["xml_to_proto", "ok"])
            .expect("ok label");
        let err = counter
            .get_metric_with_label_values(&["xml_to_proto", "err"])
            .expect("err label");
        let ok_before = ok.get();
        let err_before = err.get();
        err.inc();
        assert_eq!(err.get(), err_before + 1);
        assert_eq!(ok.get(), ok_before);
    }

    #[test]
    fn accessors_return_same_static_instance() {
        assert!(std::ptr::eq(decode_total(), decode_total()));
        assert!(std::ptr::eq(decode_seconds(), decode_seconds()));
    }
}
