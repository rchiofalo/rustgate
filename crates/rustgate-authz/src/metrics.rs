// Copyright © 2026 Roberto Chiofalo.

//! Prometheus metrics for the authz crate (issue #771).
//!
//! Coverage focus is the in-crate observation surface that
//! `rustgate-server` cannot reach without crossing the trait boundary
//! and so was previously unmeasured: per-evaluation counters with the
//! decision label, evaluation latency in canonical SI units, the live
//! decision-cache occupancy gauge, and the obligations emitted by
//! allow decisions. The pre-existing `rustgate_authz_*` metrics in
//! `rustgate-server::metrics` (cache_hits / cache_misses, the legacy
//! nanosecond histogram, and the policy-rules gauge) are intentionally
//! left in the server crate so their dashboards do not break — this
//! module is purely additive on top of that surface.
//!
//! Follows the workspace `OnceLock` + `init()` + accessor pattern
//! documented in `rules/shared-infrastructure.md`. Accessors return a
//! `&'static` reference and lazily build an unregistered fallback when
//! [`init`] has not been called.
//!
//! Gated behind the `metrics` feature; the no-features build does not
//! pull in `prometheus`.

use std::sync::OnceLock;

use prometheus::{HistogramOpts, HistogramVec, IntCounterVec, IntGauge, Opts};
use rustgate_metrics::{fallback_counter_vec, fallback_gauge, fallback_histogram_vec};

// ── Static slots ────────────────────────────────────────────────────

static EVALUATIONS_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();
static EVALUATION_SECONDS: OnceLock<HistogramVec> = OnceLock::new();
static CACHE_SIZE: OnceLock<IntGauge> = OnceLock::new();
static OBLIGATIONS_EMITTED_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();

// ── Registration ────────────────────────────────────────────────────

/// Register authz crate-side metrics with the default Prometheus registry.
///
/// Must be called once at startup. Returns the underlying registry
/// error on duplicate registration.
pub fn init() -> prometheus::Result<()> {
    let registry = prometheus::default_registry();

    let evaluations_total = IntCounterVec::new(
        Opts::new(
            "rustgate_authz_evaluations_total",
            "Authz policy evaluations performed by the engine, labelled by \
             `decision = allow | deny | not_applicable` and \
             `subject_class` (a coarse identity bucket — `tls_cn`, \
             `federated`, `anonymous`, `other` — bounded vocabulary so \
             cardinality is fixed at compile time). Sibling of the \
             pre-existing `rustgate_authz_decisions_total` in \
             `rustgate-server`: the server-side counter is wired from \
             the router PEP, this counter is wired from inside the \
             engine and so observes evaluations the PEP short-circuits \
             (cache hits, fail-open paths).",
        ),
        &["decision", "subject_class"],
    )?;
    registry.register(Box::new(evaluations_total.clone()))?;
    let _ = EVALUATIONS_TOTAL.set(evaluations_total);

    // Bucket family in canonical SI seconds. Floor at 50 ns matches the
    // documented native-engine P99 baseline (see the `rustgate_authz_
    // eval_nanos` discussion in `rustgate-server::metrics::init`); the
    // 1s ceiling catches a pathological ruleset before it monopolises a
    // dataplane thread.
    let evaluation_seconds = HistogramVec::new(
        HistogramOpts::new(
            "rustgate_authz_evaluation_seconds",
            "Authz policy evaluation duration in seconds, labelled by \
             `decision`. Canonical SI sibling of the legacy nanosecond \
             histogram registered by `rustgate-server`; both are kept \
             registered so existing dashboards do not break.",
        )
        .buckets(vec![
            0.000_000_05,
            0.000_000_1,
            0.000_000_25,
            0.000_000_5,
            0.000_001,
            0.000_002_5,
            0.000_010,
            0.000_100,
            0.001,
            0.010,
            0.100,
            1.0,
        ]),
        &["decision"],
    )?;
    registry.register(Box::new(evaluation_seconds.clone()))?;
    let _ = EVALUATION_SECONDS.set(evaluation_seconds);

    let cache_size = IntGauge::with_opts(Opts::new(
        "rustgate_authz_cache_size",
        "Live entry count across all shards of the engine's decision \
         cache. Operators alert on a sustained value at the configured \
         per-shard cap (the cache evicts on insert, so a steady-state \
         cap is the signal that the working set has outgrown the \
         current sizing).",
    ))?;
    registry.register(Box::new(cache_size.clone()))?;
    let _ = CACHE_SIZE.set(cache_size);

    let obligations_emitted_total = IntCounterVec::new(
        Opts::new(
            "rustgate_authz_obligations_emitted_total",
            "Obligations attached to allow decisions, labelled by \
             `obligation_type` (`mask_point`, `mask_payload`, \
             `tag_classified`, `audit_extended`, `unknown`). Mirrors \
             the bounded vocabulary of the `Obligation` enum so a \
             future authz upgrade with a new variant cannot silently \
             grow Prometheus cardinality — the catch-all `unknown` \
             bucket guards `#[non_exhaustive]`.",
        ),
        &["obligation_type"],
    )?;
    registry.register(Box::new(obligations_emitted_total.clone()))?;
    let _ = OBLIGATIONS_EMITTED_TOTAL.set(obligations_emitted_total);

    Ok(())
}

// ── Accessors ───────────────────────────────────────────────────────

/// Authz evaluation counter, labelled by `decision` and `subject_class`.
pub fn evaluations_total() -> &'static IntCounterVec {
    EVALUATIONS_TOTAL.get_or_init(|| {
        fallback_counter_vec(
            "rustgate_authz_evaluations_total",
            "fallback",
            &["decision", "subject_class"],
        )
    })
}

/// Authz evaluation latency histogram (seconds), labelled by `decision`.
pub fn evaluation_seconds() -> &'static HistogramVec {
    EVALUATION_SECONDS.get_or_init(|| {
        fallback_histogram_vec(
            "rustgate_authz_evaluation_seconds",
            "fallback",
            &["decision"],
        )
    })
}

/// Decision-cache live entry count gauge.
pub fn cache_size() -> &'static IntGauge {
    CACHE_SIZE.get_or_init(|| fallback_gauge("rustgate_authz_cache_size", "fallback"))
}

/// Obligations-emitted counter, labelled by `obligation_type`.
pub fn obligations_emitted_total() -> &'static IntCounterVec {
    OBLIGATIONS_EMITTED_TOTAL.get_or_init(|| {
        fallback_counter_vec(
            "rustgate_authz_obligations_emitted_total",
            "fallback",
            &["obligation_type"],
        )
    })
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn accessors_work_without_init() {
        let _ = evaluations_total();
        let _ = evaluation_seconds();
        let _ = cache_size();
        let _ = obligations_emitted_total();
    }

    #[test]
    fn evaluations_total_increment_with_known_labels_does_not_panic() {
        let counter = evaluations_total();
        if let Ok(child) = counter.get_metric_with_label_values(&["allow", "tls_cn"]) {
            child.inc();
            assert!(child.get() >= 1);
        }
    }

    #[test]
    fn cache_size_set_get_round_trip() {
        let g = cache_size();
        g.set(123);
        assert_eq!(g.get(), 123);
        g.set(0);
        assert_eq!(g.get(), 0);
    }

    #[test]
    fn evaluation_seconds_observes_per_decision_independently() {
        let h = evaluation_seconds();
        let allow = h.with_label_values(&["allow"]);
        let deny = h.with_label_values(&["deny"]);
        let allow_before = allow.get_sample_count();
        let deny_before = deny.get_sample_count();
        allow.observe(0.000_001);
        // allow sample count must increment but deny must not.
        assert_eq!(allow.get_sample_count(), allow_before + 1);
        assert_eq!(deny.get_sample_count(), deny_before);
    }

    #[test]
    fn obligations_emitted_label_isolation() {
        let counter = obligations_emitted_total();
        let mp = counter
            .get_metric_with_label_values(&["mask_point"])
            .expect("label ok");
        let other = counter
            .get_metric_with_label_values(&["audit_extended"])
            .expect("label ok");
        let mp_before = mp.get();
        let other_before = other.get();
        mp.inc();
        // mp moves but the unrelated label stays put.
        assert_eq!(mp.get(), mp_before + 1);
        assert_eq!(other.get(), other_before);
    }

    #[test]
    fn accessors_return_same_static_instance() {
        assert!(std::ptr::eq(evaluations_total(), evaluations_total()));
        assert!(std::ptr::eq(evaluation_seconds(), evaluation_seconds()));
        assert!(std::ptr::eq(cache_size(), cache_size()));
        assert!(std::ptr::eq(
            obligations_emitted_total(),
            obligations_emitted_total()
        ));
    }
}
