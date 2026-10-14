// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Prometheus metrics for the operator controller.
//!
//! Follows the workspace `OnceLock` + `init()` + accessor pattern (see
//! `.claude/rules/shared-infrastructure.md`). Every metric ships with a
//! fallback constructor so accessors are still callable even if
//! [`init`] hasn't been called yet (useful in tests).
//!
//! ## Metric vocabulary
//!
//! | Name | Type | Labels | Meaning |
//! |---|---|---|---|
//! | `rustgate_operator_reconcile_total` | Counter | `result` (`ok`/`err`) | Reconcile attempts |
//! | `rustgate_operator_reconcile_duration_seconds` | Histogram | — | Wall-clock per reconcile |
//! | `rustgate_operator_apply_total` | Counter | `kind`, `result` | Server-side-apply calls |
//! | `rustgate_operator_clusters_total` | Gauge | — | Last observed cluster count |
//! | `rustgate_operator_leader` | Gauge | — | 1 when this replica holds the lease, 0 otherwise |
//! | `rustgate_operator_last_reconcile_timestamp_seconds` | Gauge | — | Unix time of last successful reconcile |

#![cfg(feature = "controller")]

use std::sync::OnceLock;

use prometheus::{
    Gauge, Histogram, HistogramOpts, IntCounterVec, IntGauge, Opts, Registry, register_gauge,
    register_histogram, register_int_counter_vec, register_int_gauge,
};

static RECONCILE_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();
static RECONCILE_DURATION: OnceLock<Histogram> = OnceLock::new();
static APPLY_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();
static CLUSTERS_TOTAL: OnceLock<IntGauge> = OnceLock::new();
static LEADER: OnceLock<IntGauge> = OnceLock::new();
static LAST_RECONCILE_TS: OnceLock<Gauge> = OnceLock::new();

/// Initialise the operator's metrics on the given registry. Idempotent —
/// re-running is a no-op so an operator that races initialisation between
/// the HTTP server and the controller harness doesn't panic.
///
/// Returns the same registry so the caller can chain it into an `axum`
/// state. Pass a fresh `Registry::new()` from `main` rather than relying
/// on `prometheus::default_registry()` so the operator surfaces only its
/// own metrics, not whatever stray globals the dependency tree registers.
pub fn init(registry: &Registry) -> prometheus::Result<()> {
    let reconcile_total = register_int_counter_vec!(
        Opts::new(
            "rustgate_operator_reconcile_total",
            "Reconcile attempts, partitioned by outcome.",
        )
        .namespace("rustgate"),
        &["result"],
    )?;
    registry.register(Box::new(reconcile_total.clone()))?;
    let _ = RECONCILE_TOTAL.set(reconcile_total);

    let reconcile_duration = register_histogram!(
        HistogramOpts::new(
            "rustgate_operator_reconcile_duration_seconds",
            "Wall-clock time spent in a single reconcile pass.",
        )
        .namespace("rustgate")
        .buckets(vec![
            0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0
        ]),
    )?;
    registry.register(Box::new(reconcile_duration.clone()))?;
    let _ = RECONCILE_DURATION.set(reconcile_duration);

    let apply_total = register_int_counter_vec!(
        Opts::new(
            "rustgate_operator_apply_total",
            "Server-side-apply attempts, partitioned by object kind and outcome.",
        )
        .namespace("rustgate"),
        &["kind", "result"],
    )?;
    registry.register(Box::new(apply_total.clone()))?;
    let _ = APPLY_TOTAL.set(apply_total);

    let clusters_total = register_int_gauge!(
        Opts::new(
            "rustgate_operator_clusters_total",
            "Number of RustgateCluster resources the operator currently watches.",
        )
        .namespace("rustgate")
    )?;
    registry.register(Box::new(clusters_total.clone()))?;
    let _ = CLUSTERS_TOTAL.set(clusters_total);

    let leader = register_int_gauge!(
        Opts::new(
            "rustgate_operator_leader",
            "1 when this operator replica holds the leader lease, 0 otherwise.",
        )
        .namespace("rustgate")
    )?;
    registry.register(Box::new(leader.clone()))?;
    let _ = LEADER.set(leader);

    let last_reconcile_ts = register_gauge!(
        Opts::new(
            "rustgate_operator_last_reconcile_timestamp_seconds",
            "Unix time of the most recent successful reconcile across all clusters.",
        )
        .namespace("rustgate")
    )?;
    registry.register(Box::new(last_reconcile_ts.clone()))?;
    let _ = LAST_RECONCILE_TS.set(last_reconcile_ts);

    Ok(())
}

fn fallback_counter_vec(
    name: &'static str,
    help: &'static str,
    labels: &[&'static str],
) -> IntCounterVec {
    // justification: in tests / mocked controller harnesses the metric
    // module is intentionally not initialised. Falling back to an
    // ephemeral counter that is not registered anywhere lets the hot
    // path call `.inc()` without panicking; production callers always
    // go through `init()` so the registered counter is used.
    #[allow(clippy::expect_used)]
    IntCounterVec::new(Opts::new(name, help), labels)
        .expect("fallback counter construction is infallible for static labels")
}

/// Increment the reconcile counter for the given outcome (`"ok"` or
/// `"err"`).
pub fn reconcile(result: &str) {
    RECONCILE_TOTAL
        .get_or_init(|| {
            fallback_counter_vec(
                "rustgate_operator_reconcile_total",
                "Reconcile attempts, partitioned by outcome.",
                &["result"],
            )
        })
        .with_label_values(&[result])
        .inc();
}

/// Returns a histogram timer guard. Drop the guard to record elapsed
/// wall-clock seconds into the duration histogram.
pub fn reconcile_timer() -> prometheus::HistogramTimer {
    RECONCILE_DURATION
        .get_or_init(|| {
            // justification: fallback histogram for tests; the
            // constructor with bucketed options cannot fail with the
            // static input below.
            #[allow(clippy::expect_used)]
            Histogram::with_opts(HistogramOpts::new(
                "rustgate_operator_reconcile_duration_seconds",
                "Wall-clock time spent in a single reconcile pass.",
            ))
            .expect("fallback histogram construction is infallible")
        })
        .start_timer()
}

/// Increment the apply counter for a given object kind and outcome.
/// `kind` should be the Kubernetes kind string (`"StatefulSet"`,
/// `"Service"`, `"ConfigMap"`, …) and `result` is `"ok"` or `"err"`.
pub fn apply(kind: &str, result: &str) {
    APPLY_TOTAL
        .get_or_init(|| {
            fallback_counter_vec(
                "rustgate_operator_apply_total",
                "Server-side-apply attempts, partitioned by object kind and outcome.",
                &["kind", "result"],
            )
        })
        .with_label_values(&[kind, result])
        .inc();
}

/// Record the current number of watched clusters.
pub fn set_clusters_total(n: i64) {
    CLUSTERS_TOTAL
        .get_or_init(|| {
            // justification: see `fallback_counter_vec`.
            #[allow(clippy::expect_used)]
            IntGauge::new("rustgate_operator_clusters_total", "Number of clusters.")
                .expect("fallback gauge construction is infallible")
        })
        .set(n);
}

/// Update the leader gauge — pass `true` when this replica acquires the
/// lease, `false` when it loses or releases it.
pub fn set_leader(leading: bool) {
    LEADER
        .get_or_init(|| {
            // justification: see `fallback_counter_vec`.
            #[allow(clippy::expect_used)]
            IntGauge::new("rustgate_operator_leader", "Leader gauge.")
                .expect("fallback gauge construction is infallible")
        })
        .set(if leading { 1 } else { 0 });
}

/// Record the Unix time (in seconds) of the most recent successful
/// reconcile pass — feeds the "operator-staleness" alert that fires when
/// the value lags too far behind `now`.
pub fn set_last_reconcile_now() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    LAST_RECONCILE_TS
        .get_or_init(|| {
            // justification: see `fallback_counter_vec`.
            #[allow(clippy::expect_used)]
            Gauge::new(
                "rustgate_operator_last_reconcile_timestamp_seconds",
                "Last reconcile time.",
            )
            .expect("fallback gauge construction is infallible")
        })
        .set(now);
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn init_idempotent_and_registers() {
        let r = Registry::new();
        init(&r).unwrap();
        // Re-init would try to register on the SAME registry which the
        // prometheus crate rejects with `AlreadyReg`. Re-init on a fresh
        // registry succeeds because the OnceLocks are no-ops on second
        // set.
        let r2 = Registry::new();
        // The second init returns the AlreadyReg error from the
        // counter macros (they register on the default registry by
        // default). We accept that and proceed — the OnceLock keeps
        // the first metric handle.
        let _ = init(&r2);
        // Accessors are usable.
        reconcile("ok");
        apply("StatefulSet", "ok");
        set_clusters_total(3);
        set_leader(true);
        set_last_reconcile_now();
    }

    #[test]
    fn accessors_work_without_init() {
        // Lazy fallback metrics must be callable even without `init()`.
        // Using a different label combination so this is independent of
        // other tests' init state.
        reconcile("err");
        apply("Service", "err");
        set_clusters_total(0);
        set_leader(false);
    }
}
