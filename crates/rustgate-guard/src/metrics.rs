// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Prometheus metrics for the cross-domain guard.
//!
//! Follows the workspace `OnceLock` + `init()` + accessor pattern. All
//! metrics are registered centrally via [`init`] at startup; accessor
//! functions return a `&'static` reference, falling back to an
//! unregistered metric if `init()` was not called.
//!
//! Three metrics:
//!
//! - `rustgate_guard_evaluations_total{direction, decision}` — counter
//!   of every `evaluate` call, labelled by direction and the
//!   admit/deny outcome.
//! - `rustgate_guard_throughput_bps{direction}` — gauge reflecting the
//!   current token-bucket level (interpreted as bps headroom) per
//!   direction. Snapshotted on every audit emission.
//! - `rustgate_guard_rejections_total{direction, reason}` — counter
//!   of denials, labelled by direction and the typed reason
//!   (`rate_limit`, `missing_marking`, `unauthorized_classification`).

use std::sync::OnceLock;

use prometheus::{IntCounterVec, IntGaugeVec, Opts};
use rustgate_metrics::{fallback_counter_vec, fallback_gauge_vec};

static EVALUATIONS: OnceLock<IntCounterVec> = OnceLock::new();
static THROUGHPUT_BPS: OnceLock<IntGaugeVec> = OnceLock::new();
static REJECTIONS: OnceLock<IntCounterVec> = OnceLock::new();

/// Register all guard metrics with the default Prometheus registry.
///
/// Must be called once at startup. Subsequent calls are no-ops on the
/// `OnceLock` slots; if a re-registration attempt fails (e.g. operator
/// re-imports a registered metric under a new collector), the call
/// returns the underlying `prometheus::Error` so the binary surfaces
/// the misconfiguration rather than silently dropping metrics.
///
/// # Errors
///
/// Returns `prometheus::Error` when constructing or registering a
/// counter/gauge fails. Common cause: a metric name collision when
/// the binary registers multiple subsystems against the same default
/// registry.
pub fn init() -> prometheus::Result<()> {
    let registry = prometheus::default_registry();

    let evaluations = IntCounterVec::new(
        Opts::new(
            "rustgate_guard_evaluations_total",
            "Boundary evaluations by direction and decision",
        ),
        &["direction", "decision"],
    )?;
    registry.register(Box::new(evaluations.clone()))?;
    let _ = EVALUATIONS.set(evaluations);

    let throughput_bps = IntGaugeVec::new(
        Opts::new(
            "rustgate_guard_throughput_bps",
            "Current boundary token bucket level (bps headroom) per direction",
        ),
        &["direction"],
    )?;
    registry.register(Box::new(throughput_bps.clone()))?;
    let _ = THROUGHPUT_BPS.set(throughput_bps);

    let rejections = IntCounterVec::new(
        Opts::new(
            "rustgate_guard_rejections_total",
            "Boundary rejections by direction and typed reason",
        ),
        &["direction", "reason"],
    )?;
    registry.register(Box::new(rejections.clone()))?;
    let _ = REJECTIONS.set(rejections);

    Ok(())
}

/// Counter `rustgate_guard_evaluations_total{direction, decision}`.
///
/// Falls back to an unregistered counter if `init()` was never called
/// — matches the workspace pattern in
/// [`rustgate_metrics::fallback_counter_vec`].
pub fn evaluations_total() -> &'static IntCounterVec {
    EVALUATIONS.get_or_init(|| {
        fallback_counter_vec(
            "rustgate_guard_evaluations_total",
            "Boundary evaluations by direction and decision",
            &["direction", "decision"],
        )
    })
}

/// Gauge `rustgate_guard_throughput_bps{direction}`.
pub fn throughput_bps() -> &'static IntGaugeVec {
    THROUGHPUT_BPS.get_or_init(|| {
        fallback_gauge_vec(
            "rustgate_guard_throughput_bps",
            "Current boundary token bucket level (bps headroom) per direction",
            &["direction"],
        )
    })
}

/// Counter `rustgate_guard_rejections_total{direction, reason}`.
pub fn rejections_total() -> &'static IntCounterVec {
    REJECTIONS.get_or_init(|| {
        fallback_counter_vec(
            "rustgate_guard_rejections_total",
            "Boundary rejections by direction and typed reason",
            &["direction", "reason"],
        )
    })
}
