// Copyright © 2026 Roberto Chiofalo.

//! Prometheus metrics for the MQTT 5.0 / 3.1.1 transport adapter
//! (issue #771).
//!
//! Coverage focus is the in-crate observation surface that
//! `rustgate-server` cannot reach without a callback hop and so was
//! previously unmeasured: per-PUBLISH counters with the QoS label,
//! publish-handling latency (excluding network round-trip), the live
//! authenticated session gauge, and the will-message-published
//! counter.
//!
//! The pre-existing `rustgate_mqtt_*` metrics in
//! `rustgate-server::metrics` (connections / publishes / subscribes /
//! retain / will_published) stay in the server crate so their
//! dashboards do not break — this module is purely additive on top of
//! that surface, with deliberately-distinct metric names where the
//! semantic axis differs (`publish` here is per-PUBLISH-packet keyed
//! on QoS, vs the pre-existing label-free `publishes_total` family).
//!
//! Follows the workspace `OnceLock` + `init()` + accessor pattern
//! documented in `rules/shared-infrastructure.md`. Accessors return a
//! `&'static` reference and lazily build an unregistered fallback when
//! [`init`] has not been called.
//!
//! Gated behind the `metrics` feature; the no-features build does not
//! pull in `prometheus`.

use std::sync::OnceLock;

use prometheus::{HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge, Opts};
use rustgate_core::metrics_util::{
    fallback_counter, fallback_counter_vec, fallback_gauge, fallback_histogram_vec,
};

// ── Static slots ────────────────────────────────────────────────────

static PUBLISH_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();
static PUBLISH_SECONDS: OnceLock<HistogramVec> = OnceLock::new();
static ACTIVE_SESSIONS: OnceLock<IntGauge> = OnceLock::new();
static WILL_MESSAGES_TOTAL: OnceLock<IntCounter> = OnceLock::new();

// ── Registration ────────────────────────────────────────────────────

/// Register MQTT crate-side metrics with the default Prometheus registry.
///
/// Must be called once at startup. Returns the underlying registry
/// error on duplicate registration.
pub fn init() -> prometheus::Result<()> {
    let registry = prometheus::default_registry();

    let publish_total = IntCounterVec::new(
        Opts::new(
            "rustgate_mqtt_publish_total",
            "MQTT PUBLISH packets handled by the broker, labelled by \
             `qos = 0 | 1 | 2`. Sibling of the pre-existing label-free \
             `rustgate_mqtt_publishes_total` in `rustgate-server`: this \
             counter splits on the QoS axis so operators can observe \
             the share of at-most-once / at-least-once / exactly-once \
             traffic — essential for sizing the inflight window and \
             tracking PUBACK/PUBREC volumes in the broker.",
        ),
        &["qos"],
    )?;
    registry.register(Box::new(publish_total.clone()))?;
    let _ = PUBLISH_TOTAL.set(publish_total);

    // Buckets cover the operationally meaningful broker-side handling
    // window. Healthy P50 for a small payload is sub-millisecond; the
    // 1s ceiling catches a stuck broker before it monopolises a
    // connection-handling task. Network round-trip to the publisher
    // is excluded — this histogram observes broker-side handling
    // only.
    let publish_seconds = HistogramVec::new(
        HistogramOpts::new(
            "rustgate_mqtt_publish_seconds",
            "MQTT broker-side PUBLISH handling latency in seconds, \
             labelled by `qos`. Excludes publisher network round-trip; \
             observes from packet decode through router admission.",
        )
        .buckets(vec![0.000_010, 0.000_100, 0.001, 0.010, 0.100, 1.0]),
        &["qos"],
    )?;
    registry.register(Box::new(publish_seconds.clone()))?;
    let _ = PUBLISH_SECONDS.set(publish_seconds);

    let active_sessions = IntGauge::with_opts(Opts::new(
        "rustgate_mqtt_active_sessions",
        "Live authenticated MQTT sessions currently handled by the \
         broker. Sibling of the connection-attempt counters in \
         `rustgate-server::metrics`: those count attempts, this gauge \
         is the steady-state count after authentication and CONNACK. A \
         persistent gap between successful CONNECT attempts and this \
         gauge is the operator signal that sessions are dying without \
         clean DISCONNECT.",
    ))?;
    registry.register(Box::new(active_sessions.clone()))?;
    let _ = ACTIVE_SESSIONS.set(active_sessions);

    let will_messages_total = IntCounter::with_opts(Opts::new(
        "rustgate_mqtt_will_messages_total",
        "MQTT Last-Will-and-Testament messages registered by clients on \
         CONNECT (whether or not the will eventually fires on \
         disconnect). Sibling of `rustgate_mqtt_will_published_total` \
         in `rustgate-server`: that counts wills *delivered*, this \
         counts wills *registered*. Operators graph the ratio to gauge \
         what fraction of clients leave the session ungracefully.",
    ))?;
    registry.register(Box::new(will_messages_total.clone()))?;
    let _ = WILL_MESSAGES_TOTAL.set(will_messages_total);

    Ok(())
}

// ── Accessors ───────────────────────────────────────────────────────

/// Per-QoS PUBLISH counter.
pub fn publish_total() -> &'static IntCounterVec {
    PUBLISH_TOTAL
        .get_or_init(|| fallback_counter_vec("rustgate_mqtt_publish_total", "fallback", &["qos"]))
}

/// Per-QoS PUBLISH-handling latency histogram (seconds).
pub fn publish_seconds() -> &'static HistogramVec {
    PUBLISH_SECONDS.get_or_init(|| {
        fallback_histogram_vec("rustgate_mqtt_publish_seconds", "fallback", &["qos"])
    })
}

/// Live authenticated session gauge.
pub fn active_sessions() -> &'static IntGauge {
    ACTIVE_SESSIONS.get_or_init(|| fallback_gauge("rustgate_mqtt_active_sessions", "fallback"))
}

/// Last-Will-and-Testament registration counter.
pub fn will_messages_total() -> &'static IntCounter {
    WILL_MESSAGES_TOTAL
        .get_or_init(|| fallback_counter("rustgate_mqtt_will_messages_total", "fallback"))
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn accessors_work_without_init() {
        let _ = publish_total();
        let _ = publish_seconds();
        let _ = active_sessions();
        let _ = will_messages_total();
    }

    #[test]
    fn publish_total_increments_per_qos_label() {
        let counter = publish_total();
        for qos in &["0", "1", "2"] {
            if let Ok(child) = counter.get_metric_with_label_values(&[qos]) {
                child.inc();
                assert!(child.get() >= 1);
            }
        }
    }

    #[test]
    fn publish_seconds_observes_per_qos_independently() {
        let h = publish_seconds();
        let q0 = h.with_label_values(&["0"]);
        let q1 = h.with_label_values(&["1"]);
        let q0_before = q0.get_sample_count();
        let q1_before = q1.get_sample_count();
        q0.observe(0.001);
        // q0 sample count must increment but q1 must not.
        assert_eq!(q0.get_sample_count(), q0_before + 1);
        assert_eq!(q1.get_sample_count(), q1_before);
    }

    #[test]
    fn active_sessions_inc_dec_round_trip() {
        let g = active_sessions();
        let before = g.get();
        g.inc();
        assert_eq!(g.get(), before + 1);
        g.dec();
        assert_eq!(g.get(), before);
    }

    #[test]
    fn will_messages_total_increments() {
        let c = will_messages_total();
        let before = c.get();
        c.inc();
        assert_eq!(c.get(), before + 1);
    }

    #[test]
    fn accessors_return_same_static_instance() {
        assert!(std::ptr::eq(publish_total(), publish_total()));
        assert!(std::ptr::eq(publish_seconds(), publish_seconds()));
        assert!(std::ptr::eq(active_sessions(), active_sessions()));
        assert!(std::ptr::eq(will_messages_total(), will_messages_total()));
    }
}
