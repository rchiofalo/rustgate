//! Prometheus metrics for federation.
//!
//! Provides counters and gauges tracking federation connections,
//! messages, errors, and heartbeats. Follows the same `OnceLock`
//! pattern as `rustgate-server`'s metrics module.

use std::sync::OnceLock;

use prometheus::{IntCounter, IntCounterVec, IntGauge, Opts};

// ── Metric statics ──────────────────────────────────────────────────

static CONNECTIONS: OnceLock<IntGauge> = OnceLock::new();
static CONNECTIONS_INBOUND: OnceLock<IntGauge> = OnceLock::new();
static CONNECTIONS_OUTBOUND: OnceLock<IntGauge> = OnceLock::new();

static MESSAGES_IN: OnceLock<IntCounter> = OnceLock::new();
static MESSAGES_OUT: OnceLock<IntCounter> = OnceLock::new();

static ERRORS: OnceLock<IntCounter> = OnceLock::new();

static HEARTBEATS: OnceLock<IntCounterVec> = OnceLock::new();

static MESSAGES_DROPPED: OnceLock<IntCounter> = OnceLock::new();

static RECONNECTS: OnceLock<IntCounter> = OnceLock::new();

// ── Registration ────────────────────────────────────────────────────

/// Register all federation metrics with the default Prometheus registry.
///
/// Must be called once at startup. Safe to call multiple times —
/// subsequent calls return the existing registration error, but
/// callers should only call this once.
pub fn init() -> prometheus::Result<()> {
    let registry = prometheus::default_registry();

    let connections = IntGauge::with_opts(Opts::new(
        "rustgate_federation_connections",
        "Active federation peer connections",
    ))?;
    registry.register(Box::new(connections.clone()))?;
    let _ = CONNECTIONS.set(connections);

    let connections_inbound = IntGauge::with_opts(Opts::new(
        "rustgate_federation_connections_inbound",
        "Active inbound federation connections",
    ))?;
    registry.register(Box::new(connections_inbound.clone()))?;
    let _ = CONNECTIONS_INBOUND.set(connections_inbound);

    let connections_outbound = IntGauge::with_opts(Opts::new(
        "rustgate_federation_connections_outbound",
        "Active outbound federation connections",
    ))?;
    registry.register(Box::new(connections_outbound.clone()))?;
    let _ = CONNECTIONS_OUTBOUND.set(connections_outbound);

    let messages_in = IntCounter::with_opts(Opts::new(
        "rustgate_federation_messages_in_total",
        "Total messages received from federation peers",
    ))?;
    registry.register(Box::new(messages_in.clone()))?;
    let _ = MESSAGES_IN.set(messages_in);

    let messages_out = IntCounter::with_opts(Opts::new(
        "rustgate_federation_messages_out_total",
        "Total messages sent to federation peers",
    ))?;
    registry.register(Box::new(messages_out.clone()))?;
    let _ = MESSAGES_OUT.set(messages_out);

    let errors = IntCounter::with_opts(Opts::new(
        "rustgate_federation_errors_total",
        "Total federation errors",
    ))?;
    registry.register(Box::new(errors.clone()))?;
    let _ = ERRORS.set(errors);

    let heartbeats = IntCounterVec::new(
        Opts::new(
            "rustgate_federation_heartbeats_total",
            "Federation heartbeats by direction",
        ),
        &["direction"],
    )?;
    registry.register(Box::new(heartbeats.clone()))?;
    let _ = HEARTBEATS.set(heartbeats);

    let messages_dropped = IntCounter::with_opts(Opts::new(
        "rustgate_federation_messages_dropped_total",
        "Messages dropped due to loop detection or hop limit",
    ))?;
    registry.register(Box::new(messages_dropped.clone()))?;
    let _ = MESSAGES_DROPPED.set(messages_dropped);

    let reconnects = IntCounter::with_opts(Opts::new(
        "rustgate_federation_reconnects_total",
        "Total outbound reconnection attempts",
    ))?;
    registry.register(Box::new(reconnects.clone()))?;
    let _ = RECONNECTS.set(reconnects);

    Ok(())
}

// ── Accessor functions ──────────────────────────────────────────────

/// Active federation connection count (gauge).
pub fn connections() -> &'static IntGauge {
    CONNECTIONS
        .get()
        .expect("federation metrics not initialized")
}

/// Active inbound federation connections (gauge).
pub fn connections_inbound() -> &'static IntGauge {
    CONNECTIONS_INBOUND
        .get()
        .expect("federation metrics not initialized")
}

/// Active outbound federation connections (gauge).
pub fn connections_outbound() -> &'static IntGauge {
    CONNECTIONS_OUTBOUND
        .get()
        .expect("federation metrics not initialized")
}

/// Total messages received from federation peers (counter).
pub fn messages_in() -> &'static IntCounter {
    MESSAGES_IN
        .get()
        .expect("federation metrics not initialized")
}

/// Total messages sent to federation peers (counter).
pub fn messages_out() -> &'static IntCounter {
    MESSAGES_OUT
        .get()
        .expect("federation metrics not initialized")
}

/// Total federation errors (counter).
pub fn errors() -> &'static IntCounter {
    ERRORS.get().expect("federation metrics not initialized")
}

/// Federation heartbeats by direction (counter vec, labels: direction=in|out).
pub fn heartbeats() -> &'static IntCounterVec {
    HEARTBEATS
        .get()
        .expect("federation metrics not initialized")
}

/// Messages dropped due to loop detection or hop limit (counter).
pub fn messages_dropped() -> &'static IntCounter {
    MESSAGES_DROPPED
        .get()
        .expect("federation metrics not initialized")
}

/// Total outbound reconnection attempts (counter).
pub fn reconnects() -> &'static IntCounter {
    RECONNECTS
        .get()
        .expect("federation metrics not initialized")
}

// ── Snapshot ────────────────────────────────────────────────────────

/// A point-in-time snapshot of all federation metric values.
///
/// Useful for the REST API `/stats` endpoint and for testing.
#[derive(Debug, Clone, serde::Serialize)]
pub struct MetricsSnapshot {
    pub connections: i64,
    pub connections_inbound: i64,
    pub connections_outbound: i64,
    pub messages_in: u64,
    pub messages_out: u64,
    pub errors: u64,
    pub heartbeats_in: u64,
    pub heartbeats_out: u64,
    pub messages_dropped: u64,
    pub reconnects: u64,
}

/// Capture a snapshot of all current federation metric values.
pub fn snapshot() -> MetricsSnapshot {
    MetricsSnapshot {
        connections: connections().get(),
        connections_inbound: connections_inbound().get(),
        connections_outbound: connections_outbound().get(),
        messages_in: messages_in().get(),
        messages_out: messages_out().get(),
        errors: errors().get(),
        heartbeats_in: heartbeats().with_label_values(&["in"]).get(),
        heartbeats_out: heartbeats().with_label_values(&["out"]).get(),
        messages_dropped: messages_dropped().get(),
        reconnects: reconnects().get(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Once;

    static INIT: Once = Once::new();

    fn ensure_init() {
        INIT.call_once(|| {
            init().expect("federation metrics init failed");
        });
    }

    #[test]
    fn init_registers_all_metrics() {
        ensure_init();

        let _ = connections();
        let _ = connections_inbound();
        let _ = connections_outbound();
        let _ = messages_in();
        let _ = messages_out();
        let _ = errors();
        let _ = heartbeats();
        let _ = messages_dropped();
        let _ = reconnects();
    }

    #[test]
    fn connections_gauge_inc_dec() {
        ensure_init();

        let before = connections().get();
        connections().inc();
        assert_eq!(connections().get(), before + 1);
        connections().dec();
        assert_eq!(connections().get(), before);
    }

    #[test]
    fn inbound_gauge_inc_dec() {
        ensure_init();

        let before = connections_inbound().get();
        connections_inbound().inc();
        assert_eq!(connections_inbound().get(), before + 1);
        connections_inbound().dec();
        assert_eq!(connections_inbound().get(), before);
    }

    #[test]
    fn outbound_gauge_inc_dec() {
        ensure_init();

        let before = connections_outbound().get();
        connections_outbound().inc();
        assert_eq!(connections_outbound().get(), before + 1);
        connections_outbound().dec();
        assert_eq!(connections_outbound().get(), before);
    }

    #[test]
    fn messages_in_counter() {
        ensure_init();

        let before = messages_in().get();
        messages_in().inc();
        assert_eq!(messages_in().get(), before + 1);
    }

    #[test]
    fn messages_out_counter() {
        ensure_init();

        let before = messages_out().get();
        messages_out().inc();
        assert_eq!(messages_out().get(), before + 1);
    }

    #[test]
    fn errors_counter() {
        ensure_init();

        let before = errors().get();
        errors().inc();
        assert_eq!(errors().get(), before + 1);
    }

    #[test]
    fn heartbeats_direction_labels() {
        ensure_init();

        let before_in = heartbeats().with_label_values(&["in"]).get();
        let before_out = heartbeats().with_label_values(&["out"]).get();

        heartbeats().with_label_values(&["in"]).inc();
        heartbeats().with_label_values(&["out"]).inc();
        heartbeats().with_label_values(&["out"]).inc();

        assert_eq!(heartbeats().with_label_values(&["in"]).get(), before_in + 1);
        assert_eq!(
            heartbeats().with_label_values(&["out"]).get(),
            before_out + 2
        );
    }

    #[test]
    fn messages_dropped_counter() {
        ensure_init();

        let before = messages_dropped().get();
        messages_dropped().inc();
        assert_eq!(messages_dropped().get(), before + 1);
    }

    #[test]
    fn reconnects_counter() {
        ensure_init();

        let before = reconnects().get();
        reconnects().inc();
        assert_eq!(reconnects().get(), before + 1);
    }

    #[test]
    fn snapshot_captures_current_values() {
        ensure_init();

        // Record some known increments
        let baseline = snapshot();

        messages_in().inc();
        messages_out().inc();
        messages_out().inc();

        let snap = snapshot();
        assert_eq!(snap.messages_in, baseline.messages_in + 1);
        assert_eq!(snap.messages_out, baseline.messages_out + 2);
    }

    #[test]
    fn snapshot_serializes_to_json() {
        ensure_init();

        let snap = snapshot();
        let json = serde_json::to_string(&snap).expect("serialize");
        assert!(json.contains("\"connections\""));
        assert!(json.contains("\"messages_in\""));
        assert!(json.contains("\"messages_out\""));
        assert!(json.contains("\"errors\""));
        assert!(json.contains("\"heartbeats_in\""));
        assert!(json.contains("\"heartbeats_out\""));
        assert!(json.contains("\"messages_dropped\""));
        assert!(json.contains("\"reconnects\""));
    }

    #[test]
    fn snapshot_debug() {
        ensure_init();

        let snap = snapshot();
        let debug = format!("{snap:?}");
        assert!(debug.contains("MetricsSnapshot"));
    }
}
