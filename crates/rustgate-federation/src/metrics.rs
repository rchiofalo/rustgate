// Copyright © 2026 Roberto Chiofalo.

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
static MESSAGES_IN_BY_RPC: OnceLock<IntCounterVec> = OnceLock::new();
static MESSAGES_OUT: OnceLock<IntCounter> = OnceLock::new();

static ERRORS: OnceLock<IntCounter> = OnceLock::new();

static HEARTBEATS: OnceLock<IntCounterVec> = OnceLock::new();

static MESSAGES_DROPPED: OnceLock<IntCounter> = OnceLock::new();

static RECONNECTS: OnceLock<IntCounter> = OnceLock::new();

static CIRCUIT_BREAKER_TRIPS: OnceLock<IntCounter> = OnceLock::new();
static CIRCUIT_BREAKER_RECOVERIES: OnceLock<IntCounter> = OnceLock::new();

static FORWARD_TTL_EXPIRED: OnceLock<IntCounter> = OnceLock::new();

static REPLAY_PERSISTED: OnceLock<IntCounter> = OnceLock::new();
static REPLAY_RESTORED: OnceLock<IntCounter> = OnceLock::new();
static REPLAY_RESTORED_SKIPPED_TTL: OnceLock<IntCounter> = OnceLock::new();
static REPLAY_BUFFER_BYTES: OnceLock<IntGauge> = OnceLock::new();

static PEER_LATENCY_NANOS: OnceLock<prometheus::IntGaugeVec> = OnceLock::new();
static PEER_QUEUE_BYTES: OnceLock<prometheus::IntGaugeVec> = OnceLock::new();
static CROSS_REGION_FORWARDS: OnceLock<IntCounter> = OnceLock::new();

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

    let messages_in_by_rpc = IntCounterVec::new(
        Opts::new(
            "rustgate_federation_messages_in_by_rpc_total",
            "Total messages received from federation peers, broken out by V2 RPC method",
        ),
        &["rpc"],
    )?;
    registry.register(Box::new(messages_in_by_rpc.clone()))?;
    let _ = MESSAGES_IN_BY_RPC.set(messages_in_by_rpc);

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

    let circuit_trips = IntCounter::with_opts(Opts::new(
        "rustgate_federation_circuit_breaker_trips_total",
        "Total circuit breaker trips across all federation peers",
    ))?;
    registry.register(Box::new(circuit_trips.clone()))?;
    let _ = CIRCUIT_BREAKER_TRIPS.set(circuit_trips);

    let circuit_recoveries = IntCounter::with_opts(Opts::new(
        "rustgate_federation_circuit_breaker_recoveries_total",
        "Total circuit breaker recoveries across all federation peers",
    ))?;
    registry.register(Box::new(circuit_recoveries.clone()))?;
    let _ = CIRCUIT_BREAKER_RECOVERIES.set(circuit_recoveries);

    let forward_ttl_expired = IntCounter::with_opts(Opts::new(
        "rustgate_federation_forward_ttl_expired_total",
        "Messages dropped at the federation forward boundary because their TTL had expired",
    ))?;
    registry.register(Box::new(forward_ttl_expired.clone()))?;
    let _ = FORWARD_TTL_EXPIRED.set(forward_ttl_expired);

    let replay_persisted = IntCounter::with_opts(Opts::new(
        "rustgate_federation_replay_persisted_total",
        "Total federation replay buffer entries persisted to disk",
    ))?;
    registry.register(Box::new(replay_persisted.clone()))?;
    let _ = REPLAY_PERSISTED.set(replay_persisted);

    let replay_restored = IntCounter::with_opts(Opts::new(
        "rustgate_federation_replay_restored_total",
        "Total federation replay buffer entries restored from disk on startup",
    ))?;
    registry.register(Box::new(replay_restored.clone()))?;
    let _ = REPLAY_RESTORED.set(replay_restored);

    let replay_restored_skipped_ttl = IntCounter::with_opts(Opts::new(
        "rustgate_federation_replay_restored_skipped_ttl_total",
        "Persisted federation replay entries skipped on rehydrate because their TTL had already expired",
    ))?;
    registry.register(Box::new(replay_restored_skipped_ttl.clone()))?;
    let _ = REPLAY_RESTORED_SKIPPED_TTL.set(replay_restored_skipped_ttl);

    let replay_buffer_bytes = IntGauge::with_opts(Opts::new(
        "rustgate_federation_replay_buffer_bytes",
        "Accounted on-disk size of the redb-backed federation replay buffer across all peers, including per-record overhead",
    ))?;
    registry.register(Box::new(replay_buffer_bytes.clone()))?;
    let _ = REPLAY_BUFFER_BYTES.set(replay_buffer_bytes);

    let peer_latency_nanos = prometheus::IntGaugeVec::new(
        Opts::new(
            "rustgate_federation_peer_latency_nanos",
            "EWMA round-trip latency to a federation peer in nanoseconds",
        ),
        &["peer"],
    )?;
    registry.register(Box::new(peer_latency_nanos.clone()))?;
    let _ = PEER_LATENCY_NANOS.set(peer_latency_nanos);

    let peer_queue_bytes = prometheus::IntGaugeVec::new(
        Opts::new(
            "rustgate_federation_peer_queue_bytes",
            "Bytes currently sitting in the outbound queue to a federation peer",
        ),
        &["peer"],
    )?;
    registry.register(Box::new(peer_queue_bytes.clone()))?;
    let _ = PEER_QUEUE_BYTES.set(peer_queue_bytes);

    let cross_region_forwards = IntCounter::with_opts(Opts::new(
        "rustgate_federation_cross_region_forwards_total",
        "Messages forwarded to federation peers in a different region",
    ))?;
    registry.register(Box::new(cross_region_forwards.clone()))?;
    let _ = CROSS_REGION_FORWARDS.set(cross_region_forwards);

    Ok(())
}

// ── Fallback constructors ───────────────────────────────────────────
//
// When `init()` has not been called, accessor functions lazily create
// an unregistered metric via `OnceLock::get_or_init()`. These helpers
// construct the fallback without `unwrap()` or `expect()`.

fn fallback_counter(name: &str, help: &str) -> IntCounter {
    match IntCounter::with_opts(Opts::new(name, help)) {
        Ok(c) => c,
        Err(_) => std::process::abort(),
    }
}

fn fallback_gauge(name: &str, help: &str) -> IntGauge {
    match IntGauge::with_opts(Opts::new(name, help)) {
        Ok(g) => g,
        Err(_) => std::process::abort(),
    }
}

fn fallback_counter_vec(name: &str, help: &str, labels: &[&str]) -> IntCounterVec {
    match IntCounterVec::new(Opts::new(name, help), labels) {
        Ok(cv) => cv,
        Err(_) => std::process::abort(),
    }
}

fn fallback_gauge_vec(name: &str, help: &str, labels: &[&str]) -> prometheus::IntGaugeVec {
    match prometheus::IntGaugeVec::new(Opts::new(name, help), labels) {
        Ok(gv) => gv,
        Err(_) => std::process::abort(),
    }
}

// ── Accessor functions ──────────────────────────────────────────────
//
// Each accessor returns a reference to the registered metric. If
// `init()` has not been called, `get_or_init()` lazily creates an
// unregistered metric that absorbs increments without effect. This
// eliminates panics from initialization-order races without adding
// Option propagation to every call site.

/// Active federation connection count (gauge).
pub fn connections() -> &'static IntGauge {
    CONNECTIONS.get_or_init(|| fallback_gauge("rustgate_federation_connections", "fallback"))
}

/// Active inbound federation connections (gauge).
pub fn connections_inbound() -> &'static IntGauge {
    CONNECTIONS_INBOUND
        .get_or_init(|| fallback_gauge("rustgate_federation_connections_inbound", "fallback"))
}

/// Active outbound federation connections (gauge).
pub fn connections_outbound() -> &'static IntGauge {
    CONNECTIONS_OUTBOUND
        .get_or_init(|| fallback_gauge("rustgate_federation_connections_outbound", "fallback"))
}

/// Total messages received from federation peers (counter).
pub fn messages_in() -> &'static IntCounter {
    MESSAGES_IN
        .get_or_init(|| fallback_counter("rustgate_federation_messages_in_total", "fallback"))
}

/// Total messages received from federation peers, broken out by V2 RPC
/// method (counter vec, label: `rpc`).
///
/// Tracks accepted ingress per RPC handler so operators can attribute
/// inbound load to a specific federation transport — e.g.
/// `rpc="send_one_event"` for unary single-event delivery vs. the
/// (future) streaming variants. Increments only after the handler has
/// passed mTLS, hop-count, and group-allowlist checks.
pub fn messages_in_by_rpc() -> &'static IntCounterVec {
    MESSAGES_IN_BY_RPC.get_or_init(|| {
        fallback_counter_vec(
            "rustgate_federation_messages_in_by_rpc_total",
            "fallback",
            &["rpc"],
        )
    })
}

/// Total messages sent to federation peers (counter).
pub fn messages_out() -> &'static IntCounter {
    MESSAGES_OUT
        .get_or_init(|| fallback_counter("rustgate_federation_messages_out_total", "fallback"))
}

/// Total federation errors (counter).
pub fn errors() -> &'static IntCounter {
    ERRORS.get_or_init(|| fallback_counter("rustgate_federation_errors_total", "fallback"))
}

/// Federation heartbeats by direction (counter vec, labels: direction=in|out).
pub fn heartbeats() -> &'static IntCounterVec {
    HEARTBEATS.get_or_init(|| {
        fallback_counter_vec(
            "rustgate_federation_heartbeats_total",
            "fallback",
            &["direction"],
        )
    })
}

/// Messages dropped due to loop detection or hop limit (counter).
pub fn messages_dropped() -> &'static IntCounter {
    MESSAGES_DROPPED
        .get_or_init(|| fallback_counter("rustgate_federation_messages_dropped_total", "fallback"))
}

/// Total outbound reconnection attempts (counter).
pub fn reconnects() -> &'static IntCounter {
    RECONNECTS.get_or_init(|| fallback_counter("rustgate_federation_reconnects_total", "fallback"))
}

/// Total circuit breaker trips (counter).
pub fn circuit_breaker_trips() -> &'static IntCounter {
    CIRCUIT_BREAKER_TRIPS.get_or_init(|| {
        fallback_counter(
            "rustgate_federation_circuit_breaker_trips_total",
            "fallback",
        )
    })
}

/// Total circuit breaker recoveries (counter).
pub fn circuit_breaker_recoveries() -> &'static IntCounter {
    CIRCUIT_BREAKER_RECOVERIES.get_or_init(|| {
        fallback_counter(
            "rustgate_federation_circuit_breaker_recoveries_total",
            "fallback",
        )
    })
}

/// Messages dropped at the federation forward boundary due to TTL expiry (counter).
pub fn forward_ttl_expired() -> &'static IntCounter {
    FORWARD_TTL_EXPIRED.get_or_init(|| {
        fallback_counter("rustgate_federation_forward_ttl_expired_total", "fallback")
    })
}

/// Replay buffer entries persisted to disk (counter).
pub fn replay_persisted() -> &'static IntCounter {
    REPLAY_PERSISTED
        .get_or_init(|| fallback_counter("rustgate_federation_replay_persisted_total", "fallback"))
}

/// Replay buffer entries restored from disk on startup (counter).
pub fn replay_restored() -> &'static IntCounter {
    REPLAY_RESTORED
        .get_or_init(|| fallback_counter("rustgate_federation_replay_restored_total", "fallback"))
}

/// Persisted replay entries skipped on rehydrate because their TTL had
/// already expired before the server restarted (counter).
pub fn replay_restored_skipped_ttl() -> &'static IntCounter {
    REPLAY_RESTORED_SKIPPED_TTL.get_or_init(|| {
        fallback_counter(
            "rustgate_federation_replay_restored_skipped_ttl_total",
            "fallback",
        )
    })
}

/// Accounted on-disk size of the redb-backed federation replay buffer,
/// summed across all peers and including per-record overhead (gauge).
///
/// Updated by [`crate::replay_persist::ReplayStore`] at every mutation
/// site (rehydrate, put, delete, clear). Provides visibility into the
/// persistent buffer's occupancy so operators can alert before it
/// saturates its configured byte cap. The value is clamped to
/// [`i64::MAX`] on improbable overflow to satisfy the `IntGauge` signed
/// contract — the same convention used by `peer_queue_bytes` (#744).
pub fn replay_buffer_bytes() -> &'static IntGauge {
    REPLAY_BUFFER_BYTES
        .get_or_init(|| fallback_gauge("rustgate_federation_replay_buffer_bytes", "fallback"))
}

/// EWMA latency per federation peer in nanoseconds (gauge vec, label: peer).
pub fn peer_latency_nanos() -> &'static prometheus::IntGaugeVec {
    PEER_LATENCY_NANOS.get_or_init(|| {
        fallback_gauge_vec(
            "rustgate_federation_peer_latency_nanos",
            "fallback",
            &["peer"],
        )
    })
}

/// Outbound queue bytes per federation peer (gauge vec, label: peer).
///
/// Feeds from [`crate::peer::PeerHandle::record_enqueue`],
/// [`crate::peer::PeerHandle::record_dequeue`], and
/// [`crate::peer::PeerHandle::reset_queue`]. Alert on high or rising
/// values to detect federation pipeline stalls before they propagate
/// to upstream producers via global backpressure.
pub fn peer_queue_bytes() -> &'static prometheus::IntGaugeVec {
    PEER_QUEUE_BYTES.get_or_init(|| {
        fallback_gauge_vec(
            "rustgate_federation_peer_queue_bytes",
            "fallback",
            &["peer"],
        )
    })
}

/// Messages forwarded to federation peers in a different region (counter).
pub fn cross_region_forwards() -> &'static IntCounter {
    CROSS_REGION_FORWARDS.get_or_init(|| {
        fallback_counter(
            "rustgate_federation_cross_region_forwards_total",
            "fallback",
        )
    })
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
    pub circuit_breaker_trips: u64,
    pub circuit_breaker_recoveries: u64,
    pub forward_ttl_expired: u64,
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
        circuit_breaker_trips: circuit_breaker_trips().get(),
        circuit_breaker_recoveries: circuit_breaker_recoveries().get(),
        forward_ttl_expired: forward_ttl_expired().get(),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Once;

    use super::*;

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
        let _ = circuit_breaker_trips();
        let _ = circuit_breaker_recoveries();
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
    fn circuit_breaker_trips_counter() {
        ensure_init();

        let before = circuit_breaker_trips().get();
        circuit_breaker_trips().inc();
        assert_eq!(circuit_breaker_trips().get(), before + 1);
    }

    #[test]
    fn circuit_breaker_recoveries_counter() {
        ensure_init();

        let before = circuit_breaker_recoveries().get();
        circuit_breaker_recoveries().inc();
        assert_eq!(circuit_breaker_recoveries().get(), before + 1);
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
        // Use > because parallel tests share the global counters and may
        // increment them between our baseline and check snapshots.
        assert!(
            snap.messages_in > baseline.messages_in,
            "messages_in: expected > {}, got {}",
            baseline.messages_in,
            snap.messages_in,
        );
        assert!(
            snap.messages_out > baseline.messages_out + 1,
            "messages_out: expected > {}, got {}",
            baseline.messages_out + 1,
            snap.messages_out,
        );
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
        assert!(json.contains("\"circuit_breaker_trips\""));
        assert!(json.contains("\"circuit_breaker_recoveries\""));
    }

    #[test]
    fn snapshot_debug() {
        ensure_init();

        let snap = snapshot();
        let debug = format!("{snap:?}");
        assert!(debug.contains("MetricsSnapshot"));
    }
}
