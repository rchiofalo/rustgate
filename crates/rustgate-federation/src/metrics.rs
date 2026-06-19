// Copyright © 2026 Roberto Chiofalo.

//! Prometheus metrics for federation.
//!
//! Provides counters and gauges tracking federation connections,
//! messages, errors, and heartbeats. Follows the same `OnceLock`
//! pattern as `rustgate-server`'s metrics module.

use std::sync::OnceLock;

use prometheus::{
    HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge, IntGaugeVec, Opts,
};

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

static KV_WRITE_FAILURES: OnceLock<IntCounter> = OnceLock::new();
static REPLAY_BUFFER_BYTES: OnceLock<IntGauge> = OnceLock::new();

static PEER_LATENCY_NANOS: OnceLock<prometheus::IntGaugeVec> = OnceLock::new();
static PEER_QUEUE_BYTES: OnceLock<prometheus::IntGaugeVec> = OnceLock::new();
static CROSS_REGION_FORWARDS: OnceLock<IntCounter> = OnceLock::new();

// ── Per-RPC observability (closes #1299) ────────────────────────────
//
// Three vector metrics give operators per-RPC granularity over the V2
// federation gRPC suite — the aggregate counters above can't tell
// "slow `SendOneBlob` (large payloads)" from "slow `ServerEventStream`
// (steady state)" from "bursty `ServerROLStream`". The label
// vocabulary is shared across all three so PromQL can `sum by (rpc)`
// to get a uniform view.
static RPC_DURATION: OnceLock<HistogramVec> = OnceLock::new();
static RPC_IN_FLIGHT: OnceLock<IntGaugeVec> = OnceLock::new();
static RPC_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();

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

    let kv_write_failures = IntCounter::with_opts(Opts::new(
        "rustgate_federation_kv_write_failures_total",
        "Total HA federate-store KV writes that permanently failed after retries (SEC-4) — \
         local cache and the distributed KV store have diverged; alert and reconcile",
    ))?;
    registry.register(Box::new(kv_write_failures.clone()))?;
    let _ = KV_WRITE_FAILURES.set(kv_write_failures);

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

    // Per-RPC observability (closes #1299).
    let rpc_duration = HistogramVec::new(
        HistogramOpts::new(
            "rustgate_federation_rpc_duration_seconds",
            "Per-RPC wall-clock duration of V2 federation gRPC calls. The \
             `rpc` label is one of `server_event_stream`, `send_one_blob`, \
             `server_rol_stream`, `client_federate_groups_stream`. The \
             `result` label is `success`, `error`, or `timeout`.",
        ),
        &["rpc", "peer", "result"],
    )?;
    registry.register(Box::new(rpc_duration.clone()))?;
    let _ = RPC_DURATION.set(rpc_duration);

    let rpc_in_flight = IntGaugeVec::new(
        Opts::new(
            "rustgate_federation_rpc_in_flight",
            "Per-RPC in-flight count for V2 federation gRPC calls. \
             Incremented on entry into the handler / send path and \
             decremented when it returns (RAII via the duration timer's \
             `Drop` and a paired gauge guard).",
        ),
        &["rpc", "peer"],
    )?;
    registry.register(Box::new(rpc_in_flight.clone()))?;
    let _ = RPC_IN_FLIGHT.set(rpc_in_flight);

    let rpc_total = IntCounterVec::new(
        Opts::new(
            "rustgate_federation_rpc_total",
            "Per-RPC total invocation count for V2 federation gRPC calls, \
             classified by outcome. The `result` label distinguishes \
             `success` (gRPC `Ok`), `error` (any non-OK gRPC `Status` \
             other than `DeadlineExceeded`), and `timeout` \
             (`DeadlineExceeded` or local deadline hit).",
        ),
        &["rpc", "peer", "result"],
    )?;
    registry.register(Box::new(rpc_total.clone()))?;
    let _ = RPC_TOTAL.set(rpc_total);

    Ok(())
}

// ── Fallback constructors ───────────────────────────────────────────
//
// When `init()` has not been called, accessor functions lazily create
// an unregistered metric via `OnceLock::get_or_init()`. The helpers
// live in `rustgate_metrics` so every crate following the
// `OnceLock` + `init()` + accessor pattern shares one implementation.

use rustgate_core::sanitize::sanitize_for_log;
use rustgate_metrics::{
    fallback_counter, fallback_counter_vec, fallback_gauge, fallback_gauge_vec,
    fallback_histogram_vec,
};

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

/// HA federate-store KV writes that permanently failed after retries (SEC-4).
/// A non-zero value means the local in-memory cache and the distributed KV
/// store have diverged — alert on this and reconcile (the watch loop + load
/// on restart re-sync from KV).
pub fn kv_write_failures() -> &'static IntCounter {
    KV_WRITE_FAILURES
        .get_or_init(|| fallback_counter("rustgate_federation_kv_write_failures_total", "fallback"))
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

// ── Per-RPC observability accessors (closes #1299) ──────────────────

/// Canonical `rpc` label for `ServerEventStream` send path / handler.
pub const RPC_SERVER_EVENT_STREAM: &str = "server_event_stream";
/// Canonical `rpc` label for `SendOneBlob` (unary).
pub const RPC_SEND_ONE_BLOB: &str = "send_one_blob";
/// Canonical `rpc` label for `ServerROLStream`.
pub const RPC_SERVER_ROL_STREAM: &str = "server_rol_stream";
/// Canonical `rpc` label for `ClientFederateGroupsStream`.
pub const RPC_CLIENT_FEDERATE_GROUPS_STREAM: &str = "client_federate_groups_stream";

/// Result label `success` — RPC completed with gRPC `Ok` status.
pub const RESULT_SUCCESS: &str = "success";
/// Result label `error` — explicit non-OK / non-`DeadlineExceeded` gRPC `Err`.
pub const RESULT_ERROR: &str = "error";
/// Result label `timeout` — `DeadlineExceeded` or local deadline.
pub const RESULT_TIMEOUT: &str = "timeout";

/// Per-RPC duration histogram (vec, labels: `rpc`, `peer`, `result`).
///
/// Each bucket observation is the wall-clock duration of one V2
/// federation gRPC invocation. Use [`HistogramVec::with_label_values`]
/// at the call site; pair with [`rpc_in_flight`] for an in-flight gauge.
pub fn rpc_duration() -> &'static HistogramVec {
    RPC_DURATION.get_or_init(|| {
        fallback_histogram_vec(
            "rustgate_federation_rpc_duration_seconds",
            "fallback",
            &["rpc", "peer", "result"],
        )
    })
}

/// Per-RPC in-flight gauge (vec, labels: `rpc`, `peer`).
///
/// Incremented on entry into the RPC handler / send path; decremented on
/// exit. The `result` label is intentionally absent here — operators
/// already get success-vs-error rates from [`rpc_total`], and a third
/// dimension would inflate the cardinality of an in-flight series with
/// values that are mechanically zero except in transient bursts.
pub fn rpc_in_flight() -> &'static IntGaugeVec {
    RPC_IN_FLIGHT.get_or_init(|| {
        fallback_gauge_vec(
            "rustgate_federation_rpc_in_flight",
            "fallback",
            &["rpc", "peer"],
        )
    })
}

/// Per-RPC invocation counter classified by outcome (vec, labels:
/// `rpc`, `peer`, `result`).
///
/// `result` ∈ `{success, error, timeout}`. See [`classify_status`] for
/// the canonical gRPC `Status` → label mapping.
pub fn rpc_total() -> &'static IntCounterVec {
    RPC_TOTAL.get_or_init(|| {
        fallback_counter_vec(
            "rustgate_federation_rpc_total",
            "fallback",
            &["rpc", "peer", "result"],
        )
    })
}

/// Sanitize a peer-id label value for the per-RPC metric vectors.
///
/// Peer-id is the federate-id string from a peer-controlled `Identity`
/// or the mTLS CN. Both are user-influenced surfaces — we route them
/// through [`sanitize_for_log`] so a peer that smuggled `\r\n` into its
/// federate-id can't forge log lines downstream of a Prometheus scrape
/// that prints labels verbatim.
pub fn sanitize_peer_label(peer: &str) -> String {
    sanitize_for_log(peer)
}

/// Classify a `tonic::Status` into the canonical `result` label value
/// for [`rpc_total`] / [`rpc_duration`].
///
/// - `Code::Ok` → [`RESULT_SUCCESS`]
/// - `Code::DeadlineExceeded` → [`RESULT_TIMEOUT`]
/// - any other code → [`RESULT_ERROR`]
///
/// Local deadline hits surface as `DeadlineExceeded` from tonic's timer
/// machinery, so callers that wrap an RPC in `tokio::time::timeout`
/// should map the elapsed branch to [`RESULT_TIMEOUT`] explicitly —
/// this helper only sees the gRPC layer's view.
#[cfg(feature = "v2")]
pub fn classify_status(code: tonic::Code) -> &'static str {
    match code {
        tonic::Code::Ok => RESULT_SUCCESS,
        tonic::Code::DeadlineExceeded => RESULT_TIMEOUT,
        _ => RESULT_ERROR,
    }
}

/// RAII guard that increments [`rpc_in_flight`] on construction and
/// decrements on `Drop`. Pair with `rpc_duration().start_timer()` for
/// the matching duration histogram (the histogram timer's RAII is its
/// own type; we keep a separate guard so the two metrics can diverge
/// in the unlikely future where one wants different label cardinality).
#[derive(Debug)]
pub struct InFlightGuard {
    rpc: &'static str,
    peer: String,
}

impl InFlightGuard {
    /// Increment the in-flight gauge for `(rpc, peer)` and return a
    /// guard that decrements on `Drop`. The `rpc` value is one of the
    /// `RPC_*` constants in this module; the `peer` value goes through
    /// [`sanitize_peer_label`] before being used as a label.
    pub fn enter(rpc: &'static str, peer: &str) -> Self {
        let peer = sanitize_peer_label(peer);
        rpc_in_flight()
            .with_label_values(&[rpc, peer.as_str()])
            .inc();
        Self { rpc, peer }
    }
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        rpc_in_flight()
            .with_label_values(&[self.rpc, self.peer.as_str()])
            .dec();
    }
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

    // ── Per-RPC observability (closes #1299) ────────────────────────

    /// `init()` is idempotent — a second call returns
    /// `Err(AlreadyReg)` from prometheus's registry but must not panic.
    /// All call sites guard with `let _ = init();` precisely so the
    /// second-call error is silently absorbed.
    #[test]
    fn rpc_metrics_init_is_idempotent() {
        // First call may succeed (or be a re-entry from another test);
        // second call must not panic regardless.
        let _ = init();
        let _ = init();
        // Sentinel: the accessor still returns a usable metric.
        let _ = rpc_duration();
    }

    /// Accessors must work even when `init()` was never called — the
    /// `OnceLock::get_or_init` fallback path constructs an unregistered
    /// metric on demand. We can't isolate the global `OnceLock` from a
    /// preceding test that already triggered `init()`, but the
    /// fallback constructor's correctness is independently exercised
    /// by `rustgate_metrics` unit tests; here we just
    /// confirm the accessor returns a callable handle.
    #[test]
    fn rpc_metrics_accessor_works_without_init() {
        let dur = rpc_duration();
        let inf = rpc_in_flight();
        let tot = rpc_total();
        // Calling `with_label_values` on each must not panic — that
        // proves the accessor returned a vec with the expected label
        // arity (3 / 2 / 3 respectively) regardless of whether the
        // metric is registered or fallback.
        let _ = dur.with_label_values(&[RPC_SEND_ONE_BLOB, "peer-fallback", RESULT_SUCCESS]);
        let _ = inf.with_label_values(&[RPC_SEND_ONE_BLOB, "peer-fallback"]);
        let _ = tot.with_label_values(&[RPC_SEND_ONE_BLOB, "peer-fallback", RESULT_SUCCESS]);
    }

    /// The peer-id label must be sanitized before reaching the metric
    /// vector — a peer that injected `\r\n` into its federate-id
    /// would otherwise forge log lines downstream of any scrape that
    /// prints labels verbatim. The output of [`sanitize_peer_label`]
    /// must contain neither CR nor LF.
    #[test]
    fn rpc_metrics_label_peer_is_sanitized() {
        let evil = "peer-\r\nfake-line";
        let safe = sanitize_peer_label(evil);
        assert!(!safe.contains('\r'), "CR must be stripped: {safe:?}");
        assert!(!safe.contains('\n'), "LF must be stripped: {safe:?}");
    }

    /// `classify_status` is the canonical gRPC `Code` → `result`
    /// label mapping. Pin the three branches so a future tonic
    /// upgrade that renames a variant fails this test instead of
    /// silently mis-classifying outcomes.
    #[cfg(feature = "v2")]
    #[test]
    fn rpc_metrics_classify_status_three_buckets() {
        assert_eq!(classify_status(tonic::Code::Ok), RESULT_SUCCESS);
        assert_eq!(
            classify_status(tonic::Code::DeadlineExceeded),
            RESULT_TIMEOUT,
        );
        assert_eq!(classify_status(tonic::Code::Internal), RESULT_ERROR);
        assert_eq!(classify_status(tonic::Code::Unavailable), RESULT_ERROR);
        assert_eq!(classify_status(tonic::Code::Unauthenticated), RESULT_ERROR,);
    }

    /// The in-flight gauge must increment when an `InFlightGuard` is
    /// created and decrement on `Drop`. Drives the success path
    /// (no early return between `enter` and the implicit drop) and
    /// pins both transitions.
    #[test]
    fn rpc_in_flight_gauge_enters_and_exits_via_guard() {
        ensure_init();
        let before = rpc_in_flight()
            .with_label_values(&[RPC_SEND_ONE_BLOB, "peer-guard-test"])
            .get();
        {
            let _g = InFlightGuard::enter(RPC_SEND_ONE_BLOB, "peer-guard-test");
            let during = rpc_in_flight()
                .with_label_values(&[RPC_SEND_ONE_BLOB, "peer-guard-test"])
                .get();
            assert_eq!(during, before + 1, "guard must increment on enter");
        }
        let after = rpc_in_flight()
            .with_label_values(&[RPC_SEND_ONE_BLOB, "peer-guard-test"])
            .get();
        assert_eq!(after, before, "guard must decrement on drop");
    }
}
