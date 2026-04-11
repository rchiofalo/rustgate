//! Prometheus metrics for rustgate.
//!
//! Exposes counters, gauges, and labels covering connection lifecycle,
//! message routing, NATS bridge, and protocol negotiation. All metrics
//! are registered with the default Prometheus registry and served at
//! `/metrics` via a lightweight hyper HTTP server.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use prometheus::{
    Encoder, Histogram, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge, Opts,
    TextEncoder,
};
use rustgate_core::constants::HTTP_CONNECTION_TIMEOUT;
use serde::Serialize;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Type-erased federation API handler.
///
/// When set, the metrics server delegates requests under `/api/federation/`
/// to this handler. Returns `None` for unrecognized paths so the caller can
/// fall through to 404.
#[cfg(feature = "federation")]
pub type FedApiHandler =
    Arc<dyn Fn(&hyper::Method, &str, &[u8]) -> Option<Response<Full<Bytes>>> + Send + Sync>;

/// Type-erased ACL API handler.
///
/// When set, the metrics server delegates requests under `/api/acl/`
/// to this handler. Returns `None` for unrecognized paths so the caller
/// can fall through to 404.
pub type AclApiHandler = Arc<
    dyn Fn(&hyper::Method, &str, Option<&str>, &[u8]) -> Option<Response<Full<Bytes>>>
        + Send
        + Sync,
>;

/// Maximum concurrent connections to the metrics HTTP server.
/// Bounds memory usage from connection floods against the unauthenticated
/// HTTP endpoint (the TLS listener has its own separate limit).
const MAX_HTTP_CONNECTIONS: usize = 128;

// ── Metric statics ──────────────────────────────────────────────────

static CONNECTIONS_ACCEPTED: OnceLock<IntCounter> = OnceLock::new();
static CONNECTIONS_ACTIVE: OnceLock<IntGauge> = OnceLock::new();
static CONNECTIONS_REJECTED: OnceLock<IntCounter> = OnceLock::new();
static ACCEPT_ERRORS: OnceLock<IntCounter> = OnceLock::new();
static QUEUED_BYTES: OnceLock<IntGauge> = OnceLock::new();
static ADMISSION_DEFERRED_TOTAL: OnceLock<IntCounter> = OnceLock::new();

static MESSAGES_RECEIVED: OnceLock<IntCounter> = OnceLock::new();
static MESSAGES_DROPPED: OnceLock<IntCounterVec> = OnceLock::new();
static MESSAGES_EXPIRED: OnceLock<IntCounter> = OnceLock::new();
static MESSAGES_REPLAYED: OnceLock<IntCounter> = OnceLock::new();
static MESSAGES_ROUTED: OnceLock<IntCounterVec> = OnceLock::new();

static DEDUP_HITS: OnceLock<IntCounter> = OnceLock::new();
static DEDUP_CACHE_SIZE: OnceLock<IntGauge> = OnceLock::new();

static COT_DELTA_FULL: OnceLock<IntCounter> = OnceLock::new();
static COT_DELTA_DELTA: OnceLock<IntCounter> = OnceLock::new();
static COT_DELTA_SUPPRESSED: OnceLock<IntCounter> = OnceLock::new();
static COT_DELTA_BYTES_SAVED: OnceLock<IntCounter> = OnceLock::new();

// Tier 2 (per-identity) metrics. Registered only when
// `--metrics-per-identity` is enabled; remain `None` otherwise so they
// add zero overhead.
static PER_IDENTITY_HANDSHAKE_FAILURES: OnceLock<IntCounterVec> = OnceLock::new();
static PER_IDENTITY_SESSION_DURATION: OnceLock<HistogramVec> = OnceLock::new();
static PER_IDENTITY_BYTES_SENT: OnceLock<IntCounterVec> = OnceLock::new();
static PER_IDENTITY_BYTES_RECEIVED: OnceLock<IntCounterVec> = OnceLock::new();
static SESSIONS_ACTIVE: OnceLock<IntGauge> = OnceLock::new();

static NATS_PUBLISHES: OnceLock<IntCounter> = OnceLock::new();

#[cfg(feature = "nats")]
static NATS_CONSUMER_PENDING: OnceLock<IntGauge> = OnceLock::new();
#[cfg(feature = "nats")]
static NATS_CONSUMER_NUM_REDELIVERED: OnceLock<IntGauge> = OnceLock::new();
#[cfg(feature = "nats")]
static NATS_CONSUMER_ACK_FLOOR_STREAM_SEQ: OnceLock<IntGauge> = OnceLock::new();
#[cfg(feature = "nats")]
static NATS_CONSUMER_INFO_SECONDS: OnceLock<Histogram> = OnceLock::new();

static NEGOTIATIONS: OnceLock<IntCounterVec> = OnceLock::new();

static HANDSHAKE_FAILURES: OnceLock<IntCounterVec> = OnceLock::new();

static CLIENT_OCSP_CACHE_HITS: OnceLock<IntCounter> = OnceLock::new();
static CLIENT_OCSP_CACHE_MISSES: OnceLock<IntCounter> = OnceLock::new();

static CLIENT_QUEUE_DEPTH: OnceLock<prometheus::IntGaugeVec> = OnceLock::new();
static CLIENT_QUEUE_BYTES: OnceLock<prometheus::IntGaugeVec> = OnceLock::new();
static CLIENT_QUEUE_DROPS: OnceLock<IntCounter> = OnceLock::new();
static CLIENT_QUEUE_DRAINS: OnceLock<IntCounter> = OnceLock::new();
static CLIENT_QUEUE_ENQUEUES: OnceLock<IntCounter> = OnceLock::new();
static CLIENT_QUEUE_WRITER_DROPS: OnceLock<IntCounter> = OnceLock::new();
static CLIENT_QUEUE_EXPIRED: OnceLock<IntCounter> = OnceLock::new();
static CLIENT_QUEUE_SKIPPED_UNSUPPORTED: OnceLock<IntCounter> = OnceLock::new();

#[cfg(feature = "federation")]
static FEDERATION_PEER_QUEUE_BYTES: OnceLock<prometheus::IntGaugeVec> = OnceLock::new();
#[cfg(feature = "federation")]
static FEDERATION_PEER_OLDEST_SECONDS: OnceLock<prometheus::IntGaugeVec> = OnceLock::new();

static AUTHZ_DECISIONS: OnceLock<IntCounterVec> = OnceLock::new();
static AUTHZ_EVAL_NANOS: OnceLock<Histogram> = OnceLock::new();
static AUTHZ_RELOADS: OnceLock<IntCounterVec> = OnceLock::new();
static AUTHZ_POLICY_RULES: OnceLock<IntGauge> = OnceLock::new();
static AUTHZ_CACHE_HITS: OnceLock<IntCounter> = OnceLock::new();
static AUTHZ_CACHE_MISSES: OnceLock<IntCounter> = OnceLock::new();

static ARCHIVE_BYTES: OnceLock<IntGauge> = OnceLock::new();
static ENROLLMENT_RATE_LIMITED: OnceLock<IntCounter> = OnceLock::new();

#[cfg(feature = "spiffe")]
static SPIFFE_SVID_REFRESH_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();
#[cfg(feature = "spiffe")]
static SPIFFE_SVID_EXPIRY_SECONDS: OnceLock<IntGauge> = OnceLock::new();

#[cfg(feature = "jemalloc")]
static JEMALLOC_RESIDENT: OnceLock<IntGauge> = OnceLock::new();
#[cfg(feature = "jemalloc")]
static JEMALLOC_ACTIVE: OnceLock<IntGauge> = OnceLock::new();
#[cfg(feature = "jemalloc")]
static JEMALLOC_ALLOCATED: OnceLock<IntGauge> = OnceLock::new();
#[cfg(feature = "jemalloc")]
static JEMALLOC_MAPPED: OnceLock<IntGauge> = OnceLock::new();

// ── Fallback constructors ───────────────────────────────────────────
//
// When `init()` has not been called, accessor functions lazily create
// an unregistered metric via `OnceLock::get_or_init()`. These helpers
// construct the fallback without `unwrap()` or `expect()`.

fn fallback_counter(name: &str, help: &str) -> IntCounter {
    match IntCounter::with_opts(Opts::new(name, help)) {
        Ok(c) => c,
        // Hardcoded metric names are always valid; this branch is unreachable.
        // If prometheus is fundamentally broken, abort cleanly rather than panic.
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

// ── Registration ────────────────────────────────────────────────────

/// Register all metrics with the default Prometheus registry.
/// Must be called once at startup before any metrics are recorded.
pub fn init() -> prometheus::Result<()> {
    let registry = prometheus::default_registry();

    let connections_accepted = IntCounter::with_opts(Opts::new(
        "rustgate_connections_accepted_total",
        "Total TLS connections accepted",
    ))?;
    registry.register(Box::new(connections_accepted.clone()))?;
    let _ = CONNECTIONS_ACCEPTED.set(connections_accepted);

    let connections_active = IntGauge::with_opts(Opts::new(
        "rustgate_connections_active",
        "Currently active TLS connections",
    ))?;
    registry.register(Box::new(connections_active.clone()))?;
    let _ = CONNECTIONS_ACTIVE.set(connections_active);

    let connections_rejected = IntCounter::with_opts(Opts::new(
        "rustgate_connections_rejected_total",
        "Connections rejected due to limit",
    ))?;
    registry.register(Box::new(connections_rejected.clone()))?;
    let _ = CONNECTIONS_REJECTED.set(connections_rejected);

    let accept_errors = IntCounter::with_opts(Opts::new(
        "rustgate_accept_errors_total",
        "TLS accept errors",
    ))?;
    registry.register(Box::new(accept_errors.clone()))?;
    let _ = ACCEPT_ERRORS.set(accept_errors);

    let queued_bytes = IntGauge::with_opts(Opts::new(
        "rustgate_queued_bytes",
        "Current in-flight queued bytes tracked by the admission-control gate",
    ))?;
    registry.register(Box::new(queued_bytes.clone()))?;
    let _ = QUEUED_BYTES.set(queued_bytes);

    let admission_deferred_total = IntCounter::with_opts(Opts::new(
        "rustgate_admission_deferred_total",
        "Number of times the TLS accept loop was deferred due to backpressure",
    ))?;
    registry.register(Box::new(admission_deferred_total.clone()))?;
    let _ = ADMISSION_DEFERRED_TOTAL.set(admission_deferred_total);

    let messages_received = IntCounter::with_opts(Opts::new(
        "rustgate_messages_received_total",
        "Total CoT messages received from clients",
    ))?;
    registry.register(Box::new(messages_received.clone()))?;
    let _ = MESSAGES_RECEIVED.set(messages_received);

    let messages_dropped = IntCounterVec::new(
        Opts::new(
            "rustgate_messages_dropped_total",
            "Messages dropped due to per-client rate limiting",
        ),
        &["identity_cn"],
    )?;
    registry.register(Box::new(messages_dropped.clone()))?;
    let _ = MESSAGES_DROPPED.set(messages_dropped);

    let messages_expired = IntCounter::with_opts(Opts::new(
        "rustgate_messages_expired_total",
        "Messages dropped due to TTL expiration before delivery",
    ))?;
    registry.register(Box::new(messages_expired.clone()))?;
    let _ = MESSAGES_EXPIRED.set(messages_expired);

    let messages_replayed = IntCounter::with_opts(Opts::new(
        "rustgate_messages_replayed_total",
        "Messages dropped due to anti-replay detection",
    ))?;
    registry.register(Box::new(messages_replayed.clone()))?;
    let _ = MESSAGES_REPLAYED.set(messages_replayed);

    let dedup_hits = IntCounter::with_opts(Opts::new(
        "rustgate_dedup_hits_total",
        "Cross-path duplicate messages suppressed before dispatch",
    ))?;
    registry.register(Box::new(dedup_hits.clone()))?;
    let _ = DEDUP_HITS.set(dedup_hits);

    let dedup_cache_size = IntGauge::with_opts(Opts::new(
        "rustgate_dedup_cache_size",
        "Current number of entries in the cross-path dedup cache",
    ))?;
    registry.register(Box::new(dedup_cache_size.clone()))?;
    let _ = DEDUP_CACHE_SIZE.set(dedup_cache_size);

    let cot_delta_full = IntCounter::with_opts(Opts::new(
        "rustgate_cot_delta_full_total",
        "Outbound CoT events emitted as full by the per-UID delta encoder",
    ))?;
    registry.register(Box::new(cot_delta_full.clone()))?;
    let _ = COT_DELTA_FULL.set(cot_delta_full);

    let cot_delta_delta = IntCounter::with_opts(Opts::new(
        "rustgate_cot_delta_delta_total",
        "Outbound CoT events emitted as deltas by the per-UID delta encoder",
    ))?;
    registry.register(Box::new(cot_delta_delta.clone()))?;
    let _ = COT_DELTA_DELTA.set(cot_delta_delta);

    let cot_delta_suppressed = IntCounter::with_opts(Opts::new(
        "rustgate_cot_delta_suppressed_total",
        "Outbound CoT events suppressed by the per-UID delta encoder (sub-epsilon drift, no field change)",
    ))?;
    registry.register(Box::new(cot_delta_suppressed.clone()))?;
    let _ = COT_DELTA_SUPPRESSED.set(cot_delta_suppressed);

    let cot_delta_bytes_saved = IntCounter::with_opts(Opts::new(
        "rustgate_cot_delta_bytes_saved_total",
        "Total bytes saved by the per-UID delta encoder (full_len - delta_len per emitted delta)",
    ))?;
    registry.register(Box::new(cot_delta_bytes_saved.clone()))?;
    let _ = COT_DELTA_BYTES_SAVED.set(cot_delta_bytes_saved);

    let messages_routed = IntCounterVec::new(
        Opts::new(
            "rustgate_messages_routed_total",
            "Messages routed by destination type and source identity",
        ),
        &["destination", "identity_cn"],
    )?;
    registry.register(Box::new(messages_routed.clone()))?;
    let _ = MESSAGES_ROUTED.set(messages_routed);

    let sessions_active = IntGauge::with_opts(Opts::new(
        "rustgate_sessions_active",
        "Registered sessions in the router",
    ))?;
    registry.register(Box::new(sessions_active.clone()))?;
    let _ = SESSIONS_ACTIVE.set(sessions_active);

    let nats_publishes = IntCounter::with_opts(Opts::new(
        "rustgate_nats_publishes_total",
        "Messages published to NATS",
    ))?;
    registry.register(Box::new(nats_publishes.clone()))?;
    let _ = NATS_PUBLISHES.set(nats_publishes);

    #[cfg(feature = "nats")]
    {
        let pending = IntGauge::with_opts(Opts::new(
            "rustgate_nats_consumer_pending",
            "JetStream pull-consumer messages pending delivery (num_pending)",
        ))?;
        registry.register(Box::new(pending.clone()))?;
        let _ = NATS_CONSUMER_PENDING.set(pending);

        let redelivered = IntGauge::with_opts(Opts::new(
            "rustgate_nats_consumer_num_redelivered",
            "JetStream pull-consumer messages currently in a redelivered state (num_redelivered)",
        ))?;
        registry.register(Box::new(redelivered.clone()))?;
        let _ = NATS_CONSUMER_NUM_REDELIVERED.set(redelivered);

        let ack_floor = IntGauge::with_opts(Opts::new(
            "rustgate_nats_consumer_ack_floor_stream_seq",
            "JetStream pull-consumer ack floor stream sequence (ack_floor.stream_seq)",
        ))?;
        registry.register(Box::new(ack_floor.clone()))?;
        let _ = NATS_CONSUMER_ACK_FLOOR_STREAM_SEQ.set(ack_floor);

        let info_seconds = Histogram::with_opts(HistogramOpts::new(
            "rustgate_nats_consumer_info_seconds",
            "Latency of JetStream pull-consumer info() poll calls in seconds",
        ))?;
        registry.register(Box::new(info_seconds.clone()))?;
        let _ = NATS_CONSUMER_INFO_SECONDS.set(info_seconds);
    }

    let negotiations = IntCounterVec::new(
        Opts::new(
            "rustgate_negotiations_total",
            "Protocol negotiations by result",
        ),
        &["result"],
    )?;
    registry.register(Box::new(negotiations.clone()))?;
    let _ = NEGOTIATIONS.set(negotiations);

    let handshake_failures = IntCounterVec::new(
        Opts::new(
            "rustgate_handshake_failures_total",
            "TLS handshake failures by reason",
        ),
        &["reason"],
    )?;
    registry.register(Box::new(handshake_failures.clone()))?;
    let _ = HANDSHAKE_FAILURES.set(handshake_failures);

    let client_ocsp_cache_hits = IntCounter::with_opts(Opts::new(
        "rustgate_client_ocsp_cache_hits_total",
        "Client certificate OCSP cache hits (cached good or revoked status served)",
    ))?;
    registry.register(Box::new(client_ocsp_cache_hits.clone()))?;
    let _ = CLIENT_OCSP_CACHE_HITS.set(client_ocsp_cache_hits);

    let client_ocsp_cache_misses = IntCounter::with_opts(Opts::new(
        "rustgate_client_ocsp_cache_misses_total",
        "Client certificate OCSP cache misses (background fetch dispatched)",
    ))?;
    registry.register(Box::new(client_ocsp_cache_misses.clone()))?;
    let _ = CLIENT_OCSP_CACHE_MISSES.set(client_ocsp_cache_misses);

    let client_queue_depth = prometheus::IntGaugeVec::new(
        Opts::new(
            "rustgate_client_queue_depth",
            "Current number of messages queued for store-and-forward per CN (bucketed)",
        ),
        &["identity_cn"],
    )?;
    registry.register(Box::new(client_queue_depth.clone()))?;
    let _ = CLIENT_QUEUE_DEPTH.set(client_queue_depth);

    let client_queue_bytes = prometheus::IntGaugeVec::new(
        Opts::new(
            "rustgate_client_queue_bytes",
            "Current encoded bytes queued for store-and-forward per CN (bucketed)",
        ),
        &["identity_cn"],
    )?;
    registry.register(Box::new(client_queue_bytes.clone()))?;
    let _ = CLIENT_QUEUE_BYTES.set(client_queue_bytes);

    let client_queue_drops = IntCounter::with_opts(Opts::new(
        "rustgate_client_queue_drops_total",
        "Total messages dropped from the client store-and-forward queue (cap eviction)",
    ))?;
    registry.register(Box::new(client_queue_drops.clone()))?;
    let _ = CLIENT_QUEUE_DROPS.set(client_queue_drops);

    let client_queue_drains = IntCounter::with_opts(Opts::new(
        "rustgate_client_queue_drains_total",
        "Total successful client store-and-forward drain operations",
    ))?;
    registry.register(Box::new(client_queue_drains.clone()))?;
    let _ = CLIENT_QUEUE_DRAINS.set(client_queue_drains);

    let client_queue_enqueues = IntCounter::with_opts(Opts::new(
        "rustgate_client_queue_enqueues_total",
        "Total messages successfully submitted to the client store-and-forward writer",
    ))?;
    registry.register(Box::new(client_queue_enqueues.clone()))?;
    let _ = CLIENT_QUEUE_ENQUEUES.set(client_queue_enqueues);

    let client_queue_writer_drops = IntCounter::with_opts(Opts::new(
        "rustgate_client_queue_writer_drops_total",
        "Messages dropped because the async writer channel was full or closed",
    ))?;
    registry.register(Box::new(client_queue_writer_drops.clone()))?;
    let _ = CLIENT_QUEUE_WRITER_DROPS.set(client_queue_writer_drops);

    let client_queue_expired = IntCounter::with_opts(Opts::new(
        "rustgate_client_queue_expired_total",
        "Queued messages skipped during drain because their TTL had elapsed",
    ))?;
    registry.register(Box::new(client_queue_expired.clone()))?;
    let _ = CLIENT_QUEUE_EXPIRED.set(client_queue_expired);

    let client_queue_skipped_unsupported = IntCounter::with_opts(Opts::new(
        "rustgate_client_queue_skipped_unsupported_total",
        "Queue entries skipped on reopen because destination was not direct (broadcast/group)",
    ))?;
    registry.register(Box::new(client_queue_skipped_unsupported.clone()))?;
    let _ = CLIENT_QUEUE_SKIPPED_UNSUPPORTED.set(client_queue_skipped_unsupported);

    #[cfg(feature = "federation")]
    {
        let federation_peer_queue_bytes = prometheus::IntGaugeVec::new(
            Opts::new(
                "rustgate_federation_peer_queue_bytes",
                "Bytes currently queued for delivery to a federation peer",
            ),
            &["peer"],
        )?;
        registry.register(Box::new(federation_peer_queue_bytes.clone()))?;
        let _ = FEDERATION_PEER_QUEUE_BYTES.set(federation_peer_queue_bytes);

        let federation_peer_oldest_seconds = prometheus::IntGaugeVec::new(
            Opts::new(
                "rustgate_federation_peer_oldest_seconds",
                "Age in seconds of the oldest message still queued for a federation peer",
            ),
            &["peer"],
        )?;
        registry.register(Box::new(federation_peer_oldest_seconds.clone()))?;
        let _ = FEDERATION_PEER_OLDEST_SECONDS.set(federation_peer_oldest_seconds);
    }

    let archive_bytes = IntGauge::with_opts(Opts::new(
        "rustgate_archive_bytes",
        "Total bytes currently held in the CoT event archive directory",
    ))?;
    registry.register(Box::new(archive_bytes.clone()))?;
    let _ = ARCHIVE_BYTES.set(archive_bytes);

    let enrollment_rate_limited = IntCounter::with_opts(Opts::new(
        "rustgate_enrollment_rate_limited_total",
        "CSR signing requests rejected by the per-IP rate limiter",
    ))?;
    registry.register(Box::new(enrollment_rate_limited.clone()))?;
    let _ = ENROLLMENT_RATE_LIMITED.set(enrollment_rate_limited);

    let authz_decisions = IntCounterVec::new(
        Opts::new(
            "rustgate_authz_decisions_total",
            "Authz decisions emitted by the router PEP, labelled by action and decision",
        ),
        &["action", "decision"],
    )?;
    registry.register(Box::new(authz_decisions.clone()))?;
    let _ = AUTHZ_DECISIONS.set(authz_decisions);

    // Bucket floor is 50 ns: the native engine's measured P99 on a
    // single rule is ~80 ns, and we need at least one bucket below
    // that so the dashboards and the P99 SLO test are not all
    // crammed into the first bucket. The ceiling stays at 100 µs to
    // catch pathological slow decisions. 10 µs is the documented
    // SLO — `histogram_quantile(0.99, …) <= 10_000` is the gate.
    let authz_eval_nanos = Histogram::with_opts(
        HistogramOpts::new(
            "rustgate_authz_eval_nanos",
            "Authz policy evaluation duration in nanoseconds",
        )
        .buckets(vec![
            50.0, 100.0, 250.0, 500.0, 1_000.0, 2_500.0, 10_000.0, 100_000.0,
        ]),
    )?;
    registry.register(Box::new(authz_eval_nanos.clone()))?;
    let _ = AUTHZ_EVAL_NANOS.set(authz_eval_nanos);

    let authz_reloads = IntCounterVec::new(
        Opts::new(
            "rustgate_authz_reloads_total",
            "Authz policy reload outcomes, labelled by result",
        ),
        &["result"],
    )?;
    registry.register(Box::new(authz_reloads.clone()))?;
    let _ = AUTHZ_RELOADS.set(authz_reloads);

    let authz_policy_rules = IntGauge::with_opts(Opts::new(
        "rustgate_authz_policy_rules",
        "Number of rules in the currently installed authz policy",
    ))?;
    registry.register(Box::new(authz_policy_rules.clone()))?;
    let _ = AUTHZ_POLICY_RULES.set(authz_policy_rules);

    let authz_cache_hits = IntCounter::with_opts(Opts::new(
        "rustgate_authz_cache_hits_total",
        "Authz decision-cache lookups that returned a cached outcome",
    ))?;
    registry.register(Box::new(authz_cache_hits.clone()))?;
    let _ = AUTHZ_CACHE_HITS.set(authz_cache_hits);

    let authz_cache_misses = IntCounter::with_opts(Opts::new(
        "rustgate_authz_cache_misses_total",
        "Authz decision-cache lookups that ran the full scan and populated the cache",
    ))?;
    registry.register(Box::new(authz_cache_misses.clone()))?;
    let _ = AUTHZ_CACHE_MISSES.set(authz_cache_misses);

    #[cfg(feature = "jemalloc")]
    {
        let jemalloc_resident = IntGauge::with_opts(Opts::new(
            "rustgate_jemalloc_resident_bytes",
            "jemalloc resident memory in bytes (RSS attributed to the allocator)",
        ))?;
        registry.register(Box::new(jemalloc_resident.clone()))?;
        let _ = JEMALLOC_RESIDENT.set(jemalloc_resident);

        let jemalloc_active = IntGauge::with_opts(Opts::new(
            "rustgate_jemalloc_active_bytes",
            "jemalloc active memory in bytes (allocated pages that back application data)",
        ))?;
        registry.register(Box::new(jemalloc_active.clone()))?;
        let _ = JEMALLOC_ACTIVE.set(jemalloc_active);

        let jemalloc_allocated = IntGauge::with_opts(Opts::new(
            "rustgate_jemalloc_allocated_bytes",
            "jemalloc allocated memory in bytes (application-requested allocations)",
        ))?;
        registry.register(Box::new(jemalloc_allocated.clone()))?;
        let _ = JEMALLOC_ALLOCATED.set(jemalloc_allocated);

        let jemalloc_mapped = IntGauge::with_opts(Opts::new(
            "rustgate_jemalloc_mapped_bytes",
            "jemalloc mapped memory in bytes (total virtual memory mapped by the allocator)",
        ))?;
        registry.register(Box::new(jemalloc_mapped.clone()))?;
        let _ = JEMALLOC_MAPPED.set(jemalloc_mapped);
    }

    Ok(())
}

fn fallback_histogram(name: &str, help: &str) -> Histogram {
    match Histogram::with_opts(HistogramOpts::new(name, help)) {
        Ok(h) => h,
        Err(_) => std::process::abort(),
    }
}

/// Observe an authz evaluation event emitted by the router PEP.
///
/// Installed as the router's `AuthzObserver` at startup so every Allow
/// and Deny decision increments the decisions counter and records the
/// evaluation latency histogram.
///
/// Both match statements include a wildcard `_` arm to satisfy the
/// `#[non_exhaustive]` contract on [`rustgate_authz::Action`] and
/// [`rustgate_authz::Decision`]: the authz crate may add new variants
/// in future releases without making this a breaking change, and we
/// degrade to a neutral `"unknown"` label rather than failing the
/// metric update so the decision counter never drops events.
pub fn observe_authz_event(ev: &rustgate_transport::AuthzEvent<'_>) {
    let action = match ev.action {
        rustgate_authz::Action::Send => "send",
        rustgate_authz::Action::Receive => "receive",
        rustgate_authz::Action::Federate => "federate",
        rustgate_authz::Action::Publish => "publish",
        rustgate_authz::Action::Subscribe => "subscribe",
        _ => "unknown",
    };
    let decision = match ev.decision {
        rustgate_authz::Decision::Allow => "allow",
        rustgate_authz::Decision::Deny => "deny",
        _ => "unknown",
    };
    if let Ok(child) = authz_decisions().get_metric_with_label_values(&[action, decision]) {
        child.inc();
    }
    authz_eval_nanos().observe(ev.eval_nanos as f64);
}

/// Record an authz policy reload outcome and update the rule-count gauge.
pub fn record_authz_reload(success: bool, rule_count: Option<usize>) {
    let label = if success { "success" } else { "failure" };
    if let Ok(child) = authz_reloads().get_metric_with_label_values(&[label]) {
        child.inc();
    }
    if let Some(n) = rule_count {
        authz_policy_rules().set(i64::try_from(n).unwrap_or(i64::MAX));
    }
}

pub fn authz_decisions() -> &'static IntCounterVec {
    AUTHZ_DECISIONS.get_or_init(|| {
        fallback_counter_vec(
            "rustgate_authz_decisions_total",
            "fallback",
            &["action", "decision"],
        )
    })
}

pub fn authz_eval_nanos() -> &'static Histogram {
    AUTHZ_EVAL_NANOS.get_or_init(|| fallback_histogram("rustgate_authz_eval_nanos", "fallback"))
}

pub fn authz_reloads() -> &'static IntCounterVec {
    AUTHZ_RELOADS.get_or_init(|| {
        fallback_counter_vec("rustgate_authz_reloads_total", "fallback", &["result"])
    })
}

pub fn authz_policy_rules() -> &'static IntGauge {
    AUTHZ_POLICY_RULES.get_or_init(|| fallback_gauge("rustgate_authz_policy_rules", "fallback"))
}

pub fn authz_cache_hits() -> &'static IntCounter {
    AUTHZ_CACHE_HITS.get_or_init(|| fallback_counter("rustgate_authz_cache_hits_total", "fallback"))
}

pub fn authz_cache_misses() -> &'static IntCounter {
    AUTHZ_CACHE_MISSES
        .get_or_init(|| fallback_counter("rustgate_authz_cache_misses_total", "fallback"))
}

/// Record a delta of authz decision-cache hits/misses. Called on a timer
/// from the background cache-stats scraper in `main.rs`.
pub fn record_authz_cache_stats(hits_delta: u64, misses_delta: u64) {
    if hits_delta > 0 {
        authz_cache_hits().inc_by(hits_delta);
    }
    if misses_delta > 0 {
        authz_cache_misses().inc_by(misses_delta);
    }
}

/// Returns the federation per-peer queue-bytes gauge vector.
#[cfg(feature = "federation")]
#[allow(dead_code)] // exposed for future API consumers / tests
pub fn federation_peer_queue_bytes() -> Option<&'static prometheus::IntGaugeVec> {
    FEDERATION_PEER_QUEUE_BYTES.get()
}

/// Returns the federation per-peer oldest-message-age gauge vector.
#[cfg(feature = "federation")]
#[allow(dead_code)] // exposed for future API consumers / tests
pub fn federation_peer_oldest_seconds() -> Option<&'static prometheus::IntGaugeVec> {
    FEDERATION_PEER_OLDEST_SECONDS.get()
}

/// Spawn a background task that periodically snapshots per-peer federation
/// lag from the manager and publishes it to the Prometheus gauges.
///
/// The task runs until the provided shutdown signal fires. It is a no-op
/// if the gauges were never registered.
#[cfg(feature = "federation")]
pub fn spawn_federation_lag_updater(
    manager: std::sync::Arc<tokio::sync::RwLock<rustgate_federation::manager::FederationManager>>,
    interval: std::time::Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut known_peers: std::collections::HashSet<String> = std::collections::HashSet::new();
        loop {
            let _ = ticker.tick().await;
            let snapshot = {
                let guard = manager.read().await;
                guard.peer_lag_snapshot()
            };
            let bytes_vec = FEDERATION_PEER_QUEUE_BYTES.get();
            let oldest_vec = FEDERATION_PEER_OLDEST_SECONDS.get();
            let mut current: std::collections::HashSet<String> = std::collections::HashSet::new();
            for (peer, bytes, oldest) in &snapshot {
                let _ = current.insert(peer.clone());
                if let Some(g) = bytes_vec
                    && let Ok(child) = g.get_metric_with_label_values(&[peer.as_str()])
                {
                    child.set(*bytes as i64);
                }
                if let Some(g) = oldest_vec
                    && let Ok(child) = g.get_metric_with_label_values(&[peer.as_str()])
                {
                    child.set(oldest.round() as i64);
                }
            }
            for stale in known_peers.difference(&current) {
                if let Some(g) = bytes_vec {
                    let _ = g.remove_label_values(&[stale.as_str()]);
                }
                if let Some(g) = oldest_vec {
                    let _ = g.remove_label_values(&[stale.as_str()]);
                }
            }
            known_peers = current;
        }
    })
}

/// Returns the archive-bytes gauge (current total size of the CoT
/// archive directory, refreshed by the rotation task).
pub fn archive_bytes() -> &'static IntGauge {
    ARCHIVE_BYTES.get_or_init(|| fallback_gauge("rustgate_archive_bytes", "fallback"))
}

// ── Accessor functions ──────────────────────────────────────────────
//
// Each accessor returns a reference to the registered metric. If
// `init()` has not been called, `get_or_init()` lazily creates an
// unregistered metric that absorbs increments without effect. This
// eliminates panics from initialization-order races without adding
// Option propagation to every call site.

pub fn connections_accepted() -> &'static IntCounter {
    CONNECTIONS_ACCEPTED
        .get_or_init(|| fallback_counter("rustgate_connections_accepted_total", "fallback"))
}

pub fn connections_active() -> &'static IntGauge {
    CONNECTIONS_ACTIVE.get_or_init(|| fallback_gauge("rustgate_connections_active", "fallback"))
}

pub fn connections_rejected() -> &'static IntCounter {
    CONNECTIONS_REJECTED
        .get_or_init(|| fallback_counter("rustgate_connections_rejected_total", "fallback"))
}

pub fn accept_errors() -> &'static IntCounter {
    ACCEPT_ERRORS.get_or_init(|| fallback_counter("rustgate_accept_errors_total", "fallback"))
}

pub fn queued_bytes() -> &'static IntGauge {
    QUEUED_BYTES.get_or_init(|| fallback_gauge("rustgate_queued_bytes", "fallback"))
}

pub fn admission_deferred_total() -> &'static IntCounter {
    ADMISSION_DEFERRED_TOTAL
        .get_or_init(|| fallback_counter("rustgate_admission_deferred_total", "fallback"))
}

pub fn messages_received() -> &'static IntCounter {
    MESSAGES_RECEIVED
        .get_or_init(|| fallback_counter("rustgate_messages_received_total", "fallback"))
}

pub fn messages_dropped() -> &'static IntCounterVec {
    MESSAGES_DROPPED.get_or_init(|| {
        fallback_counter_vec(
            "rustgate_messages_dropped_total",
            "fallback",
            &["identity_cn"],
        )
    })
}

#[allow(dead_code)] // wired when router TTL drops are observed from the session layer
pub fn messages_expired() -> &'static IntCounter {
    MESSAGES_EXPIRED.get_or_init(|| fallback_counter("rustgate_messages_expired_total", "fallback"))
}

pub fn messages_replayed() -> &'static IntCounter {
    MESSAGES_REPLAYED
        .get_or_init(|| fallback_counter("rustgate_messages_replayed_total", "fallback"))
}

pub fn dedup_hits() -> &'static IntCounter {
    DEDUP_HITS.get_or_init(|| fallback_counter("rustgate_dedup_hits_total", "fallback"))
}

pub fn dedup_cache_size() -> &'static IntGauge {
    DEDUP_CACHE_SIZE.get_or_init(|| fallback_gauge("rustgate_dedup_cache_size", "fallback"))
}

pub fn cot_delta_full() -> &'static IntCounter {
    COT_DELTA_FULL.get_or_init(|| fallback_counter("rustgate_cot_delta_full_total", "fallback"))
}

pub fn cot_delta_delta() -> &'static IntCounter {
    COT_DELTA_DELTA.get_or_init(|| fallback_counter("rustgate_cot_delta_delta_total", "fallback"))
}

pub fn cot_delta_suppressed() -> &'static IntCounter {
    COT_DELTA_SUPPRESSED
        .get_or_init(|| fallback_counter("rustgate_cot_delta_suppressed_total", "fallback"))
}

pub fn cot_delta_bytes_saved() -> &'static IntCounter {
    COT_DELTA_BYTES_SAVED
        .get_or_init(|| fallback_counter("rustgate_cot_delta_bytes_saved_total", "fallback"))
}

pub fn messages_routed() -> &'static IntCounterVec {
    MESSAGES_ROUTED.get_or_init(|| {
        fallback_counter_vec(
            "rustgate_messages_routed_total",
            "fallback",
            &["destination", "identity_cn"],
        )
    })
}

pub fn sessions_active() -> &'static IntGauge {
    SESSIONS_ACTIVE.get_or_init(|| fallback_gauge("rustgate_sessions_active", "fallback"))
}

pub fn nats_publishes() -> &'static IntCounter {
    NATS_PUBLISHES.get_or_init(|| fallback_counter("rustgate_nats_publishes_total", "fallback"))
}

/// Returns the JetStream consumer `num_pending` gauge if registered.
#[cfg(feature = "nats")]
pub fn nats_consumer_pending() -> Option<&'static IntGauge> {
    NATS_CONSUMER_PENDING.get()
}

/// Returns the JetStream consumer `num_redelivered` gauge if registered.
#[cfg(feature = "nats")]
pub fn nats_consumer_num_redelivered() -> Option<&'static IntGauge> {
    NATS_CONSUMER_NUM_REDELIVERED.get()
}

/// Returns the JetStream consumer `ack_floor.stream_seq` gauge if registered.
#[cfg(feature = "nats")]
pub fn nats_consumer_ack_floor_stream_seq() -> Option<&'static IntGauge> {
    NATS_CONSUMER_ACK_FLOOR_STREAM_SEQ.get()
}

/// Returns the JetStream `consumer.info()` poll latency histogram if registered.
#[cfg(feature = "nats")]
pub fn nats_consumer_info_seconds() -> Option<&'static Histogram> {
    NATS_CONSUMER_INFO_SECONDS.get()
}

#[allow(dead_code)] // only used when `proto` feature enables TAK negotiation
pub fn negotiations() -> &'static IntCounterVec {
    NEGOTIATIONS.get_or_init(|| {
        fallback_counter_vec("rustgate_negotiations_total", "fallback", &["result"])
    })
}

pub fn handshake_failures() -> &'static IntCounterVec {
    HANDSHAKE_FAILURES.get_or_init(|| {
        fallback_counter_vec("rustgate_handshake_failures_total", "fallback", &["reason"])
    })
}

/// Counter for SPIFFE X.509-SVID refresh outcomes, labelled by
/// `outcome="success"` or `outcome="failure"`. Incremented by the refresh
/// task each time the Workload API is polled.
#[cfg(feature = "spiffe")]
pub fn spiffe_refresh_total() -> &'static IntCounterVec {
    SPIFFE_SVID_REFRESH_TOTAL.get_or_init(|| {
        fallback_counter_vec(
            "rustgate_spiffe_svid_refresh_total",
            "SPIFFE SVID refresh attempts by outcome",
            &["outcome"],
        )
    })
}

/// Gauge tracking the unix-seconds expiry (`notAfter`) of the active
/// SPIFFE X.509-SVID leaf certificate. Updated whenever the refresh task
/// rotates the SVID.
#[cfg(feature = "spiffe")]
pub fn spiffe_svid_expiry_seconds() -> &'static IntGauge {
    SPIFFE_SVID_EXPIRY_SECONDS.get_or_init(|| {
        fallback_gauge(
            "rustgate_spiffe_svid_expiry_seconds",
            "Active SPIFFE SVID leaf notAfter (unix seconds)",
        )
    })
}

/// Refresh jemalloc memory statistics gauges.
///
/// Advances the jemalloc epoch (so cached stats become current) and then
/// reads resident, active, allocated, and mapped byte counts via
/// `tikv-jemalloc-ctl`'s safe API. Any individual stat that fails to read
/// is silently skipped — partial updates are still useful.
#[cfg(feature = "jemalloc")]
pub fn refresh_jemalloc_stats() {
    // Epoch must be advanced before reading; stale cached values are
    // returned otherwise. Ignore errors — stats will be stale but not
    // absent.
    let _ = tikv_jemalloc_ctl::epoch::advance();

    if let Some(g) = JEMALLOC_RESIDENT.get() {
        if let Ok(v) = tikv_jemalloc_ctl::stats::resident::read() {
            g.set(i64::try_from(v).unwrap_or(i64::MAX));
        }
    }
    if let Some(g) = JEMALLOC_ACTIVE.get() {
        if let Ok(v) = tikv_jemalloc_ctl::stats::active::read() {
            g.set(i64::try_from(v).unwrap_or(i64::MAX));
        }
    }
    if let Some(g) = JEMALLOC_ALLOCATED.get() {
        if let Ok(v) = tikv_jemalloc_ctl::stats::allocated::read() {
            g.set(i64::try_from(v).unwrap_or(i64::MAX));
        }
    }
    if let Some(g) = JEMALLOC_MAPPED.get() {
        if let Ok(v) = tikv_jemalloc_ctl::stats::mapped::read() {
            g.set(i64::try_from(v).unwrap_or(i64::MAX));
        }
    }
}

/// Returns the client-cert OCSP cache hit counter.
#[allow(dead_code)] // only referenced when the `ocsp` feature is enabled
pub fn client_ocsp_cache_hits() -> Option<&'static IntCounter> {
    CLIENT_OCSP_CACHE_HITS.get()
}

/// Returns the client-cert OCSP cache miss counter.
#[allow(dead_code)] // only referenced when the `ocsp` feature is enabled
pub fn client_ocsp_cache_misses() -> Option<&'static IntCounter> {
    CLIENT_OCSP_CACHE_MISSES.get()
}

/// Counter for CSR signing requests rejected by the enrollment server's
/// per-IP rate limiter. Wired from a callback registered on
/// `EnrollmentServer` in `setup::start_enrollment`.
#[cfg(feature = "enrollment")]
pub fn enrollment_rate_limited() -> &'static IntCounter {
    ENROLLMENT_RATE_LIMITED
        .get_or_init(|| fallback_counter("rustgate_enrollment_rate_limited_total", "fallback"))
}

/// Returns the client-queue depth gauge vector (Tier 1, registered
/// only when `init()` succeeded).
pub fn client_queue_depth() -> Option<&'static prometheus::IntGaugeVec> {
    CLIENT_QUEUE_DEPTH.get()
}

/// Returns the client-queue byte-usage gauge vector.
pub fn client_queue_bytes() -> Option<&'static prometheus::IntGaugeVec> {
    CLIENT_QUEUE_BYTES.get()
}

/// Returns the client-queue drop counter.
pub fn client_queue_drops() -> Option<&'static IntCounter> {
    CLIENT_QUEUE_DROPS.get()
}

/// Returns the client-queue drain counter.
pub fn client_queue_drains() -> Option<&'static IntCounter> {
    CLIENT_QUEUE_DRAINS.get()
}

/// Returns the client-queue enqueues counter.
pub fn client_queue_enqueues() -> Option<&'static IntCounter> {
    CLIENT_QUEUE_ENQUEUES.get()
}

/// Returns the client-queue async writer overflow/close drop counter.
pub fn client_queue_writer_drops() -> Option<&'static IntCounter> {
    CLIENT_QUEUE_WRITER_DROPS.get()
}

/// Returns the client-queue TTL-expired-on-drain counter.
pub fn client_queue_expired() -> Option<&'static IntCounter> {
    CLIENT_QUEUE_EXPIRED.get()
}

/// Returns the client-queue skipped-non-direct-on-reopen counter.
pub fn client_queue_skipped_unsupported() -> Option<&'static IntCounter> {
    CLIENT_QUEUE_SKIPPED_UNSUPPORTED.get()
}

/// Spawn a background task that periodically samples the given client
/// queue and updates the Prometheus metrics. CN labels are bucketed
/// against `identity` to bound label cardinality.
///
/// The task exits when the queue's last `Arc` reference is dropped.
pub fn spawn_client_queue_metrics_task(
    queue: Arc<rustgate_transport::ClientQueue>,
    identity: Arc<MetricsIdentity>,
) {
    use std::collections::HashMap;
    drop(tokio::spawn(async move {
        let mut last_drops: u64 = 0;
        let mut last_drains: u64 = 0;
        let mut last_enqueues: u64 = 0;
        let mut last_writer_drops: u64 = 0;
        let mut last_expired: u64 = 0;
        let mut last_skipped: u64 = 0;
        let mut ticker = tokio::time::interval(Duration::from_secs(5));
        loop {
            let _ = ticker.tick().await;
            if Arc::strong_count(&queue) == 1 {
                return;
            }
            // Aggregate per-bucket depth/bytes across every CN that
            // currently has queued entries. CNs not in the allowlist
            // are bucketed under the "other" label, matching the Tier
            // 2 per-identity cardinality guarantees.
            let snapshot = queue.snapshot();
            let mut bucket_depth: HashMap<String, i64> = HashMap::new();
            let mut bucket_bytes: HashMap<String, i64> = HashMap::new();
            for (cn, stats) in &snapshot {
                let label = identity.bucket(cn).to_string();
                *bucket_depth.entry(label.clone()).or_insert(0) += stats.depth as i64;
                *bucket_bytes.entry(label).or_insert(0) += stats.bytes as i64;
            }
            if let Some(gauge) = client_queue_depth() {
                for (label, v) in &bucket_depth {
                    gauge.with_label_values(&[label.as_str()]).set(*v);
                }
            }
            if let Some(gauge) = client_queue_bytes() {
                for (label, v) in &bucket_bytes {
                    gauge.with_label_values(&[label.as_str()]).set(*v);
                }
            }
            let drops_now = queue.drops_total();
            if drops_now > last_drops
                && let Some(c) = client_queue_drops()
            {
                c.inc_by(drops_now - last_drops);
            }
            last_drops = drops_now;
            let drains_now = queue.drains_total();
            if drains_now > last_drains
                && let Some(c) = client_queue_drains()
            {
                c.inc_by(drains_now - last_drains);
            }
            last_drains = drains_now;

            let enq_now = queue.enqueues_total();
            if enq_now > last_enqueues
                && let Some(c) = client_queue_enqueues()
            {
                c.inc_by(enq_now - last_enqueues);
            }
            last_enqueues = enq_now;

            let wd_now = queue.writer_drops_total();
            if wd_now > last_writer_drops
                && let Some(c) = client_queue_writer_drops()
            {
                c.inc_by(wd_now - last_writer_drops);
            }
            last_writer_drops = wd_now;

            let exp_now = queue.expired_total();
            if exp_now > last_expired
                && let Some(c) = client_queue_expired()
            {
                c.inc_by(exp_now - last_expired);
            }
            last_expired = exp_now;

            let skip_now = queue.skipped_unsupported_total();
            if skip_now > last_skipped
                && let Some(c) = client_queue_skipped_unsupported()
            {
                c.inc_by(skip_now - last_skipped);
            }
            last_skipped = skip_now;
        }
    }));
}

/// Classify a TLS handshake error into a metric label.
///
/// Maps common TLS error strings to well-known reason labels for the
/// `rustgate_handshake_failures_total` metric. Unknown errors are
/// bucketed under `"other"`.
pub fn classify_handshake_error(error: &str) -> &'static str {
    let lower = error.to_lowercase();
    if lower.contains("expired") || lower.contains("not yet valid") {
        "expired_cert"
    } else if lower.contains("revoked") {
        "revoked_cert"
    } else if lower.contains("unknown ca")
        || lower.contains("untrusted")
        || lower.contains("ca certificate")
    {
        "wrong_ca"
    } else if lower.contains("key usage")
        || lower.contains("eku")
        || lower.contains("extended key usage")
    {
        "eku_mismatch"
    } else if lower.contains("timeout") || lower.contains("timed out") {
        "timeout"
    } else {
        "other"
    }
}

// ── Per-identity metrics (Tier 1 + Tier 2) ──────────────────────────

/// Per-identity metrics configuration.
///
/// Holds the optional CN allowlist used to bound label cardinality, and
/// a `per_identity` flag controlling whether Tier 2 metrics
/// (handshake failures, session duration, bytes sent/received) are
/// recorded with `identity_cn` labels.
///
/// When `allowlist` is `None`, allowlist mode is OFF and **all** CNs are
/// bucketed under the literal `"other"` label, capping cardinality at 1.
/// When `Some`, listed CNs pass through verbatim and unlisted CNs are
/// bucketed under `"other"`.
pub struct MetricsIdentity {
    allowlist: Option<HashSet<String>>,
    #[allow(dead_code)] // read by `per_identity_enabled` and used by callers when wiring Tier 2
    per_identity: bool,
}

impl MetricsIdentity {
    /// Construct a new `MetricsIdentity`.
    ///
    /// `per_identity` enables registration and recording of Tier 2
    /// per-identity metrics. `allowlist` constrains the set of CNs that
    /// appear as label values; pass `None` to bucket every CN under
    /// `"other"`.
    pub fn new(allowlist: Option<HashSet<String>>, per_identity: bool) -> Self {
        Self {
            allowlist,
            per_identity,
        }
    }

    /// Construct a disabled identity (no allowlist, Tier 2 off).
    #[allow(dead_code)] // helper for tests and external embedders
    pub fn disabled() -> Self {
        Self {
            allowlist: None,
            per_identity: false,
        }
    }

    /// Returns the bucketed label for a CN.
    ///
    /// Returns the CN if listed in the allowlist, else the literal
    /// `"other"`. When the allowlist is `None`, always returns
    /// `"other"`.
    pub fn bucket<'a>(&'a self, cn: &'a str) -> &'a str {
        bucket_cn(cn, &self.allowlist)
    }

    /// Whether Tier 2 per-identity metrics are enabled.
    #[allow(dead_code)] // observable on the type for callers
    pub fn per_identity_enabled(&self) -> bool {
        self.per_identity
    }
}

/// Bucket a CN against an optional allowlist.
///
/// Returns the original CN slice if it's a member of the allowlist,
/// else the static `"other"` literal. If `allowlist` is `None`, always
/// returns `"other"`.
pub fn bucket_cn<'a>(cn: &'a str, allowlist: &Option<HashSet<String>>) -> &'a str {
    match allowlist {
        Some(set) if set.contains(cn) => cn,
        _ => "other",
    }
}

/// Load a CN allowlist from a file.
///
/// One CN per line; empty lines and lines beginning with `#` are
/// ignored. Trailing whitespace is trimmed.
pub fn load_identity_allowlist(path: &Path) -> std::io::Result<HashSet<String>> {
    let contents = std::fs::read_to_string(path)?;
    Ok(contents
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.to_string())
        .collect())
}

/// Initialize Tier 2 per-identity metrics. Idempotent: subsequent calls
/// are no-ops. Must be called after [`init`] and only when the operator
/// has explicitly opted in via `--metrics-per-identity`.
pub fn init_per_identity() -> prometheus::Result<()> {
    let registry = prometheus::default_registry();

    let handshake_failures = IntCounterVec::new(
        Opts::new(
            "rustgate_per_identity_handshake_failures_total",
            "Per-identity TLS handshake failures (Tier 2, opt-in)",
        ),
        &["identity_cn"],
    )?;
    registry.register(Box::new(handshake_failures.clone()))?;
    let _ = PER_IDENTITY_HANDSHAKE_FAILURES.set(handshake_failures);

    let session_duration = HistogramVec::new(
        HistogramOpts::new(
            "rustgate_per_identity_session_duration_seconds",
            "Per-identity session duration in seconds (Tier 2, opt-in)",
        )
        .buckets(vec![
            1.0, 5.0, 30.0, 60.0, 300.0, 1_800.0, 3_600.0, 14_400.0, 86_400.0,
        ]),
        &["identity_cn"],
    )?;
    registry.register(Box::new(session_duration.clone()))?;
    let _ = PER_IDENTITY_SESSION_DURATION.set(session_duration);

    let bytes_sent = IntCounterVec::new(
        Opts::new(
            "rustgate_per_identity_bytes_sent_total",
            "Per-identity bytes sent to client (Tier 2, opt-in)",
        ),
        &["identity_cn"],
    )?;
    registry.register(Box::new(bytes_sent.clone()))?;
    let _ = PER_IDENTITY_BYTES_SENT.set(bytes_sent);

    let bytes_received = IntCounterVec::new(
        Opts::new(
            "rustgate_per_identity_bytes_received_total",
            "Per-identity bytes received from client (Tier 2, opt-in)",
        ),
        &["identity_cn"],
    )?;
    registry.register(Box::new(bytes_received.clone()))?;
    let _ = PER_IDENTITY_BYTES_RECEIVED.set(bytes_received);

    Ok(())
}

/// Returns the per-identity handshake failures counter, if Tier 2 is
/// enabled. `None` indicates the metric was never registered.
pub fn per_identity_handshake_failures() -> Option<&'static IntCounterVec> {
    PER_IDENTITY_HANDSHAKE_FAILURES.get()
}

/// Returns the per-identity session duration histogram, if Tier 2 is
/// enabled.
pub fn per_identity_session_duration() -> Option<&'static HistogramVec> {
    PER_IDENTITY_SESSION_DURATION.get()
}

/// Returns the per-identity bytes-sent counter, if Tier 2 is enabled.
pub fn per_identity_bytes_sent() -> Option<&'static IntCounterVec> {
    PER_IDENTITY_BYTES_SENT.get()
}

/// Returns the per-identity bytes-received counter, if Tier 2 is
/// enabled.
pub fn per_identity_bytes_received() -> Option<&'static IntCounterVec> {
    PER_IDENTITY_BYTES_RECEIVED.get()
}

// ── HTTP server ─────────────────────────────────────────────────────

/// Fallback response when `Response::builder()` unexpectedly fails.
fn internal_error_response() -> Response<Full<Bytes>> {
    let mut resp = Response::new(Full::new(Bytes::from("internal server error")));
    *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
    resp
}

/// Differentiated health probe state for Kubernetes-style probes.
///
/// Three independent flags expose distinct lifecycle stages:
///
/// - `live` — process is alive. Flipped to `true` once the metrics server
///   starts handling requests; never flipped back. A failing liveness
///   probe instructs the orchestrator to restart the pod.
/// - `ready` — instance can serve traffic. Flipped to `true` after the
///   listener is bound and core subsystems (ACL, federation if enabled)
///   have completed initial wiring. Flipped back to `false` during
///   graceful shutdown so load balancers stop routing new traffic.
/// - `started` — one-shot initial warmup complete. Flipped exactly once
///   after the server enters its accept loop and never reset. The startup
///   probe gives slow-starting pods extra grace before liveness/readiness
///   checks begin in earnest.
#[derive(Debug)]
pub struct HealthState {
    live: AtomicBool,
    ready: AtomicBool,
    started: AtomicBool,
}

impl HealthState {
    /// Create a new `HealthState`. All flags start as `false`; callers
    /// flip them as the corresponding lifecycle stage completes.
    pub fn new() -> Self {
        Self {
            live: AtomicBool::new(false),
            ready: AtomicBool::new(false),
            started: AtomicBool::new(false),
        }
    }

    /// Mark the process as live. Idempotent.
    pub fn set_live(&self, v: bool) {
        self.live.store(v, Ordering::Release);
    }

    /// Mark the instance as ready (or not) to serve traffic.
    pub fn set_ready(&self, v: bool) {
        self.ready.store(v, Ordering::Release);
    }

    /// Mark initial startup as complete. One-shot — typically called once
    /// after the accept loop is entered.
    ///
    /// Prefer [`HealthState::mark_started`] for the typical
    /// "transition false → true exactly once" use case. This setter is
    /// retained for tests and other edge cases that need to construct a
    /// specific state, but production code paths must not call it with
    /// `false` after startup has been observed.
    #[cfg(test)]
    pub fn set_started(&self, v: bool) {
        self.started.store(v, Ordering::Release);
    }

    /// One-shot transition of the `started` flag from `false` to `true`.
    ///
    /// Returns `true` if this call performed the transition, `false` if
    /// the flag was already set. Implemented with `compare_exchange` so
    /// concurrent callers race safely and the flag can never regress to
    /// `false` once observed as `true`.
    pub fn mark_started(&self) -> bool {
        let result =
            self.started
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire);
        debug_assert!(
            result.is_ok() || result == Err(true),
            "started flag must never regress",
        );
        result.is_ok()
    }

    /// Returns `true` once the process loop is reachable.
    pub fn is_live(&self) -> bool {
        self.live.load(Ordering::Acquire)
    }

    /// Returns `true` when the instance can serve traffic.
    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }

    /// Returns `true` once initial warmup has completed.
    pub fn is_started(&self) -> bool {
        self.started.load(Ordering::Acquire)
    }
}

impl Default for HealthState {
    fn default() -> Self {
        Self::new()
    }
}

// ── Readiness dependency checks ────────────────────────────────────

/// Status of an individual dependency check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    /// Dependency is healthy.
    Ok,
    /// Dependency is reachable but in a degraded state.
    Degraded,
    /// Dependency is unreachable or broken.
    Unhealthy,
}

/// Result of a single readiness dependency check.
#[derive(Debug, Clone, Serialize)]
pub struct DependencyCheck {
    pub status: CheckStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl DependencyCheck {
    fn ok() -> Self {
        Self {
            status: CheckStatus::Ok,
            message: None,
        }
    }

    fn degraded(msg: impl Into<String>) -> Self {
        Self {
            status: CheckStatus::Degraded,
            message: Some(msg.into()),
        }
    }

    fn unhealthy(msg: impl Into<String>) -> Self {
        Self {
            status: CheckStatus::Unhealthy,
            message: Some(msg.into()),
        }
    }
}

/// Aggregate readiness report returned as structured JSON from the
/// `/readyz` and `/health/ready` endpoints.
#[derive(Debug, Clone, Serialize)]
pub struct ReadinessReport {
    pub status: CheckStatus,
    pub checks: std::collections::BTreeMap<String, DependencyCheck>,
}

/// Optional dependency handles used by readiness checks.
///
/// The metrics server holds an `Arc<ReadinessState>` and inspects each
/// registered dependency when `/readyz` or `/health/ready` is hit.
/// Fields that are `None` are skipped — the corresponding check is not
/// included in the report.
pub struct ReadinessState {
    /// TLS certificate reloader — checked for cert existence and expiry.
    pub cert_reloader: Option<Arc<rustgate_transport::CertReloader>>,

    /// NATS publisher — checked for connection state via
    /// `NatsPublisher::is_connected`.
    #[cfg(feature = "nats")]
    pub nats_publisher: std::sync::Mutex<Option<rustgate_nats::NatsPublisher>>,

    /// Federation manager — checked for connected peer count.
    #[cfg(feature = "federation")]
    pub federation_manager: std::sync::Mutex<
        Option<Arc<tokio::sync::RwLock<rustgate_federation::manager::FederationManager>>>,
    >,
}

impl std::fmt::Debug for ReadinessState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReadinessState")
            .field("cert_reloader", &self.cert_reloader.is_some())
            .finish()
    }
}

impl ReadinessState {
    /// Create a new empty readiness state with no dependencies registered.
    pub fn new() -> Self {
        Self {
            cert_reloader: None,
            #[cfg(feature = "nats")]
            nats_publisher: std::sync::Mutex::new(None),
            #[cfg(feature = "federation")]
            federation_manager: std::sync::Mutex::new(None),
        }
    }

    /// Register a NATS publisher for readiness checking.
    #[cfg(feature = "nats")]
    pub fn set_nats_publisher(&self, publisher: rustgate_nats::NatsPublisher) {
        if let Ok(mut guard) = self.nats_publisher.lock() {
            *guard = Some(publisher);
        }
    }

    /// Register a federation manager for readiness checking.
    #[cfg(feature = "federation")]
    pub fn set_federation_manager(
        &self,
        mgr: Arc<tokio::sync::RwLock<rustgate_federation::manager::FederationManager>>,
    ) {
        if let Ok(mut guard) = self.federation_manager.lock() {
            *guard = Some(mgr);
        }
    }

    /// Run all registered dependency checks and return a structured report.
    ///
    /// The aggregate status is the worst individual status:
    /// - All `Ok` -> `Ok`
    /// - Any `Degraded` (no `Unhealthy`) -> `Degraded`
    /// - Any `Unhealthy` -> `Unhealthy`
    pub fn check(&self) -> ReadinessReport {
        let mut checks = std::collections::BTreeMap::new();

        // TLS certificate validity
        if let Some(ref reloader) = self.cert_reloader {
            let _ = checks.insert("tls".to_string(), check_tls_cert(reloader));
        }

        // NATS connection state
        #[cfg(feature = "nats")]
        if let Ok(guard) = self.nats_publisher.lock()
            && let Some(ref publisher) = *guard
        {
            let _ = checks.insert("nats".to_string(), check_nats(publisher));
        }

        // Federation peer connectivity
        #[cfg(feature = "federation")]
        if let Ok(guard) = self.federation_manager.lock()
            && let Some(ref mgr) = *guard
        {
            let _ = checks.insert("federation".to_string(), check_federation(mgr));
        }

        let status = aggregate_status(checks.values());
        ReadinessReport { status, checks }
    }
}

impl Default for ReadinessState {
    fn default() -> Self {
        Self::new()
    }
}

/// Check TLS certificate validity by parsing the end-entity cert and
/// comparing its `notBefore`/`notAfter` fields against the current time.
fn check_tls_cert(reloader: &rustgate_transport::CertReloader) -> DependencyCheck {
    let Some(certified_key) = reloader.certified_key() else {
        return DependencyCheck::unhealthy("certificate not loaded");
    };

    let Some(ee_cert_der) = certified_key.cert.first() else {
        return DependencyCheck::unhealthy("certificate chain is empty");
    };

    let Ok((_rem, cert)) = x509_parser::parse_x509_certificate(ee_cert_der.as_ref()) else {
        return DependencyCheck::unhealthy("failed to parse certificate");
    };

    let validity = cert.validity();
    let now = x509_parser::time::ASN1Time::now();

    if now < validity.not_before {
        return DependencyCheck::unhealthy("certificate not yet valid");
    }
    if now > validity.not_after {
        return DependencyCheck::unhealthy("certificate has expired");
    }

    // Warn if the certificate expires within 7 days.
    let not_after_ts = validity.not_after.timestamp();
    let now_ts = now.timestamp();
    let remaining_secs = not_after_ts - now_ts;
    let seven_days_secs: i64 = 7 * 24 * 60 * 60;
    if remaining_secs < seven_days_secs {
        let days = remaining_secs / (24 * 60 * 60);
        return DependencyCheck::degraded(format!("certificate expires in {days} day(s)"));
    }

    DependencyCheck::ok()
}

/// Check NATS connection state via `NatsPublisher` helper methods,
/// avoiding a direct dependency on `async-nats` in this crate.
#[cfg(feature = "nats")]
fn check_nats(publisher: &rustgate_nats::NatsPublisher) -> DependencyCheck {
    if publisher.is_connected() {
        DependencyCheck::ok()
    } else if publisher.is_pending() {
        DependencyCheck::degraded("NATS connection pending")
    } else {
        DependencyCheck::unhealthy("NATS disconnected")
    }
}

/// Check federation peer connectivity.
#[cfg(feature = "federation")]
fn check_federation(
    mgr: &Arc<tokio::sync::RwLock<rustgate_federation::manager::FederationManager>>,
) -> DependencyCheck {
    let Ok(guard) = mgr.try_read() else {
        // Lock contention during reconfiguration; report degraded rather
        // than blocking the health endpoint.
        return DependencyCheck::degraded("federation manager busy");
    };
    let total = guard.peer_count();
    let connected = guard.connected_peer_count();

    if total == 0 {
        // No peers configured — federation is effectively idle; this is not
        // an error condition.
        return DependencyCheck::ok();
    }

    if connected == 0 {
        return DependencyCheck::unhealthy(format!("0/{total} peers connected"));
    }
    if connected < total {
        return DependencyCheck::degraded(format!("{connected}/{total} peers connected"));
    }
    DependencyCheck::ok()
}

/// Aggregate individual check statuses into the worst-case overall status.
fn aggregate_status<'a>(checks: impl Iterator<Item = &'a DependencyCheck>) -> CheckStatus {
    let mut worst = CheckStatus::Ok;
    for c in checks {
        match c.status {
            CheckStatus::Unhealthy => return CheckStatus::Unhealthy,
            CheckStatus::Degraded => worst = CheckStatus::Degraded,
            CheckStatus::Ok => {}
        }
    }
    worst
}

fn probe_response(
    ok: bool,
    ok_body: &'static str,
    fail_body: &'static str,
) -> Response<Full<Bytes>> {
    if ok {
        Response::builder()
            .status(StatusCode::OK)
            .body(Full::new(Bytes::from(ok_body)))
            .unwrap_or_else(|_| internal_error_response())
    } else {
        Response::builder()
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .body(Full::new(Bytes::from(fail_body)))
            .unwrap_or_else(|_| internal_error_response())
    }
}

/// Constant-time check of a supplied bearer token against the expected value.
///
/// Returns `true` when the `Authorization` header is present, starts with
/// `Bearer `, and the remainder matches `expected` in constant time.
fn metrics_auth_ok(header: Option<&str>, expected: &[u8]) -> bool {
    let Some(raw) = header else {
        return false;
    };
    let Some(token) = raw.strip_prefix("Bearer ") else {
        return false;
    };
    token.as_bytes().ct_eq(expected).into()
}

/// Build a structured JSON readiness response that includes dependency
/// check results alongside the base `ready` flag from `HealthState`.
///
/// When `HealthState::is_ready()` is `false` (e.g. during graceful
/// shutdown), the overall status is forced to `unhealthy` regardless of
/// individual check outcomes. Otherwise the aggregate status reflects
/// the worst individual check.
///
/// Returns HTTP 200 for `ok` or `degraded`, 503 for `unhealthy`.
fn readiness_response(health: &HealthState, readiness: &ReadinessState) -> Response<Full<Bytes>> {
    let mut report = readiness.check();

    // Override aggregate status when the base readiness flag is off
    // (graceful shutdown or not yet ready).
    if !health.is_ready() {
        report.status = CheckStatus::Unhealthy;
    }

    let status_code = match report.status {
        CheckStatus::Ok | CheckStatus::Degraded => StatusCode::OK,
        CheckStatus::Unhealthy => StatusCode::SERVICE_UNAVAILABLE,
    };

    match serde_json::to_string(&report) {
        Ok(body) => Response::builder()
            .status(status_code)
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(body)))
            .unwrap_or_else(|_| internal_error_response()),
        Err(_) => internal_error_response(),
    }
}

fn handle_request(
    req: Request<hyper::body::Incoming>,
    health: Arc<HealthState>,
    readiness: Arc<ReadinessState>,
    metrics_token: Option<Arc<Zeroizing<Vec<u8>>>>,
    router_slot: RouterSlot,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    match req.uri().path() {
        // Liveness: process loop is reachable. Returns 200 once the
        // metrics server is up; orchestrators interpret a non-200 as
        // "restart the pod".
        "/health/live" => Ok(probe_response(health.is_live(), "ok", "not live")),

        // Readiness: returns structured JSON with dependency checks.
        // HTTP 200 for ok/degraded, 503 for unhealthy.
        "/health/ready" => Ok(readiness_response(&health, &readiness)),

        // Startup: initial warmup complete. Allows slow-starting pods to
        // delay liveness/readiness checks during boot.
        "/health/startup" => Ok(probe_response(health.is_started(), "ok", "starting")),

        // Authz health: compile warnings from the installed policy
        // engine, if any. Returns a JSON object so operators can
        // inspect warnings without scraping logs.
        "/health/authz" => Ok(authz_health_response(router_slot.get())),

        // Legacy aliases — kept for backwards compatibility. `/healthz`
        // mirrors `/health/live` and `/readyz` mirrors `/health/ready`.
        "/healthz" => Ok(probe_response(health.is_live(), "ok", "not live")),

        // Legacy alias — `/readyz` mirrors `/health/ready` (structured
        // readiness with dependency checks).
        "/readyz" => Ok(readiness_response(&health, &readiness)),

        "/metrics" => {
            // When a metrics token is configured, require valid auth.
            if let Some(ref expected) = metrics_token {
                let auth = req
                    .headers()
                    .get(hyper::header::AUTHORIZATION)
                    .and_then(|v| v.to_str().ok());
                if !metrics_auth_ok(auth, expected) {
                    return Ok(Response::builder()
                        .status(StatusCode::UNAUTHORIZED)
                        .header(hyper::header::WWW_AUTHENTICATE, "Bearer")
                        .body(Full::new(Bytes::from("unauthorized")))
                        .unwrap_or_else(|_| internal_error_response()));
                }
            }

            // Refresh jemalloc stats on every scrape so Prometheus sees
            // current memory values rather than stale cached counters.
            #[cfg(feature = "jemalloc")]
            refresh_jemalloc_stats();

            let encoder = TextEncoder::new();
            let metric_families = prometheus::gather();
            let mut buffer = Vec::new();
            if encoder.encode(&metric_families, &mut buffer).is_err() {
                return Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Full::new(Bytes::from("metrics encoding failed")))
                    .unwrap_or_else(|_| internal_error_response()));
            }
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("content-type", encoder.format_type())
                .body(Full::new(Bytes::from(buffer)))
                .unwrap_or_else(|_| internal_error_response()))
        }

        _ => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::from("not found")))
            .unwrap_or_else(|_| internal_error_response())),
    }
}

/// Build a JSON response for the `/health/authz` endpoint.
///
/// When a policy engine is installed, returns:
/// ```json
/// {
///     "policy_id": "<sha256>",
///     "compile_warnings": ["warning 1", "warning 2"]
/// }
/// ```
///
/// When no engine is installed, returns:
/// ```json
/// {
///     "policy_id": null,
///     "compile_warnings": []
/// }
/// ```
fn authz_health_response(
    router: Option<&Arc<rustgate_transport::Router>>,
) -> Response<Full<Bytes>> {
    /// Typed response for `/health/authz` — serialized via `serde_json`
    /// to guarantee RFC 8259-compliant escaping of all string values.
    #[derive(serde::Serialize)]
    struct AuthzHealth<'a> {
        policy_id: Option<&'a str>,
        compile_warnings: &'a [String],
    }

    let (policy_id, warnings): (Option<String>, Vec<String>) = match router {
        Some(r) => match r.authz_snapshot() {
            Some(engine) => {
                let id = engine.policy_id().to_string();
                let w = engine
                    .compile_warnings()
                    .iter()
                    .map(|s| s.to_string())
                    .collect();
                (Some(id), w)
            }
            None => (None, Vec::new()),
        },
        None => (None, Vec::new()),
    };

    let resp = AuthzHealth {
        policy_id: policy_id.as_deref(),
        compile_warnings: &warnings,
    };

    let body = serde_json::to_string(&resp).unwrap_or_else(|_| String::from("{}"));

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap_or_else(|_| internal_error_response())
}

/// Type alias for the router reference shared with the metrics server.
///
/// Populated via `OnceLock` after the router is constructed (which happens
/// after `start_metrics` spawns the HTTP server). Requests that arrive
/// before the slot is filled return an empty warnings list.
pub type RouterSlot = Arc<OnceLock<Arc<rustgate_transport::Router>>>;

/// Serve Prometheus metrics and health endpoints at the given address.
///
/// Routes:
/// - `GET /metrics`        — Prometheus text format (optionally authenticated)
/// - `GET /health/live`    — Kubernetes liveness probe
/// - `GET /health/ready`   — Kubernetes readiness probe (structured JSON
///   with dependency checks)
/// - `GET /health/startup` — Kubernetes startup probe
/// - `GET /health/authz`   — Authz engine compile warnings (JSON)
/// - `GET /healthz`        — Deprecated alias for `/health/live`
/// - `GET /readyz`         — Deprecated alias for `/health/ready`
///
/// When `metrics_token` is `Some`, requests to `/metrics` must present a
/// valid `Authorization: Bearer <token>` header; missing or mismatched
/// tokens yield a 401 response. When `None`, `/metrics` is served without
/// authentication for backward compatibility.
///
/// The server is hardened against unauthenticated abuse:
/// - Connection count bounded by [`MAX_HTTP_CONNECTIONS`]
/// - Per-connection timeout of [`HTTP_CONNECTION_TIMEOUT`]
/// - Header read timeout of 5 seconds
pub async fn serve(
    bind: SocketAddr,
    health: Arc<HealthState>,
    readiness: Arc<ReadinessState>,
    #[cfg(feature = "federation")] fed_api: Arc<OnceLock<FedApiHandler>>,
    acl_api: Arc<OnceLock<AclApiHandler>>,
    metrics_token: Option<Arc<Zeroizing<Vec<u8>>>>,
    router_slot: RouterSlot,
) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(bind).await?;
    let conn_limit = Arc::new(tokio::sync::Semaphore::new(MAX_HTTP_CONNECTIONS));
    // The metrics server is up — the process loop is reachable, so the
    // liveness flag may flip on. Readiness/startup remain controlled by
    // the main server lifecycle.
    health.set_live(true);
    tracing::info!(addr = %bind, "metrics server started");

    loop {
        let (stream, _) = listener.accept().await?;

        let permit = match Arc::clone(&conn_limit).try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                drop(stream);
                continue;
            }
        };

        let io = hyper_util::rt::TokioIo::new(stream);
        let health = Arc::clone(&health);
        let readiness = Arc::clone(&readiness);
        #[cfg(feature = "federation")]
        let fed_api = Arc::clone(&fed_api);
        let acl_api = Arc::clone(&acl_api);
        let metrics_token = metrics_token.clone();
        let router_slot = Arc::clone(&router_slot);
        drop(tokio::spawn(async move {
            let _permit = permit;
            let conn = hyper::server::conn::http1::Builder::new()
                .timer(hyper_util::rt::TokioTimer::new())
                .header_read_timeout(Duration::from_secs(5))
                .serve_connection(
                    io,
                    service_fn(move |req: Request<hyper::body::Incoming>| {
                        let health = Arc::clone(&health);
                        let readiness = Arc::clone(&readiness);
                        #[cfg(feature = "federation")]
                        let fed_api = Arc::clone(&fed_api);
                        let acl_api = Arc::clone(&acl_api);
                        let metrics_token = metrics_token.clone();
                        let router_slot = Arc::clone(&router_slot);
                        async move {
                            // Delegate /api/federation/ paths to the federation handler
                            #[cfg(feature = "federation")]
                            if req.uri().path().starts_with("/api/federation/") {
                                if let Some(handler) = fed_api.get() {
                                    let method = req.method().clone();
                                    let path = req.uri().path().to_string();
                                    let body = http_body_util::BodyExt::collect(req.into_body())
                                        .await
                                        .map(|b| b.to_bytes())
                                        .unwrap_or_default();
                                    if let Some(resp) = handler(&method, &path, &body) {
                                        return Ok(resp);
                                    }
                                }
                                return Ok(Response::builder()
                                    .status(StatusCode::SERVICE_UNAVAILABLE)
                                    .body(Full::new(Bytes::from("federation API not ready")))
                                    .unwrap_or_else(|_| internal_error_response()));
                            }
                            // Delegate /api/acl/ paths to the ACL management handler
                            if req.uri().path().starts_with("/api/acl/")
                                && let Some(handler) = acl_api.get()
                            {
                                let method = req.method().clone();
                                let path = req.uri().path().to_string();
                                let auth = req
                                    .headers()
                                    .get(hyper::header::AUTHORIZATION)
                                    .and_then(|v| v.to_str().ok())
                                    .map(|s| s.to_string());
                                let body = http_body_util::BodyExt::collect(req.into_body())
                                    .await
                                    .map(|b| b.to_bytes())
                                    .unwrap_or_default();
                                if let Some(resp) = handler(&method, &path, auth.as_deref(), &body)
                                {
                                    return Ok(resp);
                                }
                                return Ok(Response::builder()
                                    .status(StatusCode::NOT_FOUND)
                                    .body(Full::new(Bytes::from("not found")))
                                    .unwrap_or_else(|_| internal_error_response()));
                            }
                            // If no ACL handler is registered, fall
                            // through to the generic request handler,
                            // which returns 404 for unknown paths.
                            handle_request(req, health, readiness, metrics_token, router_slot)
                        }
                    }),
                );
            match tokio::time::timeout(HTTP_CONNECTION_TIMEOUT, conn).await {
                Ok(Err(e)) => tracing::debug!(error = %e, "metrics connection error"),
                Err(_) => tracing::debug!("metrics connection timed out"),
                Ok(Ok(())) => {}
            }
        }));
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use std::sync::Once;

    use super::*;

    static INIT: Once = Once::new();

    fn ensure_init() {
        INIT.call_once(|| {
            init().expect("metrics init failed");
        });
    }

    #[test]
    fn fallback_constructors_do_not_panic() {
        // Verify fallback helpers produce valid metrics without panicking.
        let c = super::fallback_counter("test_counter", "test");
        c.inc();
        assert_eq!(c.get(), 1);

        let g = super::fallback_gauge("test_gauge", "test");
        g.inc();
        g.dec();
        assert_eq!(g.get(), 0);

        let cv = super::fallback_counter_vec("test_vec", "test", &["label"]);
        cv.with_label_values(&["x"]).inc();
        assert_eq!(cv.with_label_values(&["x"]).get(), 1);
    }

    #[test]
    fn init_registers_all_metrics() {
        ensure_init();

        let _ = connections_accepted();
        let _ = connections_active();
        let _ = connections_rejected();
        let _ = accept_errors();
        let _ = messages_received();
        let _ = messages_expired();
        let _ = messages_routed();
        let _ = sessions_active();
        let _ = nats_publishes();
        let _ = negotiations();
        let _ = handshake_failures();
    }

    #[test]
    fn counter_increments() {
        ensure_init();

        let before = connections_accepted().get();
        connections_accepted().inc();
        assert_eq!(connections_accepted().get(), before + 1);
    }

    #[test]
    fn gauge_inc_dec() {
        ensure_init();

        let before = connections_active().get();
        connections_active().inc();
        assert_eq!(connections_active().get(), before + 1);
        connections_active().dec();
        assert_eq!(connections_active().get(), before);
    }

    #[test]
    fn counter_vec_labels() {
        ensure_init();

        let before = messages_routed()
            .with_label_values(&["broadcast", "other"])
            .get();
        messages_routed()
            .with_label_values(&["broadcast", "other"])
            .inc();
        assert_eq!(
            messages_routed()
                .with_label_values(&["broadcast", "other"])
                .get(),
            before + 1
        );
    }

    #[test]
    fn bucket_cn_no_allowlist_returns_other() {
        assert_eq!(bucket_cn("alice", &None), "other");
        assert_eq!(bucket_cn("", &None), "other");
    }

    #[test]
    fn bucket_cn_listed_returns_cn() {
        let mut set = HashSet::new();
        let _ = set.insert("alice".to_string());
        let _ = set.insert("bob".to_string());
        let allow = Some(set);
        assert_eq!(bucket_cn("alice", &allow), "alice");
        assert_eq!(bucket_cn("bob", &allow), "bob");
        assert_eq!(bucket_cn("eve", &allow), "other");
    }

    #[test]
    fn metrics_identity_disabled_buckets_to_other() {
        let id = MetricsIdentity::disabled();
        assert!(!id.per_identity_enabled());
        assert_eq!(id.bucket("alice"), "other");
    }

    #[test]
    fn metrics_identity_with_allowlist() {
        let mut set = HashSet::new();
        let _ = set.insert("alice".to_string());
        let id = MetricsIdentity::new(Some(set), true);
        assert!(id.per_identity_enabled());
        assert_eq!(id.bucket("alice"), "alice");
        assert_eq!(id.bucket("eve"), "other");
    }

    #[test]
    fn tier2_metrics_none_when_not_initialized() {
        // Note: this test only validates that accessors are Option-typed.
        // We can't reliably assert None here because other tests may have
        // called init_per_identity, but we can at least call the
        // accessors without panicking.
        let _ = per_identity_handshake_failures();
        let _ = per_identity_session_duration();
        let _ = per_identity_bytes_sent();
        let _ = per_identity_bytes_received();
    }

    #[test]
    fn tier2_metrics_some_when_initialized() {
        // init_per_identity is idempotent: subsequent registrations
        // return AlreadyReg, which we ignore here.
        let _ = init_per_identity();
        assert!(per_identity_handshake_failures().is_some());
        assert!(per_identity_session_duration().is_some());
        assert!(per_identity_bytes_sent().is_some());
        assert!(per_identity_bytes_received().is_some());
    }

    #[test]
    fn load_identity_allowlist_parses_file() {
        use std::io::Write;
        let mut tmp = tempfile::NamedTempFile::new().expect("tmp");
        writeln!(tmp, "# comment").expect("w");
        writeln!(tmp, "alice").expect("w");
        writeln!(tmp).expect("w");
        writeln!(tmp, "  bob  ").expect("w");
        let set = load_identity_allowlist(tmp.path()).expect("load");
        assert!(set.contains("alice"));
        assert!(set.contains("bob"));
        assert_eq!(set.len(), 2);
    }

    #[tokio::test]
    async fn serve_health_and_metrics_endpoints() {
        ensure_init();

        let health = Arc::new(HealthState::new());
        let readiness = Arc::new(ReadinessState::new());
        // Mark ready for the bulk of the test; serve() flips live=true.
        health.set_ready(true);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        drop(listener);

        let router_slot: RouterSlot = Arc::new(OnceLock::new());
        let _ = router_slot.set(Arc::new(rustgate_transport::Router::new()));

        let server_health = Arc::clone(&health);
        let server_router_slot = Arc::clone(&router_slot);
        let server_readiness = Arc::clone(&readiness);
        drop(tokio::spawn(async move {
            let _ = serve(
                addr,
                server_health,
                server_readiness,
                #[cfg(feature = "federation")]
                Arc::new(OnceLock::new()),
                Arc::new(OnceLock::new()),
                None, // no metrics token — backward compatible unauthenticated
                server_router_slot,
            )
            .await;
        }));

        tokio::time::sleep(Duration::from_millis(50)).await;

        // /health/live returns 200 once serve() is up.
        let (status, body) = http_get(addr, "/health/live").await;
        assert_eq!(status, 200);
        assert_eq!(body, "ok");

        // Legacy alias /healthz mirrors /health/live.
        let (status, _) = http_get(addr, "/healthz").await;
        assert_eq!(status, 200);

        // /health/ready returns structured JSON when ready (no deps
        // registered, so the report has an empty checks map and status "ok").
        let (status, body) = http_get(addr, "/health/ready").await;
        assert_eq!(status, 200);
        let report: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(report["status"], "ok");

        // Legacy alias /readyz mirrors /health/ready.
        let (status, body) = http_get(addr, "/readyz").await;
        assert_eq!(status, 200);
        let report: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(report["status"], "ok");

        // /health/startup is 503 until startup is marked complete.
        let (status, body) = http_get(addr, "/health/startup").await;
        assert_eq!(status, 503);
        assert_eq!(body, "starting");

        assert!(health.mark_started());
        let (status, body) = http_get(addr, "/health/startup").await;
        assert_eq!(status, 200);
        assert_eq!(body, "ok");

        // /health/ready returns 503 after marking not ready (shutdown).
        health.set_ready(false);
        let (status, body) = http_get(addr, "/health/ready").await;
        assert_eq!(status, 503);
        let report: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(report["status"], "unhealthy");

        let (status, body) = http_get(addr, "/readyz").await;
        assert_eq!(status, 503);
        let report: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(report["status"], "unhealthy");

        // /metrics returns Prometheus text
        let (status, body) = http_get(addr, "/metrics").await;
        assert_eq!(status, 200);
        assert!(body.contains("rustgate_connections_accepted_total"));

        // /health/authz returns JSON with no engine installed
        let (status, body) = http_get(addr, "/health/authz").await;
        assert_eq!(status, 200);
        assert!(body.contains("\"policy_id\":null"));
        assert!(body.contains("\"compile_warnings\":[]"));

        // Unknown path returns 404
        let (status, _) = http_get(addr, "/unknown").await;
        assert_eq!(status, 404);
    }

    #[test]
    fn health_state_flags_are_independent() {
        let h = HealthState::new();
        assert!(!h.is_live());
        assert!(!h.is_ready());
        assert!(!h.is_started());

        h.set_live(true);
        assert!(h.is_live());
        assert!(!h.is_ready());
        assert!(!h.is_started());

        h.set_ready(true);
        h.set_started(true);
        assert!(h.is_live());
        assert!(h.is_ready());
        assert!(h.is_started());

        // Readiness can flip back (graceful shutdown), startup does not.
        h.set_ready(false);
        assert!(!h.is_ready());
        assert!(h.is_started());
    }

    #[test]
    fn mark_started_is_one_shot() {
        let h = HealthState::new();
        assert!(!h.is_started());

        // First call performs the transition.
        assert!(h.mark_started());
        assert!(h.is_started());

        // Subsequent calls are no-ops and report `false`, but the
        // observable flag remains `true`.
        assert!(!h.mark_started());
        assert!(h.is_started());
        assert!(!h.mark_started());
        assert!(h.is_started());
    }

    #[tokio::test]
    async fn authz_health_endpoint_surfaces_compile_warnings() {
        ensure_init();

        // Build a policy with an overly broad allow+any rule that
        // triggers a compile warning.
        let rules = rustgate_authz::RuleSet {
            version: 1,
            default_effect: rustgate_authz::Effect::Deny,
            rules: vec![rustgate_authz::Rule {
                id: smol_str::SmolStr::new("broad-rule"),
                effect: rustgate_authz::Effect::Allow,
                action: rustgate_authz::Action::Send,
                resource: rustgate_authz::ResourceMatcher::Any,
                subject: rustgate_authz::SubjectMatcher::default(),
                obligations: Vec::new(),
            }],
        };
        let engine = rustgate_authz::NativeEngine::new(rules).expect("compile");
        assert!(
            !engine.compile_warnings().is_empty(),
            "test policy should emit at least one compile warning"
        );

        let router = Arc::new(
            rustgate_transport::Router::new()
                .with_authz(Arc::new(engine) as Arc<dyn rustgate_authz::PolicyEngine>),
        );

        let router_slot: RouterSlot = Arc::new(OnceLock::new());
        let _ = router_slot.set(router);

        let health = Arc::new(HealthState::new());
        health.set_ready(true);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        drop(listener);

        let server_health = Arc::clone(&health);
        let server_router_slot = Arc::clone(&router_slot);
        drop(tokio::spawn(async move {
            let _ = serve(
                addr,
                server_health,
                #[cfg(feature = "federation")]
                Arc::new(OnceLock::new()),
                Arc::new(OnceLock::new()),
                server_router_slot,
            )
            .await;
        }));

        tokio::time::sleep(Duration::from_millis(50)).await;

        let (status, body) = http_get(addr, "/health/authz").await;
        assert_eq!(status, 200);

        // The response must contain a policy_id and at least one warning.
        assert!(
            body.contains("\"policy_id\":\""),
            "expected policy_id in response: {body}"
        );
        assert!(
            body.contains("broad-rule"),
            "expected warning mentioning the rule id: {body}"
        );
        assert!(
            !body.contains("\"compile_warnings\":[]"),
            "warnings list should not be empty: {body}"
        );
    }

    /// When a Router is present in the slot but has no authz engine
    /// installed, the `/health/authz` endpoint must still return a
    /// well-formed JSON response with `policy_id: null` and an empty
    /// warnings list. This exercises a distinct code path from the
    /// slot being empty (no Router at all).
    #[tokio::test]
    async fn authz_health_returns_empty_when_router_has_no_engine() {
        ensure_init();

        let router = Arc::new(rustgate_transport::Router::new());
        // Confirm the router truly has no authz engine.
        assert!(
            router.authz_snapshot().is_none(),
            "Router::new() should not have an authz engine"
        );

        let router_slot: RouterSlot = Arc::new(OnceLock::new());
        let _ = router_slot.set(router);

        let health = Arc::new(HealthState::new());
        health.set_ready(true);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        drop(listener);

        let server_health = Arc::clone(&health);
        let server_router_slot = Arc::clone(&router_slot);
        drop(tokio::spawn(async move {
            let _ = serve(
                addr,
                server_health,
                #[cfg(feature = "federation")]
                Arc::new(OnceLock::new()),
                Arc::new(OnceLock::new()),
                server_router_slot,
            )
            .await;
        }));

        tokio::time::sleep(Duration::from_millis(50)).await;

        let (status, body) = http_get(addr, "/health/authz").await;
        assert_eq!(status, 200);
        assert!(
            body.contains("\"policy_id\":null"),
            "expected null policy_id: {body}"
        );
        assert!(
            body.contains("\"compile_warnings\":[]"),
            "expected empty warnings: {body}"
        );
    }

    /// Minimal HTTP GET using raw TCP. Returns (status_code, body).
    async fn http_get(addr: SocketAddr, path: &str) -> (u16, String) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");

        let request = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
        stream.write_all(request.as_bytes()).await.expect("write");

        let mut buf = Vec::new();
        let _ = stream.read_to_end(&mut buf).await.expect("read");
        let response = String::from_utf8_lossy(&buf);

        let status_line = response.lines().next().unwrap_or("");
        let status: u16 = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        let body = response
            .split_once("\r\n\r\n")
            .map(|(_, b)| b.to_string())
            .unwrap_or_default();

        (status, body)
    }

    #[test]
    fn internal_error_response_returns_500() {
        let resp = internal_error_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn classify_handshake_error_expired() {
        assert_eq!(
            classify_handshake_error("certificate has expired"),
            "expired_cert"
        );
        assert_eq!(
            classify_handshake_error("cert not yet valid"),
            "expired_cert"
        );
    }

    #[test]
    fn classify_handshake_error_revoked() {
        assert_eq!(
            classify_handshake_error("certificate revoked by CRL"),
            "revoked_cert"
        );
    }

    #[test]
    fn classify_handshake_error_wrong_ca() {
        assert_eq!(classify_handshake_error("unknown ca in chain"), "wrong_ca");
        assert_eq!(
            classify_handshake_error("peer sent untrusted cert"),
            "wrong_ca"
        );
        assert_eq!(
            classify_handshake_error("invalid CA certificate"),
            "wrong_ca"
        );
    }

    #[test]
    fn classify_handshake_error_eku_mismatch() {
        assert_eq!(
            classify_handshake_error("extended key usage violation"),
            "eku_mismatch"
        );
        assert_eq!(
            classify_handshake_error("invalid key usage bits"),
            "eku_mismatch"
        );
        assert_eq!(
            classify_handshake_error("wrong EKU on client cert"),
            "eku_mismatch"
        );
    }

    #[test]
    fn classify_handshake_error_timeout() {
        assert_eq!(classify_handshake_error("connection timed out"), "timeout");
        assert_eq!(
            classify_handshake_error("handshake timeout reached"),
            "timeout"
        );
    }

    #[test]
    fn classify_handshake_error_other() {
        assert_eq!(classify_handshake_error("some unknown error"), "other");
        assert_eq!(classify_handshake_error(""), "other");
    }

    #[test]
    fn handshake_failures_counter_vec() {
        ensure_init();

        let before = handshake_failures()
            .with_label_values(&["expired_cert"])
            .get();
        handshake_failures()
            .with_label_values(&["expired_cert"])
            .inc();
        assert_eq!(
            handshake_failures()
                .with_label_values(&["expired_cert"])
                .get(),
            before + 1
        );
    }

    // ── Metrics authentication tests ───────────────────────────────

    #[test]
    fn metrics_auth_ok_rejects_missing_header() {
        assert!(!metrics_auth_ok(None, b"s3cret-token-for-metrics-test1"));
    }

    #[test]
    fn metrics_auth_ok_rejects_wrong_scheme() {
        assert!(!metrics_auth_ok(
            Some("Basic s3cret-token-for-metrics-test1"),
            b"s3cret-token-for-metrics-test1"
        ));
    }

    #[test]
    fn metrics_auth_ok_rejects_wrong_token() {
        assert!(!metrics_auth_ok(
            Some("Bearer wrong-token-value-padding-xxxx"),
            b"s3cret-token-for-metrics-test1"
        ));
    }

    #[test]
    fn metrics_auth_ok_accepts_correct_token() {
        assert!(metrics_auth_ok(
            Some("Bearer s3cret-token-for-metrics-test1"),
            b"s3cret-token-for-metrics-test1"
        ));
    }

    /// Minimal HTTP GET with an optional Authorization header.
    async fn http_get_with_auth(addr: SocketAddr, path: &str, auth: Option<&str>) -> (u16, String) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");

        let auth_header = match auth {
            Some(val) => format!("Authorization: {val}\r\n"),
            None => String::new(),
        };
        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: {addr}\r\n{auth_header}Connection: close\r\n\r\n"
        );
        stream.write_all(request.as_bytes()).await.expect("write");

        let mut buf = Vec::new();
        let _ = stream.read_to_end(&mut buf).await.expect("read");
        let response = String::from_utf8_lossy(&buf);

        let status_line = response.lines().next().unwrap_or("");
        let status: u16 = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        let body = response
            .split_once("\r\n\r\n")
            .map(|(_, b)| b.to_string())
            .unwrap_or_default();

        (status, body)
    }

    /// Minimal HTTP GET returning status, raw headers block, and body.
    async fn http_get_raw(
        addr: SocketAddr,
        path: &str,
        auth: Option<&str>,
    ) -> (u16, String, String) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");

        let auth_header = match auth {
            Some(val) => format!("Authorization: {val}\r\n"),
            None => String::new(),
        };
        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: {addr}\r\n{auth_header}Connection: close\r\n\r\n"
        );
        stream.write_all(request.as_bytes()).await.expect("write");

        let mut buf = Vec::new();
        let _ = stream.read_to_end(&mut buf).await.expect("read");
        let response = String::from_utf8_lossy(&buf);

        let status_line = response.lines().next().unwrap_or("");
        let status: u16 = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        let (headers_part, body) = response
            .split_once("\r\n\r\n")
            .map(|(h, b)| (h.to_string(), b.to_string()))
            .unwrap_or_default();

        (status, headers_part, body)
    }

    /// Helper to start a metrics server with an optional auth token.
    async fn start_test_server(token: Option<&[u8]>) -> SocketAddr {
        let health = Arc::new(HealthState::new());
        health.set_ready(true);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        drop(listener);

        let metrics_token = token.map(|t| Arc::new(Zeroizing::new(t.to_vec())));
        let readiness = Arc::new(ReadinessState::new());
        let router_slot: RouterSlot = Arc::new(OnceLock::new());
        let _ = router_slot.set(Arc::new(rustgate_transport::Router::new()));

        drop(tokio::spawn(async move {
            let _ = serve(
                addr,
                health,
                readiness,
                #[cfg(feature = "federation")]
                Arc::new(OnceLock::new()),
                Arc::new(OnceLock::new()),
                metrics_token,
                router_slot,
            )
            .await;
        }));

        tokio::time::sleep(Duration::from_millis(50)).await;
        addr
    }

    #[tokio::test]
    async fn metrics_requires_auth_when_token_configured() {
        ensure_init();
        let addr = start_test_server(Some(b"test-metrics-token-abcdef1234567")).await;

        // No auth header -> 401
        let (status, body) = http_get_with_auth(addr, "/metrics", None).await;
        assert_eq!(status, 401);
        assert!(body.contains("unauthorized"));
    }

    #[tokio::test]
    async fn metrics_accepts_valid_token() {
        ensure_init();
        let token = b"test-metrics-token-abcdef1234567";
        let addr = start_test_server(Some(token)).await;

        let (status, body) = http_get_with_auth(
            addr,
            "/metrics",
            Some("Bearer test-metrics-token-abcdef1234567"),
        )
        .await;
        assert_eq!(status, 200);
        assert!(body.contains("rustgate_connections_accepted_total"));
    }

    #[tokio::test]
    async fn metrics_rejects_invalid_token() {
        ensure_init();
        let addr = start_test_server(Some(b"test-metrics-token-abcdef1234567")).await;

        let (status, body) = http_get_with_auth(
            addr,
            "/metrics",
            Some("Bearer wrong-metrics-token-padding-here"),
        )
        .await;
        assert_eq!(status, 401);
        assert!(body.contains("unauthorized"));
    }

    #[tokio::test]
    async fn metrics_401_includes_www_authenticate_header() {
        ensure_init();
        let addr = start_test_server(Some(b"test-metrics-token-abcdef1234567")).await;

        // RFC 6750 Section 3: 401 responses for bearer auth must include
        // a WWW-Authenticate: Bearer header.
        let (status, headers, _body) = http_get_raw(addr, "/metrics", None).await;
        assert_eq!(status, 401);
        let lower = headers.to_ascii_lowercase();
        assert!(
            lower.contains("www-authenticate: bearer"),
            "expected WWW-Authenticate: Bearer header, got: {headers}"
        );
    }

    #[tokio::test]
    async fn metrics_unauthenticated_when_no_token() {
        ensure_init();
        let addr = start_test_server(None).await;

        // No token configured -> /metrics is open (backward compat)
        let (status, body) = http_get_with_auth(addr, "/metrics", None).await;
        assert_eq!(status, 200);
        assert!(body.contains("rustgate_connections_accepted_total"));
    }

    #[tokio::test]
    async fn health_endpoints_bypass_metrics_auth() {
        ensure_init();
        let addr = start_test_server(Some(b"test-metrics-token-abcdef1234567")).await;

        // Health endpoints should remain accessible without auth even
        // when a metrics token is configured.
        let (status, _) = http_get_with_auth(addr, "/health/live", None).await;
        assert_eq!(status, 200);

        let (status, _) = http_get_with_auth(addr, "/health/ready", None).await;
        assert_eq!(status, 200);

        let (status, _) = http_get_with_auth(addr, "/healthz", None).await;
        assert_eq!(status, 200);
    }

    /// Verify that `refresh_jemalloc_stats` runs without error and populates
    /// the four gauges with non-negative values when the jemalloc allocator
    /// is active.
    #[cfg(feature = "jemalloc")]
    #[test]
    fn jemalloc_stats_are_populated() {
        ensure_init();

        refresh_jemalloc_stats();

        // After a refresh the gauges must be set. jemalloc always reports
        // at least some resident and allocated memory for the process
        // itself, so all four values should be > 0.
        let resident = JEMALLOC_RESIDENT.get().map(IntGauge::get);
        let active = JEMALLOC_ACTIVE.get().map(IntGauge::get);
        let allocated = JEMALLOC_ALLOCATED.get().map(IntGauge::get);
        let mapped = JEMALLOC_MAPPED.get().map(IntGauge::get);

        assert!(
            resident.is_some_and(|v| v > 0),
            "resident should be > 0, got {resident:?}",
        );
        assert!(
            active.is_some_and(|v| v > 0),
            "active should be > 0, got {active:?}",
        );
        assert!(
            allocated.is_some_and(|v| v > 0),
            "allocated should be > 0, got {allocated:?}",
        );
        assert!(
            mapped.is_some_and(|v| v > 0),
            "mapped should be > 0, got {mapped:?}",
        );

        // Sanity-check the one invariant that jemalloc guarantees:
        // allocated <= active. The resident-vs-active and mapped-vs-resident
        // orderings can transiently invert during OS page reclaim, so we
        // only assert positivity for those (already checked above).
        let a = allocated.unwrap();
        let act = active.unwrap();
        assert!(a <= act, "allocated ({a}) <= active ({act})");
    }

    // ── Readiness check unit tests ─────────────────────────────────

    #[test]
    fn readiness_state_no_deps_returns_ok() {
        let state = ReadinessState::new();
        let report = state.check();
        assert_eq!(report.status, CheckStatus::Ok);
        assert!(report.checks.is_empty());
    }

    #[test]
    fn readiness_report_serializes_to_json() {
        let state = ReadinessState::new();
        let report = state.check();
        let json = serde_json::to_string(&report).expect("serialize");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("parse");
        assert_eq!(parsed["status"], "ok");
        assert!(parsed["checks"].is_object());
    }

    #[test]
    fn aggregate_status_all_ok() {
        let checks = [DependencyCheck::ok(), DependencyCheck::ok()];
        assert_eq!(aggregate_status(checks.iter()), CheckStatus::Ok);
    }

    #[test]
    fn aggregate_status_degraded_wins_over_ok() {
        let checks = [DependencyCheck::ok(), DependencyCheck::degraded("slow")];
        assert_eq!(aggregate_status(checks.iter()), CheckStatus::Degraded);
    }

    #[test]
    fn aggregate_status_unhealthy_wins_over_degraded() {
        let checks = [
            DependencyCheck::degraded("slow"),
            DependencyCheck::unhealthy("down"),
            DependencyCheck::ok(),
        ];
        assert_eq!(aggregate_status(checks.iter()), CheckStatus::Unhealthy);
    }

    #[test]
    fn aggregate_status_empty_is_ok() {
        let checks: [DependencyCheck; 0] = [];
        assert_eq!(aggregate_status(checks.iter()), CheckStatus::Ok);
    }

    #[test]
    fn check_status_json_variants() {
        assert_eq!(
            serde_json::to_string(&CheckStatus::Ok).expect("ser"),
            "\"ok\""
        );
        assert_eq!(
            serde_json::to_string(&CheckStatus::Degraded).expect("ser"),
            "\"degraded\""
        );
        assert_eq!(
            serde_json::to_string(&CheckStatus::Unhealthy).expect("ser"),
            "\"unhealthy\""
        );
    }

    #[test]
    fn dependency_check_ok_omits_message() {
        let check = DependencyCheck::ok();
        let json = serde_json::to_string(&check).expect("ser");
        let v: serde_json::Value = serde_json::from_str(&json).expect("parse");
        assert_eq!(v["status"], "ok");
        assert!(v.get("message").is_none());
    }

    #[test]
    fn dependency_check_degraded_includes_message() {
        let check = DependencyCheck::degraded("expiring soon");
        let json = serde_json::to_string(&check).expect("ser");
        let v: serde_json::Value = serde_json::from_str(&json).expect("parse");
        assert_eq!(v["status"], "degraded");
        assert_eq!(v["message"], "expiring soon");
    }

    #[test]
    fn dependency_check_unhealthy_includes_message() {
        let check = DependencyCheck::unhealthy("cert expired");
        let json = serde_json::to_string(&check).expect("ser");
        let v: serde_json::Value = serde_json::from_str(&json).expect("parse");
        assert_eq!(v["status"], "unhealthy");
        assert_eq!(v["message"], "cert expired");
    }

    #[test]
    fn tls_check_with_valid_cert() {
        use rustgate_test_utils::certs::TestCa;

        let ca = TestCa::new("test-ca");
        let server = ca.issue_server_cert("test-server", &["localhost"]);

        let dir = tempfile::tempdir().expect("tmpdir");
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        std::fs::write(&cert_path, &server.cert_pem).expect("write cert");
        std::fs::write(&key_path, &server.key_pem).expect("write key");

        let reloader =
            rustgate_transport::CertReloader::new(&cert_path, &key_path).expect("reloader");
        let check = check_tls_cert(&reloader);
        assert_eq!(check.status, CheckStatus::Ok);
    }

    #[test]
    fn tls_check_with_expired_cert() {
        use rustgate_test_utils::certs::TestCa;

        let ca = TestCa::new("test-ca");
        let expired = ca.issue_expired_client_cert("expired-server", &[]);

        let dir = tempfile::tempdir().expect("tmpdir");
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        std::fs::write(&cert_path, &expired.cert_pem).expect("write cert");
        std::fs::write(&key_path, &expired.key_pem).expect("write key");

        let reloader =
            rustgate_transport::CertReloader::new(&cert_path, &key_path).expect("reloader");
        let check = check_tls_cert(&reloader);
        assert_eq!(check.status, CheckStatus::Unhealthy);
        assert!(check.message.as_deref().unwrap_or("").contains("expired"));
    }

    #[test]
    fn tls_check_degraded_for_near_expiry_cert() {
        use rustgate_test_utils::certs::TestCa;

        let ca = TestCa::new("test-ca");
        // Certificate expires in 3 days — below the 7-day degraded threshold.
        let near_expiry = ca.issue_near_expiry_server_cert("expiring-server", &["localhost"], 3);

        let dir = tempfile::tempdir().expect("tmpdir");
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        std::fs::write(&cert_path, &near_expiry.cert_pem).expect("write cert");
        std::fs::write(&key_path, &near_expiry.key_pem).expect("write key");

        let reloader =
            rustgate_transport::CertReloader::new(&cert_path, &key_path).expect("reloader");
        let check = check_tls_cert(&reloader);
        assert_eq!(
            check.status,
            CheckStatus::Degraded,
            "cert expiring in 3 days should be degraded, got: {:?}",
            check
        );
        let msg = check.message.as_deref().unwrap_or("");
        assert!(
            msg.contains("expires"),
            "message should mention expiry: {msg}"
        );
    }

    #[test]
    fn readiness_response_unhealthy_when_not_ready() {
        let health = HealthState::new();
        let readiness = ReadinessState::new();
        // health.is_ready() defaults to false, so readiness should be unhealthy.
        let resp = readiness_response(&health, &readiness);
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn readiness_response_ok_when_ready_no_deps() {
        let health = HealthState::new();
        health.set_ready(true);
        let readiness = ReadinessState::new();
        let resp = readiness_response(&health, &readiness);
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
