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
    Encoder, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge, Opts, TextEncoder,
};
use rustgate_core::constants::HTTP_CONNECTION_TIMEOUT;

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

// Tier 2 (per-identity) metrics. Registered only when
// `--metrics-per-identity` is enabled; remain `None` otherwise so they
// add zero overhead.
static PER_IDENTITY_HANDSHAKE_FAILURES: OnceLock<IntCounterVec> = OnceLock::new();
static PER_IDENTITY_SESSION_DURATION: OnceLock<HistogramVec> = OnceLock::new();
static PER_IDENTITY_BYTES_SENT: OnceLock<IntCounterVec> = OnceLock::new();
static PER_IDENTITY_BYTES_RECEIVED: OnceLock<IntCounterVec> = OnceLock::new();
static SESSIONS_ACTIVE: OnceLock<IntGauge> = OnceLock::new();

static NATS_PUBLISHES: OnceLock<IntCounter> = OnceLock::new();

static NEGOTIATIONS: OnceLock<IntCounterVec> = OnceLock::new();

static HANDSHAKE_FAILURES: OnceLock<IntCounterVec> = OnceLock::new();

static CLIENT_QUEUE_DEPTH: OnceLock<prometheus::IntGaugeVec> = OnceLock::new();
static CLIENT_QUEUE_BYTES: OnceLock<prometheus::IntGaugeVec> = OnceLock::new();
static CLIENT_QUEUE_DROPS: OnceLock<IntCounter> = OnceLock::new();
static CLIENT_QUEUE_DRAINS: OnceLock<IntCounter> = OnceLock::new();
static CLIENT_QUEUE_ENQUEUES: OnceLock<IntCounter> = OnceLock::new();
static CLIENT_QUEUE_WRITER_DROPS: OnceLock<IntCounter> = OnceLock::new();
static CLIENT_QUEUE_EXPIRED: OnceLock<IntCounter> = OnceLock::new();
static CLIENT_QUEUE_SKIPPED_UNSUPPORTED: OnceLock<IntCounter> = OnceLock::new();

static ENROLLMENT_RATE_LIMITED: OnceLock<IntCounter> = OnceLock::new();

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

    let enrollment_rate_limited = IntCounter::with_opts(Opts::new(
        "rustgate_enrollment_rate_limited_total",
        "CSR signing requests rejected by the per-IP rate limiter",
    ))?;
    registry.register(Box::new(enrollment_rate_limited.clone()))?;
    let _ = ENROLLMENT_RATE_LIMITED.set(enrollment_rate_limited);

    Ok(())
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
    pub fn set_started(&self, v: bool) {
        self.started.store(v, Ordering::Release);
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

fn handle_request(
    req: Request<hyper::body::Incoming>,
    health: Arc<HealthState>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    match req.uri().path() {
        // Liveness: process loop is reachable. Returns 200 once the
        // metrics server is up; orchestrators interpret a non-200 as
        // "restart the pod".
        "/health/live" => Ok(probe_response(health.is_live(), "ok", "not live")),

        // Readiness: instance can accept traffic. Flips to 503 during
        // graceful shutdown so load balancers stop sending new requests.
        "/health/ready" => Ok(probe_response(health.is_ready(), "ok", "not ready")),

        // Startup: initial warmup complete. Allows slow-starting pods to
        // delay liveness/readiness checks during boot.
        "/health/startup" => Ok(probe_response(health.is_started(), "ok", "starting")),

        // Legacy aliases — kept for backwards compatibility. `/healthz`
        // mirrors `/health/live` and `/readyz` mirrors `/health/ready`.
        "/healthz" => Ok(probe_response(health.is_live(), "ok", "not live")),

        "/readyz" => Ok(probe_response(health.is_ready(), "ok", "not ready")),

        "/metrics" => {
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

/// Serve Prometheus metrics and health endpoints at the given address.
///
/// Routes:
/// - `GET /metrics`        — Prometheus text format
/// - `GET /health/live`    — Kubernetes liveness probe
/// - `GET /health/ready`   — Kubernetes readiness probe
/// - `GET /health/startup` — Kubernetes startup probe
/// - `GET /healthz`        — Deprecated alias for `/health/live`
/// - `GET /readyz`         — Deprecated alias for `/health/ready`
///
/// The server is hardened against unauthenticated abuse:
/// - Connection count bounded by [`MAX_HTTP_CONNECTIONS`]
/// - Per-connection timeout of [`HTTP_CONNECTION_TIMEOUT`]
/// - Header read timeout of 5 seconds
pub async fn serve(
    bind: SocketAddr,
    health: Arc<HealthState>,
    #[cfg(feature = "federation")] fed_api: Arc<OnceLock<FedApiHandler>>,
    acl_api: Arc<OnceLock<AclApiHandler>>,
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
        #[cfg(feature = "federation")]
        let fed_api = Arc::clone(&fed_api);
        let acl_api = Arc::clone(&acl_api);
        drop(tokio::spawn(async move {
            let _permit = permit;
            let conn = hyper::server::conn::http1::Builder::new()
                .timer(hyper_util::rt::TokioTimer::new())
                .header_read_timeout(Duration::from_secs(5))
                .serve_connection(
                    io,
                    service_fn(move |req: Request<hyper::body::Incoming>| {
                        let health = Arc::clone(&health);
                        #[cfg(feature = "federation")]
                        let fed_api = Arc::clone(&fed_api);
                        let acl_api = Arc::clone(&acl_api);
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
                            handle_request(req, health)
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
        // Mark ready for the bulk of the test; serve() flips live=true.
        health.set_ready(true);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        drop(listener);

        let server_health = Arc::clone(&health);
        drop(tokio::spawn(async move {
            let _ = serve(
                addr,
                server_health,
                #[cfg(feature = "federation")]
                Arc::new(OnceLock::new()),
                Arc::new(OnceLock::new()),
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

        // /health/ready returns 200 when ready.
        let (status, body) = http_get(addr, "/health/ready").await;
        assert_eq!(status, 200);
        assert_eq!(body, "ok");

        // Legacy alias /readyz mirrors /health/ready.
        let (status, _) = http_get(addr, "/readyz").await;
        assert_eq!(status, 200);

        // /health/startup is 503 until startup is marked complete.
        let (status, body) = http_get(addr, "/health/startup").await;
        assert_eq!(status, 503);
        assert_eq!(body, "starting");

        health.set_started(true);
        let (status, body) = http_get(addr, "/health/startup").await;
        assert_eq!(status, 200);
        assert_eq!(body, "ok");

        // /health/ready returns 503 after marking not ready (shutdown).
        health.set_ready(false);
        let (status, body) = http_get(addr, "/health/ready").await;
        assert_eq!(status, 503);
        assert_eq!(body, "not ready");
        let (status, _) = http_get(addr, "/readyz").await;
        assert_eq!(status, 503);

        // /metrics returns Prometheus text
        let (status, body) = http_get(addr, "/metrics").await;
        assert_eq!(status, 200);
        assert!(body.contains("rustgate_connections_accepted_total"));

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
}
