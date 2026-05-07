// Copyright © 2026 Roberto Chiofalo.

//! Prometheus metrics for rustgate.
//!
//! Exposes counters, gauges, and labels covering connection lifecycle,
//! message routing, NATS bridge, and protocol negotiation. All metrics
//! are registered with the default Prometheus registry and served at
//! `/metrics` via a lightweight hyper HTTP server.

use std::collections::HashSet;
use std::path::Path;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use prometheus::{
    Histogram, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge, Opts,
};
use rustgate_core::tasks::spawn_background;

// ── Metric statics ──────────────────────────────────────────────────

static BUILD_INFO: OnceLock<prometheus::IntGaugeVec> = OnceLock::new();

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
static MESSAGES_ROUTED_BY_KIND: OnceLock<IntCounterVec> = OnceLock::new();

static DEDUP_HITS: OnceLock<IntCounter> = OnceLock::new();
static DEDUP_CACHE_SIZE: OnceLock<IntGauge> = OnceLock::new();

static POSITION_CACHE_SIZE: OnceLock<IntGauge> = OnceLock::new();

static COT_DELTA_FULL: OnceLock<IntCounter> = OnceLock::new();
static COT_DELTA_DELTA: OnceLock<IntCounter> = OnceLock::new();
static COT_DELTA_SUPPRESSED: OnceLock<IntCounter> = OnceLock::new();
static COT_DELTA_BYTES_SAVED: OnceLock<IntCounter> = OnceLock::new();
static COT_DELTA_EVICTED: OnceLock<IntCounter> = OnceLock::new();
static COT_DELTA_OVERSIZED: OnceLock<IntCounter> = OnceLock::new();

// Tier 2 (per-identity) metrics. Registered only when
// `--metrics-per-identity` is enabled; remain `None` otherwise so they
// add zero overhead.
static PER_IDENTITY_HANDSHAKE_FAILURES: OnceLock<IntCounterVec> = OnceLock::new();
static PER_IDENTITY_SESSION_DURATION: OnceLock<HistogramVec> = OnceLock::new();
static PER_IDENTITY_BYTES_SENT: OnceLock<IntCounterVec> = OnceLock::new();
static PER_IDENTITY_BYTES_RECEIVED: OnceLock<IntCounterVec> = OnceLock::new();
static SESSIONS_ACTIVE: OnceLock<IntGauge> = OnceLock::new();

static NATS_PUBLISHES: OnceLock<IntCounter> = OnceLock::new();

#[cfg(feature = "mqtt")]
static MQTT_CONNECTIONS: OnceLock<IntCounter> = OnceLock::new();
#[cfg(feature = "mqtt")]
static MQTT_CONNECTIONS_REJECTED: OnceLock<IntCounter> = OnceLock::new();

#[cfg(feature = "websocket")]
static WS_CONNECTIONS: OnceLock<IntCounter> = OnceLock::new();
#[cfg(feature = "websocket")]
static WS_CONNECTIONS_REJECTED: OnceLock<IntCounter> = OnceLock::new();

#[cfg(feature = "mqtt")]
static MQTT_PUBLISHES: OnceLock<IntCounter> = OnceLock::new();
#[cfg(feature = "mqtt")]
static MQTT_PUBLISHES_REJECTED: OnceLock<IntCounter> = OnceLock::new();
#[cfg(feature = "mqtt")]
static MQTT_SUBSCRIBES: OnceLock<IntCounter> = OnceLock::new();
#[cfg(feature = "mqtt")]
static MQTT_SUBSCRIBES_REJECTED: OnceLock<IntCounter> = OnceLock::new();
#[cfg(feature = "mqtt")]
static MQTT_RETAIN_STORED: OnceLock<IntCounter> = OnceLock::new();
#[cfg(feature = "mqtt")]
static MQTT_RETAIN_CLEARED: OnceLock<IntCounter> = OnceLock::new();
#[cfg(feature = "mqtt")]
static MQTT_RETAIN_REPLAYED: OnceLock<IntCounter> = OnceLock::new();
#[cfg(feature = "mqtt")]
static MQTT_WILL_PUBLISHED: OnceLock<IntCounter> = OnceLock::new();

/// Operator-initiated graceful drain trigger. Labelled by `source` so
/// SIEM and dashboards can distinguish API-driven drains (Kubernetes
/// preStop hook firing `POST /api/drain`) from any future surface
/// (e.g. a SIGUSR2 handler) that fans into the same shutdown `Notify`.
/// Closes #791.
static ADMIN_DRAIN_TRIGGERED: OnceLock<IntCounterVec> = OnceLock::new();

static MAVLINK_HEARTBEATS: OnceLock<IntCounterVec> = OnceLock::new();

/// Multicast messages dropped because the destination group list
/// exceeded the router's `MAX_MULTICAST_GROUPS` cap. Closes #741: this
/// path was previously observable only via `tracing::warn` so operators
/// could not dashboard or alert on the drop rate.
static MULTICAST_OVERSIZE_DROPPED: OnceLock<IntCounter> = OnceLock::new();

/// SA (situational-awareness) payloads whose `<event version=…>`
/// attribute was rewritten from a legacy form to the current
/// `2.0` envelope, labelled by `from_version` (`"v1"`,
/// `"v2-pre-2.0"`). Closes #741: the auto-upgrade path was previously
/// silent, so fleet-upgrade-progress dashboards had nothing to plot.
static SA_AUTO_UPGRADED: OnceLock<IntCounterVec> = OnceLock::new();

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
static TLS_HANDSHAKE_DURATION_SECONDS: OnceLock<HistogramVec> = OnceLock::new();

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
/// Per-message dwell time distribution for store-forward drain. Issue
/// #729 — observed once per drained message with the value
/// `drain_time - queued_at`. Operationally answers "how long did
/// messages actually sit in the offline queue?" without conflating
/// that with `received_at`, which is the original origin time and
/// would inflate dwell on messages that rode multiple transports
/// before queueing.
static STORE_FORWARD_DWELL_SECONDS: OnceLock<Histogram> = OnceLock::new();

#[cfg(feature = "federation")]
static FEDERATION_PEER_QUEUE_BYTES: OnceLock<prometheus::IntGaugeVec> = OnceLock::new();
#[cfg(feature = "federation")]
static FEDERATION_PEER_OLDEST_SECONDS: OnceLock<prometheus::IntGaugeVec> = OnceLock::new();
#[cfg(feature = "federation")]
static FEDERATION_PEER_LATENCY_NANOS: OnceLock<prometheus::IntGaugeVec> = OnceLock::new();

static AUTHZ_DECISIONS: OnceLock<IntCounterVec> = OnceLock::new();
static AUTHZ_EVAL_NANOS: OnceLock<Histogram> = OnceLock::new();
static AUTHZ_RELOADS: OnceLock<IntCounterVec> = OnceLock::new();
static AUTHZ_POLICY_RULES: OnceLock<IntGauge> = OnceLock::new();
static AUTHZ_CACHE_HITS: OnceLock<IntCounter> = OnceLock::new();
static AUTHZ_CACHE_MISSES: OnceLock<IntCounter> = OnceLock::new();
static RELOAD_ROLLBACK: OnceLock<IntCounterVec> = OnceLock::new();
static AUTHZ_OBLIGATION_UNKNOWN: OnceLock<IntCounterVec> = OnceLock::new();
/// Live count of in-flight authz evaluations holding the engine `Arc`
/// cloned out of the router's `ArcSwap`. Issue #721: the
/// `ArcSwap`-based hot-reload is lock-free and a `swap_authz` install
/// is atomic for *future* `.load()` calls, but already-running
/// evaluations continue against the pre-swap engine until they
/// finish. This gauge is the operator-visible drain signal — when it
/// returns to its pre-swap baseline, every evaluation that observed
/// the previous engine has retired.
static AUTHZ_EVALUATIONS_IN_FLIGHT: OnceLock<IntGauge> = OnceLock::new();

// ── Router fanout, PEP, and obligation metrics (issue #768) ─────────
//
// Operationally additive: every metric below is registered only when
// `--features metrics` is on, and the router-side callbacks that feed
// them are installed only under the same cfg gate. Builds without the
// feature observe identical behaviour to pre-#768.

static ROUTER_FANOUT_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();
static ROUTER_FANOUT_SUBSCRIBERS: OnceLock<Histogram> = OnceLock::new();
static ROUTER_DROPPED_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();
static PEP_SEND_DECISIONS: OnceLock<IntCounterVec> = OnceLock::new();
static PEP_RECEIVE_DECISIONS: OnceLock<IntCounterVec> = OnceLock::new();
static PEP_EVALUATION_SECONDS: OnceLock<HistogramVec> = OnceLock::new();
static OBLIGATION_APPLIED_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();
static OBLIGATION_FAILURES_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();

static ARCHIVE_BYTES: OnceLock<IntGauge> = OnceLock::new();
static CRL_AGE_SECONDS: OnceLock<IntGauge> = OnceLock::new();
static ENROLLMENT_RATE_LIMITED: OnceLock<IntCounter> = OnceLock::new();
static ENROLLMENT_RATE_LIMIT_POISON: OnceLock<IntCounter> = OnceLock::new();
static TENANT_QUOTA_REJECTIONS: OnceLock<IntCounterVec> = OnceLock::new();
// Issue #883 sub-item 4: per-tenant aggregate-throughput metrics.
static TENANT_THROUGHPUT_REJECTIONS: OnceLock<IntCounterVec> = OnceLock::new();
static TENANT_THROUGHPUT_BPS: OnceLock<prometheus::GaugeVec> = OnceLock::new();

#[cfg(feature = "spiffe")]
static SPIFFE_SVID_REFRESH_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();
#[cfg(feature = "spiffe")]
static SPIFFE_SVID_EXPIRY_SECONDS: OnceLock<IntGauge> = OnceLock::new();

// jemalloc is POSIX-only (see `tikv-jemallocator` target gate in
// `Cargo.toml`); pair the feature flag with `not(target_os = "windows")`
// so the per-allocator gauges only register on platforms where the
// underlying allocator can actually run. Refs #831 (F-B).
#[cfg(all(feature = "jemalloc", not(target_os = "windows")))]
static JEMALLOC_RESIDENT: OnceLock<IntGauge> = OnceLock::new();
#[cfg(all(feature = "jemalloc", not(target_os = "windows")))]
static JEMALLOC_ACTIVE: OnceLock<IntGauge> = OnceLock::new();
#[cfg(all(feature = "jemalloc", not(target_os = "windows")))]
static JEMALLOC_ALLOCATED: OnceLock<IntGauge> = OnceLock::new();
#[cfg(all(feature = "jemalloc", not(target_os = "windows")))]
static JEMALLOC_MAPPED: OnceLock<IntGauge> = OnceLock::new();

// ── Fallback constructors ───────────────────────────────────────────
//
// When `init()` has not been called, accessor functions lazily create
// an unregistered metric via `OnceLock::get_or_init()`. The helpers
// live in `rustgate_metrics` so every crate following the
// `OnceLock` + `init()` + accessor pattern shares one implementation.

use rustgate_metrics::{
    fallback_counter, fallback_counter_vec, fallback_gauge, fallback_histogram,
    fallback_histogram_vec,
};

/// Labels emitted on the `rustgate_build_info` gauge.
///
/// Fixed at compile time — the metric carries one time series over the
/// lifetime of a process, so the values never change after startup and
/// any Grafana `topk` / `group by` over these labels is safe to run on
/// cardinality grounds. Version tracking across a fleet works by diffing
/// the label set visible at scrape time, which is the conventional
/// Prometheus `*_build_info` pattern.
pub(crate) const BUILD_INFO_LABELS: &[&str] = &["version", "rust_version", "features"];

/// Return the comma-separated list of optional features enabled at
/// compile time, ordered to match [`BUILD_INFO_LABELS`].
///
/// Each `cfg!` macro is resolved at compile time by rustc so the string
/// is computed once per build. `metrics` is always present because this
/// function only compiles under `#[cfg(feature = "metrics")]` in the
/// first place; it is listed explicitly so operators grepping the
/// scraped output see the full active feature set.
pub(crate) fn enabled_features() -> String {
    let mut features: Vec<&'static str> = Vec::new();
    features.push("metrics");
    if cfg!(feature = "nats") {
        features.push("nats");
    }
    if cfg!(feature = "enrollment") {
        features.push("enrollment");
    }
    if cfg!(feature = "est") {
        features.push("est");
    }
    if cfg!(feature = "proto") {
        features.push("proto");
    }
    if cfg!(feature = "full-detail") {
        features.push("full-detail");
    }
    if cfg!(feature = "federation") {
        features.push("federation");
    }
    if cfg!(feature = "federation-ha") {
        features.push("federation-ha");
    }
    if cfg!(feature = "peer-discovery-dns-sd") {
        features.push("peer-discovery-dns-sd");
    }
    if cfg!(feature = "peer-discovery-consul") {
        features.push("peer-discovery-consul");
    }
    if cfg!(feature = "peer-discovery-etcd") {
        features.push("peer-discovery-etcd");
    }
    if cfg!(feature = "websocket") {
        features.push("websocket");
    }
    if cfg!(feature = "mqtt") {
        features.push("mqtt");
    }
    if cfg!(feature = "otel") {
        features.push("otel");
    }
    if cfg!(feature = "fips") {
        features.push("fips");
    }
    if cfg!(feature = "post-quantum") {
        features.push("post-quantum");
    }
    if cfg!(feature = "jemalloc") {
        features.push("jemalloc");
    }
    if cfg!(feature = "ocsp") {
        features.push("ocsp");
    }
    if cfg!(feature = "spiffe") {
        features.push("spiffe");
    }
    if cfg!(feature = "cedar") {
        features.push("cedar");
    }
    if cfg!(feature = "http") {
        features.push("http");
    }
    features.join(",")
}

// ── Registration ────────────────────────────────────────────────────

/// Register all metrics with the default Prometheus registry.
/// Must be called once at startup before any metrics are recorded.
pub fn init() -> prometheus::Result<()> {
    let registry = prometheus::default_registry();

    // Standard Prometheus `*_build_info` gauge — a single time series
    // pinned at value 1 for the active (version, rust_version, features)
    // tuple. Grafana queries use `count by (version) (rustgate_build_info)`
    // to observe rollout progress across a fleet, and `rustgate_build_info{version!~"0\\.8\\..*"}`
    // alerts when instances lag behind the approved release window.
    let build_info = prometheus::IntGaugeVec::new(
        Opts::new(
            "rustgate_build_info",
            "Build metadata for this rustgate process (version, rust_version, features). Always 1.",
        ),
        BUILD_INFO_LABELS,
    )?;
    registry.register(Box::new(build_info.clone()))?;
    let features = enabled_features();
    build_info
        .with_label_values(&[
            env!("CARGO_PKG_VERSION"),
            env!("CARGO_PKG_RUST_VERSION"),
            features.as_str(),
        ])
        .set(1);
    let _ = BUILD_INFO.set(build_info);

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

    let position_cache_size = IntGauge::with_opts(Opts::new(
        "rustgate_position_cache_size",
        "Current number of entries in the latest-position cache \
         (one per client CN). Bounded by the cache's `max_entries` \
         capacity (default 100,000); sustained growth near the cap \
         indicates either a large active fleet or leaked stale entries \
         from clients that never disconnected. Alert on approach to \
         capacity: `rustgate_position_cache_size / 100000 > 0.9`.",
    ))?;
    registry.register(Box::new(position_cache_size.clone()))?;
    let _ = POSITION_CACHE_SIZE.set(position_cache_size);

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

    let cot_delta_evicted = IntCounter::with_opts(Opts::new(
        "rustgate_cot_delta_evicted_total",
        "UIDs evicted from the per-session delta encoder cache under capacity pressure — sustained non-zero rate indicates cache_size is undersized",
    ))?;
    registry.register(Box::new(cot_delta_evicted.clone()))?;
    let _ = COT_DELTA_EVICTED.set(cot_delta_evicted);

    let cot_delta_oversized = IntCounter::with_opts(Opts::new(
        "rustgate_cot_delta_oversized_total",
        "Outbound CoT events whose payload exceeded the delta encoder scan limit and were forcibly emitted as full — alert on sustained rate (indicates legitimate large events OR hostile padding to defeat delta compression)",
    ))?;
    registry.register(Box::new(cot_delta_oversized.clone()))?;
    let _ = COT_DELTA_OVERSIZED.set(cot_delta_oversized);

    let messages_routed = IntCounterVec::new(
        Opts::new(
            "rustgate_messages_routed_total",
            "Messages routed by destination type and source identity",
        ),
        &["destination", "identity_cn"],
    )?;
    registry.register(Box::new(messages_routed.clone()))?;
    let _ = MESSAGES_ROUTED.set(messages_routed);

    // Closes #847. Per-kind routed-message counter, labelled by the
    // canonical `EntityKind::as_str()` tag (`aircraft`, `ground`,
    // `marine`, `sensor`, `track`, `munition`, `unknown`) and the
    // `metadata.source_protocol` string. Cardinality is bounded by the
    // closed `EntityKind` vocabulary; the protocol label is also a
    // small fixed vocabulary in practice (`cot`, `mavlink`, `asterix`,
    // `stanag4586`, `nats`, `federation`, `tcp`, `websocket`, …) — the
    // operator who registers a codec for a new protocol is the same
    // operator who controls the metric label, so this is not an
    // attacker-controlled axis.
    let messages_routed_by_kind = IntCounterVec::new(
        Opts::new(
            "rustgate_messages_routed_by_kind_total",
            "Messages routed by canonical EntityKind and source_protocol — populated when an EntityCodecRegistry is installed; \"unknown\" covers unregistered protocols and codec parse failures",
        ),
        &["kind", "protocol"],
    )?;
    registry.register(Box::new(messages_routed_by_kind.clone()))?;
    let _ = MESSAGES_ROUTED_BY_KIND.set(messages_routed_by_kind);

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

    #[cfg(feature = "mqtt")]
    {
        let mqtt_connections = IntCounter::with_opts(Opts::new(
            "rustgate_mqtt_connections_total",
            "mTLS-authenticated MQTT sessions accepted by the MQTT listener. \
             Incremented after the TLS handshake and client-certificate \
             validation succeed and the shared cross-transport connection-limit \
             permit is acquired, immediately before the per-session task is \
             spawned. Does not count TLS handshake failures, certificate \
             validation failures, or per-IP rate-limit rejections — those are \
             visible via the shared listener-level counters.",
        ))?;
        registry.register(Box::new(mqtt_connections.clone()))?;
        let _ = MQTT_CONNECTIONS.set(mqtt_connections);

        let mqtt_connections_rejected = IntCounter::with_opts(Opts::new(
            "rustgate_mqtt_connections_rejected_total",
            "MQTT connections rejected because the shared cross-transport \
             connection-limit semaphore was saturated at the moment the session \
             was about to be admitted. A non-zero rate indicates the operator \
             should either raise `--max-connections` or investigate whether a \
             misbehaving client is consuming the budget.",
        ))?;
        registry.register(Box::new(mqtt_connections_rejected.clone()))?;
        let _ = MQTT_CONNECTIONS_REJECTED.set(mqtt_connections_rejected);
    }

    #[cfg(feature = "websocket")]
    {
        let ws_connections = IntCounter::with_opts(Opts::new(
            "rustgate_ws_connections_total",
            "WebSocket sessions successfully registered (post-mTLS, post-upgrade, post-tenant-quota)",
        ))?;
        registry.register(Box::new(ws_connections.clone()))?;
        let _ = WS_CONNECTIONS.set(ws_connections);

        let ws_connections_rejected = IntCounter::with_opts(Opts::new(
            "rustgate_ws_connections_rejected_total",
            "WebSocket connections rejected on the session-handler boundary (per-IP rate limit, TLS, identity, upgrade, connection-limit, tenant quota)",
        ))?;
        registry.register(Box::new(ws_connections_rejected.clone()))?;
        let _ = WS_CONNECTIONS_REJECTED.set(ws_connections_rejected);
    }

    #[cfg(feature = "mqtt")]
    {
        let mqtt_publishes = IntCounter::with_opts(Opts::new(
            "rustgate_mqtt_publishes_total",
            "MQTT PUBLISH packets authorised and handed to the router for \
             delivery. Incremented exactly once per PUBLISH after topic \
             validation, prefix mapping, and group-membership authorisation \
             all pass. A flat-lined value while `rustgate_mqtt_connections_\
             total` is still climbing indicates clients are connecting but not \
             publishing — typically a credential-scope mismatch on the \
             producer side.",
        ))?;
        registry.register(Box::new(mqtt_publishes.clone()))?;
        let _ = MQTT_PUBLISHES.set(mqtt_publishes);

        let mqtt_publishes_rejected = IntCounter::with_opts(Opts::new(
            "rustgate_mqtt_publishes_rejected_total",
            "MQTT PUBLISH packets rejected by the session handler before \
             reaching the router. Covers QoS2 (unsupported), topic validation \
             failures, prefix-mapping failures, and group-membership \
             authorisation failures. A rising rate on this counter with a flat \
             `rustgate_mqtt_publishes_total` indicates clients are publishing \
             but routinely violating topic or authorisation contracts.",
        ))?;
        registry.register(Box::new(mqtt_publishes_rejected.clone()))?;
        let _ = MQTT_PUBLISHES_REJECTED.set(mqtt_publishes_rejected);

        let mqtt_subscribes = IntCounter::with_opts(Opts::new(
            "rustgate_mqtt_subscribes_total",
            "MQTT SUBSCRIBE topic filters successfully bound to an authorised \
             group. Incremented *per filter*, not per SUBSCRIBE packet — a \
             single SUBSCRIBE carrying three filters may produce up to three \
             increments — so the counter tracks actual group bindings rather \
             than raw packet counts.",
        ))?;
        registry.register(Box::new(mqtt_subscribes.clone()))?;
        let _ = MQTT_SUBSCRIBES.set(mqtt_subscribes);

        let mqtt_subscribes_rejected = IntCounter::with_opts(Opts::new(
            "rustgate_mqtt_subscribes_rejected_total",
            "MQTT SUBSCRIBE topic filters rejected by the session handler. \
             Covers QoS2 (unsupported), filter invalid under the active \
             wildcard policy, and authorisation failures (no mapping to an \
             authorised group). Incremented *per filter*, mirroring \
             `rustgate_mqtt_subscribes_total` — a SUBSCRIBE with three filters \
             where two are denied produces two increments on this counter and \
             one on the successful counter.",
        ))?;
        registry.register(Box::new(mqtt_subscribes_rejected.clone()))?;
        let _ = MQTT_SUBSCRIBES_REJECTED.set(mqtt_subscribes_rejected);

        let mqtt_retain_stored = IntCounter::with_opts(Opts::new(
            "rustgate_mqtt_retain_stored_total",
            "MQTT PUBLISH packets that inserted or overwrote a retained \
             message in the broker's last-known-value store (retain=1, \
             non-empty payload). Operators can divide this by \
             `rustgate_mqtt_publishes_total` to gauge what fraction of \
             traffic is `retain=1` — sudden swings often correlate with \
             operator config changes (a fleet flipping its retain bit on \
             startup) and are useful for capacity planning.",
        ))?;
        registry.register(Box::new(mqtt_retain_stored.clone()))?;
        let _ = MQTT_RETAIN_STORED.set(mqtt_retain_stored);

        let mqtt_retain_cleared = IntCounter::with_opts(Opts::new(
            "rustgate_mqtt_retain_cleared_total",
            "MQTT PUBLISH packets that triggered the MQTT 5.0 §3.3.1.3 \
             zero-byte clear semantic against the broker's retain store \
             (retain=1 AND zero-length payload). Always non-decreasing; a \
             flat line on this counter while `rustgate_mqtt_retain_stored_\
             total` climbs indicates clients are setting retained values \
             but never clearing them — the operational signal that the \
             retain store will keep growing for the listener's lifetime.",
        ))?;
        registry.register(Box::new(mqtt_retain_cleared.clone()))?;
        let _ = MQTT_RETAIN_CLEARED.set(mqtt_retain_cleared);

        let mqtt_retain_replayed = IntCounter::with_opts(Opts::new(
            "rustgate_mqtt_retain_replayed_total",
            "MQTT retained messages delivered as PUBLISH packets to fresh \
             subscribers. Incremented *per delivered message*, not per \
             SUBSCRIBE — a single SUBSCRIBE whose filter expands to N \
             retained topics produces N increments. The authorisation \
             re-check runs before the increment fires, so this counter \
             only counts replays the subscriber was actually allowed to \
             receive. A spike correlates with an operator opening a wide \
             wildcard subscribe across the retain set; flat-lined values \
             typically mean the broker has not yet stored anything to \
             replay.",
        ))?;
        registry.register(Box::new(mqtt_retain_replayed.clone()))?;
        let _ = MQTT_RETAIN_REPLAYED.set(mqtt_retain_replayed);
        let mqtt_will_published = IntCounter::with_opts(Opts::new(
            "rustgate_mqtt_will_published_total",
            "MQTT will messages published on a client's behalf when the \
             connection ended ungracefully (TLS error, keep-alive timeout, \
             write-loop early exit, abrupt TCP close — anything that is NOT \
             a clean DISCONNECT). Fires AFTER the will payload has been \
             routed via `Router::route_for_egress` and only on the \
             ungraceful path; clean DISCONNECT (MQTT 3.1.1 §3.14 / 5.0 \
             §3.14.4 NormalDisconnection) suppresses the will and does not \
             increment this counter. A spike correlates with a partition \
             or a fleet of clients hitting their keep-alive timeout — the \
             operational signal is 'presence-loss is happening at scale, \
             look at the network'.",
        ))?;
        registry.register(Box::new(mqtt_will_published.clone()))?;
        let _ = MQTT_WILL_PUBLISHED.set(mqtt_will_published);
    }

    let mavlink_heartbeats = IntCounterVec::new(
        Opts::new(
            "rustgate_mavlink_heartbeats_total",
            "MAVLink HEARTBEAT (MSG_ID 0) frames received and decoded at the \
             framing layer, labelled by `system_id` (the v1/v2 header field). \
             A typical drone fleet emits HEARTBEATs at 1 Hz, so the counter \
             gives a per-aircraft presence ping at the wire level — useful \
             for correlating 'aircraft fell off the network' SIEM events with \
             dashboard signals like network partition or radio link drop. \
             Cardinality is bounded by the size of the fleet (system_id is a \
             u8, max 256 distinct values), and the counter is always-on \
             across builds because the metric registry is shared by every \
             rustgate process regardless of which transport listeners are \
             wired in.",
        ),
        &["system_id"],
    )?;
    registry.register(Box::new(mavlink_heartbeats.clone()))?;
    let _ = MAVLINK_HEARTBEATS.set(mavlink_heartbeats);

    // Closes #741. Multicast UDP CoT receivers (and the central
    // router) drop messages whose destination group list exceeds the
    // internal `MAX_MULTICAST_GROUPS` cap. Previously this surface was
    // observable only via tracing — there was no Prometheus counter
    // operators could alert on, so capacity-exhaustion incidents were
    // visible only in log aggregation. The counter increments once
    // per dropped multicast message, keyed off the existing router
    // drop site via the `OnMulticastOversizeDropped` callback wired at
    // server startup.
    let multicast_oversize_dropped = IntCounter::with_opts(Opts::new(
        "rustgate_multicast_oversize_dropped_total",
        "Multicast messages dropped because the destination group list \
         exceeded the router's `MAX_MULTICAST_GROUPS` cap. Operators alert \
         on a non-zero rate to catch a misconfigured publisher fanning out \
         to thousands of groups (amplification-DoS shape) or a broken \
         federation peer that lost its group-membership view and fell back \
         to a wildcard fanout. Counter is always-on; it is wired by the \
         server binary via the router's \
         `set_on_multicast_oversize_dropped` callback under \
         `#[cfg(feature = \"metrics\")]`. Closes #741.",
    ))?;
    registry.register(Box::new(multicast_oversize_dropped.clone()))?;
    let _ = MULTICAST_OVERSIZE_DROPPED.set(multicast_oversize_dropped);

    // Closes #741. SA (situational-awareness) auto-upgrade rewrites
    // legacy `<event version=…>` envelopes (`v1` for missing-version
    // payloads, `v2-pre-2.0` for `version="1.x"`) to the current
    // `2.0` form so the rest of the pipeline only ever sees the
    // canonical shape. The counter exposes the rewrite rate per
    // `from_version` so fleet dashboards can plot upgrade progress —
    // a healthy roll-out trends the `v1` and `v2-pre-2.0` curves
    // toward zero as legacy senders rotate to current clients.
    let sa_auto_upgraded = IntCounterVec::new(
        Opts::new(
            "rustgate_sa_auto_upgraded_total",
            "SA (situational-awareness) payloads whose `<event version=…>` \
             attribute was rewritten from a legacy form to the current \
             `2.0` envelope, labelled by `from_version`. The two \
             current label values are `v1` (no version attribute on \
             the `<event>` tag) and `v2-pre-2.0` (a `version=\"…\"` \
             value below 2.0). Cardinality is bounded by the small \
             fixed set of legacy buckets — finer granularity (e.g. \
             `1.0`, `1.5`) was rejected because most pre-2.0 \
             senders in the wild are `1.0` and label inflation would \
             complicate dashboards without adding operational signal. \
             Wired by the server binary at startup via \
             `MessageBuilder::with_on_sa_upgraded`. Closes #741.",
        ),
        &["from_version"],
    )?;
    registry.register(Box::new(sa_auto_upgraded.clone()))?;
    let _ = SA_AUTO_UPGRADED.set(sa_auto_upgraded);

    let admin_drain_triggered = IntCounterVec::new(
        Opts::new(
            "rustgate_admin_drain_triggered_total",
            "Operator-initiated graceful drain triggers, labelled by \
             `source`. `source=\"api\"` covers `POST /api/drain` invoked by \
             the Kubernetes preStop hook (closes #791); the label exists so \
             SIEM and dashboards can attribute API-initiated drains \
             separately from SIGTERM-initiated drains, which would otherwise \
             collapse into one indistinguishable stream during a rolling \
             upgrade. Cardinality is bounded — only a small fixed set of \
             documented source tokens is ever emitted.",
        ),
        &["source"],
    )?;
    registry.register(Box::new(admin_drain_triggered.clone()))?;
    let _ = ADMIN_DRAIN_TRIGGERED.set(admin_drain_triggered);

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

    // Bucket range picked for tactical mTLS handshakes:
    //  - Floor 1 ms captures ring/aws-lc-rs best-case LAN handshakes
    //    (typical ~2–5 ms); a coarser floor would collapse the P50
    //    into the first bucket on healthy deployments.
    //  - 100–500 ms brackets cross-WAN and PQ/hybrid kx groups
    //    (ML-KEM-768 adds ~30–60 ms per round trip on commodity CPUs).
    //  - Ceiling 10 s catches pathological stalls before the TLS
    //    acceptor surrenders; anything slower is a bug, not a bucket.
    let tls_handshake_duration_seconds = HistogramVec::new(
        HistogramOpts::new(
            "rustgate_tls_handshake_duration_seconds",
            "TLS handshake duration in seconds, labelled by outcome",
        )
        .buckets(vec![
            0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
        ]),
        &["outcome"],
    )?;
    registry.register(Box::new(tls_handshake_duration_seconds.clone()))?;
    let _ = TLS_HANDSHAKE_DURATION_SECONDS.set(tls_handshake_duration_seconds);

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

    // Issue #729: per-message dwell histogram. Buckets cover the
    // operationally meaningful range from sub-second (a client that
    // briefly disconnected during a TCP retransmit storm) up to ~6h
    // (an extended outage). The 1s floor keeps the head of the
    // distribution from collapsing into the implicit 0 bucket on
    // healthy reconnects; the 21600s ceiling matches the longest
    // outages we expect to observe before the operator manually
    // discards the queue. Anything above 6h almost certainly means
    // queue retention policy is misconfigured — a separate signal
    // from "messages ride a long but bounded outage", which is what
    // this histogram is here to characterize.
    let store_forward_dwell_seconds = Histogram::with_opts(
        HistogramOpts::new(
            "rustgate_store_forward_dwell_seconds",
            "Per-message dwell time spent in the store-forward offline queue \
             (drain_time - queued_at), in seconds",
        )
        .buckets(vec![1.0, 10.0, 60.0, 300.0, 1800.0, 7200.0, 21600.0]),
    )?;
    registry.register(Box::new(store_forward_dwell_seconds.clone()))?;
    let _ = STORE_FORWARD_DWELL_SECONDS.set(store_forward_dwell_seconds);

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

        let federation_peer_latency_nanos = prometheus::IntGaugeVec::new(
            Opts::new(
                "rustgate_federation_peer_latency_nanos",
                "EWMA round-trip latency to a federation peer in nanoseconds",
            ),
            &["peer"],
        )?;
        registry.register(Box::new(federation_peer_latency_nanos.clone()))?;
        let _ = FEDERATION_PEER_LATENCY_NANOS.set(federation_peer_latency_nanos);
    }

    let archive_bytes = IntGauge::with_opts(Opts::new(
        "rustgate_archive_bytes",
        "Total bytes currently held in the CoT event archive directory",
    ))?;
    registry.register(Box::new(archive_bytes.clone()))?;
    let _ = ARCHIVE_BYTES.set(archive_bytes);

    // Age of the stalest loaded CRL, in seconds. Set at startup after CRL
    // parsing and refreshed on SIGHUP reload. A growing value means the
    // CRL publisher has stopped refreshing; alert on >86400 (24h) to
    // catch stalled revocation pipelines before cert lifecycles lapse.
    let crl_age_seconds = IntGauge::with_opts(Opts::new(
        "rustgate_crl_age_seconds",
        "Seconds since the stalest loaded CRL's `thisUpdate` timestamp \
         (maximum across all configured CRLs). Stays at 0 when no CRL is \
         configured. Refreshed at startup and on SIGHUP. Alert on >86400 \
         (24h) to detect CRL publishers that have stopped refreshing.",
    ))?;
    registry.register(Box::new(crl_age_seconds.clone()))?;
    let _ = CRL_AGE_SECONDS.set(crl_age_seconds);

    let enrollment_rate_limited = IntCounter::with_opts(Opts::new(
        "rustgate_enrollment_rate_limited_total",
        "CSR signing requests rejected by the per-IP rate limiter",
    ))?;
    registry.register(Box::new(enrollment_rate_limited.clone()))?;
    let _ = ENROLLMENT_RATE_LIMITED.set(enrollment_rate_limited);

    // Pre-#798 this counter incremented per request observed while the
    // std::sync::Mutex-backed RateLimiter was poisoned (issue #767).
    // The unified `SlidingWindowLimiter` uses `parking_lot::Mutex`
    // which does not poison; the counter is retained at registration
    // time so operator dashboards do not 404, but it remains
    // permanently zero. Operators may safely retire the alert.
    let enrollment_rate_limit_poison = IntCounter::with_opts(Opts::new(
        "rustgate_enrollment_rate_limit_poison_total",
        "Pre-#798 enrollment rate-limiter mutex poison counter (now permanently zero — parking_lot::Mutex does not poison)",
    ))?;
    registry.register(Box::new(enrollment_rate_limit_poison.clone()))?;
    let _ = ENROLLMENT_RATE_LIMIT_POISON.set(enrollment_rate_limit_poison);

    let tenant_quota_rejections = IntCounterVec::new(
        Opts::new(
            "rustgate_tenant_quota_rejections_total",
            "Sessions rejected because the tenant connection quota was exceeded",
        ),
        &["tenant"],
    )?;
    registry.register(Box::new(tenant_quota_rejections.clone()))?;
    let _ = TENANT_QUOTA_REJECTIONS.set(tenant_quota_rejections);

    // Issue #883 sub-item 4: per-tenant aggregate-throughput metrics.
    // The token-bucket layer in `TenantQuotaTracker` fires
    // `OnTenantThroughputRejection` once per dropped message and
    // `OnTenantThroughputConsumed` once per acquire (admit OR reject)
    // with the post-decision bucket level — let operators see both
    // total rejections and current headroom in a single dashboard.
    let tenant_throughput_rejections = IntCounterVec::new(
        Opts::new(
            "rustgate_tenant_throughput_rejections_total",
            "Messages dropped because the per-tenant aggregate-throughput token bucket was exhausted",
        ),
        &["tenant"],
    )?;
    registry.register(Box::new(tenant_throughput_rejections.clone()))?;
    let _ = TENANT_THROUGHPUT_REJECTIONS.set(tenant_throughput_rejections);

    let tenant_throughput_bps = prometheus::GaugeVec::new(
        Opts::new(
            "rustgate_tenant_throughput_bps",
            "Current aggregate-throughput token-bucket level (bytes) per tenant; updated on every send admit or reject",
        ),
        &["tenant"],
    )?;
    registry.register(Box::new(tenant_throughput_bps.clone()))?;
    let _ = TENANT_THROUGHPUT_BPS.set(tenant_throughput_bps);

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

    // Issue #721: in-flight authz evaluations gauge. Observation-only
    // — the value rises by `+1` on entry to every PEP evaluation and
    // falls by `-1` on the corresponding RAII guard drop. Operators
    // monitoring an `Router::swap_authz` reload watch this gauge for
    // the post-swap drain time: when it returns to the pre-swap
    // baseline, every evaluation that observed the previous policy
    // engine has retired.
    let authz_evaluations_in_flight = IntGauge::with_opts(Opts::new(
        "rustgate_authz_evaluations_in_flight",
        "In-flight authz evaluations currently holding the engine Arc cloned \
         out of the router's ArcSwap; observe this gauge after a SIGHUP / \
         policy reload to determine when the previous engine has fully drained",
    ))?;
    registry.register(Box::new(authz_evaluations_in_flight.clone()))?;
    let _ = AUTHZ_EVALUATIONS_IN_FLIGHT.set(authz_evaluations_in_flight);

    // Subsystem-labelled rollback counter for #818. Operators page on
    // a non-zero `rate(rustgate_reload_rollback_total{subsystem="authz"}[5m])`
    // because a sustained rollback rate means the on-disk policy is
    // diverging from what the broker enforces — the kind of silent
    // drift that pre-this-PR only surfaced through tracing logs. The
    // `subsystem` label keeps a single counter family covering authz,
    // ACL, CRL, and any future hot-reload subsystem rather than
    // multiplying counters per reload path.
    let reload_rollback = IntCounterVec::new(
        Opts::new(
            "rustgate_reload_rollback_total",
            "Hot-reload failures that rolled back to the previously installed policy, \
             labelled by subsystem (authz, acl, crl, ...)",
        ),
        &["subsystem"],
    )?;
    registry.register(Box::new(reload_rollback.clone()))?;
    let _ = RELOAD_ROLLBACK.set(reload_rollback);

    // Issue #769 (F-3b): unknown-obligation encounter counter. The
    // sibling per-(policy_id, variant) audit-rate-limiter (F-3a)
    // suppresses repeated audit-log emissions for a misconfigured
    // policy that returns the same unknown variant on every routed
    // message; this counter increments on EVERY encounter regardless
    // of audit suppression so operator dashboards see the true rate.
    // Operators page on `rate(rustgate_authz_obligation_unknown_total[5m])`.
    let authz_obligation_unknown = IntCounterVec::new(
        Opts::new(
            "rustgate_authz_obligation_unknown_total",
            "Unknown authz obligation variants encountered by the transport, \
             labelled by `{:?}` rendering of the variant (issue #769)",
        ),
        &["variant"],
    )?;
    registry.register(Box::new(authz_obligation_unknown.clone()))?;
    let _ = AUTHZ_OBLIGATION_UNKNOWN.set(authz_obligation_unknown);

    // ── Router fanout / PEP / obligation metrics (issue #768) ──────
    //
    // Bounded label vocabularies — the router callbacks installed by
    // `setup`/`main` only emit static `&'static str` keys, so cardinality
    // is fixed at compile time regardless of policy or workload shape.

    let router_fanout_total = IntCounterVec::new(
        Opts::new(
            "rustgate_router_fanout_total",
            "Number of `Router::route_for_egress` calls that reached a \
             terminal fan-out, labelled by `destination` \
             (`direct`, `group`, `broadcast`, `multicast`). Operators \
             alert on a sudden imbalance between destinations or a \
             flatlined `direct` rate against a climbing connection \
             count (typical signal of broken store-and-forward).",
        ),
        &["destination"],
    )?;
    registry.register(Box::new(router_fanout_total.clone()))?;
    let _ = ROUTER_FANOUT_TOTAL.set(router_fanout_total);

    // Buckets cover the operationally meaningful range from a unicast
    // direct (1) up to a fleet-wide broadcast (1000+). The 0-bucket
    // captures the no-subscribers / fully-filtered case, which is a
    // distinct operational signal from a small fan-out.
    let router_fanout_subscribers = Histogram::with_opts(
        HistogramOpts::new(
            "rustgate_router_fanout_subscribers",
            "Distribution of recipient counts per `Router::route_for_egress` call. \
             Observes the number of sessions the router successfully delivered \
             to (post-ACL, post-authz, post-obligation), NOT the candidate pool \
             size. The 0-bucket captures fully-filtered fan-outs.",
        )
        .buckets(vec![0.0, 1.0, 5.0, 10.0, 50.0, 100.0, 500.0, 1000.0]),
    )?;
    registry.register(Box::new(router_fanout_subscribers.clone()))?;
    let _ = ROUTER_FANOUT_SUBSCRIBERS.set(router_fanout_subscribers);

    let router_dropped_total = IntCounterVec::new(
        Opts::new(
            "rustgate_router_dropped_total",
            "Recipients (or whole messages) the router dropped after \
             admission, labelled by `reason` \
             (`no_subscribers`, `backpressure`, `acl_denied`, \
             `authz_denied`, `obligation_failed`). Same `reason` \
             vocabulary the audit log emits — Prometheus dashboards and \
             SIEM pivots stay in lock-step.",
        ),
        &["reason"],
    )?;
    registry.register(Box::new(router_dropped_total.clone()))?;
    let _ = ROUTER_DROPPED_TOTAL.set(router_dropped_total);

    let pep_send_decisions = IntCounterVec::new(
        Opts::new(
            "rustgate_pep_send_decisions_total",
            "Send-PEP decisions emitted by the router, labelled by \
             `decision` (`allow`, `deny`, `fail_open`). Sibling counter \
             to `rustgate_pep_receive_decisions_total` — the two are \
             kept separate so dashboards can graph allow/deny ratios by \
             direction without pivoting on a label.",
        ),
        &["decision"],
    )?;
    registry.register(Box::new(pep_send_decisions.clone()))?;
    let _ = PEP_SEND_DECISIONS.set(pep_send_decisions);

    let pep_receive_decisions = IntCounterVec::new(
        Opts::new(
            "rustgate_pep_receive_decisions_total",
            "Receive-PEP decisions emitted by the router, labelled by \
             `decision` (`allow`, `deny`, `fail_open`). Sibling of \
             `rustgate_pep_send_decisions_total`.",
        ),
        &["decision"],
    )?;
    registry.register(Box::new(pep_receive_decisions.clone()))?;
    let _ = PEP_RECEIVE_DECISIONS.set(pep_receive_decisions);

    // Same bucket family as the existing nanosecond histogram but in
    // seconds — Prometheus best practice is one canonical SI unit per
    // exposition. The floor is 50 ns so the same dashboards that read
    // `rustgate_authz_eval_nanos` see a consistent P50 here, with a
    // 10s ceiling to catch pathological evaluations (anything above is
    // a bug, not a bucket worth widening for).
    let pep_evaluation_seconds = HistogramVec::new(
        HistogramOpts::new(
            "rustgate_pep_evaluation_seconds",
            "Wall-clock PEP evaluation latency in seconds, labelled by \
             `direction` (`send`, `receive`, `other`). Covers the same \
             call sites as `rustgate_authz_eval_nanos` but in canonical \
             SI units; both are kept registered so existing dashboards \
             do not break.",
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
            10.0,
        ]),
        &["direction"],
    )?;
    registry.register(Box::new(pep_evaluation_seconds.clone()))?;
    let _ = PEP_EVALUATION_SECONDS.set(pep_evaluation_seconds);

    let obligation_applied_total = IntCounterVec::new(
        Opts::new(
            "rustgate_obligation_applied_total",
            "Data-plane authz obligations actually applied to outbound \
             messages, labelled by `kind` (`mask_point`, `mask_payload`, \
             `tag_classified`, `audit_extended`, `unknown`). One \
             increment per applied obligation, per outbound copy — \
             emitted alongside the existing `authz.classified_delivery` \
             audit record so operators can correlate the metric rate \
             with the audit trail. `unknown` is bounded by a single \
             label value because the authz crate's `Obligation` enum \
             is `#[non_exhaustive]` and a future variant must not grow \
             Prometheus cardinality without an explicit transport \
             update.",
        ),
        &["kind"],
    )?;
    registry.register(Box::new(obligation_applied_total.clone()))?;
    let _ = OBLIGATION_APPLIED_TOTAL.set(obligation_applied_total);

    let obligation_failures_total = IntCounterVec::new(
        Opts::new(
            "rustgate_obligation_failures_total",
            "Obligation actuation failures encountered by the router, \
             labelled by `reason` (`mask_point_non_xml`, \
             `mask_point_xml_error`, `mask_point_io_error`, \
             `mask_point_attr_budget_exceeded`, `unknown_variant`). \
             Mirrors the `reason` field on the audit log emitted by \
             [`rustgate_core::audit::authz_obligation_failed`] so SIEM \
             correlation rules and Prometheus alert rules stay in \
             lock-step. Closes #768.",
        ),
        &["reason"],
    )?;
    registry.register(Box::new(obligation_failures_total.clone()))?;
    let _ = OBLIGATION_FAILURES_TOTAL.set(obligation_failures_total);

    #[cfg(all(feature = "jemalloc", not(target_os = "windows")))]
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
pub fn observe_authz_event(ev: &rustgate_router::AuthzEvent<'_>) {
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

/// Record a hot-reload rollback for a subsystem.
///
/// Increments `rustgate_reload_rollback_total{subsystem=<name>}` at
/// every call site that detected a failed reload and kept the
/// previously installed policy active. Paired with the
/// `*.reload_rollback` audit event so SIEM correlation rules can match
/// metric and audit-log signals from the same incident. Closes #818
/// (F-144).
///
/// `subsystem` is one of the documented values (`"authz"`, `"acl"`,
/// `"crl"`); new subsystems gain coverage by adding the same call at
/// their reload-failure site.
pub fn record_reload_rollback(subsystem: &str) {
    if let Ok(child) = reload_rollback().get_metric_with_label_values(&[subsystem]) {
        child.inc();
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

/// Subsystem-labelled rollback counter; see [`record_reload_rollback`]
/// for the call-site contract and #818 for context.
pub fn reload_rollback() -> &'static IntCounterVec {
    RELOAD_ROLLBACK.get_or_init(|| {
        fallback_counter_vec("rustgate_reload_rollback_total", "fallback", &["subsystem"])
    })
}

/// Unknown-obligation encounter counter (issue #769, F-3b).
///
/// Incremented once per encounter at the
/// [`rustgate_router::obligations::ObligationRateLimiter`] callback
/// boundary, **before** the per-`(policy_id, variant)` audit-rate-limit
/// gate. The counter therefore reflects every unknown-variant
/// encounter, not just the audit emissions that survived rate-limiting.
/// Wired into the transport via
/// [`rustgate_router::obligations::ObligationRateLimiter::with_on_unknown`]
/// at server startup.
pub fn authz_obligation_unknown() -> &'static IntCounterVec {
    AUTHZ_OBLIGATION_UNKNOWN.get_or_init(|| {
        fallback_counter_vec(
            "rustgate_authz_obligation_unknown_total",
            "fallback",
            &["variant"],
        )
    })
}

// ── Router fanout / PEP / obligation accessors (issue #768) ─────────

/// Per-destination router-fanout counter. Wired by the server binary
/// at startup via [`rustgate_router::Router::set_on_fanout`] under
/// `#[cfg(feature = "metrics")]`. Closes #768.
pub fn router_fanout_total() -> &'static IntCounterVec {
    ROUTER_FANOUT_TOTAL.get_or_init(|| {
        fallback_counter_vec("rustgate_router_fanout_total", "fallback", &["destination"])
    })
}

/// Histogram of recipient counts per fanout. Closes #768.
pub fn router_fanout_subscribers() -> &'static Histogram {
    ROUTER_FANOUT_SUBSCRIBERS
        .get_or_init(|| fallback_histogram("rustgate_router_fanout_subscribers", "fallback"))
}

/// Per-reason router-drop counter. Wired by the server binary at
/// startup via [`rustgate_router::Router::set_on_dropped`] under
/// `#[cfg(feature = "metrics")]`. Closes #768.
pub fn router_dropped_total() -> &'static IntCounterVec {
    ROUTER_DROPPED_TOTAL.get_or_init(|| {
        fallback_counter_vec("rustgate_router_dropped_total", "fallback", &["reason"])
    })
}

/// Send-PEP decision counter. Wired alongside
/// [`router_fanout_total`] via `OnPepDecision` at startup.
pub fn pep_send_decisions() -> &'static IntCounterVec {
    PEP_SEND_DECISIONS.get_or_init(|| {
        fallback_counter_vec(
            "rustgate_pep_send_decisions_total",
            "fallback",
            &["decision"],
        )
    })
}

/// Receive-PEP decision counter. Sibling of
/// [`pep_send_decisions`].
pub fn pep_receive_decisions() -> &'static IntCounterVec {
    PEP_RECEIVE_DECISIONS.get_or_init(|| {
        fallback_counter_vec(
            "rustgate_pep_receive_decisions_total",
            "fallback",
            &["decision"],
        )
    })
}

/// Per-direction PEP evaluation latency histogram (seconds).
pub fn pep_evaluation_seconds() -> &'static HistogramVec {
    PEP_EVALUATION_SECONDS.get_or_init(|| {
        fallback_histogram_vec(
            "rustgate_pep_evaluation_seconds",
            "fallback",
            &["direction"],
        )
    })
}

/// Per-kind data-plane obligation-applied counter. Closes #768.
pub fn obligation_applied_total() -> &'static IntCounterVec {
    OBLIGATION_APPLIED_TOTAL.get_or_init(|| {
        fallback_counter_vec("rustgate_obligation_applied_total", "fallback", &["kind"])
    })
}

/// Per-reason obligation actuation failure counter. The label
/// vocabulary mirrors the `reason` field emitted by
/// [`rustgate_core::audit::authz_obligation_failed`]. Wired by the
/// server binary at startup via
/// [`rustgate_router::obligations::ObligationRateLimiter::with_on_failure`]
/// under `#[cfg(feature = "metrics")]`. Closes #768.
pub fn obligation_failures_total() -> &'static IntCounterVec {
    OBLIGATION_FAILURES_TOTAL.get_or_init(|| {
        fallback_counter_vec(
            "rustgate_obligation_failures_total",
            "fallback",
            &["reason"],
        )
    })
}

/// Build the [`rustgate_router::OnFanout`] callback that feeds the
/// `rustgate_router_fanout_total{destination}` counter and the
/// `rustgate_router_fanout_subscribers` histogram. Wired by the server
/// binary once at startup so every fan-out observed by the router
/// funnels into the same metrics. Closes #768.
pub fn router_fanout_callback() -> rustgate_router::OnFanout {
    Arc::new(|destination: &'static str, subscribers: u64| {
        router_fanout_total()
            .with_label_values(&[destination])
            .inc();
        // `as f64` is safe — `u64::MAX` is rounded into the +inf bucket
        // and the histogram is only ever read for distribution shape,
        // not exact counts.
        router_fanout_subscribers().observe(subscribers as f64);
    })
}

/// Build the [`rustgate_router::OnDropped`] callback that feeds the
/// `rustgate_router_dropped_total{reason}` counter. Closes #768.
pub fn router_dropped_callback() -> rustgate_router::OnDropped {
    Arc::new(|reason: &'static str| {
        router_dropped_total().with_label_values(&[reason]).inc();
    })
}

/// Build the [`rustgate_router::OnPepDecision`] callback that feeds
/// the Send/Receive PEP counters and the per-direction evaluation
/// latency histogram. The router emits direction labels `"send"`,
/// `"receive"`, or `"other"`; the callback maps the first two to the
/// dedicated counter and bins everything else under the histogram so
/// future `AuthzAction` variants stay observable without extra
/// counters. Closes #768.
pub fn router_pep_decision_callback() -> rustgate_router::OnPepDecision {
    Arc::new(
        |direction: &'static str, decision: &'static str, eval_secs: f64| {
            match direction {
                "send" => pep_send_decisions().with_label_values(&[decision]).inc(),
                "receive" => pep_receive_decisions().with_label_values(&[decision]).inc(),
                _ => {}
            }
            pep_evaluation_seconds()
                .with_label_values(&[direction])
                .observe(eval_secs);
        },
    )
}

/// Build the [`rustgate_router::OnObligationApplied`] callback that
/// feeds the `rustgate_obligation_applied_total{kind}` counter. Closes
/// #768.
pub fn router_obligation_applied_callback() -> rustgate_router::OnObligationApplied {
    Arc::new(|kind: &'static str| {
        obligation_applied_total().with_label_values(&[kind]).inc();
    })
}

/// Accessor for the in-flight authz-evaluations gauge. Issue #721.
pub fn authz_evaluations_in_flight() -> &'static IntGauge {
    AUTHZ_EVALUATIONS_IN_FLIGHT
        .get_or_init(|| fallback_gauge("rustgate_authz_evaluations_in_flight", "fallback"))
}

/// Build the [`rustgate_router::OnAuthzInFlightChanged`] callback
/// that feeds the `rustgate_authz_evaluations_in_flight` gauge with
/// the signed `+1` / `-1` deltas emitted by the router's RAII
/// `AuthzEvalGuard`. Wired by the server binary once at startup so
/// every authz evaluation observed by the router contributes to the
/// gauge — and so the gauge is a faithful drain signal across an
/// `Router::swap_authz` policy reload. Closes #721.
pub fn router_authz_in_flight_callback() -> rustgate_router::OnAuthzInFlightChanged {
    Arc::new(|delta: i64| {
        authz_evaluations_in_flight().add(delta);
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
// justification: accessor exposed for the federation admin API (issue #778)
// and for integration tests that assert on peer-lag gauges without poking
// Prometheus default registry. Kept `pub` so the rustgate-federation crate
// can read it once wired, without re-registering a parallel gauge.
#[cfg(feature = "federation")]
#[allow(dead_code)]
pub fn federation_peer_queue_bytes() -> Option<&'static prometheus::IntGaugeVec> {
    FEDERATION_PEER_QUEUE_BYTES.get()
}

/// Returns the federation per-peer oldest-message-age gauge vector.
// justification: sibling of `federation_peer_queue_bytes` — same
// admin-API/tests rationale; the two are consumed as a pair.
#[cfg(feature = "federation")]
#[allow(dead_code)]
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
            let (lag_snapshot, latency_snapshot) = {
                let guard = manager.read().await;
                (guard.peer_lag_snapshot(), guard.peer_latency_snapshot())
            };
            let bytes_vec = FEDERATION_PEER_QUEUE_BYTES.get();
            let oldest_vec = FEDERATION_PEER_OLDEST_SECONDS.get();
            let latency_vec = FEDERATION_PEER_LATENCY_NANOS.get();
            let mut current: std::collections::HashSet<String> = std::collections::HashSet::new();
            for (peer, bytes, oldest) in &lag_snapshot {
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
            for (peer, nanos) in &latency_snapshot {
                if let Some(g) = latency_vec
                    && let Ok(child) = g.get_metric_with_label_values(&[peer.as_str()])
                {
                    child.set(*nanos as i64);
                }
            }
            for stale in known_peers.difference(&current) {
                if let Some(g) = bytes_vec {
                    let _ = g.remove_label_values(&[stale.as_str()]);
                }
                if let Some(g) = oldest_vec {
                    let _ = g.remove_label_values(&[stale.as_str()]);
                }
                if let Some(g) = latency_vec {
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

/// Returns the CRL-age gauge. The value is the age in seconds of the
/// stalest loaded CRL's `thisUpdate` field. Refreshed at startup after
/// CRL parsing and after every SIGHUP-driven CRL re-validation.
pub fn crl_age_seconds() -> &'static IntGauge {
    CRL_AGE_SECONDS.get_or_init(|| fallback_gauge("rustgate_crl_age_seconds", "fallback"))
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

// justification: registered counter with no increment site yet — the router
// does not currently observe TTL drops at the session layer (planned as part
// of issue #887 session-side observability). Registering the metric now keeps
// the Prometheus schema stable for operators who already scrape it.
#[allow(dead_code)]
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

pub fn position_cache_size() -> &'static IntGauge {
    POSITION_CACHE_SIZE.get_or_init(|| fallback_gauge("rustgate_position_cache_size", "fallback"))
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

pub fn cot_delta_evicted() -> &'static IntCounter {
    COT_DELTA_EVICTED
        .get_or_init(|| fallback_counter("rustgate_cot_delta_evicted_total", "fallback"))
}

pub fn cot_delta_oversized() -> &'static IntCounter {
    COT_DELTA_OVERSIZED
        .get_or_init(|| fallback_counter("rustgate_cot_delta_oversized_total", "fallback"))
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

/// Accessor for the per-kind routed-message counter (closes #847).
///
/// Labelled by the canonical [`rustgate_core::entity::EntityKind::as_str`]
/// tag and the `metadata.source_protocol` string. Use the wired-up
/// [`router_routed_by_kind_callback`] to emit observations rather than
/// poking this counter directly — the callback runs inside the router's
/// dispatch path so a single hot-path observation site stays
/// authoritative.
pub fn messages_routed_by_kind() -> &'static IntCounterVec {
    MESSAGES_ROUTED_BY_KIND.get_or_init(|| {
        fallback_counter_vec(
            "rustgate_messages_routed_by_kind_total",
            "fallback",
            &["kind", "protocol"],
        )
    })
}

/// Build the [`rustgate_router::OnRoutedByKind`] callback that feeds
/// the `rustgate_messages_routed_by_kind_total{kind, protocol}` counter.
/// Wired by the server binary at startup so every admitted message
/// (post-Send-PEP) increments the counter once. Closes #847.
pub fn router_routed_by_kind_callback() -> rustgate_router::OnRoutedByKind {
    Arc::new(|kind: &'static str, protocol: &str| {
        messages_routed_by_kind()
            .with_label_values(&[kind, protocol])
            .inc();
    })
}

pub fn sessions_active() -> &'static IntGauge {
    SESSIONS_ACTIVE.get_or_init(|| fallback_gauge("rustgate_sessions_active", "fallback"))
}

pub fn nats_publishes() -> &'static IntCounter {
    NATS_PUBLISHES.get_or_init(|| fallback_counter("rustgate_nats_publishes_total", "fallback"))
}

/// Counter incremented once per mTLS-authenticated MQTT session accepted
/// by the MQTT listener. Wired from `rustgate_mqtt::MqttServerConfig::on_accept`.
#[cfg(feature = "mqtt")]
pub fn mqtt_connections() -> &'static IntCounter {
    MQTT_CONNECTIONS.get_or_init(|| fallback_counter("rustgate_mqtt_connections_total", "fallback"))
}

/// Counter incremented once per MQTT connection rejected because the
/// shared cross-transport connection-limit semaphore was saturated.
/// Wired from `rustgate_mqtt::MqttServerConfig::on_reject`.
#[cfg(feature = "mqtt")]
pub fn mqtt_connections_rejected() -> &'static IntCounter {
    MQTT_CONNECTIONS_REJECTED
        .get_or_init(|| fallback_counter("rustgate_mqtt_connections_rejected_total", "fallback"))
}

/// Accepted WebSocket session counter. Fired once per session the router
/// successfully registers (post-mTLS, post-upgrade, post-tenant-quota).
#[cfg(feature = "websocket")]
pub fn ws_connections() -> &'static IntCounter {
    WS_CONNECTIONS.get_or_init(|| fallback_counter("rustgate_ws_connections_total", "fallback"))
}

/// Rejected WebSocket connection counter. Fired once per connection refused
/// on the session-handler boundary. Reasons are retained in the audit trail
/// (`rustgate_core::audit::connection_rejected`); this counter tracks the
/// aggregate rate for dashboards and alerting.
#[cfg(feature = "websocket")]
pub fn ws_connections_rejected() -> &'static IntCounter {
    WS_CONNECTIONS_REJECTED
        .get_or_init(|| fallback_counter("rustgate_ws_connections_rejected_total", "fallback"))
}

/// Counter incremented once per MQTT PUBLISH authorised and handed to
/// the router for delivery. Wired from
/// `rustgate_mqtt::MqttSessionHooks::on_publish`.
#[cfg(feature = "mqtt")]
pub fn mqtt_publishes() -> &'static IntCounter {
    MQTT_PUBLISHES.get_or_init(|| fallback_counter("rustgate_mqtt_publishes_total", "fallback"))
}

/// Counter incremented once per MQTT PUBLISH rejected by the session
/// handler (QoS2 unsupported, topic validation, prefix mapping, or
/// authorisation failure). Wired from
/// `rustgate_mqtt::MqttSessionHooks::on_publish_reject`.
#[cfg(feature = "mqtt")]
pub fn mqtt_publishes_rejected() -> &'static IntCounter {
    MQTT_PUBLISHES_REJECTED
        .get_or_init(|| fallback_counter("rustgate_mqtt_publishes_rejected_total", "fallback"))
}

/// Counter incremented once per MQTT SUBSCRIBE topic filter bound to an
/// authorised group. Wired from
/// `rustgate_mqtt::MqttSessionHooks::on_subscribe`.
#[cfg(feature = "mqtt")]
pub fn mqtt_subscribes() -> &'static IntCounter {
    MQTT_SUBSCRIBES.get_or_init(|| fallback_counter("rustgate_mqtt_subscribes_total", "fallback"))
}

/// Counter incremented once per MQTT SUBSCRIBE topic filter rejected by
/// the session handler. Wired from
/// `rustgate_mqtt::MqttSessionHooks::on_subscribe_reject`.
#[cfg(feature = "mqtt")]
pub fn mqtt_subscribes_rejected() -> &'static IntCounter {
    MQTT_SUBSCRIBES_REJECTED
        .get_or_init(|| fallback_counter("rustgate_mqtt_subscribes_rejected_total", "fallback"))
}

/// Counter incremented once per MQTT PUBLISH that inserted or
/// overwrote a retained message in the broker's last-known-value
/// store. Wired from `rustgate_mqtt::MqttSessionHooks::on_retain_stored`.
#[cfg(feature = "mqtt")]
pub fn mqtt_retain_stored() -> &'static IntCounter {
    MQTT_RETAIN_STORED
        .get_or_init(|| fallback_counter("rustgate_mqtt_retain_stored_total", "fallback"))
}

/// Counter incremented once per MQTT PUBLISH that triggered the
/// MQTT 5.0 §3.3.1.3 zero-byte clear semantic against the broker's
/// retain store. Wired from
/// `rustgate_mqtt::MqttSessionHooks::on_retain_cleared`.
#[cfg(feature = "mqtt")]
pub fn mqtt_retain_cleared() -> &'static IntCounter {
    MQTT_RETAIN_CLEARED
        .get_or_init(|| fallback_counter("rustgate_mqtt_retain_cleared_total", "fallback"))
}

/// Counter incremented once per retained MQTT message delivered to a
/// fresh subscriber after a successful SUBSCRIBE. Wired from
/// `rustgate_mqtt::MqttSessionHooks::on_retain_replayed`.
#[cfg(feature = "mqtt")]
pub fn mqtt_retain_replayed() -> &'static IntCounter {
    MQTT_RETAIN_REPLAYED
        .get_or_init(|| fallback_counter("rustgate_mqtt_retain_replayed_total", "fallback"))
}

/// Counter incremented once per MQTT will message published on a
/// client's behalf when the connection ended ungracefully. Wired from
/// `rustgate_mqtt::MqttSessionHooks::on_will_published`.
#[cfg(feature = "mqtt")]
pub fn mqtt_will_published() -> &'static IntCounter {
    MQTT_WILL_PUBLISHED
        .get_or_init(|| fallback_counter("rustgate_mqtt_will_published_total", "fallback"))
}

/// Per-source counter for operator-initiated graceful drain triggers
/// (`POST /api/drain` from the Kubernetes preStop hook, closes #791).
///
/// The `source` label is a short token like `"api"` for the management
/// endpoint. The fallback constructor preserves the same shape so the
/// accessor is safe to call before [`init`] runs — required by the
/// crate-wide convention that fallback metrics keep the same label
/// dimensionality.
pub fn admin_drain_triggered() -> &'static IntCounterVec {
    ADMIN_DRAIN_TRIGGERED.get_or_init(|| {
        fallback_counter_vec(
            "rustgate_admin_drain_triggered_total",
            "fallback",
            &["source"],
        )
    })
}

/// Per-system_id counter for MAVLink HEARTBEAT (MSG_ID 0) frame
/// receipts at the framing layer. The label is the wire-level
/// `system_id` byte rendered as a decimal string (`"42"`, `"7"`,
/// etc.) — Prometheus expects `&str`, so callers must `.to_string()`
/// the `u8` at the call site. Cardinality is bounded by `u8::MAX + 1`
/// (256 distinct labels), well below the per-metric limit a typical
/// scrape-target pipeline accepts.
///
/// Wired from `rustgate_mavlink::OnMavlinkHeartbeat` callbacks
/// installed under `#[cfg(feature = "metrics")]` at the future MAVLink
/// listener wiring point — incrementing the counter once per decoded
/// HEARTBEAT frame.
// justification: registered at startup via `init()` for the Prometheus
// exposition surface; the increment site lands with the MAVLink UDP/TCP
// listener wiring (forward reference to issue #909, of which this is
// the framing-layer half). Until then the accessor is `pub` so the
// metric is exposed at `/metrics` immediately and operators can begin
// shipping dashboards before the increment lights up.
#[allow(dead_code)]
pub fn mavlink_heartbeats() -> &'static IntCounterVec {
    MAVLINK_HEARTBEATS.get_or_init(|| {
        fallback_counter_vec(
            "rustgate_mavlink_heartbeats_total",
            "fallback",
            &["system_id"],
        )
    })
}

/// Counter for multicast messages dropped because the destination
/// group list exceeded the router's `MAX_MULTICAST_GROUPS` cap. Wired
/// to the router via `rustgate_router::Router::set_on_multicast_oversize_dropped`
/// at server startup under `#[cfg(feature = "metrics")]`. Closes #741.
pub fn multicast_oversize_dropped() -> &'static IntCounter {
    MULTICAST_OVERSIZE_DROPPED
        .get_or_init(|| fallback_counter("rustgate_multicast_oversize_dropped_total", "fallback"))
}

/// Counter for SA payloads whose `<event version=…>` attribute was
/// rewritten by the auto-upgrade path. Labelled by `from_version`
/// (`"v1"` for missing-attribute payloads, `"v2-pre-2.0"` for
/// `version="1.x"` payloads). Wired via
/// [`rustgate_cot::MessageBuilder::with_on_sa_upgraded`] at server
/// startup under `#[cfg(feature = "metrics")]`. Closes #741.
pub fn sa_auto_upgraded() -> &'static IntCounterVec {
    SA_AUTO_UPGRADED.get_or_init(|| {
        fallback_counter_vec(
            "rustgate_sa_auto_upgraded_total",
            "fallback",
            &["from_version"],
        )
    })
}

/// Build the [`rustgate_cot::OnSaAutoUpgraded`] callback that feeds the
/// `rustgate_sa_auto_upgraded_total{from_version}` counter. Each
/// transport that constructs a [`rustgate_cot::MessageBuilder`] calls
/// this once at startup and passes the result through
/// [`rustgate_cot::MessageBuilder::with_on_sa_upgraded`] so every
/// upgrade observed across every listener funnels into the same
/// counter family. Closes #741.
pub fn sa_auto_upgraded_callback() -> rustgate_cot::OnSaAutoUpgraded {
    Arc::new(|label: &str| {
        sa_auto_upgraded().with_label_values(&[label]).inc();
    })
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

// justification: only the `proto` feature increments this counter (TAK
// protocol-version negotiation). Left unconditionally `pub` so the metric
// exposition is identical across feature sets — operators do not need a
// branched dashboard for the proto build vs the default build.
#[allow(dead_code)]
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

/// Histogram of TLS handshake durations in seconds, labelled by
/// `outcome="success"` or `outcome="failure"`. Populated via the
/// `TlsListener::set_on_handshake_duration` callback installed under
/// `#[cfg(feature = "metrics")]` at startup.
pub fn tls_handshake_duration_seconds() -> &'static HistogramVec {
    TLS_HANDSHAKE_DURATION_SECONDS.get_or_init(|| {
        fallback_histogram_vec(
            "rustgate_tls_handshake_duration_seconds",
            "fallback",
            &["outcome"],
        )
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
#[cfg(all(feature = "jemalloc", not(target_os = "windows")))]
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
// justification: incremented only on the `ocsp` feature path inside the
// transport crate; the accessor is kept `pub` + unconditional so the server
// metrics module has one place to list the full OCSP metric surface.
// Gating this with `#[cfg(feature = "ocsp")]` would fragment the exposition
// in a way that operators on a non-ocsp build would see as "missing metrics".
#[allow(dead_code)]
pub fn client_ocsp_cache_hits() -> Option<&'static IntCounter> {
    CLIENT_OCSP_CACHE_HITS.get()
}

/// Returns the client-cert OCSP cache miss counter.
// justification: sibling of `client_ocsp_cache_hits` — same ocsp-feature
// rationale, same rationale for staying unconditional.
#[allow(dead_code)]
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

/// Counter for CSR signing requests observed while the enrollment
/// server's rate-limiter state mutex is poisoned (issue #767 / F-41).
///
/// Pre-#798 a non-zero sample indicated a prior panic while holding
/// the lock and the limiter was fail-closed. After the unification of
/// the rate limiter onto `parking_lot::Mutex` in #798, the underlying
/// lock can no longer poison and this counter remains permanently
/// zero. The accessor is retained so the metric registration stays
/// reachable and external dashboards / Prometheus rules that scrape
/// this counter continue to find it (returning a zero sample is the
/// strongest possible "no poison ever observed" signal).
// justification: the metric stays registered for dashboard
// compatibility — the counter is permanently zero post-#798 because
// `parking_lot::Mutex` does not poison, and no internal call site
// touches it any longer. Removing the accessor would force
// downstream consumers (Grafana panels, alert rules) to update at
// the same time as this PR; keeping it is the operationally
// additive choice. The `dead_code` warning fires precisely because
// of this no-internal-caller property; suppressing it documents the
// trade-off explicitly.
#[cfg(feature = "enrollment")]
#[allow(dead_code)]
pub fn enrollment_rate_limit_poison() -> &'static IntCounter {
    ENROLLMENT_RATE_LIMIT_POISON
        .get_or_init(|| fallback_counter("rustgate_enrollment_rate_limit_poison_total", "fallback"))
}

/// Per-tenant quota rejection counter, labelled by `tenant`.
pub fn tenant_quota_rejections() -> &'static IntCounterVec {
    TENANT_QUOTA_REJECTIONS.get_or_init(|| {
        fallback_counter_vec(
            "rustgate_tenant_quota_rejections_total",
            "fallback",
            &["tenant"],
        )
    })
}

/// Per-tenant aggregate-throughput rejection counter (issue #883
/// sub-item 4). Labelled by `tenant`. Increments once per message
/// dropped by the per-tenant token bucket; pair with
/// `rustgate_tenant_throughput_bps` to see both current headroom and
/// drop rate in the same panel.
pub fn tenant_throughput_rejections() -> &'static IntCounterVec {
    TENANT_THROUGHPUT_REJECTIONS.get_or_init(|| {
        fallback_counter_vec(
            "rustgate_tenant_throughput_rejections_total",
            "fallback",
            &["tenant"],
        )
    })
}

/// Per-tenant aggregate-throughput level gauge (issue #883
/// sub-item 4), in bytes. Updated on every send admit or reject
/// with the post-decision bucket level so a Prometheus scrape sees
/// the same value the next acquire would observe.
///
/// Returns `None` if `init()` was not called and the fallback
/// constructor failed — callers gate their `.set()` on the
/// presence of the metric, matching the workspace pattern for
/// tier-1 instruments that test paths construct without `init()`.
pub fn tenant_throughput_bps() -> Option<&'static prometheus::GaugeVec> {
    if let Some(g) = TENANT_THROUGHPUT_BPS.get() {
        return Some(g);
    }
    // Fallback for callers that bypass `init()` (rare). On the
    // expected `init()` path the gauge is registered with the
    // default registry and `TENANT_THROUGHPUT_BPS.get()` above
    // returns it. The fallback keeps the accessor non-panicking
    // even if a future refactor calls it before init.
    let fallback = prometheus::GaugeVec::new(
        Opts::new("rustgate_tenant_throughput_bps", "fallback"),
        &["tenant"],
    )
    .ok()?;
    let _ = TENANT_THROUGHPUT_BPS.set(fallback);
    TENANT_THROUGHPUT_BPS.get()
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

/// Returns the per-message store-forward dwell histogram (issue #729).
///
/// Falls back to a non-registered fallback when `init()` was not
/// called (so the accessor is safe in tests) but in production this is
/// `Some` whenever the metrics layer has been initialized. Observing
/// against the fallback is a no-op for `/metrics` consumers but keeps
/// the call site straightforward — the same shape the other
/// `&'static Histogram` accessors use.
pub fn store_forward_dwell_seconds() -> &'static Histogram {
    STORE_FORWARD_DWELL_SECONDS.get_or_init(|| {
        fallback_histogram(
            "rustgate_store_forward_dwell_seconds",
            "Per-message dwell time spent in the store-forward offline queue, in seconds",
        )
    })
}

/// Spawn a background task that periodically samples the given client
/// queue and updates the Prometheus metrics. CN labels are bucketed
/// against `identity` to bound label cardinality.
///
/// The task exits when the queue's last `Arc` reference is dropped.
pub fn spawn_client_queue_metrics_task(
    queue: Arc<rustgate_router::ClientQueue>,
    identity: Arc<MetricsIdentity>,
) {
    use std::collections::HashMap;
    spawn_background("client-queue-metrics", async move {
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
    });
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
    // justification: read by `per_identity_enabled()` and consumed by
    // callers wiring the Tier 2 per-identity histograms. Clippy flags the
    // field because the constructor stores it without any internal method
    // consuming it, but the accessor below (also `#[allow(dead_code)]` for
    // the same reason) is the entire point of the field.
    #[allow(dead_code)]
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
    // justification: ergonomic constructor for tests and external embedders
    // (the rustgate-client integration test binary uses this to silence
    // cardinality without threading `Option<HashSet>` through every call).
    // Used outside this crate, so clippy's dead-code heuristic misses it.
    #[allow(dead_code)]
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
    // justification: external observers (tests, admin API) query this to
    // decide whether to scrape the Tier-2 histogram set. There is no
    // internal caller; the method exists for callers outside this crate.
    #[allow(dead_code)]
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
        #[cfg(feature = "mqtt")]
        {
            let _ = mqtt_connections();
            let _ = mqtt_connections_rejected();
            let _ = mqtt_publishes();
            let _ = mqtt_publishes_rejected();
            let _ = mqtt_subscribes();
            let _ = mqtt_subscribes_rejected();
        }
        #[cfg(feature = "websocket")]
        {
            let _ = ws_connections();
            let _ = ws_connections_rejected();
        }
        let _ = negotiations();
        let _ = handshake_failures();
        let _ = tls_handshake_duration_seconds();
    }

    /// Dedicated tests for the MQTT listener counters wired via the
    /// `rustgate_mqtt::MqttServerConfig::{on_accept, on_reject}` callback
    /// slots. Grouped into a nested module so the assertions read together
    /// as the contract being protected.
    #[cfg(feature = "mqtt")]
    mod mqtt_connections_counters {
        use super::*;

        #[test]
        fn mqtt_connections_registered_under_documented_name() {
            // A drift between the registered Prometheus name and the help
            // text documented in dashboards would silently break ops alerts.
            // Gather the default registry and confirm an entry with the
            // expected name and zero label arity (a bare `IntCounter`,
            // not a `CounterVec` — a future refactor that adds labels must
            // land here first so the alerting grammar evolves in lockstep).
            ensure_init();
            let families = prometheus::default_registry().gather();
            let found = families
                .iter()
                .find(|m| m.name() == "rustgate_mqtt_connections_total")
                .expect("rustgate_mqtt_connections_total must be registered");
            assert_eq!(
                found.get_field_type(),
                prometheus::proto::MetricType::COUNTER,
            );
            let sample = found
                .get_metric()
                .first()
                .expect("counter metric family must have one sample");
            assert!(
                sample.get_label().is_empty(),
                "rustgate_mqtt_connections_total must be label-free — a future refactor \
                 that introduces labels would silently break existing PromQL queries. \
                 Got labels: {:?}",
                sample.get_label(),
            );
        }

        #[test]
        fn mqtt_connections_rejected_registered_under_documented_name() {
            ensure_init();
            let families = prometheus::default_registry().gather();
            let found = families
                .iter()
                .find(|m| m.name() == "rustgate_mqtt_connections_rejected_total")
                .expect("rustgate_mqtt_connections_rejected_total must be registered");
            assert_eq!(
                found.get_field_type(),
                prometheus::proto::MetricType::COUNTER,
            );
            let sample = found
                .get_metric()
                .first()
                .expect("counter metric family must have one sample");
            assert!(
                sample.get_label().is_empty(),
                "rustgate_mqtt_connections_rejected_total must be label-free. \
                 Got labels: {:?}",
                sample.get_label(),
            );
        }

        #[test]
        fn mqtt_connections_increments_are_observable() {
            // Pins the hot-path contract: `counter.inc()` — i.e. what the
            // callback installed from setup.rs actually runs — is visible
            // in the next `.get()` read. Use a relative delta so parallel
            // tests that also touch the counter do not race us.
            ensure_init();
            let before = mqtt_connections().get();
            mqtt_connections().inc();
            assert!(
                mqtt_connections().get() > before,
                "mqtt_connections counter must be monotonically increasing after inc(); \
                 before={before}, after={}",
                mqtt_connections().get(),
            );
        }

        #[test]
        fn mqtt_connections_rejected_increments_are_observable() {
            ensure_init();
            let before = mqtt_connections_rejected().get();
            mqtt_connections_rejected().inc();
            assert!(
                mqtt_connections_rejected().get() > before,
                "mqtt_connections_rejected counter must be monotonically increasing; \
                 before={before}, after={}",
                mqtt_connections_rejected().get(),
            );
        }

        #[test]
        fn fed_by_mqtt_on_accept_callback_end_to_end() {
            // End-to-end contract: the exact closure shape that setup.rs
            // installs — `Arc::new(|| metrics::mqtt_connections().inc())` —
            // must produce a visible increment when driven by the same
            // `Fn()` dispatch that `rustgate_mqtt::MqttServer` uses. This
            // is the single regression guard for the cross-crate wiring;
            // without it, a silent refactor of the callback signature on
            // either side (e.g. narrowing `Fn()` to `FnMut()` which is not
            // `Sync`) would land green and ship dark.
            ensure_init();
            let cb: rustgate_mqtt::OnMqttAccept = std::sync::Arc::new(|| mqtt_connections().inc());
            let before = mqtt_connections().get();
            cb();
            cb();
            assert!(
                mqtt_connections().get() > before + 1,
                "double-invoked callback must produce two visible increments; \
                 before={before}, after={}",
                mqtt_connections().get(),
            );
        }

        #[test]
        fn fed_by_mqtt_on_reject_callback_end_to_end() {
            ensure_init();
            let cb: rustgate_mqtt::OnMqttReject =
                std::sync::Arc::new(|| mqtt_connections_rejected().inc());
            let before = mqtt_connections_rejected().get();
            cb();
            assert!(
                mqtt_connections_rejected().get() > before,
                "callback invocation must produce a visible reject-counter increment; \
                 before={before}, after={}",
                mqtt_connections_rejected().get(),
            );
        }
    }

    /// Dedicated tests for the per-operation MQTT counters wired via the
    /// `rustgate_mqtt::MqttSessionHooks` slots. Pairs with the
    /// `mqtt_connections_counters` block above — connections-level counters
    /// live on `MqttServerConfig::{on_accept, on_reject}`, while these
    /// operation-level counters live on the nested `session_hooks` struct
    /// so the session task can fire them at each PUBLISH/SUBSCRIBE path.
    #[cfg(feature = "mqtt")]
    mod mqtt_publish_subscribe_counters {
        use super::*;

        #[test]
        fn mqtt_publishes_registered_under_documented_name() {
            ensure_init();
            let families = prometheus::default_registry().gather();
            let found = families
                .iter()
                .find(|m| m.name() == "rustgate_mqtt_publishes_total")
                .expect("rustgate_mqtt_publishes_total must be registered");
            assert_eq!(
                found.get_field_type(),
                prometheus::proto::MetricType::COUNTER,
            );
            let sample = found
                .get_metric()
                .first()
                .expect("counter metric family must have one sample");
            assert!(
                sample.get_label().is_empty(),
                "rustgate_mqtt_publishes_total must be label-free — the PUBLISH \
                 path fires per MQTT packet, so introducing labels would explode \
                 cardinality on dashboards. Got labels: {:?}",
                sample.get_label(),
            );
        }

        #[test]
        fn mqtt_publishes_rejected_registered_under_documented_name() {
            ensure_init();
            let families = prometheus::default_registry().gather();
            let found = families
                .iter()
                .find(|m| m.name() == "rustgate_mqtt_publishes_rejected_total")
                .expect("rustgate_mqtt_publishes_rejected_total must be registered");
            assert_eq!(
                found.get_field_type(),
                prometheus::proto::MetricType::COUNTER,
            );
            let sample = found
                .get_metric()
                .first()
                .expect("counter metric family must have one sample");
            assert!(
                sample.get_label().is_empty(),
                "rustgate_mqtt_publishes_rejected_total must be label-free. \
                 Got labels: {:?}",
                sample.get_label(),
            );
        }

        #[test]
        fn mqtt_subscribes_registered_under_documented_name() {
            ensure_init();
            let families = prometheus::default_registry().gather();
            let found = families
                .iter()
                .find(|m| m.name() == "rustgate_mqtt_subscribes_total")
                .expect("rustgate_mqtt_subscribes_total must be registered");
            assert_eq!(
                found.get_field_type(),
                prometheus::proto::MetricType::COUNTER,
            );
            let sample = found
                .get_metric()
                .first()
                .expect("counter metric family must have one sample");
            assert!(
                sample.get_label().is_empty(),
                "rustgate_mqtt_subscribes_total must be label-free — SUBSCRIBE \
                 packets carry one or more filters, and counting packets \
                 (not filters) is the documented semantic. Got labels: {:?}",
                sample.get_label(),
            );
        }

        #[test]
        fn mqtt_subscribes_rejected_registered_under_documented_name() {
            ensure_init();
            let families = prometheus::default_registry().gather();
            let found = families
                .iter()
                .find(|m| m.name() == "rustgate_mqtt_subscribes_rejected_total")
                .expect("rustgate_mqtt_subscribes_rejected_total must be registered");
            assert_eq!(
                found.get_field_type(),
                prometheus::proto::MetricType::COUNTER,
            );
            let sample = found
                .get_metric()
                .first()
                .expect("counter metric family must have one sample");
            assert!(
                sample.get_label().is_empty(),
                "rustgate_mqtt_subscribes_rejected_total must be label-free. \
                 Got labels: {:?}",
                sample.get_label(),
            );
        }

        #[test]
        fn mqtt_publishes_increments_are_observable() {
            ensure_init();
            let before = mqtt_publishes().get();
            mqtt_publishes().inc();
            assert!(
                mqtt_publishes().get() > before,
                "mqtt_publishes counter must be monotonically increasing after inc(); \
                 before={before}, after={}",
                mqtt_publishes().get(),
            );
        }

        #[test]
        fn mqtt_publishes_rejected_increments_are_observable() {
            ensure_init();
            let before = mqtt_publishes_rejected().get();
            mqtt_publishes_rejected().inc();
            assert!(
                mqtt_publishes_rejected().get() > before,
                "mqtt_publishes_rejected counter must be monotonically increasing; \
                 before={before}, after={}",
                mqtt_publishes_rejected().get(),
            );
        }

        #[test]
        fn mqtt_subscribes_increments_are_observable() {
            ensure_init();
            let before = mqtt_subscribes().get();
            mqtt_subscribes().inc();
            assert!(
                mqtt_subscribes().get() > before,
                "mqtt_subscribes counter must be monotonically increasing; \
                 before={before}, after={}",
                mqtt_subscribes().get(),
            );
        }

        #[test]
        fn mqtt_subscribes_rejected_increments_are_observable() {
            ensure_init();
            let before = mqtt_subscribes_rejected().get();
            mqtt_subscribes_rejected().inc();
            assert!(
                mqtt_subscribes_rejected().get() > before,
                "mqtt_subscribes_rejected counter must be monotonically increasing; \
                 before={before}, after={}",
                mqtt_subscribes_rejected().get(),
            );
        }

        #[test]
        fn fed_by_mqtt_on_publish_callback_end_to_end() {
            // End-to-end contract: the closure shape that setup.rs installs
            // into `MqttSessionHooks::on_publish` — an `Arc<dyn Fn()>` — must
            // produce a visible increment when driven by the same dispatch
            // the session task uses. Guards against a silent refactor of
            // either the callback alias (e.g. narrowing to `FnMut`, which
            // is not `Sync`) or the session firing site dropping the hook.
            ensure_init();
            let cb: rustgate_mqtt::OnMqttPublish = std::sync::Arc::new(|| mqtt_publishes().inc());
            let before = mqtt_publishes().get();
            cb();
            cb();
            assert!(
                mqtt_publishes().get() > before + 1,
                "double-invoked callback must produce two visible increments; \
                 before={before}, after={}",
                mqtt_publishes().get(),
            );
        }

        #[test]
        fn fed_by_mqtt_on_publish_reject_callback_end_to_end() {
            ensure_init();
            let cb: rustgate_mqtt::OnMqttPublishReject =
                std::sync::Arc::new(|| mqtt_publishes_rejected().inc());
            let before = mqtt_publishes_rejected().get();
            cb();
            assert!(
                mqtt_publishes_rejected().get() > before,
                "callback invocation must produce a visible publish-reject increment; \
                 before={before}, after={}",
                mqtt_publishes_rejected().get(),
            );
        }

        #[test]
        fn fed_by_mqtt_on_subscribe_callback_end_to_end() {
            ensure_init();
            let cb: rustgate_mqtt::OnMqttSubscribe =
                std::sync::Arc::new(|| mqtt_subscribes().inc());
            let before = mqtt_subscribes().get();
            cb();
            cb();
            assert!(
                mqtt_subscribes().get() > before + 1,
                "double-invoked callback must produce two visible increments; \
                 before={before}, after={}",
                mqtt_subscribes().get(),
            );
        }

        #[test]
        fn fed_by_mqtt_on_subscribe_reject_callback_end_to_end() {
            ensure_init();
            let cb: rustgate_mqtt::OnMqttSubscribeReject =
                std::sync::Arc::new(|| mqtt_subscribes_rejected().inc());
            let before = mqtt_subscribes_rejected().get();
            cb();
            assert!(
                mqtt_subscribes_rejected().get() > before,
                "callback invocation must produce a visible subscribe-reject increment; \
                 before={before}, after={}",
                mqtt_subscribes_rejected().get(),
            );
        }

        #[test]
        fn session_hooks_struct_accepts_all_four_counter_callbacks() {
            // Guards the cross-crate construction grammar: setup.rs builds
            // `MqttSessionHooks { on_publish: Some(Arc::new(|| ...)), ... }`
            // in one expression. If any field rename or type change in
            // `rustgate-mqtt` slips in without a matching setup.rs update,
            // this assembly would fail to compile — this test is the
            // compile-time guard for that shape.
            ensure_init();
            let hooks = rustgate_mqtt::MqttSessionHooks {
                on_publish: Some(std::sync::Arc::new(|| mqtt_publishes().inc())),
                on_publish_reject: Some(std::sync::Arc::new(|| mqtt_publishes_rejected().inc())),
                on_subscribe: Some(std::sync::Arc::new(|| mqtt_subscribes().inc())),
                on_subscribe_reject: Some(std::sync::Arc::new(|| mqtt_subscribes_rejected().inc())),
                on_retain_stored: Some(std::sync::Arc::new(|| mqtt_retain_stored().inc())),
                on_retain_cleared: Some(std::sync::Arc::new(|| mqtt_retain_cleared().inc())),
                on_retain_replayed: Some(std::sync::Arc::new(|| mqtt_retain_replayed().inc())),
                on_will_published: Some(std::sync::Arc::new(|| mqtt_will_published().inc())),
            };
            let pub_before = mqtt_publishes().get();
            let pub_rej_before = mqtt_publishes_rejected().get();
            let sub_before = mqtt_subscribes().get();
            let sub_rej_before = mqtt_subscribes_rejected().get();
            let retain_stored_before = mqtt_retain_stored().get();
            let retain_cleared_before = mqtt_retain_cleared().get();
            let retain_replayed_before = mqtt_retain_replayed().get();
            let will_pub_before = mqtt_will_published().get();
            if let Some(cb) = &hooks.on_publish {
                cb();
            }
            if let Some(cb) = &hooks.on_publish_reject {
                cb();
            }
            if let Some(cb) = &hooks.on_subscribe {
                cb();
            }
            if let Some(cb) = &hooks.on_subscribe_reject {
                cb();
            }
            if let Some(cb) = &hooks.on_retain_stored {
                cb();
            }
            if let Some(cb) = &hooks.on_retain_cleared {
                cb();
            }
            if let Some(cb) = &hooks.on_retain_replayed {
                cb();
            }
            if let Some(cb) = &hooks.on_will_published {
                cb();
            }
            assert!(mqtt_publishes().get() > pub_before);
            assert!(mqtt_publishes_rejected().get() > pub_rej_before);
            assert!(mqtt_will_published().get() > will_pub_before);
            assert!(mqtt_subscribes().get() > sub_before);
            assert!(mqtt_subscribes_rejected().get() > sub_rej_before);
            assert!(mqtt_retain_stored().get() > retain_stored_before);
            assert!(mqtt_retain_cleared().get() > retain_cleared_before);
            assert!(mqtt_retain_replayed().get() > retain_replayed_before);
        }
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
    fn mavlink_heartbeats_label_isolates_per_system_id() {
        // Two distinct system_id labels must increment independently.
        // Per-aircraft cardinality (the dashboard signal: "is this
        // particular drone still emitting heartbeats?") relies on
        // Prometheus separating the two time series — a regression
        // that collapsed them onto a single `system_id=""` label
        // would silently break every per-aircraft alert.
        ensure_init();
        let sys_a = "42";
        let sys_b = "7";

        let before_a = mavlink_heartbeats().with_label_values(&[sys_a]).get();
        let before_b = mavlink_heartbeats().with_label_values(&[sys_b]).get();

        mavlink_heartbeats().with_label_values(&[sys_a]).inc();
        mavlink_heartbeats().with_label_values(&[sys_a]).inc();
        mavlink_heartbeats().with_label_values(&[sys_b]).inc();

        assert_eq!(
            mavlink_heartbeats().with_label_values(&[sys_a]).get(),
            before_a + 2,
        );
        assert_eq!(
            mavlink_heartbeats().with_label_values(&[sys_b]).get(),
            before_b + 1,
        );
    }

    #[test]
    fn mavlink_heartbeats_registered_under_documented_name() {
        // The metric name and `system_id` label arity are the public
        // dashboard-and-alerting contract; a rename or label drop
        // would silently break PromQL queries that depend on
        // `rustgate_mavlink_heartbeats_total{system_id="..."}`. The
        // rendered exposition must always carry the label so the
        // Grafana queries can join against fleet-inventory data.
        ensure_init();
        // Force a sample to materialise so the family appears in the
        // gathered output. Some prometheus-rs versions omit empty
        // CounterVec families; populating one label-value ensures the
        // family is gathered.
        mavlink_heartbeats().with_label_values(&["255"]).inc();
        let families = prometheus::default_registry().gather();
        let found = families
            .iter()
            .find(|m| m.name() == "rustgate_mavlink_heartbeats_total")
            .expect("rustgate_mavlink_heartbeats_total must be registered");
        assert_eq!(
            found.get_field_type(),
            prometheus::proto::MetricType::COUNTER,
        );
        // Force a sample to materialise so the labels are visible in
        // the gathered families. A fresh registry has no metric
        // children until at least one `with_label_values()` call.
        mavlink_heartbeats().with_label_values(&["255"]).inc();
        let families = prometheus::default_registry().gather();
        let found = families
            .iter()
            .find(|m| m.name() == "rustgate_mavlink_heartbeats_total")
            .expect("metric family must remain registered after sampling");
        let sample = found
            .get_metric()
            .first()
            .expect("counter vec must expose at least one sample after inc");
        let labels: Vec<&str> = sample.get_label().iter().map(|l| l.name()).collect();
        assert_eq!(
            labels,
            vec!["system_id"],
            "exposition must surface the `system_id` label exactly once"
        );
    }

    // ── multicast oversize-drop + SA auto-upgrade (issue #741) ─────

    #[test]
    fn multicast_oversize_dropped_registered_under_documented_name() {
        // The metric name `rustgate_multicast_oversize_dropped_total`
        // is the dashboard-and-alerting contract for #741. A rename
        // or type change would silently break operators' PromQL.
        ensure_init();
        // Materialise a sample so the family is gathered.
        multicast_oversize_dropped().inc();
        let families = prometheus::default_registry().gather();
        let found = families
            .iter()
            .find(|m| m.name() == "rustgate_multicast_oversize_dropped_total")
            .expect("rustgate_multicast_oversize_dropped_total must be registered");
        assert_eq!(
            found.get_field_type(),
            prometheus::proto::MetricType::COUNTER,
        );
    }

    #[test]
    fn sa_auto_upgraded_registered_under_documented_name() {
        // `rustgate_sa_auto_upgraded_total` MUST stay an IntCounterVec
        // with the `from_version` label — fleet-upgrade dashboards key
        // off both. Closes #741.
        ensure_init();
        sa_auto_upgraded().with_label_values(&["v1"]).inc();
        let families = prometheus::default_registry().gather();
        let found = families
            .iter()
            .find(|m| m.name() == "rustgate_sa_auto_upgraded_total")
            .expect("rustgate_sa_auto_upgraded_total must be registered");
        assert_eq!(
            found.get_field_type(),
            prometheus::proto::MetricType::COUNTER,
        );
        let sample = found
            .get_metric()
            .first()
            .expect("counter vec must expose at least one sample after inc");
        let labels: Vec<&str> = sample.get_label().iter().map(|l| l.name()).collect();
        assert_eq!(
            labels,
            vec!["from_version"],
            "exposition must surface the `from_version` label exactly once"
        );
    }

    #[test]
    fn sa_auto_upgraded_label_isolates_per_from_version() {
        // The two production label values (`v1` and `v2-pre-2.0`)
        // drive distinct dashboard panels, so increments on one MUST
        // NOT bleed into the other. This test uses synthetic
        // label-value sentinels to avoid contention with sibling
        // tests that target the production values directly — the
        // prometheus default registry is shared across the entire
        // `cargo test` process, so two tests that both inc `v1` race
        // against each other under default `--test-threads=N`. The
        // sentinel pair pins the isolation property as a structural
        // assertion on the IntCounterVec key tuple, independent of
        // any other test's traffic on the production labels.
        ensure_init();
        let label_a = "isolation-test-a";
        let label_b = "isolation-test-b";

        let before_a = sa_auto_upgraded().with_label_values(&[label_a]).get();
        let before_b = sa_auto_upgraded().with_label_values(&[label_b]).get();

        sa_auto_upgraded().with_label_values(&[label_a]).inc();
        sa_auto_upgraded().with_label_values(&[label_a]).inc();
        sa_auto_upgraded().with_label_values(&[label_b]).inc();

        assert_eq!(
            sa_auto_upgraded().with_label_values(&[label_a]).get(),
            before_a + 2,
            "label_a increments must not bleed into label_b"
        );
        assert_eq!(
            sa_auto_upgraded().with_label_values(&[label_b]).get(),
            before_b + 1,
            "label_b increments must not bleed into label_a"
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

    // ── tls_handshake_duration_seconds ─────────────────────────────

    #[test]
    fn tls_handshake_duration_is_registered_under_canonical_name() {
        // Operators scrape by name — a rename without a dashboard update
        // silently drops the alert. Pin the canonical name here so any
        // accidental churn fails the build before it reaches ops.
        ensure_init();
        let hv = super::tls_handshake_duration_seconds();
        // Exercise both label values the callback emits to guarantee both
        // series materialize in `/metrics`.
        hv.with_label_values(&["success"]).observe(0.002);
        hv.with_label_values(&["failure"]).observe(0.002);
        let mfs = prometheus::default_registry().gather();
        let names: Vec<&str> = mfs.iter().map(|mf| mf.name()).collect();
        assert!(
            names.contains(&"rustgate_tls_handshake_duration_seconds"),
            "expected rustgate_tls_handshake_duration_seconds in registry, got: {names:?}",
        );
    }

    #[test]
    fn tls_handshake_duration_success_label_observes() {
        ensure_init();
        let hv = super::tls_handshake_duration_seconds();
        // Use a large, unlikely value so an unrelated test's observation
        // does not accidentally satisfy the sum delta.
        let before = hv.with_label_values(&["success"]).get_sample_sum();
        hv.with_label_values(&["success"]).observe(1.5);
        let after = hv.with_label_values(&["success"]).get_sample_sum();
        assert!(
            (after - before - 1.5).abs() < 1e-9,
            "expected sum to rise by 1.5 after observe(1.5); before={before}, after={after}",
        );
    }

    #[test]
    fn tls_handshake_duration_failure_label_observes_separately_from_success() {
        // The two label values are distinct series; observing one must
        // not move the counter on the other. A regression would mean the
        // label was either ignored on registration or collapsed into a
        // single bucket — either breaks the "% success" PromQL queries
        // operators build on top of this histogram.
        ensure_init();
        let hv = super::tls_handshake_duration_seconds();
        let success_before = hv.with_label_values(&["success"]).get_sample_count();
        hv.with_label_values(&["failure"]).observe(0.042);
        let success_after = hv.with_label_values(&["success"]).get_sample_count();
        assert_eq!(
            success_before, success_after,
            "observing on failure label must not touch the success series",
        );
    }

    #[test]
    fn tls_handshake_duration_bucket_floor_separates_from_ceiling() {
        // Confirm the configured buckets actually cover the tactical mTLS
        // latency range. A silent buckets(&[]) default on a future edit
        // would collapse every observation into `+Inf`, killing any
        // P50/P99 query; observing at 1 ms and 5 s must land in
        // different cumulative buckets.
        ensure_init();
        let hv = super::tls_handshake_duration_seconds();
        // Fresh label value to avoid cross-test interference.
        let child = hv.with_label_values(&["success"]);
        let fast_before = child.get_sample_count();
        child.observe(0.001);
        child.observe(5.0);
        let fast_after = child.get_sample_count();
        assert_eq!(
            fast_after - fast_before,
            2,
            "both observations must be counted",
        );
        // Use gathered metric families to inspect the buckets directly.
        let mfs = prometheus::default_registry().gather();
        let mf = mfs
            .iter()
            .find(|mf| mf.name() == "rustgate_tls_handshake_duration_seconds")
            .expect("metric family must be registered");
        // At least 6 bucket boundaries — the configured list has 12.
        let metric = mf
            .get_metric()
            .first()
            .expect("at least one labelled series");
        let buckets = metric.get_histogram().get_bucket();
        assert!(
            buckets.len() >= 6,
            "expected >=6 buckets on TLS handshake histogram, got {}",
            buckets.len(),
        );
    }

    /// is active.
    #[cfg(all(feature = "jemalloc", not(target_os = "windows")))]
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
    fn crl_age_gauge_registered_under_documented_name() {
        ensure_init();
        let families = prometheus::default_registry().gather();
        let family = families
            .iter()
            .find(|mf| mf.name() == "rustgate_crl_age_seconds")
            .expect("rustgate_crl_age_seconds not registered");
        // Single time-series — no labels, matches the documented shape.
        assert_eq!(family.get_metric().len(), 1);
        assert!(family.get_metric()[0].get_label().is_empty());
    }

    #[test]
    fn crl_age_gauge_set_and_read_roundtrip() {
        ensure_init();
        // Deliberately idempotent: restore prior value at end so parallel
        // readiness tests observing the gauge see the baseline.
        let prior = crl_age_seconds().get();
        crl_age_seconds().set(12_345);
        assert_eq!(crl_age_seconds().get(), 12_345);
        crl_age_seconds().set(prior);
    }

    #[test]
    fn crl_age_gauge_fed_by_tlsconfig_helper_for_real_crl() {
        use rustgate_test_utils::certs::TestCa;

        ensure_init();
        let ca = TestCa::new("crl-age-server-ca");
        let server = ca.issue_server_cert("server", &["localhost"]);
        let client = ca.issue_client_cert("victim", &["alpha"]);
        let crl_pem = ca.generate_crl(&[&client.cert_pem]);

        // Go through the full production path: load into `TlsConfig`,
        // read the age from the convenience method, then push it into
        // the gauge. This is exactly the sequence setup.rs runs at
        // startup.
        let tls_config =
            rustgate_tls::TlsConfig::from_pem(&server.cert_pem, &server.key_pem, &ca.cert_pem)
                .expect("TlsConfig::from_pem");
        let tls_config = tls_config.with_crls(&crl_pem).expect("with_crls");
        let age = tls_config
            .crl_max_age_seconds()
            .expect("CRL just issued, expected Some(age)");
        assert!(
            (0..=60).contains(&age),
            "fresh CRL age {age}s out of [0,60]"
        );

        let prior = crl_age_seconds().get();
        crl_age_seconds().set(age);
        assert_eq!(crl_age_seconds().get(), age);
        crl_age_seconds().set(prior);
    }

    mod position_cache_size_gauge {
        use std::sync::Arc;

        use rustgate_router::PositionCache;

        use super::*;

        #[test]
        fn registered_under_documented_name() {
            ensure_init();
            // Confirm the gauge is reachable on a scrape and carries no labels
            // (alert rules consume the bare metric name). A rename or
            // accidental labelling would silently break every deployed alert.
            let families = prometheus::default_registry().gather();
            let mf = families
                .iter()
                .find(|f| f.name() == "rustgate_position_cache_size")
                .expect("rustgate_position_cache_size must be registered");
            assert_eq!(mf.get_metric().len(), 1);
            assert!(
                mf.get_metric()[0].get_label().is_empty(),
                "gauge must have no labels"
            );
        }

        #[test]
        fn set_and_read_roundtrip() {
            ensure_init();
            let prior = position_cache_size().get();
            position_cache_size().set(42);
            assert_eq!(position_cache_size().get(), 42);
            // Restore so sibling tests that use the shared default registry
            // observe the starting value they expect.
            position_cache_size().set(prior);
        }

        #[tokio::test]
        async fn fed_by_cache_callback_end_to_end() {
            ensure_init();

            let cache = Arc::new(PositionCache::new());
            cache.set_on_size(Arc::new(|size| {
                position_cache_size().set(size as i64);
            }));

            let prior = position_cache_size().get();

            let msg = rustgate_core::message::RoutableMessage {
                source: rustgate_core::identity::Identity::new(
                    "alice".to_string(),
                    "alice-fp".to_string(),
                    std::collections::BTreeSet::new(),
                )
                .expect("valid identity"),
                destination: rustgate_core::message::Destination::Broadcast,
                payload: bytes::Bytes::from_static(b"<event/>"),
                metadata: rustgate_core::message::Metadata::new(
                    std::time::SystemTime::now(),
                    "cot".to_string(),
                    rustgate_core::message::MessageType::Position,
                ),
            };

            cache.store(msg).await;
            assert_eq!(
                position_cache_size().get(),
                prior + 1,
                "store must increment gauge via callback"
            );

            cache.remove("alice").await;
            assert_eq!(
                position_cache_size().get(),
                prior,
                "remove must decrement gauge via callback"
            );
        }
    }

    #[test]
    fn build_info_labels_shape() {
        // The documented label order is (version, rust_version, features);
        // scrapers and dashboards depend on this. Lock it in a test.
        assert_eq!(BUILD_INFO_LABELS, &["version", "rust_version", "features"]);
    }

    #[test]
    fn enabled_features_always_includes_metrics() {
        // `enabled_features` is only reachable from the metrics HTTP server,
        // which is itself feature-gated. "metrics" must therefore always be
        // present in the returned string.
        let s = enabled_features();
        assert!(s.split(',').any(|f| f == "metrics"), "features: {s:?}");
    }

    #[test]
    fn build_info_registered_after_init() {
        ensure_init();
        assert!(
            BUILD_INFO.get().is_some(),
            "init() must populate BUILD_INFO OnceLock"
        );
    }

    #[test]
    fn build_info_exposes_pinned_label_tuple_at_one() {
        ensure_init();
        let gv = BUILD_INFO.get().expect("init must have run");
        let gauge = gv.with_label_values(&[
            env!("CARGO_PKG_VERSION"),
            env!("CARGO_PKG_RUST_VERSION"),
            enabled_features().as_str(),
        ]);
        assert_eq!(gauge.get(), 1, "rustgate_build_info must be pinned at 1");
    }

    #[test]
    fn build_info_gathered_from_default_registry() {
        ensure_init();
        let families = prometheus::default_registry().gather();
        let family = families
            .iter()
            .find(|mf| mf.name() == "rustgate_build_info")
            .expect("rustgate_build_info not registered");
        assert_eq!(
            family.get_metric().len(),
            1,
            "expected a single time series"
        );
        let metric = &family.get_metric()[0];
        let mut label_names: Vec<&str> = metric.get_label().iter().map(|l| l.name()).collect();
        label_names.sort_unstable();
        let mut expected: Vec<&str> = BUILD_INFO_LABELS.to_vec();
        expected.sort_unstable();
        assert_eq!(label_names, expected);
        assert_eq!(metric.get_gauge().get_value() as i64, 1);
    }

    #[cfg(feature = "websocket")]
    mod ws_connection_counters {
        use std::sync::Arc;

        use super::super::{ws_connections, ws_connections_rejected};
        use super::ensure_init;

        fn find_metric_family(name: &str) -> Option<prometheus::proto::MetricFamily> {
            prometheus::default_registry()
                .gather()
                .into_iter()
                .find(|mf| mf.name() == name)
        }

        #[test]
        fn ws_connections_registered_under_documented_name() {
            ensure_init();
            let mf = find_metric_family("rustgate_ws_connections_total")
                .expect("rustgate_ws_connections_total should be registered by init()");
            assert_eq!(mf.get_metric().len(), 1, "counter is unlabeled");
            assert_eq!(
                mf.get_metric()[0].get_label().len(),
                0,
                "counter has zero label arity"
            );
        }

        #[test]
        fn ws_connections_rejected_registered_under_documented_name() {
            ensure_init();
            let mf = find_metric_family("rustgate_ws_connections_rejected_total")
                .expect("rustgate_ws_connections_rejected_total should be registered by init()");
            assert_eq!(mf.get_metric().len(), 1, "counter is unlabeled");
            assert_eq!(
                mf.get_metric()[0].get_label().len(),
                0,
                "counter has zero label arity"
            );
        }

        #[test]
        fn ws_connections_increment_observable() {
            ensure_init();
            let before = ws_connections().get();
            ws_connections().inc();
            assert!(ws_connections().get() > before);
        }

        #[test]
        fn ws_connections_rejected_increment_observable() {
            ensure_init();
            let before = ws_connections_rejected().get();
            ws_connections_rejected().inc();
            assert!(ws_connections_rejected().get() > before);
        }

        #[test]
        fn fed_by_ws_on_connection_accept_callback_end_to_end() {
            ensure_init();
            // Mirrors the closure `rustgate-server::setup::setup_websocket`
            // builds under `#[cfg(feature = "metrics")]`.
            let cb: Arc<dyn Fn() + Send + Sync> = Arc::new(|| ws_connections().inc());
            let before = ws_connections().get();
            cb();
            cb();
            assert!(ws_connections().get() >= before + 2);
        }

        #[test]
        fn fed_by_ws_on_connection_rejected_callback_end_to_end() {
            ensure_init();
            let cb: Arc<dyn Fn() + Send + Sync> = Arc::new(|| ws_connections_rejected().inc());
            let before = ws_connections_rejected().get();
            cb();
            assert!(ws_connections_rejected().get() > before);
        }

        #[test]
        fn session_hooks_struct_accepts_both_counter_callbacks() {
            ensure_init();
            let hooks = rustgate_websocket::WsSessionHooks {
                on_connection_accept: Some(Arc::new(|| ws_connections().inc())),
                on_connection_rejected: Some(Arc::new(|| ws_connections_rejected().inc())),
            };
            let before_accept = ws_connections().get();
            let before_reject = ws_connections_rejected().get();
            if let Some(cb) = hooks.on_connection_accept.as_ref() {
                cb();
            }
            if let Some(cb) = hooks.on_connection_rejected.as_ref() {
                cb();
            }
            assert!(ws_connections().get() > before_accept);
            assert!(ws_connections_rejected().get() > before_reject);
        }
    }

    /// Closes #818 (F-144). Pins the documented Prometheus name,
    /// the single `subsystem` label dimension, and the call shape of
    /// `record_reload_rollback("<subsystem>")` so a SIEM dashboard
    /// alert on `rate(rustgate_reload_rollback_total{subsystem="authz"}[5m])`
    /// cannot silently break under a future refactor.
    ///
    /// Implementation note: these tests probe the counter via the
    /// `reload_rollback()` accessor (which is the same call path the
    /// production hot path takes through `record_reload_rollback`).
    /// We deliberately avoid scanning `prometheus::default_registry()
    /// .gather()` because in this binary's parallel test scheduler the
    /// `RELOAD_ROLLBACK` `OnceLock` may be primed via the
    /// `get_or_init` fallback path before `init()` runs — exercised by
    /// the `authz_reloader` tests that drive `reload()` through the
    /// failure path and indirectly call `record_reload_rollback`.
    /// `prometheus::core::Collector::desc` reflects whichever
    /// constructor primed the static, so the contract pinned here
    /// (canonical name + label arity) is the one SIEM dashboards
    /// observe regardless of which path won the race.
    mod reload_rollback_counter {
        use prometheus::core::Collector;

        use super::*;

        /// The Prometheus name and label dimension that downstream
        /// alerting consumes. A change to either constant is the
        /// signal a SIEM owner must re-grok before merging.
        const EXPECTED_NAME: &str = "rustgate_reload_rollback_total";
        const EXPECTED_LABEL: &str = "subsystem";

        #[test]
        fn reload_rollback_registered_under_documented_name() {
            ensure_init();
            let family = reload_rollback();
            let descs = family.desc();
            let desc = descs
                .into_iter()
                .next()
                .expect("metric must carry at least one Desc");
            assert_eq!(
                desc.fq_name, EXPECTED_NAME,
                "rustgate_reload_rollback_total must be registered under the documented \
                 name; a SIEM rule on `rate({EXPECTED_NAME}{{{EXPECTED_LABEL}=\"authz\"}}[5m])` \
                 would silently break if this drifts. Got: {}",
                desc.fq_name,
            );
            assert_eq!(
                desc.variable_labels,
                vec![EXPECTED_LABEL.to_string()],
                "rustgate_reload_rollback_total must carry exactly one label \
                 ({EXPECTED_LABEL}); a future refactor that changes the label set \
                 would invalidate every dashboard PromQL query. Got: {:?}",
                desc.variable_labels,
            );
        }

        #[test]
        fn record_reload_rollback_increments_authz_label() {
            ensure_init();
            // Hot-path contract: the helper increments the counter for
            // the subsystem the caller names. Use a relative delta
            // because parallel tests may also exercise the `authz`
            // label.
            let before = reload_rollback().with_label_values(&["authz"]).get();
            record_reload_rollback("authz");
            let after = reload_rollback().with_label_values(&["authz"]).get();
            assert!(
                after > before,
                "record_reload_rollback(\"authz\") must increment the authz time series; \
                 before={before}, after={after}",
            );
        }

        #[test]
        fn record_reload_rollback_distinguishes_subsystems() {
            ensure_init();
            // Each subsystem token must produce an independent time
            // series. A future refactor that collapsed labels would
            // turn a CRL rollback alert into an authz alert (or vice
            // versa) — exactly the kind of silent regression this
            // test guards against. Use unique synthetic tokens so the
            // assertion is invariant against parallel tests touching
            // the documented `acl` / `crl` labels.
            let acl_token = "__test_acl_isolated_probe__";
            let crl_token = "__test_crl_isolated_probe__";
            let acl_before = reload_rollback().with_label_values(&[acl_token]).get();
            let crl_before = reload_rollback().with_label_values(&[crl_token]).get();
            record_reload_rollback(acl_token);
            let acl_after = reload_rollback().with_label_values(&[acl_token]).get();
            let crl_after = reload_rollback().with_label_values(&[crl_token]).get();
            assert!(
                acl_after > acl_before,
                "acl subsystem must increment after record_reload_rollback(\"{acl_token}\")",
            );
            assert_eq!(
                crl_before, crl_after,
                "crl subsystem must NOT change when only acl was recorded",
            );
        }
    }

    /// Closes #769 (F-3b). Pins the documented Prometheus name and the
    /// single `variant` label dimension. Operators page on
    /// `rate(rustgate_authz_obligation_unknown_total[5m])`; a rename or
    /// relabelling silently breaks every deployed alert.
    ///
    /// Probes via the `authz_obligation_unknown()` accessor for the
    /// same `OnceLock` race-tolerance reasons as the reload-rollback
    /// counter test above.
    mod authz_obligation_unknown_counter {
        use prometheus::core::Collector;

        use super::*;

        const EXPECTED_NAME: &str = "rustgate_authz_obligation_unknown_total";
        const EXPECTED_LABEL: &str = "variant";

        #[test]
        fn obligation_unknown_registered_under_documented_name() {
            ensure_init();
            let family = authz_obligation_unknown();
            let descs = family.desc();
            let desc = descs
                .into_iter()
                .next()
                .expect("metric must carry at least one Desc");
            assert_eq!(
                desc.fq_name, EXPECTED_NAME,
                "{EXPECTED_NAME} must be registered under the documented \
                 name; a SIEM rule on \
                 `rate({EXPECTED_NAME}{{{EXPECTED_LABEL}=\"...\"}}[5m])` \
                 would silently break if this drifts. Got: {}",
                desc.fq_name,
            );
            assert_eq!(
                desc.variable_labels,
                vec![EXPECTED_LABEL.to_string()],
                "{EXPECTED_NAME} must carry exactly one label \
                 ({EXPECTED_LABEL}); a future refactor that changes the label set \
                 would invalidate every dashboard PromQL query. Got: {:?}",
                desc.variable_labels,
            );
        }

        #[test]
        fn obligation_unknown_increments_variant_label() {
            ensure_init();
            // The accessor returns the registered IntCounterVec; the
            // increment path used at runtime is the
            // `with_label_values(&[variant]).inc()` call wired into
            // `ObligationRateLimiter::with_on_unknown` at startup.
            // Use a unique synthetic variant label so the assertion is
            // invariant against any parallel test touching the
            // documented variants.
            let token = "__test_variant_isolated_probe__";
            let before = authz_obligation_unknown().with_label_values(&[token]).get();
            authz_obligation_unknown().with_label_values(&[token]).inc();
            let after = authz_obligation_unknown().with_label_values(&[token]).get();
            assert!(
                after > before,
                "increment must advance the variant time series; \
                 before={before}, after={after}",
            );
        }

        #[test]
        fn obligation_unknown_distinguishes_variants() {
            ensure_init();
            // Distinct variant tokens must produce independent time
            // series. A regression that collapsed labels would let one
            // misconfigured policy mask another's signal.
            let a = "__test_variant_A_isolated__";
            let b = "__test_variant_B_isolated__";
            let a_before = authz_obligation_unknown().with_label_values(&[a]).get();
            let b_before = authz_obligation_unknown().with_label_values(&[b]).get();
            authz_obligation_unknown().with_label_values(&[a]).inc();
            let a_after = authz_obligation_unknown().with_label_values(&[a]).get();
            let b_after = authz_obligation_unknown().with_label_values(&[b]).get();
            assert!(
                a_after > a_before,
                "variant A must increment after its own .inc() call",
            );
            assert_eq!(
                b_before, b_after,
                "variant B must NOT change when only variant A was incremented",
            );
        }
    }

    /// Closes #768. Registration tests for the router/PEP/obligation
    /// metric family. Each test pins one operationally-load-bearing
    /// property: the metric is reachable on `/metrics`, the documented
    /// label arity matches what dashboards consume, and the bound
    /// callback factories produce the documented increment shape.
    mod router_pep_obligation_metrics {
        use super::*;

        fn family(name: &str) -> Option<prometheus::proto::MetricFamily> {
            prometheus::default_registry()
                .gather()
                .into_iter()
                .find(|mf| mf.name() == name)
        }

        #[test]
        fn router_fanout_total_registered_with_destination_label() {
            // Pin the metric name and label vocabulary — dashboards
            // and SIEM rules query on `destination=` so a rename or
            // accidental label drop would silently break ops.
            ensure_init();
            // Touch one bounded label value so the family is
            // materialized and observable on `gather()`. Prometheus
            // CounterVecs do not appear in the registry's gather
            // output until at least one label tuple has been seen,
            // so test order or single-test-per-process runners
            // (nextest) would otherwise see an unmaterialized family.
            router_fanout_total()
                .with_label_values(&["direct"])
                .inc_by(0);
            let mf = family("rustgate_router_fanout_total")
                .expect("rustgate_router_fanout_total must be registered");
            assert_eq!(mf.get_field_type(), prometheus::proto::MetricType::COUNTER);
            let labels: Vec<&str> = mf
                .get_metric()
                .first()
                .map(|m| m.get_label().iter().map(|l| l.name()).collect())
                .unwrap_or_default();
            assert!(
                labels.contains(&"destination"),
                "must carry `destination` label, got {labels:?}"
            );
        }

        #[test]
        fn router_fanout_subscribers_registered_as_histogram() {
            // The histogram is a single time series with no label arity
            // — anything else would unintentionally fan-out cardinality.
            ensure_init();
            let mf = family("rustgate_router_fanout_subscribers")
                .expect("rustgate_router_fanout_subscribers must be registered");
            assert_eq!(
                mf.get_field_type(),
                prometheus::proto::MetricType::HISTOGRAM
            );
            assert_eq!(mf.get_metric().len(), 1, "no labels — single time series");
        }

        #[test]
        fn router_dropped_total_registered_with_reason_label() {
            // The `reason` vocabulary is fixed at compile time on the
            // transport side — pin the metric name + label so a
            // future label rename surfaces here as a test failure
            // rather than silently breaking dashboards.
            ensure_init();
            // Touch the metric so the CounterVec family appears in
            // `gather()` even when no other test has exercised it
            // first (per-test-process runners like nextest).
            router_dropped_total()
                .with_label_values(&["no_subscribers"])
                .inc_by(0);
            let mf = family("rustgate_router_dropped_total")
                .expect("rustgate_router_dropped_total must be registered");
            assert_eq!(mf.get_field_type(), prometheus::proto::MetricType::COUNTER);
            let labels: Vec<&str> = mf
                .get_metric()
                .first()
                .map(|m| m.get_label().iter().map(|l| l.name()).collect())
                .unwrap_or_default();
            assert!(
                labels.contains(&"reason"),
                "must carry `reason` label, got {labels:?}"
            );
        }

        #[test]
        fn pep_send_and_receive_decisions_registered_independently() {
            // Two sibling counters share the same vocabulary so
            // dashboards can pivot direction without re-keying labels.
            // A regression that collapsed both onto a single counter
            // with a `direction=` label would silently break those
            // dashboards.
            ensure_init();
            pep_send_decisions().with_label_values(&["allow"]).inc_by(0);
            pep_receive_decisions()
                .with_label_values(&["allow"])
                .inc_by(0);
            assert!(family("rustgate_pep_send_decisions_total").is_some());
            assert!(family("rustgate_pep_receive_decisions_total").is_some());
        }

        #[test]
        fn pep_evaluation_seconds_registered_with_direction_label() {
            ensure_init();
            pep_evaluation_seconds()
                .with_label_values(&["send"])
                .observe(0.0);
            let mf = family("rustgate_pep_evaluation_seconds")
                .expect("rustgate_pep_evaluation_seconds must be registered");
            assert_eq!(
                mf.get_field_type(),
                prometheus::proto::MetricType::HISTOGRAM
            );
            let labels: Vec<&str> = mf
                .get_metric()
                .first()
                .map(|m| m.get_label().iter().map(|l| l.name()).collect())
                .unwrap_or_default();
            assert!(
                labels.contains(&"direction"),
                "must carry `direction` label, got {labels:?}"
            );
        }

        #[test]
        fn obligation_applied_total_registered_with_kind_label() {
            ensure_init();
            obligation_applied_total()
                .with_label_values(&["mask_point"])
                .inc_by(0);
            let mf = family("rustgate_obligation_applied_total")
                .expect("rustgate_obligation_applied_total must be registered");
            assert_eq!(mf.get_field_type(), prometheus::proto::MetricType::COUNTER);
            let labels: Vec<&str> = mf
                .get_metric()
                .first()
                .map(|m| m.get_label().iter().map(|l| l.name()).collect())
                .unwrap_or_default();
            assert!(
                labels.contains(&"kind"),
                "must carry `kind` label, got {labels:?}"
            );
        }

        #[test]
        fn obligation_failures_total_registered_with_reason_label() {
            ensure_init();
            // CounterVec families do not appear in `gather()` output
            // until at least one label tuple has been materialized,
            // so touch the documented vocabulary first. A regression
            // that renamed the metric or changed its type would still
            // surface — the find-by-name below still panics in that
            // case.
            obligation_failures_total()
                .with_label_values(&["unknown_variant"])
                .inc_by(0);
            let mf = family("rustgate_obligation_failures_total")
                .expect("rustgate_obligation_failures_total must be registered");
            assert_eq!(mf.get_field_type(), prometheus::proto::MetricType::COUNTER);
            let labels: Vec<&str> = mf
                .get_metric()
                .first()
                .map(|m| m.get_label().iter().map(|l| l.name()).collect())
                .unwrap_or_default();
            assert!(
                labels.contains(&"reason"),
                "must carry `reason` label, got {labels:?}"
            );
        }

        #[test]
        fn router_fanout_callback_increments_counter_and_records_histogram() {
            // End-to-end contract for the wired callback shape: the
            // exact closure setup.rs/main.rs installs must produce a
            // visible counter increment AND a histogram sample for the
            // same call. A regression that touched only one would
            // silently desync ops dashboards from the audit log.
            ensure_init();
            let cb = router_fanout_callback();
            let counter_before = router_fanout_total().with_label_values(&["direct"]).get();
            let hist_before = router_fanout_subscribers().get_sample_count();
            cb("direct", 7);
            let counter_after = router_fanout_total().with_label_values(&["direct"]).get();
            let hist_after = router_fanout_subscribers().get_sample_count();
            assert!(
                counter_after > counter_before,
                "counter must increment on callback fire; before={counter_before}, after={counter_after}"
            );
            assert!(
                hist_after > hist_before,
                "histogram must record sample on callback fire; before={hist_before}, after={hist_after}"
            );
        }

        #[test]
        fn router_dropped_callback_increments_per_reason_label() {
            // Two distinct reasons must increment independently —
            // collapsing them would cost operators the ability to
            // distinguish backpressure (fixable) from authz_denied
            // (intentional).
            ensure_init();
            let cb = router_dropped_callback();
            let bp_before = router_dropped_total()
                .with_label_values(&["backpressure"])
                .get();
            let authz_before = router_dropped_total()
                .with_label_values(&["authz_denied"])
                .get();
            cb("backpressure");
            cb("backpressure");
            cb("authz_denied");
            let bp_after = router_dropped_total()
                .with_label_values(&["backpressure"])
                .get();
            let authz_after = router_dropped_total()
                .with_label_values(&["authz_denied"])
                .get();
            assert_eq!(bp_after - bp_before, 2);
            assert_eq!(authz_after - authz_before, 1);
        }

        #[test]
        fn pep_decision_callback_routes_send_and_receive_to_distinct_counters() {
            // The router emits direction=send for Send-PEP and
            // direction=receive for Receive-PEP; the bridge callback
            // routes each onto its dedicated counter. A regression
            // that mis-routed (e.g. always to send) would silently
            // collapse the operational signal.
            ensure_init();
            let cb = router_pep_decision_callback();
            let send_before = pep_send_decisions().with_label_values(&["allow"]).get();
            let recv_before = pep_receive_decisions().with_label_values(&["deny"]).get();
            cb("send", "allow", 0.0);
            cb("receive", "deny", 0.0);
            let send_after = pep_send_decisions().with_label_values(&["allow"]).get();
            let recv_after = pep_receive_decisions().with_label_values(&["deny"]).get();
            assert!(send_after > send_before);
            assert!(recv_after > recv_before);
        }

        #[test]
        fn obligation_applied_callback_increments_per_kind_label() {
            ensure_init();
            let cb = router_obligation_applied_callback();
            let mp_before = obligation_applied_total()
                .with_label_values(&["mask_point"])
                .get();
            let mp_payload_before = obligation_applied_total()
                .with_label_values(&["mask_payload"])
                .get();
            cb("mask_point");
            cb("mask_payload");
            cb("mask_point");
            let mp_after = obligation_applied_total()
                .with_label_values(&["mask_point"])
                .get();
            let mp_payload_after = obligation_applied_total()
                .with_label_values(&["mask_payload"])
                .get();
            assert_eq!(mp_after - mp_before, 2);
            assert_eq!(mp_payload_after - mp_payload_before, 1);
        }
    }
}
