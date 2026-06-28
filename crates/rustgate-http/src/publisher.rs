// Copyright © 2026 Roberto Chiofalo.

//! Core HTTP publish engine with background dispatch worker.
//!
//! The [`HttpPublisher`] accepts routable messages via a fire-and-forget
//! [`publish`](HttpPublisher::publish) method, dispatching them through a
//! bounded internal channel to a background worker that fans out to all
//! matching targets concurrently. Each target has its own reqwest client,
//! circuit breaker, filter, and optional authentication.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use reqwest::header::HeaderName;
use rustgate_core::b64;
use rustgate_core::message::RoutableMessage;
use rustgate_core::sanitize::sanitize_for_log;
use rustgate_core::secrets::{SecretFileOpts, read_secret_file};
use rustgate_core::tasks::spawn_background;
use rustgate_resilience::backpressure::{BackpressureGate, BackpressurePermit};
use rustgate_resilience::circuit::{
    CircuitBreaker, OnStateChange, STATE_CLOSED, STATE_HALF_OPEN, STATE_OPEN,
};
use rustgate_resilience::retry;
use rustgate_resilience::token_bucket::TokenBucket;
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tracing::Instrument;
use zeroize::Zeroizing;

use crate::auth::AuthState;
use crate::batch::Batcher;
use crate::config::{BatchFormat, HttpConfig, PayloadFormat, TargetConfig};
use crate::dlq::DeadLetterQueue;
use crate::error::HttpError;
use crate::filter::CompiledFilter;
use crate::payload;
use crate::resolver::SsrfSafeResolver;

/// Channel buffer size for the dispatch queue.
const CHANNEL_BUFFER: usize = 256;

/// Channel buffer size for the DLQ auto-drain trigger queue.
///
/// A successful `HalfOpen → Closed` circuit transition pushes the
/// recovering target's name through this channel; the drain worker
/// receives the name and replays that target's sealed DLQ segments.
/// Sized small because the triggers are rare (one per confirmed
/// recovery) and the worker coalesces repeats naturally — each
/// drain pass re-scans the directory, so a dropped trigger is
/// picked up on the next circuit cycle (or the admin replay
/// endpoint, see `#881` PR C).
const DRAIN_CHANNEL_BUFFER: usize = 32;

/// Non-revealing User-Agent to prevent version fingerprinting.
const RUSTGATE_USER_AGENT: &str = "Rustgate";

/// Synthetic DLQ target name for admission-queue drops.
///
/// Used when a message is shed before per-target dispatch (the bounded
/// channel is full or closed). DLQ filenames will be
/// `admission_{timestamp}.dlq.enc`. Target-name config validation allows
/// users to choose the literal string "admission" for one of their own
/// targets, which would interleave user traffic with admission-shed
/// messages in the same DLQ files. The `target` field inside each JSON
/// entry always disambiguates, and users can avoid the collision by not
/// naming a target "admission".
const ADMISSION_DLQ_TARGET: &str = "admission";

/// A message queued for dispatch, optionally carrying a byte-reservation
/// permit on the shared [`BackpressureGate`].
///
/// The permit's `Drop` impl releases the reservation automatically when the
/// worker finishes dispatching the message, so the gate's in-flight
/// accounting stays accurate without explicit bookkeeping on the worker
/// side. Wrapped in `Arc` because permits are not `Clone` and we may want
/// to share one across retries in the future.
struct QueuedMessage {
    msg: Arc<RoutableMessage>,
    // justification: field is pure RAII — held only so its `Drop`
    // releases the gate's byte reservation when the worker finishes.
    #[allow(dead_code)]
    permit: Option<Arc<BackpressurePermit>>,
}

/// Publishes routable messages to configured HTTP targets.
///
/// Designed to be called from the routing path like `NatsPublisher`.
/// Publishing is fire-and-forget: messages are dispatched via an internal
/// bounded channel to a background worker task.
#[derive(Clone)]
pub struct HttpPublisher {
    tx: mpsc::Sender<QueuedMessage>,
    targets: Arc<Vec<TargetState>>,
    shutdown: Arc<tokio::sync::Notify>,
    /// Dedicated shutdown signal for the DLQ drain worker, populated only
    /// when a DLQ is configured. Kept separate from `shutdown` so we can
    /// wake both workers deterministically with `notify_one` on each.
    /// `notify_waiters` would wake both, but has no stored-permit semantics
    /// and silently drops the signal if a worker is mid-processing at the
    /// call moment.
    drain_shutdown: Option<Arc<tokio::sync::Notify>>,
    /// Sender side of the DLQ drain trigger channel, populated only when
    /// a DLQ is configured. Held so that operator-initiated drains via
    /// the management API (`POST /api/dlq/{target}/replay`) and the
    /// circuit-recovery observer feed the same worker — coalescing
    /// duplicate triggers naturally and keeping the audit trail
    /// uniform. The per-target circuit observers also clone this
    /// sender; closing this top-level handle is therefore not enough
    /// to shut the channel down, which is the desired property: the
    /// drain worker only exits on its dedicated `Notify`.
    drain_tx: Option<mpsc::Sender<String>>,
    /// Encrypted dead-letter queue for circuit-breaker-shed messages.
    dlq: Option<Arc<DeadLetterQueue>>,
    /// Worker task handle for panic detection during shutdown.
    worker_handle: Arc<std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>>,
    /// Optional global backpressure gate. When configured, each in-flight
    /// message holds a byte-sized permit so a slow HTTP target pressures
    /// the global admission counter rather than silently hoarding memory
    /// inside this publisher's bounded channel.
    gate: Option<Arc<BackpressureGate>>,
}

impl fmt::Debug for HttpPublisher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpPublisher")
            .field("target_count", &self.targets.len())
            .finish_non_exhaustive()
    }
}

/// Reasons [`HttpPublisher::trigger_drain`] can refuse to enqueue a
/// drain. Surfaced to the management API so the
/// `POST /api/dlq/{target}/replay` endpoint can return precise HTTP
/// status codes (`404` for unknown target, `503` for missing DLQ,
/// `429` for backpressure) rather than collapsing every failure to a
/// generic `500`. Display strings are stable — operator-facing tooling
/// and runbooks can grep for them.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TriggerDrainError {
    /// The publisher was constructed without `dlq_dir`/`dlq_key_file`,
    /// so no drain worker exists. Surface as `503 Service Unavailable`
    /// — manual replay is unavailable for fundamental configuration
    /// reasons, not a transient problem.
    #[error("DLQ not configured: cannot trigger drain")]
    DlqNotConfigured,
    /// The target name does not match any configured (and enabled)
    /// HTTP target. Surface as `404 Not Found` — operators get a
    /// precise signal that the target was renamed, removed, or
    /// disabled rather than a misleading `429`.
    #[error("unknown HTTP target")]
    UnknownTarget,
    /// The drain trigger channel is at capacity. The drain worker is
    /// either mid-pass on another target or already has a backlog of
    /// triggers to process; either way another drain will run shortly.
    /// Surface as `429 Too Many Requests` so operator tooling can
    /// retry without escalating to a hard error path.
    #[error("drain trigger channel is full; another drain is in flight")]
    ChannelFull,
    /// The drain trigger channel has been closed — the publisher is
    /// shutting down or the worker exited. Surface as `503 Service
    /// Unavailable` so callers know the publisher is no longer
    /// honoring drains.
    #[error("drain trigger channel is closed; publisher is shutting down")]
    ChannelClosed,
}

/// Per-target runtime state.
struct TargetState {
    name: String,
    client: reqwest::Client,
    url: String,
    /// URL path component cached at construction time. Bound into the HMAC
    /// canonical payload (`<timestamp>.<METHOD>.<path>.<body>`) so a
    /// signature captured for `/alert` cannot be replayed at `/shutdown`.
    /// Cached here (rather than re-parsing per request) because the URL is
    /// fixed for the target's lifetime and reqwest's `Url::parse` is the
    /// only way to get the path component cleanly.
    url_path: String,
    method: reqwest::Method,
    format: PayloadFormat,
    auth: Option<AuthState>,
    filter: CompiledFilter,
    circuit: CircuitBreaker,
    max_attempts: u32,
    backoff_base: Duration,
    instance_id: String,
    custom_headers: Vec<(HeaderName, String)>,
    max_payload_bytes: usize,
    /// Per-target rate limiter. `None` means unlimited.
    rate_limiter: Option<TokenBucket>,
    /// Capture the response body on 2xx responses and emit it alongside
    /// the per-request `delivery_id` in a structured debug log. Lets
    /// operators recover downstream acknowledgement IDs (Splunk HEC
    /// `ackId`, Elastic `_id`, Loki `traceID`) without a receiver-side
    /// proxy. Failure-path bodies are always captured independently.
    capture_response_body: bool,
    /// Maximum bytes of response body to capture on either path.
    /// Enforced symmetrically to prevent a misconfigured endpoint from
    /// flooding structured logs with megabytes of error detail.
    max_response_body_bytes: usize,
    /// Batch framing used when [`batcher`](Self::batcher) is `Some`.
    batch_format: BatchFormat,
    /// Per-target in-memory batcher, present iff batching is enabled
    /// in config. `parking_lot::Mutex` is the workspace hot-path
    /// primitive — doesn't poison, no `.unwrap()` on lock.
    batcher: Option<Arc<parking_lot::Mutex<Batcher>>>,
}

impl fmt::Debug for TargetState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TargetState")
            .field("name", &self.name)
            .field("url", &self.url)
            .finish_non_exhaustive()
    }
}

impl HttpPublisher {
    /// Build publisher from config, constructing per-target reqwest clients.
    ///
    /// Validates configuration, loads auth secrets, and builds a dedicated
    /// HTTP client for each enabled target. Spawns two background tasks
    /// automatically: a dispatch worker that fans out inbound messages to
    /// matching targets, and (when a DLQ is configured) a drain worker
    /// that replays sealed DLQ segments whenever a target's circuit
    /// breaker recovers (`HalfOpen → Closed`). `#881`.
    ///
    /// # Runtime requirement
    ///
    /// **Must be called from within a tokio runtime context.** Despite
    /// the synchronous `pub fn new` signature, this constructor calls
    /// [`tokio::spawn`] for the dispatch worker (and a second time for
    /// the DLQ drain worker when `dlq_dir` + `dlq_key_file` are
    /// configured). Calling it from outside a tokio runtime panics
    /// with `there is no reactor running`.
    ///
    /// # Blocking I/O
    ///
    /// In addition to the spawned tasks, this constructor performs
    /// **synchronous, blocking** filesystem I/O when a DLQ is
    /// configured: it reads the encryption key ring via
    /// [`std::fs`](std::fs) and creates the DLQ directory tree with
    /// `std::fs::create_dir_all`. From a tokio worker thread the cost
    /// is paid once at startup; if the key file lives on slow storage,
    /// wrap the call in
    /// [`tokio::task::spawn_blocking`](tokio::task::spawn_blocking) so
    /// the runtime worker is not starved.
    pub fn new(config: HttpConfig) -> Result<Self, HttpError> {
        config.validate()?;

        let resolver = Arc::new(SsrfSafeResolver::new(config.allow_private_urls));
        let instance_id = config.instance_id.unwrap_or_else(generate_instance_id);

        // Drain channel: the circuit observer on every target `try_send`s
        // the target's own name through this channel when it transitions
        // from `HalfOpen → Closed`. Bounded so a pathologically flapping
        // circuit cannot inflate memory with queued drain triggers; the
        // worker processes triggers sequentially and coalesces repeats
        // naturally (the directory scan on every pass picks up anything
        // that was dropped on channel-full).
        let (drain_tx, drain_rx) = mpsc::channel::<String>(DRAIN_CHANNEL_BUFFER);

        let mut targets = Vec::with_capacity(config.targets.len());

        for tc in &config.targets {
            if tc.enabled == Some(false) {
                tracing::info!(target = %tc.name, "HTTP target disabled, skipping");
                continue;
            }

            // The drain_tx is cloned per-target so each circuit observer
            // owns its own `Sender`; dropping a single target does not
            // close the channel.
            let target = build_target(
                tc,
                &instance_id,
                Arc::clone(&resolver),
                Some(drain_tx.clone()),
            )?;
            targets.push(target);
        }

        if targets.is_empty() {
            return Err(HttpError::Config(
                "no enabled HTTP targets configured".to_string(),
            ));
        }

        // Initialize encrypted dead-letter queue if configured
        let dlq = match (&config.dlq_dir, &config.dlq_key_file) {
            (Some(dir), Some(key_file)) => {
                let key_ring =
                    rustgate_archive::encrypted::KeyRing::load(std::path::Path::new(key_file))
                        .map_err(|e| HttpError::Dlq {
                            target: "_global".to_string(),
                            message: format!("failed to load DLQ key ring: {e}"),
                        })?;

                // Create DLQ directory if it doesn't exist
                std::fs::create_dir_all(dir).map_err(|e| HttpError::Dlq {
                    target: "_global".to_string(),
                    message: format!("failed to create DLQ directory `{dir}`: {e}"),
                })?;

                tracing::info!(
                    dlq_dir = %dir,
                    "encrypted dead-letter queue enabled"
                );
                Some(Arc::new(DeadLetterQueue::new(
                    std::path::PathBuf::from(dir),
                    key_ring,
                    config.dlq_max_bytes,
                    config.dlq_max_target_bytes,
                )))
            }
            _ => None,
        };

        tracing::info!(
            target_count = targets.len(),
            instance_id = %instance_id,
            dlq_enabled = dlq.is_some(),
            "HTTP publisher initialized"
        );

        let (tx, rx) = mpsc::channel(CHANNEL_BUFFER);
        let shutdown = Arc::new(tokio::sync::Notify::new());
        let targets = Arc::new(targets);

        // Spawn background worker — handle stored for panic detection
        let worker_targets = Arc::clone(&targets);
        let worker_shutdown = Arc::clone(&shutdown);
        let worker_dlq = dlq.clone();
        let handle = tokio::spawn(dispatch_worker(
            rx,
            worker_targets,
            worker_shutdown,
            worker_dlq,
        ));

        // Spawn the DLQ drain worker only when a DLQ is configured.
        // Without a DLQ there are no sealed segments to replay, so the
        // worker would spin on `recv()` forever consuming nothing.
        // Dropping the receiver now (`drain_rx`) also closes the
        // channel from the reader side, so the per-target `try_send`
        // in the circuit observer observes `Err(Closed)` and
        // gracefully degrades to audit/log only.
        //
        // The drain worker gets its own `Notify`, distinct from the
        // dispatch worker's `shutdown`, so `HttpPublisher::shutdown`
        // can wake both with `notify_one` each. A shared `Notify` +
        // `notify_waiters` would race a worker that was mid-segment
        // at the call moment and silently drop the signal.
        let drain_shutdown = if let Some(ref dlq_arc) = dlq {
            let drain_notify = Arc::new(tokio::sync::Notify::new());
            let drain_targets = Arc::clone(&targets);
            let drain_dlq = Arc::clone(dlq_arc);
            let drain_notify_worker = Arc::clone(&drain_notify);
            // Detach the drain worker: it is a best-effort background
            // task, and its panic or exit does not require a
            // graceful-shutdown wait. The dedicated `drain_notify`
            // signals termination and the channel close drains any
            // pending triggers on publisher drop. `spawn_background`
            // is the workspace-wide helper that adds panic logging
            // around the spawned future.
            spawn_background(
                "http-dlq-drain-worker",
                drain_worker(drain_rx, drain_targets, drain_dlq, drain_notify_worker),
            );
            Some(drain_notify)
        } else {
            // No DLQ → no drain worker spawned → no drain shutdown
            // signal to hold. Dropping `drain_rx` closes the channel
            // from the reader side so any per-target `try_send` in the
            // circuit observer observes `Err(Closed)` and gracefully
            // degrades to audit/log only.
            std::mem::drop(drain_rx);
            None
        };

        // Retain the top-level drain sender only when a DLQ is
        // configured. Without one the drain worker is never spawned
        // and the receiver was already dropped above, so we hold
        // `None` rather than a sender into a dead channel — that way
        // `trigger_drain` returns a precise `DlqNotConfigured` error
        // instead of `ChannelClosed`.
        let top_level_drain_tx = if dlq.is_some() {
            Some(drain_tx)
        } else {
            std::mem::drop(drain_tx);
            None
        };

        Ok(Self {
            tx,
            targets,
            shutdown,
            drain_shutdown,
            drain_tx: top_level_drain_tx,
            dlq,
            worker_handle: Arc::new(std::sync::Mutex::new(Some(handle))),
            gate: None,
        })
    }

    /// Attach a shared [`BackpressureGate`] so HTTP egress participates in
    /// global admission control.
    ///
    /// When configured, each message that survives echo-prevention acquires
    /// a byte permit sized to its payload *before* entering the dispatch
    /// channel. The permit drops when the worker finishes dispatching the
    /// message, so the gate's in-flight byte counter reflects what this
    /// publisher has actually buffered. A slow HTTP endpoint that causes
    /// the channel to back up now also pressures the global gate — the
    /// router will see `is_admitting()` flip to `false` and stop admitting
    /// new ingress instead of silently hoarding memory here.
    ///
    /// If the gate is already blocking (over the high-water mark) when
    /// `publish` is called, the message is rejected fast via the DLQ path
    /// rather than waiting: HTTP egress is fire-and-forget and must not
    /// block the router's dispatch task.
    #[must_use]
    pub fn with_backpressure(mut self, gate: Arc<BackpressureGate>) -> Self {
        self.gate = Some(gate);
        self
    }

    /// Fire-and-forget publish. Non-blocking — drops on channel full.
    ///
    /// When the admission queue rejects a message (channel full or closed,
    /// or the global backpressure gate is not admitting), and a DLQ is
    /// configured, the message is persisted under the synthetic
    /// `admission` DLQ target with the drop reason. This prevents silent
    /// loss of messages that never reach per-target dispatch and keeps
    /// the forensic trail symmetric with circuit-open drops.
    pub fn publish(&self, msg: &RoutableMessage) {
        // Echo prevention at the publisher level (case-insensitive to
        // defend against inconsistent casing across transport adapters)
        if msg.metadata.source_protocol.eq_ignore_ascii_case("http") {
            return;
        }

        // Global admission check: if the shared gate is parked over the
        // high-water mark, shed immediately rather than queueing another
        // permit on top of the existing backlog. DLQ path below keeps the
        // forensic trail intact.
        let permit = match self.gate.as_ref() {
            Some(gate) => {
                if !gate.is_admitting() {
                    tracing::warn!(
                        source_cn = %sanitize_for_log(&msg.source.cn),
                        "HTTP backpressure gate over high-water, dropping message"
                    );
                    #[cfg(feature = "metrics")]
                    crate::metrics::dropped()
                        .with_label_values(&["backpressure"])
                        .inc();
                    if let Some(ref dlq) = self.dlq {
                        dlq.dead_letter(ADMISSION_DLQ_TARGET, msg, "backpressure");
                    }
                    return;
                }
                Some(Arc::new(gate.acquire(msg.payload.len())))
            }
            None => None,
        };

        let queued = QueuedMessage {
            msg: Arc::new(msg.clone()),
            permit,
        };

        match self.tx.try_send(queued) {
            Ok(()) => {
                // The worker decrements this gauge on recv — see
                // `dispatch_worker`.
                #[cfg(feature = "metrics")]
                crate::metrics::queue_depth().inc();
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                tracing::warn!(
                    source_cn = %sanitize_for_log(&msg.source.cn),
                    target_count = self.targets.len(),
                    "HTTP dispatch channel full, dropping message"
                );
                #[cfg(feature = "metrics")]
                {
                    crate::metrics::errors()
                        .with_label_values(&["_all", "channel_full"])
                        .inc();
                    crate::metrics::dropped()
                        .with_label_values(&["channel_full"])
                        .inc();
                }
                // Fail-open DLQ persist so the drop is not silent.
                if let Some(ref dlq) = self.dlq {
                    dlq.dead_letter(ADMISSION_DLQ_TARGET, msg, "channel_full");
                }
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                tracing::warn!("HTTP dispatch channel closed");
                #[cfg(feature = "metrics")]
                crate::metrics::dropped()
                    .with_label_values(&["channel_closed"])
                    .inc();
                if let Some(ref dlq) = self.dlq {
                    dlq.dead_letter(ADMISSION_DLQ_TARGET, msg, "channel_closed");
                }
            }
        }
    }

    /// True when all circuit breakers are closed (healthy).
    pub fn is_healthy(&self) -> bool {
        self.targets.iter().all(|t| t.circuit.is_closed())
    }

    /// Names of every configured (and enabled) HTTP target, in
    /// configuration order. Exposed for the management API so the
    /// `POST /api/dlq/{target}/replay` handler can short-circuit
    /// unknown-target requests with a `404` before queueing a drain
    /// trigger that the worker would otherwise quietly drop. Ordering
    /// matches `HttpConfig::targets` because the per-target build is
    /// in-order — operators reading the list back via diagnostics
    /// see the names in the same order they configured them.
    #[must_use]
    pub fn target_names(&self) -> Vec<String> {
        self.targets.iter().map(|t| t.name.clone()).collect()
    }

    /// Manually trigger a DLQ drain for `target_name`.
    ///
    /// Designed for the management API endpoint
    /// `POST /api/dlq/{target}/replay` — operator-initiated drains
    /// share the same channel and the same drain worker as the
    /// circuit-recovery observer, so a manual trigger and a recovery
    /// trigger are indistinguishable downstream and the audit trail
    /// stays uniform. The trigger is fire-and-forget: success means
    /// "the drain worker has been notified", not "the drain has
    /// completed" — the actual replay runs asynchronously.
    ///
    /// # Errors
    ///
    /// - [`TriggerDrainError::DlqNotConfigured`] when this publisher
    ///   was built without `dlq_dir`/`dlq_key_file`. The drain worker
    ///   is not spawned in that case and there is nothing to drain.
    /// - [`TriggerDrainError::UnknownTarget`] when `target_name` does
    ///   not match any configured (and enabled) target. Pinned at this
    ///   layer so the management API can return `404` rather than
    ///   silently queueing a trigger the worker will skip.
    /// - [`TriggerDrainError::ChannelFull`] when the drain trigger
    ///   channel is full. Means another drain is already queued or
    ///   running for some target — operators can retry or rely on the
    ///   automatic recovery trigger.
    /// - [`TriggerDrainError::ChannelClosed`] when the publisher is
    ///   shutting down. The drain worker has either exited or is
    ///   about to.
    pub fn trigger_drain(&self, target_name: &str) -> Result<(), TriggerDrainError> {
        let Some(ref drain_tx) = self.drain_tx else {
            return Err(TriggerDrainError::DlqNotConfigured);
        };
        if !self.targets.iter().any(|t| t.name == target_name) {
            return Err(TriggerDrainError::UnknownTarget);
        }
        match drain_tx.try_send(target_name.to_string()) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => Err(TriggerDrainError::ChannelFull),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(TriggerDrainError::ChannelClosed),
        }
    }

    /// Signal the background worker to shut down, await drain, and seal DLQ.
    ///
    /// Logs a warning if the worker panicked. Seals DLQ writers to ensure
    /// encrypted terminators are written (readers reject unterminated files).
    pub async fn shutdown(&self) {
        self.shutdown.notify_one();
        // The drain worker (when a DLQ is configured) waits on its own
        // dedicated `Notify` handle — see the `drain_shutdown` field —
        // so we signal it separately rather than sharing a single
        // `Notify` with the dispatch worker. Sharing would require
        // `notify_waiters`, which has no stored-permit semantics and
        // silently drops the signal if a worker was mid-processing
        // at the call moment; two single-waiter `Notify`s with
        // `notify_one` each are both simpler and strictly correct.
        if let Some(ref drain_shutdown) = self.drain_shutdown {
            drain_shutdown.notify_one();
        }

        // Take the handle out of the lock, then await it — avoids holding
        // a std::sync::Mutex guard across an .await point.
        let handle = self
            .worker_handle
            .lock()
            .ok()
            .and_then(|mut guard| guard.take());
        if let Some(handle) = handle {
            match handle.await {
                Ok(()) => {}
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        "HTTP dispatch worker panicked during shutdown"
                    );
                }
            }
        }

        if let Some(ref dlq) = self.dlq {
            dlq.finish();
        }
    }
}

/// Build a single target's runtime state from config.
///
/// `drain_tx` is the sender half of the DLQ drain channel held by
/// [`HttpPublisher::new`]; when `Some(tx)`, the per-target circuit
/// observer will fire a `try_send(target_name)` on every confirmed
/// recovery (`HalfOpen → Closed`). Pass `None` from test/diagnostic
/// paths that do not spawn a drain worker; the observer then degrades
/// to audit/log only without attempting to signal a non-existent worker.
fn build_target(
    tc: &TargetConfig,
    instance_id: &str,
    resolver: Arc<SsrfSafeResolver>,
    drain_tx: Option<mpsc::Sender<String>>,
) -> Result<TargetState, HttpError> {
    let client = build_client(tc, resolver)?;

    let method = match tc.method.unwrap_or_default() {
        crate::config::HttpMethod::Post => reqwest::Method::POST,
        crate::config::HttpMethod::Put => reqwest::Method::PUT,
        crate::config::HttpMethod::Patch => reqwest::Method::PATCH,
    };

    let auth = tc.auth.as_ref().map(AuthState::from_config).transpose()?;

    let filter = tc
        .filter
        .as_ref()
        .map(CompiledFilter::from_config)
        .unwrap_or_else(CompiledFilter::default_filter);

    let retry = tc.retry.as_ref();
    let circuit = CircuitBreaker::new(
        retry.and_then(|r| r.circuit_breaker_threshold).unwrap_or(5),
        Duration::from_secs(
            retry
                .and_then(|r| r.circuit_breaker_cooldown_secs)
                .unwrap_or(30),
        ),
        retry.and_then(|r| r.half_open_max_probes).unwrap_or(3),
        retry
            .and_then(|r| r.half_open_success_threshold)
            .unwrap_or(2),
    )
    .with_on_state_change(build_circuit_observer(&tc.name, drain_tx));

    let custom_headers = tc
        .headers
        .as_ref()
        .map(|hdrs| {
            hdrs.iter()
                .filter_map(|h| {
                    h.name
                        .parse::<HeaderName>()
                        .ok()
                        .map(|name| (name, h.value.clone()))
                })
                .collect()
        })
        .unwrap_or_default();

    let rate_limiter = tc
        .rate_limit_per_sec
        .map(|rate| TokenBucket::new(rate, None));

    // Only instantiate a batcher when the operator opted in — `None`
    // keeps the single-message hot path free of any lock/branch cost
    // for the overwhelming majority of pre-#906 deployments.
    let batcher = if tc.effective_batch_enabled() {
        Some(Arc::new(parking_lot::Mutex::new(Batcher::new(
            tc.effective_batch_max_messages(),
            tc.effective_batch_max_bytes(),
        ))))
    } else {
        None
    };

    // Cache the URL path component for HMAC canonical-payload binding.
    // Validated at config time, so parse-failure here is unreachable in
    // practice, but the fall-back keeps the function infallible without
    // panicking — an empty path is a harmless tombstone that simply
    // produces a signature that cannot match any well-formed receiver
    // reconstruction.
    let url_path = reqwest::Url::parse(&tc.url)
        .map(|u| u.path().to_string())
        .unwrap_or_default();

    Ok(TargetState {
        name: tc.name.clone(),
        client,
        url: tc.url.clone(),
        url_path,
        method,
        format: tc.format.unwrap_or_default(),
        auth,
        filter,
        circuit,
        max_attempts: retry.and_then(|r| r.max_attempts).unwrap_or(3),
        backoff_base: Duration::from_secs(retry.and_then(|r| r.backoff_base_secs).unwrap_or(1)),
        instance_id: instance_id.to_string(),
        custom_headers,
        max_payload_bytes: tc.effective_max_payload_bytes(),
        rate_limiter,
        capture_response_body: tc.effective_capture_response_body(),
        max_response_body_bytes: tc.effective_max_response_body_bytes(),
        batch_format: tc.effective_batch_format(),
        batcher,
    })
}

/// Build the per-target `OnStateChange` observer attached to the circuit.
///
/// The observer fires on every transition and acts on two of them:
///
/// 1. `Open → HalfOpen` — the moment the breaker decides to admit a
///    probe after cooldown. Emits `http_circuit_probing`, nudges the
///    Prometheus gauge to `half-open (2)`, and logs the probe intent
///    so operators can correlate probe admission with any concurrent
///    4xx/5xx burst. No DLQ side-effect yet: one successful probe does
///    not guarantee the upstream is healthy, and a failed probe would
///    re-open the circuit immediately — replaying at this point would
///    risk inflating an outage by burning DLQ entries against an
///    endpoint that is about to trip again.
///
/// 2. `HalfOpen → Closed` — confirmed recovery. The breaker only makes
///    this transition after `half_open_success_threshold` consecutive
///    successes, so we treat it as durable-enough to start the auto-
///    drain pass. The observer sends the target name through a bounded
///    drain channel (`try_send`, non-blocking) whose receive end is
///    held by the drain worker spawned in [`HttpPublisher::new`].
///    If the channel is full, the drain request is dropped rather than
///    blocking the circuit hot path — the admin endpoint (see PR C)
///    and the next trip cycle both act as safety nets.
///
/// The `Closed → Open` transition is NOT emitted from this observer —
/// its audit event is emitted at the `record_failure` call site in
/// `publish_with_retry`, and firing again here would double-log.
/// `HalfOpen → Open` (probe failure) is treated the same way
/// (`record_failure` already emits `http_circuit_tripped`).
///
/// The callback body is deliberately short: it emits at most one audit
/// event, nudges the Prometheus gauge, optionally `try_send`s a drain
/// request, and returns. Heavy work runs in the drain worker, not in
/// the transition path.
fn build_circuit_observer(
    target_name: &str,
    drain_tx: Option<mpsc::Sender<String>>,
) -> OnStateChange {
    let name = target_name.to_string();
    Arc::new(move |old, new| {
        if old == STATE_OPEN && new == STATE_HALF_OPEN {
            rustgate_core::audit::http_circuit_probing(&name);
            #[cfg(feature = "metrics")]
            crate::metrics::circuit_state()
                .with_label_values(&[name.as_str()])
                // 2 == half-open; matches rustgate_resilience::circuit::STATE_HALF_OPEN
                .set(2);
            tracing::info!(
                target = %sanitize_for_log(&name),
                "HTTP target entering half-open probe window; queued DLQ messages eligible for drain on recovery"
            );
        } else if old == STATE_HALF_OPEN && new == STATE_CLOSED {
            // Confirmed recovery — trigger the auto-drain pass. The
            // `http_circuit_recovered` audit event is already emitted by
            // `record_success` on this transition, so we do NOT re-emit
            // it here; the drain worker emits its own separate
            // `http_dlq_drain_started` / `http_dlq_drain_completed`
            // pair so operators can tell circuit recovery apart from
            // DLQ replay progress.
            if let Some(tx) = drain_tx.as_ref() {
                match tx.try_send(name.clone()) {
                    Ok(()) => {
                        tracing::info!(
                            target = %sanitize_for_log(&name),
                            "HTTP target recovered; auto-drain triggered"
                        );
                    }
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        // Another drain is queued or running; dropping
                        // this trigger is safe because the drain worker
                        // re-scans the directory on every pass and the
                        // next recovery cycle (or admin replay) will
                        // catch anything we miss.
                        tracing::debug!(
                            target = %sanitize_for_log(&name),
                            "DLQ drain channel full, trigger coalesced"
                        );
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        tracing::warn!(
                            target = %sanitize_for_log(&name),
                            "DLQ drain channel closed, auto-drain unavailable"
                        );
                    }
                }
            }
        }
    })
}

/// Build a reqwest::Client for a target with timeout and optional TLS.
///
/// Security hardening:
/// - SSRF-safe DNS resolver validates resolved IPs at connect time (DNS rebinding defense).
/// - Redirects disabled to prevent SSRF via 3xx to internal endpoints.
/// - Separate connect timeout prevents slow-connect DoS.
/// - Minimum TLS 1.2 enforced for outbound connections.
/// - Certificate pinning via custom rustls verifier when `pin-sha256` is configured.
fn build_client(
    tc: &TargetConfig,
    resolver: Arc<SsrfSafeResolver>,
) -> Result<reqwest::Client, HttpError> {
    let has_pins = tc
        .tls
        .as_ref()
        .and_then(|t| t.pin_sha256.as_ref())
        .is_some_and(|pins| !pins.is_empty());

    if has_pins {
        build_pinned_client(tc, resolver)
    } else {
        build_standard_client(tc, resolver)
    }
}

/// Build a reqwest client using reqwest's native TLS configuration (no pinning).
fn build_standard_client(
    tc: &TargetConfig,
    resolver: Arc<SsrfSafeResolver>,
) -> Result<reqwest::Client, HttpError> {
    let timeout = Duration::from_secs(tc.effective_timeout_secs());
    let mut builder = reqwest::Client::builder()
        .timeout(timeout)
        .connect_timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .min_tls_version(reqwest::tls::Version::TLS_1_2)
        .user_agent(RUSTGATE_USER_AGENT)
        .dns_resolver(resolver);

    if let Some(tls) = &tc.tls {
        if let Some(ca_path) = &tls.ca_cert {
            let ca_pem = std::fs::read(ca_path).map_err(|e| HttpError::TlsFile {
                target: tc.name.clone(),
                path: ca_path.clone(),
                source: e,
            })?;
            let cert =
                reqwest::Certificate::from_pem(&ca_pem).map_err(|e| HttpError::ClientBuild {
                    target: tc.name.clone(),
                    source: e,
                })?;
            builder = builder.add_root_certificate(cert);
        }

        if let Some(cert_path) = &tls.client_cert {
            let key_path = tls.client_key.as_ref().ok_or_else(|| {
                HttpError::Config(format!(
                    "target `{}`: client-cert requires client-key",
                    tc.name
                ))
            })?;

            let mut identity_pem =
                Zeroizing::new(std::fs::read(cert_path).map_err(|e| HttpError::TlsFile {
                    target: tc.name.clone(),
                    path: cert_path.clone(),
                    source: e,
                })?);

            // SEC-5: the private key goes through the shared secrets gate
            // (mode-0o077 + 16 KiB size cap) instead of raw std::fs::read;
            // the public cert above stays on plain std::fs::read.
            let key_pem = {
                let mut k = read_secret_file(key_path, &SecretFileOpts::with_max_bytes(16 * 1024))?;
                Zeroizing::new(std::mem::take(&mut *k).into_bytes())
            };

            // reqwest::Identity::from_pem expects cert+key concatenated
            identity_pem.extend_from_slice(&key_pem);

            let identity =
                reqwest::Identity::from_pem(&identity_pem).map_err(|e| HttpError::ClientBuild {
                    target: tc.name.clone(),
                    source: e,
                })?;
            builder = builder.identity(identity);
        }
    }

    builder.build().map_err(|e| HttpError::ClientBuild {
        target: tc.name.clone(),
        source: e,
    })
}

/// Build a reqwest client with certificate pinning via a custom rustls verifier.
///
/// When pin-sha256 is configured, we build the entire rustls ClientConfig
/// manually so we can wrap the standard WebPKI verifier with our pinning
/// check. This overrides reqwest's native TLS configuration.
fn build_pinned_client(
    tc: &TargetConfig,
    resolver: Arc<SsrfSafeResolver>,
) -> Result<reqwest::Client, HttpError> {
    let tls = tc.tls.as_ref().ok_or_else(|| {
        HttpError::Config(format!(
            "target `{}`: certificate pinning requires TLS configuration",
            tc.name
        ))
    })?;

    // Config validation ensures ca-cert is set when pins are configured
    let ca_path = tls.ca_cert.as_ref().ok_or_else(|| {
        HttpError::Config(format!("target `{}`: pin-sha256 requires ca-cert", tc.name))
    })?;

    let ca_pem = std::fs::read(ca_path).map_err(|e| HttpError::TlsFile {
        target: tc.name.clone(),
        path: ca_path.clone(),
        source: e,
    })?;

    let root_store = crate::pinning::build_root_store(&ca_pem).map_err(|e| {
        HttpError::Config(format!(
            "target `{}`: failed to build root store: {e}",
            tc.name
        ))
    })?;

    let pins_config = tls.pin_sha256.as_ref().ok_or_else(|| {
        HttpError::Config(format!(
            "target `{}`: expected pin-sha256 in TLS config",
            tc.name
        ))
    })?;
    let parsed_pins = crate::pinning::parse_pins(pins_config)?;

    // Build the standard WebPKI verifier as the inner chain validator
    let inner_verifier = rustls::client::WebPkiServerVerifier::builder(Arc::new(root_store))
        .build()
        .map_err(|e| {
            HttpError::Config(format!(
                "target `{}`: failed to build WebPKI verifier: {e}",
                tc.name
            ))
        })?;

    let pinned_verifier = Arc::new(crate::pinning::PinnedCertVerifier::new(
        inner_verifier,
        parsed_pins,
    ));

    // Build rustls ClientConfig with the pinning verifier
    let tls_config = if let Some(cert_path) = &tls.client_cert {
        let key_path = tls.client_key.as_ref().ok_or_else(|| {
            HttpError::Config(format!(
                "target `{}`: client-cert requires client-key",
                tc.name
            ))
        })?;

        let cert_pem =
            Zeroizing::new(std::fs::read(cert_path).map_err(|e| HttpError::TlsFile {
                target: tc.name.clone(),
                path: cert_path.clone(),
                source: e,
            })?);
        // SEC-5: private key via the shared secrets gate (mode-0o077 +
        // 16 KiB cap); the public cert above stays on plain std::fs::read.
        let key_pem = {
            let mut k = read_secret_file(key_path, &SecretFileOpts::with_max_bytes(16 * 1024))?;
            Zeroizing::new(std::mem::take(&mut *k).into_bytes())
        };

        let certs = crate::pinning::parse_pem_certs(&cert_pem);
        let key = crate::pinning::parse_pem_private_key(&key_pem).ok_or_else(|| {
            HttpError::Config(format!(
                "target `{}`: failed to parse client private key PEM",
                tc.name
            ))
        })?;

        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(pinned_verifier)
            .with_client_auth_cert(certs, key)
            .map_err(|e| {
                HttpError::Config(format!(
                    "target `{}`: failed to build TLS config with client cert: {e}",
                    tc.name
                ))
            })?
    } else {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(pinned_verifier)
            .with_no_client_auth()
    };

    let timeout = Duration::from_secs(tc.effective_timeout_secs());
    reqwest::Client::builder()
        .timeout(timeout)
        .connect_timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(RUSTGATE_USER_AGENT)
        .dns_resolver(resolver)
        .use_preconfigured_tls(tls_config)
        .build()
        .map_err(|e| HttpError::ClientBuild {
            target: tc.name.clone(),
            source: e,
        })
}

/// Background worker that drains the channel and fans out to targets.
///
/// Each [`QueuedMessage`] carries an optional [`BackpressurePermit`] that
/// remains alive for the duration of `fan_out`; dropping the envelope at
/// the end of each iteration releases the gate's byte reservation
/// automatically.
async fn dispatch_worker(
    mut rx: mpsc::Receiver<QueuedMessage>,
    targets: Arc<Vec<TargetState>>,
    shutdown: Arc<tokio::sync::Notify>,
    dlq: Option<Arc<DeadLetterQueue>>,
) {
    loop {
        tokio::select! {
            biased;
            () = shutdown.notified() => {
                tracing::info!("HTTP dispatch worker shutting down, draining queue");
                rx.close();
                while let Some(queued) = rx.recv().await {
                    #[cfg(feature = "metrics")]
                    crate::metrics::queue_depth().dec();
                    fan_out(&queued.msg, &targets, dlq.as_deref()).await;
                    // `queued` drops here, releasing the permit.
                    drop(queued);
                }
                // Drain every per-target batcher so buffered messages that
                // never hit a count/bytes threshold still get one final
                // HTTP send before the worker returns. No-op on targets
                // with batching disabled.
                drain_batchers(&targets).await;
                tracing::info!("HTTP dispatch worker stopped");
                return;
            }
            msg = rx.recv() => {
                match msg {
                    Some(queued) => {
                        // Paired with the inc() in `HttpPublisher::publish`.
                        #[cfg(feature = "metrics")]
                        crate::metrics::queue_depth().dec();
                        fan_out(&queued.msg, &targets, dlq.as_deref()).await;
                        // `queued` drops here, releasing the permit.
                        drop(queued);
                    }
                    None => {
                        tracing::info!("HTTP dispatch channel closed");
                        drain_batchers(&targets).await;
                        return;
                    }
                }
            }
        }
    }
}

/// Fan out a message to all matching targets concurrently.
///
/// Dispatches are independent — a slow or failing target does not block
/// delivery to other targets. Uses `join_all` within the current task
/// (no spawn) so borrowed references remain valid.
async fn fan_out(msg: &RoutableMessage, targets: &[TargetState], dlq: Option<&DeadLetterQueue>) {
    let sanitized_cn = sanitize_for_log(&msg.source.cn);

    let futures: Vec<_> = targets
        .iter()
        .filter(|target| {
            if target.filter.matches(msg) {
                return true;
            }
            tracing::trace!(
                target = %target.name,
                source_cn = %sanitized_cn,
                source_protocol = %msg.metadata.source_protocol,
                "message filtered out for target"
            );
            #[cfg(feature = "metrics")]
            crate::metrics::filtered()
                .with_label_values(&[target.name.as_str()])
                .inc();
            false
        })
        .map(|target| {
            let span = tracing::debug_span!(
                "http_dispatch",
                target = %target.name,
                source_cn = %sanitized_cn,
            );
            dispatch_to_target(target, msg, dlq).instrument(span)
        })
        .collect();

    let _ = futures::future::join_all(futures).await;
}

/// Dispatch a single message to a target with retry and circuit breaking.
async fn dispatch_to_target(
    target: &TargetState,
    msg: &RoutableMessage,
    dlq: Option<&DeadLetterQueue>,
) {
    // Per-target rate limiting — shed excess traffic before any work.
    if let Some(ref limiter) = target.rate_limiter
        && !limiter.try_acquire()
    {
        tracing::debug!(
            target = %target.name,
            source_cn = %sanitize_for_log(&msg.source.cn),
            "rate limited, dropping message"
        );
        rustgate_core::audit::http_rate_limited(&target.name, &sanitize_for_log(&msg.source.cn));
        #[cfg(feature = "metrics")]
        crate::metrics::errors()
            .with_label_values(&[target.name.as_str(), "rate_limited"])
            .inc();
        return;
    }

    // Circuit breaker check — persist to DLQ if configured
    if !target.circuit.allow_request() {
        tracing::warn!(
            target = %target.name,
            source_cn = %sanitize_for_log(&msg.source.cn),
            message_type = %msg.metadata.message_type,
            payload_size = msg.payload.len(),
            "circuit open, dead-lettering message"
        );
        if let Some(dlq) = dlq {
            dlq.dead_letter(&target.name, msg, "circuit_open");
        }
        #[cfg(feature = "metrics")]
        crate::metrics::errors()
            .with_label_values(&[target.name.as_str(), "circuit_open"])
            .inc();
        return;
    }

    // Reject oversized payloads before serialization (memory DoS prevention)
    if msg.payload.len() > target.max_payload_bytes {
        tracing::warn!(
            target = %target.name,
            payload_size = msg.payload.len(),
            max_payload_bytes = target.max_payload_bytes,
            "message payload exceeds size limit, dropping"
        );
        #[cfg(feature = "metrics")]
        crate::metrics::errors()
            .with_label_values(&[target.name.as_str(), "payload_too_large"])
            .inc();
        return;
    }

    // Serialize payload. `serialize` returns `Bytes` directly so retries
    // and auth signing share a single allocation via ref-count clones —
    // no `Vec<u8> -> Bytes` round-trip on the message-path hot loop.
    let (body, content_type) = match payload::serialize(msg, target.format, &target.instance_id) {
        Ok(result) => result,
        Err(e) => {
            tracing::warn!(
                target = %target.name,
                error = %e,
                "payload serialization failed"
            );
            #[cfg(feature = "metrics")]
            crate::metrics::errors()
                .with_label_values(&[target.name.as_str(), "serialize"])
                .inc();
            return;
        }
    };

    // Batching branch: when the operator opted into `batch-enabled`, push
    // the serialized single-message body into the per-target batcher and
    // return early unless a count/bytes threshold fires. When a flush
    // fires, render the combined batch body and run a *single* retry
    // loop on it. The rate-limit / circuit / oversize checks above still
    // run per-message (they govern admission into the batcher, not the
    // outbound request cadence).
    if let Some(ref batcher_lock) = target.batcher {
        let flush = {
            let mut batcher = batcher_lock.lock();
            batcher.push(body.clone())
        };
        let Some(flush) = flush else {
            return;
        };
        #[cfg(feature = "metrics")]
        crate::metrics::batches_flushed()
            .with_label_values(&[target.name.as_str(), flush.reason.as_str()])
            .inc();
        let bodies = flush.bodies();
        let (batch_body, batch_ct) =
            payload::render_batch(&bodies, target.format, target.batch_format);
        publish_with_retry(target, batch_body, batch_ct, Some(flush.len())).await;
        return;
    }

    publish_with_retry(target, body, content_type, None).await;
}

/// Retry loop for a single outbound request — shared by the solo-message
/// path and the batched path. `batch_size = Some(n)` adds `batch_size`
/// fields to every structured log line so operators can tell a batched
/// request apart from a solo send in the access log.
async fn publish_with_retry(
    target: &TargetState,
    body: bytes::Bytes,
    content_type: &'static str,
    batch_size: Option<usize>,
) {
    // Stable delivery ID: generated once per request (solo or batch) so
    // retries carry the same ID, enabling receiver-side deduplication.
    let delivery_id = generate_delivery_id();

    // Content-Digest (RFC 9530): SHA-256 hash of the serialized body for
    // end-to-end integrity verification by the receiver.
    let content_digest = compute_content_digest(&body);

    // Retry loop with optional Retry-After from 429 responses
    let mut retry_after_hint: Option<Duration> = None;
    for attempt in 0..target.max_attempts {
        if attempt > 0 {
            let delay = if let Some(server_delay) = retry_after_hint.take() {
                // Respect server's Retry-After header, capped at 5 minutes
                server_delay.min(Duration::from_secs(300))
            } else {
                retry::backoff_with_jitter(target.backoff_base, attempt)
            };
            tokio::time::sleep(delay).await;
        }

        #[cfg(feature = "metrics")]
        let request_start = std::time::Instant::now();

        match send_request(
            target,
            body.clone(),
            content_type,
            &delivery_id,
            &content_digest,
        )
        .await
        {
            Ok(captured) => {
                #[cfg(feature = "metrics")]
                crate::metrics::request_duration().observe(request_start.elapsed().as_secs_f64());

                if target.circuit.record_success() {
                    rustgate_core::audit::http_circuit_recovered(&target.name);
                    #[cfg(feature = "metrics")]
                    crate::metrics::circuit_state()
                        .with_label_values(&[target.name.as_str()])
                        .set(0);
                }
                #[cfg(feature = "metrics")]
                crate::metrics::publishes()
                    .with_label_values(&[target.name.as_str()])
                    .inc();

                // Capture-enabled targets surface the response body on
                // a dedicated debug line alongside the delivery_id, so
                // operators can grep the access log for downstream
                // acknowledgement IDs (Splunk HEC `ackId`, Elastic
                // `_id`, Loki `traceID`). Skipped when the target has
                // the capture flag off or the response carried no
                // body.
                if let Some(ref ack_body) = captured {
                    #[cfg(feature = "metrics")]
                    crate::metrics::response_bodies_captured()
                        .with_label_values(&[target.name.as_str()])
                        .inc();
                    tracing::debug!(
                        target = %target.name,
                        attempt = attempt + 1,
                        delivery_id = %delivery_id,
                        batch_size = batch_size.unwrap_or(1),
                        body_bytes = ack_body.len(),
                        body = %format_body_snippet(ack_body),
                        "HTTP publish succeeded with response body"
                    );
                } else {
                    tracing::debug!(
                        target = %target.name,
                        attempt = attempt + 1,
                        delivery_id = %delivery_id,
                        batch_size = batch_size.unwrap_or(1),
                        "HTTP publish succeeded"
                    );
                }
                return;
            }
            Err((status, err, retry_after)) => {
                #[cfg(feature = "metrics")]
                crate::metrics::request_duration().observe(request_start.elapsed().as_secs_f64());

                let is_last = attempt + 1 >= target.max_attempts;
                let retryable = status.is_some_and(retry::is_retryable_status);

                if is_last || !retryable {
                    // Only server errors (5xx), rate limits (429), and network
                    // failures (status=None) count toward the circuit breaker.
                    // 4xx client errors indicate config issues, not endpoint
                    // health problems — tripping on them would mask the real fix.
                    let affects_circuit =
                        status.is_none_or(|s| s == 429 || (500..600).contains(&s));
                    if affects_circuit && target.circuit.record_failure() {
                        rustgate_core::audit::http_circuit_tripped(&target.name);
                        #[cfg(feature = "metrics")]
                        crate::metrics::circuit_state()
                            .with_label_values(&[target.name.as_str()])
                            .set(1);
                    }

                    rustgate_core::audit::http_publish_failed(
                        &target.name,
                        status.unwrap_or(0),
                        &err,
                    );

                    #[cfg(feature = "metrics")]
                    {
                        let reason = match status {
                            Some(s) if (400..500).contains(&s) => "status_4xx",
                            Some(s) if (500..600).contains(&s) => "status_5xx",
                            Some(_) => "status_other",
                            None => "network",
                        };
                        crate::metrics::errors()
                            .with_label_values(&[target.name.as_str(), reason])
                            .inc();
                    }

                    tracing::warn!(
                        target = %target.name,
                        attempt = attempt + 1,
                        delivery_id = %delivery_id,
                        batch_size = batch_size.unwrap_or(1),
                        error = %err,
                        status = ?status,
                        retryable,
                        affects_circuit,
                        "HTTP publish failed (final)"
                    );
                    return;
                }

                #[cfg(feature = "metrics")]
                crate::metrics::retries()
                    .with_label_values(&[target.name.as_str()])
                    .inc();

                retry_after_hint = retry_after;
                tracing::debug!(
                    target = %target.name,
                    attempt = attempt + 1,
                    delivery_id = %delivery_id,
                    batch_size = batch_size.unwrap_or(1),
                    error = %err,
                    status = ?status,
                    "HTTP publish failed, will retry"
                );
            }
        }
    }
}

/// Background task that replays sealed DLQ segments when a target's
/// circuit breaker recovers (`HalfOpen → Closed`). `#881`.
///
/// The worker listens on the drain channel fed by every per-target
/// circuit observer (see [`build_circuit_observer`]). On each recovery
/// trigger it:
///
/// 1. Seals the target's currently-active DLQ segment (so every
///    dead-lettered entry — even those in the in-flight writer — is
///    visible to the replay pass).
/// 2. Enumerates every sealed `.dlq.enc` segment for the target, in
///    oldest-first order.
/// 3. For each entry in each segment, reconstructs a
///    [`RoutableMessage`] and calls [`send_request`] with the entry's
///    preserved `delivery_id` as `X-Rustgate-Delivery-Id` — so receiver
///    dedup keyed on the id survives a partial replay.
/// 4. On success the entry is counted and moves on; on failure the
///    entry is re-persisted via [`DeadLetterQueue::dead_letter_with_id`]
///    with reason `"replay_failed"`, preserving the original id.
/// 5. After every entry in a segment is processed, the segment is
///    removed from disk. Even a segment whose entries all failed is
///    removed because the failures are safely re-captured in a fresh
///    segment — leaving the old one would cause an infinite replay
///    loop on every subsequent trigger.
///
/// The worker shuts down when either the channel closes (publisher
/// dropped) or the `shutdown` notify fires, whichever comes first. It
/// does NOT pace drain with back-pressure on the outbound HTTP —
/// `send_request` already carries timeout, retry, and circuit logic,
/// so a target that drops back into the open state mid-drain simply
/// starts re-DLQ'ing entries and the pass ends cleanly on the next
/// `allow_request()` check.
async fn drain_worker(
    mut rx: mpsc::Receiver<String>,
    targets: Arc<Vec<TargetState>>,
    dlq: Arc<DeadLetterQueue>,
    shutdown: Arc<tokio::sync::Notify>,
) {
    tracing::info!("HTTP DLQ drain worker started");
    loop {
        tokio::select! {
            biased;
            () = shutdown.notified() => {
                tracing::info!("HTTP DLQ drain worker shutting down");
                return;
            }
            next = rx.recv() => {
                let Some(target_name) = next else {
                    tracing::info!("HTTP DLQ drain channel closed, worker exiting");
                    return;
                };
                drain_target(&target_name, &targets, &dlq).await;
            }
        }
    }
}

/// Replay every sealed DLQ segment for `target_name`. Invoked by
/// [`drain_worker`] on each recovery trigger.
///
/// Seals the active writer first so the sweep sees every queued entry
/// (even those that never hit a rotation), then walks the sealed list
/// oldest-first. Each entry is either successfully re-delivered or
/// re-DLQ'd under reason `"replay_failed"`; the segment is removed
/// from disk after processing regardless of the per-entry outcome
/// (failed entries are preserved in the newly-written segment, so the
/// original file is redundant).
///
/// The per-entry loop short-circuits if the target's circuit re-opens
/// mid-drain — remaining entries of the current segment are re-DLQ'd
/// and the next sealed segment is skipped until the next recovery
/// trigger. This prevents a flapping endpoint from burning the entire
/// backlog in a single pass against an unhealthy target.
async fn drain_target(target_name: &str, targets: &[TargetState], dlq: &DeadLetterQueue) {
    let Some(target) = targets.iter().find(|t| t.name == target_name) else {
        tracing::warn!(
            target = %sanitize_for_log(target_name),
            "DLQ drain: unknown target, ignoring trigger"
        );
        return;
    };

    // Seal the active writer so its entries become visible to the
    // replay pass. Missing active writer is normal (target never
    // dead-lettered anything since the last drain).
    let _ = dlq.rotate_active_segment(target_name);

    let segments = dlq.list_sealed_segments(target_name);
    let segment_count = segments.len();

    rustgate_core::audit::http_dlq_drain_started(target_name, segment_count);
    tracing::info!(
        target = %sanitize_for_log(target_name),
        segments = segment_count,
        "HTTP DLQ drain pass started"
    );

    if segments.is_empty() {
        rustgate_core::audit::http_dlq_drain_completed(target_name, 0, 0);
        return;
    }

    let mut replayed: u64 = 0;
    let mut failed: u64 = 0;

    for segment in segments {
        let entries = match dlq.read_segment(&segment) {
            Ok(e) => e,
            Err(err) => {
                tracing::warn!(
                    target = %sanitize_for_log(target_name),
                    path = %segment.display(),
                    error = %err,
                    "DLQ drain: failed to decrypt segment, skipping"
                );
                // Leave the unreadable segment in place — the key ring
                // may have a compatible key added later, and silently
                // deleting forensic evidence is the worst option.
                continue;
            }
        };

        for entry in entries {
            match replay_entry(target, &entry).await {
                ReplayOutcome::Delivered => {
                    replayed += 1;
                    #[cfg(feature = "metrics")]
                    crate::metrics::dlq_replayed()
                        .with_label_values(&[target.name.as_str(), "success"])
                        .inc();
                }
                ReplayOutcome::Failed => {
                    failed += 1;
                    #[cfg(feature = "metrics")]
                    crate::metrics::dlq_replayed()
                        .with_label_values(&[target.name.as_str(), "failed"])
                        .inc();
                    requeue_failed_entry(dlq, target_name, &entry);
                }
                ReplayOutcome::Dropped => {
                    failed += 1;
                    #[cfg(feature = "metrics")]
                    crate::metrics::dlq_replayed()
                        .with_label_values(&[target.name.as_str(), "dropped"])
                        .inc();
                }
            }
        }

        // Remove the sealed segment regardless of per-entry outcome —
        // failed entries were re-persisted under a fresh segment, so
        // leaving the drained file on disk would cause an infinite
        // replay loop on every subsequent recovery trigger.
        let _ = dlq.remove_segment(&segment);
    }

    rustgate_core::audit::http_dlq_drain_completed(target_name, replayed, failed);
    tracing::info!(
        target = %sanitize_for_log(target_name),
        replayed,
        failed,
        "HTTP DLQ drain pass completed"
    );
}

/// Outcome of replaying a single DLQ entry.
enum ReplayOutcome {
    /// Entry was successfully re-delivered (2xx on first attempt).
    Delivered,
    /// Entry failed the replay (transport error or non-2xx) — caller
    /// must re-persist it under a fresh DLQ segment.
    Failed,
    /// Entry was malformed beyond recovery (payload base64 decode
    /// error, unsupported schema) and dropped without re-persistence.
    Dropped,
}

/// Decode and re-deliver a single DLQ entry to `target`.
///
/// Reconstructs a [`RoutableMessage`] with a synthetic [`rustgate_core::identity::Identity`]
/// (CN preserved, everything else defaulted — the original cert
/// material is not captured in the DLQ). Calls [`send_request`]
/// directly so the entry's preserved `delivery_id` is forwarded on the
/// wire exactly as-was (via `X-Rustgate-Delivery-Id`), enabling the
/// receiver to dedup a replayed delivery against the original.
///
/// This uses a SINGLE HTTP attempt per entry rather than the full
/// [`publish_with_retry`] loop: replay already runs inside the
/// circuit-recovery window, and burning the retry budget here would
/// re-trip the circuit on a mass replay against a flapping target.
/// A single-attempt failure re-DLQs the entry instead, delegating the
/// backoff to the next recovery cycle.
async fn replay_entry(
    target: &TargetState,
    entry: &crate::dlq_reader::OwnedDlqEntry,
) -> ReplayOutcome {
    // Respect the circuit breaker on replay, exactly as the live dispatch
    // path does. Drain is triggered on the circuit closing, but if the target
    // degrades again partway through a large drain the circuit re-opens —
    // without this gate the loop would keep firing one request per remaining
    // entry at the unhealthy target. Re-DLQ the entry (Failed) so the next
    // recovery cycle retries it, rather than hammering a flapping target.
    if !target.circuit.allow_request() {
        return ReplayOutcome::Failed;
    }

    // Decode the original payload bytes. A decode failure here is a
    // hard drop — the DLQ file is intact but the entry itself is
    // unusable, and no retry can fix it.
    let payload_bytes = match entry.decode_payload() {
        Ok(bytes) => bytes,
        Err(err) => {
            tracing::warn!(
                target = %target.name,
                source_cn = %sanitize_for_log(&entry.source_cn),
                error = %err,
                "DLQ replay: payload decode failed, dropping entry"
            );
            return ReplayOutcome::Dropped;
        }
    };
    let payload = bytes::Bytes::from(payload_bytes);

    // Reconstruct a synthetic RoutableMessage. Fields that are not
    // serialized in the DLQ entry (fingerprint, groups, tenant,
    // spiffe_id, attributes) default to empty — this mirrors what
    // offline replay tools do and is safe because the HTTP bridge
    // only reads `msg.source.cn`, `msg.destination`, `msg.payload`,
    // and `msg.metadata` during serialization.
    let msg = rustgate_core::message::RoutableMessage {
        source: rustgate_core::identity::Identity {
            // `Identity.cn` is `Arc<str>` (closes #784); convert from
            // the DLQ entry's owned `String` via `Arc::<str>::from`.
            cn: std::sync::Arc::<str>::from(entry.source_cn.as_str()),
            fingerprint: String::new(),
            groups: entry.source_groups.iter().cloned().collect(),
            tenant: None,
            spiffe_id: None,
            attributes: std::sync::Arc::new(Default::default()),
        },
        destination: rustgate_core::message::Destination::Broadcast,
        payload,
        metadata: rustgate_core::message::Metadata::new(
            std::time::SystemTime::now(),
            entry.source_protocol.clone(),
            parse_message_type(&entry.message_type),
        ),
    };

    // Rate-limit and oversize checks mirror the dispatch path so a
    // replay surge cannot burst past a target's steady-state cap.
    if let Some(ref limiter) = target.rate_limiter
        && !limiter.try_acquire()
    {
        tracing::debug!(
            target = %target.name,
            "DLQ replay: rate-limited, requeueing"
        );
        return ReplayOutcome::Failed;
    }

    if msg.payload.len() > target.max_payload_bytes {
        tracing::warn!(
            target = %target.name,
            payload_size = msg.payload.len(),
            "DLQ replay: payload exceeds size limit, dropping entry"
        );
        return ReplayOutcome::Dropped;
    }

    let (body, content_type) = match payload::serialize(&msg, target.format, &target.instance_id) {
        Ok(result) => result,
        Err(err) => {
            tracing::warn!(
                target = %target.name,
                error = %err,
                "DLQ replay: payload serialization failed, dropping entry"
            );
            return ReplayOutcome::Dropped;
        }
    };

    // Use the preserved delivery_id when available; fall back to a
    // fresh id for pre-migration entries that carry the
    // `#[serde(default)]` empty string.
    let delivery_id = if entry.delivery_id.is_empty() {
        generate_delivery_id()
    } else {
        entry.delivery_id.clone()
    };
    let content_digest = compute_content_digest(&body);

    match send_request(target, body, content_type, &delivery_id, &content_digest).await {
        Ok(_) => {
            tracing::debug!(
                target = %target.name,
                delivery_id = %delivery_id,
                "DLQ replay: entry re-delivered"
            );
            ReplayOutcome::Delivered
        }
        Err((status, err, _)) => {
            tracing::warn!(
                target = %target.name,
                delivery_id = %delivery_id,
                status = ?status,
                error = %err,
                "DLQ replay: entry delivery failed, will re-DLQ"
            );
            // Feed the circuit breaker so a mass replay against an
            // unhealthy target re-trips it quickly, preventing the
            // worker from burning through the backlog against an
            // endpoint that is still down. 4xx client errors do NOT
            // affect the circuit (consistent with the live dispatch
            // path's classification).
            let affects_circuit = status.is_none_or(|s| s == 429 || (500..600).contains(&s));
            if affects_circuit && target.circuit.record_failure() {
                rustgate_core::audit::http_circuit_tripped(&target.name);
                #[cfg(feature = "metrics")]
                crate::metrics::circuit_state()
                    .with_label_values(&[target.name.as_str()])
                    .set(1);
            }
            ReplayOutcome::Failed
        }
    }
}

/// Re-persist a replay-failed entry into a fresh DLQ segment,
/// preserving the original `delivery_id` so a future retry against a
/// receiver that actually accepted the first replay can dedup on id.
fn requeue_failed_entry(
    dlq: &DeadLetterQueue,
    target_name: &str,
    entry: &crate::dlq_reader::OwnedDlqEntry,
) {
    let payload_bytes = match entry.decode_payload() {
        Ok(b) => b,
        Err(_) => {
            // Already logged in replay_entry; don't double-log.
            return;
        }
    };
    let msg = rustgate_core::message::RoutableMessage {
        source: rustgate_core::identity::Identity {
            // `Identity.cn` is `Arc<str>` (closes #784); convert from
            // the DLQ entry's owned `String` via `Arc::<str>::from`.
            cn: std::sync::Arc::<str>::from(entry.source_cn.as_str()),
            fingerprint: String::new(),
            groups: entry.source_groups.iter().cloned().collect(),
            tenant: None,
            spiffe_id: None,
            attributes: std::sync::Arc::new(Default::default()),
        },
        destination: rustgate_core::message::Destination::Broadcast,
        payload: bytes::Bytes::from(payload_bytes),
        metadata: rustgate_core::message::Metadata::new(
            std::time::SystemTime::now(),
            entry.source_protocol.clone(),
            parse_message_type(&entry.message_type),
        ),
    };
    if entry.delivery_id.is_empty() {
        // Pre-migration entry without an id: re-persist with a fresh
        // id generated by the normal path so the receiver at least has
        // some idempotency token to work with on the next replay.
        dlq.dead_letter(target_name, &msg, "replay_failed");
    } else {
        dlq.dead_letter_with_id(target_name, &msg, "replay_failed", &entry.delivery_id);
    }
}

/// Round-trip parse `MessageType` from the stringified form stored in
/// the DLQ entry. Mirrors the cases in the `Display` impl exactly so a
/// value written by the producer round-trips through the replay path
/// without loss. Unknown strings fall back to `Other(raw)`.
fn parse_message_type(s: &str) -> rustgate_core::message::MessageType {
    use rustgate_core::message::MessageType;
    match s {
        "position" => MessageType::Position,
        "chat" => MessageType::Chat,
        "alert" => MessageType::Alert,
        "status" => MessageType::Status,
        "file" => MessageType::File,
        "mavlink" => MessageType::Mavlink,
        other => {
            // `Display` writes `Other(x)` as `other:x`; peel the
            // prefix back off if present so a round-trip produces the
            // same variant shape. Otherwise treat the whole string as
            // an opaque custom type.
            if let Some(tail) = other.strip_prefix("other:") {
                MessageType::Other(tail.to_string())
            } else {
                MessageType::Other(other.to_string())
            }
        }
    }
}

/// Drain every target's in-memory batcher on shutdown, issuing one last
/// HTTP request per non-empty batcher so buffered messages don't vanish
/// when the worker stops. Runs after the main dispatch channel has
/// drained and before the worker returns.
///
/// If a target's circuit is open at drain time the retry loop will
/// still fire its attempts — that is consistent with the single-message
/// shutdown path, which also runs its normal circuit / retry logic on
/// the trailing messages.
async fn drain_batchers(targets: &[TargetState]) {
    for target in targets {
        let Some(ref batcher_lock) = target.batcher else {
            continue;
        };
        let flush = {
            let mut batcher = batcher_lock.lock();
            batcher.drain()
        };
        let Some(flush) = flush else {
            continue;
        };
        #[cfg(feature = "metrics")]
        crate::metrics::batches_flushed()
            .with_label_values(&[target.name.as_str(), flush.reason.as_str()])
            .inc();
        let bodies = flush.bodies();
        let (batch_body, batch_ct) =
            payload::render_batch(&bodies, target.format, target.batch_format);
        tracing::info!(
            target = %target.name,
            batch_size = flush.len(),
            "flushing trailing batch on shutdown"
        );
        publish_with_retry(target, batch_body, batch_ct, Some(flush.len())).await;
    }
}

/// Successful send outcome, carrying an optional captured response body.
///
/// The body is only populated when the target has `capture-response-body`
/// enabled AND the response actually returned bytes. Empty responses
/// (204 No Content, 200 with zero Content-Length) produce `None` so the
/// caller can distinguish "capture disabled" from "no body" if needed.
type SendOk = Option<bytes::Bytes>;

/// Failure outcome tuple.
///
/// - `status`: the numeric HTTP status when the response reached us
///   (None indicates a transport-level failure).
/// - `error`: human-readable error string. Always includes the captured
///   error-response body prefix when available — SIEM collectors return
///   structured error details there and operators need them to diagnose
///   misconfigured webhook targets.
/// - `retry_after`: parsed `Retry-After` header on 429 responses, so the
///   retry loop can respect server-specified backoff.
type SendErr = (Option<u16>, String, Option<Duration>);

/// Send a single HTTP request to the target.
///
/// The `delivery_id` is stable across retry attempts for the same message,
/// enabling receiver-side deduplication. The `content_digest` is the
/// RFC 9530 `Content-Digest` header value (SHA-256).
///
/// On 2xx, returns `Ok(Some(body_bytes))` when the target is configured
/// to capture the success body (and the response is non-empty), or
/// `Ok(None)` otherwise.
///
/// On non-2xx, always captures the response body up to the per-target
/// limit and embeds a truncated snippet in the error string so the
/// failure-path log carries the server's structured error details.
async fn send_request(
    target: &TargetState,
    body: bytes::Bytes,
    content_type: &str,
    delivery_id: &str,
    content_digest: &str,
) -> Result<SendOk, SendErr> {
    let mut builder = target
        .client
        .request(target.method.clone(), &target.url)
        .header("Content-Type", content_type)
        .header("Content-Digest", content_digest)
        .header("X-Rustgate-Instance", &target.instance_id)
        .header("X-Rustgate-Delivery-Id", delivery_id);

    // Apply custom headers
    for (name, value) in &target.custom_headers {
        builder = builder.header(name.clone(), value);
    }

    // Apply authentication. HMAC binds the canonical request
    // (`<timestamp>.<METHOD>.<path>.<body>`) so a captured signature
    // cannot be replayed against a different endpoint or with a
    // different verb (#747).
    if let Some(auth) = &target.auth {
        builder = auth
            .apply(builder, target.method.as_str(), &target.url_path, &body)
            .map_err(|e| (None, e.to_string(), None))?;
    }

    // OpenTelemetry trace context propagation: inject W3C traceparent
    // header so the receiving service can correlate this request with
    // the originating trace. Noop when the otel feature is disabled or
    // no active trace context exists.
    #[cfg(feature = "otel")]
    {
        builder = inject_trace_context(builder);
    }

    // Bytes::clone() is a ref-count bump, not a memcpy — free across retries.
    builder = builder.body(body);

    let response = builder.send().await.map_err(|e| {
        let status = e.status().map(|s| s.as_u16());
        (status, e.to_string(), None)
    })?;

    let status = response.status().as_u16();
    if (200..300).contains(&status) {
        // Drain (or capture) the success response body so the connection
        // returns to the pool in a clean state (prevents keep-alive leaks).
        let captured = capture_response_body(
            response,
            target.max_response_body_bytes,
            target.capture_response_body,
        )
        .await;
        Ok(captured)
    } else {
        // Parse Retry-After header on 429 (rate-limited) responses so the
        // retry loop can respect the server's requested backoff interval.
        let retry_after = if status == 429 {
            response
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok())
                .map(Duration::from_secs)
        } else {
            None
        };
        // Error-path capture is unconditional — structured error bodies
        // from SIEM collectors are the highest-leverage signal for
        // diagnosing misconfigured targets, and the same bytes were
        // going to be drained either way to keep the pool clean.
        let captured = capture_response_body(response, target.max_response_body_bytes, true).await;
        let err = match captured.as_ref() {
            Some(body) if !body.is_empty() => {
                format!("HTTP {status}: {}", format_body_snippet(body))
            }
            _ => format!("HTTP {status}"),
        };
        Err((Some(status), err, retry_after))
    }
}

/// Maximum bytes of response body to ever hold in memory before returning
/// the connection to the pool. This is a hard ceiling on top of the
/// per-target limit — a target configured with
/// `max-response-body-bytes = 4096` caps its own captures at 4 KiB,
/// while a target with no limit still never exceeds this global cap.
const MAX_ERROR_RESPONSE_BYTES: usize = 1024 * 1024;

/// Drain (or capture + drain) a response body, returning the captured
/// prefix when the caller requested it.
///
/// HTTP/1.1 persistent connections require the full response body to be
/// consumed before the connection can be reused. If we skip this, the
/// connection is dropped and must be re-established (TCP + TLS handshake),
/// which adds latency on subsequent requests.
///
/// When `capture` is `true`, returns up to `max_bytes` of the body so the
/// caller can surface structured error details or acknowledgement IDs.
/// When `capture` is `false`, still drains but returns `None`.
///
/// The per-target `max_bytes` is clamped against [`MAX_ERROR_RESPONSE_BYTES`],
/// and the body is read by streaming chunks with a hard ceiling on total bytes
/// consumed — never trusting (or requiring) a Content-Length header. A hostile
/// server replying with a chunked, Content-Length-less, multi-gigabyte body
/// therefore cannot exhaust memory: reads stop at the ceiling and the
/// connection is dropped.
async fn capture_response_body(
    response: reqwest::Response,
    max_bytes: usize,
    capture: bool,
) -> Option<bytes::Bytes> {
    // Clamp against the crate-wide ceiling — a misconfigured per-target
    // cap cannot exceed this no matter what.
    let effective_cap = max_bytes.min(MAX_ERROR_RESPONSE_BYTES);

    // Content-Length guard: if the server *advertises* a body larger than
    // the global ceiling, don't read it. Drop the connection instead. This is
    // only a fast path — a chunked response carries no Content-Length, so the
    // streaming ceiling below is what actually bounds memory.
    if let Some(len) = response.content_length()
        && len > MAX_ERROR_RESPONSE_BYTES as u64
    {
        return None;
    }

    // Stream the body chunk-by-chunk rather than buffering it whole. We retain
    // at most `effective_cap` bytes for capture, but keep draining (and
    // discarding) up to the hard `MAX_ERROR_RESPONSE_BYTES` ceiling so a
    // well-behaved body returns the connection to the pool clean. Once that
    // ceiling is reached we stop reading and drop the connection — this is the
    // bound that a Content-Length-less (chunked) response would otherwise
    // evade, letting a hostile upstream buffer an unbounded body into memory.
    let mut response = response;
    let mut buf = bytes::BytesMut::new();
    let mut total_read: usize = 0;
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                if accumulate_capped(
                    &mut buf,
                    &mut total_read,
                    &chunk,
                    effective_cap,
                    MAX_ERROR_RESPONSE_BYTES,
                ) {
                    break;
                }
            }
            // Body fully consumed — connection can be reused.
            Ok(None) => break,
            // Partial read (timeout, reset): return what we have; the
            // connection will be dropped and a new one established.
            Err(_) => break,
        }
    }

    if !capture || buf.is_empty() {
        return None;
    }
    Some(buf.freeze())
}

/// Accumulate `chunk` into the capture buffer (retaining at most `cap` bytes)
/// and advance `total_read` by the full chunk length. Returns `true` once
/// `read_ceiling` total bytes have been consumed and reading must stop.
///
/// Pulled out as a pure function so the cap arithmetic — the bound that stops
/// an unbounded chunked response from being buffered — is unit-testable
/// without a streaming HTTP server.
fn accumulate_capped(
    buf: &mut bytes::BytesMut,
    total_read: &mut usize,
    chunk: &[u8],
    cap: usize,
    read_ceiling: usize,
) -> bool {
    *total_read = total_read.saturating_add(chunk.len());
    if buf.len() < cap {
        let take = (cap - buf.len()).min(chunk.len());
        buf.extend_from_slice(&chunk[..take]);
    }
    *total_read >= read_ceiling
}

/// Format a captured response body for inclusion in a structured log
/// field or error string.
///
/// The body is decoded as UTF-8 with replacement characters — SIEM
/// collectors and webhook targets overwhelmingly return JSON or
/// plain-text error details, and a replacement-character'ed prefix is
/// still readable in an operator dashboard. Control characters are
/// filtered via `sanitize_for_log` to prevent log-forging attacks where
/// a malicious server injects CR/LF into the error string.
fn format_body_snippet(body: &[u8]) -> String {
    let decoded = String::from_utf8_lossy(body);
    sanitize_for_log(&decoded)
}

/// Compute the RFC 9530 Content-Digest header value for body integrity.
///
/// Format: `sha-256=:<base64>:` (structured field sf-binary encoding).
/// Receivers can verify the digest to detect in-transit corruption or
/// proxy tampering, complementing TLS transport-level encryption.
fn compute_content_digest(body: &[u8]) -> String {
    let hash = Sha256::digest(body);
    let encoded = b64::encode(hash);
    format!("sha-256=:{encoded}:")
}

/// Generate a unique instance ID based on process ID and timestamp.
///
/// Used when no explicit `instance-id` is configured. The ID is
/// stable for the lifetime of the process.
fn generate_instance_id() -> String {
    format!("rustgate-{}", std::process::id())
}

/// Generate a unique per-request delivery ID for receiver-side idempotency.
///
/// Produces a 32-character hex string from 16 bytes of the OS CSPRNG, giving
/// 128 bits of collision resistance. Uses [`rand::rngs::OsRng`] (not the
/// non-cryptographic `fastrand`) so the ID is unpredictable — a receiver may
/// fence replays on this ID, so a guessable value would let an attacker forge
/// or suppress deliveries (#1520).
fn generate_delivery_id() -> String {
    use rand::RngCore;
    let mut buf = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}

/// Inject W3C Trace Context (`traceparent`) header into an outbound request.
///
/// Extracts the current OpenTelemetry span context from the tracing span
/// and formats it as a W3C traceparent header value. If no valid trace
/// context exists (OTel not configured or no active span), the request
/// is returned unmodified — graceful degradation.
#[cfg(feature = "otel")]
fn inject_trace_context(builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    use opentelemetry::trace::TraceContextExt;
    use tracing_opentelemetry::OpenTelemetrySpanExt;

    let cx = tracing::Span::current().context();
    let sc = cx.span().span_context().clone();

    if sc.is_valid() {
        // W3C Trace Context flags: bit 0 = sampled
        let flags: u8 = if sc.trace_flags().is_sampled() {
            0x01
        } else {
            0x00
        };
        let traceparent = format!("00-{}-{}-{flags:02x}", sc.trace_id(), sc.span_id(),);
        let builder = builder.header("traceparent", traceparent);

        // W3C tracestate: forward vendor-specific trace data from the
        // upstream context so downstream services retain full baggage.
        let ts = sc.trace_state();
        if !ts.header().is_empty() {
            builder.header("tracestate", ts.header())
        } else {
            builder
        }
    } else {
        builder
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn debug_shows_target_count() {
        let (tx, _rx) = mpsc::channel(1);
        let publisher = HttpPublisher {
            tx,
            targets: Arc::new(vec![]),
            shutdown: Arc::new(tokio::sync::Notify::new()),
            drain_shutdown: None,
            drain_tx: None,
            dlq: None,
            worker_handle: Arc::new(std::sync::Mutex::new(None)),
            gate: None,
        };
        let debug = format!("{publisher:?}");
        assert!(debug.contains("target_count"));
        assert!(debug.contains("0"));
    }

    #[test]
    fn generate_instance_id_not_empty() {
        let id = generate_instance_id();
        assert!(id.starts_with("rustgate-"));
        assert!(id.len() > "rustgate-".len());
    }

    #[test]
    fn delivery_id_is_32_char_hex() {
        let id = generate_delivery_id();
        assert_eq!(id.len(), 32);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn delivery_ids_are_unique() {
        let id1 = generate_delivery_id();
        let id2 = generate_delivery_id();
        assert_ne!(id1, id2);
    }

    #[test]
    fn content_digest_is_rfc9530_format() {
        let body = b"hello world";
        let digest = compute_content_digest(body);
        // RFC 9530 format: sha-256=:<base64>:
        assert!(digest.starts_with("sha-256=:"), "got: {digest}");
        assert!(digest.ends_with(':'), "got: {digest}");
        // Verify correct SHA-256 of "hello world"
        let expected_hash = sha2::Sha256::digest(body);
        let expected_b64 = b64::encode(expected_hash);
        assert_eq!(digest, format!("sha-256=:{expected_b64}:"));
    }

    #[test]
    fn content_digest_deterministic() {
        let body = b"test payload";
        let d1 = compute_content_digest(body);
        let d2 = compute_content_digest(body);
        assert_eq!(d1, d2);
    }

    #[test]
    fn content_digest_differs_for_different_bodies() {
        let d1 = compute_content_digest(b"payload A");
        let d2 = compute_content_digest(b"payload B");
        assert_ne!(d1, d2);
    }

    #[test]
    fn echo_prevention_blocks_http_case_insensitive() {
        let (tx, _rx) = mpsc::channel(1);
        let publisher = HttpPublisher {
            tx,
            targets: Arc::new(vec![]),
            shutdown: Arc::new(tokio::sync::Notify::new()),
            drain_shutdown: None,
            drain_tx: None,
            dlq: None,
            worker_handle: Arc::new(std::sync::Mutex::new(None)),
            gate: None,
        };
        // These should all be silently dropped (echo prevention)
        for protocol in &["http", "HTTP", "Http", "hTTp"] {
            let msg = rustgate_core::message::RoutableMessage {
                source: rustgate_core::identity::Identity {
                    cn: "test".into(),
                    fingerprint: Default::default(),
                    groups: Default::default(),
                    tenant: None,
                    spiffe_id: None,
                    attributes: Arc::new(Default::default()),
                },
                destination: rustgate_core::message::Destination::Broadcast,
                payload: bytes::Bytes::from_static(b"test"),
                metadata: rustgate_core::message::Metadata::new(
                    std::time::SystemTime::now(),
                    protocol.to_string(),
                    rustgate_core::message::MessageType::Position,
                ),
            };
            publisher.publish(&msg);
        }
        // If echo prevention failed, try_recv would return messages
        // Since we dropped _rx, the send would fail — but publish()
        // should return before even trying to send (echo prevention)
    }

    /// Build a minimal `RoutableMessage` for admission tests.
    fn admission_test_msg(cn: &str) -> rustgate_core::message::RoutableMessage {
        rustgate_core::message::RoutableMessage {
            source: rustgate_core::identity::Identity {
                cn: cn.into(),
                fingerprint: Default::default(),
                groups: Default::default(),
                tenant: None,
                spiffe_id: None,
                attributes: Arc::new(Default::default()),
            },
            destination: rustgate_core::message::Destination::Broadcast,
            payload: bytes::Bytes::from_static(b"admission-shed payload"),
            metadata: rustgate_core::message::Metadata::new(
                std::time::SystemTime::now(),
                "tcp".to_string(),
                rustgate_core::message::MessageType::Position,
            ),
        }
    }

    /// Synthetic key ring for DLQ encryption in tests.
    fn admission_test_key_ring() -> rustgate_archive::encrypted::KeyRing {
        let key_json = r#"{
            "active_key_id": "test-key",
            "keys": {
                "test-key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            }
        }"#;
        rustgate_archive::encrypted::KeyRing::from_bytes(key_json.as_bytes()).unwrap()
    }

    #[test]
    fn admission_full_persists_to_dlq() {
        // Regression for #813: admission-queue drops previously bypassed
        // the DLQ, silently losing messages that never reached dispatch.
        let dir = tempfile::tempdir().unwrap();
        let dlq = Arc::new(DeadLetterQueue::new(
            dir.path().to_path_buf(),
            admission_test_key_ring(),
            None,
            None,
        ));

        // Capacity-1 channel: first send fills it, second send returns Full.
        let (tx, rx) = mpsc::channel::<QueuedMessage>(1);

        let publisher = HttpPublisher {
            tx: tx.clone(),
            targets: Arc::new(vec![]),
            shutdown: Arc::new(tokio::sync::Notify::new()),
            drain_shutdown: None,
            drain_tx: None,
            dlq: Some(dlq),
            worker_handle: Arc::new(std::sync::Mutex::new(None)),
            gate: None,
        };

        // Saturate the channel so the next `publish` hits `TrySendError::Full`.
        tx.try_send(QueuedMessage {
            msg: Arc::new(admission_test_msg("filler")),
            permit: None,
        })
        .unwrap();

        let msg = admission_test_msg("alice");
        publisher.publish(&msg);

        // Keep the receiver alive to ensure we exercised the Full path, not Closed.
        drop(rx);

        // A DLQ file prefixed with the synthetic target name must exist.
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert_eq!(entries.len(), 1, "expected exactly one DLQ file");
        let name = entries[0].file_name().to_string_lossy().into_owned();
        assert!(
            name.starts_with(&format!("{ADMISSION_DLQ_TARGET}_")),
            "expected admission-shed DLQ file, got: {name}"
        );
        assert!(name.ends_with(".dlq.enc"), "got: {name}");
    }

    #[test]
    fn admission_full_without_dlq_is_tolerated() {
        // Admission-full must remain non-fatal when no DLQ is configured.
        let (tx, rx) = mpsc::channel::<QueuedMessage>(1);

        let publisher = HttpPublisher {
            tx: tx.clone(),
            targets: Arc::new(vec![]),
            shutdown: Arc::new(tokio::sync::Notify::new()),
            drain_shutdown: None,
            drain_tx: None,
            dlq: None,
            worker_handle: Arc::new(std::sync::Mutex::new(None)),
            gate: None,
        };

        tx.try_send(QueuedMessage {
            msg: Arc::new(admission_test_msg("filler")),
            permit: None,
        })
        .unwrap();
        // Must not panic, must not block.
        publisher.publish(&admission_test_msg("alice"));
        drop(rx);
    }

    #[tokio::test]
    async fn backpressure_over_high_water_drops_to_dlq() {
        // When the shared gate is over the high-water mark, `publish`
        // must shed new messages instead of hoarding them in the channel.
        let dir = tempfile::tempdir().unwrap();
        let dlq = Arc::new(DeadLetterQueue::new(
            dir.path().to_path_buf(),
            admission_test_key_ring(),
            None,
            None,
        ));

        // Gate with a tiny 64-byte cap and zero resume dwell so the
        // first `acquire` puts us over the high-water mark and keeps us
        // there while the permit is alive.
        let mut gate = BackpressureGate::with_limits(64, 32);
        gate.with_resume_dwell(std::time::Duration::ZERO).unwrap();
        // Saturate the gate so `is_admitting()` is false.
        let _saturate = gate.acquire(128);

        let (tx, rx) = mpsc::channel::<QueuedMessage>(16);
        let publisher = HttpPublisher {
            tx,
            targets: Arc::new(vec![]),
            shutdown: Arc::new(tokio::sync::Notify::new()),
            drain_shutdown: None,
            drain_tx: None,
            dlq: Some(dlq),
            worker_handle: Arc::new(std::sync::Mutex::new(None)),
            gate: Some(Arc::clone(&gate)),
        };

        publisher.publish(&admission_test_msg("alice"));

        // Nothing queued — the message was shed before try_send.
        drop(rx);

        // DLQ has a backpressure-labelled entry.
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert_eq!(entries.len(), 1, "expected exactly one DLQ file");
    }

    #[tokio::test]
    async fn backpressure_permit_releases_on_worker_drain() {
        // End-to-end sanity: a message entering the publisher with a
        // configured gate acquires a permit, and dropping the envelope
        // after dispatch releases the reservation.
        let gate = BackpressureGate::new(1024);
        assert_eq!(gate.current(), 0);

        let (tx, mut rx) = mpsc::channel::<QueuedMessage>(4);
        let publisher = HttpPublisher {
            tx,
            targets: Arc::new(vec![]),
            shutdown: Arc::new(tokio::sync::Notify::new()),
            drain_shutdown: None,
            drain_tx: None,
            dlq: None,
            worker_handle: Arc::new(std::sync::Mutex::new(None)),
            gate: Some(Arc::clone(&gate)),
        };

        let msg = admission_test_msg("alice");
        let payload_len = msg.payload.len();
        publisher.publish(&msg);

        // While the envelope sits in the channel, the permit holds the
        // reservation.
        assert_eq!(gate.current(), payload_len);

        // Simulate the dispatch worker consuming and dropping the envelope.
        let queued = rx.recv().await.expect("envelope");
        drop(queued);
        assert_eq!(gate.current(), 0);
    }

    #[test]
    fn all_targets_disabled_returns_error() {
        let config = HttpConfig {
            instance_id: None,
            targets: vec![crate::config::TargetConfig {
                name: "disabled".to_string(),
                url: "https://example.com".to_string(),
                method: None,
                auth: None,
                tls: None,
                timeout_secs: None,
                format: None,
                filter: None,
                retry: None,
                enabled: Some(false),
                headers: None,
                max_payload_bytes: None,
                rate_limit_per_sec: None,
                capture_response_body: None,
                max_response_body_bytes: None,
                batch_enabled: None,
                batch_max_messages: None,
                batch_max_bytes: None,
                batch_format: None,
            }],
            dlq_dir: None,
            dlq_key_file: None,
            dlq_max_bytes: None,
            dlq_max_target_bytes: None,
            allow_private_urls: false,
        };
        let err = HttpPublisher::new(config).unwrap_err();
        assert!(err.to_string().contains("no enabled"), "got: {err}");
    }

    // ── Circuit breaker observer wiring (issue #881) ───────────────

    // Only the metrics-gated tests below reference these state constants;
    // gating the import keeps the `post-quantum` build (no `metrics`) clean.
    #[cfg(feature = "metrics")]
    use rustgate_resilience::circuit::{
        STATE_CLOSED as CB_CLOSED, STATE_HALF_OPEN as CB_HALF_OPEN, STATE_OPEN as CB_OPEN,
    };

    /// Directly invoking the observer with the load-bearing transition
    /// `(Open, HalfOpen)` must not panic and must set the Prometheus
    /// circuit_state gauge to 2 for the target. This is the contract
    /// downstream DLQ auto-drain wiring relies on — the observer is
    /// responsible for visibility; actual replay is a follow-up.
    #[cfg(feature = "metrics")]
    #[test]
    fn circuit_observer_sets_gauge_to_halfopen_on_open_to_halfopen() {
        let target = "test-observer-halfopen-transition";
        // `None` — this test exercises only the gauge-update side
        // effect; drain triggers are validated by a separate test.
        let obs = build_circuit_observer(target, None);

        obs(CB_OPEN, CB_HALF_OPEN);

        let gauge = crate::metrics::circuit_state()
            .get_metric_with_label_values(&[target])
            .expect("label ok");
        assert_eq!(gauge.get(), 2);
    }

    /// Transitions other than `(Open, HalfOpen)` must not touch the
    /// metric. `Closed → Open` and `HalfOpen → Closed` have their own
    /// emitters in `publish_with_retry`; firing from the observer too
    /// would double-log the audit event and double-set the gauge.
    #[cfg(feature = "metrics")]
    #[test]
    fn circuit_observer_ignores_unrelated_transitions() {
        // Use a unique target so prior tests can't contaminate the
        // assertion (Prometheus label values are a shared process-wide
        // namespace across tests in the same binary).
        let target = "test-observer-no-op-transitions";
        // `None` — this test asserts the observer is a no-op for
        // non-`(Open, HalfOpen)` transitions; it has nothing to drain.
        let obs = build_circuit_observer(target, None);

        // None of these are the load-bearing Open → HalfOpen transition.
        obs(CB_CLOSED, CB_OPEN);
        obs(CB_HALF_OPEN, CB_OPEN);
        obs(CB_HALF_OPEN, CB_CLOSED);
        // Self-transitions are nonsensical but must not panic either.
        obs(CB_CLOSED, CB_CLOSED);

        let gauge = crate::metrics::circuit_state()
            .get_metric_with_label_values(&[target])
            .expect("label ok");
        // If the observer fired on any of the above, the gauge would
        // have been set to 2. Default value is 0 for an unobserved
        // label tuple.
        assert_eq!(gauge.get(), 0);
    }

    /// End-to-end: a real `CircuitBreaker` with the HTTP observer
    /// attached transitions through Closed → Open → HalfOpen under the
    /// normal API (trip via `record_failure`, recover via cooldown +
    /// `allow_request`), and the gauge reaches 2 at the HalfOpen
    /// probe window. Pins the full wiring — if a future refactor
    /// drops `.with_on_state_change()` from `build_target`, this test
    /// fails instead of the regression slipping silently into main.
    #[cfg(feature = "metrics")]
    #[tokio::test]
    async fn circuit_observer_fires_via_real_breaker_transition() {
        let target = "test-observer-end-to-end";
        // `None` — this test validates the metrics side of the observer
        // via a real breaker; the drain side has its own dedicated test.
        let breaker =
            rustgate_resilience::circuit::CircuitBreaker::new(1, Duration::from_millis(10), 3, 1)
                .with_on_state_change(build_circuit_observer(target, None));

        // Closed → Open (record_failure returns bool; discarded deliberately).
        let _ = breaker.record_failure();
        // Cooldown elapses → next allow_request transitions to HalfOpen.
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(breaker.allow_request());

        let gauge = crate::metrics::circuit_state()
            .get_metric_with_label_values(&[target])
            .expect("label ok");
        assert_eq!(gauge.get(), 2, "observer did not set gauge to halfopen");
    }

    /// The observer is fire-and-forget: cloning the closure (which
    /// happens every time `with_on_state_change` is called) and firing
    /// it concurrently from multiple threads must be safe. Pins the
    /// `Arc<dyn Fn + Send + Sync>` contract in the callback type
    /// alias so a future refactor that accidentally drops `Sync`
    /// breaks here rather than at some distant call site.
    #[cfg(feature = "metrics")]
    #[test]
    fn circuit_observer_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>(_: &T) {}
        // `None` — only the auto-trait bounds are under test here.
        let obs = build_circuit_observer("send-sync-check", None);
        assert_send_sync(&obs);
    }

    // ── DLQ auto-drain helpers (issue #881) ───────────────────────────

    /// `parse_message_type` is the inverse of `MessageType::Display`.
    /// DLQ entries store the message type as a string (written by the
    /// `Display` impl in `rustgate-core`) and the drain path must
    /// reconstruct the original variant exactly so the replayed message
    /// carries the same classification as the original. A silent round-trip
    /// mismatch (e.g. `Position` → `Other("position")`) would corrupt
    /// downstream routing on every replay.
    #[test]
    fn parse_message_type_round_trips_every_named_variant() {
        use rustgate_core::message::MessageType;
        let cases = [
            MessageType::Position,
            MessageType::Chat,
            MessageType::Alert,
            MessageType::Status,
            MessageType::File,
            MessageType::Mavlink,
        ];
        for mt in cases {
            let s = mt.to_string();
            let parsed = parse_message_type(&s);
            assert_eq!(parsed, mt, "round-trip failed for {s}");
        }
    }

    /// `Other(x)` writes as `other:x` via `Display`, so the parser must
    /// strip the `other:` prefix and reconstruct `Other(x)` — not leak
    /// the prefix into the payload. Covers both non-empty tails and the
    /// empty-tail edge case (`other:` → `Other("")`).
    #[test]
    fn parse_message_type_preserves_other_variant_tail() {
        use rustgate_core::message::MessageType;
        assert_eq!(
            parse_message_type("other:custom"),
            MessageType::Other("custom".to_string())
        );
        assert_eq!(
            parse_message_type("other:"),
            MessageType::Other(String::new())
        );
        // A tail with its own colons must not be stripped a second time
        // — the prefix peel is single-pass.
        assert_eq!(
            parse_message_type("other:ns:subtype"),
            MessageType::Other("ns:subtype".to_string())
        );
    }

    /// Strings that do not match any named variant and do not carry the
    /// `other:` prefix fall through to `Other(raw)` verbatim. This is
    /// the graceful-degradation path for a future variant that a newer
    /// producer might write before an older consumer's parser is
    /// updated — replay preserves the raw tag rather than crashing or
    /// silently dropping the entry.
    #[test]
    fn parse_message_type_falls_back_to_other_for_unknown_strings() {
        use rustgate_core::message::MessageType;
        assert_eq!(
            parse_message_type("unknown"),
            MessageType::Other("unknown".to_string())
        );
        assert_eq!(parse_message_type(""), MessageType::Other(String::new()));
    }

    // ── Response body helpers (issue #906) ────────────────────────────

    /// Valid UTF-8 is returned unchanged.
    #[test]
    fn format_body_snippet_preserves_utf8_json() {
        let body = br#"{"ackId":"abc-123"}"#;
        assert_eq!(format_body_snippet(body), r#"{"ackId":"abc-123"}"#);
    }

    /// Invalid UTF-8 gets replacement characters, never panics. The
    /// snippet is always safe to log — critical defence against
    /// malicious servers returning garbled bytes.
    #[test]
    fn format_body_snippet_replaces_invalid_utf8() {
        // 0xff is invalid as a UTF-8 lead byte, 0xfe is a continuation
        // without a lead — both should become U+FFFD.
        let body = b"ok\xff\xfegarble";
        let out = format_body_snippet(body);
        assert!(out.starts_with("ok"));
        assert!(out.ends_with("garble"));
        assert!(out.contains('\u{FFFD}'), "got: {out}");
    }

    /// Log-forging defence: CR/LF in a response body cannot inject a
    /// fake log line via the `body = ...` field. `sanitize_for_log`
    /// replaces control characters with U+FFFD so the injected prefix
    /// never reaches operators' grep results intact.
    #[test]
    fn format_body_snippet_sanitises_log_forging_attempt() {
        let body = b"real\r\n[audit] fake_event=success";
        let out = format_body_snippet(body);
        assert!(!out.contains('\r'), "CR leaked: {out:?}");
        assert!(!out.contains('\n'), "LF leaked: {out:?}");
    }

    /// Empty body renders as an empty string — callers check
    /// `body.is_empty()` before emitting so the debug line stays
    /// concise.
    #[test]
    fn format_body_snippet_empty() {
        assert_eq!(format_body_snippet(b""), "");
    }

    /// Simulates a successful publish where the server returned a JSON
    /// ack body and the target has `capture-response-body = true`.
    /// Asserts the full body comes back (under the cap) and is
    /// zero-copy — the returned `Bytes` shares the reqwest allocation.
    #[tokio::test]
    async fn capture_response_body_success_returns_full_body() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let ack = r#"{"ackId":"splunk-abc-123"}"#;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string(ack))
            .mount(&server)
            .await;

        let response = reqwest::get(server.uri()).await.unwrap();
        let captured = capture_response_body(response, 4 * 1024, true).await;
        assert_eq!(captured.as_deref(), Some(ack.as_bytes()));
    }

    /// When capture is disabled, the helper still drains the body
    /// (connection-pool hygiene) but returns `None`. This is the
    /// contract the success path relies on: `None` → emit the
    /// no-body debug line; `Some` → emit the with-body debug line.
    #[tokio::test]
    async fn capture_response_body_disabled_returns_none_but_drains() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("ignored"))
            .mount(&server)
            .await;

        let response = reqwest::get(server.uri()).await.unwrap();
        let captured = capture_response_body(response, 4 * 1024, false).await;
        assert!(captured.is_none());
    }

    /// Empty bodies produce `None` even when capture is enabled, so the
    /// caller doesn't emit an empty `body = ""` field.
    #[tokio::test]
    async fn capture_response_body_empty_returns_none() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;

        let response = reqwest::get(server.uri()).await.unwrap();
        let captured = capture_response_body(response, 4 * 1024, true).await;
        assert!(captured.is_none());
    }

    /// Oversized bodies clamp at the per-target cap. Protects operators
    /// from a target returning a malicious multi-MB error blob that
    /// would otherwise flood their structured logs.
    #[tokio::test]
    async fn capture_response_body_clamps_at_per_target_cap() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let body = "A".repeat(2048);
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;

        let response = reqwest::get(server.uri()).await.unwrap();
        // 512-byte cap — well below the server's 2 KiB payload.
        let captured = capture_response_body(response, 512, true).await;
        assert_eq!(captured.as_ref().map(|b| b.len()), Some(512));
    }

    /// Global ceiling guard: when the server advertises a
    /// Content-Length larger than MAX_ERROR_RESPONSE_BYTES (1 MiB),
    /// the helper returns `None` without reading the body. Pins the
    /// defence against a runaway error-body pull eating megabytes of
    /// heap before the response is ever logged.
    #[tokio::test]
    async fn capture_response_body_content_length_exceeds_ceiling_short_circuits() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        // Just over 1 MiB. ResponseTemplate::set_body_bytes sets
        // Content-Length for us.
        let oversized = vec![b'B'; MAX_ERROR_RESPONSE_BYTES + 1];
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(oversized))
            .mount(&server)
            .await;

        let response = reqwest::get(server.uri()).await.unwrap();
        // Per-target cap is 1 MiB — without the Content-Length guard
        // the helper would happily allocate 1 MiB+1 into a Bytes.
        let captured = capture_response_body(response, MAX_ERROR_RESPONSE_BYTES, true).await;
        assert!(
            captured.is_none(),
            "oversized Content-Length must short-circuit before body read"
        );
    }

    /// `accumulate_capped` retains at most `cap` bytes but counts the full
    /// chunk toward `total_read` — so a single oversized chunk is truncated in
    /// the capture buffer without losing track of how much was actually read.
    #[test]
    fn accumulate_capped_retains_only_cap_bytes() {
        let mut buf = bytes::BytesMut::new();
        let mut total = 0usize;
        let stop = accumulate_capped(&mut buf, &mut total, &vec![0xAB; 4096], 512, 1024 * 1024);
        assert!(!stop, "4 KiB read is far under the 1 MiB ceiling");
        assert_eq!(buf.len(), 512, "capture buffer retains at most the cap");
        assert_eq!(
            total, 4096,
            "total_read counts the full chunk, not the retained slice"
        );
    }

    /// The read ceiling — not the capture cap — is what stops an unbounded
    /// (chunked, no Content-Length) drain. Consuming past it must signal stop.
    #[test]
    fn accumulate_capped_stops_at_read_ceiling() {
        let mut buf = bytes::BytesMut::new();
        let mut total = 0usize;
        let stop = accumulate_capped(&mut buf, &mut total, &vec![0u8; 2048], 256, 1024);
        assert!(
            stop,
            "consuming past the read ceiling must stop the drain loop"
        );
        assert_eq!(buf.len(), 256, "capture is still bounded by the cap");
        assert_eq!(total, 2048);
    }

    /// Across multiple chunks the cap fills only once and `total_read` spans
    /// every chunk seen.
    #[test]
    fn accumulate_capped_accumulates_across_chunks() {
        let mut buf = bytes::BytesMut::new();
        let mut total = 0usize;
        assert!(!accumulate_capped(
            &mut buf,
            &mut total,
            &[1, 2, 3],
            4,
            1024
        ));
        assert!(!accumulate_capped(
            &mut buf,
            &mut total,
            &[4, 5, 6],
            4,
            1024
        ));
        assert_eq!(
            &buf[..],
            &[1, 2, 3, 4],
            "second chunk fills only the remaining cap"
        );
        assert_eq!(total, 6, "total_read spans both chunks");
    }

    // ── trigger_drain (manual DLQ replay, issue #881 PR C) ─────────

    /// Build a `TargetConfig` whose URL is reachable for `reqwest::Client`
    /// construction but never actually contacted — `trigger_drain` is a
    /// pure in-process check, the URL only matters at `publish` time.
    fn trigger_drain_test_target(name: &str) -> crate::config::TargetConfig {
        crate::config::TargetConfig {
            name: name.to_string(),
            url: "http://127.0.0.1:1/never".to_string(),
            method: None,
            auth: None,
            tls: None,
            timeout_secs: Some(1),
            format: None,
            filter: None,
            retry: None,
            enabled: None,
            headers: None,
            max_payload_bytes: None,
            rate_limit_per_sec: None,
            capture_response_body: None,
            max_response_body_bytes: None,
            batch_enabled: None,
            batch_max_messages: None,
            batch_max_bytes: None,
            batch_format: None,
        }
    }

    /// A replay must respect the circuit breaker: if the target's circuit is
    /// open (it re-tripped mid-drain), `replay_entry` returns `Failed`
    /// without issuing a request, so the entry is re-DLQ'd for the next
    /// recovery cycle rather than hammering an unhealthy target (#1626).
    #[tokio::test]
    async fn replay_entry_skips_when_circuit_open() {
        let tc = trigger_drain_test_target("siem");
        let resolver = Arc::new(SsrfSafeResolver::new(true));
        let target = build_target(&tc, "instance-1", resolver, None).expect("build target");

        // Drive the circuit open the way a flapping target would. The guard
        // bounds the loop so a config change can never hang the test.
        let mut guard = 0;
        while target.circuit.allow_request() && guard < 10_000 {
            let _ = target.circuit.record_failure();
            guard += 1;
        }
        assert!(
            !target.circuit.allow_request(),
            "circuit must be open before the replay"
        );

        let entry = crate::dlq_reader::OwnedDlqEntry {
            timestamp: "2026-06-26T00:00:00Z".to_string(),
            target: "siem".to_string(),
            reason: "circuit_open".to_string(),
            delivery_id: "0000000000000000ffffffffffffffff".to_string(),
            source_cn: "alice".to_string(),
            source_groups: vec!["alpha".to_string()],
            destination: "broadcast".to_string(),
            message_type: "position".to_string(),
            source_protocol: "tcp".to_string(),
            payload_b64: rustgate_core::b64::encode(b"hello"),
            payload_size: 5,
        };

        let outcome = replay_entry(&target, &entry).await;
        assert!(
            matches!(outcome, ReplayOutcome::Failed),
            "replay against an open circuit must Fail (re-DLQ), not send"
        );
    }

    /// Write a 64-zero-hex KeyRing JSON fixture and return its path,
    /// keyed by `tmp` so the file is unlinked when the dir drops.
    fn trigger_drain_test_keyring(tmp: &tempfile::TempDir) -> std::path::PathBuf {
        let key_json = r#"{
            "active_key_id": "k",
            "keys": { "k": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }
        }"#;
        let p = tmp.path().join("keys.json");
        std::fs::write(&p, key_json).unwrap();
        p
    }

    /// Build a publisher with one named target and the given DLQ
    /// configuration. The returned `TempDir` must outlive the publisher
    /// — drop order: publisher first, then `tmp` so the key file
    /// survives any background reader for `Drop` paths.
    fn trigger_drain_test_publisher(
        target_name: &str,
        with_dlq: bool,
    ) -> (HttpPublisher, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let dlq_dir = tmp.path().join("dlq");
        let key_path = trigger_drain_test_keyring(&tmp);

        let config = HttpConfig {
            instance_id: Some("trigger-drain-test".to_string()),
            targets: vec![trigger_drain_test_target(target_name)],
            dlq_dir: if with_dlq {
                Some(dlq_dir.to_string_lossy().into_owned())
            } else {
                None
            },
            dlq_key_file: if with_dlq {
                Some(key_path.to_string_lossy().into_owned())
            } else {
                None
            },
            dlq_max_bytes: None,
            dlq_max_target_bytes: None,
            allow_private_urls: true, // 127.0.0.1 URL above
        };
        (HttpPublisher::new(config).unwrap(), tmp)
    }

    #[tokio::test]
    async fn trigger_drain_returns_dlq_not_configured_when_no_dlq() {
        // Without a DLQ the drain worker is never spawned and the
        // top-level `drain_tx` is `None` — no point queueing a trigger
        // that nothing will read.
        let (publisher, _tmp) = trigger_drain_test_publisher("anything", false);
        assert_eq!(
            publisher.trigger_drain("anything"),
            Err(TriggerDrainError::DlqNotConfigured)
        );
        publisher.shutdown().await;
    }

    #[tokio::test]
    async fn trigger_drain_returns_unknown_target_for_unconfigured_name() {
        // The publisher is built with one target named `webhook-prod`;
        // a request for `does-not-exist` must surface a precise
        // `UnknownTarget` so the management API maps it to `404`
        // instead of silently queueing a trigger the drain worker
        // would skip.
        let (publisher, _tmp) = trigger_drain_test_publisher("webhook-prod", true);
        assert_eq!(
            publisher.trigger_drain("does-not-exist"),
            Err(TriggerDrainError::UnknownTarget)
        );
        publisher.shutdown().await;
    }

    #[tokio::test]
    async fn trigger_drain_succeeds_for_configured_target() {
        // Happy path: the target name matches and the channel has
        // capacity. The trigger is fire-and-forget — `Ok(())` means
        // "the worker has been notified", not "the drain has run".
        let (publisher, _tmp) = trigger_drain_test_publisher("webhook-prod", true);
        assert_eq!(publisher.trigger_drain("webhook-prod"), Ok(()));
        publisher.shutdown().await;
    }

    #[tokio::test]
    async fn trigger_drain_returns_unknown_target_before_check_channel_state() {
        // The order of checks inside `trigger_drain` is load-bearing:
        // an unknown-target request must NOT consume a slot in the
        // bounded channel, otherwise an attacker hammering an invalid
        // name could starve legitimate triggers. Pin the order by
        // saturating the channel first and then asserting an
        // unknown-target call still returns `UnknownTarget` rather
        // than `ChannelFull`.
        let (publisher, _tmp) = trigger_drain_test_publisher("webhook-prod", true);
        // Saturate: the channel buffer is `DRAIN_CHANNEL_BUFFER` (32).
        // Fire that many valid-target triggers — the drain worker may
        // drain some, but at least one should still be in the
        // channel by the time we check the unknown-target case.
        for _ in 0..DRAIN_CHANNEL_BUFFER * 2 {
            let _ = publisher.trigger_drain("webhook-prod");
        }
        // Even with the channel under pressure, an unknown target
        // returns `UnknownTarget` because that check fires before the
        // `try_send`.
        assert_eq!(
            publisher.trigger_drain("does-not-exist"),
            Err(TriggerDrainError::UnknownTarget)
        );
        publisher.shutdown().await;
    }

    #[test]
    fn trigger_drain_error_display_strings_are_stable() {
        // Pin the rendered Display strings — these surface in the
        // management-API JSON `error` field, in audit logs, and in
        // operator runbooks. Any change is a wire-format break.
        assert_eq!(
            TriggerDrainError::DlqNotConfigured.to_string(),
            "DLQ not configured: cannot trigger drain"
        );
        assert_eq!(
            TriggerDrainError::UnknownTarget.to_string(),
            "unknown HTTP target"
        );
        assert_eq!(
            TriggerDrainError::ChannelFull.to_string(),
            "drain trigger channel is full; another drain is in flight"
        );
        assert_eq!(
            TriggerDrainError::ChannelClosed.to_string(),
            "drain trigger channel is closed; publisher is shutting down"
        );
    }

    #[tokio::test]
    async fn target_names_returns_configured_targets_in_order() {
        // The management API uses `target_names()` to enumerate which
        // `target` path segments are routable; pin the ordering so
        // operators reading back the list see config order.
        let tmp = tempfile::tempdir().unwrap();
        let key_path = trigger_drain_test_keyring(&tmp);
        let dlq_dir = tmp.path().join("dlq");
        let config = HttpConfig {
            instance_id: None,
            targets: vec![
                trigger_drain_test_target("alpha"),
                trigger_drain_test_target("bravo"),
                trigger_drain_test_target("charlie"),
            ],
            dlq_dir: Some(dlq_dir.to_string_lossy().into_owned()),
            dlq_key_file: Some(key_path.to_string_lossy().into_owned()),
            dlq_max_bytes: None,
            dlq_max_target_bytes: None,
            allow_private_urls: true,
        };
        let publisher = HttpPublisher::new(config).unwrap();
        assert_eq!(
            publisher.target_names(),
            vec![
                "alpha".to_string(),
                "bravo".to_string(),
                "charlie".to_string()
            ]
        );
        publisher.shutdown().await;
    }
}
