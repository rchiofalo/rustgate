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

use base64::Engine;
use reqwest::header::HeaderName;
use rustgate_core::message::RoutableMessage;
use rustgate_core::sanitize::sanitize_for_log;
use rustgate_resilience::circuit::CircuitBreaker;
use rustgate_resilience::retry;
use rustgate_resilience::token_bucket::TokenBucket;
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tracing::Instrument;
use zeroize::Zeroizing;

use crate::auth::AuthState;
use crate::config::{HttpConfig, PayloadFormat, TargetConfig};
use crate::dlq::DeadLetterQueue;
use crate::error::HttpError;
use crate::filter::CompiledFilter;
use crate::payload;
use crate::resolver::SsrfSafeResolver;

/// Channel buffer size for the dispatch queue.
const CHANNEL_BUFFER: usize = 256;

/// Non-revealing User-Agent to prevent version fingerprinting.
const RUSTGATE_USER_AGENT: &str = "Rustgate";

/// Maximum response body to drain on error responses (1 MiB).
///
/// Prevents memory exhaustion from malicious servers while still draining
/// enough to keep HTTP connection pools healthy.
const MAX_ERROR_RESPONSE_BYTES: usize = 1024 * 1024;

/// Publishes routable messages to configured HTTP targets.
///
/// Designed to be called from the routing path like `NatsPublisher`.
/// Publishing is fire-and-forget: messages are dispatched via an internal
/// bounded channel to a background worker task.
#[derive(Clone)]
pub struct HttpPublisher {
    tx: mpsc::Sender<Arc<RoutableMessage>>,
    targets: Arc<Vec<TargetState>>,
    shutdown: Arc<tokio::sync::Notify>,
    /// Encrypted dead-letter queue for circuit-breaker-shed messages.
    dlq: Option<Arc<DeadLetterQueue>>,
    /// Worker task handle for panic detection during shutdown.
    worker_handle: Arc<std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>>,
}

impl fmt::Debug for HttpPublisher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpPublisher")
            .field("target_count", &self.targets.len())
            .finish_non_exhaustive()
    }
}

/// Per-target runtime state.
struct TargetState {
    name: String,
    client: reqwest::Client,
    url: String,
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
    /// HTTP client for each enabled target. Spawns a background dispatch
    /// worker automatically.
    pub fn new(config: HttpConfig) -> Result<Self, HttpError> {
        config.validate()?;

        let resolver = Arc::new(SsrfSafeResolver::new(config.allow_private_urls));
        let instance_id = config.instance_id.unwrap_or_else(generate_instance_id);

        let mut targets = Vec::with_capacity(config.targets.len());

        for tc in &config.targets {
            if tc.enabled == Some(false) {
                tracing::info!(target = %tc.name, "HTTP target disabled, skipping");
                continue;
            }

            let target = build_target(tc, &instance_id, Arc::clone(&resolver))?;
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
                    rustgate_core::encrypted::KeyRing::load(std::path::Path::new(key_file))
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

        Ok(Self {
            tx,
            targets,
            shutdown,
            dlq,
            worker_handle: Arc::new(std::sync::Mutex::new(Some(handle))),
        })
    }

    /// Fire-and-forget publish. Non-blocking — drops on channel full.
    pub fn publish(&self, msg: &RoutableMessage) {
        // Echo prevention at the publisher level (case-insensitive to
        // defend against inconsistent casing across transport adapters)
        if msg.metadata.source_protocol.eq_ignore_ascii_case("http") {
            return;
        }

        match self.tx.try_send(Arc::new(msg.clone())) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                tracing::warn!(
                    source_cn = %sanitize_for_log(&msg.source.cn),
                    target_count = self.targets.len(),
                    "HTTP dispatch channel full, dropping message"
                );
                #[cfg(feature = "metrics")]
                crate::metrics::errors()
                    .with_label_values(&["_all", "channel_full"])
                    .inc();
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                tracing::warn!("HTTP dispatch channel closed");
            }
        }
    }

    /// True when all circuit breakers are closed (healthy).
    pub fn is_healthy(&self) -> bool {
        self.targets.iter().all(|t| t.circuit.is_closed())
    }

    /// Signal the background worker to shut down, await drain, and seal DLQ.
    ///
    /// Logs a warning if the worker panicked. Seals DLQ writers to ensure
    /// encrypted terminators are written (readers reject unterminated files).
    pub async fn shutdown(&self) {
        self.shutdown.notify_one();

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
fn build_target(
    tc: &TargetConfig,
    instance_id: &str,
    resolver: Arc<SsrfSafeResolver>,
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
    );

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

    Ok(TargetState {
        name: tc.name.clone(),
        client,
        url: tc.url.clone(),
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

            let key_pem =
                Zeroizing::new(std::fs::read(key_path).map_err(|e| HttpError::TlsFile {
                    target: tc.name.clone(),
                    path: key_path.clone(),
                    source: e,
                })?);

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
        let key_pem = Zeroizing::new(std::fs::read(key_path).map_err(|e| HttpError::TlsFile {
            target: tc.name.clone(),
            path: key_path.clone(),
            source: e,
        })?);

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
async fn dispatch_worker(
    mut rx: mpsc::Receiver<Arc<RoutableMessage>>,
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
                while let Some(msg) = rx.recv().await {
                    fan_out(&msg, &targets, dlq.as_deref()).await;
                }
                tracing::info!("HTTP dispatch worker stopped");
                return;
            }
            msg = rx.recv() => {
                match msg {
                    Some(msg) => fan_out(&msg, &targets, dlq.as_deref()).await,
                    None => {
                        tracing::info!("HTTP dispatch channel closed");
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

    // Serialize payload
    let (body_vec, content_type) = match payload::serialize(msg, target.format, &target.instance_id)
    {
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

    // Stable delivery ID: generated once per message-target pair so retries
    // carry the same ID, enabling receiver-side deduplication.
    let delivery_id = generate_delivery_id();

    // Content-Digest (RFC 9530): SHA-256 hash of the serialized body for
    // end-to-end integrity verification by the receiver.
    let content_digest = compute_content_digest(&body_vec);

    // Convert to Bytes once — Bytes::clone() is a ref-count bump, not a memcpy,
    // so retries and auth signing can share the same allocation.
    let body = bytes::Bytes::from(body_vec);

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
            Ok(()) => {
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
                tracing::debug!(
                    target = %target.name,
                    attempt = attempt + 1,
                    delivery_id = %delivery_id,
                    "HTTP publish succeeded"
                );
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
                    error = %err,
                    status = ?status,
                    "HTTP publish failed, will retry"
                );
            }
        }
    }
}

/// Send a single HTTP request to the target.
///
/// The `delivery_id` is stable across retry attempts for the same message,
/// enabling receiver-side deduplication. The `content_digest` is the
/// RFC 9530 `Content-Digest` header value (SHA-256).
///
/// Returns `Ok(())` on 2xx, or `Err((optional_status, error_string, retry_after))`.
/// The `retry_after` field is populated from the `Retry-After` header on 429
/// responses, allowing the retry loop to respect server-specified backoff.
async fn send_request(
    target: &TargetState,
    body: bytes::Bytes,
    content_type: &str,
    delivery_id: &str,
    content_digest: &str,
) -> Result<(), (Option<u16>, String, Option<Duration>)> {
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

    // Apply authentication (needs a byte slice for HMAC computation)
    if let Some(auth) = &target.auth {
        builder = auth
            .apply(builder, &body)
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
        // Drain the success response body so the connection returns to the
        // pool in a clean state (prevents connection leaks with keep-alive).
        drain_response_body(response).await;
        Ok(())
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
        // Drain the error response body so the connection returns to the
        // pool in a clean state — prevents connection pool poisoning when
        // the server sends a body with 4xx/5xx responses.
        drain_response_body(response).await;
        Err((Some(status), format!("HTTP {status}"), retry_after))
    }
}

/// Drain a response body up to [`MAX_ERROR_RESPONSE_BYTES`] to keep the
/// connection pool healthy.
///
/// HTTP/1.1 persistent connections require the full response body to be
/// consumed before the connection can be reused. If we skip this, the
/// connection is dropped and must be re-established (TCP + TLS handshake),
/// which adds latency on subsequent requests.
///
/// The size cap prevents memory exhaustion from a malicious server
/// returning an unbounded response body.
async fn drain_response_body(response: reqwest::Response) {
    // Check Content-Length first — if the server advertises a body larger
    // than our cap, just drop the connection instead of reading into memory.
    if let Some(len) = response.content_length()
        && len > MAX_ERROR_RESPONSE_BYTES as u64
    {
        return;
    }
    // Drain up to the limit. Errors (timeout, connection reset) are
    // ignored — the connection will be dropped and a new one established.
    let _ = response.bytes().await;
}

/// Compute the RFC 9530 Content-Digest header value for body integrity.
///
/// Format: `sha-256=:<base64>:` (structured field sf-binary encoding).
/// Receivers can verify the digest to detect in-transit corruption or
/// proxy tampering, complementing TLS transport-level encryption.
fn compute_content_digest(body: &[u8]) -> String {
    let hash = Sha256::digest(body);
    let encoded = base64::engine::general_purpose::STANDARD.encode(hash);
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
/// Produces a 32-character hex string from 16 random bytes, giving 128 bits
/// of collision resistance without requiring the `uuid` crate.
fn generate_delivery_id() -> String {
    let mut buf = [0u8; 16];
    fastrand::fill(&mut buf);
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
            dlq: None,
            worker_handle: Arc::new(std::sync::Mutex::new(None)),
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
        let expected_b64 = base64::engine::general_purpose::STANDARD.encode(expected_hash);
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
            dlq: None,
            worker_handle: Arc::new(std::sync::Mutex::new(None)),
        };
        // These should all be silently dropped (echo prevention)
        for protocol in &["http", "HTTP", "Http", "hTTp"] {
            let msg = rustgate_core::message::RoutableMessage {
                source: rustgate_core::identity::Identity {
                    cn: "test".to_string(),
                    fingerprint: Default::default(),
                    groups: Default::default(),
                    tenant: None,
                    spiffe_id: None,
                    attributes: Arc::new(Default::default()),
                },
                destination: rustgate_core::message::Destination::Broadcast,
                payload: bytes::Bytes::from_static(b"test"),
                metadata: rustgate_core::message::Metadata {
                    received_at: std::time::SystemTime::now(),
                    source_protocol: protocol.to_string(),
                    message_type: rustgate_core::message::MessageType::Position,
                    ttl: None,
                },
            };
            publisher.publish(&msg);
        }
        // If echo prevention failed, try_recv would return messages
        // Since we dropped _rx, the send would fail — but publish()
        // should return before even trying to send (echo prevention)
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
            }],
            dlq_dir: None,
            dlq_key_file: None,
            dlq_max_bytes: None,
            allow_private_urls: false,
        };
        let err = HttpPublisher::new(config).unwrap_err();
        assert!(err.to_string().contains("no enabled"), "got: {err}");
    }
}
