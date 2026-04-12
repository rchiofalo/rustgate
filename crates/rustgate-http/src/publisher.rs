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
use rustgate_core::message::RoutableMessage;
use tokio::sync::mpsc;
use tracing::Instrument;

use crate::auth::AuthState;
use crate::circuit::CircuitBreaker;
use crate::config::{HttpConfig, PayloadFormat, TargetConfig};
use crate::error::HttpError;
use crate::filter::CompiledFilter;
use crate::{payload, retry};

/// Channel buffer size for the dispatch queue.
const CHANNEL_BUFFER: usize = 256;

/// Publishes routable messages to configured HTTP targets.
///
/// Designed to be called from the routing path like [`NatsPublisher`].
/// Publishing is fire-and-forget: messages are dispatched via an internal
/// bounded channel to a background worker task.
#[derive(Clone)]
pub struct HttpPublisher {
    tx: mpsc::Sender<Arc<RoutableMessage>>,
    targets: Arc<Vec<TargetState>>,
    shutdown: Arc<tokio::sync::Notify>,
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
    /// HTTP client for each enabled target. Call [`start`](Self::start) to
    /// spawn the background worker.
    pub fn new(config: HttpConfig) -> Result<Self, HttpError> {
        config.validate()?;

        let instance_id = config.instance_id.unwrap_or_else(generate_instance_id);

        let mut targets = Vec::with_capacity(config.targets.len());

        for tc in &config.targets {
            if tc.enabled == Some(false) {
                tracing::info!(target = %tc.name, "HTTP target disabled, skipping");
                continue;
            }

            let target = build_target(tc, &instance_id)?;
            targets.push(target);
        }

        if targets.is_empty() {
            return Err(HttpError::Config(
                "no enabled HTTP targets configured".to_string(),
            ));
        }

        tracing::info!(
            target_count = targets.len(),
            instance_id = %instance_id,
            "HTTP publisher initialized"
        );

        let (tx, rx) = mpsc::channel(CHANNEL_BUFFER);
        let shutdown = Arc::new(tokio::sync::Notify::new());
        let targets = Arc::new(targets);

        // Spawn background worker
        let worker_targets = Arc::clone(&targets);
        let worker_shutdown = Arc::clone(&shutdown);
        // Worker runs independently — JoinHandle intentionally dropped
        drop(tokio::spawn(dispatch_worker(
            rx,
            worker_targets,
            worker_shutdown,
        )));

        Ok(Self {
            tx,
            targets,
            shutdown,
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
                    source_cn = %msg.source.cn,
                    target_count = self.targets.len(),
                    "HTTP dispatch channel full, dropping message"
                );
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

    /// Signal the background worker to shut down.
    pub fn shutdown(&self) {
        self.shutdown.notify_one();
    }
}

/// Build a single target's runtime state from config.
fn build_target(tc: &TargetConfig, instance_id: &str) -> Result<TargetState, HttpError> {
    let client = build_client(tc)?;

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
    })
}

/// Build a reqwest::Client for a target with timeout and optional TLS.
///
/// Security hardening:
/// - Redirects disabled to prevent SSRF via 3xx to internal endpoints.
/// - Separate connect timeout prevents slow-connect DoS.
/// - Minimum TLS 1.2 enforced for outbound connections.
fn build_client(tc: &TargetConfig) -> Result<reqwest::Client, HttpError> {
    let timeout = Duration::from_secs(tc.effective_timeout_secs());
    let mut builder = reqwest::Client::builder()
        .timeout(timeout)
        .connect_timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .min_tls_version(reqwest::tls::Version::TLS_1_2);

    // Apply TLS configuration
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

            let mut identity_pem = std::fs::read(cert_path).map_err(|e| HttpError::TlsFile {
                target: tc.name.clone(),
                path: cert_path.clone(),
                source: e,
            })?;

            let key_pem = std::fs::read(key_path).map_err(|e| HttpError::TlsFile {
                target: tc.name.clone(),
                path: key_path.clone(),
                source: e,
            })?;

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

/// Background worker that drains the channel and fans out to targets.
async fn dispatch_worker(
    mut rx: mpsc::Receiver<Arc<RoutableMessage>>,
    targets: Arc<Vec<TargetState>>,
    shutdown: Arc<tokio::sync::Notify>,
) {
    loop {
        tokio::select! {
            biased;
            () = shutdown.notified() => {
                tracing::info!("HTTP dispatch worker shutting down, draining queue");
                // Drain remaining messages
                rx.close();
                while let Some(msg) = rx.recv().await {
                    fan_out(&msg, &targets).await;
                }
                tracing::info!("HTTP dispatch worker stopped");
                return;
            }
            msg = rx.recv() => {
                match msg {
                    Some(msg) => fan_out(&msg, &targets).await,
                    None => {
                        tracing::info!("HTTP dispatch channel closed");
                        return;
                    }
                }
            }
        }
    }
}

/// Fan out a message to all matching targets sequentially.
///
/// Targets are dispatched one at a time to avoid requiring `Send` bounds
/// on borrowed references. Each target dispatch is independent and logged
/// with its own tracing span.
async fn fan_out(msg: &RoutableMessage, targets: &[TargetState]) {
    for target in targets {
        if !target.filter.matches(msg) {
            continue;
        }

        let span = tracing::debug_span!(
            "http_dispatch",
            target = %target.name,
            source_cn = %msg.source.cn,
        );
        dispatch_to_target(target, msg).instrument(span).await;
    }
}

/// Dispatch a single message to a target with retry and circuit breaking.
async fn dispatch_to_target(target: &TargetState, msg: &RoutableMessage) {
    // Circuit breaker check
    if !target.circuit.allow_request() {
        tracing::warn!(
            target = %target.name,
            source_cn = %msg.source.cn,
            message_type = %msg.metadata.message_type,
            payload_size = msg.payload.len(),
            "circuit open, dead-lettering message"
        );
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
        return;
    }

    // Serialize payload
    let (body, content_type) = match payload::serialize(msg, target.format, &target.instance_id) {
        Ok(result) => result,
        Err(e) => {
            tracing::warn!(
                target = %target.name,
                error = %e,
                "payload serialization failed"
            );
            return;
        }
    };

    // Retry loop
    for attempt in 0..target.max_attempts {
        if attempt > 0 {
            let delay = retry::backoff_with_jitter(target.backoff_base, attempt);
            tokio::time::sleep(delay).await;
        }

        match send_request(target, &body, content_type).await {
            Ok(()) => {
                target.circuit.record_success();
                tracing::debug!(
                    target = %target.name,
                    attempt = attempt + 1,
                    "HTTP publish succeeded"
                );
                return;
            }
            Err((status, err)) => {
                let is_last = attempt + 1 >= target.max_attempts;
                let retryable = status.is_some_and(retry::is_retryable_status);

                if is_last || !retryable {
                    target.circuit.record_failure();
                    tracing::warn!(
                        target = %target.name,
                        attempt = attempt + 1,
                        error = %err,
                        status = ?status,
                        retryable,
                        "HTTP publish failed (final)"
                    );
                    return;
                }

                tracing::debug!(
                    target = %target.name,
                    attempt = attempt + 1,
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
/// Returns `Ok(())` on 2xx, or `Err((optional_status, error_string))`.
async fn send_request(
    target: &TargetState,
    body: &[u8],
    content_type: &str,
) -> Result<(), (Option<u16>, String)> {
    // Per-request delivery ID for receiver-side idempotency and audit.
    // 16 random bytes → 32-char hex string (128-bit collision resistance).
    let delivery_id = generate_delivery_id();

    let mut builder = target
        .client
        .request(target.method.clone(), &target.url)
        .header("Content-Type", content_type)
        .header("X-Rustgate-Instance", &target.instance_id)
        .header("X-Rustgate-Delivery-Id", &delivery_id);

    // Apply custom headers
    for (name, value) in &target.custom_headers {
        builder = builder.header(name.clone(), value);
    }

    // Apply authentication
    if let Some(auth) = &target.auth {
        builder = auth
            .apply(builder, body)
            .map_err(|e| (None, e.to_string()))?;
    }

    builder = builder.body(body.to_vec());

    let response = builder.send().await.map_err(|e| {
        let status = e.status().map(|s| s.as_u16());
        (status, e.to_string())
    })?;

    let status = response.status().as_u16();
    if (200..300).contains(&status) {
        Ok(())
    } else {
        Err((Some(status), format!("HTTP {status}")))
    }
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
}
