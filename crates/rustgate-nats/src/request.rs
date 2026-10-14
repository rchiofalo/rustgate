// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! NATS request/reply pattern support.
//!
//! The pub/sub bridge in [`crate::publisher`] and [`crate::subscriber`]
//! carries streaming telemetry (positions, chat, status) between local
//! sessions and the NATS bus. Request/reply is a different use case:
//! operator-facing queries ("what is the status of peer X"), command and
//! control ("reload ACLs"), and health probes that want a single
//! synchronous answer. Splitting it into its own module keeps the
//! streaming hot path free of the per-request inbox bookkeeping that the
//! NATS client performs internally for `client.request(...)`.
//!
//! Two halves:
//!
//! - [`NatsRequestResponder`] subscribes to a configured subject, hands
//!   each incoming message to a caller-supplied [`NatsRequestHandler`],
//!   and publishes the handler's result on `msg.reply`. A handler error
//!   is surfaced via the [`ERROR_HEADER`] so the requesting side can
//!   distinguish "no responders" from "handler rejected the request".
//!
//! - [`NatsRequestClient`] delegates to [`async_nats::Client::request`]
//!   with a configurable timeout and maps the `async-nats` error taxonomy
//!   into [`RequestError`], which is the type we want in public
//!   rustgate-facing APIs (so callers do not need a direct `async-nats`
//!   dependency to interpret failures).
//!
//! The responder dispatches each request to an independent task so a
//! slow handler cannot block newer requests on the same subject, and so
//! a panicking handler cannot take down the responder loop. The spawn
//! uses [`rustgate_core::tasks::spawn_background`] which logs panics via
//! `tracing::error!` instead of silently dropping them.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use async_nats::client::{RequestError as NatsRequestError, RequestErrorKind};
use bytes::Bytes;
use futures::StreamExt;
use rustgate_core::tasks::spawn_background;
use tokio::sync::Notify;
use tracing::Instrument;

/// Async callback invoked by [`NatsRequestResponder`] for every incoming
/// request message. The handler receives the raw request payload and
/// returns either a reply payload (`Ok`) or an error message (`Err`) that
/// will be relayed to the requester via the [`ERROR_HEADER`].
///
/// `Arc<dyn Fn + Send + Sync>` rather than `AsyncFn` because
/// `dyn AsyncFn` is not object-safe as of Rust 1.94, and the workspace
/// convention (see `.claude/rules/code-style.md`) is to type-alias these
/// as `Arc<dyn Fn(...) -> Pin<Box<...>>>` — see
/// `rustgate_enrollment::contacts::ContactsProvider` for the canonical
/// precedent.
pub type NatsRequestHandler =
    Arc<dyn Fn(Bytes) -> Pin<Box<dyn Future<Output = Result<Bytes, String>> + Send>> + Send + Sync>;

/// Reply header used by [`NatsRequestResponder`] to carry a handler error
/// message back to the requesting side.
///
/// When present, [`NatsRequestClient::request`] returns
/// [`RequestError::HandlerError`]. An empty payload accompanies the
/// header (no meaningful response body is produced on the error path).
pub const ERROR_HEADER: &str = "NATS-Rustgate-Error";

/// Errors returned by [`NatsRequestClient::request`].
///
/// Distinct from [`NatsRequestError`] (the `async-nats` crate's error
/// type) so callers of rustgate-nats can handle the common failure modes
/// — timeout, no responders, handler-reported error — without depending
/// directly on the transport crate or pattern-matching `RequestErrorKind`
/// at every call site.
#[derive(Debug, thiserror::Error)]
pub enum RequestError {
    /// A responder is subscribed but did not publish a reply within the
    /// configured timeout. The NATS client discards the inbox subscription
    /// when this fires so a late reply is dropped, not buffered.
    #[error("NATS request to `{subject}` timed out after {timeout:?}")]
    Timeout {
        /// The subject the request targeted.
        subject: String,
        /// The timeout that elapsed.
        timeout: Duration,
    },

    /// The NATS server reports no subscribers on the subject. Distinct
    /// from [`Self::Timeout`]: the server answers immediately with a
    /// "503 No Responders" message, no timer elapses. Typically means
    /// the responder is not running on any peer, not that it is slow.
    #[error("no NATS responders for subject `{subject}`")]
    NoResponders {
        /// The subject with no listeners.
        subject: String,
    },

    /// The responder handler returned an error string which was relayed
    /// via the [`ERROR_HEADER`] reply header.
    #[error("NATS responder returned error for `{subject}`: {message}")]
    HandlerError {
        /// The subject the request targeted.
        subject: String,
        /// The error message the handler produced.
        message: String,
    },

    /// Underlying `async-nats` failure (invalid subject, disconnect,
    /// etc.). The original error is preserved as the `source` so
    /// diagnostics are not lost, but pattern matching is discouraged —
    /// prefer the specific variants above for routing decisions.
    #[error("NATS request failed for `{subject}`: {source}")]
    Client {
        /// The subject the request targeted.
        subject: String,
        /// The `async-nats` client error.
        source: NatsRequestError,
    },
}

/// Client handle for sending NATS request/reply queries.
///
/// A thin wrapper over [`async_nats::Client::send_request`]: the NATS
/// client already owns the per-request inbox machinery, so the wrapper
/// only needs to set the per-call timeout, map errors into
/// [`RequestError`], and inspect the reply for an [`ERROR_HEADER`].
/// Clone freely — the underlying `async_nats::Client` is cheap to clone
/// (it holds an `Arc` internally) and `NatsRequestClient` has no
/// connection state of its own.
#[derive(Debug, Clone)]
pub struct NatsRequestClient {
    client: async_nats::Client,
    default_timeout: Duration,
}

impl NatsRequestClient {
    /// Default request timeout: 5 seconds.
    ///
    /// A deliberately short budget because request/reply is for
    /// interactive operator queries, not batch jobs. If the responder is
    /// healthy it should answer in well under a second; if it is not, the
    /// caller benefits from a fast failure rather than a 30-second hang
    /// on every operator click. Override with [`Self::with_timeout`] or
    /// [`Self::request_with_timeout`] when the use case justifies it.
    pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

    /// Build a client over an existing NATS connection.
    pub fn new(client: async_nats::Client) -> Self {
        Self {
            client,
            default_timeout: Self::DEFAULT_TIMEOUT,
        }
    }

    /// Override the default per-request timeout used by [`Self::request`].
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.default_timeout = timeout;
        self
    }

    /// Return the timeout that would be applied by [`Self::request`] if
    /// no per-call override is provided.
    pub fn default_timeout(&self) -> Duration {
        self.default_timeout
    }

    /// Send a request and wait for a reply, applying the default
    /// timeout.
    ///
    /// Fails with [`RequestError::Timeout`] if the responder does not
    /// reply in time, [`RequestError::NoResponders`] if nothing is
    /// subscribed, or [`RequestError::HandlerError`] if the responder
    /// reported an error via [`ERROR_HEADER`].
    pub async fn request(
        &self,
        subject: impl Into<String>,
        payload: Bytes,
    ) -> Result<Bytes, RequestError> {
        let subject = subject.into();
        let timeout = self.default_timeout;
        self.request_with_timeout(subject, payload, timeout).await
    }

    /// Send a request with an explicit per-call timeout, overriding the
    /// default.
    pub async fn request_with_timeout(
        &self,
        subject: String,
        payload: Bytes,
        timeout: Duration,
    ) -> Result<Bytes, RequestError> {
        let request = async_nats::Request::new()
            .payload(payload)
            .timeout(Some(timeout));
        match self.client.send_request(subject.clone(), request).await {
            Ok(msg) => {
                if let Some(headers) = &msg.headers
                    && let Some(err_val) = headers.get(ERROR_HEADER)
                {
                    return Err(RequestError::HandlerError {
                        subject,
                        message: err_val.as_str().to_string(),
                    });
                }
                Ok(msg.payload)
            }
            Err(e) => Err(map_request_error(subject, timeout, e)),
        }
    }
}

/// Map an `async-nats` request error into the rustgate
/// [`RequestError`] taxonomy. Kept as a free function so the mapping can
/// be unit-tested without a live NATS connection.
fn map_request_error(subject: String, timeout: Duration, error: NatsRequestError) -> RequestError {
    match error.kind() {
        RequestErrorKind::TimedOut => RequestError::Timeout { subject, timeout },
        RequestErrorKind::NoResponders => RequestError::NoResponders { subject },
        _ => RequestError::Client {
            subject,
            source: error,
        },
    }
}

/// Subscribes to a NATS subject and dispatches each request to a
/// caller-supplied [`NatsRequestHandler`].
///
/// Long-lived task driven by [`run`](Self::run). For every received
/// message the responder spawns a background task (via
/// [`spawn_background`]) that invokes the handler and publishes the
/// result on `msg.reply`. Dispatching per-request means:
///
/// - a slow handler does not head-of-line block newer requests on the
///   same subject, and
/// - a panicking handler is contained by `spawn_background`'s panic
///   logging wrapper rather than taking the responder loop down.
///
/// The shutdown signal is an [`Arc<Notify>`] — the same primitive used
/// by other rustgate subsystems — so callers can wire it into the shared
/// `SubsystemHandle` drain protocol.
pub struct NatsRequestResponder {
    client: async_nats::Client,
    subject: String,
    handler: NatsRequestHandler,
}

impl std::fmt::Debug for NatsRequestResponder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NatsRequestResponder")
            .field("subject", &self.subject)
            .finish_non_exhaustive()
    }
}

impl NatsRequestResponder {
    /// Build a responder. Does not subscribe or spawn anything yet —
    /// call [`run`](Self::run) to start processing requests.
    pub fn new(client: async_nats::Client, subject: String, handler: NatsRequestHandler) -> Self {
        Self {
            client,
            subject,
            handler,
        }
    }

    /// Run the responder loop until `shutdown` is notified or the
    /// subscription terminates.
    ///
    /// Each request is dispatched on a fresh background task so handler
    /// latency is independent of request arrival rate and a handler
    /// panic does not poison the main loop. When shutdown is requested
    /// the responder stops accepting new messages; in-flight handler
    /// tasks continue to completion on their own (the broader shutdown
    /// budget is the caller's responsibility via
    /// [`rustgate_core::tasks::stop_subsystem`]).
    pub async fn run(self, shutdown: Arc<Notify>) -> Result<(), async_nats::Error> {
        let mut subscription = self.client.subscribe(self.subject.clone()).await?;
        tracing::info!(subject = %self.subject, "NATS request responder started");

        loop {
            tokio::select! {
                _ = shutdown.notified() => {
                    tracing::info!(subject = %self.subject, "NATS request responder shutting down");
                    break;
                }
                maybe_msg = subscription.next() => {
                    let Some(msg) = maybe_msg else {
                        tracing::info!(
                            subject = %self.subject,
                            "NATS request subscription ended",
                        );
                        break;
                    };
                    let Some(reply) = msg.reply.clone() else {
                        tracing::debug!(
                            subject = %self.subject,
                            "incoming NATS message has no reply subject, ignoring",
                        );
                        continue;
                    };

                    let client = self.client.clone();
                    let handler = Arc::clone(&self.handler);
                    let subject = self.subject.clone();
                    let span = tracing::debug_span!(
                        "nats_request",
                        subject = %subject,
                        reply = %reply,
                    );
                    let payload = msg.payload;
                    spawn_background(
                        "nats-request-responder",
                        async move { dispatch_request(client, reply, handler, payload).await }
                            .instrument(span),
                    );
                }
            }
        }
        Ok(())
    }
}

/// Run a single request through the handler and publish the result.
///
/// Factored out of [`NatsRequestResponder::run`] so the dispatch
/// behaviour — including the error-header encoding — can be exercised
/// directly without a live NATS connection.
async fn dispatch_request(
    client: async_nats::Client,
    reply: async_nats::Subject,
    handler: NatsRequestHandler,
    payload: Bytes,
) {
    match handler(payload).await {
        Ok(reply_payload) => {
            if let Err(e) = client.publish(reply, reply_payload).await {
                tracing::warn!(error = %e, "failed to publish NATS reply");
            }
        }
        Err(err_msg) => {
            let mut headers = async_nats::HeaderMap::new();
            headers.insert(ERROR_HEADER, err_msg.as_str());
            if let Err(e) = client
                .publish_with_headers(reply, headers, Bytes::new())
                .await
            {
                tracing::warn!(error = %e, "failed to publish NATS error reply");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn request_error_display_timeout() {
        let err = RequestError::Timeout {
            subject: "svc.ping".to_string(),
            timeout: Duration::from_millis(250),
        };
        let msg = err.to_string();
        assert!(
            msg.contains("svc.ping"),
            "display should include subject: {msg}"
        );
        assert!(
            msg.contains("250"),
            "display should include duration: {msg}"
        );
    }

    #[test]
    fn request_error_display_no_responders() {
        let err = RequestError::NoResponders {
            subject: "svc.missing".to_string(),
        };
        assert!(err.to_string().contains("svc.missing"));
    }

    #[test]
    fn request_error_display_handler_error() {
        let err = RequestError::HandlerError {
            subject: "svc.echo".to_string(),
            message: "bad payload".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("svc.echo"));
        assert!(msg.contains("bad payload"));
    }

    #[test]
    fn error_header_constant_is_stable() {
        // Pin the header name so consumers on the requesting side can rely
        // on it. Changing this string is a wire-compatible break for any
        // external tool inspecting replies, so make that break loud.
        assert_eq!(ERROR_HEADER, "NATS-Rustgate-Error");
    }

    #[test]
    fn default_timeout_is_five_seconds() {
        // Defensive pin: the default is documented in `DEFAULT_TIMEOUT`
        // as 5 seconds and becomes part of the observable behaviour of
        // callers that do not set their own timeout. Silently shortening
        // or lengthening it would change production latency profiles.
        assert_eq!(NatsRequestClient::DEFAULT_TIMEOUT, Duration::from_secs(5));
    }

    #[tokio::test]
    async fn handler_type_can_be_constructed_from_async_closure() {
        // Compile-time sanity that the public callback shape can be
        // built from an idiomatic async closure — if the `Arc<dyn Fn ->
        // Pin<Box<dyn Future>>>` alias ever drifts into something that
        // rejects async closures, this test will break at build time.
        // Also asserts the round-trip payload echoes at runtime so the
        // future is actually driven (avoids `let_underscore_future`).
        let handler: NatsRequestHandler = Arc::new(|payload: Bytes| {
            Box::pin(async move { Ok(payload) })
                as Pin<Box<dyn Future<Output = Result<Bytes, String>> + Send>>
        });
        let echoed = handler(Bytes::from_static(b"hi")).await.unwrap();
        assert_eq!(echoed.as_ref(), b"hi");
    }
}
