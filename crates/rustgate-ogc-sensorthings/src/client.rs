// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! HTTP polling client for the OGC SensorThings v1.0 REST API.
//!
//! The client is a thin wrapper around a configured
//! [`reqwest::Client`] plus the per-subscription URL composition
//! and pagination logic. It does **not** drive its own poll loop —
//! the [`crate::wiring`] module owns the per-datastream tokio task
//! that calls [`SensorThingsClient::poll`] on a cadence and feeds
//! the resulting observations into the router. Splitting the I/O
//! surface from the loop driver makes the wiring testable against a
//! `MockServer` without needing a global tokio time mock.
//!
//! # URL composition
//!
//! For every subscription `S` with `datastream-id = N`, the client
//! constructs the polling URL as
//!
//! ```text
//! <endpoint>/Datastreams(<N>)/Observations?$top=<page>&$orderby=phenomenonTime+asc[&$expand=Datastream/Thing/Locations][&$filter=phenomenonTime gt <iso8601>]
//! ```
//!
//! The `?$expand=Datastream/Thing/Locations` segment is included
//! when [`crate::SensorThingsConfig::expand_location`] is `true`
//! (the default) — this is the standard SensorThings idiom for
//! fetching the sensor station's lat/lon in a single round trip.
//! The `?$filter=phenomenonTime gt …` segment is included when the
//! caller passes a non-`None` `since` argument, so subsequent polls
//! request only newer observations.
//!
//! # Authentication
//!
//! When the configured `auth-token-path` is set, the wiring layer
//! reads the file at startup, wraps it in `Zeroizing`, and passes
//! the token through to [`SensorThingsClient::with_bearer`]. Every
//! poll then carries `Authorization: Bearer <token>`. The MVP does
//! not refresh the token — operators rotate it by restarting the
//! server (or signalling SIGHUP, when the future config-reload
//! umbrella lands).

use std::sync::Arc;
use std::time::Duration;

use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};
use reqwest::{Method, StatusCode};
use rustgate_core::constants::MAX_FRAME_SIZE;

use crate::config::SensorThingsConfig;
use crate::error::SensorThingsError;
use crate::types::ObservationsPage;

/// HTTP polling client for an OGC SensorThings v1.0 server.
///
/// Construct one client per `[sensorthings]` config block and reuse
/// it across every per-subscription poll task — `reqwest::Client`
/// pools connections internally so a single client amortises
/// TLS/TCP setup across the whole subscription set.
#[derive(Clone)]
pub struct SensorThingsClient {
    inner: reqwest::Client,
    endpoint: String,
    expand_location: bool,
    /// Optional bearer token. Stored as `Arc<str>` rather than
    /// `Arc<Zeroizing<String>>` because the token is rebuilt into a
    /// `HeaderValue` per request and the wiring layer holds the
    /// authoritative `Zeroizing` copy. The `Arc<str>` clone here is
    /// a refcount bump; the wiring layer's `Zeroizing` wrap drops
    /// the buffer on shutdown.
    bearer_token: Option<Arc<str>>,
    request_timeout: Duration,
}

impl std::fmt::Debug for SensorThingsClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Custom Debug to redact the bearer token.
        f.debug_struct("SensorThingsClient")
            .field("endpoint", &self.endpoint)
            .field("expand_location", &self.expand_location)
            .field(
                "bearer_token",
                &self.bearer_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("request_timeout", &self.request_timeout)
            .finish()
    }
}

impl SensorThingsClient {
    /// Construct a client for the given configuration. The reqwest
    /// client is built with the configured request timeout and the
    /// `Rustgate` user-agent string.
    ///
    /// `bearer_token` is optional — passing `Some(...)` enables
    /// `Authorization: Bearer …` on every request. The wiring layer
    /// owns the `Zeroizing<String>` buffer; the `Arc<str>` here is
    /// a refcount bump.
    pub fn new(
        config: &SensorThingsConfig,
        bearer_token: Option<Arc<str>>,
    ) -> Result<Self, SensorThingsError> {
        config.validate()?;
        let inner = reqwest::Client::builder()
            .timeout(config.effective_request_timeout())
            .connect_timeout(Duration::from_secs(5))
            .user_agent("Rustgate")
            // Disable redirects so a hostile server cannot redirect
            // us to an internal endpoint. Matches the discipline
            // applied in `rustgate_http::publisher::build_client`.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| SensorThingsError::Config {
                message: format!("failed to build reqwest client: {e}"),
            })?;

        Ok(Self {
            inner,
            endpoint: config.normalised_endpoint().to_string(),
            expand_location: config.expand_location,
            bearer_token,
            request_timeout: config.effective_request_timeout(),
        })
    }

    /// Construct a client from already-built parts. Useful in tests
    /// to inject a pre-configured `reqwest::Client` against a
    /// `MockServer`.
    pub fn from_parts(
        inner: reqwest::Client,
        endpoint: String,
        expand_location: bool,
        bearer_token: Option<Arc<str>>,
        request_timeout: Duration,
    ) -> Self {
        Self {
            inner,
            endpoint: endpoint.trim_end_matches('/').to_string(),
            expand_location,
            bearer_token,
            request_timeout,
        }
    }

    /// Replace the bearer token. Returns a new client; the old one
    /// is unaffected and may continue to serve in-flight polls.
    /// Reserved for the future SIGHUP-driven token rotation path.
    #[must_use]
    pub fn with_bearer(mut self, bearer_token: Option<Arc<str>>) -> Self {
        self.bearer_token = bearer_token;
        self
    }

    /// Compose the polling URL for a given datastream id, page
    /// size, and `since` cursor. Exposed `pub(crate)` so the
    /// wiring task tests can pin the URL shape without going
    /// through a full HTTP round trip.
    pub(crate) fn build_url(&self, datastream_id: u64, top: u32, since: Option<&str>) -> String {
        let mut url = format!(
            "{endpoint}/Datastreams({id})/Observations?$top={top}&$orderby=phenomenonTime+asc",
            endpoint = self.endpoint,
            id = datastream_id,
            top = top,
        );
        if self.expand_location {
            url.push_str("&$expand=Datastream/Thing/Locations");
        }
        if let Some(cursor) = since {
            // The cursor is a `phenomenonTime` value validated as RFC 3339 by
            // the polling task (see `wiring::max_parseable_cursor`) before it
            // reaches here — it is NOT free-form server text. Because only an
            // RFC-3339-valid timestamp literal can arrive, raw interpolation
            // into the OData `$filter` clause cannot inject operators.
            // SensorThings datetime literals are written bare (no quotes).
            url.push_str(&format!("&$filter=phenomenonTime gt {cursor}"));
        }
        url
    }

    /// Issue one poll for the given datastream. Returns the parsed
    /// [`ObservationsPage`] on success, with the per-error variant
    /// surfaced on failure.
    ///
    /// `since` is the most recent `phenomenonTime` the caller has
    /// already processed — pass `None` on the first poll, then on
    /// subsequent polls pass the maximum `phenomenonTime` from the
    /// last successful response. The request is composed with a
    /// `?$filter=phenomenonTime gt <since>` clause so the server
    /// only returns newer observations.
    pub async fn poll(
        &self,
        datastream_id: u64,
        page_size: u32,
        since: Option<&str>,
    ) -> Result<ObservationsPage, SensorThingsError> {
        let url = self.build_url(datastream_id, page_size, since);
        let mut headers = HeaderMap::new();
        if let Some(token) = self.bearer_token.as_ref() {
            let value = HeaderValue::from_str(&format!("Bearer {token}")).map_err(|e| {
                SensorThingsError::Config {
                    message: format!("bearer token contained an invalid header byte: {e}"),
                }
            })?;
            let _ = headers.insert(AUTHORIZATION, value);
        }
        let response = self
            .inner
            .request(Method::GET, &url)
            .headers(headers)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    SensorThingsError::Timeout {
                        elapsed: self.request_timeout,
                    }
                } else {
                    SensorThingsError::Transport { source: e }
                }
            })?;

        let status = response.status();
        if !status.is_success() {
            let message = response
                .text()
                .await
                .ok()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| status.canonical_reason().unwrap_or("unknown").to_string());
            return Err(SensorThingsError::HttpStatus {
                status: status.as_u16(),
                message,
            });
        }

        // Cap the response body. A SensorThings page is bounded, but the
        // endpoint is untrusted (redirects are disabled above for the same
        // reason), so a hostile or MITM'd server returning a chunked,
        // Content-Length-less, multi-gigabyte body must not be buffered into
        // heap. Reject once the body exceeds MAX_FRAME_SIZE rather than
        // trusting (or requiring) the advertised Content-Length.
        if let Some(len) = response.content_length()
            && len > MAX_FRAME_SIZE as u64
        {
            return Err(SensorThingsError::ResponseTooLarge {
                limit: MAX_FRAME_SIZE,
            });
        }
        let mut response = response;
        let mut body: Vec<u8> = Vec::new();
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) => {
                    if would_exceed_limit(body.len(), chunk.len(), MAX_FRAME_SIZE) {
                        return Err(SensorThingsError::ResponseTooLarge {
                            limit: MAX_FRAME_SIZE,
                        });
                    }
                    body.extend_from_slice(&chunk);
                }
                Ok(None) => break,
                // Body-read failure after the headers arrived — surface as a
                // transport error so the wiring's backoff path applies.
                Err(e) => return Err(SensorThingsError::Transport { source: e }),
            }
        }
        serde_json::from_slice::<ObservationsPage>(&body).map_err(|e| SensorThingsError::Decode {
            message: format!("failed to decode SensorThings response: {e}"),
        })
    }

    /// HTTP status helper — `true` when the previous poll failed
    /// with a transient HTTP status. Surfaced for tests; the
    /// production path goes through `SensorThingsError::is_transient`.
    pub fn is_transient_status(status: StatusCode) -> bool {
        status == StatusCode::REQUEST_TIMEOUT
            || status == StatusCode::TOO_MANY_REQUESTS
            || status.is_server_error()
    }
}

/// Whether appending `incoming` bytes to an already-`accumulated` buffer would
/// push it past `limit`. Pulled out as a pure function so the streaming
/// response-body cap — the bound that stops an unbounded (chunked,
/// Content-Length-less) body from being buffered — is unit-testable without a
/// streaming HTTP server. `saturating_add` keeps the check correct even if a
/// hostile chunk length were near `usize::MAX`.
fn would_exceed_limit(accumulated: usize, incoming: usize, limit: usize) -> bool {
    accumulated.saturating_add(incoming) > limit
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn would_exceed_limit_bounds_the_streamed_body() {
        // Under the limit: keep reading.
        assert!(!would_exceed_limit(0, 1024, MAX_FRAME_SIZE));
        assert!(!would_exceed_limit(MAX_FRAME_SIZE - 1, 1, MAX_FRAME_SIZE));
        // Exactly the limit is fine; one byte over trips.
        assert!(!would_exceed_limit(MAX_FRAME_SIZE, 0, MAX_FRAME_SIZE));
        assert!(would_exceed_limit(MAX_FRAME_SIZE, 1, MAX_FRAME_SIZE));
        // Accumulation across chunks crosses the limit.
        assert!(would_exceed_limit(MAX_FRAME_SIZE - 10, 11, MAX_FRAME_SIZE));
        // A near-usize::MAX chunk length cannot wrap the check.
        assert!(would_exceed_limit(1, usize::MAX, MAX_FRAME_SIZE));
    }
    use crate::config::SensorThingsConfig;

    fn cfg_with_endpoint(endpoint: &str) -> SensorThingsConfig {
        SensorThingsConfig {
            endpoint: endpoint.to_string(),
            auth_token_path: None,
            poll_interval_secs: 30,
            request_timeout_secs: 10,
            expand_location: true,
            subscriptions: vec![],
            #[cfg(feature = "mqtt-push")]
            mqtt_push: None,
        }
    }

    #[test]
    fn build_url_includes_top_and_expand_when_configured() {
        let cfg = cfg_with_endpoint("https://example.org/SensorThings/v1.0/");
        let client = SensorThingsClient::new(&cfg, None).expect("build");
        let url = client.build_url(42, 100, None);
        assert!(
            url.starts_with("https://example.org/SensorThings/v1.0/Datastreams(42)/Observations")
        );
        assert!(
            url.contains("$top=100"),
            "url must include page size, got {url}"
        );
        assert!(
            url.contains("$expand=Datastream/Thing/Locations"),
            "expand-location=true must include expand clause, got {url}"
        );
        assert!(
            url.contains("$orderby=phenomenonTime+asc"),
            "url must request ascending ordering, got {url}"
        );
        assert!(
            !url.contains("$filter="),
            "no since cursor → no filter clause"
        );
    }

    #[test]
    fn build_url_omits_expand_when_disabled() {
        let cfg = SensorThingsConfig {
            expand_location: false,
            ..cfg_with_endpoint("https://example.org/SensorThings/v1.0")
        };
        let client = SensorThingsClient::new(&cfg, None).expect("build");
        let url = client.build_url(42, 100, None);
        assert!(
            !url.contains("$expand="),
            "expand-location=false must omit expand clause"
        );
    }

    #[test]
    fn build_url_includes_filter_when_since_is_set() {
        let cfg = cfg_with_endpoint("https://example.org/SensorThings/v1.0");
        let client = SensorThingsClient::new(&cfg, None).expect("build");
        let url = client.build_url(42, 100, Some("2026-05-08T10:00:00Z"));
        assert!(
            url.contains("$filter=phenomenonTime gt 2026-05-08T10:00:00Z"),
            "since cursor must produce a `phenomenonTime gt` filter clause, got {url}"
        );
    }

    #[test]
    fn debug_redacts_bearer_token() {
        let cfg = cfg_with_endpoint("https://example.org/SensorThings/v1.0");
        let client =
            SensorThingsClient::new(&cfg, Some(Arc::from("secret-token-value"))).expect("build");
        let dbg = format!("{client:?}");
        assert!(
            !dbg.contains("secret-token-value"),
            "Debug must not leak bearer token, got {dbg}"
        );
        assert!(dbg.contains("REDACTED"));
    }

    #[test]
    fn debug_marks_token_absent_when_none() {
        let cfg = cfg_with_endpoint("https://example.org/SensorThings/v1.0");
        let client = SensorThingsClient::new(&cfg, None).expect("build");
        let dbg = format!("{client:?}");
        assert!(dbg.contains("None"));
    }

    #[test]
    fn from_parts_normalises_trailing_slash() {
        let inner = reqwest::Client::new();
        let client = SensorThingsClient::from_parts(
            inner,
            "https://example.org/v1.0/".into(),
            false,
            None,
            Duration::from_secs(5),
        );
        let url = client.build_url(1, 10, None);
        assert!(url.starts_with("https://example.org/v1.0/Datastreams(1)/"));
    }

    #[test]
    fn rejects_invalid_endpoint_scheme_at_build_time() {
        let cfg = cfg_with_endpoint("ftp://example.org/SensorThings/v1.0");
        let err = SensorThingsClient::new(&cfg, None).expect_err("invalid scheme");
        match err {
            SensorThingsError::Config { message } => {
                assert!(
                    message.contains("http"),
                    "message must explain rejection, got {message}"
                );
            }
            other => panic!("expected Config variant, got {:?}", other),
        }
    }

    #[test]
    fn is_transient_status_classifies_canonical_codes() {
        assert!(SensorThingsClient::is_transient_status(
            StatusCode::REQUEST_TIMEOUT
        ));
        assert!(SensorThingsClient::is_transient_status(
            StatusCode::TOO_MANY_REQUESTS
        ));
        assert!(SensorThingsClient::is_transient_status(
            StatusCode::INTERNAL_SERVER_ERROR
        ));
        assert!(SensorThingsClient::is_transient_status(
            StatusCode::BAD_GATEWAY
        ));
        assert!(!SensorThingsClient::is_transient_status(
            StatusCode::UNAUTHORIZED
        ));
        assert!(!SensorThingsClient::is_transient_status(
            StatusCode::NOT_FOUND
        ));
        assert!(!SensorThingsClient::is_transient_status(StatusCode::OK));
    }
}
