// Copyright © 2026 Roberto Chiofalo.

//! Management REST API for operator diagnostics and runtime control.
//!
//! Mounted alongside the `/api/acl/` endpoints on the metrics HTTP server
//! (gated by the `metrics` feature). Exposes status endpoints that
//! surface runtime state, and write endpoints that drive disconnects and
//! config reloads without requiring a shell on the host:
//!
//! | Route                                      | Purpose                                                 |
//! |--------------------------------------------|---------------------------------------------------------|
//! | `GET  /api/cert/status`                    | Server certificate subject, SANs, expiry                |
//! | `GET  /api/crl/status`                     | Loaded CRL file — count + staleness, if configured      |
//! | `GET  /api/dedup/stats`                    | Cross-path deduplication cache — hits, size, window     |
//! | `POST /api/clients/{cn}/disconnect`        | Force a single mTLS client to drain and exit            |
//! | `POST /api/dlq/{target}/replay`            | Manually trigger a DLQ drain for an HTTP egress target  |
//! | `POST /api/drain`                          | Initiate graceful drain (Kubernetes preStop, closes #791) |
//! | `POST /api/reload`                         | Trigger the same reload path SIGHUP runs, structured    |
//!
//! Every response is a JSON envelope of the form `{"data": ...}` on
//! success or `{"error": "..."}` on failure, mirroring the `acl_api`
//! shape. Mutating endpoints (`POST /api/clients/{cn}/disconnect`,
//! `POST /api/reload`) emit the same audit events as their SIGHUP
//! counterparts so the reload trail stays unified regardless of which
//! surface triggered it.
//!
//! ## Authentication
//!
//! All routes require `Authorization: Bearer <token>`. The configured
//! token is compared in constant time via [`subtle::ConstantTimeEq`] to
//! prevent timing oracles, and the `Bearer ` prefix is required
//! (otherwise-valid bare tokens are rejected). The token is wrapped in
//! [`Zeroizing`] so it is wiped from memory on drop, matching the
//! workspace convention for secret material.
//!
//! The API is only registered when `--mgmt-api-token-file` is supplied,
//! and the token length is validated at startup with the same bounds as
//! the ACL API (`32..=256` bytes via
//! [`crate::acl_api::validate_bearer_token_length`]).

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Method, Response, StatusCode};
use rustgate_transport::{CertReloader, Router};
use serde::Serialize;
use serde_json::Value as JsonValue;
use subtle::ConstantTimeEq;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::oid_registry::OID_X509_COMMON_NAME;
use x509_parser::prelude::FromDer;
use x509_parser::x509::X509Name;
use zeroize::Zeroizing;

/// Callback that drives a full SIGHUP-style reload pass.
///
/// Returns a JSON-serializable value (typically the `ReloadReport` from
/// `main.rs`) that the HTTP handler wraps in the standard `{"data": ...}`
/// envelope. The callback is `Arc<dyn Fn>` rather than `Box<dyn Fn>` so
/// it can be cheaply cloned into every request future spawned by the
/// metrics server, matching the workspace convention for cross-thread
/// callbacks.
pub type ReloadFn = Arc<dyn Fn() -> Pin<Box<dyn Future<Output = JsonValue> + Send>> + Send + Sync>;

/// Shared state for the management REST API.
///
/// Constructed once at startup and shared between all handler
/// invocations. None of the fields are mutated after construction —
/// mutations belong on dedicated reload paths (SIGHUP or the
/// `acl_api::handle_request` mutation routes), not on this read-only
/// surface.
pub struct MgmtApiState {
    /// Router handle used by [`dedup_stats`] to read cache metrics and
    /// by [`disconnect_client_handler`] to signal a session writer task.
    pub router: Arc<Router>,
    /// Certificate reloader handle. Present when the server is running
    /// with a file-backed cert (the only case where
    /// [`CertReloader::certified_key`] can surface a live leaf); `None`
    /// yields an explicit `"certificate reloader not available"` error
    /// rather than silently returning stale data.
    pub cert_reloader: Option<Arc<CertReloader>>,
    /// On-disk CRL path when one was configured via `--crl`. The
    /// [`crl_status`] handler re-parses this file on every request via
    /// [`rustgate_transport::TlsConfig::validate_crl_file`] so the
    /// response reflects what the next SIGHUP would load — there is no
    /// separate in-memory CRL cache to go stale.
    pub crl_path: Option<PathBuf>,
    /// Reload driver. When `None`, `POST /api/reload` returns 503 —
    /// typically because the server was started without any reloadable
    /// configuration (no cert reloader, no ACL reloader, no CRL path,
    /// no federation peer reloader), which would make the endpoint a
    /// no-op anyway.
    pub reload: Option<ReloadFn>,
    /// HTTP egress publisher handle. Present when the server is running
    /// with HTTP egress configured; `None` causes
    /// `POST /api/dlq/{target}/replay` to return `503` rather than
    /// silently no-op. Held by value because [`HttpPublisher`] is
    /// `Clone` and cloning is cheap (the type owns internal `Arc`s);
    /// the management API does not own the lifecycle — drop is still
    /// driven by the outer subsystem handle in `main`.
    ///
    /// Feature-gated on `http` because `rustgate_http` is itself an
    /// optional workspace dependency — without the feature there is
    /// no publisher type to refer to.
    ///
    /// [`HttpPublisher`]: rustgate_http::HttpPublisher
    #[cfg(feature = "http")]
    pub http_publisher: Option<rustgate_http::HttpPublisher>,
    /// Drain trigger fired by `POST /api/drain` (closes #791). The same
    /// `Notify` instance is awaited by the main accept-loop's
    /// `shutdown_signal()` future, so a `notify_one()` here transitions
    /// the server into the SubsystemHandle drain path that SIGTERM
    /// would otherwise drive — no separate "drain code" exists. Stored
    /// as `Arc` so the API state and the main loop both observe the
    /// same notifier; constructed at startup before either side
    /// captures it.
    pub drain_notify: Arc<tokio::sync::Notify>,
    /// Bearer token required on every request. Stored as raw bytes so
    /// the comparison can run in constant time, wrapped in
    /// [`Zeroizing`] so the value is wiped from memory on drop.
    pub auth_token: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for MgmtApiState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the bearer token; redact by default.
        #[cfg(feature = "http")]
        let http_publisher_present = self.http_publisher.is_some();
        #[cfg(not(feature = "http"))]
        let http_publisher_present = false;
        f.debug_struct("MgmtApiState")
            .field("cert_reloader_present", &self.cert_reloader.is_some())
            .field("crl_path", &self.crl_path)
            .field("reload_configured", &self.reload.is_some())
            .field("http_publisher_present", &http_publisher_present)
            .field("drain_notify_present", &true)
            .finish_non_exhaustive()
    }
}

#[derive(Serialize)]
struct SuccessResponse<T: Serialize> {
    data: T,
}

#[derive(Serialize)]
struct ErrorResponse<'a> {
    error: &'a str,
}

fn internal_error_response() -> Response<Full<Bytes>> {
    let mut resp = Response::new(Full::new(Bytes::from("internal server error")));
    *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
    resp
}

fn json_ok<T: Serialize>(data: &T) -> Response<Full<Bytes>> {
    let body = serde_json::to_vec(&SuccessResponse { data }).unwrap_or_default();
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap_or_else(|_| internal_error_response())
}

fn json_error(status: StatusCode, message: &str) -> Response<Full<Bytes>> {
    let body = serde_json::to_vec(&ErrorResponse { error: message }).unwrap_or_default();
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap_or_else(|_| internal_error_response())
}

/// Constant-time bearer-token check. Exposed `pub(crate)` so the
/// integration tests in this crate can drive the same helper that
/// [`handle_request`] uses, rather than a near-duplicate reimplementation.
pub(crate) fn auth_ok(header: Option<&str>, expected: &[u8]) -> bool {
    let Some(raw) = header else {
        return false;
    };
    let Some(token) = raw.strip_prefix("Bearer ") else {
        return false;
    };
    token.as_bytes().ct_eq(expected).into()
}

/// Path prefixes the management API owns. Exposed so the metrics
/// dispatcher can decide which handler to route a request to before
/// calling this module.
///
/// `/api/reload` and `/api/drain` are bare paths, not prefixes — the
/// dispatcher in `metrics.rs` handles those exact-match cases
/// alongside these prefixes.
pub(crate) const MGMT_PATH_PREFIXES: &[&str] = &[
    "/api/cert/",
    "/api/crl/",
    "/api/dedup/",
    "/api/clients/",
    "/api/dlq/",
];

/// Bare-path management API routes (no trailing slash, no path params).
/// Pinned in a constant so the dispatcher in `metrics.rs` and the
/// `handle_request` matcher cannot drift — adding a new bare path here
/// is the one edit needed in both layers. Closes #791 added
/// `/api/drain`; #1140-series added `/api/reload`.
pub(crate) const MGMT_EXACT_PATHS: &[&str] = &["/api/reload", "/api/drain"];

/// Entry point called by the metrics HTTP server. Returns `Some(resp)`
/// when the path matches a management-API route (recognized or not),
/// `None` when the request should fall through to another handler so
/// callers can register additional handlers alongside.
///
/// This is an `async fn` because the write endpoints await on
/// [`Router::disconnect_client`] and the reload callback. The read
/// endpoints do not await internally, but the shared async signature
/// lets the dispatcher in `metrics.rs` drive both surfaces through one
/// handler type without a sync/async split.
pub async fn handle_request(
    method: &Method,
    path: &str,
    authorization: Option<&str>,
    _body: &[u8],
    state: &MgmtApiState,
) -> Option<Response<Full<Bytes>>> {
    let matches_prefix = MGMT_PATH_PREFIXES.iter().any(|p| path.starts_with(p));
    let matches_exact = MGMT_EXACT_PATHS.contains(&path);
    if !matches_prefix && !matches_exact {
        return None;
    }
    if !auth_ok(authorization, &state.auth_token) {
        return Some(json_error(StatusCode::UNAUTHORIZED, "unauthorized"));
    }
    Some(route(method, path, state).await)
}

async fn route(method: &Method, path: &str, state: &MgmtApiState) -> Response<Full<Bytes>> {
    // Write endpoints first — each has a dedicated path shape
    // (`/api/clients/{cn}/disconnect`, `/api/reload`, `/api/drain`) so
    // they cannot collide with the status prefixes.
    if path == "/api/reload" {
        return match method {
            &Method::POST => reload_handler(state).await,
            _ => json_error(StatusCode::METHOD_NOT_ALLOWED, "method not allowed"),
        };
    }
    if path == "/api/drain" {
        return match method {
            &Method::POST => drain_handler(state),
            _ => json_error(StatusCode::METHOD_NOT_ALLOWED, "method not allowed"),
        };
    }
    if let Some(cn) = path
        .strip_prefix("/api/clients/")
        .and_then(|s| s.strip_suffix("/disconnect"))
    {
        return match method {
            &Method::POST => disconnect_client_handler(cn, state).await,
            _ => json_error(StatusCode::METHOD_NOT_ALLOWED, "method not allowed"),
        };
    }
    #[cfg(feature = "http")]
    if let Some(target) = path
        .strip_prefix("/api/dlq/")
        .and_then(|s| s.strip_suffix("/replay"))
    {
        return match method {
            &Method::POST => dlq_replay_handler(target, state),
            _ => json_error(StatusCode::METHOD_NOT_ALLOWED, "method not allowed"),
        };
    }
    // Without `http` the prefix is still in MGMT_PATH_PREFIXES (so the
    // dispatcher routes here instead of returning a generic 404), but
    // we short-circuit to `503` so operators get a clear "not compiled
    // in" signal instead of an opaque "not found".
    #[cfg(not(feature = "http"))]
    if path.starts_with("/api/dlq/") {
        return json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "HTTP egress not compiled in (rebuild with --features http)",
        );
    }

    match (method, path) {
        (&Method::GET, "/api/cert/status") => cert_status(state),
        (&Method::GET, "/api/crl/status") => crl_status(state),
        (&Method::GET, "/api/dedup/stats") => dedup_stats(state),
        // A recognized prefix with an unrecognized suffix or an
        // incorrect method gets a 405/404 split: wrong method on a
        // known endpoint is `METHOD_NOT_ALLOWED` (so operators see
        // "this endpoint exists but not for that verb"), unknown
        // suffix is `NOT_FOUND`.
        (_, "/api/cert/status" | "/api/crl/status" | "/api/dedup/stats") => {
            json_error(StatusCode::METHOD_NOT_ALLOWED, "method not allowed")
        }
        _ => json_error(StatusCode::NOT_FOUND, "not found"),
    }
}

// ── /api/cert/status ────────────────────────────────────────────────

/// On-wire shape for the `/api/cert/status` endpoint.
///
/// Field order is part of the operator-facing contract and is pinned by
/// unit tests — appending is fine, renaming or removing is a breaking
/// change.
#[derive(Debug, Serialize)]
pub(crate) struct CertStatus {
    /// Subject CN (X.509 subject commonName), if present.
    subject_cn: Option<String>,
    /// Issuer CN, if present — so operators can see which CA signed the
    /// current live leaf in a multi-CA environment.
    issuer_cn: Option<String>,
    /// `notBefore` in RFC 3339.
    not_before: String,
    /// `notAfter` in RFC 3339.
    not_after: String,
    /// Seconds from "now" until `notAfter`. Negative for expired certs;
    /// saturating, so wildly-future certs cannot overflow the i64.
    seconds_until_expiry: i64,
    /// `true` when the current wall time is within `notBefore..notAfter`.
    valid_now: bool,
    /// `true` when the certificate has expired.
    expired: bool,
    /// DNS SANs, sorted alphabetically and deduplicated.
    san_dns: Vec<String>,
    /// URI SANs, sorted alphabetically and deduplicated. Holds SPIFFE
    /// IDs when the leaf is a SPIFFE SVID.
    san_uri: Vec<String>,
    /// IP SANs, formatted as IPv4 dotted-quad or IPv6 canonical form.
    san_ip: Vec<String>,
}

fn cert_status(state: &MgmtApiState) -> Response<Full<Bytes>> {
    let Some(reloader) = state.cert_reloader.as_ref() else {
        return json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "certificate reloader not available",
        );
    };
    let Some(ckey) = reloader.certified_key() else {
        return json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "no active certified key on reloader",
        );
    };
    // `end_entity_cert()` returns the leaf from the chain — the cert
    // presented to clients during the TLS handshake. Chain intermediates
    // are ignored; operators asking "is my server cert expiring" want
    // the leaf's expiry, not an intermediate's.
    let leaf_der = match ckey.end_entity_cert() {
        Ok(der) => der,
        Err(e) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("no leaf certificate in chain: {e}"),
            );
        }
    };
    match build_cert_status(leaf_der.as_ref()) {
        Ok(status) => json_ok(&status),
        Err(msg) => json_error(StatusCode::INTERNAL_SERVER_ERROR, &msg),
    }
}

/// Parse a DER-encoded leaf and build a [`CertStatus`]. Exposed
/// `pub(crate)` so unit tests can drive it without spinning up a
/// full [`CertReloader`].
pub(crate) fn build_cert_status(der: &[u8]) -> Result<CertStatus, String> {
    let (_, cert) =
        X509Certificate::from_der(der).map_err(|e| format!("parse X.509 certificate: {e}"))?;

    let subject_cn = first_rdn_value(cert.subject(), &OID_X509_COMMON_NAME);
    let issuer_cn = first_rdn_value(cert.issuer(), &OID_X509_COMMON_NAME);
    let not_before = asn1_to_rfc3339(cert.validity().not_before)
        .map_err(|e| format!("render notBefore: {e}"))?;
    let not_after =
        asn1_to_rfc3339(cert.validity().not_after).map_err(|e| format!("render notAfter: {e}"))?;

    let now_ts = OffsetDateTime::now_utc().unix_timestamp();
    let not_before_ts = cert.validity().not_before.timestamp();
    let not_after_ts = cert.validity().not_after.timestamp();
    let valid_now = now_ts >= not_before_ts && now_ts <= not_after_ts;
    let expired = now_ts > not_after_ts;
    let seconds_until_expiry = not_after_ts.saturating_sub(now_ts);

    let mut san_dns: Vec<String> = Vec::new();
    let mut san_uri: Vec<String> = Vec::new();
    let mut san_ip: Vec<String> = Vec::new();
    for ext in cert.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
            for name in &san.general_names {
                match name {
                    GeneralName::DNSName(s) => san_dns.push((*s).to_string()),
                    GeneralName::URI(s) => san_uri.push((*s).to_string()),
                    GeneralName::IPAddress(bytes) => san_ip.push(format_ip(bytes)),
                    _ => {}
                }
            }
        }
    }
    san_dns.sort();
    san_dns.dedup();
    san_uri.sort();
    san_uri.dedup();
    san_ip.sort();
    san_ip.dedup();

    Ok(CertStatus {
        subject_cn,
        issuer_cn,
        not_before,
        not_after,
        seconds_until_expiry,
        valid_now,
        expired,
        san_dns,
        san_uri,
        san_ip,
    })
}

fn first_rdn_value(
    name: &X509Name<'_>,
    oid: &x509_parser::der_parser::oid::Oid<'_>,
) -> Option<String> {
    name.iter_by_oid(oid)
        .next()
        .and_then(|rdn| rdn.as_str().ok().map(|s| s.to_string()))
}

fn format_ip(bytes: &[u8]) -> String {
    match bytes.len() {
        4 => std::net::Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]).to_string(),
        16 => {
            let mut arr = [0u8; 16];
            arr.copy_from_slice(bytes);
            std::net::Ipv6Addr::from(arr).to_string()
        }
        _ => hex::encode(bytes),
    }
}

fn asn1_to_rfc3339(t: x509_parser::time::ASN1Time) -> Result<String, String> {
    let secs = t.timestamp();
    OffsetDateTime::from_unix_timestamp(secs)
        .map_err(|e| format!("unix timestamp {secs}: {e}"))?
        .format(&Rfc3339)
        .map_err(|e| format!("format rfc3339: {e}"))
}

// ── /api/crl/status ────────────────────────────────────────────────

/// On-wire shape for `/api/crl/status`.
///
/// `configured` is always present; the remaining fields are populated
/// only when a CRL file was supplied via `--crl` AND it could be parsed
/// at request time. A configured-but-failing CRL surfaces `error` with
/// a human-readable description (file not found, invalid PEM, etc.) and
/// `count` / `max_age_seconds` are `None`.
#[derive(Debug, Serialize)]
struct CrlStatus {
    /// `true` when the server was started with `--crl <path>`.
    configured: bool,
    /// Configured CRL path (even if currently unreadable). `None` when
    /// no CRL was configured.
    path: Option<String>,
    /// Number of CRL entries parsed from the file at request time.
    count: Option<usize>,
    /// Age in seconds of the stalest CRL's `thisUpdate` field. `None`
    /// when the file could not be re-parsed.
    max_age_seconds: Option<i64>,
    /// Human-readable parse/read error. `None` when the file parsed
    /// successfully.
    error: Option<String>,
}

fn crl_status(state: &MgmtApiState) -> Response<Full<Bytes>> {
    let Some(path) = state.crl_path.as_ref() else {
        return json_ok(&CrlStatus {
            configured: false,
            path: None,
            count: None,
            max_age_seconds: None,
            error: None,
        });
    };
    let display = path.display().to_string();
    match rustgate_transport::TlsConfig::validate_crl_file(&display) {
        Ok(summary) => json_ok(&CrlStatus {
            configured: true,
            path: Some(display),
            count: Some(summary.count),
            max_age_seconds: summary.max_age_seconds,
            error: None,
        }),
        Err(e) => json_ok(&CrlStatus {
            configured: true,
            path: Some(display),
            count: None,
            max_age_seconds: None,
            error: Some(e.to_string()),
        }),
    }
}

// ── /api/dedup/stats ───────────────────────────────────────────────

/// On-wire shape for `/api/dedup/stats`.
///
/// All fields are optional because the dedup cache is opt-in: a server
/// running without `--dedup-window` reports `enabled: false` and leaves
/// the counters unpopulated rather than returning a 404 (operators can
/// then programmatically distinguish "dedup off" from "dedup on, zero
/// traffic yet").
#[derive(Debug, Serialize)]
struct DedupStats {
    enabled: bool,
    entries: Option<usize>,
    duplicates_suppressed: Option<u64>,
    window_seconds: Option<u64>,
}

fn dedup_stats(state: &MgmtApiState) -> Response<Full<Bytes>> {
    match state.router.dedup_stats() {
        Some((hits, entries)) => json_ok(&DedupStats {
            enabled: true,
            entries: Some(entries),
            duplicates_suppressed: Some(hits),
            window_seconds: state.router.dedup_window_seconds(),
        }),
        None => json_ok(&DedupStats {
            enabled: false,
            entries: None,
            duplicates_suppressed: None,
            window_seconds: None,
        }),
    }
}

// ── /api/clients/{cn}/disconnect ───────────────────────────────────

/// On-wire shape for the `/api/clients/{cn}/disconnect` endpoint.
#[derive(Debug, Serialize)]
struct DisconnectResult {
    /// Echo of the CN that was the disconnect target. Helpful when the
    /// operator scripts a batch disconnect and wants to correlate
    /// responses with the input list.
    cn: String,
    /// `true` when a session matching `cn` was found and its writer
    /// channels were signalled to drain. `false` when no session was
    /// registered under that CN — either it already disconnected or the
    /// CN never matched a live client. Both are reported with `200 OK`
    /// because "not connected" is a normal, not-exceptional state for
    /// this endpoint.
    disconnected: bool,
}

async fn disconnect_client_handler(cn: &str, state: &MgmtApiState) -> Response<Full<Bytes>> {
    // Reject an empty CN segment (`/api/clients//disconnect`) with a
    // structured 400 rather than falling into the Router and returning
    // a misleading `disconnected: false`.
    if cn.is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "client CN must not be empty");
    }
    let disconnected = state.router.disconnect_client(cn).await;
    json_ok(&DisconnectResult {
        cn: cn.to_string(),
        disconnected,
    })
}

// ── /api/dlq/{target}/replay ───────────────────────────────────────

/// On-wire response for `POST /api/dlq/{target}/replay`.
///
/// The endpoint is fire-and-forget — `triggered: true` means "the
/// drain worker has been notified", not "the drain has completed".
/// Operators can poll `/metrics` for `rustgate_http_dlq_replayed_total`
/// to observe progress.
#[cfg(feature = "http")]
#[derive(Debug, Serialize)]
struct DlqReplayResult {
    /// Echo of the requested target name. Round-trips so operators
    /// scripting the endpoint can correlate the request with the
    /// response without re-parsing the URL.
    target: String,
    /// `true` when the drain trigger was successfully enqueued.
    /// Always `true` in a `200` response — error cases use
    /// `json_error` and do not return this struct.
    triggered: bool,
}

#[cfg(feature = "http")]
fn dlq_replay_handler(target: &str, state: &MgmtApiState) -> Response<Full<Bytes>> {
    if target.is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "target name must not be empty");
    }
    let Some(publisher) = state.http_publisher.as_ref() else {
        return json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "HTTP publisher not configured",
        );
    };
    match publisher.trigger_drain(target) {
        Ok(()) => {
            rustgate_core::audit::http_dlq_drain_started(target, 0);
            json_ok(&DlqReplayResult {
                target: target.to_string(),
                triggered: true,
            })
        }
        Err(rustgate_http::TriggerDrainError::DlqNotConfigured) => json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "DLQ not configured on HTTP publisher",
        ),
        Err(rustgate_http::TriggerDrainError::UnknownTarget) => {
            json_error(StatusCode::NOT_FOUND, "unknown HTTP target")
        }
        Err(rustgate_http::TriggerDrainError::ChannelFull) => json_error(
            StatusCode::TOO_MANY_REQUESTS,
            "drain trigger channel is full; another drain is in flight",
        ),
        Err(rustgate_http::TriggerDrainError::ChannelClosed) => json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "drain trigger channel is closed; publisher is shutting down",
        ),
    }
}

// ── /api/reload ────────────────────────────────────────────────────

async fn reload_handler(state: &MgmtApiState) -> Response<Full<Bytes>> {
    let Some(reload) = state.reload.as_ref() else {
        // No reloadable components are configured — the server is
        // running with purely static config and SIGHUP would also be a
        // no-op. Surface that as 503 rather than pretending a reload
        // succeeded.
        return json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "reload not available: no reloadable components configured",
        );
    };
    let report = reload().await;
    json_ok(&report)
}

// ── /api/drain ────────────────────────────────────────────────────

/// On-wire response for `POST /api/drain`.
///
/// `status` is always the literal `"drain_initiated"` on the success
/// path so a Kubernetes preStop hook script can pin a single string
/// match and keep working across rustgate versions; `source` echoes
/// the literal token the audit event records, which is the same
/// token operators see in their SIEM trail and dashboards.
#[derive(Debug, Serialize)]
struct DrainResult {
    /// Always `"drain_initiated"` on the success path. The endpoint
    /// returns immediately after firing the shutdown notify — completion
    /// is observable via the rustgate process exiting and existing
    /// SubsystemHandle drain logs, not via this response.
    status: &'static str,
    /// Mirrors the `source` field on the emitted audit event so log /
    /// metric / response stay aligned for forensic correlation.
    source: &'static str,
}

/// Initiate a graceful drain — fires the shared shutdown `Notify` that
/// drives the same SubsystemHandle path SIGTERM would. Returns
/// IMMEDIATELY after the `notify_one()` call; the K8s preStop hook is
/// expected to `sleep` separately if a bounded wait is required (the
/// rustgate drain itself runs under the SubsystemHandle 5s grace
/// timeout). Closes #791.
fn drain_handler(state: &MgmtApiState) -> Response<Full<Bytes>> {
    // The audit emission and metric increment run BEFORE notify_one()
    // so a forensic trail exists even if the process panics during
    // drain — operators can correlate the API call with the eventual
    // exit even when the post-notify path produced no further logs.
    rustgate_core::audit::admin_drain_triggered("api");
    #[cfg(feature = "metrics")]
    crate::metrics::admin_drain_triggered()
        .with_label_values(&["api"])
        .inc();
    state.drain_notify.notify_one();
    json_ok(&DrainResult {
        status: "drain_initiated",
        source: "api",
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use std::sync::Arc;

    use rustgate_test_utils::certs::TestCa;
    use rustls_pki_types::CertificateDer;
    use rustls_pki_types::pem::PemObject;

    use super::*;

    fn token() -> Zeroizing<Vec<u8>> {
        Zeroizing::new(b"unit-test-token-padded-to-enough-bytes-to-pass-bounds".to_vec())
    }

    #[test]
    fn auth_ok_rejects_missing_header() {
        assert!(!auth_ok(None, token().as_slice()));
    }

    #[test]
    fn auth_ok_rejects_non_bearer_prefix() {
        let t = token();
        let hdr = String::from_utf8(t.to_vec()).unwrap();
        // No "Bearer " prefix → reject even though the raw bytes match.
        assert!(!auth_ok(Some(&hdr), t.as_slice()));
    }

    #[test]
    fn auth_ok_accepts_matching_bearer() {
        let t = token();
        let hdr = format!("Bearer {}", String::from_utf8(t.to_vec()).unwrap());
        assert!(auth_ok(Some(&hdr), t.as_slice()));
    }

    #[test]
    fn auth_ok_rejects_wrong_token() {
        let t = token();
        assert!(!auth_ok(
            Some("Bearer wrong-token-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
            t.as_slice()
        ));
    }

    fn state_with(crl_path: Option<PathBuf>) -> MgmtApiState {
        MgmtApiState {
            router: Arc::new(Router::new()),
            cert_reloader: None,
            crl_path,
            reload: None,
            #[cfg(feature = "http")]
            http_publisher: None,
            drain_notify: Arc::new(tokio::sync::Notify::new()),
            auth_token: token(),
        }
    }

    #[test]
    fn mgmt_path_prefixes_cover_all_endpoints() {
        // The dispatcher in metrics.rs uses MGMT_PATH_PREFIXES and
        // MGMT_EXACT_PATHS to decide whether to route to this handler
        // at all. Pin the set so a new endpoint added to `route()`
        // cannot silently become 404 because its prefix was forgotten
        // here.
        assert!(
            MGMT_PATH_PREFIXES
                .iter()
                .any(|p| "/api/cert/status".starts_with(p))
        );
        assert!(
            MGMT_PATH_PREFIXES
                .iter()
                .any(|p| "/api/crl/status".starts_with(p))
        );
        assert!(
            MGMT_PATH_PREFIXES
                .iter()
                .any(|p| "/api/dedup/stats".starts_with(p))
        );
        assert!(
            MGMT_PATH_PREFIXES
                .iter()
                .any(|p| "/api/clients/alice/disconnect".starts_with(p))
        );
        assert!(
            MGMT_PATH_PREFIXES
                .iter()
                .any(|p| "/api/dlq/webhook-prod/replay".starts_with(p))
        );
        // Bare-path routes (no trailing slash) live in MGMT_EXACT_PATHS
        // — closes #791 added `/api/drain`.
        assert!(MGMT_EXACT_PATHS.contains(&"/api/reload"));
        assert!(MGMT_EXACT_PATHS.contains(&"/api/drain"));
    }

    #[tokio::test]
    async fn unknown_prefix_returns_none() {
        let state = state_with(None);
        let resp = handle_request(
            &Method::GET,
            "/metrics",
            Some("Bearer anything"),
            &[],
            &state,
        )
        .await;
        assert!(resp.is_none(), "non-mgmt path should fall through");
    }

    #[tokio::test]
    async fn missing_auth_header_returns_401() {
        let state = state_with(None);
        let resp = handle_request(&Method::GET, "/api/dedup/stats", None, &[], &state)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn wrong_method_on_known_endpoint_returns_405() {
        let state = state_with(None);
        let t = token();
        let hdr = format!("Bearer {}", String::from_utf8(t.to_vec()).unwrap());
        let resp = handle_request(&Method::POST, "/api/dedup/stats", Some(&hdr), &[], &state)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn unknown_suffix_under_mgmt_prefix_returns_404() {
        let state = state_with(None);
        let t = token();
        let hdr = format!("Bearer {}", String::from_utf8(t.to_vec()).unwrap());
        let resp = handle_request(
            &Method::GET,
            "/api/cert/does-not-exist",
            Some(&hdr),
            &[],
            &state,
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn cert_status_without_reloader_returns_service_unavailable() {
        let state = state_with(None);
        let t = token();
        let hdr = format!("Bearer {}", String::from_utf8(t.to_vec()).unwrap());
        let resp = handle_request(&Method::GET, "/api/cert/status", Some(&hdr), &[], &state)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn crl_status_returns_configured_false_when_no_crl_configured() {
        let state = state_with(None);
        let t = token();
        let hdr = format!("Bearer {}", String::from_utf8(t.to_vec()).unwrap());
        let resp = handle_request(&Method::GET, "/api/crl/status", Some(&hdr), &[], &state)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = extract_json_body(resp).await;
        let data = body.get("data").unwrap();
        assert!(!data.get("configured").unwrap().as_bool().unwrap());
        assert!(data.get("path").unwrap().is_null());
    }

    #[tokio::test]
    async fn crl_status_reports_error_for_missing_file() {
        let state = state_with(Some(PathBuf::from("/definitely/not/a/real/crl/path.pem")));
        let t = token();
        let hdr = format!("Bearer {}", String::from_utf8(t.to_vec()).unwrap());
        let resp = handle_request(&Method::GET, "/api/crl/status", Some(&hdr), &[], &state)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = extract_json_body(resp).await;
        let data = body.get("data").unwrap();
        assert!(data.get("configured").unwrap().as_bool().unwrap());
        assert!(data.get("error").unwrap().is_string());
        assert!(data.get("count").unwrap().is_null());
    }

    #[tokio::test]
    async fn dedup_stats_returns_disabled_when_router_has_no_cache() {
        let state = state_with(None);
        let t = token();
        let hdr = format!("Bearer {}", String::from_utf8(t.to_vec()).unwrap());
        let resp = handle_request(&Method::GET, "/api/dedup/stats", Some(&hdr), &[], &state)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = extract_json_body(resp).await;
        let data = body.get("data").unwrap();
        assert!(!data.get("enabled").unwrap().as_bool().unwrap());
        assert!(data.get("entries").unwrap().is_null());
    }

    #[tokio::test]
    async fn disconnect_unknown_cn_returns_ok_with_disconnected_false() {
        // No session registered → disconnect is a no-op, reported as
        // `disconnected: false` with a 200. "Not connected" is normal
        // state for this endpoint, not an error.
        let state = state_with(None);
        let t = token();
        let hdr = format!("Bearer {}", String::from_utf8(t.to_vec()).unwrap());
        let resp = handle_request(
            &Method::POST,
            "/api/clients/ghost/disconnect",
            Some(&hdr),
            &[],
            &state,
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = extract_json_body(resp).await;
        let data = body.get("data").unwrap();
        assert_eq!(data.get("cn").unwrap().as_str().unwrap(), "ghost");
        assert!(!data.get("disconnected").unwrap().as_bool().unwrap());
    }

    #[tokio::test]
    async fn disconnect_wrong_method_returns_405() {
        let state = state_with(None);
        let t = token();
        let hdr = format!("Bearer {}", String::from_utf8(t.to_vec()).unwrap());
        let resp = handle_request(
            &Method::GET,
            "/api/clients/alice/disconnect",
            Some(&hdr),
            &[],
            &state,
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn disconnect_empty_cn_returns_400() {
        let state = state_with(None);
        let t = token();
        let hdr = format!("Bearer {}", String::from_utf8(t.to_vec()).unwrap());
        let resp = handle_request(
            &Method::POST,
            "/api/clients//disconnect",
            Some(&hdr),
            &[],
            &state,
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn reload_without_callback_returns_503() {
        // A server with no reloadable components configured reports
        // 503 rather than a fake-success no-op — matching the
        // operator expectation that "reload" implies work happened.
        let state = state_with(None);
        let t = token();
        let hdr = format!("Bearer {}", String::from_utf8(t.to_vec()).unwrap());
        let resp = handle_request(&Method::POST, "/api/reload", Some(&hdr), &[], &state)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn reload_wrong_method_returns_405() {
        let state = state_with(None);
        let t = token();
        let hdr = format!("Bearer {}", String::from_utf8(t.to_vec()).unwrap());
        let resp = handle_request(&Method::GET, "/api/reload", Some(&hdr), &[], &state)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn reload_callback_is_driven_and_body_is_returned() {
        // Install a stub reload callback that returns a canned JSON
        // payload and verify the handler wraps it in the envelope.
        let mut state = state_with(None);
        state.reload = Some(Arc::new(|| {
            Box::pin(async {
                serde_json::json!({
                    "cert": {"result": "skipped"},
                    "acl":  {"result": "success", "changed": true},
                })
            })
        }));
        let t = token();
        let hdr = format!("Bearer {}", String::from_utf8(t.to_vec()).unwrap());
        let resp = handle_request(&Method::POST, "/api/reload", Some(&hdr), &[], &state)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = extract_json_body(resp).await;
        let data = body.get("data").unwrap();
        assert_eq!(
            data.get("cert")
                .and_then(|v| v.get("result"))
                .and_then(|v| v.as_str()),
            Some("skipped")
        );
        assert_eq!(
            data.get("acl")
                .and_then(|v| v.get("result"))
                .and_then(|v| v.as_str()),
            Some("success")
        );
    }

    #[test]
    fn build_cert_status_parses_leaf_and_surfaces_cn_and_sans() {
        // Drive the parser directly with a freshly-issued test cert so
        // the happy path is pinned without needing a live CertReloader.
        let ca = TestCa::new("mgmt-api-test-ca");
        let server = ca.issue_server_cert("example.test", &["example.test", "alt.test"]);
        let leaf_der: CertificateDer<'static> =
            CertificateDer::pem_slice_iter(server.cert_pem.as_bytes())
                .next()
                .unwrap()
                .unwrap();
        let status = build_cert_status(leaf_der.as_ref()).unwrap();
        assert_eq!(status.subject_cn.as_deref(), Some("example.test"));
        assert!(status.san_dns.contains(&"example.test".to_string()));
        assert!(status.san_dns.contains(&"alt.test".to_string()));
        assert!(status.valid_now);
        assert!(!status.expired);
        assert!(status.seconds_until_expiry > 0);
        // RFC 3339 timestamps always include 'T' between date and time.
        assert!(status.not_before.contains('T'));
        assert!(status.not_after.contains('T'));
    }

    #[test]
    fn debug_redacts_bearer_token() {
        // Safety: the bearer token must never appear in `{:?}`
        // — that would leak into logs and panic messages. Redaction is
        // a tested property, not an incidental one.
        let state = state_with(None);
        let rendered = format!("{state:?}");
        assert!(
            !rendered.contains("unit-test-token"),
            "token leaked: {rendered}"
        );
    }

    async fn extract_json_body(resp: Response<Full<Bytes>>) -> serde_json::Value {
        use http_body_util::BodyExt;
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    // ── /api/dlq/{target}/replay (issue #881 PR C) ─────────────────

    /// Without a configured publisher the endpoint returns `503` so
    /// operators get a precise "not configured" signal rather than a
    /// misleading `404` (which would imply the path is wrong).
    #[cfg(feature = "http")]
    #[tokio::test]
    async fn dlq_replay_without_publisher_returns_503() {
        let state = state_with(None);
        let t = token();
        let hdr = format!("Bearer {}", String::from_utf8(t.to_vec()).unwrap());
        let resp = handle_request(
            &Method::POST,
            "/api/dlq/whatever/replay",
            Some(&hdr),
            &[],
            &state,
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = extract_json_body(resp).await;
        assert!(
            body.get("error")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .contains("HTTP publisher"),
            "got: {body}"
        );
    }

    /// Wrong method on the DLQ replay path is `405` — the path matches
    /// a known endpoint shape, just not for that verb.
    #[cfg(feature = "http")]
    #[tokio::test]
    async fn dlq_replay_wrong_method_returns_405() {
        let state = state_with(None);
        let t = token();
        let hdr = format!("Bearer {}", String::from_utf8(t.to_vec()).unwrap());
        let resp = handle_request(
            &Method::GET,
            "/api/dlq/anything/replay",
            Some(&hdr),
            &[],
            &state,
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    /// `POST /api/dlq//replay` (empty target segment) is a structured
    /// `400` rather than falling through to the publisher with an
    /// empty string — operators get a precise diagnostic.
    #[cfg(feature = "http")]
    #[tokio::test]
    async fn dlq_replay_empty_target_returns_400() {
        // Build a publisher so the handler doesn't short-circuit on
        // "publisher not configured" before checking the empty-target
        // guard.
        let publisher = build_test_publisher_with_target("any");
        let state = MgmtApiState {
            router: Arc::new(Router::new()),
            cert_reloader: None,
            crl_path: None,
            reload: None,
            http_publisher: Some(publisher.clone()),
            drain_notify: Arc::new(tokio::sync::Notify::new()),
            auth_token: token(),
        };
        let t = token();
        let hdr = format!("Bearer {}", String::from_utf8(t.to_vec()).unwrap());
        let resp = handle_request(&Method::POST, "/api/dlq//replay", Some(&hdr), &[], &state)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        publisher.shutdown().await;
    }

    /// Unknown target name surfaces as `404` so operator tooling can
    /// distinguish a typo from a configuration drift.
    #[cfg(feature = "http")]
    #[tokio::test]
    async fn dlq_replay_unknown_target_returns_404() {
        let publisher = build_test_publisher_with_target("webhook-prod");
        let state = MgmtApiState {
            router: Arc::new(Router::new()),
            cert_reloader: None,
            crl_path: None,
            reload: None,
            http_publisher: Some(publisher.clone()),
            drain_notify: Arc::new(tokio::sync::Notify::new()),
            auth_token: token(),
        };
        let t = token();
        let hdr = format!("Bearer {}", String::from_utf8(t.to_vec()).unwrap());
        let resp = handle_request(
            &Method::POST,
            "/api/dlq/no-such-target/replay",
            Some(&hdr),
            &[],
            &state,
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let body = extract_json_body(resp).await;
        assert_eq!(
            body.get("error").and_then(|v| v.as_str()),
            Some("unknown HTTP target")
        );
        publisher.shutdown().await;
    }

    /// Happy path: a valid target on a publisher with DLQ configured
    /// returns `200` and the JSON envelope echoes the target name.
    #[cfg(feature = "http")]
    #[tokio::test]
    async fn dlq_replay_known_target_returns_200() {
        let publisher = build_test_publisher_with_target("webhook-prod");
        let state = MgmtApiState {
            router: Arc::new(Router::new()),
            cert_reloader: None,
            crl_path: None,
            reload: None,
            http_publisher: Some(publisher.clone()),
            drain_notify: Arc::new(tokio::sync::Notify::new()),
            auth_token: token(),
        };
        let t = token();
        let hdr = format!("Bearer {}", String::from_utf8(t.to_vec()).unwrap());
        let resp = handle_request(
            &Method::POST,
            "/api/dlq/webhook-prod/replay",
            Some(&hdr),
            &[],
            &state,
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = extract_json_body(resp).await;
        let data = body.get("data").expect("envelope.data");
        assert_eq!(
            data.get("target").and_then(|v| v.as_str()),
            Some("webhook-prod")
        );
        assert_eq!(data.get("triggered").and_then(|v| v.as_bool()), Some(true));
        publisher.shutdown().await;
    }

    /// Auth still applies to the DLQ replay endpoint — pin the 401
    /// behaviour so a future refactor that accidentally moves the
    /// auth check out of `handle_request` fails loudly.
    #[cfg(feature = "http")]
    #[tokio::test]
    async fn dlq_replay_without_auth_returns_401() {
        let state = state_with(None);
        let resp = handle_request(&Method::POST, "/api/dlq/anything/replay", None, &[], &state)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // ── /api/drain (issue #791) ────────────────────────────────────

    /// Happy path — a valid bearer token returns `200` with the pinned
    /// JSON envelope. The status string is part of the operator
    /// contract: K8s preStop scripts grep for `"drain_initiated"` to
    /// gate the subsequent `sleep` step, so the test pins the literal
    /// rather than just `is_string()`.
    #[tokio::test]
    async fn admin_drain_returns_200_with_valid_token() {
        let state = state_with(None);
        let t = token();
        let hdr = format!("Bearer {}", String::from_utf8(t.to_vec()).unwrap());
        let resp = handle_request(&Method::POST, "/api/drain", Some(&hdr), &[], &state)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = extract_json_body(resp).await;
        let data = body.get("data").expect("envelope.data");
        assert_eq!(
            data.get("status").and_then(|v| v.as_str()),
            Some("drain_initiated"),
        );
        assert_eq!(data.get("source").and_then(|v| v.as_str()), Some("api"),);
    }

    /// The endpoint is bearer-auth-gated — pin the 401 boundary so a
    /// future refactor that accidentally moves the auth check out of
    /// `handle_request` cannot silently expose drain to anonymous
    /// callers (which would let any cluster pod with metrics-port
    /// connectivity terminate the server).
    #[tokio::test]
    async fn admin_drain_returns_401_without_token() {
        let state = state_with(None);
        let resp = handle_request(&Method::POST, "/api/drain", None, &[], &state)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// Drain increments `rustgate_admin_drain_triggered_total{source="api"}`
    /// so dashboards can graph operator-driven drains. Pin pre/post
    /// counter values rather than absolute reads — the metric is a
    /// process-wide singleton and other tests may have advanced it.
    #[cfg(feature = "metrics")]
    #[tokio::test]
    async fn admin_drain_increments_metric() {
        // Drive the full HTTP path so a regression that moves the
        // metric increment out of `drain_handler` is caught by the
        // strict +1 delta. The metric is a process-wide singleton,
        // so the snapshot-then-call-then-snapshot pattern protects
        // against test parallelism advancing it under us.
        let counter = crate::metrics::admin_drain_triggered().with_label_values(&["api"]);
        let before = counter.get();
        let state = state_with(None);
        let t = token();
        let hdr = format!("Bearer {}", String::from_utf8(t.to_vec()).unwrap());
        let resp = handle_request(&Method::POST, "/api/drain", Some(&hdr), &[], &state)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let after = counter.get();
        assert!(
            after > before,
            "metric must advance by at least 1: before={before} after={after}"
        );
    }

    /// Drain emits `audit::admin_drain_triggered("api")` so SIEM rules
    /// can attribute API-driven drains separately from SIGTERM-driven
    /// ones. The wire shape of the emitted record (`event_type`,
    /// `action`, `result`, `source`) is pinned by the integration
    /// test in `tests/admin_drain_audit.rs`; this unit test pins
    /// only that the HTTP route reaches the audit emission
    /// codepath without panicking under a thread-local subscriber.
    /// The integration-test boundary is required because tracing
    /// caches per-callsite `Interest` globally and a thread-local
    /// subscriber installed in a unit test cannot capture an
    /// audit-target event whose Interest was already cached as
    /// `never` by an earlier sibling test in the same binary —
    /// same rationale as `tests/store_forward_dwell_audit.rs` and
    /// `tests/position_replay_rate_limit_audit.rs`.
    #[tokio::test]
    async fn admin_drain_emits_audit_event() {
        // Smoke-test that the route reaches the audit emission
        // without panicking. The audit-record wire shape is pinned
        // in the integration test where the Interest cache is fresh.
        let state = state_with(None);
        let t = token();
        let hdr = format!("Bearer {}", String::from_utf8(t.to_vec()).unwrap());
        let resp = handle_request(&Method::POST, "/api/drain", Some(&hdr), &[], &state)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        // The audit fn is reachable from this test binary —
        // calling it directly does not error.
        rustgate_core::audit::admin_drain_triggered("api");
    }

    /// The drain endpoint must fire the shared shutdown notify so the
    /// accept loop exits and the SubsystemHandle drain runs. Pin the
    /// invariant by awaiting the same notifier with a bounded timeout
    /// — a regression that no-ops the `notify_one()` would hang the
    /// test until timeout, and the timeout itself is what fails the
    /// test.
    #[tokio::test]
    async fn admin_drain_triggers_shutdown_notify() {
        let notify = Arc::new(tokio::sync::Notify::new());
        let state = MgmtApiState {
            router: Arc::new(Router::new()),
            cert_reloader: None,
            crl_path: None,
            reload: None,
            #[cfg(feature = "http")]
            http_publisher: None,
            drain_notify: Arc::clone(&notify),
            auth_token: token(),
        };
        let t = token();
        let hdr = format!("Bearer {}", String::from_utf8(t.to_vec()).unwrap());

        // Park a `notified()` waiter BEFORE calling the endpoint —
        // `tokio::sync::Notify::notify_one()` only wakes a permit if a
        // waiter is already registered; absent that, the permit is
        // stored and the next `notified()` call returns immediately.
        // Either ordering should satisfy the contract, but registering
        // first proves the wake-up path works without relying on the
        // permit-storage fallback.
        let waiter = Arc::clone(&notify);
        let task = tokio::spawn(async move {
            tokio::time::timeout(std::time::Duration::from_secs(1), waiter.notified()).await
        });
        // Yield so the spawned task has a chance to register its
        // waiter before we fire the notify.
        tokio::task::yield_now().await;

        let resp = handle_request(&Method::POST, "/api/drain", Some(&hdr), &[], &state)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // The waiter must observe the notify within 1s — the actual
        // wake-up should be sub-millisecond, the timeout exists to
        // turn a regression (notify never fires) into a hard failure.
        let outcome = task.await.expect("waiter task must not panic");
        assert!(
            outcome.is_ok(),
            "drain_notify must fire within the bounded window"
        );
    }

    /// `GET /api/drain` is `405`, not `404`. The path matches a known
    /// endpoint shape, just not for that verb — surface the
    /// distinction to operators so a script that types the wrong verb
    /// gets a precise diagnostic instead of a misleading "no such
    /// endpoint" signal.
    #[tokio::test]
    async fn admin_drain_wrong_method_returns_405() {
        let state = state_with(None);
        let t = token();
        let hdr = format!("Bearer {}", String::from_utf8(t.to_vec()).unwrap());
        let resp = handle_request(&Method::GET, "/api/drain", Some(&hdr), &[], &state)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    /// The endpoint MUST return immediately after firing the notify —
    /// the K8s preStop hook can sleep separately if a bounded wait is
    /// required, but blocking on drain completion inside the handler
    /// would either keep the response open past the kubelet's preStop
    /// timeout or serialize concurrent drain calls. 100ms is two
    /// orders of magnitude looser than the actual hot-path latency
    /// (which is the cost of a `notify_one()` plus JSON serde) and
    /// exists to turn a regression into a hard failure.
    #[tokio::test]
    async fn admin_drain_does_not_block_on_completion() {
        let state = state_with(None);
        let t = token();
        let hdr = format!("Bearer {}", String::from_utf8(t.to_vec()).unwrap());
        let start = std::time::Instant::now();
        let resp = handle_request(&Method::POST, "/api/drain", Some(&hdr), &[], &state)
            .await
            .unwrap();
        let elapsed = start.elapsed();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(
            elapsed < std::time::Duration::from_millis(100),
            "drain handler must not block on completion; took {elapsed:?}"
        );
    }

    /// Build a minimal publisher with a single named target and a
    /// DLQ configured under a tempdir. The `TempDir` is deliberately
    /// leaked via `Box::leak` so the key file outlives any background
    /// drain reader for the duration of the test process — drop
    /// ordering on tokio runtime shutdown is otherwise racy.
    #[cfg(feature = "http")]
    fn build_test_publisher_with_target(target_name: &str) -> rustgate_http::HttpPublisher {
        let tmp = tempfile::tempdir().unwrap();
        let key_json = r#"{
            "active_key_id": "k",
            "keys": { "k": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }
        }"#;
        let key_path = tmp.path().join("keys.json");
        std::fs::write(&key_path, key_json).unwrap();
        let dlq_dir = tmp.path().join("dlq");

        let config = rustgate_http::HttpConfig {
            instance_id: Some("mgmt-api-test".to_string()),
            targets: vec![rustgate_http::config::TargetConfig {
                name: target_name.to_string(),
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
            }],
            dlq_dir: Some(dlq_dir.to_string_lossy().into_owned()),
            dlq_key_file: Some(key_path.to_string_lossy().into_owned()),
            dlq_max_bytes: None,
            dlq_max_target_bytes: None,
            allow_private_urls: true,
        };
        let publisher = rustgate_http::HttpPublisher::new(config).unwrap();
        // Leak the tempdir so the key file outlives the publisher's
        // background workers — the alternative is racy drop ordering
        // when the tokio runtime tears down at end-of-test.
        std::mem::forget(tmp);
        publisher
    }
}
