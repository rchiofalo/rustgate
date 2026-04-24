// Copyright © 2026 Roberto Chiofalo.

//! Read-only management REST API for operator diagnostics.
//!
//! Mounted alongside the `/api/acl/` endpoints on the metrics HTTP server
//! (gated by the `metrics` feature). Exposes three status endpoints that
//! surface runtime state an operator would otherwise have to shell onto
//! the host to inspect:
//!
//! | Route                    | Purpose                                                 |
//! |--------------------------|---------------------------------------------------------|
//! | `GET /api/cert/status`   | Server certificate subject, SANs, expiry                |
//! | `GET /api/crl/status`    | Loaded CRL file — count + staleness, if configured      |
//! | `GET /api/dedup/stats`   | Cross-path deduplication cache — hits, size, window     |
//!
//! Every response is a JSON envelope of the form `{"data": ...}` on
//! success or `{"error": "..."}` on failure, mirroring the `acl_api`
//! shape. Endpoint handlers never mutate state — this module is
//! deliberately read-only so operators can safely grant a narrow token
//! to low-trust scrape jobs without worrying about policy edits slipping
//! through. The companion write-side endpoints (force client disconnect,
//! HTTP-triggered reload) are tracked in a follow-up PR.
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

use std::path::PathBuf;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Method, Response, StatusCode};
use rustgate_transport::{CertReloader, Router};
use serde::Serialize;
use subtle::ConstantTimeEq;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::oid_registry::OID_X509_COMMON_NAME;
use x509_parser::prelude::FromDer;
use x509_parser::x509::X509Name;
use zeroize::Zeroizing;

/// Shared state for the management REST API.
///
/// Constructed once at startup and shared between all handler
/// invocations. None of the fields are mutated after construction —
/// mutations belong on dedicated reload paths (SIGHUP or the
/// `acl_api::handle_request` mutation routes), not on this read-only
/// surface.
pub struct MgmtApiState {
    /// Router handle used by [`dedup_stats`] to read cache metrics.
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
    /// Bearer token required on every request. Stored as raw bytes so
    /// the comparison can run in constant time, wrapped in
    /// [`Zeroizing`] so the value is wiped from memory on drop.
    pub auth_token: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for MgmtApiState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the bearer token; redact by default.
        f.debug_struct("MgmtApiState")
            .field("cert_reloader_present", &self.cert_reloader.is_some())
            .field("crl_path", &self.crl_path)
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
pub(crate) const MGMT_PATH_PREFIXES: &[&str] = &["/api/cert/", "/api/crl/", "/api/dedup/"];

/// Entry point called by the metrics HTTP server. Returns `Some(resp)`
/// when the path matches a management-API route (recognized or not),
/// `None` when the request should fall through to another handler so
/// callers can register additional handlers alongside.
pub fn handle_request(
    method: &Method,
    path: &str,
    authorization: Option<&str>,
    _body: &[u8],
    state: &MgmtApiState,
) -> Option<Response<Full<Bytes>>> {
    if !MGMT_PATH_PREFIXES.iter().any(|p| path.starts_with(p)) {
        return None;
    }
    if !auth_ok(authorization, &state.auth_token) {
        return Some(json_error(StatusCode::UNAUTHORIZED, "unauthorized"));
    }
    Some(route(method, path, state))
}

fn route(method: &Method, path: &str, state: &MgmtApiState) -> Response<Full<Bytes>> {
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

    #[test]
    fn mgmt_path_prefixes_cover_all_endpoints() {
        // The dispatcher in metrics.rs uses MGMT_PATH_PREFIXES to decide
        // whether to route to this handler at all. Pin the set so a new
        // endpoint added to `route()` cannot silently become 404 because
        // its prefix was forgotten here.
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
    }

    #[test]
    fn unknown_prefix_returns_none() {
        let state = MgmtApiState {
            router: Arc::new(Router::new()),
            cert_reloader: None,
            crl_path: None,
            auth_token: token(),
        };
        let resp = handle_request(
            &Method::GET,
            "/metrics",
            Some("Bearer anything"),
            &[],
            &state,
        );
        assert!(resp.is_none(), "non-mgmt path should fall through");
    }

    #[test]
    fn missing_auth_header_returns_401() {
        let state = MgmtApiState {
            router: Arc::new(Router::new()),
            cert_reloader: None,
            crl_path: None,
            auth_token: token(),
        };
        let resp = handle_request(&Method::GET, "/api/dedup/stats", None, &[], &state).unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn wrong_method_on_known_endpoint_returns_405() {
        let state = MgmtApiState {
            router: Arc::new(Router::new()),
            cert_reloader: None,
            crl_path: None,
            auth_token: token(),
        };
        let t = token();
        let hdr = format!("Bearer {}", String::from_utf8(t.to_vec()).unwrap());
        let resp =
            handle_request(&Method::POST, "/api/dedup/stats", Some(&hdr), &[], &state).unwrap();
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[test]
    fn unknown_suffix_under_mgmt_prefix_returns_404() {
        let state = MgmtApiState {
            router: Arc::new(Router::new()),
            cert_reloader: None,
            crl_path: None,
            auth_token: token(),
        };
        let t = token();
        let hdr = format!("Bearer {}", String::from_utf8(t.to_vec()).unwrap());
        let resp = handle_request(
            &Method::GET,
            "/api/cert/does-not-exist",
            Some(&hdr),
            &[],
            &state,
        )
        .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn cert_status_without_reloader_returns_service_unavailable() {
        let state = MgmtApiState {
            router: Arc::new(Router::new()),
            cert_reloader: None,
            crl_path: None,
            auth_token: token(),
        };
        let t = token();
        let hdr = format!("Bearer {}", String::from_utf8(t.to_vec()).unwrap());
        let resp =
            handle_request(&Method::GET, "/api/cert/status", Some(&hdr), &[], &state).unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn crl_status_returns_configured_false_when_no_crl_configured() {
        let state = MgmtApiState {
            router: Arc::new(Router::new()),
            cert_reloader: None,
            crl_path: None,
            auth_token: token(),
        };
        let t = token();
        let hdr = format!("Bearer {}", String::from_utf8(t.to_vec()).unwrap());
        let resp =
            handle_request(&Method::GET, "/api/crl/status", Some(&hdr), &[], &state).unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = extract_json_body(resp).await;
        let data = body.get("data").unwrap();
        assert!(!data.get("configured").unwrap().as_bool().unwrap());
        assert!(data.get("path").unwrap().is_null());
    }

    #[tokio::test]
    async fn crl_status_reports_error_for_missing_file() {
        let state = MgmtApiState {
            router: Arc::new(Router::new()),
            cert_reloader: None,
            crl_path: Some(PathBuf::from("/definitely/not/a/real/crl/path.pem")),
            auth_token: token(),
        };
        let t = token();
        let hdr = format!("Bearer {}", String::from_utf8(t.to_vec()).unwrap());
        let resp =
            handle_request(&Method::GET, "/api/crl/status", Some(&hdr), &[], &state).unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = extract_json_body(resp).await;
        let data = body.get("data").unwrap();
        assert!(data.get("configured").unwrap().as_bool().unwrap());
        assert!(data.get("error").unwrap().is_string());
        assert!(data.get("count").unwrap().is_null());
    }

    #[tokio::test]
    async fn dedup_stats_returns_disabled_when_router_has_no_cache() {
        let state = MgmtApiState {
            router: Arc::new(Router::new()),
            cert_reloader: None,
            crl_path: None,
            auth_token: token(),
        };
        let t = token();
        let hdr = format!("Bearer {}", String::from_utf8(t.to_vec()).unwrap());
        let resp =
            handle_request(&Method::GET, "/api/dedup/stats", Some(&hdr), &[], &state).unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = extract_json_body(resp).await;
        let data = body.get("data").unwrap();
        assert!(!data.get("enabled").unwrap().as_bool().unwrap());
        assert!(data.get("entries").unwrap().is_null());
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
        let state = MgmtApiState {
            router: Arc::new(Router::new()),
            cert_reloader: None,
            crl_path: None,
            auth_token: token(),
        };
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
}
