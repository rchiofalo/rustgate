// Copyright © 2026 Roberto Chiofalo.

//! Marti API compatibility shim for drop-in TAK Server replacement.
//!
//! ATAK / WinTAK / iTAK clients connect to TAK Server's Marti REST API.
//! This module exposes those URLs on the admin HTTP server so existing
//! clients work as-is without reconfiguration. Each handler is a thin
//! adapter that translates the Marti URL/JSON shape into a call against
//! a native rustgate subsystem and back-translates the response — this
//! is a **compatibility adapter**, not new functionality.
//!
//! Closes #863.
//!
//! # URL prefix
//!
//! Marti uses `/Marti/api/*` (with capital M; case is load-bearing —
//! ATAK builds the URL with that exact spelling). All handlers in this
//! module reject any other prefix with a `None` fallthrough so the
//! dispatcher can fall through to the next handler ladder rung.
//!
//! # Endpoints (MVP)
//!
//! | Marti endpoint                       | Maps to                                                                   |
//! | ------------------------------------ | ------------------------------------------------------------------------- |
//! | `POST /Marti/api/tls/signClient/`    | `rustgate-enrollment` CSR signing path → PKCS#12 (`.p12`) blob            |
//! | `GET  /Marti/api/missions`           | `rustgate-missions` lightweight package store (#1329)                     |
//! | `GET  /Marti/api/contacts/all`       | Connected client list from the router                                     |
//! | `GET  /Marti/api/video`              | Video stream catalog from `rustgate-admin::video` (#1328)                 |
//! | `GET  /Marti/api/tls/config`         | TLS configuration export (CA cert + accepted ciphers + protocol versions) |
//! | `GET  /Marti/sync/search`            | `rustgate-missions` [`PackageStore::list`] in the Marti sync envelope     |
//! | `GET  /Marti/sync/content`           | `rustgate-missions` [`PackageStore::download`] → raw `application/zip`     |
//! | `POST /Marti/sync/{missionupload,upload}` | `rustgate-missions` [`PackageStore::upload`] (multipart or raw ZIP)  |
//!
//! # Enterprise Sync (#1455)
//!
//! The `/Marti/sync/*` routes are the first slice of the TAK
//! application-layer roadmap recorded in
//! [ADR 0030](../../../docs/adr/0030-tak-marti-application-layer.md).
//! They are a pure adapter over the content-addressed
//! [`rustgate_missions::PackageStore`] — no new persistence layer is
//! introduced. Because the exact TAK Server wire shape (query-param
//! names, the search-results JSON envelope, and which of
//! `missionupload`/`upload` an ATAK build posts to) is defined
//! clean-room from protocol knowledge per ADR 0021, these routes are
//! **best-effort pending live-client validation**: both upload path
//! spellings are accepted, and the search envelope is a stable
//! superset of the fields ATAK reads.
//!
//! # Out of scope (deferred)
//!
//! - `Marti/api/cot/xml` — live CoT push (would need a WebSocket tap into the router)
//! - Mission API / data-sync (`/Marti/mission/*`) — needs the replayable
//!   CoT persistence store tracked in #1455 / ADR 0030; not this slice.
//! - Deprecated XML response variants (we ship JSON only — ATAK is tolerant about format)
//!
//! # Auth model
//!
//! `signClient` uses HTTP Basic auth — `rustgate-enrollment::Credentials`
//! validates the header. The other endpoints accept the standard admin
//! bearer token (same shape as the missions / ACL APIs) so an operator
//! who already provisioned the admin token does not have to mint a
//! second one. When no token is configured the endpoints fall back to
//! "open" — the same disposition the existing `signClient` enrollment
//! endpoint uses, on the assumption the admin port is fronted by mTLS.

use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Full;
use hyper::header::CONTENT_TYPE;
use hyper::{Method, Response, StatusCode};
use rustgate_enrollment::{ContactsProvider, Credentials, CsrSigner, pkcs12};
use rustgate_missions::{
    MissionsError, PackageStore, extract_boundary, extract_multipart_field,
    extract_multipart_filename,
};
use serde::Serialize;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::video::VideoStreamCatalog;

/// URL prefix the Marti shim listens on. Capital M is load-bearing —
/// ATAK builds requests against this exact spelling.
pub const MARTI_PREFIX: &str = "/Marti/";

/// Shared state for the Marti compatibility shim.
///
/// Every field is optional: a deployment that wires only the missions
/// store still gets `/Marti/api/missions` working, and the rest of the
/// endpoints return `503 Service Unavailable` so an ATAK client logs
/// the gap rather than silently receiving an empty success response.
///
/// Mirrors the shape of [`crate::missions_api::MissionsApiState`] so
/// the registration boilerplate at the call site stays identical to
/// the other admin sub-APIs.
pub struct MartiCompatState {
    /// CSR signer reused for `POST /Marti/api/tls/signClient`. Wraps the
    /// existing enrollment-server signer so the signing surface is one
    /// codebase rather than two parallel implementations.
    pub signer: Option<Arc<CsrSigner>>,
    /// Basic-auth credentials for the signClient endpoint. When `None`
    /// the endpoint returns `503` — there is no anonymous-CSR path.
    pub credentials: Option<Arc<Credentials>>,
    /// Contacts provider — same callback shape as the enrollment-server
    /// Marti endpoints. When unset, returns an empty contact list.
    pub contacts: Option<ContactsProvider>,
    /// Lightweight Mission Packages store (#1329).
    pub packages: Option<PackageStore>,
    /// Video stream catalog (#1328).
    pub video: Option<Arc<VideoStreamCatalog>>,
    /// Optional bearer token gating the read-only endpoints. When `None`
    /// the GET endpoints answer without auth (the enrollment-side
    /// `signClient` always demands Basic auth regardless of this slot).
    pub auth_token: Option<Zeroizing<Vec<u8>>>,
}

impl std::fmt::Debug for MartiCompatState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MartiCompatState")
            .field("signer", &self.signer.is_some())
            .field("credentials", &self.credentials.is_some())
            .field("contacts", &self.contacts.is_some())
            .field("packages", &self.packages.is_some())
            .field("video", &self.video.is_some())
            .field("auth_token", &self.auth_token.is_some())
            .finish()
    }
}

impl MartiCompatState {
    /// Construct a fully-empty state. Operators populate fields via the
    /// public setters or by direct field assignment as the corresponding
    /// subsystem becomes available during startup.
    pub fn empty() -> Self {
        Self {
            signer: None,
            credentials: None,
            contacts: None,
            packages: None,
            video: None,
            auth_token: None,
        }
    }
}

impl Default for MartiCompatState {
    fn default() -> Self {
        Self::empty()
    }
}

/// Type-erased Marti compatibility handler shape registered with the
/// admin server's `/Marti/` routing slot.
///
/// Returns a boxed `Future` because the signing path needs to `.await`
/// on the body collector and the contacts provider is async. Mirrors
/// the [`crate::server::MgmtApiHandler`] async shape exactly so the
/// dispatcher pattern in [`crate::server::serve`] is identical.
pub type MartiCompatHandler = Arc<
    dyn Fn(
            &Method,
            &str,
            Option<&str>,
            Option<&str>,
            &[u8],
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Option<Response<Full<Bytes>>>> + Send>,
        > + Send
        + Sync,
>;

#[derive(Serialize)]
struct ErrorResponse<'a> {
    error: &'a str,
}

fn internal_error_response() -> Response<Full<Bytes>> {
    let mut resp = Response::new(Full::new(Bytes::from("internal server error")));
    *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
    resp
}

fn json_response(status: StatusCode, body: Bytes) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json")
        .body(Full::new(body))
        .unwrap_or_else(|_| internal_error_response())
}

fn json_error(status: StatusCode, message: &str) -> Response<Full<Bytes>> {
    let body = serde_json::to_vec(&ErrorResponse { error: message }).unwrap_or_default();
    json_response(status, Bytes::from(body))
}

fn unavailable(message: &str) -> Response<Full<Bytes>> {
    json_error(StatusCode::SERVICE_UNAVAILABLE, message)
}

/// Constant-time bearer-token comparison. Mirrors
/// [`crate::missions_api`] so the admin port has one consistent auth
/// shape.
fn bearer_ok(header: Option<&str>, expected: &[u8]) -> bool {
    let Some(raw) = header else {
        return false;
    };
    let Some(token) = raw.strip_prefix("Bearer ") else {
        return false;
    };
    token.as_bytes().ct_eq(expected).into()
}

/// Top-level dispatcher entrypoint registered against `/Marti/`.
///
/// Returns `None` for any path outside the `/Marti/` prefix so the
/// admin dispatcher can fall through to the next handler. Inside the
/// prefix every outcome is a fully-formed `Response<Full<Bytes>>`.
pub async fn handle_request(
    method: &Method,
    path: &str,
    authorization: Option<&str>,
    content_type: Option<&str>,
    body: &[u8],
    state: &MartiCompatState,
) -> Option<Response<Full<Bytes>>> {
    if !path.starts_with(MARTI_PREFIX) {
        return None;
    }

    Some(route(method, path, authorization, content_type, body, state).await)
}

async fn route(
    method: &Method,
    path: &str,
    authorization: Option<&str>,
    // Read by the Enterprise Sync upload route to slice the
    // `multipart/form-data` body; the other routes ignore it.
    content_type: Option<&str>,
    body: &[u8],
    state: &MartiCompatState,
) -> Response<Full<Bytes>> {
    // A TAK client appends a query string to the sync routes
    // (`?hash=…`). Split it off so the exact-path match below stays
    // stable regardless of whether the transport already stripped it.
    let (base_path, query) = match path.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (path, None),
    };

    match (method, base_path) {
        (&Method::GET, "/Marti/api/tls/config") => {
            match deny_unless_authorized(authorization, state) {
                Some(deny) => deny,
                None => handle_tls_config(state),
            }
        }
        (&Method::POST, "/Marti/api/tls/signClient")
        | (&Method::POST, "/Marti/api/tls/signClient/") => {
            handle_sign_client(authorization, body, state)
        }
        // Auth is checked BEFORE the handler runs. The previous form
        // `require_bearer(auth, state, handle(state).await)` evaluated the
        // handler argument first (Rust evaluates call arguments eagerly), so
        // the handler's side effects — DB queries, the contacts provider
        // callback, the video catalog snapshot — executed for unauthenticated
        // requests even though the response was later replaced with 401
        // (#1504). `deny_unless_authorized` short-circuits to 401 without
        // touching the handler.
        (&Method::GET, "/Marti/api/missions") => match deny_unless_authorized(authorization, state)
        {
            Some(deny) => deny,
            None => handle_missions(state).await,
        },
        (&Method::GET, "/Marti/api/contacts/all") => {
            match deny_unless_authorized(authorization, state) {
                Some(deny) => deny,
                None => handle_contacts(state).await,
            }
        }
        (&Method::GET, "/Marti/api/video") => match deny_unless_authorized(authorization, state) {
            Some(deny) => deny,
            None => handle_video(state),
        },
        // Enterprise Sync (#1455) — thin adapter over `PackageStore`.
        (&Method::GET, "/Marti/sync/search") => {
            match deny_unless_authorized(authorization, state) {
                Some(deny) => deny,
                None => handle_sync_search(state).await,
            }
        }
        (&Method::GET, "/Marti/sync/content") => {
            match deny_unless_authorized(authorization, state) {
                Some(deny) => deny,
                None => handle_sync_content(state, query).await,
            }
        }
        // ATAK builds disagree on the upload path spelling; accept both
        // so a real client's POST is never silently 404'd (best-effort
        // per ADR 0030, pending live-client validation).
        (&Method::POST, "/Marti/sync/missionupload") | (&Method::POST, "/Marti/sync/upload") => {
            match deny_unless_authorized(authorization, state) {
                Some(deny) => deny,
                None => handle_sync_upload(state, content_type, body).await,
            }
        }
        _ => json_error(StatusCode::NOT_FOUND, "not found"),
    }
}

/// Authorization gate for the bearer-token-protected Marti routes.
///
/// Returns `None` when the request may proceed — either no token is
/// configured (open mode) or the bearer token matched — and `Some(401)`
/// when it must be rejected. Callers MUST short-circuit on `Some` before
/// invoking the route handler, so handler side effects never run for an
/// unauthenticated request (#1504).
fn deny_unless_authorized(
    authorization: Option<&str>,
    state: &MartiCompatState,
) -> Option<Response<Full<Bytes>>> {
    let Some(ref expected) = state.auth_token else {
        return None;
    };
    if bearer_ok(authorization, expected) {
        None
    } else {
        Some(json_error(StatusCode::UNAUTHORIZED, "unauthorized"))
    }
}

/// `GET /Marti/api/tls/config`
///
/// Returns the CA cert + accepted ciphers + protocol versions so a TAK
/// client can build its truststore during preflight. When an admin
/// bearer token is configured the caller gates this route through
/// [`deny_unless_authorized`] first (#1551) — same disposition as the
/// other read-only GET endpoints; in open mode it answers without auth.
/// ATAK is tolerant about missing/extra fields, so we ship a stable
/// JSON shape rather than reproducing TAK Server's exact XML envelope.
fn handle_tls_config(state: &MartiCompatState) -> Response<Full<Bytes>> {
    // CA cert (DER → base64) is the only field that depends on the
    // signer; accepted ciphers and protocol versions are static for
    // the rustls build, so they come from a fixed list.
    let (ca_b64, organization) = match state.signer.as_ref() {
        Some(signer) => (
            rustgate_core::b64::encode(signer.ca_cert_der()),
            signer.organization().to_string(),
        ),
        None => (String::new(), String::new()),
    };

    let body = serde_json::json!({
        "version": "3",
        "type": "TlsConfig",
        "data": {
            "organization": organization,
            "caCert": ca_b64,
            "acceptedCiphers": [
                "TLS_AES_256_GCM_SHA384",
                "TLS_AES_128_GCM_SHA256",
                "TLS_CHACHA20_POLY1305_SHA256",
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            ],
            "protocolVersions": ["TLSv1.3", "TLSv1.2"],
        },
        "nodeId": "rustgate",
    });
    json_response(StatusCode::OK, Bytes::from(body.to_string()))
}

/// `POST /Marti/api/tls/signClient[/]`
///
/// ATAK posts a CSR (PEM) and expects a PKCS#12 (`.p12`) blob in
/// response with the signed cert + chain. Auth is HTTP Basic — the
/// authenticated username becomes the certificate CN (subject
/// injection is impossible because the CSR only contributes the
/// public key, see `CsrSigner::sign_csr`).
fn handle_sign_client(
    authorization: Option<&str>,
    body: &[u8],
    state: &MartiCompatState,
) -> Response<Full<Bytes>> {
    let Some(ref signer) = state.signer else {
        return unavailable("CSR signing not configured");
    };
    let Some(ref credentials) = state.credentials else {
        return unavailable("CSR signing not configured");
    };

    let Some(username) = credentials.validate(authorization) else {
        let mut resp = json_error(StatusCode::UNAUTHORIZED, "unauthorized");
        let _ = resp.headers_mut().insert(
            "WWW-Authenticate",
            hyper::header::HeaderValue::from_static("Basic realm=\"rustgate-marti\""),
        );
        return resp;
    };

    let csr_text = match std::str::from_utf8(body) {
        Ok(s) => s,
        Err(_) => return json_error(StatusCode::BAD_REQUEST, "CSR is not valid UTF-8"),
    };

    let signed_der = match signer.sign_csr(csr_text, username) {
        Ok(der) => der,
        Err(e) => {
            tracing::debug!(error = %e, username = %username, "Marti CSR signing failed");
            rustgate_core::audit::enrollment_sign_failed(username, "marti-compat", &e.to_string());
            return json_error(StatusCode::BAD_REQUEST, "failed to sign CSR");
        }
    };

    let p12 = match pkcs12::build_p12_bundle(&signed_der, signer.ca_cert_der()) {
        Ok(bundle) => bundle,
        Err(e) => {
            tracing::warn!(error = %e, username = %username, "PKCS#12 bundle creation failed");
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to build PKCS#12 bundle",
            );
        }
    };

    rustgate_core::audit::enrollment_signed(username, "marti-compat");
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/x-pkcs12")
        .body(Full::new(Bytes::from(p12)))
        .unwrap_or_else(|_| internal_error_response())
}

/// `GET /Marti/api/missions`
///
/// Returns the lightweight package store inventory in the Marti envelope
/// shape. Empty when no store is wired in — keeps the endpoint silent-
/// success instead of error so an ATAK client polling for missions does
/// not spam the log with retries.
async fn handle_missions(state: &MartiCompatState) -> Response<Full<Bytes>> {
    let entries = match state.packages.as_ref() {
        Some(store) => match store.list().await {
            Ok(items) => items
                .into_iter()
                .map(|m| {
                    serde_json::json!({
                        "name": m.name,
                        "hash": m.hash,
                        "size": m.size,
                        "creatorUid": m.creator_uid,
                        "uploadTime": m.upload_time,
                    })
                })
                .collect::<Vec<_>>(),
            Err(e) => {
                tracing::debug!(error = %e, "Marti missions listing failed");
                Vec::new()
            }
        },
        None => Vec::new(),
    };

    let body = serde_json::json!({
        "version": "3",
        "type": "Mission",
        "data": entries,
        "nodeId": "rustgate",
    });
    json_response(StatusCode::OK, Bytes::from(body.to_string()))
}

/// `GET /Marti/api/contacts/all`
///
/// Returns connected clients in the ATAK-expected shape. The field
/// names are load-bearing — `uid`, `callsign`, `team`, `role`,
/// `takv`, `endpoint` — because `lastStatus` is part of the contract
/// every Marti consumer relies on.
async fn handle_contacts(state: &MartiCompatState) -> Response<Full<Bytes>> {
    let contacts = match state.contacts.as_ref() {
        Some(provider) => provider().await,
        None => Vec::new(),
    };

    // Re-emit in the field-stable shape ATAK expects. Default any
    // optional field to a sensible value rather than skipping the
    // key — ATAK assumes the keys are always present.
    let payload: Vec<serde_json::Value> = contacts
        .into_iter()
        .map(|c| {
            serde_json::json!({
                "uid": c.uid,
                "callsign": c.callsign,
                "team": c.groups.first().cloned().unwrap_or_else(|| "Cyan".to_string()),
                "role": "Team Member",
                "takv": "rustgate",
                "endpoint": "*:-1:stcp",
                "lastStatus": c.last_status,
                "filterGroups": c.groups,
            })
        })
        .collect();

    json_response(
        StatusCode::OK,
        Bytes::from(serde_json::Value::Array(payload).to_string()),
    )
}

/// `GET /Marti/api/video`
///
/// Returns the video stream catalog in the Marti `Feed` envelope.
/// Each entry carries the stream URL + sensor framing block ATAK uses
/// to drive the in-app feed list. Empty when no catalog is wired.
fn handle_video(state: &MartiCompatState) -> Response<Full<Bytes>> {
    let entries: Vec<serde_json::Value> = match state.video.as_ref() {
        Some(catalog) => catalog
            .snapshot()
            .into_iter()
            .map(|e| {
                serde_json::json!({
                    "uid": e.uid,
                    "alias": e.uid,
                    "url": e.stream_url,
                    "protocol": e.stream_url.as_deref().and_then(infer_protocol),
                    "address": e.stream_url,
                    "buffer": -1,
                    "timeout": 12000,
                    "rover": false,
                    "ignoreEmbeddedKLV": false,
                    "preferredMacAddress": "",
                    "source": e.source_cn,
                    "type": e.event_type,
                    "fov": e.sensor_fov,
                    "azimuth": e.sensor_azimuth,
                    "elevation": e.sensor_elevation,
                    "lat": e.lat,
                    "lon": e.lon,
                })
            })
            .collect(),
        None => Vec::new(),
    };

    let body = serde_json::json!({
        "version": "3",
        "type": "Feed",
        "data": entries,
        "nodeId": "rustgate",
    });
    json_response(StatusCode::OK, Bytes::from(body.to_string()))
}

/// Best-effort scheme classifier for the `protocol` field on the video
/// envelope. ATAK uses the protocol field to pick which decoder to
/// instantiate; an unknown scheme rides as the literal string so the
/// client can still surface it in its error path.
fn infer_protocol(url: &str) -> Option<String> {
    let scheme = url.split("://").next()?.to_lowercase();
    if scheme.is_empty() || scheme == url {
        None
    } else {
        Some(scheme)
    }
}

/// Map a [`MissionsError`] onto the Marti sync HTTP status + message.
///
/// Mirrors the mapping in [`crate::missions_api`]: a malformed hash is
/// a client error (`400`), a well-formed-but-absent hash is `404`, and
/// everything else collapses to `500` without leaking filesystem
/// detail to the caller.
fn map_missions_error(err: &MissionsError) -> (StatusCode, &'static str) {
    match err {
        MissionsError::InvalidHash => (StatusCode::BAD_REQUEST, "invalid hash"),
        MissionsError::NotFound { .. } => (StatusCode::NOT_FOUND, "package not found"),
        MissionsError::EmptyUpload => (StatusCode::BAD_REQUEST, "empty upload"),
        MissionsError::PackageTooLarge { .. } | MissionsError::CapacityExceeded { .. } => {
            (StatusCode::PAYLOAD_TOO_LARGE, "package too large")
        }
        MissionsError::Manifest(_) => (StatusCode::BAD_REQUEST, "invalid mission package"),
        _ => (StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    }
}

/// Return the value of `key` from a `&`-joined query string, if present.
///
/// A minimal non-allocating scan — sufficient for the single `hash`
/// param the Enterprise Sync content route reads. No percent-decoding
/// is applied because a SHA-256 hash is already URL-safe hex; a value
/// carrying reserved characters simply fails
/// [`PackageStore::download`]'s hash validation and returns `400`.
fn query_param<'a>(query: Option<&'a str>, key: &str) -> Option<&'a str> {
    query?.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k == key).then_some(v)
    })
}

/// `GET /Marti/sync/search`
///
/// Re-emits the [`PackageStore`] inventory in the Marti sync
/// `results` envelope. Empty (and `200`, not `500`) when no store is
/// wired or the listing fails — an ATAK client polling for content
/// should see "nothing here yet", not an error it will retry-spam.
async fn handle_sync_search(state: &MartiCompatState) -> Response<Full<Bytes>> {
    let results = match state.packages.as_ref() {
        Some(store) => match store.list().await {
            Ok(items) => items
                .into_iter()
                .map(|m| {
                    serde_json::json!({
                        "UID": m.hash,
                        "Name": m.name,
                        "Hash": m.hash,
                        "PrimaryKey": m.hash,
                        "SubmissionUser": m.creator_uid,
                        "CreatorUid": m.creator_uid,
                        "SubmissionDateTime": m.upload_time,
                        "Keywords": Vec::<String>::new(),
                        "MIMEType": "application/zip",
                        "Size": m.size,
                        "Tool": "public",
                    })
                })
                .collect::<Vec<_>>(),
            Err(e) => {
                tracing::debug!(error = %e, "Marti sync search listing failed");
                Vec::new()
            }
        },
        None => Vec::new(),
    };

    let body = serde_json::json!({
        "resultCount": results.len(),
        "results": results,
    });
    json_response(StatusCode::OK, Bytes::from(body.to_string()))
}

/// `GET /Marti/sync/content?hash={h}`
///
/// Streams the raw ZIP body for a content-addressed package with
/// `Content-Type: application/zip`. A missing `hash` param is `400`; a
/// malformed hash is `400` (via [`PackageStore::download`]); a
/// well-formed-but-absent hash is `404`.
async fn handle_sync_content(
    state: &MartiCompatState,
    query: Option<&str>,
) -> Response<Full<Bytes>> {
    let Some(store) = state.packages.as_ref() else {
        return unavailable("mission package store not configured");
    };
    let Some(hash) = query_param(query, "hash") else {
        return json_error(StatusCode::BAD_REQUEST, "missing hash parameter");
    };

    match store.download(hash).await {
        Ok((meta, bytes)) => Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "application/zip")
            .header(
                "content-disposition",
                format!("attachment; filename=\"{}\"", meta.name),
            )
            .body(Full::new(Bytes::from(bytes)))
            .unwrap_or_else(|_| internal_error_response()),
        Err(e) => {
            let (status, msg) = map_missions_error(&e);
            tracing::debug!(error = %e, "Marti sync content download failed");
            json_error(status, msg)
        }
    }
}

/// `POST /Marti/sync/{missionupload,upload}`
///
/// Accepts either a `multipart/form-data` form (the canonical TAK
/// client shape — the ZIP rides in a field named `assetfile`, falling
/// back to `file`) or a raw `application/zip` body, and forwards it to
/// [`PackageStore::upload`]. Returns the stored package's content hash
/// so the client can immediately reference it via
/// `/Marti/sync/content?hash={h}`.
async fn handle_sync_upload(
    state: &MartiCompatState,
    content_type: Option<&str>,
    body: &[u8],
) -> Response<Full<Bytes>> {
    let Some(store) = state.packages.as_ref() else {
        return unavailable("mission package store not configured");
    };
    if body.is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "empty request body");
    }

    // Two accepted shapes, mirroring the native missions upload path:
    //   1. multipart/form-data — the ZIP is the `assetfile` field
    //      (ATAK's spelling), with `file` accepted as a fallback.
    //   2. raw application/zip — the curl/integration-test path.
    let (zip_bytes, name): (&[u8], String) =
        if let Some(ct) = content_type.filter(|ct| ct.starts_with("multipart/form-data")) {
            let Some(boundary) = extract_boundary(ct).map(|s| s.to_string()) else {
                return json_error(StatusCode::BAD_REQUEST, "missing multipart boundary");
            };
            let Some(zip) = extract_multipart_field(body, &boundary, "assetfile")
                .or_else(|| extract_multipart_field(body, &boundary, "file"))
            else {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    "multipart body missing `assetfile` field",
                );
            };
            let filename = extract_multipart_filename(body, &boundary)
                .unwrap_or_else(|| "package.zip".to_string());
            (zip, filename)
        } else {
            (body, "package.zip".to_string())
        };

    if zip_bytes.is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "empty package body");
    }

    // TAK sync uploads are anonymous at the transport layer here; the
    // bearer-token principal stands in as the creator until per-token
    // identity is wired through the admin auth layer.
    let creator_uid = "marti-sync";
    match store.upload(zip_bytes, &name, creator_uid).await {
        Ok(meta) => {
            tracing::info!(
                target: "audit",
                event_type = "marti.sync_upload",
                hash = %meta.hash,
                name = %rustgate_core::sanitize::sanitize_for_log(&meta.name),
                size = meta.size,
                "mission package uploaded via Marti Enterprise Sync",
            );
            let body = serde_json::json!({
                "UID": meta.hash,
                "Hash": meta.hash,
                "Name": meta.name,
                "Size": meta.size,
                "SubmissionUser": meta.creator_uid,
            });
            json_response(StatusCode::OK, Bytes::from(body.to_string()))
        }
        Err(e) => {
            let (status, msg) = map_missions_error(&e);
            tracing::debug!(error = %e, "Marti sync upload failed");
            json_error(status, msg)
        }
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::Arc;
    use std::time::SystemTime;

    use http_body_util::BodyExt;
    use rustgate_core::identity::Identity;
    use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};
    use rustgate_enrollment::ContactInfo;
    use rustgate_missions::StoreLimits;

    use super::*;

    fn token_bytes() -> Vec<u8> {
        b"marti-compat-test-token-padding-32bytes".to_vec()
    }

    fn mock_contacts(items: Vec<ContactInfo>) -> ContactsProvider {
        Arc::new(move || {
            let items = items.clone();
            Box::pin(async move { items })
        })
    }

    async fn body_string(resp: Response<Full<Bytes>>) -> (StatusCode, String) {
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8_lossy(&bytes).to_string())
    }

    #[tokio::test]
    async fn fallthrough_for_non_marti_path() {
        let state = MartiCompatState::empty();
        let resp = handle_request(&Method::GET, "/api/acl/groups", None, None, b"", &state).await;
        assert!(resp.is_none());
    }

    #[tokio::test]
    async fn unknown_marti_path_returns_404() {
        let state = MartiCompatState::empty();
        let resp = handle_request(&Method::GET, "/Marti/api/unknown", None, None, b"", &state)
            .await
            .expect("path inside prefix");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn marti_prefix_requires_capital_m() {
        let state = MartiCompatState::empty();
        let resp =
            handle_request(&Method::GET, "/marti/api/missions", None, None, b"", &state).await;
        assert!(resp.is_none(), "lowercase /marti/ must fall through");
    }

    #[tokio::test]
    async fn missions_returns_empty_envelope_without_store() {
        let state = MartiCompatState::empty();
        let resp = handle_request(&Method::GET, "/Marti/api/missions", None, None, b"", &state)
            .await
            .unwrap();
        let (status, body) = body_string(resp).await;
        assert_eq!(status, StatusCode::OK);
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["type"], "Mission");
        assert_eq!(parsed["nodeId"], "rustgate");
        assert!(parsed["data"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn missions_lists_uploaded_packages() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::new(
            dir.path().to_path_buf(),
            b"marti-compat-integrity-key-32-bytes".to_vec(),
            StoreLimits::default(),
        )
        .await
        .unwrap();
        let _ = store
            .upload(b"package-body", "demo.zip", "tester")
            .await
            .unwrap();

        let mut state = MartiCompatState::empty();
        state.packages = Some(store);

        let resp = handle_request(&Method::GET, "/Marti/api/missions", None, None, b"", &state)
            .await
            .unwrap();
        let (status, body) = body_string(resp).await;
        assert_eq!(status, StatusCode::OK);
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        let data = parsed["data"].as_array().unwrap();
        assert_eq!(data.len(), 1);
        assert_eq!(data[0]["name"], "demo.zip");
        assert!(data[0]["hash"].as_str().unwrap().len() == 64);
    }

    #[tokio::test]
    async fn contacts_translates_to_atak_shape() {
        let provider = mock_contacts(vec![ContactInfo {
            uid: "alpha-1".into(),
            callsign: "Alpha One".into(),
            groups: vec!["Team-A".into()],
            last_status: "Connected".into(),
        }]);
        let mut state = MartiCompatState::empty();
        state.contacts = Some(provider);

        let resp = handle_request(
            &Method::GET,
            "/Marti/api/contacts/all",
            None,
            None,
            b"",
            &state,
        )
        .await
        .unwrap();
        let (status, body) = body_string(resp).await;
        assert_eq!(status, StatusCode::OK);
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        let arr = parsed.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["uid"], "alpha-1");
        assert_eq!(arr[0]["callsign"], "Alpha One");
        assert_eq!(arr[0]["team"], "Team-A");
        assert_eq!(arr[0]["lastStatus"], "Connected");
        assert!(arr[0]["takv"].is_string());
        assert!(arr[0]["endpoint"].is_string());
    }

    #[tokio::test]
    async fn unauthorized_request_does_not_execute_handler() {
        use std::sync::atomic::{AtomicBool, Ordering};

        // #1504: the bearer check must gate handler EXECUTION, not just swap
        // the response. A provider that records its invocation proves the
        // handler body never runs for an unauthenticated request. A "401-only"
        // assertion would pass even pre-fix, because the old code ran the
        // handler and merely discarded its result.
        let ran = Arc::new(AtomicBool::new(false));
        let probe = ran.clone();
        let provider: ContactsProvider = Arc::new(move || {
            probe.store(true, Ordering::SeqCst);
            Box::pin(async move { Vec::<ContactInfo>::new() })
        });
        let mut state = MartiCompatState::empty();
        state.contacts = Some(provider);
        state.auth_token = Some(Zeroizing::new(b"s3cr3t".to_vec()));

        // No Authorization header → 401, and the provider must NOT run.
        let resp = handle_request(
            &Method::GET,
            "/Marti/api/contacts/all",
            None,
            None,
            b"",
            &state,
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(
            !ran.load(Ordering::SeqCst),
            "contacts provider must not execute without a valid bearer token",
        );

        // Wrong token → 401, still no execution.
        let resp = handle_request(
            &Method::GET,
            "/Marti/api/contacts/all",
            Some("Bearer wrong"),
            None,
            b"",
            &state,
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(
            !ran.load(Ordering::SeqCst),
            "contacts provider must not execute with a wrong bearer token",
        );

        // Correct token → handler runs, 200.
        let resp = handle_request(
            &Method::GET,
            "/Marti/api/contacts/all",
            Some("Bearer s3cr3t"),
            None,
            b"",
            &state,
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(
            ran.load(Ordering::SeqCst),
            "contacts provider must execute with a valid bearer token",
        );

        // #1551: tls/config shares the same gate — reject with no header,
        // reject on a wrong token, and admit only the correct bearer.
        let resp = handle_request(
            &Method::GET,
            "/Marti/api/tls/config",
            None,
            None,
            b"",
            &state,
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let resp = handle_request(
            &Method::GET,
            "/Marti/api/tls/config",
            Some("Bearer wrong"),
            None,
            b"",
            &state,
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let resp = handle_request(
            &Method::GET,
            "/Marti/api/tls/config",
            Some("Bearer s3cr3t"),
            None,
            b"",
            &state,
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn video_envelope_includes_stream_metadata() {
        let catalog = Arc::new(VideoStreamCatalog::new());
        let identity = Identity::plaintext("alpha-cn".to_string(), BTreeSet::new()).unwrap();
        let payload = r#"<event uid="VID-A" type="b-i-v-r"><point lat="35.0" lon="-100.0" hae="100"/><detail><__video url="rtsp://10.0.0.1/feed"/><sensor fov="40.0" azimuth="180.0" elevation="-10.0"/></detail></event>"#;
        let meta = Metadata::new(
            SystemTime::now(),
            "tcp".to_string(),
            MessageType::Other("b-i-v-r".to_string()),
        );
        catalog.observe(&RoutableMessage {
            source: identity,
            destination: Destination::Broadcast,
            payload: Bytes::from(payload),
            metadata: meta,
            entity: None,
        });

        let mut state = MartiCompatState::empty();
        state.video = Some(catalog);

        let resp = handle_request(&Method::GET, "/Marti/api/video", None, None, b"", &state)
            .await
            .unwrap();
        let (status, body) = body_string(resp).await;
        assert_eq!(status, StatusCode::OK);
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["type"], "Feed");
        let data = parsed["data"].as_array().unwrap();
        assert_eq!(data.len(), 1);
        assert_eq!(data[0]["uid"], "VID-A");
        assert_eq!(data[0]["url"], "rtsp://10.0.0.1/feed");
        assert_eq!(data[0]["protocol"], "rtsp");
        assert_eq!(data[0]["fov"], 40.0);
    }

    #[tokio::test]
    async fn tls_config_returns_static_shape_without_signer() {
        let state = MartiCompatState::empty();
        let resp = handle_request(
            &Method::GET,
            "/Marti/api/tls/config",
            None,
            None,
            b"",
            &state,
        )
        .await
        .unwrap();
        let (status, body) = body_string(resp).await;
        assert_eq!(status, StatusCode::OK);
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["type"], "TlsConfig");
        let ciphers = parsed["data"]["acceptedCiphers"].as_array().unwrap();
        assert!(!ciphers.is_empty());
        let versions = parsed["data"]["protocolVersions"].as_array().unwrap();
        assert!(versions.iter().any(|v| v == "TLSv1.3"));
    }

    #[tokio::test]
    async fn tls_config_requires_bearer_when_token_configured() {
        // #1551: GET /Marti/api/tls/config must sit behind the same
        // bearer gate as its sibling GET endpoints when a token is
        // configured. In open mode (no token) it still answers 200.
        let mut state = MartiCompatState::empty();
        state.auth_token = Some(Zeroizing::new(token_bytes()));

        // No header: 401.
        let resp = handle_request(
            &Method::GET,
            "/Marti/api/tls/config",
            None,
            None,
            b"",
            &state,
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // Wrong token: 401.
        let resp = handle_request(
            &Method::GET,
            "/Marti/api/tls/config",
            Some("Bearer wrong-token"),
            None,
            b"",
            &state,
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // Correct token: 200.
        let auth = format!("Bearer {}", String::from_utf8(token_bytes()).unwrap());
        let resp = handle_request(
            &Method::GET,
            "/Marti/api/tls/config",
            Some(&auth),
            None,
            b"",
            &state,
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Open mode (no token configured): 200 without any header.
        let open_state = MartiCompatState::empty();
        let resp = handle_request(
            &Method::GET,
            "/Marti/api/tls/config",
            None,
            None,
            b"",
            &open_state,
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn sign_client_unavailable_without_signer() {
        let state = MartiCompatState::empty();
        let resp = handle_request(
            &Method::POST,
            "/Marti/api/tls/signClient",
            Some("Basic dGVzdDp0ZXN0"),
            None,
            b"",
            &state,
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn sign_client_signs_a_csr_and_returns_pkcs12() {
        use rustgate_test_utils::certs::TestCa;

        let ca = TestCa::new("rustgate-marti-test-ca");
        let signer = Arc::new(
            CsrSigner::from_pem(&ca.cert_pem, &ca.key_pem, "rustgate-test").expect("build signer"),
        );

        let creds = Arc::new(Credentials::new(
            "operator".to_string(),
            Zeroizing::new("p@ssw0rd-padding-32bytes-aaaa".to_string()),
        ));

        // Generate a fresh CSR using rcgen — same code path the
        // production enrollment server tests already rely on.
        let csr_keypair = rcgen::KeyPair::generate().expect("gen key");
        let mut csr_params = rcgen::CertificateParams::new(vec![]).expect("params");
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, "operator");
        csr_params.distinguished_name = dn;
        let csr_pem = csr_params
            .serialize_request(&csr_keypair)
            .expect("serialize CSR")
            .pem()
            .expect("PEM");

        let mut state = MartiCompatState::empty();
        state.signer = Some(Arc::clone(&signer));
        state.credentials = Some(Arc::clone(&creds));

        // Build a Basic Auth header for the configured user/pass.
        let basic = rustgate_core::b64::encode(b"operator:p@ssw0rd-padding-32bytes-aaaa");
        let auth = format!("Basic {basic}");

        let resp = handle_request(
            &Method::POST,
            "/Marti/api/tls/signClient",
            Some(&auth),
            None,
            csr_pem.as_bytes(),
            &state,
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/x-pkcs12")
        );
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        // PKCS#12 starts with `0x30 0x82` (SEQUENCE, long-form length).
        assert!(
            bytes.len() > 4 && bytes[0] == 0x30 && bytes[1] == 0x82,
            "expected PKCS#12 SEQUENCE header, got {:?}",
            &bytes.iter().take(8).collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn bearer_token_required_when_configured() {
        let mut state = MartiCompatState::empty();
        state.auth_token = Some(Zeroizing::new(token_bytes()));

        // No header: 401.
        let resp = handle_request(&Method::GET, "/Marti/api/missions", None, None, b"", &state)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // Wrong scheme: 401.
        let resp = handle_request(
            &Method::GET,
            "/Marti/api/missions",
            Some("Basic abcdef"),
            None,
            b"",
            &state,
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // Correct token: 200.
        let auth = format!("Bearer {}", String::from_utf8(token_bytes()).unwrap());
        let resp = handle_request(
            &Method::GET,
            "/Marti/api/missions",
            Some(&auth),
            None,
            b"",
            &state,
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    async fn store_with_package(body: &[u8], name: &str) -> (tempfile::TempDir, PackageStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::new(
            dir.path().to_path_buf(),
            b"marti-sync-integrity-key-32-bytes".to_vec(),
            StoreLimits::default(),
        )
        .await
        .unwrap();
        let _ = store.upload(body, name, "tester").await.unwrap();
        (dir, store)
    }

    #[tokio::test]
    async fn sync_search_empty_without_store() {
        let state = MartiCompatState::empty();
        let resp = handle_request(&Method::GET, "/Marti/sync/search", None, None, b"", &state)
            .await
            .unwrap();
        let (status, body) = body_string(resp).await;
        assert_eq!(status, StatusCode::OK);
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["resultCount"], 0);
        assert!(parsed["results"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn sync_round_trip_upload_search_content() {
        // Upload a raw ZIP body, confirm it surfaces in search, then
        // fetch the exact bytes back via content?hash=.
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::new(
            dir.path().to_path_buf(),
            b"marti-sync-integrity-key-32-bytes".to_vec(),
            StoreLimits::default(),
        )
        .await
        .unwrap();
        let mut state = MartiCompatState::empty();
        state.packages = Some(store);

        let zip = b"PK\x03\x04-fake-mission-package-body";
        let resp = handle_request(
            &Method::POST,
            "/Marti/sync/upload",
            None,
            Some("application/zip"),
            zip,
            &state,
        )
        .await
        .unwrap();
        let (status, body) = body_string(resp).await;
        assert_eq!(status, StatusCode::OK);
        let uploaded: serde_json::Value = serde_json::from_str(&body).unwrap();
        let hash = uploaded["Hash"].as_str().unwrap().to_string();
        assert_eq!(hash.len(), 64);

        // Search must now list the package.
        let resp = handle_request(&Method::GET, "/Marti/sync/search", None, None, b"", &state)
            .await
            .unwrap();
        let (status, body) = body_string(resp).await;
        assert_eq!(status, StatusCode::OK);
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["resultCount"], 1);
        assert_eq!(parsed["results"][0]["Hash"], hash);

        // Content must return the exact bytes with application/zip.
        let path = format!("/Marti/sync/content?hash={hash}");
        let resp = handle_request(&Method::GET, &path, None, None, b"", &state)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/zip")
        );
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(bytes.as_ref(), zip);
    }

    #[tokio::test]
    async fn sync_upload_accepts_multipart_assetfile() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::new(
            dir.path().to_path_buf(),
            b"marti-sync-integrity-key-32-bytes".to_vec(),
            StoreLimits::default(),
        )
        .await
        .unwrap();
        let mut state = MartiCompatState::empty();
        state.packages = Some(store);

        let boundary = "----martisyncboundary";
        let mut multipart = Vec::new();
        multipart.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        multipart.extend_from_slice(
            b"Content-Disposition: form-data; name=\"assetfile\"; filename=\"pkg.zip\"\r\n",
        );
        multipart.extend_from_slice(b"Content-Type: application/zip\r\n\r\n");
        multipart.extend_from_slice(b"PK\x03\x04-multipart-body");
        multipart.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());

        let ct = format!("multipart/form-data; boundary={boundary}");
        let resp = handle_request(
            &Method::POST,
            "/Marti/sync/missionupload",
            None,
            Some(&ct),
            &multipart,
            &state,
        )
        .await
        .unwrap();
        let (status, body) = body_string(resp).await;
        assert_eq!(status, StatusCode::OK);
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["Name"], "pkg.zip");
        assert_eq!(parsed["Hash"].as_str().unwrap().len(), 64);
    }

    #[tokio::test]
    async fn sync_content_missing_hash_is_400() {
        let (_dir, store) = store_with_package(b"body", "demo.zip").await;
        let mut state = MartiCompatState::empty();
        state.packages = Some(store);

        let resp = handle_request(&Method::GET, "/Marti/sync/content", None, None, b"", &state)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn sync_content_absent_hash_is_404_malformed_is_400() {
        let (_dir, store) = store_with_package(b"body", "demo.zip").await;
        let mut state = MartiCompatState::empty();
        state.packages = Some(store);

        // Well-formed (64 hex) but never stored → 404.
        let absent = format!("/Marti/sync/content?hash={}", "a".repeat(64));
        let resp = handle_request(&Method::GET, &absent, None, None, b"", &state)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        // Malformed hash → 400.
        let malformed = "/Marti/sync/content?hash=not-a-valid-hash";
        let resp = handle_request(&Method::GET, malformed, None, None, b"", &state)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn sync_routes_gated_by_bearer_token() {
        let (_dir, store) = store_with_package(b"body", "demo.zip").await;
        let mut state = MartiCompatState::empty();
        state.packages = Some(store);
        state.auth_token = Some(Zeroizing::new(token_bytes()));

        // Search: 401 without a token.
        let resp = handle_request(&Method::GET, "/Marti/sync/search", None, None, b"", &state)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // Content: 401 with a wrong token (even before hash validation).
        let resp = handle_request(
            &Method::GET,
            &format!("/Marti/sync/content?hash={}", "a".repeat(64)),
            Some("Bearer wrong"),
            None,
            b"",
            &state,
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // Upload: 401 without a token.
        let resp = handle_request(
            &Method::POST,
            "/Marti/sync/upload",
            None,
            Some("application/zip"),
            b"PK\x03\x04body",
            &state,
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // Correct token admits search.
        let auth = format!("Bearer {}", String::from_utf8(token_bytes()).unwrap());
        let resp = handle_request(
            &Method::GET,
            "/Marti/sync/search",
            Some(&auth),
            None,
            b"",
            &state,
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[test]
    fn infer_protocol_extracts_scheme() {
        assert_eq!(infer_protocol("rtsp://1.2.3.4/feed"), Some("rtsp".into()));
        assert_eq!(infer_protocol("HTTPS://x"), Some("https".into()));
        assert_eq!(infer_protocol("no-scheme-here"), None);
    }

    #[test]
    fn query_param_extracts_hash() {
        assert_eq!(query_param(Some("hash=abc&x=1"), "hash"), Some("abc"));
        assert_eq!(query_param(Some("x=1&hash=def"), "hash"), Some("def"));
        assert_eq!(query_param(Some("x=1"), "hash"), None);
        assert_eq!(query_param(None, "hash"), None);
    }
}
