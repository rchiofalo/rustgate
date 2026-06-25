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
//!
//! # Out of scope (deferred)
//!
//! - `Marti/api/sync/*` — full mission sync (lands with the rest of #860)
//! - `Marti/api/cot/xml` — live CoT push (would need a WebSocket tap into the router)
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
use rustgate_missions::PackageStore;
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
    // `content_type` is part of the public handler shape so a future
    // multipart-upload variant on `signClient` (or a JSON v2 alias)
    // can land without a signature change. Today no MVP route reads
    // it, so it rides unused.
    _content_type: Option<&str>,
    body: &[u8],
    state: &MartiCompatState,
) -> Response<Full<Bytes>> {
    match (method, path) {
        (&Method::GET, "/Marti/api/tls/config") => handle_tls_config(state),
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
/// client can build its truststore from an unauthenticated preflight.
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

    #[test]
    fn infer_protocol_extracts_scheme() {
        assert_eq!(infer_protocol("rtsp://1.2.3.4/feed"), Some("rtsp".into()));
        assert_eq!(infer_protocol("HTTPS://x"), Some("https".into()));
        assert_eq!(infer_protocol("no-scheme-here"), None);
    }
}
