// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Expanded management REST API (closes #875).
//!
//! This module ships the new operator-facing read endpoints requested
//! by the Modular Open Systems Approach (MOSA) deliverable: a structured
//! JSON view of running configuration, connected clients, build / FIPS
//! identity, metrics summary, store-and-forward queue depth, and a
//! verifier driver for the hash-chained audit log. Mutating endpoints
//! (`POST /api/config/reload`) reuse the same `Notify`-driven plumbing
//! the existing `/api/reload` endpoint and SIGHUP handler share.
//!
//! ## Routes
//!
//! | Route                       | Purpose                                                |
//! |-----------------------------|--------------------------------------------------------|
//! | `GET  /api/config`          | Running config snapshot (secrets redacted)             |
//! | `POST /api/config/reload`   | Trigger a SIGHUP-equivalent reload (returns `202`)     |
//! | `GET  /api/clients`         | Snapshot of connected clients                          |
//! | `GET  /api/clients/{cn}`    | Detail for one client (404 when not connected)         |
//! | `GET  /api/metrics/summary` | JSON router/federation/store-forward summary           |
//! | `GET  /api/store-forward`   | Per-CN store-and-forward queue depth + bytes           |
//! | `GET  /api/audit/verify`    | Run [`verify_audit_log`] over the configured audit log |
//! | `GET  /api/version`         | Build version, git hash, feature flags, FIPS status    |
//!
//! All endpoints require an `Authorization: Bearer <token>` header,
//! validated in constant time via [`subtle::ConstantTimeEq`]. The
//! response envelope mirrors the existing `acl_api` / `mgmt_api`
//! convention: `{"data": ...}` for success, `{"error": "..."}` for
//! failures.
//!
//! ## Auth model
//!
//! The MOSA OSMP calls for an "admin cert OU group" gate on write
//! endpoints. The metrics HTTP server fronting this API uses bearer
//! tokens, not mTLS — the bearer token itself is the admin
//! credential. A future PR can layer mTLS in front by capturing the
//! peer cert and checking its OU membership inside the `auth_ok`
//! helper without changing the per-endpoint contract.
//!
//! ## Wiring
//!
//! The `rustgate-server` binary owns the long-lived runtime state
//! (router handle, drain `Notify`, audit log path, etc.) and exposes
//! it to this module via the `Providers` callback bag below. The
//! callback shape keeps this crate from depending on `rustgate-router`
//! or `rustgate-server` directly — both would create a workspace
//! cycle with `rustgate-admin` already being a downstream dep of
//! `rustgate-server`.

use std::path::PathBuf;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Method, Response, StatusCode};
use rustgate_archive::audit_chain::verify_audit_log;
use serde::Serialize;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// JSON payload for `GET /api/config`. Mirrors the running CLI shape
/// with secret fields redacted. The `rustgate-server` wiring builds
/// this snapshot from its CLI struct after applying `serde(skip)` to
/// known sensitive fields (auth token paths, key files, etc.).
pub type ConfigJson = serde_json::Value;

/// Snapshot of one connected client. Populated by the wiring layer
/// from the router's session registry.
#[derive(Debug, Clone, Serialize)]
pub struct ClientSnapshot {
    /// Certificate Common Name.
    pub cn: String,
    /// SHA-256 fingerprint of the presented cert (lowercase hex). Empty
    /// for plaintext sessions.
    pub fingerprint: String,
    /// RFC 3339 timestamp the session connected. `None` when the wiring
    /// layer does not track per-session connect time (e.g. a trimmed-down
    /// test build).
    pub connected_at: Option<String>,
    /// Bytes received from this client. `None` when telemetry is not
    /// wired through to the session handle.
    pub bytes_rx: Option<u64>,
    /// Bytes sent to this client. `None` when telemetry is not wired
    /// through.
    pub bytes_tx: Option<u64>,
    /// Source protocol (`"tls"`, `"plaintext"`, `"websocket"`,
    /// `"mqtt"`, `"federation"`, `"nats"`, etc.).
    pub source_protocol: Option<String>,
    /// Group memberships derived from cert OU fields.
    pub groups: Vec<String>,
    /// Optional tenant identifier extracted from cert Organization (O).
    pub tenant: Option<String>,
}

/// Detail for one client. Adds queue / rate snapshot fields on top of
/// the base [`ClientSnapshot`].
#[derive(Debug, Clone, Serialize)]
pub struct ClientDetail {
    #[serde(flatten)]
    pub snapshot: ClientSnapshot,
    /// Current per-session bounded-channel queue depth. `None` when
    /// the wiring layer does not surface queue depth.
    pub queue_depth: Option<usize>,
    /// Effective per-CN rate cap (messages/sec) installed on the
    /// router throttle, when configured.
    pub rate_limit_per_sec: Option<u32>,
}

/// Per-CN store-and-forward queue snapshot.
#[derive(Debug, Clone, Serialize)]
pub struct StoreForwardEntry {
    /// Owning client CN.
    pub cn: String,
    /// Queued message count.
    pub messages: u64,
    /// Total bytes queued for this CN.
    pub bytes: u64,
}

/// Aggregate response shape for `GET /api/store-forward`.
#[derive(Debug, Clone, Serialize)]
pub struct StoreForwardSnapshot {
    /// `true` when a store-and-forward queue is configured.
    pub enabled: bool,
    /// Total bytes queued across all CNs.
    pub total_bytes: u64,
    /// Total messages queued across all CNs.
    pub total_messages: u64,
    /// Per-CN breakdown.
    pub entries: Vec<StoreForwardEntry>,
}

/// Aggregate response shape for `GET /api/metrics/summary`. JSON
/// equivalent of the most-relevant Prometheus counters — operators
/// reading the HTTP API should not have to parse Prometheus text.
#[derive(Debug, Clone, Serialize)]
pub struct MetricsSummary {
    /// Cumulative router fanout subscribers reached.
    pub router_fanout_total: u64,
    /// Cumulative messages dropped at the router (any reason).
    pub router_dropped_total: u64,
    /// Currently-tracked store-and-forward entries (sum across CNs).
    pub store_forward_messages: u64,
    /// Currently-tracked store-and-forward bytes.
    pub store_forward_bytes: u64,
    /// Total federation peers configured.
    pub federation_peer_count: u64,
    /// Federation peers currently connected.
    pub federation_connected_peers: u64,
    /// Connected client sessions.
    pub connected_clients: u64,
}

/// Response shape for `GET /api/version`.
#[derive(Debug, Clone, Serialize)]
pub struct VersionInfo {
    /// `CARGO_PKG_VERSION` of the running binary.
    pub version: String,
    /// Git hash baked in at build time, when available. Falls back to
    /// `"unknown"` when the build environment did not set the
    /// `RUSTGATE_GIT_HASH` env var.
    pub git_hash: String,
    /// Feature flags compiled into the running binary.
    pub features: Vec<String>,
    /// `true` when the binary was built with the `fips` feature flag.
    pub fips_active: bool,
}

/// Audit-verify response shape (mirrors [`rustgate_archive::audit_chain::VerifyReport`]
/// for serialisation, plus a `verified: true` flag the operator can
/// branch on).
#[derive(Debug, Clone, Serialize)]
pub struct AuditVerifyReport {
    /// `true` when the chain verified cleanly.
    pub verified: bool,
    /// Number of records validated.
    pub records: usize,
    /// Final chain tip after the last validated record.
    pub tip: String,
    /// Final sequence number after the last validated record.
    pub tip_seq: u64,
    /// On-disk audit log path that was verified.
    pub audit_log_path: String,
}

/// Type alias for the per-method snapshot callbacks the wiring layer
/// supplies. Each closure is invoked synchronously inside the request
/// handler — heavy work is the wiring layer's responsibility, not
/// this module's.
pub type ConfigFn = Arc<dyn Fn() -> ConfigJson + Send + Sync>;

/// Returns the current set of [`ClientSnapshot`]s. Async because the
/// router's session registry sits behind a `tokio::sync::RwLock`.
pub type ClientsFn = Arc<
    dyn Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = Vec<ClientSnapshot>> + Send>>
        + Send
        + Sync,
>;

/// Returns one [`ClientDetail`] for the supplied CN, or `None` when no
/// session matches. Async, same rationale as [`ClientsFn`].
pub type ClientDetailFn = Arc<
    dyn Fn(
            String,
        )
            -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<ClientDetail>> + Send>>
        + Send
        + Sync,
>;

/// Returns the current [`MetricsSummary`]. Async so wiring layers
/// can await on the router's session registry without blocking the
/// runtime.
pub type MetricsSummaryFn = Arc<
    dyn Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = MetricsSummary> + Send>>
        + Send
        + Sync,
>;

/// Returns the current [`StoreForwardSnapshot`].
pub type StoreForwardFn = Arc<dyn Fn() -> StoreForwardSnapshot + Send + Sync>;

/// Returns the current [`VersionInfo`].
pub type VersionFn = Arc<dyn Fn() -> VersionInfo + Send + Sync>;

/// Bag of provider callbacks supplied by the wiring layer. Held as
/// `Option<...>` so a partially-wired deployment (e.g. no
/// federation, no store-and-forward) can register the
/// [`ManagementApiState`] without forcing every callback to be
/// supplied; missing providers degrade individual endpoints to
/// structured `503`s rather than silently misreporting data.
#[derive(Default)]
pub struct Providers {
    pub config: Option<ConfigFn>,
    pub clients: Option<ClientsFn>,
    pub client_detail: Option<ClientDetailFn>,
    pub metrics_summary: Option<MetricsSummaryFn>,
    pub store_forward: Option<StoreForwardFn>,
    pub version: Option<VersionFn>,
}

impl std::fmt::Debug for Providers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Providers")
            .field("config", &self.config.is_some())
            .field("clients", &self.clients.is_some())
            .field("client_detail", &self.client_detail.is_some())
            .field("metrics_summary", &self.metrics_summary.is_some())
            .field("store_forward", &self.store_forward.is_some())
            .field("version", &self.version.is_some())
            .finish()
    }
}

/// Shared state for the expanded management REST API.
///
/// Constructed once at startup and shared between handler invocations
/// via `Arc`. None of the fields are mutated post-construction — the
/// reload notification is the sole side-effect surface and it is
/// driven by `notify_one()` rather than mutation of `MgmtApiState`.
pub struct ManagementApiState {
    /// Provider callbacks supplied by the wiring layer.
    pub providers: Providers,
    /// `Notify` fired by `POST /api/config/reload`. Same instance that
    /// SIGHUP and the existing `/api/reload` endpoint observe — so a
    /// reload triggered through any of the three surfaces drives the
    /// same handler in `main.rs`.
    pub reload_notify: Arc<tokio::sync::Notify>,
    /// On-disk audit log path used by `GET /api/audit/verify`. `None`
    /// when no audit log was configured at startup; the endpoint
    /// returns `503` in that case.
    pub audit_log_path: Option<PathBuf>,
    /// Bearer token required on every `/api/*` route this module owns.
    /// Wrapped in [`Zeroizing`] so the value is wiped on drop.
    pub auth_token: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for ManagementApiState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManagementApiState")
            .field("providers", &self.providers)
            .field("audit_log_path", &self.audit_log_path)
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

fn json_status<T: Serialize>(status: StatusCode, data: &T) -> Response<Full<Bytes>> {
    let body = serde_json::to_vec(&SuccessResponse { data }).unwrap_or_default();
    Response::builder()
        .status(status)
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

/// Constant-time bearer-token check. Same shape as
/// [`crate::acl_api::auth_ok`] so this module's auth contract is
/// instantly recognisable to operators familiar with the rest of the
/// admin surface.
fn auth_ok(header: Option<&str>, expected: &[u8]) -> bool {
    let Some(raw) = header else {
        return false;
    };
    let Some(token) = raw.strip_prefix("Bearer ") else {
        return false;
    };
    token.as_bytes().ct_eq(expected).into()
}

/// Path prefixes and exact paths owned by this handler. Pinned in
/// constants so the dispatcher in `server.rs` and the internal
/// `route` matcher cannot drift.
pub const MANAGEMENT_API_PREFIXES: &[&str] = &["/api/clients/"];

/// Bare paths owned by this handler (no trailing slash).
pub const MANAGEMENT_API_EXACT_PATHS: &[&str] = &[
    "/api/config",
    "/api/config/reload",
    "/api/clients",
    "/api/metrics/summary",
    "/api/store-forward",
    "/api/audit/verify",
    "/api/version",
];

/// Returns `true` when `path` is a route this handler owns.
///
/// The `/api/clients/` prefix is shared with the legacy `mgmt_api`
/// handler, which owns `/api/clients/{cn}/disconnect`. To avoid
/// silently swallowing those requests in the dispatcher this helper
/// rejects any `/api/clients/...` path that contains a second `/`
/// after the CN segment. The dispatcher then falls through to the
/// legacy handler unchanged.
pub fn handles_path(path: &str) -> bool {
    if MANAGEMENT_API_EXACT_PATHS.contains(&path) {
        return true;
    }
    if let Some(rest) = path.strip_prefix("/api/clients/") {
        // Bare `/api/clients/` (empty rest) is owned by the
        // exact-path matcher above; any sub-route with a slash falls
        // through to the legacy handler.
        return !rest.is_empty() && !rest.contains('/');
    }
    false
}

/// Top-level dispatch entrypoint. Returns `None` when `path` falls
/// outside the routes this module owns so the dispatcher can fall
/// through to other handlers (`mgmt_api` in `rustgate-server`,
/// `acl_api`, federation API, etc.).
pub async fn handle_request(
    method: &Method,
    path: &str,
    authorization: Option<&str>,
    state: &ManagementApiState,
) -> Option<Response<Full<Bytes>>> {
    if !handles_path(path) {
        return None;
    }
    if !auth_ok(authorization, &state.auth_token) {
        return Some(json_error(StatusCode::UNAUTHORIZED, "unauthorized"));
    }
    Some(route(method, path, state).await)
}

async fn route(method: &Method, path: &str, state: &ManagementApiState) -> Response<Full<Bytes>> {
    // Detail route under /api/clients/{cn} — must come before the
    // exact-path matcher so it takes precedence over a trailing-slash
    // probe of /api/clients/.
    if let Some(rest) = path.strip_prefix("/api/clients/")
        && !rest.is_empty()
    {
        // Reject `/api/clients/{cn}/...` shapes so a future endpoint
        // (e.g. /api/clients/{cn}/disconnect) doesn't get silently
        // matched by this handler before the dispatcher routes it
        // elsewhere. The existing `mgmt_api::handle_request` claims
        // `/api/clients/{cn}/disconnect`; this handler must only
        // serve the bare `{cn}` shape.
        if rest.contains('/') {
            return json_error(StatusCode::NOT_FOUND, "not found");
        }
        return match method {
            &Method::GET => client_detail_handler(rest, state).await,
            _ => json_error(StatusCode::METHOD_NOT_ALLOWED, "method not allowed"),
        };
    }

    match (method, path) {
        (&Method::GET, "/api/config") => config_handler(state),
        (&Method::POST, "/api/config/reload") => config_reload_handler(state),
        (&Method::GET, "/api/clients") => clients_handler(state).await,
        (&Method::GET, "/api/metrics/summary") => metrics_summary_handler(state).await,
        (&Method::GET, "/api/store-forward") => store_forward_handler(state),
        (&Method::GET, "/api/audit/verify") => audit_verify_handler(state),
        (&Method::GET, "/api/version") => version_handler(state),
        (
            _,
            "/api/config"
            | "/api/config/reload"
            | "/api/clients"
            | "/api/metrics/summary"
            | "/api/store-forward"
            | "/api/audit/verify"
            | "/api/version",
        ) => json_error(StatusCode::METHOD_NOT_ALLOWED, "method not allowed"),
        _ => json_error(StatusCode::NOT_FOUND, "not found"),
    }
}

fn config_handler(state: &ManagementApiState) -> Response<Full<Bytes>> {
    let Some(provider) = state.providers.config.as_ref() else {
        return json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "config provider not configured",
        );
    };
    let cfg = provider();
    json_ok(&cfg)
}

/// `POST /api/config/reload` — fire the shared reload `Notify`. The
/// `202 Accepted` status code mirrors the contract operators expect
/// for "request accepted, completion observable elsewhere" — the
/// matching reload completion is logged by the SIGHUP handler in
/// `main.rs` and exposed on `/metrics`.
fn config_reload_handler(state: &ManagementApiState) -> Response<Full<Bytes>> {
    state.reload_notify.notify_one();
    rustgate_core::audit::admin_drain_triggered("config_reload_api");
    json_status(
        StatusCode::ACCEPTED,
        &serde_json::json!({
            "status": "reload_initiated",
            "source": "api",
        }),
    )
}

async fn clients_handler(state: &ManagementApiState) -> Response<Full<Bytes>> {
    let Some(provider) = state.providers.clients.as_ref() else {
        return json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "clients provider not configured",
        );
    };
    let snapshots = provider().await;
    json_ok(&snapshots)
}

async fn client_detail_handler(cn: &str, state: &ManagementApiState) -> Response<Full<Bytes>> {
    let Some(provider) = state.providers.client_detail.as_ref() else {
        return json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "client detail provider not configured",
        );
    };
    match provider(cn.to_string()).await {
        Some(detail) => json_ok(&detail),
        None => json_error(StatusCode::NOT_FOUND, "client not connected"),
    }
}

async fn metrics_summary_handler(state: &ManagementApiState) -> Response<Full<Bytes>> {
    let Some(provider) = state.providers.metrics_summary.as_ref() else {
        return json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "metrics summary provider not configured",
        );
    };
    let summary = provider().await;
    json_ok(&summary)
}

fn store_forward_handler(state: &ManagementApiState) -> Response<Full<Bytes>> {
    let Some(provider) = state.providers.store_forward.as_ref() else {
        // Providers must always be supplied for `/api/store-forward`
        // — the wiring layer can return an `enabled: false` snapshot
        // when no queue is configured, so a missing provider is a
        // wiring bug, not a runtime mode.
        return json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "store-forward provider not configured",
        );
    };
    let snapshot = provider();
    json_ok(&snapshot)
}

fn audit_verify_handler(state: &ManagementApiState) -> Response<Full<Bytes>> {
    let Some(path) = state.audit_log_path.as_ref() else {
        return json_error(StatusCode::SERVICE_UNAVAILABLE, "no audit log configured");
    };
    match verify_audit_log(path) {
        Ok(report) => {
            let body = AuditVerifyReport {
                verified: true,
                records: report.records,
                tip: report.tip,
                tip_seq: report.tip_seq,
                audit_log_path: path.display().to_string(),
            };
            json_ok(&body)
        }
        Err(e) => {
            // Verification failures get a structured 200 with
            // `verified: false` so dashboards can scrape the endpoint
            // without distinguishing transport errors from chain
            // errors. The actual diagnostic rides on `error` and the
            // operator's audit log archive.
            let body = serde_json::json!({
                "verified": false,
                "error": format!("{e}"),
                "audit_log_path": path.display().to_string(),
            });
            json_status(StatusCode::OK, &body)
        }
    }
}

fn version_handler(state: &ManagementApiState) -> Response<Full<Bytes>> {
    let Some(provider) = state.providers.version.as_ref() else {
        return json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "version provider not configured",
        );
    };
    let info = provider();
    json_ok(&info)
}

/// Type-erased handler shape registered with the admin server's
/// management-API routing slot. Stored in an `Arc<OnceLock<…>>` so
/// the wiring layer can register the providers after the metrics
/// server starts listening.
pub type ManagementApiHandler = Arc<
    dyn Fn(
            &Method,
            &str,
            Option<&str>,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Option<Response<Full<Bytes>>>> + Send>,
        > + Send
        + Sync,
>;

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use http_body::Body;
    use http_body_util::BodyExt;

    use super::*;

    fn token() -> Zeroizing<Vec<u8>> {
        Zeroizing::new(b"management-api-test-token-padding-32b".to_vec())
    }

    fn auth_header() -> String {
        let t = token();
        format!("Bearer {}", String::from_utf8(t.to_vec()).unwrap())
    }

    fn empty_state() -> ManagementApiState {
        ManagementApiState {
            providers: Providers::default(),
            reload_notify: Arc::new(tokio::sync::Notify::new()),
            audit_log_path: None,
            auth_token: token(),
        }
    }

    fn state_with_full_providers(audit_path: Option<PathBuf>) -> ManagementApiState {
        let providers = Providers {
            config: Some(Arc::new(
                || serde_json::json!({"bind": "0.0.0.0:9443", "redacted_token": "***"}),
            )),
            clients: Some(Arc::new(|| {
                Box::pin(async {
                    vec![ClientSnapshot {
                        cn: "alice".into(),
                        fingerprint: "abc".into(),
                        connected_at: Some("2026-05-08T12:00:00Z".into()),
                        bytes_rx: Some(1024),
                        bytes_tx: Some(2048),
                        source_protocol: Some("tls".into()),
                        groups: vec!["squad-alpha".into()],
                        tenant: Some("acme".into()),
                    }]
                })
            })),
            client_detail: Some(Arc::new(|cn| {
                Box::pin(async move {
                    if cn == "alice" {
                        Some(ClientDetail {
                            snapshot: ClientSnapshot {
                                cn: "alice".into(),
                                fingerprint: "abc".into(),
                                connected_at: Some("2026-05-08T12:00:00Z".into()),
                                bytes_rx: Some(1024),
                                bytes_tx: Some(2048),
                                source_protocol: Some("tls".into()),
                                groups: vec!["squad-alpha".into()],
                                tenant: Some("acme".into()),
                            },
                            queue_depth: Some(3),
                            rate_limit_per_sec: Some(100),
                        })
                    } else {
                        None
                    }
                })
            })),
            metrics_summary: Some(Arc::new(|| {
                Box::pin(async {
                    MetricsSummary {
                        router_fanout_total: 100,
                        router_dropped_total: 5,
                        store_forward_messages: 0,
                        store_forward_bytes: 0,
                        federation_peer_count: 2,
                        federation_connected_peers: 2,
                        connected_clients: 1,
                    }
                })
            })),
            store_forward: Some(Arc::new(|| StoreForwardSnapshot {
                enabled: true,
                total_bytes: 0,
                total_messages: 0,
                entries: vec![],
            })),
            version: Some(Arc::new(|| VersionInfo {
                version: "0.0.0-test".into(),
                git_hash: "deadbeef".into(),
                features: vec!["metrics".into()],
                fips_active: false,
            })),
        };
        ManagementApiState {
            providers,
            reload_notify: Arc::new(tokio::sync::Notify::new()),
            audit_log_path: audit_path,
            auth_token: token(),
        }
    }

    async fn body_text(resp: Response<Full<Bytes>>) -> (StatusCode, String) {
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8_lossy(&bytes).to_string())
    }

    #[tokio::test]
    async fn unknown_path_returns_none() {
        let state = empty_state();
        let resp = handle_request(&Method::GET, "/healthz", Some(&auth_header()), &state).await;
        assert!(resp.is_none());
    }

    #[tokio::test]
    async fn config_route_is_owned() {
        assert!(handles_path("/api/config"));
        assert!(handles_path("/api/clients"));
        assert!(handles_path("/api/clients/alice"));
        assert!(handles_path("/api/audit/verify"));
        assert!(handles_path("/api/version"));
        assert!(!handles_path("/api/clients/alice/disconnect"));
        assert!(!handles_path("/api/cert/status"));
    }

    #[tokio::test]
    async fn missing_token_returns_401() {
        let state = empty_state();
        let resp = handle_request(&Method::GET, "/api/version", None, &state)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn wrong_token_returns_401() {
        let state = empty_state();
        let resp = handle_request(
            &Method::GET,
            "/api/version",
            Some("Bearer wrong-token-padding-padding-padding"),
            &state,
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn malformed_authorization_returns_401() {
        let state = empty_state();
        let resp = handle_request(
            &Method::GET,
            "/api/version",
            Some("Basic something"),
            &state,
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn config_returns_provider_payload() {
        let state = state_with_full_providers(None);
        let resp = handle_request(&Method::GET, "/api/config", Some(&auth_header()), &state)
            .await
            .unwrap();
        let (status, body) = body_text(resp).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("\"bind\":\"0.0.0.0:9443\""));
        assert!(body.contains("\"redacted_token\":\"***\""));
    }

    #[tokio::test]
    async fn config_with_no_provider_returns_503() {
        let state = empty_state();
        let resp = handle_request(&Method::GET, "/api/config", Some(&auth_header()), &state)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn config_reload_fires_notify_and_returns_202() {
        let state = state_with_full_providers(None);
        let notify = Arc::clone(&state.reload_notify);

        // Start a waiter before firing so notify_one is observable.
        let waiter = tokio::spawn(async move {
            notify.notified().await;
        });
        // Allow the waiter to register before we fire the notify.
        tokio::task::yield_now().await;

        let resp = handle_request(
            &Method::POST,
            "/api/config/reload",
            Some(&auth_header()),
            &state,
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);

        // The notify must have woken the waiter — bound the wait so a
        // bug here cannot hang the test forever.
        tokio::time::timeout(std::time::Duration::from_secs(2), waiter)
            .await
            .expect("reload notify must wake the waiter")
            .unwrap();
    }

    #[tokio::test]
    async fn clients_returns_snapshot_list() {
        let state = state_with_full_providers(None);
        let resp = handle_request(&Method::GET, "/api/clients", Some(&auth_header()), &state)
            .await
            .unwrap();
        let (status, body) = body_text(resp).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("\"cn\":\"alice\""));
        assert!(body.contains("\"source_protocol\":\"tls\""));
        assert!(body.contains("\"groups\":[\"squad-alpha\"]"));
        assert!(body.contains("\"bytes_rx\":1024"));
    }

    #[tokio::test]
    async fn client_detail_returns_full_payload() {
        let state = state_with_full_providers(None);
        let resp = handle_request(
            &Method::GET,
            "/api/clients/alice",
            Some(&auth_header()),
            &state,
        )
        .await
        .unwrap();
        let (status, body) = body_text(resp).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("\"queue_depth\":3"));
        assert!(body.contains("\"rate_limit_per_sec\":100"));
    }

    #[tokio::test]
    async fn client_detail_unknown_returns_404() {
        let state = state_with_full_providers(None);
        let resp = handle_request(
            &Method::GET,
            "/api/clients/unknown",
            Some(&auth_header()),
            &state,
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn client_detail_falls_through_for_disconnect_subroute() {
        // /api/clients/{cn}/disconnect is owned by the legacy
        // mgmt_api handler — this module must not claim it.
        let state = state_with_full_providers(None);
        let resp = handle_request(
            &Method::POST,
            "/api/clients/alice/disconnect",
            Some(&auth_header()),
            &state,
        )
        .await;
        // Either falls through (handles_path == false) or returns 404,
        // never 200 — pin both as acceptable.
        match resp {
            None => {} // ok — fall through
            Some(r) => assert_eq!(r.status(), StatusCode::NOT_FOUND),
        }
    }

    #[tokio::test]
    async fn metrics_summary_returns_provider_payload() {
        let state = state_with_full_providers(None);
        let resp = handle_request(
            &Method::GET,
            "/api/metrics/summary",
            Some(&auth_header()),
            &state,
        )
        .await
        .unwrap();
        let (status, body) = body_text(resp).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("\"router_fanout_total\":100"));
        assert!(body.contains("\"router_dropped_total\":5"));
        assert!(body.contains("\"federation_peer_count\":2"));
    }

    #[tokio::test]
    async fn store_forward_returns_provider_snapshot() {
        let state = state_with_full_providers(None);
        let resp = handle_request(
            &Method::GET,
            "/api/store-forward",
            Some(&auth_header()),
            &state,
        )
        .await
        .unwrap();
        let (status, body) = body_text(resp).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("\"enabled\":true"));
    }

    #[tokio::test]
    async fn version_includes_required_fields() {
        let state = state_with_full_providers(None);
        let resp = handle_request(&Method::GET, "/api/version", Some(&auth_header()), &state)
            .await
            .unwrap();
        let (status, body) = body_text(resp).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("\"version\":"));
        assert!(body.contains("\"git_hash\":"));
        assert!(body.contains("\"features\":"));
        assert!(body.contains("\"fips_active\":"));
    }

    #[tokio::test]
    async fn audit_verify_with_no_path_returns_503() {
        let state = state_with_full_providers(None);
        let resp = handle_request(
            &Method::GET,
            "/api/audit/verify",
            Some(&auth_header()),
            &state,
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn audit_verify_handles_synthetic_chain() {
        use std::io::Write;

        use rustgate_archive::audit_chain::{GENESIS_PREV, HashChainWriter};

        // Synthesize a 2-record audit chain in a temp file, then drive
        // the verify endpoint over it. The expected JSON shape carries
        // `verified: true`, `records: 2`, and a non-empty `tip`.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        {
            let file = std::fs::File::create(&path).unwrap();
            let mut writer = HashChainWriter::new(file, GENESIS_PREV.to_string());
            writer.write_all(b"{\"event\":\"first\"}\n").unwrap();
            writer.write_all(b"{\"event\":\"second\"}\n").unwrap();
        }

        let mut state = state_with_full_providers(Some(path.clone()));
        // Ensure the wiring's reload Notify is fresh — irrelevant
        // here but defensively zeroed so a stale notify cannot leak
        // across tests.
        state.reload_notify = Arc::new(tokio::sync::Notify::new());
        let resp = handle_request(
            &Method::GET,
            "/api/audit/verify",
            Some(&auth_header()),
            &state,
        )
        .await
        .unwrap();
        let (status, body) = body_text(resp).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("\"verified\":true"));
        assert!(body.contains("\"records\":2"));
        assert!(body.contains("\"audit_log_path\":"));
    }

    #[tokio::test]
    async fn unsupported_method_returns_405() {
        let state = state_with_full_providers(None);
        let resp = handle_request(
            &Method::DELETE,
            "/api/version",
            Some(&auth_header()),
            &state,
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn store_forward_serializes_per_cn_breakdown() {
        let providers = Providers {
            store_forward: Some(Arc::new(|| StoreForwardSnapshot {
                enabled: true,
                total_bytes: 4096,
                total_messages: 4,
                entries: vec![
                    StoreForwardEntry {
                        cn: "alice".into(),
                        messages: 3,
                        bytes: 3072,
                    },
                    StoreForwardEntry {
                        cn: "bob".into(),
                        messages: 1,
                        bytes: 1024,
                    },
                ],
            })),
            ..Default::default()
        };
        let state = ManagementApiState {
            providers,
            reload_notify: Arc::new(tokio::sync::Notify::new()),
            audit_log_path: None,
            auth_token: token(),
        };
        let resp = handle_request(
            &Method::GET,
            "/api/store-forward",
            Some(&auth_header()),
            &state,
        )
        .await
        .unwrap();
        let (status, body) = body_text(resp).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("\"cn\":\"alice\""));
        assert!(body.contains("\"cn\":\"bob\""));
        assert!(body.contains("\"bytes\":3072"));
        assert!(body.contains("\"total_messages\":4"));
    }

    // Body trait must be in scope for collect/poll_frame in tests above.
    #[allow(dead_code)]
    fn _body_trait_in_scope(_b: &dyn Body<Data = Bytes, Error = std::convert::Infallible>) {}
}
