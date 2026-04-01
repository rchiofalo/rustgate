//! REST API for federation management.
//!
//! Provides HTTP endpoints for managing federation peers, certificates,
//! and monitoring connection status. Designed to be mounted alongside
//! the existing metrics HTTP server in `rustgate-server`.
//!
//! ## Routes
//!
//! ### Connections
//! - `GET  /api/federation/connections`      — list all active connections
//! - `GET  /api/federation/connections/{id}`  — get specific connection
//!
//! ### Federates
//! - `GET    /api/federation/federates`            — list all configured federates
//! - `POST   /api/federation/federates`            — add new federate
//! - `GET    /api/federation/federates/{id}`        — get federate details
//! - `PUT    /api/federation/federates/{id}`        — update federate
//! - `DELETE /api/federation/federates/{id}`        — remove federate
//! - `PUT    /api/federation/federates/{id}/enable`  — enable federate
//! - `PUT    /api/federation/federates/{id}/disable` — disable federate
//! - `PUT    /api/federation/federates/{id}/routing-mode` — set routing mode
//!
//! ### Certificates
//! - `GET    /api/federation/certificates`      — list trusted CA certificates
//! - `POST   /api/federation/certificates`      — upload CA certificate (PEM body)
//! - `GET    /api/federation/certificates/{cn}` — get certificate info
//! - `DELETE /api/federation/certificates/{cn}` — remove certificate
//!
//! ### Status
//! - `GET /api/federation/stats`  — aggregated statistics
//! - `GET /api/federation/status` — federation manager status

use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Method, Response, StatusCode};
use serde::{Deserialize, Serialize};

use crate::config::RoutingMode;
use crate::manager::FederationStatus;
use crate::peer::PeerStatus;
use crate::store::{FederateInfo, FederateStore, FederateUpdate};
use crate::trust_store::TrustStore;

/// Shared state provided to the API handler.
///
/// The caller (e.g., `rustgate-server`) constructs this and passes it
/// to [`handle_request`] for each incoming HTTP request that matches
/// the `/api/federation/` prefix.
/// Callback type for looking up a peer's status by ID.
pub type PeerStatusFn = Arc<dyn Fn(&str) -> Option<PeerStatus> + Send + Sync>;

pub struct ApiState<S: FederateStore> {
    /// The federation peer store.
    pub store: Arc<std::sync::RwLock<S>>,
    /// The CA trust store.
    pub trust_store: Arc<TrustStore>,
    /// A closure that returns the current federation status snapshot.
    pub status_fn: Arc<dyn Fn() -> FederationStatus + Send + Sync>,
    /// A closure that returns a specific peer's status by ID.
    pub peer_status_fn: PeerStatusFn,
}

impl<S: FederateStore> std::fmt::Debug for ApiState<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiState").finish()
    }
}

/// Request body for creating a new federate.
#[derive(Debug, Deserialize)]
pub struct CreateFederateRequest {
    pub id: String,
    pub address: String,
    #[serde(default)]
    pub groups: Vec<String>,
    pub inbound_groups: Option<Vec<String>>,
    pub outbound_groups: Option<Vec<String>>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub is_outbound: bool,
    pub trust_cert_cn: Option<String>,
    #[serde(default)]
    pub routing_mode: RoutingMode,
}

fn default_true() -> bool {
    true
}

/// Request body for updating an existing federate.
#[derive(Debug, Deserialize)]
pub struct UpdateFederateRequest {
    pub address: Option<String>,
    pub groups: Option<Vec<String>>,
    pub inbound_groups: Option<Option<Vec<String>>>,
    pub outbound_groups: Option<Option<Vec<String>>>,
    pub is_outbound: Option<bool>,
    pub trust_cert_cn: Option<Option<String>>,
}

/// Request body for setting routing mode.
#[derive(Debug, Deserialize)]
pub struct SetRoutingModeRequest {
    pub routing_mode: RoutingMode,
}

/// Standard JSON success envelope.
#[derive(Debug, Serialize)]
struct SuccessResponse<T: Serialize> {
    data: T,
}

/// Standard JSON error envelope.
#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

// ── HTTP handler ────────────────────────────────────────────────────

/// Handle a federation API request.
///
/// Routes all requests under `/api/federation/` to the appropriate handler.
/// Returns `None` if the request path does not start with `/api/federation/`,
/// allowing the caller to fall through to other handlers.
///
/// The `body` parameter should contain the pre-read request body bytes.
pub fn handle_request<S: FederateStore>(
    method: &Method,
    path: &str,
    body: &[u8],
    state: &ApiState<S>,
) -> Option<Response<Full<Bytes>>> {
    if !path.starts_with("/api/federation/") {
        return None;
    }

    let sub_path = &path["/api/federation/".len()..];

    Some(route(method, sub_path, body, state))
}

/// Internal routing logic.
fn route<S: FederateStore>(
    method: &Method,
    sub_path: &str,
    body: &[u8],
    state: &ApiState<S>,
) -> Response<Full<Bytes>> {
    match (method, sub_path) {
        // ── Connections ─────────────────────────────────────────
        (&Method::GET, "connections") => handle_list_connections(state),
        (&Method::GET, path) if path.starts_with("connections/") => {
            let id = &path["connections/".len()..];
            handle_get_connection(state, id)
        }

        // ── Federates ───────────────────────────────────────────
        (&Method::GET, "federates") => handle_list_federates(state),
        (&Method::POST, "federates") => handle_create_federate(state, body),
        (&Method::PUT, path) if path.starts_with("federates/") => {
            let rest = &path["federates/".len()..];
            if let Some(slash_pos) = rest.find('/') {
                let id = &rest[..slash_pos];
                let action = &rest[slash_pos + 1..];
                match action {
                    "enable" => handle_enable_federate(state, id, true),
                    "disable" => handle_enable_federate(state, id, false),
                    "routing-mode" => handle_set_routing_mode(state, id, body),
                    _ => json_error(StatusCode::NOT_FOUND, "unknown action"),
                }
            } else {
                let id = rest;
                handle_update_federate(state, id, body)
            }
        }
        (&Method::DELETE, path) if path.starts_with("federates/") => {
            let rest = &path["federates/".len()..];
            let id = rest.split('/').next().unwrap_or(rest);
            handle_delete_federate(state, id)
        }
        (&Method::GET, path) if path.starts_with("federates/") => {
            let rest = &path["federates/".len()..];
            let id = rest.split('/').next().unwrap_or(rest);
            handle_get_federate(state, id)
        }

        // ── Certificates ────────────────────────────────────────
        (&Method::GET, "certificates") => handle_list_certificates(state),
        (&Method::POST, "certificates") => handle_add_certificate(state, body),
        (&Method::GET, path) if path.starts_with("certificates/") => {
            let cn = &path["certificates/".len()..];
            let cn = percent_decode(cn);
            handle_get_certificate(state, &cn)
        }
        (&Method::DELETE, path) if path.starts_with("certificates/") => {
            let cn = &path["certificates/".len()..];
            let cn = percent_decode(cn);
            handle_delete_certificate(state, &cn)
        }

        // ── Stats / Status ──────────────────────────────────────
        (&Method::GET, "stats") => handle_stats(state),
        (&Method::GET, "status") => handle_status(state),

        // ── Fallthrough ─────────────────────────────────────────
        _ => json_error(StatusCode::NOT_FOUND, "not found"),
    }
}

// ── Connection handlers ─────────────────────────────────────────────

fn handle_list_connections<S: FederateStore>(state: &ApiState<S>) -> Response<Full<Bytes>> {
    let status = (state.status_fn)();
    json_ok(&status.peers)
}

fn handle_get_connection<S: FederateStore>(state: &ApiState<S>, id: &str) -> Response<Full<Bytes>> {
    match (state.peer_status_fn)(id) {
        Some(peer) => json_ok(&peer),
        None => json_error(StatusCode::NOT_FOUND, "connection not found"),
    }
}

// ── Federate handlers ───────────────────────────────────────────────

fn handle_list_federates<S: FederateStore>(state: &ApiState<S>) -> Response<Full<Bytes>> {
    match state.store.read() {
        Ok(store) => json_ok(&store.list()),
        Err(e) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("store lock poisoned: {e}"),
        ),
    }
}

fn handle_create_federate<S: FederateStore>(
    state: &ApiState<S>,
    body: &[u8],
) -> Response<Full<Bytes>> {
    let req: CreateFederateRequest = match serde_json::from_slice(body) {
        Ok(r) => r,
        Err(e) => return json_error(StatusCode::BAD_REQUEST, &format!("invalid JSON: {e}")),
    };

    if req.id.is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "id is required");
    }
    if req.address.is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "address is required");
    }

    let info = FederateInfo {
        id: req.id.clone(),
        address: req.address,
        groups: req.groups,
        inbound_groups: req.inbound_groups,
        outbound_groups: req.outbound_groups,
        enabled: req.enabled,
        is_outbound: req.is_outbound,
        trust_cert_cn: req.trust_cert_cn,
        routing_mode: req.routing_mode,
        created_at: std::time::SystemTime::now(),
        last_seen: None,
        messages_sent: 0,
        messages_recv: 0,
    };

    match state.store.write() {
        Ok(mut store) => {
            store.add(info.clone());
            if let Err(e) = store.save() {
                tracing::warn!(error = %e, "failed to persist store after add");
            }
            json_created(&info)
        }
        Err(e) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("store lock poisoned: {e}"),
        ),
    }
}

fn handle_get_federate<S: FederateStore>(state: &ApiState<S>, id: &str) -> Response<Full<Bytes>> {
    match state.store.read() {
        Ok(store) => match store.get(id) {
            Some(info) => json_ok(&info),
            None => json_error(StatusCode::NOT_FOUND, "federate not found"),
        },
        Err(e) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("store lock poisoned: {e}"),
        ),
    }
}

fn handle_update_federate<S: FederateStore>(
    state: &ApiState<S>,
    id: &str,
    body: &[u8],
) -> Response<Full<Bytes>> {
    let req: UpdateFederateRequest = match serde_json::from_slice(body) {
        Ok(r) => r,
        Err(e) => return json_error(StatusCode::BAD_REQUEST, &format!("invalid JSON: {e}")),
    };

    let update = FederateUpdate {
        address: req.address,
        groups: req.groups,
        inbound_groups: req.inbound_groups,
        outbound_groups: req.outbound_groups,
        is_outbound: req.is_outbound,
        trust_cert_cn: req.trust_cert_cn,
    };

    match state.store.write() {
        Ok(mut store) => match store.update(id, update) {
            Ok(_) => {
                if let Err(e) = store.save() {
                    tracing::warn!(error = %e, "failed to persist store after update");
                }
                match store.get(id) {
                    Some(info) => json_ok(&info),
                    None => json_error(StatusCode::NOT_FOUND, "federate not found after update"),
                }
            }
            Err(e) => json_error(StatusCode::NOT_FOUND, &format!("{e}")),
        },
        Err(e) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("store lock poisoned: {e}"),
        ),
    }
}

fn handle_delete_federate<S: FederateStore>(
    state: &ApiState<S>,
    id: &str,
) -> Response<Full<Bytes>> {
    match state.store.write() {
        Ok(mut store) => {
            if store.remove(id) {
                if let Err(e) = store.save() {
                    tracing::warn!(error = %e, "failed to persist store after delete");
                }
                json_ok(&serde_json::json!({ "deleted": id }))
            } else {
                json_error(StatusCode::NOT_FOUND, "federate not found")
            }
        }
        Err(e) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("store lock poisoned: {e}"),
        ),
    }
}

fn handle_enable_federate<S: FederateStore>(
    state: &ApiState<S>,
    id: &str,
    enabled: bool,
) -> Response<Full<Bytes>> {
    match state.store.write() {
        Ok(mut store) => match store.set_enabled(id, enabled) {
            Ok(()) => {
                if let Err(e) = store.save() {
                    tracing::warn!(error = %e, "failed to persist store after enable/disable");
                }
                match store.get(id) {
                    Some(info) => json_ok(&info),
                    None => json_error(StatusCode::NOT_FOUND, "federate not found"),
                }
            }
            Err(e) => json_error(StatusCode::NOT_FOUND, &format!("{e}")),
        },
        Err(e) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("store lock poisoned: {e}"),
        ),
    }
}

fn handle_set_routing_mode<S: FederateStore>(
    state: &ApiState<S>,
    id: &str,
    body: &[u8],
) -> Response<Full<Bytes>> {
    let req: SetRoutingModeRequest = match serde_json::from_slice(body) {
        Ok(r) => r,
        Err(e) => return json_error(StatusCode::BAD_REQUEST, &format!("invalid JSON: {e}")),
    };

    match state.store.write() {
        Ok(mut store) => match store.set_routing_mode(id, req.routing_mode) {
            Ok(()) => {
                if let Err(e) = store.save() {
                    tracing::warn!(error = %e, "failed to persist store after routing mode change");
                }
                match store.get(id) {
                    Some(info) => json_ok(&info),
                    None => json_error(StatusCode::NOT_FOUND, "federate not found"),
                }
            }
            Err(e) => json_error(StatusCode::NOT_FOUND, &format!("{e}")),
        },
        Err(e) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("store lock poisoned: {e}"),
        ),
    }
}

// ── Certificate handlers ────────────────────────────────────────────

fn handle_list_certificates<S: FederateStore>(state: &ApiState<S>) -> Response<Full<Bytes>> {
    json_ok(&state.trust_store.list_certificates())
}

fn handle_add_certificate<S: FederateStore>(
    state: &ApiState<S>,
    body: &[u8],
) -> Response<Full<Bytes>> {
    if body.is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "PEM body is required");
    }
    match state.trust_store.add_certificate_from_pem(body) {
        Ok(info) => json_created(&info),
        Err(e) => json_error(StatusCode::BAD_REQUEST, &format!("{e}")),
    }
}

fn handle_get_certificate<S: FederateStore>(
    state: &ApiState<S>,
    cn: &str,
) -> Response<Full<Bytes>> {
    match state.trust_store.get_certificate_info(cn) {
        Some(info) => json_ok(&info),
        None => json_error(StatusCode::NOT_FOUND, "certificate not found"),
    }
}

fn handle_delete_certificate<S: FederateStore>(
    state: &ApiState<S>,
    cn: &str,
) -> Response<Full<Bytes>> {
    if state.trust_store.remove_certificate(cn) {
        json_ok(&serde_json::json!({ "deleted": cn }))
    } else {
        json_error(StatusCode::NOT_FOUND, "certificate not found")
    }
}

// ── Stats / Status handlers ─────────────────────────────────────────

fn handle_stats<S: FederateStore>(state: &ApiState<S>) -> Response<Full<Bytes>> {
    let status = (state.status_fn)();

    let total_sent: u64 = status.peers.iter().map(|p| p.messages_sent).sum();
    let total_recv: u64 = status.peers.iter().map(|p| p.messages_recv).sum();

    let stats = serde_json::json!({
        "total_peers": status.total_peers,
        "connected_peers": status.connected_peers,
        "running": status.running,
        "messages_sent": total_sent,
        "messages_received": total_recv,
        "certificates": state.trust_store.count(),
    });

    json_ok(&stats)
}

fn handle_status<S: FederateStore>(state: &ApiState<S>) -> Response<Full<Bytes>> {
    let status = (state.status_fn)();
    json_ok(&status)
}

// ── JSON response helpers ───────────────────────────────────────────

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

fn json_created<T: Serialize>(data: &T) -> Response<Full<Bytes>> {
    let body = serde_json::to_vec(&SuccessResponse { data }).unwrap_or_default();
    Response::builder()
        .status(StatusCode::CREATED)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap_or_else(|_| internal_error_response())
}

fn json_error(status: StatusCode, message: &str) -> Response<Full<Bytes>> {
    let body = serde_json::to_vec(&ErrorResponse {
        error: message.to_string(),
    })
    .unwrap_or_default();
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap_or_else(|_| internal_error_response())
}

/// Simple percent-decoding for URL path segments.
fn percent_decode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.bytes();
    while let Some(b) = chars.next() {
        if b == b'%' {
            let hi = chars.next().unwrap_or(b'0');
            let lo = chars.next().unwrap_or(b'0');
            let decoded = hex_byte(hi, lo);
            result.push(decoded as char);
        } else if b == b'+' {
            result.push(' ');
        } else {
            result.push(b as char);
        }
    }
    result
}

fn hex_byte(hi: u8, lo: u8) -> u8 {
    (hex_nibble(hi) << 4) | hex_nibble(lo)
}

fn hex_nibble(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manager::FederationStatus;
    use crate::peer::PeerStatus;
    use crate::store::file::FileStore;

    fn make_state() -> ApiState<FileStore> {
        let store = FileStore::new(None);
        let trust_store = TrustStore::new(None);

        ApiState {
            store: Arc::new(std::sync::RwLock::new(store)),
            trust_store: Arc::new(trust_store),
            status_fn: Arc::new(|| FederationStatus {
                running: true,
                v1_server_active: true,
                v2_server_active: false,
                total_peers: 2,
                connected_peers: 1,
                peers: vec![],
                ha_enabled: false,
                pod_id: None,
            }),
            peer_status_fn: Arc::new(|_id| None),
        }
    }

    /// Extract the body bytes from a `Full<Bytes>` response.
    ///
    /// `Full<Bytes>` yields exactly one data frame and completes
    /// immediately, so we can poll it synchronously with a no-op
    /// waker — no tokio runtime needed.
    fn body_string(resp: Response<Full<Bytes>>) -> String {
        use std::pin::Pin;
        use std::task::{Context, Wake};

        use http_body::Body;

        struct NoopWaker;
        impl Wake for NoopWaker {
            fn wake(self: Arc<Self>) {}
        }

        let (_, mut body) = resp.into_parts();
        let waker = Arc::new(NoopWaker).into();
        let mut cx = Context::from_waker(&waker);

        let mut buf = bytes::BytesMut::new();
        while let std::task::Poll::Ready(Some(Ok(frame))) = Pin::new(&mut body).poll_frame(&mut cx)
        {
            if let Ok(data) = frame.into_data() {
                buf.extend_from_slice(&data);
            }
        }
        String::from_utf8_lossy(&buf).to_string()
    }

    // ── Routing tests ───────────────────────────────────────────

    #[test]
    fn non_federation_path_returns_none() {
        let state = make_state();
        assert!(handle_request(&Method::GET, "/healthz", &[], &state).is_none());
    }

    #[test]
    fn unknown_federation_path_returns_404() {
        let state = make_state();
        let resp =
            handle_request(&Method::GET, "/api/federation/unknown", &[], &state).expect("handle");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn route_connections() {
        let state = make_state();
        let resp =
            handle_request(&Method::GET, "/api/federation/connections", &[], &state).expect("h");
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[test]
    fn route_federates() {
        let state = make_state();
        let resp =
            handle_request(&Method::GET, "/api/federation/federates", &[], &state).expect("h");
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[test]
    fn route_certificates() {
        let state = make_state();
        let resp =
            handle_request(&Method::GET, "/api/federation/certificates", &[], &state).expect("h");
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[test]
    fn route_stats() {
        let state = make_state();
        let resp = handle_request(&Method::GET, "/api/federation/stats", &[], &state).expect("h");
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[test]
    fn route_status() {
        let state = make_state();
        let resp = handle_request(&Method::GET, "/api/federation/status", &[], &state).expect("h");
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // ── Connection tests ────────────────────────────────────────

    #[test]
    fn list_connections_returns_peers() {
        let state = make_state();
        let resp = handle_list_connections(&state);
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp);
        assert!(body.contains("\"data\""));
    }

    #[test]
    fn get_connection_not_found() {
        let state = make_state();
        let resp = handle_get_connection(&state, "nonexistent");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn get_connection_found() {
        let store = FileStore::new(None);
        let trust_store = TrustStore::new(None);

        let state = ApiState {
            store: Arc::new(std::sync::RwLock::new(store)),
            trust_store: Arc::new(trust_store),
            status_fn: Arc::new(|| FederationStatus {
                running: true,
                v1_server_active: true,
                v2_server_active: false,
                total_peers: 1,
                connected_peers: 1,
                peers: vec![],
                ha_enabled: false,
                pod_id: None,
            }),
            peer_status_fn: Arc::new(|id| {
                if id == "peer-1" {
                    Some(PeerStatus {
                        id: "peer-1".into(),
                        address: "10.0.0.1:9001".into(),
                        state: crate::peer::PeerState::Connected,
                        groups: vec!["Alpha".into()],
                        inbound_groups: None,
                        outbound_groups: None,
                        enabled: true,
                        is_outbound: true,
                        messages_sent: 10,
                        messages_recv: 5,
                        last_error: None,
                        connected_duration_secs: Some(120),
                        reconnect_count: 0,
                        circuit_state: crate::peer::CircuitState::Closed,
                        circuit_trips: 0,
                    })
                } else {
                    None
                }
            }),
        };

        let resp = handle_get_connection(&state, "peer-1");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp);
        assert!(body.contains("peer-1"));
    }

    // ── Federate tests ──────────────────────────────────────────

    #[test]
    fn list_federates_empty() {
        let state = make_state();
        let resp = handle_list_federates(&state);
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp);
        assert!(body.contains("\"data\":[]"));
    }

    #[test]
    fn create_federate_success() {
        let state = make_state();
        let body = serde_json::to_vec(&serde_json::json!({
            "id": "new-peer",
            "address": "10.0.0.2:9001",
            "groups": ["Alpha"],
            "is_outbound": true
        }))
        .expect("serialize");

        let resp = handle_create_federate(&state, &body);
        assert_eq!(resp.status(), StatusCode::CREATED);
        let resp_body = body_string(resp);
        assert!(resp_body.contains("new-peer"));

        // Verify it persists in store
        let resp = handle_list_federates(&state);
        let resp_body = body_string(resp);
        assert!(resp_body.contains("new-peer"));
    }

    #[test]
    fn create_federate_empty_id_fails() {
        let state = make_state();
        let body = serde_json::to_vec(&serde_json::json!({
            "id": "",
            "address": "10.0.0.2:9001"
        }))
        .expect("serialize");

        let resp = handle_create_federate(&state, &body);
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn create_federate_empty_address_fails() {
        let state = make_state();
        let body = serde_json::to_vec(&serde_json::json!({
            "id": "peer-1",
            "address": ""
        }))
        .expect("serialize");

        let resp = handle_create_federate(&state, &body);
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn create_federate_invalid_json_fails() {
        let state = make_state();
        let resp = handle_create_federate(&state, b"not json");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn get_federate_not_found() {
        let state = make_state();
        let resp = handle_get_federate(&state, "nonexistent");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn get_federate_found() {
        let state = make_state();
        let body = serde_json::to_vec(&serde_json::json!({
            "id": "peer-1",
            "address": "10.0.0.1:9001",
            "groups": ["Alpha"],
            "is_outbound": true
        }))
        .expect("serialize");
        let _ = handle_create_federate(&state, &body);

        let resp = handle_get_federate(&state, "peer-1");
        assert_eq!(resp.status(), StatusCode::OK);
        let resp_body = body_string(resp);
        assert!(resp_body.contains("peer-1"));
    }

    #[test]
    fn update_federate_success() {
        let state = make_state();
        let body = serde_json::to_vec(&serde_json::json!({
            "id": "peer-1",
            "address": "10.0.0.1:9001",
            "groups": ["Alpha"]
        }))
        .expect("serialize");
        let _ = handle_create_federate(&state, &body);

        let update = serde_json::to_vec(&serde_json::json!({
            "address": "10.0.0.2:9001"
        }))
        .expect("serialize");
        let resp = handle_update_federate(&state, "peer-1", &update);
        assert_eq!(resp.status(), StatusCode::OK);
        let resp_body = body_string(resp);
        assert!(resp_body.contains("10.0.0.2:9001"));
    }

    #[test]
    fn update_federate_not_found() {
        let state = make_state();
        let update = serde_json::to_vec(&serde_json::json!({
            "address": "10.0.0.2:9001"
        }))
        .expect("serialize");
        let resp = handle_update_federate(&state, "nonexistent", &update);
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn delete_federate_success() {
        let state = make_state();
        let body = serde_json::to_vec(&serde_json::json!({
            "id": "peer-1",
            "address": "10.0.0.1:9001"
        }))
        .expect("serialize");
        let _ = handle_create_federate(&state, &body);

        let resp = handle_delete_federate(&state, "peer-1");
        assert_eq!(resp.status(), StatusCode::OK);
        let resp_body = body_string(resp);
        assert!(resp_body.contains("peer-1"));

        // Verify it's gone
        let resp = handle_get_federate(&state, "peer-1");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn delete_federate_not_found() {
        let state = make_state();
        let resp = handle_delete_federate(&state, "nonexistent");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn enable_federate_success() {
        let state = make_state();
        let body = serde_json::to_vec(&serde_json::json!({
            "id": "peer-1",
            "address": "10.0.0.1:9001",
            "enabled": false
        }))
        .expect("serialize");
        let _ = handle_create_federate(&state, &body);

        let resp = handle_enable_federate(&state, "peer-1", true);
        assert_eq!(resp.status(), StatusCode::OK);
        let resp_body = body_string(resp);
        assert!(resp_body.contains("\"enabled\":true"));
    }

    #[test]
    fn enable_federate_not_found() {
        let state = make_state();
        let resp = handle_enable_federate(&state, "nonexistent", true);
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn disable_federate() {
        let state = make_state();
        let body = serde_json::to_vec(&serde_json::json!({
            "id": "peer-1",
            "address": "10.0.0.1:9001",
            "enabled": true
        }))
        .expect("serialize");
        let _ = handle_create_federate(&state, &body);

        let resp = handle_enable_federate(&state, "peer-1", false);
        assert_eq!(resp.status(), StatusCode::OK);
        let resp_body = body_string(resp);
        assert!(resp_body.contains("\"enabled\":false"));
    }

    #[test]
    fn set_routing_mode_success() {
        let state = make_state();
        let body = serde_json::to_vec(&serde_json::json!({
            "id": "peer-1",
            "address": "10.0.0.1:9001"
        }))
        .expect("serialize");
        let _ = handle_create_federate(&state, &body);

        let mode_body = serde_json::to_vec(&serde_json::json!({
            "routing_mode": "broadcast"
        }))
        .expect("serialize");
        let resp = handle_set_routing_mode(&state, "peer-1", &mode_body);
        assert_eq!(resp.status(), StatusCode::OK);
        let resp_body = body_string(resp);
        assert!(resp_body.contains("broadcast"));
    }

    #[test]
    fn set_routing_mode_invalid_json() {
        let state = make_state();
        let resp = handle_set_routing_mode(&state, "peer-1", b"bad");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    // ── Certificate tests ───────────────────────────────────────

    #[test]
    fn list_certificates_empty() {
        let state = make_state();
        let resp = handle_list_certificates(&state);
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp);
        assert!(body.contains("\"data\":[]"));
    }

    #[test]
    fn add_certificate_empty_body_fails() {
        let state = make_state();
        let resp = handle_add_certificate(&state, &[]);
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn add_certificate_invalid_pem_fails() {
        let state = make_state();
        let resp = handle_add_certificate(&state, b"not a PEM certificate");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn add_certificate_success() {
        use rustgate_test_utils::certs::TestCa;

        let ca = TestCa::new("API Test CA");
        let pem_bytes = ca.cert_pem.into_bytes();

        let tmp = tempfile::tempdir().expect("tempdir");
        let trust_store = TrustStore::new(Some(tmp.path().to_path_buf()));

        let state = ApiState {
            store: Arc::new(std::sync::RwLock::new(FileStore::new(None))),
            trust_store: Arc::new(trust_store),
            status_fn: Arc::new(|| FederationStatus {
                running: false,
                v1_server_active: false,
                v2_server_active: false,
                total_peers: 0,
                connected_peers: 0,
                peers: vec![],
                ha_enabled: false,
                pod_id: None,
            }),
            peer_status_fn: Arc::new(|_| None),
        };

        let resp = handle_add_certificate(&state, &pem_bytes);
        assert_eq!(resp.status(), StatusCode::CREATED);
        let body = body_string(resp);
        assert!(body.contains("API Test CA"));

        // Verify it appears in list
        let resp = handle_list_certificates(&state);
        let body = body_string(resp);
        assert!(body.contains("API Test CA"));
    }

    #[test]
    fn get_certificate_not_found() {
        let state = make_state();
        let resp = handle_get_certificate(&state, "nonexistent");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn delete_certificate_not_found() {
        let state = make_state();
        let resp = handle_delete_certificate(&state, "nonexistent");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // ── Stats / Status tests ────────────────────────────────────

    #[test]
    fn stats_endpoint() {
        let state = make_state();
        let resp = handle_stats(&state);
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp);
        assert!(body.contains("\"total_peers\""));
        assert!(body.contains("\"connected_peers\""));
        assert!(body.contains("\"running\""));
    }

    #[test]
    fn status_endpoint() {
        let state = make_state();
        let resp = handle_status(&state);
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp);
        assert!(body.contains("\"running\":true"));
        assert!(body.contains("\"v1_server_active\":true"));
    }

    // ── JSON helper tests ───────────────────────────────────────

    #[test]
    fn json_ok_response_format() {
        let resp = json_ok(&serde_json::json!({"key": "value"}));
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get("content-type")
                .map(|v| v.to_str().unwrap_or("")),
            Some("application/json")
        );
    }

    #[test]
    fn json_created_response_format() {
        let resp = json_created(&serde_json::json!({"id": "new"}));
        assert_eq!(resp.status(), StatusCode::CREATED);
        assert_eq!(
            resp.headers()
                .get("content-type")
                .map(|v| v.to_str().unwrap_or("")),
            Some("application/json")
        );
    }

    #[test]
    fn json_error_response_format() {
        let resp = json_error(StatusCode::BAD_REQUEST, "test error");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_string(resp);
        assert!(body.contains("test error"));
    }

    // ── Percent decode tests ────────────────────────────────────

    #[test]
    fn percent_decode_simple() {
        assert_eq!(percent_decode("hello"), "hello");
        assert_eq!(percent_decode("hello%20world"), "hello world");
        assert_eq!(percent_decode("a+b"), "a b");
        assert_eq!(percent_decode("test%2Fpath"), "test/path");
    }

    #[test]
    fn percent_decode_empty() {
        assert_eq!(percent_decode(""), "");
    }

    #[test]
    fn percent_decode_all_encoded() {
        assert_eq!(percent_decode("%48%65%6C%6C%6F"), "Hello");
    }

    // ── Misc tests ──────────────────────────────────────────────

    #[test]
    fn api_state_debug() {
        let state = make_state();
        let debug = format!("{state:?}");
        assert!(debug.contains("ApiState"));
    }

    #[test]
    fn hex_nibble_values() {
        assert_eq!(hex_nibble(b'0'), 0);
        assert_eq!(hex_nibble(b'9'), 9);
        assert_eq!(hex_nibble(b'a'), 10);
        assert_eq!(hex_nibble(b'f'), 15);
        assert_eq!(hex_nibble(b'A'), 10);
        assert_eq!(hex_nibble(b'F'), 15);
        assert_eq!(hex_nibble(b'g'), 0);
    }

    #[test]
    fn hex_byte_values() {
        assert_eq!(hex_byte(b'2', b'0'), 0x20);
        assert_eq!(hex_byte(b'4', b'1'), 0x41);
        assert_eq!(hex_byte(b'F', b'F'), 0xFF);
    }

    #[test]
    fn create_federate_with_all_fields() {
        let state = make_state();
        let body = serde_json::to_vec(&serde_json::json!({
            "id": "full-peer",
            "address": "10.0.0.5:9001",
            "groups": ["Alpha", "Bravo"],
            "enabled": true,
            "is_outbound": true,
            "trust_cert_cn": "peer-cert",
            "routing_mode": "broadcast"
        }))
        .expect("serialize");

        let resp = handle_create_federate(&state, &body);
        assert_eq!(resp.status(), StatusCode::CREATED);
        let resp_body = body_string(resp);
        assert!(resp_body.contains("full-peer"));
        assert!(resp_body.contains("broadcast"));
    }

    #[test]
    fn update_federate_groups() {
        let state = make_state();
        let body = serde_json::to_vec(&serde_json::json!({
            "id": "peer-1",
            "address": "10.0.0.1:9001",
            "groups": ["Alpha"]
        }))
        .expect("serialize");
        let _ = handle_create_federate(&state, &body);

        let update = serde_json::to_vec(&serde_json::json!({
            "groups": ["Alpha", "Bravo", "Charlie"]
        }))
        .expect("serialize");
        let resp = handle_update_federate(&state, "peer-1", &update);
        assert_eq!(resp.status(), StatusCode::OK);
        let resp_body = body_string(resp);
        assert!(resp_body.contains("Charlie"));
    }

    #[test]
    fn route_get_connection_by_id() {
        let state = make_state();
        let resp = handle_request(
            &Method::GET,
            "/api/federation/connections/peer-1",
            &[],
            &state,
        )
        .expect("h");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn route_delete_federate() {
        let state = make_state();
        let resp = handle_request(
            &Method::DELETE,
            "/api/federation/federates/peer-1",
            &[],
            &state,
        )
        .expect("h");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn route_get_certificate_by_cn() {
        let state = make_state();
        let resp = handle_request(
            &Method::GET,
            "/api/federation/certificates/my-ca",
            &[],
            &state,
        )
        .expect("h");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn route_delete_certificate() {
        let state = make_state();
        let resp = handle_request(
            &Method::DELETE,
            "/api/federation/certificates/my-ca",
            &[],
            &state,
        )
        .expect("h");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn internal_error_response_returns_500() {
        let resp = internal_error_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
