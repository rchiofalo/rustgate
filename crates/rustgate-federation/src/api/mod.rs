//! REST API for federation management.
//!
//! Provides HTTP endpoints for managing federation peers, certificates,
//! and monitoring connection status. Designed to be mounted alongside
//! the existing metrics HTTP server in `rustgate-server`.
//!
//! ## Routes
//!
//! ### Connections
//! - `GET  /api/federation/connections`      -- list all active connections
//! - `GET  /api/federation/connections/{id}`  -- get specific connection
//!
//! ### Federates
//! - `GET    /api/federation/federates`            -- list all configured federates
//! - `POST   /api/federation/federates`            -- add new federate
//! - `GET    /api/federation/federates/{id}`        -- get federate details
//! - `PUT    /api/federation/federates/{id}`        -- update federate
//! - `DELETE /api/federation/federates/{id}`        -- remove federate
//! - `PUT    /api/federation/federates/{id}/enable`  -- enable federate
//! - `PUT    /api/federation/federates/{id}/disable` -- disable federate
//! - `PUT    /api/federation/federates/{id}/routing-mode` -- set routing mode
//!
//! ### Certificates
//! - `GET    /api/federation/certificates`      -- list trusted CA certificates
//! - `POST   /api/federation/certificates`      -- upload CA certificate (PEM body)
//! - `GET    /api/federation/certificates/{cn}` -- get certificate info
//! - `DELETE /api/federation/certificates/{cn}` -- remove certificate
//!
//! ### Status
//! - `GET /api/federation/stats`  -- aggregated statistics
//! - `GET /api/federation/status` -- federation manager status

mod handlers;
mod helpers;
mod types;

use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Method, Response, StatusCode};

use self::handlers::{
    handle_add_certificate, handle_create_federate, handle_delete_certificate,
    handle_delete_federate, handle_enable_federate, handle_get_certificate, handle_get_connection,
    handle_get_federate, handle_list_certificates, handle_list_connections, handle_list_federates,
    handle_set_routing_mode, handle_stats, handle_status, handle_update_federate,
};
use self::helpers::{json_error, percent_decode};
pub use self::types::{CreateFederateRequest, SetRoutingModeRequest, UpdateFederateRequest};
use crate::manager::FederationStatus;
use crate::peer::PeerStatus;
use crate::store::FederateStore;
use crate::trust_store::TrustStore;

/// Callback type for looking up a peer's status by ID.
pub type PeerStatusFn = Arc<dyn Fn(&str) -> Option<PeerStatus> + Send + Sync>;

/// Shared state provided to the API handler.
///
/// The caller (e.g., `rustgate-server`) constructs this and passes it
/// to [`handle_request`] for each incoming HTTP request that matches
/// the `/api/federation/` prefix.
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

#[cfg(test)]
mod tests {
    use self::helpers::{hex_byte, hex_nibble, internal_error_response, json_created, json_ok};
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
    /// waker -- no tokio runtime needed.
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
