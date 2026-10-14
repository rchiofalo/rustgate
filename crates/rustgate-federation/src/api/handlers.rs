// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Request handlers for the federation REST API.
//!
//! Each handler corresponds to one or more API endpoints and operates
//! on the shared [`ApiState`](super::ApiState).

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Response, StatusCode};

use super::ApiState;
use super::helpers::{json_created, json_error, json_ok};
use super::types::{CreateFederateRequest, SetRoutingModeRequest, UpdateFederateRequest};
use crate::store::{FederateInfo, FederateStore, FederateUpdate};

// ── Connection handlers ─────────────────────────────────────────────

pub(crate) fn handle_list_connections<S: FederateStore>(
    state: &ApiState<S>,
) -> Response<Full<Bytes>> {
    let status = (state.status_fn)();
    json_ok(&status.peers)
}

pub(crate) fn handle_get_connection<S: FederateStore>(
    state: &ApiState<S>,
    id: &str,
) -> Response<Full<Bytes>> {
    match (state.peer_status_fn)(id) {
        Some(peer) => json_ok(&peer),
        None => json_error(StatusCode::NOT_FOUND, "connection not found"),
    }
}

// ── Federate handlers ───────────────────────────────────────────────

pub(crate) fn handle_list_federates<S: FederateStore>(
    state: &ApiState<S>,
) -> Response<Full<Bytes>> {
    match state.store.read() {
        Ok(store) => json_ok(&store.list()),
        Err(e) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("store lock poisoned: {e}"),
        ),
    }
}

pub(crate) fn handle_create_federate<S: FederateStore>(
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

pub(crate) fn handle_get_federate<S: FederateStore>(
    state: &ApiState<S>,
    id: &str,
) -> Response<Full<Bytes>> {
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

pub(crate) fn handle_update_federate<S: FederateStore>(
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

pub(crate) fn handle_delete_federate<S: FederateStore>(
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

pub(crate) fn handle_enable_federate<S: FederateStore>(
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

pub(crate) fn handle_set_routing_mode<S: FederateStore>(
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

pub(crate) fn handle_list_certificates<S: FederateStore>(
    state: &ApiState<S>,
) -> Response<Full<Bytes>> {
    match state.trust_store.list_certificates() {
        Ok(certs) => json_ok(&certs),
        Err(e) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("trust store lock poisoned: {e}"),
        ),
    }
}

pub(crate) fn handle_add_certificate<S: FederateStore>(
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

pub(crate) fn handle_get_certificate<S: FederateStore>(
    state: &ApiState<S>,
    cn: &str,
) -> Response<Full<Bytes>> {
    match state.trust_store.get_certificate_info(cn) {
        Ok(Some(info)) => json_ok(&info),
        Ok(None) => json_error(StatusCode::NOT_FOUND, "certificate not found"),
        Err(e) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("trust store lock poisoned: {e}"),
        ),
    }
}

pub(crate) fn handle_delete_certificate<S: FederateStore>(
    state: &ApiState<S>,
    cn: &str,
) -> Response<Full<Bytes>> {
    match state.trust_store.remove_certificate(cn) {
        Ok(true) => json_ok(&serde_json::json!({ "deleted": cn })),
        Ok(false) => json_error(StatusCode::NOT_FOUND, "certificate not found"),
        Err(e) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("trust store lock poisoned: {e}"),
        ),
    }
}

// ── Stats / Status handlers ─────────────────────────────────────────

pub(crate) fn handle_stats<S: FederateStore>(state: &ApiState<S>) -> Response<Full<Bytes>> {
    let status = (state.status_fn)();

    let total_sent: u64 = status.peers.iter().map(|p| p.messages_sent).sum();
    let total_recv: u64 = status.peers.iter().map(|p| p.messages_recv).sum();

    let stats = serde_json::json!({
        "total_peers": status.total_peers,
        "connected_peers": status.connected_peers,
        "running": status.running,
        "messages_sent": total_sent,
        "messages_received": total_recv,
        "certificates": state.trust_store.count().unwrap_or(0),
    });

    json_ok(&stats)
}

pub(crate) fn handle_status<S: FederateStore>(state: &ApiState<S>) -> Response<Full<Bytes>> {
    let status = (state.status_fn)();
    json_ok(&status)
}

// ── JWKS handler (closes #760) ──────────────────────────────────────

/// Serve the federation JWT verifier's currently-trusted JWKS at
/// `/.well-known/jwks.json`. Returns RFC 7517 envelope `{"keys": […]}`.
///
/// The response body is a bare JWKS document, not the workspace's
/// `{"data": …}` envelope used by the rest of the management API —
/// JWKS is a public-spec endpoint that third-party JWT libraries
/// expect to deserialize without unwrapping. The content-type is
/// `application/jwk-set+json` per RFC 7517 §8.5.
///
/// When [`super::ApiState::jwks_fn`] returns `None` the endpoint
/// responds `404 Not Found` so consumers can distinguish "JWKS not
/// configured" (federation JWT auth disabled) from "empty key set"
/// (configured but no asymmetric verifiers registered).
pub(crate) fn handle_jwks<S: FederateStore>(state: &ApiState<S>) -> Response<Full<Bytes>> {
    let Some(jwks) = (state.jwks_fn)() else {
        return json_error(StatusCode::NOT_FOUND, "JWKS not configured");
    };
    let body = match serde_json::to_vec(&jwks) {
        Ok(b) => b,
        Err(e) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("JWKS serialization failed: {e}"),
            );
        }
    };
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/jwk-set+json")
        // RFC 8615: a discovery URI is cacheable for short windows.
        // Five minutes balances "operator rotated a key and wants
        // verifiers to pick it up" against "verifier hammers JWKS
        // every request".
        .header("cache-control", "public, max-age=300")
        .body(Full::new(Bytes::from(body)))
        .unwrap_or_else(|_| super::helpers::internal_error_response())
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    //! Defensive unit tests for every `pub(crate)` handler in this file.
    //!
    //! The handlers are fan-in points for the federation REST API — every
    //! `POST`/`PUT`/`DELETE` the external management plane can reach flows
    //! through one of them. Before this test module existed the file had
    //! zero inline tests; the only coverage was the happy-path
    //! `api_integration.rs` integration test that exercises
    //! `handle_request` end-to-end without pinning the individual
    //! handlers' status codes, JSON envelope shape, or required-field
    //! validation. A silent regression that (a) dropped the 404 arm of
    //! `handle_get_federate`, (b) changed `handle_create_federate` to
    //! accept an empty id or address, (c) stopped surfacing the
    //! `{"deleted": id}` payload on delete success, (d) let
    //! `handle_add_certificate` touch the trust store on an empty body,
    //! (e) stopped propagating `trust_store` and `store` errors as 404s,
    //! or (f) regressed the `handle_stats` aggregation math across
    //! `messages_sent` / `messages_recv` would all ship green until a
    //! downstream consumer noticed.
    //!
    //! Each test constructs a fresh `ApiState<FileStore>` (in-memory,
    //! `FileStore::new(None)`) so there's no filesystem contention and
    //! the tests parallelise cleanly under nextest. The `trust_store` is
    //! always `TrustStore::new(None)` (in-memory, no disk persistence).
    //! Response bodies are collected via the same `BodyExt::collect`
    //! pattern the `helpers.rs` test module uses so the decoding path
    //! stays consistent across the api module's test surface.

    use std::sync::Arc;

    use http_body_util::BodyExt;
    use rustgate_core::peer_id::PeerId;

    use super::*;
    use crate::api::PeerStatusFn;
    use crate::config::RoutingMode;
    use crate::manager::FederationStatus;
    use crate::peer::{CircuitState, PeerState, PeerStatus};
    use crate::store::file::FileStore;
    use crate::trust_store::TrustStore;

    async fn body_bytes(resp: Response<Full<Bytes>>) -> Bytes {
        resp.into_body()
            .collect()
            .await
            .expect("collect body")
            .to_bytes()
    }

    async fn body_json(resp: Response<Full<Bytes>>) -> serde_json::Value {
        let bytes = body_bytes(resp).await;
        serde_json::from_slice(&bytes).expect("response body must be valid JSON")
    }

    fn empty_status() -> FederationStatus {
        FederationStatus {
            running: false,
            v1_server_active: false,
            v2_server_active: false,
            total_peers: 0,
            connected_peers: 0,
            peers: vec![],
            ha_enabled: false,
            pod_id: None,
        }
    }

    fn make_peer(id: &str, sent: u64, recv: u64) -> PeerStatus {
        PeerStatus {
            id: PeerId::new(id.to_string()),
            address: format!("10.0.0.1:{}", 9000 + id.len() as u16),
            state: PeerState::Connected,
            groups: vec!["Alpha".into()],
            inbound_groups: None,
            outbound_groups: None,
            enabled: true,
            is_outbound: true,
            messages_sent: sent,
            messages_recv: recv,
            last_error: None,
            connected_duration_secs: Some(42),
            reconnect_count: 0,
            circuit_state: CircuitState::Closed,
            circuit_trips: 0,
        }
    }

    fn make_state_with(
        status_fn: Arc<dyn Fn() -> FederationStatus + Send + Sync>,
        peer_status_fn: PeerStatusFn,
    ) -> ApiState<FileStore> {
        ApiState {
            store: Arc::new(std::sync::RwLock::new(FileStore::new(None))),
            trust_store: Arc::new(TrustStore::new(None)),
            status_fn,
            peer_status_fn,
            jwks_fn: Arc::new(|| None),
        }
    }

    fn make_default_state() -> ApiState<FileStore> {
        make_state_with(Arc::new(empty_status), Arc::new(|_| None))
    }

    /// Priming helper: insert one federate so `get`/`update`/`delete`
    /// handlers can exercise the happy path. The test asserts the
    /// insert worked before returning.
    fn prime_federate(state: &ApiState<FileStore>, id: &str) -> FederateInfo {
        let info = FederateInfo {
            id: id.to_string(),
            address: "10.0.0.1:9001".into(),
            groups: vec!["Alpha".into()],
            inbound_groups: None,
            outbound_groups: None,
            enabled: true,
            is_outbound: true,
            trust_cert_cn: None,
            routing_mode: RoutingMode::Matrix,
            created_at: std::time::SystemTime::now(),
            last_seen: None,
            messages_sent: 0,
            messages_recv: 0,
        };
        state.store.write().expect("write lock").add(info.clone());
        assert!(
            state.store.read().expect("read lock").get(id).is_some(),
            "prime_federate must leave the entry discoverable via get()"
        );
        info
    }

    // ── handle_list_connections / handle_get_connection ─────────────────

    /// Pins the contract that `handle_list_connections` surfaces the
    /// `peers` vector produced by `state.status_fn` wrapped in the
    /// standard `{"data": [...]}` success envelope. A regression that
    /// accidentally dropped the envelope, serialized the full
    /// `FederationStatus` (leaking `running`/`pod_id`/etc. into the
    /// response), or forgot to call `status_fn` at all would fail here.
    #[tokio::test]
    async fn handle_list_connections_surfaces_status_fn_peers_in_data_envelope() {
        let state = make_state_with(
            Arc::new(|| {
                let mut s = empty_status();
                s.peers = vec![make_peer("peer-a", 1, 2), make_peer("peer-b", 3, 4)];
                s.total_peers = 2;
                s
            }),
            Arc::new(|_| None),
        );
        let resp = handle_list_connections(&state);
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        let data = json.get("data").expect("response must use data envelope");
        let arr = data.as_array().expect("data must be an array");
        assert_eq!(
            arr.len(),
            2,
            "two peers must round-trip through the handler"
        );
        // Asserting on ids is stable across PeerStatus field churn; a
        // regression that changed the serialisation shape (e.g. moved
        // the id inside a nested `peer` object) would still fail.
        let ids: Vec<&str> = arr
            .iter()
            .map(|p| p.get("id").and_then(|v| v.as_str()).unwrap_or(""))
            .collect();
        assert!(ids.contains(&"peer-a") && ids.contains(&"peer-b"));
    }

    /// Pins the 404 arm of `handle_get_connection` — when the
    /// `peer_status_fn` closure returns `None`, the handler must emit
    /// a 404 with an error envelope carrying a human-readable message.
    /// A regression that swallowed the `None` into a 200 with empty body
    /// would silently mask every "connection disappeared between listing
    /// and detail view" case in the management UI.
    #[tokio::test]
    async fn handle_get_connection_returns_404_envelope_when_peer_status_fn_returns_none() {
        let state = make_default_state(); // peer_status_fn always returns None
        let resp = handle_get_connection(&state, "ghost-peer");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let json = body_json(resp).await;
        let err = json
            .get("error")
            .and_then(|v| v.as_str())
            .expect("404 must use error envelope with 'error' string");
        assert!(
            err.contains("not found"),
            "error message must mention 'not found'; got: {err}",
        );
    }

    /// Pins the happy path for `handle_get_connection` — a `Some(peer)`
    /// from the callback must produce 200 + peer JSON inside the data
    /// envelope. The callback returns a peer whose id matches the
    /// lookup; this test guards against a regression that forgot to
    /// serialize the peer through the envelope.
    #[tokio::test]
    async fn handle_get_connection_returns_peer_inside_data_envelope_when_found() {
        let state = make_state_with(
            Arc::new(empty_status),
            Arc::new(|id| Some(make_peer(id, 10, 20))),
        );
        let resp = handle_get_connection(&state, "live-peer");
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        let peer = json.get("data").expect("data envelope");
        assert_eq!(peer.get("id").and_then(|v| v.as_str()), Some("live-peer"));
        assert_eq!(peer.get("messages_sent").and_then(|v| v.as_u64()), Some(10));
    }

    // ── handle_create_federate ──────────────────────────────────────────

    /// Pins the 400-on-malformed-JSON contract for create. A regression
    /// that started accepting `{` or `null` and silently constructed a
    /// default-valued federate would be a silent corruption of the
    /// store — the test routes through the same `serde_json::from_slice`
    /// path the handler uses.
    #[tokio::test]
    async fn handle_create_federate_rejects_malformed_json_with_400() {
        let state = make_default_state();
        let resp = handle_create_federate(&state, b"{");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let err = body_json(resp)
            .await
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        assert!(
            err.contains("invalid JSON"),
            "error must mention 'invalid JSON'; got: {err}",
        );
    }

    /// Pins the "id is required" branch — a create with a present-but-
    /// empty id must 400 with a specific message rather than inserting
    /// an empty-id federate that would be unrecoverable without direct
    /// JSON file edits.
    #[tokio::test]
    async fn handle_create_federate_rejects_empty_id_with_specific_message() {
        let state = make_default_state();
        let body = br#"{"id":"","address":"10.0.0.1:9001"}"#;
        let resp = handle_create_federate(&state, body);
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let err = body_json(resp)
            .await
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        assert!(
            err.contains("id is required"),
            "error must name the missing 'id' field; got: {err}",
        );
    }

    /// Mirrors the id-check for address — the two guards live on
    /// consecutive lines and a regression that deleted one by accident
    /// while refactoring the other is exactly the shape this test
    /// catches.
    #[tokio::test]
    async fn handle_create_federate_rejects_empty_address_with_specific_message() {
        let state = make_default_state();
        let body = br#"{"id":"peer-1","address":""}"#;
        let resp = handle_create_federate(&state, body);
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let err = body_json(resp)
            .await
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        assert!(
            err.contains("address is required"),
            "error must name the missing 'address' field; got: {err}",
        );
    }

    /// Happy path — valid JSON produces a 201 Created, the response
    /// body carries the full `FederateInfo`, and the side effect on the
    /// store is visible to a follow-up `get`. Pinning both the response
    /// and the side effect guards against a regression where the
    /// handler returned 201 without actually inserting (a silent drop
    /// that would only surface on the next list-federates call).
    #[tokio::test]
    async fn handle_create_federate_returns_201_and_persists_to_store() {
        let state = make_default_state();
        let body = br#"{"id":"peer-new","address":"10.0.0.5:9001","groups":["Alpha"]}"#;
        let resp = handle_create_federate(&state, body);
        assert_eq!(resp.status(), StatusCode::CREATED);
        let data = body_json(resp).await;
        let peer = data.get("data").expect("data envelope");
        assert_eq!(peer.get("id").and_then(|v| v.as_str()), Some("peer-new"));
        // Side-effect check: the record is discoverable via the store.
        let stored = state
            .store
            .read()
            .expect("read lock")
            .get("peer-new")
            .expect("created federate must be in the store");
        assert_eq!(stored.address, "10.0.0.5:9001");
        assert_eq!(stored.groups, vec!["Alpha".to_string()]);
    }

    // ── handle_get_federate / handle_update_federate ────────────────────

    /// Pins the 404 arm of `handle_get_federate` — a lookup for an id
    /// that was never inserted must produce 404 + error envelope. A
    /// regression that returned 200 with an empty data envelope or a
    /// partial federate record with default fields would silently mask
    /// every "does this federate exist" preflight in the UI.
    #[tokio::test]
    async fn handle_get_federate_returns_404_envelope_for_unknown_id() {
        let state = make_default_state();
        let resp = handle_get_federate(&state, "never-inserted");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let err = body_json(resp)
            .await
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        assert!(err.contains("not found"), "got: {err}");
    }

    /// Pins that `handle_update_federate` routes malformed JSON to a
    /// 400 *without* taking the store write lock — a regression that
    /// acquired the lock before parsing would expose the store's
    /// backing HashMap to an unnecessary contention window under a
    /// bulk-typo scenario.
    #[tokio::test]
    async fn handle_update_federate_rejects_malformed_json_with_400() {
        let state = make_default_state();
        let resp = handle_update_federate(&state, "peer-x", b"not-json");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let err = body_json(resp)
            .await
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        assert!(err.contains("invalid JSON"), "got: {err}");
    }

    /// Pins the 404 arm of `handle_update_federate` — when the store's
    /// `update` call errors because the id does not exist, the handler
    /// must surface that as 404, not 500. The store returns an error
    /// (not `Option::None`) for this case, so this test also guards the
    /// `Err(e) => json_error(NOT_FOUND, ...)` arm from accidentally
    /// being reclassified as INTERNAL_SERVER_ERROR.
    #[tokio::test]
    async fn handle_update_federate_returns_404_when_id_does_not_exist() {
        let state = make_default_state();
        let body = br#"{"address":"10.0.0.9:9001"}"#;
        let resp = handle_update_federate(&state, "missing-id", body);
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // ── handle_delete_federate ──────────────────────────────────────────

    /// Pins both branches of `handle_delete_federate` in one test: a
    /// first delete against a primed federate returns 200 with the
    /// `{"deleted": id}` payload, and the second delete (against the
    /// same — now absent — id) returns 404. A regression that always
    /// returned 200 would let the management UI present "delete
    /// succeeded" for every nonexistent id, masking config drift.
    #[tokio::test]
    async fn handle_delete_federate_returns_deleted_payload_then_404_on_second_call() {
        let state = make_default_state();
        let _info = prime_federate(&state, "peer-del");

        let first = handle_delete_federate(&state, "peer-del");
        assert_eq!(first.status(), StatusCode::OK);
        let json = body_json(first).await;
        let data = json.get("data").expect("data envelope");
        assert_eq!(
            data.get("deleted").and_then(|v| v.as_str()),
            Some("peer-del"),
            "200 body must carry the deleted id",
        );

        let second = handle_delete_federate(&state, "peer-del");
        assert_eq!(
            second.status(),
            StatusCode::NOT_FOUND,
            "second delete of same id must 404",
        );
    }

    // ── handle_enable_federate / handle_set_routing_mode ────────────────

    /// Pins the 404 arm of `handle_enable_federate` — store errors must
    /// surface as 404 so the management UI can surface a clean "that
    /// federate is gone" rather than a generic 500.
    #[tokio::test]
    async fn handle_enable_federate_returns_404_for_unknown_id() {
        let state = make_default_state();
        let resp = handle_enable_federate(&state, "missing-id", true);
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// Pins the happy path of `handle_set_routing_mode` — an update
    /// from the default Matrix mode to Broadcast must round-trip
    /// through the store and be visible to a follow-up `get`. This
    /// test is the primary cross-check that the request-body-parsed
    /// `routing_mode` field is the one actually applied; a regression
    /// that accidentally dropped it on the floor would return 200 +
    /// the old routing mode without changing anything.
    #[tokio::test]
    async fn handle_set_routing_mode_round_trips_matrix_to_broadcast() {
        let state = make_default_state();
        let _info = prime_federate(&state, "peer-mode");
        // Sanity: starts at Matrix (the default from prime_federate).
        assert_eq!(
            state
                .store
                .read()
                .expect("read lock")
                .get("peer-mode")
                .expect("primed")
                .routing_mode,
            RoutingMode::Matrix,
        );

        let resp = handle_set_routing_mode(&state, "peer-mode", br#"{"routing_mode":"broadcast"}"#);
        assert_eq!(resp.status(), StatusCode::OK);
        let data = body_json(resp).await;
        assert_eq!(
            data.get("data")
                .and_then(|d| d.get("routing_mode"))
                .and_then(|v| v.as_str()),
            Some("broadcast"),
            "response body must show updated routing_mode",
        );
        // Side-effect check: the change survives in the store.
        assert_eq!(
            state
                .store
                .read()
                .expect("read lock")
                .get("peer-mode")
                .expect("still there")
                .routing_mode,
            RoutingMode::Broadcast,
        );
    }

    /// Pins the 400 arm of `handle_set_routing_mode` — malformed JSON
    /// must reject cleanly without touching the store. The body
    /// `{"routing_mode":"invalid"}` trips serde's `rename_all =
    /// "lowercase"` enum deserializer, producing an `invalid value`
    /// error that serde surfaces inside the 400 envelope.
    #[tokio::test]
    async fn handle_set_routing_mode_rejects_unknown_enum_variant_with_400() {
        let state = make_default_state();
        let _info = prime_federate(&state, "peer-mode");
        let resp = handle_set_routing_mode(&state, "peer-mode", br#"{"routing_mode":"bogus"}"#);
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        // The record must not have been mutated.
        assert_eq!(
            state
                .store
                .read()
                .expect("read lock")
                .get("peer-mode")
                .expect("still there")
                .routing_mode,
            RoutingMode::Matrix,
            "routing_mode must not change when request body is invalid",
        );
    }

    // ── handle_add_certificate / handle_get_certificate /
    //    handle_delete_certificate ──────────────────────────────────────

    /// Pins the empty-body guard on `handle_add_certificate` —
    /// the check must fire *before* any call into the trust store so a
    /// client that sends `Content-Length: 0` cannot cause a PEM-parse
    /// path to open a file, allocate a buffer, or any other side effect.
    /// A regression that moved the guard below the `add_certificate_from_pem`
    /// call would still return 400 but would have already done
    /// non-trivial work.
    #[tokio::test]
    async fn handle_add_certificate_rejects_empty_body_with_400() {
        let state = make_default_state();
        let resp = handle_add_certificate(&state, b"");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let err = body_json(resp)
            .await
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        assert!(
            err.contains("PEM body is required"),
            "error must mention required PEM body; got: {err}",
        );
        // The trust store must remain empty — no side effect on the empty-body path.
        assert_eq!(
            state.trust_store.count().expect("trust_store count"),
            0,
            "empty-body rejection must not insert into trust store",
        );
    }

    /// Pins that a non-empty-but-unparsable body routes through
    /// `trust_store.add_certificate_from_pem` and produces a 400 with
    /// the upstream error `Display` text inside the envelope. A
    /// regression that reclassified this to 500 would make operator
    /// feedback on a pasted cert typo much worse.
    #[tokio::test]
    async fn handle_add_certificate_rejects_malformed_pem_with_400() {
        let state = make_default_state();
        let resp = handle_add_certificate(
            &state,
            b"-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n",
        );
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            state.trust_store.count().expect("trust_store count"),
            0,
            "malformed-PEM rejection must not insert into trust store",
        );
    }

    /// Pins the 404 arm of `handle_get_certificate`. A regression that
    /// returned 200 with a null `data` field would break every
    /// "does this cert exist" preflight on the management UI.
    #[tokio::test]
    async fn handle_get_certificate_returns_404_for_unknown_cn() {
        let state = make_default_state();
        let resp = handle_get_certificate(&state, "cn-does-not-exist");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// Pins the 404 arm of `handle_delete_certificate` — `remove`
    /// returning `Ok(false)` must surface as 404 rather than 200 with
    /// an empty body, so the UI can distinguish "deleted" from
    /// "never existed".
    #[tokio::test]
    async fn handle_delete_certificate_returns_404_for_unknown_cn() {
        let state = make_default_state();
        let resp = handle_delete_certificate(&state, "cn-does-not-exist");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // ── handle_stats / handle_status ────────────────────────────────────

    /// Pins the aggregation math in `handle_stats` — the handler sums
    /// `messages_sent` and `messages_recv` across every peer returned
    /// by `status_fn`, then reports the totals plus the trust-store
    /// certificate count inside the data envelope. A regression that
    /// swapped `sum()` for `count()`, forgot to aggregate one of the
    /// two counters, or stopped calling `trust_store.count()` entirely
    /// would all trip at least one of the four assertions below.
    #[tokio::test]
    async fn handle_stats_aggregates_messages_across_peers_and_exposes_trust_store_count() {
        let state = make_state_with(
            Arc::new(|| {
                let mut s = empty_status();
                s.running = true;
                s.peers = vec![
                    make_peer("p1", 10, 1),
                    make_peer("p2", 20, 2),
                    make_peer("p3", 30, 3),
                ];
                s.total_peers = 3;
                s.connected_peers = 2;
                s
            }),
            Arc::new(|_| None),
        );
        let resp = handle_stats(&state);
        assert_eq!(resp.status(), StatusCode::OK);
        let data = body_json(resp).await;
        let stats = data.get("data").expect("data envelope");
        assert_eq!(
            stats.get("messages_sent").and_then(|v| v.as_u64()),
            Some(60),
            "messages_sent must sum across peers (10+20+30)",
        );
        assert_eq!(
            stats.get("messages_received").and_then(|v| v.as_u64()),
            Some(6),
            "messages_received must sum across peers (1+2+3)",
        );
        assert_eq!(stats.get("total_peers").and_then(|v| v.as_u64()), Some(3),);
        assert_eq!(
            stats.get("certificates").and_then(|v| v.as_u64()),
            Some(0),
            "certificates field must surface trust_store.count() (0 on fresh store)",
        );
    }

    /// Pins that `handle_status` returns the full status snapshot
    /// produced by `status_fn`, not a filtered subset. A regression
    /// that accidentally stripped the `ha_enabled` flag or flipped
    /// `running` on every response would fail here.
    #[tokio::test]
    async fn handle_status_returns_status_fn_snapshot_verbatim() {
        let state = make_state_with(
            Arc::new(|| {
                let mut s = empty_status();
                s.running = true;
                s.v1_server_active = true;
                s.ha_enabled = true;
                s.pod_id = Some("pod-7".into());
                s
            }),
            Arc::new(|_| None),
        );
        let resp = handle_status(&state);
        assert_eq!(resp.status(), StatusCode::OK);
        let data = body_json(resp).await;
        let status = data.get("data").expect("data envelope");
        assert_eq!(status.get("running").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(
            status.get("v1_server_active").and_then(|v| v.as_bool()),
            Some(true),
        );
        assert_eq!(
            status.get("ha_enabled").and_then(|v| v.as_bool()),
            Some(true),
        );
        assert_eq!(status.get("pod_id").and_then(|v| v.as_str()), Some("pod-7"),);
    }

    /// Pins the happy path for `handle_list_federates` on a fresh
    /// in-memory store — the response is 200 with an empty `data`
    /// array. A regression that returned `null` or `{}` instead of
    /// `[]` would break every JSON-strict consumer.
    #[tokio::test]
    async fn handle_list_federates_returns_empty_array_on_fresh_store() {
        let state = make_default_state();
        let resp = handle_list_federates(&state);
        assert_eq!(resp.status(), StatusCode::OK);
        let data = body_json(resp).await;
        let arr = data
            .get("data")
            .and_then(|v| v.as_array())
            .expect("data must be array");
        assert!(arr.is_empty(), "fresh store must produce empty array");
    }

    /// Pins that `handle_list_certificates` returns an empty array
    /// (not `null`) on a freshly-constructed in-memory trust store.
    /// Same rationale as the federate list test: JSON-strict clients
    /// rely on the shape being a list.
    #[tokio::test]
    async fn handle_list_certificates_returns_empty_array_on_fresh_trust_store() {
        let state = make_default_state();
        let resp = handle_list_certificates(&state);
        assert_eq!(resp.status(), StatusCode::OK);
        let data = body_json(resp).await;
        let arr = data
            .get("data")
            .and_then(|v| v.as_array())
            .expect("data must be array");
        assert!(arr.is_empty(), "fresh trust store must produce empty array");
    }
}
