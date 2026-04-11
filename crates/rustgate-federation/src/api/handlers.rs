// Copyright © 2026 Roberto Chiofalo.

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
