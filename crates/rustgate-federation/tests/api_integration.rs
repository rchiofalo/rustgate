// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

#![cfg(feature = "api")]
#![allow(clippy::panic, clippy::unwrap_used)]

//! Integration tests for the federation API feature gate.
//!
//! These tests verify that the `api` feature correctly exposes the
//! federation REST API module and its public types.

use std::sync::Arc;

use rustgate_federation::api::{
    ApiState, CreateFederateRequest, PeerStatusFn, SetRoutingModeRequest, UpdateFederateRequest,
    handle_request,
};
use rustgate_federation::manager::FederationStatus;
use rustgate_federation::store::FederateStore;
use rustgate_federation::store::file::FileStore;
use rustgate_federation::trust_store::TrustStore;

/// Verify the API types are accessible when the `api` feature is enabled.
#[test]
fn api_types_accessible() {
    // CreateFederateRequest can be deserialized
    let json = r#"{"id":"peer-1","address":"10.0.0.1:9001","groups":["Alpha"]}"#;
    let req: CreateFederateRequest = serde_json::from_str(json).unwrap();
    assert_eq!(req.id, "peer-1");
    assert_eq!(req.address, "10.0.0.1:9001");

    // UpdateFederateRequest can be deserialized
    let json = r#"{"address":"10.0.0.2:9001"}"#;
    let req: UpdateFederateRequest = serde_json::from_str(json).unwrap();
    assert_eq!(req.address.as_deref(), Some("10.0.0.2:9001"));

    // SetRoutingModeRequest can be deserialized
    let json = r#"{"routing_mode":"broadcast"}"#;
    let _req: SetRoutingModeRequest = serde_json::from_str(json).unwrap();
}

/// Verify the `ApiState` struct can be constructed with a `FileStore`.
#[test]
fn api_state_construction() {
    let store = FileStore::new(None);
    let trust_store = TrustStore::new(None);
    let peer_status_fn: PeerStatusFn = Arc::new(|_| None);

    let state = ApiState {
        store: Arc::new(std::sync::RwLock::new(store)),
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
        peer_status_fn,
        jwks_fn: Arc::new(|| None),
    };

    // Verify debug formatting works
    let debug = format!("{state:?}");
    assert!(debug.contains("ApiState"));
}

/// Verify `handle_request` returns `None` for non-federation paths.
#[test]
fn handle_request_non_federation_path() {
    let state = make_state();
    let result = handle_request(&hyper::Method::GET, "/healthz", &[], &state);
    assert!(result.is_none());
}

/// Verify `handle_request` routes federation paths.
#[test]
fn handle_request_federation_path() {
    let state = make_state();
    let result = handle_request(&hyper::Method::GET, "/api/federation/status", &[], &state);
    assert!(result.is_some());
    let resp = result.unwrap();
    assert_eq!(resp.status(), hyper::StatusCode::OK);
}

/// Verify the `FederateStore` trait is accessible and `FileStore` implements it.
#[test]
fn federate_store_trait_accessible() {
    let store = FileStore::new(None);
    // FileStore implements FederateStore -- verify via trait method
    assert!(store.list().is_empty());
}

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
            total_peers: 0,
            connected_peers: 0,
            peers: vec![],
            ha_enabled: false,
            pod_id: None,
        }),
        peer_status_fn: Arc::new(|_| None),
        jwks_fn: Arc::new(|| None),
    }
}
