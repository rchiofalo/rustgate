// Copyright © 2026 Roberto Chiofalo.

//! End-to-end integration tests for the expanded management REST API
//! (closes #875).
//!
//! These tests exercise the public [`rustgate_admin::management_api`]
//! handler surface end-to-end with synthesised provider callbacks and
//! a real bearer-token check. The router/transport/wiring layer is
//! exercised separately in `rustgate-server` integration tests; this
//! file pins the handler-level contract operators see when they hit
//! the API directly.

#![cfg(feature = "management-api")]
#![allow(clippy::panic, clippy::unwrap_used)]

use std::io::Write;
use std::sync::Arc;

use http_body_util::BodyExt;
use hyper::{Method, StatusCode};
use rustgate_admin::management_api::{
    ClientDetail, ClientSnapshot, ManagementApiState, MetricsSummary, Providers, StoreForwardEntry,
    StoreForwardSnapshot, VersionInfo, handle_request,
};
use rustgate_archive::audit_chain::{GENESIS_PREV, HashChainWriter};
use zeroize::Zeroizing;

const TOKEN: &str = "integration-test-token-padding-32bytes";

fn auth() -> String {
    format!("Bearer {TOKEN}")
}

fn full_state(audit_path: Option<std::path::PathBuf>) -> ManagementApiState {
    let providers = Providers {
        config: Some(Arc::new(|| serde_json::json!({"bind": "0.0.0.0:9443"}))),
        clients: Some(Arc::new(|| {
            Box::pin(async {
                vec![ClientSnapshot {
                    cn: "alice".into(),
                    fingerprint: "abc123".into(),
                    connected_at: Some("2026-05-08T00:00:00Z".into()),
                    bytes_rx: Some(100),
                    bytes_tx: Some(200),
                    source_protocol: Some("tls".into()),
                    groups: vec!["squad".into()],
                    tenant: None,
                }]
            })
        })),
        client_detail: Some(Arc::new(|cn: String| {
            Box::pin(async move {
                if cn == "alice" {
                    Some(ClientDetail {
                        snapshot: ClientSnapshot {
                            cn: "alice".into(),
                            fingerprint: "abc123".into(),
                            connected_at: Some("2026-05-08T00:00:00Z".into()),
                            bytes_rx: Some(100),
                            bytes_tx: Some(200),
                            source_protocol: Some("tls".into()),
                            groups: vec!["squad".into()],
                            tenant: None,
                        },
                        queue_depth: Some(2),
                        rate_limit_per_sec: Some(50),
                    })
                } else {
                    None
                }
            })
        })),
        metrics_summary: Some(Arc::new(|| {
            Box::pin(async {
                MetricsSummary {
                    router_fanout_total: 42,
                    router_dropped_total: 3,
                    store_forward_messages: 7,
                    store_forward_bytes: 1024,
                    federation_peer_count: 5,
                    federation_connected_peers: 4,
                    connected_clients: 1,
                }
            })
        })),
        store_forward: Some(Arc::new(|| StoreForwardSnapshot {
            enabled: true,
            total_bytes: 1024,
            total_messages: 2,
            entries: vec![StoreForwardEntry {
                cn: "bob".into(),
                messages: 2,
                bytes: 1024,
            }],
        })),
        version: Some(Arc::new(|| VersionInfo {
            version: "0.0.0-integ".into(),
            git_hash: "f00".into(),
            features: vec!["management-api".into()],
            fips_active: false,
        })),
    };
    ManagementApiState {
        providers,
        reload_notify: Arc::new(tokio::sync::Notify::new()),
        audit_log_path: audit_path,
        auth_token: Zeroizing::new(TOKEN.as_bytes().to_vec()),
    }
}

async fn body_text(
    resp: hyper::Response<http_body_util::Full<bytes::Bytes>>,
) -> (StatusCode, String) {
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&bytes).to_string())
}

#[tokio::test]
async fn config_endpoint_round_trip_with_admin_token() {
    let state = full_state(None);
    let resp = handle_request(&Method::GET, "/api/config", Some(&auth()), &state)
        .await
        .unwrap();
    let (status, body) = body_text(resp).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("\"bind\":\"0.0.0.0:9443\""));
}

#[tokio::test]
async fn config_reload_returns_202_and_fires_notify() {
    let state = full_state(None);
    let notify = Arc::clone(&state.reload_notify);
    let waiter = tokio::spawn(async move { notify.notified().await });
    tokio::task::yield_now().await;

    let resp = handle_request(&Method::POST, "/api/config/reload", Some(&auth()), &state)
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);

    tokio::time::timeout(std::time::Duration::from_secs(2), waiter)
        .await
        .expect("reload notify must fire")
        .unwrap();
}

#[tokio::test]
async fn clients_endpoint_lists_connected_clients() {
    let state = full_state(None);
    let resp = handle_request(&Method::GET, "/api/clients", Some(&auth()), &state)
        .await
        .unwrap();
    let (status, body) = body_text(resp).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("\"cn\":\"alice\""));
    assert!(body.contains("\"fingerprint\":\"abc123\""));
    assert!(body.contains("\"source_protocol\":\"tls\""));
}

#[tokio::test]
async fn client_detail_returns_full_payload_for_known_cn() {
    let state = full_state(None);
    let resp = handle_request(&Method::GET, "/api/clients/alice", Some(&auth()), &state)
        .await
        .unwrap();
    let (status, body) = body_text(resp).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("\"queue_depth\":2"));
    assert!(body.contains("\"rate_limit_per_sec\":50"));
}

#[tokio::test]
async fn client_detail_returns_404_for_unknown_cn() {
    let state = full_state(None);
    let resp = handle_request(&Method::GET, "/api/clients/unknown", Some(&auth()), &state)
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn metrics_summary_pins_required_fields() {
    let state = full_state(None);
    let resp = handle_request(&Method::GET, "/api/metrics/summary", Some(&auth()), &state)
        .await
        .unwrap();
    let (status, body) = body_text(resp).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("\"router_fanout_total\":42"));
    assert!(body.contains("\"router_dropped_total\":3"));
    assert!(body.contains("\"store_forward_messages\":7"));
    assert!(body.contains("\"store_forward_bytes\":1024"));
    assert!(body.contains("\"federation_peer_count\":5"));
    assert!(body.contains("\"federation_connected_peers\":4"));
    assert!(body.contains("\"connected_clients\":1"));
}

#[tokio::test]
async fn store_forward_snapshot_includes_per_cn_breakdown() {
    let state = full_state(None);
    let resp = handle_request(&Method::GET, "/api/store-forward", Some(&auth()), &state)
        .await
        .unwrap();
    let (status, body) = body_text(resp).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("\"enabled\":true"));
    assert!(body.contains("\"cn\":\"bob\""));
    assert!(body.contains("\"bytes\":1024"));
}

#[tokio::test]
async fn version_endpoint_includes_required_shape() {
    let state = full_state(None);
    let resp = handle_request(&Method::GET, "/api/version", Some(&auth()), &state)
        .await
        .unwrap();
    let (status, body) = body_text(resp).await;
    assert_eq!(status, StatusCode::OK);
    // Field-presence assertions: version, git_hash, features, fips_active.
    assert!(body.contains("\"version\":\"0.0.0-integ\""));
    assert!(body.contains("\"git_hash\":\"f00\""));
    assert!(body.contains("\"features\":["));
    assert!(body.contains("\"fips_active\":false"));
}

#[tokio::test]
async fn audit_verify_with_synthetic_chain_returns_expected_report() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.log");
    {
        let f = std::fs::File::create(&path).unwrap();
        let mut writer = HashChainWriter::new(f, GENESIS_PREV.to_string());
        writer.write_all(b"{\"event\":\"first\"}\n").unwrap();
        writer.write_all(b"{\"event\":\"second\"}\n").unwrap();
        writer.write_all(b"{\"event\":\"third\"}\n").unwrap();
    }

    let state = full_state(Some(path.clone()));
    let resp = handle_request(&Method::GET, "/api/audit/verify", Some(&auth()), &state)
        .await
        .unwrap();
    let (status, body) = body_text(resp).await;
    assert_eq!(status, StatusCode::OK);

    // Pin the JSON shape so a regression in field naming is caught.
    let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
    let data = &parsed["data"];
    assert_eq!(data["verified"], serde_json::Value::Bool(true));
    assert_eq!(data["records"], serde_json::Value::from(3i64));
    assert!(data["tip"].as_str().is_some());
    assert_eq!(
        data["audit_log_path"],
        serde_json::Value::String(path.display().to_string())
    );

    // Pin the public field names that operators will scrape.
    assert!(body.contains("\"verified\":true"));
    assert!(body.contains("\"records\":3"));
    assert!(body.contains("\"tip\":"));
    assert!(body.contains("\"tip_seq\":"));
}

#[tokio::test]
async fn audit_verify_without_path_returns_503() {
    let state = full_state(None);
    let resp = handle_request(&Method::GET, "/api/audit/verify", Some(&auth()), &state)
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn missing_token_returns_401_on_every_endpoint() {
    let state = full_state(None);
    for path in [
        "/api/config",
        "/api/clients",
        "/api/clients/alice",
        "/api/metrics/summary",
        "/api/store-forward",
        "/api/audit/verify",
        "/api/version",
    ] {
        let resp = handle_request(&Method::GET, path, None, &state)
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "no-token request to {path} must be 401"
        );
    }
    let resp = handle_request(&Method::POST, "/api/config/reload", None, &state)
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn wrong_token_returns_401_on_write_endpoint() {
    let state = full_state(None);
    let resp = handle_request(
        &Method::POST,
        "/api/config/reload",
        Some("Bearer wrong-token-padding-padding-padding-32"),
        &state,
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn legacy_disconnect_subroute_falls_through_or_404s() {
    // The expanded API must not silently swallow
    // `/api/clients/{cn}/disconnect` — that surface belongs to the
    // legacy `mgmt_api` handler. Either fall through (None) or return
    // a structured 404, never a 200.
    let state = full_state(None);
    let resp = handle_request(
        &Method::POST,
        "/api/clients/alice/disconnect",
        Some(&auth()),
        &state,
    )
    .await;
    match resp {
        None => {} // ok — fell through to next handler
        Some(r) => assert_eq!(r.status(), StatusCode::NOT_FOUND),
    }
}
