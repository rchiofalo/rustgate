// Copyright © 2026 Roberto Chiofalo.

#![allow(clippy::panic, clippy::unwrap_used)]

//! Integration tests for the admin HTTP server.
//!
//! Moved from `rustgate-server/src/metrics.rs` as part of the
//! `rustgate-admin` extraction (#895). These tests exercise the
//! `serve()` entrypoint, the bearer-token auth path, and the structured
//! readiness/liveness/startup probes end-to-end on a real loopback
//! socket. Lives in the integration-test directory rather than under
//! `#[cfg(test)] mod tests` because the tests need to bind a TCP
//! listener and the test binary boundary keeps the per-test runtime
//! isolated from neighbouring unit tests.

use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use rustgate_admin::{
    AclApiHandler, DEFAULT_MAX_HTTP_CONNECTIONS, HealthState, MgmtApiHandler, ReadinessState,
    RouterSlot, serve,
};

/// Minimal HTTP/1.1 GET helper — used for assertions on `/health/*` and
/// `/metrics`. Returns the parsed status code and decoded body. Reads
/// the full response and trims any trailing chunked-encoding metadata
/// so callers can compare bodies with simple equality.
async fn http_get(addr: SocketAddr, path: &str) -> (u16, String) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let req = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).await.expect("write");
    let mut buf = Vec::new();
    let _ = stream.read_to_end(&mut buf).await;
    let resp = String::from_utf8_lossy(&buf).to_string();
    let status = resp
        .split_whitespace()
        .nth(1)
        .unwrap_or("0")
        .parse::<u16>()
        .unwrap_or(0);
    let body = resp.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    // Bodies for `/health/ready` and `/metrics` may be chunked; if so
    // strip the size prefix line and the trailing 0-chunk envelope.
    let body = if body.contains("\r\n") {
        body.lines()
            .filter(|l| !l.is_empty() && !l.chars().all(|c| c.is_ascii_hexdigit()) && *l != "0")
            .collect::<Vec<_>>()
            .join("")
    } else {
        body
    };
    (status, body)
}

async fn http_get_with_auth(addr: SocketAddr, path: &str, auth: Option<&str>) -> (u16, String) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let auth_header = match auth {
        Some(token) => format!("Authorization: {token}\r\n"),
        None => String::new(),
    };
    let req =
        format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\n{auth_header}Connection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).await.expect("write");
    let mut buf = Vec::new();
    let _ = stream.read_to_end(&mut buf).await;
    let resp = String::from_utf8_lossy(&buf).to_string();
    let status = resp
        .split_whitespace()
        .nth(1)
        .unwrap_or("0")
        .parse::<u16>()
        .unwrap_or(0);
    let body = resp.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    (status, body)
}

async fn http_get_raw(addr: SocketAddr, path: &str, auth: Option<&str>) -> (u16, String) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let auth_header = match auth {
        Some(token) => format!("Authorization: {token}\r\n"),
        None => String::new(),
    };
    let req =
        format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\n{auth_header}Connection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).await.expect("write");
    let mut buf = Vec::new();
    let _ = stream.read_to_end(&mut buf).await;
    let resp = String::from_utf8_lossy(&buf).to_string();
    let status = resp
        .split_whitespace()
        .nth(1)
        .unwrap_or("0")
        .parse::<u16>()
        .unwrap_or(0);
    (status, resp)
}

async fn start_test_server(token: Option<&[u8]>) -> SocketAddr {
    let health = Arc::new(HealthState::new());
    health.set_ready(true);
    let readiness = Arc::new(ReadinessState::new());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    drop(listener);

    let metrics_token = token.map(|t| Arc::new(zeroize::Zeroizing::new(t.to_vec())));
    let router_slot: RouterSlot = Arc::new(OnceLock::new());
    let _ = router_slot.set(Arc::new(rustgate_router::Router::new()));

    let server_health = Arc::clone(&health);
    let server_readiness = Arc::clone(&readiness);
    drop(tokio::spawn(async move {
        let _ = serve(
            addr,
            server_health,
            server_readiness,
            #[cfg(feature = "federation")]
            Arc::new(OnceLock::new()),
            Arc::new(OnceLock::new()),
            Arc::new(OnceLock::new()),
            #[cfg(feature = "management-api")]
            Arc::new(OnceLock::new()),
            #[cfg(feature = "video")]
            Arc::new(OnceLock::new()),
            #[cfg(feature = "correlation")]
            Arc::new(OnceLock::new()),
            #[cfg(feature = "missions")]
            Arc::new(OnceLock::new()),
            metrics_token,
            router_slot,
            DEFAULT_MAX_HTTP_CONNECTIONS,
        )
        .await;
    }));

    tokio::time::sleep(Duration::from_millis(50)).await;
    addr
}

#[tokio::test]
async fn serve_health_and_metrics_endpoints() {
    let health = Arc::new(HealthState::new());
    let readiness = Arc::new(ReadinessState::new());
    health.set_ready(true);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    drop(listener);

    let router_slot: RouterSlot = Arc::new(OnceLock::new());
    let _ = router_slot.set(Arc::new(rustgate_router::Router::new()));

    let server_health = Arc::clone(&health);
    let server_router_slot = Arc::clone(&router_slot);
    let server_readiness = Arc::clone(&readiness);
    drop(tokio::spawn(async move {
        let _ = serve(
            addr,
            server_health,
            server_readiness,
            #[cfg(feature = "federation")]
            Arc::new(OnceLock::new()),
            Arc::new(OnceLock::new()),
            Arc::new(OnceLock::new()),
            #[cfg(feature = "management-api")]
            Arc::new(OnceLock::new()),
            #[cfg(feature = "video")]
            Arc::new(OnceLock::new()),
            #[cfg(feature = "correlation")]
            Arc::new(OnceLock::new()),
            #[cfg(feature = "missions")]
            Arc::new(OnceLock::new()),
            None,
            server_router_slot,
            DEFAULT_MAX_HTTP_CONNECTIONS,
        )
        .await;
    }));

    tokio::time::sleep(Duration::from_millis(50)).await;

    // /health/live returns 200 once serve() is up.
    let (status, body) = http_get(addr, "/health/live").await;
    assert_eq!(status, 200);
    assert_eq!(body, "ok");

    // Legacy alias /healthz mirrors /health/live.
    let (status, _) = http_get(addr, "/healthz").await;
    assert_eq!(status, 200);

    // /health/ready returns structured JSON when ready (no deps
    // registered, so the report has an empty checks map and status "ok").
    let (status, body) = http_get(addr, "/health/ready").await;
    assert_eq!(status, 200);
    let report: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    assert_eq!(report["status"], "ok");

    // /health/startup is 503 until startup is marked complete.
    let (status, body) = http_get(addr, "/health/startup").await;
    assert_eq!(status, 503);
    assert_eq!(body, "starting");

    assert!(health.mark_started());
    let (status, body) = http_get(addr, "/health/startup").await;
    assert_eq!(status, 200);
    assert_eq!(body, "ok");

    // /health/ready returns 503 after marking not ready (shutdown).
    health.set_ready(false);
    let (status, body) = http_get(addr, "/health/ready").await;
    assert_eq!(status, 503);
    let report: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    assert_eq!(report["status"], "unhealthy");

    // /health/authz returns JSON with no engine installed
    let (status, body) = http_get(addr, "/health/authz").await;
    assert_eq!(status, 200);
    assert!(body.contains("\"policy_id\":null"));
    assert!(body.contains("\"compile_warnings\":[]"));

    // Unknown path returns 404
    let (status, _) = http_get(addr, "/unknown").await;
    assert_eq!(status, 404);
}

#[test]
fn health_state_flags_are_independent() {
    let h = HealthState::new();
    assert!(!h.is_live());
    assert!(!h.is_ready());
    assert!(!h.is_started());

    h.set_live(true);
    assert!(h.is_live());
    assert!(!h.is_ready());
    assert!(!h.is_started());

    h.set_ready(true);
    h.set_started(true);
    assert!(h.is_live());
    assert!(h.is_ready());
    assert!(h.is_started());

    h.set_ready(false);
    assert!(h.is_live());
    assert!(!h.is_ready());
    assert!(h.is_started());
}

#[test]
fn mark_started_is_one_shot() {
    let h = HealthState::new();
    assert!(!h.is_started());

    // First call performs the transition.
    assert!(h.mark_started(), "first mark_started must return true");
    assert!(h.is_started());

    // Second call observes the flag already set, returns false.
    assert!(!h.mark_started(), "second mark_started must return false");
    assert!(h.is_started());

    // Repeated calls remain idempotent.
    for _ in 0..10 {
        assert!(!h.mark_started());
    }
    assert!(h.is_started());
}

#[tokio::test]
async fn metrics_requires_auth_when_token_configured() {
    let token = b"test-token-with-sufficient-length-32-chars";
    let addr = start_test_server(Some(token)).await;

    let (status, body) = http_get_with_auth(addr, "/metrics", None).await;
    assert_eq!(status, 401);
    assert_eq!(body, "unauthorized");
}

#[tokio::test]
async fn metrics_accepts_valid_token() {
    let token = b"test-token-with-sufficient-length-32-chars";
    let addr = start_test_server(Some(token)).await;

    let auth = format!("Bearer {}", String::from_utf8_lossy(token));
    let (status, _body) = http_get_with_auth(addr, "/metrics", Some(&auth)).await;
    assert_eq!(status, 200);
}

#[tokio::test]
async fn metrics_rejects_invalid_token() {
    let token = b"test-token-with-sufficient-length-32-chars";
    let addr = start_test_server(Some(token)).await;

    let auth = "Bearer wrong-token";
    let (status, body) = http_get_with_auth(addr, "/metrics", Some(auth)).await;
    assert_eq!(status, 401);
    assert_eq!(body, "unauthorized");
}

#[tokio::test]
async fn metrics_401_includes_www_authenticate_header() {
    let token = b"test-token-with-sufficient-length-32-chars";
    let addr = start_test_server(Some(token)).await;

    let (status, raw) = http_get_raw(addr, "/metrics", None).await;
    assert_eq!(status, 401);
    assert!(
        raw.to_lowercase().contains("www-authenticate: bearer"),
        "raw response: {raw}"
    );
}

#[tokio::test]
async fn metrics_unauthenticated_when_no_token() {
    let addr = start_test_server(None).await;

    let (status, _body) = http_get_with_auth(addr, "/metrics", None).await;
    assert_eq!(status, 200);
}

#[tokio::test]
async fn health_endpoints_bypass_metrics_auth() {
    let token = b"test-token-with-sufficient-length-32-chars";
    let addr = start_test_server(Some(token)).await;

    // /health/* paths should always be reachable, even without auth.
    let (status, _) = http_get_with_auth(addr, "/health/live", None).await;
    assert_eq!(status, 200);
    let (status, _) = http_get_with_auth(addr, "/health/ready", None).await;
    assert_eq!(status, 200);
}

// Compile-time check that AclApiHandler/MgmtApiHandler types exist and
// satisfy `Send + Sync`. Issue #1316 caught a regression where a feature
// gate dropped this constraint at the type alias.
#[test]
fn handler_aliases_are_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<AclApiHandler>();
    assert_send_sync::<MgmtApiHandler>();
}
