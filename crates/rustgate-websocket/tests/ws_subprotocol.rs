// Copyright © 2026 Roberto Chiofalo.

#![allow(clippy::panic, clippy::unwrap_used)]
//! Integration tests for WebSocket subprotocol negotiation (RFC 6455 §4.2.2).
//!
//! These tests cover the handshake-level behaviour end-to-end — they wire
//! a real `WsListener` to a real `tokio_tungstenite` client and assert the
//! server's `Sec-WebSocket-Protocol` response + the negotiated token
//! surfaced on `WsSession::negotiated_subprotocol()`. Pure unit tests for
//! the selection function live inline in `src/lib.rs`.

use std::sync::Arc;
use std::time::Duration;

use rustgate_test_utils::certs::TestCa;
use rustgate_test_utils::tls::build_client_tls_config;
use rustgate_transport::TlsConfig;
use rustgate_websocket::{WsListener, WsListenerConfig};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::header;

/// Build a plain `WsListenerConfig` with the provided subprotocols but all
/// other fields at defaults. `WsListenerConfig` has no public builder; it is
/// a plain struct so tests use `..Default::default()`.
fn config_with(subprotocols: Vec<String>) -> WsListenerConfig {
    WsListenerConfig {
        supported_subprotocols: subprotocols,
        ..WsListenerConfig::default()
    }
}

/// Build an `IntoClientRequest` carrying the given `Sec-WebSocket-Protocol`
/// header values. Accepts multiple values — each is appended as a separate
/// header line so we can exercise the multi-header code path. Pass an empty
/// slice to build a request with no protocol header at all.
fn request_for(
    port: u16,
    protocols: &[&str],
) -> tokio_tungstenite::tungstenite::handshake::client::Request {
    let uri = format!("wss://localhost:{port}/");
    let mut req = uri.into_client_request().unwrap();
    for p in protocols {
        // HeaderMap::append returns bool ("was the key already present?"); we don't
        // care — we're building a fresh request and only need the side effect.
        let _ = req.headers_mut().append(
            header::SEC_WEBSOCKET_PROTOCOL,
            tokio_tungstenite::tungstenite::http::HeaderValue::from_str(p).unwrap(),
        );
    }
    req
}

/// Connect a TLS+WS client bound to the loopback listener and return the
/// stream + handshake response. Unwraps on success; callers that expect a
/// handshake *failure* use [`connect_expecting_error`] instead.
async fn connect_with_request(
    addr: std::net::SocketAddr,
    tls_config: &rustls::ClientConfig,
    req: tokio_tungstenite::tungstenite::handshake::client::Request,
) -> (
    tokio_tungstenite::WebSocketStream<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>,
    tokio_tungstenite::tungstenite::handshake::client::Response,
) {
    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config.clone()));
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let server_name = "localhost".try_into().unwrap();
    let tls_stream = connector.connect(server_name, tcp).await.unwrap();
    tokio_tungstenite::client_async(req, tls_stream)
        .await
        .unwrap()
}

/// Connect expecting the handshake to fail — used when the server is
/// supposed to reject the request with 400. Returns the tungstenite error
/// so tests can assert on the specific failure mode.
async fn connect_expecting_error(
    addr: std::net::SocketAddr,
    tls_config: &rustls::ClientConfig,
    req: tokio_tungstenite::tungstenite::handshake::client::Request,
) -> tokio_tungstenite::tungstenite::Error {
    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config.clone()));
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let server_name = "localhost".try_into().unwrap();
    let tls_stream = connector.connect(server_name, tcp).await.unwrap();
    tokio_tungstenite::client_async(req, tls_stream)
        .await
        .expect_err("expected handshake to fail, but it succeeded")
}

/// Bring up a listener, hand the `bound_addr` back to the caller, and return
/// a handle that resolves to `Ok(Option<String>)` for the successful-accept
/// case or `Err(())` if the accept timed out (used in reject-path tests
/// where the server should emit 400 *before* `accept()` returns a session,
/// so the handle's accept will never complete).
///
/// We return a type-erased `tokio::task::JoinHandle` so the caller can
/// decide whether to `.await` it (happy path) or drop it (reject path).
fn spawn_listener(
    server_protocols: Vec<String>,
) -> (
    std::net::SocketAddr,
    rustls::ClientConfig,
    tokio::task::JoinHandle<Option<String>>,
) {
    let ca = TestCa::new("Test CA");
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);
    let client_cert = ca.issue_client_cert("alice", &["engineers"]);

    let tls_config =
        TlsConfig::from_pem(&server_cert.cert_pem, &server_cert.key_pem, &ca.cert_pem).unwrap();

    let addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let listener =
        WsListener::bind_with_config(addr, &tls_config, config_with(server_protocols)).unwrap();
    let bound_addr = listener.local_addr().unwrap();

    let handle = tokio::spawn(async move {
        // A 2-second bound means reject-path tests (where accept never
        // completes) drop fast instead of hanging the test runner.
        let session = match tokio::time::timeout(Duration::from_secs(2), listener.accept()).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => panic!("accept returned error: {e}"),
            Err(_) => return None, // timeout — the reject-path fast-exit
        };
        session.negotiated_subprotocol().map(str::to_owned)
    });

    let client_tls =
        build_client_tls_config(&client_cert.cert_pem, &client_cert.key_pem, &ca.cert_pem);

    (bound_addr, client_tls, handle)
}

/// Happy path: server advertises a list, client offers overlapping list,
/// the first client-order overlap wins. The selected token surfaces on
/// both the `WsSession` and the HTTP `Sec-WebSocket-Protocol` response.
#[tokio::test]
async fn negotiated_protocol_surfaces_on_session_and_response() {
    let (addr, client_tls, handle) =
        spawn_listener(vec!["cot.v2".to_string(), "tak.proto.v1".to_string()]);
    let req = request_for(addr.port(), &["tak.proto.v1", "cot.v2"]);
    let (_ws, response) = connect_with_request(addr, &client_tls, req).await;

    assert_eq!(
        response
            .headers()
            .get(header::SEC_WEBSOCKET_PROTOCOL)
            .expect("server should echo the chosen subprotocol")
            .to_str()
            .unwrap(),
        "tak.proto.v1"
    );

    let server_saw = handle.await.unwrap();
    assert_eq!(server_saw.as_deref(), Some("tak.proto.v1"));
}

/// Server advertises nothing (backward-compatible default). Even when the
/// client offers a protocol, the server omits the response header — the
/// server has no way to pick a value it never configured. tungstenite's
/// client will treat this as an error on its end, which is the right
/// signal for operators who opt out of subprotocols while their clients
/// still speak them.
#[tokio::test]
async fn empty_server_list_rejects_client_with_subprotocol_request() {
    let (addr, client_tls, handle) = spawn_listener(Vec::new());
    let req = request_for(addr.port(), &["cot.v2"]);
    let err = connect_expecting_error(addr, &client_tls, req).await;
    // tungstenite surfaces this as a `SubProtocolError` at the client side.
    let msg = err.to_string();
    assert!(
        msg.contains("SubProtocol") || msg.contains("subprotocol") || msg.contains("protocol"),
        "expected a subprotocol-related client error, got: {msg}",
    );
    // The server timed out waiting for `accept()` to yield a session —
    // tungstenite's server-side handshake rejected the upgrade before
    // building the session, so the accept loop returns nothing.
    let server_saw = handle.await.unwrap();
    assert!(
        server_saw.is_none(),
        "listener must not surface a session when the handshake failed",
    );
}

/// Server advertises a list, client offers nothing. Handshake succeeds
/// without a negotiated protocol — RFC 6455 §4.2.2 allows this and leaves
/// the close/keep decision to the client.
#[tokio::test]
async fn client_offers_none_leaves_protocol_unset() {
    let (addr, client_tls, handle) = spawn_listener(vec!["cot.v2".to_string()]);
    let req = request_for(addr.port(), &[]);
    let (_ws, response) = connect_with_request(addr, &client_tls, req).await;

    assert!(
        response
            .headers()
            .get(header::SEC_WEBSOCKET_PROTOCOL)
            .is_none()
    );
    let server_saw = handle.await.unwrap();
    assert!(server_saw.is_none());
}

/// Server advertises a list, client offers a disjoint list — server
/// rejects the upgrade with 400. This matches every real client's
/// expectation that "I asked for a protocol, you didn't pick one" is a
/// fatal error, and keeps the rejection reason surfaced in server logs.
#[tokio::test]
async fn disjoint_client_offer_is_rejected_with_400() {
    let (addr, client_tls, handle) = spawn_listener(vec!["cot.v2".to_string()]);
    let req = request_for(addr.port(), &["proprietary.only", "also.unsupported"]);
    let err = connect_expecting_error(addr, &client_tls, req).await;
    let msg = err.to_string();
    // tungstenite reports a 400 as `HttpFormat` / `Http` with the status.
    assert!(
        msg.contains("400") || msg.to_lowercase().contains("bad request"),
        "expected a 400 Bad Request client error, got: {msg}",
    );
    let server_saw = handle.await.unwrap();
    assert!(server_saw.is_none());
}

/// RFC 7230 §3.2.2: a list-valued header may be folded into one
/// comma-separated value. Exercise that form end-to-end — some HTTP
/// stacks always collapse, others always split, and the server must
/// accept either.
#[tokio::test]
async fn comma_separated_client_header_is_parsed() {
    let (addr, client_tls, handle) =
        spawn_listener(vec!["cot.v2".to_string(), "tak.proto.v1".to_string()]);
    let req = request_for(addr.port(), &["unsupported, tak.proto.v1, cot.v2"]);
    let (_ws, response) = connect_with_request(addr, &client_tls, req).await;
    assert_eq!(
        response
            .headers()
            .get(header::SEC_WEBSOCKET_PROTOCOL)
            .unwrap()
            .to_str()
            .unwrap(),
        "tak.proto.v1",
    );
    let server_saw = handle.await.unwrap();
    assert_eq!(server_saw.as_deref(), Some("tak.proto.v1"));
}
