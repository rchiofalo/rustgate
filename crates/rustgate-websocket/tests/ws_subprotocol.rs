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
use rustgate_tls::TlsConfig;
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

/// Build a `WsListenerConfig` with strict subprotocol enforcement opted in.
/// Used by the strict-rejection test below; default behaviour is lenient
/// (`subprotocol_strict = false`) per #884, which the lenient-mode test
/// pins as the cross-version contract.
fn strict_config_with(subprotocols: Vec<String>) -> WsListenerConfig {
    WsListenerConfig {
        supported_subprotocols: subprotocols,
        subprotocol_strict: true,
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
    spawn_listener_with(config_with(server_protocols))
}

/// Lower-level variant that accepts a fully built `WsListenerConfig`. Lets
/// the strict-mode test inject `subprotocol_strict = true` while the rest
/// of the harness stays at defaults.
fn spawn_listener_with(
    config: WsListenerConfig,
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
    let listener = WsListener::bind_with_config(addr, &tls_config, config).unwrap();
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

/// **#884 default-flip pin.** Server advertises a list, client offers a
/// disjoint list. The lenient default (the new #884 behaviour) keeps the
/// upgrade alive: tungstenite's *client* will then surface an error
/// because the server omitted `Sec-WebSocket-Protocol` in the response, but
/// the *server* did not reject the upgrade. This is the right tradeoff for
/// TAK and similar tactical clients that probe many subprotocols and fall
/// back to native non-subprotocol framing on no-match — a strict 400 here
/// regresses interop. See `subprotocol_no_match_strict_rejects_with_400`
/// for the opt-in strict path.
#[tokio::test]
async fn subprotocol_no_match_lenient_completes_without_header() {
    let (addr, client_tls, handle) = spawn_listener(vec!["cot.v2".to_string()]);
    let req = request_for(addr.port(), &["proprietary.only", "also.unsupported"]);
    let err = connect_expecting_error(addr, &client_tls, req).await;
    let msg = err.to_string();
    // The error must NOT be a server-side 400 — instead tungstenite's
    // client surfaces a subprotocol-error variant because the server
    // legitimately omitted the response header. Pin both shapes: the
    // absence of a 400 *and* the presence of subprotocol-related
    // wording.
    assert!(
        !msg.contains("400") && !msg.to_lowercase().contains("bad request"),
        "lenient mode must not surface a server 400; got: {msg}",
    );
    assert!(
        msg.contains("SubProtocol") || msg.contains("subprotocol") || msg.contains("protocol"),
        "expected client-side subprotocol error in lenient mode, got: {msg}",
    );
    let server_saw = handle.await.unwrap();
    assert!(server_saw.is_none());
}

/// Strict mode: the operator opted into rejecting disjoint offers with a
/// 400. Used by deployments where every client is expected to speak one of
/// the advertised subprotocols — a config drift then surfaces as a clean
/// server-side 400 in logs instead of an opaque client-side protocol
/// error.
#[tokio::test]
async fn subprotocol_no_match_strict_rejects_with_400() {
    let (addr, client_tls, handle) =
        spawn_listener_with(strict_config_with(vec!["cot.v2".to_string()]));
    let req = request_for(addr.port(), &["proprietary.only", "also.unsupported"]);
    let err = connect_expecting_error(addr, &client_tls, req).await;
    let msg = err.to_string();
    // tungstenite reports a server 400 as `HttpFormat` / `Http` with the
    // status — match either the literal status code or the standard
    // status reason phrase.
    assert!(
        msg.contains("400") || msg.to_lowercase().contains("bad request"),
        "expected a 400 Bad Request client error in strict mode, got: {msg}",
    );
    let server_saw = handle.await.unwrap();
    assert!(server_saw.is_none());
}

/// **#884 contract pin.** Per RFC 6455 §4.2.2, the server picks the first
/// client-offered subprotocol that also appears in the server's allow-list.
/// Client preference order wins — the server's order is a *filter*, not a
/// strict ranking. This test pins the cross-version semantics promised in
/// the README.
///
/// We pass the offers as a single comma-separated header value because
/// tungstenite's client-side handshake stores only the *first*
/// `Sec-WebSocket-Protocol` header value (it never folds multiple headers
/// into one list internally), so multi-header appends would have the
/// client reject the server's perfectly valid choice with
/// `InvalidSubProtocol`. Real browser/Node/Python clients always emit a
/// single comma-separated header, so the test mirrors deployment shape.
#[tokio::test]
async fn subprotocol_first_match_is_chosen() {
    let (addr, client_tls, handle) = spawn_listener(vec!["bar".to_string(), "tak.v1".to_string()]);
    let req = request_for(addr.port(), &["foo, tak.v1, bar"]);
    let (_ws, response) = connect_with_request(addr, &client_tls, req).await;
    assert_eq!(
        response
            .headers()
            .get(header::SEC_WEBSOCKET_PROTOCOL)
            .expect("server should echo the chosen subprotocol")
            .to_str()
            .unwrap(),
        "tak.v1",
        "client preference order wins (RFC 6455 §4.2.2)",
    );
    let server_saw = handle.await.unwrap();
    assert_eq!(server_saw.as_deref(), Some("tak.v1"));
}

/// **#884 default-empty pin.** When `subprotocols` is empty (the default),
/// the server preserves pre-#884 / pre-#1131 behaviour: no
/// `Sec-WebSocket-Protocol` header is processed and the upgrade always
/// succeeds. Every existing deployment that did not configure the
/// subprotocol list must continue to work uncompressed.
#[tokio::test]
async fn subprotocols_default_empty_preserves_existing_behavior() {
    let (addr, client_tls, handle) = spawn_listener(Vec::new());
    let req = request_for(addr.port(), &[]); // no Sec-WebSocket-Protocol either
    let (_ws, response) = connect_with_request(addr, &client_tls, req).await;
    assert!(
        response
            .headers()
            .get(header::SEC_WEBSOCKET_PROTOCOL)
            .is_none(),
        "default-empty config must not emit a Sec-WebSocket-Protocol header",
    );
    let server_saw = handle.await.unwrap();
    assert!(
        server_saw.is_none(),
        "default-empty config must not record a negotiated subprotocol",
    );
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
