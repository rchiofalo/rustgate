// Copyright © 2026 Roberto Chiofalo.

#![allow(clippy::panic, clippy::unwrap_used)]
//! Integration tests for `permessage-deflate` (RFC 7692) negotiation.
//!
//! These tests cover the handshake-level behaviour end-to-end — they wire a
//! real `WsListener` to a real `tokio_tungstenite` client and assert the
//! server's `Sec-WebSocket-Extensions` response. The wire-frame compressed-
//! payload codec is gated on a future tokio-tungstenite release exposing
//! the upstream `deflate` feature; until that lands, the negotiation
//! handshake is the operator-visible surface and the bandwidth-savings
//! claim is pinned by the unit-level codec round-trip in
//! `compression::tests::deflate_compresses_repetitive_xml_payload`. See
//! the `compression` module-level docs for the full rationale.

use std::sync::Arc;
use std::time::Duration;

use rustgate_test_utils::certs::TestCa;
use rustgate_test_utils::tls::build_client_tls_config;
use rustgate_tls::TlsConfig;
use rustgate_websocket::{
    CompressionConfig, Deflater, Inflater, PermessageDeflateConfig, WsListener, WsListenerConfig,
};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::header;

/// Build a listener config with the provided compression mode and all
/// other fields at the workspace defaults.
fn config_with_compression(compression: CompressionConfig) -> WsListenerConfig {
    WsListenerConfig {
        compression,
        ..WsListenerConfig::default()
    }
}

/// Build an `IntoClientRequest` carrying the given
/// `Sec-WebSocket-Extensions` header value.
fn request_with_extensions(
    port: u16,
    extensions: Option<&str>,
) -> tokio_tungstenite::tungstenite::handshake::client::Request {
    let uri = format!("wss://localhost:{port}/");
    let mut req = uri.into_client_request().unwrap();
    if let Some(value) = extensions {
        // HeaderMap::insert returns an `Option<HeaderValue>` (the previous
        // value); we don't use it.
        let _ = req.headers_mut().insert(
            header::SEC_WEBSOCKET_EXTENSIONS,
            tokio_tungstenite::tungstenite::http::HeaderValue::from_str(value).unwrap(),
        );
    }
    req
}

/// Connect a TLS+WS client and return the response. The handshake is
/// expected to succeed for the negotiation tests — wire-level compressed
/// frames are out of scope here (see module docs).
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

/// Bring up a listener and return the bound address, client TLS config,
/// and a handle that resolves to the session's negotiated-compression
/// boolean (`true` when the upgrade attached a `NegotiatedExtension`).
fn spawn_compression_listener(
    config: WsListenerConfig,
) -> (
    std::net::SocketAddr,
    rustls::ClientConfig,
    tokio::task::JoinHandle<bool>,
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
        let session = match tokio::time::timeout(Duration::from_secs(2), listener.accept()).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => panic!("accept returned error: {e}"),
            Err(_) => return false, // timeout — reject path
        };
        session.negotiated_compression().is_some()
    });

    let client_tls =
        build_client_tls_config(&client_cert.cert_pem, &client_cert.key_pem, &ca.cert_pem);

    (bound_addr, client_tls, handle)
}

/// Test 1 — **`permessage_deflate_negotiated_when_both_sides_offer_it`.**
/// Client sends `Sec-WebSocket-Extensions: permessage-deflate`; server
/// (default config — compression enabled) echoes the extension back in
/// the response. The session records the negotiation so downstream
/// metrics/audit can branch on it. This pins the negotiation-handshake
/// surface, which is the operator-visible deliverable of #884; the
/// per-frame wire compression follows when tokio-tungstenite ships
/// upstream `deflate` support (see `compression` module-level docs).
#[tokio::test]
async fn permessage_deflate_negotiated_when_both_sides_offer_it() {
    let (addr, client_tls, handle) =
        spawn_compression_listener(config_with_compression(CompressionConfig::default()));
    let req = request_with_extensions(addr.port(), Some("permessage-deflate"));
    let (_ws, response) = connect_with_request(addr, &client_tls, req).await;

    let echoed = response
        .headers()
        .get(header::SEC_WEBSOCKET_EXTENSIONS)
        .expect("server should echo permessage-deflate")
        .to_str()
        .unwrap();
    assert!(
        echoed.starts_with("permessage-deflate"),
        "response extension must start with permessage-deflate, got: {echoed}",
    );

    let server_negotiated = handle.await.unwrap();
    assert!(
        server_negotiated,
        "session must record negotiated compression",
    );
}

/// Test 2 — **`permessage_deflate_disabled_via_config_is_not_negotiated`.**
/// Operator opted out (`CompressionConfig::Disabled`). Even when the
/// client offers `permessage-deflate`, the server emits no
/// `Sec-WebSocket-Extensions` response header. The handshake still
/// succeeds — the operator's CRIME-conscious deployment continues
/// uncompressed.
#[tokio::test]
async fn permessage_deflate_disabled_via_config_is_not_negotiated() {
    let (addr, client_tls, handle) =
        spawn_compression_listener(config_with_compression(CompressionConfig::Disabled));
    let req = request_with_extensions(addr.port(), Some("permessage-deflate"));
    let (_ws, response) = connect_with_request(addr, &client_tls, req).await;

    assert!(
        response
            .headers()
            .get(header::SEC_WEBSOCKET_EXTENSIONS)
            .is_none(),
        "disabled config must not echo any Sec-WebSocket-Extensions header",
    );

    let server_negotiated = handle.await.unwrap();
    assert!(
        !server_negotiated,
        "session must not record negotiated compression when disabled",
    );
}

/// Test 3 — **`permessage_deflate_compresses_repetitive_payload`.** A 64
/// KiB CoT-shaped XML payload must compress to less than 30% of its
/// original size on the `permessage-deflate` codec; if this regresses,
/// the deployment benefit story collapses. Wire-level frame compression
/// is gated on tokio-tungstenite exposing upstream deflate support, so
/// this asserts on the raw codec round-trip — exactly the bytes that
/// would be on the wire when the per-frame plumbing lands. See
/// `compression` module-level docs for the layered design.
#[tokio::test]
async fn permessage_deflate_compresses_repetitive_payload() {
    // Realistic CoT XML — every field is shaped to produce repetition
    // across messages, which is exactly the workload `permessage-deflate`
    // exists to compress. Loop until we exceed 64 KiB so the inflater has
    // enough material to populate its LZ77 window.
    let snippet = br#"<event version="2.0" uid="ANDROID-deadbeef" type="a-f-G-U-C" how="m-g"><point lat="38.889483" lon="-77.035280" hae="100.0" ce="9.9" le="9.9"/><detail><contact callsign="Alpha-1" endpoint="*:-1:stcp"/><__group name="Cyan" role="Team Member"/><status battery="86"/><takv device="ATAK-CIV" platform="ATAK-CIV" os="29" version="4.10.0.16"/></detail></event>"#;
    let mut payload = Vec::with_capacity(64 * 1024);
    while payload.len() < 64 * 1024 {
        payload.extend_from_slice(snippet);
    }
    let original = payload.len();

    let mut deflater = Deflater::new(15);
    let mut inflater = Inflater::new(15);
    let compressed = deflater.compress_message(&payload).unwrap();
    let recovered = inflater.decompress_message(&compressed).unwrap();

    assert_eq!(recovered.len(), original, "round-trip must preserve length");
    assert_eq!(recovered, payload, "round-trip must preserve content");

    let ratio = (compressed.len() as f64) / (original as f64);
    eprintln!(
        "permessage_deflate ratio: {ratio:.4} ({} compressed / {original} original)",
        compressed.len()
    );
    assert!(
        ratio < 0.30,
        "expected <30% size on repetitive XML, got {ratio:.4} ({} bytes from {original})",
        compressed.len(),
    );
}

/// Bonus — operator-supplied parameters (server window 12, client no
/// context takeover required) pass through to the response header. This
/// guards against silent envelope drift between the operator config and
/// the wire — if the operator's TOML says "12-bit window" and the
/// negotiated-extension response says "15", deployments would compute
/// wrong bandwidth budgets.
#[tokio::test]
async fn permessage_deflate_envelope_is_reflected_in_response() {
    let envelope = PermessageDeflateConfig {
        require_client_no_context_takeover: true,
        max_window_bits: 12,
        ..PermessageDeflateConfig::default()
    };
    let (addr, client_tls, handle) = spawn_compression_listener(config_with_compression(
        CompressionConfig::Enabled(envelope),
    ));
    let req = request_with_extensions(addr.port(), Some("permessage-deflate"));
    let (_ws, response) = connect_with_request(addr, &client_tls, req).await;

    let echoed = response
        .headers()
        .get(header::SEC_WEBSOCKET_EXTENSIONS)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        echoed.contains("client_no_context_takeover"),
        "envelope must surface in response, got: {echoed}",
    );
    assert!(
        echoed.contains("server_max_window_bits=12"),
        "envelope server-bits must surface in response, got: {echoed}",
    );

    let _ = handle.await.unwrap();
}
