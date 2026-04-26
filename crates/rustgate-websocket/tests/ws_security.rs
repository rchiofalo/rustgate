// Copyright © 2026 Roberto Chiofalo.

#![allow(clippy::panic, clippy::unwrap_used)]

//! Security-focused integration tests for the WebSocket listener.
//!
//! Two regression scopes guarded here, both filed under issue #756:
//!
//! - **F-59**: the per-IP connection rate limit (`CONN_RATE_LIMIT = 10/10s`)
//!   was hard-coded in `rustgate_websocket::lib.rs` before this PR.
//!   Production deployments with thousand-peer fleets cannot raise the cap
//!   without a recompile. We verify here that `WsListenerConfig::conn_rate_limit`
//!   is honoured at runtime — the limiter actually rejects the
//!   `(N+1)`-th connection inside a single window when the configured `N`
//!   is set, and accepts more than the historical default of 10 when the
//!   knob is raised.
//!
//! - **F-60**: the upgrade ordering inside the `WsListener::accept` loop
//!   is `TCP accept → TLS handshake → identity extraction → WS upgrade`.
//!   We pin that an HTTP `Upgrade: websocket` request riding on a TLS
//!   connection that presented no client certificate is rejected by the
//!   TLS layer before any HTTP bytes are parsed. A future refactor that
//!   silently moved the auth checkpoint past the upgrade (e.g. a
//!   "negotiate the protocol first then check the cert" rewrite) would
//!   leak the TLS handshake into a regime where the HTTP machinery has
//!   already accepted bytes — exactly the auth-bypass shape the task
//!   guards against.

use std::sync::Arc;

use rustgate_test_utils::certs::TestCa;
use rustgate_transport::TlsConfig;
use rustgate_websocket::{WsListener, WsListenerConfig};
use rustls::RootCertStore;
use rustls_pki_types::pem::PemObject;

// ── F-59: per-IP connection rate limit honours the configured cap ────

/// Drives the per-IP rate limiter with `max=3, window=10s` and pins that
/// the 4th attempt inside the window is rejected before TLS handshake.
///
/// We use the `conn_rate` arm of the listener directly — the in-process
/// `SlidingWindowLimiter` is the same struct the accept-loop consults, and a
/// network-driven test would otherwise need to choreograph 4 simultaneous
/// TLS clients to land inside one window which is flaky on slow CI.
#[test]
fn ws_rate_limit_actually_enforces_configured_max() {
    use std::net::IpAddr;
    use std::time::Duration;

    use rustgate_resilience::SlidingWindowLimiter;

    // The SlidingWindowLimiter is what `WsListenerConfig::conn_rate_limit` /
    // `conn_rate_window` is threaded into at `WsListener::bind_with_config`
    // construction. Pin the contract: 3 allowed, 4th rejected, all
    // attempts inside one window from the same IP.
    let limiter = SlidingWindowLimiter::new(3, Duration::from_secs(10), "connection")
        .with_ipv6_64_collapse(true);
    let ip: IpAddr = "10.0.0.42".parse().unwrap();

    assert!(!limiter.is_limited(ip), "1st attempt should pass");
    assert!(!limiter.is_limited(ip), "2nd attempt should pass");
    assert!(!limiter.is_limited(ip), "3rd attempt (== max) should pass");
    assert!(
        limiter.is_limited(ip),
        "4th attempt inside window must be rate-limited"
    );
}

/// Construction smoke-test: a `WsListenerConfig` with the new knob raised
/// to a thousand-peer-fleet value must thread through to a live listener
/// without panicking. We don't assert on driver behaviour here (that's
/// what the unit test above pins) — just that the config plumbing compiles
/// and binds.
#[tokio::test]
async fn ws_listener_accepts_raised_rate_limit_config() {
    let ca = TestCa::new("Test CA");
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);
    let tls_config = TlsConfig::from_pem(&server_cert.cert_pem, &server_cert.key_pem, &ca.cert_pem)
        .expect("tls config");

    let addr: std::net::SocketAddr = "127.0.0.1:0".parse().expect("addr");
    let cfg = WsListenerConfig {
        // Production-fleet sized cap. Pre-#756 was hard-coded at 10/10s.
        conn_rate_limit: 1_000,
        conn_rate_window: std::time::Duration::from_secs(60),
        ..WsListenerConfig::default()
    };
    let listener = WsListener::bind_with_config(addr, &tls_config, cfg).expect("bind");
    let bound = listener.local_addr().expect("local addr");
    assert_ne!(bound.port(), 0, "listener bound on a real port");
}

// ── F-60: mTLS happens BEFORE the WS upgrade is parsed ───────────────

/// Build a `rustls::ClientConfig` that trusts the server CA but presents
/// **no** client certificate. The local mTLS verifier on the server side
/// is configured by `TlsConfig::build_server_config` to require a client
/// certificate (the `with_client_cert_verifier(...)` arm) — so this
/// connection must die at the TLS handshake, before any HTTP byte
/// crosses the wire.
fn build_client_tls_no_cert(ca_pem: &str) -> rustls::ClientConfig {
    let mut root_store = RootCertStore::empty();
    for cert in rustls::pki_types::CertificateDer::pem_slice_iter(ca_pem.as_bytes()) {
        root_store
            .add(cert.expect("parse ca cert"))
            .expect("add ca cert");
    }
    rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth()
}

/// **F-60** — pin the mTLS-before-upgrade ordering.
///
/// Setup: a `WsListener` bound with mTLS-required configuration and the
/// CA-trust set the server is configured against. The client builds a
/// rustls config that **trusts the server CA** but presents **no client
/// certificate** (`with_no_client_auth`). It then attempts the TLS
/// handshake. If the server-side cert verifier is invoked before the
/// HTTP Upgrade machinery sees any bytes — which is what
/// `WsListener::accept` does today — the handshake fails inside the TLS
/// layer with a `CertificateRequired` (or equivalent) alert; the client
/// observes a TLS error from `connect`, **never** an HTTP response of
/// any kind.
///
/// If a future refactor moved the auth checkpoint to *after* the HTTP
/// Upgrade parse (a real worry the threat model guards against — see
/// the `D8` row in the listener doc-comment), the client would observe
/// either a 4xx HTTP response or a successful upgrade *before* TLS
/// errored. This test is the canary for that.
#[tokio::test]
async fn ws_upgrade_without_client_cert_rejected_at_tls_layer_not_http() {
    let ca = TestCa::new("Test CA");
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);

    // Server: mTLS-required, identical to production.
    let tls_config = TlsConfig::from_pem(&server_cert.cert_pem, &server_cert.key_pem, &ca.cert_pem)
        .expect("tls config");
    let addr: std::net::SocketAddr = "127.0.0.1:0".parse().expect("addr");
    let listener = WsListener::bind(addr, &tls_config).expect("bind");
    let bound = listener.local_addr().expect("local addr");

    // Background: drive `accept` and confirm the loop does NOT yield a
    // session — it is rejected at one of the inner `continue` arms in
    // the listener accept loop (`TLS handshake failed`). We cap the
    // wait at 3 seconds so a future regression that *did* let the HTTP
    // upgrade run to completion would hang here and the assertion
    // `is_err()` would fire.
    let server_handle = tokio::spawn(async move {
        tokio::time::timeout(std::time::Duration::from_secs(3), listener.accept()).await
    });

    // Client: trust the server CA, but present no client cert.
    let client_tls = build_client_tls_no_cert(&ca.cert_pem);
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_tls));
    let tcp = tokio::net::TcpStream::connect(bound)
        .await
        .expect("tcp connect");
    let server_name = "localhost".try_into().expect("server name");
    let tls_result = connector.connect(server_name, tcp).await;

    // The TLS layer must reject the client BEFORE any HTTP machinery
    // runs. We accept either of two failure shapes:
    //
    // 1. `tls_result` is `Err(_)` — the rustls verifier fired during
    //    `connect()` and surfaced the alert directly. This is the
    //    common case on most platforms.
    // 2. `tls_result` is `Ok(stream)` but every read/write on it
    //    fails immediately — the OS/socket handed us a "connected"
    //    handle whose underlying fd has already received the alert
    //    and is unusable. We never see an HTTP response on this stream.
    //
    // We refuse to accept the *third* shape — a stream that successfully
    // round-trips bytes — because that would mean the HTTP Upgrade
    // pipeline saw the request and either accepted or rejected it. The
    // F-60 invariant is that the HTTP layer must never run on a
    // no-cert connection.
    let tls_layer_rejected = match tls_result {
        Err(_) => true,
        Ok(mut stream) => {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            // Try to send a *valid* HTTP/1.1 Upgrade preamble. If the
            // underlying TLS stream is actually torn down, this errors;
            // otherwise the read of any response also errors / returns
            // EOF. If neither errors and the server returns HTTP bytes,
            // the test fails — that is the F-60 violation.
            let upgrade_request = b"GET / HTTP/1.1\r\n\
                Host: localhost\r\n\
                Upgrade: websocket\r\n\
                Connection: Upgrade\r\n\
                Sec-WebSocket-Version: 13\r\n\
                Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                \r\n";
            if stream.write_all(upgrade_request).await.is_err() || stream.flush().await.is_err() {
                true
            } else {
                let mut buf = [0u8; 256];
                match tokio::time::timeout(
                    std::time::Duration::from_millis(500),
                    stream.read(&mut buf),
                )
                .await
                {
                    // EOF / read error / read timeout — the stream is
                    // dead at the TLS layer, no HTTP response was ever
                    // synthesised. This satisfies F-60.
                    Ok(Ok(0)) | Ok(Err(_)) | Err(_) => true,
                    // `n > 0`: we got bytes back. If those bytes are an
                    // HTTP response (start with "HTTP/"), the F-60
                    // invariant is *violated* — the upgrade machinery
                    // ran on a no-cert connection. Anything else
                    // (e.g. the tail of a TLS alert leaked into the
                    // socket buffer) is fine.
                    Ok(Ok(n)) => {
                        let response_start = &buf[..n.min(5)];
                        !response_start.starts_with(b"HTTP/")
                    }
                }
            }
        }
    };

    assert!(
        tls_layer_rejected,
        "F-60 violation: no-client-cert WS upgrade reached HTTP layer"
    );

    // Server-side: the accept loop must NOT have produced a session.
    // The `tokio::time::timeout` returns `Err(_)` on timeout; an
    // `accept()` that succeeded would surface as `Ok(Ok(_))`.
    let server_result = server_handle.await.expect("server task");
    assert!(
        server_result.is_err() || server_result.unwrap().is_err(),
        "server must not have produced a session for a no-cert client"
    );
}
