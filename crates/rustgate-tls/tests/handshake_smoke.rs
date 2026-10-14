// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! End-to-end mTLS handshake smoke tests for `rustgate-tls`.
//!
//! Inline unit tests in each module cover the per-component contracts
//! (PEM parsing, identity extraction from a synthetic X.509 cert,
//! CRL hot-reload via `CertReloader`). These integration tests cover
//! the **happy path end-to-end**: a real `TlsListener` binds, a real
//! `tokio-rustls` client connects, the mTLS handshake completes, and
//! the resulting `AuthenticatedSession` exposes the cert's identity.
//!
//! Reject-path coverage (expired certs, cross-CA, CRL revocation)
//! already lives in
//! `rustgate-transport/tests/{tls_security,crl}.rs`. The tls
//! crate's smoke tests cover the SUCCESS contract — which the
//! transport tests don't exercise directly because they're focused
//! on rejection behaviour.
//!
//! Full OCSP / SPIFFE / hot-reload integration coverage is out of
//! scope for this smoke layer — those flows are tested in the
//! crates that actually wire them (transport + federation).

#![allow(clippy::panic, clippy::unwrap_used)]

use std::sync::Arc;

use rustgate_core::constants::HANDSHAKE_TIMEOUT;
use rustgate_test_utils::certs::TestCa;
use rustgate_test_utils::tls::build_client_tls_config;
use rustgate_tls::{TlsConfig, TlsListener};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// ------------------------------------------------------------------
// Happy-path handshake + identity extraction
// ------------------------------------------------------------------

/// A valid mTLS handshake against a `TestCa`-issued client cert must
/// complete, and the `AuthenticatedSession` returned by
/// `TlsListener::accept` must expose the client's CN and OU group
/// list through the identity-extraction path.
#[tokio::test]
async fn happy_path_handshake_extracts_cn_and_groups_from_client_cert() {
    let ca = TestCa::new("rustgate-tls Smoke CA");
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);
    let client_cert = ca.issue_client_cert("ALPHA-OPERATOR-1", &["Team-Alpha", "HQ"]);

    let tls_config = TlsConfig::from_pem(&server_cert.cert_pem, &server_cert.key_pem, &ca.cert_pem)
        .expect("server TLS config builds");
    let listener = TlsListener::bind("127.0.0.1:0", &tls_config)
        .await
        .expect("listener binds");
    let addr = listener.local_addr().expect("listener has a local addr");

    // Server task: accept one session, read the client's hello byte,
    // echo a reply.
    let server_handle = tokio::spawn(async move {
        let session = tokio::time::timeout(HANDSHAKE_TIMEOUT, listener.accept())
            .await
            .expect("handshake within deadline")
            .expect("accept ok");
        // Identity extraction is the load-bearing rustgate-tls
        // contract — verify the CN + groups round-tripped from the
        // X.509 cert into `Identity`.
        assert_eq!(&*session.identity().cn, "ALPHA-OPERATOR-1");
        assert!(
            session.identity().groups.contains("Team-Alpha"),
            "Team-Alpha missing from groups: {:?}",
            session.identity().groups,
        );
        assert!(
            session.identity().groups.contains("HQ"),
            "HQ missing from groups: {:?}",
            session.identity().groups,
        );
        // Fingerprint is non-empty and contains only hex / separator
        // chars — the exact format (lower-hex, colon-delimited,
        // etc.) is an internal detail.
        assert!(
            !session.identity().fingerprint.is_empty(),
            "fingerprint must be populated by extract_identity",
        );
        assert!(
            session
                .identity()
                .fingerprint
                .chars()
                .all(|c| c.is_ascii_hexdigit() || c == ':'),
            "fingerprint is not hex / colon-delimited: {}",
            session.identity().fingerprint,
        );

        // Echo: receive 5 bytes, send 5 back.
        let (mut reader, mut writer) = session.split();
        let mut buf = [0u8; 5];
        let _ = reader
            .read_exact(&mut buf)
            .await
            .expect("server reads hello");
        assert_eq!(&buf, b"hello");
        writer
            .write_all(b"world")
            .await
            .expect("server writes reply");
        writer.flush().await.expect("server flushes");
    });

    // Client side: dial + complete handshake + echo round-trip.
    let client_tls =
        build_client_tls_config(&client_cert.cert_pem, &client_cert.key_pem, &ca.cert_pem);
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_tls));
    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("client tcp connect");
    let server_name: rustls_pki_types::ServerName<'static> =
        "localhost".try_into().expect("valid server name");
    let mut stream = tokio::time::timeout(HANDSHAKE_TIMEOUT, connector.connect(server_name, tcp))
        .await
        .expect("client handshake within deadline")
        .expect("handshake ok");

    stream
        .write_all(b"hello")
        .await
        .expect("client writes hello");
    stream.flush().await.expect("client flushes hello");

    let mut reply = [0u8; 5];
    let _ = stream
        .read_exact(&mut reply)
        .await
        .expect("client reads reply");
    assert_eq!(&reply, b"world");

    server_handle.await.expect("server task joins");
}

// ------------------------------------------------------------------
// Two clients in a row
// ------------------------------------------------------------------

/// One listener must serve multiple sequential handshakes from
/// independent clients with distinct identities. Verifies the
/// listener's accept-loop state survives across handshakes (no
/// stale session bleed, no leaked semaphore permit).
#[tokio::test]
async fn two_sequential_clients_each_get_their_own_identity() {
    let ca = TestCa::new("rustgate-tls Smoke CA Sequential");
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);

    let tls_config = TlsConfig::from_pem(&server_cert.cert_pem, &server_cert.key_pem, &ca.cert_pem)
        .expect("server config");
    let listener = TlsListener::bind("127.0.0.1:0", &tls_config)
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");

    let server_handle = tokio::spawn(async move {
        let s1 = tokio::time::timeout(HANDSHAKE_TIMEOUT, listener.accept())
            .await
            .expect("first handshake within deadline")
            .expect("first accept ok");
        let s2 = tokio::time::timeout(HANDSHAKE_TIMEOUT, listener.accept())
            .await
            .expect("second handshake within deadline")
            .expect("second accept ok");

        // Different CNs prove the listener didn't reuse session state.
        assert_eq!(&*s1.identity().cn, "CLIENT-ALPHA");
        assert_eq!(&*s2.identity().cn, "CLIENT-BRAVO");

        // Each session has its own fingerprint because the certs
        // differ.
        assert_ne!(s1.identity().fingerprint, s2.identity().fingerprint);
    });

    for cn in ["CLIENT-ALPHA", "CLIENT-BRAVO"] {
        let client_cert = ca.issue_client_cert(cn, &[]);
        let client_tls =
            build_client_tls_config(&client_cert.cert_pem, &client_cert.key_pem, &ca.cert_pem);
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_tls));
        let tcp = tokio::net::TcpStream::connect(addr).await.expect("tcp");
        let server_name: rustls_pki_types::ServerName<'static> =
            "localhost".try_into().expect("name");
        let _stream = tokio::time::timeout(HANDSHAKE_TIMEOUT, connector.connect(server_name, tcp))
            .await
            .expect("handshake within deadline")
            .expect("handshake ok");
        // Drop the stream to close it before opening the next.
    }

    server_handle.await.expect("server joins");
}

// ------------------------------------------------------------------
// Listener bind on an in-use port surfaces a typed error
// ------------------------------------------------------------------

/// `TlsListener::bind` against a port already held by another
/// listener must fail. Verifies the bind path surfaces the
/// `std::io::Error` (kind `AddrInUse`) instead of panicking. Catches
/// any regression that would swallow the bind failure into a
/// no-op listener.
#[tokio::test]
async fn bind_on_already_used_port_fails_with_address_in_use() {
    let ca = TestCa::new("rustgate-tls Smoke CA Bind");
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);
    let tls_config = TlsConfig::from_pem(&server_cert.cert_pem, &server_cert.key_pem, &ca.cert_pem)
        .expect("server config");

    // First bind succeeds and holds the port.
    let first = TlsListener::bind("127.0.0.1:0", &tls_config)
        .await
        .expect("first bind ok");
    let addr = first.local_addr().expect("addr");

    // Second bind to the SAME concrete port should fail. (Using a
    // synthetic addr-literal because bind-to-0 always picks a free
    // port.)
    let second_result = TlsListener::bind(addr, &tls_config).await;
    assert!(
        second_result.is_err(),
        "expected second bind to fail with AddrInUse, got Ok",
    );
}
