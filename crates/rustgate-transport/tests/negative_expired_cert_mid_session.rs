// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

#![allow(clippy::panic, clippy::unwrap_used)]
#![allow(unused_results)]
//! Negative integration test: client certificate expires mid-session.
//!
//! Refs #789 / F-134. Drives a real mTLS handshake with a client cert
//! that is valid for only a few seconds, hands off the live session,
//! sleeps past the expiry, then attempts to send and receive bytes.
//!
//! # What this test pins
//!
//! Whatever the current behaviour is, the test pins it as the
//! reference. Today, `tokio-rustls` only validates client cert
//! expiry at the TLS handshake — once the handshake completes, the
//! resulting `TlsStream` is grandfathered. The transport layer does
//! NOT poll for cert expiry on every read/write because the rustls
//! API doesn't expose that hook on the connection-server side, and
//! neither does the workspace's `CertReloader` re-evaluate already-
//! established sessions. So:
//!
//! - The handshake succeeds while the cert is still valid.
//! - The session continues to read and write **after** expiry,
//!   because no part of the transport polls the cert clock on the
//!   live socket.
//!
//! This is the intentional baseline — the regression target this
//! test gives us is "session continues to function past expiry".
//! A future feature (issue #1095, hypothetical "fail-closed
//! reload-on-expiry") would flip this expectation, and rewriting
//! this test will be the cheap, mechanical signal that the policy
//! has been deliberately changed rather than silently broken.
//!
//! The test waits a fixed grace window past expiry (a few seconds —
//! short enough to keep the suite fast, long enough that the cert
//! is unambiguously expired) and asserts the session can still
//! exchange bytes. If a future change starts terminating expired
//! sessions, the test failure points the reviewer at this file
//! and at the cert-expiry-policy decision they're touching.

use std::sync::Arc;
use std::time::Duration;

use rustgate_test_utils::certs::TestCa;
use rustgate_test_utils::tls::build_client_tls_config;
use rustgate_tls::{TlsConfig, TlsListener};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The cert is issued with 5 seconds of remaining validity. The test
/// then sleeps 6 seconds before attempting to send the post-expiry
/// payload. Both numbers are independent constants so a future
/// reviewer who wants to widen the grace window can do so without
/// reading the expiry-issuance call site.
const CERT_VALIDITY_SECS: i64 = 5;
const POST_EXPIRY_SLEEP_SECS: u64 = 6;

#[tokio::test(flavor = "current_thread", start_paused = false)]
async fn live_session_survives_client_cert_expiry() {
    let ca = TestCa::new("Test CA");
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);
    // Cert is valid NOW — the handshake will succeed — but expires in
    // CERT_VALIDITY_SECS seconds, which is well before the test's
    // post-expiry probe.
    let client_cert =
        ca.issue_near_expiry_client_cert("ephemeral", &["operators"], CERT_VALIDITY_SECS);

    let tls_config = TlsConfig::from_pem(&server_cert.cert_pem, &server_cert.key_pem, &ca.cert_pem)
        .expect("tls config");
    let listener = TlsListener::bind("127.0.0.1:0", &tls_config)
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");

    let server_handle = tokio::spawn(async move {
        let session = listener.accept().await.expect("accept");
        let identity = session.identity().clone();
        let (mut reader, mut writer) = session.split();

        // Pre-expiry roundtrip — confirms the handshake worked and
        // gives the test a known-good baseline before the wait.
        let mut buf = [0u8; 4];
        reader
            .read_exact(&mut buf)
            .await
            .expect("server read pre-expiry");
        assert_eq!(&buf, b"pre-");
        writer
            .write_all(b"ok-1")
            .await
            .expect("server write pre-expiry");

        // Post-expiry roundtrip. If this fails (because some future
        // feature starts policing live sessions for cert expiry), the
        // assertion at the call site drives the test failure with a
        // clearer message; here we just propagate whatever the I/O
        // layer returns.
        let mut buf2 = [0u8; 5];
        let post_read = reader.read_exact(&mut buf2).await;
        let post_write = if post_read.is_ok() {
            writer.write_all(b"ok-2").await
        } else {
            // Read failed — write probably also fails; bubble up the
            // shape so the assertion site can introspect.
            Err(std::io::Error::other("post-expiry read failed"))
        };

        (identity, post_read.is_ok() && post_write.is_ok())
    });

    let config = build_client_tls_config(&client_cert.cert_pem, &client_cert.key_pem, &ca.cert_pem);
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("tcp connect");
    let server_name = "localhost".try_into().expect("server name");
    let mut stream = connector
        .connect(server_name, tcp)
        .await
        .expect("tls connect (cert is still valid at handshake time)");

    // Pre-expiry exchange.
    stream
        .write_all(b"pre-")
        .await
        .expect("client write pre-expiry");
    let mut buf = [0u8; 4];
    stream
        .read_exact(&mut buf)
        .await
        .expect("client read pre-expiry");
    assert_eq!(&buf, b"ok-1");

    // Sleep PAST the cert's not_after so any policy that polls the
    // clock has a definite signal to act on.
    tokio::time::sleep(Duration::from_secs(POST_EXPIRY_SLEEP_SECS)).await;

    // Post-expiry exchange. With today's transport behaviour this
    // succeeds — the cert was checked at handshake and the session
    // is grandfathered. If a future PR starts policing expiry on
    // live sessions, this write/read pair becomes the failure point
    // and the test docs explain the deliberate behavioural change.
    stream
        .write_all(b"post-")
        .await
        .expect("client write post-expiry");
    let mut buf2 = [0u8; 4];
    stream
        .read_exact(&mut buf2)
        .await
        .expect("client read post-expiry");
    assert_eq!(&buf2, b"ok-2");

    let (identity, post_ok) = server_handle.await.expect("server task");

    assert_eq!(
        &*identity.cn, "ephemeral",
        "identity from the cert is extracted correctly"
    );
    assert!(
        identity.is_member_of("operators"),
        "OU groups carry over from the near-expiry cert"
    );
    assert!(
        post_ok,
        "current behaviour: live session continues past cert expiry. \
         If a future PR introduces fail-closed reload-on-expiry, update \
         this test to assert the new policy and document the decision."
    );
}
