// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

#![allow(unused_results)]
#![allow(clippy::panic, clippy::unwrap_used)]
//! Error path tests for TLS: expired certificates, wrong CA rejection,
//! self-signed certificate rejection, and channel backpressure.

use std::sync::Arc;

use rustgate_test_utils::certs::TestCa;
use rustgate_test_utils::tls::build_client_tls_config;
use rustgate_tls::{TlsConfig, TlsListener};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// ── Expired certificate rejection ───────────────────────────────────────

/// A client presenting an expired certificate should be rejected during
/// or immediately after the TLS handshake.
#[tokio::test]
async fn expired_client_cert_rejected() {
    let ca = TestCa::new("Test CA");
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);
    let expired_cert = ca.issue_expired_client_cert("expired-alice", &["team"]);

    let tls_config = TlsConfig::from_pem(&server_cert.cert_pem, &server_cert.key_pem, &ca.cert_pem)
        .expect("tls config");
    let listener = TlsListener::bind("127.0.0.1:0", &tls_config)
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");

    let server_handle = tokio::spawn(async move {
        tokio::time::timeout(std::time::Duration::from_secs(5), listener.accept()).await
    });

    let config =
        build_client_tls_config(&expired_cert.cert_pem, &expired_cert.key_pem, &ca.cert_pem);
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("tcp connect");
    let server_name = "localhost".try_into().expect("server name");
    let result = connector.connect(server_name, tcp).await;

    // The handshake may succeed at the TLS level (TLS 1.3 defers client cert
    // validation), but the connection should fail when the server validates
    // the certificate.
    let failed = match result {
        Err(_) => true,
        Ok(mut stream) => {
            // TLS 1.3 may defer the alert — try using the connection
            if stream.write_all(b"x").await.is_err() || stream.flush().await.is_err() {
                true
            } else {
                let mut buf = [0u8; 1];
                match tokio::time::timeout(
                    std::time::Duration::from_millis(500),
                    stream.read(&mut buf),
                )
                .await
                {
                    Ok(Ok(0)) | Ok(Err(_)) | Err(_) => true,
                    Ok(Ok(_)) => false,
                }
            }
        }
    };

    assert!(
        failed,
        "expired client cert should not establish a usable session"
    );

    let server_result = server_handle.await.expect("server task");
    // Server should either return an error or time out
    let rejected = match server_result {
        Ok(Err(_)) => true, // Accept returned an error
        Err(_) => true,     // Timeout — no valid session
        Ok(Ok(_)) => false, // Session was accepted (unexpected)
    };
    assert!(rejected, "server should reject expired client certificate");
}

// ── Wrong CA rejection ──────────────────────────────────────────────────

/// A client presenting a certificate signed by a different CA than the
/// server trusts should be rejected.
#[tokio::test]
async fn wrong_ca_client_cert_rejected() {
    let server_ca = TestCa::new("Server CA");
    let rogue_ca = TestCa::new("Rogue CA");

    let server_cert = server_ca.issue_server_cert("localhost", &["localhost"]);
    let rogue_client = rogue_ca.issue_client_cert("mallory", &["hackers"]);

    let tls_config = TlsConfig::from_pem(
        &server_cert.cert_pem,
        &server_cert.key_pem,
        &server_ca.cert_pem,
    )
    .expect("tls config");

    let listener = TlsListener::bind("127.0.0.1:0", &tls_config)
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");

    let server_handle = tokio::spawn(async move {
        tokio::time::timeout(std::time::Duration::from_secs(5), listener.accept()).await
    });

    // Client trusts the server CA but presents a cert from the rogue CA
    let config = build_client_tls_config(
        &rogue_client.cert_pem,
        &rogue_client.key_pem,
        &server_ca.cert_pem,
    );
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("tcp connect");
    let server_name = "localhost".try_into().expect("server name");
    let result = connector.connect(server_name, tcp).await;

    let failed = match result {
        Err(_) => true,
        Ok(mut stream) => {
            if stream.write_all(b"x").await.is_err() || stream.flush().await.is_err() {
                true
            } else {
                let mut buf = [0u8; 1];
                match tokio::time::timeout(
                    std::time::Duration::from_millis(500),
                    stream.read(&mut buf),
                )
                .await
                {
                    Ok(Ok(0)) | Ok(Err(_)) | Err(_) => true,
                    Ok(Ok(_)) => false,
                }
            }
        }
    };

    assert!(
        failed,
        "client with cert from wrong CA should not communicate"
    );

    let server_result = server_handle.await.expect("server task");
    assert!(
        server_result.is_err() || matches!(server_result, Ok(Err(_))),
        "server should reject client with cert from wrong CA"
    );
}

// ── Self-signed certificate rejection ───────────────────────────────────

/// A client using a self-signed certificate (its own CA) not in the
/// server's trust chain should be rejected.
#[tokio::test]
async fn self_signed_client_cert_rejected() {
    let server_ca = TestCa::new("Server CA");
    let self_signed_ca = TestCa::new("Self-Signed");

    let server_cert = server_ca.issue_server_cert("localhost", &["localhost"]);
    // The "self-signed" client uses its own CA as both issuer and trust root
    let self_signed_client = self_signed_ca.issue_client_cert("eve", &["intruders"]);

    let tls_config = TlsConfig::from_pem(
        &server_cert.cert_pem,
        &server_cert.key_pem,
        &server_ca.cert_pem,
    )
    .expect("tls config");

    let listener = TlsListener::bind("127.0.0.1:0", &tls_config)
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");

    let server_handle = tokio::spawn(async move {
        tokio::time::timeout(std::time::Duration::from_secs(5), listener.accept()).await
    });

    // Client trusts the server CA (to verify the server cert) but presents
    // a cert signed by self_signed_ca which the server does not trust.
    let config = build_client_tls_config(
        &self_signed_client.cert_pem,
        &self_signed_client.key_pem,
        &server_ca.cert_pem,
    );
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("tcp connect");
    let server_name = "localhost".try_into().expect("server name");
    let result = connector.connect(server_name, tcp).await;

    let failed = match result {
        Err(_) => true,
        Ok(mut stream) => {
            if stream.write_all(b"x").await.is_err() || stream.flush().await.is_err() {
                true
            } else {
                let mut buf = [0u8; 1];
                match tokio::time::timeout(
                    std::time::Duration::from_millis(500),
                    stream.read(&mut buf),
                )
                .await
                {
                    Ok(Ok(0)) | Ok(Err(_)) | Err(_) => true,
                    Ok(Ok(_)) => false,
                }
            }
        }
    };

    assert!(
        failed,
        "self-signed client cert should not establish a usable session"
    );

    let server_result = server_handle.await.expect("server task");
    assert!(
        server_result.is_err() || matches!(server_result, Ok(Err(_))),
        "server should reject self-signed client certificate"
    );
}

// ── Channel backpressure ────────────────────────────────────────────────

/// Fill a session's group-send channel and verify that messages are dropped
/// gracefully without panicking. Group sends use `try_send` internally,
/// so a full channel causes silent drops rather than blocking.
#[tokio::test]
async fn group_send_backpressure_drops_without_panic() {
    use std::collections::BTreeSet;
    use std::time::SystemTime;

    use bytes::Bytes;
    use rustgate_core::identity::Identity;
    use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};
    use rustgate_router::{Router, SessionHandle};
    use tokio::sync::mpsc;

    let router = Router::new();

    let alice = Arc::new(
        Identity::new(
            "alice".to_string(),
            "alice-fp".to_string(),
            ["team".to_string()].into_iter().collect::<BTreeSet<_>>(),
        )
        .expect("valid identity"),
    );
    let bob = Arc::new(
        Identity::new(
            "bob".to_string(),
            "bob-fp".to_string(),
            ["team".to_string()].into_iter().collect::<BTreeSet<_>>(),
        )
        .expect("valid identity"),
    );

    // Alice gets a tiny normal channel — capacity 1 (chat goes to normal)
    let (ptx_a, _prx_a) = mpsc::channel(16);
    let (ntx_a, _nrx_a) = mpsc::channel(1);
    let (ptx_b, _prx_b) = mpsc::channel(16);
    let (ntx_b, _nrx_b) = mpsc::channel(16);

    router
        .register(SessionHandle::new(alice.clone(), ptx_a, ntx_a))
        .await;
    router
        .register(SessionHandle::new(bob.clone(), ptx_b, ntx_b))
        .await;

    // Bob floods the group — alice's channel overflows.
    // Group sends use try_send, so this completes immediately.
    for i in 0..20 {
        let msg = RoutableMessage {
            source: (*bob).clone(),
            destination: Destination::Group("team".into()),
            payload: Bytes::from(format!("msg-{i}")),
            metadata: Metadata::new(SystemTime::now(), "cot".to_string(), MessageType::Chat),
            entity: None,
        };
        router.route(msg).await;
    }

    // No panic — test passes if we reach here
}

/// When a receiver is dropped (simulating a disconnected session), both
/// direct sends and broadcasts should return immediately with an error
/// rather than blocking or panicking.
#[tokio::test]
async fn disconnected_receiver_drops_gracefully() {
    use std::collections::BTreeSet;
    use std::time::SystemTime;

    use bytes::Bytes;
    use rustgate_core::identity::Identity;
    use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};
    use rustgate_router::{Router, SessionHandle};
    use tokio::sync::mpsc;

    let router = Router::new();

    let alice = Arc::new(
        Identity::new("alice".to_string(), "alice-fp".to_string(), BTreeSet::new())
            .expect("valid identity"),
    );
    let bob = Arc::new(
        Identity::new("bob".to_string(), "bob-fp".to_string(), BTreeSet::new())
            .expect("valid identity"),
    );

    let (ptx_a, _prx_a) = mpsc::channel(16);
    let (ntx_a, _nrx_a) = mpsc::channel(16);
    let (ptx_b, prx_b) = mpsc::channel(1);
    let (ntx_b, nrx_b) = mpsc::channel(1);

    router
        .register(SessionHandle::new(alice.clone(), ptx_a, ntx_a))
        .await;
    router
        .register(SessionHandle::new(bob.clone(), ptx_b, ntx_b))
        .await;

    // Drop bob's receivers — simulates a disconnected session.
    // Now send().await will return Err immediately instead of blocking.
    drop(prx_b);
    drop(nrx_b);

    // Direct send to disconnected bob
    for i in 0..5 {
        let msg = RoutableMessage {
            source: (*alice).clone(),
            destination: Destination::Direct((*bob).clone()),
            payload: Bytes::from(format!("direct-{i}")),
            metadata: Metadata::new(SystemTime::now(), "cot".to_string(), MessageType::Chat),
            entity: None,
        };
        router.route(msg).await;
    }

    // Broadcast to disconnected bob
    for i in 0..5 {
        let msg = RoutableMessage {
            source: (*alice).clone(),
            destination: Destination::Broadcast,
            payload: Bytes::from(format!("broadcast-{i}")),
            metadata: Metadata::new(SystemTime::now(), "cot".to_string(), MessageType::Chat),
            entity: None,
        };
        router.route(msg).await;
    }

    // No panic — test passes if we reach here
}
