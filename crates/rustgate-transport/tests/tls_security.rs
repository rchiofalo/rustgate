// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

#![allow(clippy::panic, clippy::unwrap_used)]
//! End-to-end TLS handshake security tests.
//!
//! Validates that the mTLS handshake correctly rejects expired client
//! certificates, cross-CA certificates, and accepts valid certificates
//! from the trusted CA.

use std::sync::Arc;

use rustgate_test_utils::certs::TestCa;
use rustgate_test_utils::tls::build_client_tls_config;
use rustgate_tls::{TlsConfig, TlsListener};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// ── Expired certificate rejection ──────────────────────────────────────

/// A client presenting an expired certificate must be rejected during
/// or immediately after the TLS handshake. This validates the server's
/// certificate validity period enforcement at the transport layer.
#[tokio::test]
async fn expired_client_cert_rejected() {
    let ca = TestCa::new("Security Test CA");
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);
    let expired_cert = ca.issue_expired_client_cert("expired-operator", &["team"]);

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

    // TLS 1.3 may defer client cert validation; probe the connection
    // to surface the deferred alert.
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
        "expired client cert should not establish a usable session"
    );

    let server_result = server_handle.await.expect("server task");
    let rejected = match server_result {
        Ok(Err(_)) => true,
        Err(_) => true,
        Ok(Ok(_)) => false,
    };
    assert!(rejected, "server should reject expired client certificate");
}

// ── Cross-CA (self-signed) certificate rejection ───────────────────────

/// A client presenting a certificate signed by a different CA than the
/// server trusts must be rejected. This simulates a self-signed or
/// rogue-CA scenario where an attacker has their own PKI.
#[tokio::test]
async fn self_signed_cert_rejected() {
    let server_ca = TestCa::new("Server CA");
    let rogue_ca = TestCa::new("Rogue CA");

    let server_cert = server_ca.issue_server_cert("localhost", &["localhost"]);
    let rogue_client = rogue_ca.issue_client_cert("rogue-operator", &["attackers"]);

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
        "cross-CA client cert should not establish a usable session"
    );

    let server_result = server_handle.await.expect("server task");
    assert!(
        server_result.is_err() || matches!(server_result, Ok(Err(_))),
        "server should reject client with cert from untrusted CA"
    );
}

// ── Valid client certificate acceptance ─────────────────────────────────

/// Positive test: a valid client certificate from the same CA connects
/// successfully and the server extracts the correct identity.
#[tokio::test]
async fn valid_client_cert_accepted() {
    let ca = TestCa::new("Security Test CA");
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);
    let client_cert = ca.issue_client_cert("valid-operator", &["ops", "admins"]);

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

        let mut buf = [0u8; 5];
        let _ = reader.read_exact(&mut buf).await.expect("read");
        assert_eq!(&buf, b"hello");
        writer.write_all(b"world").await.expect("write");

        identity
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
        .expect("tls connect should succeed for valid cert");

    stream.write_all(b"hello").await.expect("client write");
    let mut buf = [0u8; 5];
    let _ = stream.read_exact(&mut buf).await.expect("client read");
    assert_eq!(&buf, b"world");

    let identity = server_handle.await.expect("server task");
    assert_eq!(&*identity.cn, "valid-operator");
    assert!(identity.is_member_of("ops"));
    assert!(identity.is_member_of("admins"));
    assert!(!identity.fingerprint.is_empty());
}
