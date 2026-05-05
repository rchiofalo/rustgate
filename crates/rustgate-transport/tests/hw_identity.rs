// Copyright © 2026 Roberto Chiofalo.

//! Integration tests for the `HardwareIdentity` trait + reference
//! `Pkcs11StubBackend` (refs #856).
//!
//! The trait + stub ship in `crates/rustgate-transport/src/hw_identity.rs`
//! together with their unit-test surface; this file pins the
//! end-to-end contract through a real `TlsListener` so a future
//! refactor that breaks the resolver wiring fails the build instead
//! of silently regressing the fail-closed behaviour.

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    unused_results
)]

use std::sync::Arc;

use rustgate_test_utils::certs::TestCa;
use rustgate_test_utils::tls::build_client_tls_config;
use rustgate_transport::{
    HardwareIdentity, HardwareIdentityResolver, Pkcs11StubBackend, TlsConfig, TlsListener,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn install_provider() {
    // Idempotent across tests.
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Build a `ServerConfig` whose certificate resolver is backed by a
/// `Pkcs11StubBackend` rather than an on-disk cert/key pair.
fn server_config_with_hw_identity(
    server_cert_pem: &str,
    server_key_pem: &str,
    ca_pem: &str,
) -> Arc<rustls::ServerConfig> {
    let tls_config =
        TlsConfig::from_pem(server_cert_pem, server_key_pem, ca_pem).expect("tls config from pem");
    let verifier = tls_config
        .build_default_verifier()
        .expect("default client verifier");
    let stub =
        Pkcs11StubBackend::from_pem(server_cert_pem, server_key_pem).expect("stub init from pem");
    let backend: Arc<dyn HardwareIdentity> = Arc::new(stub);
    let resolver = Arc::new(HardwareIdentityResolver::new(backend));
    let server_config = tls_config
        .build_reloadable_server_config(verifier, resolver)
        .expect("reloadable server config with hw identity resolver");
    Arc::new(server_config)
}

/// Full mTLS handshake where the server's identity material is
/// served through the `HardwareIdentity` resolver. Pins:
///
/// 1. Bind succeeds with the hardware-identity-backed `ServerConfig`.
/// 2. A trusted client completes the handshake.
/// 3. Bytes flow round-trip through the resulting session — proving
///    the stub's `certified_key()` produced a working signing key.
#[tokio::test]
async fn tls_listener_uses_hw_identity_when_configured() {
    install_provider();

    let ca = TestCa::new("hw-identity-integration-ca");
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);
    let client_cert = ca.issue_client_cert("alice", &["engineers"]);

    let server_config =
        server_config_with_hw_identity(&server_cert.cert_pem, &server_cert.key_pem, &ca.cert_pem);
    let listener = TlsListener::bind_with_server_config("127.0.0.1:0", server_config, 8)
        .await
        .expect("bind with hw identity");
    let addr = listener.local_addr().expect("local addr");

    let server_handle = tokio::spawn(async move {
        let session = listener.accept().await.expect("hw-identity-backed accept");
        let identity = session.identity().clone();
        let (mut reader, mut writer) = session.split();
        let mut buf = [0u8; 5];
        reader.read_exact(&mut buf).await.expect("server read");
        assert_eq!(&buf, b"hello");
        writer.write_all(b"world").await.expect("server write");
        identity
    });

    let client_config =
        build_client_tls_config(&client_cert.cert_pem, &client_cert.key_pem, &ca.cert_pem);
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let tcp = tokio::net::TcpStream::connect(addr).await.expect("tcp");
    let server_name = "localhost".try_into().expect("server name");
    let mut stream = connector
        .connect(server_name, tcp)
        .await
        .expect("client tls connect against hw identity");

    stream.write_all(b"hello").await.expect("client write");
    let mut buf = [0u8; 5];
    stream.read_exact(&mut buf).await.expect("client read");
    assert_eq!(&buf, b"world");

    let identity = server_handle.await.expect("server task");
    assert_eq!(&*identity.cn, "alice");
}

/// When the hardware-identity backend reports unavailable
/// (`set_available(false)` simulating an unplugged token / locked
/// PIN / dropped workload-API socket), the resolver returns `None`
/// — rustls fails the handshake without touching the listener's
/// fallback paths.
#[tokio::test]
async fn tls_listener_rejects_handshake_when_hw_identity_unavailable() {
    install_provider();

    let ca = TestCa::new("hw-identity-fail-closed-ca");
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);
    let client_cert = ca.issue_client_cert("alice", &["engineers"]);

    let tls_config = TlsConfig::from_pem(&server_cert.cert_pem, &server_cert.key_pem, &ca.cert_pem)
        .expect("tls config");
    let verifier = tls_config.build_default_verifier().expect("verifier");

    // Construct the stub via Arc<Pkcs11StubBackend> first so the
    // test can flip the availability flag without recovering the
    // concrete type from the trait object.
    let stub = Arc::new(
        Pkcs11StubBackend::from_pem(&server_cert.cert_pem, &server_cert.key_pem)
            .expect("stub init"),
    );
    stub.set_available(false);
    let backend: Arc<dyn HardwareIdentity> = stub.clone();
    let resolver = Arc::new(HardwareIdentityResolver::new(backend));
    let server_config = Arc::new(
        tls_config
            .build_reloadable_server_config(verifier, resolver)
            .expect("reloadable server config"),
    );

    let listener = TlsListener::bind_with_server_config("127.0.0.1:0", server_config, 4)
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");

    let server_handle = tokio::spawn(async move {
        // The handshake must fail before this call yields a session;
        // give it a bounded window and assert nothing came through.
        tokio::time::timeout(std::time::Duration::from_secs(2), listener.accept()).await
    });

    let client_config =
        build_client_tls_config(&client_cert.cert_pem, &client_cert.key_pem, &ca.cert_pem);
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let tcp = tokio::net::TcpStream::connect(addr).await.expect("tcp");
    let server_name = "localhost".try_into().expect("server name");
    let result = connector.connect(server_name, tcp).await;

    // The handshake must fail because the resolver returned None.
    // rustls surfaces this as a connection-level error.
    let handshake_failed = match result {
        Err(_) => true,
        Ok(mut stream) => {
            // Some TLS versions defer the failure — exercise the
            // session and assert it cannot complete a round-trip.
            if stream.write_all(b"x").await.is_err() || stream.flush().await.is_err() {
                true
            } else {
                let mut buf = [0u8; 1];
                tokio::time::timeout(std::time::Duration::from_millis(500), stream.read(&mut buf))
                    .await
                    .map_or(true, |inner| matches!(inner, Ok(0) | Err(_)))
            }
        }
    };
    assert!(
        handshake_failed,
        "fail-closed contract violated: resolver returned None but client completed handshake"
    );

    let server_result = server_handle.await.expect("server task");
    assert!(
        server_result.is_err(),
        "listener.accept() must time out — fail-closed resolver yields no session"
    );
}
