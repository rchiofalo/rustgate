// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Post-quantum key exchange integration tests.
//!
//! These tests verify that the aws-lc-rs post-quantum provider installs
//! correctly, that TLS handshakes negotiate PQ key exchange groups, and
//! that custom KX group ordering works as expected.
//!
//! Only compiled when the `post-quantum` feature is enabled. Run with:
//! ```sh
//! cargo test -p rustgate-transport --features post-quantum
//! ```
#![cfg(feature = "post-quantum")]

use std::sync::{Arc, OnceLock};

use rustgate_test_utils::certs::TestCa;
use rustgate_test_utils::tls::build_client_tls_config;
use rustgate_tls::{TlsConfig, TlsListener, install_pq_provider, is_pq_provider_active};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// ── setup ────────────────────────────────────────────────────────────────

/// Install the PQ provider exactly once across all tests in this binary.
///
/// Must be called before `TestCa::new()` to ensure aws-lc-rs is the active
/// provider. The test-utils `ensure_crypto_provider()` will silently skip
/// installing ring because a provider is already installed.
static PQ_INIT: OnceLock<()> = OnceLock::new();
fn ensure_pq() {
    let _ = PQ_INIT.get_or_init(|| {
        install_pq_provider().expect("failed to install PQ provider");
    });
}

// ── PQ provider tests ──────────────────────────────────────────────────

/// After installing the PQ provider, a second `install_pq_provider()`
/// must return an error because `CryptoProvider::install_default` only
/// permits one installation per process.
#[test]
fn pq_double_install_returns_error() {
    ensure_pq();

    let result = install_pq_provider();
    assert!(
        result.is_err(),
        "second install_pq_provider() should return Err"
    );
}

/// After installing the PQ provider, `is_pq_provider_active()` must
/// return `true`, confirming X25519MLKEM768 is available.
#[test]
fn pq_provider_reports_active() {
    ensure_pq();
    assert!(
        is_pq_provider_active(),
        "is_pq_provider_active() must return true after install_pq_provider()"
    );
}

/// Verify the installed PQ provider includes X25519MLKEM768 in its
/// key exchange groups and at least one classical group for fallback
/// to legacy peers that do not speak a hybrid.
///
/// The "classical" set varies by backend feature combination:
///   * `post-quantum` alone (non-FIPS) — `aws_lc_rs::default_provider()`
///     exposes `X25519` plus the NIST curves.
///   * `post-quantum + fips` — the provider is restricted to
///     FIPS-approved groups, which excludes `X25519` but retains
///     `secp256r1` / `secp384r1` as classical fallbacks.
///
/// The invariant we care about is "hybrid PQ is offered *and* at
/// least one classical group remains negotiable" — not the exact
/// identity of the classical group. Asserting the specific name
/// breaks the moment FIPS is added to the build, which is what
/// issue #957 observed (misreported as a race — it is actually a
/// deterministic feature-combination mismatch).
#[test]
fn pq_provider_includes_mlkem_groups() {
    ensure_pq();

    let provider =
        rustls::crypto::CryptoProvider::get_default().expect("crypto provider should be installed");

    let group_names: Vec<_> = provider.kx_groups.iter().map(|g| (*g).name()).collect();

    assert!(
        group_names.contains(&rustls::NamedGroup::X25519MLKEM768),
        "PQ provider must include X25519MLKEM768, got: {group_names:?}"
    );
    // At least one classical group must remain for fallback to
    // non-PQ peers. Exact identity depends on whether FIPS is also
    // enabled: non-FIPS has X25519, FIPS has secp256r1/secp384r1.
    let has_classical_fallback = group_names.iter().any(|n| {
        matches!(
            n,
            rustls::NamedGroup::X25519
                | rustls::NamedGroup::secp256r1
                | rustls::NamedGroup::secp384r1
                | rustls::NamedGroup::secp521r1
        )
    });
    assert!(
        has_classical_fallback,
        "PQ provider must include at least one classical group (X25519, \
         secp256r1, secp384r1, or secp521r1) for fallback, got: \
         {group_names:?}"
    );
}

/// Full mTLS handshake using the PQ provider. Verifies that certificate
/// generation, TLS server setup, client connection, and bidirectional data
/// exchange all work correctly with the aws-lc-rs PQ backend.
#[tokio::test]
async fn pq_mtls_handshake() {
    ensure_pq();

    let ca = TestCa::new("PQ Test CA");
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);
    let client_cert = ca.issue_client_cert("pq-operator", &["pq-team"]);

    let tls_config = TlsConfig::from_pem(&server_cert.cert_pem, &server_cert.key_pem, &ca.cert_pem)
        .expect("tls config with PQ provider");

    let listener = TlsListener::bind("127.0.0.1:0", &tls_config)
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");

    let server_handle = tokio::spawn(async move {
        let session = listener.accept().await.expect("accept");
        let identity = session.identity().clone();
        let (mut reader, mut writer) = session.split();

        let mut buf = [0u8; 7];
        let _ = reader.read_exact(&mut buf).await.expect("read");
        assert_eq!(&buf, b"pq-data");
        writer.write_all(b"pq-resp").await.expect("write");

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
        .expect("tls connect with PQ provider");

    stream.write_all(b"pq-data").await.expect("client write");
    let mut buf = [0u8; 7];
    let _ = stream.read_exact(&mut buf).await.expect("client read");
    assert_eq!(&buf, b"pq-resp");

    let identity = server_handle.await.expect("server task");
    assert_eq!(&*identity.cn, "pq-operator");
    assert!(identity.is_member_of("pq-team"));
}

/// Verify the negotiated key exchange group is X25519MLKEM768 when both
/// client and server use the PQ provider.
#[tokio::test]
async fn pq_negotiated_kx_group_is_mlkem() {
    ensure_pq();

    let ca = TestCa::new("PQ KX CA");
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);
    let client_cert = ca.issue_client_cert("kx-check", &["team"]);

    let tls_config = TlsConfig::from_pem(&server_cert.cert_pem, &server_cert.key_pem, &ca.cert_pem)
        .expect("tls config");

    let listener = TlsListener::bind("127.0.0.1:0", &tls_config)
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");

    let server_handle = tokio::spawn(async move {
        let _session = listener.accept().await.expect("accept");
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    });

    let config = build_client_tls_config(&client_cert.cert_pem, &client_cert.key_pem, &ca.cert_pem);
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("tcp connect");
    let server_name = "localhost".try_into().expect("server name");
    let stream = connector
        .connect(server_name, tcp)
        .await
        .expect("tls connect");

    let (_, conn) = stream.get_ref();
    let kx_group = conn
        .negotiated_key_exchange_group()
        .expect("should have negotiated a key exchange group");

    assert_eq!(
        kx_group.name(),
        rustls::NamedGroup::X25519MLKEM768,
        "both sides support PQ — should negotiate X25519MLKEM768, got {:?}",
        kx_group.name()
    );

    server_handle.abort();
}

/// PQ provider works with CRL-enabled TLS config. Ensures the two
/// features compose correctly — CRL checking under the PQ backend.
#[tokio::test]
async fn pq_with_crl_rejects_revoked() {
    ensure_pq();

    let ca = TestCa::new("PQ CRL CA");
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);
    let revoked_client = ca.issue_client_cert("revoked-pq", &["team"]);

    let crl_pem = ca.generate_crl(&[&revoked_client.cert_pem]);

    let tls_config = TlsConfig::from_pem(&server_cert.cert_pem, &server_cert.key_pem, &ca.cert_pem)
        .expect("tls config")
        .with_crls(&crl_pem)
        .expect("load CRL");

    let listener = TlsListener::bind("127.0.0.1:0", &tls_config)
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");

    // Server must be accepting for the TLS handshake to proceed
    let server_handle = tokio::spawn(async move {
        tokio::time::timeout(std::time::Duration::from_secs(2), listener.accept()).await
    });

    // Revoked client tries to connect
    let revoked_config = build_client_tls_config(
        &revoked_client.cert_pem,
        &revoked_client.key_pem,
        &ca.cert_pem,
    );
    let connector = tokio_rustls::TlsConnector::from(Arc::new(revoked_config));
    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("tcp connect");
    let server_name: rustls::pki_types::ServerName<'_> =
        "localhost".try_into().expect("server name");
    let result = connector.connect(server_name, tcp).await;

    let revoked_failed = match result {
        Err(_) => true,
        Ok(mut stream) => {
            stream.write_all(b"x").await.is_err()
                || stream.flush().await.is_err()
                || matches!(
                    tokio::time::timeout(
                        std::time::Duration::from_millis(500),
                        stream.read(&mut [0u8; 1]),
                    )
                    .await,
                    Ok(Ok(0)) | Ok(Err(_)) | Err(_)
                )
        }
    };
    assert!(
        revoked_failed,
        "revoked client should not connect under PQ provider"
    );

    // Server should not have produced a valid session
    let server_result = server_handle.await.expect("server task");
    assert!(
        server_result.is_err(),
        "server should timeout — revoked client under PQ + CRL"
    );
}

/// When a client only supports classical key exchange (ring), the
/// PQ-enabled server must gracefully fall back to *some* classical
/// group that both sides support.
///
/// In non-FIPS builds the server's PQ provider exposes X25519 and
/// ring prefers it, so negotiation lands on X25519. In FIPS builds
/// the server's group list is restricted to FIPS-approved options
/// (no X25519), so both sides meet on `secp256r1` instead. Either
/// outcome is a correct graceful fallback; asserting a specific
/// group name is what regressed into a false failure under the
/// CI feature combo `proto,fips,post-quantum,ocsp,spiffe` (see
/// issue #957).
#[tokio::test]
async fn pq_classical_client_falls_back_to_x25519() {
    ensure_pq();

    let ca = TestCa::new("PQ Fallback CA");
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);
    let client_cert = ca.issue_client_cert("classical-client", &["team"]);

    // Server uses the PQ provider (installed by ensure_pq)
    let tls_config = TlsConfig::from_pem(&server_cert.cert_pem, &server_cert.key_pem, &ca.cert_pem)
        .expect("tls config");

    let listener = TlsListener::bind("127.0.0.1:0", &tls_config)
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");

    let server_handle = tokio::spawn(async move {
        let _session = listener.accept().await.expect("accept");
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    });

    // Build a client config using the ring provider (classical groups only)
    let certs = rustgate_test_utils::tls::parse_certs(&client_cert.cert_pem);
    let key = rustgate_test_utils::tls::parse_key(&client_cert.key_pem);
    let mut root_store = rustls::RootCertStore::empty();
    for cert in rustgate_test_utils::tls::parse_certs(&ca.cert_pem) {
        root_store.add(cert).expect("add CA");
    }

    let ring_config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .expect("tls13")
    .with_root_certificates(root_store)
    .with_client_auth_cert(certs, key)
    .expect("client auth");

    let connector = tokio_rustls::TlsConnector::from(Arc::new(ring_config));
    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("tcp connect");
    let server_name = "localhost".try_into().expect("server name");
    let stream = connector
        .connect(server_name, tcp)
        .await
        .expect("tls connect — fallback to classical must succeed");

    let (_, conn) = stream.get_ref();
    let kx_group = conn
        .negotiated_key_exchange_group()
        .expect("should have negotiated a key exchange group");

    // The fallback group must be classical (the client has no PQ
    // support), but we do not pin a specific name because FIPS mode
    // drops X25519 from the server's advertised list and forces the
    // pair onto a NIST curve instead. Any non-PQ group here is proof
    // the PQ server gracefully fell back.
    let negotiated = kx_group.name();
    let is_classical_fallback = matches!(
        negotiated,
        rustls::NamedGroup::X25519
            | rustls::NamedGroup::secp256r1
            | rustls::NamedGroup::secp384r1
            | rustls::NamedGroup::secp521r1
    );
    assert!(
        is_classical_fallback,
        "classical-only client should negotiate a classical (non-PQ) \
         group (X25519 or secp256r1/secp384r1/secp521r1), got {negotiated:?}"
    );

    server_handle.abort();
}

/// Verify that ML-KEM-1024 (Level 5) negotiates end-to-end when both
/// client and server include it as the preferred key exchange group.
#[tokio::test]
async fn pq_mlkem1024_negotiation() {
    ensure_pq();

    let ca = TestCa::new("PQ MLKEM1024 CA");
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);
    let client_cert = ca.issue_client_cert("mlkem1024-client", &["team"]);

    // Build server with a custom provider that prefers MLKEM1024.
    // The default PQ provider has X25519MLKEM768 first, so we must
    // override the group order for this test.
    let tls_config = TlsConfig::from_pem(&server_cert.cert_pem, &server_cert.key_pem, &ca.cert_pem)
        .expect("tls config");
    let verifier = tls_config.build_default_verifier().expect("verifier");

    let server_certs = rustgate_test_utils::tls::parse_certs(&server_cert.cert_pem);
    let server_key = rustgate_test_utils::tls::parse_key(&server_cert.key_pem);

    let mut server_provider = rustls::crypto::aws_lc_rs::default_provider();
    server_provider.kx_groups = vec![
        rustls::crypto::aws_lc_rs::kx_group::MLKEM1024,
        rustls::crypto::aws_lc_rs::kx_group::X25519,
    ];

    let mut server_config = rustls::ServerConfig::builder_with_provider(Arc::new(server_provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("tls13")
        .with_client_cert_verifier(verifier)
        .with_single_cert(server_certs, server_key)
        .expect("server cert");
    server_config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});

    let listener = TlsListener::bind_with_server_config("127.0.0.1:0", Arc::new(server_config), 10)
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");

    let server_handle = tokio::spawn(async move {
        let _session = listener.accept().await.expect("accept");
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    });

    // Build client with aws-lc-rs provider, MLKEM1024 as preferred group
    let certs = rustgate_test_utils::tls::parse_certs(&client_cert.cert_pem);
    let key = rustgate_test_utils::tls::parse_key(&client_cert.key_pem);
    let mut root_store = rustls::RootCertStore::empty();
    for cert in rustgate_test_utils::tls::parse_certs(&ca.cert_pem) {
        root_store.add(cert).expect("add CA");
    }

    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.kx_groups = vec![
        rustls::crypto::aws_lc_rs::kx_group::MLKEM1024,
        rustls::crypto::aws_lc_rs::kx_group::X25519,
    ];

    let mlkem_config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("tls13")
        .with_root_certificates(root_store)
        .with_client_auth_cert(certs, key)
        .expect("client auth");

    let connector = tokio_rustls::TlsConnector::from(Arc::new(mlkem_config));
    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("tcp connect");
    let server_name = "localhost".try_into().expect("server name");
    let stream = connector
        .connect(server_name, tcp)
        .await
        .expect("tls connect — MLKEM1024 negotiation must succeed");

    let (_, conn) = stream.get_ref();
    let kx_group = conn
        .negotiated_key_exchange_group()
        .expect("should have negotiated a key exchange group");

    assert_eq!(
        kx_group.name(),
        rustls::NamedGroup::MLKEM1024,
        "both sides prefer MLKEM1024 — should negotiate it, got {:?}",
        kx_group.name()
    );

    server_handle.abort();
}
