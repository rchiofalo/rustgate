//! Integration tests for TLS listener with mTLS authentication.

use rustgate_test_utils::certs::TestCa;
use rustgate_transport::{extract_identity, TlsConfig, TlsListener};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::RootCertStore;
use std::io::BufReader;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Test that identity extraction works correctly on a generated certificate.
#[test]
fn test_extract_identity_directly() {
    let ca = TestCa::new("Test CA");
    let client_cert = ca.issue_client_cert("alice", &["engineers", "admins"]);

    let certs = parse_certs(&client_cert.cert_pem);
    let cert_der = certs.first().expect("no cert found");

    let identity = extract_identity(cert_der).expect("failed to extract identity");

    assert_eq!(identity.cn, "alice", "CN should be alice");
    assert_eq!(
        identity.groups.len(),
        2,
        "should have 2 groups, got: {:?}",
        identity.groups
    );
    assert!(
        identity.is_member_of("engineers"),
        "should be member of engineers, groups: {:?}",
        identity.groups
    );
    assert!(
        identity.is_member_of("admins"),
        "should be member of admins, groups: {:?}",
        identity.groups
    );
    assert!(!identity.fingerprint.is_empty(), "fingerprint should not be empty");
}

fn parse_certs(pem: &str) -> Vec<CertificateDer<'static>> {
    let mut reader = BufReader::new(pem.as_bytes());
    rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .expect("failed to parse certs")
}

fn parse_key(pem: &str) -> PrivateKeyDer<'static> {
    let mut reader = BufReader::new(pem.as_bytes());
    rustls_pemfile::private_key(&mut reader)
        .expect("failed to parse key")
        .expect("no key found")
}

fn build_client_config(
    client_cert_pem: &str,
    client_key_pem: &str,
    server_ca_pem: &str,
) -> rustls::ClientConfig {
    let client_certs = parse_certs(client_cert_pem);
    let client_key = parse_key(client_key_pem);

    let mut root_store = RootCertStore::empty();
    for cert in parse_certs(server_ca_pem) {
        root_store.add(cert).expect("failed to add CA cert");
    }

    rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(client_certs, client_key)
        .expect("invalid client cert")
}

#[tokio::test]
async fn test_mtls_identity_extraction() {
    // Create CA and issue certs
    let ca = TestCa::new("Test CA");
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);
    let client_cert = ca.issue_client_cert("alice", &["engineers", "admins"]);

    // Configure and bind TLS listener
    let tls_config = TlsConfig::from_pem(&server_cert.cert_pem, &server_cert.key_pem, &ca.cert_pem)
        .expect("failed to create TLS config");

    let listener = TlsListener::bind("127.0.0.1:0", &tls_config)
        .await
        .expect("failed to bind");

    let addr = listener.local_addr().expect("failed to get local addr");

    // Spawn server task
    let server_handle = tokio::spawn(async move {
        let session = listener
            .accept()
            .await
            .expect("listener closed")
            .expect("accept failed");

        let identity = session.identity().clone();

        // Test bidirectional I/O
        let (mut reader, mut writer) = session.split();
        let mut buf = [0u8; 5];
        let _ = reader.read_exact(&mut buf).await.expect("read failed");
        assert_eq!(&buf, b"hello");

        writer.write_all(b"world").await.expect("write failed");

        identity
    });

    // Connect as client
    let client_config = build_client_config(&client_cert.cert_pem, &client_cert.key_pem, &ca.cert_pem);

    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let tcp_stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("TCP connect failed");

    let server_name = "localhost".try_into().expect("invalid server name");
    let mut tls_stream = connector
        .connect(server_name, tcp_stream)
        .await
        .expect("TLS connect failed");

    // Send and receive data
    tls_stream
        .write_all(b"hello")
        .await
        .expect("client write failed");

    let mut buf = [0u8; 5];
    let _ = tls_stream
        .read_exact(&mut buf)
        .await
        .expect("client read failed");
    assert_eq!(&buf, b"world");

    // Verify identity extracted by server
    let identity = server_handle.await.expect("server task panicked");
    assert_eq!(identity.cn, "alice");
    assert!(identity.is_member_of("engineers"));
    assert!(identity.is_member_of("admins"));
    assert!(!identity.is_member_of("other"));
    assert!(!identity.fingerprint.is_empty());
}

#[tokio::test]
async fn test_mtls_rejects_untrusted_client() {
    // Create two separate CAs
    let server_ca = TestCa::new("Server CA");
    let rogue_ca = TestCa::new("Rogue CA");

    // Server uses server_ca, client has cert from rogue_ca
    let server_cert = server_ca.issue_server_cert("localhost", &["localhost"]);
    let rogue_client_cert = rogue_ca.issue_client_cert("mallory", &["hackers"]);

    // Configure listener to trust only server_ca (for client verification)
    let tls_config = TlsConfig::from_pem(
        &server_cert.cert_pem,
        &server_cert.key_pem,
        &server_ca.cert_pem, // Server only trusts certs signed by server_ca
    )
    .expect("failed to create TLS config");

    let listener = TlsListener::bind("127.0.0.1:0", &tls_config)
        .await
        .expect("failed to bind");

    let addr = listener.local_addr().expect("failed to get local addr");

    // Spawn server that accepts (should not get a successful connection)
    let server_handle = tokio::spawn(async move {
        // Use a timeout to prevent hanging
        tokio::time::timeout(std::time::Duration::from_secs(2), listener.accept()).await
    });

    // Try to connect with rogue client cert
    // Client trusts server_ca for server verification
    let client_config = build_client_config(
        &rogue_client_cert.cert_pem,
        &rogue_client_cert.key_pem,
        &server_ca.cert_pem, // Client trusts server's CA
    );

    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let tcp_stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("TCP connect failed");

    let server_name = "localhost".try_into().expect("invalid server name");
    let connect_result = connector.connect(server_name, tcp_stream).await;

    // With TLS 1.3, handshake might "succeed" from client's perspective,
    // but the connection should be unusable. Either handshake fails OR
    // subsequent I/O should fail.
    let connection_failed = match connect_result {
        Err(_) => true, // Handshake failed immediately
        Ok(mut stream) => {
            // Try to use the connection - should fail
            // Write some data
            if stream.write_all(b"test").await.is_err() {
                true
            } else if stream.flush().await.is_err() {
                true
            } else {
                // Try to read - if server rejected us, read should fail or timeout
                let mut buf = [0u8; 1];
                let read_result = tokio::time::timeout(
                    std::time::Duration::from_millis(500),
                    stream.read(&mut buf),
                )
                .await;

                // Connection should be rejected: either timeout (server won't respond)
                // or error (connection reset)
                match read_result {
                    Ok(Ok(0)) => true,     // Connection closed
                    Ok(Err(_)) => true,    // Read error
                    Err(_) => true,        // Timeout (server not responding)
                    Ok(Ok(_)) => false,    // Unexpectedly got data
                }
            }
        }
    };

    assert!(
        connection_failed,
        "expected connection to fail due to untrusted client cert"
    );

    // Server should have timed out waiting for more connections after the failed handshake
    let server_result = server_handle.await.expect("server task panicked");
    // Server should have timed out since the handshake failed and no more connections came
    assert!(
        server_result.is_err(),
        "server should timeout waiting for next connection"
    );
}
