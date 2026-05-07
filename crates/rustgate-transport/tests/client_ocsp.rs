// Copyright © 2026 Roberto Chiofalo.

//! Integration test for the [`ClientOcspVerifier`] wrapper.
//!
//! Spins up a real TLS listener whose client cert verifier is wrapped
//! with `ClientOcspVerifier` and a fake (in-memory) OCSP responder.
//! Verifies cache miss → background fetch → cache hit, and that a
//! cached `Revoked` status causes the next handshake to be rejected.

#![allow(clippy::panic, clippy::unwrap_used)]
#![cfg(feature = "ocsp")]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use rustgate_test_utils::certs::TestCa;
use rustgate_test_utils::tls::build_client_tls_config;
use rustgate_tls::{
    ClientOcspVerifier, DEFAULT_MAX_HANDSHAKES, FetchFuture, OcspFetcher, TlsConfig, TlsListener,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// In-memory mock OCSP responder. Returns a configurable status (good
/// or revoked) and counts how many requests it has served — the moral
/// equivalent of an HTTP responder for the purposes of this test
/// without having to encode a real OCSP DER blob.
struct MockOcspResponder {
    revoked: AtomicBool,
    requests: AtomicUsize,
}

impl OcspFetcher for MockOcspResponder {
    fn fetch<'a>(&'a self, _leaf: &'a [u8], _issuer: &'a [u8]) -> FetchFuture<'a> {
        let _ = self.requests.fetch_add(1, Ordering::SeqCst);
        let good = !self.revoked.load(Ordering::SeqCst);
        Box::pin(async move { Ok(good) })
    }
}

async fn client_connect(
    addr: std::net::SocketAddr,
    config: &rustls::ClientConfig,
) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config.clone()));
    let tcp = tokio::net::TcpStream::connect(addr).await.expect("tcp");
    let server_name = "localhost".try_into().expect("server name");
    connector.connect(server_name, tcp).await.expect("tls")
}

#[tokio::test]
async fn miss_then_hit_then_revoked() {
    let ca = TestCa::new("client-ocsp-it");
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);
    let client_cert = ca.issue_client_cert("ocsp-client", &[]);

    let tls_config = TlsConfig::from_pem(&server_cert.cert_pem, &server_cert.key_pem, &ca.cert_pem)
        .expect("tls config");

    // ── Listener 1: mock responder reports Good ─────────────────────
    let inner_verifier = tls_config.build_default_verifier().expect("inner verifier");
    let mock = Arc::new(MockOcspResponder {
        revoked: AtomicBool::new(false),
        requests: AtomicUsize::new(0),
    });
    let hits = Arc::new(AtomicUsize::new(0));
    let misses = Arc::new(AtomicUsize::new(0));
    let h = hits.clone();
    let m = misses.clone();
    let verifier = ClientOcspVerifier::new(
        inner_verifier,
        mock.clone(),
        Some(Arc::new(move || {
            let _ = h.fetch_add(1, Ordering::SeqCst);
        })),
        Some(Arc::new(move || {
            let _ = m.fetch_add(1, Ordering::SeqCst);
        })),
    );
    let server_config = tls_config
        .build_server_config_with_verifier(verifier.clone())
        .expect("server config");
    let listener = TlsListener::bind_with_server_config(
        "127.0.0.1:0",
        Arc::new(server_config),
        DEFAULT_MAX_HANDSHAKES,
    )
    .await
    .expect("bind");
    let addr = listener.local_addr().expect("addr");

    // First handshake — cache miss.
    let server_task = tokio::spawn(async move {
        let s1 = listener.accept().await.expect("accept 1");
        let (mut r, mut w) = s1.split();
        let mut buf = [0u8; 5];
        let _ = r.read_exact(&mut buf).await;
        let _ = w.write_all(b"world").await;
        // second handshake on the same listener
        let s2 = listener.accept().await.expect("accept 2");
        let (mut r2, mut w2) = s2.split();
        let _ = r2.read_exact(&mut buf).await;
        let _ = w2.write_all(b"world").await;
    });

    let cfg = build_client_tls_config(&client_cert.cert_pem, &client_cert.key_pem, &ca.cert_pem);
    let mut s = client_connect(addr, &cfg).await;
    s.write_all(b"hello").await.expect("write");
    let mut buf = [0u8; 5];
    let _ = s.read_exact(&mut buf).await.expect("read");
    drop(s);

    assert_eq!(misses.load(Ordering::SeqCst), 1, "expected first miss");
    assert_eq!(hits.load(Ordering::SeqCst), 0, "no hits before fetch");

    // Wait for background fetcher.
    for _ in 0..50 {
        if verifier.cache_len() > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        mock.requests.load(Ordering::SeqCst) >= 1,
        "mock OCSP responder should have received a request"
    );
    assert_eq!(verifier.cache_len(), 1);

    // Second handshake — cache hit.
    let mut s2 = client_connect(addr, &cfg).await;
    s2.write_all(b"hello").await.expect("write 2");
    let _ = s2.read_exact(&mut buf).await.expect("read 2");
    drop(s2);
    server_task.await.expect("server task");
    assert_eq!(hits.load(Ordering::SeqCst), 1, "expected one hit");

    // ── Listener 2: mock responder reports Revoked ───────────────────
    let inner2 = tls_config.build_default_verifier().expect("inner v2");
    let mock_revoked = Arc::new(MockOcspResponder {
        revoked: AtomicBool::new(true),
        requests: AtomicUsize::new(0),
    });
    let verifier2 = ClientOcspVerifier::new(inner2, mock_revoked, None, None);
    let server_config2 = tls_config
        .build_server_config_with_verifier(verifier2.clone())
        .expect("server config 2");
    let listener2 = TlsListener::bind_with_server_config(
        "127.0.0.1:0",
        Arc::new(server_config2),
        DEFAULT_MAX_HANDSHAKES,
    )
    .await
    .expect("bind 2");
    let addr2 = listener2.local_addr().expect("addr 2");

    let server_task2 = tokio::spawn(async move {
        // First handshake should succeed (fail-open on miss); the
        // second one will fail before producing a session — but the
        // listener loop in `accept()` keeps trying, so we time out.
        let s = listener2.accept().await.expect("accept 1");
        let (mut r, mut w) = s.split();
        let mut buf = [0u8; 5];
        let _ = r.read_exact(&mut buf).await;
        let _ = w.write_all(b"world").await;
        // The second client handshake will fail; the listener loop
        // will go back to wait for the next TCP connection. Cap the
        // wait so the test does not hang.
        let _ = tokio::time::timeout(Duration::from_secs(2), listener2.accept()).await;
    });

    let mut s3 = client_connect(addr2, &cfg).await;
    s3.write_all(b"hello").await.expect("write 3");
    let _ = s3.read_exact(&mut buf).await.expect("read 3");
    drop(s3);
    for _ in 0..50 {
        if verifier2.cache_len() > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(verifier2.cache_len(), 1, "cache should have revoked entry");

    // Second handshake should be rejected.
    let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg.clone()));
    let tcp = tokio::net::TcpStream::connect(addr2).await.expect("tcp 4");
    let server_name = "localhost".try_into().expect("server name");
    let result = connector.connect(server_name, tcp).await;
    let rejected = match result {
        Err(_) => true,
        Ok(mut stream) => {
            // The server may accept the TCP/TLS handshake bytes and only
            // surface the verifier rejection on a subsequent read or
            // write. Try a full round-trip and treat any failure as
            // rejection.
            if stream.write_all(b"hello").await.is_err() || stream.flush().await.is_err() {
                true
            } else {
                let mut buf = [0u8; 5];
                stream.read_exact(&mut buf).await.is_err()
            }
        }
    };
    assert!(rejected, "handshake should fail when cached as Revoked");

    let _ = server_task2.await;
}
