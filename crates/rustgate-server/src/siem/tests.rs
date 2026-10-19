// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! End-to-end tests: the forwarder against a local syslog-over-TLS
//! collector.

#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

use std::sync::atomic::Ordering;
use std::time::Duration;

use rustgate_test_utils::certs::{TestCa, TestCert};
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::AsyncReadExt as _;
use tokio::net::TcpListener; // playbook-drift-ok: test-only TLS collector fixture, not a production listener
use tokio_rustls::TlsAcceptor;
use tracing_subscriber::layer::SubscriberExt as _;

use super::*;

fn ensure_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

fn certs(pem: &str) -> Vec<CertificateDer<'static>> {
    CertificateDer::pem_slice_iter(pem.as_bytes())
        .map(|c| c.unwrap_or_else(|_| panic!("certificate PEM")))
        .collect()
}

fn key(pem: &str) -> PrivateKeyDer<'static> {
    PrivateKeyDer::from_pem_slice(pem.as_bytes()).unwrap_or_else(|_| panic!("key PEM"))
}

fn write(dir: &std::path::Path, name: &str, contents: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, contents).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    path
}

/// A TLS collector on 127.0.0.1. `client_ca` makes it require a client
/// certificate signed by that CA.
async fn collector(server: &TestCert, client_ca: Option<&TestCa>) -> (TcpListener, TlsAcceptor) {
    let builder = rustls::ServerConfig::builder();
    let config = match client_ca {
        Some(ca) => {
            let mut roots = rustls::RootCertStore::empty();
            for cert in certs(&ca.cert_pem) {
                roots.add(cert).unwrap();
            }
            let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
                .build()
                .unwrap();
            builder.with_client_cert_verifier(verifier)
        }
        None => builder.with_no_client_auth(),
    }
    .with_single_cert(certs(&server.cert_pem), key(&server.key_pem))
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    (listener, TlsAcceptor::from(Arc::new(config)))
}

/// Read one RFC 5425 frame and return its syslog message.
async fn read_frame<R: tokio::io::AsyncRead + Unpin>(stream: &mut R) -> Option<String> {
    let mut len = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        if stream.read_exact(&mut byte).await.is_err() {
            return None;
        }
        if byte[0] == b' ' {
            break;
        }
        len.push(byte[0]);
    }
    let len: usize = String::from_utf8(len).ok()?.parse().ok()?;
    let mut message = vec![0u8; len];
    let _ = stream.read_exact(&mut message).await.ok()?;
    String::from_utf8(message).ok()
}

fn settings(endpoint: String, ca: PathBuf, format: Format, queue_size: usize) -> SiemSettings {
    SiemSettings {
        endpoint,
        ca,
        client_auth: None,
        format,
        queue_size,
        include_classified: false,
    }
}

#[tokio::test]
async fn delivers_audit_events_to_the_collector_in_order() {
    ensure_provider();
    let ca = TestCa::new("SIEM Test CA");
    let server = ca.issue_server_cert("localhost", &["localhost"]);
    let dir = tempfile::tempdir().unwrap();
    let ca_path = write(dir.path(), "ca.pem", &ca.cert_pem);
    let (listener, acceptor) = collector(&server, None).await;
    let port = listener.local_addr().unwrap().port();

    let (layer, pending) = layer(settings(
        format!("localhost:{port}"),
        ca_path,
        Format::Cef,
        64,
    ));
    let _guard = tracing::subscriber::set_default(tracing_subscriber::registry().with(layer));
    let handle = start(pending).unwrap();

    let peer: std::net::SocketAddr = "203.0.113.7:44100".parse().unwrap();
    rustgate_core::audit::connection_rejected(peer, "connection limit reached");
    rustgate_core::audit::server_started("127.0.0.1:8089", "test");

    let (tcp, _) = listener.accept().await.unwrap();
    let mut tls = acceptor.accept(tcp).await.unwrap();
    let mut messages = Vec::new();
    while messages.len() < 3 {
        let message = tokio::time::timeout(Duration::from_secs(10), read_frame(&mut tls))
            .await
            .unwrap()
            .expect("frame");
        messages.push(message);
    }
    // Queued before the connection existed, so they arrive first, then the
    // forwarder's own connect event.
    assert!(
        messages[0].contains("|client.rejected|client.rejected|5|"),
        "{}",
        messages[0]
    );
    assert!(
        messages[0].contains(" src=203.0.113.7 spt=44100 "),
        "{}",
        messages[0]
    );
    assert!(messages[1].contains("|server.started|"), "{}", messages[1]);
    assert!(messages[2].contains("|siem.connected|"), "{}", messages[2]);
    assert!(
        messages
            .iter()
            .all(|m| m.starts_with('<') && m.contains(" rustgate "))
    );

    rustgate_core::tasks::stop_subsystem("siem", handle).await;
}

#[tokio::test]
async fn json_format_sends_one_object_per_message() {
    ensure_provider();
    let ca = TestCa::new("SIEM Test CA");
    let server = ca.issue_server_cert("localhost", &["localhost"]);
    let dir = tempfile::tempdir().unwrap();
    let ca_path = write(dir.path(), "ca.pem", &ca.cert_pem);
    let (listener, acceptor) = collector(&server, None).await;
    let port = listener.local_addr().unwrap().port();

    let (layer, pending) = layer(settings(
        format!("localhost:{port}"),
        ca_path,
        Format::Json,
        64,
    ));
    let _guard = tracing::subscriber::set_default(tracing_subscriber::registry().with(layer));
    let handle = start(pending).unwrap();
    rustgate_core::audit::server_started("127.0.0.1:8089", "test");

    let (tcp, _) = listener.accept().await.unwrap();
    let mut tls = acceptor.accept(tcp).await.unwrap();
    let message = tokio::time::timeout(Duration::from_secs(10), read_frame(&mut tls))
        .await
        .unwrap()
        .expect("frame");
    let json = message.split_once(" audit - ").expect("RFC 5424 header").1;
    let value: serde_json::Value = serde_json::from_str(json).unwrap();
    assert_eq!(value["event_type"], "server.started");
    assert_eq!(value["bind"], "127.0.0.1:8089");

    rustgate_core::tasks::stop_subsystem("siem", handle).await;
}

#[tokio::test]
async fn reconnects_after_the_collector_drops_the_connection() {
    ensure_provider();
    let ca = TestCa::new("SIEM Test CA");
    let server = ca.issue_server_cert("localhost", &["localhost"]);
    let dir = tempfile::tempdir().unwrap();
    let ca_path = write(dir.path(), "ca.pem", &ca.cert_pem);
    let (listener, acceptor) = collector(&server, None).await;
    let port = listener.local_addr().unwrap().port();

    let (layer, pending) = layer(settings(
        format!("localhost:{port}"),
        ca_path,
        Format::Cef,
        64,
    ));
    let _guard = tracing::subscriber::set_default(tracing_subscriber::registry().with(layer));
    let handle = start(pending).unwrap();

    // First connection: read the connect event, then hang up.
    let (tcp, _) = listener.accept().await.unwrap();
    let mut tls = acceptor.accept(tcp).await.unwrap();
    let first = read_frame(&mut tls).await.expect("frame");
    assert!(first.contains("|siem.connected|"), "{first}");
    drop(tls);

    // Keep emitting until the forwarder notices and reconnects; then the
    // events written after the reconnect must arrive.
    let accept = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        acceptor.accept(tcp).await.unwrap()
    });
    let mut second = None;
    for _ in 0..100 {
        rustgate_core::audit::server_started("127.0.0.1:8089", "after-drop");
        tokio::time::sleep(Duration::from_millis(50)).await;
        if accept.is_finished() {
            second = Some(accept.await.unwrap());
            break;
        }
    }
    let mut tls = second.expect("forwarder reconnected");
    rustgate_core::audit::server_started("127.0.0.1:8089", "after-reconnect");
    let mut seen = Vec::new();
    for _ in 0..200 {
        let message = tokio::time::timeout(Duration::from_secs(10), read_frame(&mut tls))
            .await
            .unwrap()
            .expect("frame");
        let done = message.contains("after-reconnect");
        seen.push(message);
        if done {
            break;
        }
    }
    assert!(seen.iter().any(|m| m.contains("|siem.disconnected|")));
    assert!(seen.iter().any(|m| m.contains("|siem.connected|")));
    assert!(seen.last().is_some_and(|m| m.contains("after-reconnect")));

    rustgate_core::tasks::stop_subsystem("siem", handle).await;
}

#[tokio::test]
async fn an_unreachable_collector_never_blocks_and_drops_are_counted() {
    ensure_provider();
    let ca = TestCa::new("SIEM Test CA");
    let dir = tempfile::tempdir().unwrap();
    let ca_path = write(dir.path(), "ca.pem", &ca.cert_pem);
    // Reserve a port and close it so nothing is listening there.
    let port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    let (layer, pending) = layer(settings(
        format!("localhost:{port}"),
        ca_path,
        Format::Cef,
        10,
    ));
    let stats = Arc::clone(&pending.stats);
    let _guard = tracing::subscriber::set_default(tracing_subscriber::registry().with(layer));
    let handle = start(pending).unwrap();

    let started = std::time::Instant::now();
    for _ in 0..500 {
        rustgate_core::audit::server_started("127.0.0.1:8089", "test");
    }
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "emitting audit events blocked"
    );
    assert_eq!(stats.dropped_queue_full.load(Ordering::Relaxed), 490);

    rustgate_core::tasks::stop_subsystem("siem", handle).await;
    assert_eq!(stats.sent.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn refuses_a_collector_whose_certificate_is_not_from_the_configured_ca() {
    ensure_provider();
    let trusted = TestCa::new("SIEM Test CA");
    let other = TestCa::new("Other CA");
    let server = other.issue_server_cert("localhost", &["localhost"]);
    let dir = tempfile::tempdir().unwrap();
    let ca_path = write(dir.path(), "ca.pem", &trusted.cert_pem);
    let (listener, acceptor) = collector(&server, None).await;
    let port = listener.local_addr().unwrap().port();

    let (layer, pending) = layer(settings(
        format!("localhost:{port}"),
        ca_path,
        Format::Cef,
        64,
    ));
    let stats = Arc::clone(&pending.stats);
    let _guard = tracing::subscriber::set_default(tracing_subscriber::registry().with(layer));
    let handle = start(pending).unwrap();
    rustgate_core::audit::server_started("127.0.0.1:8089", "test");

    // The forwarder aborts the handshake, so the collector never gets a
    // usable stream and nothing is sent.
    let (tcp, _) = listener.accept().await.unwrap();
    assert!(acceptor.accept(tcp).await.is_err());
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(stats.sent.load(Ordering::Relaxed), 0);

    rustgate_core::tasks::stop_subsystem("siem", handle).await;
}

#[tokio::test]
async fn presents_the_client_certificate_when_configured() {
    ensure_provider();
    let ca = TestCa::new("SIEM Test CA");
    let server = ca.issue_server_cert("localhost", &["localhost"]);
    let client = ca.issue_client_cert("rustgate-siem", &[]);
    let dir = tempfile::tempdir().unwrap();
    let ca_path = write(dir.path(), "ca.pem", &ca.cert_pem);
    let cert_path = write(dir.path(), "client.pem", &client.cert_pem);
    let key_path = write(dir.path(), "client.key", &client.key_pem);
    let (listener, acceptor) = collector(&server, Some(&ca)).await;
    let port = listener.local_addr().unwrap().port();

    let mut cfg = settings(format!("localhost:{port}"), ca_path, Format::Cef, 64);
    cfg.client_auth = Some((cert_path, key_path));
    let (layer, pending) = layer(cfg);
    let _guard = tracing::subscriber::set_default(tracing_subscriber::registry().with(layer));
    let handle = start(pending).unwrap();

    let (tcp, _) = listener.accept().await.unwrap();
    let mut tls = acceptor
        .accept(tcp)
        .await
        .expect("client certificate accepted");
    let message = tokio::time::timeout(Duration::from_secs(10), read_frame(&mut tls))
        .await
        .unwrap()
        .expect("frame");
    assert!(message.contains("|siem.connected|"), "{message}");

    rustgate_core::tasks::stop_subsystem("siem", handle).await;
}

#[test]
fn start_rejects_an_endpoint_without_a_valid_host() {
    ensure_provider();
    let ca = TestCa::new("SIEM Test CA");
    let dir = tempfile::tempdir().unwrap();
    let ca_path = write(dir.path(), "ca.pem", &ca.cert_pem);
    let (_layer, pending) = layer(settings(":6514".to_owned(), ca_path, Format::Cef, 4));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let _enter = runtime.enter();
    assert!(start(pending).is_err());
}

#[tokio::test]
async fn a_collector_that_drops_every_connection_is_not_redialled_in_a_loop() {
    ensure_provider();
    let ca = TestCa::new("SIEM Test CA");
    let server = ca.issue_server_cert("localhost", &["localhost"]);
    let dir = tempfile::tempdir().unwrap();
    let ca_path = write(dir.path(), "ca.pem", &ca.cert_pem);
    let (listener, acceptor) = collector(&server, None).await;
    let port = listener.local_addr().unwrap().port();

    let (layer, pending) = layer(settings(
        format!("localhost:{port}"),
        ca_path,
        Format::Cef,
        64,
    ));
    let _guard = tracing::subscriber::set_default(tracing_subscriber::registry().with(layer));
    let handle = start(pending).unwrap();

    // Complete each handshake, then hang up at once.
    let accepts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = Arc::clone(&accepts);
    let collector = tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let _ = counter.fetch_add(1, Ordering::Relaxed);
            drop(acceptor.accept(tcp).await);
        }
    });
    tokio::time::sleep(Duration::from_millis(2500)).await;
    // Backoff is 1 s then 2 s, so at most three connections in 2.5 s; a
    // missing backoff redials at network speed.
    let n = accepts.load(Ordering::Relaxed);
    assert!((1..=3).contains(&n), "{n} connections in 2.5 s");

    collector.abort();
    rustgate_core::tasks::stop_subsystem("siem", handle).await;
}

/// Send one `classification.denied` through the forwarder and return the
/// message the collector receives for it.
async fn forwarded_classification_denied(include_classified: bool) -> String {
    ensure_provider();
    let ca = TestCa::new("SIEM Test CA");
    let server = ca.issue_server_cert("localhost", &["localhost"]);
    let dir = tempfile::tempdir().unwrap();
    let ca_path = write(dir.path(), "ca.pem", &ca.cert_pem);
    let (listener, acceptor) = collector(&server, None).await;
    let port = listener.local_addr().unwrap().port();

    let mut cfg = settings(format!("localhost:{port}"), ca_path, Format::Json, 64);
    cfg.include_classified = include_classified;
    let (layer, pending) = layer(cfg);
    let _guard = tracing::subscriber::set_default(tracing_subscriber::registry().with(layer));
    let handle = start(pending).unwrap();
    rustgate_core::audit::classification_denied(
        "alice",
        "bob",
        "msg-42",
        "SECRET//SI//NOFORN",
        "blue",
    );

    let (tcp, _) = listener.accept().await.unwrap();
    let mut tls = acceptor.accept(tcp).await.unwrap();
    let message = loop {
        let message = tokio::time::timeout(Duration::from_secs(10), read_frame(&mut tls))
            .await
            .unwrap()
            .expect("frame");
        if message.contains("classification.denied") {
            break message;
        }
    };
    rustgate_core::tasks::stop_subsystem("siem", handle).await;
    message
}

#[tokio::test]
async fn classification_denials_are_pseudonymized_by_default() {
    let message = forwarded_classification_denied(false).await;
    let json = message.split_once(" audit - ").expect("RFC 5424 header").1;
    let value: serde_json::Value = serde_json::from_str(json).unwrap();
    assert!(
        value["source"].as_str().unwrap().starts_with("p:"),
        "{message}"
    );
    assert!(
        value["dest"].as_str().unwrap().starts_with("p:"),
        "{message}"
    );
    assert_eq!(value["marking"], "SECRET");
    assert!(value.get("uid").is_none());
    assert_eq!(value["group"], "blue");
    for raw in ["alice", "bob", "msg-42", "NOFORN"] {
        assert!(!message.contains(raw), "{raw} leaked: {message}");
    }
}

#[tokio::test]
async fn include_classified_forwards_classification_denials_unchanged() {
    let message = forwarded_classification_denied(true).await;
    for raw in ["alice", "bob", "msg-42", "SECRET//SI//NOFORN"] {
        assert!(message.contains(raw), "{raw} missing: {message}");
    }
}
