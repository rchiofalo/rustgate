// Copyright © 2026 Roberto Chiofalo.

#![allow(unused_results)]
#![allow(clippy::panic, clippy::unwrap_used)]
//! End-to-end routing tests: mTLS clients through a real server stack,
//! plus direct router tests for group/direct delivery.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::SystemTime;

use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use rustgate_core::identity::Identity;
use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};
use rustgate_core::protocol::HeaderSize;
use rustgate_test_utils::certs::TestCa;
use rustgate_test_utils::tls::build_client_tls_config;
use rustgate_transport::{
    AuthenticatedSession, LengthPrefixedCodec, Router, SessionHandle, TlsConfig, TlsListener,
};
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tokio_util::codec::{FramedRead, FramedWrite};

fn make_identity(cn: &str, groups: &[&str]) -> Identity {
    Identity::new(
        cn.to_string(),
        format!("fake:{cn}"),
        groups
            .iter()
            .map(|g| g.to_string())
            .collect::<BTreeSet<_>>(),
    )
    .expect("valid identity")
}

fn build_message(source: &Identity, payload: &[u8], dest: Destination) -> RoutableMessage {
    RoutableMessage {
        source: source.clone(),
        destination: dest,
        payload: Bytes::copy_from_slice(payload),
        metadata: Metadata {
            received_at: SystemTime::now(),
            source_protocol: "tcp".into(),
            message_type: MessageType::Other("raw".into()),
            ttl: None,
        },
    }
}

/// Spawn a server-side session handler (mirrors main.rs logic).
fn spawn_session(session: AuthenticatedSession, router: Arc<Router>) {
    drop(tokio::spawn(async move {
        let identity = session.identity_arc();
        let cn = identity.cn.clone();

        let (ptx, priority_rx) = mpsc::channel::<rustgate_transport::RoutedMessage>(16);
        let (ntx, normal_rx) = mpsc::channel::<rustgate_transport::RoutedMessage>(64);
        let handle = SessionHandle::new(Arc::clone(&identity), ptx, ntx);
        let session_id = handle.id;
        let _ = router.register(handle).await;

        let (reader, writer) = session.split();

        tokio::select! {
            r = server_read(reader, &identity, &router) => {
                if let Err(e) = r { eprintln!("{cn} read: {e}"); }
            }
            r = server_write(writer, priority_rx, normal_rx) => {
                if let Err(e) = r { eprintln!("{cn} write: {e}"); }
            }
        }

        router.unregister(&cn, session_id).await;
    }));
}

async fn server_read(
    reader: rustgate_transport::SessionReader,
    identity: &Identity,
    router: &Router,
) -> std::io::Result<()> {
    let mut framed = FramedRead::new(reader, LengthPrefixedCodec::new(HeaderSize::Four));
    while let Some(result) = framed.next().await {
        let frame = result?;
        router
            .route(build_message(identity, &frame, Destination::Broadcast))
            .await;
    }
    Ok(())
}

async fn server_write(
    writer: rustgate_transport::SessionWriter,
    mut priority_rx: mpsc::Receiver<rustgate_transport::RoutedMessage>,
    mut normal_rx: mpsc::Receiver<rustgate_transport::RoutedMessage>,
) -> std::io::Result<()> {
    let mut framed = FramedWrite::new(writer, LengthPrefixedCodec::new(HeaderSize::Four));
    loop {
        let msg = tokio::select! {
            biased;
            msg = priority_rx.recv() => msg,
            msg = normal_rx.recv() => msg,
        };
        let Some(msg) = msg else { break };
        framed
            .send(tokio_util::bytes::BytesMut::from(msg.payload.as_ref()))
            .await?;
    }
    Ok(())
}

type ClientTx = futures::stream::SplitSink<
    tokio_util::codec::Framed<
        tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
        LengthPrefixedCodec,
    >,
    tokio_util::bytes::BytesMut,
>;
type ClientRx = futures::stream::SplitStream<
    tokio_util::codec::Framed<
        tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
        LengthPrefixedCodec,
    >,
>;

async fn connect_client(
    addr: std::net::SocketAddr,
    cert_pem: &str,
    key_pem: &str,
    ca_pem: &str,
) -> (ClientTx, ClientRx) {
    let config = build_client_tls_config(cert_pem, key_pem, ca_pem);
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("tcp connect");
    let server_name = "localhost".try_into().expect("server name");
    let tls = connector
        .connect(server_name, tcp)
        .await
        .expect("tls connect");
    let framed = tokio_util::codec::Framed::new(tls, LengthPrefixedCodec::new(HeaderSize::Four));
    framed.split()
}

async fn connect_raw(
    addr: std::net::SocketAddr,
    cert_pem: &str,
    key_pem: &str,
    ca_pem: &str,
) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
    let config = build_client_tls_config(cert_pem, key_pem, ca_pem);
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("tcp connect");
    let server_name = "localhost".try_into().expect("server name");
    connector
        .connect(server_name, tcp)
        .await
        .expect("tls connect")
}

/// Receive one frame with a timeout. Panics with `label` on failure.
async fn recv(rx: &mut ClientRx, label: &str) -> Vec<u8> {
    tokio::time::timeout(std::time::Duration::from_secs(5), rx.next())
        .await
        .unwrap_or_else(|_| panic!("{label}: timeout"))
        .unwrap_or_else(|| panic!("{label}: stream ended"))
        .unwrap_or_else(|e| panic!("{label}: decode error: {e}"))
        .to_vec()
}

/// Assert no data frame arrives — timeout or stream-end are both acceptable.
async fn assert_no_message(rx: &mut ClientRx, label: &str) {
    match tokio::time::timeout(std::time::Duration::from_secs(1), rx.next()).await {
        Err(_) => {}           // Timeout — nothing arrived
        Ok(None) => {}         // Stream closed
        Ok(Some(Err(_))) => {} // Read error (connection reset)
        Ok(Some(Ok(frame))) => {
            panic!("{label}: unexpected data: {:?}", &frame[..]);
        }
    }
}

/// Stand up a server with a listener and router, accept `n` clients.
struct TestServer {
    addr: std::net::SocketAddr,
    router: Arc<Router>,
    ca: TestCa,
}

impl TestServer {
    async fn new(accept_count: usize) -> (Self, tokio::task::JoinHandle<()>) {
        let ca = TestCa::new("Test CA");
        let server_cert = ca.issue_server_cert("localhost", &["localhost"]);

        let tls_config =
            TlsConfig::from_pem(&server_cert.cert_pem, &server_cert.key_pem, &ca.cert_pem)
                .expect("tls config");
        let listener = TlsListener::bind("127.0.0.1:0", &tls_config)
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let router = Arc::new(Router::new());

        let server_router = Arc::clone(&router);
        let handle = tokio::spawn(async move {
            for _ in 0..accept_count {
                let session = listener.accept().await.expect("accept");
                spawn_session(session, Arc::clone(&server_router));
            }
        });

        let server = Self { addr, router, ca };
        (server, handle)
    }

    fn issue_client(&self, cn: &str, groups: &[&str]) -> rustgate_test_utils::certs::TestCert {
        self.ca.issue_client_cert(cn, groups)
    }

    async fn connect(&self, cert: &rustgate_test_utils::certs::TestCert) -> (ClientTx, ClientRx) {
        connect_client(self.addr, &cert.cert_pem, &cert.key_pem, &self.ca.cert_pem).await
    }

    async fn wait_ready(&self, handle: tokio::task::JoinHandle<()>) {
        handle.await.expect("server accept loop");
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

// ── e2e: full stack through TLS ──────────────────────────────────────────

#[tokio::test]
async fn broadcast_between_two_clients() {
    let (server, handle) = TestServer::new(2).await;
    let alice = server.issue_client("alice", &["engineers"]);
    let bob = server.issue_client("bob", &["engineers"]);

    let (mut alice_tx, mut alice_rx) = server.connect(&alice).await;
    let (mut bob_tx, mut bob_rx) = server.connect(&bob).await;
    server.wait_ready(handle).await;

    assert_eq!(server.router.session_count().await, 2);

    alice_tx
        .send(tokio_util::bytes::BytesMut::from("hello bob"))
        .await
        .expect("send");
    assert_eq!(recv(&mut bob_rx, "bob").await, b"hello bob");

    bob_tx
        .send(tokio_util::bytes::BytesMut::from("hey alice"))
        .await
        .expect("send");
    assert_eq!(recv(&mut alice_rx, "alice").await, b"hey alice");
}

/// Sender must not receive their own broadcast back.
#[tokio::test]
async fn no_self_echo() {
    let (server, handle) = TestServer::new(1).await;
    let alice = server.issue_client("alice", &["team"]);

    let (mut alice_tx, mut alice_rx) = server.connect(&alice).await;
    server.wait_ready(handle).await;

    alice_tx
        .send(tokio_util::bytes::BytesMut::from("echo?"))
        .await
        .expect("send");
    assert_no_message(&mut alice_rx, "alice self-echo").await;
}

/// When a client disconnects, the router removes it and remaining clients
/// keep working.
#[tokio::test]
async fn disconnect_cleanup() {
    let (server, handle) = TestServer::new(3).await;
    let alice = server.issue_client("alice", &["ops"]);
    let bob = server.issue_client("bob", &["ops"]);
    let charlie = server.issue_client("charlie", &["ops"]);

    let (alice_tx, alice_rx) = server.connect(&alice).await;
    let (mut bob_tx, _bob_rx) = server.connect(&bob).await;
    let (_charlie_tx, mut charlie_rx) = server.connect(&charlie).await;
    server.wait_ready(handle).await;

    assert_eq!(server.router.session_count().await, 3);

    drop(alice_tx);
    drop(alice_rx);
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    assert_eq!(server.router.session_count().await, 2);

    bob_tx
        .send(tokio_util::bytes::BytesMut::from("still here"))
        .await
        .expect("send");
    assert_eq!(
        recv(&mut charlie_rx, "charlie after disconnect").await,
        b"still here"
    );
}

/// Same CN reconnecting replaces the old session. The stale session's
/// eventual unregister must not evict the replacement.
#[tokio::test]
async fn same_cn_reconnect_replaces_session() {
    let ca = TestCa::new("Test CA");
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);
    let alice_cert = ca.issue_client_cert("alice", &["ops"]);
    let bob_cert = ca.issue_client_cert("bob", &["ops"]);

    let tls_config = TlsConfig::from_pem(&server_cert.cert_pem, &server_cert.key_pem, &ca.cert_pem)
        .expect("tls config");
    let listener = TlsListener::bind("127.0.0.1:0", &tls_config)
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let router = Arc::new(Router::new());

    // Accept one at a time so registration order is deterministic
    let r = Arc::clone(&router);
    let accept_handle = tokio::spawn(async move {
        let session = listener.accept().await.expect("accept alice1");
        spawn_session(session, Arc::clone(&r));
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let session = listener.accept().await.expect("accept bob");
        spawn_session(session, Arc::clone(&r));
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let session = listener.accept().await.expect("accept alice2");
        spawn_session(session, r);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    });

    let (alice1_tx, mut alice1_rx) = connect_client(
        addr,
        &alice_cert.cert_pem,
        &alice_cert.key_pem,
        &ca.cert_pem,
    )
    .await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let (mut bob_tx, _bob_rx) =
        connect_client(addr, &bob_cert.cert_pem, &bob_cert.key_pem, &ca.cert_pem).await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let (_alice2_tx, mut alice2_rx) = connect_client(
        addr,
        &alice_cert.cert_pem,
        &alice_cert.key_pem,
        &ca.cert_pem,
    )
    .await;

    accept_handle.await.expect("accept loop");

    assert_eq!(router.session_count().await, 2);

    drop(alice1_tx);
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    bob_tx
        .send(tokio_util::bytes::BytesMut::from("who's there"))
        .await
        .expect("send");
    assert_eq!(recv(&mut alice2_rx, "alice2").await, b"who's there");
    assert_no_message(&mut alice1_rx, "alice1 stale").await;
}

/// Full 0x00–0xFF byte range. Catches codecs that choke on nulls or
/// treat certain bytes as delimiters.
#[tokio::test]
async fn binary_payload() {
    let (server, handle) = TestServer::new(2).await;
    let alice = server.issue_client("alice", &["sigint"]);
    let bob = server.issue_client("bob", &["sigint"]);

    let (mut alice_tx, _alice_rx) = server.connect(&alice).await;
    let (_bob_tx, mut bob_rx) = server.connect(&bob).await;
    server.wait_ready(handle).await;

    let payload: Vec<u8> = (0u8..=255).collect();
    alice_tx
        .send(tokio_util::bytes::BytesMut::from(payload.as_slice()))
        .await
        .expect("send");

    assert_eq!(recv(&mut bob_rx, "binary").await, payload);
}

/// 64KB frame forces multi-segment TCP reads and exercises codec reassembly.
/// Prime modulus pattern (251) avoids false alignment with power-of-2 boundaries.
#[tokio::test]
async fn large_frame() {
    let (server, handle) = TestServer::new(2).await;
    let alice = server.issue_client("alice", &["imagery"]);
    let bob = server.issue_client("bob", &["imagery"]);

    let (mut alice_tx, _alice_rx) = server.connect(&alice).await;
    let (_bob_tx, mut bob_rx) = server.connect(&bob).await;
    server.wait_ready(handle).await;

    let payload: Vec<u8> = (0..65_536).map(|i| (i % 251) as u8).collect();
    alice_tx
        .send(tokio_util::bytes::BytesMut::from(payload.as_slice()))
        .await
        .expect("send");

    let got = recv(&mut bob_rx, "large frame").await;
    assert_eq!(got.len(), 65_536);
    assert_eq!(got, payload);
}

/// Zero-length frame — valid per the codec, must not hang or crash.
#[tokio::test]
async fn zero_length_frame() {
    let (server, handle) = TestServer::new(2).await;
    let alice = server.issue_client("alice", &["team"]);
    let bob = server.issue_client("bob", &["team"]);

    let (mut alice_tx, _alice_rx) = server.connect(&alice).await;
    let (_bob_tx, mut bob_rx) = server.connect(&bob).await;
    server.wait_ready(handle).await;

    // Send empty frame
    alice_tx
        .send(tokio_util::bytes::BytesMut::new())
        .await
        .expect("send empty");

    let got = recv(&mut bob_rx, "empty frame").await;
    assert!(got.is_empty());

    // Send a normal frame after to prove the codec isn't stuck
    alice_tx
        .send(tokio_util::bytes::BytesMut::from("still alive"))
        .await
        .expect("send after empty");

    assert_eq!(recv(&mut bob_rx, "after empty").await, b"still alive");
}

/// Client sends a raw header claiming a 20MB payload. The server's codec
/// must reject it (MAX_FRAME_SIZE = 16MB) and drop the connection
/// instead of allocating 20MB.
#[tokio::test]
async fn oversized_frame_rejected() {
    let (server, handle) = TestServer::new(1).await;
    let alice = server.issue_client("alice", &["team"]);

    // Use raw TLS (no codec) so we can craft a malicious header
    let mut raw = connect_raw(
        server.addr,
        &alice.cert_pem,
        &alice.key_pem,
        &server.ca.cert_pem,
    )
    .await;

    handle.await.expect("server accept");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Write a 4-byte length header claiming 20MB
    let fake_len: u32 = 20 * 1024 * 1024;
    raw.write_all(&fake_len.to_be_bytes())
        .await
        .expect("write header");
    let _ = raw.flush().await;

    // Server should kill the connection — read should get EOF or error
    let mut buf = [0u8; 1];
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::io::AsyncReadExt::read(&mut raw, &mut buf),
    )
    .await;

    match result {
        Ok(Ok(0)) => {}  // EOF — server closed
        Ok(Err(_)) => {} // Read error — server reset
        Err(_) => panic!("server did not close the connection after oversized header"),
        Ok(Ok(_)) => panic!("server sent data back on an invalid frame"),
    }

    // Router should have cleaned up
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert_eq!(server.router.session_count().await, 0);
}

// ── router: group and direct delivery ────────────────────────────────────
// These test routing logic directly without TLS, since the transport is
// already proven above.

/// Route to a specific group — only members of that group receive the
/// message, excluding the sender.
#[tokio::test]
async fn route_to_group() {
    let router = Router::new();

    let alice = Arc::new(make_identity("alice", &["engineers"]));
    let bob = Arc::new(make_identity("bob", &["engineers"]));
    let charlie = Arc::new(make_identity("charlie", &["medics"]));

    let (alice_ptx, alice_ntx, _alice_prx, mut alice_nrx) = {
        let (p, pr) = mpsc::channel::<rustgate_transport::RoutedMessage>(16);
        let (n, nr) = mpsc::channel::<rustgate_transport::RoutedMessage>(16);
        (p, n, pr, nr)
    };
    let (bob_ptx, bob_ntx, _bob_prx, mut bob_nrx) = {
        let (p, pr) = mpsc::channel::<rustgate_transport::RoutedMessage>(16);
        let (n, nr) = mpsc::channel::<rustgate_transport::RoutedMessage>(16);
        (p, n, pr, nr)
    };
    let (charlie_ptx, charlie_ntx, _charlie_prx, mut charlie_nrx) = {
        let (p, pr) = mpsc::channel::<rustgate_transport::RoutedMessage>(16);
        let (n, nr) = mpsc::channel::<rustgate_transport::RoutedMessage>(16);
        (p, n, pr, nr)
    };

    router
        .register(SessionHandle::new(alice.clone(), alice_ptx, alice_ntx))
        .await;
    router
        .register(SessionHandle::new(bob.clone(), bob_ptx, bob_ntx))
        .await;
    router
        .register(SessionHandle::new(
            charlie.clone(),
            charlie_ptx,
            charlie_ntx,
        ))
        .await;

    // Alice sends to group "engineers"
    let msg = build_message(&alice, b"eng-only", Destination::Group("engineers".into()));
    router.route(msg).await;

    // Bob is in engineers — should receive (Other type → normal channel)
    let got = bob_nrx.try_recv().expect("bob should receive");
    assert_eq!(got.payload.as_ref(), b"eng-only");

    // Alice is in engineers but is the sender — should not receive
    assert!(
        alice_nrx.try_recv().is_err(),
        "sender should not self-receive"
    );

    // Charlie is in medics — should not receive
    assert!(
        charlie_nrx.try_recv().is_err(),
        "wrong group should not receive"
    );
}

/// Helper: create dual-channel senders and a pair of receivers.
#[allow(clippy::type_complexity)]
fn make_channels(
    cap: usize,
) -> (
    mpsc::Sender<rustgate_transport::RoutedMessage>,
    mpsc::Sender<rustgate_transport::RoutedMessage>,
    mpsc::Receiver<rustgate_transport::RoutedMessage>,
    mpsc::Receiver<rustgate_transport::RoutedMessage>,
) {
    let (ptx, prx) = mpsc::channel(cap);
    let (ntx, nrx) = mpsc::channel(cap);
    (ptx, ntx, prx, nrx)
}

/// Route directly to a specific CN — only the target receives it.
#[tokio::test]
async fn route_direct() {
    let router = Router::new();

    let alice = Arc::new(make_identity("alice", &["team"]));
    let bob = Arc::new(make_identity("bob", &["team"]));
    let charlie = Arc::new(make_identity("charlie", &["team"]));

    let (aptx, antx, _aprx, mut anrx) = make_channels(16);
    let (bptx, bntx, _bprx, mut bnrx) = make_channels(16);
    let (cptx, cntx, _cprx, mut cnrx) = make_channels(16);

    router
        .register(SessionHandle::new(alice.clone(), aptx, antx))
        .await;
    router
        .register(SessionHandle::new(bob.clone(), bptx, bntx))
        .await;
    router
        .register(SessionHandle::new(charlie.clone(), cptx, cntx))
        .await;

    // Alice sends directly to bob (Other type → normal channel)
    let target = (*bob).clone();
    let msg = build_message(&alice, b"for-bob-only", Destination::Direct(target));
    router.route(msg).await;

    // Bob should receive on normal channel
    let got = bnrx.try_recv().expect("bob should receive direct");
    assert_eq!(got.payload.as_ref(), b"for-bob-only");

    // Nobody else
    assert!(anrx.try_recv().is_err());
    assert!(cnrx.try_recv().is_err());
}

/// Direct message to a CN that isn't registered — must not panic.
#[tokio::test]
async fn route_direct_to_offline_user() {
    let router = Router::new();

    let alice = Arc::new(make_identity("alice", &["team"]));
    let (ptx, ntx, _prx, _nrx) = make_channels(16);
    router
        .register(SessionHandle::new(alice.clone(), ptx, ntx))
        .await;

    let ghost = make_identity("ghost", &["team"]);
    let msg = build_message(&alice, b"hello?", Destination::Direct(ghost));

    // Should not panic — just silently drops
    router.route(msg).await;
}

/// Group message to a group with no members — must not panic.
#[tokio::test]
async fn route_to_empty_group() {
    let router = Router::new();

    let alice = Arc::new(make_identity("alice", &["engineers"]));
    let (ptx, ntx, _prx, _nrx) = make_channels(16);
    router
        .register(SessionHandle::new(alice.clone(), ptx, ntx))
        .await;

    let msg = build_message(&alice, b"anyone?", Destination::Group("ghosts".into()));

    // Should not panic
    router.route(msg).await;
}

/// When a CN re-registers with different groups, stale group entries
/// must be cleaned. Otherwise group routing leaks into old groups.
#[tokio::test]
async fn register_with_group_change() {
    let router = Router::new();

    let alice_v1 = Arc::new(make_identity("alice", &["alpha"]));
    let bob = Arc::new(make_identity("bob", &["alpha", "bravo"]));
    let charlie = Arc::new(make_identity("charlie", &["bravo"]));

    let (av1ptx, av1ntx, _av1prx, _av1nrx) = make_channels(16);
    let (bptx, bntx, _bprx, mut bnrx) = make_channels(16);
    let (cptx, cntx, _cprx, mut cnrx) = make_channels(16);

    router
        .register(SessionHandle::new(alice_v1.clone(), av1ptx, av1ntx))
        .await;
    router
        .register(SessionHandle::new(bob.clone(), bptx, bntx))
        .await;
    router
        .register(SessionHandle::new(charlie.clone(), cptx, cntx))
        .await;

    // Alice moves from "alpha" to "bravo"
    let alice_v2 = Arc::new(make_identity("alice", &["bravo"]));
    let (av2ptx, av2ntx, _av2prx, mut av2nrx) = make_channels(16);
    router
        .register(SessionHandle::new(alice_v2.clone(), av2ptx, av2ntx))
        .await;

    // Alice (now in bravo) sends to group "alpha" — rejected because
    // the router enforces sender group membership.
    let msg = build_message(&alice_v2, b"alpha-msg", Destination::Group("alpha".into()));
    router.route(msg).await;

    assert!(
        bnrx.try_recv().is_err(),
        "alice is not in alpha, message should be rejected"
    );
    assert!(
        av2nrx.try_recv().is_err(),
        "alice left alpha, should not receive"
    );

    // Charlie sends to group "bravo" — alice and bob receive (both in bravo)
    let msg = build_message(&charlie, b"bravo-msg", Destination::Group("bravo".into()));
    router.route(msg).await;

    let got = av2nrx.try_recv().expect("alice is now in bravo");
    assert_eq!(got.payload.as_ref(), b"bravo-msg");
    let got = bnrx.try_recv().expect("bob is in bravo");
    assert_eq!(got.payload.as_ref(), b"bravo-msg");

    // Charlie sent bravo-msg → self-filtered. Not in alpha → nothing from there.
    assert!(cnrx.try_recv().is_err());
}

/// Direct-message to yourself. `send_to_session` does not filter the sender,
/// so this should deliver.
#[tokio::test]
async fn route_direct_to_self() {
    let router = Router::new();

    let alice = Arc::new(make_identity("alice", &["team"]));
    let (ptx, ntx, _prx, mut nrx) = make_channels(16);
    router
        .register(SessionHandle::new(alice.clone(), ptx, ntx))
        .await;

    let target = (*alice).clone();
    let msg = build_message(&alice, b"note-to-self", Destination::Direct(target));
    router.route(msg).await;

    let got = nrx.try_recv().expect("direct to self should deliver");
    assert_eq!(got.payload.as_ref(), b"note-to-self");
}

/// Position messages are cached and replayed to newly connecting sessions.
/// This provides the SA (situational awareness) picture on connect.
#[tokio::test]
async fn position_cache_replay() {
    let router = Router::new();

    let alice = Arc::new(make_identity("alice", &["team"]));
    let bob = Arc::new(make_identity("bob", &["team"]));

    let (aptx, antx, _aprx, _anrx) = make_channels(16);
    let alice_handle = SessionHandle::new(alice.clone(), aptx, antx);
    let _ = router.register(alice_handle.clone()).await;
    router.replay_positions(&alice_handle).await;

    // Alice sends a position message (broadcast)
    let position_msg = RoutableMessage {
        source: (*alice).clone(),
        destination: Destination::Broadcast,
        payload: Bytes::from("<event type='a-f-G'/>"),
        metadata: Metadata {
            received_at: SystemTime::now(),
            source_protocol: "cot".into(),
            message_type: MessageType::Position,
            ttl: None,
        },
    };
    router.route(position_msg).await;

    // Verify it's cached
    assert_eq!(router.cache().len().await, 1);

    // Bob connects later — position goes to priority channel
    let (bptx, bntx, mut bprx, _bnrx) = make_channels(16);
    let bob_handle = SessionHandle::new(bob.clone(), bptx, bntx);
    let _ = router.register(bob_handle.clone()).await;
    router.replay_positions(&bob_handle).await;

    // Bob should receive Alice's cached position on priority channel
    let got = bprx.try_recv().expect("bob should receive cached position");
    assert_eq!(got.source.cn, "alice");
    assert_eq!(got.metadata.message_type, MessageType::Position);
}

/// Non-position messages are not cached.
#[tokio::test]
async fn chat_messages_not_cached() {
    let router = Router::new();

    let alice = Arc::new(make_identity("alice", &["team"]));
    let (ptx, ntx, _prx, _nrx) = make_channels(16);
    router
        .register(SessionHandle::new(alice.clone(), ptx, ntx))
        .await;

    // Alice sends a chat message
    let chat_msg = RoutableMessage {
        source: (*alice).clone(),
        destination: Destination::Broadcast,
        payload: Bytes::from("hello"),
        metadata: Metadata {
            received_at: SystemTime::now(),
            source_protocol: "cot".into(),
            message_type: MessageType::Chat,
            ttl: None,
        },
    };
    router.route(chat_msg).await;

    // Chat should not be cached
    assert!(router.cache().is_empty().await);
}

/// Multiple positions from same CN — only latest is cached.
#[tokio::test]
async fn position_cache_replaces_old() {
    let router = Router::new();

    let alice = Arc::new(make_identity("alice", &["team"]));
    let (ptx, ntx, _prx, _nrx) = make_channels(16);
    router
        .register(SessionHandle::new(alice.clone(), ptx, ntx))
        .await;

    // Alice sends first position
    let pos1 = RoutableMessage {
        source: (*alice).clone(),
        destination: Destination::Broadcast,
        payload: Bytes::from("pos1"),
        metadata: Metadata {
            received_at: SystemTime::now(),
            source_protocol: "cot".into(),
            message_type: MessageType::Position,
            ttl: None,
        },
    };
    router.route(pos1).await;

    // Alice sends second position
    let pos2 = RoutableMessage {
        source: (*alice).clone(),
        destination: Destination::Broadcast,
        payload: Bytes::from("pos2"),
        metadata: Metadata {
            received_at: SystemTime::now(),
            source_protocol: "cot".into(),
            message_type: MessageType::Position,
            ttl: None,
        },
    };
    router.route(pos2).await;

    // Only one entry (latest)
    assert_eq!(router.cache().len().await, 1);

    // Bob connects and gets the latest position (priority channel)
    let bob = Arc::new(make_identity("bob", &["team"]));
    let (bptx, bntx, mut bprx, _bnrx) = make_channels(16);
    let bob_handle = SessionHandle::new(bob.clone(), bptx, bntx);
    let _ = router.register(bob_handle.clone()).await;
    router.replay_positions(&bob_handle).await;

    let got = bprx.try_recv().expect("bob should receive cached position");
    assert_eq!(got.payload.as_ref(), b"pos2");
}

// ── TTL enforcement ─────────────────────────────────────────────────────

/// Messages whose TTL has expired before delivery are silently dropped
/// and never delivered to any session.
#[tokio::test]
async fn expired_message_is_dropped() {
    let router = Router::new();

    let alice = Arc::new(make_identity("alice", &["team"]));
    let bob = Arc::new(make_identity("bob", &["team"]));

    let (aptx, antx, mut _aprx, mut alice_rx) = make_channels(16);
    let (bptx, bntx, mut _bprx, mut bob_rx) = make_channels(16);

    router
        .register(SessionHandle::new(alice.clone(), aptx, antx))
        .await;
    router
        .register(SessionHandle::new(bob.clone(), bptx, bntx))
        .await;

    // Build a message that is already expired: received 10s ago with 1s TTL
    let expired_msg = RoutableMessage {
        source: (*alice).clone(),
        destination: Destination::Broadcast,
        payload: Bytes::from("stale"),
        metadata: Metadata {
            received_at: SystemTime::now() - std::time::Duration::from_secs(10),
            source_protocol: "tcp".into(),
            message_type: MessageType::Other("raw".into()),
            ttl: Some(std::time::Duration::from_secs(1)),
        },
    };
    router.route(expired_msg).await;

    // Neither alice (sender) nor bob should receive the expired message
    assert!(
        alice_rx.try_recv().is_err(),
        "expired message should not be delivered to sender"
    );
    assert!(
        bob_rx.try_recv().is_err(),
        "expired message should not be delivered to any session"
    );
}

/// Messages without a TTL are never considered expired and route normally.
#[tokio::test]
async fn message_without_ttl_routes_normally() {
    let router = Router::new();

    let alice = Arc::new(make_identity("alice", &["team"]));
    let bob = Arc::new(make_identity("bob", &["team"]));

    let (_aptx, _antx, _aprx, _arx) = make_channels(16);
    let (bptx, bntx, _bprx, mut bob_rx) = make_channels(16);

    router
        .register(SessionHandle::new(alice.clone(), _aptx, _antx))
        .await;
    router
        .register(SessionHandle::new(bob.clone(), bptx, bntx))
        .await;

    // Message with no TTL — should be delivered regardless of age
    let msg = RoutableMessage {
        source: (*alice).clone(),
        destination: Destination::Broadcast,
        payload: Bytes::from("no-ttl"),
        metadata: Metadata {
            received_at: SystemTime::now() - std::time::Duration::from_secs(3600),
            source_protocol: "tcp".into(),
            message_type: MessageType::Other("raw".into()),
            ttl: None,
        },
    };
    router.route(msg).await;

    let got = bob_rx
        .try_recv()
        .expect("message without TTL should be delivered");
    assert_eq!(got.payload.as_ref(), b"no-ttl");
}

/// Messages with a TTL that has not yet expired route normally.
#[tokio::test]
async fn non_expired_ttl_message_routes_normally() {
    let router = Router::new();

    let alice = Arc::new(make_identity("alice", &["team"]));
    let bob = Arc::new(make_identity("bob", &["team"]));

    let (_aptx, _antx, _aprx, _arx) = make_channels(16);
    let (bptx, bntx, _bprx, mut bob_rx) = make_channels(16);

    router
        .register(SessionHandle::new(alice.clone(), _aptx, _antx))
        .await;
    router
        .register(SessionHandle::new(bob.clone(), bptx, bntx))
        .await;

    // Message with a generous TTL — should be delivered
    let msg = RoutableMessage {
        source: (*alice).clone(),
        destination: Destination::Broadcast,
        payload: Bytes::from("fresh"),
        metadata: Metadata {
            received_at: SystemTime::now(),
            source_protocol: "tcp".into(),
            message_type: MessageType::Other("raw".into()),
            ttl: Some(std::time::Duration::from_secs(300)),
        },
    };
    router.route(msg).await;

    let got = bob_rx
        .try_recv()
        .expect("non-expired TTL message should be delivered");
    assert_eq!(got.payload.as_ref(), b"fresh");
}

// ── codec: header sizes and overflow ─────────────────────────────────────

/// HeaderSize::One — encode and decode a frame within the 255-byte limit.
#[test]
fn codec_header_one() {
    use tokio_util::codec::{Decoder, Encoder};
    let mut codec = LengthPrefixedCodec::new(HeaderSize::One);
    let payload = tokio_util::bytes::BytesMut::from(&b"short"[..]);

    let mut wire = tokio_util::bytes::BytesMut::new();
    codec.encode(payload, &mut wire).expect("encode");

    // 1-byte header + 5 bytes payload
    assert_eq!(wire.len(), 6);
    assert_eq!(wire[0], 5); // length byte

    let decoded = codec.decode(&mut wire).expect("decode").expect("frame");
    assert_eq!(&decoded[..], b"short");
}

/// HeaderSize::Two — encode and decode a frame that needs 2-byte length.
#[test]
fn codec_header_two() {
    use tokio_util::codec::{Decoder, Encoder};
    let mut codec = LengthPrefixedCodec::new(HeaderSize::Two);

    // 300 bytes — doesn't fit in a 1-byte header
    let payload = tokio_util::bytes::BytesMut::from(vec![0xAB_u8; 300].as_slice());

    let mut wire = tokio_util::bytes::BytesMut::new();
    codec.encode(payload, &mut wire).expect("encode");

    // 2-byte header + 300 bytes
    assert_eq!(wire.len(), 302);
    assert_eq!(&wire[0..2], &300_u16.to_be_bytes());

    let decoded = codec.decode(&mut wire).expect("decode").expect("frame");
    assert_eq!(decoded.len(), 300);
    assert!(decoded.iter().all(|&b| b == 0xAB));
}

/// HeaderSize::One encode must reject payloads > 255 bytes.
#[test]
fn codec_header_one_overflow() {
    use tokio_util::codec::Encoder;
    let mut codec = LengthPrefixedCodec::new(HeaderSize::One);
    let payload = tokio_util::bytes::BytesMut::from(vec![0u8; 256].as_slice());

    let mut wire = tokio_util::bytes::BytesMut::new();
    let result = codec.encode(payload, &mut wire);

    assert!(
        result.is_err(),
        "256 bytes should not fit in a 1-byte header"
    );
}

/// HeaderSize::Two encode must reject payloads > 65535 bytes.
#[test]
fn codec_header_two_overflow() {
    use tokio_util::codec::Encoder;
    let mut codec = LengthPrefixedCodec::new(HeaderSize::Two);
    let payload = tokio_util::bytes::BytesMut::from(vec![0u8; 65_536].as_slice());

    let mut wire = tokio_util::bytes::BytesMut::new();
    let result = codec.encode(payload, &mut wire);

    assert!(
        result.is_err(),
        "65536 bytes should not fit in a 2-byte header"
    );
}
