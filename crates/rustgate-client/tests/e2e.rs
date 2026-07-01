// Copyright © 2026 Roberto Chiofalo.

#![allow(clippy::panic, clippy::unwrap_used)]
//! End-to-end tests using `rustgate-client` against a real `TlsListener`.
//!
//! These mirror two existing transport-layer tests
//! (`broadcast_between_two_clients` and `binary_payload` in
//! `crates/rustgate-transport/tests/e2e_routing.rs`) but use the high-level
//! `Client` API instead of hand-rolled TLS + framing setup. The original
//! versions stand at ~30 lines of TLS plumbing each; here they reduce to a
//! few `Client::connect` calls.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use rustgate_client::{Client, ClientConfig, Codec, Message, ReconnectPolicy};
use rustgate_core::identity::Identity;
use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};
use rustgate_core::protocol::HeaderSize;
use rustgate_router::{Router, SessionHandle};
use rustgate_test_utils::certs::TestCa;
use rustgate_tls::{AuthenticatedSession, TlsConfig, TlsListener};
use rustgate_transport::LengthPrefixedCodec;
use tokio::sync::mpsc;
use tokio_util::codec::{FramedRead, FramedWrite};

fn build_message(source: &Identity, payload: &[u8]) -> RoutableMessage {
    RoutableMessage {
        source: source.clone(),
        destination: Destination::Broadcast,
        payload: Bytes::copy_from_slice(payload),
        metadata: Metadata::new(
            SystemTime::now(),
            "tcp".into(),
            MessageType::Other("raw".into()),
        ),
    }
}

fn spawn_session(session: AuthenticatedSession, router: Arc<Router>) {
    drop(tokio::spawn(async move {
        let identity = session.identity_arc();
        let (ptx, mut prx) = mpsc::channel::<rustgate_router::RoutedMessage>(16);
        let (ntx, mut nrx) = mpsc::channel::<rustgate_router::RoutedMessage>(64);
        let handle = SessionHandle::new(Arc::clone(&identity), ptx, ntx);
        let session_id = handle.id;
        let _ = router.register(handle).await;
        let (reader, writer) = session.split();
        let id_for_read = Arc::clone(&identity);
        let router_for_read = Arc::clone(&router);

        let read_task = tokio::spawn(async move {
            let mut framed = FramedRead::new(reader, LengthPrefixedCodec::new(HeaderSize::Four));
            while let Some(Ok(frame)) = framed.next().await {
                router_for_read
                    .route(build_message(&id_for_read, &frame))
                    .await;
            }
        });
        let write_task = tokio::spawn(async move {
            let mut framed = FramedWrite::new(writer, LengthPrefixedCodec::new(HeaderSize::Four));
            loop {
                let msg = tokio::select! {
                    biased;
                    msg = prx.recv() => msg,
                    msg = nrx.recv() => msg,
                };
                let Some(msg) = msg else { break };
                if framed
                    .send(tokio_util::bytes::BytesMut::from(msg.payload.as_ref()))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });

        let _ = read_task.await;
        write_task.abort();
        let _ = write_task.await;
        router.unregister(&identity.cn, session_id).await;
    }));
}

struct TestServer {
    addr: std::net::SocketAddr,
    ca: TestCa,
}

async fn start_server(accept_count: usize) -> (TestServer, tokio::task::JoinHandle<()>) {
    let ca = TestCa::new("Test CA");
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);
    let tls_config =
        TlsConfig::from_pem(&server_cert.cert_pem, &server_cert.key_pem, &ca.cert_pem).unwrap();
    let listener = TlsListener::bind("127.0.0.1:0", &tls_config).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = Arc::new(Router::new());
    let r = Arc::clone(&router);
    let h = tokio::spawn(async move {
        for _ in 0..accept_count {
            let session = listener.accept().await.unwrap();
            spawn_session(session, Arc::clone(&r));
        }
    });
    (TestServer { addr, ca }, h)
}

async fn connect_via_client(server: &TestServer, cn: &str, groups: &[&str]) -> Client {
    let cert = server.ca.issue_client_cert(cn, groups);
    let config = ClientConfig::builder()
        .server_addr(server.addr.to_string())
        .server_name("localhost")
        .mtls_pem_bytes(
            cert.cert_pem.into_bytes(),
            cert.key_pem.into_bytes(),
            server.ca.cert_pem.clone().into_bytes(),
        )
        .codec(Codec::LengthPrefixed4)
        .connect_timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    Client::connect(config).await.unwrap()
}

async fn recv_one(
    stream: &mut (impl futures::Stream<Item = rustgate_client::Result<Message>> + Unpin),
    label: &str,
) -> Bytes {
    let msg = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .unwrap_or_else(|_| panic!("{label}: timeout"))
        .unwrap_or_else(|| panic!("{label}: stream ended"))
        .unwrap_or_else(|e| panic!("{label}: error: {e}"));
    msg.payload
}

#[tokio::test]
async fn broadcast_between_two_clients_via_client_api() {
    let (server, accept_handle) = start_server(2).await;
    let alice = connect_via_client(&server, "alice", &["engineers"]).await;
    let bob = connect_via_client(&server, "bob", &["engineers"]).await;
    accept_handle.await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut bob_rx = Box::pin(bob.subscribe());
    let mut alice_rx = Box::pin(alice.subscribe());

    alice.send(Bytes::from_static(b"hello bob")).await.unwrap();
    assert_eq!(recv_one(&mut bob_rx, "bob").await, &b"hello bob"[..]);

    bob.send(Bytes::from_static(b"hey alice")).await.unwrap();
    assert_eq!(recv_one(&mut alice_rx, "alice").await, &b"hey alice"[..]);

    alice.disconnect().await;
    bob.disconnect().await;
}

#[tokio::test]
async fn client_recovers_after_server_restart() {
    // First server: accept one connection, then drop the listener so the
    // port is released. The accepted session's task is aborted to force
    // the client's read loop to see a connection-reset/EOF.
    let ca = TestCa::new("Test CA");
    let server_cert = ca.issue_server_cert("localhost", &["localhost"]);
    let tls_config =
        TlsConfig::from_pem(&server_cert.cert_pem, &server_cert.key_pem, &ca.cert_pem).unwrap();
    let listener = TlsListener::bind("127.0.0.1:0", &tls_config).await.unwrap();
    let addr = listener.local_addr().unwrap();

    let session_slot: Arc<tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>> =
        Arc::new(tokio::sync::Mutex::new(None));
    let slot_clone = Arc::clone(&session_slot);
    let accept_handle = tokio::spawn(async move {
        let session = listener.accept().await.unwrap();
        let router = Arc::new(Router::new());
        // Stash the session-task future so we can abort it later.
        let jh = tokio::spawn(async move {
            let identity = session.identity_arc();
            let (ptx, mut prx) = mpsc::channel::<rustgate_router::RoutedMessage>(16);
            let (ntx, mut nrx) = mpsc::channel::<rustgate_router::RoutedMessage>(64);
            let handle = SessionHandle::new(Arc::clone(&identity), ptx, ntx);
            let _ = router.register(handle).await;
            let (reader, writer) = session.split();
            let mut framed_r = FramedRead::new(reader, LengthPrefixedCodec::new(HeaderSize::Four));
            let mut framed_w = FramedWrite::new(writer, LengthPrefixedCodec::new(HeaderSize::Four));
            loop {
                tokio::select! {
                    frame = framed_r.next() => {
                        if frame.is_none() { break; }
                    }
                    msg = prx.recv() => {
                        let Some(msg) = msg else { break };
                        let _ = framed_w
                            .send(tokio_util::bytes::BytesMut::from(msg.payload.as_ref()))
                            .await;
                    }
                    msg = nrx.recv() => {
                        let Some(msg) = msg else { break };
                        let _ = framed_w
                            .send(tokio_util::bytes::BytesMut::from(msg.payload.as_ref()))
                            .await;
                    }
                }
            }
        });
        *slot_clone.lock().await = Some(jh);
        // Drop listener by exiting the task.
    });

    let client_cert = ca.issue_client_cert("alice", &["engineers"]);
    let cert_pem_bytes = client_cert.cert_pem.into_bytes();
    let key_pem_bytes = client_cert.key_pem.into_bytes();
    let ca_pem_bytes = ca.cert_pem.clone().into_bytes();
    let config = ClientConfig::builder()
        .server_addr(addr.to_string())
        .server_name("localhost")
        .mtls_pem_bytes(
            cert_pem_bytes.clone(),
            key_pem_bytes.clone(),
            ca_pem_bytes.clone(),
        )
        .codec(Codec::LengthPrefixed4)
        .connect_timeout(Duration::from_secs(5))
        .reconnect(ReconnectPolicy {
            initial_backoff: Duration::from_millis(50),
            max_backoff: Duration::from_secs(1),
            max_attempts: 0,
        })
        .build()
        .unwrap();

    let client = Client::connect(config).await.unwrap();
    accept_handle.await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Tear down the first server's session, freeing the connection.
    if let Some(jh) = session_slot.lock().await.take() {
        jh.abort();
        let _ = jh.await;
    }
    // Give the OS a moment to release the port.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Restart on the same address.
    let server_cert2 = ca.issue_server_cert("localhost", &["localhost"]);
    let tls_config2 =
        TlsConfig::from_pem(&server_cert2.cert_pem, &server_cert2.key_pem, &ca.cert_pem).unwrap();
    let listener2 = TlsListener::bind(addr, &tls_config2).await.unwrap();
    // Second server: accept the reconnect, then immediately echo back the
    // first frame we read on that session so the client can observe it.
    let (echo_tx, mut echo_rx) = tokio::sync::mpsc::channel::<Bytes>(1);
    let accept2 = tokio::spawn(async move {
        let session = listener2.accept().await.unwrap();
        let (reader, writer) = session.split();
        let mut framed_r = FramedRead::new(reader, LengthPrefixedCodec::new(HeaderSize::Four));
        let mut framed_w = FramedWrite::new(writer, LengthPrefixedCodec::new(HeaderSize::Four));
        while let Some(Ok(frame)) = framed_r.next().await {
            let bytes = frame.freeze();
            let _ = echo_tx.send(bytes.clone()).await;
            if framed_w
                .send(tokio_util::bytes::BytesMut::from(bytes.as_ref()))
                .await
                .is_err()
            {
                break;
            }
        }
    });

    // Client should reconnect; keep sending until the second server reports
    // it received a frame, then verify the client observes the echo.
    let mut rx = Box::pin(client.subscribe());
    let mut received_on_server = false;
    for _ in 0..60 {
        let _ = client.send(Bytes::from_static(b"post-reconnect")).await;
        if let Ok(Some(got)) =
            tokio::time::timeout(Duration::from_millis(200), echo_rx.recv()).await
        {
            assert_eq!(got.as_ref(), b"post-reconnect");
            received_on_server = true;
            break;
        }
    }
    assert!(
        received_on_server,
        "client did not reconnect to restarted server"
    );

    // The second server echoes; the client's subscribe stream should see it.
    let delivered = tokio::time::timeout(Duration::from_secs(3), async {
        while let Some(Ok(msg)) = rx.next().await {
            if msg.payload.as_ref() == b"post-reconnect" {
                return true;
            }
        }
        false
    })
    .await
    .unwrap_or(false);
    assert!(
        delivered,
        "client did not receive echoed frame after reconnect"
    );

    client.disconnect().await;
    accept2.abort();
    let _ = accept2.await;
}

#[tokio::test]
async fn disconnect_during_reconnect_does_not_hang() {
    // #1497 / H-9 regression: `disconnect()` sets the `disconnected` flag then
    // fires `notify_waiters()`, which only wakes tasks *currently* parked on
    // `shutdown.notified()`. If that notify races with the run loop being
    // inside `dial()` (the reconnect backoff path), the wakeup is lost and
    // `disconnect().await` would hang forever on `task.await`. The fix threads
    // the flag into `run()` and checks it (Acquire) at the top of every
    // iteration and again right after redialing.
    //
    // Drive the loop into the redial state by binding a plaintext listener,
    // accepting once, then dropping the connection so the client's read loop
    // hits EOF and starts hammering the (now dead) port with reconnect
    // attempts. Then `disconnect()` must still return promptly.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let accept_task = tokio::spawn(async move {
        // Accept exactly one connection, hold it briefly, then drop it so the
        // client sees EOF and enters the reconnect loop against a dead port.
        if let Ok((sock, _)) = listener.accept().await {
            tokio::time::sleep(Duration::from_millis(50)).await;
            drop(sock);
        }
        // Drop the listener so subsequent redials get connection-refused.
        drop(listener);
    });

    let config = ClientConfig::builder()
        .server_addr(addr.to_string())
        .plaintext(true)
        .codec(Codec::LengthPrefixed4)
        .connect_timeout(Duration::from_secs(5))
        .reconnect(ReconnectPolicy {
            initial_backoff: Duration::from_millis(20),
            max_backoff: Duration::from_millis(50),
            max_attempts: 0, // infinite — the loop only stops on disconnect
        })
        .build()
        .unwrap();

    let client = Client::connect(config).await.unwrap();
    accept_task.await.unwrap();

    // Let the client cycle through a few failed redials so `disconnect()` is
    // very likely to land while the loop is mid-`dial()` or mid-backoff.
    tokio::time::sleep(Duration::from_millis(120)).await;

    // The whole point: this must not hang. Bound it generously; a lost wakeup
    // would blow straight through this timeout.
    tokio::time::timeout(Duration::from_secs(5), client.disconnect())
        .await
        .expect("disconnect() hung — H-9 lost-wakeup regression");
}

#[tokio::test]
async fn binary_payload_via_client_api() {
    let (server, accept_handle) = start_server(2).await;
    let alice = connect_via_client(&server, "alice", &["sigint"]).await;
    let bob = connect_via_client(&server, "bob", &["sigint"]).await;
    accept_handle.await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut bob_rx = Box::pin(bob.subscribe());

    let payload: Vec<u8> = (0u8..=255).collect();
    alice.send(Bytes::from(payload.clone())).await.unwrap();

    let got = recv_one(&mut bob_rx, "binary").await;
    assert_eq!(got.as_ref(), payload.as_slice());

    alice.disconnect().await;
    bob.disconnect().await;
}
