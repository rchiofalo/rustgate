// Copyright © 2026 Roberto Chiofalo.

#![allow(clippy::panic, clippy::unwrap_used)]
//! Integration tests for the generic UDP codec ingress listener
//! ([`rustgate_transport::codec_ingress::CodecUdpInput`], #1473).
//!
//! These exercise the *listener contract* — admission, validate-and-drop at
//! the edge, and routing of accepted datagrams with the right
//! `source_protocol` tag — with a controllable mock [`EntityCodec`], so the
//! test is independent of any specific protocol codec (DIS/ASTERIX/VMF are
//! validated in their own crates). A datagram whose payload begins with
//! `GOOD` decodes; anything else is rejected by the mock, standing in for
//! malformed wire input.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use rustgate_core::entity::{Entity, EntityCodec, EntityKind};
use rustgate_core::identity::Identity;
use rustgate_core::message::MessageType;
use rustgate_router::{RoutedMessage, Router, SessionHandle};
use rustgate_transport::codec_ingress::{CodecIngressConfig, CodecUdpInput};
use tokio::net::UdpSocket;
use tokio::sync::{Notify, mpsc};

#[derive(Debug)]
struct MockCodecError(&'static str);
impl std::fmt::Display for MockCodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "mock decode error: {}", self.0)
    }
}
impl std::error::Error for MockCodecError {}

/// Accepts datagrams whose payload begins with `GOOD`; rejects all others.
#[derive(Debug)]
struct MockCodec;
impl EntityCodec for MockCodec {
    type Error = MockCodecError;

    fn to_entity(&self, payload: &[u8]) -> Result<Entity, Self::Error> {
        if !payload.starts_with(b"GOOD") {
            return Err(MockCodecError("payload not well-formed"));
        }
        Ok(Entity {
            uid: "mock-uid".into(),
            kind: EntityKind::Track,
            position: None,
            velocity: None,
            timestamp: SystemTime::UNIX_EPOCH,
            callsign: None,
            mil_std_2525_sidc: None,
            attributes: BTreeMap::new(),
            taskings: Default::default(),
            files: Default::default(),
        })
    }

    fn from_entity(&self, _entity: &Entity) -> Result<bytes::Bytes, Self::Error> {
        Ok(bytes::Bytes::new())
    }
}

const GROUP: &str = "tac-feed";

/// Spawn the listener and register a sink session in `GROUP`; returns the
/// client socket addr to send to, the priority+normal receivers, and the
/// shutdown handle.
async fn spawn_listener() -> (
    std::net::SocketAddr,
    mpsc::Receiver<RoutedMessage>,
    mpsc::Receiver<RoutedMessage>,
    Arc<Notify>,
    tokio::task::JoinHandle<()>,
) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
    let local = socket.local_addr().expect("local_addr");

    let router = Arc::new(Router::new());

    // Sink session in the destination group so routed datagrams land.
    let mut groups = BTreeSet::new();
    let _ = groups.insert(GROUP.to_string());
    let sink_identity =
        Arc::new(Identity::plaintext("sink".to_string(), groups).expect("identity"));
    let (ptx, prx) = mpsc::channel::<RoutedMessage>(64);
    let (ntx, nrx) = mpsc::channel::<RoutedMessage>(64);
    let _ = router
        .register(SessionHandle::new(sink_identity, ptx, ntx))
        .await;

    let config = CodecIngressConfig {
        cn_prefix: "test-anonymous".to_string(),
        group: GROUP.to_string(),
        max_pps: Some(1000),
        allowed_cidrs: None,
        max_identities: 64,
        max_datagram_size: 65_535,
    };
    let shutdown = Arc::new(Notify::new());
    let shutdown_clone = Arc::clone(&shutdown);
    let task = tokio::spawn(async move {
        CodecUdpInput::run(
            socket,
            router,
            Arc::new(MockCodec),
            "test-proto".to_string(),
            MessageType::Position,
            config,
            shutdown_clone,
        )
        .await;
    });
    (local, prx, nrx, shutdown, task)
}

async fn recv_one(
    prx: &mut mpsc::Receiver<RoutedMessage>,
    nrx: &mut mpsc::Receiver<RoutedMessage>,
) -> Option<RoutedMessage> {
    tokio::time::timeout(Duration::from_millis(500), async {
        tokio::select! {
            biased;
            m = prx.recv() => m,
            m = nrx.recv() => m,
        }
    })
    .await
    .ok()
    .flatten()
}

#[tokio::test]
async fn valid_datagram_is_routed_with_source_protocol_tag() {
    let (local, mut prx, mut nrx, shutdown, task) = spawn_listener().await;

    let client = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");
    let _ = client.send_to(b"GOODpayload", local).await.expect("send");

    let msg = recv_one(&mut prx, &mut nrx)
        .await
        .expect("a valid datagram should be routed");
    assert_eq!(msg.metadata.source_protocol, "test-proto");

    shutdown.notify_one();
    let _ = tokio::time::timeout(Duration::from_secs(1), task).await;
}

#[tokio::test]
async fn malformed_datagram_is_dropped_at_edge() {
    let (local, mut prx, mut nrx, shutdown, task) = spawn_listener().await;

    let client = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");
    // Does not start with GOOD → the mock codec rejects it → dropped.
    let _ = client.send_to(b"BADpayload", local).await.expect("send");

    assert!(
        recv_one(&mut prx, &mut nrx).await.is_none(),
        "a datagram that fails to decode must be dropped, not routed"
    );

    shutdown.notify_one();
    let _ = tokio::time::timeout(Duration::from_secs(1), task).await;
}

#[tokio::test]
async fn empty_datagram_is_ignored() {
    let (local, mut prx, mut nrx, shutdown, task) = spawn_listener().await;

    let client = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");
    let _ = client.send_to(b"", local).await.expect("send");

    assert!(
        recv_one(&mut prx, &mut nrx).await.is_none(),
        "a zero-length datagram must be ignored"
    );

    shutdown.notify_one();
    let _ = tokio::time::timeout(Duration::from_secs(1), task).await;
}
