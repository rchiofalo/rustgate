// Copyright © 2026 Roberto Chiofalo.

#![allow(clippy::panic, clippy::unwrap_used)]
//! Integration tests for the generic stream-framed TCP ingress listener
//! ([`rustgate_transport::codec_tcp_ingress::CodecTcpInput`], #1473).
//!
//! These exercise the *listener contract* — frame delimitation (varint
//! length-delimited), per-frame validate-and-drop, and routing of accepted
//! frames with the right `source_protocol` tag — with a controllable mock
//! [`EntityCodec`], independent of any specific protocol codec. A frame whose
//! payload begins with `GOOD` decodes; anything else is rejected by the mock,
//! standing in for malformed wire input. The frames are delimited with the
//! production `VarintDelimitedCodec`, so the framing path itself is covered
//! end-to-end (including splitting a frame across two writes).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use rustgate_core::entity::{Entity, EntityCodec, EntityKind};
use rustgate_core::identity::Identity;
use rustgate_core::message::MessageType;
use rustgate_router::{RoutedMessage, Router, SessionHandle};
use rustgate_transport::codec_tcp_ingress::{CodecTcpIngressConfig, CodecTcpInput, FramingFactory};
use rustgate_transport::{FramedCodec, VarintDelimitedCodec};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, mpsc};

#[derive(Debug)]
struct MockCodecError(&'static str);
impl std::fmt::Display for MockCodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "mock decode error: {}", self.0)
    }
}
impl std::error::Error for MockCodecError {}

/// Accepts frames whose payload begins with `GOOD`; rejects all others.
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

const GROUP: &str = "tac-stream";

/// Encode `body` as one varint length-delimited frame.
fn frame(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut len = body.len() as u64;
    loop {
        let mut byte = (len & 0x7F) as u8;
        len >>= 7;
        if len != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if len == 0 {
            break;
        }
    }
    out.extend_from_slice(body);
    out
}

async fn spawn_listener() -> (
    std::net::SocketAddr,
    mpsc::Receiver<RoutedMessage>,
    mpsc::Receiver<RoutedMessage>,
    Arc<Notify>,
    tokio::task::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let local = listener.local_addr().expect("local_addr");

    let router = Arc::new(Router::new());
    let mut groups = BTreeSet::new();
    let _ = groups.insert(GROUP.to_string());
    let sink_identity =
        Arc::new(Identity::plaintext("sink".to_string(), groups).expect("identity"));
    let (ptx, prx) = mpsc::channel::<RoutedMessage>(64);
    let (ntx, nrx) = mpsc::channel::<RoutedMessage>(64);
    let _ = router
        .register(SessionHandle::new(sink_identity, ptx, ntx))
        .await;

    let config = CodecTcpIngressConfig {
        cn_prefix: "test-anonymous".to_string(),
        group: GROUP.to_string(),
        max_accepts_per_sec: Some(1000),
        allowed_cidrs: None,
        max_identities: 64,
        max_connections: 64,
    };
    let framing: FramingFactory =
        Arc::new(|| FramedCodec::VarintDelimited(VarintDelimitedCodec::new()));
    let shutdown = Arc::new(Notify::new());
    let shutdown_clone = Arc::clone(&shutdown);
    let task = tokio::spawn(async move {
        CodecTcpInput::run(
            listener,
            router,
            Arc::new(MockCodec),
            framing,
            "test-stream".to_string(),
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
    tokio::time::timeout(Duration::from_millis(700), async {
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
async fn valid_frames_route_with_source_protocol_tag() {
    let (local, mut prx, mut nrx, shutdown, task) = spawn_listener().await;

    let mut client = TcpStream::connect(local).await.expect("connect");
    // Two back-to-back frames in one write.
    let mut wire = frame(b"GOODone");
    wire.extend_from_slice(&frame(b"GOODtwo"));
    client.write_all(&wire).await.expect("write");

    let m1 = recv_one(&mut prx, &mut nrx)
        .await
        .expect("first frame routed");
    assert_eq!(m1.metadata.source_protocol, "test-stream");
    let m2 = recv_one(&mut prx, &mut nrx)
        .await
        .expect("second frame routed");
    assert_eq!(m2.metadata.source_protocol, "test-stream");

    shutdown.notify_one();
    let _ = tokio::time::timeout(Duration::from_secs(1), task).await;
}

#[tokio::test]
async fn frame_split_across_writes_is_reassembled() {
    let (local, mut prx, mut nrx, shutdown, task) = spawn_listener().await;

    let mut client = TcpStream::connect(local).await.expect("connect");
    let wire = frame(b"GOODsplit-payload");
    // Send the prefix+half, pause, then the rest — exercises partial reads.
    let split = wire.len() / 2;
    client
        .write_all(&wire[..split])
        .await
        .expect("write part 1");
    client.flush().await.expect("flush");
    tokio::time::sleep(Duration::from_millis(50)).await;
    client
        .write_all(&wire[split..])
        .await
        .expect("write part 2");

    let m = recv_one(&mut prx, &mut nrx)
        .await
        .expect("split frame should reassemble and route");
    assert_eq!(m.metadata.source_protocol, "test-stream");

    shutdown.notify_one();
    let _ = tokio::time::timeout(Duration::from_secs(1), task).await;
}

#[tokio::test]
async fn malformed_frame_is_dropped_but_connection_survives() {
    let (local, mut prx, mut nrx, shutdown, task) = spawn_listener().await;

    let mut client = TcpStream::connect(local).await.expect("connect");
    // A bad frame (rejected by the mock) followed by a good one on the same
    // connection: the bad frame is dropped, the good one still routes.
    let mut wire = frame(b"BADpayload");
    wire.extend_from_slice(&frame(b"GOODafter"));
    client.write_all(&wire).await.expect("write");

    let m = recv_one(&mut prx, &mut nrx)
        .await
        .expect("the good frame after a dropped one must still route");
    assert_eq!(m.metadata.source_protocol, "test-stream");
    // Only one message (the bad frame produced none).
    assert!(
        recv_one(&mut prx, &mut nrx).await.is_none(),
        "the malformed frame must not produce a routed message"
    );

    shutdown.notify_one();
    let _ = tokio::time::timeout(Duration::from_secs(1), task).await;
}

// SEC-10 (#1553): a slow-drip peer that buffers an incomplete frame and never
// completes it must be closed by the incomplete-frame cap. The per-read
// READ_TIMEOUT resets on every byte, so without a separate dwell deadline this
// peer would hold a connection — and a concurrency-cap slot — open forever.
//
// `start_paused` lets the mock clock auto-advance to the server's
// `sleep_until(INCOMPLETE_FRAME_TIMEOUT)` deadline the moment both ends park,
// so the 60s cap elapses in zero wall-clock time.
#[tokio::test(start_paused = true)]
async fn slow_drip_incomplete_frame_is_closed_by_dwell_cap() {
    let (local, mut prx, mut nrx, shutdown, task) = spawn_listener().await;

    let mut client = TcpStream::connect(local).await.expect("connect");
    // A varint length prefix promising a 50-byte body, but only 3 body bytes
    // are ever delivered. The codec reads the prefix, buffers the 3 bytes,
    // and waits forever for the remaining 47 — the partial frame never
    // completes, yet bytes *were* read, so READ_TIMEOUT never fires.
    client
        .write_all(&[50u8, b'G', b'O', b'O'])
        .await
        .expect("write partial frame");
    client.flush().await.expect("flush");

    // No frame should route (the body never arrives).
    assert!(
        recv_one(&mut prx, &mut nrx).await.is_none(),
        "an incomplete frame must not route"
    );

    // The server must close the connection once INCOMPLETE_FRAME_TIMEOUT
    // elapses. The 120s virtual bound only trips (failing the test) if the
    // close never happens — i.e. if the dwell cap regressed.
    let mut sink = [0u8; 16];
    let n = tokio::time::timeout(Duration::from_secs(120), client.read(&mut sink))
        .await
        .expect("connection must be closed by the dwell cap, not hang")
        .expect("read after server-side close");
    assert_eq!(
        n, 0,
        "server must close the slow-drip connection (observed as EOF)"
    );

    shutdown.notify_one();
    let _ = tokio::time::timeout(Duration::from_secs(1), task).await;
}

// SEC-10 regression guard: a healthy low-rate sensor — one that completes a
// frame, then idles well past INCOMPLETE_FRAME_TIMEOUT on a clean frame
// boundary, then sends another frame — must NOT be disconnected by the cap.
// (A naive "time since last completed frame" cap would wrongly kill it.) The
// dwell cap only runs while a *partial* frame is pending, so an empty buffer
// between frames is fine up to the much longer READ_TIMEOUT.
#[tokio::test(start_paused = true)]
async fn idle_between_complete_frames_is_not_closed_by_dwell_cap() {
    let (local, mut prx, mut nrx, shutdown, task) = spawn_listener().await;

    let mut client = TcpStream::connect(local).await.expect("connect");
    // First complete frame → buffer drains to a clean boundary.
    client
        .write_all(&frame(b"GOODfirst"))
        .await
        .expect("write 1");
    assert_eq!(
        recv_one(&mut prx, &mut nrx)
            .await
            .expect("first frame routes")
            .metadata
            .source_protocol,
        "test-stream",
    );

    // With nothing buffered (a clean frame boundary), the connection must NOT
    // be closed by the incomplete-frame cap no matter how long it idles, short
    // of the 5-min READ_TIMEOUT. Assert the server emits no EOF within a window
    // well past the 60s cap: a client read must still be *pending* at 180s, not
    // observe EOF. The mock clock auto-advances to the 180s deadline while both
    // ends park (this asserts a timeout, which paused time handles exactly — no
    // reliance on real-I/O delivery). A regressed time-since-frame cap would
    // close the connection at 60s and the read would return Ok(0) instead.
    let mut sink = [0u8; 16];
    let read = tokio::time::timeout(Duration::from_secs(180), client.read(&mut sink)).await;
    assert!(
        read.is_err(),
        "connection must stay open while idle past the 60s cap, but the client \
         read returned {read:?} (Ok(0) would mean the server wrongly closed it)",
    );

    shutdown.notify_one();
    let _ = tokio::time::timeout(Duration::from_secs(1), task).await;
}
