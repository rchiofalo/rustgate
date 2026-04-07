#![allow(clippy::panic, clippy::unwrap_used)]
//! Graceful drain integration tests.
//!
//! Verifies that `Router::close_all_session_senders` lets every session's
//! receiver finish draining its in-flight queued messages before observing
//! a clean EOF (`None` from `recv`). This is the core router-side primitive
//! that backs the `--shutdown-drain-timeout` graceful shutdown path.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use rustgate_core::identity::Identity;
use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};
use rustgate_transport::{
    NORMAL_CHANNEL_CAPACITY, PRIORITY_CHANNEL_CAPACITY, Router, SessionHandle,
};
use tokio::sync::mpsc;

fn make_identity(cn: &str) -> Arc<Identity> {
    Arc::new(
        Identity::new(cn.to_string(), format!("{cn}-fp"), BTreeSet::new()).expect("valid identity"),
    )
}

fn make_chat(source: &Arc<Identity>, dest: Destination, seq: usize) -> RoutableMessage {
    RoutableMessage {
        source: (**source).clone(),
        destination: dest,
        payload: Bytes::from(format!("<chat seq=\"{seq}\"/>")),
        metadata: Metadata {
            received_at: SystemTime::now(),
            source_protocol: "cot".to_string(),
            message_type: MessageType::Chat,
            ttl: None,
        },
    }
}

#[tokio::test]
async fn drain_flushes_queued_messages_before_eof() {
    let router = Arc::new(Router::new());
    let alice = make_identity("alice");
    let bob = make_identity("bob");

    let (alice_p, _alice_p_rx) = mpsc::channel(PRIORITY_CHANNEL_CAPACITY);
    let (alice_n, _alice_n_rx) = mpsc::channel(NORMAL_CHANNEL_CAPACITY);
    router
        .register(SessionHandle::new(alice.clone(), alice_p, alice_n))
        .await;

    let (bob_p, mut bob_p_rx) = mpsc::channel(PRIORITY_CHANNEL_CAPACITY);
    let (bob_n, mut bob_n_rx) = mpsc::channel(NORMAL_CHANNEL_CAPACITY);
    let bob_handle = SessionHandle::new(bob.clone(), bob_p, bob_n);
    router.register(bob_handle.clone()).await;

    // Push a healthy batch of messages to bob via the router. Stay
    // under NORMAL_CHANNEL_CAPACITY so nothing is rejected before the
    // drain begins — this models the steady-state, well-behaved client
    // case the issue cares about.
    let n: usize = NORMAL_CHANNEL_CAPACITY / 2;
    // Send directly through the SessionHandle so the test focuses on
    // the drain primitive itself without intersecting routing filters
    // (dedup, position cache, expiry, admission control). The
    // production code path also calls `handle.send` from within the
    // router after its filter chain.
    for i in 0..n {
        let msg = Arc::new(make_chat(&alice, Destination::Direct((*bob).clone()), i));
        bob_handle
            .send(rustgate_transport::RoutedMessage::new(msg))
            .await
            .expect("send must succeed before drain");
    }

    // Trigger the graceful-drain primitive: every registered session's
    // outbound senders are dropped so subsequent `recv()` calls observe
    // EOF after the queue empties.
    let closed = router.close_all_session_senders().await;
    assert!(closed >= 1, "expected at least one session to be closed");

    // Spawn a writer that mirrors the production write loop: read both
    // channels with priority bias and stop on EOF.
    let writer = tokio::spawn(async move {
        let mut delivered = 0usize;
        let mut p_open = true;
        let mut n_open = true;
        while p_open || n_open {
            tokio::select! {
                biased;
                msg = bob_p_rx.recv(), if p_open => match msg {
                    Some(_) => delivered += 1,
                    None => p_open = false,
                },
                msg = bob_n_rx.recv(), if n_open => match msg {
                    Some(_) => delivered += 1,
                    None => n_open = false,
                },
            }
        }
        delivered
    });

    let delivered = tokio::time::timeout(Duration::from_secs(5), writer)
        .await
        .expect("writer must terminate after drain")
        .expect("writer task must not panic");

    assert_eq!(
        delivered, n,
        "every queued message must be delivered before close_notify"
    );
}

#[tokio::test]
async fn drain_with_no_sessions_is_a_noop() {
    let router = Router::new();
    assert_eq!(router.close_all_session_senders().await, 0);
}
