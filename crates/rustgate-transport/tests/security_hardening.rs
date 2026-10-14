// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

#![allow(clippy::panic, clippy::unwrap_used)]
//! Security hardening integration tests: slow consumer isolation and
//! circuit breaker disconnect.
//!
//! These tests verify that per-session backpressure prevents a single
//! slow consumer from blocking delivery to other sessions, and that
//! the circuit breaker disconnects persistently slow sessions.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::SystemTime;

use bytes::Bytes;
use rustgate_core::identity::Identity;
use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};
use rustgate_router::{RoutedMessage, Router, SessionHandle};
use tokio::sync::mpsc;

fn identity(cn: &str, groups: &[&str]) -> Arc<Identity> {
    Arc::new(
        Identity::new(
            cn.to_string(),
            format!("{cn}-fp"),
            groups
                .iter()
                .map(|g| g.to_string())
                .collect::<BTreeSet<_>>(),
        )
        .expect("valid identity"),
    )
}

fn chat(source: &Arc<Identity>, dest: Destination) -> RoutableMessage {
    RoutableMessage {
        source: (**source).clone(),
        destination: dest,
        payload: Bytes::from_static(b"<chat/>"),
        metadata: Metadata::new(SystemTime::now(), "cot".to_string(), MessageType::Chat),
        entity: None,
    }
}

// ── Slow consumer cannot block other sessions ──────────────────────────

/// Register two sessions (alice, bob) in the same group. Fill alice's
/// channel to capacity so she cannot receive any more messages. Send a
/// group message. Verify that bob still receives the message (non-blocking
/// delivery via try_send) and that alice's message is dropped rather than
/// blocking the routing task.
#[tokio::test]
async fn slow_consumer_cannot_block_other_sessions() {
    let router = Router::new();

    let alice = identity("alice", &["team"]);
    let bob = identity("bob", &["team"]);
    let sender = identity("sender", &["team"]);

    // Alice gets a tiny normal channel (capacity 1) that will fill up
    let (ptx_a, _prx_a) = mpsc::channel::<RoutedMessage>(16);
    let (ntx_a, mut nrx_a) = mpsc::channel::<RoutedMessage>(1);

    // Bob gets a normal-sized channel
    let (ptx_b, _prx_b) = mpsc::channel::<RoutedMessage>(16);
    let (ntx_b, mut nrx_b) = mpsc::channel::<RoutedMessage>(16);

    let _ = router
        .register(SessionHandle::new(alice.clone(), ptx_a, ntx_a))
        .await;
    let _ = router
        .register(SessionHandle::new(bob.clone(), ptx_b, ntx_b))
        .await;

    // Fill alice's normal channel to capacity so subsequent sends drop
    router
        .route(chat(&sender, Destination::Group("team".into())))
        .await;

    // Alice's channel (capacity 1) is now full. Send another group
    // message. This must NOT block: bob should still receive it.
    router
        .route(chat(&sender, Destination::Group("team".into())))
        .await;

    // Bob must have received both messages
    let msg1 = nrx_b.try_recv().expect("bob should receive first message");
    assert_eq!(&*msg1.source.cn, "sender");
    let msg2 = nrx_b.try_recv().expect("bob should receive second message");
    assert_eq!(&*msg2.source.cn, "sender");

    // Alice received one (capacity 1) and the second was dropped
    let alice_msg = nrx_a
        .try_recv()
        .expect("alice should receive first message");
    assert_eq!(&*alice_msg.source.cn, "sender");
    // The second message should have been dropped (channel was full)
    assert!(
        nrx_a.try_recv().is_err(),
        "alice's second message should be dropped because her channel was full"
    );
}

// ── Circuit breaker disconnects persistently slow session ──────────────

/// Register a session with a small channel capacity and a low circuit
/// breaker threshold. Send enough messages to trip the breaker. Verify
/// that the session's receiver gets `None` (channel closed), indicating
/// the circuit breaker disconnected the session.
#[tokio::test]
async fn circuit_breaker_disconnects_persistently_slow_session() {
    let router = Router::new();

    let slow = identity("slow-consumer", &["team"]);
    let sender = identity("sender", &["team"]);

    // Capacity 1, circuit breaker threshold of 3: after 3 consecutive
    // failed sends the session is disconnected.
    let (ptx, _prx) = mpsc::channel::<RoutedMessage>(1);
    let (ntx, mut nrx) = mpsc::channel::<RoutedMessage>(1);

    let handle = SessionHandle::with_drop_threshold(slow.clone(), ptx, ntx, 3);
    let _ = router.register(handle.clone()).await;

    // First message fills the channel (capacity 1)
    router
        .route(chat(&sender, Destination::Group("team".into())))
        .await;

    // Next 3 attempts should fail (channel full), tripping breaker on 3rd
    for _ in 0..3 {
        router
            .route(chat(&sender, Destination::Group("team".into())))
            .await;
    }

    // Drain the one message that was successfully delivered
    let msg = nrx.try_recv().expect("should receive the first message");
    assert_eq!(&*msg.source.cn, "sender");

    // After the circuit breaker trips, the channel is closed.
    // Subsequent recv should return None (channel closed).
    assert!(
        handle.is_closed(),
        "circuit breaker should have tripped and closed the session channels"
    );

    // Verify the receiver sees the channel as closed
    assert!(
        nrx.try_recv().is_err(),
        "no more messages should be available after circuit breaker trip"
    );
}
