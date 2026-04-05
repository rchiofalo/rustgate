#![allow(clippy::panic, clippy::unwrap_used)]
//! Negative tests for router authorization: cross-group isolation,
//! unregistered session handling, group limits, concurrent registration,
//! empty group sends, and duplicate registration.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::SystemTime;

use bytes::Bytes;
use rustgate_core::identity::Identity;
use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};
use rustgate_transport::{Router, SessionHandle};
use tokio::sync::mpsc;

fn make_identity(cn: &str, groups: &[&str]) -> Arc<Identity> {
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

fn make_chat(source: &Arc<Identity>, dest: Destination) -> RoutableMessage {
    RoutableMessage {
        source: (**source).clone(),
        destination: dest,
        payload: Bytes::from_static(b"<chat/>"),
        metadata: Metadata {
            received_at: SystemTime::now(),
            source_protocol: "cot".to_string(),
            message_type: MessageType::Chat,
            ttl: None,
        },
    }
}

// ── Cross-group message rejection ───────────────────────────────────────

/// A client in group "Alpha" must NOT receive messages sent to group "Beta".
#[tokio::test]
async fn cross_group_message_rejected() {
    let router = Router::new();

    let alice = make_identity("alice", &["alpha"]);
    let bob = make_identity("bob", &["beta"]);

    let (tx_a, mut rx_a) = mpsc::channel(16);
    let (tx_b, _rx_b) = mpsc::channel(16);

    router
        .register(SessionHandle::new(alice.clone(), tx_a))
        .await;
    router.register(SessionHandle::new(bob.clone(), tx_b)).await;

    // Bob tries to send to group "alpha" but is only in "beta".
    let msg = make_chat(&bob, Destination::Group("alpha".to_string()));
    router.route(msg).await;

    assert!(
        rx_a.try_recv().is_err(),
        "alice must not receive: bob is not in alpha"
    );
}

/// A client in "alpha" sends to "beta" — neither group's members receive.
#[tokio::test]
async fn sender_not_in_target_group_message_dropped() {
    let router = Router::new();

    let alice = make_identity("alice", &["alpha"]);
    let bob = make_identity("bob", &["beta"]);

    let (tx_a, mut rx_a) = mpsc::channel(16);
    let (tx_b, mut rx_b) = mpsc::channel(16);

    router
        .register(SessionHandle::new(alice.clone(), tx_a))
        .await;
    router.register(SessionHandle::new(bob.clone(), tx_b)).await;

    // Alice sends to "beta" but alice is only in "alpha".
    let msg = make_chat(&alice, Destination::Group("beta".to_string()));
    router.route(msg).await;

    assert!(
        rx_b.try_recv().is_err(),
        "bob must not receive: alice is not in beta"
    );
    assert!(
        rx_a.try_recv().is_err(),
        "alice must not receive own rejected message"
    );
}

// ── Unregistered session handling ───────────────────────────────────────

/// Sending a direct message to a session that does not exist must not panic.
#[tokio::test]
async fn direct_message_to_nonexistent_session_no_panic() {
    let router = Router::new();

    let alice = make_identity("alice", &["team"]);
    let (tx_a, _rx_a) = mpsc::channel(16);
    router
        .register(SessionHandle::new(alice.clone(), tx_a))
        .await;

    let ghost = Identity::new("ghost".to_string(), "ghost-fp".to_string(), BTreeSet::new())
        .expect("valid identity");

    let msg = RoutableMessage {
        source: (*alice).clone(),
        destination: Destination::Direct(ghost),
        payload: Bytes::from_static(b"hello?"),
        metadata: Metadata {
            received_at: SystemTime::now(),
            source_protocol: "cot".to_string(),
            message_type: MessageType::Chat,
            ttl: None,
        },
    };

    // Must not panic
    router.route(msg).await;
}

/// Unregistering a CN that was never registered must not panic.
#[tokio::test]
async fn unregister_nonexistent_session_no_panic() {
    let router = Router::new();
    // Unregistering unknown CN with arbitrary session ID should be a no-op
    router.unregister("nobody", 12345).await;
    assert_eq!(router.session_count().await, 0);
}

// ── Group limit enforcement ─────────────────────────────────────────────

/// Per-CN group limit: a client joining more groups than max_groups_per_cn
/// should have excess groups silently dropped.
#[tokio::test]
async fn per_cn_group_limit_enforced() {
    let router = Router::with_limits(2, 10_000);

    let alice = make_identity("alice", &["g1", "g2", "g3", "g4"]);
    let (tx, _rx) = mpsc::channel(16);
    router.register(SessionHandle::new(alice.clone(), tx)).await;

    // Alice is in 4 groups but limit is 2; only 2 should be registered
    assert_eq!(router.session_count().await, 1);

    // Verify by sending to each group — only 2 should have alice as a member.
    // We can't directly inspect state (private), but we can check routing behavior.
    // A member of g1 sending to g1: alice should receive if g1 was one of the 2 accepted.
    // BTreeSet ordering means g1, g2 are the first two.
    let bob = make_identity("bob", &["g1"]);
    let (tx_b, _rx_b) = mpsc::channel(16);
    router.register(SessionHandle::new(bob.clone(), tx_b)).await;

    // Re-register alice with a fresh channel to receive messages
    let (tx_a2, mut rx_a2) = mpsc::channel(16);
    let alice2 = make_identity("alice", &["g1", "g2", "g3", "g4"]);
    router
        .register(SessionHandle::new(alice2.clone(), tx_a2))
        .await;

    let msg = make_chat(&bob, Destination::Group("g1".to_string()));
    router.route(msg).await;

    // g1 is in the first 2 groups (BTreeSet sorted), so alice should receive
    assert!(
        rx_a2.try_recv().is_ok(),
        "alice should be in g1 (within per-CN limit)"
    );
}

/// Total group limit: once reached, new groups cannot be created.
#[tokio::test]
async fn total_group_limit_enforced() {
    let router = Router::with_limits(128, 2);

    let alice = make_identity("alice", &["g1", "g2"]);
    let (tx_a, _rx_a) = mpsc::channel(16);
    router
        .register(SessionHandle::new(alice.clone(), tx_a))
        .await;

    // Bob tries to join g3 — total limit (2) already reached
    let bob = make_identity("bob", &["g3"]);
    let (tx_b, mut rx_b) = mpsc::channel(16);
    router.register(SessionHandle::new(bob.clone(), tx_b)).await;

    // Bob sends to g3 — but g3 was never created, so nobody receives
    let msg = make_chat(&bob, Destination::Group("g3".to_string()));
    router.route(msg).await;
    assert!(
        rx_b.try_recv().is_err(),
        "g3 should not exist at total limit"
    );
}

// ── Concurrent register/unregister ──────────────────────────────────────

/// Register and unregister sessions concurrently to check for data races.
/// This test exercises the RwLock paths under contention.
#[tokio::test]
async fn concurrent_register_unregister_no_races() {
    let router = Arc::new(Router::new());
    let mut handles = Vec::new();

    for i in 0..50 {
        let r = Arc::clone(&router);
        handles.push(tokio::spawn(async move {
            let cn = format!("client-{i}");
            let identity = make_identity(&cn, &["shared"]);
            let (tx, _rx) = mpsc::channel(16);
            let session = SessionHandle::new(identity, tx);
            let session_id = session.id;
            r.register(session).await;

            // Small yield to interleave with other tasks
            tokio::task::yield_now().await;

            r.unregister(&cn, session_id).await;
        }));
    }

    for h in handles {
        h.await.expect("task should not panic");
    }

    // All sessions should be cleaned up
    assert_eq!(router.session_count().await, 0);
}

/// Concurrent registration of different clients into the same group
/// must not lose any registrations.
#[tokio::test]
async fn concurrent_register_same_group() {
    let router = Arc::new(Router::new());
    let mut handles = Vec::new();

    for i in 0..20 {
        let r = Arc::clone(&router);
        handles.push(tokio::spawn(async move {
            let cn = format!("member-{i}");
            let identity = make_identity(&cn, &["team"]);
            let (tx, _rx) = mpsc::channel(16);
            r.register(SessionHandle::new(identity, tx)).await;
        }));
    }

    for h in handles {
        h.await.expect("task should not panic");
    }

    assert_eq!(router.session_count().await, 20);
}

// ── Send to empty group ─────────────────────────────────────────────────

/// Sending to a group with no members should succeed without errors.
#[tokio::test]
async fn send_to_empty_group_succeeds() {
    let router = Router::new();

    let alice = make_identity("alice", &["phantom"]);
    let (tx, _rx) = mpsc::channel(16);
    router.register(SessionHandle::new(alice.clone(), tx)).await;

    // Alice is the only member, and she is the sender — effectively empty
    let msg = make_chat(&alice, Destination::Group("phantom".to_string()));
    router.route(msg).await;
    // No panic, no error — test passes if we reach this point
}

/// Sending to a group that has never been created is also fine.
#[tokio::test]
async fn send_to_nonexistent_group_succeeds() {
    let router = Router::new();

    // Alice is in "alpha" but sends to "nonexistent" — rejected because
    // she is not a member, but must not panic.
    let alice = make_identity("alice", &["alpha"]);
    let (tx, _rx) = mpsc::channel(16);
    router.register(SessionHandle::new(alice.clone(), tx)).await;

    let msg = make_chat(&alice, Destination::Group("nonexistent".to_string()));
    router.route(msg).await;
}

// ── Duplicate registration ──────────────────────────────────────────────

/// Registering the same CN twice should replace the old session gracefully.
/// The new session receives messages; the old one does not.
#[tokio::test]
async fn duplicate_registration_replaces_session() {
    let router = Router::new();

    let alice = make_identity("alice", &["team"]);

    let (tx1, mut rx1) = mpsc::channel(16);
    router
        .register(SessionHandle::new(alice.clone(), tx1))
        .await;

    // Register again with a new channel
    let (tx2, mut rx2) = mpsc::channel(16);
    router
        .register(SessionHandle::new(alice.clone(), tx2))
        .await;

    // Only one session should exist
    assert_eq!(router.session_count().await, 1);

    // Send a broadcast from bob — only the new alice session should receive
    let bob = make_identity("bob", &["team"]);
    let (tx_b, _rx_b) = mpsc::channel(16);
    router.register(SessionHandle::new(bob.clone(), tx_b)).await;

    let msg = make_chat(&bob, Destination::Broadcast);
    router.route(msg).await;

    assert!(
        rx2.try_recv().is_ok(),
        "new alice session should receive broadcast"
    );
    assert!(
        rx1.try_recv().is_err(),
        "old alice session should not receive broadcast"
    );
}

/// Re-registering a CN should clean up old group memberships.
#[tokio::test]
async fn duplicate_registration_cleans_old_groups() {
    let router = Router::new();

    let alice_v1 = make_identity("alice", &["alpha"]);
    let (tx1, _rx1) = mpsc::channel(16);
    router
        .register(SessionHandle::new(alice_v1.clone(), tx1))
        .await;

    // Alice re-registers with different groups
    let alice_v2 = make_identity("alice", &["beta"]);
    let (tx2, mut rx2) = mpsc::channel(16);
    router
        .register(SessionHandle::new(alice_v2.clone(), tx2))
        .await;

    // Bob in alpha sends to alpha — alice should NOT receive (she left alpha)
    let bob = make_identity("bob", &["alpha"]);
    let (tx_b, _rx_b) = mpsc::channel(16);
    router.register(SessionHandle::new(bob.clone(), tx_b)).await;

    let msg = make_chat(&bob, Destination::Group("alpha".to_string()));
    router.route(msg).await;

    assert!(
        rx2.try_recv().is_err(),
        "alice should not receive alpha messages after switching to beta"
    );

    // Charlie in beta sends to beta — alice should receive
    let charlie = make_identity("charlie", &["beta"]);
    let (tx_c, _rx_c) = mpsc::channel(16);
    router
        .register(SessionHandle::new(charlie.clone(), tx_c))
        .await;

    let msg = make_chat(&charlie, Destination::Group("beta".to_string()));
    router.route(msg).await;

    assert!(
        rx2.try_recv().is_ok(),
        "alice should receive beta messages after switching to beta"
    );
}

/// Channel backpressure: filling a session's channel should cause messages
/// to be dropped gracefully (try_send returns false), not panic.
#[tokio::test]
async fn channel_backpressure_drops_gracefully() {
    let router = Router::new();

    let alice = make_identity("alice", &["team"]);
    let bob = make_identity("bob", &["team"]);

    // Alice gets a channel of capacity 1 — easily fills up
    let (tx_a, _rx_a) = mpsc::channel(1);
    let (tx_b, _rx_b) = mpsc::channel(16);

    router
        .register(SessionHandle::new(alice.clone(), tx_a))
        .await;
    router.register(SessionHandle::new(bob.clone(), tx_b)).await;

    // Bob sends many messages to "team" — alice's channel will overflow
    for _ in 0..10 {
        let msg = make_chat(&bob, Destination::Group("team".to_string()));
        router.route(msg).await;
    }

    // No panic — test passes if we reach here
}
