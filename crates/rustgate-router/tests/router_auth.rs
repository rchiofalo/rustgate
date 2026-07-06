// Copyright © 2026 Roberto Chiofalo.

#![allow(unused_results)]
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
use rustgate_router::{Router, SessionHandle};
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
        metadata: Metadata::new(SystemTime::now(), "cot".to_string(), MessageType::Chat),
        entity: None,
    }
}

/// Helper: create dual-channel senders and receivers.
#[allow(clippy::type_complexity)]
fn make_channels(
    cap: usize,
) -> (
    mpsc::Sender<rustgate_router::RoutedMessage>,
    mpsc::Sender<rustgate_router::RoutedMessage>,
    mpsc::Receiver<rustgate_router::RoutedMessage>,
    mpsc::Receiver<rustgate_router::RoutedMessage>,
) {
    let (ptx, prx) = mpsc::channel(cap);
    let (ntx, nrx) = mpsc::channel(cap);
    (ptx, ntx, prx, nrx)
}

// ── Cross-group message rejection ───────────────────────────────────────

/// A client in group "Alpha" must NOT receive messages sent to group "Beta".
#[tokio::test]
async fn cross_group_message_rejected() {
    let router = Router::new();

    let alice = make_identity("alice", &["alpha"]);
    let bob = make_identity("bob", &["beta"]);

    let (ptx_a, ntx_a, _prx_a, mut nrx_a) = make_channels(16);
    let (ptx_b, ntx_b, _prx_b, _nrx_b) = make_channels(16);

    router
        .register(SessionHandle::new(alice.clone(), ptx_a, ntx_a))
        .await;
    router
        .register(SessionHandle::new(bob.clone(), ptx_b, ntx_b))
        .await;

    // Bob tries to send to group "alpha" but is only in "beta".
    let msg = make_chat(&bob, Destination::Group("alpha".into()));
    router.route(msg).await;

    assert!(
        nrx_a.try_recv().is_err(),
        "alice must not receive: bob is not in alpha"
    );
}

/// A client in "alpha" sends to "beta" — neither group's members receive.
#[tokio::test]
async fn sender_not_in_target_group_message_dropped() {
    let router = Router::new();

    let alice = make_identity("alice", &["alpha"]);
    let bob = make_identity("bob", &["beta"]);

    let (ptx_a, ntx_a, _prx_a, mut nrx_a) = make_channels(16);
    let (ptx_b, ntx_b, _prx_b, mut nrx_b) = make_channels(16);

    router
        .register(SessionHandle::new(alice.clone(), ptx_a, ntx_a))
        .await;
    router
        .register(SessionHandle::new(bob.clone(), ptx_b, ntx_b))
        .await;

    // Alice sends to "beta" but alice is only in "alpha".
    let msg = make_chat(&alice, Destination::Group("beta".into()));
    router.route(msg).await;

    assert!(
        nrx_b.try_recv().is_err(),
        "bob must not receive: alice is not in beta"
    );
    assert!(
        nrx_a.try_recv().is_err(),
        "alice must not receive own rejected message"
    );
}

// ── Unregistered session handling ───────────────────────────────────────

/// Sending a direct message to a session that does not exist must not panic.
#[tokio::test]
async fn direct_message_to_nonexistent_session_no_panic() {
    let router = Router::new();

    let alice = make_identity("alice", &["team"]);
    let (ptx_a, ntx_a, _prx_a, _nrx_a) = make_channels(16);
    router
        .register(SessionHandle::new(alice.clone(), ptx_a, ntx_a))
        .await;

    let ghost = Identity::new("ghost".to_string(), "ghost-fp".to_string(), BTreeSet::new())
        .expect("valid identity");

    let msg = RoutableMessage {
        source: (*alice).clone(),
        destination: Destination::Direct(ghost),
        payload: Bytes::from_static(b"hello?"),
        metadata: Metadata::new(SystemTime::now(), "cot".to_string(), MessageType::Chat),
        entity: None,
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
    let (ptx, ntx, _prx, _nrx) = make_channels(16);
    router
        .register(SessionHandle::new(alice.clone(), ptx, ntx))
        .await;

    // Alice is in 4 groups but limit is 2; only 2 should be registered
    assert_eq!(router.session_count().await, 1);

    // Verify by sending to each group — only 2 should have alice as a member.
    // We can't directly inspect state (private), but we can check routing behavior.
    // A member of g1 sending to g1: alice should receive if g1 was one of the 2 accepted.
    // BTreeSet ordering means g1, g2 are the first two.
    let bob = make_identity("bob", &["g1"]);
    let (ptx_b, ntx_b, _prx_b, _nrx_b) = make_channels(16);
    router
        .register(SessionHandle::new(bob.clone(), ptx_b, ntx_b))
        .await;

    // Re-register alice with a fresh channel to receive messages
    let (ptx_a2, ntx_a2, _prx_a2, mut nrx_a2) = make_channels(16);
    let alice2 = make_identity("alice", &["g1", "g2", "g3", "g4"]);
    router
        .register(SessionHandle::new(alice2.clone(), ptx_a2, ntx_a2))
        .await;

    let msg = make_chat(&bob, Destination::Group("g1".into()));
    router.route(msg).await;

    // g1 is in the first 2 groups (BTreeSet sorted), so alice should receive
    assert!(
        nrx_a2.try_recv().is_ok(),
        "alice should be in g1 (within per-CN limit)"
    );
}

/// Total group limit: once reached, new groups cannot be created.
#[tokio::test]
async fn total_group_limit_enforced() {
    let router = Router::with_limits(128, 2);

    let alice = make_identity("alice", &["g1", "g2"]);
    let (ptx_a, ntx_a, _prx_a, _nrx_a) = make_channels(16);
    router
        .register(SessionHandle::new(alice.clone(), ptx_a, ntx_a))
        .await;

    // Bob tries to join g3 — total limit (2) already reached
    let bob = make_identity("bob", &["g3"]);
    let (ptx_b, ntx_b, _prx_b, mut nrx_b) = make_channels(16);
    router
        .register(SessionHandle::new(bob.clone(), ptx_b, ntx_b))
        .await;

    // Bob sends to g3 — but g3 was never created, so nobody receives
    let msg = make_chat(&bob, Destination::Group("g3".into()));
    router.route(msg).await;
    assert!(
        nrx_b.try_recv().is_err(),
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
            let (ptx, ntx, _prx, _nrx) = make_channels(16);
            let session = SessionHandle::new(identity, ptx, ntx);
            let session_id = session.id;
            let _ = r.register(session).await;

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
            let (ptx, ntx, _prx, _nrx) = make_channels(16);
            let _ = r.register(SessionHandle::new(identity, ptx, ntx)).await;
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
    let (ptx, ntx, _prx, _nrx) = make_channels(16);
    router
        .register(SessionHandle::new(alice.clone(), ptx, ntx))
        .await;

    // Alice is the only member, and she is the sender — effectively empty
    let msg = make_chat(&alice, Destination::Group("phantom".into()));
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
    let (ptx, ntx, _prx, _nrx) = make_channels(16);
    router
        .register(SessionHandle::new(alice.clone(), ptx, ntx))
        .await;

    let msg = make_chat(&alice, Destination::Group("nonexistent".into()));
    router.route(msg).await;
}

// ── Duplicate registration ──────────────────────────────────────────────

/// Registering the same CN twice should replace the old session gracefully.
/// The new session receives messages; the old one does not.
#[tokio::test]
async fn duplicate_registration_replaces_session() {
    let router = Router::new();

    let alice = make_identity("alice", &["team"]);

    let (ptx1, ntx1, _prx1, mut nrx1) = make_channels(16);
    router
        .register(SessionHandle::new(alice.clone(), ptx1, ntx1))
        .await;

    // Register again with a new channel
    let (ptx2, ntx2, _prx2, mut nrx2) = make_channels(16);
    router
        .register(SessionHandle::new(alice.clone(), ptx2, ntx2))
        .await;

    // Only one session should exist
    assert_eq!(router.session_count().await, 1);

    // Send a broadcast from bob — only the new alice session should receive
    let bob = make_identity("bob", &["team"]);
    let (ptx_b, ntx_b, _prx_b, _nrx_b) = make_channels(16);
    router
        .register(SessionHandle::new(bob.clone(), ptx_b, ntx_b))
        .await;

    let msg = make_chat(&bob, Destination::Broadcast);
    router.route(msg).await;

    assert!(
        nrx2.try_recv().is_ok(),
        "new alice session should receive broadcast"
    );
    assert!(
        nrx1.try_recv().is_err(),
        "old alice session should not receive broadcast"
    );
}

/// Re-registering a CN should clean up old group memberships.
#[tokio::test]
async fn duplicate_registration_cleans_old_groups() {
    let router = Router::new();

    let alice_v1 = make_identity("alice", &["alpha"]);
    let (ptx1, ntx1, _prx1, _nrx1) = make_channels(16);
    router
        .register(SessionHandle::new(alice_v1.clone(), ptx1, ntx1))
        .await;

    // Alice re-registers with different groups
    let alice_v2 = make_identity("alice", &["beta"]);
    let (ptx2, ntx2, _prx2, mut nrx2) = make_channels(16);
    router
        .register(SessionHandle::new(alice_v2.clone(), ptx2, ntx2))
        .await;

    // Bob in alpha sends to alpha — alice should NOT receive (she left alpha)
    let bob = make_identity("bob", &["alpha"]);
    let (ptx_b, ntx_b, _prx_b, _nrx_b) = make_channels(16);
    router
        .register(SessionHandle::new(bob.clone(), ptx_b, ntx_b))
        .await;

    let msg = make_chat(&bob, Destination::Group("alpha".into()));
    router.route(msg).await;

    assert!(
        nrx2.try_recv().is_err(),
        "alice should not receive alpha messages after switching to beta"
    );

    // Charlie in beta sends to beta — alice should receive
    let charlie = make_identity("charlie", &["beta"]);
    let (ptx_c, ntx_c, _prx_c, _nrx_c) = make_channels(16);
    router
        .register(SessionHandle::new(charlie.clone(), ptx_c, ntx_c))
        .await;

    let msg = make_chat(&charlie, Destination::Group("beta".into()));
    router.route(msg).await;

    assert!(
        nrx2.try_recv().is_ok(),
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

    // Alice gets channels of capacity 1 — easily fills up
    let (ptx_a, ntx_a, _prx_a, _nrx_a) = make_channels(1);
    let (ptx_b, ntx_b, _prx_b, _nrx_b) = make_channels(16);

    router
        .register(SessionHandle::new(alice.clone(), ptx_a, ntx_a))
        .await;
    router
        .register(SessionHandle::new(bob.clone(), ptx_b, ntx_b))
        .await;

    // Bob sends many messages to "team" — alice's channel will overflow
    for _ in 0..10 {
        let msg = make_chat(&bob, Destination::Group("team".into()));
        router.route(msg).await;
    }

    // No panic — test passes if we reach here
}
