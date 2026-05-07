// Copyright © 2026 Roberto Chiofalo.

#![allow(clippy::panic, clippy::unwrap_used)]
//! Integration tests for store-forward authorization re-evaluation.
//!
//! When messages are stored for an offline session and the authz policy
//! changes before the session reconnects, `filter_offline_messages` must
//! re-evaluate the policy at delivery time and drop messages that are no
//! longer permitted.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::SystemTime;

use bytes::Bytes;
use rustgate_authz::{
    Action, DecisionOutcome, Effect, NativeEngine, PolicyEngine, Resource, RuleSet, Subject,
};
use rustgate_core::identity::Identity;
use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};
use rustgate_router::{ClientQueue, Router, SessionHandle};
use tempfile::TempDir;
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
    }
}

fn allow_all_engine() -> Arc<dyn PolicyEngine> {
    let rules = RuleSet {
        version: 1,
        default_effect: Effect::Allow,
        rules: Vec::new(),
    };
    Arc::new(NativeEngine::new(rules).expect("compile"))
}

/// Engine that denies everything.
struct DenyAllEngine;
impl PolicyEngine for DenyAllEngine {
    fn evaluate(&self, _s: &Subject<'_>, _r: &Resource<'_>, _a: Action) -> DecisionOutcome {
        DecisionOutcome::deny()
    }
    fn policy_id(&self) -> &str {
        "deny-all"
    }
}

// ── Stored message denied after policy change ──────────────────────────

/// Store a message for an offline recipient under an allow-all policy,
/// then swap to a deny-all policy before the recipient reconnects.
/// The message must be filtered out and NOT delivered during drain.
#[tokio::test]
async fn stored_message_denied_after_policy_change() {
    let tmp = TempDir::new().expect("tempdir");
    let queue = Arc::new(ClientQueue::open(tmp.path(), 1_000_000).expect("open queue"));
    let router = Router::new()
        .with_client_queue(Arc::clone(&queue))
        .with_authz(allow_all_engine());

    let alice = identity("alice", &["alpha"]);
    let bob = identity("bob", &["alpha"]);

    // Route a direct message to bob while bob is offline.
    // The message is persisted to the store-forward queue.
    router
        .route(chat(&alice, Destination::Direct((*bob).clone())))
        .await;

    // Wait for the async writer task to persist the message.
    for _ in 0..200 {
        if queue.stats("bob").depth == 1 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(queue.stats("bob").depth, 1, "message must be queued");

    // Swap to deny-all policy before bob reconnects.
    router.swap_authz(Arc::new(DenyAllEngine));

    // Drain offline messages and filter through current policy.
    let drained = router.drain_offline_messages("bob").await;
    assert_eq!(drained.len(), 1, "raw drain should return the message");

    let filtered = router.filter_offline_messages(&bob, drained);
    assert!(
        filtered.is_empty(),
        "after policy swap to deny-all, the stored message must be filtered out"
    );
}

// ── Stored message delivered when policy allows ────────────────────────

/// Same setup as above but keep the permissive policy active. The
/// message must be delivered successfully during drain.
#[tokio::test]
async fn stored_message_delivered_when_policy_allows() {
    let tmp = TempDir::new().expect("tempdir");
    let queue = Arc::new(ClientQueue::open(tmp.path(), 1_000_000).expect("open queue"));
    let router = Router::new()
        .with_client_queue(Arc::clone(&queue))
        .with_authz(allow_all_engine());

    let alice = identity("alice", &["alpha"]);
    let bob = identity("bob", &["alpha"]);

    // Route a direct message to bob while bob is offline.
    router
        .route(chat(&alice, Destination::Direct((*bob).clone())))
        .await;

    // Wait for the async writer task to persist the message.
    for _ in 0..200 {
        if queue.stats("bob").depth == 1 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(queue.stats("bob").depth, 1, "message must be queued");

    // Policy remains allow-all: drain and filter should pass the message.
    let drained = router.drain_offline_messages("bob").await;
    assert_eq!(drained.len(), 1, "raw drain should return the message");

    let filtered = router.filter_offline_messages(&bob, drained);
    assert_eq!(
        filtered.len(),
        1,
        "with allow-all policy, the stored message must pass filtering"
    );

    // Deliver the filtered messages through a session handle.
    let (ptx_b, _prx_b) = mpsc::channel(16);
    let (ntx_b, mut nrx_b) = mpsc::channel(16);
    let handle = SessionHandle::new(bob.clone(), ptx_b, ntx_b);

    let _ = router.register(handle.clone()).await;
    for pending in filtered {
        let (msg, audit) = pending.into_parts();
        handle
            .send(Arc::new(msg))
            .await
            .expect("deliver offline msg");
        audit.emit_on_delivered();
    }

    let received = nrx_b.try_recv().expect("bob should receive the message");
    assert_eq!(received.payload.as_ref(), b"<chat/>");
}
