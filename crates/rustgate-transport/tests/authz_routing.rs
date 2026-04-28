// Copyright © 2026 Roberto Chiofalo.

#![allow(unused_results)]
#![allow(clippy::panic, clippy::unwrap_used)]
//! Integration tests for the rustgate-authz PolicyEngine wired into
//! `Router::route`. Covers the acceptance scenarios:
//!
//! 1. no engine installed → routing behaves as before
//! 2. engine that allows everything → all messages flow
//! 3. engine that denies sends to a specific group → message dropped
//! 4. engine that denies one recipient on Receive → other recipients
//!    still get the message
//! 5. `swap_authz` mid-flight → the new engine takes effect atomically
//! 6. direct unicast honours per-recipient Receive deny
//! 7. broadcast honours per-recipient Receive deny
//! 8. store-forward drain re-evaluates authz after policy change
//! 9. store-forward drain allows delivery when policy permits

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::SystemTime;

use bytes::Bytes;
use rustgate_core::identity::Identity;
use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};
use rustgate_transport::rustgate_authz::{
    Action, Decision, DecisionOutcome, Effect, NativeEngine, Obligation, PolicyEngine, Resource,
    ResourceMatcher, Rule, RuleSet, Subject, SubjectMatcher,
};
use rustgate_transport::{Router, SessionHandle};
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

#[allow(clippy::type_complexity)]
fn channels() -> (
    mpsc::Sender<rustgate_transport::RoutedMessage>,
    mpsc::Sender<rustgate_transport::RoutedMessage>,
    mpsc::Receiver<rustgate_transport::RoutedMessage>,
    mpsc::Receiver<rustgate_transport::RoutedMessage>,
) {
    let (ptx, prx) = mpsc::channel(16);
    let (ntx, nrx) = mpsc::channel(16);
    (ptx, ntx, prx, nrx)
}

fn chat(source: &Arc<Identity>, dest: Destination) -> RoutableMessage {
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

fn rule(id: &str, effect: Effect, action: Action, resource: ResourceMatcher) -> Rule {
    Rule {
        id: smol_str::SmolStr::new(id),
        effect,
        action,
        resource,
        subject: SubjectMatcher::default(),
        obligations: Vec::new(),
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

fn deny_send_group_engine(group: &str) -> Arc<dyn PolicyEngine> {
    let rules = RuleSet {
        version: 1,
        default_effect: Effect::Allow,
        rules: vec![rule(
            "deny-send-group",
            Effect::Deny,
            Action::Send,
            ResourceMatcher::Group {
                group: group.to_string(),
            },
        )],
    };
    Arc::new(NativeEngine::new(rules).expect("compile"))
}

/// A hand-rolled engine that denies `Receive` for one specific recipient CN.
/// The builtin matcher AST evaluates the subject of the evaluation call;
/// in `send_to_group` the router runs a per-recipient pass that builds the
/// subject from the recipient's own `Identity`, so a subject `cn_eq` rule
/// is the natural way to express "do not deliver to CN X".
fn deny_receive_for_cn(cn: &str) -> Arc<dyn PolicyEngine> {
    let rules = RuleSet {
        version: 1,
        default_effect: Effect::Allow,
        rules: vec![Rule {
            id: smol_str::SmolStr::new("deny-recv-cn"),
            effect: Effect::Deny,
            action: Action::Receive,
            resource: ResourceMatcher::Any,
            subject: SubjectMatcher {
                cn_eq: Some(cn.to_string()),
                ..SubjectMatcher::default()
            },
            obligations: Vec::new(),
        }],
    };
    Arc::new(NativeEngine::new(rules).expect("compile"))
}

/// Engine that denies everything. Useful for mid-flight swap.
struct DenyAllEngine;
impl PolicyEngine for DenyAllEngine {
    fn evaluate(&self, _s: &Subject<'_>, _r: &Resource<'_>, _a: Action) -> DecisionOutcome {
        DecisionOutcome::deny()
    }
    fn policy_id(&self) -> &str {
        "deny-all"
    }
}

#[tokio::test]
async fn no_engine_installed_behaves_as_before() {
    let router = Router::new();
    let alice = identity("alice", &["alpha"]);
    let bob = identity("bob", &["alpha"]);

    let (ptx_a, ntx_a, _pa, mut nrx_a) = channels();
    let (ptx_b, ntx_b, _pb, _nb) = channels();
    router
        .register(SessionHandle::new(alice.clone(), ptx_a, ntx_a))
        .await;
    router
        .register(SessionHandle::new(bob.clone(), ptx_b, ntx_b))
        .await;

    router
        .route(chat(&bob, Destination::Group("alpha".into())))
        .await;
    let got = nrx_a.try_recv().expect("alice should receive");
    assert_eq!(&*got.source.cn, "bob");
}

#[tokio::test]
async fn allow_all_engine_permits_flow() {
    let router = Router::new().with_authz(allow_all_engine());
    let alice = identity("alice", &["alpha"]);
    let bob = identity("bob", &["alpha"]);

    let (ptx_a, ntx_a, _pa, mut nrx_a) = channels();
    let (ptx_b, ntx_b, _pb, _nb) = channels();
    router
        .register(SessionHandle::new(alice.clone(), ptx_a, ntx_a))
        .await;
    router
        .register(SessionHandle::new(bob.clone(), ptx_b, ntx_b))
        .await;

    router
        .route(chat(&bob, Destination::Group("alpha".into())))
        .await;
    assert!(nrx_a.try_recv().is_ok());
}

#[tokio::test]
async fn deny_send_on_group_drops_message() {
    let router = Router::new().with_authz(deny_send_group_engine("alpha"));
    let alice = identity("alice", &["alpha"]);
    let bob = identity("bob", &["alpha"]);

    let (ptx_a, ntx_a, _pa, mut nrx_a) = channels();
    let (ptx_b, ntx_b, _pb, _nb) = channels();
    router
        .register(SessionHandle::new(alice.clone(), ptx_a, ntx_a))
        .await;
    router
        .register(SessionHandle::new(bob.clone(), ptx_b, ntx_b))
        .await;

    router
        .route(chat(&bob, Destination::Group("alpha".into())))
        .await;
    assert!(
        nrx_a.try_recv().is_err(),
        "policy denies send to alpha; alice must not receive"
    );
}

#[tokio::test]
async fn deny_receive_for_one_recipient_only() {
    let router = Router::new().with_authz(deny_receive_for_cn("charlie"));
    let alice = identity("alice", &["alpha"]);
    let bob = identity("bob", &["alpha"]);
    let charlie = identity("charlie", &["alpha"]);

    let (ptx_a, ntx_a, _pa, mut nrx_a) = channels();
    let (ptx_b, ntx_b, _pb, _nb) = channels();
    let (ptx_c, ntx_c, _pc, mut nrx_c) = channels();
    router
        .register(SessionHandle::new(alice.clone(), ptx_a, ntx_a))
        .await;
    router
        .register(SessionHandle::new(bob.clone(), ptx_b, ntx_b))
        .await;
    router
        .register(SessionHandle::new(charlie.clone(), ptx_c, ntx_c))
        .await;

    router
        .route(chat(&bob, Destination::Group("alpha".into())))
        .await;

    assert!(nrx_a.try_recv().is_ok(), "alice allowed: should receive");
    assert!(
        nrx_c.try_recv().is_err(),
        "charlie is denied Receive and must not see the message"
    );
}

#[tokio::test]
async fn swap_authz_takes_effect_mid_flight() {
    let router = Router::new().with_authz(allow_all_engine());
    let alice = identity("alice", &["alpha"]);
    let bob = identity("bob", &["alpha"]);

    let (ptx_a, ntx_a, _pa, mut nrx_a) = channels();
    let (ptx_b, ntx_b, _pb, _nb) = channels();
    router
        .register(SessionHandle::new(alice.clone(), ptx_a, ntx_a))
        .await;
    router
        .register(SessionHandle::new(bob.clone(), ptx_b, ntx_b))
        .await;

    // First message with allow-all engine.
    router
        .route(chat(&bob, Destination::Group("alpha".into())))
        .await;
    assert!(nrx_a.try_recv().is_ok());

    // Swap to deny-all and try again.
    router.swap_authz(Arc::new(DenyAllEngine));
    router
        .route(chat(&bob, Destination::Group("alpha".into())))
        .await;
    assert!(
        nrx_a.try_recv().is_err(),
        "after swap to deny-all, the message must be dropped"
    );

    // Clearing should restore routing.
    router.clear_authz();
    router
        .route(chat(&bob, Destination::Group("alpha".into())))
        .await;
    assert!(nrx_a.try_recv().is_ok());
}

/// Direct unicast must honour a per-recipient Receive deny. Without a
/// Receive PEP in `send_to_session`, a rule that denies `charlie` from
/// receiving any direct message would silently be ignored — the sender
/// side Send PEP cannot know about recipient-side attributes.
#[tokio::test]
async fn deny_receive_blocks_direct_unicast() {
    let router = Router::new().with_authz(deny_receive_for_cn("charlie"));
    let alice = identity("alice", &["alpha"]);
    let charlie = identity("charlie", &["alpha"]);

    let (ptx_a, ntx_a, _pa, _na) = channels();
    let (ptx_c, ntx_c, _pc, mut nrx_c) = channels();
    router
        .register(SessionHandle::new(alice.clone(), ptx_a, ntx_a))
        .await;
    router
        .register(SessionHandle::new(charlie.clone(), ptx_c, ntx_c))
        .await;

    // Alice sends a direct message to Charlie. The send PEP allows it
    // (alice is not the denied subject), but the recipient-side Receive
    // PEP must filter Charlie out.
    router
        .route(chat(&alice, Destination::Direct((*charlie).clone())))
        .await;

    assert!(
        nrx_c.try_recv().is_err(),
        "charlie is denied Receive on direct unicast and must not see the message"
    );
}

/// Broadcast must honour a per-recipient Receive deny. Without a Receive
/// PEP in `send_to_all`, a broadcast-specific deny rule for one CN would
/// silently be ignored.
#[tokio::test]
async fn deny_receive_blocks_broadcast_per_recipient() {
    let router = Router::new().with_authz(deny_receive_for_cn("charlie"));
    let alice = identity("alice", &["alpha"]);
    let bob = identity("bob", &["alpha"]);
    let charlie = identity("charlie", &["alpha"]);

    let (ptx_a, ntx_a, _pa, mut nrx_a) = channels();
    let (ptx_b, ntx_b, _pb, _nb) = channels();
    let (ptx_c, ntx_c, _pc, mut nrx_c) = channels();
    router
        .register(SessionHandle::new(alice.clone(), ptx_a, ntx_a))
        .await;
    router
        .register(SessionHandle::new(bob.clone(), ptx_b, ntx_b))
        .await;
    router
        .register(SessionHandle::new(charlie.clone(), ptx_c, ntx_c))
        .await;

    router.route(chat(&bob, Destination::Broadcast)).await;

    assert!(
        nrx_a.try_recv().is_ok(),
        "alice allowed: should receive broadcast"
    );
    assert!(
        nrx_c.try_recv().is_err(),
        "charlie is denied Receive and must not see the broadcast"
    );
}

/// Messages queued via store-forward while no policy was active must be
/// filtered out when a deny policy is installed before the drain runs.
/// This proves that `filter_offline_messages` re-evaluates the *current*
/// engine, not the one in effect at storage time.
#[tokio::test]
async fn store_forward_drain_re_evaluates_authz_after_policy_change() {
    use rustgate_transport::ClientQueue;

    let tmp = tempfile::TempDir::new().unwrap();
    let queue = std::sync::Arc::new(ClientQueue::open(tmp.path(), 1_000_000).unwrap());

    // Start with NO authz engine so the message is accepted by the Send PEP.
    let router = Router::new().with_client_queue(std::sync::Arc::clone(&queue));
    let alice = identity("alice", &["alpha"]);
    let bob = identity("bob", &["alpha"]);

    // Route a direct message to bob while bob is offline. The router
    // persists it to the store-forward queue.
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

    // Now install a deny-all policy BEFORE draining.
    router.swap_authz(Arc::new(DenyAllEngine));

    // Drain and filter: the deny-all engine must block the stored message
    // even though it was accepted at storage time.
    let drained = router.drain_offline_messages("bob").await;
    assert_eq!(drained.len(), 1, "drain returns the raw stored message");

    let filtered = router.filter_offline_messages(&bob, drained);
    assert!(
        filtered.is_empty(),
        "policy change after storage must block delivery on drain"
    );
}

/// Complement of the deny test: messages queued while a deny policy was
/// active and then drained after clearing the policy must be delivered.
/// This confirms that `filter_offline_messages` uses the *current*
/// engine snapshot, not a stale one.
#[tokio::test]
async fn store_forward_drain_allows_delivery_when_policy_permits() {
    use rustgate_transport::ClientQueue;

    let tmp = tempfile::TempDir::new().unwrap();
    let queue = std::sync::Arc::new(ClientQueue::open(tmp.path(), 1_000_000).unwrap());

    // Start with allow-all so the Send PEP lets the message through.
    let router = Router::new()
        .with_authz(allow_all_engine())
        .with_client_queue(std::sync::Arc::clone(&queue));
    let alice = identity("alice", &["alpha"]);
    let bob = identity("bob", &["alpha"]);

    router
        .route(chat(&alice, Destination::Direct((*bob).clone())))
        .await;

    for _ in 0..200 {
        if queue.stats("bob").depth == 1 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(queue.stats("bob").depth, 1);

    // Policy stays allow-all — drain should pass the filter.
    let drained = router.drain_offline_messages("bob").await;
    let filtered = router.filter_offline_messages(&bob, drained);
    assert_eq!(
        filtered.len(),
        1,
        "allow-all policy must permit delivery of queued messages"
    );
}

// ---------------------------------------------------------------------------
// Obligation actuation (MaskPoint / MaskPayload / TagClassified)
// ---------------------------------------------------------------------------

const SAMPLE_COT: &[u8] = br#"<event uid="u1" type="a-f-G-U-C" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z"><point lat="38.8977" lon="-77.0365" hae="125.4"/></event>"#;

fn position(source: &Arc<Identity>, dest: Destination) -> RoutableMessage {
    RoutableMessage {
        source: (**source).clone(),
        destination: dest,
        payload: Bytes::from_static(SAMPLE_COT),
        metadata: Metadata {
            received_at: SystemTime::now(),
            source_protocol: "cot".to_string(),
            message_type: MessageType::Position,
            ttl: None,
        },
    }
}

/// Allow every decision, attaching `obligations` on the given `action` only.
/// Other actions return a plain allow so Send and Receive can be shaped
/// independently (e.g. receive-side masking without affecting the sender's
/// Send PEP outcome).
struct AllowWithObligationEngine {
    target_action: Action,
    obligations: Vec<Obligation>,
}

impl PolicyEngine for AllowWithObligationEngine {
    fn evaluate(&self, _s: &Subject<'_>, _r: &Resource<'_>, a: Action) -> DecisionOutcome {
        let obligations = if a == self.target_action {
            self.obligations.clone()
        } else {
            Vec::new()
        };
        DecisionOutcome {
            decision: Decision::Allow,
            rule_id: Some(smol_str::SmolStr::new("test-obligation")),
            obligations,
        }
    }
    fn policy_id(&self) -> &str {
        "test-obligation"
    }
}

fn allow_with_obligation(action: Action, obligation: Obligation) -> Arc<dyn PolicyEngine> {
    Arc::new(AllowWithObligationEngine {
        target_action: action,
        obligations: vec![obligation],
    })
}

/// Recipient-side `MaskPoint` on a group message must zero the CoT
/// `<point>` coordinates before delivery. The sender is unaffected
/// because the router fans out a per-recipient copy.
#[tokio::test]
async fn allow_with_mask_point_for_receive_masks_group_payload() {
    let router = Router::new().with_authz(allow_with_obligation(
        Action::Receive,
        Obligation::MaskPoint,
    ));
    let alice = identity("alice", &["alpha"]);
    let bob = identity("bob", &["alpha"]);

    let (ptx_a, ntx_a, mut prx_a, _na) = channels();
    let (ptx_b, ntx_b, _pb, _nb) = channels();
    router
        .register(SessionHandle::new(alice.clone(), ptx_a, ntx_a))
        .await;
    router
        .register(SessionHandle::new(bob.clone(), ptx_b, ntx_b))
        .await;

    router
        .route(position(&bob, Destination::Group("alpha".into())))
        .await;

    let got = prx_a.try_recv().expect("alice should receive");
    let s = std::str::from_utf8(&got.payload).expect("masked payload is valid UTF-8");
    assert!(s.contains(r#"lat="0.0""#), "lat not zeroed: {s}");
    assert!(s.contains(r#"lon="0.0""#), "lon not zeroed: {s}");
    assert!(!s.contains("38.8977"), "raw lat leaked: {s}");
}

/// Recipient-side `MaskPayload` on a direct unicast must strip the body
/// and coerce the classified message type to `other:masked`, but still
/// deliver the envelope so downstream UIs can render a placeholder.
#[tokio::test]
async fn allow_with_mask_payload_for_receive_strips_direct_body() {
    let router = Router::new().with_authz(allow_with_obligation(
        Action::Receive,
        Obligation::MaskPayload,
    ));
    let alice = identity("alice", &["alpha"]);
    let charlie = identity("charlie", &["alpha"]);

    let (ptx_a, ntx_a, _pa, _na) = channels();
    // MaskPayload coerces message_type to `other:masked`, so the message
    // is routed on the *normal* channel even though the source was a
    // position. The coercion happens inside the router's Receive PEP
    // per-recipient; the classification at try_send time reflects the
    // masked type.
    let (ptx_c, ntx_c, mut prx_c, mut nrx_c) = channels();
    router
        .register(SessionHandle::new(alice.clone(), ptx_a, ntx_a))
        .await;
    router
        .register(SessionHandle::new(charlie.clone(), ptx_c, ntx_c))
        .await;

    router
        .route(position(&alice, Destination::Direct((*charlie).clone())))
        .await;

    // The router classifies priority based on the pre-obligation message
    // type (Position), so the delivery still lands on the priority
    // channel — but the copy carries an emptied body with coerced type.
    let got = prx_c
        .try_recv()
        .or_else(|_| nrx_c.try_recv())
        .expect("charlie should receive on priority or normal channel");
    assert!(
        got.payload.is_empty(),
        "payload must be wiped by MaskPayload"
    );
    assert_eq!(
        got.metadata.message_type,
        MessageType::Other("masked".into()),
        "message type must be coerced to other:masked"
    );
    // Envelope fields preserved for downstream rendering.
    assert_eq!(&*got.source.cn, "alice");
}

/// Broadcast must apply `MaskPoint` on Receive per-recipient without
/// mutating the sender's in-flight copy (each recipient gets an
/// independently-masked envelope).
#[tokio::test]
async fn allow_with_mask_point_on_broadcast_masks_each_recipient() {
    let router = Router::new().with_authz(allow_with_obligation(
        Action::Receive,
        Obligation::MaskPoint,
    ));
    let alice = identity("alice", &["alpha"]);
    let bob = identity("bob", &["alpha"]);
    let charlie = identity("charlie", &["alpha"]);

    let (ptx_a, ntx_a, mut prx_a, _na) = channels();
    let (ptx_b, ntx_b, _pb, _nb) = channels();
    let (ptx_c, ntx_c, mut prx_c, _nc) = channels();
    router
        .register(SessionHandle::new(alice.clone(), ptx_a, ntx_a))
        .await;
    router
        .register(SessionHandle::new(bob.clone(), ptx_b, ntx_b))
        .await;
    router
        .register(SessionHandle::new(charlie.clone(), ptx_c, ntx_c))
        .await;

    router.route(position(&bob, Destination::Broadcast)).await;

    let got_a = prx_a.try_recv().expect("alice should receive");
    let got_c = prx_c.try_recv().expect("charlie should receive");
    for (who, got) in [("alice", &got_a), ("charlie", &got_c)] {
        let s = std::str::from_utf8(&got.payload).expect("masked payload is valid UTF-8");
        assert!(s.contains(r#"lat="0.0""#), "{who}: lat not zeroed: {s}");
        assert!(!s.contains("38.8977"), "{who}: raw lat leaked: {s}");
    }
}

/// Position replay on reconnect must re-apply the current Receive
/// obligations — a recipient who can no longer see raw coordinates in
/// the live stream must not receive them via SA replay either.
#[tokio::test]
async fn position_replay_applies_mask_point_obligation() {
    // Step 1: cache a position with no authz engine (so cache.store fires).
    let router = Router::new();
    let alice = identity("alice", &["alpha"]);
    let bob = identity("bob", &["alpha"]);

    let (ptx_a, ntx_a, _pa, _na) = channels();
    router
        .register(SessionHandle::new(alice.clone(), ptx_a, ntx_a))
        .await;
    router.route(position(&alice, Destination::Broadcast)).await;

    // Step 2: install a MaskPoint-on-Receive policy, then replay to bob.
    router.swap_authz(allow_with_obligation(
        Action::Receive,
        Obligation::MaskPoint,
    ));
    let (ptx_b, ntx_b, mut prx_b, _nb) = channels();
    let bob_handle = SessionHandle::new(bob.clone(), ptx_b, ntx_b);
    router.replay_positions(&bob_handle).await;

    let got = prx_b.try_recv().expect("bob should receive replay");
    let s = std::str::from_utf8(&got.payload).expect("masked payload is valid UTF-8");
    assert!(s.contains(r#"lat="0.0""#), "replay not masked: {s}");
    assert!(!s.contains("38.8977"), "raw lat leaked through replay: {s}");
}

/// Store-forward drain must apply per-recipient obligations when
/// delivering queued messages. A policy change while the client was
/// offline — adding `MaskPayload` on Receive — must take effect on
/// drain, not just on live fan-out.
#[tokio::test]
async fn store_forward_drain_applies_mask_payload_obligation() {
    use rustgate_transport::ClientQueue;

    let tmp = tempfile::TempDir::new().unwrap();
    let queue = std::sync::Arc::new(ClientQueue::open(tmp.path(), 1_000_000).unwrap());

    // Queue a direct message with no authz engine active.
    let router = Router::new().with_client_queue(std::sync::Arc::clone(&queue));
    let alice = identity("alice", &["alpha"]);
    let bob = identity("bob", &["alpha"]);

    router
        .route(position(&alice, Destination::Direct((*bob).clone())))
        .await;

    for _ in 0..200 {
        if queue.stats("bob").depth == 1 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(queue.stats("bob").depth, 1);

    // Install MaskPayload-on-Receive and drain.
    router.swap_authz(allow_with_obligation(
        Action::Receive,
        Obligation::MaskPayload,
    ));
    let drained = router.drain_offline_messages("bob").await;
    let filtered = router.filter_offline_messages(&bob, drained);

    assert_eq!(filtered.len(), 1, "message must survive allow decision");
    let msg = filtered[0].message();
    assert!(msg.payload.is_empty(), "drain must apply MaskPayload");
    assert_eq!(
        msg.metadata.message_type,
        MessageType::Other("masked".into())
    );
}

/// `TagClassified` is an audit-only obligation: the dispatcher must not
/// touch the payload or metadata. The audit record emission itself is
/// verified indirectly through the router's `audit_classified_receive`
/// helper; here we prove the wire payload passes through unchanged.
#[tokio::test]
async fn tag_classified_does_not_mutate_payload() {
    let router = Router::new().with_authz(allow_with_obligation(
        Action::Receive,
        Obligation::TagClassified,
    ));
    let alice = identity("alice", &["alpha"]);
    let bob = identity("bob", &["alpha"]);

    let (ptx_a, ntx_a, mut prx_a, _na) = channels();
    let (ptx_b, ntx_b, _pb, _nb) = channels();
    router
        .register(SessionHandle::new(alice.clone(), ptx_a, ntx_a))
        .await;
    router
        .register(SessionHandle::new(bob.clone(), ptx_b, ntx_b))
        .await;

    router
        .route(position(&bob, Destination::Group("alpha".into())))
        .await;

    let got = prx_a.try_recv().expect("alice should receive");
    assert_eq!(
        got.payload.as_ref(),
        SAMPLE_COT,
        "payload must be untouched"
    );
    assert_eq!(got.metadata.message_type, MessageType::Position);
}

/// Send-side `MaskPoint` is applied once on the envelope before fan-out,
/// so every recipient on a broadcast sees the same masked copy.
#[tokio::test]
async fn send_side_mask_point_masks_before_fanout() {
    let router =
        Router::new().with_authz(allow_with_obligation(Action::Send, Obligation::MaskPoint));
    let alice = identity("alice", &["alpha"]);
    let bob = identity("bob", &["alpha"]);
    let charlie = identity("charlie", &["alpha"]);

    let (ptx_a, ntx_a, mut prx_a, _na) = channels();
    let (ptx_b, ntx_b, _pb, _nb) = channels();
    let (ptx_c, ntx_c, mut prx_c, _nc) = channels();
    router
        .register(SessionHandle::new(alice.clone(), ptx_a, ntx_a))
        .await;
    router
        .register(SessionHandle::new(bob.clone(), ptx_b, ntx_b))
        .await;
    router
        .register(SessionHandle::new(charlie.clone(), ptx_c, ntx_c))
        .await;

    router.route(position(&bob, Destination::Broadcast)).await;

    for (who, rx) in [("alice", &mut prx_a), ("charlie", &mut prx_c)] {
        let got = rx
            .try_recv()
            .unwrap_or_else(|_| panic!("{who} should receive"));
        let s = std::str::from_utf8(&got.payload).expect("masked payload is valid UTF-8");
        assert!(
            s.contains(r#"lat="0.0""#),
            "{who}: send-side mask not applied: {s}"
        );
        assert!(!s.contains("38.8977"), "{who}: raw lat leaked: {s}");
    }
}

// ---------------------------------------------------------------------------
// Audit fidelity: classified_delivery must only fire on successful delivery
// ---------------------------------------------------------------------------

/// When `try_send` fails (channel full or session closed), the router must
/// NOT emit an `authz.classified_delivery` audit record. Emitting one
/// anyway would misrepresent a dropped message as a delivered tagged copy
/// — forensically worse than a missing record because a compliance
/// reviewer would see a tag for material the recipient never observed.
///
/// The drain path (`filter_offline_messages`) owns the audit record for
/// store-forward redelivery at live-delivery time, so a channel-full
/// persistence path that later drains + delivers still produces exactly
/// one classified_delivery record per actual on-the-wire delivery.
#[tokio::test(flavor = "current_thread")]
async fn classified_delivery_audit_skipped_when_try_send_fails() {
    use std::io::Write;
    use std::sync::Mutex;

    use tracing_subscriber::Layer;
    use tracing_subscriber::filter::Targets;
    use tracing_subscriber::fmt::MakeWriter;
    use tracing_subscriber::layer::SubscriberExt;

    #[derive(Clone, Default)]
    struct SharedBuf(Arc<Mutex<Vec<u8>>>);
    impl SharedBuf {
        fn snapshot(&self) -> String {
            let g = self.0.lock().unwrap();
            String::from_utf8_lossy(&g).into_owned()
        }
    }
    impl Write for SharedBuf {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl<'a> MakeWriter<'a> for SharedBuf {
        type Writer = SharedBuf;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    let buf = SharedBuf::default();
    let layer = tracing_subscriber::fmt::layer()
        .json()
        .with_writer(buf.clone())
        .with_filter(Targets::new().with_target("audit", tracing::Level::INFO));
    let subscriber = tracing_subscriber::registry().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    // TagClassified on Receive: a successful delivery emits exactly one
    // `authz.classified_delivery` audit record per recipient. A failed
    // delivery must emit none — that is the invariant under test.
    let router = Router::new().with_authz(allow_with_obligation(
        Action::Receive,
        Obligation::TagClassified,
    ));
    let alice = identity("alice", &["alpha"]);
    let bob = identity("bob", &["alpha"]);

    // Recipient channels sized 1 and pre-filled, so the next `try_send`
    // by the router into either channel fails with "full".
    let (ptx_b, ntx_b, _prx_b, _nrx_b) = {
        let (ptx, prx) = mpsc::channel(1);
        let (ntx, nrx) = mpsc::channel(1);
        // Saturate the normal channel. Chat is non-priority, so
        // `send_to_session` routes into this one.
        ntx.try_send(rustgate_transport::RoutedMessage::from(Arc::new(chat(
            &alice,
            Destination::Direct((*bob).clone()),
        ))))
        .expect("pre-fill should succeed");
        // Also saturate the priority channel so the classification path
        // cannot fall back to it for any message variant.
        ptx.try_send(rustgate_transport::RoutedMessage::from(Arc::new(chat(
            &alice,
            Destination::Direct((*bob).clone()),
        ))))
        .expect("pre-fill should succeed");
        (ptx, ntx, prx, nrx)
    };
    router
        .register(SessionHandle::new(bob.clone(), ptx_b, ntx_b))
        .await;

    // Route a direct message — delivery must fail with both bob channels
    // already at capacity. The audit emission is deferred until after a
    // successful `try_send`, so no classified_delivery line should land
    // in the buffer.
    router
        .route(chat(&alice, Destination::Direct((*bob).clone())))
        .await;

    let captured = buf.snapshot();
    assert!(
        !captured.contains("\"event_type\":\"authz.classified_delivery\""),
        "classified_delivery audit must not fire when try_send drops the \
         message; captured: {captured}"
    );
}

/// Converse of the above: a successful delivery DOES emit exactly one
/// `authz.classified_delivery` audit record per on-the-wire recipient.
/// Paired with the "skipped when try_send fails" test, this pins the
/// invariant: audit fidelity = delivery count, not policy-decision count.
#[tokio::test(flavor = "current_thread")]
async fn classified_delivery_audit_fires_on_successful_delivery() {
    use std::io::Write;
    use std::sync::Mutex;

    use tracing_subscriber::Layer;
    use tracing_subscriber::filter::Targets;
    use tracing_subscriber::fmt::MakeWriter;
    use tracing_subscriber::layer::SubscriberExt;

    #[derive(Clone, Default)]
    struct SharedBuf(Arc<Mutex<Vec<u8>>>);
    impl SharedBuf {
        fn snapshot(&self) -> String {
            let g = self.0.lock().unwrap();
            String::from_utf8_lossy(&g).into_owned()
        }
    }
    impl Write for SharedBuf {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl<'a> MakeWriter<'a> for SharedBuf {
        type Writer = SharedBuf;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    let buf = SharedBuf::default();
    let layer = tracing_subscriber::fmt::layer()
        .json()
        .with_writer(buf.clone())
        .with_filter(Targets::new().with_target("audit", tracing::Level::INFO));
    let subscriber = tracing_subscriber::registry().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    let router = Router::new().with_authz(allow_with_obligation(
        Action::Receive,
        Obligation::TagClassified,
    ));
    let alice = identity("alice", &["alpha"]);
    let bob = identity("bob", &["alpha"]);

    let (ptx_b, ntx_b, _pb, mut nrx_b) = channels();
    router
        .register(SessionHandle::new(bob.clone(), ptx_b, ntx_b))
        .await;

    router
        .route(chat(&alice, Destination::Direct((*bob).clone())))
        .await;

    // Drain the delivery so the assertion cannot race the emit.
    let _ = nrx_b.recv().await.expect("bob should receive");

    let captured = buf.snapshot();
    assert!(
        captured.contains("\"event_type\":\"authz.classified_delivery\""),
        "successful delivery must emit classified_delivery audit; captured: {captured}"
    );
}

// ---------------------------------------------------------------------------
// Audit fidelity regression tests for every Receive PEP fan-out site.
//
// The invariant under test is identical at every site:
//
//     audit.classified_delivery fires iff try_send succeeded.
//
// A failed try_send (channel full or session closed) must NOT produce an
// `authz.classified_delivery` record, because that record documents an
// actual on-the-wire classified delivery — forensically worse to log a
// delivery that never happened than to omit one that did.
//
// Each of the four tests below saturates the recipient's channels before
// routing a classified-tagged copy and asserts the audit buffer remains
// empty of any classified_delivery line. They cover the four live Receive
// PEP sites plus the offline drain path:
//
//   1. `send_to_group`            (Destination::Group)
//   2. `send_to_all`              (Destination::Broadcast)
//   3. `send_to_group_excluding`  (Destination::Multicast)
//   4. `filter_offline_messages`  (store-forward drain)
// ---------------------------------------------------------------------------

/// Shared audit-capture helper. Installed as a thread-local tracing
/// subscriber filtered to the `audit` target so tests can assert on
/// exactly the audit records that fired during the test body.
mod audit_capture {
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    use tracing_subscriber::Layer;
    use tracing_subscriber::filter::Targets;
    use tracing_subscriber::fmt::MakeWriter;
    use tracing_subscriber::layer::SubscriberExt;

    #[derive(Clone, Default)]
    pub(super) struct SharedBuf(pub Arc<Mutex<Vec<u8>>>);
    impl SharedBuf {
        pub(super) fn snapshot(&self) -> String {
            let g = self.0.lock().expect("buf lock");
            String::from_utf8_lossy(&g).into_owned()
        }
    }
    impl Write for SharedBuf {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("buf lock").extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl<'a> MakeWriter<'a> for SharedBuf {
        type Writer = SharedBuf;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// Install a JSON-formatted audit-only subscriber on the current
    /// thread. The returned guard must outlive the test body.
    pub(super) fn install() -> (SharedBuf, tracing::subscriber::DefaultGuard) {
        let buf = SharedBuf::default();
        let layer = tracing_subscriber::fmt::layer()
            .json()
            .with_writer(buf.clone())
            .with_filter(Targets::new().with_target("audit", tracing::Level::INFO));
        let subscriber = tracing_subscriber::registry().with(layer);
        let guard = tracing::subscriber::set_default(subscriber);
        (buf, guard)
    }
}

/// `send_to_group` must not emit `authz.classified_delivery` when the
/// per-recipient `try_send` fails. A saturated recipient channel is a
/// drop, not a delivery, and the audit trail must reflect that.
#[tokio::test(flavor = "current_thread")]
async fn group_send_classified_delivery_audit_skipped_when_try_send_fails() {
    let (buf, _guard) = audit_capture::install();

    let router = Router::new().with_authz(allow_with_obligation(
        Action::Receive,
        Obligation::TagClassified,
    ));
    let alice = identity("alice", &["alpha"]);
    let bob = identity("bob", &["alpha"]);

    // Bob's recipient channels sized 1 and pre-filled so the next
    // `try_send` by the router into either will fail.
    let (ptx_b, prx_b) = mpsc::channel(1);
    let (ntx_b, nrx_b) = mpsc::channel(1);
    ntx_b
        .try_send(rustgate_transport::RoutedMessage::from(Arc::new(chat(
            &alice,
            Destination::Group("alpha".into()),
        ))))
        .expect("pre-fill normal");
    ptx_b
        .try_send(rustgate_transport::RoutedMessage::from(Arc::new(chat(
            &alice,
            Destination::Group("alpha".into()),
        ))))
        .expect("pre-fill priority");
    // Keep receivers alive so the senders stay open — the router needs
    // the channel to be full, not closed, to exercise the drop path.
    let _prx_b = prx_b;
    let _nrx_b = nrx_b;
    router
        .register(SessionHandle::new(bob.clone(), ptx_b, ntx_b))
        .await;

    router
        .route(chat(&alice, Destination::Group("alpha".into())))
        .await;

    let captured = buf.snapshot();
    assert!(
        !captured.contains("\"event_type\":\"authz.classified_delivery\""),
        "group send must not audit classified_delivery on saturated try_send; \
         captured: {captured}"
    );
}

/// `send_to_all` (broadcast) must not emit `authz.classified_delivery`
/// when a recipient's `try_send` fails. Broadcast fan-out with a slow
/// consumer would otherwise produce phantom classified-delivery records
/// for every dropped recipient.
#[tokio::test(flavor = "current_thread")]
async fn broadcast_classified_delivery_audit_skipped_when_try_send_fails() {
    let (buf, _guard) = audit_capture::install();

    let router = Router::new().with_authz(allow_with_obligation(
        Action::Receive,
        Obligation::TagClassified,
    ));
    let alice = identity("alice", &["alpha"]);
    let bob = identity("bob", &["alpha"]);

    let (ptx_b, prx_b) = mpsc::channel(1);
    let (ntx_b, nrx_b) = mpsc::channel(1);
    ntx_b
        .try_send(rustgate_transport::RoutedMessage::from(Arc::new(chat(
            &alice,
            Destination::Broadcast,
        ))))
        .expect("pre-fill normal");
    ptx_b
        .try_send(rustgate_transport::RoutedMessage::from(Arc::new(chat(
            &alice,
            Destination::Broadcast,
        ))))
        .expect("pre-fill priority");
    let _prx_b = prx_b;
    let _nrx_b = nrx_b;
    router
        .register(SessionHandle::new(bob.clone(), ptx_b, ntx_b))
        .await;

    router.route(chat(&alice, Destination::Broadcast)).await;

    let captured = buf.snapshot();
    assert!(
        !captured.contains("\"event_type\":\"authz.classified_delivery\""),
        "broadcast must not audit classified_delivery on saturated try_send; \
         captured: {captured}"
    );
}

/// `send_to_group_excluding` (multicast fan-out) must not emit
/// `authz.classified_delivery` when the per-recipient `try_send` fails.
/// Multicast walks each target group in turn; a saturated recipient in
/// the first group must not be tagged as delivered, and a subsequent
/// group delivery attempt must also not tag a failed drop.
#[tokio::test(flavor = "current_thread")]
async fn multicast_classified_delivery_audit_skipped_when_try_send_fails() {
    let (buf, _guard) = audit_capture::install();

    let router = Router::new().with_authz(allow_with_obligation(
        Action::Receive,
        Obligation::TagClassified,
    ));
    // Both identities are members of both groups so the cross-group
    // multicast sender check (`msg.source.is_member_of(group)`) passes
    // on both hops without the router short-circuiting before the
    // try_send under test.
    let alice = identity("alice", &["alpha", "bravo"]);
    let bob = identity("bob", &["alpha", "bravo"]);

    let (ptx_b, prx_b) = mpsc::channel(1);
    let (ntx_b, nrx_b) = mpsc::channel(1);
    ntx_b
        .try_send(rustgate_transport::RoutedMessage::from(Arc::new(chat(
            &alice,
            Destination::Multicast(vec!["alpha".into(), "bravo".into()]),
        ))))
        .expect("pre-fill normal");
    ptx_b
        .try_send(rustgate_transport::RoutedMessage::from(Arc::new(chat(
            &alice,
            Destination::Multicast(vec!["alpha".into(), "bravo".into()]),
        ))))
        .expect("pre-fill priority");
    let _prx_b = prx_b;
    let _nrx_b = nrx_b;
    router
        .register(SessionHandle::new(bob.clone(), ptx_b, ntx_b))
        .await;

    router
        .route(chat(
            &alice,
            Destination::Multicast(vec!["alpha".into(), "bravo".into()]),
        ))
        .await;

    let captured = buf.snapshot();
    assert!(
        !captured.contains("\"event_type\":\"authz.classified_delivery\""),
        "multicast must not audit classified_delivery on saturated try_send; \
         captured: {captured}"
    );
}

/// Store-forward drain must not emit `authz.classified_delivery` until
/// the caller explicitly calls [`PendingAudit::emit_on_delivered`]. If
/// the caller drops the `PendingAudit` (e.g. because `SessionHandle::send`
/// returned an error), no audit record may fire — the on-the-wire
/// delivery never happened.
///
/// This test also pins the positive half of the contract: when the
/// caller does call `emit_on_delivered`, exactly one classified_delivery
/// audit record lands in the buffer.
#[tokio::test(flavor = "current_thread")]
async fn drain_classified_delivery_audit_driven_by_emit_on_delivered() {
    use rustgate_transport::ClientQueue;

    let (buf, _guard) = audit_capture::install();

    let tmp = tempfile::TempDir::new().expect("tempdir");
    let queue = Arc::new(ClientQueue::open(tmp.path(), 1_000_000).expect("open queue"));
    let router = Router::new()
        .with_client_queue(Arc::clone(&queue))
        .with_authz(allow_with_obligation(
            Action::Receive,
            Obligation::TagClassified,
        ));

    let alice = identity("alice", &["alpha"]);
    let bob = identity("bob", &["alpha"]);

    router
        .route(chat(&alice, Destination::Direct((*bob).clone())))
        .await;
    for _ in 0..200 {
        if queue.stats("bob").depth == 1 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(queue.stats("bob").depth, 1, "message must be queued");

    // Negative half: drain + filter, then drop the PendingAudit without
    // calling emit_on_delivered. Simulates the caller's send failing and
    // the pending audit falling out of scope.
    let drained = router.drain_offline_messages("bob").await;
    let filtered = router.filter_offline_messages(&bob, drained);
    assert_eq!(filtered.len(), 1, "drain must yield one pending delivery");
    {
        let (_msg, _audit) = filtered
            .into_iter()
            .next()
            .expect("one pending")
            .into_parts();
        // `_audit` (PendingAudit) drops here without emit_on_delivered —
        // exactly the code path that must NOT fire an audit record.
    }
    let captured_after_drop = buf.snapshot();
    assert!(
        !captured_after_drop.contains("\"event_type\":\"authz.classified_delivery\""),
        "dropping PendingAudit without emit_on_delivered must not audit; \
         captured: {captured_after_drop}"
    );

    // Positive half: re-persist the same message (first drain popped it
    // off the queue), drain again, and this time call emit_on_delivered.
    // Exactly one classified_delivery record must land.
    router
        .route(chat(&alice, Destination::Direct((*bob).clone())))
        .await;
    for _ in 0..200 {
        if queue.stats("bob").depth == 1 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let drained = router.drain_offline_messages("bob").await;
    let filtered = router.filter_offline_messages(&bob, drained);
    assert_eq!(filtered.len(), 1, "second drain must yield one pending");
    for pending in filtered {
        let (_msg, audit) = pending.into_parts();
        audit.emit_on_delivered();
    }
    let captured_after_emit = buf.snapshot();
    let emit_hits = captured_after_emit
        .matches("\"event_type\":\"authz.classified_delivery\"")
        .count();
    assert_eq!(
        emit_hits, 1,
        "emit_on_delivered must fire exactly one classified_delivery audit; \
         captured: {captured_after_emit}"
    );
}

// ---------------------------------------------------------------------------
// Federation defense-in-depth (issue #719)
//
// Messages received from a federation peer enter the router via the
// `on_inbound` callback in `rustgate-server::setup`, which constructs a
// `RoutableMessage` with `source_protocol = "federation"` and hands it to
// `router.route()`. The wire protocol does NOT carry authz obligations, so
// obligation actuation depends entirely on the local PEP chain re-running.
//
// These tests pin the guarantee documented in `docs/federation.md` — that
// the local Receive-PEP is authoritative for every federated message,
// regardless of what the upstream peer did. Asymmetric policies between
// federation peers (stricter local policy, permissive upstream) must not
// degrade to the less-strict peer.
// ---------------------------------------------------------------------------

/// Build a RoutableMessage that looks like it arrived via the federation
/// inbound path: `source_protocol = "federation"` and a broadcast
/// destination (the shape produced by `on_inbound` in
/// `rustgate-server::setup`). The source CN is the federation peer's CN.
fn federated_position(peer_source: &Arc<Identity>) -> RoutableMessage {
    RoutableMessage {
        source: (**peer_source).clone(),
        destination: Destination::Broadcast,
        payload: Bytes::from_static(SAMPLE_COT),
        metadata: Metadata {
            received_at: SystemTime::now(),
            source_protocol: "federation".to_string(),
            message_type: MessageType::Position,
            ttl: None,
        },
    }
}

/// A federated broadcast must have the local `MaskPoint` Receive
/// obligation applied per recipient — even though the upstream peer
/// may have allowed delivery without masking.
///
/// This is the core defense-in-depth guarantee of issue #719: the
/// federation wire protocol does not carry obligations, so the local
/// PEP is the only line of defense against a permissive upstream.
#[tokio::test]
async fn federated_broadcast_applies_local_mask_point_receive() {
    let router = Router::new().with_authz(allow_with_obligation(
        Action::Receive,
        Obligation::MaskPoint,
    ));
    // Simulate a federation peer identity — what `on_inbound` constructs
    // from the peer certificate CN via `Identity::plaintext`.
    let peer = identity("federation-peer-1", &[]);
    let alice = identity("alice", &["alpha"]);

    let (ptx_a, ntx_a, mut prx_a, _na) = channels();
    router
        .register(SessionHandle::new(alice.clone(), ptx_a, ntx_a))
        .await;

    router.route(federated_position(&peer)).await;

    let got = prx_a
        .try_recv()
        .expect("alice should receive the federated broadcast");
    let s = std::str::from_utf8(&got.payload).expect("masked payload is valid UTF-8");
    assert!(
        s.contains(r#"lat="0.0""#),
        "local MaskPoint Receive obligation must apply to federated message: {s}"
    );
    assert!(
        !s.contains("38.8977"),
        "raw lat from upstream leaked despite local MaskPoint: {s}"
    );
    assert_eq!(
        got.metadata.source_protocol, "federation",
        "source_protocol must be preserved — downstream sinks still need to know the origin"
    );
}

/// A federated broadcast must have the local `MaskPayload` Receive
/// obligation applied per recipient. This is stricter than MaskPoint —
/// it zeros the entire payload — and must take effect even when the
/// upstream peer forwarded an unmasked body.
#[tokio::test]
async fn federated_broadcast_applies_local_mask_payload_receive() {
    let router = Router::new().with_authz(allow_with_obligation(
        Action::Receive,
        Obligation::MaskPayload,
    ));
    let peer = identity("federation-peer-1", &[]);
    let alice = identity("alice", &["alpha"]);

    // MaskPayload coerces message type to `other:masked`, so the
    // classifier routes the copy to the normal channel rather than the
    // priority channel that Position normally takes.
    let (ptx_a, ntx_a, mut prx_a, mut nrx_a) = channels();
    router
        .register(SessionHandle::new(alice.clone(), ptx_a, ntx_a))
        .await;

    router.route(federated_position(&peer)).await;

    let got = prx_a
        .try_recv()
        .or_else(|_| nrx_a.try_recv())
        .expect("alice should receive the federated broadcast on priority or normal channel");
    assert!(
        got.payload.is_empty(),
        "local MaskPayload Receive obligation must zero the federated payload"
    );
    assert_eq!(
        got.metadata.message_type,
        MessageType::Other("masked".into()),
        "MaskPayload must coerce message type even on federated messages"
    );
}

/// A federated broadcast must honour per-recipient Receive deny rules.
/// A denied recipient gets no delivery; an allowed peer on the same
/// broadcast still receives it. This verifies the PEP runs per
/// recipient with the recipient's identity as subject — the upstream
/// peer's identity does not override local per-recipient rules.
#[tokio::test]
async fn federated_broadcast_respects_per_recipient_receive_deny() {
    let router = Router::new().with_authz(deny_receive_for_cn("charlie"));
    let peer = identity("federation-peer-1", &[]);
    let alice = identity("alice", &["alpha"]);
    let charlie = identity("charlie", &["alpha"]);

    let (ptx_a, ntx_a, mut prx_a, _na) = channels();
    let (ptx_c, ntx_c, mut prx_c, _nc) = channels();
    router
        .register(SessionHandle::new(alice.clone(), ptx_a, ntx_a))
        .await;
    router
        .register(SessionHandle::new(charlie.clone(), ptx_c, ntx_c))
        .await;

    router.route(federated_position(&peer)).await;

    // Alice is allowed, Charlie is denied — regardless of what the
    // upstream federation peer's policy said.
    assert!(
        prx_a.try_recv().is_ok(),
        "alice should receive the federated broadcast"
    );
    assert!(
        prx_c.try_recv().is_err(),
        "charlie must be filtered by local Receive deny, even for federated messages"
    );
}
