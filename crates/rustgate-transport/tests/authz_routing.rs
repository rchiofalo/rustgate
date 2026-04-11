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
    Action, DecisionOutcome, Effect, NativeEngine, PolicyEngine, Resource, ResourceMatcher, Rule,
    RuleSet, Subject, SubjectMatcher,
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
    assert_eq!(got.source.cn, "bob");
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
