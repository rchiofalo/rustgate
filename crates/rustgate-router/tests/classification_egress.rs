// Copyright © 2026 Roberto Chiofalo.

#![allow(unused_results)]
#![allow(clippy::panic, clippy::unwrap_used)]
//! Integration tests for the per-recipient classification-marking
//! enforcement at egress (refs #849, items 3 + 4).
//!
//! Coverage map (per the umbrella issue's test plan):
//!
//! 1. `egress_filters_recipient_when_classification_dominates_their_clearance`
//! 2. `egress_admits_recipient_when_clearance_dominates_classification`
//! 3. `egress_with_classification_none_preserves_legacy_behavior`
//! 4. `mandatory_marking_rejects_inbound_without_classification`
//! 5. `mandatory_marking_admits_inbound_with_classification`
//! 6. `default_classification_applied_to_inbound_via_listener_flag`
//!    (covered by the `Metadata::with_classification` builder + the
//!    `MessageBuilder` patches; pin via the round-trip test in
//!    `rustgate-core::message::tests` and the wire-format test below)
//! 7. `classification_denied_audit_event_fires_with_correct_fields`
//! 8. `classification_obligation_demotion_via_inject_marking_works_at_boundary`

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::SystemTime;

use bytes::Bytes;
use rustgate_authz::{
    Action, AuthzContext, DecisionOutcome, Effect, NativeEngine, Obligation, PolicyEngine,
    Resource, ResourceMatcher, Rule, RuleSet, Subject, SubjectMatcher,
};
use rustgate_core::classification::{Classification, ClassificationMarking};
use rustgate_core::identity::Identity;
use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};
use rustgate_router::{Router, SessionHandle};
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
    mpsc::Sender<rustgate_router::RoutedMessage>,
    mpsc::Sender<rustgate_router::RoutedMessage>,
    mpsc::Receiver<rustgate_router::RoutedMessage>,
    mpsc::Receiver<rustgate_router::RoutedMessage>,
) {
    let (ptx, prx) = mpsc::channel(16);
    let (ntx, nrx) = mpsc::channel(16);
    (ptx, ntx, prx, nrx)
}

fn chat(source: &Arc<Identity>, dest: Destination) -> RoutableMessage {
    RoutableMessage {
        source: (**source).clone(),
        destination: dest,
        payload: Bytes::from_static(
            b"<event uid=\"u1\" type=\"a-f-G-U-C\"><detail><contact callsign=\"A\"/></detail></event>",
        ),
        metadata: Metadata::new(SystemTime::now(), "cot".to_string(), MessageType::Chat),
        entity: None,
    }
}

fn chat_with_marking(
    source: &Arc<Identity>,
    dest: Destination,
    marking: ClassificationMarking,
) -> RoutableMessage {
    let mut msg = chat(source, dest);
    msg.metadata = msg.metadata.with_classification(marking);
    msg
}

/// Engine that denies Receive when the message carries a classification
/// marking dominating `//UNCLASSIFIED`. Implements the AuthzContext
/// `evaluate_with_context` hook directly so the test does not depend on
/// the optional `cedar` feature.
struct ClearanceUnclassEngine;

impl PolicyEngine for ClearanceUnclassEngine {
    fn evaluate(&self, _s: &Subject<'_>, _r: &Resource<'_>, _a: Action) -> DecisionOutcome {
        // Without context, behave as a permit-all engine: this lets the
        // legacy-traffic test (no marking on Metadata) pass through.
        DecisionOutcome::allow()
    }

    fn evaluate_with_context(
        &self,
        _s: &Subject<'_>,
        _r: &Resource<'_>,
        action: Action,
        context: &AuthzContext,
    ) -> DecisionOutcome {
        // Only deny on the Receive side when a marking is present and
        // dominates `//UNCLASSIFIED`. Send-side stays Allow so the
        // sender never gets an early deny and the message reaches the
        // per-recipient fan-out.
        if !matches!(action, Action::Receive) {
            return DecisionOutcome::allow();
        }
        let Some(marking) = context.classification.as_ref() else {
            return DecisionOutcome::allow();
        };
        let unclass = ClassificationMarking::new(Classification::Unclassified);
        if marking.dominates(&unclass) && marking.classification > Classification::Unclassified {
            DecisionOutcome::deny()
        } else {
            DecisionOutcome::allow()
        }
    }

    fn policy_id(&self) -> &str {
        "clearance-unclass"
    }
}

/// Engine that always allows but injects a `MaskPoint` obligation when
/// a marking is present. Used by the legacy-behavior test to confirm
/// that messages without classification skip context-aware paths.
fn allow_all_engine() -> Arc<dyn PolicyEngine> {
    let rules = RuleSet {
        version: 1,
        default_effect: Effect::Allow,
        rules: Vec::new(),
    };
    Arc::new(NativeEngine::new(rules).expect("compile"))
}

/// Engine that admits all traffic AND attaches an `InjectMarking`
/// obligation on Send for the demotion-at-boundary test.
fn inject_marking_engine(marking: &str) -> Arc<dyn PolicyEngine> {
    let rules = RuleSet {
        version: 1,
        default_effect: Effect::Allow,
        rules: vec![Rule {
            id: smol_str::SmolStr::new("inject-marking-on-send"),
            effect: Effect::Allow,
            action: Action::Send,
            resource: ResourceMatcher::Any,
            subject: SubjectMatcher::default(),
            obligations: vec![Obligation::InjectMarking {
                marking: marking.to_string(),
            }],
        }],
    };
    Arc::new(NativeEngine::new(rules).expect("compile"))
}

// ── Test 5: //SECRET → //UNCLASSIFIED group recipient is filtered ───

#[tokio::test]
async fn egress_filters_recipient_when_classification_dominates_their_clearance() {
    // The recipient's policy denies receive when the marking dominates
    // //UNCLASSIFIED. A //SECRET marking on the source message must
    // cause the recipient to be filtered out — no message delivered.
    let router = Router::new().with_authz(Arc::new(ClearanceUnclassEngine));
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

    let secret_marking = ClassificationMarking::new(Classification::Secret);
    router
        .route(chat_with_marking(
            &bob,
            Destination::Group("alpha".into()),
            secret_marking,
        ))
        .await;

    // Allow the dispatch loop to drain.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(
        nrx_a.try_recv().is_err(),
        "alice (clearance //UNCLASSIFIED) must NOT receive a //SECRET message"
    );
}

// ── Test 6: //UNCLASSIFIED is admitted ─────────────────────────────

#[tokio::test]
async fn egress_admits_recipient_when_clearance_dominates_classification() {
    // An //UNCLASSIFIED marking does not dominate //UNCLASSIFIED in
    // the strict sense, so the engine returns Allow and the message
    // is delivered. (Equivalent to the deny test but flipped.)
    let router = Router::new().with_authz(Arc::new(ClearanceUnclassEngine));
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

    let unclass_marking = ClassificationMarking::new(Classification::Unclassified);
    router
        .route(chat_with_marking(
            &bob,
            Destination::Group("alpha".into()),
            unclass_marking,
        ))
        .await;

    let received = nrx_a.try_recv().expect("alice must receive //UNCLASSIFIED");
    assert_eq!(&*received.source.cn, "bob");
}

// ── Test 7: legacy traffic (no marking) flows unchanged ─────────────

#[tokio::test]
async fn egress_with_classification_none_preserves_legacy_behavior() {
    // A message without `Metadata.classification` is the pre-#849
    // shape. The engine's context-aware path returns Allow because
    // `context.classification` is None — the recipient is delivered.
    let router = Router::new().with_authz(Arc::new(ClearanceUnclassEngine));
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

    // No `with_classification` — the legacy shape.
    router
        .route(chat(&bob, Destination::Group("alpha".into())))
        .await;
    let got = nrx_a.try_recv().expect("alice must receive legacy traffic");
    assert_eq!(&*got.source.cn, "bob");
}

// ── Test 8 + 9: mandatory-marking flag ──────────────────────────────

#[tokio::test]
async fn mandatory_marking_rejects_inbound_without_classification() {
    // The `--require-classification-marking` opt-in: any inbound
    // message that lacks a marking is rejected at admission (no
    // delivery, no PEP eval, no fanout). The audit record fires; we
    // verify the absence of delivery here and the audit shape via
    // the unit test in `rustgate-core::audit::tests`.
    let router = Router::new()
        .with_authz(allow_all_engine())
        .with_require_classification_marking(true);
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

    // No marking on the message → rejected.
    router
        .route(chat(&bob, Destination::Group("alpha".into())))
        .await;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(
        nrx_a.try_recv().is_err(),
        "mandatory-marking must reject inbound without classification"
    );
}

#[tokio::test]
async fn mandatory_marking_admits_inbound_with_classification() {
    // Same flag, but the message carries a marking → admitted.
    let router = Router::new()
        .with_authz(allow_all_engine())
        .with_require_classification_marking(true);
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

    let marking = ClassificationMarking::new(Classification::Unclassified);
    router
        .route(chat_with_marking(
            &bob,
            Destination::Group("alpha".into()),
            marking,
        ))
        .await;
    let got = nrx_a.try_recv().expect("delivery must succeed when marked");
    assert_eq!(&*got.source.cn, "bob");
}

// ── Test 10: default-classification at the construction site ────────

#[test]
fn default_classification_applied_to_inbound_via_metadata_builder() {
    // The "per-listener default classification" hook is implemented as
    // the `Metadata::with_classification` builder; the listener-side
    // code applies it before handing the message to the router. Pin
    // here that the builder shape produces the expected metadata so a
    // listener flag wired to it cannot regress silently.
    let marking: ClassificationMarking = "//UNCLASSIFIED//".parse().unwrap();
    let meta = Metadata::new(SystemTime::UNIX_EPOCH, "tcp".into(), MessageType::Position)
        .with_classification(marking.clone());
    assert_eq!(meta.classification, Some(marking));
}

// ── Test 11: classification.denied audit fires with the right fields

#[tokio::test(flavor = "current_thread")]
async fn classification_denied_audit_event_fires_with_correct_fields() {
    // Compose the engine that filters //SECRET, route a message
    // carrying that marking, and assert the dedicated audit record
    // fires. The dispatcher is set as the default for the current
    // thread for the duration of the test; tokio's current-thread
    // flavor keeps every poll on this single thread so the
    // dispatcher applies to all spans/events emitted by the route
    // call below.
    use std::sync::Mutex;

    use tracing_subscriber::Layer;
    use tracing_subscriber::filter::Targets;
    use tracing_subscriber::layer::SubscriberExt;

    #[derive(Default, Clone)]
    struct SharedBuf(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for SharedBuf {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("buf").extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for SharedBuf {
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

    let router = Router::new().with_authz(Arc::new(ClearanceUnclassEngine));
    let alice = identity("alice", &["alpha"]);
    let bob = identity("bob", &["alpha"]);
    let (ptx_a, ntx_a, _pa, _nra) = channels();
    let (ptx_b, ntx_b, _pb, _nb) = channels();
    router
        .register(SessionHandle::new(alice.clone(), ptx_a, ntx_a))
        .await;
    router
        .register(SessionHandle::new(bob.clone(), ptx_b, ntx_b))
        .await;

    let marking = ClassificationMarking::new(Classification::Secret);
    router
        .route(chat_with_marking(
            &bob,
            Destination::Group("alpha".into()),
            marking,
        ))
        .await;

    let raw = String::from_utf8(buf.0.lock().expect("buf").clone()).expect("utf8");
    assert!(
        raw.lines().any(|l| l.contains("classification.denied")
            && l.contains("//SECRET")
            && l.contains("alpha")),
        "expected classification.denied audit record in: {raw}"
    );
}

// ── Test 12: composing with InjectMarking from #1286 ────────────────

#[tokio::test]
async fn classification_obligation_demotion_via_inject_marking_works_at_boundary() {
    // CDS rule: a //SECRET//NOFORN message routed through a
    // demotion boundary should have its banner replaced with
    // //UNCLASSIFIED//FOUO via the `InjectMarking` obligation. The
    // existing CDI obligation kinds from #1286 already implement the
    // payload-level marking rewrite; this test pins that the marking
    // on a routed message survives the trip and that an Allow with
    // the obligation produces a delivered, demoted payload.
    let router = Router::new().with_authz(inject_marking_engine("//UNCLASSIFIED//FOUO"));
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

    let secret_noforn: ClassificationMarking = "//SECRET//NOFORN".parse().unwrap();
    router
        .route(chat_with_marking(
            &bob,
            Destination::Group("alpha".into()),
            secret_noforn,
        ))
        .await;

    let got = nrx_a.try_recv().expect("delivery expected");
    let payload = std::str::from_utf8(&got.payload).expect("utf8");
    assert!(
        payload.contains("//UNCLASSIFIED//FOUO"),
        "InjectMarking obligation should rewrite banner in payload: {payload}"
    );
}
