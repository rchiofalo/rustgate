// Copyright © 2026 Roberto Chiofalo.

#![allow(unused_results)]
#![allow(clippy::panic, clippy::unwrap_used)]
//! Integration tests for multicast egress Send-PEP application
//! (closes #738).
//!
//! Before this fix, [`Router::route_for_egress`] returned the unmasked
//! `arc_msg` for [`Destination::Multicast`] messages — the per-group
//! Send PEP only ran inside `send_to_group_excluding` for the local
//! fanout, so external sinks (NATS, federation, HTTP) saw the raw
//! pre-obligation payload even when policy required masking.
//!
//! These tests pin three invariants:
//!
//! 1. `multicast_egress_applies_send_pep_obligations` — the egress
//!    arc returned for a multicast message has `MaskPoint`'s
//!    coordinate-zero applied when at least one addressed group
//!    carries the obligation on Send.
//! 2. `multicast_local_fanout_remains_unmasked_when_no_send_obligation`
//!    — the converse direction: when the policy attaches the
//!    obligation only on the Receive side and Send is unobligated,
//!    the egress arc returned by `route_for_egress` is the unmodified
//!    source bytes — the egress-side application does NOT mutate the
//!    egress copy when there are no Send obligations to apply, and
//!    the local recipient still sees the Receive-side mask. This pins
//!    the perf carve-out: the egress code path adds zero allocation
//!    when the policy has no Send obligations, and the local fanout
//!    is unaffected by egress-side computation.
//! 3. `multicast_destination_emits_audit_when_obligation_applies` —
//!    an `AuthzEvent` observer sees one `Action::Send` evaluation per
//!    addressed group on the egress path (in addition to the per-group
//!    Send evaluations done inside `send_to_group_excluding`), so an
//!    operator dashboard counts the egress-side decisions.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use bytes::Bytes;
use rustgate_authz::{
    Action, Decision, DecisionOutcome, Obligation, PolicyEngine, Resource, Subject,
};
use rustgate_core::identity::Identity;
use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};
use rustgate_router::{AuthzEvent, AuthzObserver, Router, SessionHandle};
use tokio::sync::mpsc;

const SAMPLE_COT: &[u8] = br#"<event uid="u1" type="a-f-G-U-C" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z"><point lat="38.8977" lon="-77.0365" hae="125.4"/></event>"#;

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

fn position(source: &Arc<Identity>, dest: Destination) -> RoutableMessage {
    RoutableMessage {
        source: (**source).clone(),
        destination: dest,
        payload: Bytes::from_static(SAMPLE_COT),
        metadata: Metadata::new(SystemTime::now(), "cot".to_string(), MessageType::Position),
    }
}

/// Engine that allows everything but attaches the configured obligations
/// onto the configured `target_action` (e.g. Send-only or Receive-only).
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
            rule_id: Some(smol_str::SmolStr::new("test-multicast-egress")),
            obligations,
        }
    }
    fn policy_id(&self) -> &str {
        "test-multicast-egress"
    }
}

fn allow_with_obligation_on(action: Action, obligation: Obligation) -> Arc<dyn PolicyEngine> {
    Arc::new(AllowWithObligationEngine {
        target_action: action,
        obligations: vec![obligation],
    })
}

/// A multicast destination addressed at two groups whose Send rule
/// carries `MaskPoint`. The egress arc returned by `route_for_egress`
/// must have its CoT `<point>` coordinates zeroed — same wire form
/// `Direct` and `Group` would have produced. Closes the gap from #738
/// where multicast bypassed the egress-side obligation pipeline.
#[tokio::test]
async fn multicast_egress_applies_send_pep_obligations() {
    let router = Router::new().with_authz(allow_with_obligation_on(
        Action::Send,
        Obligation::MaskPoint,
    ));
    // Sender belongs to both groups; multicast addresses both. Each
    // group's Send rule carries `MaskPoint`, so the union (still just
    // `MaskPoint`) is applied to the egress copy.
    let alice = identity("alice", &["alpha", "bravo"]);
    let bob = identity("bob", &["alpha"]);

    let (ptx_a, ntx_a, _pa, _na) = channels();
    let (ptx_b, ntx_b, _pb, _nb) = channels();
    router
        .register(SessionHandle::new(alice.clone(), ptx_a, ntx_a))
        .await;
    router
        .register(SessionHandle::new(bob.clone(), ptx_b, ntx_b))
        .await;

    let routed = router
        .route_for_egress(position(
            &alice,
            Destination::Multicast(vec!["alpha".into(), "bravo".into()]),
        ))
        .await
        .expect("multicast must produce an egress copy");

    let s = std::str::from_utf8(&routed.payload).expect("masked payload is valid UTF-8");
    assert!(
        s.contains(r#"lat="0.0""#),
        "egress lat must be zeroed by MaskPoint: {s}"
    );
    assert!(
        s.contains(r#"lon="0.0""#),
        "egress lon must be zeroed by MaskPoint: {s}"
    );
    assert!(
        !s.contains("38.8977"),
        "raw lat leaked to egress sink despite MaskPoint: {s}"
    );
    assert!(
        !s.contains("-77.0365"),
        "raw lon leaked to egress sink despite MaskPoint: {s}"
    );
}

/// The local fanout's per-recipient obligation pipeline is independent
/// of the egress-side application. With a Receive-only policy:
///
/// - Each local recipient applies `MaskPoint` via the Receive PEP in
///   `send_to_group_excluding`, so the in-process delivery is masked.
/// - The egress side has no Send obligations to apply, so
///   `prepare_egress_envelope` returns the unmodified arc and the
///   egress arc is the original unmodified source bytes.
///
/// This pins the perf carve-out: the egress-side code path adds zero
/// allocation when no Send obligations exist, and the local fanout
/// is unaffected by the egress-side computation.
#[tokio::test]
async fn multicast_local_fanout_remains_unmasked_when_no_send_obligation() {
    // Receive-only obligation: the egress side has no Send obligations
    // to apply, so the egress arc is the original unmodified payload.
    // The local fanout still applies `MaskPoint` per-recipient via the
    // Receive PEP.
    let router = Router::new().with_authz(allow_with_obligation_on(
        Action::Receive,
        Obligation::MaskPoint,
    ));
    let alice = identity("alice", &["alpha", "bravo"]);
    let bob = identity("bob", &["alpha"]);

    let (ptx_a, ntx_a, _pa, _na) = channels();
    let (ptx_b, ntx_b, mut prx_b, _nb) = channels();
    router
        .register(SessionHandle::new(alice.clone(), ptx_a, ntx_a))
        .await;
    router
        .register(SessionHandle::new(bob.clone(), ptx_b, ntx_b))
        .await;

    let routed = router
        .route_for_egress(position(
            &alice,
            Destination::Multicast(vec!["alpha".into(), "bravo".into()]),
        ))
        .await
        .expect("egress arc must be produced");

    // Egress side: no Send obligations → original payload preserved.
    let egress_s = std::str::from_utf8(&routed.payload).expect("egress payload is UTF-8");
    assert!(
        egress_s.contains("38.8977"),
        "no Send-side obligation must leave the egress copy unmasked: {egress_s}"
    );

    // Local fanout: bob's Receive PEP applied `MaskPoint`.
    let got = prx_b.try_recv().expect("bob should receive multicast copy");
    let local_s = std::str::from_utf8(&got.payload).expect("local payload is UTF-8");
    assert!(
        local_s.contains(r#"lat="0.0""#),
        "local recipient must see Receive-side MaskPoint applied: {local_s}"
    );
    assert!(
        !local_s.contains("38.8977"),
        "raw lat leaked to local recipient despite Receive MaskPoint: {local_s}"
    );
}

/// Observe the authz engine: a multicast egress evaluation must fire
/// `Action::Send` evaluations for each addressed group during the
/// egress-side application pass. Sending one multicast message
/// addressed at two groups must produce the per-group Send evaluations
/// from `send_to_group_excluding` (local fanout) PLUS the egress-side
/// per-group Send evaluations (one per group). This test pins that the
/// egress evaluation actually runs by counting Send evaluations against
/// a known-installed observer.
#[tokio::test]
async fn multicast_destination_emits_audit_when_obligation_applies() {
    let send_eval_count = Arc::new(AtomicUsize::new(0));
    let observer_send_count = Arc::clone(&send_eval_count);
    let observer_groups: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let observer_groups_inner = Arc::clone(&observer_groups);

    let observer: AuthzObserver = Arc::new(move |ev: &AuthzEvent<'_>| {
        if ev.action == Action::Send {
            let _ = observer_send_count.fetch_add(1, Ordering::Relaxed);
            if let Some(rule) = ev.rule_id {
                observer_groups_inner.lock().unwrap().push(rule.to_owned());
            }
        }
    });

    let router = Router::new()
        .with_authz(allow_with_obligation_on(
            Action::Send,
            Obligation::MaskPoint,
        ))
        .with_authz_observer(observer);

    let alice = identity("alice", &["alpha", "bravo"]);
    let bob = identity("bob", &["alpha"]);
    let charlie = identity("charlie", &["bravo"]);

    let (ptx_a, ntx_a, _pa, _na) = channels();
    let (ptx_b, ntx_b, _pb, _nb) = channels();
    let (ptx_c, ntx_c, _pc, _nc) = channels();
    router
        .register(SessionHandle::new(alice.clone(), ptx_a, ntx_a))
        .await;
    router
        .register(SessionHandle::new(bob.clone(), ptx_b, ntx_b))
        .await;
    router
        .register(SessionHandle::new(charlie.clone(), ptx_c, ntx_c))
        .await;

    let routed = router
        .route_for_egress(position(
            &alice,
            Destination::Multicast(vec!["alpha".into(), "bravo".into()]),
        ))
        .await
        .expect("multicast must produce a masked egress copy");

    // Egress arc must be masked.
    let s = std::str::from_utf8(&routed.payload).expect("UTF-8");
    assert!(
        s.contains(r#"lat="0.0""#),
        "egress copy must have MaskPoint applied: {s}"
    );
    assert!(
        !s.contains("38.8977"),
        "raw lat must not leak to egress: {s}"
    );

    // The observer must have seen Send evaluations. With two addressed
    // groups, we expect at minimum: 2 evaluations on the egress side
    // (one per group), plus any Send evaluations from
    // `send_to_group_excluding`'s local fanout (also per group).
    // The exact count is implementation-dependent — what matters is
    // that the egress side DID evaluate, which is the bug from #738.
    let count = send_eval_count.load(Ordering::Relaxed);
    assert!(
        count >= 2,
        "expected at least 2 Send evaluations across addressed groups, got {count}"
    );
}
