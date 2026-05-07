// Copyright © 2026 Roberto Chiofalo.

#![allow(unused_results)]
#![allow(clippy::panic, clippy::unwrap_used)]
//! Regression tests for the authz_evaluate split (closes #730).
//!
//! Pre-#730, the router had a single `authz_evaluate(action: AuthzAction)`
//! helper that dispatched to either the Send PEP or the Receive PEP
//! based on a runtime `Action` parameter. A refactor that dropped or
//! relabelled an action value would silently route a Send-side
//! evaluation through the Receive PEP path (or vice-versa) with no
//! compile-time guard — the type system permitted the bug.
//!
//! After #730 the helper is split into two direction-anchored entry
//! points: `authz_evaluate_send` and `authz_evaluate_receive`. The
//! direction is implicit in the function name; the call site can no
//! longer pick the wrong action by accident, and a future refactor
//! that retires or renames an `Action` variant cannot silently
//! reroute a PEP. These tests pin the post-split behaviour.
//!
//! 1. `authz_evaluate_send_path_only_emits_send_action` — a sender-side
//!    flow (broadcast Send PEP) MUST observe `Action::Send` events on
//!    the authz observer and MUST NOT produce any `Action::Receive`
//!    event for the same evaluation pass.
//! 2. `authz_evaluate_receive_path_only_emits_receive_action` — a
//!    per-recipient delivery flow (broadcast Receive PEP) MUST observe
//!    `Action::Receive` events on the authz observer and MUST NOT
//!    produce a `Action::Send` event for that recipient pass.
//! 3. `direction_swap_is_observable_on_full_route` — a complete
//!    end-to-end broadcast routing exercises both PEPs in order
//!    (Send before Receive) and the recorded sequence MUST start
//!    with at least one Send before any Receive event. This pins the
//!    invariant that the split did not silently swap the call sites.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use bytes::Bytes;
use rustgate_authz::{Action, Decision, DecisionOutcome, PolicyEngine, Resource, Subject};
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

fn chat(source: &Arc<Identity>, dest: Destination) -> RoutableMessage {
    RoutableMessage {
        source: (**source).clone(),
        destination: dest,
        payload: Bytes::from_static(SAMPLE_COT),
        metadata: Metadata::new(SystemTime::now(), "cot".to_string(), MessageType::Chat),
    }
}

/// Always-Allow engine that reports its own `policy_id`. The split
/// tests need only a uniform Allow verdict — the variable under test
/// is which PEP path observed each evaluation, not the engine output.
struct AllowAllEngine;

impl PolicyEngine for AllowAllEngine {
    fn evaluate(&self, _s: &Subject<'_>, _r: &Resource<'_>, _a: Action) -> DecisionOutcome {
        DecisionOutcome {
            decision: Decision::Allow,
            rule_id: Some(smol_str::SmolStr::new("allow-all-split-test")),
            obligations: Vec::new(),
        }
    }
    fn policy_id(&self) -> &'static str {
        "test-authz-evaluate-split"
    }
}

/// Build an `AuthzObserver` that records every observed action into
/// the supplied `Mutex<Vec<Action>>` in evaluation order.
fn recording_observer(record: Arc<Mutex<Vec<Action>>>) -> AuthzObserver {
    Arc::new(move |ev: &AuthzEvent<'_>| {
        if let Ok(mut guard) = record.lock() {
            guard.push(ev.action);
        }
    })
}

/// Closes #730 (1/3). A sender-side broadcast Send-PEP evaluation MUST
/// emit exactly `Action::Send` on the authz observer and MUST NOT emit
/// any `Action::Receive` event for the *same* sender evaluation.
///
/// The test calls `route_for_egress` on a broadcast destination with
/// no registered recipients. The Send PEP runs once for the sender
/// at the head of `route_inner`; the Receive PEP loop runs over the
/// (empty) recipient set, so no `Action::Receive` events are produced.
/// A regression that wired the sender-side call to the Receive entry
/// point would record a Receive event here and fail this test.
#[tokio::test]
async fn authz_evaluate_send_path_only_emits_send_action() {
    let actions: Arc<Mutex<Vec<Action>>> = Arc::new(Mutex::new(Vec::new()));
    let observer = recording_observer(Arc::clone(&actions));

    let router = Router::new()
        .with_authz(Arc::new(AllowAllEngine))
        .with_authz_observer(observer);

    // Sender is in group "alpha"; no recipients registered, so the
    // Receive PEP loop is empty by construction.
    let alice = identity("alice", &["alpha"]);
    let (ptx_a, ntx_a, _pa, _na) = channels();
    router
        .register(SessionHandle::new(alice.clone(), ptx_a, ntx_a))
        .await;

    let _ = router
        .route_for_egress(chat(&alice, Destination::Broadcast))
        .await;

    let recorded = actions.lock().unwrap().clone();
    let send_count = recorded.iter().filter(|a| **a == Action::Send).count();
    let recv_count = recorded.iter().filter(|a| **a == Action::Receive).count();

    assert!(
        send_count >= 1,
        "Send-PEP path must produce at least one Action::Send event, got {recorded:?}"
    );
    assert_eq!(
        recv_count, 0,
        "Send-PEP path must NOT emit any Action::Receive events when the recipient set is empty; \
         got {recorded:?}"
    );
}

/// Closes #730 (2/3). A per-recipient broadcast Receive-PEP evaluation
/// MUST emit `Action::Receive` events for every registered recipient,
/// in addition to a single `Action::Send` from the sender-side check.
/// A regression that wired the recipient pass to the Send entry point
/// would record only Send events for the recipient evaluations and
/// fail this test.
#[tokio::test]
async fn authz_evaluate_receive_path_only_emits_receive_action() {
    let actions: Arc<Mutex<Vec<Action>>> = Arc::new(Mutex::new(Vec::new()));
    let observer = recording_observer(Arc::clone(&actions));

    let router = Router::new()
        .with_authz(Arc::new(AllowAllEngine))
        .with_authz_observer(observer);

    let alice = identity("alice", &["alpha"]);
    let bob = identity("bob", &["alpha"]);
    let charlie = identity("charlie", &["alpha"]);

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

    let _ = router
        .route_for_egress(chat(&alice, Destination::Broadcast))
        .await;

    let recorded = actions.lock().unwrap().clone();
    let send_count = recorded.iter().filter(|a| **a == Action::Send).count();
    let recv_count = recorded.iter().filter(|a| **a == Action::Receive).count();

    // Two recipients (bob, charlie) — the sender (alice) is excluded
    // from her own broadcast fan-out, so the Receive PEP runs exactly
    // once per non-self registered session.
    assert_eq!(
        send_count, 1,
        "exactly one sender-side Action::Send is expected for a single broadcast routing, \
         got {recorded:?}"
    );
    assert_eq!(
        recv_count, 2,
        "Receive-PEP path must emit exactly one Action::Receive per non-self recipient (bob, charlie), \
         got {recorded:?}"
    );
}

/// Closes #730 (3/3). The split must preserve the documented PEP
/// ordering: every Send-PEP evaluation runs before any Receive-PEP
/// evaluation for the same routing pass. A regression that
/// accidentally swapped the two call sites — the Send call site now
/// invokes `authz_evaluate_receive` and the Receive site invokes
/// `authz_evaluate_send` — would still produce the same total count
/// of events and fool tests that only count action variants. The
/// stricter invariant pinned here is *order*: in the recorded
/// sequence, every `Action::Receive` event MUST be preceded by at
/// least one `Action::Send` event. The atomic counter snapshots the
/// `Send` count at the moment each `Receive` event is recorded.
#[tokio::test]
async fn direction_swap_is_observable_on_full_route() {
    let send_seen_at_recv: Arc<Mutex<Vec<usize>>> = Arc::new(Mutex::new(Vec::new()));
    let send_count = Arc::new(AtomicUsize::new(0));

    let send_count_for_obs = Arc::clone(&send_count);
    let recv_witness_for_obs = Arc::clone(&send_seen_at_recv);
    let observer: AuthzObserver = Arc::new(move |ev: &AuthzEvent<'_>| match ev.action {
        Action::Send => {
            send_count_for_obs.fetch_add(1, Ordering::SeqCst);
        }
        Action::Receive => {
            // Snapshot the Send count at this point. If the call
            // sites were swapped, this would fire BEFORE the Send
            // pass and the recorded snapshot would be 0.
            let n = send_count_for_obs.load(Ordering::SeqCst);
            if let Ok(mut guard) = recv_witness_for_obs.lock() {
                guard.push(n);
            }
        }
        _ => {}
    });

    let router = Router::new()
        .with_authz(Arc::new(AllowAllEngine))
        .with_authz_observer(observer);

    let alice = identity("alice", &["alpha"]);
    let bob = identity("bob", &["alpha"]);

    let (ptx_a, ntx_a, _pa, _na) = channels();
    let (ptx_b, ntx_b, _pb, _nb) = channels();
    router
        .register(SessionHandle::new(alice.clone(), ptx_a, ntx_a))
        .await;
    router
        .register(SessionHandle::new(bob.clone(), ptx_b, ntx_b))
        .await;

    let _ = router
        .route_for_egress(chat(&alice, Destination::Broadcast))
        .await;

    let witnesses = send_seen_at_recv.lock().unwrap().clone();
    assert!(
        !witnesses.is_empty(),
        "expected at least one Receive event during broadcast fan-out, got {witnesses:?}"
    );
    for (i, snapshot) in witnesses.iter().enumerate() {
        assert!(
            *snapshot >= 1,
            "Receive event #{i} fired with Send count {snapshot} — expected ≥1 prior Send. \
             A direction swap (Send call site invoking the Receive PEP, or vice-versa) would \
             land here. witnesses={witnesses:?}"
        );
    }
}
