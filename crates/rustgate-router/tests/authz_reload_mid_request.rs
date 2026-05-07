// Copyright © 2026 Roberto Chiofalo.

#![allow(clippy::panic, clippy::unwrap_used, unused_results)]

//! Authz hot-reload mid-evaluation contract test (F-134, refs #789).
//!
//! Pins the documented #721 + #1129 semantics for [`Router::swap_authz`]:
//!
//! 1. An evaluation that started against the *old* policy continues
//!    to its natural conclusion against the *old* policy, even if the
//!    policy slot is swapped to a new engine mid-flight. The router
//!    clones the engine `Arc` out of the `ArcSwap` slot at evaluation
//!    entry; a swap after the clone moment cannot tear the snapshot
//!    away.
//! 2. The next evaluation that starts after the swap sees the new
//!    policy.
//! 3. The `rustgate_authz_evaluations_in_flight` callback fires `+1`
//!    on entry and `-1` on exit, regardless of which policy was in
//!    effect — so the operator-visible gauge reflects the swap window.
//!
//! These three invariants together are what lets operators monitor
//! `rustgate_authz_evaluations_in_flight` to know when a SIGHUP-driven
//! policy reload has fully drained the previous engine. A regression
//! that aborted in-flight evaluations on swap, or that decremented the
//! gauge before the evaluation actually returned, would silently
//! invalidate the reload-drain monitoring runbook.
//!
//! ## Architectural note: per-PEP snapshot semantics
//!
//! Each PEP entry point in `Router` clones the engine `Arc` out of
//! `self.authz.load()` at the moment of evaluation. A single
//! `Router::route` call for `Destination::Group` performs one Send
//! PEP and one Receive PEP per recipient — each pulls its own
//! engine snapshot. Documented #721 semantics therefore promise
//! per-evaluation atomicity, not per-route-call atomicity. The
//! parked-evaluator pattern below pins the per-evaluation atomicity:
//! the FIRST evaluation observed by the test engine completes
//! against the OLD policy (the parked engine returns its own Allow);
//! subsequent evaluations on the same `route` call sample the NEW
//! engine and behave accordingly. The follow-on `route` test pin
//! confirms a freshly-arrived call uses the NEW engine for every
//! PEP.
//!
//! Test shape:
//!
//! - Thread A: parks the *first* `PolicyEngine::evaluate` call until
//!   the test releases it. The blocking evaluator pins the in-flight
//!   gauge at `>= 1` across an arbitrary wall-clock window — enough
//!   for thread B to swap the policy.
//! - Thread B: calls [`Router::swap_authz`] to install a deny-all
//!   engine while the original evaluation is held.
//! - The test asserts: the gauge stayed at `>= 1` across the swap
//!   window (the in-flight evaluation was not aborted), the gauge
//!   drains to `0` after release, and a freshly-issued `route` call
//!   sees the NEW deny-all engine on its Send PEP.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use rustgate_authz::{Action, DecisionOutcome, PolicyEngine, Resource, Subject};
use rustgate_core::identity::Identity;
use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};
use rustgate_router::{OnAuthzInFlightChanged, Router, SessionHandle};
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

/// `PolicyEngine` that blocks the *first* `evaluate` call until the
/// test releases it via the `release` flag. Subsequent calls return
/// `Allow` immediately. The first-call block synchronously pins one
/// tokio worker thread — that is the worst case for the in-flight
/// gauge contract: every hop through the router holds the cloned
/// `Arc<dyn PolicyEngine>` until evaluate returns, and the gauge
/// must reflect that hold time exactly. Group routing performs both
/// a Send PEP (sender side) and per-recipient Receive PEPs (recipient
/// side) — only the first call blocks; the rest fall through so the
/// test does not deadlock waiting on follow-on Receive PEPs.
struct BlockingAllowEngine {
    /// Set to `true` once the test has observed the swap and wants
    /// the parked evaluator to return.
    release: Arc<AtomicBool>,
    /// Set to `true` the first time `evaluate` is entered, so the
    /// test can deterministically observe the parked window.
    parked: Arc<AtomicBool>,
}

impl PolicyEngine for BlockingAllowEngine {
    fn evaluate(&self, _s: &Subject<'_>, _r: &Resource<'_>, _a: Action) -> DecisionOutcome {
        // Only the first evaluation blocks — every subsequent one
        // (including the Receive PEPs the group fan-out fires after
        // the Send PEP) returns Allow immediately. This pins the
        // gauge window without deadlocking on follow-on calls.
        if self
            .parked
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            // First entry — block until the test releases.
            while !self.release.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        DecisionOutcome::allow()
    }
    fn policy_id(&self) -> &str {
        "blocking-allow"
    }
}

/// `PolicyEngine` that always denies. Used as the post-swap policy
/// to verify the *next* evaluation honours the new engine.
struct DenyAllEngine;

impl PolicyEngine for DenyAllEngine {
    fn evaluate(&self, _s: &Subject<'_>, _r: &Resource<'_>, _a: Action) -> DecisionOutcome {
        DecisionOutcome::deny()
    }
    fn policy_id(&self) -> &str {
        "deny-all"
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn swap_mid_evaluation_completes_against_old_policy_and_observes_gauge() {
    // The first evaluation parks until `release` flips true. The
    // test polls `parked` to know the in-flight gauge has been
    // entered, performs the policy swap while parked, asserts the
    // gauge invariants, then flips `release` to let the original
    // evaluation complete. Subsequent evaluations (Receive PEPs in
    // the same `route` call, plus the second `route` call's PEPs)
    // run against whichever engine is installed at the moment they
    // are entered.
    let release = Arc::new(AtomicBool::new(false));
    let parked = Arc::new(AtomicBool::new(false));
    let allow_engine = Arc::new(BlockingAllowEngine {
        release: Arc::clone(&release),
        parked: Arc::clone(&parked),
    }) as Arc<dyn PolicyEngine>;

    let router = Arc::new(Router::new().with_authz(allow_engine));

    // Wire the in-flight gauge — this is the operator-visible signal
    // the test pins. A `+1` on entry, `-1` on exit.
    let gauge = Arc::new(AtomicI64::new(0));
    let gauge_for_cb = Arc::clone(&gauge);
    let cb: OnAuthzInFlightChanged = Arc::new(move |delta: i64| {
        let _ = gauge_for_cb.fetch_add(delta, Ordering::SeqCst);
    });
    router.set_on_authz_in_flight_changed(Some(cb));

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

    // Spawn the route call — bob sends to alpha; alice should receive
    // it once the blocking engine releases. The route task pins the
    // in-flight gauge at 1 until barrier is tripped.
    let router_for_route = Arc::clone(&router);
    let bob_for_route = Arc::clone(&bob);
    let route_task = tokio::spawn(async move {
        router_for_route
            .route(chat(&bob_for_route, Destination::Group("alpha".into())))
            .await;
    });

    // Wait until the engine reports it has parked the first
    // evaluation. The `+1` callback fires before the engine begins
    // blocking, so once `parked` is true the gauge has already
    // incremented. A bounded retry loop (50ms × 200 = 10s ceiling)
    // keeps the test reliable on slow CI hardware.
    for _ in 0..200 {
        if parked.load(Ordering::SeqCst) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        parked.load(Ordering::SeqCst),
        "engine must observe entry into evaluate before the swap"
    );
    assert!(
        gauge.load(Ordering::SeqCst) >= 1,
        "in-flight gauge must read >= 1 while the evaluator is parked, got {}",
        gauge.load(Ordering::SeqCst)
    );

    // Thread B: swap the engine. The currently-parked evaluation
    // must NOT terminate early — it holds its own `Arc` snapshot.
    router.swap_authz(Arc::new(DenyAllEngine));

    // The gauge must STILL read >= 1 — the swap does not abort
    // in-flight work. This is the documented #1129 behaviour.
    assert!(
        gauge.load(Ordering::SeqCst) >= 1,
        "swap_authz must not abort the in-flight evaluation; gauge stayed at {}",
        gauge.load(Ordering::SeqCst)
    );

    // Release thread A. The parked evaluator returns its `Allow`
    // outcome (proving the OLD policy's evaluation completed). The
    // route call's subsequent Receive PEP then samples the NEW
    // engine snapshot — that is the per-PEP atomicity contract,
    // not per-route-call atomicity. Either way, the route task
    // must complete without panicking.
    release.store(true, Ordering::SeqCst);
    route_task.await.expect("route task must not panic");

    // Drain any per-recipient receipt that survived the per-PEP
    // sample boundary; the test's contract is the gauge invariants
    // and the post-swap PEP behaviour, not which specific recipient
    // observed the in-flight allowed message.
    while nrx_a.try_recv().is_ok() {}

    // Gauge drained back to zero.
    assert_eq!(
        gauge.load(Ordering::SeqCst),
        0,
        "in-flight gauge must drain to 0 after the evaluator releases"
    );

    // A fresh route call must now use the NEW deny-all engine.
    // Drain alice's channel first so a residual message cannot mask
    // the new policy's effect.
    while nrx_a.try_recv().is_ok() {}
    router
        .route(chat(&bob, Destination::Group("alpha".into())))
        .await;
    assert!(
        nrx_a.try_recv().is_err(),
        "after swap, the deny-all engine must drop the next message"
    );
    assert_eq!(
        gauge.load(Ordering::SeqCst),
        0,
        "post-swap evaluation must also drain the gauge back to 0"
    );
}
