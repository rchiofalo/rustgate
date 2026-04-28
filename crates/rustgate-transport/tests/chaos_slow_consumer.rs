// Copyright © 2026 Roberto Chiofalo.

#![allow(clippy::panic, clippy::unwrap_used, unused_results)]

//! Chaos test: slow-consumer fault injection (refs #788).
//!
//! Drives the router fanout against a session whose normal mpsc channel is
//! deliberately under-sized (capacity 1) so `try_send` deterministically
//! returns `Err(TrySendError::Full)` after the first delivery — modelling a
//! consumer that has stalled in its read loop.
//!
//! Pins the three behavioural invariants that chaos must not violate:
//!
//! 1. **Permits release as messages drop.** Each `Router::route` call
//!    acquires a [`BackpressurePermit`] sized for the payload. When the
//!    per-session `try_send` rejects the delivery (broadcast / multicast /
//!    group fan-out, where dropped envelopes do not divert to
//!    store-and-forward), the envelope's reference to the permit dies
//!    with the envelope, and the gate's queued-bytes counter returns to
//!    zero. A regression that leaked permits would peg the gauge at
//!    high-water and brick the accept loop.
//! 2. **High-water mark is respected.** The peak observed via the
//!    `set_on_bytes_changed` callback never exceeds the configured cap
//!    while only one slow consumer is parked. The cap is set so that one
//!    in-flight message fits but two would breach it; the test then
//!    drives ten messages through and confirms the peak stays below
//!    the breach point.
//! 3. **No deadlock when the slow consumer drains.** After the test
//!    drains the channel, every subsequent `route` call observes
//!    `is_admitting() == true` and the eventual final message is
//!    delivered through the live channel. A regression that left the
//!    gate in `blocking = true` after a stalled consumer reconnected
//!    would silently park the accept loop forever.
//!
//! Deterministic: no sleeps, no `tokio::time::pause`. The slow-consumer
//! semantics are produced by sizing `mpsc::channel(1)` so there is exactly
//! one in-flight slot, and by holding the receiver until the assertion
//! point.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use rustgate_core::identity::Identity;
use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};
use rustgate_transport::{BackpressureGate, Router, SessionHandle};
use tokio::sync::mpsc;

fn ident(cn: &str) -> Identity {
    Identity::plaintext(cn.to_string(), Default::default()).expect("valid cn")
}

fn broadcast(payload_bytes: usize) -> RoutableMessage {
    RoutableMessage {
        source: ident("sender"),
        destination: Destination::Broadcast,
        metadata: Metadata {
            received_at: std::time::SystemTime::now(),
            source_protocol: "test".to_string(),
            message_type: MessageType::Chat,
            ttl: None,
        },
        payload: Bytes::from(vec![0u8; payload_bytes]),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slow_consumer_drops_without_leaking_permits_or_deadlocking() {
    // Tight cap so a single 1 KiB message in flight is comfortably below
    // high-water but two would exceed it. The chaos invariant is that
    // even when a session deterministically rejects every queued
    // delivery, the gate must come back to zero — not stay pegged at
    // capacity.
    let mut gate = BackpressureGate::with_limits(4096, 2048);

    let peak = Arc::new(AtomicUsize::new(0));
    let p_cb = Arc::clone(&peak);
    BackpressureGate::set_on_bytes_changed(
        &mut gate,
        Arc::new(move |n| {
            // Lock-free watermark update.
            let mut cur = p_cb.load(Ordering::Relaxed);
            while n > cur {
                match p_cb.compare_exchange_weak(cur, n, Ordering::Relaxed, Ordering::Relaxed) {
                    Ok(_) => break,
                    Err(actual) => cur = actual,
                }
            }
        }),
    )
    .unwrap();

    let router = Arc::new(Router::new().with_backpressure(Arc::clone(&gate)));

    // Slow consumer: capacity-1 normal channel that we never drain. The
    // first envelope occupies the slot; every later try_send returns
    // `TrySendError::Full`. Priority channel is a no-op for a
    // `MessageType::Chat` workload, so make it tiny too.
    let slow = Arc::new(ident("slow"));
    let (pri_tx, _pri_rx) = mpsc::channel(1);
    let (norm_tx, mut norm_rx) = mpsc::channel(1);
    router
        .register(SessionHandle::new(Arc::clone(&slow), pri_tx, norm_tx))
        .await;

    // Drive ten 1 KiB broadcast messages — one fits in the channel, the
    // other nine are dropped at try_send. The router-side `Arc<Permit>`
    // dies as the (dropped) envelope clones go out of scope, so the
    // gauge must return to zero.
    for _ in 0..10 {
        router.route(broadcast(1024)).await;
    }

    // Allow any spawned router fan-out task to drop its envelope clones.
    tokio::task::yield_now().await;

    // Invariant 1 + 2 — the permit for the in-channel message is still
    // alive, but the gauge must NOT exceed our cap (one message in,
    // many discards). With a 4 KiB cap, a 1 KiB resident message gives
    // us 1024; the peak across the run must stay strictly below the
    // cap because the discards never cumulatively pile up.
    let observed_peak = peak.load(Ordering::Relaxed);
    assert!(
        observed_peak < 4096,
        "peak {observed_peak} must stay below high-water cap (4096) — \
         dropped envelopes leaked permits if the gauge oscillated up to capacity"
    );
    assert!(
        gate.current() <= 1024,
        "gate should hold at most one resident message (~1 KiB), got {} bytes",
        gate.current()
    );

    // Drain the slow consumer's pending message — its envelope drops on
    // recv, releasing the last permit clone.
    let _delivered = norm_rx
        .try_recv()
        .expect("the in-channel message must be deliverable");
    drop(_delivered);
    tokio::task::yield_now().await;

    // Invariant 1 final: the gate has fully released.
    assert_eq!(
        gate.current(),
        0,
        "all permits must release once the resident message is consumed"
    );

    // Invariant 3 — no deadlock. With the gate empty and admitting,
    // a final route() must complete and the message must be delivered
    // (the channel has capacity 1 again).
    assert!(
        gate.is_admitting(),
        "gate must be admitting once the slow consumer has drained"
    );
    router.route(broadcast(512)).await;
    let final_env = norm_rx
        .try_recv()
        .expect("post-drain delivery must succeed — slow-consumer stall has cleared");
    drop(final_env);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deterministic_slow_consumer_does_not_starve_other_sessions() {
    // Chaos invariant: a single deterministically-stalled consumer must
    // not block delivery to live consumers. With per-session try_send,
    // the slow channel rejects, the live channel accepts, and the gate
    // sees a clean rise-and-fall on every message.
    let gate = BackpressureGate::with_limits(64 * 1024, 32 * 1024);
    let router = Arc::new(Router::new().with_backpressure(Arc::clone(&gate)));

    // Stalled session.
    let slow = Arc::new(ident("slow"));
    let (s_pri_tx, _s_pri_rx) = mpsc::channel(1);
    let (s_norm_tx, _s_norm_rx) = mpsc::channel(1);
    router
        .register(SessionHandle::new(slow, s_pri_tx, s_norm_tx))
        .await;

    // Live session — drains continuously.
    let fast = Arc::new(ident("fast"));
    let (f_pri_tx, mut f_pri_rx) = mpsc::channel(64);
    let (f_norm_tx, mut f_norm_rx) = mpsc::channel(64);
    router
        .register(SessionHandle::new(fast, f_pri_tx, f_norm_tx))
        .await;

    let drain_pri = tokio::spawn(async move { while f_pri_rx.recv().await.is_some() {} });
    let drain_norm = tokio::spawn(async move {
        let mut count = 0usize;
        while let Some(_env) = f_norm_rx.recv().await {
            count += 1;
            if count >= 50 {
                break;
            }
        }
        count
    });

    // 50 broadcast messages. The slow session swallows one and rejects
    // the rest; the fast session receives all 50.
    for _ in 0..50 {
        router.route(broadcast(256)).await;
    }

    // Wait for the fast session to consume its 50 envelopes — the
    // success criterion is that the live session was not starved
    // by the slow session's rejections.
    let count = tokio::time::timeout(std::time::Duration::from_secs(5), drain_norm)
        .await
        .expect("fast session must not be starved by stalled peer")
        .expect("drain task join");
    assert_eq!(
        count, 50,
        "live session must receive every broadcast despite the parallel slow consumer"
    );

    drain_pri.abort();
}
