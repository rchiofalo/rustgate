//! Integration test proving the admission-control gate observes
//! *downstream* memory pressure: the permit acquired in `Router::route`
//! stays alive until the last session channel drains the message, so
//! slow readers actually press the gate.

#![allow(clippy::panic, clippy::unwrap_used, unused_results)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use rustgate_core::identity::Identity;
use rustgate_core::message::{Destination, MessageType, RoutableMessage};
use rustgate_transport::{BackpressureGate, Router, SessionHandle};
use tokio::sync::mpsc;

fn make_identity(cn: &str) -> Identity {
    Identity::plaintext(cn.to_string(), Default::default()).expect("valid cn")
}

fn make_msg(bytes: usize) -> RoutableMessage {
    RoutableMessage {
        source: make_identity("sender"),
        destination: Destination::Direct(make_identity("slow")),
        metadata: rustgate_core::message::Metadata {
            received_at: std::time::SystemTime::now(),
            source_protocol: "test".to_string(),
            message_type: MessageType::Chat,
            ttl: None,
        },
        payload: Bytes::from(vec![0u8; bytes]),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slow_reader_keeps_gate_pressed_until_drain() {
    // Tiny cap so a handful of parked messages trip the high-water mark.
    let mut gate = BackpressureGate::with_limits(4096, 2048);

    let deferred = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    {
        let d = Arc::clone(&deferred);
        BackpressureGate::set_on_deferred(
            &mut gate,
            Arc::new(move || {
                let _ = d.fetch_add(1, Ordering::Relaxed);
            }),
        );
        let p = Arc::clone(&peak);
        BackpressureGate::set_on_bytes_changed(
            &mut gate,
            Arc::new(move |n| {
                let mut cur = p.load(Ordering::Relaxed);
                while n > cur {
                    match p.compare_exchange_weak(cur, n, Ordering::Relaxed, Ordering::Relaxed) {
                        Ok(_) => break,
                        Err(actual) => cur = actual,
                    }
                }
            }),
        );
    }

    let router = Arc::new(Router::new().with_backpressure(Arc::clone(&gate)));

    // Slow reader: a direct-target session whose receiver is never
    // drained until the end of the test. The mpsc channel capacity is
    // sized so that a few queued messages fit.
    let slow_identity = Arc::new(make_identity("slow"));
    let (pri_tx, _pri_rx) = mpsc::channel(8);
    let (norm_tx, mut norm_rx) = mpsc::channel(8);
    router
        .register(SessionHandle::new(
            Arc::clone(&slow_identity),
            pri_tx,
            norm_tx,
        ))
        .await;

    // Drive the router purely through `Router::route` — no
    // `wait_for_capacity` in the producer loop. Each routed message is
    // 1 KiB; after 4 queued messages the gate trips (4096 >= high-water).
    for _ in 0..4 {
        let mut m = make_msg(1024);
        m.destination = Destination::Direct(make_identity("slow"));
        router.route(m).await;
    }

    // Queued bytes must reflect the messages still sitting in the
    // slow-reader's mpsc channel.
    assert!(
        gate.current() >= 4096,
        "gate should be pegged at/above high-water while slow reader is parked, current={}",
        gate.current(),
    );
    assert!(
        !gate.is_admitting(),
        "gate must be blocking after slow reader fills its queue"
    );

    // A separate task calling `wait_for_capacity` must park (and thus
    // increment `admission_deferred_total` via the callback).
    let g_wait = Arc::clone(&gate);
    let waiter = tokio::spawn(async move { g_wait.wait_for_capacity().await });
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        !waiter.is_finished(),
        "waiter must be parked while gate is blocking"
    );
    assert!(
        deferred.load(Ordering::Relaxed) >= 1,
        "admission_deferred callback must fire when waiter parks"
    );

    // Drain the slow reader; bytes return to ~0 and the waiter wakes.
    while let Ok(_env) = norm_rx.try_recv() {
        // drop immediately, releasing the permit reference
    }
    tokio::time::sleep(Duration::from_millis(50)).await;

    tokio::time::timeout(Duration::from_secs(2), waiter)
        .await
        .expect("waiter must wake once drain crosses low-water")
        .expect("join");

    assert_eq!(
        gate.current(),
        0,
        "all permits must release once the slow reader drains"
    );
    assert!(gate.is_admitting());

    let observed_peak = peak.load(Ordering::Relaxed);
    assert!(
        observed_peak >= 4096,
        "peak should reflect at least the high-water mark, got {observed_peak}"
    );
}

#[tokio::test]
async fn disabled_equivalent_huge_cap_has_no_observable_effect() {
    let gate = BackpressureGate::new(usize::MAX / 4);
    let router = Arc::new(Router::new().with_backpressure(Arc::clone(&gate)));

    let (pri_tx, mut pri_rx) = mpsc::channel(64);
    let (norm_tx, mut norm_rx) = mpsc::channel(64);
    let handle = SessionHandle::new(Arc::new(make_identity("fast")), pri_tx, norm_tx);
    router.register(handle).await;

    // Drain receivers to allow immediate throughput.
    tokio::spawn(async move { while pri_rx.recv().await.is_some() {} });
    tokio::spawn(async move { while norm_rx.recv().await.is_some() {} });

    for _ in 0..256 {
        let mut m = make_msg(512);
        m.destination = Destination::Direct(make_identity("fast"));
        router.route(m).await;
        assert!(gate.is_admitting());
    }
    // Give drain tasks a moment.
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(gate.current(), 0);
}
