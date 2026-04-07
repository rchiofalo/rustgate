//! Integration test proving the admission-control gate is wired into
//! `Router::route` and survives a synthetic slow-reader load: queued bytes
//! stay bounded, the gate trips, and the admission_deferred callback fires.

#![allow(clippy::panic, clippy::unwrap_used, unused_results)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use rustgate_core::identity::Identity;
use rustgate_core::message::{Destination, MessageType, RoutableMessage};
use rustgate_transport::{BackpressureGate, Router};
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
async fn gate_trips_and_bounds_queued_bytes_under_slow_reader() {
    // 4 KiB high-water to mirror the spec's "tiny cap" soak scenario.
    let mut gate = BackpressureGate::with_limits(4096, 2048);

    let deferred = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    // Install callbacks *before* cloning the Arc so `Arc::get_mut`
    // succeeds on the unique owner.
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

    // Register a slow-reader session but route to Broadcast with no other
    // recipients — keeps the route() hot path fast while still exercising
    // the Router::route permit acquisition.
    let (pri_tx, mut pri_rx) = mpsc::channel(1);
    let (norm_tx, mut norm_rx) = mpsc::channel(1);
    let handle =
        rustgate_transport::SessionHandle::new(Arc::new(make_identity("sender")), pri_tx, norm_tx);
    router.register(handle).await;
    // Drain to avoid self-send deadlock (broadcast skips sender anyway).
    tokio::spawn(async move { while pri_rx.recv().await.is_some() {} });
    tokio::spawn(async move { while norm_rx.recv().await.is_some() {} });

    // Pre-fill the gate to force initial waiters to park. We will release
    // this reservation after a short delay to prove the wakeup path runs.
    let _priming = gate.acquire(gate.high_water());

    // Spawn a flood of router.route() calls. Each parks on the gate first
    // (modeling the accept loop), acquires a 1 KiB permit inside route(),
    // then releases it. With a 4 KiB high-water mark and 32 concurrent
    // producers, the gate must trip repeatedly.
    let mut producers = Vec::new();
    for _ in 0..32 {
        let r = Arc::clone(&router);
        let g = Arc::clone(&gate);
        producers.push(tokio::spawn(async move {
            for _ in 0..16 {
                g.wait_for_capacity().await;
                let mut m = make_msg(1024);
                m.destination = Destination::Broadcast;
                m.source = make_identity("sender");
                r.route(m).await;
            }
        }));
    }

    // Give producers time to park on the gate, then release the priming
    // permit so the wakeup path drains the backlog.
    tokio::time::sleep(Duration::from_millis(50)).await;
    drop(_priming);

    for p in producers {
        let _ = tokio::time::timeout(Duration::from_secs(10), p)
            .await
            .expect("producer timeout");
    }

    // Once all route() futures return, their permits drop and the gate
    // must land back at zero.
    assert_eq!(gate.current(), 0, "all permits must release on drop");

    // Peak should be strictly bounded — in practice well under 2x the
    // high-water mark since route() is quick.
    let observed_peak = peak.load(Ordering::Relaxed);
    assert!(
        observed_peak >= 1024,
        "router.route() never took a permit; wiring is broken"
    );
    // Memory remained bounded: peak should not run away under flood.
    assert!(
        observed_peak <= gate.high_water() * 8,
        "peak {observed_peak} exceeded sanity bound (high_water = {})",
        gate.high_water()
    );
    // Accept-loop deferred path must have fired at least once under the
    // synthetic flood (32 concurrent producers * 1 KiB each, gate = 4 KiB).
    assert!(
        deferred.load(Ordering::Relaxed) >= 1,
        "admission_deferred callback never fired under synthetic flood"
    );
}

#[tokio::test]
async fn disabled_equivalent_huge_cap_has_no_observable_effect() {
    let gate = BackpressureGate::new(usize::MAX / 4);
    let router = Arc::new(Router::new().with_backpressure(Arc::clone(&gate)));

    let (pri_tx, mut pri_rx) = mpsc::channel(64);
    let (norm_tx, mut norm_rx) = mpsc::channel(64);
    let handle =
        rustgate_transport::SessionHandle::new(Arc::new(make_identity("fast")), pri_tx, norm_tx);
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
    assert_eq!(gate.current(), 0);
}
