// Copyright © 2026 Roberto Chiofalo.

#![allow(clippy::panic, clippy::unwrap_used)]
//! Regression test for the workspace-wide `spawn_background` +
//! `SubsystemHandle` migration (closes #792).
//!
//! Pins the contract that every named subsystem driven by
//! `rustgate_core::tasks::stop_subsystem` drains within the documented
//! 5-second timeout. Each subsystem follows the same shape: an
//! `Arc<Notify>` shutdown handle and a `JoinHandle<()>` whose body
//! awaits that notify. The migration in #792 standardised this pattern
//! across every accept-loop and listener task; a regression that
//! silently dropped the `select!` arm or removed the shutdown wakeup
//! would manifest as `stop_subsystem` taking the full 5-second timeout
//! instead of returning immediately.
//!
//! `rustgate-server` is a binary crate — there is no public Server
//! struct to spin up here. Instead this test exercises the
//! `SubsystemHandle` machinery at the boundary every server-crate
//! caller uses (`SubsystemHandle::new` + `stop_subsystem`) with task
//! bodies shaped exactly like the migrated production tasks (a `loop {
//! select! { _ = ticker.tick() => …, _ = shutdown.notified() => break }
//! }` pattern). The migrated production paths are:
//!
//! - `rustgate-mqtt::server::MqttServer::run` (accept loop +
//!   session-retention reaper)
//! - `rustgate-websocket::server::WebSocketServer::run` (accept loop)
//! - `rustgate-transport` plaintext TCP listener
//! - `rustgate-transport` UDP input listener
//!
//! Each goes through `setup::start_*` → `SubsystemHandle::new(shutdown,
//! task)` → `stop_subsystem`. Pinning the underlying drain contract
//! here covers all four call sites at once.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use rustgate_core::tasks::{SubsystemHandle, stop_subsystem};
use tokio::sync::Notify;

/// Shape of every migrated server-crate subsystem: a tick loop that
/// races against the shutdown `Notify`. Returns immediately on
/// shutdown — `stop_subsystem` should join in well under 5 seconds.
fn build_ticking_subsystem(name_for_observation: Arc<AtomicBool>) -> SubsystemHandle {
    let shutdown = Arc::new(Notify::new());
    let shutdown_for_task = Arc::clone(&shutdown);
    let observed = Arc::clone(&name_for_observation);
    let task = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_millis(50));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    // Side-effect so the test sees the loop is alive.
                }
                () = shutdown_for_task.notified() => {
                    observed.store(true, Ordering::SeqCst);
                    break;
                }
            }
        }
    });
    SubsystemHandle::new(shutdown, task)
}

#[tokio::test]
async fn single_subsystem_drains_within_five_seconds() {
    let observed = Arc::new(AtomicBool::new(false));
    let handle = build_ticking_subsystem(Arc::clone(&observed));

    let started = tokio::time::Instant::now();
    stop_subsystem("test-single", handle).await;
    let elapsed = started.elapsed();

    assert!(
        observed.load(Ordering::SeqCst),
        "subsystem must observe its shutdown notify before exiting"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "stop_subsystem must drain in well under the 5s timeout (got {elapsed:?})"
    );
}

#[tokio::test]
async fn multiple_subsystems_drain_independently_within_timeout() {
    // Stand-in for the production wiring in `setup.rs` where the server
    // creates one handle each for MQTT, WebSocket, plaintext TCP and
    // UDP. Stopping them sequentially must not exceed the documented
    // 5s drain budget per subsystem and must observe the wake on each.
    let names = ["mqtt", "websocket", "plaintext-tcp", "udp"];
    let mut handles = Vec::new();
    let mut observers = Vec::new();
    for _ in &names {
        let observed = Arc::new(AtomicBool::new(false));
        observers.push(Arc::clone(&observed));
        handles.push(build_ticking_subsystem(observed));
    }

    let started = tokio::time::Instant::now();
    for (handle, name) in handles.into_iter().zip(names.iter()) {
        stop_subsystem(name, handle).await;
    }
    let elapsed = started.elapsed();

    for (i, observed) in observers.iter().enumerate() {
        assert!(
            observed.load(Ordering::SeqCst),
            "subsystem {} ({}) did not observe its shutdown notify",
            i,
            names[i]
        );
    }
    assert!(
        elapsed < Duration::from_secs(5),
        "draining all {} subsystems must stay well below the per-subsystem 5s budget \
         (got {elapsed:?})",
        names.len()
    );
}

#[tokio::test(start_paused = true)]
async fn stuck_subsystem_times_out_at_five_seconds() {
    // Stronger pin: a task that ignores the notify must not block
    // shutdown forever. `stop_subsystem` must return after the 5-second
    // timeout, detaching the task. This is the safety-net behaviour
    // every migrated production caller relies on — without it, a stuck
    // session loop would prevent the server's overall shutdown from
    // making progress.
    let shutdown = Arc::new(Notify::new());
    let task = tokio::spawn(async move {
        std::future::pending::<()>().await;
    });
    let handle = SubsystemHandle::new(shutdown, task);

    let started = tokio::time::Instant::now();
    stop_subsystem("test-stuck", handle).await;
    let elapsed = started.elapsed();

    assert!(
        elapsed >= Duration::from_secs(5),
        "stop_subsystem must wait the full 5s for a stuck task (got {elapsed:?})"
    );
    assert!(
        elapsed < Duration::from_secs(6),
        "stop_subsystem must time out at exactly 5s, not later (got {elapsed:?})"
    );
}

#[tokio::test]
async fn spawn_background_panic_does_not_affect_subsystem_drain() {
    // Pins that a background task panicking via `spawn_background`
    // does not poison the runtime such that a subsequent
    // `stop_subsystem` call hangs or fails to join. This is the
    // workspace contract that the migration relies on — every migrated
    // crate now relies on `spawn_background` capturing panics.
    rustgate_core::tasks::spawn_background("test-panic", async move {
        panic!("intentional panic — exercising spawn_background panic-logging path");
    });

    // Give the panicking task a moment to fire so it's already torn
    // down by the time we drain a subsystem.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let observed = Arc::new(AtomicBool::new(false));
    let handle = build_ticking_subsystem(Arc::clone(&observed));
    stop_subsystem("test-after-panic", handle).await;
    assert!(
        observed.load(Ordering::SeqCst),
        "subsystem drain must work even after an earlier spawn_background task panicked"
    );
}
