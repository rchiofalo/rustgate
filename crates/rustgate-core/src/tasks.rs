// Copyright © 2026 Roberto Chiofalo.

//! Background-task utilities for workspace-wide panic-logging and graceful shutdown.
//!
//! Library crates cannot import helpers from the binary crate, which led
//! to bare `tokio::spawn` drift where panics in background tasks were
//! silently dropped. These helpers live in `rustgate-core` so every crate
//! has one path to spawn observable fire-and-forget work
//! ([`spawn_background`]) or manage a drainable subsystem
//! ([`SubsystemHandle`] + [`stop_subsystem`]).

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

/// Spawn a tokio task whose `JoinHandle` is intentionally not tracked.
///
/// Logs `tracing::error!` if the task panics or is cancelled unexpectedly.
/// Prefer this over bare `drop(tokio::spawn(...))` so that panics in
/// background work are observable rather than silently lost.
pub fn spawn_background(name: &'static str, fut: impl Future<Output = ()> + Send + 'static) {
    let handle = tokio::spawn(fut);
    drop(tokio::spawn(async move {
        if let Err(e) = handle.await {
            error!(task = name, error = %e, "background task panicked");
        }
    }));
}

/// Handle for a subsystem that can be gracefully stopped.
///
/// Unlike [`spawn_background`], subsystem handles let the caller signal
/// shutdown and then await the task's completion. Used for listener
/// tasks (WebSocket, plaintext TCP, UDP, enrollment server, metrics
/// server) so they stop accepting before connection draining begins.
///
/// Construct via [`SubsystemHandle::new`]; drive shutdown via
/// [`stop_subsystem`].
#[derive(Debug)]
pub struct SubsystemHandle {
    /// Fired by [`stop_subsystem`] to signal the subsystem's accept loop
    /// to exit. Cloned and passed into the task body so the same `Arc`
    /// that's stored here is the one the task awaits on.
    pub shutdown: Arc<Notify>,
    task: JoinHandle<()>,
}

impl SubsystemHandle {
    /// Build a subsystem handle from a shared shutdown notifier and the
    /// task that notifier controls.
    ///
    /// Callers typically:
    /// 1. Build `let shutdown = Arc::new(Notify::new());`
    /// 2. `tokio::spawn` the task, giving it `Arc::clone(&shutdown)`
    /// 3. Wrap both in `SubsystemHandle::new(shutdown, task)`
    pub fn new(shutdown: Arc<Notify>, task: JoinHandle<()>) -> Self {
        Self { shutdown, task }
    }
}

/// Signal a subsystem to stop and await its completion with a 5s timeout.
///
/// Matches the drain deadline used by the binary's graceful-shutdown
/// flow. If the subsystem does not exit within 5s, a `tracing::warn!`
/// is emitted and the `JoinHandle` is dropped (detaching the task).
pub async fn stop_subsystem(name: &str, handle: SubsystemHandle) {
    handle.shutdown.notify_one();
    match tokio::time::timeout(Duration::from_secs(5), handle.task).await {
        Ok(Ok(())) => info!(subsystem = name, "stopped"),
        Ok(Err(e)) => error!(subsystem = name, error = %e, "panicked during shutdown"),
        Err(_) => warn!(subsystem = name, "did not stop within 5s timeout"),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    #[tokio::test]
    async fn spawn_background_runs_the_future() {
        let ran = Arc::new(AtomicBool::new(false));
        let ran_clone = Arc::clone(&ran);
        spawn_background("test-ran", async move {
            ran_clone.store(true, Ordering::SeqCst);
        });
        // Give the task a moment to execute.
        for _ in 0..100 {
            if ran.load(Ordering::SeqCst) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(
            ran.load(Ordering::SeqCst),
            "background task should have run"
        );
    }

    #[tokio::test]
    async fn stop_subsystem_signals_and_awaits() {
        let shutdown = Arc::new(Notify::new());
        let shutdown_task = Arc::clone(&shutdown);
        let exited = Arc::new(AtomicBool::new(false));
        let exited_task = Arc::clone(&exited);
        let task = tokio::spawn(async move {
            shutdown_task.notified().await;
            exited_task.store(true, Ordering::SeqCst);
        });
        let handle = SubsystemHandle::new(shutdown, task);
        stop_subsystem("test-subsystem", handle).await;
        assert!(
            exited.load(Ordering::SeqCst),
            "subsystem should have exited after shutdown notify"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn stop_subsystem_times_out_when_task_ignores_shutdown() {
        let shutdown = Arc::new(Notify::new());
        // Task that never exits — stop_subsystem must timeout and detach
        // the `JoinHandle` rather than block forever.
        let task = tokio::spawn(async move {
            std::future::pending::<()>().await;
        });
        let handle = SubsystemHandle::new(shutdown, task);
        // Paused clock: the internal 5s timeout completes in virtual time.
        stop_subsystem("stuck-subsystem", handle).await;
    }
}
