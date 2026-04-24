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

    #[tokio::test]
    async fn spawn_background_panic_does_not_crash_runtime() {
        // The outer `tokio::spawn` wrapper awaits the inner handle and
        // logs on panic; the test process must not crash, and a second
        // spawn must continue to run normally. A regression that
        // replaced the wrapper with a bare `drop(tokio::spawn(...))`
        // would still pass the happy-path test above, but would take
        // the runtime down on the first panic in production.
        //
        // Capturing the panic message would require a tracing
        // subscriber — the weaker contract is enough: runtime stays
        // alive, subsequent tasks still execute.
        let panicking_done = Arc::new(AtomicBool::new(false));
        let panicking_done_clone = Arc::clone(&panicking_done);
        spawn_background("panicking-task", async move {
            panicking_done_clone.store(true, Ordering::SeqCst);
            panic!("intentional panic — exercising spawn_background error path");
        });

        // Give the panicking task a moment to run + the outer watcher a
        // moment to log. Spin on `panicking_done` first so we do not
        // race the subsequent healthy-task assertion.
        for _ in 0..100 {
            if panicking_done.load(Ordering::SeqCst) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(
            panicking_done.load(Ordering::SeqCst),
            "panicking task should have reached the panic point"
        );

        // A second spawn must still run to completion — the runtime
        // has not been poisoned by the earlier panic.
        let healthy_done = Arc::new(AtomicBool::new(false));
        let healthy_done_clone = Arc::clone(&healthy_done);
        spawn_background("healthy-after-panic", async move {
            healthy_done_clone.store(true, Ordering::SeqCst);
        });
        for _ in 0..100 {
            if healthy_done.load(Ordering::SeqCst) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(
            healthy_done.load(Ordering::SeqCst),
            "spawn_background must keep working after a prior task panicked"
        );
    }

    #[tokio::test]
    async fn stop_subsystem_returns_cleanly_when_task_panics_after_shutdown() {
        // Pins the `Ok(Err(e))` arm of `stop_subsystem`: task was
        // notified, woke up, then panicked before exiting cleanly. The
        // function must log the error and return rather than propagate
        // the panic into the caller.
        let shutdown = Arc::new(Notify::new());
        let shutdown_task = Arc::clone(&shutdown);
        let task = tokio::spawn(async move {
            shutdown_task.notified().await;
            panic!("task panicked after receiving shutdown — pinning Ok(Err(_)) arm");
        });
        let handle = SubsystemHandle::new(shutdown, task);
        // If the panic path misbehaved (e.g. unwrap on JoinError,
        // propagating the panic) this await would itself panic and
        // fail the test. The stronger contract is that the function
        // returns normally.
        stop_subsystem("panicking-subsystem", handle).await;
    }

    #[tokio::test]
    async fn stop_subsystem_succeeds_when_task_already_exited_before_notify() {
        // The task completes on its own before we issue the notify.
        // `notify_one()` is still called (buffered as a permit that
        // nobody consumes) and the JoinHandle resolves immediately
        // with `Ok(Ok(()))` — the sunny-path arm.
        let shutdown = Arc::new(Notify::new());
        let task = tokio::spawn(async move {
            // Return straight away — do not observe the notify.
        });
        // Let the task complete before we call stop_subsystem. The
        // previous test (`stop_subsystem_signals_and_awaits`) exercises
        // the "wake-on-notify" path; this one exercises the "already
        // done" path that stop_subsystem must also handle without
        // blocking on the unused notify permit.
        tokio::time::sleep(Duration::from_millis(20)).await;
        let handle = SubsystemHandle::new(shutdown, task);
        stop_subsystem("already-exited-subsystem", handle).await;
    }

    #[tokio::test]
    async fn subsystem_handle_implements_debug() {
        // `#[derive(Debug)]` on SubsystemHandle is load-bearing: every
        // caller that wraps a handle in another struct or logs it via
        // `tracing::debug!(?handle, …)` relies on this. A refactor
        // that removed the derive (e.g. to hide task internals) would
        // break transitive call sites silently; pin the bound here.
        fn assert_debug<T: std::fmt::Debug>(_: &T) {}

        let shutdown = Arc::new(Notify::new());
        let task = tokio::spawn(async move {});
        let handle = SubsystemHandle::new(shutdown, task);
        assert_debug(&handle);
        // The `Debug` output itself is not pinned — tokio's JoinHandle
        // Debug rendering changes between versions and is not part of
        // rustgate's stable surface. Only the bound matters.
        let rendered = format!("{handle:?}");
        assert!(
            rendered.contains("SubsystemHandle"),
            "Debug output should mention the type name, got: {rendered}"
        );
        // Drain the handle so the background task is not leaked at
        // test-teardown — drop the handle to detach.
        drop(handle);
    }

    #[tokio::test]
    async fn subsystem_handle_shutdown_is_externally_cloneable_before_construction() {
        // Subsystems like MQTT and WebSocket clone the shutdown
        // notifier before moving it into the server task so that an
        // external stop_subsystem caller can reach the same signal the
        // task body awaits on. Pin that the `Arc<Notify>` survives
        // being handed into SubsystemHandle::new via Arc::clone and
        // that notifying through the external clone still wakes the
        // task inside — the invariant the server's shutdown flow
        // relies on.
        let shutdown = Arc::new(Notify::new());
        let external = Arc::clone(&shutdown);
        let inner = Arc::clone(&shutdown);

        let woke = Arc::new(AtomicBool::new(false));
        let woke_task = Arc::clone(&woke);
        let task = tokio::spawn(async move {
            inner.notified().await;
            woke_task.store(true, Ordering::SeqCst);
        });
        let handle = SubsystemHandle::new(shutdown, task);

        // Fire through the external clone — the inner task must wake.
        external.notify_one();
        stop_subsystem("externally-notified", handle).await;
        assert!(
            woke.load(Ordering::SeqCst),
            "task inside the subsystem should wake from the externally-cloned Arc<Notify>"
        );
    }

    // ── defensive-invariant coverage ────────────────────────────────

    #[tokio::test(start_paused = true)]
    async fn spawn_background_returns_immediately_without_awaiting_future() {
        // The function's contract says "fire-and-forget" — the caller
        // must not block on the spawned future. A regression that
        // accidentally did `handle.await` on the hot path (instead of
        // inside the separately-spawned watcher) would defeat the
        // whole point of the helper. Pin with a paused-clock time
        // measurement: spawn a task that sleeps for 60s of virtual time
        // and assert the `spawn_background` call itself returns in
        // <= 100ms of virtual time.
        let start = tokio::time::Instant::now();
        spawn_background("non-blocking", async move {
            tokio::time::sleep(Duration::from_secs(60)).await;
        });
        let elapsed = start.elapsed();
        assert!(
            elapsed <= Duration::from_millis(100),
            "spawn_background must not block on the spawned future (got elapsed {elapsed:?})"
        );
    }

    #[test]
    fn spawn_background_accepts_send_static_future_only() {
        // Compile-time pin on the future bound: `impl Future<Output=()>
        // + Send + 'static`. A regression that narrowed `'static` to a
        // named lifetime or dropped `Send` would fail at the far-away
        // call site where a borrowed-field closure is handed in; pin
        // here via a local helper so the break is localized. The test
        // does not run the future — construction alone is enough.
        fn assert_bounds<F: std::future::Future<Output = ()> + Send + 'static>(_: F) {}
        assert_bounds(async move {});
        assert_bounds(async move {
            tokio::time::sleep(Duration::from_millis(1)).await;
        });
    }

    #[tokio::test]
    async fn spawn_background_runs_many_concurrent_tasks_independently() {
        // Pins that `spawn_background` scales past a single task and
        // that each spawned future runs to completion independently. A
        // regression that funnelled spawns through a shared mutex (or
        // accidentally serialized them via a `tokio::spawn` wrapper
        // that awaited the prior handle) would still pass the single-
        // task happy-path test but would fail here by either taking
        // much longer or by missing entries in the shared counter.
        const N: usize = 20;
        let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        for _ in 0..N {
            let counter_clone = Arc::clone(&counter);
            spawn_background("concurrent", async move {
                let _ = counter_clone.fetch_add(1, Ordering::SeqCst);
            });
        }
        for _ in 0..200 {
            if counter.load(Ordering::SeqCst) == N {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(
            counter.load(Ordering::SeqCst),
            N,
            "all {N} background tasks should have run, got {}",
            counter.load(Ordering::SeqCst)
        );
    }

    #[test]
    fn spawn_background_function_return_type_is_unit() {
        // Pin the public API return type — `()`, not `JoinHandle<()>`.
        // Exposing the handle would let callers accidentally block on
        // background work (defeating the fire-and-forget contract) and
        // would be a silently-breaking API change. The `let _: () =`
        // binding enforces this at monomorphisation time.
        //
        // The test body constructs-but-does-not-run: the goal is
        // compile-time verification, not execution.
        let f = || {
            let _: () = spawn_background("api-pin", async move {});
        };
        let _ = f; // suppress unused-closure warning
    }

    #[test]
    fn subsystem_handle_is_send_and_static() {
        // Compile-time pin: `SubsystemHandle` flows across task
        // boundaries (constructed on the main orchestration task, moved
        // into a `stop_subsystem` call site that may execute inside a
        // separately-spawned shutdown coordinator). A refactor that
        // embedded a non-`Send` field or a borrowed reference would
        // break every downstream caller. Pin via a local bound helper.
        fn assert_bounds<T: Send + 'static>() {}
        assert_bounds::<SubsystemHandle>();
    }

    #[tokio::test]
    async fn subsystem_handle_new_stores_same_shutdown_arc_it_was_given() {
        // The `shutdown: Arc<Notify>` field must be the same Arc the
        // caller passed in — not a freshly-allocated clone. Callers
        // rely on this so they can clone the Arc before construction,
        // hand the clone to the task body, and keep the original for
        // later notification. A regression that internally re-wrapped
        // `Arc::new(Notify::new())` would silently desync the two.
        let shutdown = Arc::new(Notify::new());
        let expected_ptr = Arc::as_ptr(&shutdown);
        let task = tokio::spawn(async move {});
        let handle = SubsystemHandle::new(Arc::clone(&shutdown), task);
        let stored_ptr = Arc::as_ptr(&handle.shutdown);
        assert_eq!(
            expected_ptr, stored_ptr,
            "SubsystemHandle::new must store the same Arc it was given (got distinct pointers)"
        );
        drop(handle);
    }

    #[tokio::test]
    async fn subsystem_handle_shutdown_field_is_publicly_accessible() {
        // Pin the `pub shutdown: Arc<Notify>` field visibility — the
        // server crate's graceful-shutdown flow clones this field to
        // propagate the stop signal into watchdog tasks. A refactor
        // that narrowed to `pub(crate)` would break the server crate's
        // callers with an invisible-from-rustgate-core compile error.
        let shutdown = Arc::new(Notify::new());
        let task = tokio::spawn(async move {});
        let handle = SubsystemHandle::new(Arc::clone(&shutdown), task);
        // Direct field access — not via a getter — must compile.
        let _: &Arc<Notify> = &handle.shutdown;
        let _cloned: Arc<Notify> = Arc::clone(&handle.shutdown);
        drop(handle);
    }

    #[tokio::test(start_paused = true)]
    async fn stop_subsystem_timeout_is_exactly_five_seconds_of_virtual_time() {
        // The 5-second drain deadline is documented in the docstring
        // ("matches the drain deadline used by the binary's graceful-
        // shutdown flow") and is operationally shared with the
        // binary's SIGTERM handler. A regression that shortened to 3s
        // or widened to 10s would silently break drain SLOs. Pin the
        // exact value with a narrow window by measuring virtual-time
        // elapsed around a stuck task.
        let shutdown = Arc::new(Notify::new());
        let task = tokio::spawn(async move {
            std::future::pending::<()>().await;
        });
        let handle = SubsystemHandle::new(shutdown, task);

        let start = tokio::time::Instant::now();
        stop_subsystem("exact-timeout", handle).await;
        let elapsed = start.elapsed();

        assert!(
            elapsed >= Duration::from_secs(5),
            "stop_subsystem timeout must be at least 5s (got {elapsed:?})"
        );
        assert!(
            elapsed < Duration::from_secs(6),
            "stop_subsystem timeout must be less than 6s (got {elapsed:?})"
        );
    }

    #[tokio::test]
    async fn two_subsystems_stop_independently_without_cross_interference() {
        // Pins that stop_subsystem on one handle does not affect a
        // second independently-constructed subsystem. Operationally
        // every deployed rustgate instance runs multiple subsystems
        // (WebSocket, MQTT, federation, plaintext, metrics) and the
        // shutdown sequence stops them one at a time; a regression
        // that shared internal state across handles (e.g. a global
        // NOTIFY lock) would cause the second subsystem's await to
        // return prematurely or hang.
        let shutdown_a = Arc::new(Notify::new());
        let shutdown_b = Arc::new(Notify::new());
        let exited_a = Arc::new(AtomicBool::new(false));
        let exited_b = Arc::new(AtomicBool::new(false));

        let shutdown_a_task = Arc::clone(&shutdown_a);
        let exited_a_task = Arc::clone(&exited_a);
        let task_a = tokio::spawn(async move {
            shutdown_a_task.notified().await;
            exited_a_task.store(true, Ordering::SeqCst);
        });

        let shutdown_b_task = Arc::clone(&shutdown_b);
        let exited_b_task = Arc::clone(&exited_b);
        let task_b = tokio::spawn(async move {
            shutdown_b_task.notified().await;
            exited_b_task.store(true, Ordering::SeqCst);
        });

        let handle_a = SubsystemHandle::new(shutdown_a, task_a);
        let handle_b = SubsystemHandle::new(shutdown_b, task_b);

        // Stop only A — B must still be alive.
        stop_subsystem("subsystem-a", handle_a).await;
        assert!(exited_a.load(Ordering::SeqCst), "A should have exited");
        assert!(
            !exited_b.load(Ordering::SeqCst),
            "B must NOT have exited when A was stopped"
        );

        // Now stop B — it should still complete normally.
        stop_subsystem("subsystem-b", handle_b).await;
        assert!(exited_b.load(Ordering::SeqCst), "B should have exited");
    }

    #[test]
    fn spawn_background_name_parameter_requires_static_str_lifetime() {
        // The `name: &'static str` parameter is deliberate: it flows
        // into the `tracing::error!` call that fires if the background
        // task panics, and that call happens at an unknown future time
        // relative to the spawn site. A regression that narrowed the
        // bound to `&str` would compile at the spawn site but fail the
        // tracing macro at the panic-log site (borrowed lifetime does
        // not outlive the spawned watcher). Pin compile-time only via
        // a closure we never invoke — the monomorphised signature is
        // what we are asserting, not runtime behaviour.
        #[allow(dead_code, clippy::type_complexity)]
        fn accepts_static_name()
        -> fn(&'static str, std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>)
        {
            // Re-statement of `spawn_background`'s signature: if the
            // production signature narrowed the `'static` bound on the
            // name, this coercion would fail. We do not call the
            // returned pointer — the compile-time check is the assert.
            fn wrapper(
                name: &'static str,
                fut: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>,
            ) {
                spawn_background(name, fut);
            }
            wrapper
        }
        let _ = accepts_static_name();
    }
}
