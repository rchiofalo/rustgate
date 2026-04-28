# ADR 0010: `spawn_background` + `SubsystemHandle` for task lifecycle

- **Status:** Accepted
- **Date:** 2026-04-27
- **Related:** `crates/rustgate-core/src/tasks.rs`,
  `.claude/rules/shared-infrastructure.md`
  "Shutdown / Subsystem Lifecycle"

## Context

A typical rustgate process spawns dozens of background tokio
tasks: per-session listeners (TLS, WebSocket, MQTT, plaintext TCP
and UDP), the federation peer connector, the NATS bridge, the
Prometheus / health HTTP server, periodic CRL reloaders, position
cache sweepers, peer-discovery reconcilers, and so on. Two
recurring problems show up if every site reaches for `tokio::spawn`
directly:

1. **Silent panics.** `tokio::spawn` returns a `JoinHandle` whose
   `JoinError` carries the panic. If the handle is dropped (the
   common "fire and forget" case), the panic disappears. We have
   shipped at least one bug where a background task panicked on a
   condition the unit tests didn't cover and the operator only
   noticed because a metric flatlined.
2. **Ungraceful shutdown.** The server's SIGTERM path needs to
   stop accepting new connections, drain existing ones, and shut
   down the metrics endpoint last (so the readiness probe goes
   `503` before listeners stop). A bare `JoinHandle` does not
   give the orchestrator a way to signal "stop accepting" without
   killing in-flight work.

`tokio` itself has primitives for both (`tokio_util::task::Tracker`,
`CancellationToken`, etc.) but they are general-purpose and don't
encode the patterns we want. We want one workspace-wide answer for
"spawn a task that might panic, and if it does, log the panic" and
one for "manage a subsystem that needs graceful drain on SIGTERM".

## Decision

Two helpers in `rustgate-core::tasks` cover the workspace:

**`spawn_background(name: &'static str, fut)`** — fire-and-forget
spawn with panic logging. Equivalent to `tokio::spawn(fut)` plus a
second outer task that awaits the inner `JoinHandle` and emits
`tracing::error!(task = name, error = ...)` on panic or unexpected
cancellation. Used for tasks that are *not* part of the graceful-
shutdown contract — periodic sweepers, log writers, fire-and-
forget telemetry pushes.

**`SubsystemHandle { shutdown: Arc<Notify>, task: JoinHandle<()> }`**
— managed subsystem with cooperative shutdown. The caller builds
a shared `Arc<Notify>`, passes a clone into the task body so the
task can `select!` on its accept loop and the notification, and
wraps both in a `SubsystemHandle`. The `stop_subsystem(name,
handle)` helper fires the notification, awaits the task with a 5-
second timeout, and emits structured tracing for each outcome
(stopped cleanly, panicked, did not stop in time). Used for
listeners, the federation manager, the metrics server, and other
subsystems that the SIGTERM path must drain in order.

The `.claude/rules/shared-infrastructure.md` decision table lists
both helpers as the canonical answer for "spawn a background
task" and "start a drainable subsystem" respectively.

## Alternatives considered

- **Bare `tokio::spawn` with a comment "we don't care about the
  return".** Rejected: silent panics in background tasks are how
  observability bugs ship to production. The cost of the wrapper
  helper is a few dozen lines in `rustgate-core`; the savings is
  that every panic surfaces in the audit / tracing log with the
  task name.
- **`tokio_util::task::TaskTracker`.** Workable, and possibly the
  right migration target if we needed structured task
  hierarchies. The current shape is intentionally minimal: most
  subsystems don't need a `TaskTracker`, they need a single
  shutdown signal.
- **A bespoke actor framework.** Rejected: the workspace's
  background-task population is large but not complex. An actor
  framework would impose ceremony (mailboxes, addresses,
  supervisor trees) on tasks that just need to start, run a
  loop, and stop on a signal.
- **Force every task to participate in the graceful-shutdown
  protocol.** Rejected: some tasks genuinely are fire-and-forget
  (a one-shot Prometheus push, a sweep that runs to completion in
  milliseconds). Forcing every spawn through `SubsystemHandle`
  would add boilerplate for no benefit.

## Consequences

- Bare `tokio::spawn` is rare in the workspace. The two cases
  where it appears are (a) inside helper crates where the panic-
  logging wrapper would be circular, and (b) inside test code
  where the test runner catches panics directly.
- `SubsystemHandle` users follow a three-step shape:
  1. `let shutdown = Arc::new(Notify::new());`
  2. `let task = tokio::spawn(async move { ... shutdown.notified().await ... });`
  3. `SubsystemHandle::new(shutdown, task)`
  The shape is mechanical and grep-able across the workspace.
- The 5-second drain timeout in `stop_subsystem` matches the
  default shutdown deadline in the binary
  (`--shutdown-drain-timeout`). If a subsystem genuinely needs
  longer to drain, the right move is to extend the binary
  deadline; the helper's timeout is a guardrail against a
  subsystem hanging forever.
- Future contributors who add a new background task should reach
  for `spawn_background` (fire-and-forget) or `SubsystemHandle`
  (drainable). Reviewers push back on bare `tokio::spawn` calls
  unless there's a clear reason neither helper fits.
- Panics in background tasks are surfaced as structured tracing
  events and, where appropriate, as audit events. The
  `audit::*` family already covers shutdown-time events; a
  background-task panic during steady state shows up in the
  tracing log under the task's name.
