# ADR 0002: `tokio::sync` locks for state held across `.await`

- **Status:** Accepted
- **Date:** 2026-04-27
- **Related:** [ADR 0001](0001-parking-lot-mutexes-for-sync-paths.md),
  [ADR 0003](0003-arcswap-hot-reload.md)

## Context

Some shared state in rustgate must be held across `.await` points —
for example, an iterator over the federation peer set while the
runtime awaits a per-peer dial, or a guard on the store-and-forward
queue while a redb write completes. Holding a `std::sync::Mutex`
or `parking_lot::Mutex` guard across `.await` is unsound for two
reasons:

1. The tokio runtime can move the awaiting task to a different
   thread when it resumes, but the OS-level mutex bookkeeping
   captures the locking thread. On wake-up the unlock attempt
   crosses a thread boundary that the mutex did not consent to.
2. Even setting aside soundness, cooperative scheduling means a
   task holding a sync lock across `.await` blocks every other
   task on the same runtime thread for the duration of the await.
   That converts a brief I/O wait into a runtime-wide stall.

The clippy lint `clippy::await_holding_lock` catches the obvious
shape (`let g = m.lock(); some_async().await;`) but not every
indirect one — for instance, a `MutexGuard` stored in a struct
that the async function later uses.

## Decision

State that needs to be locked across `.await` uses the `tokio::sync`
family:

- `tokio::sync::RwLock<T>` for read-heavy state where multiple
  readers can proceed in parallel and writers are rare.
- `tokio::sync::Mutex<T>` for state where exclusion is required
  even on the read path, or where the contention pattern doesn't
  benefit from RW separation.

Sync primitives (`parking_lot::Mutex`, `std::sync::OnceLock`,
atomic types) remain the right choice for state that is *not* held
across `.await`. The two regimes coexist: `parking_lot` for short
nanosecond-scale critical sections inside async tasks (see
[ADR 0001](0001-parking-lot-mutexes-for-sync-paths.md)),
`tokio::sync` for state held while the task awaits.

The `.claude/rules/shared-infrastructure.md` decision table lists
this as the "take a lock across `.await`" answer.

## Alternatives considered

- **Hold a `parking_lot::Mutex` across `.await`.** Unsafe per the
  reasoning above. The unsoundness is subtle but real, and even if
  the language ever made it sound, the runtime-wide stall cost
  remains.
- **Use a single `tokio::sync` primitive for everything.** Rejected:
  the `tokio::sync` types are heavier than `parking_lot` and require
  the runtime context for scheduling. For nanosecond-scale critical
  sections that never await, that overhead is unjustified.
- **`async-lock` or other third-party async lock crates.**
  Rejected: tokio is already the runtime; using its native lock
  family avoids one more dependency and one more set of cross-crate
  interactions to reason about.

## Consequences

- Two locking regimes in the workspace. Reviewers and authors must
  pick the right one. The decision table in
  `.claude/rules/shared-infrastructure.md` is the canonical
  reference and the clippy `await_holding_lock` lint catches most
  drift automatically.
- A future change that converts a sync code path to async cannot
  simply leave the existing `parking_lot` lock in place — the lock
  type must change as the await lands. This is friction worth
  accepting for the soundness guarantee.
- Frequently-read but rarely-written state has a third option that
  often wins: hot-reload via [`ArcSwap`](0003-arcswap-hot-reload.md).
  ACL, authz, dedup, CRL, and the peer set all use `ArcSwap`
  precisely because the read path is on the hot path of every
  message and never needs to await. When the read path is short
  *and* there are no writers across await, prefer `ArcSwap` over
  `tokio::sync::RwLock`.
- If a contributor finds themselves wanting to hold a
  `parking_lot::Mutex` across `.await`, the right move is to
  rethink the data structure. Most often the answer is to copy or
  move the relevant field out of the lock before the await, not to
  switch lock types.
