# ADR 0001: `parking_lot::Mutex` for sync hot paths

- **Status:** Accepted
- **Date:** 2026-04-27
- **Related:** [ADR 0002](0002-tokio-rwlock-across-await.md),
  `.claude/rules/shared-infrastructure.md` decision table

## Context

rustgate has several short-duration sync critical sections that are
on the hot path of every routed message — per-session sender slots
(`router.rs`), the dedup cache, the position cache replay buckets,
the per-tenant quota tracker. These sections are never held across
`.await`. They are entered from inside async tasks but they
themselves are a few non-async lines of work: read a `HashMap`, swap
an `Option`, update a counter.

Two viable Rust mutex implementations exist for this shape of work:
`std::sync::Mutex` from the standard library, and
`parking_lot::Mutex` from the `parking_lot` crate. They differ in
two material ways:

1. **Poisoning.** `std::sync::Mutex` poisons itself if a thread
   panics while holding the lock; subsequent `.lock()` calls return
   `Err(PoisonError)` and callers must unwrap or handle the error.
   `parking_lot::Mutex` does not poison — a panic releases the lock
   and the next caller sees the (potentially inconsistent) state.
2. **Hot-path cost and size.** `parking_lot` uses a one-byte mutex
   with a sleep-then-spin fast path; `std::sync::Mutex` is several
   words and goes through the kernel sooner. For a critical section
   that takes nanoseconds, that difference is measurable.

The workspace lints `clippy::unwrap_used = "deny"`. Every
`std::sync::Mutex::lock()` site would either need an `expect()`
with context or explicit poison handling — both of which clutter
the call site and obscure the intent (we *want* to crash hard if
the lock is held during a panic; the panic is the bug). Tests are
exempt from the unwrap denial, so the friction is concentrated in
production code where it hurts the most.

## Decision

Use `parking_lot::Mutex` for any synchronous lock that is not held
across `.await`. The hot paths under `rustgate-transport::router`,
the per-session sender slots, the multicast subscriber map, and
similar internal state all use `parking_lot`.

`std::sync::Mutex` is acceptable in tests, in `build.rs` scripts,
and anywhere the call site genuinely wants poisoning semantics —
but in the workspace today, no production code does.

The `.claude/rules/shared-infrastructure.md` decision table lists
this as the "take a sync mutex on a hot path" answer.

## Alternatives considered

- **`std::sync::Mutex`.** Rejected for hot paths because the
  poisoning ergonomics force every call site to either `unwrap` (a
  workspace-wide denied lint) or handle a `PoisonError` we do not
  meaningfully recover from. The kernel-fast-path cost is also
  measurable in tight loops.
- **`crossbeam::sync` primitives.** Rejected for general-purpose
  use — the workspace already has `parking_lot` as a transitive
  dependency through `tokio` and other crates, so adopting it
  directly costs nothing extra.
- **Spin locks.** Rejected: critical sections in the router can run
  long enough that pure spinning would burn CPU. `parking_lot`'s
  spin-then-sleep is the right shape.

## Consequences

- Production code reaches for `parking_lot::Mutex` by default for
  short sync critical sections. No `.unwrap()` on `.lock()`.
- A panic inside a critical section leaves the data in whatever
  state it was when the panic landed; the next lock holder sees
  that state. We accept this in exchange for cleaner hot-path
  code. Where consistency matters, the contained data must be
  designed to tolerate a partial update (most often, an
  `Option<T>` with `None` as the safe default).
- `parking_lot` is a non-trivial dependency that we now rely on for
  correctness. It is well-maintained, MIT/Apache-2.0, and audited
  by `cargo-deny`.
- Locks held *across* `.await` go through the `tokio::sync` family
  instead — see [ADR 0002](0002-tokio-rwlock-across-await.md). The
  two ADRs together describe the workspace's locking discipline.
- Future contributors who reach for `std::sync::Mutex` on a hot
  path will trip the clippy unwrap denial as soon as they call
  `.lock()`. That is the lint working as intended; the fix is to
  switch to `parking_lot`, not to add an `// justification:`.
