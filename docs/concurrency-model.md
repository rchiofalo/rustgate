# Concurrency Model

This document is the source of truth for choosing concurrency primitives
in rustgate. Atomic ordering, mutex selection, hot-reload patterns, and
background-task lifecycle are surveyed here so a contributor adding a
new shared-state site does not have to re-derive the rules from 350+
existing call sites.

The audience is anyone writing code that crosses a thread or task
boundary. If you are about to type `Mutex`, `Arc`, `Ordering::`,
`ArcSwap`, `tokio::spawn`, or `Send + Sync`, read the relevant section
below first.

## 1. Mutex Discipline

| Primitive | When to use | Notes |
|---|---|---|
| `parking_lot::Mutex<T>` | Default for sync-only critical sections. | Does not poison on panic. **Cannot** be held across `.await` (`MutexGuard` is `!Send`). |
| `parking_lot::RwLock<T>` | Read-heavy sync critical section. | Same `!Send` guard, same await ban. |
| `tokio::sync::Mutex<T>` | Critical section needs to await on I/O, channel send, etc. | More expensive than parking_lot; only reach for this when an await inside the section is unavoidable. |
| `tokio::sync::RwLock<T>` | Read-heavy async critical section. | Same trade-off as above. |
| `std::sync::Mutex<T>` | Avoid in production code. | Banned across `.await` (the standard guard is `!Send`); prefer `parking_lot` for sync sections so a panic on the holder does not poison the lock. Acceptable inside test helpers. |

### Single-source-of-truth rule

A given piece of mutable state is owned by **exactly one** mutex. If a
field needs to be observed from multiple call sites, it is reached via
a shared `Arc<…<Mutex<T>>>` or via accessor methods on the owning type.
**No nested locking** unless the lock-acquisition order is documented
as a deadlock hierarchy at both lock-declaration sites.

In practice, the workspace avoids nested locks entirely. Sites that
appear nested are usually a `parking_lot::Mutex` plus an
`AtomicUsize` (e.g. `DedupCache` holds an `LruCache` under a mutex but
exposes its hit-count via `AtomicU64::fetch_add(.., Relaxed)` so a
caller can read stats without taking the lock).

### Async-await poisoning

The single most common bug pattern in this codebase's history has been
"sync mutex held across an `.await`". Rust's `Send` rules normally
catch it, but the failure mode is subtle when the guard is implicit:

```rust
// BAD — `cache.lock()` returns a !Send guard; awaiting on `tx.send`
// while it is live will not compile, but a refactor that hides the
// guard behind a method can let it slip past review.
let mut cache = self.cache.lock();
cache.put(key, value);
tx.send(notification).await?;   // refuses to compile, but only because
                                 // the guard is still in scope here
```

The fix is to bound the guard's scope explicitly:

```rust
{
    let mut cache = self.cache.lock();
    cache.put(key, value);
}                                // guard drops here
tx.send(notification).await?;    // OK — no live guard across the await
```

This pattern is used throughout `crates/rustgate-transport/src/router.rs`,
`crates/rustgate-transport/src/dedup.rs`, and
`crates/rustgate-resilience/src/token_bucket.rs`. Reviewers should
treat any "lock + await in the same function" diff as suspicious until
the scoping is clear.

## 2. Atomic Ordering Rules

The workspace uses ~350 `Ordering::*` sites across 38 source files.
Picking the right ordering is not optional — `Relaxed` where `Acquire`
is needed produces races that only manifest under load on weakly-ordered
ARM/RISC-V hosts.

### Primer

| Ordering | Cost | Semantics |
|---|---|---|
| `Relaxed` | Cheapest. | No synchronization with other memory. Atomicity only. |
| `Acquire` (loads) / `Release` (stores) | Cheap on x86, real cost on ARM. | Pairs: a `Release` store is observed by an `Acquire` load on the same location, and any earlier writes by the producer become visible to the consumer. |
| `AcqRel` | Read-modify-write equivalent of an `Acquire` load + a `Release` store on the same operation. | Use for CAS, `fetch_add`, `swap` when both halves matter. |
| `SeqCst` | Most expensive. Establishes a single global total order across all `SeqCst` operations. | Use only when correctness genuinely requires global ordering across multiple variables — this is rare in practice. |

### Ordering by primitive class

The workspace's atomic sites cluster into a small number of patterns.
Each row below names the pattern, picks a representative file, and
explains the rationale.

| Pattern | Representative site | Ordering | Rationale |
|---|---|---|---|
| Counters that don't synchronize anything (metrics, hit counts) | `DedupCache::hits` (`crates/rustgate-transport/src/dedup.rs`) | `Relaxed` on load, `Relaxed` on `fetch_add` | Counter is observable but never gates other reads. Strict ordering would buy nothing. |
| Per-tenant connection / queue counters with bounded admission | `TenantQuotaTracker::active_connections` (`crates/rustgate-transport/src/quota.rs`) | `Relaxed` for both halves of the CAS loop | The admission decision is the CAS itself; nothing else hangs on memory ordering between the load and the CAS attempt. CAS retries on contention rather than depending on a happens-before edge. |
| Federation circuit breaker state machine | `CircuitBreaker::state` (`crates/rustgate-resilience/src/circuit.rs`) | `Acquire` on read, `Release` on store, `AcqRel` on CAS / swap | Producer writes "now Open" must be observed by every consumer that subsequently checks state. The `Release` on the trip-side pairs with the `Acquire` on every `is_open()` check. CAS uses `AcqRel` for success and `Acquire` for failure (the standard pattern). |
| Backpressure gate state | `BackpressureGate::blocking` (`crates/rustgate-resilience/src/backpressure.rs`) | `Acquire` / `Release` for state flips, `Relaxed` for byte counters | When the gate flips closed, every subsequent admission check on a different thread must see the closure. The byte counter is `Relaxed` because the gate flip is what gates admission, not the counter value alone. |
| Federation peer state machine | `PeerHandle::state`, `PeerHandle::circuit` (`crates/rustgate-federation/src/peer.rs`) | `Acquire` on read, `Release` on store | Same producer/consumer handoff as `CircuitBreaker`. |
| Federation generation token (used to fence stale reconnect attempts) | `connector.rs:generation` | `Acquire` on read, `Release` on store | Each reconnect attempt loads the current generation; the supervisor publishes a new generation via `Release`. A stale attempt that loads the old value with `Acquire` will see all the supervisor's setup writes that happened before the bump. |
| Token bucket rate limiter (lazy refill) | `TokenBucket::state` (`crates/rustgate-transport/src/throttle.rs`) | `Relaxed` on the CAS loop | The packed (tokens, last_refill) state is a self-contained invariant; CAS is correctness. No happens-before edge needed with anything else. |
| Replay buffer monotonic sequence | `ReplayBuffer::next_seq` (`crates/rustgate-federation/src/replay_buffer.rs`) | `Relaxed` on `fetch_add` | The producer of the sequence number is also the producer of the entry it tags; the entry insertion (under a mutex) carries the happens-before. |

### What we do NOT use

- **`SeqCst` is not used in any production hot path.** Every production
  `SeqCst` site in the workspace is in a `#[cfg(test)]` block, where
  reaching for the heaviest ordering is acceptable to keep test code
  simple. If a production site needs `SeqCst`, it must carry a comment
  explaining why a release-acquire pair would not suffice. Prefer to
  redesign the protocol than to deploy `SeqCst`.

### Adding a new atomic site

When you write a new `AtomicUsize` (or similar):

1. Decide whether the value gates anything else. If not, `Relaxed`.
2. If a producer must publish "now" to a consumer who reads "now",
   `Release` for the producer and `Acquire` for the consumer.
3. For CAS / `fetch_add` / `swap` that both observe and publish, use
   `AcqRel` on success and `Acquire` on failure (the std-library
   recommended idiom for `compare_exchange`).
4. Add a one-line comment at the load and the store explaining the
   pair if the rationale is not local.

If your case does not fit one of these patterns, do not invent a new
one — bring it up in the PR description so a reviewer can pick the
right ordering with you.

## 3. ArcSwap Discipline

`arc_swap::ArcSwap<Option<T>>` is the workspace's standard for hot-
reload of expensive immutable state: the read side is lock-free, the
write side is a single atomic pointer swap, and the old value lives
until every outstanding reader drops its guard.

In-tree consumers:

- `Router::acl: ArcSwap<Option<GroupAclPolicy>>` — group-membership ACL
  hot-reloaded on SIGHUP.
- `Router::authz_engine: ArcSwap<Option<Arc<dyn PolicyEngine>>>` —
  RBAC/ABAC engine swapped when policies recompile.
- `Router::authz_observer: ArcSwap<Option<AuthzObserver>>` — observer
  callback bag.
- `Router::dedup: ArcSwap<Option<DedupCache>>` — the dedup cache (the
  subject of section 4 below).
- `Router::multicast_config: ArcSwap<Option<MulticastConfig>>` — SA
  auto-multicast configuration.
- TLS verifier root store: dynamic `WebPkiClientVerifier` rebuilt on
  CRL reload.

### Read pattern

The double-deref load is required because `ArcSwap::load` returns an
`arc_swap::Guard` that wraps an `Arc<T>`. To get at the inner
`Option<T>`, deref through both:

```rust
let guard = self.acl.load();           // -> Guard<Arc<Option<T>>>
let acl_ref: &Option<T> = &guard;      // double-deref to Option<T>
if let Some(acl) = acl_ref { ... }
```

Equivalent compact form used throughout `router.rs`:

```rust
let guard = self.dedup.load();
if let Some(ref dedup) = **guard { ... }
```

### Write pattern

```rust
self.acl.store(Arc::new(Some(new_policy)));
```

Readers see the new value on their next `.load()`. There is no lock,
no spin, and no per-reader fence beyond what `Arc` already provides.

### The eventual-consistency window

The window between "new policy is published" and "every in-flight
request finishes evaluating against the old policy" is the
**propagation window**. It is bounded by the longest critical section
that holds an outstanding `Guard`. For ACL and authz, this is
microseconds; for `DedupCache`, the same.

A request that started before the swap evaluates against the old
policy and is consistent with itself for that decision. A request
that started after evaluates against the new policy. There is no
"split-brain" window where the same request sees both. See
`docs/authorization.md` for the audit-log implications.

### The no-await-during-load rule (DedupCache)

The most subtle ArcSwap pitfall is holding a `Guard` across an
`.await`. This is the contract enforced by the comment in
`Router::route_inner`:

```rust
{
    // INVARIANT: no `.await` between this load and the end of scope.
    let guard = self.dedup.load();
    if let Some(ref dedup) = **guard
        && dedup.check_payload(...) {
        ...
    }
}
```

Why this matters: the `Guard` is an RAII reference into the
currently-installed value. If a SIGHUP fires while we are awaiting,
the `store` will publish a new `Arc`, but the old `Arc` is held alive
by our guard — fine for memory safety. The hazard is correctness:
the guard now points at a `DedupCache` that no other code reaches.
Any side effects (LRU eviction, metrics callbacks) happen on a
detached cache that is about to be dropped. Reads against it can
deliver stale answers that the operator believed were corrected by
the SIGHUP.

For `DedupCache` specifically, the body uses `parking_lot::Mutex`,
whose `MutexGuard` is `!Send`. The borrow checker would refuse to
compile any `.await` while the inner mutex guard is live. The outer
ArcSwap `Guard` is `Send`, however, so the comment is the load-bearing
documentation of the rule, not the borrow checker.

If you genuinely need to await across the swap window:

- Take a `Clone` of the inner state (`(**guard).clone()`) and let the
  guard drop before the await. Most types in the workspace are `Arc`
  inside the `Option`, so the clone is cheap.
- Or split the work: do the synchronous lookup inside a tight scope
  that drops the guard, then do the awaiting work after.

## 4. Callback Discipline

Every cross-thread function pointer in the workspace has the same
shape:

```rust
pub type OnFoo = Arc<dyn Fn(Args) + Send + Sync>;
```

(See `crates/rustgate-core/src/audit.rs`, `crates/rustgate-transport/
src/cache.rs`, `crates/rustgate-transport/src/dedup.rs`, and 23 other
sites.)

Constraints:

- `Arc<dyn Fn(...) + Send + Sync>`, **not** `Box<dyn FnMut>` and
  **not** `Arc<dyn AsyncFn>`. `dyn AsyncFn` is not object-safe today,
  so async callbacks are expressed by spawning inside the closure.
- Callbacks are sync. If a callback needs to do async work, it does
  `rustgate_core::tasks::spawn_background("name", async move { ... })`
  inside the closure body. The synchronous part runs on the caller's
  thread; the async part is picked up by the runtime.
- Naming: `On*` for events (`OnDuplicate`, `OnInsert`, `OnReject`),
  `*Fn` for forwarding callbacks (`SendFn`, `RouteFn`).

This is summarised in `.claude/rules/shared-infrastructure.md` under
"Callback Type Aliases". This document is the long-form rationale.

## 5. Background Task Lifecycle

Two helpers in `rustgate-core` cover every async task spawned in the
workspace:

| Helper | Use for | Lifecycle |
|---|---|---|
| `spawn_background("name", future)` | Fire-and-forget tasks (timer ticks, log emitters, periodic GC). | Tracing span around the future; panics are caught and logged with `name`. |
| `SubsystemHandle` + `stop_subsystem(name, handle).await` | Listeners, publishers, anything that owns a port or a connection. | Graceful drain via `Arc<tokio::sync::Notify>` with a 5s timeout, then abort. |

### Fire-and-forget

```rust
spawn_background("dedup-sweeper", async move {
    let mut interval = tokio::time::interval(Duration::from_secs(15));
    loop {
        interval.tick().await;
        cache.sweep();
    }
});
```

A panic in the future is recorded as an audit event and the task ends
— it does not crash the process. The lifetime of the task is the
lifetime of any captured `Arc`s in the closure; for tasks that must be
cancellable, prefer `SubsystemHandle`.

### Drainable subsystem

```rust
let shutdown = Arc::new(tokio::sync::Notify::new());
let task = {
    let shutdown = shutdown.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown.notified() => break,
                msg = inbox.recv() => {
                    let Some(msg) = msg else { break };
                    handle(msg).await;
                }
            }
        }
    })
};
let handle = SubsystemHandle { shutdown, task };
// later, on shutdown:
stop_subsystem("publisher", handle).await;
```

`stop_subsystem` notifies, awaits the task with a 5s timeout, and
aborts if the task does not finish. The 5s budget is a system-wide
constant so a slow subsystem cannot block process shutdown.

## 6. Picking a Primitive — Decision Flowchart

Use this chart when you are about to share state across threads or
tasks:

```
Is the state mutated after construction?
├── No  ──> Arc<T>. Done.
│
└── Yes ──> Does a reader need to see a producer's recent writes?
            ├── No (counter, metric only) ──> AtomicU{...} with Relaxed.
            │
            └── Yes ──> Is the state cheap to clone (Arc, copy types)?
                        ├── Yes, AND it's hot-reloaded (rare writes,
                        │       many reads, swap-the-whole-thing) ──>
                        │       ArcSwap<Option<T>>. Read with double-deref;
                        │       no .await between load and drop.
                        │
                        └── No, or you need to read-modify-write in place ──>
                            Need to .await inside the critical section?
                            ├── Yes ──> tokio::sync::{Mutex,RwLock}.
                            │           RwLock if read-heavy.
                            │
                            └── No  ──> parking_lot::{Mutex,RwLock}.
                                        RwLock if read-heavy.
                                        Bound the guard's scope so
                                        future refactors cannot
                                        accidentally await inside.
```

Quick checklist before merging a PR that introduces a new shared-state
site:

- [ ] The primitive matches one of the patterns in section 1 or 2.
- [ ] If `Acquire`/`Release`, the pair is identified at both ends.
- [ ] If a `parking_lot` mutex, no `.await` is reachable inside its
      scope (the borrow checker will catch it; bounding the scope
      explicitly makes the constraint legible to reviewers).
- [ ] If `ArcSwap`, no `.await` between `load()` and the guard drop.
- [ ] If a callback, `Arc<dyn Fn(...) + Send + Sync>` and not
      `dyn AsyncFn`.
- [ ] If a background task, dispatched via `spawn_background` (fire-
      and-forget) or `SubsystemHandle` (drainable).

## Cross-references

- `.claude/rules/shared-infrastructure.md` — workspace-wide quick-
  reference table for "I want to do X, what should I reach for?".
- `docs/authorization.md` — eventual-consistency semantics for the
  authz `ArcSwap` reload.
- `docs/architecture.md` — high-level component diagram.
- `crates/rustgate-resilience/src/circuit.rs` — canonical example of a
  three-state machine implemented in atomics.
- `crates/rustgate-transport/src/dedup.rs` and the
  `Router::route_inner` call site in
  `crates/rustgate-transport/src/router.rs` — canonical example of an
  `ArcSwap`-backed hot-reload with the no-await-between-load-and-drop
  comment that pins the contract.

---

Footer: this document closes #806. It addresses two audit findings
from the internal improvement-analysis review — F-13 (the missing
DedupCache invariant comment, fixed alongside this doc) and F-123
(143 atomic-ordering uses across 23 files lacked a documented model,
addressed by section 2 of this document).
