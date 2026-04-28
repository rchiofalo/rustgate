# ADR 0003: `ArcSwap<Option<T>>` for hot-reloadable shared state

- **Status:** Accepted
- **Date:** 2026-04-27
- **Related:** [ADR 0001](0001-parking-lot-mutexes-for-sync-paths.md),
  [ADR 0002](0002-tokio-rwlock-across-await.md)

## Context

Several pieces of state in the rustgate router are read on every
message but written only when an operator triggers a SIGHUP reload:
the ACL policy, the authorization engine, the dedup cache, the
peer-discovery snapshot, the CRL, the per-tenant quota tracker, and
several Prometheus-callback slots. Two access patterns dominate:

- Read-heavy: a fan-out routing operation may consult the ACL and
  authz engine for every recipient. Even at modest throughput, the
  read rate is orders of magnitude higher than the write rate.
- Write-rare: the only writes happen when a config file is
  reloaded, when peer discovery converges, or when a feature flag
  is flipped at runtime — events that occur seconds to minutes
  apart at most.

A `tokio::sync::RwLock<T>` would work but pays for synchronization
on every read. A `parking_lot::RwLock<T>` is faster but still
contends a writer against readers. Neither is acceptable on a hot
path that needs to scale to tens of thousands of routed messages
per second per server.

`arc_swap::ArcSwap<T>` is a lock-free read primitive: readers do an
atomic load of an `Arc<T>` and increment a refcount; writers
atomically swap a new `Arc<T>` into the slot. There is no exclusion
between readers and writers — readers see whichever value was
current at the moment they loaded.

## Decision

Use `ArcSwap<Option<T>>` for state that is read on the hot path
and written only at reload boundaries. The `Option` wrapper
expresses the "feature is configured" state without an extra
sentinel: `None` means the feature is not installed, `Some(value)`
means it is.

The canonical access patterns are:

```rust
// Read (router hot path — fires per message)
let guard = self.acl.load();           // arc_swap::Guard<Arc<Option<T>>>
let acl_ref: &Option<T> = &guard;      // deref through Guard to inner
if let Some(acl) = acl_ref {
    // use acl
}
```

```rust
// Write (SIGHUP reload — fires at most once per few seconds)
self.acl.store(Arc::new(Some(new_policy)));
// readers see the new value on their next .load()
```

The double-deref `(**guard)` form appears in places where the inner
`Option` needs to be matched directly — see `router.rs` for the
exact spelling. Both forms are correct; the explicit `&*guard` is
preferred when the caller wants to bind a named reference.

The router (`crates/rustgate-transport/src/router.rs`) is the
single largest consumer; representative fields:

- `acl: ArcSwap<Option<GroupAclPolicy>>`
- `authz: ArcSwap<Option<Arc<dyn PolicyEngine>>>`
- `authz_observer: ArcSwap<Option<AuthzObserver>>`
- `dedup: ArcSwap<Option<DedupCache>>`
- `multicast_config: ArcSwap<Option<MulticastConfig>>`
- `quota_tracker: ArcSwap<Option<Arc<TenantQuotaTracker>>>`

The TLS verifier root store and CRL use the same pattern through a
rebuilt `WebPkiClientVerifier`.

## Alternatives considered

- **`tokio::sync::RwLock<T>`.** Read paths block when a writer is
  waiting (or vice versa, depending on policy). Acceptable for
  state that needs to be held across `.await`, but on the routing
  hot path it becomes the contended primitive. See
  [ADR 0002](0002-tokio-rwlock-across-await.md) for when this
  primitive is the right choice.
- **`parking_lot::RwLock<T>`.** Faster than `tokio::sync::RwLock`
  but still contends. Acceptable when the read path is rare or the
  contention shape is symmetric; not acceptable on the hot path.
- **Atomics.** Workable for a single primitive (e.g. an `AtomicBool`
  feature flag), but the policies we hot-reload are large structs
  whose atomic-replacement is not expressible without a wrapper
  like `ArcSwap`.
- **Copy on read.** Cloning the policy on every read trades
  contention for allocation cost, which is worse on a hot path.

## Consequences

- The router carries `ArcSwap` fields whose `Debug` impls have to
  handle the `arc_swap::Guard` indirection (see the `Debug` derive
  on `Router` in `router.rs`).
- Readers see consistent values *within* a single load, but two
  consecutive loads can see different values if a write landed
  between them. This is not a problem for the policies we
  hot-reload — each routing decision is self-contained — but it
  means the pattern is unsuitable for invariants that span
  multiple reads of the same field. When such a span is required,
  load once into a local and reuse the local.
- A reload is observable on the next `.load()` after the `.store()`
  call; there is no API for "wait until all readers have moved on"
  because the shape doesn't need it. The previous `Arc` is
  released as the last in-flight `Guard` drops.
- The `arc_swap` crate is now a foundational workspace dependency.
  It is small, well-maintained, and on the audit allowlist.
- Future state that fits the read-heavy / write-rare shape should
  default to this pattern. Reviewers will push back on a
  `tokio::sync::RwLock` on a routing-hot field unless there is a
  good reason (e.g. the lock is held across `.await`).
