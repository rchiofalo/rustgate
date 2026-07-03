# ADR 0028: `dashmap` for the position cache; single mutex stays for LRU/window maps

- **Status:** Accepted
- **Date:** 2026-07-03
- **Deciders:** rustgate maintainers
- **Related:** #1524, #836, #902, #1542; [ADR 0001](0001-parking-lot-mutexes-for-sync-paths.md), [ADR 0002](0002-tokio-rwlock-across-await.md)

## Context

Issue #836 asked whether the `parking_lot::Mutex<HashMap>` /
`RwLock<HashMap>` shapes on the router hot path — the dedup cache, the
position cache, the sliding-window connection rate limiter, and the
tenant quota tracker — cap out on a single lock at the 10k+ msg/s the
tactical fleet targets on a 16-core host. The correct answer is "measure
first, migrate only what the data justifies," and #1524 is the follow-up
that carries the measurement and the one clean migration.

Before this change the measurement could not actually be taken. Two
criterion benches live in `crates/rustgate-router/benches/`
(`router_fanout.rs` for single-thread routing latency and
`dedup_contention.rs` for the cross-thread map-contention question), but
neither had a `[[bench]] harness = false` entry in `Cargo.toml`. Cargo
therefore ran each under the default libtest harness ("running 0
tests"); `criterion_main!` never executed, and the benchmark-gate
collected zero data. The prerequisite the "benchmark first" instruction
assumes was silently missing.

## Decision

1. **Wire the benches to criterion.** Add `[[bench]] name = "…"
   harness = false` entries for both `router_fanout` and
   `dedup_contention` so `criterion_main!` runs and the gate produces
   numbers.

2. **Migrate the position cache to `dashmap::DashMap`.**
   `crates/rustgate-router/src/cache.rs` now stores
   `DashMap<Arc<str>, PositionEntry>` instead of
   `RwLock<HashMap<Arc<str>, PositionEntry>>`. The public API stays
   `async` so no call site changes; DashMap's per-shard locks never span
   an `.await`, so this does not run afoul of [ADR 0002](0002-tokio-rwlock-across-await.md).

3. **Explicitly defer the dedup and rate-limiter migrations** to
   follow-up branches — a raw `DashMap` swap of either would be a
   regression, not an improvement (see Alternatives).

### Captured baseline

`cargo bench -p rustgate-router --bench dedup_contention`, Apple M3 Max
dev box (14 physical cores; the issue's target is a 16-core Linux host,
so absolute throughput will differ but the deltas carry):

| Workers | `parking_lot::Mutex<HashMap>` | `dashmap::DashMap` |
|--------:|------------------------------:|-------------------:|
| 4       | ~10.2 Melem/s                 | ~51 Melem/s        |
| 8       | ~7.9 Melem/s                  | ~55 Melem/s        |
| 16      | ~6.4 Melem/s                  | ~58 Melem/s        |

The single-mutex shape *collapses* from 10.2 to 6.4 Melem/s as workers
climb from 4 to 16 (contention on the one lock dominates), while the
sharded map holds ~51–58 Melem/s — roughly 8x faster at 16 workers, and
flat under contention. That delta is what justifies migrating the one
map that can take a sharded store cleanly.

## Alternatives considered

- **Migrate all four hot-path maps to `DashMap` in one pass.** Rejected:
  only the position cache is a clean swap. It has no
  read-time-mutation or capacity-accounting coupling, so a sharded map
  is a drop-in. The others are not (below).

- **Swap the dedup cache to a raw `DashMap`.** Rejected as *harmful*.
  The dedup cache wraps an `LruCache`: every lookup mutates the LRU
  recency pointer, and capacity eviction with miss/eviction accounting
  is a correctness feature (#902). A raw `DashMap` has no LRU semantics,
  so this swap would silently drop capacity eviction and the accounting —
  degrading dedup correctness under exactly the load the migration is
  meant to help. `dedup_contention.rs` deliberately benches a raw map
  (not `LruCache`) so the contention number is not muddied by the LRU
  dimension; that is a contention probe, not a proposed shape. The right
  follow-up is a manual N-shard `Mutex<LruCache>`, which preserves
  per-shard LRU + eviction accounting. Deferred to its own branch.

- **Swap the sliding-window connection rate limiter to `DashMap`.**
  Rejected. It holds `Mutex<HashMap<IpAddr, VecDeque<Instant>>>` plus a
  `last_sweep` bookkeeping field; a naive per-key shard would fragment
  the sweep bookkeeping and change the window semantics. Deferred.

- **Convert the position-cache API from `async` to sync** (since DashMap
  is sync). Rejected for this change: dropping `.await` from
  `store`/`get_all`/`remove`/`sweep` would ripple into `router.rs`, the
  JetStream replay path, and several integration tests across crates for
  no functional benefit. Keeping the API `async` makes the migration a
  contained, call-site-invisible internal change.

## Consequences

- The benchmark-gate now runs. `cargo bench -p rustgate-router --bench
  dedup_contention` and `--bench router_fanout` emit timing lines and
  write to `target/criterion/`; future PRs touching these paths can
  detect contention or fanout regressions.

- The position cache is lock-free-ish under contention (per-shard locks
  only). One semantic change: `sweep`, `get_all`, and the
  capacity-eviction min-seq scan take per-shard locks rather than one
  map-wide lock, so they no longer observe a single consistent snapshot
  of the map. This is acceptable — TTL expiry and capacity eviction were
  already approximate (interval sweep, monotonic-seq ranking per #1542),
  `get_all` filters expired entries on read, and no invariant depends on
  a whole-map atomic view.

- The dedup cache and rate limiter keep their single-lock shapes and
  their `parking_lot` discipline from [ADR 0001](0001-parking-lot-mutexes-for-sync-paths.md).
  Their sharded migrations are tracked as follow-ups and must preserve
  LRU/eviction accounting (dedup) and window/sweep bookkeeping
  (limiter), not swap in a raw `DashMap`.

- Reversible: the position cache can revert to `RwLock<HashMap>` by
  restoring the field type and re-adding `.read()/.write().await` inside
  the (unchanged) async methods. No external contract depends on the
  internal store type.
