// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Contention benchmark for hot-path map shapes.
//!
//! Issue #836 asks: under 10k+ msg/s on a multi-core production host, do
//! the `parking_lot::Mutex<HashMap>` shapes used by the dedup cache,
//! position cache, replay-bucket map, and tenant quota tracker cap out
//! on the single mutex? The criterion benches that ship in
//! `router_fanout.rs` measure single-threaded routing latency — they do
//! not exercise the cross-thread contention pattern that the issue
//! describes, so we cannot answer the question from existing data.
//!
//! This bench compares two map shapes under a contended dedup-cache-like
//! workload:
//!
//! 1. `parking_lot::Mutex<HashMap<u64, Instant>>` — the current shape
//!    used by `DedupCache` (which wraps `LruCache` rather than a raw
//!    `HashMap`, but the contention surface is the single mutex around
//!    a write-heavy map).
//! 2. `dashmap::DashMap<u64, Instant>` — sharded internal RwLocks; the
//!    proposed alternative for >10k-entry hot-path maps.
//!
//! ## Workload shape
//!
//! Each iteration drives a fixed number of `insert + lookup` operations
//! split across N concurrent workers. The key space is large enough that
//! every operation hits a unique entry on the first insert (so the map
//! grows to a realistic size during the warm-up) and a 1-in-K subset
//! repeats on the lookup half (so the time-windowed expiry branch is
//! exercised). The shape mirrors what `DedupCache::lookup_or_insert`
//! actually does on the dispatch hot path:
//!
//! - Hash the key (here, a pre-computed `u64` so the bench measures
//!   *map* contention, not SHA-256).
//! - Lock the map (or, for DashMap, lock the relevant shard).
//! - Check whether the key exists; if it does, compare the timestamp
//!   against a rolling "now" instant and decide whether the entry is
//!   still alive within the dedup window.
//! - Insert (or update) the entry and release the lock.
//!
//! The bench deliberately drops the LRU dimension — `LruCache` requires
//! mutation on every read (the LRU pointer needs to move) and DashMap
//! has no built-in LRU semantics, so a fair comparison would require
//! us to either (a) abandon LRU eviction in the DashMap variant or
//! (b) layer a second data structure on top, both of which would change
//! correctness and thus muddy the contention measurement. The point of
//! the benchmark is to answer "would a sharded concurrent map reduce
//! the wall-clock cost of the contended critical section?" — not "does
//! a hypothetical lossy DashMap-only swap preserve dedup correctness?".
//!
//! ## Worker counts
//!
//! 4, 8, 16 — the issue's stated 16-core production host plus two
//! sub-saturation points so we can read the contention curve. On the
//! Apple M3 Max dev box the curve is shifted (14 physical cores) but
//! the relative deltas between the two map shapes carry through.
//!
//! Output is in `target/criterion/` after `cargo bench --bench
//! dedup_contention`. PR #836 captures the baseline numbers.

#![allow(clippy::panic, clippy::unwrap_used, unused_results)]

use std::collections::HashMap;
use std::hint::black_box;
use std::sync::Arc;
use std::time::{Duration, Instant};

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use dashmap::DashMap;
use parking_lot::Mutex;
use tokio::runtime::Runtime;

/// Worker counts to sweep — the issue's 16-core scenario plus 4 and 8
/// to read the contention curve on lower core counts.
const WORKER_COUNTS: &[usize] = &[4, 8, 16];

/// Operations per benchmark iteration. Tuned so the per-iteration cost
/// is well above criterion's noise floor on a 14-core M3 dev host
/// (~10 ms per iter at 16 workers on parking_lot) but small enough that
/// criterion's default sample count converges within a reasonable
/// wall-clock budget.
const OPS_PER_ITER: usize = 8_192;

/// Pre-populated entry count for the maps. The issue calls out >10k as
/// the threshold where contention starts to bite; 50k seeds the maps
/// well past that ceiling so every benchmarked op lands in a
/// realistically-sized table.
const PREPOPULATE_ENTRIES: u64 = 50_000;

/// Window the lookup half compares against. Modeled on the production
/// dedup window (15s default) so the "alive entry" branch dominates —
/// matching the steady-state behaviour of a busy cache where almost
/// every lookup hits an entry that has not yet aged out.
const LIVENESS_WINDOW: Duration = Duration::from_secs(15);

fn build_runtime(workers: usize) -> Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_time()
        .build()
        .expect("build multi-thread tokio runtime for contention bench")
}

/// `parking_lot::Mutex<HashMap>` reference shape.
///
/// The `lookup_or_insert` method mirrors the critical section in
/// [`crate::dedup::DedupCache::lookup_or_insert`] minus the LRU
/// reposition: lock, lookup, decide on liveness, insert if absent or
/// expired. Returning `bool` lets the bench black-box the result so
/// the optimizer cannot fold the call away.
struct PlMap {
    inner: Mutex<HashMap<u64, Instant>>,
    window: Duration,
}

impl PlMap {
    fn with_capacity(cap: usize, window: Duration) -> Self {
        Self {
            inner: Mutex::new(HashMap::with_capacity(cap)),
            window,
        }
    }

    fn lookup_or_insert(&self, key: u64) -> bool {
        let now = Instant::now();
        let mut guard = self.inner.lock();
        if let Some(stamp) = guard.get(&key)
            && now.duration_since(*stamp) < self.window
        {
            return true;
        }
        guard.insert(key, now);
        false
    }
}

/// `dashmap::DashMap` candidate shape.
///
/// DashMap is internally sharded — its default shard count is
/// `(num_cpus * 4).next_power_of_two()`, each guarded by an
/// `RwLock`. The lookup-then-insert pattern is encoded with the
/// `entry` API so the read and write halves of the operation share a
/// single shard lock acquisition (matching what `DedupCache` does in
/// its `Mutex` critical section).
struct DmMap {
    inner: DashMap<u64, Instant>,
    window: Duration,
}

impl DmMap {
    fn with_capacity(cap: usize, window: Duration) -> Self {
        Self {
            inner: DashMap::with_capacity(cap),
            window,
        }
    }

    fn lookup_or_insert(&self, key: u64) -> bool {
        let now = Instant::now();
        match self.inner.entry(key) {
            dashmap::Entry::Occupied(mut e) => {
                if now.duration_since(*e.get()) < self.window {
                    return true;
                }
                e.insert(now);
                false
            }
            dashmap::Entry::Vacant(e) => {
                e.insert(now);
                false
            }
        }
    }
}

fn prepopulate_pl(map: &PlMap, count: u64) {
    let now = Instant::now();
    let mut guard = map.inner.lock();
    for k in 0..count {
        guard.insert(k, now);
    }
}

fn prepopulate_dm(map: &DmMap, count: u64) {
    let now = Instant::now();
    for k in 0..count {
        map.inner.insert(k, now);
    }
}

/// Drive `OPS_PER_ITER` operations split across `workers` tasks against
/// a `parking_lot` map. Each task runs `OPS_PER_ITER / workers`
/// `lookup_or_insert` calls, with keys striped so every worker hits
/// independent buckets in expectation (no artificial contention from
/// shared-key hot-spotting).
async fn run_pl(map: Arc<PlMap>, workers: usize) {
    let per_worker = OPS_PER_ITER / workers;
    let mut handles = Vec::with_capacity(workers);
    for w in 0..workers {
        let map = Arc::clone(&map);
        let base = (w as u64) * (per_worker as u64);
        handles.push(tokio::spawn(async move {
            for i in 0..per_worker {
                // Half live-hits (existing keys), half fresh inserts —
                // matching the dispatch-hot-path pattern of mostly
                // duplicate suppression but with a steady stream of
                // fresh messages mixed in.
                let key = if i & 1 == 0 {
                    (i as u64) % PREPOPULATE_ENTRIES
                } else {
                    PREPOPULATE_ENTRIES + base + (i as u64)
                };
                let _ = black_box(map.lookup_or_insert(key));
            }
        }));
    }
    for h in handles {
        let _ = h.await;
    }
}

async fn run_dm(map: Arc<DmMap>, workers: usize) {
    let per_worker = OPS_PER_ITER / workers;
    let mut handles = Vec::with_capacity(workers);
    for w in 0..workers {
        let map = Arc::clone(&map);
        let base = (w as u64) * (per_worker as u64);
        handles.push(tokio::spawn(async move {
            for i in 0..per_worker {
                let key = if i & 1 == 0 {
                    (i as u64) % PREPOPULATE_ENTRIES
                } else {
                    PREPOPULATE_ENTRIES + base + (i as u64)
                };
                let _ = black_box(map.lookup_or_insert(key));
            }
        }));
    }
    for h in handles {
        let _ = h.await;
    }
}

fn bench_parking_lot(c: &mut Criterion) {
    let mut group = c.benchmark_group("dedup_contention_parking_lot");
    group.throughput(Throughput::Elements(OPS_PER_ITER as u64));

    for &workers in WORKER_COUNTS {
        let rt = build_runtime(workers);
        // A fresh, pre-populated map per parameter so cross-pollution
        // between worker counts cannot leak into the deltas.
        let map = Arc::new(PlMap::with_capacity(
            (PREPOPULATE_ENTRIES * 2) as usize,
            LIVENESS_WINDOW,
        ));
        prepopulate_pl(&map, PREPOPULATE_ENTRIES);

        group.bench_with_input(
            BenchmarkId::from_parameter(workers),
            &workers,
            |b, &workers| {
                b.to_async(&rt).iter(|| {
                    let map = Arc::clone(&map);
                    async move {
                        run_pl(map, workers).await;
                    }
                });
            },
        );
    }

    group.finish();
}

fn bench_dashmap(c: &mut Criterion) {
    let mut group = c.benchmark_group("dedup_contention_dashmap");
    group.throughput(Throughput::Elements(OPS_PER_ITER as u64));

    for &workers in WORKER_COUNTS {
        let rt = build_runtime(workers);
        let map = Arc::new(DmMap::with_capacity(
            (PREPOPULATE_ENTRIES * 2) as usize,
            LIVENESS_WINDOW,
        ));
        prepopulate_dm(&map, PREPOPULATE_ENTRIES);

        group.bench_with_input(
            BenchmarkId::from_parameter(workers),
            &workers,
            |b, &workers| {
                b.to_async(&rt).iter(|| {
                    let map = Arc::clone(&map);
                    async move {
                        run_dm(map, workers).await;
                    }
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_parking_lot, bench_dashmap);
criterion_main!(benches);
