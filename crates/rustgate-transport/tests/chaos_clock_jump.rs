// Copyright © 2026 Roberto Chiofalo.

#![allow(clippy::panic, clippy::unwrap_used, unused_results)]

//! Chaos test: clock-jump fault injection (refs #788).
//!
//! Two of the production code paths that depend on time are tested here:
//!
//! 1. **Position cache TTL** (`rustgate_router::cache::PositionCache`)
//!    expires entries when `received_at + ttl < SystemTime::now()`.
//!    Because the cache uses `SystemTime` (not `tokio::time::Instant`),
//!    `tokio::time::pause` does not affect it — instead we drive
//!    artificial clock progress by constructing messages with
//!    backdated `received_at` fields. This is functionally identical
//!    to advancing the clock and is the same technique the cache's own
//!    unit tests use for their `make_expired_position` helper.
//! 2. **`tokio::time` driven background work** (`start_sweep_task`).
//!    The sweep task uses `tokio::time::interval`, which IS affected by
//!    `tokio::time::pause` / `advance`. Tests that drive the task use
//!    `#[tokio::test(start_paused = true)]` per the issue's constraint
//!    so they cannot share a runtime with multi-threaded tests.
//!
//! Pinned invariants:
//!
//! - Clock jump **forwards past TTL** retires the entry (covered by
//!   the `received_at`-backdated test).
//! - Clock jump **backwards** is treated as not-expired — the docs in
//!   `cache.rs` say "Clock-backwards tolerance (treats as not-expired)
//!   to avoid spurious eviction"; we pin that.
//! - The TTL check is per-entry: a forward jump that retires one entry
//!   does not retire others with longer TTLs.
//! - `tokio::time::advance` past the sweep interval triggers the
//!   sweep — confirming the `start_sweep_task` integration with the
//!   virtual clock works (regression guard for a tokio version bump
//!   that broke virtual time on `interval`).
//!
//! Deterministic: every test is either pure synchronous arithmetic
//! over backdated `received_at` fields, or runs on a paused-time
//! current-thread runtime. No real-clock sleeps, no flaky races.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use rustgate_core::identity::Identity;
use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};
use rustgate_router::PositionCache;

fn ident(cn: &str) -> Identity {
    Identity::new(cn.to_string(), format!("{cn}-fp"), BTreeSet::new()).unwrap()
}

/// Build a position message whose `received_at` is `received_at` and
/// whose TTL is `ttl`. Manipulating `received_at` is the deterministic
/// equivalent of advancing the wall clock — the TTL check uses
/// `received_at.elapsed()` against `SystemTime::now()`.
fn position_with_received_at(
    cn: &str,
    received_at: SystemTime,
    ttl: Option<Duration>,
) -> RoutableMessage {
    let mut metadata = Metadata::new(received_at, "cot".to_string(), MessageType::Position);
    if let Some(t) = ttl {
        metadata = metadata.with_ttl(t);
    }
    RoutableMessage {
        source: ident(cn),
        destination: Destination::Broadcast,
        payload: Bytes::from_static(b"<event/>"),
        metadata,
    }
}

#[tokio::test]
async fn clock_jump_forward_past_ttl_excludes_entry_from_replay() {
    // Insert an entry stamped 10s ago with a 5s TTL: equivalent to a
    // clock jump of 10s past the TTL. `get_all` must filter it.
    let cache = PositionCache::new();
    let backdated = SystemTime::now() - Duration::from_secs(10);
    cache.store(position_with_received_at(
        "alice",
        backdated,
        Some(Duration::from_secs(5)),
    ));

    // Insert a fresh entry that should NOT expire — pin the per-entry
    // semantics so a regression that uses a global "all-or-nothing"
    // expiry is caught.
    cache.store(position_with_received_at(
        "bob",
        SystemTime::now(),
        Some(Duration::from_secs(3600)),
    ));

    let visible = cache.get_all();
    let names: Vec<&str> = visible.iter().map(|m| &*m.source.cn).collect();
    assert!(
        !names.contains(&"alice"),
        "alice's entry must be filtered after a clock jump past its 5s TTL"
    );
    assert!(
        names.contains(&"bob"),
        "bob's entry must survive — clock jump applies per-entry"
    );
}

#[tokio::test]
async fn clock_jump_backwards_does_not_evict_entries() {
    // The cache treats `received_at.elapsed() == Err(_)` (which
    // happens when `received_at > now`) as not-expired. We model a
    // backwards clock jump by stamping `received_at` 30 seconds in
    // the future; the entry must survive every TTL filter.
    let cache = PositionCache::new();
    let future_received = SystemTime::now() + Duration::from_secs(30);
    cache.store(position_with_received_at(
        "from-the-future",
        future_received,
        Some(Duration::from_secs(1)),
    ));

    // The 1s TTL would otherwise be long-expired given normal time
    // arithmetic; the backwards-clock branch must rescue this entry.
    let visible = cache.get_all();
    assert_eq!(
        visible.len(),
        1,
        "future-stamped entry must survive — clock-backwards tolerance"
    );
    assert_eq!(&*visible[0].source.cn, "from-the-future");

    // Sweep must also leave the entry alone.
    let removed = cache.sweep();
    assert_eq!(
        removed, 0,
        "sweep must not remove future-stamped entries (clock-backwards safety)"
    );
}

#[tokio::test(start_paused = true)]
async fn paused_runtime_drives_sweep_task_deterministically() {
    // The sweep task uses `tokio::time::interval`, which is on the
    // paused-time clock. Advancing past the sweep interval must
    // trigger one (and only one) sweep cycle, and an expired entry
    // must be removed.
    //
    // Note: `received_at` uses SystemTime — not paused — so we use a
    // backdated `received_at` to mark the entry expired. The sweep's
    // *trigger* is on virtual time; the TTL *check* is on wall time.
    // Both must work together for the chaos signal to be meaningful.
    let cache = Arc::new(PositionCache::new());
    let backdated = SystemTime::now() - Duration::from_secs(10);
    cache.store(position_with_received_at(
        "stale",
        backdated,
        Some(Duration::from_secs(1)),
    ));
    assert_eq!(cache.len(), 1);

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let handle = cache.start_sweep_task_with_interval(shutdown_rx, Duration::from_millis(100));

    // Advance virtual time past one sweep interval. The sweep task
    // must observe the tick and remove the expired entry.
    tokio::time::advance(Duration::from_millis(150)).await;
    // Yield so the sweep task can run after the timer fires.
    tokio::task::yield_now().await;
    tokio::task::yield_now().await;

    // Cooperatively wait briefly for the sweep to land — the
    // `start_paused` runtime auto-advances when there's no other work
    // pending, so this is bounded but deterministic.
    let drained = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if cache.len() == 0 {
                return;
            }
            tokio::time::advance(Duration::from_millis(110)).await;
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert!(
        drained.is_ok(),
        "paused-time advance past interval must drive a sweep cycle"
    );
    assert_eq!(cache.len(), 0, "expired entry must be removed by the sweep");

    // Clean shutdown.
    shutdown_tx.send(true).unwrap();
    handle.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn sweep_does_not_fire_before_first_interval_elapses() {
    // The sweep task skips its initial immediate tick (so the first
    // sweep happens after one full interval). Pin that behaviour: an
    // expired entry must remain visible to `len()` if we have not
    // advanced past one interval. A regression that fires the sweep
    // immediately would silently retire entries that the operator
    // expects to survive their first interval.
    let cache = Arc::new(PositionCache::new());
    cache.store(position_with_received_at(
        "stale",
        SystemTime::now() - Duration::from_secs(10),
        Some(Duration::from_secs(1)),
    ));
    assert_eq!(cache.len(), 1);

    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let _handle = cache.start_sweep_task_with_interval(shutdown_rx, Duration::from_secs(60));

    // Advance only 10ms — far below the interval. The sweep task
    // must NOT have fired yet, even on a paused-time runtime.
    tokio::time::advance(Duration::from_millis(10)).await;
    tokio::task::yield_now().await;

    assert_eq!(
        cache.len(),
        1,
        "sweep must not fire before first interval elapses (entry should still be present)"
    );
}

#[tokio::test]
async fn clock_jump_zero_ttl_excludes_entry_on_next_read() {
    // Edge case: a TTL of zero with any non-zero elapsed time means
    // expired. The chaos test pins this — observed via
    // `get_all` filtering — so a future change that re-interprets
    // `Duration::ZERO` as "infinite" or "default" is caught.
    //
    // We backdate `received_at` by 1 ms (the smallest reliable
    // clock-difference across runtimes) and pair it with `ttl =
    // Duration::ZERO`. Any non-zero elapsed time exceeds the zero
    // TTL, so the entry must be filtered.
    let cache = PositionCache::new();
    cache.store(position_with_received_at(
        "zero-ttl",
        SystemTime::now() - Duration::from_millis(1),
        Some(Duration::ZERO),
    ));

    // The store call itself does not filter — it only inserts. The
    // filtering happens on `get_all`.
    assert_eq!(cache.len(), 1, "store must persist the entry");
    let visible = cache.get_all();
    assert!(
        visible.is_empty(),
        "TTL=0 with elapsed > 0 must be filtered from get_all (got {visible:?})"
    );
}
