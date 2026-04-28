// Copyright © 2026 Roberto Chiofalo.

#![allow(clippy::panic, clippy::unwrap_used, unused_results)]

//! Chaos test: federation network-partition fault injection (refs #788).
//!
//! Models a federation peer flipping between connected and disconnected
//! states (the "partition + heal" pattern) and pins three behavioural
//! invariants that the production reconnect path must preserve:
//!
//! 1. **Backoff is deterministic and bounded.** The shared
//!    `rustgate_resilience::reconnect::backoff_delay` helper produces
//!    reproducible delays that grow exponentially up to a fixed cap.
//!    The chaos test simulates 12 partition cycles and confirms every
//!    delay obeys the documented `min(base * 2^attempt, MAX_DELAY)`
//!    formula — no jitter, no drift across runs.
//! 2. **Reconnect-limit termination is precise.** With a finite
//!    `max_reconnects`, the loop must stop *exactly* at the configured
//!    boundary — neither one early (lost reconnect attempt) nor one
//!    late (extra wakeup). The CLI surfaces this as a hard cap;
//!    drifting silently is a quality-of-service regression.
//! 3. **Dedup suppresses on-replay duplication.** When a peer
//!    reconnects, the V1 path replays buffered messages. The
//!    `MessageDedup` cache must reject any envelope whose `(uid, time)`
//!    pair has already been seen — otherwise a flapping link would
//!    multiply CoT events on every heal.
//!
//! ## Why no `turmoil`/socket-level partition
//!
//! The reconnect loop in `crates/rustgate-federation/src/v1/client.rs`
//! and the dedup cache in `crates/rustgate-federation/src/dedup.rs`
//! are the parts of partition behaviour the test budget cares about.
//! Spinning up two real `tokio::net::TcpListener`s and tearing one
//! down mid-flight would add a TLS handshake, a tonic / framed-codec
//! plumbing layer, and a 100+ ms connect/close cycle per partition —
//! all of which test the OS networking stack rather than the
//! reconnect logic. The integration tests in `v2_integration.rs`
//! already cover the wire-level handshake; this chaos test pins the
//! resilience invariants without re-litigating them.
//!
//! Deterministic: no `tokio::time::pause`, no real sockets, no
//! background tasks. The two helpers under test are pure functions and
//! a synchronous cache — every assertion is reproducible.

use std::time::Duration;

use rustgate_federation::dedup::MessageDedup;
use rustgate_resilience::reconnect::{backoff_delay, should_stop_reconnecting};

/// Recompute the documented backoff formula here so the chaos test
/// fails on its own terms if the production helper drifts. The shared
/// helper caps the exponent at 5 and the absolute delay at 5 minutes.
fn expected_backoff(base: Duration, attempt: u32) -> Duration {
    const MAX_DELAY: Duration = Duration::from_secs(300);
    let exp = attempt.min(5);
    let nominal = base.saturating_mul(2u32.pow(exp));
    nominal.min(MAX_DELAY)
}

#[test]
fn partition_cycles_produce_deterministic_backoff_delays() {
    // Simulate 12 partition cycles with a 1-second base. Every cycle's
    // delay must equal the closed-form expectation. No jitter — a
    // refactor that introduced randomness here would fail the run
    // regardless of seed.
    let base = Duration::from_secs(1);
    for attempt in 0..12 {
        let observed = backoff_delay(base, attempt);
        let expected = expected_backoff(base, attempt);
        assert_eq!(
            observed, expected,
            "partition cycle {attempt}: backoff drifted from min(base*2^attempt, 300s)"
        );
    }

    // Specifically pin the cap: at attempt 5 the nominal delay (32s) is
    // below cap; at attempt 6 the exponent caps and produces the same
    // delay; at attempt 100 we are still capped.
    assert_eq!(backoff_delay(base, 5), Duration::from_secs(32));
    assert_eq!(backoff_delay(base, 6), Duration::from_secs(32));
    assert_eq!(backoff_delay(base, 100), Duration::from_secs(32));
}

#[test]
fn reconnect_loop_terminates_at_exact_boundary() {
    // With `max_reconnects = 5`, attempts 0..=4 must continue (the
    // count `n` at the time of the check is the number of failures so
    // far, not the count *after* the upcoming attempt). Attempt 5
    // must terminate.
    let max = 5;
    for n in 0..max {
        assert!(
            !should_stop_reconnecting(max, n as u32),
            "must keep retrying at count {n} (boundary at {max})"
        );
    }
    assert!(
        should_stop_reconnecting(max, max as u32),
        "must terminate exactly at the configured max ({max})"
    );
    // And every count beyond.
    assert!(should_stop_reconnecting(max, (max + 1) as u32));
    assert!(should_stop_reconnecting(max, u32::MAX));

    // Negative `max` means unlimited — partition cycles forever.
    assert!(!should_stop_reconnecting(-1, 0));
    assert!(!should_stop_reconnecting(-1, 100));
    assert!(!should_stop_reconnecting(-1, u32::MAX));
}

#[test]
fn replay_after_partition_heal_suppresses_duplicates() {
    // Model the partition-heal sequence: the peer was connected, sent
    // event A, partitioned, the local side re-buffers A in its replay
    // queue, the link heals, A is replayed. The receiving end's
    // dedup cache must classify the replay as a duplicate even though
    // the underlying TCP connection is brand new — otherwise every
    // heal would multiply event counts.
    let mut dedup = MessageDedup::new();

    let event_a =
        br#"<event uid="ALPHA-1" type="a-f-G" time="2026-04-27T12:00:00Z" start="x" stale="y"/>"#;
    let event_b =
        br#"<event uid="BRAVO-2" type="a-f-G" time="2026-04-27T12:00:01Z" start="x" stale="y"/>"#;

    // Pre-partition: both events flow through cleanly.
    assert!(!dedup.is_duplicate(event_a), "first sighting of A");
    assert!(!dedup.is_duplicate(event_b), "first sighting of B");

    // Simulate three partition cycles. After each heal the V1 client
    // replays its buffered events. The dedup cache must reject every
    // replay because the `(uid, time)` keys are unchanged.
    for cycle in 0..3 {
        assert!(
            dedup.is_duplicate(event_a),
            "partition cycle {cycle}: replayed A must be classified as duplicate"
        );
        assert!(
            dedup.is_duplicate(event_b),
            "partition cycle {cycle}: replayed B must be classified as duplicate"
        );
    }

    // A new event after the heal must still flow.
    let event_c =
        br#"<event uid="CHARLIE-3" type="a-f-G" time="2026-04-27T12:00:02Z" start="x" stale="y"/>"#;
    assert!(
        !dedup.is_duplicate(event_c),
        "fresh event after heal must be admitted — dedup must not blanket-reject"
    );
}

#[test]
fn flapping_link_dedup_size_stays_bounded() {
    // Chaos invariant: a link that flaps between partition and heal
    // for hours must not unbounded-grow the dedup cache. The cache
    // uses FIFO eviction with a configurable capacity; we set it to 4
    // and confirm that across 100 partition cycles with rotating event
    // IDs, the cache size is clamped.
    let mut dedup = MessageDedup::with_capacity(4);

    // 100 cycles of 4 distinct events each — 400 unique (uid, time)
    // keys total. With capacity 4, only the most recent 4 must be
    // present, but the cache must not panic or leak.
    for cycle in 0u32..100 {
        for slot in 0..4u32 {
            let payload = format!(
                r#"<event uid="EVT-{cycle}-{slot}" type="a-f-G" time="2026-04-27T{cycle:02}:00:00Z" start="x" stale="y"/>"#
            );
            // First sighting must NOT be a duplicate — the cache evicts
            // the oldest entry before inserting.
            assert!(
                !dedup.is_duplicate(payload.as_bytes()),
                "cycle {cycle} slot {slot}: fresh event misclassified as duplicate"
            );
        }
    }

    assert!(
        dedup.len() <= 4,
        "cache size {} exceeds configured capacity 4 across 100 partition cycles",
        dedup.len()
    );
}
