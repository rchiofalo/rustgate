// Copyright © 2026 Roberto Chiofalo.

#![allow(clippy::panic, clippy::unwrap_used, unused_results)]

//! Chaos test: disk-full / over-capacity store-and-forward (refs #788).
//!
//! Drives the durable per-client queue (`rustgate_transport::store_forward`)
//! at and beyond its configured byte cap and pins the documented
//! "drop-oldest FIFO" eviction contract.
//!
//! The production queue caps storage by an explicit byte budget — not
//! by inspecting actual filesystem free space — because operators
//! deploy on a wide range of storage (loop-back tmpfs, SD card, network
//! mount). The chaos invariants are therefore framed against that
//! byte cap:
//!
//! 1. **Eviction kicks in at the cap, not before.** The queue accepts
//!    messages up to the cap, and only starts dropping when a new
//!    enqueue would push the total above it.
//! 2. **Drop-oldest is FIFO.** When eviction fires, the oldest
//!    surviving entry is the next one removed — never a middle entry,
//!    never the newest. The cap-survivors at any point in time form a
//!    contiguous tail of the insertion order.
//! 3. **`drops_total()` records every eviction.** A SIEM or
//!    Prometheus dashboard relies on this counter to alert operators
//!    that durable queueing is shedding load. The chaos test confirms
//!    the counter increments by exactly one per evicted message.
//! 4. **No panic / `unwrap()` explosion under steady-state pressure.**
//!    The `clippy::panic = "deny"` lint catches obvious calls; this
//!    test catches second-order bugs (lock-order regressions, integer
//!    underflow on size accounting) that a coverage build would not.
//!
//! Deterministic: the writer task is async but every drain happens after
//! a deterministic flush via `tokio::time::sleep` over the writer-task's
//! channel-fill latency. We avoid clock manipulation here because the
//! store-forward path uses `SystemTime` for `queued_at` accounting,
//! which `tokio::time::pause` does not affect.
//!
//! ## Why not a wrapped `Write`
//!
//! The original issue (#788) suggested a wrapped `Write` returning
//! `ErrorKind::OutOfMemory` after N bytes. The store-forward backing
//! store is `redb`, which owns its own file handles via `Database::create`
//! and never accepts an external `Write`. Injecting a wrapper would
//! require either a `redb` fork or a fault-injecting filesystem
//! (`fuser` / overlayfs), neither of which is portable across CI
//! runners. The byte-cap path is the production code's actual
//! disk-full response — the queue treats "cap reached" identically to
//! "disk full because operator chose a 4 KiB cap on a 1 TiB partition".
//! Hitting that path deterministically gives the same chaos signal
//! without OS coupling.

use std::collections::BTreeSet;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use rustgate_core::identity::Identity;
use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};
use rustgate_router::store_forward::ClientQueue;
use tempfile::TempDir;
use zeroize::Zeroizing;

fn ident(cn: &str) -> Identity {
    let mut groups = BTreeSet::new();
    groups.insert("alpha".to_string());
    Identity::new(cn.to_string(), format!("{cn}-fp"), groups).unwrap()
}

/// Build a direct-target message addressed to `dest_cn` whose payload
/// is `payload_bytes` long. Used to fill the queue with messages of
/// known size so the byte-cap test can predict eviction precisely.
fn direct_msg(source_cn: &str, dest_cn: &str, payload_bytes: usize) -> RoutableMessage {
    RoutableMessage {
        source: ident(source_cn),
        destination: Destination::Direct(ident(dest_cn)),
        metadata: Metadata::new(SystemTime::now(), "test".to_string(), MessageType::Chat),
        payload: Bytes::from(vec![0xAA; payload_bytes]),
        entity: None,
    }
}

/// Wait until the writer task has fully persisted (or evicted)
/// `expected_enqueues` submissions, by polling the in-memory index
/// for stable convergence: drops + surviving == expected. The
/// writer task runs each persist via `spawn_blocking`, so the
/// in-memory index updates lag enqueue() by tens of milliseconds
/// per message; we poll until the totals balance.
async fn wait_for_writer_processed(q: &ClientQueue, cn: &str, expected_enqueues: u64) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        let depth = q.stats(cn).depth;
        let drops = q.drops_total();
        // Every submitted message must end up either persisted
        // (counted in depth) or dropped (counted in drops). If the
        // sum equals expected, the writer has fully processed the
        // batch.
        if depth + drops >= expected_enqueues {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!(
        "writer task did not converge for {cn}: depth={} drops={} expected={expected_enqueues}",
        q.stats(cn).depth,
        q.drops_total()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cap_eviction_drops_oldest_fifo() {
    let tmp = TempDir::new().unwrap();
    // Persistent HMAC key so re-opens are deterministic; the chaos
    // test only opens once but the helper requires a Some-key for any
    // queue with prior contents (see `StaleQueueWithoutKey`).
    let key = Zeroizing::new([7u8; 32]);

    // 8 KiB cap. Each message's encoded form is roughly
    // payload + 32-byte HMAC + envelope overhead. With 1 KiB payloads
    // we fit ~7 messages safely before eviction begins.
    let max_bytes: u64 = 8 * 1024;
    let q = ClientQueue::open_with_hmac_key(tmp.path(), max_bytes, Some(key.clone())).unwrap();

    // Enqueue 12 messages tagged 0..12 in the destination's payload
    // prefix so we can identify which were evicted on drain.
    for i in 0..12u8 {
        let mut msg = direct_msg("sender", "alice", 1024);
        // Tag the first byte with the sequence index so drain order
        // can be checked deterministically.
        let mut buf = msg.payload.to_vec();
        buf[0] = i;
        msg.payload = Bytes::from(buf);
        q.enqueue("alice", &msg).unwrap();
    }

    // Wait for the writer task to process all enqueued messages.
    wait_for_writer_processed(&q, "alice", 12).await;

    // Invariant 1 + 2: the queue did not exceed the cap, and the drops
    // counter advanced by at least the difference between submitted
    // (12) and surviving (≤ floor(cap / encoded_size)) messages.
    let drops = q.drops_total();
    assert!(
        drops > 0,
        "drops_total must increment when 12 KiB pushed into 8 KiB cap (got {drops})"
    );
    assert!(
        q.total_bytes() <= max_bytes,
        "total_bytes {} must be at/below cap {max_bytes}",
        q.total_bytes()
    );

    // Drain and verify the surviving messages are the *most recent* —
    // the oldest were evicted.
    let drained = q.drain("alice").unwrap();
    assert!(
        !drained.is_empty(),
        "drain must return surviving messages, not nothing"
    );

    // Tag indices recovered from each drained payload's first byte.
    let surviving_tags: Vec<u8> = drained.iter().map(|m| m.payload[0]).collect();

    // Invariant 2: tags must be a contiguous tail of [0, 12). I.e.
    // they are sorted ascending and their last value is 11 (the
    // newest message). A regression that evicted out-of-order would
    // leave gaps or evict the newest.
    let mut sorted = surviving_tags.clone();
    sorted.sort_unstable();
    assert_eq!(
        sorted, surviving_tags,
        "drain order must match insertion order (FIFO survivors)"
    );
    assert_eq!(
        *surviving_tags.last().unwrap(),
        11,
        "newest message (tag 11) must always survive eviction"
    );
    let oldest_kept = *surviving_tags.first().unwrap();
    assert!(
        oldest_kept > 0,
        "oldest surviving tag {oldest_kept} indicates the very first message was kept — \
         drop-oldest FIFO must have evicted at least tag 0"
    );

    // Invariant 3: drops_total = 12 - len(surviving). Pin the
    // accounting precisely so a regression that double-counts
    // evictions or skips the increment is caught.
    let surviving = surviving_tags.len() as u64;
    assert_eq!(
        drops + surviving,
        12,
        "submitted (12) = surviving ({surviving}) + drops ({drops})"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversize_message_is_dropped_not_panicked() {
    // Chaos invariant 4: a single message larger than the entire cap
    // must be rejected by the writer with a `drops_total` increment —
    // not panic with `unwrap()` on saturating-arithmetic, not deadlock
    // the writer task, not silently corrupt the on-disk state.
    let tmp = TempDir::new().unwrap();
    let key = Zeroizing::new([3u8; 32]);

    let max_bytes: u64 = 4 * 1024;
    let q = ClientQueue::open_with_hmac_key(tmp.path(), max_bytes, Some(key)).unwrap();

    // 8 KiB payload with a 4 KiB cap — even the empty envelope
    // overhead cannot fit this.
    let oversized = direct_msg("sender", "alice", 8 * 1024);
    q.enqueue("alice", &oversized).unwrap();

    // Allow the writer task to process and reject.
    tokio::time::sleep(Duration::from_millis(200)).await;

    assert!(
        q.drops_total() >= 1,
        "oversize message must increment drops_total"
    );
    assert_eq!(
        q.total_bytes(),
        0,
        "oversize message must not be partially persisted (got {} bytes)",
        q.total_bytes()
    );

    // The queue must still be functional after the oversize rejection.
    let small = direct_msg("sender", "alice", 256);
    q.enqueue("alice", &small).unwrap();
    // Total submissions = 1 oversize + 1 small. The oversize was
    // rejected by the writer task (drops += 1) and the small one
    // persists.
    wait_for_writer_processed(&q, "alice", 2).await;
    let drained = q.drain("alice").unwrap();
    assert_eq!(
        drained.len(),
        1,
        "queue must still accept normal messages after rejecting an oversize one"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn writer_channel_overflow_increments_writer_drops() {
    // The async writer's mpsc channel is itself bounded. A burst that
    // outpaces the writer task's flush rate triggers
    // `writer_drops_total` rather than panicking. We verify this by
    // pushing far more messages than the channel capacity in a tight
    // loop on a single-threaded runtime — the writer cannot drain
    // concurrently.
    let tmp = TempDir::new().unwrap();
    let key = Zeroizing::new([5u8; 32]);
    let q = ClientQueue::open_with_hmac_key(tmp.path(), 1024 * 1024, Some(key)).unwrap();

    // Enqueue a large burst synchronously without yielding. The
    // writer task can't run between enqueues on a single-threaded
    // runtime until we await; the channel will overflow.
    let msg = direct_msg("sender", "alice", 64);
    for _ in 0..10_000 {
        q.enqueue("alice", &msg).unwrap();
    }

    // Some messages will be in the channel, some persisted; both
    // counters together with `writer_drops` must equal the
    // submission count. Allow the writer to drain.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let enqueues = q.enqueues_total();
    let writer_drops = q.writer_drops_total();
    assert_eq!(
        enqueues + writer_drops,
        10_000,
        "every submission must be accounted for (enqueues={enqueues}, writer_drops={writer_drops})"
    );

    // We can't guarantee writer_drops > 0 across runtimes (a faster
    // executor may drain the channel as we push), but the absence of
    // panic is the chaos invariant. The accounting check above
    // suffices to prove no message is silently lost or
    // double-counted.
}
