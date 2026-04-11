// Copyright © 2026 Roberto Chiofalo.

//! Integration tests for issue #557 — persistent federation replay buffer.
//!
//! These tests exercise the redb-backed [`ReplayStore`] together with
//! the in-memory [`ReplayBuffer`] to ensure buffered messages survive a
//! simulated server restart and that a peer reconnecting after the
//! restart sees a full replay starting from the last persisted point.

#![allow(clippy::panic, clippy::unwrap_used)]

use std::sync::Arc;

use bytes::Bytes;
use rustgate_federation::replay_buffer::{BufferedMessage, ReplayBuffer};
use rustgate_federation::replay_persist::ReplayStore;

/// Simulates kill-mid-stream-then-restart: a peer disconnects, the
/// server keeps buffering, the process is killed before the peer
/// reconnects, and on restart the buffered messages must still be
/// available for replay.
#[test]
fn replay_resumes_after_simulated_restart() {
    let dir = tempfile::tempdir().unwrap();

    // ── Run 1: server is up, peer is offline, messages are buffered ──
    {
        let store = Arc::new(ReplayStore::open(dir.path(), 1024 * 1024).unwrap());
        let mut buf = ReplayBuffer::with_store(1000, "peer-alpha", Arc::clone(&store));
        for i in 0..5 {
            let _ = buf.push(
                Bytes::from(format!("msg-{i}")),
                vec!["GroupA".into(), "GroupB".into()],
            );
        }
        assert_eq!(buf.len(), 5);
        // Simulate kill -9: drop everything without a graceful shutdown.
        drop(buf);
        drop(store);
    }

    // ── Run 2: server restarts; rehydrate from disk and verify replay ──
    let store = Arc::new(ReplayStore::open(dir.path(), 1024 * 1024).unwrap());
    let entries = store.load_all().unwrap();
    assert_eq!(entries.len(), 5, "expected all 5 messages to be persisted");

    let restored: Vec<BufferedMessage> = entries
        .into_iter()
        .filter(|e| e.peer_id == "peer-alpha")
        .map(BufferedMessage::from)
        .collect();

    let mut buf = ReplayBuffer::with_store(1000, "peer-alpha", Arc::clone(&store));
    buf.hydrate_from_records(restored);

    // Peer reconnects with a "last seen seq = 0" — full replay.
    let pending = buf.messages_since(0);
    assert_eq!(pending.len(), 5, "full replay should return all entries");
    for (i, msg) in pending.iter().enumerate() {
        assert_eq!(msg.payload, Bytes::from(format!("msg-{i}")));
        assert_eq!(msg.groups, vec!["GroupA".to_string(), "GroupB".to_string()]);
    }
    // The next push must continue past the restored sequence numbers.
    let next_seq = buf.push(Bytes::from("msg-after-restart"), vec!["GroupA".into()]);
    assert_eq!(next_seq, 6);
}

/// After a partial replay, only messages newer than the peer's last
/// seen sequence number are returned — the survival across restart
/// must preserve those sequence numbers exactly.
#[test]
fn partial_replay_after_restart_uses_persisted_seq_numbers() {
    let dir = tempfile::tempdir().unwrap();
    let last_seen;

    {
        let store = Arc::new(ReplayStore::open(dir.path(), 1024 * 1024).unwrap());
        let mut buf = ReplayBuffer::with_store(1000, "peer-bravo", Arc::clone(&store));
        let _ = buf.push(Bytes::from("a"), vec![]);
        last_seen = buf.push(Bytes::from("b"), vec![]);
        let _ = buf.push(Bytes::from("c"), vec![]);
        let _ = buf.push(Bytes::from("d"), vec![]);
    }

    // Restart the server.
    let store = Arc::new(ReplayStore::open(dir.path(), 1024 * 1024).unwrap());
    let restored: Vec<BufferedMessage> = store
        .load_all()
        .unwrap()
        .into_iter()
        .filter(|e| e.peer_id == "peer-bravo")
        .map(BufferedMessage::from)
        .collect();
    let mut buf = ReplayBuffer::with_store(1000, "peer-bravo", store);
    buf.hydrate_from_records(restored);

    let pending = buf.messages_since(last_seen);
    assert_eq!(pending.len(), 2);
    assert_eq!(pending[0].payload, Bytes::from("c"));
    assert_eq!(pending[1].payload, Bytes::from("d"));
}

/// Clearing the buffer (e.g. after a successful replay) must also
/// remove the persisted entries so the same messages are not replayed
/// twice on the next restart.
#[test]
fn clear_after_replay_persists_across_restart() {
    let dir = tempfile::tempdir().unwrap();
    {
        let store = Arc::new(ReplayStore::open(dir.path(), 1024 * 1024).unwrap());
        let mut buf = ReplayBuffer::with_store(1000, "peer-charlie", Arc::clone(&store));
        let _ = buf.push(Bytes::from("x"), vec![]);
        let _ = buf.push(Bytes::from("y"), vec![]);
        buf.clear();
    }
    let store = ReplayStore::open(dir.path(), 1024 * 1024).unwrap();
    assert!(
        store.is_empty(),
        "clear() must remove persisted entries for the peer"
    );
}

/// The byte cap evicts oldest entries across all peers. After a
/// restart the bookkeeping must reflect the post-eviction state.
#[test]
fn byte_cap_eviction_survives_restart() {
    let dir = tempfile::tempdir().unwrap();
    // Tiny cap so just a couple of entries fit.
    // Cap is large enough to fit a couple of records once the
    // accounted size now includes key bytes + redb overhead.
    let cap = 256u64;
    {
        let store = Arc::new(ReplayStore::open(dir.path(), cap).unwrap());
        let mut buf = ReplayBuffer::with_store(1000, "peer-delta", Arc::clone(&store));
        for i in 0..20u64 {
            let _ = buf.push(Bytes::from(vec![b'x'; 16]), vec![format!("g{i}")]);
        }
    }
    let store = ReplayStore::open(dir.path(), cap).unwrap();
    assert!(
        store.total_bytes() <= cap,
        "byte cap must hold across restart, got {}",
        store.total_bytes()
    );
    assert!(!store.is_empty());
}

/// Records whose TTL has already elapsed at rehydrate time must not
/// be returned to the replay buffer — persistence cannot become a
/// TTL-bypass channel across restarts.
#[test]
fn expired_ttl_records_are_skipped_on_rehydrate() {
    let dir = tempfile::tempdir().unwrap();
    let store = ReplayStore::open(dir.path(), 1024 * 1024).unwrap();
    // Enqueued long ago with a 1 ms TTL — already expired.
    store
        .put(
            "peer-echo",
            1,
            1, // year 1970
            Some(1),
            &[],
            &Bytes::from_static(b"stale"),
        )
        .unwrap();
    // Same peer, fresh TTL — must survive.
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    store
        .put(
            "peer-echo",
            2,
            now_ms,
            Some(60_000),
            &[],
            &Bytes::from_static(b"fresh"),
        )
        .unwrap();

    // Filter exactly the way the manager does on rehydrate.
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let restored: Vec<BufferedMessage> = store
        .load_all()
        .unwrap()
        .into_iter()
        .filter(|e| {
            e.ttl_ms
                .map(|ttl| e.enqueued_at_unix_ms.saturating_add(ttl) >= now_ms)
                .unwrap_or(true)
        })
        .map(BufferedMessage::from)
        .collect();
    assert_eq!(restored.len(), 1);
    assert_eq!(restored[0].payload, Bytes::from_static(b"fresh"));
}
