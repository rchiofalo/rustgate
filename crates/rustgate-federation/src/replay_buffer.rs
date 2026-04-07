//! Bounded replay buffer for federation peer reconnection.
//!
//! Stores recent forwarded messages in a per-peer ring buffer so that
//! when a peer reconnects, missed messages can be replayed before
//! resuming the live stream.

use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use tracing::warn;

use crate::replay_persist::ReplayStore;

/// Default maximum number of messages retained per peer.
pub const DEFAULT_REPLAY_CAPACITY: usize = 1000;

/// A message stored in the replay buffer with a sequence number.
#[derive(Debug, Clone)]
pub struct BufferedMessage {
    /// Monotonically increasing sequence number.
    pub seq: u64,
    /// Raw message payload.
    pub payload: Bytes,
    /// Source groups for routing.
    pub groups: Vec<String>,
}

/// Bounded ring buffer for storing recent federation messages.
///
/// Uses a `VecDeque` as a ring buffer with a fixed capacity. When full,
/// the oldest message is evicted to make room for new ones.
#[derive(Debug)]
pub struct ReplayBuffer {
    buffer: VecDeque<BufferedMessage>,
    capacity: usize,
    next_seq: AtomicU64,
    /// Optional disk-backed store. When set, every push/eviction/clear is
    /// mirrored to the store so the buffer can be restored across restarts.
    store: Option<Arc<ReplayStore>>,
    /// Peer id this buffer belongs to. Only meaningful when `store` is set.
    peer_id: String,
}

impl ReplayBuffer {
    /// Create a new in-memory replay buffer with the given capacity.
    pub fn new(capacity: usize) -> Self {
        Self {
            buffer: VecDeque::with_capacity(capacity.min(1024)),
            capacity,
            next_seq: AtomicU64::new(1),
            store: None,
            peer_id: String::new(),
        }
    }

    /// Create a new persistent replay buffer for `peer_id` backed by `store`.
    ///
    /// New pushes are written through to disk; eviction and clear are
    /// reflected to the store so the on-disk state stays bounded.
    pub fn with_store(
        capacity: usize,
        peer_id: impl Into<String>,
        store: Arc<ReplayStore>,
    ) -> Self {
        Self {
            buffer: VecDeque::with_capacity(capacity.min(1024)),
            capacity,
            next_seq: AtomicU64::new(1),
            store: Some(store),
            peer_id: peer_id.into(),
        }
    }

    /// Hydrate this buffer from already-restored persistent records.
    ///
    /// Records must be supplied in ascending sequence order. The buffer's
    /// `next_seq` is advanced past the highest restored seq. If more records
    /// than `capacity` are supplied, only the most recent `capacity` are
    /// retained in memory and the older ones are deleted from the store.
    pub fn hydrate_from_records<I>(&mut self, records: I)
    where
        I: IntoIterator<Item = BufferedMessage>,
    {
        let mut max_seq: u64 = 0;
        for msg in records {
            if msg.seq > max_seq {
                max_seq = msg.seq;
            }
            if self.capacity == 0 {
                if let Some(store) = self.store.as_ref()
                    && let Err(e) = store.delete(&self.peer_id, msg.seq)
                {
                    warn!(error = %e, "failed to delete restored replay entry");
                }
                continue;
            }
            if self.buffer.len() >= self.capacity
                && let Some(evicted) = self.buffer.pop_front()
                && let Some(store) = self.store.as_ref()
                && let Err(e) = store.delete(&self.peer_id, evicted.seq)
            {
                warn!(error = %e, "failed to delete evicted replay entry");
            }
            self.buffer.push_back(msg);
        }
        if max_seq > 0 {
            self.next_seq.store(max_seq + 1, Ordering::Relaxed);
        }
    }

    /// Store a message in the buffer, evicting the oldest if at capacity.
    ///
    /// Returns the sequence number assigned to the message. If capacity is
    /// zero, the message is discarded but a sequence number is still assigned.
    pub fn push(&mut self, payload: Bytes, groups: Vec<String>) -> u64 {
        let seq = self.next_seq.fetch_add(1, Ordering::Relaxed);
        if self.capacity == 0 {
            return seq;
        }
        if self.buffer.len() >= self.capacity
            && let Some(evicted) = self.buffer.pop_front()
            && let Some(store) = self.store.as_ref()
            && let Err(e) = store.delete(&self.peer_id, evicted.seq)
        {
            warn!(error = %e, "failed to delete evicted replay entry");
        }
        if let Some(store) = self.store.as_ref() {
            match store.put(&self.peer_id, seq, &groups, &payload) {
                Ok(()) => {
                    #[cfg(feature = "api")]
                    crate::metrics::replay_persisted().inc();
                }
                Err(e) => warn!(error = %e, "failed to persist replay entry"),
            }
        }
        self.buffer.push_back(BufferedMessage {
            seq,
            payload,
            groups,
        });
        seq
    }

    /// Return all messages with sequence numbers greater than `since_seq`.
    ///
    /// Used during reconnection: the peer reports its last seen sequence
    /// and the buffer returns all messages after that point.
    pub fn messages_since(&self, since_seq: u64) -> Vec<BufferedMessage> {
        self.buffer
            .iter()
            .filter(|m| m.seq > since_seq)
            .cloned()
            .collect()
    }

    /// Return all buffered messages (for full replay on first connect).
    pub fn all_messages(&self) -> Vec<BufferedMessage> {
        self.buffer.iter().cloned().collect()
    }

    /// Current number of buffered messages.
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Returns `true` if the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// The next sequence number that will be assigned.
    pub fn next_seq(&self) -> u64 {
        self.next_seq.load(Ordering::Relaxed)
    }

    /// The oldest sequence number still in the buffer, or `None` if empty.
    pub fn oldest_seq(&self) -> Option<u64> {
        self.buffer.front().map(|m| m.seq)
    }

    /// Remove all buffered messages and reset the buffer.
    ///
    /// The sequence counter is **not** reset — new messages pushed after
    /// `clear()` continue with the next monotonic sequence number.
    pub fn clear(&mut self) {
        self.buffer.clear();
        if let Some(store) = self.store.as_ref()
            && let Err(e) = store.clear_peer(&self.peer_id)
        {
            warn!(error = %e, "failed to clear persisted replay entries");
        }
    }

    /// Return all buffered messages, deduplicating by payload content.
    ///
    /// Messages with identical payloads are collapsed, keeping only the
    /// first occurrence (lowest sequence number). This prevents resending
    /// the same content multiple times during replay.
    pub fn all_messages_deduped(&self) -> Vec<BufferedMessage> {
        let mut seen = HashSet::new();
        self.buffer
            .iter()
            .filter(|m| seen.insert(m.payload.clone()))
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn push_and_retrieve() {
        let mut buf = ReplayBuffer::new(10);
        let seq1 = buf.push(Bytes::from("msg1"), vec!["alpha".into()]);
        let seq2 = buf.push(Bytes::from("msg2"), vec!["bravo".into()]);

        assert_eq!(buf.len(), 2);
        assert_eq!(seq1, 1);
        assert_eq!(seq2, 2);

        let all = buf.all_messages();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].payload, Bytes::from("msg1"));
        assert_eq!(all[1].payload, Bytes::from("msg2"));
    }

    #[test]
    fn evicts_oldest_at_capacity() {
        let mut buf = ReplayBuffer::new(3);
        let _ = buf.push(Bytes::from("a"), vec![]);
        let _ = buf.push(Bytes::from("b"), vec![]);
        let _ = buf.push(Bytes::from("c"), vec![]);
        let _ = buf.push(Bytes::from("d"), vec![]);

        assert_eq!(buf.len(), 3);
        let all = buf.all_messages();
        assert_eq!(all[0].payload, Bytes::from("b"));
        assert_eq!(all[1].payload, Bytes::from("c"));
        assert_eq!(all[2].payload, Bytes::from("d"));
    }

    #[test]
    fn messages_since_filters_correctly() {
        let mut buf = ReplayBuffer::new(10);
        let s1 = buf.push(Bytes::from("a"), vec![]);
        let _s2 = buf.push(Bytes::from("b"), vec![]);
        let _s3 = buf.push(Bytes::from("c"), vec![]);

        let since = buf.messages_since(s1);
        assert_eq!(since.len(), 2);
        assert_eq!(since[0].payload, Bytes::from("b"));
        assert_eq!(since[1].payload, Bytes::from("c"));
    }

    #[test]
    fn messages_since_zero_returns_all() {
        let mut buf = ReplayBuffer::new(10);
        let _ = buf.push(Bytes::from("a"), vec![]);
        let _ = buf.push(Bytes::from("b"), vec![]);

        let since = buf.messages_since(0);
        assert_eq!(since.len(), 2);
    }

    #[test]
    fn messages_since_future_returns_empty() {
        let mut buf = ReplayBuffer::new(10);
        let _ = buf.push(Bytes::from("a"), vec![]);

        let since = buf.messages_since(999);
        assert!(since.is_empty());
    }

    #[test]
    fn empty_buffer() {
        let buf = ReplayBuffer::new(10);
        assert!(buf.is_empty());
        assert_eq!(buf.len(), 0);
        assert!(buf.oldest_seq().is_none());
        assert!(buf.all_messages().is_empty());
    }

    #[test]
    fn oldest_seq_tracks_eviction() {
        let mut buf = ReplayBuffer::new(2);
        let _ = buf.push(Bytes::from("a"), vec![]);
        assert_eq!(buf.oldest_seq(), Some(1));

        let _ = buf.push(Bytes::from("b"), vec![]);
        assert_eq!(buf.oldest_seq(), Some(1));

        let _ = buf.push(Bytes::from("c"), vec![]);
        assert_eq!(buf.oldest_seq(), Some(2)); // "a" evicted
    }

    #[test]
    fn zero_capacity_evicts_immediately() {
        let mut buf = ReplayBuffer::new(0);
        let _ = buf.push(Bytes::from("a"), vec![]);
        assert!(buf.is_empty());
    }

    #[test]
    fn clear_removes_all_messages() {
        let mut buf = ReplayBuffer::new(10);
        let _ = buf.push(Bytes::from("a"), vec![]);
        let _ = buf.push(Bytes::from("b"), vec![]);
        assert_eq!(buf.len(), 2);

        buf.clear();
        assert!(buf.is_empty());
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn clear_preserves_sequence_counter() {
        let mut buf = ReplayBuffer::new(10);
        let _ = buf.push(Bytes::from("a"), vec![]);
        let _ = buf.push(Bytes::from("b"), vec![]);
        buf.clear();

        // Next push should continue from seq 3, not restart at 1
        let seq = buf.push(Bytes::from("c"), vec![]);
        assert_eq!(seq, 3);
    }

    #[test]
    fn all_messages_deduped_removes_duplicates() {
        let mut buf = ReplayBuffer::new(10);
        let _ = buf.push(Bytes::from("a"), vec!["g1".into()]);
        let _ = buf.push(Bytes::from("b"), vec!["g2".into()]);
        let _ = buf.push(Bytes::from("a"), vec!["g3".into()]); // duplicate payload

        let deduped = buf.all_messages_deduped();
        assert_eq!(deduped.len(), 2);
        assert_eq!(deduped[0].payload, Bytes::from("a"));
        assert_eq!(deduped[1].payload, Bytes::from("b"));
    }

    #[test]
    fn all_messages_deduped_keeps_first_occurrence() {
        let mut buf = ReplayBuffer::new(10);
        let _ = buf.push(Bytes::from("x"), vec!["alpha".into()]);
        let _ = buf.push(Bytes::from("x"), vec!["bravo".into()]);

        let deduped = buf.all_messages_deduped();
        assert_eq!(deduped.len(), 1);
        // Should keep first occurrence (seq=1, groups=["alpha"])
        assert_eq!(deduped[0].seq, 1);
        assert_eq!(deduped[0].groups, vec!["alpha".to_string()]);
    }

    #[test]
    fn all_messages_deduped_empty_buffer() {
        let buf = ReplayBuffer::new(10);
        assert!(buf.all_messages_deduped().is_empty());
    }

    // ── persistence tests (issue #557) ─────────────────────────────────

    use crate::replay_persist::ReplayStore;

    fn open_store() -> (tempfile::TempDir, Arc<ReplayStore>) {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(ReplayStore::open(dir.path(), 1024 * 1024).unwrap());
        (dir, store)
    }

    #[test]
    fn persistent_push_writes_through_to_store() {
        let (_dir, store) = open_store();
        let mut buf = ReplayBuffer::with_store(10, "peer-a", Arc::clone(&store));
        let _ = buf.push(Bytes::from_static(b"hello"), vec!["alpha".into()]);
        let _ = buf.push(Bytes::from_static(b"world"), vec!["bravo".into()]);
        assert_eq!(store.load_all().unwrap().len(), 2);
    }

    #[test]
    fn persistent_eviction_deletes_oldest_from_store() {
        let (_dir, store) = open_store();
        let mut buf = ReplayBuffer::with_store(2, "peer-a", Arc::clone(&store));
        let _ = buf.push(Bytes::from_static(b"a"), vec![]);
        let _ = buf.push(Bytes::from_static(b"b"), vec![]);
        let _ = buf.push(Bytes::from_static(b"c"), vec![]);
        let all = store.load_all().unwrap();
        assert_eq!(all.len(), 2);
        let seqs: Vec<u64> = all.iter().map(|e| e.seq).collect();
        assert!(seqs.contains(&2));
        assert!(seqs.contains(&3));
        assert!(!seqs.contains(&1));
    }

    #[test]
    fn persistent_clear_drops_peer_entries() {
        let (_dir, store) = open_store();
        let mut buf = ReplayBuffer::with_store(10, "peer-a", Arc::clone(&store));
        let _ = buf.push(Bytes::from_static(b"a"), vec![]);
        let _ = buf.push(Bytes::from_static(b"b"), vec![]);
        buf.clear();
        assert!(store.load_all().unwrap().is_empty());
    }

    #[test]
    fn hydrate_restores_buffer_and_continues_seq() {
        let (_dir, store) = open_store();
        // Pretend a previous run wrote three entries.
        store
            .put("peer-a", 1, &["alpha".into()], &Bytes::from_static(b"a"))
            .unwrap();
        store
            .put("peer-a", 2, &["alpha".into()], &Bytes::from_static(b"b"))
            .unwrap();
        store
            .put("peer-a", 3, &["alpha".into()], &Bytes::from_static(b"c"))
            .unwrap();

        let mut buf = ReplayBuffer::with_store(10, "peer-a", Arc::clone(&store));
        let restored: Vec<BufferedMessage> = store
            .load_all()
            .unwrap()
            .into_iter()
            .filter(|e| e.peer_id == "peer-a")
            .map(|e| BufferedMessage {
                seq: e.seq,
                payload: e.payload,
                groups: e.groups,
            })
            .collect();
        buf.hydrate_from_records(restored);

        assert_eq!(buf.len(), 3);
        // New pushes continue past the restored max seq (3 -> next is 4).
        let next = buf.push(Bytes::from_static(b"d"), vec![]);
        assert_eq!(next, 4);
    }

    #[test]
    fn hydrate_evicts_excess_records_beyond_capacity() {
        let (_dir, store) = open_store();
        for i in 1u64..=5 {
            store
                .put("peer-a", i, &[], &Bytes::from(vec![b'x']))
                .unwrap();
        }
        let mut buf = ReplayBuffer::with_store(2, "peer-a", Arc::clone(&store));
        let restored: Vec<BufferedMessage> = store
            .load_all()
            .unwrap()
            .into_iter()
            .filter(|e| e.peer_id == "peer-a")
            .map(|e| BufferedMessage {
                seq: e.seq,
                payload: e.payload,
                groups: e.groups,
            })
            .collect();
        buf.hydrate_from_records(restored);
        assert_eq!(buf.len(), 2);
        let in_mem: Vec<u64> = buf.all_messages().iter().map(|m| m.seq).collect();
        assert_eq!(in_mem, vec![4, 5]);
        // Disk should match memory after hydrate-driven eviction.
        let on_disk: Vec<u64> = store.load_all().unwrap().iter().map(|e| e.seq).collect();
        assert_eq!(on_disk, vec![4, 5]);
    }

    #[test]
    fn restart_then_messages_since_returns_pending() {
        // Simulates issue #557 acceptance: restart the server, peer reconnects
        // and replay resumes from its last seen seq.
        let dir = tempfile::tempdir().unwrap();
        let store_path = dir.path();
        let last_seen;
        {
            let store = Arc::new(ReplayStore::open(store_path, 1024 * 1024).unwrap());
            let mut buf = ReplayBuffer::with_store(10, "peer-a", Arc::clone(&store));
            let _ = buf.push(Bytes::from_static(b"a"), vec![]);
            last_seen = buf.push(Bytes::from_static(b"b"), vec![]);
            let _ = buf.push(Bytes::from_static(b"c"), vec![]);
            let _ = buf.push(Bytes::from_static(b"d"), vec![]);
        }
        // "Restart" — open the store fresh and rehydrate.
        let store = Arc::new(ReplayStore::open(store_path, 1024 * 1024).unwrap());
        let mut buf = ReplayBuffer::with_store(10, "peer-a", Arc::clone(&store));
        let restored: Vec<BufferedMessage> = store
            .load_all()
            .unwrap()
            .into_iter()
            .filter(|e| e.peer_id == "peer-a")
            .map(|e| BufferedMessage {
                seq: e.seq,
                payload: e.payload,
                groups: e.groups,
            })
            .collect();
        buf.hydrate_from_records(restored);

        let pending = buf.messages_since(last_seen);
        assert_eq!(pending.len(), 2);
        assert_eq!(pending[0].payload, Bytes::from_static(b"c"));
        assert_eq!(pending[1].payload, Bytes::from_static(b"d"));
    }
}
