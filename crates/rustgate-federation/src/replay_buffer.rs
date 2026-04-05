//! Bounded replay buffer for federation peer reconnection.
//!
//! Stores recent forwarded messages in a per-peer ring buffer so that
//! when a peer reconnects, missed messages can be replayed before
//! resuming the live stream.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;

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
}

impl ReplayBuffer {
    /// Create a new replay buffer with the given capacity.
    pub fn new(capacity: usize) -> Self {
        Self {
            buffer: VecDeque::with_capacity(capacity.min(1024)),
            capacity,
            next_seq: AtomicU64::new(1),
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
        if self.buffer.len() >= self.capacity {
            let _ = self.buffer.pop_front();
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
        buf.push(Bytes::from("a"), vec![]);
        buf.push(Bytes::from("b"), vec![]);
        buf.push(Bytes::from("c"), vec![]);
        buf.push(Bytes::from("d"), vec![]);

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
        buf.push(Bytes::from("a"), vec![]);
        buf.push(Bytes::from("b"), vec![]);

        let since = buf.messages_since(0);
        assert_eq!(since.len(), 2);
    }

    #[test]
    fn messages_since_future_returns_empty() {
        let mut buf = ReplayBuffer::new(10);
        buf.push(Bytes::from("a"), vec![]);

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
        buf.push(Bytes::from("a"), vec![]);
        assert_eq!(buf.oldest_seq(), Some(1));

        buf.push(Bytes::from("b"), vec![]);
        assert_eq!(buf.oldest_seq(), Some(1));

        buf.push(Bytes::from("c"), vec![]);
        assert_eq!(buf.oldest_seq(), Some(2)); // "a" evicted
    }

    #[test]
    fn zero_capacity_evicts_immediately() {
        let mut buf = ReplayBuffer::new(0);
        buf.push(Bytes::from("a"), vec![]);
        assert!(buf.is_empty());
    }
}
