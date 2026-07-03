// Copyright © 2026 Roberto Chiofalo.

//! Backend-agnostic durable, replayable message store abstraction.
//!
//! The workspace currently carries three bespoke append-and-replay stores,
//! each with its own on-disk layout, error type, and retention logic:
//!
//! - `rustgate-router`'s store-and-forward `ClientQueue` (per-CN,
//!   HMAC-tagged, redb-backed),
//! - `rustgate-mqtt`'s in-memory `session_store` (persisted session state),
//! - `rustgate-federation`'s `ReplayStore` (per-peer replay buffer,
//!   redb-backed).
//!
//! [`DurableStore`] is the unifying seam those three stores are intended to
//! grow onto. It captures the shared contract — append a payload to a named
//! stream and get back a monotonic offset, replay records from an offset, and
//! enforce a retention policy — without dictating a backend. Concrete
//! implementations may sit on redb today and on a JetStream-style log later;
//! callers hold `Arc<dyn DurableStore>` and never see the difference.
//!
//! This module is deliberately **additive**. Landing the trait does not
//! rewire any of the three live stores; the migration path is recorded in
//! `docs/adr/0028-durable-replayable-message-store.md` and tracked by its
//! named follow-up issues. See [`DurableStore`] for the contract each store
//! will implement in turn.

use bytes::Bytes;

/// A single record recovered from a [`DurableStore`] during replay.
///
/// The `offset` is the monotonic position assigned by the store at
/// [`DurableStore::append`] time. It is stable for the life of the record and
/// is the value a caller passes to [`DurableStore::replay_from`] to resume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredRecord {
    /// Monotonic per-stream position assigned when the record was appended.
    pub offset: u64,
    /// The stored payload, zero-copy where the backend allows it.
    pub payload: Bytes,
}

/// Retention policy applied by [`DurableStore::retain`].
///
/// Bounds are independent and inclusive caps: a `None` field imposes no limit
/// on that dimension. When both are set, an implementation evicts oldest-first
/// until **both** caps are satisfied. A policy with every field `None` is a
/// no-op and MUST NOT drop records.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RetentionPolicy {
    /// Maximum total payload bytes to retain per stream, or unlimited.
    pub max_bytes: Option<u64>,
    /// Maximum number of records to retain per stream, or unlimited.
    pub max_records: Option<u64>,
}

impl RetentionPolicy {
    /// A policy that retains everything (both caps unset).
    #[must_use]
    pub const fn unbounded() -> Self {
        Self {
            max_bytes: None,
            max_records: None,
        }
    }
}

/// Errors surfaced by a [`DurableStore`] implementation.
///
/// Backends map their own error types (redb, I/O, a remote log client) onto
/// these variants so callers can reason about failure uniformly regardless of
/// which store they hold behind `dyn DurableStore`.
#[derive(Debug, thiserror::Error)]
pub enum DurableStoreError {
    /// The underlying backend failed (I/O, redb, transport, serialization).
    ///
    /// Carries a human-readable description; the concrete cause is
    /// backend-specific and intentionally not part of the public contract.
    #[error("durable store backend error: {0}")]
    Backend(String),

    /// The requested stream or offset does not exist.
    #[error("durable store: stream `{stream}` has no record at offset {offset}")]
    NotFound {
        /// The stream that was queried.
        stream: String,
        /// The offset that was requested but not present.
        offset: u64,
    },

    /// A stored record failed an integrity check (e.g. HMAC mismatch, torn
    /// write, or an unrecognized on-disk layout) and cannot be trusted.
    #[error("durable store: stream `{stream}` is corrupt: {detail}")]
    Corrupt {
        /// The stream whose data failed validation.
        stream: String,
        /// Description of the integrity failure.
        detail: String,
    },
}

/// A backend-agnostic durable, replayable, append-only message store.
///
/// The trait is intentionally **object-safe**: every method takes `&self`,
/// none are generic, and none are `async`. Callers hold implementations as
/// `Arc<dyn DurableStore>`. Mirroring the existing synchronous redb-backed
/// stores keeps the seam dyn-safe without forcing boxed futures; a future
/// async backend can wrap a blocking implementation with the workspace's
/// task-offload helpers rather than changing this contract.
///
/// # Streams
///
/// A *stream* is a named, independent append-only log (e.g. a per-CN queue or
/// a per-peer replay buffer). Offsets are per-stream and monotonic.
///
/// # Contract
///
/// - [`append`](DurableStore::append) returns a strictly increasing offset per
///   stream; the first appended record MAY start at any value, but subsequent
///   records in the same stream MUST have strictly greater offsets.
/// - [`replay_from`](DurableStore::replay_from) returns every retained record
///   whose offset is `>= offset`, in ascending offset order.
/// - [`retain`](DurableStore::retain) evicts oldest-first to satisfy the
///   policy and MUST be idempotent for an unchanged stream.
pub trait DurableStore: Send + Sync {
    /// Append `payload` to `stream`, returning the assigned monotonic offset.
    ///
    /// # Errors
    ///
    /// Returns [`DurableStoreError::Backend`] if the underlying store cannot
    /// persist the record.
    fn append(&self, stream: &str, payload: &[u8]) -> Result<u64, DurableStoreError>;

    /// Replay all retained records in `stream` at or after `offset`, in
    /// ascending offset order.
    ///
    /// An empty vector means the stream has no records at or after `offset`
    /// (including the case where retention has already evicted them); this is
    /// not an error. [`DurableStoreError::NotFound`] is reserved for a stream
    /// that was never opened by the backend, where that distinction is
    /// meaningful.
    ///
    /// # Errors
    ///
    /// Returns [`DurableStoreError::Corrupt`] if a stored record fails its
    /// integrity check, or [`DurableStoreError::Backend`] on a read failure.
    fn replay_from(
        &self,
        stream: &str,
        offset: u64,
    ) -> Result<Vec<StoredRecord>, DurableStoreError>;

    /// Apply `policy` to `stream`, evicting oldest records first until the
    /// retention caps are satisfied.
    ///
    /// # Errors
    ///
    /// Returns [`DurableStoreError::Backend`] if eviction cannot be persisted.
    fn retain(&self, stream: &str, policy: RetentionPolicy) -> Result<(), DurableStoreError>;

    /// Number of records currently retained in `stream`.
    ///
    /// # Errors
    ///
    /// Returns [`DurableStoreError::Backend`] on a read failure.
    fn len(&self, stream: &str) -> Result<u64, DurableStoreError>;

    /// Whether `stream` currently retains no records.
    ///
    /// # Errors
    ///
    /// Returns [`DurableStoreError::Backend`] on a read failure.
    fn is_empty(&self, stream: &str) -> Result<bool, DurableStoreError> {
        Ok(self.len(stream)? == 0)
    }

    /// Total retained payload bytes in `stream`.
    ///
    /// # Errors
    ///
    /// Returns [`DurableStoreError::Backend`] on a read failure.
    fn total_bytes(&self, stream: &str) -> Result<u64, DurableStoreError>;
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use super::*;

    /// Minimal in-memory [`DurableStore`] used to prove the trait is
    /// object-safe and to exercise the documented offset/replay/retention
    /// contract. Test-only; not part of the crate's public surface.
    #[derive(Default)]
    struct MemDurableStore {
        streams: Mutex<HashMap<String, Vec<StoredRecord>>>,
        next: Mutex<HashMap<String, u64>>,
    }

    impl DurableStore for MemDurableStore {
        fn append(&self, stream: &str, payload: &[u8]) -> Result<u64, DurableStoreError> {
            let mut next = self.next.lock().unwrap();
            let offset = next.entry(stream.to_owned()).or_insert(0);
            let assigned = *offset;
            *offset += 1;
            drop(next);

            let mut streams = self.streams.lock().unwrap();
            streams
                .entry(stream.to_owned())
                .or_default()
                .push(StoredRecord {
                    offset: assigned,
                    payload: Bytes::copy_from_slice(payload),
                });
            Ok(assigned)
        }

        fn replay_from(
            &self,
            stream: &str,
            offset: u64,
        ) -> Result<Vec<StoredRecord>, DurableStoreError> {
            let streams = self.streams.lock().unwrap();
            let records = streams
                .get(stream)
                .map(|recs| {
                    recs.iter()
                        .filter(|r| r.offset >= offset)
                        .cloned()
                        .collect()
                })
                .unwrap_or_default();
            Ok(records)
        }

        fn retain(&self, stream: &str, policy: RetentionPolicy) -> Result<(), DurableStoreError> {
            let mut streams = self.streams.lock().unwrap();
            let Some(recs) = streams.get_mut(stream) else {
                return Ok(());
            };

            if let Some(max_records) = policy.max_records {
                let max = max_records as usize;
                if recs.len() > max {
                    let drop_count = recs.len() - max;
                    let _ = recs.drain(0..drop_count);
                }
            }

            if let Some(max_bytes) = policy.max_bytes {
                let mut total: u64 = recs.iter().map(|r| r.payload.len() as u64).sum();
                while total > max_bytes && !recs.is_empty() {
                    let removed = recs.remove(0);
                    total -= removed.payload.len() as u64;
                }
            }

            Ok(())
        }

        fn len(&self, stream: &str) -> Result<u64, DurableStoreError> {
            let streams = self.streams.lock().unwrap();
            Ok(streams.get(stream).map_or(0, |r| r.len() as u64))
        }

        fn total_bytes(&self, stream: &str) -> Result<u64, DurableStoreError> {
            let streams = self.streams.lock().unwrap();
            Ok(streams
                .get(stream)
                .map_or(0, |r| r.iter().map(|rec| rec.payload.len() as u64).sum()))
        }
    }

    #[test]
    fn append_returns_monotonic_offsets_per_stream() {
        let store: Arc<dyn DurableStore> = Arc::new(MemDurableStore::default());

        let a0 = store.append("cn-a", b"one").unwrap();
        let a1 = store.append("cn-a", b"two").unwrap();
        let b0 = store.append("cn-b", b"first").unwrap();

        assert!(a1 > a0, "offsets must strictly increase within a stream");
        assert_eq!(a0, 0);
        assert_eq!(a1, 1);
        // Streams are independent: cn-b starts its own offset sequence.
        assert_eq!(b0, 0);
        assert_eq!(store.len("cn-a").unwrap(), 2);
        assert_eq!(store.len("cn-b").unwrap(), 1);
    }

    #[test]
    fn replay_from_returns_records_at_or_after_offset_in_order() {
        let store = MemDurableStore::default();
        for payload in [&b"a"[..], b"b", b"c", b"d"] {
            let _ = store.append("s", payload).unwrap();
        }

        let tail = store.replay_from("s", 2).unwrap();
        let offsets: Vec<u64> = tail.iter().map(|r| r.offset).collect();
        assert_eq!(offsets, vec![2, 3]);
        assert_eq!(tail[0].payload.as_ref(), b"c");

        // Replaying from a fresh, never-touched stream is empty, not an error.
        assert!(store.replay_from("unknown", 0).unwrap().is_empty());
    }

    #[test]
    fn retain_max_records_drops_oldest() {
        let store = MemDurableStore::default();
        for payload in [&b"1"[..], b"2", b"3", b"4", b"5"] {
            let _ = store.append("s", payload).unwrap();
        }

        store
            .retain(
                "s",
                RetentionPolicy {
                    max_records: Some(2),
                    max_bytes: None,
                },
            )
            .unwrap();

        assert_eq!(store.len("s").unwrap(), 2);
        let remaining: Vec<u64> = store
            .replay_from("s", 0)
            .unwrap()
            .iter()
            .map(|r| r.offset)
            .collect();
        assert_eq!(remaining, vec![3, 4], "oldest records evicted first");
    }

    #[test]
    fn retain_max_bytes_evicts_oldest_by_byte_cap() {
        let store = MemDurableStore::default();
        // Four 4-byte records = 16 bytes total.
        for payload in [&b"aaaa"[..], b"bbbb", b"cccc", b"dddd"] {
            let _ = store.append("s", payload).unwrap();
        }

        // Cap at 8 bytes → only the two newest 4-byte records survive.
        store
            .retain(
                "s",
                RetentionPolicy {
                    max_bytes: Some(8),
                    max_records: None,
                },
            )
            .unwrap();

        assert_eq!(store.total_bytes("s").unwrap(), 8);
        let remaining: Vec<u64> = store
            .replay_from("s", 0)
            .unwrap()
            .iter()
            .map(|r| r.offset)
            .collect();
        assert_eq!(remaining, vec![2, 3]);
    }

    #[test]
    fn unbounded_policy_is_a_no_op() {
        let store = MemDurableStore::default();
        for payload in [&b"x"[..], b"y", b"z"] {
            let _ = store.append("s", payload).unwrap();
        }

        store.retain("s", RetentionPolicy::unbounded()).unwrap();

        assert_eq!(store.len("s").unwrap(), 3);
        assert!(!store.is_empty("s").unwrap());
    }

    #[test]
    fn is_empty_reflects_stream_state() {
        let store = MemDurableStore::default();
        assert!(store.is_empty("fresh").unwrap());
        let _ = store.append("fresh", b"data").unwrap();
        assert!(!store.is_empty("fresh").unwrap());
    }

    #[test]
    fn error_variants_render_via_thiserror_display() {
        let backend = DurableStoreError::Backend("disk full".to_owned());
        assert_eq!(
            backend.to_string(),
            "durable store backend error: disk full"
        );

        let not_found = DurableStoreError::NotFound {
            stream: "cn-a".to_owned(),
            offset: 7,
        };
        assert_eq!(
            not_found.to_string(),
            "durable store: stream `cn-a` has no record at offset 7"
        );

        let corrupt = DurableStoreError::Corrupt {
            stream: "cn-a".to_owned(),
            detail: "HMAC mismatch".to_owned(),
        };
        assert_eq!(
            corrupt.to_string(),
            "durable store: stream `cn-a` is corrupt: HMAC mismatch"
        );
    }
}
