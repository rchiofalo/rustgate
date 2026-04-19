// Copyright © 2026 Roberto Chiofalo.

//! Disk persistence for the per-peer federation replay buffer.
//!
//! The in-memory [`crate::replay_buffer::ReplayBuffer`] is bounded and
//! lost on restart. Operationally, server restart often coincides with a
//! peer reconnect — exactly the moment we want to replay buffered
//! messages. This module persists each buffered message to a redb table
//! so the replay buffers can be restored on startup.
//!
//! The on-disk format is intentionally minimal:
//!
//! ```text
//! key   = peer_id (str) + b"\x00" + seq (u64 big-endian)
//! value = u64 enqueued_at_unix_ms,
//!         u64 ttl_ms (0 = no TTL),
//!         u32 groups_len, [u32 group_len, group_bytes]*,
//!         payload bytes
//! ```
//!
//! A single redb table is used so we can iterate by peer prefix on
//! startup and walk in seq order for global byte-cap eviction.
//!
//! This store is **independent** of the client store-and-forward
//! database (`crates/rustgate-transport/src/store_forward.rs`) — they
//! solve different problems (per-CN client queue vs. per-federation-peer
//! replay window) and pinning them to separate files keeps the schemas
//! decoupled.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use parking_lot::Mutex;
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use thiserror::Error;
use tracing::{debug, warn};

/// redb table backing persisted replay-buffer entries. The key is the
/// composite (peer_id, seq) blob described in the module docs.
// Bumped from `federation_replay_v1` when the value schema gained the
// `enqueued_at_unix_ms` and `ttl_ms` prefix used for TTL-on-rehydrate
// (#557 follow-up). Older databases that only contain the v1 table will
// open cleanly with an empty v2 table — those legacy entries are
// effectively dropped on first start of the new binary.
const REPLAY_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("federation_replay_v2");

/// Per-record overhead estimate added to the raw key + value byte counts
/// when enforcing the global byte cap. Covers redb's per-entry metadata
/// (page accounting, b-tree pointers, etc.) without paying the cost of a
/// full `Database::stats()` round-trip on every put. The constant is
/// intentionally generous: undercounting overhead would let the on-disk
/// footprint exceed the operator's `--federation-replay-max-bytes`
/// budget, which is the failure mode we are trying to avoid.
const REDB_PER_RECORD_OVERHEAD: u64 = 32;

/// Default global byte cap when the operator enables persistence
/// without an explicit `--federation-replay-max-bytes`.
pub const DEFAULT_REPLAY_MAX_BYTES: u64 = 64 * 1024 * 1024;

/// Errors returned by [`ReplayStore`].
#[derive(Debug, Error)]
pub enum ReplayStoreError {
    /// An underlying redb error.
    #[error("federation replay store database error: {0}")]
    Database(String),
    /// A persisted entry failed to decode and was dropped.
    #[error("malformed federation replay entry")]
    Decode,
}

/// Restored buffered message returned by [`ReplayStore::load_all`].
#[derive(Debug, Clone)]
pub struct RestoredEntry {
    /// Peer this entry belongs to.
    pub peer_id: String,
    /// Sequence number originally assigned by the in-memory ring.
    pub seq: u64,
    /// Wall-clock time (Unix milliseconds) at which the entry was first
    /// enqueued. Used to enforce TTL-on-rehydrate so persistence cannot
    /// resurrect messages that should have been dropped.
    pub enqueued_at_unix_ms: u64,
    /// Original TTL in milliseconds, or `None` if the source message
    /// had no TTL.
    pub ttl_ms: Option<u64>,
    /// Source groups for routing.
    pub groups: Vec<String>,
    /// Raw message payload.
    pub payload: Bytes,
}

#[derive(Debug)]
struct Entry {
    peer_id: String,
    seq: u64,
    /// Accounted on-disk size including key bytes, value bytes, and a
    /// constant overhead estimate for redb's per-record metadata.
    bytes: u64,
    /// Enqueue timestamp used to drive global drop-oldest eviction —
    /// not insertion order, so peers that drain at different rates
    /// still age out in the right order after a rehydrate.
    enqueued_at_unix_ms: u64,
}

#[derive(Debug)]
struct Inner {
    /// FIFO of all entries in insertion order, used to drive global
    /// byte-cap eviction (drop oldest first).
    global: VecDeque<Entry>,
    total_bytes: u64,
}

impl Inner {
    fn new() -> Self {
        Self {
            global: VecDeque::new(),
            total_bytes: 0,
        }
    }
}

/// Persistent, bounded redb-backed store for the federation replay buffer.
///
/// Cloning a [`ReplayStore`] is cheap; it holds an `Arc` to the shared
/// database and in-memory index.
#[derive(Clone, Debug)]
pub struct ReplayStore {
    db: Arc<Database>,
    inner: Arc<Mutex<Inner>>,
    max_bytes: u64,
    #[allow(dead_code)]
    path: PathBuf,
}

impl ReplayStore {
    /// Open or create the replay store rooted at `dir`. The database
    /// file is named `federation_replay.redb`. The directory is created
    /// if it does not exist.
    pub fn open(dir: &Path, max_bytes: u64) -> Result<Self, ReplayStoreError> {
        std::fs::create_dir_all(dir).map_err(|e| ReplayStoreError::Database(e.to_string()))?;
        let path = dir.join("federation_replay.redb");
        let db = Database::create(&path).map_err(|e| ReplayStoreError::Database(e.to_string()))?;

        // Ensure the table exists.
        {
            let write = db
                .begin_write()
                .map_err(|e| ReplayStoreError::Database(e.to_string()))?;
            {
                let _ = write
                    .open_table(REPLAY_TABLE)
                    .map_err(|e| ReplayStoreError::Database(e.to_string()))?;
            }
            write
                .commit()
                .map_err(|e| ReplayStoreError::Database(e.to_string()))?;
        }

        let mut inner = Inner::new();
        {
            let read = db
                .begin_read()
                .map_err(|e| ReplayStoreError::Database(e.to_string()))?;
            let table = read
                .open_table(REPLAY_TABLE)
                .map_err(|e| ReplayStoreError::Database(e.to_string()))?;
            for entry in table
                .iter()
                .map_err(|e| ReplayStoreError::Database(e.to_string()))?
            {
                let (k, v) = match entry {
                    Ok(kv) => kv,
                    Err(e) => {
                        warn!(error = %e, "skipping unreadable replay-store entry");
                        continue;
                    }
                };
                let key = k.value();
                let value = v.value();
                let (peer_id, seq) = match decode_key(key) {
                    Some(p) => p,
                    None => {
                        debug!("skipping malformed replay-store key on rebuild");
                        continue;
                    }
                };
                let Some((enqueued_at_unix_ms, _ttl_ms, _groups, _payload)) = decode_value(value)
                else {
                    debug!("skipping malformed replay-store value on rebuild");
                    continue;
                };
                let bytes = accounted_size(key.len(), value.len());
                inner.total_bytes = inner.total_bytes.saturating_add(bytes);
                inner.global.push_back(Entry {
                    peer_id,
                    seq,
                    bytes,
                    enqueued_at_unix_ms,
                });
            }
            // Restore global drop-oldest ordering by original enqueue
            // timestamp, not by the (peer_id, seq) iteration order we
            // happened to read off disk.
            inner
                .global
                .make_contiguous()
                .sort_by_key(|e| e.enqueued_at_unix_ms);
        }

        // Seed the gauge with the rehydrated total so dashboards reflect
        // the persisted footprint immediately on startup, before any new
        // put/delete traffic arrives.
        publish_total_bytes(inner.total_bytes);

        Ok(Self {
            db: Arc::new(db),
            inner: Arc::new(Mutex::new(inner)),
            max_bytes,
            path,
        })
    }

    /// Persist a single replay entry. Returns `Ok(())` on success even
    /// when the entry was evicted by the byte cap (caller should treat
    /// the in-memory ring as the source of truth for current contents).
    pub fn put(
        &self,
        peer_id: &str,
        seq: u64,
        enqueued_at_unix_ms: u64,
        ttl_ms: Option<u64>,
        groups: &[String],
        payload: &Bytes,
    ) -> Result<(), ReplayStoreError> {
        let value = encode_value(enqueued_at_unix_ms, ttl_ms, groups, payload);
        let key = encode_key(peer_id, seq);
        let accounted = accounted_size(key.len(), value.len());

        // Evict from the front until we have room. Done before the
        // write so the database commit reflects the post-eviction state.
        // The deque is kept ordered by `enqueued_at_unix_ms` so the
        // front is always the globally-oldest record across peers,
        // even when peers drain at different rates.
        let (to_delete, new_total_bytes): (Vec<(String, u64)>, u64) = {
            let mut inner = self.inner.lock();
            let mut victims = Vec::new();
            while inner.total_bytes.saturating_add(accounted) > self.max_bytes
                && let Some(front) = inner.global.pop_front()
            {
                inner.total_bytes = inner.total_bytes.saturating_sub(front.bytes);
                victims.push((front.peer_id, front.seq));
            }
            // Insertion-sorted by enqueue timestamp. Since timestamps
            // are monotonic for live writes, this almost always lands
            // at the back; the search exists to keep correctness if a
            // hydrate or clock skew produces an out-of-order put.
            let new_entry = Entry {
                peer_id: peer_id.to_string(),
                seq,
                bytes: accounted,
                enqueued_at_unix_ms,
            };
            let pos = inner
                .global
                .iter()
                .rposition(|e| e.enqueued_at_unix_ms <= enqueued_at_unix_ms)
                .map(|p| p + 1)
                .unwrap_or(0);
            inner.global.insert(pos, new_entry);
            inner.total_bytes = inner.total_bytes.saturating_add(accounted);
            (victims, inner.total_bytes)
        };
        publish_total_bytes(new_total_bytes);

        let write = self
            .db
            .begin_write()
            .map_err(|e| ReplayStoreError::Database(e.to_string()))?;
        {
            let mut table = write
                .open_table(REPLAY_TABLE)
                .map_err(|e| ReplayStoreError::Database(e.to_string()))?;
            for (pid, seq) in &to_delete {
                let k = encode_key(pid, *seq);
                let _ = table
                    .remove(k.as_slice())
                    .map_err(|e| ReplayStoreError::Database(e.to_string()))?;
            }
            let _ = table
                .insert(key.as_slice(), value.as_slice())
                .map_err(|e| ReplayStoreError::Database(e.to_string()))?;
        }
        write
            .commit()
            .map_err(|e| ReplayStoreError::Database(e.to_string()))?;
        Ok(())
    }

    /// Delete a single (peer, seq) entry. Used when the in-memory ring
    /// evicts the oldest message after exceeding its capacity.
    pub fn delete(&self, peer_id: &str, seq: u64) -> Result<(), ReplayStoreError> {
        let key = encode_key(peer_id, seq);
        let new_total_bytes = {
            let mut inner = self.inner.lock();
            if let Some(pos) = inner
                .global
                .iter()
                .position(|e| e.seq == seq && e.peer_id == peer_id)
                && let Some(entry) = inner.global.remove(pos)
            {
                inner.total_bytes = inner.total_bytes.saturating_sub(entry.bytes);
            }
            inner.total_bytes
        };
        publish_total_bytes(new_total_bytes);
        let write = self
            .db
            .begin_write()
            .map_err(|e| ReplayStoreError::Database(e.to_string()))?;
        {
            let mut table = write
                .open_table(REPLAY_TABLE)
                .map_err(|e| ReplayStoreError::Database(e.to_string()))?;
            let _ = table
                .remove(key.as_slice())
                .map_err(|e| ReplayStoreError::Database(e.to_string()))?;
        }
        write
            .commit()
            .map_err(|e| ReplayStoreError::Database(e.to_string()))?;
        Ok(())
    }

    /// Delete every persisted entry belonging to `peer_id`. Used by
    /// [`crate::manager::FederationManager::clear_replay_buffer`] and
    /// [`crate::manager::FederationManager::remove_replay_buffer`].
    pub fn clear_peer(&self, peer_id: &str) -> Result<(), ReplayStoreError> {
        let (victims, new_total_bytes): (Vec<u64>, u64) = {
            let mut inner = self.inner.lock();
            let mut seqs = Vec::new();
            let mut bytes_freed: u64 = 0;
            inner.global.retain(|e| {
                if e.peer_id == peer_id {
                    bytes_freed = bytes_freed.saturating_add(e.bytes);
                    seqs.push(e.seq);
                    false
                } else {
                    true
                }
            });
            inner.total_bytes = inner.total_bytes.saturating_sub(bytes_freed);
            (seqs, inner.total_bytes)
        };
        publish_total_bytes(new_total_bytes);
        if victims.is_empty() {
            return Ok(());
        }
        let write = self
            .db
            .begin_write()
            .map_err(|e| ReplayStoreError::Database(e.to_string()))?;
        {
            let mut table = write
                .open_table(REPLAY_TABLE)
                .map_err(|e| ReplayStoreError::Database(e.to_string()))?;
            for seq in victims {
                let k = encode_key(peer_id, seq);
                let _ = table
                    .remove(k.as_slice())
                    .map_err(|e| ReplayStoreError::Database(e.to_string()))?;
            }
        }
        write
            .commit()
            .map_err(|e| ReplayStoreError::Database(e.to_string()))?;
        Ok(())
    }

    /// Load every persisted entry from the database. Returned in
    /// (peer_id, seq) order so the caller can rehydrate per-peer rings
    /// in their original FIFO order.
    pub fn load_all(&self) -> Result<Vec<RestoredEntry>, ReplayStoreError> {
        let read = self
            .db
            .begin_read()
            .map_err(|e| ReplayStoreError::Database(e.to_string()))?;
        let table = read
            .open_table(REPLAY_TABLE)
            .map_err(|e| ReplayStoreError::Database(e.to_string()))?;
        let mut out = Vec::new();
        for entry in table
            .iter()
            .map_err(|e| ReplayStoreError::Database(e.to_string()))?
        {
            let (k, v) = match entry {
                Ok(kv) => kv,
                Err(e) => {
                    warn!(error = %e, "skipping unreadable replay-store entry on load");
                    continue;
                }
            };
            let Some((peer_id, seq)) = decode_key(k.value()) else {
                debug!("skipping malformed replay-store key on load");
                continue;
            };
            let Some((enqueued_at_unix_ms, ttl_ms, groups, payload)) = decode_value(v.value())
            else {
                debug!("skipping malformed replay-store value on load");
                continue;
            };
            out.push(RestoredEntry {
                peer_id,
                seq,
                enqueued_at_unix_ms,
                ttl_ms,
                groups,
                payload,
            });
        }
        out.sort_by(|a, b| (a.peer_id.as_str(), a.seq).cmp(&(b.peer_id.as_str(), b.seq)));
        Ok(out)
    }

    /// Number of entries currently tracked in memory.
    pub fn len(&self) -> usize {
        self.inner.lock().global.len()
    }

    /// Returns true if the store has no tracked entries.
    pub fn is_empty(&self) -> bool {
        self.inner.lock().global.is_empty()
    }

    /// Total bytes currently persisted across all peers.
    pub fn total_bytes(&self) -> u64 {
        self.inner.lock().total_bytes
    }
}

fn encode_key(peer_id: &str, seq: u64) -> Vec<u8> {
    let mut k = Vec::with_capacity(peer_id.len() + 1 + 8);
    k.extend_from_slice(peer_id.as_bytes());
    k.push(0);
    k.extend_from_slice(&seq.to_be_bytes());
    k
}

fn decode_key(raw: &[u8]) -> Option<(String, u64)> {
    if raw.len() < 9 {
        return None;
    }
    let split = raw.len() - 9;
    if raw[split] != 0 {
        return None;
    }
    let peer = std::str::from_utf8(&raw[..split]).ok()?.to_string();
    let mut seq_bytes = [0u8; 8];
    seq_bytes.copy_from_slice(&raw[split + 1..]);
    Some((peer, u64::from_be_bytes(seq_bytes)))
}

fn encode_value(
    enqueued_at_unix_ms: u64,
    ttl_ms: Option<u64>,
    groups: &[String],
    payload: &Bytes,
) -> Vec<u8> {
    let mut buf = BytesMut::new();
    buf.put_u64(enqueued_at_unix_ms);
    // Encode `None` as 0; live messages are never enqueued with a 0 ms
    // TTL because the forward boundary would have already dropped them.
    buf.put_u64(ttl_ms.unwrap_or(0));
    buf.put_u32(groups.len() as u32);
    for g in groups {
        buf.put_u32(g.len() as u32);
        buf.put_slice(g.as_bytes());
    }
    buf.put_slice(payload);
    buf.to_vec()
}

fn decode_value(mut raw: &[u8]) -> Option<(u64, Option<u64>, Vec<String>, Bytes)> {
    if raw.len() < 8 + 8 + 4 {
        return None;
    }
    let enqueued_at_unix_ms = raw.get_u64();
    let ttl_raw = raw.get_u64();
    let ttl_ms = if ttl_raw == 0 { None } else { Some(ttl_raw) };
    let n = raw.get_u32() as usize;
    let mut groups = Vec::with_capacity(n);
    for _ in 0..n {
        if raw.len() < 4 {
            return None;
        }
        let glen = raw.get_u32() as usize;
        if raw.len() < glen {
            return None;
        }
        let g = std::str::from_utf8(&raw[..glen]).ok()?.to_string();
        raw.advance(glen);
        groups.push(g);
    }
    Some((
        enqueued_at_unix_ms,
        ttl_ms,
        groups,
        Bytes::copy_from_slice(raw),
    ))
}

/// Estimated on-disk footprint for a (key, value) pair, used by the
/// global byte-cap. We deliberately overcount by adding a constant
/// `REDB_PER_RECORD_OVERHEAD` to cover redb's per-entry b-tree and
/// page metadata, which `value.len()` alone does not include. This is
/// the simplification documented at the top of this module: cheaper
/// than calling `Database::stats()` on every put, and biased toward
/// staying *under* the operator's byte budget rather than over it.
fn accounted_size(key_len: usize, value_len: usize) -> u64 {
    (key_len as u64)
        .saturating_add(value_len as u64)
        .saturating_add(REDB_PER_RECORD_OVERHEAD)
}

/// Publish the current accounted total bytes to the
/// `rustgate_federation_replay_buffer_bytes` Prometheus gauge.
///
/// Compiles to a no-op when the `api` feature (which gates the
/// [`crate::metrics`] module) is disabled, so production builds without
/// the management API pay no overhead. Clamps to [`i64::MAX`] on
/// improbable overflow because Prometheus's `IntGauge` is signed — at
/// the default [`DEFAULT_REPLAY_MAX_BYTES`] cap of 64 MiB this clamp is
/// unreachable, but the saturation keeps the type boundary panic-free
/// under any operator-chosen cap.
#[cfg(feature = "api")]
fn publish_total_bytes(total_bytes: u64) {
    let clamped = i64::try_from(total_bytes).unwrap_or(i64::MAX);
    crate::metrics::replay_buffer_bytes().set(clamped);
}

#[cfg(not(feature = "api"))]
fn publish_total_bytes(_total_bytes: u64) {}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use super::*;

    fn put(store: &ReplayStore, peer: &str, seq: u64, ts_ms: u64, payload: &'static [u8]) {
        store
            .put(peer, seq, ts_ms, None, &[], &Bytes::from_static(payload))
            .unwrap();
    }

    #[test]
    fn round_trip_persist_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let store = ReplayStore::open(dir.path(), 1024 * 1024).unwrap();

        store
            .put(
                "peer-a",
                1,
                100,
                Some(60_000),
                &["alpha".into(), "bravo".into()],
                &Bytes::from_static(b"hello"),
            )
            .unwrap();
        store
            .put(
                "peer-a",
                2,
                200,
                None,
                &["alpha".into()],
                &Bytes::from_static(b"world"),
            )
            .unwrap();
        store
            .put("peer-b", 1, 300, None, &[], &Bytes::from_static(b"solo"))
            .unwrap();
        drop(store);

        let store = ReplayStore::open(dir.path(), 1024 * 1024).unwrap();
        let mut all = store.load_all().unwrap();
        all.sort_by(|a, b| (a.peer_id.clone(), a.seq).cmp(&(b.peer_id.clone(), b.seq)));
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].peer_id, "peer-a");
        assert_eq!(all[0].seq, 1);
        assert_eq!(all[0].enqueued_at_unix_ms, 100);
        assert_eq!(all[0].ttl_ms, Some(60_000));
        assert_eq!(
            all[0].groups,
            vec!["alpha".to_string(), "bravo".to_string()]
        );
        assert_eq!(all[0].payload, Bytes::from_static(b"hello"));
        assert_eq!(all[2].peer_id, "peer-b");
        assert_eq!(all[2].payload, Bytes::from_static(b"solo"));
        assert_eq!(all[2].ttl_ms, None);
    }

    #[test]
    fn clear_peer_removes_only_that_peer() {
        let dir = tempfile::tempdir().unwrap();
        let store = ReplayStore::open(dir.path(), 1024 * 1024).unwrap();
        put(&store, "a", 1, 10, b"1");
        put(&store, "a", 2, 20, b"2");
        put(&store, "b", 1, 30, b"3");
        store.clear_peer("a").unwrap();
        let all = store.load_all().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].peer_id, "b");
    }

    #[test]
    fn delete_single_entry() {
        let dir = tempfile::tempdir().unwrap();
        let store = ReplayStore::open(dir.path(), 1024 * 1024).unwrap();
        put(&store, "a", 1, 10, b"1");
        put(&store, "a", 2, 20, b"2");
        store.delete("a", 1).unwrap();
        let all = store.load_all().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].seq, 2);
    }

    #[test]
    fn byte_cap_evicts_oldest_by_enqueue_timestamp() {
        let dir = tempfile::tempdir().unwrap();
        // Each accounted record is roughly: key (~10) + value
        // (16 header + 4 groups_len + 8 payload) + 32 overhead ≈ 70 B.
        // A 200 B cap is enough for ~2-3 records.
        let store = ReplayStore::open(dir.path(), 200).unwrap();
        for i in 0u64..6 {
            store
                .put(
                    "p",
                    i + 1,
                    1_000 + i,
                    None,
                    &[],
                    &Bytes::from(vec![b'x'; 8]),
                )
                .unwrap();
        }
        let all = store.load_all().unwrap();
        assert!(all.len() < 6, "expected eviction to drop oldest entries");
        // Newest entry must still be there.
        assert!(all.iter().any(|e| e.seq == 6));
        assert!(store.total_bytes() <= 200);
    }

    #[test]
    fn byte_cap_evicts_globally_oldest_across_peers() {
        // Two peers: peer A enqueued first, then peer B. Under cap
        // pressure, A's records must be evicted before B's even though
        // B's seq numbers are equal — eviction is by enqueue time, not
        // per-peer insertion order.
        let dir = tempfile::tempdir().unwrap();
        let store = ReplayStore::open(dir.path(), 350).unwrap();
        // Two A records first.
        store
            .put("a", 1, 1_000, None, &[], &Bytes::from(vec![b'x'; 32]))
            .unwrap();
        store
            .put("a", 2, 1_001, None, &[], &Bytes::from(vec![b'x'; 32]))
            .unwrap();
        // Then two B records.
        store
            .put("b", 1, 2_000, None, &[], &Bytes::from(vec![b'x'; 32]))
            .unwrap();
        store
            .put("b", 2, 2_001, None, &[], &Bytes::from(vec![b'x'; 32]))
            .unwrap();
        // One more push triggers eviction; peer A is the oldest.
        store
            .put("b", 3, 3_000, None, &[], &Bytes::from(vec![b'x'; 32]))
            .unwrap();

        let all = store.load_all().unwrap();
        let a_seqs: Vec<u64> = all
            .iter()
            .filter(|e| e.peer_id == "a")
            .map(|e| e.seq)
            .collect();
        let b_seqs: Vec<u64> = all
            .iter()
            .filter(|e| e.peer_id == "b")
            .map(|e| e.seq)
            .collect();
        // At least one A record was evicted before any B record.
        assert!(
            a_seqs.len() < 2,
            "expected peer A's oldest record to be evicted first, got a_seqs={a_seqs:?} b_seqs={b_seqs:?}"
        );
        assert!(b_seqs.contains(&3));
    }

    // The Prometheus-gauge test is only meaningful with the `api`
    // feature (which gates `crate::metrics`). Under the default
    // no-`api` build, `publish_total_bytes` is a compile-time no-op and
    // there is no gauge to read back.
    #[cfg(feature = "api")]
    #[test]
    fn replay_buffer_bytes_gauge_tracks_mutations() {
        use std::sync::Once;
        static METRICS_INIT: Once = Once::new();
        // `crate::metrics::init()` fails on double-register; gate behind
        // a Once so parallel tests sharing the default Prometheus
        // registry do not race.
        METRICS_INIT.call_once(|| {
            let _ = crate::metrics::init();
        });

        let gauge = crate::metrics::replay_buffer_bytes();

        let dir = tempfile::tempdir().unwrap();
        let store = ReplayStore::open(dir.path(), 1024 * 1024).unwrap();
        // Empty open: accounted total is 0, gauge reflects it.
        assert_eq!(
            gauge.get(),
            i64::try_from(store.total_bytes()).unwrap_or(i64::MAX),
        );

        // After a put, the gauge must match the store's own accounting
        // to prove we are reading and publishing the same field.
        put(&store, "peer-a", 1, 100, b"hello");
        assert_eq!(
            gauge.get(),
            i64::try_from(store.total_bytes()).unwrap_or(i64::MAX),
        );
        assert!(gauge.get() > 0, "expected gauge to grow after put");

        put(&store, "peer-a", 2, 200, b"world");
        put(&store, "peer-b", 1, 300, b"solo");
        let after_three_puts = gauge.get();
        assert_eq!(
            after_three_puts,
            i64::try_from(store.total_bytes()).unwrap_or(i64::MAX),
        );

        // Delete: gauge drops to match the new accounted total.
        store.delete("peer-a", 1).unwrap();
        assert!(
            gauge.get() < after_three_puts,
            "expected gauge to shrink after delete: before={after_three_puts}, after={}",
            gauge.get(),
        );
        assert_eq!(
            gauge.get(),
            i64::try_from(store.total_bytes()).unwrap_or(i64::MAX),
        );

        // clear_peer: removes every peer-a record; gauge tracks.
        store.clear_peer("peer-a").unwrap();
        assert_eq!(
            gauge.get(),
            i64::try_from(store.total_bytes()).unwrap_or(i64::MAX),
        );

        // Drop and reopen: rehydrate path must re-seed the gauge from
        // the on-disk footprint, not leave it at the mid-test value.
        drop(store);
        let store = ReplayStore::open(dir.path(), 1024 * 1024).unwrap();
        assert_eq!(
            gauge.get(),
            i64::try_from(store.total_bytes()).unwrap_or(i64::MAX),
        );
    }

    #[test]
    fn rehydrated_store_preserves_global_oldest_ordering() {
        let dir = tempfile::tempdir().unwrap();
        {
            let store = ReplayStore::open(dir.path(), 4096).unwrap();
            // Out-of-order writes to ensure the in-memory deque doesn't
            // accidentally rely on insertion order.
            store
                .put("a", 1, 1_000, None, &[], &Bytes::from_static(b"a1"))
                .unwrap();
            store
                .put("b", 1, 2_000, None, &[], &Bytes::from_static(b"b1"))
                .unwrap();
            store
                .put("a", 2, 3_000, None, &[], &Bytes::from_static(b"a2"))
                .unwrap();
        }
        // Reopen and shrink the cap so eviction happens against the
        // restored deque. The very first record (a/seq=1, ts=1_000)
        // must be evicted before the later ones.
        let store = ReplayStore::open(dir.path(), 130).unwrap();
        store
            .put("b", 2, 4_000, None, &[], &Bytes::from_static(b"b2"))
            .unwrap();
        let all = store.load_all().unwrap();
        let still_there: Vec<(String, u64)> =
            all.iter().map(|e| (e.peer_id.clone(), e.seq)).collect();
        assert!(
            !still_there.contains(&("a".to_string(), 1)),
            "expected globally-oldest entry to be evicted, got {still_there:?}"
        );
    }
}
