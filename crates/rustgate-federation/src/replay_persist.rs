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
//! value = u32 groups_len, [u32 group_len, group_bytes]*, payload bytes
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
use redb::{Database, ReadableTable, TableDefinition};
use thiserror::Error;
use tracing::{debug, warn};

/// redb table backing persisted replay-buffer entries. The key is the
/// composite (peer_id, seq) blob described in the module docs.
const REPLAY_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("federation_replay_v1");

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
    /// Source groups for routing.
    pub groups: Vec<String>,
    /// Raw message payload.
    pub payload: Bytes,
}

#[derive(Debug)]
struct Entry {
    peer_id: String,
    seq: u64,
    bytes: u64,
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
                let bytes = v.value().len() as u64;
                let (peer_id, seq) = match decode_key(key) {
                    Some(p) => p,
                    None => {
                        debug!("skipping malformed replay-store key on rebuild");
                        continue;
                    }
                };
                inner.total_bytes = inner.total_bytes.saturating_add(bytes);
                inner.global.push_back(Entry {
                    peer_id,
                    seq,
                    bytes,
                });
            }
        }

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
        groups: &[String],
        payload: &Bytes,
    ) -> Result<(), ReplayStoreError> {
        let value = encode_value(groups, payload);
        let value_len = value.len() as u64;
        let key = encode_key(peer_id, seq);

        // Evict from the front until we have room. Done before the
        // write so the database commit reflects the post-eviction state.
        let to_delete: Vec<(String, u64)> = {
            let mut inner = self.inner.lock();
            let mut victims = Vec::new();
            while inner.total_bytes.saturating_add(value_len) > self.max_bytes
                && let Some(front) = inner.global.pop_front()
            {
                inner.total_bytes = inner.total_bytes.saturating_sub(front.bytes);
                victims.push((front.peer_id, front.seq));
            }
            inner.global.push_back(Entry {
                peer_id: peer_id.to_string(),
                seq,
                bytes: value_len,
            });
            inner.total_bytes = inner.total_bytes.saturating_add(value_len);
            victims
        };

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
        {
            let mut inner = self.inner.lock();
            if let Some(pos) = inner
                .global
                .iter()
                .position(|e| e.seq == seq && e.peer_id == peer_id)
                && let Some(entry) = inner.global.remove(pos)
            {
                inner.total_bytes = inner.total_bytes.saturating_sub(entry.bytes);
            }
        }
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
        let victims: Vec<u64> = {
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
            seqs
        };
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
            let Some((groups, payload)) = decode_value(v.value()) else {
                debug!("skipping malformed replay-store value on load");
                continue;
            };
            out.push(RestoredEntry {
                peer_id,
                seq,
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

fn encode_value(groups: &[String], payload: &Bytes) -> Vec<u8> {
    let mut buf = BytesMut::new();
    buf.put_u32(groups.len() as u32);
    for g in groups {
        buf.put_u32(g.len() as u32);
        buf.put_slice(g.as_bytes());
    }
    buf.put_slice(payload);
    buf.to_vec()
}

fn decode_value(mut raw: &[u8]) -> Option<(Vec<String>, Bytes)> {
    if raw.len() < 4 {
        return None;
    }
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
    Some((groups, Bytes::copy_from_slice(raw)))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn round_trip_persist_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let store = ReplayStore::open(dir.path(), 1024 * 1024).unwrap();

        store
            .put(
                "peer-a",
                1,
                &["alpha".into(), "bravo".into()],
                &Bytes::from_static(b"hello"),
            )
            .unwrap();
        store
            .put(
                "peer-a",
                2,
                &["alpha".into()],
                &Bytes::from_static(b"world"),
            )
            .unwrap();
        store
            .put("peer-b", 1, &[], &Bytes::from_static(b"solo"))
            .unwrap();
        drop(store);

        let store = ReplayStore::open(dir.path(), 1024 * 1024).unwrap();
        let mut all = store.load_all().unwrap();
        all.sort_by(|a, b| (a.peer_id.clone(), a.seq).cmp(&(b.peer_id.clone(), b.seq)));
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].peer_id, "peer-a");
        assert_eq!(all[0].seq, 1);
        assert_eq!(
            all[0].groups,
            vec!["alpha".to_string(), "bravo".to_string()]
        );
        assert_eq!(all[0].payload, Bytes::from_static(b"hello"));
        assert_eq!(all[2].peer_id, "peer-b");
        assert_eq!(all[2].payload, Bytes::from_static(b"solo"));
    }

    #[test]
    fn clear_peer_removes_only_that_peer() {
        let dir = tempfile::tempdir().unwrap();
        let store = ReplayStore::open(dir.path(), 1024 * 1024).unwrap();
        store.put("a", 1, &[], &Bytes::from_static(b"1")).unwrap();
        store.put("a", 2, &[], &Bytes::from_static(b"2")).unwrap();
        store.put("b", 1, &[], &Bytes::from_static(b"3")).unwrap();
        store.clear_peer("a").unwrap();
        let all = store.load_all().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].peer_id, "b");
    }

    #[test]
    fn delete_single_entry() {
        let dir = tempfile::tempdir().unwrap();
        let store = ReplayStore::open(dir.path(), 1024 * 1024).unwrap();
        store.put("a", 1, &[], &Bytes::from_static(b"1")).unwrap();
        store.put("a", 2, &[], &Bytes::from_static(b"2")).unwrap();
        store.delete("a", 1).unwrap();
        let all = store.load_all().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].seq, 2);
    }

    #[test]
    fn byte_cap_evicts_oldest() {
        let dir = tempfile::tempdir().unwrap();
        // Each value encodes to 4 (groups_len) + payload bytes; cap of
        // 32 bytes is enough for ~3 small messages.
        let store = ReplayStore::open(dir.path(), 32).unwrap();
        for i in 0u64..6 {
            store
                .put("p", i + 1, &[], &Bytes::from(vec![b'x'; 8]))
                .unwrap();
        }
        let all = store.load_all().unwrap();
        assert!(all.len() < 6, "expected eviction to drop oldest entries");
        // Newest entry must still be there.
        assert!(all.iter().any(|e| e.seq == 6));
        assert!(store.total_bytes() <= 32);
    }
}
