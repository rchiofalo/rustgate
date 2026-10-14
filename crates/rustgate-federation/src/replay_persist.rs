// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Disk persistence for the per-peer federation replay buffer.
//!
//! The in-memory [`crate::replay_buffer::ReplayBuffer`] is bounded and
//! lost on restart. Operationally, server restart often coincides with a
//! peer reconnect — exactly the moment we want to replay buffered
//! messages. This module persists each buffered message to a redb table
//! so the replay buffers can be restored on startup.
//!
//! The on-disk format is intentionally minimal. There are two value
//! layouts kept in the same redb table for backward compatibility:
//!
//! ```text
//! key       = peer_id (str) + b"\x00" + seq (u64 big-endian)
//! value v1  = u64 enqueued_at_unix_ms,
//!             u64 ttl_ms (0 = no TTL),
//!             u32 groups_len, [u32 group_len, group_bytes]*,
//!             payload bytes
//! value v2  = b"\xFF\xFE" magic,
//!             u8  version (currently 1),
//!             u32 current_hops (post-increment — what we will emit),
//!             u64 enqueued_at_unix_ms,
//!             u64 ttl_ms (0 = no TTL),
//!             u32 groups_len, [u32 group_len, group_bytes]*,
//!             payload bytes
//! ```
//!
//! The v2 layout was introduced to fix #763 (store-forward persisted
//! the pre-hop-increment envelope, so the drain hot-path re-evaluated
//! hops against a stale value). The two-byte magic prefix `0xFF 0xFE`
//! cannot collide with a legitimate v1 record because v1 starts with a
//! `u64::to_be_bytes` of a Unix-millisecond timestamp — real values
//! near year-2024 are well under `0x00_00_FF_FF_FF_FF_FF_FF`, so the
//! first two bytes of any plausible v1 record are `0x00 0x00`. On read,
//! a v1 record (no version field) is treated as **legacy /
//! pre-increment**: the drain hot-path applies `+1` lazily to bring it
//! into agreement with what a fresh post-increment write would produce.
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
    /// Federation hop counter at the point of persistence. For records
    /// written by v2 of the value codec this is the post-increment
    /// value — what would have been emitted live. For legacy v1
    /// records (see [`is_legacy_pre_increment`](Self::is_legacy_pre_increment))
    /// this is `0` and the drain hot-path is responsible for applying
    /// the `+1` lazily before the limit check, because v1 stored the
    /// pre-increment envelope (closes #763).
    pub current_hops: u32,
    /// `true` when the entry was decoded from a v1 (legacy) value
    /// layout, which predates persisted hop accounting. The drain
    /// hot-path treats `current_hops` as pre-increment in this case
    /// and applies `+1` before the hop-limit check, mirroring what a
    /// post-#763 live emit would have done.
    pub is_legacy_pre_increment: bool,
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
    // justification: kept for `Debug` derivation and forthcoming restart
    // diagnostics (issue #656 — replay-store maintenance CLI). The handle is
    // cloned into every federation peer task, so adding the field now avoids
    // a format-shift later when the diagnostic hook lands.
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
                let Some(decoded) = decode_value(value) else {
                    debug!("skipping malformed replay-store value on rebuild");
                    continue;
                };
                let enqueued_at_unix_ms = decoded.enqueued_at_unix_ms;
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
    ///
    /// `current_hops` is the **post-increment** federation hop counter
    /// — i.e. what the message would carry if it were emitted live
    /// instead of buffered. Persisting the post-increment value (not
    /// the pre-increment input) is the fix for #763: it lets the drain
    /// hot-path evaluate the same hop-limit check that a live emit
    /// would, with no extra bookkeeping.
    // justification: the persistence call site in
    // `replay_buffer::push_with_hops` already destructures
    // `BufferedMessage` into the same fields, and the test harnesses
    // call `put` positionally for readability. Bundling these into a
    // struct would push the same fan-in upstream without reducing live
    // references at the call site — it only renames the arguments.
    #[allow(clippy::too_many_arguments)]
    pub fn put(
        &self,
        peer_id: &str,
        seq: u64,
        enqueued_at_unix_ms: u64,
        ttl_ms: Option<u64>,
        current_hops: u32,
        groups: &[String],
        payload: &Bytes,
    ) -> Result<(), ReplayStoreError> {
        let value = encode_value(enqueued_at_unix_ms, ttl_ms, current_hops, groups, payload);
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
            let Some(decoded) = decode_value(v.value()) else {
                debug!("skipping malformed replay-store value on load");
                continue;
            };
            out.push(RestoredEntry {
                peer_id,
                seq,
                enqueued_at_unix_ms: decoded.enqueued_at_unix_ms,
                ttl_ms: decoded.ttl_ms,
                groups: decoded.groups,
                payload: decoded.payload,
                current_hops: decoded.current_hops,
                is_legacy_pre_increment: decoded.is_legacy_pre_increment,
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

/// Two-byte magic prefix that distinguishes a v2 (post-#763) value
/// layout from a legacy v1 value. Cannot collide with v1 because v1
/// records start with a Unix-millisecond timestamp encoded as
/// `u64::to_be_bytes`, whose high two bytes are always `0x00 0x00` for
/// any plausible wall-clock value.
const VALUE_MAGIC_V2: [u8; 2] = [0xFF, 0xFE];

/// Current value codec version. Bumped only on a wire-shape change;
/// readers branch on this byte before parsing anything else.
const VALUE_VERSION_V2: u8 = 1;

/// Decoded value payload. Carries the fields written by either codec
/// version plus a `is_legacy_pre_increment` flag the drain path uses
/// to apply the lazy `+1` for v1 records (see module docs / #763).
struct DecodedValue {
    enqueued_at_unix_ms: u64,
    ttl_ms: Option<u64>,
    current_hops: u32,
    is_legacy_pre_increment: bool,
    groups: Vec<String>,
    payload: Bytes,
}

fn encode_value(
    enqueued_at_unix_ms: u64,
    ttl_ms: Option<u64>,
    current_hops: u32,
    groups: &[String],
    payload: &Bytes,
) -> Vec<u8> {
    let mut buf = BytesMut::new();
    // v2 layout — magic + version + post-increment hops up front so a
    // legacy reader (or a corrupted byte) never accidentally accepts a
    // v2 record as v1 and vice versa.
    buf.put_slice(&VALUE_MAGIC_V2);
    buf.put_u8(VALUE_VERSION_V2);
    buf.put_u32(current_hops);
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

fn decode_value(raw: &[u8]) -> Option<DecodedValue> {
    // Branch on the v2 magic prefix. Anything that doesn't match is a
    // legacy v1 record — the on-disk format predates persisted hop
    // accounting, so the drain hot-path applies +1 lazily.
    if raw.len() >= 2 && raw[..2] == VALUE_MAGIC_V2 {
        decode_value_v2(&raw[2..])
    } else {
        decode_value_v1(raw)
    }
}

fn decode_value_v1(mut raw: &[u8]) -> Option<DecodedValue> {
    if raw.len() < 8 + 8 + 4 {
        return None;
    }
    let enqueued_at_unix_ms = raw.get_u64();
    let ttl_raw = raw.get_u64();
    let ttl_ms = if ttl_raw == 0 { None } else { Some(ttl_raw) };
    let (groups, payload) = decode_groups_and_payload(&mut raw)?;
    Some(DecodedValue {
        enqueued_at_unix_ms,
        ttl_ms,
        // v1 records have no persisted hop counter. Surface 0 plus the
        // legacy flag so the drain hot-path applies +1 before the
        // hop-limit check, matching what a post-#763 live emit would
        // have done at the boundary.
        current_hops: 0,
        is_legacy_pre_increment: true,
        groups,
        payload,
    })
}

fn decode_value_v2(mut raw: &[u8]) -> Option<DecodedValue> {
    // Header after the magic: 1 (version) + 4 (hops) + 8 (ts) + 8 (ttl) + 4 (groups_len) = 25 bytes.
    if raw.len() < 1 + 4 + 8 + 8 + 4 {
        return None;
    }
    let version = raw.get_u8();
    if version != VALUE_VERSION_V2 {
        // Future versions land here. Refuse rather than parse unknown
        // bytes — the rebuild path treats `None` as "drop the entry"
        // and continues with the rest of the table.
        return None;
    }
    let current_hops = raw.get_u32();
    let enqueued_at_unix_ms = raw.get_u64();
    let ttl_raw = raw.get_u64();
    let ttl_ms = if ttl_raw == 0 { None } else { Some(ttl_raw) };
    let (groups, payload) = decode_groups_and_payload(&mut raw)?;
    Some(DecodedValue {
        enqueued_at_unix_ms,
        ttl_ms,
        current_hops,
        is_legacy_pre_increment: false,
        groups,
        payload,
    })
}

fn decode_groups_and_payload(raw: &mut &[u8]) -> Option<(Vec<String>, Bytes)> {
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
            .put(peer, seq, ts_ms, None, 1, &[], &Bytes::from_static(payload))
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
                1,
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
                1,
                &["alpha".into()],
                &Bytes::from_static(b"world"),
            )
            .unwrap();
        store
            .put("peer-b", 1, 300, None, 1, &[], &Bytes::from_static(b"solo"))
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
                    1,
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
            .put("a", 1, 1_000, None, 1, &[], &Bytes::from(vec![b'x'; 32]))
            .unwrap();
        store
            .put("a", 2, 1_001, None, 1, &[], &Bytes::from(vec![b'x'; 32]))
            .unwrap();
        // Then two B records.
        store
            .put("b", 1, 2_000, None, 1, &[], &Bytes::from(vec![b'x'; 32]))
            .unwrap();
        store
            .put("b", 2, 2_001, None, 1, &[], &Bytes::from(vec![b'x'; 32]))
            .unwrap();
        // One more push triggers eviction; peer A is the oldest.
        store
            .put("b", 3, 3_000, None, 1, &[], &Bytes::from(vec![b'x'; 32]))
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
                .put("a", 1, 1_000, None, 1, &[], &Bytes::from_static(b"a1"))
                .unwrap();
            store
                .put("b", 1, 2_000, None, 1, &[], &Bytes::from_static(b"b1"))
                .unwrap();
            store
                .put("a", 2, 3_000, None, 1, &[], &Bytes::from_static(b"a2"))
                .unwrap();
        }
        // Reopen and shrink the cap so eviction happens against the
        // restored deque. The very first record (a/seq=1, ts=1_000)
        // must be evicted before the later ones.
        let store = ReplayStore::open(dir.path(), 130).unwrap();
        store
            .put("b", 2, 4_000, None, 1, &[], &Bytes::from_static(b"b2"))
            .unwrap();
        let all = store.load_all().unwrap();
        let still_there: Vec<(String, u64)> =
            all.iter().map(|e| (e.peer_id.clone(), e.seq)).collect();
        assert!(
            !still_there.contains(&("a".to_string(), 1)),
            "expected globally-oldest entry to be evicted, got {still_there:?}"
        );
    }

    // -----------------------------------------------------------------
    // Defensive-invariant coverage (Refs #909).
    //
    // The tests above exercise happy-path and a couple of eviction
    // cases. The block below locks down the wire-format contract, the
    // schema-version pin, the byte-cap accounting invariants, the
    // `Clone`/`Debug` surface, and the silent-skip behavior of the
    // decoders so regressions surface here instead of at runtime on a
    // rehydrate.
    // -----------------------------------------------------------------

    /// The module-level byte-cap default is a wire/operator-visible
    /// constant — dashboards and docs reference it. Pin the value so a
    /// "just bump the default" change has to pass through this test.
    #[test]
    fn default_replay_max_bytes_is_sixty_four_mib() {
        assert_eq!(DEFAULT_REPLAY_MAX_BYTES, 64 * 1024 * 1024);
    }

    /// Pin the per-record overhead constant that drives accounted
    /// size. Bumping this changes the effective cap for operators who
    /// have tuned `--federation-replay-max-bytes` against the current
    /// overhead — it is a compatibility knob, not an implementation
    /// detail.
    #[test]
    fn redb_per_record_overhead_constant_is_pinned_to_32() {
        assert_eq!(REDB_PER_RECORD_OVERHEAD, 32);
    }

    /// Bumping the redb table name drops legacy entries on first open
    /// of the new binary (per the module doc comment). Pin the current
    /// name so that migration is an intentional act with a deliberate
    /// rename, not an accidental typo that silently resets every
    /// operator's replay buffer on upgrade.
    #[test]
    fn replay_table_name_is_v2() {
        use redb::TableHandle;
        assert_eq!(REPLAY_TABLE.name(), "federation_replay_v2");
    }

    #[test]
    fn encode_decode_key_round_trip_typical() {
        let key = encode_key("peer-zulu", 0xDEAD_BEEF_CAFE_BABE);
        let (peer, seq) = decode_key(&key).expect("valid key must decode");
        assert_eq!(peer, "peer-zulu");
        assert_eq!(seq, 0xDEAD_BEEF_CAFE_BABE);
    }

    #[test]
    fn encode_decode_key_round_trip_empty_peer() {
        // Empty peer names are not expected operationally, but the
        // codec must survive them — a nine-byte key with a leading 0x00
        // separator and 8-byte seq is still valid per the layout.
        let key = encode_key("", 7);
        assert_eq!(key.len(), 9, "empty peer → 0 bytes peer + 1 sep + 8 seq");
        let (peer, seq) = decode_key(&key).expect("empty-peer key must decode");
        assert_eq!(peer, "");
        assert_eq!(seq, 7);
    }

    #[test]
    fn encode_decode_key_preserves_internal_nul_in_peer_id() {
        // `decode_key` splits at `len - 9`; the separator is the byte
        // immediately before the 8 seq bytes. Internal 0x00 bytes in
        // the peer must survive a round-trip — the split is length-
        // based, not a `split_once(0x00)`.
        let key = encode_key("a\x00b", 42);
        let (peer, seq) = decode_key(&key).expect("peer with internal NUL must decode");
        assert_eq!(peer.as_bytes(), b"a\x00b");
        assert_eq!(seq, 42);
    }

    #[test]
    fn encode_decode_key_round_trip_u64_max_seq() {
        let key = encode_key("edge", u64::MAX);
        let (peer, seq) = decode_key(&key).expect("u64::MAX seq must decode");
        assert_eq!(peer, "edge");
        assert_eq!(seq, u64::MAX);
    }

    #[test]
    fn decode_key_rejects_input_shorter_than_nine_bytes() {
        // The layout guarantees 1 separator + 8 seq bytes at the tail,
        // so anything below 9 bytes is structurally impossible.
        for n in 0..9usize {
            let raw = vec![0u8; n];
            assert!(
                decode_key(&raw).is_none(),
                "expected None for {n}-byte raw key"
            );
        }
    }

    #[test]
    fn decode_key_rejects_wrong_separator_byte() {
        // The byte at (len - 9) must be 0x00. Any other value is a
        // malformed key — either a corrupted record or a key from an
        // incompatible format — and the decoder must refuse it rather
        // than parsing garbage into a peer_id.
        let mut raw = encode_key("peer", 1);
        let split = raw.len() - 9;
        raw[split] = 0x01;
        assert!(decode_key(&raw).is_none());
    }

    #[test]
    fn decode_key_rejects_invalid_utf8_in_peer_segment() {
        // Peer IDs must be valid UTF-8. A stray 0xFF before the
        // separator is not — the decoder must drop the entry rather
        // than produce a lossy peer string.
        let mut raw = vec![0xFFu8];
        raw.push(0); // separator
        raw.extend_from_slice(&42u64.to_be_bytes()); // seq
        assert!(decode_key(&raw).is_none());
    }

    #[test]
    fn encode_decode_value_round_trip_typical() {
        let groups = vec!["alpha".to_string(), "bravo".to_string()];
        let payload = Bytes::from_static(b"hello");
        let raw = encode_value(100, Some(60_000), 2, &groups, &payload);
        let decoded = decode_value(&raw).expect("round-trip must decode");
        assert_eq!(decoded.enqueued_at_unix_ms, 100);
        assert_eq!(decoded.ttl_ms, Some(60_000));
        assert_eq!(decoded.current_hops, 2);
        assert!(!decoded.is_legacy_pre_increment);
        assert_eq!(decoded.groups, groups);
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn encode_decode_value_round_trip_empty_groups_and_payload() {
        let raw = encode_value(0, None, 0, &[], &Bytes::new());
        let decoded = decode_value(&raw).expect("minimal value must decode");
        assert_eq!(decoded.enqueued_at_unix_ms, 0);
        assert_eq!(decoded.ttl_ms, None);
        assert_eq!(decoded.current_hops, 0);
        assert!(!decoded.is_legacy_pre_increment);
        assert!(decoded.groups.is_empty());
        assert!(decoded.payload.is_empty());
    }

    /// The encoder represents a missing TTL as `0`, and the decoder
    /// treats any zero as `None`. Callers that try to persist a
    /// `Some(0)` TTL will see it round-trip as `None` — the module
    /// documents this at `encode_value` ("live messages are never
    /// enqueued with a 0 ms TTL"). Pin the contract so a future "fix"
    /// that replaces the sentinel with a tagged representation doesn't
    /// silently change on-disk format for existing deployments.
    #[test]
    fn ttl_some_zero_round_trips_as_none_by_sentinel_convention() {
        let raw = encode_value(1, Some(0), 1, &[], &Bytes::from_static(b"x"));
        let decoded = decode_value(&raw).expect("value must decode");
        assert_eq!(
            decoded.ttl_ms, None,
            "Some(0) must decode as None by sentinel convention"
        );
    }

    #[test]
    fn decode_value_rejects_header_shorter_than_required() {
        // Smallest valid v2 header (after magic): 1 (ver) + 4 (hops) + 8 (ts) + 8 (ttl) + 4 (groups_len) = 25 bytes.
        for n in 0..25usize {
            let mut raw = vec![0xFFu8, 0xFE]; // valid v2 magic
            raw.extend_from_slice(&vec![0u8; n]);
            assert!(
                decode_value(&raw).is_none(),
                "expected None for {n}-byte v2 body",
            );
        }
        // Legacy (no magic) — header is 8 + 8 + 4 = 20 bytes.
        for n in 0..20usize {
            let raw = vec![0u8; n];
            assert!(
                decode_value(&raw).is_none(),
                "expected None for {n}-byte legacy header",
            );
        }
    }

    #[test]
    fn decode_value_rejects_group_length_exceeding_remaining_bytes() {
        // Craft a v2 value that claims 1 group of 100 bytes but supplies
        // only 2. The decoder must refuse rather than read past the
        // buffer or return a partial group.
        let mut raw = BytesMut::new();
        raw.put_slice(&VALUE_MAGIC_V2);
        raw.put_u8(VALUE_VERSION_V2);
        raw.put_u32(0); // hops
        raw.put_u64(0); // ts
        raw.put_u64(0); // ttl
        raw.put_u32(1); // groups_len = 1
        raw.put_u32(100); // glen = 100 … but …
        raw.put_slice(b"ab"); // … only 2 bytes follow.
        assert!(decode_value(&raw).is_none());
    }

    #[test]
    fn decode_value_rejects_missing_group_length_field() {
        // 25-byte v2 header says 1 group follows, but no group-length u32
        // is present at all.
        let mut raw = BytesMut::new();
        raw.put_slice(&VALUE_MAGIC_V2);
        raw.put_u8(VALUE_VERSION_V2);
        raw.put_u32(0);
        raw.put_u64(0);
        raw.put_u64(0);
        raw.put_u32(1);
        assert!(decode_value(&raw).is_none());
    }

    #[test]
    fn decode_value_rejects_invalid_utf8_group_name() {
        let mut raw = BytesMut::new();
        raw.put_slice(&VALUE_MAGIC_V2);
        raw.put_u8(VALUE_VERSION_V2);
        raw.put_u32(0);
        raw.put_u64(0);
        raw.put_u64(0);
        raw.put_u32(1);
        raw.put_u32(1);
        raw.put_u8(0xFF); // not a valid UTF-8 scalar
        assert!(decode_value(&raw).is_none());
    }

    #[test]
    fn encode_decode_value_many_groups_round_trip() {
        let groups: Vec<String> = (0..32).map(|i| format!("g-{i}")).collect();
        let raw = encode_value(999, Some(1), 5, &groups, &Bytes::from_static(b"body"));
        let decoded = decode_value(&raw).expect("must decode");
        assert_eq!(decoded.current_hops, 5);
        assert_eq!(decoded.groups, groups);
        assert_eq!(decoded.payload, Bytes::from_static(b"body"));
    }

    /// Pin the v2 magic prefix bytes — wire-format invariant. The two
    /// bytes are picked so they cannot collide with a v1 record (whose
    /// first 8 bytes are a Unix-millisecond timestamp encoded big-endian,
    /// always starting `0x00 0x00` for any plausible wall-clock value).
    /// Bumping these without bumping `VALUE_VERSION_V2` would silently
    /// invalidate every existing on-disk record on operator upgrade.
    #[test]
    fn value_magic_v2_is_pinned_to_ff_fe() {
        assert_eq!(VALUE_MAGIC_V2, [0xFF, 0xFE]);
        assert_eq!(VALUE_VERSION_V2, 1);
    }

    /// A v2-encoded record must be flagged as post-increment and
    /// preserve `current_hops` exactly across a round-trip — the
    /// drain hot-path relies on this to evaluate the same hop-limit
    /// check that a live emit would.
    #[test]
    fn v2_round_trip_preserves_hop_count() {
        for hops in [0u32, 1, 5, 9, u32::MAX] {
            let raw = encode_value(123, None, hops, &[], &Bytes::from_static(b"p"));
            let decoded = decode_value(&raw).expect("must decode");
            assert_eq!(decoded.current_hops, hops);
            assert!(!decoded.is_legacy_pre_increment);
        }
    }

    /// Records written by the v1 codec (no magic prefix) decode as
    /// `is_legacy_pre_increment = true`, with `current_hops = 0`. The
    /// drain hot-path applies `+1` lazily so legacy entries match the
    /// post-#763 invariant. Hand-build the legacy bytes here rather
    /// than calling a removed encoder so the regression test cannot
    /// drift if someone later renames or reshuffles fields.
    #[test]
    fn legacy_v1_record_decodes_as_pre_increment() {
        let mut raw = BytesMut::new();
        raw.put_u64(42); // ts
        raw.put_u64(0); // ttl (None)
        raw.put_u32(1); // groups_len
        raw.put_u32(3);
        raw.put_slice(b"abc");
        raw.put_slice(b"hello");
        let decoded = decode_value(&raw).expect("legacy must decode");
        assert!(decoded.is_legacy_pre_increment);
        assert_eq!(decoded.current_hops, 0);
        assert_eq!(decoded.enqueued_at_unix_ms, 42);
        assert_eq!(decoded.groups, vec!["abc".to_string()]);
        assert_eq!(decoded.payload, Bytes::from_static(b"hello"));
    }

    /// Future codec versions return `None` on read so the rebuild path
    /// drops the entry rather than silently mis-parsing unknown bytes.
    #[test]
    fn decode_rejects_unknown_v2_version_byte() {
        let mut raw = BytesMut::new();
        raw.put_slice(&VALUE_MAGIC_V2);
        raw.put_u8(VALUE_VERSION_V2.saturating_add(1));
        raw.put_u32(0);
        raw.put_u64(0);
        raw.put_u64(0);
        raw.put_u32(0);
        assert!(decode_value(&raw).is_none());
    }

    #[test]
    fn accounted_size_sums_lengths_with_overhead() {
        assert_eq!(accounted_size(0, 0), REDB_PER_RECORD_OVERHEAD);
        assert_eq!(accounted_size(10, 20), 10 + 20 + REDB_PER_RECORD_OVERHEAD);
    }

    /// Paranoia: the accounted-size helper feeds a `u64` cap check that
    /// must never panic. Saturation is the contract: a catastrophic
    /// input (len = `usize::MAX`) returns `u64::MAX` rather than
    /// wrapping to 31. Overcounting is fine; wrapping is a silent
    /// cap-bypass that the operator has no way to observe.
    #[test]
    fn accounted_size_saturates_instead_of_wrapping() {
        assert_eq!(accounted_size(usize::MAX, usize::MAX), u64::MAX);
    }

    #[test]
    fn open_creates_directory_if_missing() {
        // The API guarantees `open` will create any missing parents —
        // exercised here by pointing at a deeply nested path.
        let root = tempfile::tempdir().unwrap();
        let nested = root.path().join("a").join("b").join("c");
        assert!(!nested.exists());
        let store = ReplayStore::open(&nested, 4096).expect("nested dir must be created");
        assert!(nested.is_dir());
        assert!(store.is_empty());
    }

    #[test]
    fn fresh_store_reports_empty_state() {
        let dir = tempfile::tempdir().unwrap();
        let store = ReplayStore::open(dir.path(), 4096).unwrap();
        assert_eq!(store.len(), 0);
        assert!(store.is_empty());
        assert_eq!(store.total_bytes(), 0);
        assert!(store.load_all().unwrap().is_empty());
    }

    #[test]
    fn put_increments_len_and_total_bytes_consistently() {
        let dir = tempfile::tempdir().unwrap();
        let store = ReplayStore::open(dir.path(), 1 << 20).unwrap();
        assert_eq!(store.len(), 0);
        put(&store, "peer-a", 1, 100, b"hello");
        assert_eq!(store.len(), 1);
        assert!(!store.is_empty());
        let after_one = store.total_bytes();
        assert!(after_one >= REDB_PER_RECORD_OVERHEAD);
        put(&store, "peer-a", 2, 200, b"world-2");
        assert_eq!(store.len(), 2);
        assert!(
            store.total_bytes() > after_one,
            "total_bytes must grow on a second put"
        );
    }

    #[test]
    fn delete_nonexistent_key_is_a_noop_not_an_error() {
        // redb's `remove` on a missing key is not an error, and the
        // in-memory accounting must likewise tolerate the no-op — any
        // drain or eviction path can race a delete on a key that the
        // in-memory ring already dropped.
        let dir = tempfile::tempdir().unwrap();
        let store = ReplayStore::open(dir.path(), 4096).unwrap();
        put(&store, "peer", 1, 10, b"only");
        let before = store.total_bytes();
        store.delete("peer", 9_999).expect("delete must return Ok");
        assert_eq!(store.len(), 1);
        assert_eq!(store.total_bytes(), before);
    }

    #[test]
    fn clear_peer_with_no_entries_is_a_noop() {
        let dir = tempfile::tempdir().unwrap();
        let store = ReplayStore::open(dir.path(), 4096).unwrap();
        put(&store, "peer-b", 1, 10, b"b");
        let before_total = store.total_bytes();
        store
            .clear_peer("peer-a")
            .expect("clear_peer must be idempotent");
        assert_eq!(store.len(), 1);
        assert_eq!(store.total_bytes(), before_total);
        // peer-b must still be intact.
        let all = store.load_all().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].peer_id, "peer-b");
    }

    #[test]
    fn delete_every_entry_returns_store_to_empty() {
        let dir = tempfile::tempdir().unwrap();
        let store = ReplayStore::open(dir.path(), 4096).unwrap();
        put(&store, "p", 1, 10, b"1");
        put(&store, "p", 2, 20, b"2");
        store.delete("p", 1).unwrap();
        store.delete("p", 2).unwrap();
        assert_eq!(store.len(), 0);
        assert!(store.is_empty());
        assert_eq!(store.total_bytes(), 0);
        assert!(store.load_all().unwrap().is_empty());
    }

    #[test]
    fn clone_shares_inner_state_with_original() {
        // `ReplayStore: Clone` is documented as cheap — it wraps the
        // inner `Arc`. A put via the clone must be visible via the
        // original, and vice-versa, or the shared-state contract is
        // broken and callers who pass clones to peer tasks will see a
        // divergent view of the buffer.
        let dir = tempfile::tempdir().unwrap();
        let original = ReplayStore::open(dir.path(), 4096).unwrap();
        let cloned = original.clone();
        put(&cloned, "shared", 1, 1, b"via-clone");
        assert_eq!(original.len(), 1);
        assert_eq!(original.total_bytes(), cloned.total_bytes());
        original.delete("shared", 1).unwrap();
        assert!(cloned.is_empty());
    }

    #[test]
    fn load_all_returns_entries_sorted_by_peer_then_seq() {
        let dir = tempfile::tempdir().unwrap();
        let store = ReplayStore::open(dir.path(), 4096).unwrap();
        // Insert in jumbled order.
        put(&store, "c", 5, 100, b"c5");
        put(&store, "a", 2, 200, b"a2");
        put(&store, "a", 1, 300, b"a1");
        put(&store, "b", 1, 400, b"b1");
        let all = store.load_all().unwrap();
        let keys: Vec<(String, u64)> = all.iter().map(|e| (e.peer_id.clone(), e.seq)).collect();
        assert_eq!(
            keys,
            vec![
                ("a".to_string(), 1),
                ("a".to_string(), 2),
                ("b".to_string(), 1),
                ("c".to_string(), 5),
            ],
            "load_all must sort primarily by peer_id, secondarily by seq"
        );
    }

    #[test]
    fn put_preserves_empty_payload_across_reload() {
        // Zero-byte payloads are valid per the codec and must survive a
        // persist + reload round-trip unchanged.
        let dir = tempfile::tempdir().unwrap();
        {
            let store = ReplayStore::open(dir.path(), 4096).unwrap();
            store
                .put("p", 1, 10, None, 1, &["g".into()], &Bytes::new())
                .unwrap();
        }
        let store = ReplayStore::open(dir.path(), 4096).unwrap();
        let all = store.load_all().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].payload.len(), 0);
        assert_eq!(all[0].groups, vec!["g".to_string()]);
    }

    #[test]
    fn replay_store_error_is_debug_and_display_and_error() {
        // Pin the public surface: `ReplayStoreError` must be usable as
        // an `anyhow::Error` source and must produce a helpful
        // `Display` form for operators tailing structured logs.
        let err = ReplayStoreError::Database("synthetic".to_string());
        let disp = format!("{err}");
        assert!(disp.contains("synthetic"), "Display must propagate inner");
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Database"), "Debug must name the variant");
        let _as_error: &dyn std::error::Error = &err;

        let decode = ReplayStoreError::Decode;
        let disp2 = format!("{decode}");
        assert!(disp2.contains("malformed"), "Decode variant has a message");
    }

    #[test]
    fn restored_entry_is_clone_and_debug() {
        let e = RestoredEntry {
            peer_id: "p".to_string(),
            seq: 1,
            enqueued_at_unix_ms: 10,
            ttl_ms: Some(42),
            groups: vec!["g".to_string()],
            payload: Bytes::from_static(b"x"),
            current_hops: 1,
            is_legacy_pre_increment: false,
        };
        let cloned = e.clone();
        assert_eq!(cloned.peer_id, e.peer_id);
        assert_eq!(cloned.payload, e.payload);
        let dbg = format!("{e:?}");
        assert!(dbg.contains("RestoredEntry"));
    }

    #[test]
    fn replay_store_is_debug() {
        // The `Debug` impl is required for `#[derive(Debug)]` on
        // downstream peer structs that embed a `ReplayStore` handle.
        let dir = tempfile::tempdir().unwrap();
        let store = ReplayStore::open(dir.path(), 4096).unwrap();
        let dbg = format!("{store:?}");
        assert!(dbg.contains("ReplayStore"));
    }

    #[test]
    fn rehydrate_skips_malformed_keys_written_directly_to_redb() {
        // Bypass `ReplayStore::put` and write a too-short key via raw
        // redb. `ReplayStore::open` must log-and-skip that entry on
        // rebuild rather than propagate an error — silent degradation
        // is the module's documented contract for malformed records.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("federation_replay.redb");
        {
            let db = redb::Database::create(&path).unwrap();
            let write = db.begin_write().unwrap();
            {
                let mut table = write.open_table(REPLAY_TABLE).unwrap();
                // 4 bytes < 9 bytes → decode_key returns None.
                let _ = table.insert(&[1u8, 2, 3, 4][..], &[0u8; 24][..]).unwrap();
            }
            write.commit().unwrap();
        }
        let store = ReplayStore::open(dir.path(), 4096).expect("open must tolerate bad keys");
        // Malformed entry is skipped; store behaves as empty.
        assert!(store.is_empty());
        assert_eq!(store.total_bytes(), 0);
    }

    #[test]
    fn rehydrate_skips_malformed_values_written_directly_to_redb() {
        // Valid key, garbage value (shorter than the 20-byte header).
        // Must be dropped on rebuild rather than tripping Decode up.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("federation_replay.redb");
        {
            let db = redb::Database::create(&path).unwrap();
            let write = db.begin_write().unwrap();
            {
                let mut table = write.open_table(REPLAY_TABLE).unwrap();
                let key = encode_key("peer", 1);
                let _ = table.insert(key.as_slice(), &[0u8; 3][..]).unwrap();
            }
            write.commit().unwrap();
        }
        let store = ReplayStore::open(dir.path(), 4096).expect("open must tolerate bad values");
        assert!(store.is_empty());
    }

    #[test]
    fn byte_cap_zero_drops_every_write() {
        // A cap of 0 means no record fits: eviction must run for every
        // put, leaving the in-memory ring empty. (The on-disk table
        // still sees the insert because the commit runs after
        // eviction of older records, but the accounted total stays at
        // the single-record size — the in-memory view is what peers
        // replay from.) Pin the small-cap edge so a future change to
        // eviction ordering doesn't accidentally skip zero-sized caps.
        let dir = tempfile::tempdir().unwrap();
        let store = ReplayStore::open(dir.path(), 0).unwrap();
        store
            .put("p", 1, 10, None, 1, &[], &Bytes::from_static(b"x"))
            .unwrap();
        // The freshly-inserted record itself always remains in memory;
        // any earlier record would be evicted first. With a cap of 0
        // and a single put, the in-memory ring has exactly one entry.
        assert_eq!(store.len(), 1);
        // A second put drops the first in memory even though both
        // exist briefly in the b-tree.
        store
            .put("p", 2, 20, None, 1, &[], &Bytes::from_static(b"y"))
            .unwrap();
        assert_eq!(store.len(), 1);
    }

    // ---------------------------------------------------------------
    // #763 — store-forward persists post-hop-increment envelope.
    // ---------------------------------------------------------------

    /// A `put(..., current_hops = N)` followed by `load_all` returns a
    /// `RestoredEntry` whose `current_hops` equals `N` and whose
    /// `is_legacy_pre_increment` flag is `false`. This is the persistence-
    /// layer half of the post-increment invariant — the drain hot-path
    /// then evaluates `current_hops < max_hops` directly.
    #[test]
    fn store_forward_persists_post_increment_hops() {
        // Admit at hops=3, persist, read back, assert hops=3 round-trips
        // unchanged with the post-increment flag set. The "+1" relative to
        // a fresh first-hop emit is the producer's responsibility — the
        // store treats whatever it is handed as the post-increment value.
        let dir = tempfile::tempdir().unwrap();
        let store = ReplayStore::open(dir.path(), 1 << 20).unwrap();
        store
            .put("peer-a", 1, 1_000, None, 3, &[], &Bytes::from_static(b"p"))
            .unwrap();
        drop(store);

        let store = ReplayStore::open(dir.path(), 1 << 20).unwrap();
        let all = store.load_all().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].current_hops, 3);
        assert!(
            !all[0].is_legacy_pre_increment,
            "v2-encoded record must not be flagged legacy"
        );
    }

    /// Records written by a pre-#763 binary (no v2 magic) decode as
    /// legacy. The drain hot-path is responsible for applying `+1`
    /// before checking the limit; this test only locks down the
    /// persistence-layer contract that the legacy flag is surfaced.
    #[test]
    fn legacy_envelope_without_version_field_is_treated_as_pre_increment() {
        // Hand-build a v1 (legacy) record by writing the value bytes
        // directly to redb, bypassing the v2 encoder. This is the
        // exact byte layout produced by binaries that predate the
        // wire-format change.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("federation_replay.redb");
        {
            let db = redb::Database::create(&path).unwrap();
            let write = db.begin_write().unwrap();
            {
                let mut table = write.open_table(REPLAY_TABLE).unwrap();
                let key = encode_key("peer-legacy", 1);
                let mut value = BytesMut::new();
                value.put_u64(7); // ts
                value.put_u64(0); // ttl=None
                value.put_u32(0); // groups_len
                value.put_slice(b"legacy-payload");
                let _ = table.insert(key.as_slice(), value.as_ref()).unwrap();
            }
            write.commit().unwrap();
        }

        let store = ReplayStore::open(dir.path(), 1 << 20).expect("open must succeed");
        let all = store.load_all().unwrap();
        assert_eq!(all.len(), 1);
        let entry = &all[0];
        assert!(
            entry.is_legacy_pre_increment,
            "v1-encoded record must surface as legacy on read"
        );
        assert_eq!(entry.current_hops, 0, "v1 carries no persisted hop count");
        assert_eq!(entry.payload, Bytes::from_static(b"legacy-payload"));
    }
}
