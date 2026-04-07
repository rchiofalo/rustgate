//! Per-client store-and-forward disk queue.
//!
//! When a client disconnects, in-flight messages destined for that CN
//! can be persisted to a bounded on-disk queue and drained on reconnect
//! before live traffic resumes. The queue is:
//!
//! - Durable across restarts (backed by redb, a single-file embedded KV).
//! - Globally bounded by a byte cap using drop-oldest FIFO eviction
//!   across all CNs.
//! - Per-CN FIFO ordering preserved via a monotonic sequence number.
//!
//! This module is completely optional — the server only instantiates a
//! [`ClientQueue`] when `--client-queue-dir` is passed on the CLI. With
//! no queue, the router falls back to its previous best-effort behavior.
//!
//! # Encoding
//!
//! Each stored message uses a tiny hand-rolled binary envelope so we do
//! not need to add `serde` to `rustgate-core`. The envelope carries
//! enough fields to faithfully reconstruct a [`RoutableMessage`] after
//! restart: source identity (cn, fingerprint, groups), destination,
//! message type, source protocol, received-at timestamp, TTL, and raw
//! payload bytes. See [`encode`] / [`decode`] for the wire layout.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use parking_lot::Mutex;
use redb::{Database, ReadableTable, TableDefinition};
use rustgate_core::identity::Identity;
use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};
use thiserror::Error;
use tracing::{debug, warn};

/// Default global byte cap applied when the operator enables
/// store-and-forward without specifying `--client-queue-max-bytes`.
pub const DEFAULT_CLIENT_QUEUE_MAX_BYTES: u64 = 100 * 1024 * 1024;

/// redb table: key = big-endian `seq_u64`, value = binary envelope.
///
/// A single flat table is used for all CNs so eviction can walk it in
/// strict global sequence order. The envelope carries the owning CN so
/// per-CN drains can filter by it.
const QUEUE_TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("client_queue_v1");

/// Errors returned by [`ClientQueue`].
#[derive(Debug, Error)]
pub enum StoreForwardError {
    /// An underlying redb error bubbled up (open/read/write).
    #[error("client queue database error: {0}")]
    Database(String),
    /// A stored envelope failed to decode — treated as corruption and
    /// the offending record is dropped rather than propagated to the
    /// router.
    #[error("malformed stored message envelope")]
    Decode,
}

/// Snapshot of queue depth / byte usage for a single CN. Returned by
/// [`ClientQueue::stats`] and used to populate gauges.
#[derive(Debug, Clone, Copy, Default)]
pub struct QueueStats {
    /// Number of messages currently queued for this CN.
    pub depth: u64,
    /// Total encoded bytes currently queued for this CN.
    pub bytes: u64,
}

#[derive(Debug)]
struct PerCnIndex {
    /// Seq numbers for this CN in FIFO order (oldest at front).
    seqs: VecDeque<u64>,
    /// Cached per-CN byte total for cheap metric updates.
    bytes: u64,
}

impl PerCnIndex {
    fn new() -> Self {
        Self {
            seqs: VecDeque::new(),
            bytes: 0,
        }
    }
}

#[derive(Debug)]
struct Inner {
    /// Global FIFO of (seq, cn, size) used to pick the next eviction
    /// victim when the byte cap is exceeded. The `cn` is redundant with
    /// the per-CN index but avoids a redb read during eviction.
    global: VecDeque<(u64, String, u64)>,
    per_cn: HashMap<String, PerCnIndex>,
    total_bytes: u64,
    next_seq: u64,
    drops: u64,
    drains: u64,
}

impl Inner {
    fn new() -> Self {
        Self {
            global: VecDeque::new(),
            per_cn: HashMap::new(),
            total_bytes: 0,
            next_seq: 0,
            drops: 0,
            drains: 0,
        }
    }
}

/// A bounded, durable per-client message queue.
///
/// Cloning a [`ClientQueue`] is cheap: internally it holds an `Arc` to
/// the shared database and index.
#[derive(Clone, Debug)]
pub struct ClientQueue {
    db: Arc<Database>,
    inner: Arc<Mutex<Inner>>,
    max_bytes: u64,
    path: PathBuf,
}

impl ClientQueue {
    /// Open or create a client queue rooted at `dir`. The database file
    /// is named `client_queue.redb` inside `dir`. The directory is
    /// created if it does not already exist.
    ///
    /// On open, any messages persisted by a previous process are
    /// scanned to rebuild the in-memory index so that [`stats`] and
    /// eviction work correctly immediately after restart. Corrupt
    /// records are skipped with a warning rather than failing open.
    pub fn open(dir: &Path, max_bytes: u64) -> Result<Self, StoreForwardError> {
        std::fs::create_dir_all(dir).map_err(|e| StoreForwardError::Database(e.to_string()))?;
        let path = dir.join("client_queue.redb");
        let db = Database::create(&path).map_err(|e| StoreForwardError::Database(e.to_string()))?;

        // Ensure the table exists and rebuild in-memory index.
        let mut inner = Inner::new();
        {
            let write = db
                .begin_write()
                .map_err(|e| StoreForwardError::Database(e.to_string()))?;
            {
                let _ = write
                    .open_table(QUEUE_TABLE)
                    .map_err(|e| StoreForwardError::Database(e.to_string()))?;
            }
            write
                .commit()
                .map_err(|e| StoreForwardError::Database(e.to_string()))?;
        }
        {
            let read = db
                .begin_read()
                .map_err(|e| StoreForwardError::Database(e.to_string()))?;
            let table = read
                .open_table(QUEUE_TABLE)
                .map_err(|e| StoreForwardError::Database(e.to_string()))?;
            for entry in table
                .iter()
                .map_err(|e| StoreForwardError::Database(e.to_string()))?
            {
                let (k, v) = match entry {
                    Ok(kv) => kv,
                    Err(e) => {
                        warn!(error = %e, "skipping unreadable client-queue entry");
                        continue;
                    }
                };
                let seq = k.value();
                let raw = v.value();
                let size = raw.len() as u64;
                // We only need the CN — peek it without materializing
                // the full RoutableMessage.
                let cn = match peek_cn(raw) {
                    Some(cn) => cn,
                    None => {
                        warn!(seq, "dropping malformed client-queue entry on open");
                        continue;
                    }
                };
                inner.global.push_back((seq, cn.clone(), size));
                let idx = inner.per_cn.entry(cn).or_insert_with(PerCnIndex::new);
                idx.seqs.push_back(seq);
                idx.bytes = idx.bytes.saturating_add(size);
                inner.total_bytes = inner.total_bytes.saturating_add(size);
                if seq >= inner.next_seq {
                    inner.next_seq = seq + 1;
                }
            }
        }

        Ok(Self {
            db: Arc::new(db),
            inner: Arc::new(Mutex::new(inner)),
            max_bytes,
            path,
        })
    }

    /// Path of the backing database file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Configured global byte cap.
    pub fn max_bytes(&self) -> u64 {
        self.max_bytes
    }

    /// Persist `msg` to the queue for delivery to `cn` when it
    /// reconnects. If the insertion pushes the total byte count above
    /// the configured cap, the oldest entries (globally, across all
    /// CNs) are evicted until the queue fits. Returns the number of
    /// messages that were dropped to make room.
    pub fn enqueue(&self, cn: &str, msg: &RoutableMessage) -> Result<u64, StoreForwardError> {
        let encoded = encode(msg);
        let size = encoded.len() as u64;
        if size > self.max_bytes {
            // A single message larger than the entire cap cannot be
            // stored — account it as a drop and skip.
            let mut inner = self.inner.lock();
            inner.drops = inner.drops.saturating_add(1);
            warn!(
                cn,
                size_bytes = size,
                cap_bytes = self.max_bytes,
                "client queue: message larger than global cap; dropping"
            );
            return Ok(1);
        }

        let mut dropped_victims: Vec<u64> = Vec::new();
        let seq;
        {
            let mut inner = self.inner.lock();
            seq = inner.next_seq;
            inner.next_seq += 1;

            // Evict oldest entries until the new message fits.
            while inner.total_bytes + size > self.max_bytes {
                let Some((victim_seq, victim_cn, victim_size)) = inner.global.pop_front() else {
                    break;
                };
                if let Some(idx) = inner.per_cn.get_mut(&victim_cn) {
                    if let Some(front) = idx.seqs.front().copied()
                        && front == victim_seq
                    {
                        let _ = idx.seqs.pop_front();
                    } else {
                        // Rare: victim not at front (already drained).
                        // Remove by value to keep index coherent.
                        idx.seqs.retain(|s| *s != victim_seq);
                    }
                    idx.bytes = idx.bytes.saturating_sub(victim_size);
                    if idx.seqs.is_empty() {
                        let _ = inner.per_cn.remove(&victim_cn);
                    }
                }
                inner.total_bytes = inner.total_bytes.saturating_sub(victim_size);
                inner.drops = inner.drops.saturating_add(1);
                dropped_victims.push(victim_seq);
            }

            // Record the new entry in memory first so a crash between
            // the memory update and the commit only leaks unreferenced
            // DB bytes (handled on next open).
            inner.global.push_back((seq, cn.to_string(), size));
            let idx = inner
                .per_cn
                .entry(cn.to_string())
                .or_insert_with(PerCnIndex::new);
            idx.seqs.push_back(seq);
            idx.bytes = idx.bytes.saturating_add(size);
            inner.total_bytes = inner.total_bytes.saturating_add(size);
        }

        // Perform the durable write in a single transaction that both
        // removes evicted victims and inserts the new record.
        let write = self
            .db
            .begin_write()
            .map_err(|e| StoreForwardError::Database(e.to_string()))?;
        {
            let mut table = write
                .open_table(QUEUE_TABLE)
                .map_err(|e| StoreForwardError::Database(e.to_string()))?;
            for v in &dropped_victims {
                let _ = table
                    .remove(v)
                    .map_err(|e| StoreForwardError::Database(e.to_string()))?;
            }
            let _ = table
                .insert(seq, encoded.as_slice())
                .map_err(|e| StoreForwardError::Database(e.to_string()))?;
        }
        write
            .commit()
            .map_err(|e| StoreForwardError::Database(e.to_string()))?;

        debug!(cn, seq, size_bytes = size, "client queue: enqueued");
        Ok(dropped_victims.len() as u64)
    }

    /// Drain every queued message for `cn` in FIFO order, removing them
    /// from durable storage. Returns the decoded messages ready for
    /// re-routing. Malformed entries are skipped with a warning.
    pub fn drain(&self, cn: &str) -> Result<Vec<RoutableMessage>, StoreForwardError> {
        let seqs: Vec<u64> = {
            let mut inner = self.inner.lock();
            let Some(idx) = inner.per_cn.remove(cn) else {
                return Ok(Vec::new());
            };
            let seqs: Vec<u64> = idx.seqs.into_iter().collect();
            let reclaim: u64 = idx.bytes;
            inner.total_bytes = inner.total_bytes.saturating_sub(reclaim);
            let set: std::collections::HashSet<u64> = seqs.iter().copied().collect();
            inner.global.retain(|(s, _, _)| !set.contains(s));
            inner.drains = inner.drains.saturating_add(1);
            seqs
        };

        if seqs.is_empty() {
            return Ok(Vec::new());
        }

        let mut out: Vec<RoutableMessage> = Vec::with_capacity(seqs.len());
        let write = self
            .db
            .begin_write()
            .map_err(|e| StoreForwardError::Database(e.to_string()))?;
        {
            let mut table = write
                .open_table(QUEUE_TABLE)
                .map_err(|e| StoreForwardError::Database(e.to_string()))?;
            for seq in &seqs {
                let removed = table
                    .remove(seq)
                    .map_err(|e| StoreForwardError::Database(e.to_string()))?;
                if let Some(access) = removed {
                    match decode(access.value()) {
                        Ok(msg) => out.push(msg),
                        Err(_) => {
                            warn!(seq, cn, "client queue: dropping malformed entry on drain");
                        }
                    }
                }
            }
        }
        write
            .commit()
            .map_err(|e| StoreForwardError::Database(e.to_string()))?;

        debug!(cn, drained = out.len(), "client queue: drained");
        Ok(out)
    }

    /// Return a stats snapshot for a single CN.
    pub fn stats(&self, cn: &str) -> QueueStats {
        let inner = self.inner.lock();
        inner
            .per_cn
            .get(cn)
            .map(|i| QueueStats {
                depth: i.seqs.len() as u64,
                bytes: i.bytes,
            })
            .unwrap_or_default()
    }

    /// Total number of messages dropped so far due to cap eviction or
    /// oversized messages.
    pub fn drops_total(&self) -> u64 {
        self.inner.lock().drops
    }

    /// Total number of [`drain`] calls that returned at least one
    /// message.
    pub fn drains_total(&self) -> u64 {
        self.inner.lock().drains
    }

    /// Total bytes currently stored across all CNs.
    pub fn total_bytes(&self) -> u64 {
        self.inner.lock().total_bytes
    }

    /// Return a snapshot of every CN that currently has at least one
    /// queued message along with its stats. Used by the metrics task.
    pub fn snapshot(&self) -> Vec<(String, QueueStats)> {
        let inner = self.inner.lock();
        inner
            .per_cn
            .iter()
            .map(|(cn, idx)| {
                (
                    cn.clone(),
                    QueueStats {
                        depth: idx.seqs.len() as u64,
                        bytes: idx.bytes,
                    },
                )
            })
            .collect()
    }
}

// ── Encoding ────────────────────────────────────────────────────────

/// Current envelope version tag. Bump on any incompatible wire change.
const ENVELOPE_VERSION: u8 = 1;

const DEST_BROADCAST: u8 = 0;
const DEST_GROUP: u8 = 1;
const DEST_DIRECT: u8 = 2;

const MT_POSITION: u8 = 0;
const MT_CHAT: u8 = 1;
const MT_ALERT: u8 = 2;
const MT_STATUS: u8 = 3;
const MT_FILE: u8 = 4;
const MT_OTHER: u8 = 5;

fn put_str(buf: &mut BytesMut, s: &str) {
    let bytes = s.as_bytes();
    buf.put_u16(bytes.len() as u16);
    buf.put_slice(bytes);
}

fn get_str(buf: &mut &[u8]) -> Option<String> {
    if buf.remaining() < 2 {
        return None;
    }
    let len = buf.get_u16() as usize;
    if buf.remaining() < len {
        return None;
    }
    let s = std::str::from_utf8(&buf[..len]).ok()?.to_string();
    buf.advance(len);
    Some(s)
}

fn put_identity(buf: &mut BytesMut, id: &Identity) {
    put_str(buf, &id.cn);
    put_str(buf, &id.fingerprint);
    buf.put_u16(id.groups.len() as u16);
    for g in &id.groups {
        put_str(buf, g);
    }
}

fn get_identity(buf: &mut &[u8]) -> Option<Identity> {
    let cn = get_str(buf)?;
    let fp = get_str(buf)?;
    if buf.remaining() < 2 {
        return None;
    }
    let n = buf.get_u16() as usize;
    let mut groups = BTreeSet::new();
    for _ in 0..n {
        let _ = groups.insert(get_str(buf)?);
    }
    Identity::new(cn, fp, groups).ok()
}

/// Encode a [`RoutableMessage`] to the on-disk envelope format.
pub fn encode(msg: &RoutableMessage) -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(128 + msg.payload.len());
    buf.put_u8(ENVELOPE_VERSION);
    put_identity(&mut buf, &msg.source);

    match &msg.destination {
        Destination::Broadcast => buf.put_u8(DEST_BROADCAST),
        Destination::Group(g) => {
            buf.put_u8(DEST_GROUP);
            put_str(&mut buf, g);
        }
        Destination::Direct(id) => {
            buf.put_u8(DEST_DIRECT);
            put_identity(&mut buf, id);
        }
    }

    match &msg.metadata.message_type {
        MessageType::Position => buf.put_u8(MT_POSITION),
        MessageType::Chat => buf.put_u8(MT_CHAT),
        MessageType::Alert => buf.put_u8(MT_ALERT),
        MessageType::Status => buf.put_u8(MT_STATUS),
        MessageType::File => buf.put_u8(MT_FILE),
        MessageType::Other(s) => {
            buf.put_u8(MT_OTHER);
            put_str(&mut buf, s);
        }
    }

    put_str(&mut buf, &msg.metadata.source_protocol);

    let received_at_ms = msg
        .metadata
        .received_at
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    buf.put_i64(received_at_ms);

    match msg.metadata.ttl {
        None => buf.put_i64(-1),
        Some(d) => buf.put_i64(d.as_secs() as i64),
    }

    buf.put_u32(msg.payload.len() as u32);
    buf.put_slice(&msg.payload);

    buf.to_vec()
}

/// Decode an envelope produced by [`encode`].
pub fn decode(raw: &[u8]) -> Result<RoutableMessage, StoreForwardError> {
    let mut buf: &[u8] = raw;
    if buf.remaining() < 1 {
        return Err(StoreForwardError::Decode);
    }
    let version = buf.get_u8();
    if version != ENVELOPE_VERSION {
        return Err(StoreForwardError::Decode);
    }

    let source = get_identity(&mut buf).ok_or(StoreForwardError::Decode)?;

    if buf.remaining() < 1 {
        return Err(StoreForwardError::Decode);
    }
    let destination = match buf.get_u8() {
        DEST_BROADCAST => Destination::Broadcast,
        DEST_GROUP => Destination::Group(get_str(&mut buf).ok_or(StoreForwardError::Decode)?),
        DEST_DIRECT => {
            Destination::Direct(get_identity(&mut buf).ok_or(StoreForwardError::Decode)?)
        }
        _ => return Err(StoreForwardError::Decode),
    };

    if buf.remaining() < 1 {
        return Err(StoreForwardError::Decode);
    }
    let message_type = match buf.get_u8() {
        MT_POSITION => MessageType::Position,
        MT_CHAT => MessageType::Chat,
        MT_ALERT => MessageType::Alert,
        MT_STATUS => MessageType::Status,
        MT_FILE => MessageType::File,
        MT_OTHER => MessageType::Other(get_str(&mut buf).ok_or(StoreForwardError::Decode)?),
        _ => return Err(StoreForwardError::Decode),
    };

    let source_protocol = get_str(&mut buf).ok_or(StoreForwardError::Decode)?;

    if buf.remaining() < 8 {
        return Err(StoreForwardError::Decode);
    }
    let received_at_ms = buf.get_i64();
    let received_at = if received_at_ms >= 0 {
        UNIX_EPOCH + Duration::from_millis(received_at_ms as u64)
    } else {
        SystemTime::now()
    };

    if buf.remaining() < 8 {
        return Err(StoreForwardError::Decode);
    }
    let ttl_secs = buf.get_i64();
    let ttl = if ttl_secs < 0 {
        None
    } else {
        Some(Duration::from_secs(ttl_secs as u64))
    };

    if buf.remaining() < 4 {
        return Err(StoreForwardError::Decode);
    }
    let payload_len = buf.get_u32() as usize;
    if buf.remaining() < payload_len {
        return Err(StoreForwardError::Decode);
    }
    let payload = Bytes::copy_from_slice(&buf[..payload_len]);

    Ok(RoutableMessage {
        source,
        destination,
        payload,
        metadata: Metadata {
            received_at,
            source_protocol,
            message_type,
            ttl,
        },
    })
}

/// Extract just the source CN from an encoded envelope without
/// allocating the full message. Returns `None` on malformed input.
///
/// The envelope layout starts with `[version u8][cn u16 len + bytes]...`
/// so we only need to skip the version byte.
fn peek_cn(raw: &[u8]) -> Option<String> {
    let mut buf: &[u8] = raw;
    if buf.remaining() < 1 {
        return None;
    }
    let _ = buf.get_u8();
    // NOTE: the peeked string is the *source* CN, but the queue is
    // keyed by *destination* CN. We therefore need to parse on through
    // to the destination. Fall back to full decode for robustness.
    let _source = get_identity(&mut buf)?;
    if buf.remaining() < 1 {
        return None;
    }
    match buf.get_u8() {
        DEST_BROADCAST => None,
        DEST_GROUP => None,
        DEST_DIRECT => {
            // Only the CN of the direct destination is needed.
            get_str(&mut buf)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used, unused_results)]

    use std::collections::BTreeSet;
    use std::time::SystemTime;

    use bytes::Bytes;
    use rustgate_core::identity::Identity;
    use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};
    use tempfile::TempDir;

    use super::*;

    fn ident(cn: &str) -> Identity {
        let mut groups = BTreeSet::new();
        let _ = groups.insert("alpha".to_string());
        Identity::new(cn.to_string(), format!("{cn}-fp"), groups).unwrap()
    }

    fn msg_for(from: &str, to: &str, payload: &[u8]) -> RoutableMessage {
        RoutableMessage {
            source: ident(from),
            destination: Destination::Direct(ident(to)),
            payload: Bytes::copy_from_slice(payload),
            metadata: Metadata {
                received_at: SystemTime::now(),
                source_protocol: "tcp".to_string(),
                message_type: MessageType::Chat,
                ttl: None,
            },
        }
    }

    #[test]
    fn encode_decode_roundtrip() {
        let m = msg_for("alice", "bob", b"hello");
        let bytes = encode(&m);
        let back = decode(&bytes).unwrap();
        assert_eq!(back.source.cn, "alice");
        assert_eq!(back.payload.as_ref(), b"hello");
        match back.destination {
            Destination::Direct(id) => assert_eq!(id.cn, "bob"),
            _ => panic!("wrong dest"),
        }
    }

    #[test]
    fn enqueue_and_drain_preserves_fifo() {
        let tmp = TempDir::new().unwrap();
        let q = ClientQueue::open(tmp.path(), 1_000_000).unwrap();
        for i in 0..5u8 {
            q.enqueue("bob", &msg_for("alice", "bob", &[i])).unwrap();
        }
        assert_eq!(q.stats("bob").depth, 5);
        let drained = q.drain("bob").unwrap();
        assert_eq!(drained.len(), 5);
        for (i, m) in drained.iter().enumerate() {
            assert_eq!(m.payload.as_ref(), &[i as u8]);
        }
        assert_eq!(q.stats("bob").depth, 0);
        assert_eq!(q.drains_total(), 1);
    }

    #[test]
    fn byte_cap_drops_oldest() {
        let tmp = TempDir::new().unwrap();
        // Small cap forces eviction after a couple of messages.
        let payload = vec![0u8; 256];
        let one = msg_for("alice", "bob", &payload);
        let single_size = encode(&one).len() as u64;
        let cap = single_size * 3 + 1;
        let q = ClientQueue::open(tmp.path(), cap).unwrap();
        for _ in 0..10 {
            q.enqueue("bob", &one).unwrap();
        }
        let stats = q.stats("bob");
        assert!(stats.depth <= 3, "depth {} exceeds cap", stats.depth);
        assert!(q.drops_total() >= 7);
    }

    #[test]
    fn survives_reopen() {
        let tmp = TempDir::new().unwrap();
        {
            let q = ClientQueue::open(tmp.path(), 1_000_000).unwrap();
            q.enqueue("bob", &msg_for("alice", "bob", b"one")).unwrap();
            q.enqueue("bob", &msg_for("alice", "bob", b"two")).unwrap();
            drop(q);
        }
        let q2 = ClientQueue::open(tmp.path(), 1_000_000).unwrap();
        assert_eq!(q2.stats("bob").depth, 2);
        let drained = q2.drain("bob").unwrap();
        assert_eq!(drained.len(), 2);
        assert_eq!(drained[0].payload.as_ref(), b"one");
        assert_eq!(drained[1].payload.as_ref(), b"two");
    }

    #[test]
    fn drain_unknown_cn_is_empty() {
        let tmp = TempDir::new().unwrap();
        let q = ClientQueue::open(tmp.path(), 1_000).unwrap();
        assert!(q.drain("ghost").unwrap().is_empty());
    }
}
