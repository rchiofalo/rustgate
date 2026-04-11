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
use tokio::sync::mpsc;
use tracing::{debug, warn};

/// Bounded capacity of the async writer channel. Enqueues submitted
/// beyond this point are dropped and counted via
/// [`ClientQueue::writer_drops_total`] rather than stalling the caller.
pub const CLIENT_QUEUE_WRITER_CHANNEL_CAPACITY: usize = 8192;

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
    enqueues: u64,
    writer_drops: u64,
    expired: u64,
    skipped_unsupported: u64,
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
            enqueues: 0,
            writer_drops: 0,
            expired: 0,
            skipped_unsupported: 0,
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
    /// Bounded sender feeding a dedicated background writer task. Keeps
    /// `enqueue` non-blocking and off the async runtime's worker threads.
    writer_tx: mpsc::Sender<(String, RoutableMessage)>,
}

impl ClientQueue {
    /// Open or create a client queue rooted at `dir`. The database file
    /// is named `client_queue.redb` inside `dir`. The directory is
    /// created if it does not already exist.
    ///
    /// On open, any messages persisted by a previous process are
    /// scanned to rebuild the in-memory index so that [`Self::stats`] and
    /// eviction work correctly immediately after restart. Corrupt
    /// records are skipped with a warning rather than failing open.
    pub fn open(dir: &Path, max_bytes: u64) -> Result<Self, StoreForwardError> {
        std::fs::create_dir_all(dir).map_err(|e| StoreForwardError::Database(e.to_string()))?;
        let path = dir.join("client_queue.redb");
        let db = Database::create(&path).map_err(|e| StoreForwardError::Database(e.to_string()))?;

        // Ensure the table exists and rebuild in-memory index.
        let mut inner = Inner::new();
        let mut malformed_seqs: Vec<u64> = Vec::new();
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
                // We only need the destination CN — peek it without
                // materializing the full RoutableMessage.
                let cn = match peek_dest_cn(raw) {
                    PeekDest::Direct(cn) => cn,
                    PeekDest::NonDirect => {
                        debug!(seq, "skipping non-direct queue entry on rebuild");
                        inner.skipped_unsupported = inner.skipped_unsupported.saturating_add(1);
                        continue;
                    }
                    PeekDest::Malformed => {
                        malformed_seqs.push(seq);
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

        // Purge corrupt entries from disk so they don't accumulate across
        // restarts. The read transaction above identified them; now remove
        // them in a separate write transaction.
        if !malformed_seqs.is_empty() {
            let purge_count = malformed_seqs.len();
            let write = db
                .begin_write()
                .map_err(|e| StoreForwardError::Database(e.to_string()))?;
            {
                let mut table = write
                    .open_table(QUEUE_TABLE)
                    .map_err(|e| StoreForwardError::Database(e.to_string()))?;
                for seq in &malformed_seqs {
                    let _ = table.remove(seq);
                }
            }
            write
                .commit()
                .map_err(|e| StoreForwardError::Database(e.to_string()))?;
            warn!(
                count = purge_count,
                "purged malformed entries from client queue on startup"
            );
        }

        let db = Arc::new(db);
        let inner = Arc::new(Mutex::new(inner));
        let (writer_tx, writer_rx) =
            mpsc::channel::<(String, RoutableMessage)>(CLIENT_QUEUE_WRITER_CHANNEL_CAPACITY);
        spawn_writer_task(Arc::clone(&db), Arc::clone(&inner), max_bytes, writer_rx);

        Ok(Self {
            db,
            inner,
            max_bytes,
            path,
            writer_tx,
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

    /// Submit `msg` to the async writer for durable persistence to the
    /// on-disk queue. Returns immediately without touching redb — the
    /// actual `begin_write` / `commit` is performed off the async
    /// runtime by a dedicated background task.
    ///
    /// If the writer channel is full, the message is dropped and
    /// [`Self::writer_drops_total`] is incremented. This preserves live
    /// routing latency under pathological bursts at the cost of
    /// losing the offending offline messages.
    pub fn enqueue(&self, cn: &str, msg: &RoutableMessage) -> Result<u64, StoreForwardError> {
        match self.writer_tx.try_send((cn.to_string(), msg.clone())) {
            Ok(()) => {
                let mut inner = self.inner.lock();
                inner.enqueues = inner.enqueues.saturating_add(1);
                Ok(0)
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                let mut inner = self.inner.lock();
                inner.writer_drops = inner.writer_drops.saturating_add(1);
                warn!(
                    cn,
                    cap = CLIENT_QUEUE_WRITER_CHANNEL_CAPACITY,
                    "client queue: writer channel full; dropping message"
                );
                Ok(0)
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                let mut inner = self.inner.lock();
                inner.writer_drops = inner.writer_drops.saturating_add(1);
                warn!(cn, "client queue: writer task gone; dropping message");
                Ok(0)
            }
        }
    }

    /// Total messages successfully submitted to the async writer.
    pub fn enqueues_total(&self) -> u64 {
        self.inner.lock().enqueues
    }

    /// Total messages dropped because the async writer channel was
    /// full or closed.
    pub fn writer_drops_total(&self) -> u64 {
        self.inner.lock().writer_drops
    }

    /// Total messages skipped during drain because their TTL had
    /// expired before the client reconnected.
    pub fn expired_total(&self) -> u64 {
        self.inner.lock().expired
    }

    /// Total queue entries skipped on reopen because their destination
    /// was not a direct-addressed CN (broadcast/group).
    pub fn skipped_unsupported_total(&self) -> u64 {
        self.inner.lock().skipped_unsupported
    }

    /// Drain every queued message for `cn` in FIFO order, removing them
    /// from durable storage. Returns the decoded messages ready for
    /// re-routing. Entries whose TTL has elapsed are silently removed
    /// and counted via [`Self::expired_total`]. Malformed entries are
    /// skipped with a warning.
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
        let mut expired_count: u64 = 0;
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
                        Ok(msg) => {
                            if msg_expired(&msg) {
                                expired_count = expired_count.saturating_add(1);
                                debug!(seq, cn, "client queue: dropping expired entry on drain");
                            } else {
                                out.push(msg);
                            }
                        }
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

        if expired_count > 0 {
            let mut inner = self.inner.lock();
            inner.expired = inner.expired.saturating_add(expired_count);
        }

        debug!(
            cn,
            drained = out.len(),
            expired = expired_count,
            "client queue: drained"
        );
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

    /// Total number of [`Self::drain`] calls that returned at least one
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

/// Result of peeking the destination CN of an encoded envelope without
/// fully decoding it.
enum PeekDest {
    /// Direct-addressed to this CN — the store-and-forward index keys
    /// queue entries by this value.
    Direct(String),
    /// Broadcast/group destination; currently never persisted but may
    /// appear in older on-disk data.
    NonDirect,
    /// Envelope is structurally invalid and should be dropped.
    Malformed,
}

/// Extract just the destination CN from an encoded envelope without
/// allocating the full message.
///
/// The envelope layout starts with
/// `[version u8][source identity][dest tag u8]...`, so we skip the
/// version byte and the source identity before reading the destination.
fn peek_dest_cn(raw: &[u8]) -> PeekDest {
    let mut buf: &[u8] = raw;
    if buf.remaining() < 1 {
        return PeekDest::Malformed;
    }
    let _ = buf.get_u8();
    let Some(_source) = get_identity(&mut buf) else {
        return PeekDest::Malformed;
    };
    if buf.remaining() < 1 {
        return PeekDest::Malformed;
    }
    match buf.get_u8() {
        DEST_BROADCAST | DEST_GROUP => PeekDest::NonDirect,
        DEST_DIRECT => match get_str(&mut buf) {
            Some(cn) => PeekDest::Direct(cn),
            None => PeekDest::Malformed,
        },
        _ => PeekDest::Malformed,
    }
}

/// Returns `true` if `msg` carries a TTL that has elapsed since its
/// `received_at` timestamp. Used by drain to skip stale queued entries.
fn msg_expired(msg: &RoutableMessage) -> bool {
    let Some(ttl) = msg.metadata.ttl else {
        return false;
    };
    let deadline = msg.metadata.received_at + ttl;
    SystemTime::now() > deadline
}

/// Spawn the background writer task that services an async queue of
/// pending enqueues. Each message is persisted via a synchronous
/// redb transaction inside `spawn_blocking` so the runtime's async
/// workers are never parked on file I/O.
fn spawn_writer_task(
    db: Arc<Database>,
    inner: Arc<Mutex<Inner>>,
    max_bytes: u64,
    mut rx: mpsc::Receiver<(String, RoutableMessage)>,
) {
    drop(tokio::spawn(async move {
        while let Some((cn, msg)) = rx.recv().await {
            let db = Arc::clone(&db);
            let inner = Arc::clone(&inner);
            let join =
                tokio::task::spawn_blocking(move || persist_one(&db, &inner, max_bytes, &cn, &msg))
                    .await;
            match join {
                Ok(Ok(())) => {}
                Ok(Err(e)) => warn!(error = %e, "client queue writer: persist failed"),
                Err(e) => warn!(error = %e, "client queue writer: join failed"),
            }
        }
    }));
}

/// Synchronous durable write path executed inside `spawn_blocking`.
/// Holds the in-memory index lock briefly to reserve a sequence number
/// and apply eviction bookkeeping, then commits the redb transaction.
fn persist_one(
    db: &Database,
    inner: &Mutex<Inner>,
    max_bytes: u64,
    cn: &str,
    msg: &RoutableMessage,
) -> Result<(), StoreForwardError> {
    let encoded = encode(msg);
    let size = encoded.len() as u64;
    if size > max_bytes {
        let mut guard = inner.lock();
        guard.drops = guard.drops.saturating_add(1);
        warn!(
            cn,
            size_bytes = size,
            cap_bytes = max_bytes,
            "client queue: message larger than global cap; dropping"
        );
        return Ok(());
    }

    let mut dropped_victims: Vec<u64> = Vec::new();
    let seq;
    {
        let mut guard = inner.lock();
        seq = guard.next_seq;
        guard.next_seq += 1;

        while guard.total_bytes + size > max_bytes {
            let Some((victim_seq, victim_cn, victim_size)) = guard.global.pop_front() else {
                break;
            };
            if let Some(idx) = guard.per_cn.get_mut(&victim_cn) {
                if let Some(front) = idx.seqs.front().copied()
                    && front == victim_seq
                {
                    let _ = idx.seqs.pop_front();
                } else {
                    idx.seqs.retain(|s| *s != victim_seq);
                }
                idx.bytes = idx.bytes.saturating_sub(victim_size);
                if idx.seqs.is_empty() {
                    let _ = guard.per_cn.remove(&victim_cn);
                }
            }
            guard.total_bytes = guard.total_bytes.saturating_sub(victim_size);
            guard.drops = guard.drops.saturating_add(1);
            dropped_victims.push(victim_seq);
        }

        guard.global.push_back((seq, cn.to_string(), size));
        let idx = guard
            .per_cn
            .entry(cn.to_string())
            .or_insert_with(PerCnIndex::new);
        idx.seqs.push_back(seq);
        idx.bytes = idx.bytes.saturating_add(size);
        guard.total_bytes = guard.total_bytes.saturating_add(size);
    }

    let write = db
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
    Ok(())
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

    async fn wait_for_depth(q: &ClientQueue, cn: &str, expected: u64) {
        for _ in 0..200 {
            if q.stats(cn).depth == expected {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!(
            "timed out waiting for depth={} on {cn} (got {})",
            expected,
            q.stats(cn).depth
        );
    }

    #[tokio::test]
    async fn enqueue_and_drain_preserves_fifo() {
        let tmp = TempDir::new().unwrap();
        let q = ClientQueue::open(tmp.path(), 1_000_000).unwrap();
        for i in 0..5u8 {
            q.enqueue("bob", &msg_for("alice", "bob", &[i])).unwrap();
        }
        wait_for_depth(&q, "bob", 5).await;
        assert_eq!(q.stats("bob").depth, 5);
        let drained = q.drain("bob").unwrap();
        assert_eq!(drained.len(), 5);
        for (i, m) in drained.iter().enumerate() {
            assert_eq!(m.payload.as_ref(), &[i as u8]);
        }
        assert_eq!(q.stats("bob").depth, 0);
        assert_eq!(q.drains_total(), 1);
    }

    #[tokio::test]
    async fn byte_cap_drops_oldest() {
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
        // Wait for writer task to catch up.
        for _ in 0..200 {
            if q.drops_total() >= 7 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let stats = q.stats("bob");
        assert!(stats.depth <= 3, "depth {} exceeds cap", stats.depth);
        assert!(q.drops_total() >= 7);
    }

    #[tokio::test]
    async fn survives_reopen() {
        let tmp = TempDir::new().unwrap();
        {
            let q = ClientQueue::open(tmp.path(), 1_000_000).unwrap();
            q.enqueue("bob", &msg_for("alice", "bob", b"one")).unwrap();
            q.enqueue("bob", &msg_for("alice", "bob", b"two")).unwrap();
            wait_for_depth(&q, "bob", 2).await;
            drop(q);
        }
        // Give the writer task a moment to observe the closed channel
        // and release its Arc<Database> so redb can unlock the file.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let q2 = ClientQueue::open(tmp.path(), 1_000_000).unwrap();
        assert_eq!(q2.stats("bob").depth, 2);
        let drained = q2.drain("bob").unwrap();
        assert_eq!(drained.len(), 2);
        assert_eq!(drained[0].payload.as_ref(), b"one");
        assert_eq!(drained[1].payload.as_ref(), b"two");
    }

    #[tokio::test]
    async fn drain_unknown_cn_is_empty() {
        let tmp = TempDir::new().unwrap();
        let q = ClientQueue::open(tmp.path(), 1_000).unwrap();
        assert!(q.drain("ghost").unwrap().is_empty());
    }

    #[tokio::test]
    async fn drain_skips_expired_and_counts() {
        let tmp = TempDir::new().unwrap();
        let q = ClientQueue::open(tmp.path(), 1_000_000).unwrap();
        // One message already expired (ttl 0 + received_at in the past).
        let mut m1 = msg_for("alice", "bob", b"stale");
        m1.metadata.received_at = SystemTime::now() - Duration::from_secs(60);
        m1.metadata.ttl = Some(Duration::from_secs(1));
        // One still fresh.
        let mut m2 = msg_for("alice", "bob", b"fresh");
        m2.metadata.ttl = Some(Duration::from_secs(3600));
        q.enqueue("bob", &m1).unwrap();
        q.enqueue("bob", &m2).unwrap();
        wait_for_depth(&q, "bob", 2).await;

        let drained = q.drain("bob").unwrap();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].payload.as_ref(), b"fresh");
        assert_eq!(q.expired_total(), 1);
    }

    #[tokio::test]
    async fn reopen_purges_malformed_entries() {
        let tmp = TempDir::new().unwrap();
        {
            let q = ClientQueue::open(tmp.path(), 1_000_000).unwrap();
            q.enqueue("bob", &msg_for("alice", "bob", b"valid"))
                .unwrap();
            wait_for_depth(&q, "bob", 1).await;
            drop(q);
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Inject a corrupt entry directly into the redb table.
        {
            let db_path = tmp.path().join("client_queue.redb");
            let db = Database::create(&db_path).unwrap();
            let write = db.begin_write().unwrap();
            {
                let mut table = write.open_table(QUEUE_TABLE).unwrap();
                // Garbage bytes that will fail peek_dest_cn parsing.
                table.insert(999_u64, &[0xFF, 0xFF][..]).unwrap();
            }
            write.commit().unwrap();
            drop(db);
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Reopen — corrupt entry should be purged from disk.
        let q2 = ClientQueue::open(tmp.path(), 1_000_000).unwrap();
        assert_eq!(q2.stats("bob").depth, 1, "valid entry should survive");

        let drained = q2.drain("bob").unwrap();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].payload.as_ref(), b"valid");

        // Verify the corrupt entry was removed from the database.
        {
            let read = q2.db.begin_read().unwrap();
            let table = read.open_table(QUEUE_TABLE).unwrap();
            assert!(
                table.get(&999_u64).unwrap().is_none(),
                "corrupt entry should have been purged on open"
            );
        }
    }

    #[tokio::test]
    async fn writer_channel_overflow_increments_drops() {
        // Shrink throughput by filling the channel faster than
        // spawn_blocking can drain it. The channel cap is large, so we
        // simulate a flood with many sends; the `try_send` path should
        // eventually begin reporting drops.
        let tmp = TempDir::new().unwrap();
        let q = ClientQueue::open(tmp.path(), 100 * 1024 * 1024).unwrap();
        let m = msg_for("alice", "bob", b"x");
        // Flood well above CLIENT_QUEUE_WRITER_CHANNEL_CAPACITY without
        // yielding so the writer task cannot drain in between.
        for _ in 0..(CLIENT_QUEUE_WRITER_CHANNEL_CAPACITY * 3) {
            q.enqueue("bob", &m).unwrap();
        }
        assert!(
            q.writer_drops_total() > 0,
            "expected writer overflow drops, got {}",
            q.writer_drops_total()
        );
    }
}
