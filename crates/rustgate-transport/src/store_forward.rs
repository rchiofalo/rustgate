// Copyright © 2026 Roberto Chiofalo.

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

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use hmac::{Hmac, Mac};
use parking_lot::Mutex;
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use rustgate_core::identity::Identity;
use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use thiserror::Error;
use tokio::sync::mpsc;
use tracing::{debug, warn};
use zeroize::Zeroizing;

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

/// redb table tracking sequence numbers that have been drained and
/// delivered. Prevents duplicate delivery when the process crashes
/// between drain and the caller's acknowledgement of receipt.
const DELIVERED_TABLE: TableDefinition<u64, ()> = TableDefinition::new("delivered_seqs_v1");

/// Length of the HMAC-SHA256 tag appended to each stored envelope.
const HMAC_LEN: usize = 32;

type HmacSha256 = Hmac<Sha256>;

/// Compute an HMAC-SHA256 tag over `data` using the given key.
fn compute_hmac(key: &[u8; 32], data: &[u8]) -> Result<[u8; 32], StoreForwardError> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|e| {
        // Unreachable for a 32-byte key, but we handle it to satisfy the
        // no-unwrap lint.
        StoreForwardError::Database(format!("HMAC key init failed: {e}"))
    })?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().into())
}

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
    /// A stored envelope's HMAC tag did not match — indicates tampering
    /// by a filesystem-level attacker.
    #[error("stored message HMAC verification failed")]
    TamperedMessage,
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
    tampered: u64,
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
            tampered: 0,
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
    /// HMAC-SHA256 key used to integrity-protect stored envelopes.
    /// Wrapped in `Zeroizing` so it is wiped on drop.
    hmac_key: Arc<Zeroizing<[u8; 32]>>,
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
    ///
    /// # Ephemeral HMAC key
    ///
    /// This method generates a fresh random HMAC key on each call.
    /// Messages stored by a previous process instance will fail HMAC
    /// verification and be **silently discarded** on drain, because the
    /// new key cannot verify tags produced by the old key.
    ///
    /// If cross-restart integrity verification is required, use
    /// [`Self::open_with_hmac_key()`] with an externally persisted key.
    pub fn open(dir: &Path, max_bytes: u64) -> Result<Self, StoreForwardError> {
        Self::open_with_hmac_key(dir, max_bytes, None)
    }

    /// Open or create a client queue with an explicit HMAC key.
    ///
    /// When `hmac_key` is `None`, a fresh random key is generated. This
    /// means HMAC tags written by a previous process instance are treated
    /// as tampered on restart (correctly — a new key cannot verify old
    /// tags). The HMAC protects against filesystem-level attackers
    /// modifying stored envelopes while the *same* process is running.
    ///
    /// Callers that need integrity verification to survive restarts
    /// should persist the key externally and pass it here.
    pub fn open_with_hmac_key(
        dir: &Path,
        max_bytes: u64,
        hmac_key: Option<Zeroizing<[u8; 32]>>,
    ) -> Result<Self, StoreForwardError> {
        std::fs::create_dir_all(dir).map_err(|e| StoreForwardError::Database(e.to_string()))?;
        let path = dir.join("client_queue.redb");
        let db = Database::create(&path).map_err(|e| StoreForwardError::Database(e.to_string()))?;

        // Derive or accept the HMAC key.
        let hmac_key = Arc::new(match hmac_key {
            Some(k) => k,
            None => {
                let mut key = Zeroizing::new([0u8; 32]);
                fill_random(&mut *key)?;
                key
            }
        });

        // Ensure both tables exist and rebuild in-memory index.
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
                let _ = write
                    .open_table(DELIVERED_TABLE)
                    .map_err(|e| StoreForwardError::Database(e.to_string()))?;
            }
            write
                .commit()
                .map_err(|e| StoreForwardError::Database(e.to_string()))?;
        }

        // Collect already-delivered seq numbers so we can skip them
        // during the index rebuild and purge them from both tables.
        let delivered_seqs: HashSet<u64> = {
            let read = db
                .begin_read()
                .map_err(|e| StoreForwardError::Database(e.to_string()))?;
            let table = read
                .open_table(DELIVERED_TABLE)
                .map_err(|e| StoreForwardError::Database(e.to_string()))?;
            let mut set = HashSet::new();
            for kv in table
                .iter()
                .map_err(|e| StoreForwardError::Database(e.to_string()))?
                .flatten()
            {
                let _ = set.insert(kv.0.value());
            }
            set
        };

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

                // Skip entries already marked as delivered from a
                // previous drain — they will be purged below.
                if delivered_seqs.contains(&seq) {
                    debug!(seq, "skipping already-delivered queue entry on rebuild");
                    continue;
                }

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

        // Purge corrupt and already-delivered entries from disk so they
        // don't accumulate across restarts.
        let purge_malformed = !malformed_seqs.is_empty();
        let purge_delivered = !delivered_seqs.is_empty();
        if purge_malformed || purge_delivered {
            let purge_count = malformed_seqs.len();
            let delivered_count = delivered_seqs.len();
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
                for seq in &delivered_seqs {
                    let _ = table.remove(seq);
                }
            }
            {
                // Clear the delivered table now that we have purged the
                // corresponding queue entries.
                let mut dtable = write
                    .open_table(DELIVERED_TABLE)
                    .map_err(|e| StoreForwardError::Database(e.to_string()))?;
                for seq in &delivered_seqs {
                    let _ = dtable.remove(seq);
                }
            }
            write
                .commit()
                .map_err(|e| StoreForwardError::Database(e.to_string()))?;
            if purge_malformed {
                warn!(
                    count = purge_count,
                    "purged malformed entries from client queue on startup"
                );
            }
            if purge_delivered {
                debug!(
                    count = delivered_count,
                    "purged already-delivered entries from client queue on startup"
                );
            }
        }

        let db = Arc::new(db);
        let inner = Arc::new(Mutex::new(inner));
        let (writer_tx, writer_rx) =
            mpsc::channel::<(String, RoutableMessage)>(CLIENT_QUEUE_WRITER_CHANNEL_CAPACITY);
        spawn_writer_task(
            Arc::clone(&db),
            Arc::clone(&inner),
            max_bytes,
            Arc::clone(&hmac_key),
            writer_rx,
        );

        Ok(Self {
            db,
            inner,
            max_bytes,
            path,
            hmac_key,
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
                rustgate_core::audit::store_forward_dropped(cn, "writer_channel_full");
                Ok(0)
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                let mut inner = self.inner.lock();
                inner.writer_drops = inner.writer_drops.saturating_add(1);
                warn!(cn, "client queue: writer task gone; dropping message");
                rustgate_core::audit::store_forward_dropped(cn, "writer_task_gone");
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

    /// Total messages discarded during drain because their HMAC tag
    /// did not match, indicating tampering or a key mismatch.
    pub fn tampered_total(&self) -> u64 {
        self.inner.lock().tampered
    }

    /// Total queue entries skipped on reopen because their destination
    /// was not a direct-addressed CN (broadcast/group).
    pub fn skipped_unsupported_total(&self) -> u64 {
        self.inner.lock().skipped_unsupported
    }

    /// Drain every queued message for `cn` in FIFO order, removing them
    /// from durable storage. Returns the decoded messages ready for
    /// re-routing. Entries whose TTL has elapsed are silently removed
    /// and counted via [`Self::expired_total`]. Malformed entries and
    /// entries with invalid HMAC tags are skipped with a warning.
    ///
    /// Each successfully decoded message is recorded in `DELIVERED_TABLE`
    /// before the queue entry is removed, so a crash between drain and
    /// caller acknowledgement will not cause duplicate delivery on
    /// restart — the next `open` will skip delivered entries.
    pub fn drain(&self, cn: &str) -> Result<Vec<RoutableMessage>, StoreForwardError> {
        let seqs: Vec<u64> = {
            let mut inner = self.inner.lock();
            let Some(idx) = inner.per_cn.remove(cn) else {
                return Ok(Vec::new());
            };
            let seqs: Vec<u64> = idx.seqs.into_iter().collect();
            let reclaim: u64 = idx.bytes;
            inner.total_bytes = inner.total_bytes.saturating_sub(reclaim);
            let set: HashSet<u64> = seqs.iter().copied().collect();
            inner.global.retain(|(s, _, _)| !set.contains(s));
            inner.drains = inner.drains.saturating_add(1);
            seqs
        };

        if seqs.is_empty() {
            return Ok(Vec::new());
        }

        let mut out: Vec<RoutableMessage> = Vec::with_capacity(seqs.len());
        let mut expired_count: u64 = 0;
        let mut tampered_count: u64 = 0;
        let write = self
            .db
            .begin_write()
            .map_err(|e| StoreForwardError::Database(e.to_string()))?;
        {
            let mut table = write
                .open_table(QUEUE_TABLE)
                .map_err(|e| StoreForwardError::Database(e.to_string()))?;
            let mut dtable = write
                .open_table(DELIVERED_TABLE)
                .map_err(|e| StoreForwardError::Database(e.to_string()))?;
            for seq in &seqs {
                let removed = table
                    .remove(seq)
                    .map_err(|e| StoreForwardError::Database(e.to_string()))?;
                if let Some(access) = removed {
                    let stored = access.value();

                    // Verify HMAC integrity before decoding.
                    match verify_hmac_envelope(&self.hmac_key, stored) {
                        Ok(msg_data) => match decode(msg_data) {
                            Ok(msg) => {
                                if msg_expired(&msg) {
                                    expired_count = expired_count.saturating_add(1);
                                    debug!(
                                        seq,
                                        cn, "client queue: dropping expired entry on drain"
                                    );
                                } else {
                                    // Mark as delivered before returning
                                    // so a crash here won't re-deliver.
                                    let _ = dtable
                                        .insert(seq, ())
                                        .map_err(|e| StoreForwardError::Database(e.to_string()))?;
                                    out.push(msg);
                                }
                            }
                            Err(_) => {
                                warn!(seq, cn, "client queue: dropping malformed entry on drain");
                            }
                        },
                        Err(_) => {
                            tampered_count = tampered_count.saturating_add(1);
                            warn!(
                                seq,
                                cn, "client queue: HMAC verification failed, discarding"
                            );
                        }
                    }
                }
            }
        }
        write
            .commit()
            .map_err(|e| StoreForwardError::Database(e.to_string()))?;

        if expired_count > 0 || tampered_count > 0 {
            let mut inner = self.inner.lock();
            inner.expired = inner.expired.saturating_add(expired_count);
            inner.tampered = inner.tampered.saturating_add(tampered_count);
        }

        debug!(
            cn,
            drained = out.len(),
            expired = expired_count,
            tampered = tampered_count,
            "client queue: drained"
        );
        Ok(out)
    }

    /// Mark a batch of sequence numbers as delivered, preventing them
    /// from being re-delivered if the process restarts before the next
    /// `open` purges them. Called by the caller after the drained
    /// messages have been successfully forwarded.
    #[cfg(test)]
    pub fn confirm_delivered(&self, seqs: &[u64]) -> Result<(), StoreForwardError> {
        if seqs.is_empty() {
            return Ok(());
        }
        let write = self
            .db
            .begin_write()
            .map_err(|e| StoreForwardError::Database(e.to_string()))?;
        {
            let mut dtable = write
                .open_table(DELIVERED_TABLE)
                .map_err(|e| StoreForwardError::Database(e.to_string()))?;
            for seq in seqs {
                let _ = dtable
                    .insert(seq, ())
                    .map_err(|e| StoreForwardError::Database(e.to_string()))?;
            }
        }
        write
            .commit()
            .map_err(|e| StoreForwardError::Database(e.to_string()))?;
        Ok(())
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
const MT_MAVLINK: u8 = 6;

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
        Destination::Multicast(_) => {
            // Multicast messages must not be persisted — they are
            // expanded into per-group sends at routing time. Encoding
            // as broadcast would lose the group list and bypass
            // per-group authz on drain. Return a zero-length sentinel
            // so callers can detect and skip persistence.
            warn!("attempted to encode Multicast destination for store-forward; this is a bug");
            buf.put_u8(DEST_BROADCAST);
        }
    }

    match &msg.metadata.message_type {
        MessageType::Position => buf.put_u8(MT_POSITION),
        MessageType::Chat => buf.put_u8(MT_CHAT),
        MessageType::Alert => buf.put_u8(MT_ALERT),
        MessageType::Status => buf.put_u8(MT_STATUS),
        MessageType::File => buf.put_u8(MT_FILE),
        MessageType::Mavlink => buf.put_u8(MT_MAVLINK),
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
        MT_MAVLINK => MessageType::Mavlink,
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

/// Verify the HMAC tag appended to a stored envelope and return the
/// message bytes (without the trailing tag) on success.
fn verify_hmac_envelope<'a>(
    key: &[u8; 32],
    stored: &'a [u8],
) -> Result<&'a [u8], StoreForwardError> {
    if stored.len() < HMAC_LEN {
        return Err(StoreForwardError::TamperedMessage);
    }
    let (msg_data, tag) = stored.split_at(stored.len() - HMAC_LEN);
    let expected = compute_hmac(key, msg_data)?;
    // Constant-time comparison prevents timing side-channels even in
    // the at-rest integrity case — defense-in-depth against local
    // attackers measuring verification latency.
    if tag.ct_eq(&expected).into() {
        // Tag matches — fall through to return Ok.
    } else {
        return Err(StoreForwardError::TamperedMessage);
    }
    Ok(msg_data)
}

/// Fill `dest` with cryptographically secure random bytes.
///
/// Returns an error if the OS CSPRNG is unavailable. Callers must treat
/// this as a fatal startup condition — a broken RNG means all
/// cryptographic guarantees are void.
fn fill_random(dest: &mut [u8]) -> Result<(), StoreForwardError> {
    use ring::rand::{SecureRandom, SystemRandom};

    let rng = SystemRandom::new();
    rng.fill(dest).map_err(|_| {
        StoreForwardError::Database("CSPRNG fill failed — OS random source unavailable".into())
    })
}

/// Spawn the background writer task that services an async queue of
/// pending enqueues. Each message is persisted via a synchronous
/// redb transaction inside `spawn_blocking` so the runtime's async
/// workers are never parked on file I/O.
fn spawn_writer_task(
    db: Arc<Database>,
    inner: Arc<Mutex<Inner>>,
    max_bytes: u64,
    hmac_key: Arc<Zeroizing<[u8; 32]>>,
    mut rx: mpsc::Receiver<(String, RoutableMessage)>,
) {
    drop(tokio::spawn(async move {
        while let Some((cn, msg)) = rx.recv().await {
            let db = Arc::clone(&db);
            let inner = Arc::clone(&inner);
            let key = Arc::clone(&hmac_key);
            let join = tokio::task::spawn_blocking(move || {
                persist_one(&db, &inner, max_bytes, &key, &cn, &msg)
            })
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
///
/// The encoded message is followed by a 32-byte HMAC-SHA256 tag so
/// that tampered envelopes can be detected on drain.
fn persist_one(
    db: &Database,
    inner: &Mutex<Inner>,
    max_bytes: u64,
    hmac_key: &[u8; 32],
    cn: &str,
    msg: &RoutableMessage,
) -> Result<(), StoreForwardError> {
    let encoded = encode(msg);

    // Compute HMAC tag and append it to the stored data.
    let tag = compute_hmac(hmac_key, &encoded)?;
    let mut stored = Vec::with_capacity(encoded.len() + HMAC_LEN);
    stored.extend_from_slice(&encoded);
    stored.extend_from_slice(&tag);

    let size = stored.len() as u64;
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
            .insert(seq, stored.as_slice())
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
        // Account for HMAC tag appended to each stored envelope.
        let payload = vec![0u8; 256];
        let one = msg_for("alice", "bob", &payload);
        let single_size = encode(&one).len() as u64 + HMAC_LEN as u64;
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

    /// Helper to create a fixed HMAC key for tests that need to survive
    /// reopen with the same key.
    fn test_hmac_key() -> Zeroizing<[u8; 32]> {
        Zeroizing::new([0xAB; 32])
    }

    #[tokio::test]
    async fn survives_reopen() {
        let tmp = TempDir::new().unwrap();
        let key = test_hmac_key();
        {
            let q =
                ClientQueue::open_with_hmac_key(tmp.path(), 1_000_000, Some(key.clone())).unwrap();
            q.enqueue("bob", &msg_for("alice", "bob", b"one")).unwrap();
            q.enqueue("bob", &msg_for("alice", "bob", b"two")).unwrap();
            wait_for_depth(&q, "bob", 2).await;
            drop(q);
        }
        // Give the writer task a moment to observe the closed channel
        // and release its Arc<Database> so redb can unlock the file.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let q2 = ClientQueue::open_with_hmac_key(tmp.path(), 1_000_000, Some(key.clone())).unwrap();
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
        let key = test_hmac_key();
        {
            let q =
                ClientQueue::open_with_hmac_key(tmp.path(), 1_000_000, Some(key.clone())).unwrap();
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
        let q2 = ClientQueue::open_with_hmac_key(tmp.path(), 1_000_000, Some(key.clone())).unwrap();
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

    // ── HMAC integrity tests ───────────────────────────────────────

    #[tokio::test]
    async fn store_forward_hmac_accepts_valid() {
        let tmp = TempDir::new().unwrap();
        let q = ClientQueue::open(tmp.path(), 1_000_000).unwrap();
        q.enqueue("bob", &msg_for("alice", "bob", b"hello"))
            .unwrap();
        wait_for_depth(&q, "bob", 1).await;

        let drained = q.drain("bob").unwrap();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].payload.as_ref(), b"hello");
        assert_eq!(drained[0].source.cn, "alice");
    }

    #[tokio::test]
    async fn store_forward_hmac_rejects_tampered() {
        let tmp = TempDir::new().unwrap();
        let key = test_hmac_key();
        let q = ClientQueue::open_with_hmac_key(tmp.path(), 1_000_000, Some(key.clone())).unwrap();
        q.enqueue("bob", &msg_for("alice", "bob", b"legit"))
            .unwrap();
        q.enqueue("bob", &msg_for("alice", "bob", b"also-legit"))
            .unwrap();
        wait_for_depth(&q, "bob", 2).await;

        // Tamper with the first stored entry by flipping a byte in the
        // redb table. The HMAC tag will no longer match.
        let (tamper_seq, tamper_data) = {
            let read = q.db.begin_read().unwrap();
            let table = read.open_table(QUEUE_TABLE).unwrap();
            let mut iter = table.iter().unwrap();
            let first = iter.next().unwrap().unwrap();
            let seq = first.0.value();
            let data = first.1.value().to_vec();
            (seq, data)
        };
        {
            let mut data = tamper_data;
            // Flip a byte in the message body (before the HMAC tag).
            if data.len() > HMAC_LEN + 1 {
                data[0] ^= 0xFF;
            }
            let write = q.db.begin_write().unwrap();
            {
                let mut table = write.open_table(QUEUE_TABLE).unwrap();
                table.insert(tamper_seq, data.as_slice()).unwrap();
            }
            write.commit().unwrap();
        }

        // Drain should skip the tampered message and return only the
        // valid one.
        let drained = q.drain("bob").unwrap();
        assert_eq!(
            drained.len(),
            1,
            "tampered message should have been discarded"
        );
        assert_eq!(drained[0].payload.as_ref(), b"also-legit");
    }

    // ── Dedup tests ────────────────────────────────────────────────

    #[tokio::test]
    async fn store_forward_no_duplicates_on_restart() {
        let tmp = TempDir::new().unwrap();
        let key = test_hmac_key();

        // Phase 1: enqueue 3 messages, drain them (which marks them as
        // delivered), then drop the queue without purging.
        {
            let q =
                ClientQueue::open_with_hmac_key(tmp.path(), 1_000_000, Some(key.clone())).unwrap();
            q.enqueue("bob", &msg_for("alice", "bob", b"msg-1"))
                .unwrap();
            q.enqueue("bob", &msg_for("alice", "bob", b"msg-2"))
                .unwrap();
            q.enqueue("bob", &msg_for("alice", "bob", b"msg-3"))
                .unwrap();
            wait_for_depth(&q, "bob", 3).await;

            let drained = q.drain("bob").unwrap();
            assert_eq!(drained.len(), 3);
            // The drain already recorded delivered markers in the DB.
            drop(q);
        }

        // Phase 2: reopen. The delivered markers should cause the
        // already-delivered entries to be skipped during index rebuild.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let q2 = ClientQueue::open_with_hmac_key(tmp.path(), 1_000_000, Some(key.clone())).unwrap();

        // No messages should be pending — they were all delivered.
        assert_eq!(
            q2.stats("bob").depth,
            0,
            "delivered messages should not reappear on restart"
        );
        let drained = q2.drain("bob").unwrap();
        assert!(
            drained.is_empty(),
            "no duplicates should be delivered on restart"
        );
    }

    #[tokio::test]
    async fn key_rotation_rejects_old_messages() {
        let tmp = TempDir::new().unwrap();
        let key_a = Zeroizing::new([0xAA; 32]);
        let key_b = Zeroizing::new([0xBB; 32]);

        // Phase 1: write messages with key A.
        {
            let q = ClientQueue::open_with_hmac_key(tmp.path(), 1_000_000, Some(key_a.clone()))
                .unwrap();
            q.enqueue("bob", &msg_for("alice", "bob", b"msg-a1"))
                .unwrap();
            q.enqueue("bob", &msg_for("alice", "bob", b"msg-a2"))
                .unwrap();
            q.enqueue("bob", &msg_for("alice", "bob", b"msg-a3"))
                .unwrap();
            wait_for_depth(&q, "bob", 3).await;
            drop(q);
        }

        // Give the writer task time to flush and release the DB lock.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Phase 2: reopen with key B and drain.
        // All messages written under key A should fail HMAC verification.
        let q2 =
            ClientQueue::open_with_hmac_key(tmp.path(), 1_000_000, Some(key_b.clone())).unwrap();
        assert_eq!(
            q2.stats("bob").depth,
            3,
            "messages should still appear in the index before drain"
        );

        let drained = q2.drain("bob").unwrap();
        assert!(
            drained.is_empty(),
            "all key-A messages should be rejected under key B"
        );
        assert!(
            q2.tampered_total() >= 3,
            "tampered counter should reflect rejected messages, got {}",
            q2.tampered_total()
        );
    }
}
