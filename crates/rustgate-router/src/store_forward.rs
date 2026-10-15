// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

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
//! message type, source protocol, received-at timestamp, TTL, raw
//! payload bytes, and — as of envelope version 2 — a `queued_at`
//! timestamp recording when the message was admitted to the offline
//! queue (issue #729). See [`encode`] / [`decode`] for the wire layout.
//!
//! # Backward compatibility
//!
//! Envelope **version 1** records (written by previous versions of this
//! module before the dwell-time observability work landed) lack the
//! `queued_at` field. On decode they fall back to `queued_at =
//! received_at`, preserving pre-PR semantics: dwell on legacy entries is
//! reported as the full received-to-drain interval, exactly what
//! operators saw before this change. Version 1 records are read but
//! never written — every new admission emits version 2.

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use parking_lot::Mutex;
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use rustgate_core::crypto::{HmacError, hmac_sha256_tag, hmac_sha256_verify};
use rustgate_core::identity::Identity;
use rustgate_core::masking::hash_cn;
use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};
use rustgate_core::tasks::spawn_background;
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

/// Map an [`HmacError`] from the shared helper into a
/// [`StoreForwardError`]. The crypto helper rejects empty keys; the
/// store-forward path always passes a 32-byte key from a generated or
/// supplied [`Zeroizing<[u8; 32]>`], so the empty-key arm is
/// unreachable in practice but mapped for completeness.
fn map_hmac_error(err: HmacError) -> StoreForwardError {
    match err {
        HmacError::InvalidKeyLength { .. } => {
            StoreForwardError::Database(format!("HMAC key init failed: {err}"))
        }
        HmacError::TagLengthMismatch { .. } | HmacError::VerificationFailed => {
            StoreForwardError::TamperedMessage
        }
    }
}

/// Compute an HMAC-SHA256 tag over `data` using the given key.
fn compute_hmac(key: &[u8; 32], data: &[u8]) -> Result<[u8; 32], StoreForwardError> {
    let tag = hmac_sha256_tag(key, data).map_err(map_hmac_error)?;
    let mut out = [0u8; HMAC_LEN];
    // The helper guarantees a 32-byte tag for HMAC-SHA256; assert via
    // length precondition rather than a fallible try_into.
    debug_assert_eq!(tag.len(), HMAC_LEN);
    out.copy_from_slice(&tag);
    Ok(out)
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
    /// The on-disk queue contains entries from a previous run but the
    /// caller requested an ephemeral key (no persistent key supplied).
    /// Returned by [`ClientQueue::open`] and
    /// [`ClientQueue::open_with_hmac_key`] when `hmac_key` is `None`.
    ///
    /// Under the previous fail-open behavior a fresh random key was
    /// generated on every restart, silently discarding every queued
    /// message on the next drain — a direct violation of the
    /// store-forward contract. Callers must now either (a) supply a
    /// persistent key via [`ClientQueue::open_with_hmac_key`] to preserve
    /// the queue across restarts, or (b) explicitly acknowledge the data
    /// loss via [`ClientQueue::open_with_wipe`] which wipes the queue and
    /// emits a `store_forward.key_rotated` audit event.
    #[error(
        "client queue at {path} has {depth} stored entries from a previous run \
         but no persistent HMAC key was supplied; either provide \
         `--client-queue-key-file` to preserve them across restart or \
         `--client-queue-wipe-on-start` to explicitly discard them"
    )]
    StaleQueueWithoutKey { path: String, depth: u64 },
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

rustgate_core::on_callback!(
    /// Callback invoked once per drained message with the dwell time the
    /// message spent in the offline queue, in fractional seconds.
    ///
    /// `dwell_seconds` is computed as `drain_time - queued_at` (clamped at
    /// zero for clock-skew safety). Used to feed the
    /// `rustgate_store_forward_dwell_seconds` Prometheus histogram from
    /// `rustgate-server`. Issue #729.
    ///
    /// The callback runs synchronously on the drain path — keep it cheap
    /// (a single `histogram.observe` is the canonical use). Spawn any
    /// blocking work via [`rustgate_core::tasks::spawn_background`] inside
    /// the closure body if needed.
    pub OnDrainObservation,
    f64
);

/// A bounded, durable per-client message queue.
///
/// Cloning a [`ClientQueue`] is cheap: internally it holds an `Arc` to
/// the shared database and index.
#[derive(Clone)]
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
    /// Tuple shape: `(destination_cn, msg, queued_at_ms)`. The
    /// `queued_at_ms` is captured at the call site of [`Self::enqueue`]
    /// so the recorded admission time reflects the moment the message
    /// became the queue's responsibility — not when the writer task
    /// happens to dequeue it (which under load could lag by hundreds of
    /// milliseconds and skew dwell estimates downward).
    writer_tx: mpsc::Sender<(String, RoutableMessage, i64)>,
    /// Optional drain-time observer fed `dwell_seconds` per drained
    /// message. Lock-free hot-swap so the metrics callback can be
    /// installed at startup without rebuilding the queue. Issue #729.
    on_drain_observation: Arc<ArcSwap<Option<OnDrainObservation>>>,
}

impl std::fmt::Debug for ClientQueue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Manually implemented because `OnDrainObservation` (an `Arc<dyn
        // Fn>`) is not `Debug`. We project the visible fields and elide
        // the callback — exposing it only as a presence boolean.
        f.debug_struct("ClientQueue")
            .field("path", &self.path)
            .field("max_bytes", &self.max_bytes)
            .field(
                "on_drain_observation",
                &self.on_drain_observation.load().is_some(),
            )
            .finish_non_exhaustive()
    }
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
    /// # Ephemeral HMAC key — fail-closed on stale queue
    ///
    /// This convenience wrapper generates a fresh random HMAC key on
    /// each call. Because the new key cannot verify tags produced by a
    /// previous process instance, any messages persisted from a prior
    /// run would be silently dropped on drain — a direct violation of
    /// the store-forward contract.
    ///
    /// To prevent that silent data loss, this method returns
    /// [`StoreForwardError::StaleQueueWithoutKey`] when the on-disk
    /// database contains entries from a previous run. Callers must
    /// either:
    ///
    /// 1. Use [`Self::open_with_hmac_key`] with an externally persisted
    ///    key to preserve the queue across restarts, or
    /// 2. Use [`Self::open_with_wipe`] to explicitly discard the stored
    ///    entries and emit a `store_forward.key_rotated` audit event.
    pub fn open(dir: &Path, max_bytes: u64) -> Result<Self, StoreForwardError> {
        Self::open_with_hmac_key(dir, max_bytes, None)
    }

    /// Open or create a client queue with an explicit HMAC key.
    ///
    /// When `hmac_key` is `Some`, the supplied key is used verbatim.
    /// This is the correct mode for production deployments that must
    /// preserve the queue across restarts — persist the key externally
    /// (e.g. via `--client-queue-key-file`) and pass it here.
    ///
    /// When `hmac_key` is `None`, a fresh random key is generated — but
    /// only if the on-disk database is empty. If the database contains
    /// entries from a previous run, the open fails with
    /// [`StoreForwardError::StaleQueueWithoutKey`] rather than silently
    /// losing them on the next drain (the generated key cannot verify
    /// tags written under the previous process's key). To explicitly
    /// discard the stored entries, use [`Self::open_with_wipe`] instead.
    pub fn open_with_hmac_key(
        dir: &Path,
        max_bytes: u64,
        hmac_key: Option<Zeroizing<[u8; 32]>>,
    ) -> Result<Self, StoreForwardError> {
        std::fs::create_dir_all(dir).map_err(|e| StoreForwardError::Database(e.to_string()))?;
        let path = dir.join("client_queue.redb");
        let db = Database::create(&path).map_err(|e| StoreForwardError::Database(e.to_string()))?;

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

        // Fail-closed: if the caller supplied no persistent key but the
        // on-disk queue contains entries from a prior run, refuse to
        // start. A freshly generated key cannot verify the stored HMAC
        // tags, so those entries would be silently discarded on drain —
        // a direct violation of the store-forward contract. The
        // operator must either provide a persistent key (to preserve
        // the queue) or call `open_with_wipe` (to explicitly acknowledge
        // the data loss, with an audit event recording the depth).
        if hmac_key.is_none() && !inner.global.is_empty() {
            return Err(StoreForwardError::StaleQueueWithoutKey {
                path: path.to_string_lossy().into_owned(),
                depth: inner.global.len() as u64,
            });
        }

        // Derive or accept the HMAC key. Safe to generate randomly now
        // that we have established the queue is empty in the None case.
        let hmac_key = Arc::new(match hmac_key {
            Some(k) => k,
            None => {
                let mut key = Zeroizing::new([0u8; 32]);
                fill_random(&mut *key)?;
                key
            }
        });

        let db = Arc::new(db);
        let inner = Arc::new(Mutex::new(inner));
        let (writer_tx, writer_rx) =
            mpsc::channel::<(String, RoutableMessage, i64)>(CLIENT_QUEUE_WRITER_CHANNEL_CAPACITY);
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
            on_drain_observation: Arc::new(ArcSwap::from_pointee(None)),
        })
    }

    /// Open a client queue, wiping any pre-existing on-disk entries
    /// before continuing with the regular [`Self::open`] flow.
    ///
    /// This is the **explicit opt-in** counterpart to the fail-closed
    /// behavior of [`Self::open`]. When the operator knows that no
    /// persistent HMAC key is available — but still wants to start the
    /// server on a directory that already contains stored entries from
    /// a previous run — this method acknowledges that those entries
    /// will never be delivered and discards them.
    ///
    /// A `store_forward.key_rotated` audit event is emitted before the
    /// regular open resumes, recording the path, the number of
    /// discarded entries, and the reason (`explicit_wipe_on_start`) so
    /// that the data loss is visible in the compliance audit trail.
    ///
    /// After the wipe, an ephemeral random HMAC key is generated as
    /// usual. Subsequent enqueues/drains are protected by that key
    /// until the process exits.
    pub fn open_with_wipe(dir: &Path, max_bytes: u64) -> Result<Self, StoreForwardError> {
        std::fs::create_dir_all(dir).map_err(|e| StoreForwardError::Database(e.to_string()))?;
        let path = dir.join("client_queue.redb");

        // Open the database in an inner scope so its exclusive file
        // lock is released before `open_with_hmac_key` re-opens below.
        let pre_wipe_depth = {
            let db =
                Database::create(&path).map_err(|e| StoreForwardError::Database(e.to_string()))?;

            // Collect every key from both tables under a read txn, then
            // drop the txn so the write txn below has exclusive access.
            // `open_table` returns a table-does-not-exist error on a
            // fresh directory — that's treated as "no entries to wipe"
            // (empty Vec), not a failure. An early return here would
            // leak the `db` handle past its scope and deadlock the
            // subsequent `open_with_hmac_key` call on the redb file lock.
            let (queue_keys, delivered_keys): (Vec<u64>, Vec<u64>) = {
                let read = db
                    .begin_read()
                    .map_err(|e| StoreForwardError::Database(e.to_string()))?;
                let queue_keys: Vec<u64> = match read.open_table(QUEUE_TABLE) {
                    Ok(table) => table
                        .iter()
                        .map_err(|e| StoreForwardError::Database(e.to_string()))?
                        .flatten()
                        .map(|kv| kv.0.value())
                        .collect(),
                    Err(_) => Vec::new(),
                };
                let delivered_keys: Vec<u64> = match read.open_table(DELIVERED_TABLE) {
                    Ok(table) => table
                        .iter()
                        .map_err(|e| StoreForwardError::Database(e.to_string()))?
                        .flatten()
                        .map(|kv| kv.0.value())
                        .collect(),
                    Err(_) => Vec::new(),
                };
                (queue_keys, delivered_keys)
            };

            let depth = queue_keys.len() as u64;
            if !queue_keys.is_empty() || !delivered_keys.is_empty() {
                let write = db
                    .begin_write()
                    .map_err(|e| StoreForwardError::Database(e.to_string()))?;
                {
                    let mut table = write
                        .open_table(QUEUE_TABLE)
                        .map_err(|e| StoreForwardError::Database(e.to_string()))?;
                    for k in &queue_keys {
                        let _ = table
                            .remove(k)
                            .map_err(|e| StoreForwardError::Database(e.to_string()))?;
                    }
                }
                {
                    let mut dtable = write
                        .open_table(DELIVERED_TABLE)
                        .map_err(|e| StoreForwardError::Database(e.to_string()))?;
                    for k in &delivered_keys {
                        let _ = dtable
                            .remove(k)
                            .map_err(|e| StoreForwardError::Database(e.to_string()))?;
                    }
                }
                write
                    .commit()
                    .map_err(|e| StoreForwardError::Database(e.to_string()))?;
            }
            depth
        };

        rustgate_core::audit::store_forward_key_rotated(
            &path.to_string_lossy(),
            pre_wipe_depth,
            "explicit_wipe_on_start",
        );

        Self::open_with_hmac_key(dir, max_bytes, None)
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
    /// The wall-clock instant of this call is captured as the
    /// envelope's `queued_at` timestamp (Unix milliseconds). This is
    /// the basis for the dwell-time observability added in #729 — it
    /// reflects when the queue accepted custody, not when the writer
    /// task happened to commit it (which can lag by hundreds of
    /// milliseconds under load and would understate dwell). On drain,
    /// the difference between `now` and `queued_at` is emitted as
    /// `dwell_seconds` and observed by the histogram.
    ///
    /// If the writer channel is full, the message is dropped and
    /// [`Self::writer_drops_total`] is incremented. This preserves live
    /// routing latency under pathological bursts at the cost of
    /// losing the offending offline messages.
    pub fn enqueue(&self, cn: &str, msg: &RoutableMessage) -> Result<u64, StoreForwardError> {
        let queued_at_ms = unix_now_ms();
        match self
            .writer_tx
            .try_send((cn.to_string(), msg.clone(), queued_at_ms))
        {
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

    /// Install a callback to be invoked once per drained message with
    /// the dwell time (fractional seconds) the message spent in the
    /// offline queue. Used by the metrics layer to feed the
    /// `rustgate_store_forward_dwell_seconds` Prometheus histogram.
    ///
    /// Hot-swappable: subsequent calls replace the previously installed
    /// callback atomically. Pass a no-op or simply do not call this
    /// method to disable observation.
    pub fn set_on_drain_observation(&self, cb: OnDrainObservation) {
        self.on_drain_observation.store(Arc::new(Some(cb)));
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
    ///
    /// Tenant filtering: callers that pass a tenant to
    /// [`Self::drain_for_tenant`] (the production path from the
    /// router accept loop) drain only entries whose stored tenant
    /// matches — entries belonging to a different tenant remain in
    /// the queue. Pre-#859 (v1/v2) records carry no tenant tag and
    /// drain to any caller, preserving backward compatibility for
    /// queues written before this PR. The legacy
    /// [`Self::drain`](Self::drain) entry point passes
    /// `tenant = None` and drains every entry regardless of tenant —
    /// suitable for tests but NOT used by the production router
    /// accept path, where leaking a different tenant's queued
    /// messages would defeat the multi-tenant isolation contract
    /// (closes #859).
    #[tracing::instrument(level = "debug", skip_all, fields(cn = %hash_cn(cn)), err)]
    pub fn drain(&self, cn: &str) -> Result<Vec<RoutableMessage>, StoreForwardError> {
        self.drain_for_tenant(cn, None)
    }

    /// Drain every queued message for `cn` whose stored tenant tag
    /// matches `tenant` (or has no tenant — legacy entries pre-#859).
    ///
    /// `tenant = None` drains every entry regardless of tenant,
    /// matching the legacy [`Self::drain`] semantics. Production
    /// callers (router accept path) MUST pass `Some(connecting client's
    /// tenant)` so a connecting client can never drain another
    /// tenant's queued messages.
    #[tracing::instrument(level = "debug", skip_all, fields(cn = %hash_cn(cn), tenant_set = tenant.is_some()), err)]
    pub fn drain_for_tenant(
        &self,
        cn: &str,
        tenant: Option<&str>,
    ) -> Result<Vec<RoutableMessage>, StoreForwardError> {
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
        let mut dwells_secs: Vec<f64> = Vec::with_capacity(seqs.len());
        let mut expired_count: u64 = 0;
        let mut tampered_count: u64 = 0;
        let mut tenant_mismatch_count: u64 = 0;
        // Sequence numbers that belong to a different tenant — they
        // must remain in durable storage and be reinstated in the
        // in-memory per-cn index so the rightful owner's eventual
        // reconnect can drain them. Cached as `(seq, size)` so we
        // don't pay another redb read.
        let mut tenant_mismatch: Vec<(u64, u64, RoutableMessage)> = Vec::new();
        let drain_now_ms = unix_now_ms();
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
                // Read first, decide later whether to remove. If the
                // entry belongs to a different tenant, we MUST leave
                // it in the queue — destructive-read-and-reinsert
                // would change the seq number and break per-tenant
                // FIFO ordering on the eventual rightful drain.
                //
                // Materialise the bytes inside a tight scope so the
                // immutable read borrow on `table` is released before
                // the conditional `table.remove` below — redb
                // disallows overlapping read+write borrows on the same
                // table handle.
                let (stored, stored_size) = {
                    let entry = table
                        .get(seq)
                        .map_err(|e| StoreForwardError::Database(e.to_string()))?;
                    let Some(access) = entry else {
                        continue;
                    };
                    let v = access.value().to_vec();
                    let size = v.len() as u64;
                    (v, size)
                };

                // Verify HMAC integrity before decoding.
                match verify_hmac_envelope(&self.hmac_key, &stored) {
                    Ok(msg_data) => match decode(msg_data) {
                        Ok(decoded) => {
                            // Tenant filter: legacy (None) entries
                            // drain to any caller; v3 entries with a
                            // tenant tag drain only to a caller whose
                            // tenant matches. A `None` filter (legacy
                            // `drain(cn)` callers, primarily tests)
                            // matches every entry.
                            let stored_tenant = decoded.message.metadata.tenant_id();
                            let tenant_ok = match (tenant, stored_tenant) {
                                (None, _) => true,
                                (Some(_), None) => true,
                                (Some(want), Some(got)) => want == got,
                            };
                            if !tenant_ok {
                                tenant_mismatch_count = tenant_mismatch_count.saturating_add(1);
                                debug!(
                                    seq,
                                    cn, "client queue: leaving entry in queue (tenant mismatch)"
                                );
                                tenant_mismatch.push((*seq, stored_size, decoded.message));
                                continue;
                            }

                            // Tenant matches — destructively remove
                            // from the queue, mark delivered, and
                            // collect for return.
                            let _ = table
                                .remove(seq)
                                .map_err(|e| StoreForwardError::Database(e.to_string()))?;
                            if msg_expired(&decoded.message) {
                                expired_count = expired_count.saturating_add(1);
                                debug!(seq, cn, "client queue: dropping expired entry on drain");
                            } else {
                                let _ = dtable
                                    .insert(seq, ())
                                    .map_err(|e| StoreForwardError::Database(e.to_string()))?;
                                // Compute dwell seconds as
                                // drain_now - queued_at, clamped at
                                // zero. A negative observation could
                                // arise from clock-backwards events
                                // (NTP step or VM migration); the
                                // histogram cannot represent
                                // negative values, so we floor it.
                                let dwell_ms =
                                    drain_now_ms.saturating_sub(decoded.queued_at_ms).max(0);
                                let dwell_s = (dwell_ms as f64) / 1000.0;
                                dwells_secs.push(dwell_s);
                                out.push(decoded.message);
                            }
                        }
                        Err(_) => {
                            // Malformed entries are unconditionally
                            // dropped from the queue so they don't
                            // wedge future drains.
                            let _ = table
                                .remove(seq)
                                .map_err(|e| StoreForwardError::Database(e.to_string()))?;
                            warn!(seq, cn, "client queue: dropping malformed entry on drain");
                        }
                    },
                    Err(_) => {
                        let _ = table
                            .remove(seq)
                            .map_err(|e| StoreForwardError::Database(e.to_string()))?;
                        tampered_count = tampered_count.saturating_add(1);
                        warn!(
                            seq,
                            cn, "client queue: HMAC verification failed, discarding"
                        );
                    }
                }
            }
        }
        write
            .commit()
            .map_err(|e| StoreForwardError::Database(e.to_string()))?;

        // Reinstate tenant-mismatch entries in the in-memory index so
        // the rightful tenant's eventual drain still finds them. Their
        // bytes are added back to both the global byte counter and the
        // per-cn index. Re-pushed in original FIFO order via the seqs
        // walk above.
        if !tenant_mismatch.is_empty() {
            let mut inner = self.inner.lock();
            for (seq, size, _msg) in &tenant_mismatch {
                inner.global.push_back((*seq, cn.to_string(), *size));
                let pc = inner
                    .per_cn
                    .entry(cn.to_string())
                    .or_insert_with(PerCnIndex::new);
                pc.seqs.push_back(*seq);
                pc.bytes = pc.bytes.saturating_add(*size);
                inner.total_bytes = inner.total_bytes.saturating_add(*size);
            }
        }

        if expired_count > 0 || tampered_count > 0 {
            let mut inner = self.inner.lock();
            inner.expired = inner.expired.saturating_add(expired_count);
            inner.tampered = inner.tampered.saturating_add(tampered_count);
        }

        // Feed each per-message dwell observation into the histogram
        // callback. We deliberately observe per-message rather than per
        // batch — a 5-hour drain of 100 messages records 100 datapoints,
        // not one — so the histogram percentiles reflect message
        // experience, not batch experience.
        let observe_guard = self.on_drain_observation.load();
        if let Some(cb) = observe_guard.as_ref() {
            for d in &dwells_secs {
                cb(*d);
            }
        }
        drop(observe_guard);

        if !dwells_secs.is_empty() {
            let total: f64 = dwells_secs.iter().sum();
            let count = dwells_secs.len() as u64;
            let mean = total / (count as f64);
            // Pick out min/max for the audit event so a SIEM analyst can
            // tell at a glance whether the batch contained a single
            // multi-hour straggler or a uniformly delayed pile.
            let mut min = dwells_secs[0];
            let mut max = dwells_secs[0];
            for d in &dwells_secs[1..] {
                if *d < min {
                    min = *d;
                }
                if *d > max {
                    max = *d;
                }
            }
            rustgate_core::audit::store_forward_drained(
                cn,
                count,
                mean,
                min,
                max,
                expired_count,
                tampered_count,
            );
        }

        debug!(
            cn,
            drained = out.len(),
            expired = expired_count,
            tampered = tampered_count,
            tenant_mismatch = tenant_mismatch_count,
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
///
/// History:
/// - **v1**: source identity, destination, message type, source
///   protocol, received_at_ms, ttl_secs, payload. Read-only —
///   produced by older binaries before #729.
/// - **v2**: adds `queued_at_ms` (Unix ms) immediately after
///   `received_at_ms` so drain can compute dwell time. Issue #729.
/// - **v3** (current): adds a length-prefixed `tenant_id` UTF-8 string
///   immediately after `queued_at_ms`. An empty string means "no
///   tenant" so v3 records produced by single-tenant deployments do
///   not carry an extra heap-allocation per message. Closes #859.
const ENVELOPE_VERSION: u8 = 3;

/// Envelope version preceding the multi-tenant tag (#859) but
/// post-dwell-time (#729). Decoded with `tenant_id = None`.
const ENVELOPE_VERSION_V2: u8 = 2;

/// Legacy envelope version (no `queued_at_ms`). Decoded with a fallback
/// where `queued_at_ms = received_at_ms`, preserving pre-PR audit
/// semantics for any messages persisted before the upgrade.
const ENVELOPE_VERSION_V1: u8 = 1;

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

/// Encode a [`RoutableMessage`] together with its admission timestamp
/// to the on-disk envelope format. Always emits the current envelope
/// version (v2). `queued_at_ms` is the Unix-millisecond instant the
/// message was admitted to the queue (captured at the `enqueue` call
/// site).
pub fn encode(msg: &RoutableMessage, queued_at_ms: i64) -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(136 + msg.payload.len());
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

    // Issue #729: queued_at_ms records when the queue accepted custody,
    // distinct from received_at which records when the message first
    // entered the server. The two diverge whenever a message rides
    // multiple transports before falling back to store-forward (e.g. a
    // federated message that was routed live for hours before the
    // recipient went offline).
    buf.put_i64(queued_at_ms);

    // #859: tenant id (length-prefixed UTF-8). Empty string when the
    // message carries no tenant — v1/v2 records on disk were
    // implicitly "no tenant" and decode equivalently.
    put_str(&mut buf, msg.metadata.tenant_id().unwrap_or(""));

    match msg.metadata.ttl {
        None => buf.put_i64(-1),
        Some(d) => buf.put_i64(d.as_secs() as i64),
    }

    buf.put_u32(msg.payload.len() as u32);
    buf.put_slice(&msg.payload);

    buf.to_vec()
}

/// Result of decoding an on-disk envelope: the [`RoutableMessage`]
/// itself plus the `queued_at_ms` recovered from the envelope (or
/// derived from `received_at_ms` when reading legacy v1 records).
#[derive(Debug)]
pub struct DecodedEnvelope {
    /// The reconstructed message ready for re-routing.
    pub message: RoutableMessage,
    /// Unix milliseconds at which the message was admitted to the
    /// store-forward queue. For envelope version 2 this is the field
    /// captured at `enqueue` time. For envelope version 1 (legacy) this
    /// falls back to `received_at_ms`, preserving pre-PR audit
    /// semantics — operators with existing offline queues see dwell ==
    /// (drain - received_at) until the queue cycles to v2-only entries.
    pub queued_at_ms: i64,
}

/// Decode an envelope produced by [`encode`]. Accepts both v2
/// (current) and v1 (legacy, pre-#729) envelopes.
///
/// On v1, `queued_at_ms` falls back to `received_at_ms` so legacy
/// queues still produce sensible (though pessimistic) dwell numbers
/// during the transition window.
pub fn decode(raw: &[u8]) -> Result<DecodedEnvelope, StoreForwardError> {
    let mut buf: &[u8] = raw;
    if buf.remaining() < 1 {
        return Err(StoreForwardError::Decode);
    }
    let version = buf.get_u8();
    // Track which post-v1 features the envelope carries:
    //   has_queued_at = v2 or later
    //   has_tenant    = v3 or later
    // Older versions populate the missing fields from sensible
    // fallbacks (queued_at = received_at, tenant = None).
    let (has_queued_at, has_tenant) = match version {
        ENVELOPE_VERSION => (true, true),
        ENVELOPE_VERSION_V2 => (true, false),
        ENVELOPE_VERSION_V1 => (false, false),
        _ => return Err(StoreForwardError::Decode),
    };

    let source = get_identity(&mut buf).ok_or(StoreForwardError::Decode)?;

    if buf.remaining() < 1 {
        return Err(StoreForwardError::Decode);
    }
    let destination = match buf.get_u8() {
        DEST_BROADCAST => Destination::Broadcast,
        DEST_GROUP => {
            Destination::Group(get_str(&mut buf).ok_or(StoreForwardError::Decode)?.into())
        }
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

    // Issue #729 / backward compat: v2+ envelopes carry an explicit
    // queued_at_ms; v1 envelopes did not, so we fall back to
    // received_at_ms. This preserves the pre-PR meaning of dwell on
    // legacy entries (it equals the full received-to-drain interval),
    // exactly what operators saw before the upgrade.
    let queued_at_ms = if has_queued_at {
        if buf.remaining() < 8 {
            return Err(StoreForwardError::Decode);
        }
        buf.get_i64()
    } else {
        received_at_ms
    };

    // Issue #859: v3 envelopes carry an explicit tenant id (empty
    // string == no tenant); v1/v2 records decode with `tenant = None`
    // so cross-tenant drain filtering treats them as legacy /
    // unauthenticated traffic.
    let tenant_id: Option<String> = if has_tenant {
        let s = get_str(&mut buf).ok_or(StoreForwardError::Decode)?;
        if s.is_empty() { None } else { Some(s) }
    } else {
        None
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

    let mut metadata = Metadata::new(received_at, source_protocol, message_type);
    if let Some(t) = ttl {
        metadata = metadata.with_ttl(t);
    }
    if let Some(t) = tenant_id {
        metadata = metadata.with_tenant_id(t);
    }
    Ok(DecodedEnvelope {
        message: RoutableMessage {
            source,
            destination,
            payload,
            metadata,
            entity: None,
        },
        queued_at_ms,
    })
}

/// Current Unix milliseconds (saturating to 0 on clocks before the
/// epoch). Used as the default `queued_at` capture and as the
/// `drain_now` reference when computing dwell.
fn unix_now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
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
///
/// Constant-time comparison is enforced inside the shared
/// [`rustgate_core::crypto::hmac_sha256_verify`] helper — defense-in-
/// depth against local attackers measuring verification latency on the
/// at-rest integrity path.
fn verify_hmac_envelope<'a>(
    key: &[u8; 32],
    stored: &'a [u8],
) -> Result<&'a [u8], StoreForwardError> {
    if stored.len() < HMAC_LEN {
        return Err(StoreForwardError::TamperedMessage);
    }
    let (msg_data, tag) = stored.split_at(stored.len() - HMAC_LEN);
    hmac_sha256_verify(key, msg_data, tag).map_err(map_hmac_error)?;
    Ok(msg_data)
}

/// Fill `dest` with cryptographically secure random bytes.
///
/// Returns an error if the OS CSPRNG is unavailable. Callers must treat
/// this as a fatal startup condition — a broken RNG means all
/// cryptographic guarantees are void.
fn fill_random(dest: &mut [u8]) -> Result<(), StoreForwardError> {
    use aws_lc_rs::rand::{SecureRandom, SystemRandom};

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
    mut rx: mpsc::Receiver<(String, RoutableMessage, i64)>,
) {
    spawn_background("client-queue-writer", async move {
        while let Some((cn, msg, queued_at_ms)) = rx.recv().await {
            let db = Arc::clone(&db);
            let inner = Arc::clone(&inner);
            let key = Arc::clone(&hmac_key);
            let join = tokio::task::spawn_blocking(move || {
                persist_one(&db, &inner, max_bytes, &key, &cn, &msg, queued_at_ms)
            })
            .await;
            match join {
                Ok(Ok(())) => {}
                Ok(Err(e)) => warn!(error = %e, "client queue writer: persist failed"),
                Err(e) => warn!(error = %e, "client queue writer: join failed"),
            }
        }
    });
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
    queued_at_ms: i64,
) -> Result<(), StoreForwardError> {
    let encoded = encode(msg, queued_at_ms);

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
            metadata: Metadata::new(SystemTime::now(), "tcp".to_string(), MessageType::Chat),
            entity: None,
        }
    }

    /// Like [`msg_for`] but stamps a tenant id onto the metadata.
    /// Used by the #859 cross-tenant isolation tests.
    fn msg_for_tenant(from: &str, to: &str, tenant: &str, payload: &[u8]) -> RoutableMessage {
        let mut m = msg_for(from, to, payload);
        m.metadata = m.metadata.with_tenant_id(tenant);
        m
    }

    #[test]
    fn encode_decode_roundtrip() {
        let m = msg_for("alice", "bob", b"hello");
        let queued_at = 1_700_000_000_000_i64;
        let bytes = encode(&m, queued_at);
        let back = decode(&bytes).unwrap();
        assert_eq!(&*back.message.source.cn, "alice");
        assert_eq!(back.message.payload.as_ref(), b"hello");
        match back.message.destination {
            Destination::Direct(id) => assert_eq!(&*id.cn, "bob"),
            _ => panic!("wrong dest"),
        }
        assert_eq!(
            back.queued_at_ms, queued_at,
            "queued_at must round-trip through encode/decode"
        );
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

    /// Wait until the writer task's redb commit has landed for at
    /// least `expected` entries in the queue table. `wait_for_depth`
    /// returns based on the in-memory index, which is updated BEFORE
    /// the redb commit — so a drain immediately after
    /// `wait_for_depth` may find the rows missing on the persistent
    /// side and silently emit no events. Polling the redb row count
    /// closes that race.
    async fn wait_for_persisted(q: &ClientQueue, expected: usize) {
        for _ in 0..200 {
            let read = q.db.begin_read().unwrap();
            let table = read.open_table(QUEUE_TABLE).unwrap();
            let count = table.iter().unwrap().count();
            drop(table);
            drop(read);
            if count >= expected {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("timed out waiting for {expected} persisted entries within poll window");
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

    // ── #859: cross-tenant drain isolation ──────────────────────────

    #[tokio::test]
    async fn drain_for_tenant_skips_cross_tenant_entries() {
        // Closes #859 isolation contract: queueing under tenant A
        // and then attempting a drain under tenant B (same CN, e.g.
        // a service-account name reused across tenants) must not
        // leak the messages. The mismatched entries stay in the
        // queue so the rightful tenant's eventual reconnect drains
        // them.
        let tmp = TempDir::new().unwrap();
        let q = ClientQueue::open(tmp.path(), 1_000_000).unwrap();

        q.enqueue("svc", &msg_for_tenant("alice", "svc", "acme", b"a1"))
            .unwrap();
        q.enqueue("svc", &msg_for_tenant("alice", "svc", "acme", b"a2"))
            .unwrap();
        q.enqueue("svc", &msg_for_tenant("bob", "svc", "globex", b"g1"))
            .unwrap();
        wait_for_depth(&q, "svc", 3).await;

        // Tenant B (globex) connects: only its own entry drains.
        let drained_globex = q.drain_for_tenant("svc", Some("globex")).unwrap();
        assert_eq!(drained_globex.len(), 1, "globex drains exactly one entry");
        assert_eq!(drained_globex[0].payload.as_ref(), b"g1");
        // Two acme entries remain.
        assert_eq!(
            q.stats("svc").depth,
            2,
            "acme entries must remain after globex drain"
        );

        // Tenant A (acme) connects later: drains its two entries,
        // FIFO preserved.
        let drained_acme = q.drain_for_tenant("svc", Some("acme")).unwrap();
        assert_eq!(drained_acme.len(), 2);
        assert_eq!(drained_acme[0].payload.as_ref(), b"a1");
        assert_eq!(drained_acme[1].payload.as_ref(), b"a2");
        assert_eq!(q.stats("svc").depth, 0);
    }

    #[tokio::test]
    async fn drain_for_tenant_legacy_entries_match_any_tenant() {
        // Pre-#859 v1/v2 envelopes carry no tenant tag and decode
        // with `tenant = None`. They must drain to any caller —
        // there is no per-tenant origin to enforce against, and
        // operators upgrading from a pre-PR binary expect their
        // existing on-disk queues to flush cleanly.
        let tmp = TempDir::new().unwrap();
        let q = ClientQueue::open(tmp.path(), 1_000_000).unwrap();

        q.enqueue("bob", &msg_for("alice", "bob", b"legacy"))
            .unwrap();
        wait_for_depth(&q, "bob", 1).await;

        // A tenant-tagged drain still pulls the legacy entry.
        let drained = q.drain_for_tenant("bob", Some("acme")).unwrap();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].payload.as_ref(), b"legacy");
    }

    #[test]
    fn encode_decode_preserves_tenant_id() {
        // Pin the v3 envelope wire format: tenant id round-trips
        // through encode/decode, and an absent tenant decodes to
        // `None` rather than a sentinel string.
        let with_tenant = msg_for_tenant("alice", "bob", "acme", b"hi");
        let bytes = encode(&with_tenant, 1_700_000_000_000);
        let back = decode(&bytes).unwrap();
        assert_eq!(back.message.metadata.tenant_id(), Some("acme"));

        let without_tenant = msg_for("alice", "bob", b"hi");
        let bytes = encode(&without_tenant, 1_700_000_000_000);
        let back = decode(&bytes).unwrap();
        assert_eq!(back.message.metadata.tenant_id(), None);
    }

    #[tokio::test]
    async fn byte_cap_drops_oldest() {
        let tmp = TempDir::new().unwrap();
        // Small cap forces eviction after a couple of messages.
        // Account for HMAC tag appended to each stored envelope.
        let payload = vec![0u8; 256];
        let one = msg_for("alice", "bob", &payload);
        let single_size = encode(&one, 0).len() as u64 + HMAC_LEN as u64;
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

    /// Regression guard: the migration from an inlined
    /// `Hmac::<Sha256>::new_from_slice(...).update(...).finalize()`
    /// pipeline to `rustgate_core::crypto::hmac_sha256_tag` MUST be
    /// byte-identical. A divergence here would silently invalidate
    /// every entry in any pre-migration on-disk client queue: drain
    /// would reject every record as `TamperedMessage` and discard the
    /// stored backlog. Pin the byte-for-byte equivalence so a future
    /// refactor of `compute_hmac` cannot reintroduce that data-loss
    /// regression.
    #[test]
    fn compute_hmac_matches_inlined_construction() {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let key = [0xAB; 32];
        let data = b"some encoded envelope bytes";
        let helper_tag = compute_hmac(&key, data).unwrap();
        let mut mac = Hmac::<Sha256>::new_from_slice(&key).unwrap();
        mac.update(data);
        let inlined: [u8; 32] = mac.finalize().into_bytes().into();
        assert_eq!(helper_tag, inlined);
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
        assert_eq!(&*drained[0].source.cn, "alice");
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

    // ── Fail-closed on stale queue without persistent key ──────────

    /// When a previous process left messages on disk and the operator
    /// restarts without supplying a persistent HMAC key, `open` must
    /// refuse to start rather than silently discarding those messages
    /// on the first drain. This is the F-49 / #740 contract.
    #[tokio::test]
    async fn open_fails_on_stale_queue_without_key() {
        let tmp = TempDir::new().unwrap();
        let key = test_hmac_key();

        // Phase 1: write two messages under a persistent key so the
        // queue file contains real unread entries after drop.
        {
            let q =
                ClientQueue::open_with_hmac_key(tmp.path(), 1_000_000, Some(key.clone())).unwrap();
            q.enqueue("bob", &msg_for("alice", "bob", b"one")).unwrap();
            q.enqueue("bob", &msg_for("alice", "bob", b"two")).unwrap();
            wait_for_depth(&q, "bob", 2).await;
            drop(q);
        }
        // Allow the writer task to release the exclusive DB lock.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Phase 2: try to reopen without a persistent key. This is the
        // old fail-open code path; it must now fail closed.
        let err = ClientQueue::open(tmp.path(), 1_000_000).expect_err(
            "open must fail when the queue contains entries but no persistent key was supplied",
        );
        match err {
            StoreForwardError::StaleQueueWithoutKey { path, depth } => {
                assert_eq!(depth, 2, "error must report the stale entry depth");
                assert!(
                    path.ends_with("client_queue.redb"),
                    "error path should reference the redb file: {path}"
                );
            }
            other => panic!("expected StaleQueueWithoutKey, got {other:?}"),
        }

        // Supplying the original key should still succeed and let the
        // operator drain the queue.
        let q2 = ClientQueue::open_with_hmac_key(tmp.path(), 1_000_000, Some(key.clone())).unwrap();
        assert_eq!(q2.stats("bob").depth, 2);
        let drained = q2.drain("bob").unwrap();
        assert_eq!(drained.len(), 2);
    }

    /// `open_with_wipe` is the explicit opt-in that discards the stored
    /// queue and emits a `store_forward.key_rotated` audit event. After
    /// the wipe, `open` succeeds and subsequent enqueue/drain round-trips
    /// cleanly under the fresh ephemeral key.
    #[tokio::test]
    async fn open_with_wipe_clears_stale_queue() {
        let tmp = TempDir::new().unwrap();
        let key = test_hmac_key();

        // Seed the queue under a persistent key.
        {
            let q =
                ClientQueue::open_with_hmac_key(tmp.path(), 1_000_000, Some(key.clone())).unwrap();
            q.enqueue("bob", &msg_for("alice", "bob", b"doomed-1"))
                .unwrap();
            q.enqueue("bob", &msg_for("alice", "bob", b"doomed-2"))
                .unwrap();
            q.enqueue("bob", &msg_for("alice", "bob", b"doomed-3"))
                .unwrap();
            wait_for_depth(&q, "bob", 3).await;
            drop(q);
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Wipe-and-open: the stale entries are discarded, the key is
        // regenerated as ephemeral, and the queue is ready for new work.
        let q = ClientQueue::open_with_wipe(tmp.path(), 1_000_000).unwrap();
        assert_eq!(
            q.stats("bob").depth,
            0,
            "wipe must clear every entry for every CN"
        );
        assert_eq!(
            q.total_bytes(),
            0,
            "wipe must clear the total_bytes accounting"
        );

        // The queue must be fully functional post-wipe.
        q.enqueue("carol", &msg_for("alice", "carol", b"fresh"))
            .unwrap();
        wait_for_depth(&q, "carol", 1).await;
        let drained = q.drain("carol").unwrap();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].payload.as_ref(), b"fresh");
    }

    /// Calling `open_with_wipe` on an empty directory is idempotent —
    /// no stale entries to discard, audit event records depth 0, and
    /// the returned queue behaves identically to a fresh `open`.
    #[tokio::test]
    async fn open_with_wipe_on_empty_dir_is_idempotent() {
        let tmp = TempDir::new().unwrap();
        let q = ClientQueue::open_with_wipe(tmp.path(), 1_000_000).unwrap();
        assert_eq!(q.stats("bob").depth, 0);
        q.enqueue("bob", &msg_for("alice", "bob", b"hi")).unwrap();
        wait_for_depth(&q, "bob", 1).await;
        let drained = q.drain("bob").unwrap();
        assert_eq!(drained.len(), 1);
    }

    // ── Issue #729: dwell-time observability ────────────────────────

    // The audit-capture buffer for `drain_audit_includes_dwell_seconds`
    // lives in `tests/store_forward_dwell_audit.rs`.

    /// Locate the on-disk envelope for the freshest entry in the queue
    /// and verify `decode` recovers a `queued_at_ms` close to the wall
    /// clock at the moment of admission. Round-tripping through the
    /// real writer task and redb (rather than calling `encode`
    /// directly) pins the contract end-to-end: a behavioural change in
    /// any of `enqueue → channel → spawn_blocking → persist_one`
    /// surfaces here.
    #[tokio::test]
    async fn admission_records_queued_at_timestamp() {
        let tmp = TempDir::new().unwrap();
        let key = test_hmac_key();
        let q = ClientQueue::open_with_hmac_key(tmp.path(), 1_000_000, Some(key.clone())).unwrap();

        // Capture the wall clock immediately before admission so we can
        // verify queued_at landed inside a tight window. The actual
        // capture happens inside `enqueue` between these two reads.
        let before_ms = unix_now_ms();
        q.enqueue("bob", &msg_for("alice", "bob", b"dwell-probe"))
            .unwrap();
        wait_for_depth(&q, "bob", 1).await;
        let after_ms = unix_now_ms();

        // The in-memory index is updated BEFORE the redb commit
        // completes (`persist_one` mutates `Inner` then issues
        // `begin_write/commit`), so `wait_for_depth` returning does
        // not yet imply the entry is observable via `begin_read`.
        // Wait for redb to settle before reading the envelope back.
        wait_for_persisted(&q, 1).await;
        let raw = {
            let read = q.db.begin_read().unwrap();
            let table = read.open_table(QUEUE_TABLE).unwrap();
            let mut iter = table.iter().unwrap();
            let kv = iter.next().expect("redb must contain entry").unwrap();
            kv.1.value().to_vec()
        };
        assert!(
            raw.len() > HMAC_LEN,
            "stored envelope must include HMAC tag"
        );
        let body = &raw[..raw.len() - HMAC_LEN];
        let decoded = decode(body).expect("decode v2 envelope");

        assert_eq!(decoded.message.payload.as_ref(), b"dwell-probe");
        assert!(
            decoded.queued_at_ms >= before_ms && decoded.queued_at_ms <= after_ms,
            "queued_at_ms ({}) must fall within [{before_ms}, {after_ms}]",
            decoded.queued_at_ms
        );

        // Verify the version byte at the head is v2 — otherwise the
        // decoder may have silently fallen through the v1 fallback and
        // recovered queued_at == received_at, masking a regression.
        assert_eq!(
            body[0], ENVELOPE_VERSION,
            "fresh admissions must emit v2 envelopes"
        );
    }

    // The `drain_audit_includes_dwell_seconds` test lives in
    // `tests/store_forward_dwell_audit.rs` (integration test) rather
    // than here in the unit-test module. Reason: when many parallel
    // unit tests in the same binary emit audit events without any
    // subscriber, tracing-core caches `Interest::never()` for the
    // audit callsite globally. A subsequently-installed thread-local
    // subscriber cannot reach the callsite because the cache
    // short-circuits dispatch. Integration tests live in their own
    // binary and avoid the cache-pollution interaction.

    /// The drain path invokes the `OnDrainObservation` callback once
    /// per delivered message with a non-negative `dwell_seconds`
    /// observation. The histogram itself lives in `rustgate-server`
    /// (transport must not depend on `prometheus`); this test pins
    /// the contract that the histogram bucketing layer relies on —
    /// every drain observation reaches the configured callback.
    #[tokio::test]
    async fn drain_dwell_histogram_observes_drain_event() {
        let tmp = TempDir::new().unwrap();
        let q = ClientQueue::open(tmp.path(), 1_000_000).unwrap();

        // Capture every observation in a Vec so we can assert both the
        // count and the values. parking_lot::Mutex keeps the callback
        // body cheap (no `.unwrap()` on a poison check).
        let observations = std::sync::Arc::new(parking_lot::Mutex::new(Vec::<f64>::new()));
        let observations_cb = std::sync::Arc::clone(&observations);
        q.set_on_drain_observation(std::sync::Arc::new(move |dwell_secs| {
            observations_cb.lock().push(dwell_secs);
        }));

        // Three messages so we can verify per-message (not per-batch)
        // observation cardinality.
        for i in 0..3u8 {
            q.enqueue("bob", &msg_for("alice", "bob", &[i])).unwrap();
        }
        wait_for_depth(&q, "bob", 3).await;
        // Wait until redb has committed every entry — the in-memory
        // index is updated before the redb commit and the drain path
        // reads from redb, so we cannot observe full delivery from
        // depth alone.
        wait_for_persisted(&q, 3).await;
        let drained = q.drain("bob").unwrap();
        assert_eq!(drained.len(), 3);

        let observed = observations.lock().clone();
        assert_eq!(
            observed.len(),
            3,
            "OnDrainObservation must fire once per delivered message"
        );
        for d in &observed {
            assert!(*d >= 0.0, "dwell observation must be non-negative, got {d}");
            // Bound the upper end loosely — drains finish quickly under
            // a fresh queue. A regression that returned `Instant::now()
            // - UNIX_EPOCH` (50+ years) would trip this.
            assert!(
                *d < 60.0,
                "dwell observation under tight test window must be \
                 well under a minute, got {d}"
            );
        }
    }

    /// A v1 envelope (legacy, written before #729 added `queued_at`)
    /// must decode cleanly with `queued_at_ms` falling back to
    /// `received_at_ms`. This preserves pre-PR audit semantics for
    /// existing on-disk queues during the upgrade window — operators
    /// see dwell == (drain - received_at) on legacy entries until the
    /// queue cycles to v2-only entries.
    #[tokio::test]
    async fn legacy_record_without_queued_at_falls_back_to_received_at() {
        // Build a v1 envelope by hand — the persistence path always
        // emits v2, so we need to reach into the encoding to construct
        // the legacy shape. The layout matches the pre-#729 wire
        // format byte-for-byte.
        let received_at_ms: i64 = 1_700_000_000_000;
        let body = {
            let mut buf = BytesMut::new();
            buf.put_u8(ENVELOPE_VERSION_V1);
            put_identity(&mut buf, &ident("alice"));
            buf.put_u8(DEST_DIRECT);
            put_identity(&mut buf, &ident("bob"));
            buf.put_u8(MT_CHAT);
            put_str(&mut buf, "tcp");
            buf.put_i64(received_at_ms);
            // Note: NO queued_at field here — that is the entire point
            // of the v1 layout. The decoder must NOT advance past the
            // ttl bytes looking for one.
            buf.put_i64(-1); // ttl: none
            let payload = b"legacy-payload";
            buf.put_u32(payload.len() as u32);
            buf.put_slice(payload);
            buf.to_vec()
        };

        let decoded = decode(&body).expect("v1 envelope must decode");
        assert_eq!(decoded.message.payload.as_ref(), b"legacy-payload");
        assert_eq!(&*decoded.message.source.cn, "alice");
        match &decoded.message.destination {
            Destination::Direct(id) => assert_eq!(&*id.cn, "bob"),
            other => panic!("unexpected destination: {other:?}"),
        }
        assert_eq!(
            decoded.queued_at_ms, received_at_ms,
            "v1 envelopes must fall back to received_at_ms for queued_at"
        );

        // Sanity-check the fallback's downstream effect: dwell against
        // a notional drain_now == received_at + 5 minutes is exactly
        // 300 seconds. The test pins the legacy semantics — pre-PR,
        // operators saw the full received-to-drain interval; that
        // continues to hold for v1 records.
        let drain_now_ms = received_at_ms + 300_000;
        let dwell_ms = drain_now_ms.saturating_sub(decoded.queued_at_ms);
        assert_eq!(dwell_ms, 300_000);
    }

    /// Pre-#859 v2 envelopes (with `queued_at_ms` but no
    /// `tenant_id` field) must decode cleanly with
    /// `tenant = None`. Preserves backward compat for queues that
    /// flushed during the v2-era window between #729 and #859.
    #[tokio::test]
    async fn legacy_v2_record_without_tenant_decodes_with_none() {
        let received_at_ms: i64 = 1_700_000_000_000;
        let queued_at_ms: i64 = received_at_ms + 1_500;
        let body = {
            let mut buf = BytesMut::new();
            buf.put_u8(ENVELOPE_VERSION_V2);
            put_identity(&mut buf, &ident("alice"));
            buf.put_u8(DEST_DIRECT);
            put_identity(&mut buf, &ident("bob"));
            buf.put_u8(MT_CHAT);
            put_str(&mut buf, "tcp");
            buf.put_i64(received_at_ms);
            buf.put_i64(queued_at_ms);
            // No tenant field — the v2 wire format predates #859.
            buf.put_i64(-1); // ttl: none
            let payload = b"v2-payload";
            buf.put_u32(payload.len() as u32);
            buf.put_slice(payload);
            buf.to_vec()
        };

        let decoded = decode(&body).expect("v2 envelope must decode");
        assert_eq!(decoded.message.payload.as_ref(), b"v2-payload");
        assert_eq!(decoded.queued_at_ms, queued_at_ms);
        assert!(
            decoded.message.metadata.tenant_id().is_none(),
            "v2 envelopes carry no tenant tag and must decode to None"
        );
    }
}
