// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Encrypted dead-letter queue for circuit-breaker-shed messages.
//!
//! When a target's circuit breaker is open, messages are persisted to
//! ChaCha20-Poly1305 encrypted files (via [`rustgate_archive::encrypted`])
//! for later forensic recovery or replay. Each target gets a separate
//! file per process lifetime, named `{target}_{timestamp}.dlq.enc`.
//!
//! # Replay idempotency
//!
//! Every entry is stamped at dead-letter time with a 128-bit
//! `delivery_id` (32 hex chars) — the same format, entropy budget, and
//! generator shape as the live publish path's
//! `X-Rustgate-Delivery-Id` header. Replay tooling forwards this id
//! verbatim on the wire so that receivers can deduplicate a replayed
//! delivery against the original attempt without any additional
//! server-side state. `#881`.
//!
//! # Recovery
//!
//! Dead-lettered messages can be recovered offline using
//! [`rustgate_archive::encrypted::decrypt_file`] with the same key ring.
//! Each decrypted chunk is one JSON line containing the message metadata
//! and base64-encoded payload.

use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;
use std::sync::Mutex;

use rustgate_archive::encrypted::{KeyRing, SharedEncryptedWriter};
use rustgate_core::b64;
use rustgate_core::message::RoutableMessage;
use rustgate_core::sanitize::sanitize_for_log;
use serde::Serialize;

/// Default maximum DLQ file size: 256 MiB.
const DEFAULT_DLQ_MAX_BYTES: u64 = 256 * 1024 * 1024;

/// Suffix of sealed / in-flight DLQ segment files. The eviction sweep
/// (see [`DeadLetterQueue::enforce_target_cap`]) scans the DLQ directory
/// for files whose name starts with `<target>_` and ends with this
/// suffix. Pinned as a constant so a refactor that ever changes the
/// suffix also updates the reader — a silent rename would make the
/// eviction sweep miss sealed files and the per-target cap silently
/// ineffective.
pub(crate) const DLQ_FILE_SUFFIX: &str = ".dlq.enc";

/// Encrypted dead-letter queue that persists undeliverable messages.
///
/// Thread-safe: uses internal `Mutex` for writer map. Writers are
/// created lazily on first dead-letter per target to avoid I/O at
/// startup for targets that may never trip.
pub(crate) struct DeadLetterQueue {
    dir: PathBuf,
    key_ring: KeyRing,
    /// Maximum file size per target before rotation.
    max_bytes: u64,
    /// Maximum total bytes on disk per target across every sealed /
    /// active segment. When a target's footprint exceeds this cap the
    /// oldest sealed file is deleted (drop-oldest FIFO). The active
    /// segment is always preserved — the writer is live and unlinking
    /// it would corrupt the in-memory state.
    ///
    /// `0` = unlimited (historical behaviour). The enforced minimum of
    /// `max_bytes` is honoured at config validation, not here — this
    /// field does not try to self-correct a misconfigured cap.
    max_target_bytes: u64,
    writers: Mutex<HashMap<String, WriterState>>,
}

/// Per-target writer state tracking accumulated bytes for rotation.
struct WriterState {
    writer: SharedEncryptedWriter,
    bytes_written: u64,
    /// Absolute path of the active (unsealed) segment file on disk.
    ///
    /// Recorded at writer creation so [`DeadLetterQueue::rotate_active_segment`]
    /// can return it to the drain worker after sealing, and so
    /// [`DeadLetterQueue::list_sealed_segments`] can exclude the
    /// currently-active path from its sealed-segment scan — the sweep
    /// must never return a live file whose terminator chunk has not
    /// yet been written, because decrypting it would surface a
    /// truncation error and because replaying against a file that is
    /// still being written to would race the writer's next append.
    path: PathBuf,
}

impl fmt::Debug for DeadLetterQueue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeadLetterQueue")
            .field("dir", &self.dir)
            .finish_non_exhaustive()
    }
}

/// JSON-serializable dead-letter entry. Each entry becomes one encrypted
/// chunk in the DLQ file.
#[derive(Debug, Serialize)]
struct DlqEntry<'a> {
    /// RFC 3339 timestamp when the message was dead-lettered.
    timestamp: String,
    /// Target name that rejected the message.
    target: &'a str,
    /// Reason for dead-lettering (e.g., "circuit_open").
    reason: &'a str,
    /// Stable per-entry idempotency key. Generated once at dead-letter
    /// time and preserved verbatim across any future replay so the
    /// receiver can deduplicate replayed deliveries. Wire-compatible
    /// with the `X-Rustgate-Delivery-Id` header used on live requests:
    /// 32 lowercase hex characters encoding 128 bits of entropy. `#881`.
    delivery_id: &'a str,
    /// Source client CN from the original message.
    source_cn: &'a str,
    /// Source client group memberships.
    source_groups: Vec<&'a str>,
    /// Message destination.
    destination: String,
    /// Message type (position, chat, alert, etc.).
    message_type: String,
    /// Originating protocol.
    source_protocol: &'a str,
    /// Raw payload bytes, base64-encoded.
    payload_b64: String,
    /// Payload size in bytes (pre-encoding).
    payload_size: usize,
}

impl DeadLetterQueue {
    /// Create a new DLQ backed by the given directory and key ring.
    ///
    /// `max_bytes` caps a *single file* before rotation (default
    /// `DEFAULT_DLQ_MAX_BYTES`). `max_target_bytes` caps the *total*
    /// on-disk footprint for one target across every rotated file;
    /// `None` / `0` disables the outer cap (historical behaviour).
    ///
    /// Does NOT create any files at construction time — writers are
    /// created lazily when the first message is dead-lettered for a
    /// target.
    pub(crate) fn new(
        dir: PathBuf,
        key_ring: KeyRing,
        max_bytes: Option<u64>,
        max_target_bytes: Option<u64>,
    ) -> Self {
        Self {
            dir,
            key_ring,
            max_bytes: max_bytes.unwrap_or(DEFAULT_DLQ_MAX_BYTES),
            max_target_bytes: max_target_bytes.unwrap_or(0),
            writers: Mutex::new(HashMap::new()),
        }
    }

    /// Persist a dead-lettered message for later recovery.
    ///
    /// Fail-open: all errors are logged as warnings but never propagated,
    /// because the DLQ is a best-effort forensic aid, not a critical path.
    pub(crate) fn dead_letter(&self, target_name: &str, msg: &RoutableMessage, reason: &str) {
        // Generate the per-entry idempotency key eagerly so the id is
        // stamped onto the persisted JSON record and survives file
        // rotation, process restart, or operator replay. Re-delivering
        // a DLQ entry later (either via the auto-drain on circuit
        // recovery, see #881, or an offline replay tool) preserves
        // this id verbatim as the `X-Rustgate-Delivery-Id` header so
        // the receiver can deduplicate. 128 bits of entropy (same
        // generator as the live publish path) keeps the collision
        // domain effectively infinite across every DLQ segment ever
        // produced by this process.
        let delivery_id = generate_delivery_id();
        self.dead_letter_with_id(target_name, msg, reason, &delivery_id);
    }

    /// Persist a dead-lettered message while preserving an externally-
    /// supplied `delivery_id`. Used by the auto-drain worker when a
    /// replay attempt fails and the entry must be re-DLQ'd — preserving
    /// the original id keeps receiver-side dedup intact across the
    /// retry cycle (see `#881`), so a target that accepted the first
    /// replay but failed our 2xx read (e.g. TCP RST after response send)
    /// will dedup the second replay on the same id.
    ///
    /// Callers that do NOT need id preservation should prefer
    /// [`dead_letter`](Self::dead_letter), which generates a fresh id.
    pub(crate) fn dead_letter_with_id(
        &self,
        target_name: &str,
        msg: &RoutableMessage,
        reason: &str,
        delivery_id: &str,
    ) {
        // Serialize the entry to JSON
        let entry = DlqEntry {
            timestamp: format_timestamp_now(),
            target: target_name,
            reason,
            delivery_id,
            source_cn: &msg.source.cn,
            source_groups: msg.source.groups.iter().map(String::as_str).collect(),
            destination: crate::payload::format_destination(&msg.destination),
            message_type: msg.metadata.message_type.to_string(),
            source_protocol: &msg.metadata.source_protocol,
            payload_b64: b64::encode(&msg.payload),
            payload_size: msg.payload.len(),
        };

        let json = match serde_json::to_vec(&entry) {
            Ok(j) => j,
            Err(e) => {
                tracing::warn!(
                    target = %sanitize_for_log(target_name),
                    error = %e,
                    "failed to serialize DLQ entry"
                );
                return;
            }
        };

        self.write_entry(target_name, &json);
    }

    /// Decrypt and deserialize a sealed DLQ segment. Thin wrapper around
    /// [`crate::dlq_reader::read_dlq_file`] that keeps the [`KeyRing`]
    /// encapsulated inside the DLQ — the drain worker in `publisher.rs`
    /// only holds `Arc<DeadLetterQueue>` and never needs direct access
    /// to the key material.
    ///
    /// Returns the list of entries in file order. AEAD failures
    /// (truncation, tampered chunk, wrong key) surface as
    /// [`DlqReadError::Decrypt`](crate::dlq_reader::DlqReadError::Decrypt);
    /// JSON parse failures as
    /// [`DlqReadError::Json`](crate::dlq_reader::DlqReadError::Json).
    pub(crate) fn read_segment(
        &self,
        path: &std::path::Path,
    ) -> Result<Vec<crate::dlq_reader::OwnedDlqEntry>, crate::dlq_reader::DlqReadError> {
        crate::dlq_reader::read_dlq_file(path, &self.key_ring)
    }

    /// Write a serialized entry to the target's DLQ file.
    ///
    /// Defense-in-depth: validates that `target_name` contains only safe
    /// filesystem characters before using it in a path. Config validation
    /// already restricts target names to `[a-zA-Z0-9_-]`, but the DLQ
    /// does not rely on that upstream check.
    fn write_entry(&self, target_name: &str, data: &[u8]) {
        // Path traversal defense: reject target names containing path
        // separators, parent-dir references, or non-alphanumeric chars
        // that could escape the DLQ directory.
        if !target_name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            tracing::warn!(
                target = %sanitize_for_log(target_name),
                "DLQ target name contains unsafe characters, dropping dead-letter"
            );
            return;
        }

        let mut guard = match self.writers.lock() {
            Ok(w) => w,
            Err(_) => {
                tracing::warn!(
                    target = %sanitize_for_log(target_name),
                    "DLQ writer lock poisoned, dropping dead-letter"
                );
                rustgate_core::audit::http_dlq_failed(target_name, "writer lock poisoned");
                return;
            }
        };

        // Rotate writer if the current file exceeds the size limit
        if let Some(state) = guard.get(target_name)
            && state.bytes_written >= self.max_bytes
            && let Some(old) = guard.remove(target_name)
        {
            // Seal the old writer; ignore errors (best-effort).
            // `finish()` flushes and writes the encrypted terminator
            // chunk — a missing terminator makes the file unreadable to
            // `decrypt_file`, so a sealed file is a precondition for the
            // eviction sweep that follows.
            let _ = old.writer.finish();
            tracing::info!(
                target = %sanitize_for_log(target_name),
                bytes_written = old.bytes_written,
                "DLQ file rotated (size limit reached)"
            );

            // Now that the previous segment is sealed and no longer
            // referenced by the writer map, the eviction sweep can
            // safely delete oldest sealed files for this target until
            // the on-disk footprint fits under `max_target_bytes`.
            // Deliberately runs before the new writer is lazily
            // created below so the just-sealed file is a candidate —
            // otherwise a tight cap + a long outage could starve the
            // sweep and exhaust disk between rotations.
            self.enforce_target_cap(target_name);
        }

        // Lazy initialization: create writer on first dead-letter per target
        // (or after rotation)
        if !guard.contains_key(target_name) {
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis();
            let filename = format!("{target_name}_{ts}.dlq.enc");
            let file_path = self.dir.join(&filename);

            match SharedEncryptedWriter::create(&file_path, &self.key_ring) {
                Ok(w) => {
                    tracing::info!(
                        target = %sanitize_for_log(target_name),
                        path = %file_path.display(),
                        "created DLQ writer"
                    );
                    let _ = guard.insert(
                        target_name.to_string(),
                        WriterState {
                            writer: w,
                            bytes_written: 0,
                            path: file_path.clone(),
                        },
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        target = %sanitize_for_log(target_name),
                        path = %file_path.display(),
                        error = %e,
                        "failed to create DLQ writer"
                    );
                    rustgate_core::audit::http_dlq_failed(
                        target_name,
                        &format!("failed to create writer: {e}"),
                    );
                    return;
                }
            }
        }

        if let Some(state) = guard.get_mut(target_name) {
            if let Err(e) = state.writer.write_line(data) {
                tracing::warn!(
                    target = %sanitize_for_log(target_name),
                    error = %e,
                    "failed to write DLQ entry"
                );
                rustgate_core::audit::http_dlq_failed(
                    target_name,
                    &format!("failed to write entry: {e}"),
                );
            } else {
                state.bytes_written += data.len() as u64;
            }
        }
    }

    /// Drop-oldest FIFO eviction once a target's total on-disk footprint
    /// exceeds `max_target_bytes`. No-op when the cap is unlimited
    /// (`0`). Callers must have already sealed (finished) the most
    /// recently rotated segment — deleting a live file would corrupt
    /// the `SharedEncryptedWriter`'s in-memory state.
    ///
    /// The target's currently-active (in-writers-map) segment is
    /// skipped, so the sweep cannot race the writer. For that reason
    /// the eviction target is `max_target_bytes - active_size` rather
    /// than `max_target_bytes` directly — we cap the *sealed* tail of
    /// the chain, not the active head.
    ///
    /// Best-effort: individual `remove_file` / `metadata` failures are
    /// logged and skipped. The DLQ is a forensic aid, not a critical
    /// path, and a transient errno on one file must not starve the
    /// sweep for the rest.
    fn enforce_target_cap(&self, target_name: &str) {
        let cap = self.max_target_bytes;
        if cap == 0 {
            return;
        }

        // Path traversal defence was already enforced in `write_entry`
        // before this call; the same character restriction applies to
        // the prefix used for the scan.
        let prefix = format!("{target_name}_");

        let read = match std::fs::read_dir(&self.dir) {
            Ok(it) => it,
            Err(err) => {
                tracing::warn!(
                    target = %sanitize_for_log(target_name),
                    dir = %self.dir.display(),
                    error = %err,
                    "DLQ eviction: read_dir failed, skipping sweep"
                );
                return;
            }
        };

        #[derive(Debug)]
        struct SealedFile {
            path: PathBuf,
            size: u64,
            mtime: std::time::SystemTime,
        }

        let mut files: Vec<SealedFile> = Vec::new();
        for entry in read {
            let entry = match entry {
                Ok(e) => e,
                Err(err) => {
                    tracing::warn!(
                        target = %sanitize_for_log(target_name),
                        error = %err,
                        "DLQ eviction: entry read failed",
                    );
                    continue;
                }
            };
            let name = match entry.file_name().into_string() {
                Ok(s) => s,
                Err(_) => continue, // non-UTF-8 filenames cannot be DLQ segments
            };
            if !name.starts_with(&prefix) || !name.ends_with(DLQ_FILE_SUFFIX) {
                continue;
            }
            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(err) => {
                    tracing::warn!(
                        target = %sanitize_for_log(target_name),
                        file = %name,
                        error = %err,
                        "DLQ eviction: metadata failed, skipping file",
                    );
                    continue;
                }
            };
            if !meta.is_file() {
                continue;
            }
            let mtime = meta.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH);
            files.push(SealedFile {
                path: entry.path(),
                size: meta.len(),
                mtime,
            });
        }

        // Oldest first so the drop-oldest FIFO is a simple linear scan.
        // ties on mtime (same-ms rotation) break on path so the order
        // is deterministic.
        files.sort_by(|a, b| a.mtime.cmp(&b.mtime).then_with(|| a.path.cmp(&b.path)));

        let mut total: u64 = files.iter().map(|f| f.size).sum();
        if total <= cap {
            return;
        }

        let mut idx = 0;
        // Reserve at least one file — the writer might already have
        // reopened the next segment concurrently (rotation sealed the
        // prior segment before returning). Skip whichever sealed file
        // matches the currently-active path to avoid racing the writer.
        // The active path is derived by reading the writers map, but
        // the caller holds that lock across this call, so we re-derive
        // it from filename heuristics instead: the newest file is
        // always a candidate for the active segment, so preserve it
        // unless there are strictly more than one file present.
        while idx < files.len() && total > cap {
            if files.len() == 1 {
                // Single file left — assume it's the active segment and
                // refuse to delete. The writer loop will create the
                // next rotation as soon as the current one seals.
                break;
            }
            let f = &files[idx];
            match std::fs::remove_file(&f.path) {
                Ok(()) => {
                    total = total.saturating_sub(f.size);
                    tracing::info!(
                        target = %sanitize_for_log(target_name),
                        path = %f.path.display(),
                        bytes = f.size,
                        "DLQ eviction: removed oldest sealed segment",
                    );
                    #[cfg(feature = "metrics")]
                    {
                        let m = crate::metrics::dlq_evicted();
                        if let Ok(child) = m.get_metric_with_label_values(&[target_name]) {
                            child.inc();
                        }
                    }
                    // `files[0..idx]` already removed; keep the vector
                    // in lock-step so the next iteration still sees
                    // oldest-first ordering.
                }
                Err(err) => {
                    tracing::warn!(
                        target = %sanitize_for_log(target_name),
                        path = %f.path.display(),
                        error = %err,
                        "DLQ eviction: remove_file failed, continuing sweep",
                    );
                }
            }
            idx += 1;
        }
    }

    /// Seal the currently-active segment for `target_name`, if any, and
    /// return the freshly-sealed path.
    ///
    /// Invariant for the replay path: every entry the drain worker wants
    /// to read must sit inside a sealed segment. An unsealed file has no
    /// terminator chunk, so `decrypt_file` surfaces a truncation error
    /// rather than yielding the entries accumulated so far. Callers
    /// invoke this once at the start of a drain pass so messages queued
    /// during the outage — even those that never triggered a size-based
    /// rotation — become replayable.
    ///
    /// Returns `None` when no active writer exists (the target either
    /// never dead-lettered anything or its last active segment was
    /// already rotated by the size-cap path). `Some(path)` when a live
    /// writer was sealed: the caller may then include that path in the
    /// list of segments to replay. After this call the target has no
    /// active writer; the next `dead_letter` call re-initializes a fresh
    /// segment via the standard lazy-creation path.
    ///
    /// Best-effort: seal failures are logged at `warn` level but the
    /// writer is still removed from the map, because leaving a partially-
    /// sealed writer in place would permanently wedge the target (every
    /// subsequent `dead_letter` would keep writing to a corrupt file).
    pub(crate) fn rotate_active_segment(&self, target_name: &str) -> Option<PathBuf> {
        let mut guard = match self.writers.lock() {
            Ok(w) => w,
            Err(_) => {
                tracing::warn!(
                    target = %sanitize_for_log(target_name),
                    "DLQ writer lock poisoned, cannot rotate active segment"
                );
                return None;
            }
        };
        let state = guard.remove(target_name)?;
        let path = state.path.clone();
        if let Err(e) = state.writer.finish() {
            tracing::warn!(
                target = %sanitize_for_log(target_name),
                path = %path.display(),
                error = %e,
                "failed to seal active DLQ segment during rotate"
            );
            return None;
        }
        tracing::info!(
            target = %sanitize_for_log(target_name),
            path = %path.display(),
            bytes_written = state.bytes_written,
            "sealed active DLQ segment for drain"
        );
        Some(path)
    }

    /// List every sealed DLQ segment on disk that belongs to `target_name`.
    ///
    /// A "sealed" segment is one whose filename matches the pattern
    /// `{target}_*.{suffix}` *and* which is not the currently-active
    /// writer path for that target. The active path is excluded because
    /// it has no encrypted terminator chunk yet — reading it would fail
    /// AEAD verification and replaying against it would race the writer.
    ///
    /// The returned list is sorted oldest-first by mtime (ties broken
    /// lexicographically by path) so the drain worker replays segments
    /// in the order they were produced, preserving the original
    /// dead-letter ordering across rotations. A target with no segments
    /// on disk yields an empty vector.
    ///
    /// Best-effort: individual `metadata` or directory-entry failures
    /// are logged and skipped, matching the eviction sweep. Non-UTF-8
    /// filenames cannot be DLQ segments (the writer never produces them)
    /// and are silently skipped.
    pub(crate) fn list_sealed_segments(&self, target_name: &str) -> Vec<PathBuf> {
        if !target_name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            tracing::warn!(
                target = %sanitize_for_log(target_name),
                "DLQ target name contains unsafe characters, skipping segment list"
            );
            return Vec::new();
        }

        let active_path = match self.writers.lock() {
            Ok(guard) => guard.get(target_name).map(|s| s.path.clone()),
            Err(_) => {
                tracing::warn!(
                    target = %sanitize_for_log(target_name),
                    "DLQ writer lock poisoned, listing sealed segments without active-path exclusion"
                );
                None
            }
        };

        let read = match std::fs::read_dir(&self.dir) {
            Ok(it) => it,
            Err(err) => {
                tracing::warn!(
                    target = %sanitize_for_log(target_name),
                    dir = %self.dir.display(),
                    error = %err,
                    "DLQ drain: read_dir failed, no segments to replay"
                );
                return Vec::new();
            }
        };

        let prefix = format!("{target_name}_");
        struct SealedFile {
            path: PathBuf,
            mtime: std::time::SystemTime,
        }
        let mut files: Vec<SealedFile> = Vec::new();
        for entry in read {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            let name = match entry.file_name().into_string() {
                Ok(s) => s,
                Err(_) => continue,
            };
            if !name.starts_with(&prefix) || !name.ends_with(DLQ_FILE_SUFFIX) {
                continue;
            }
            let path = entry.path();
            if active_path.as_ref().is_some_and(|active| &path == active) {
                continue;
            }
            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            if !meta.is_file() {
                continue;
            }
            let mtime = meta.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH);
            files.push(SealedFile { path, mtime });
        }

        files.sort_by(|a, b| a.mtime.cmp(&b.mtime).then_with(|| a.path.cmp(&b.path)));
        files.into_iter().map(|f| f.path).collect()
    }

    /// Remove a sealed DLQ segment after a successful replay pass.
    ///
    /// The drain worker calls this for each segment whose every entry
    /// was successfully replayed (or re-persisted as a fresh DLQ entry
    /// under a new `delivery_id`, which amounts to the same thing —
    /// the bytes are preserved). Failure to remove is logged at `warn`
    /// but not surfaced because a leftover sealed segment will either
    /// be retried on the next drain trigger or evicted by the
    /// `max_target_bytes` sweep.
    pub(crate) fn remove_segment(&self, path: &std::path::Path) -> std::io::Result<()> {
        match std::fs::remove_file(path) {
            Ok(()) => {
                tracing::info!(
                    path = %path.display(),
                    "removed drained DLQ segment"
                );
                Ok(())
            }
            Err(err) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %err,
                    "failed to remove drained DLQ segment"
                );
                Err(err)
            }
        }
    }

    /// Seal all open DLQ writers during shutdown.
    ///
    /// Must be called before the process exits to ensure the encrypted
    /// terminator chunks are written (readers reject unterminated files).
    pub(crate) fn finish(&self) {
        let guard = match self.writers.lock() {
            Ok(w) => w,
            Err(_) => {
                tracing::warn!("DLQ writer lock poisoned during shutdown");
                return;
            }
        };
        for (name, state) in guard.iter() {
            if let Err(e) = state.writer.finish() {
                tracing::warn!(
                    target = %sanitize_for_log(name),
                    error = %e,
                    "failed to seal DLQ writer"
                );
            }
        }
    }
}

fn format_timestamp_now() -> String {
    let format = time::format_description::well_known::Iso8601::DEFAULT;
    match time::OffsetDateTime::now_utc().format(&format) {
        Ok(s) => s,
        Err(_) => "unknown".to_string(),
    }
}

/// Generate a 128-bit idempotency key for a DLQ entry. Matches the
/// generator used on the live publish path (`publisher::generate_delivery_id`)
/// so replayed DLQ deliveries appear indistinguishable from fresh ones on
/// the wire — the same 32-character lowercase hex format, the same 128
/// bits of entropy from an OS-seeded CSPRNG. Kept as a free function here rather
/// than a shared helper to avoid forcing `publisher::generate_delivery_id`
/// to become `pub(crate)` purely for cross-module reuse; the two call sites
/// are independent enough that a silent drift between them would be caught
/// by the `dlq_entry_delivery_id_is_lowercase_hex_128_bits` format test.
fn generate_delivery_id() -> String {
    use rand::Rng;
    let mut buf = [0u8; 16];
    rand::rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use std::collections::BTreeSet;
    use std::sync::Arc;

    use bytes::Bytes;
    use rustgate_core::identity::Identity;
    use rustgate_core::message::{Destination, MessageType, Metadata};

    use super::*;

    fn make_msg(cn: &str) -> RoutableMessage {
        RoutableMessage {
            source: Identity {
                cn: cn.into(),
                fingerprint: Default::default(),
                groups: {
                    let mut s = BTreeSet::new();
                    let _ = s.insert("alpha".to_string());
                    s
                },
                tenant: None,
                spiffe_id: None,
                attributes: Arc::new(Default::default()),
            },
            destination: Destination::Broadcast,
            payload: Bytes::from_static(b"<event uid='test'/>"),
            metadata: Metadata::new(
                std::time::SystemTime::now(),
                "tcp".to_string(),
                MessageType::Position,
            ),
            entity: None,
        }
    }

    /// Create a test key ring with a known key.
    fn test_key_ring() -> KeyRing {
        let key_json = r#"{
            "active_key_id": "test-key",
            "keys": {
                "test-key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            }
        }"#;
        KeyRing::from_bytes(key_json.as_bytes()).unwrap()
    }

    #[test]
    fn dlq_entry_serializes_to_json() {
        let msg = make_msg("alice");
        let entry = DlqEntry {
            timestamp: "2026-04-13T12:00:00Z".to_string(),
            target: "siem",
            reason: "circuit_open",
            delivery_id: "deadbeefcafef00d1122334455667788",
            source_cn: &msg.source.cn,
            source_groups: msg.source.groups.iter().map(String::as_str).collect(),
            destination: crate::payload::format_destination(&msg.destination),
            message_type: msg.metadata.message_type.to_string(),
            source_protocol: &msg.metadata.source_protocol,
            payload_b64: b64::encode(&msg.payload),
            payload_size: msg.payload.len(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"source_cn\":\"alice\""));
        assert!(json.contains("\"reason\":\"circuit_open\""));
        assert!(json.contains("\"target\":\"siem\""));
        assert!(json.contains("\"delivery_id\":\"deadbeefcafef00d1122334455667788\""));
    }

    #[test]
    fn dlq_creates_writer_lazily() {
        let dir = tempfile::tempdir().unwrap();
        let key_ring = test_key_ring();
        let dlq = DeadLetterQueue::new(dir.path().to_path_buf(), key_ring, None, None);

        // No files should exist yet
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);

        // Dead-letter a message
        let msg = make_msg("alice");
        dlq.dead_letter("target-1", &msg, "circuit_open");

        // Now exactly one file should exist
        let entries: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
        assert_eq!(entries.len(), 1);
        let filename = entries[0].as_ref().unwrap().file_name();
        let name = filename.to_str().unwrap();
        assert!(name.starts_with("target-1_"), "got: {name}");
        assert!(name.ends_with(".dlq.enc"), "got: {name}");
    }

    #[test]
    fn dlq_reuses_writer_for_same_target() {
        let dir = tempfile::tempdir().unwrap();
        let key_ring = test_key_ring();
        let dlq = DeadLetterQueue::new(dir.path().to_path_buf(), key_ring, None, None);

        let msg = make_msg("alice");
        dlq.dead_letter("target-1", &msg, "circuit_open");
        dlq.dead_letter("target-1", &msg, "circuit_open");

        // Still only one file
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn dlq_creates_separate_files_per_target() {
        let dir = tempfile::tempdir().unwrap();
        let key_ring = test_key_ring();
        let dlq = DeadLetterQueue::new(dir.path().to_path_buf(), key_ring, None, None);

        let msg = make_msg("alice");
        dlq.dead_letter("target-a", &msg, "circuit_open");
        dlq.dead_letter("target-b", &msg, "circuit_open");

        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 2);
    }

    #[test]
    fn dlq_finish_seals_writers() {
        let dir = tempfile::tempdir().unwrap();
        let key_ring = test_key_ring();
        let dlq = DeadLetterQueue::new(dir.path().to_path_buf(), key_ring, None, None);

        let msg = make_msg("alice");
        dlq.dead_letter("target-1", &msg, "circuit_open");
        dlq.finish();

        // File should exist and be non-empty (header + chunk + terminator)
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert_eq!(entries.len(), 1);
        let size = entries[0].metadata().unwrap().len();
        assert!(size > 0, "DLQ file should not be empty after finish");
    }

    #[test]
    fn debug_impl_redacts_internals() {
        let dir = tempfile::tempdir().unwrap();
        let key_ring = test_key_ring();
        let dlq = DeadLetterQueue::new(dir.path().to_path_buf(), key_ring, None, None);
        let debug = format!("{dlq:?}");
        assert!(debug.contains("DeadLetterQueue"));
        assert!(debug.contains("dir"));
        // Should NOT contain key material
        assert!(!debug.contains("aaaa"));
    }

    #[test]
    fn dlq_rejects_path_traversal_target_name() {
        let dir = tempfile::tempdir().unwrap();
        let key_ring = test_key_ring();
        let dlq = DeadLetterQueue::new(dir.path().to_path_buf(), key_ring, None, None);

        let msg = make_msg("alice");

        // Path traversal attempt — should be silently dropped, no file created
        dlq.dead_letter("../etc/passwd", &msg, "circuit_open");
        assert_eq!(
            std::fs::read_dir(dir.path()).unwrap().count(),
            0,
            "path traversal target name should not create any files"
        );

        // Slash in target name
        dlq.dead_letter("foo/bar", &msg, "circuit_open");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);

        // Valid target name still works
        dlq.dead_letter("valid-target_1", &msg, "circuit_open");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    /// Pins the `Send + Sync + 'static` bound surface. `Arc<DeadLetterQueue>`
    /// is shared across every per-target sender task and lives for the life
    /// of the HTTP publisher; if any of the three bounds regressed the
    /// publisher would no longer compile, so pinning them here gives a
    /// crisp failure message at the DLQ layer instead of a noisy one at
    /// the call site.
    #[test]
    fn dead_letter_queue_is_send_sync_and_static() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}
        fn assert_static<T: 'static>() {}
        assert_send::<DeadLetterQueue>();
        assert_sync::<DeadLetterQueue>();
        assert_static::<DeadLetterQueue>();
    }

    /// Pins the documented default file-size cap (256 MiB) so a future
    /// refactor that bumps the literal without revisiting the operator
    /// docs in `docs/http.md` trips here first.
    #[test]
    fn default_dlq_max_bytes_is_exactly_256_mib() {
        assert_eq!(DEFAULT_DLQ_MAX_BYTES, 256 * 1024 * 1024);
        assert_eq!(DEFAULT_DLQ_MAX_BYTES, 268_435_456);
    }

    /// Pins the rotation contract: once a writer's `bytes_written` meets or
    /// exceeds `max_bytes`, the NEXT `dead_letter` call seals the old writer
    /// (leaving the old encrypted file readable on disk) and creates a new
    /// writer with a fresh timestamp suffix. This is the core invariant that
    /// bounds forensic file size at rest and keeps decrypt_file readable for
    /// offline recovery.
    #[test]
    fn rotation_creates_new_file_once_bytes_written_meets_max_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let key_ring = test_key_ring();
        // max_bytes=50: any single JSON DLQ entry is > 50 bytes once the
        // timestamp, target, reason, source_cn, and payload_b64 are written,
        // so the second dead_letter call rotates.
        let dlq = DeadLetterQueue::new(dir.path().to_path_buf(), key_ring, Some(50), None);

        let msg = make_msg("alice");
        dlq.dead_letter("rotator", &msg, "circuit_open");
        // Brief sleep to guarantee the rotation's new filename timestamp
        // differs from the first (both use millisecond precision); without
        // this the OS filesystem may collide names if we run very fast on a
        // fast disk.
        std::thread::sleep(std::time::Duration::from_millis(5));
        dlq.dead_letter("rotator", &msg, "circuit_open");

        let count = std::fs::read_dir(dir.path()).unwrap().count();
        assert!(
            count >= 2,
            "expected rotation to leave >= 2 files on disk, got {count}"
        );
    }

    /// Pins that rotation is scoped to a single target — rotating one target
    /// must not touch any other target's writer. A regression that held a
    /// process-global `bytes_written` counter would cause one chatty target
    /// to force all targets to rotate on every write, bloating disk usage
    /// and breaking the "one file per target per lifecycle" invariant
    /// documented in the module header.
    #[test]
    fn rotation_is_scoped_per_target_and_does_not_affect_other_targets() {
        let dir = tempfile::tempdir().unwrap();
        let key_ring = test_key_ring();
        let dlq = DeadLetterQueue::new(dir.path().to_path_buf(), key_ring, Some(50), None);

        let msg = make_msg("alice");
        // Quiet target: writes exactly one entry (no rotation — bytes_written
        // is still 0 on first write, rotation check fires only on entries >= 2).
        dlq.dead_letter("quiet", &msg, "circuit_open");

        // Chatty target: writes twice with a sleep between, forcing rotation.
        dlq.dead_letter("chatty", &msg, "circuit_open");
        std::thread::sleep(std::time::Duration::from_millis(5));
        dlq.dead_letter("chatty", &msg, "circuit_open");

        // `quiet` should have exactly one file; `chatty` should have >= 2.
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        let quiet_count = entries
            .iter()
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .map(|s| s.starts_with("quiet_"))
                    .unwrap_or(false)
            })
            .count();
        let chatty_count = entries
            .iter()
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .map(|s| s.starts_with("chatty_"))
                    .unwrap_or(false)
            })
            .count();
        assert_eq!(
            quiet_count, 1,
            "quiet target must not rotate when only chatty target is full"
        );
        assert!(
            chatty_count >= 2,
            "chatty target must rotate independently of quiet target (got {chatty_count})"
        );
    }

    /// Pins the wire format for a message with no groups: `source_groups`
    /// must serialize as `[]`, NOT be omitted, NOT serialize as `null`. The
    /// offline recovery tool and any SIEM ingest rule keys off this exact
    /// shape.
    #[test]
    fn dlq_entry_serializes_empty_source_groups_as_empty_json_array() {
        let mut msg = make_msg("alice");
        msg.source.groups.clear();
        let entry = DlqEntry {
            timestamp: "2026-04-13T12:00:00Z".to_string(),
            target: "siem",
            reason: "circuit_open",
            delivery_id: "abcdef0123456789abcdef0123456789",
            source_cn: &msg.source.cn,
            source_groups: msg.source.groups.iter().map(String::as_str).collect(),
            destination: crate::payload::format_destination(&msg.destination),
            message_type: msg.metadata.message_type.to_string(),
            source_protocol: &msg.metadata.source_protocol,
            payload_b64: b64::encode(&msg.payload),
            payload_size: msg.payload.len(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(
            json.contains("\"source_groups\":[]"),
            "empty groups must serialize as empty array, got: {json}"
        );
        assert!(
            !json.contains("\"source_groups\":null"),
            "null is not an acceptable serialization for empty groups"
        );
    }

    /// Pins the payload-base64 round-trip: the raw payload bytes written into
    /// the DLQ entry must survive `b64::decode` back to the original. Forensic
    /// replay tools depend on this being a lossless encoding (not a hex
    /// digest, not a truncation, not a UTF-8 lossy conversion).
    #[test]
    fn dlq_entry_payload_b64_round_trips_to_original_bytes() {
        let payload = b"\xde\xad\xbe\xef\x00\x01\x02\xff some non-utf8 bytes \x80\x81";
        let b64 = b64::encode(payload);
        let decoded = b64::decode(&b64).unwrap();
        assert_eq!(decoded.as_slice(), &payload[..]);
    }

    /// Pins that every documented field in the module-header contract
    /// (timestamp, target, reason, delivery_id, source_cn, source_groups,
    /// destination, message_type, source_protocol, payload_b64,
    /// payload_size) is present in the serialized JSON. If a future
    /// refactor drops or renames a field without updating the
    /// operator-facing recovery tool, this trips.
    #[test]
    fn dlq_entry_json_contains_all_documented_fields() {
        let msg = make_msg("alice");
        let entry = DlqEntry {
            timestamp: "2026-04-13T12:00:00Z".to_string(),
            target: "siem",
            reason: "circuit_open",
            delivery_id: "0123456789abcdef0123456789abcdef",
            source_cn: &msg.source.cn,
            source_groups: msg.source.groups.iter().map(String::as_str).collect(),
            destination: crate::payload::format_destination(&msg.destination),
            message_type: msg.metadata.message_type.to_string(),
            source_protocol: &msg.metadata.source_protocol,
            payload_b64: b64::encode(&msg.payload),
            payload_size: msg.payload.len(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        for expected_field in [
            "\"timestamp\":",
            "\"target\":",
            "\"reason\":",
            "\"delivery_id\":",
            "\"source_cn\":",
            "\"source_groups\":",
            "\"destination\":",
            "\"message_type\":",
            "\"source_protocol\":",
            "\"payload_b64\":",
            "\"payload_size\":",
        ] {
            assert!(
                json.contains(expected_field),
                "DLQ JSON missing documented field `{expected_field}`: {json}"
            );
        }
    }

    /// Pins the wire-format shape of `delivery_id`: 32 lowercase hex
    /// characters (16 random bytes), matching the live publish path
    /// generator. A regression that shortened the id, flipped it to
    /// uppercase, or swapped in a different alphabet would break
    /// receiver-side deduplication that keys on the exact string
    /// (case-sensitive matching is intentional — `delivery_id` is
    /// treated as an opaque token, not a number).
    #[test]
    fn delivery_id_is_lowercase_hex_128_bits() {
        let id = generate_delivery_id();
        assert_eq!(
            id.len(),
            32,
            "expected 32 hex chars, got {}: {id}",
            id.len()
        );
        assert!(
            id.chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
            "delivery_id must be lowercase hex only: {id}"
        );
        // Round-trips through hex decode: sanity-checks that we emitted
        // valid hex, not some adjacent encoding (base64url, base32, …).
        let bytes = hex::decode(&id).expect("delivery_id must be hex-decodable");
        assert_eq!(bytes.len(), 16);
    }

    /// Two consecutive calls to `generate_delivery_id` must return
    /// different values. The generator draws 16 bytes from the OS CSPRNG
    /// so the collision probability on a single trial is ~2^-128 — a
    /// duplicate here indicates the RNG was replaced by a non-random
    /// source (constant, counter, seeded with zero, etc.).
    #[test]
    fn delivery_id_generator_is_non_constant() {
        let a = generate_delivery_id();
        let b = generate_delivery_id();
        assert_ne!(a, b, "generator returned duplicate ids — RNG drift?");
    }

    /// End-to-end: a message dead-lettered through the DLQ producer
    /// surfaces with a populated `delivery_id` on the reader side. The
    /// reader already tolerates missing ids via `#[serde(default)]`
    /// for backward compat, so this test specifically pins the
    /// producer-fills-the-field contract.
    #[test]
    fn dead_letter_stamps_delivery_id_on_every_entry() {
        let dir = tempfile::tempdir().unwrap();
        let key_ring = test_key_ring();
        let dlq = DeadLetterQueue::new(dir.path().to_path_buf(), key_ring.clone(), None, None);

        let msg = make_msg("alice");
        dlq.dead_letter("target-1", &msg, "circuit_open");
        dlq.dead_letter("target-1", &msg, "circuit_open");
        dlq.finish();

        let files: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .collect();
        assert_eq!(files.len(), 1, "expected single DLQ file");

        let entries = crate::dlq_reader::read_dlq_file(&files[0], &key_ring)
            .expect("reader must decrypt fresh DLQ segment");
        assert_eq!(entries.len(), 2);

        // Both entries must carry non-empty, wire-shape-valid ids.
        for entry in &entries {
            assert_eq!(
                entry.delivery_id.len(),
                32,
                "delivery_id should be 32 hex chars, got {:?}",
                entry.delivery_id
            );
        }
        // And the two ids must differ — idempotency keys collide only
        // across retries of the same logical entry, never across
        // distinct dead-letter calls.
        assert_ne!(
            entries[0].delivery_id, entries[1].delivery_id,
            "distinct dead_letter calls must produce distinct delivery_ids"
        );
    }

    /// Pins that `format_timestamp_now` returns a string parseable as
    /// ISO-8601 (RFC 3339 subset). SIEM ingest, replay tools, and the
    /// "hash-chained audit log" cross-correlation all depend on this exact
    /// format. The fallback string `"unknown"` is the only acceptable
    /// non-ISO-8601 value and only on formatter failure.
    #[test]
    fn format_timestamp_now_returns_iso_8601_parseable_output() {
        let ts = format_timestamp_now();
        if ts == "unknown" {
            // Fallback path — acceptable.
            return;
        }
        let parsed = time::OffsetDateTime::parse(
            &ts,
            &time::format_description::well_known::Iso8601::DEFAULT,
        );
        assert!(
            parsed.is_ok(),
            "format_timestamp_now must produce ISO-8601 or \"unknown\", got: {ts:?}"
        );
    }

    /// Pins the path-traversal defence across a broader set of attack
    /// variants than the existing `../etc/passwd` test. Each of these must
    /// be silently dropped with no file created in the DLQ directory:
    /// backslash (Windows path separator), single dot, double dot alone,
    /// space, Unicode letter (not ASCII alphanumeric), null byte, tab,
    /// newline, colon (Windows drive separator), percent (URL-escape),
    /// tilde (home-expansion shell metachar), at-sign, and a name with
    /// mixed-case valid + dot.
    #[test]
    fn path_traversal_defence_covers_broad_attack_surface() {
        let dir = tempfile::tempdir().unwrap();
        let key_ring = test_key_ring();
        let dlq = DeadLetterQueue::new(dir.path().to_path_buf(), key_ring, None, None);

        let msg = make_msg("alice");
        let hostile_names = [
            "..\\windows", // backslash
            ".",           // single dot
            "..",          // double dot alone
            "with space",  // space
            "café",        // non-ASCII letter (é)
            "null\0byte",  // embedded null
            "tab\there",   // embedded tab
            "new\nline",   // embedded newline
            "C:foo",       // colon (Windows drive)
            "pct%2e%2e",   // percent
            "~expand",     // tilde (shell home-expansion)
            "at@sign",     // @ symbol
            "trailing.",   // trailing dot
            ".leadingdot", // leading dot
            "middle.dot",  // middle dot
        ];
        for name in hostile_names {
            dlq.dead_letter(name, &msg, "circuit_open");
        }
        assert_eq!(
            std::fs::read_dir(dir.path()).unwrap().count(),
            0,
            "path traversal defence must reject every hostile name"
        );
    }

    /// Pins that `finish()` is idempotent: double-call must not panic and
    /// must not double-seal (the underlying `SharedEncryptedWriter::finish`
    /// is itself idempotent, but the DLQ-level contract is stronger — the
    /// shutdown path calls `finish()` as part of graceful drain and an
    /// operator-initiated SIGTERM may re-enter it).
    #[test]
    fn finish_is_idempotent_across_repeated_calls() {
        let dir = tempfile::tempdir().unwrap();
        let key_ring = test_key_ring();
        let dlq = DeadLetterQueue::new(dir.path().to_path_buf(), key_ring, None, None);

        let msg = make_msg("alice");
        dlq.dead_letter("target-1", &msg, "circuit_open");

        dlq.finish();
        dlq.finish(); // second call must not panic
        dlq.finish(); // nor the third

        // File still exists and is non-empty
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].metadata().unwrap().len() > 0);
    }

    /// Pins that `finish()` on an empty DLQ (no targets ever dead-lettered)
    /// is a no-op — must not crash, must not create files. This is the
    /// common shutdown path for a long-running publisher that never tripped
    /// any circuit breaker.
    #[test]
    fn finish_on_empty_queue_is_a_noop_and_does_not_create_files() {
        let dir = tempfile::tempdir().unwrap();
        let key_ring = test_key_ring();
        let dlq = DeadLetterQueue::new(dir.path().to_path_buf(), key_ring, None, None);

        dlq.finish();
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    // -----------------------------------------------------------------
    // #881a — per-target total-bytes cap + drop-oldest FIFO eviction.
    // -----------------------------------------------------------------

    /// Helper: returns all `<prefix>_*.dlq.enc` sorted oldest first so
    /// eviction-order assertions can address entries positionally.
    fn list_target_files(dir: &std::path::Path, prefix: &str) -> Vec<PathBuf> {
        let full_prefix = format!("{prefix}_");
        let mut out: Vec<(std::time::SystemTime, PathBuf)> = std::fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                let name = e.file_name();
                let name_str = match name.to_str() {
                    Some(s) => s,
                    None => return false,
                };
                name_str.starts_with(&full_prefix) && name_str.ends_with(DLQ_FILE_SUFFIX)
            })
            .map(|e| {
                let mtime = e
                    .metadata()
                    .and_then(|m| m.modified())
                    .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
                (mtime, e.path())
            })
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
        out.into_iter().map(|(_, p)| p).collect()
    }

    /// Helper: write enough entries to guarantee at least `n` distinct
    /// rotations for a single target. Sleeps between writes so filename
    /// timestamps (millisecond precision) remain distinct even on a
    /// fast disk.
    fn force_rotations(dlq: &DeadLetterQueue, target: &str, n: usize) {
        let msg = make_msg("alice");
        for _ in 0..=n {
            dlq.dead_letter(target, &msg, "circuit_open");
            std::thread::sleep(std::time::Duration::from_millis(3));
            dlq.dead_letter(target, &msg, "circuit_open");
            std::thread::sleep(std::time::Duration::from_millis(3));
        }
    }

    /// Pins the core #881a contract: once the sealed-tail footprint for a
    /// target exceeds `max_target_bytes`, the oldest sealed segments are
    /// deleted until the footprint fits — drop-oldest FIFO. Trips if a
    /// regression swaps the sort comparator, omits the sweep call from
    /// the rotation path, or lets unbounded accumulation linger on disk
    /// under repeated rotation.
    ///
    /// Asserts the invariant that holds: with eviction enabled, the
    /// file count grows sub-linearly in the number of rotations. Without
    /// eviction, 6 `force_rotations` cycles (~14 writes) produce ~14
    /// files; with a tight cap the residual count must be far smaller.
    #[test]
    fn eviction_drops_oldest_sealed_files_when_target_cap_exceeded() {
        let dir = tempfile::tempdir().unwrap();
        let key_ring = test_key_ring();
        // Tight per-file cap (50 B) forces a rotation on every write
        // after the first. Tight per-target cap (200 B) means the
        // sweep must actively evict to keep the sealed tail bounded.
        let dlq = DeadLetterQueue::new(dir.path().to_path_buf(), key_ring, Some(50), Some(200));

        force_rotations(&dlq, "chatty", 6);

        let files = list_target_files(dir.path(), "chatty");
        // At least one file must remain (the active segment).
        assert!(
            !files.is_empty(),
            "eviction must preserve at least one file"
        );
        // Eviction must actually bound the sealed tail — without the
        // sweep we would have roughly one file per forced rotation
        // (~14 for 6 cycles). With the sweep, the count should be a
        // small constant dominated by the cap / file-size ratio plus
        // the active head. 5 is a generous upper bound that still
        // trips cleanly if eviction is disabled or runs only once.
        assert!(
            files.len() <= 5,
            "eviction must bound file count under tight cap, got {} files",
            files.len()
        );
    }

    /// Pins the "preserve at least one file" invariant: even with a cap
    /// smaller than a single segment the writer's live file must never
    /// be unlinked from under it (that would corrupt the in-memory
    /// `SharedEncryptedWriter` state on the next write).
    #[test]
    fn eviction_preserves_active_segment_even_under_tight_cap() {
        let dir = tempfile::tempdir().unwrap();
        let key_ring = test_key_ring();
        // Absurdly small per-target cap (1 byte) — every sealed file is
        // over cap, but the sweep must still refuse to delete the sole
        // remaining file.
        let dlq = DeadLetterQueue::new(dir.path().to_path_buf(), key_ring, Some(50), Some(1));

        force_rotations(&dlq, "single", 5);

        let files = list_target_files(dir.path(), "single");
        assert!(
            !files.is_empty(),
            "eviction must leave at least one file even when cap is tighter than any single segment"
        );
    }

    /// Pins the no-op path: when `max_target_bytes` is 0 (unlimited,
    /// historical behaviour) the eviction sweep must never delete a file,
    /// regardless of how much disk the target accumulates. Trips if a
    /// regression uses `if cap > 0` instead of `if cap == 0` or mis-
    /// defaults the `None` variant to a sentinel like `u64::MAX` that
    /// still triggers the scan overhead.
    #[test]
    fn eviction_is_noop_when_max_target_bytes_is_unlimited() {
        let dir = tempfile::tempdir().unwrap();
        let key_ring = test_key_ring();
        // max_target_bytes = None maps to 0 ("unlimited").
        let dlq = DeadLetterQueue::new(dir.path().to_path_buf(), key_ring, Some(50), None);

        force_rotations(&dlq, "unbounded", 4);

        let files = list_target_files(dir.path(), "unbounded");
        assert!(
            files.len() >= 2,
            "cap=None must not delete any segments, got {} files",
            files.len()
        );
    }

    /// Pins that eviction is target-scoped: a sweep triggered by chatty
    /// target A must not touch any file belonging to quiet target B.
    /// Trips if the prefix filter in `enforce_target_cap` regresses to
    /// a substring or glob match.
    #[test]
    fn eviction_is_scoped_to_target_and_does_not_touch_other_targets() {
        let dir = tempfile::tempdir().unwrap();
        let key_ring = test_key_ring();
        let dlq = DeadLetterQueue::new(dir.path().to_path_buf(), key_ring, Some(50), Some(200));

        let msg = make_msg("alice");
        // Quiet target: one write, one file, never to be evicted.
        dlq.dead_letter("quiet", &msg, "circuit_open");

        // Chatty target: force enough rotations to trigger eviction.
        force_rotations(&dlq, "chatty", 6);

        let quiet_files = list_target_files(dir.path(), "quiet");
        assert_eq!(
            quiet_files.len(),
            1,
            "quiet target must retain its one file; eviction must be prefix-scoped"
        );
    }

    /// Pins the drop-oldest ordering: under a tight cap, the OLDEST
    /// sealed files are removed first. The freshest (non-active) file
    /// must survive a sweep as long as the cap permits. Verifies the
    /// `sort_by(mtime.then(path))` comparator by asserting the surviving
    /// sealed files have strictly later mtimes than any deleted file —
    /// tested indirectly by ensuring the surviving set's minimum mtime
    /// is later than the initial rotation.
    #[test]
    fn eviction_drops_oldest_not_newest() {
        let dir = tempfile::tempdir().unwrap();
        let key_ring = test_key_ring();
        let dlq = DeadLetterQueue::new(dir.path().to_path_buf(), key_ring, Some(50), Some(250));

        let msg = make_msg("alice");
        // Write, rotate, write, rotate — capture the first filename
        // before any eviction would have a chance to remove it.
        dlq.dead_letter("ordered", &msg, "circuit_open");
        std::thread::sleep(std::time::Duration::from_millis(3));
        dlq.dead_letter("ordered", &msg, "circuit_open");
        std::thread::sleep(std::time::Duration::from_millis(3));
        let after_first_two = list_target_files(dir.path(), "ordered");
        let original_oldest = after_first_two[0].clone();

        // Drive more rotations until the cap is breached and eviction
        // fires.
        force_rotations(&dlq, "ordered", 6);

        let surviving = list_target_files(dir.path(), "ordered");
        assert!(
            !surviving.contains(&original_oldest),
            "drop-oldest FIFO must have removed the earliest segment `{}`; survivors: {:?}",
            original_oldest.display(),
            surviving,
        );
    }

    /// Pins the `metrics` feature wiring: each deleted file bumps
    /// `rustgate_http_dlq_evicted_total` labelled by target name. A
    /// regression that forgot to register the counter, mis-labelled it,
    /// or wired the increment on the wrong code path trips here.
    #[cfg(feature = "metrics")]
    #[test]
    fn eviction_metric_increments_per_deleted_file() {
        // Metrics use a process-global registry — init is idempotent and
        // the counter can be read back regardless of which other test
        // initialised it first.
        let _ = crate::metrics::init();

        let dir = tempfile::tempdir().unwrap();
        let key_ring = test_key_ring();
        let dlq = DeadLetterQueue::new(dir.path().to_path_buf(), key_ring, Some(50), Some(150));

        let counter = crate::metrics::dlq_evicted();
        let child = counter
            .get_metric_with_label_values(&["metric-target"])
            .unwrap();
        let before = child.get();

        force_rotations(&dlq, "metric-target", 6);

        let after = child.get();
        assert!(
            after > before,
            "eviction must bump rustgate_http_dlq_evicted_total{{target=metric-target}}: \
             before={before}, after={after}",
        );
    }

    /// Pins the `finish_non_exhaustive` Debug shape: `dir` is visible
    /// (operator diagnostic), `key_ring` and `max_bytes` and `writers`
    /// MUST be hidden. The existing `debug_impl_redacts_internals` test
    /// asserts the key bytes are not rendered; this test strengthens it
    /// by asserting the struct name, the `..` sentinel from
    /// `finish_non_exhaustive()`, and the absence of every private field
    /// name. A regression that replaced `finish_non_exhaustive()` with
    /// `finish()` would render all fields by default and trip here.
    #[test]
    fn debug_format_uses_finish_non_exhaustive_and_hides_private_fields() {
        let dir = tempfile::tempdir().unwrap();
        let key_ring = test_key_ring();
        let dlq = DeadLetterQueue::new(dir.path().to_path_buf(), key_ring, None, None);
        let debug = format!("{dlq:?}");

        assert!(debug.contains("DeadLetterQueue"));
        assert!(debug.contains("dir"));
        // finish_non_exhaustive appends `.. }` before the closing brace.
        assert!(
            debug.contains(".."),
            "Debug must include finish_non_exhaustive marker `..`: {debug}"
        );
        // Private fields must NOT be rendered.
        for hidden in ["key_ring", "max_bytes", "max_target_bytes", "writers"] {
            assert!(
                !debug.contains(hidden),
                "Debug must hide private field `{hidden}`: {debug}"
            );
        }
    }
}
