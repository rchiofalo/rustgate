// Copyright © 2026 Roberto Chiofalo.

//! Encrypted dead-letter queue for circuit-breaker-shed messages.
//!
//! When a target's circuit breaker is open, messages are persisted to
//! ChaCha20-Poly1305 encrypted files (via [`rustgate_core::encrypted`])
//! for later forensic recovery or replay. Each target gets a separate
//! file per process lifetime, named `{target}_{timestamp}.dlq.enc`.
//!
//! # Recovery
//!
//! Dead-lettered messages can be recovered offline using
//! [`rustgate_core::encrypted::decrypt_file`] with the same key ring.
//! Each decrypted chunk is one JSON line containing the message metadata
//! and base64-encoded payload.

use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;
use std::sync::Mutex;

use rustgate_core::b64;
use rustgate_core::encrypted::{KeyRing, SharedEncryptedWriter};
use rustgate_core::message::RoutableMessage;
use rustgate_core::sanitize::sanitize_for_log;
use serde::Serialize;

/// Default maximum DLQ file size: 256 MiB.
const DEFAULT_DLQ_MAX_BYTES: u64 = 256 * 1024 * 1024;

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
    writers: Mutex<HashMap<String, WriterState>>,
}

/// Per-target writer state tracking accumulated bytes for rotation.
struct WriterState {
    writer: SharedEncryptedWriter,
    bytes_written: u64,
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
    /// Does NOT create any files at construction time — writers are
    /// created lazily when the first message is dead-lettered for a target.
    pub(crate) fn new(dir: PathBuf, key_ring: KeyRing, max_bytes: Option<u64>) -> Self {
        Self {
            dir,
            key_ring,
            max_bytes: max_bytes.unwrap_or(DEFAULT_DLQ_MAX_BYTES),
            writers: Mutex::new(HashMap::new()),
        }
    }

    /// Persist a dead-lettered message for later recovery.
    ///
    /// Fail-open: all errors are logged as warnings but never propagated,
    /// because the DLQ is a best-effort forensic aid, not a critical path.
    pub(crate) fn dead_letter(&self, target_name: &str, msg: &RoutableMessage, reason: &str) {
        // Serialize the entry to JSON
        let entry = DlqEntry {
            timestamp: format_timestamp_now(),
            target: target_name,
            reason,
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
            // Seal the old writer; ignore errors (best-effort)
            let _ = old.writer.finish();
            tracing::info!(
                target = %sanitize_for_log(target_name),
                bytes_written = old.bytes_written,
                "DLQ file rotated (size limit reached)"
            );
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
                cn: cn.to_string(),
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
            metadata: Metadata {
                received_at: std::time::SystemTime::now(),
                source_protocol: "tcp".to_string(),
                message_type: MessageType::Position,
                ttl: None,
            },
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
    }

    #[test]
    fn dlq_creates_writer_lazily() {
        let dir = tempfile::tempdir().unwrap();
        let key_ring = test_key_ring();
        let dlq = DeadLetterQueue::new(dir.path().to_path_buf(), key_ring, None);

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
        let dlq = DeadLetterQueue::new(dir.path().to_path_buf(), key_ring, None);

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
        let dlq = DeadLetterQueue::new(dir.path().to_path_buf(), key_ring, None);

        let msg = make_msg("alice");
        dlq.dead_letter("target-a", &msg, "circuit_open");
        dlq.dead_letter("target-b", &msg, "circuit_open");

        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 2);
    }

    #[test]
    fn dlq_finish_seals_writers() {
        let dir = tempfile::tempdir().unwrap();
        let key_ring = test_key_ring();
        let dlq = DeadLetterQueue::new(dir.path().to_path_buf(), key_ring, None);

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
        let dlq = DeadLetterQueue::new(dir.path().to_path_buf(), key_ring, None);
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
        let dlq = DeadLetterQueue::new(dir.path().to_path_buf(), key_ring, None);

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
        let dlq = DeadLetterQueue::new(dir.path().to_path_buf(), key_ring, Some(50));

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
        let dlq = DeadLetterQueue::new(dir.path().to_path_buf(), key_ring, Some(50));

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
    /// (timestamp, target, reason, source_cn, source_groups, destination,
    /// message_type, source_protocol, payload_b64, payload_size) is present
    /// in the serialized JSON. If a future refactor drops or renames a
    /// field without updating the operator-facing recovery tool, this trips.
    #[test]
    fn dlq_entry_json_contains_all_documented_fields() {
        let msg = make_msg("alice");
        let entry = DlqEntry {
            timestamp: "2026-04-13T12:00:00Z".to_string(),
            target: "siem",
            reason: "circuit_open",
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
        let dlq = DeadLetterQueue::new(dir.path().to_path_buf(), key_ring, None);

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
        let dlq = DeadLetterQueue::new(dir.path().to_path_buf(), key_ring, None);

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
        let dlq = DeadLetterQueue::new(dir.path().to_path_buf(), key_ring, None);

        dlq.finish();
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
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
        let dlq = DeadLetterQueue::new(dir.path().to_path_buf(), key_ring, None);
        let debug = format!("{dlq:?}");

        assert!(debug.contains("DeadLetterQueue"));
        assert!(debug.contains("dir"));
        // finish_non_exhaustive appends `.. }` before the closing brace.
        assert!(
            debug.contains(".."),
            "Debug must include finish_non_exhaustive marker `..`: {debug}"
        );
        // Private fields must NOT be rendered.
        for hidden in ["key_ring", "max_bytes", "writers"] {
            assert!(
                !debug.contains(hidden),
                "Debug must hide private field `{hidden}`: {debug}"
            );
        }
    }
}
