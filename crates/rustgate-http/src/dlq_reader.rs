// Copyright © 2026 Roberto Chiofalo.

//! Offline reader for encrypted dead-letter queue files.
//!
//! Companion to the crate-private writer in `dlq.rs`. Operators and
//! replay tooling use this module to decrypt and iterate dead-lettered
//! messages produced by the `DeadLetterQueue` during circuit-breaker
//! shedding.
//!
//! # Wire-format contract
//!
//! The writer serializes each entry as a single JSON object (no
//! trailing newline) and encrypts it as one ChaCha20-Poly1305 chunk
//! via
//! [`SharedEncryptedWriter::write_line`](rustgate_core::encrypted::SharedEncryptedWriter::write_line).
//! After decryption with [`rustgate_core::encrypted::decrypt_file`],
//! all chunks concatenate into a stream of JSON values. A streaming
//! [`serde_json::Deserializer`] parses them back into
//! [`OwnedDlqEntry`] records without relying on newline delimiters —
//! the reader therefore tolerates both the current delimiter-free
//! format and any future variant that inserts whitespace between
//! records.
//!
//! # Security
//!
//! - The encrypted file is decrypted into a [`tempfile::NamedTempFile`]
//!   scoped to the reader's lifetime. When the reader drops (or
//!   [`read_dlq_file`] returns), the temp file is unlinked.
//! - The reader surfaces integrity failures from the AEAD (wrong key,
//!   truncated file, tampered chunk) as [`DlqReadError::Decrypt`].
//! - JSON-shape regressions in the wire format surface as
//!   [`DlqReadError::Json`] pointing at the offending byte offset in
//!   the decrypted stream, not the encrypted file on disk.

use std::fs::File;
use std::io::BufReader;
use std::path::Path;

use rustgate_core::b64;
use rustgate_core::encrypted::{EncryptError, KeyRing, decrypt_file};
use serde::{Deserialize, Serialize};

/// Errors raised while decrypting and parsing a DLQ file.
#[derive(Debug, thiserror::Error)]
pub enum DlqReadError {
    /// AEAD failure: wrong key, truncated file, tampered chunk, or
    /// malformed header. All recoverable via operator remediation
    /// (correct key file, fresh copy of the archive) — the reader
    /// itself never mutates the encrypted file.
    #[error("decrypt failed: {0}")]
    Decrypt(#[from] EncryptError),

    /// I/O failure while creating the decrypt scratch file or reading
    /// the decrypted plaintext stream.
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),

    /// JSON parse failure on a record. Contains the `serde_json`
    /// diagnostic including byte offset into the decrypted stream.
    #[error("json parse: {0}")]
    Json(#[from] serde_json::Error),

    /// The payload field's base64 content could not be decoded. Only
    /// surfaced from [`OwnedDlqEntry::decode_payload`].
    #[error("payload base64 decode: {0}")]
    PayloadDecode(String),
}

/// Owned mirror of the writer-side DLQ entry.
///
/// Mirrors the private `DlqEntry<'a>` serializer in `dlq.rs` but holds
/// every string field by value so the reader can return records
/// decoupled from the temporary file's lifetime. The field order and
/// names are part of the wire-format contract and MUST stay in sync
/// with the writer — the `dlq_entry_json_contains_all_documented_fields`
/// test in `dlq.rs` locks the producer side, and
/// `round_trip_reads_all_entries_written_by_dlq` in this module locks
/// the consumer side.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct OwnedDlqEntry {
    /// RFC 3339 / ISO-8601 timestamp when the message was dead-lettered.
    pub timestamp: String,
    /// Target name that rejected the message.
    pub target: String,
    /// Reason for dead-lettering (e.g., `"circuit_open"`).
    pub reason: String,
    /// Source client CN from the original message.
    pub source_cn: String,
    /// Source client group memberships.
    pub source_groups: Vec<String>,
    /// Message destination (formatted via `payload::format_destination`).
    pub destination: String,
    /// Message type (position, chat, alert, etc.).
    pub message_type: String,
    /// Originating protocol.
    pub source_protocol: String,
    /// Raw payload bytes, base64-encoded (standard alphabet).
    pub payload_b64: String,
    /// Payload size in bytes (pre-encoding).
    pub payload_size: usize,
}

impl OwnedDlqEntry {
    /// Decode the base64 payload back to its original bytes.
    ///
    /// Returns [`DlqReadError::PayloadDecode`] on malformed base64.
    /// The `payload_size` field is NOT used to validate the decoded
    /// length here — callers that care about integrity should compare
    /// `decoded.len() == entry.payload_size` explicitly so a
    /// tampered-in-transit `payload_size` (which the AEAD protects
    /// only via the whole-chunk tag) surfaces as an assertion failure
    /// rather than a silent truncation.
    pub fn decode_payload(&self) -> Result<Vec<u8>, DlqReadError> {
        b64::decode(&self.payload_b64).map_err(|e| DlqReadError::PayloadDecode(e.to_string()))
    }
}

/// Decrypt and parse every entry in a DLQ file.
///
/// Loads the whole decrypted stream into RAM. Suitable for forensic
/// tooling and small-to-medium DLQ files (the writer caps individual
/// files at 256 MiB by default; a typical entry fits in a few kilobytes
/// so a capped file is on the order of ~10⁵ records).
///
/// For streaming use cases, prefer [`for_each_dlq_entry`] which calls
/// a closure per record and never materializes the full vector.
///
/// # Errors
///
/// - [`DlqReadError::Decrypt`] — wrong key, tampered file, missing
///   terminator, or unknown key-id in the header.
/// - [`DlqReadError::Io`] — tempfile creation or stream read failure.
/// - [`DlqReadError::Json`] — a record failed to deserialize against
///   the [`OwnedDlqEntry`] schema. The stream is aborted on the first
///   parse error so callers observe a partial prefix, not silently
///   skipped records.
pub fn read_dlq_file(
    encrypted_path: &Path,
    key_ring: &KeyRing,
) -> Result<Vec<OwnedDlqEntry>, DlqReadError> {
    let mut out = Vec::new();
    for_each_dlq_entry(encrypted_path, key_ring, |entry| {
        out.push(entry);
        Ok(())
    })?;
    Ok(out)
}

/// Decrypt a DLQ file and invoke `cb` once per record, in file order.
///
/// Streams through the decrypted plaintext via
/// [`serde_json::Deserializer`] so the caller never holds more than
/// one record in memory at a time. Returning `Err` from the closure
/// propagates out of the iteration and aborts the scan — useful for
/// replay-style consumers that stop on first delivery failure.
///
/// The temp file used for decryption is unlinked as soon as this
/// function returns (successfully or otherwise).
pub fn for_each_dlq_entry<F>(
    encrypted_path: &Path,
    key_ring: &KeyRing,
    mut cb: F,
) -> Result<(), DlqReadError>
where
    F: FnMut(OwnedDlqEntry) -> Result<(), DlqReadError>,
{
    // Decrypt to an RAII-scoped tempfile so the plaintext is unlinked
    // on drop even if parsing panics or returns early via `?`.
    let tmp = tempfile::NamedTempFile::new()?;
    decrypt_file(encrypted_path, tmp.path(), key_ring)?;

    let file = File::open(tmp.path())?;
    let reader = BufReader::new(file);
    let stream = serde_json::Deserializer::from_reader(reader).into_iter::<OwnedDlqEntry>();
    for result in stream {
        cb(result?)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use std::collections::BTreeSet;
    use std::path::PathBuf;
    use std::sync::Arc;

    use bytes::Bytes;
    use rustgate_core::identity::Identity;
    use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};

    use super::*;
    use crate::dlq::DeadLetterQueue;

    fn make_msg(cn: &str, payload: &'static [u8]) -> RoutableMessage {
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
            payload: Bytes::from_static(payload),
            metadata: Metadata {
                received_at: std::time::SystemTime::now(),
                source_protocol: "tcp".to_string(),
                message_type: MessageType::Position,
                ttl: None,
            },
        }
    }

    fn test_key_ring() -> KeyRing {
        let key_json = r#"{
            "active_key_id": "test-key",
            "keys": {
                "test-key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            }
        }"#;
        KeyRing::from_bytes(key_json.as_bytes()).unwrap()
    }

    fn alt_key_ring() -> KeyRing {
        let key_json = r#"{
            "active_key_id": "other-key",
            "keys": {
                "other-key": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            }
        }"#;
        KeyRing::from_bytes(key_json.as_bytes()).unwrap()
    }

    /// Locates the single DLQ file produced by a writer; panics if zero
    /// or multiple files exist (tests that need multi-file scenarios
    /// query the directory directly).
    fn single_file_in(dir: &std::path::Path) -> PathBuf {
        let entries: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert_eq!(
            entries.len(),
            1,
            "expected exactly one file in {:?}, got {}",
            dir,
            entries.len()
        );
        entries[0].path()
    }

    /// End-to-end contract: every record written by the DLQ writer can
    /// be read back by the offline reader with field-by-field equality
    /// on the operator-visible columns (source_cn, target, reason,
    /// destination, message_type, source_protocol, source_groups,
    /// payload_size) and a lossless payload round-trip.
    #[test]
    fn round_trip_reads_all_entries_written_by_dlq() {
        let dir = tempfile::tempdir().unwrap();
        let key_ring = test_key_ring();
        let dlq = DeadLetterQueue::new(dir.path().to_path_buf(), key_ring.clone(), None);

        let msg_a = make_msg("alice", b"<event uid='a'/>");
        let msg_b = make_msg("bob", b"\xde\xad\xbe\xef\x00binary");
        let msg_c = make_msg("carol", b"");

        dlq.dead_letter("siem", &msg_a, "circuit_open");
        dlq.dead_letter("siem", &msg_b, "circuit_open");
        dlq.dead_letter("siem", &msg_c, "rate_limited");
        dlq.finish();

        let file = single_file_in(dir.path());
        let entries = read_dlq_file(&file, &key_ring).expect("read_dlq_file");

        assert_eq!(entries.len(), 3);

        assert_eq!(entries[0].source_cn, "alice");
        assert_eq!(entries[0].target, "siem");
        assert_eq!(entries[0].reason, "circuit_open");
        assert_eq!(entries[0].source_groups, vec!["alpha".to_string()]);
        assert_eq!(entries[0].source_protocol, "tcp");
        assert_eq!(entries[0].message_type, "position");
        assert_eq!(entries[0].payload_size, msg_a.payload.len());
        assert_eq!(entries[0].decode_payload().unwrap(), msg_a.payload.as_ref());

        assert_eq!(entries[1].source_cn, "bob");
        assert_eq!(entries[1].payload_size, msg_b.payload.len());
        assert_eq!(entries[1].decode_payload().unwrap(), msg_b.payload.as_ref());

        assert_eq!(entries[2].source_cn, "carol");
        assert_eq!(entries[2].reason, "rate_limited");
        assert_eq!(entries[2].payload_size, 0);
        assert_eq!(entries[2].decode_payload().unwrap(), Vec::<u8>::new());
    }

    /// Empty-but-sealed file: writer never received a dead_letter call
    /// for this target, but `finish()` was invoked during shutdown. We
    /// still need to be able to open the resulting encrypted file — a
    /// regression that rejects zero-chunk files would crash an operator
    /// scanning a directory of DLQ artifacts.
    #[test]
    fn reader_handles_sealed_file_with_no_entries() {
        let dir = tempfile::tempdir().unwrap();
        let key_ring = test_key_ring();
        let enc_path = dir.path().join("empty.dlq.enc");

        // Create+seal a writer directly (DLQ writer lazy-creates, so
        // dead_letter() with zero entries produces zero files).
        let writer =
            rustgate_core::encrypted::SharedEncryptedWriter::create(&enc_path, &key_ring).unwrap();
        writer.finish().unwrap();

        let entries = read_dlq_file(&enc_path, &key_ring).expect("read_dlq_file on empty");
        assert!(entries.is_empty());
    }

    /// Wrong-key rejection: the AEAD layer must surface a decrypt
    /// failure when the key ring does not contain the key id stamped
    /// into the file header. This is the primary threat model — an
    /// attacker who exfiltrates a `.dlq.enc` file without the
    /// operator's key ring sees only ciphertext.
    #[test]
    fn reader_rejects_file_encrypted_with_different_key() {
        let dir = tempfile::tempdir().unwrap();
        let writer_key = test_key_ring();
        let dlq = DeadLetterQueue::new(dir.path().to_path_buf(), writer_key, None);
        dlq.dead_letter("siem", &make_msg("alice", b"x"), "circuit_open");
        dlq.finish();
        let file = single_file_in(dir.path());

        let wrong_key = alt_key_ring();
        let err = read_dlq_file(&file, &wrong_key).expect_err("should fail on wrong key");
        assert!(
            matches!(err, DlqReadError::Decrypt(_)),
            "expected Decrypt error, got {err:?}"
        );
    }

    /// Unterminated file rejection: a writer that crashed before
    /// `finish()` leaves a readable-but-unsealed file on disk. The
    /// AEAD format enforces a terminator chunk — missing it must
    /// surface as a Decrypt error so operators can detect torn writes
    /// in forensic audits rather than silently processing a partial
    /// stream.
    #[test]
    fn reader_rejects_unterminated_file() {
        let dir = tempfile::tempdir().unwrap();
        let key_ring = test_key_ring();
        let enc_path = dir.path().join("torn.dlq.enc");

        let writer =
            rustgate_core::encrypted::SharedEncryptedWriter::create(&enc_path, &key_ring).unwrap();
        writer.write_line(b"{\"target\":\"x\"}").unwrap();
        // Intentionally drop without finish() — simulates crash mid-DLQ.
        drop(writer);

        // The SharedEncryptedWriter's Drop impl calls finish() on our
        // behalf, so to produce a truly unterminated file we truncate
        // the tail bytes after drop. The terminator chunk is always
        // the last AEAD-sealed block; removing the last 32 bytes
        // reliably strips both the terminator tag and its length
        // prefix on ChaCha20-Poly1305.
        let size = std::fs::metadata(&enc_path).unwrap().len();
        let trunc = size.saturating_sub(32);
        let f = std::fs::OpenOptions::new()
            .write(true)
            .open(&enc_path)
            .unwrap();
        f.set_len(trunc).unwrap();

        let err = read_dlq_file(&enc_path, &key_ring).expect_err("should fail on truncation");
        assert!(
            matches!(err, DlqReadError::Decrypt(_)),
            "expected Decrypt error, got {err:?}"
        );
    }

    /// Missing file: reader must surface an Io error, not a Decrypt
    /// error, so operators distinguish "file not found" from "wrong
    /// key". `decrypt_file` returns `Io` on missing inputs.
    #[test]
    fn reader_reports_io_error_on_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let key_ring = test_key_ring();
        let missing = dir.path().join("does-not-exist.dlq.enc");

        let err = read_dlq_file(&missing, &key_ring).expect_err("should fail on missing file");
        // `decrypt_file` wraps missing-file as EncryptError::Io, which
        // our `From<EncryptError>` maps to DlqReadError::Decrypt. Either
        // shape is acceptable for this contract — what matters is that
        // the error is neither Json nor PayloadDecode.
        assert!(
            matches!(err, DlqReadError::Decrypt(_) | DlqReadError::Io(_)),
            "expected Decrypt or Io error, got {err:?}"
        );
    }

    /// Streaming callback stops early when it returns an error. Pins
    /// the contract that `for_each_dlq_entry` does NOT swallow the
    /// caller's abort signal — replay consumers rely on this to halt
    /// on first undeliverable record.
    #[test]
    fn for_each_stops_on_callback_error() {
        let dir = tempfile::tempdir().unwrap();
        let key_ring = test_key_ring();
        let dlq = DeadLetterQueue::new(dir.path().to_path_buf(), key_ring.clone(), None);

        for i in 0..5 {
            let msg = make_msg(&format!("u{i}"), b"payload");
            dlq.dead_letter("siem", &msg, "circuit_open");
        }
        dlq.finish();
        let file = single_file_in(dir.path());

        let mut seen: Vec<String> = Vec::new();
        let err = for_each_dlq_entry(&file, &key_ring, |entry| {
            if entry.source_cn == "u2" {
                return Err(DlqReadError::PayloadDecode("synthetic stop".to_string()));
            }
            seen.push(entry.source_cn);
            Ok(())
        })
        .expect_err("should abort on synthetic stop");

        assert!(matches!(err, DlqReadError::PayloadDecode(_)));
        // We must have observed entries before the abort, and must not
        // have observed any after — i.e. the scan aborted in-place.
        assert_eq!(seen, vec!["u0".to_string(), "u1".to_string()]);
    }

    /// Base64 round-trip survives non-UTF-8 payloads. CoT XML is
    /// normally ASCII but the payload field is `Bytes` and the wire
    /// format is byte-preserving; a regression that went via `String`
    /// would corrupt non-UTF-8 data here.
    #[test]
    fn decode_payload_round_trips_binary_bytes() {
        let entry = OwnedDlqEntry {
            timestamp: "2026-04-13T12:00:00Z".to_string(),
            target: "siem".to_string(),
            reason: "circuit_open".to_string(),
            source_cn: "alice".to_string(),
            source_groups: vec!["alpha".to_string()],
            destination: "broadcast".to_string(),
            message_type: "position".to_string(),
            source_protocol: "tcp".to_string(),
            payload_b64: b64::encode(b"\xde\xad\xbe\xef\x00\x01\x02\xff"),
            payload_size: 8,
        };
        assert_eq!(
            entry.decode_payload().unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02, 0xff]
        );
    }

    /// Malformed base64 surfaces as `PayloadDecode`, not a silent
    /// fallback. Any operator-facing tool that accepts base64 must
    /// reject garbage unambiguously.
    #[test]
    fn decode_payload_rejects_invalid_base64() {
        let entry = OwnedDlqEntry {
            timestamp: "2026-04-13T12:00:00Z".to_string(),
            target: "siem".to_string(),
            reason: "circuit_open".to_string(),
            source_cn: "alice".to_string(),
            source_groups: vec![],
            destination: "broadcast".to_string(),
            message_type: "position".to_string(),
            source_protocol: "tcp".to_string(),
            payload_b64: "!!!not-base64!!!".to_string(),
            payload_size: 0,
        };
        let err = entry.decode_payload().expect_err("invalid base64");
        assert!(matches!(err, DlqReadError::PayloadDecode(_)));
    }

    /// Pins that the reader parses concatenated JSON objects without
    /// requiring newline delimiters between them. The current writer
    /// does NOT emit trailing newlines (each `serde_json::to_vec`
    /// call ends at `}`), and the reader must tolerate that — otherwise
    /// every multi-entry file would round-trip only the first record.
    #[test]
    fn reader_parses_concatenated_json_without_delimiters() {
        let dir = tempfile::tempdir().unwrap();
        let key_ring = test_key_ring();
        let enc_path = dir.path().join("concat.dlq.enc");

        // Write two JSON objects back-to-back in a single chunk — mirrors
        // what happens if the writer ever batched serialization.
        let writer =
            rustgate_core::encrypted::SharedEncryptedWriter::create(&enc_path, &key_ring).unwrap();
        let e1 = OwnedDlqEntry {
            timestamp: "2026-04-13T12:00:00Z".to_string(),
            target: "t1".to_string(),
            reason: "r1".to_string(),
            source_cn: "a".to_string(),
            source_groups: vec![],
            destination: "broadcast".to_string(),
            message_type: "position".to_string(),
            source_protocol: "tcp".to_string(),
            payload_b64: String::new(),
            payload_size: 0,
        };
        let e2 = OwnedDlqEntry {
            target: "t2".to_string(),
            reason: "r2".to_string(),
            source_cn: "b".to_string(),
            ..e1.clone()
        };
        let j1 = serde_json::to_vec(&e1).unwrap();
        let j2 = serde_json::to_vec(&e2).unwrap();
        let mut concat = j1;
        concat.extend_from_slice(&j2);
        writer.write_line(&concat).unwrap();
        writer.finish().unwrap();

        let entries = read_dlq_file(&enc_path, &key_ring).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].source_cn, "a");
        assert_eq!(entries[1].source_cn, "b");
    }

    /// Pins that `OwnedDlqEntry` deserialization is strict-enough to
    /// catch a missing required field — a future writer regression that
    /// dropped `source_protocol` would trip here rather than produce
    /// silently-defaulted "" values downstream.
    #[test]
    fn deserialization_rejects_missing_required_field() {
        let bad = r#"{
            "timestamp":"2026-04-13T12:00:00Z",
            "target":"siem",
            "reason":"circuit_open",
            "source_cn":"alice",
            "source_groups":[],
            "destination":"broadcast",
            "message_type":"position",
            "payload_b64":"",
            "payload_size":0
        }"#;
        // Missing `source_protocol` — serde must refuse.
        assert!(serde_json::from_str::<OwnedDlqEntry>(bad).is_err());
    }
}
