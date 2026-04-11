// Copyright © 2026 Roberto Chiofalo.

//! Hash-chained, tamper-evident audit log writer and verifier.
//!
//! Each audit record (a single JSON object on its own line) is augmented with
//! two fields before being written:
//!
//! - `prev_sha256` — the `sha256` of the previous record, or 64 zero hex
//!   characters for the genesis record (or when continuing an existing chain
//!   from a fresh process start that does not yet know the previous hash).
//! - `sha256` — `SHA-256(prev_sha256_bytes || canonical_json_without_chain_fields)`
//!   where the canonical JSON is the original record re-serialized via
//!   `serde_json` from a `BTreeMap<String, Value>` after removing any
//!   pre-existing `prev_sha256` / `sha256` fields. Using a `BTreeMap`
//!   guarantees deterministic key ordering regardless of whether
//!   `serde_json/preserve_order` is enabled in the workspace. The hash input
//!   uses the raw bytes of the hex-encoded `prev_sha256` (64 ASCII bytes)
//!   followed by the canonical JSON bytes.
//!
//! This makes any in-place tampering detectable: changing a byte in any record
//! invalidates that record's `sha256`, and (because subsequent records chain
//! into it via `prev_sha256`) every following record as well.
//!
//! On rotation the last hash should be written to a separate `<path>.anchor`
//! file via [`write_anchor`] so external systems can pin the chain tip.
//!
//! Note: this is a *hash chain*, not an asymmetric signature. It proves
//! integrity relative to a trusted anchor, not authorship.

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::Path;

use sha2::{Digest, Sha256};

/// Genesis previous-hash value: 64 zero hex characters.
pub const GENESIS_PREV: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Errors that can occur while writing through a [`HashChainWriter`].
#[derive(Debug, thiserror::Error)]
pub enum AuditChainError {
    #[error("io error writing audit log: {0}")]
    Io(#[from] io::Error),
    #[error("audit record on line {line_number} is not a JSON object")]
    NotAnObject { line_number: usize },
    #[error("audit record on line {line_number} is not valid JSON: {source}")]
    InvalidJson {
        line_number: usize,
        #[source]
        source: serde_json::Error,
    },
}

impl From<AuditChainError> for io::Error {
    fn from(value: AuditChainError) -> Self {
        match value {
            AuditChainError::Io(e) => e,
            other => io::Error::other(other.to_string()),
        }
    }
}

/// Streaming hash-chain writer.
///
/// Wraps an inner [`Write`] and rewrites every newline-delimited JSON record
/// passing through it to inject `prev_sha256` and `sha256` chain fields. Bytes
/// are buffered until a `\n` is observed, at which point the buffered line is
/// processed as a single record. Lines that are not JSON objects are rejected
/// at write time so stray output cannot silently break verification later.
#[derive(Debug)]
pub struct HashChainWriter<W: Write> {
    inner: W,
    buf: Vec<u8>,
    prev: String,
    line_number: usize,
}

impl<W: Write> HashChainWriter<W> {
    /// Create a new chain writer starting from `prev` (use [`GENESIS_PREV`]
    /// for a brand-new chain, or the last known hash to continue an existing
    /// chain across process restarts).
    pub fn new(inner: W, prev: String) -> Self {
        Self {
            inner,
            buf: Vec::with_capacity(1024),
            prev,
            line_number: 0,
        }
    }

    /// Return the current chain tip (last `sha256` written, or the initial
    /// `prev` if nothing has been written yet).
    pub fn tip(&self) -> &str {
        &self.prev
    }

    /// Process a single complete line (without trailing newline). The line is
    /// expected to be a JSON object; non-object input is rejected with an
    /// [`AuditChainError`] so verification cannot silently desync.
    fn process_line(&mut self, line: &[u8]) -> Result<(), AuditChainError> {
        self.line_number += 1;
        let line_number = self.line_number;
        // Empty lines are allowed and pass through without advancing the chain.
        if line.is_empty() {
            self.inner.write_all(b"\n")?;
            return Ok(());
        }
        let value: serde_json::Value =
            serde_json::from_slice(line).map_err(|source| AuditChainError::InvalidJson {
                line_number,
                source,
            })?;
        let serde_json::Value::Object(orig) = value else {
            return Err(AuditChainError::NotAnObject { line_number });
        };
        // Convert to a BTreeMap for deterministic key ordering, regardless of
        // whether serde_json/preserve_order is enabled in the workspace.
        let mut map: BTreeMap<String, serde_json::Value> = orig.into_iter().collect();
        let _ = map.remove("prev_sha256");
        let _ = map.remove("sha256");
        let canonical =
            serde_json::to_vec(&map).map_err(|source| AuditChainError::InvalidJson {
                line_number,
                source,
            })?;
        let mut hasher = Sha256::new();
        hasher.update(self.prev.as_bytes());
        hasher.update(&canonical);
        let digest = hex_encode(&hasher.finalize());
        let _ = map.insert(
            "prev_sha256".to_string(),
            serde_json::Value::String(self.prev.clone()),
        );
        let _ = map.insert(
            "sha256".to_string(),
            serde_json::Value::String(digest.clone()),
        );
        let out = serde_json::to_vec(&map).map_err(|source| AuditChainError::InvalidJson {
            line_number,
            source,
        })?;
        self.inner.write_all(&out)?;
        self.inner.write_all(b"\n")?;
        self.prev = digest;
        Ok(())
    }
}

impl<W: Write> Write for HashChainWriter<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(data);
        while let Some(pos) = self.buf.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = self.buf.drain(..=pos).collect();
            // Strip the trailing newline.
            let line = &line[..line.len() - 1];
            self.process_line(line).map_err(io::Error::from)?;
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// Result of verifying a hash-chained audit log.
#[derive(Debug, Clone)]
pub struct VerifyReport {
    /// Total number of records that were validated.
    pub records: usize,
    /// Final chain tip after the last validated record.
    pub tip: String,
}

/// Errors that can occur while verifying a hash-chained audit log.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("io error reading audit log: {0}")]
    Io(#[from] io::Error),
    #[error("record {line} is not a valid JSON object: {source}")]
    InvalidJson {
        line: usize,
        #[source]
        source: serde_json::Error,
    },
    #[error("record {line} is not a JSON object")]
    NotAnObject { line: usize },
    #[error("record {line} is missing field `{field}`")]
    MissingField { line: usize, field: &'static str },
    #[error(
        "record {line}: prev_sha256 mismatch — chain expected `{expected}`, record has `{actual}`"
    )]
    PrevMismatch {
        line: usize,
        expected: String,
        actual: String,
    },
    #[error("record {line}: sha256 mismatch — recomputed `{expected}`, record has `{actual}`")]
    HashMismatch {
        line: usize,
        expected: String,
        actual: String,
    },
}

/// Verify the hash chain in `path`. Returns a [`VerifyReport`] on success or
/// the first [`VerifyError`] encountered.
pub fn verify_audit_log(path: &Path) -> Result<VerifyReport, VerifyError> {
    let file = OpenOptions::new().read(true).open(path)?;
    let reader = BufReader::new(file);
    let mut prev = GENESIS_PREV.to_string();
    let mut count = 0usize;
    for (idx, line) in reader.lines().enumerate() {
        let line_no = idx + 1;
        let line = line?;
        if line.is_empty() {
            continue;
        }
        let value: serde_json::Value =
            serde_json::from_str(&line).map_err(|e| VerifyError::InvalidJson {
                line: line_no,
                source: e,
            })?;
        let serde_json::Value::Object(orig) = value else {
            return Err(VerifyError::NotAnObject { line: line_no });
        };
        let mut map: BTreeMap<String, serde_json::Value> = orig.into_iter().collect();
        let actual_prev = map
            .remove("prev_sha256")
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .ok_or(VerifyError::MissingField {
                line: line_no,
                field: "prev_sha256",
            })?;
        let actual_hash = map
            .remove("sha256")
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .ok_or(VerifyError::MissingField {
                line: line_no,
                field: "sha256",
            })?;
        if actual_prev != prev {
            return Err(VerifyError::PrevMismatch {
                line: line_no,
                expected: prev,
                actual: actual_prev,
            });
        }
        let canonical = serde_json::to_vec(&map).map_err(|e| VerifyError::InvalidJson {
            line: line_no,
            source: e,
        })?;
        let mut hasher = Sha256::new();
        hasher.update(prev.as_bytes());
        hasher.update(&canonical);
        let expected = hex_encode(&hasher.finalize());
        if expected != actual_hash {
            return Err(VerifyError::HashMismatch {
                line: line_no,
                expected,
                actual: actual_hash,
            });
        }
        prev = actual_hash;
        count += 1;
    }
    Ok(VerifyReport {
        records: count,
        tip: prev,
    })
}

/// Read the last chain tip from an existing audit log so a writer can resume
/// the chain across process restarts.
///
/// The *last* line of the file must be a valid JSON object containing a
/// `sha256` string field; if not, this is treated as a torn write from a
/// previous process and the partial trailing line is truncated in place
/// before returning the tip from the previous (now-final) line. Returns
/// [`GENESIS_PREV`] when the file does not exist or contains no records.
pub fn read_chain_tip(path: &Path) -> io::Result<String> {
    let mut file = match OpenOptions::new().read(true).write(true).open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(GENESIS_PREV.to_string()),
        Err(e) => return Err(e),
    };

    // Read the entire file. Audit logs are typically small relative to memory,
    // and this avoids backwards-seek bookkeeping.
    let mut bytes = Vec::new();
    let _ = file.read_to_end(&mut bytes)?;
    if bytes.is_empty() {
        return Ok(GENESIS_PREV.to_string());
    }

    // A valid file must end with a newline. If it does not, the trailing
    // partial line is torn — truncate it.
    let trailing_newline = bytes.last() == Some(&b'\n');
    if !trailing_newline {
        let last_nl = bytes.iter().rposition(|&b| b == b'\n');
        let truncate_to = last_nl.map(|i| i + 1).unwrap_or(0);
        file.set_len(truncate_to as u64)?;
        let _ = file.seek(SeekFrom::End(0))?;
        bytes.truncate(truncate_to);
        if bytes.is_empty() {
            return Ok(GENESIS_PREV.to_string());
        }
    }

    // Find the last non-empty line.
    let without_trailing = &bytes[..bytes.len() - 1];
    let last_line_start = without_trailing
        .iter()
        .rposition(|&b| b == b'\n')
        .map(|i| i + 1)
        .unwrap_or(0);
    let last_line = &without_trailing[last_line_start..];

    if last_line.is_empty() {
        // Trailing blank line(s). Treat as no records.
        return Ok(GENESIS_PREV.to_string());
    }

    // The last line must parse as a JSON object containing `sha256`. If it
    // does not (torn or corrupt), truncate it and recurse to look at the
    // previous line.
    match serde_json::from_slice::<serde_json::Value>(last_line) {
        Ok(serde_json::Value::Object(map)) => {
            if let Some(serde_json::Value::String(h)) = map.get("sha256") {
                Ok(h.clone())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "audit log last record is missing sha256 field",
                ))
            }
        }
        _ => {
            // Truncate the corrupt last line and try again from the previous
            // record.
            let new_len = last_line_start;
            file.set_len(new_len as u64)?;
            let _ = file.seek(SeekFrom::End(0))?;
            drop(file);
            read_chain_tip(path)
        }
    }
}

/// Write `tip` to `<path>.anchor` so external systems can pin the chain on
/// rotation. The anchor file is currently unsigned; signing can be layered on
/// top later without changing the on-disk format of the chain itself.
pub fn write_anchor(audit_path: &Path, tip: &str) -> io::Result<()> {
    let mut anchor = audit_path.as_os_str().to_os_string();
    anchor.push(".anchor");
    let mut f = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(Path::new(&anchor))?;
    writeln!(f, "{tip}")?;
    f.flush()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use std::io::Write as _;

    use tempfile::NamedTempFile;

    use super::*;

    fn write_records(path: &Path, records: &[&str]) {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap();
        let mut w = HashChainWriter::new(file, GENESIS_PREV.to_string());
        for r in records {
            w.write_all(r.as_bytes()).unwrap();
            w.write_all(b"\n").unwrap();
        }
        w.flush().unwrap();
    }

    #[test]
    fn writes_and_verifies_chain() {
        let f = NamedTempFile::new().unwrap();
        write_records(
            f.path(),
            &[
                r#"{"event":"a","n":1}"#,
                r#"{"event":"b","n":2}"#,
                r#"{"event":"c","n":3}"#,
            ],
        );
        let report = verify_audit_log(f.path()).unwrap();
        assert_eq!(report.records, 3);
        assert_ne!(report.tip, GENESIS_PREV);
    }

    #[test]
    fn detects_tampering_in_the_middle() {
        let f = NamedTempFile::new().unwrap();
        write_records(
            f.path(),
            &[
                r#"{"event":"a","n":1}"#,
                r#"{"event":"b","n":2}"#,
                r#"{"event":"c","n":3}"#,
            ],
        );
        // Flip a byte in the middle record.
        let bytes = std::fs::read(f.path()).unwrap();
        let s = String::from_utf8(bytes).unwrap();
        let mut lines: Vec<String> = s.lines().map(|l| l.to_string()).collect();
        lines[1] = lines[1].replace("\"n\":2", "\"n\":99");
        std::fs::write(f.path(), lines.join("\n") + "\n").unwrap();

        let err = verify_audit_log(f.path()).unwrap_err();
        match err {
            VerifyError::HashMismatch { line, .. } => assert_eq!(line, 2),
            other => panic!("expected HashMismatch, got {other:?}"),
        }
    }

    #[test]
    fn appending_continues_chain() {
        let f = NamedTempFile::new().unwrap();
        write_records(f.path(), &[r#"{"event":"a"}"#, r#"{"event":"b"}"#]);
        let tip1 = read_chain_tip(f.path()).unwrap();

        // Reopen with the saved tip and append more records.
        let file = OpenOptions::new().append(true).open(f.path()).unwrap();
        let mut w = HashChainWriter::new(file, tip1.clone());
        w.write_all(br#"{"event":"c"}"#).unwrap();
        w.write_all(b"\n").unwrap();
        w.write_all(br#"{"event":"d"}"#).unwrap();
        w.write_all(b"\n").unwrap();
        w.flush().unwrap();

        let report = verify_audit_log(f.path()).unwrap();
        assert_eq!(report.records, 4);
        assert_ne!(report.tip, tip1);
    }

    #[test]
    fn anchor_file_written() {
        let f = NamedTempFile::new().unwrap();
        write_records(f.path(), &[r#"{"event":"a"}"#]);
        let tip = read_chain_tip(f.path()).unwrap();
        write_anchor(f.path(), &tip).unwrap();
        let mut anchor = f.path().as_os_str().to_os_string();
        anchor.push(".anchor");
        let contents = std::fs::read_to_string(Path::new(&anchor)).unwrap();
        assert_eq!(contents.trim(), tip);
        let _ = std::fs::remove_file(Path::new(&anchor));
    }

    #[test]
    fn rejects_non_object_input() {
        let f = NamedTempFile::new().unwrap();
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(f.path())
            .unwrap();
        let mut w = HashChainWriter::new(file, GENESIS_PREV.to_string());
        // A bare JSON array is not an object — must be rejected.
        let err = w.write_all(b"[1,2,3]\n").unwrap_err();
        assert!(err.to_string().contains("not a JSON object"));

        // Garbage that does not even parse as JSON is also rejected.
        let f2 = NamedTempFile::new().unwrap();
        let file2 = OpenOptions::new()
            .create(true)
            .append(true)
            .open(f2.path())
            .unwrap();
        let mut w2 = HashChainWriter::new(file2, GENESIS_PREV.to_string());
        let err2 = w2.write_all(b"not json at all\n").unwrap_err();
        assert!(err2.to_string().contains("not valid JSON"));
    }

    #[test]
    fn canonical_json_is_key_order_independent() {
        // Build the same logical record with two different insertion orders
        // and assert the resulting chain hashes are identical.
        let f1 = NamedTempFile::new().unwrap();
        let f2 = NamedTempFile::new().unwrap();
        write_records(f1.path(), &[r#"{"a":1,"b":2,"c":3}"#]);
        write_records(f2.path(), &[r#"{"c":3,"b":2,"a":1}"#]);
        let tip1 = read_chain_tip(f1.path()).unwrap();
        let tip2 = read_chain_tip(f2.path()).unwrap();
        assert_eq!(tip1, tip2);
        assert_ne!(tip1, GENESIS_PREV);
    }

    #[test]
    fn read_chain_tip_recovers_from_torn_write() {
        let f = NamedTempFile::new().unwrap();
        write_records(f.path(), &[r#"{"event":"a"}"#, r#"{"event":"b"}"#]);
        let good_tip = read_chain_tip(f.path()).unwrap();

        // Simulate a torn partial trailing line: append some bytes WITHOUT
        // a final newline.
        {
            let mut file = OpenOptions::new().append(true).open(f.path()).unwrap();
            file.write_all(b"{\"event\":\"c\",\"prev_sha2").unwrap();
            file.flush().unwrap();
        }

        // Reopening for chain resume should detect and truncate the torn line
        // and return the previous good tip.
        let recovered = read_chain_tip(f.path()).unwrap();
        assert_eq!(recovered, good_tip);

        // Subsequent appends must produce a valid chain.
        let file = OpenOptions::new().append(true).open(f.path()).unwrap();
        let mut w = HashChainWriter::new(file, recovered.clone());
        w.write_all(br#"{"event":"c"}"#).unwrap();
        w.write_all(b"\n").unwrap();
        w.flush().unwrap();

        let report = verify_audit_log(f.path()).unwrap();
        assert_eq!(report.records, 3);
        assert_ne!(report.tip, recovered);
    }

    #[test]
    fn read_chain_tip_errors_on_last_line_missing_sha256() {
        let f = NamedTempFile::new().unwrap();
        // Write a complete-looking JSON object line that lacks `sha256`.
        std::fs::write(f.path(), b"{\"event\":\"a\"}\n").unwrap();
        let err = read_chain_tip(f.path()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
