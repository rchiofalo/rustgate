// Copyright © 2026 Roberto Chiofalo.

//! Hash-chained, tamper-evident audit log writer and verifier.
//!
//! Each audit record (a single JSON object on its own line) is augmented with
//! three fields before being written:
//!
//! - `seq` — monotonically increasing 64-bit record number, starting at `0`
//!   for the genesis record and resuming after restart via
//!   [`read_chain_state`]. Part of the canonical JSON, so the chain hash
//!   protects it from tampering. Lets an external consumer (SIEM tailing
//!   the log) detect gaps — the hash chain alone proves ordering and
//!   integrity but not completeness, because a tail truncation plus anchor
//!   rewrite still verifies. Sequence numbers make that attack visible to
//!   any consumer that has ever seen a later seq.
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
use std::path::{Path, PathBuf};
use std::sync::Arc;

use arc_swap::ArcSwap;
use sha2::{Digest, Sha256};

/// Genesis previous-hash value: 64 zero hex characters.
pub const GENESIS_PREV: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Maximum number of bytes read from the end of an existing chain file when
/// recovering the tip across a process restart. Caps startup cost and bounds
/// the torn-write recovery walk regardless of file size.
///
/// If the trailing window contains no valid record (all torn or corrupt),
/// [`read_chain_tip`] returns [`io::ErrorKind::InvalidData`] and refuses to
/// silently re-genesis the chain — the operator must verify/repair the log
/// out-of-band. This makes hostile or accidentally-large corruption visible
/// rather than hidden behind a multi-minute startup read that previously
/// walked the entire file (and, on each torn line, re-walked it).
pub const REWIND_BUDGET: u64 = 16 * 1024 * 1024;

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
    next_seq: u64,
    line_number: usize,
    /// Optional external observer of the current chain tip. Updated atomically
    /// on every chain advance so a shutdown path can snapshot the latest tip
    /// without needing access to the writer itself — the writer typically
    /// lives inside a `Mutex<Box<dyn Write>>` that the tracing subscriber
    /// owns. See [`HashChainWriter::with_tip_observer`] and [`write_anchor`].
    tip_observer: Option<Arc<ArcSwap<String>>>,
}

impl<W: Write> HashChainWriter<W> {
    /// Create a new chain writer starting from `prev` (use [`GENESIS_PREV`]
    /// for a brand-new chain, or the last known hash to continue an existing
    /// chain across process restarts).
    ///
    /// The record sequence counter starts at `0`. When resuming across a
    /// restart, pair this with [`HashChainWriter::with_next_seq`] using the
    /// `next_seq` returned by [`read_chain_state`] so the chain does not
    /// replay an earlier sequence number after a crash or restart.
    pub fn new(inner: W, prev: String) -> Self {
        Self {
            inner,
            buf: Vec::with_capacity(1024),
            prev,
            next_seq: 0,
            line_number: 0,
            tip_observer: None,
        }
    }

    /// Override the starting sequence number. The writer assigns `seq` to the
    /// next record, then increments monotonically. Use the value returned by
    /// [`read_chain_state`] when resuming a chain across a restart so the
    /// audit stream carries a single strictly-increasing `seq` series across
    /// process boundaries. Legacy chains that were written before `seq` was
    /// introduced report `0` here and keep writing forward; the first new
    /// record then carries `seq=0`.
    pub fn with_next_seq(mut self, next_seq: u64) -> Self {
        self.next_seq = next_seq;
        self
    }

    /// Attach an [`ArcSwap`] that the writer will update on every chain
    /// advance. The observer always contains the last `sha256` written (or
    /// the initial `prev` until the first record lands), so a shutdown hook
    /// can read it without reaching into the tracing subscriber to find the
    /// writer behind its mutex. `observer` is seeded with the current tip on
    /// attachment so no separate priming step is required.
    pub fn with_tip_observer(mut self, observer: Arc<ArcSwap<String>>) -> Self {
        observer.store(Arc::new(self.prev.clone()));
        self.tip_observer = Some(observer);
        self
    }

    /// Return the current chain tip (last `sha256` written, or the initial
    /// `prev` if nothing has been written yet).
    pub fn tip(&self) -> &str {
        &self.prev
    }

    /// Return the sequence number that will be stamped onto the *next*
    /// record. Exposed primarily for tests and for tooling that wants to
    /// snapshot the writer's cursor without flushing a record.
    pub fn next_seq(&self) -> u64 {
        self.next_seq
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
        // Any `seq` field supplied by the caller is overwritten: the chain
        // owns the sequence counter so downstream consumers can rely on it
        // being strictly monotonic across the whole log. Chain-injected
        // `seq` is part of the canonical JSON hashed below, so tampering
        // with it invalidates `sha256` and every following record.
        let _ = map.insert(
            "seq".to_string(),
            serde_json::Value::Number(self.next_seq.into()),
        );
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
        // Saturating so a pathological operator who somehow reaches 2^64
        // records does not wrap silently back to 0 and restart the series.
        // At 1M records/sec that ceiling is ~580,000 years out, but explicit
        // saturation is cheaper than reasoning about wrap-around attacks
        // against any downstream gap detector.
        self.next_seq = self.next_seq.saturating_add(1);
        if let Some(ref observer) = self.tip_observer {
            observer.store(Arc::new(self.prev.clone()));
        }
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
/// Behaviour:
/// - Returns [`GENESIS_PREV`] when the file does not exist or is empty.
/// - Reads **at most [`REWIND_BUDGET`] trailing bytes**. Startup cost is
///   `O(REWIND_BUDGET)` regardless of log size; a hostile or accidentally
///   enormous log cannot stall startup.
/// - If the last line is a torn/partial JSON record (common after a crash),
///   it is truncated in place and the *previous* complete line is used.
/// - Torn/corrupt line truncation is bounded to the rewound tail. If no
///   valid record is found within the budget, returns
///   [`io::ErrorKind::InvalidData`] so the operator can verify/repair the
///   log out-of-band rather than silently re-genesising the chain.
pub fn read_chain_tip(path: &Path) -> io::Result<String> {
    let mut file = match OpenOptions::new().read(true).write(true).open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(GENESIS_PREV.to_string()),
        Err(e) => return Err(e),
    };

    let file_len = file.metadata()?.len();
    if file_len == 0 {
        return Ok(GENESIS_PREV.to_string());
    }

    // Seek to the start of the trailing window. We only ever read the last
    // REWIND_BUDGET bytes — never the whole file — so startup is O(budget)
    // instead of O(file × torn_lines) as the previous recursive loop was.
    let start = file_len.saturating_sub(REWIND_BUDGET);
    let _ = file.seek(SeekFrom::Start(start))?;
    let mut bytes = Vec::with_capacity(file_len.saturating_sub(start) as usize);
    let _ = file.read_to_end(&mut bytes)?;

    // If we did not start at offset 0, the leading bytes are the tail of a
    // line that started before our window. Drop everything before the first
    // newline so we only examine complete records that fall entirely inside
    // the budget. `tail_file_offset` is the absolute file position where our
    // in-memory `bytes` buffer begins — used when truncating corrupt tails
    // back to disk.
    let tail_file_offset = if start > 0 {
        match bytes.iter().position(|&b| b == b'\n') {
            Some(first_nl) => {
                let drop = first_nl + 1;
                let _ = bytes.drain(..drop);
                start + drop as u64
            }
            None => {
                // No newline anywhere in REWIND_BUDGET bytes — the final
                // record is larger than the budget (or the file is a single
                // huge unterminated blob). Refuse to guess.
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "audit log tail contains no complete records within REWIND_BUDGET",
                ));
            }
        }
    } else {
        0
    };

    // A valid file ends with `\n`. If it does not, truncate the torn trailing
    // partial line on disk before we continue.
    if bytes.last() != Some(&b'\n') {
        let last_nl = bytes.iter().rposition(|&b| b == b'\n');
        let keep = last_nl.map(|i| i + 1).unwrap_or(0);
        let new_file_len = tail_file_offset + keep as u64;
        file.set_len(new_file_len)?;
        let _ = file.seek(SeekFrom::End(0))?;
        bytes.truncate(keep);
    }

    // Walk bounded-backwards through complete lines in the tail window,
    // truncating torn/corrupt trailing records on disk as we go. The loop
    // is bounded by the number of newlines in the tail (≤ REWIND_BUDGET).
    loop {
        if bytes.is_empty() {
            // If the tail began at offset 0 and we consumed the whole file
            // without finding a valid record, the file is either empty or
            // entirely corrupt. Only the empty case is safe to treat as
            // "no chain yet".
            if tail_file_offset == 0 {
                return Ok(GENESIS_PREV.to_string());
            }
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "audit log tip unrecoverable within REWIND_BUDGET; manual repair required",
            ));
        }

        // `bytes` ends in `\n` here. Find the last complete line.
        let without_trailing = &bytes[..bytes.len() - 1];
        let last_line_start = without_trailing
            .iter()
            .rposition(|&b| b == b'\n')
            .map(|i| i + 1)
            .unwrap_or(0);
        let last_line = &without_trailing[last_line_start..];

        if last_line.is_empty() {
            // Trailing blank line(s). Strip one and retry the previous line.
            bytes.truncate(bytes.len() - 1);
            continue;
        }

        match serde_json::from_slice::<serde_json::Value>(last_line) {
            Ok(serde_json::Value::Object(map)) => {
                if let Some(serde_json::Value::String(h)) = map.get("sha256") {
                    return Ok(h.clone());
                }
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "audit log last record is missing sha256 field",
                ));
            }
            _ => {
                // Corrupt last line — truncate it on disk (bounded to the
                // rewound tail) and retry against the previous record.
                let new_file_len = tail_file_offset + last_line_start as u64;
                file.set_len(new_file_len)?;
                let _ = file.seek(SeekFrom::End(0))?;
                bytes.truncate(last_line_start);
            }
        }
    }
}

/// Recover both the chain tip and the next sequence number a writer should
/// use after resuming an existing log. This is the preferred startup path
/// for a chained audit writer — using [`read_chain_tip`] alone resets the
/// sequence counter to `0` on every restart, which breaks downstream gap
/// detection.
///
/// Behaviour mirrors [`read_chain_tip`]: the file is opened, the tail is
/// truncated if torn, and the final `sha256` is returned. In addition, the
/// last record's `seq` field (if present) is parsed and returned incremented
/// by one so the caller can pass it to
/// [`HashChainWriter::with_next_seq`]. Records written by a pre-`seq` build
/// have no `seq` field; for back-compat we report `next_seq = 0` there so
/// the next record restarts the series. The hash chain still carries
/// forward correctly either way — `seq` is a downstream-visible counter,
/// not a chain linkage primitive.
pub fn read_chain_state(path: &Path) -> io::Result<(String, u64)> {
    let tip = read_chain_tip(path)?;
    if tip == GENESIS_PREV {
        return Ok((tip, 0));
    }
    // read_chain_tip has already truncated any torn trailing record, so the
    // last non-empty line on disk is guaranteed to be a valid JSON object
    // whose sha256 matches `tip`. We only need to parse its `seq` field.
    let file = OpenOptions::new().read(true).open(path)?;
    let file_len = file.metadata()?.len();
    if file_len == 0 {
        return Ok((tip, 0));
    }
    // Bounded tail read — same budget as read_chain_tip so a hostile log
    // cannot turn startup into a full-file scan on the seq path either.
    let mut file = file;
    let start = file_len.saturating_sub(REWIND_BUDGET);
    let _ = file.seek(SeekFrom::Start(start))?;
    let mut bytes = Vec::with_capacity(file_len.saturating_sub(start) as usize);
    let _ = file.read_to_end(&mut bytes)?;
    if start > 0
        && let Some(first_nl) = bytes.iter().position(|&b| b == b'\n')
    {
        let _ = bytes.drain(..=first_nl);
    }
    // Trim the terminating newline (if any) so rposition gives us the start
    // of the *last* record rather than an empty suffix.
    while bytes.last() == Some(&b'\n') {
        bytes.truncate(bytes.len() - 1);
    }
    let last_line_start = bytes
        .iter()
        .rposition(|&b| b == b'\n')
        .map(|i| i + 1)
        .unwrap_or(0);
    let last_line = &bytes[last_line_start..];
    let seq = match serde_json::from_slice::<serde_json::Value>(last_line) {
        Ok(serde_json::Value::Object(map)) => map
            .get("seq")
            .and_then(|v| v.as_u64())
            .map(|n| n.saturating_add(1))
            .unwrap_or(0),
        // read_chain_tip already validated the last line parses and has
        // `sha256`; the only way we get here is if the tip file changed
        // under us between calls, which is an operational race we surface
        // rather than paper over.
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "audit log last record changed between read_chain_tip and read_chain_state",
            ));
        }
    };
    Ok((tip, seq))
}

/// Compute the anchor-file path for a given audit-log path. Kept as a
/// standalone helper so every caller (writer, reader, continuity checker)
/// agrees on the naming convention.
pub fn anchor_path(audit_path: &Path) -> PathBuf {
    let mut anchor = audit_path.as_os_str().to_os_string();
    anchor.push(".anchor");
    PathBuf::from(anchor)
}

/// Write `tip` to `<path>.anchor` so external systems can pin the chain on
/// rotation. The anchor file is currently unsigned; signing can be layered on
/// top later without changing the on-disk format of the chain itself.
pub fn write_anchor(audit_path: &Path, tip: &str) -> io::Result<()> {
    let target = anchor_path(audit_path);
    let mut f = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&target)?;
    writeln!(f, "{tip}")?;
    f.flush()
}

/// Read a previously-persisted chain tip from `<path>.anchor`. Returns
/// `Ok(None)` when no anchor exists (fresh install, or audit log enabled for
/// the first time), `Ok(Some(tip))` on success, and an I/O error on any
/// other failure. The on-disk format is a single hex string followed by
/// optional whitespace; surrounding whitespace is trimmed. A non-64-char or
/// non-hex payload is rejected with [`io::ErrorKind::InvalidData`] so a
/// hand-edited or truncated anchor cannot masquerade as a valid tip.
pub fn read_anchor(audit_path: &Path) -> io::Result<Option<String>> {
    let target = anchor_path(audit_path);
    let bytes = match std::fs::read(&target) {
        Ok(b) => b,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let s = std::str::from_utf8(&bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if trimmed.len() != 64 || !trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "audit log anchor file does not contain a 64-char hex SHA-256",
        ));
    }
    Ok(Some(trimmed.to_ascii_lowercase()))
}

/// Outcome of comparing a persisted anchor tip with the live chain tip
/// recovered from the audit log on disk. Used by startup logic to decide
/// whether the chain continued across the last shutdown or whether the log
/// was tampered with, rotated without carrying the anchor forward, or
/// truncated.
///
/// See [`check_chain_continuity`] for the comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainContinuity {
    /// No anchor file exists yet. Happens on fresh installs and on the
    /// first startup after the audit-log feature is enabled. Callers
    /// should treat this as benign but persist the anchor on the next
    /// graceful shutdown so subsequent starts can detect tampering.
    NoAnchor,
    /// Anchor matches the current live tip. Chain is continuous across
    /// the last shutdown.
    Match { tip: String },
    /// Anchor does not match the current live tip. Either the audit log
    /// was tampered with (rewritten, truncated, or replaced) while the
    /// process was down, or the log was rotated without carrying the
    /// anchor forward. Callers should refuse to start by default and
    /// require an explicit operator opt-in (e.g.
    /// `--audit-allow-chain-break`) to continue.
    Mismatch {
        anchor_tip: String,
        live_tip: String,
    },
}

/// Compare the persisted anchor tip (from `<path>.anchor`) with the live
/// tip recovered from the audit log itself. Returns a [`ChainContinuity`]
/// verdict without side effects — the caller owns the policy decision.
pub fn check_chain_continuity(audit_path: &Path) -> io::Result<ChainContinuity> {
    let live_tip = read_chain_tip(audit_path)?;
    match read_anchor(audit_path)? {
        None => Ok(ChainContinuity::NoAnchor),
        Some(anchor_tip) => {
            if anchor_tip == live_tip {
                Ok(ChainContinuity::Match { tip: live_tip })
            } else {
                Ok(ChainContinuity::Mismatch {
                    anchor_tip,
                    live_tip,
                })
            }
        }
    }
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

    #[test]
    fn tip_observer_reflects_chain_advance() {
        let f = NamedTempFile::new().unwrap();
        let observer = Arc::new(ArcSwap::from_pointee(GENESIS_PREV.to_string()));

        // Seed + first record advance.
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(f.path())
            .unwrap();
        let mut w = HashChainWriter::new(file, GENESIS_PREV.to_string())
            .with_tip_observer(Arc::clone(&observer));
        assert_eq!(&**observer.load(), GENESIS_PREV);

        w.write_all(br#"{"event":"a"}"#).unwrap();
        w.write_all(b"\n").unwrap();
        w.flush().unwrap();

        let after_first: String = (**observer.load()).clone();
        assert_ne!(after_first, GENESIS_PREV);

        w.write_all(br#"{"event":"b"}"#).unwrap();
        w.write_all(b"\n").unwrap();
        w.flush().unwrap();

        let after_second: String = (**observer.load()).clone();
        assert_ne!(after_second, after_first);
        // Observer must expose the authoritative writer tip.
        assert_eq!(after_second, w.tip());
    }

    #[test]
    fn read_anchor_returns_none_when_missing() {
        let f = NamedTempFile::new().unwrap();
        assert!(read_anchor(f.path()).unwrap().is_none());
    }

    #[test]
    fn read_anchor_round_trips_write_anchor() {
        let f = NamedTempFile::new().unwrap();
        write_records(f.path(), &[r#"{"event":"a"}"#]);
        let tip = read_chain_tip(f.path()).unwrap();
        write_anchor(f.path(), &tip).unwrap();

        let back = read_anchor(f.path()).unwrap();
        assert_eq!(back.as_deref(), Some(tip.as_str()));

        let _ = std::fs::remove_file(anchor_path(f.path()));
    }

    #[test]
    fn read_anchor_rejects_malformed_payload() {
        let f = NamedTempFile::new().unwrap();
        let anchor = anchor_path(f.path());
        std::fs::write(&anchor, b"not-a-hex-sha256\n").unwrap();
        let err = read_anchor(f.path()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        let _ = std::fs::remove_file(&anchor);
    }

    #[test]
    fn read_anchor_rejects_wrong_length_payload() {
        let f = NamedTempFile::new().unwrap();
        let anchor = anchor_path(f.path());
        // 32 hex chars (128-bit), not the 64 chars (256-bit) a valid SHA-256 tip produces.
        std::fs::write(&anchor, b"0123456789abcdef0123456789abcdef\n").unwrap();
        let err = read_anchor(f.path()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        let _ = std::fs::remove_file(&anchor);
    }

    #[test]
    fn read_anchor_treats_whitespace_only_as_missing() {
        let f = NamedTempFile::new().unwrap();
        let anchor = anchor_path(f.path());
        std::fs::write(&anchor, b"   \n\n").unwrap();
        assert!(read_anchor(f.path()).unwrap().is_none());
        let _ = std::fs::remove_file(&anchor);
    }

    #[test]
    fn check_chain_continuity_no_anchor_when_none_persisted() {
        let f = NamedTempFile::new().unwrap();
        write_records(f.path(), &[r#"{"event":"a"}"#]);
        let verdict = check_chain_continuity(f.path()).unwrap();
        assert!(matches!(verdict, ChainContinuity::NoAnchor));
    }

    #[test]
    fn check_chain_continuity_match_when_anchor_aligns_with_live_tip() {
        let f = NamedTempFile::new().unwrap();
        write_records(f.path(), &[r#"{"event":"a"}"#, r#"{"event":"b"}"#]);
        let tip = read_chain_tip(f.path()).unwrap();
        write_anchor(f.path(), &tip).unwrap();

        let verdict = check_chain_continuity(f.path()).unwrap();
        match verdict {
            ChainContinuity::Match { tip: got } => assert_eq!(got, tip),
            other => panic!("expected Match, got {other:?}"),
        }

        let _ = std::fs::remove_file(anchor_path(f.path()));
    }

    #[test]
    fn check_chain_continuity_mismatch_detects_post_anchor_truncation() {
        // Attack model: attacker truncates the tail of the audit log after
        // the operator persisted an anchor. The live tip now reflects the
        // earlier state, but the anchor still names the authoritative tip.
        let f = NamedTempFile::new().unwrap();
        write_records(
            f.path(),
            &[r#"{"event":"a"}"#, r#"{"event":"b"}"#, r#"{"event":"c"}"#],
        );
        let real_tip = read_chain_tip(f.path()).unwrap();
        write_anchor(f.path(), &real_tip).unwrap();

        // Simulate truncation: drop the last record.
        let contents = std::fs::read_to_string(f.path()).unwrap();
        let mut lines: Vec<&str> = contents.lines().collect();
        let _ = lines.pop();
        let truncated = lines.join("\n") + "\n";
        std::fs::write(f.path(), truncated).unwrap();

        let live_after_truncate = read_chain_tip(f.path()).unwrap();
        assert_ne!(live_after_truncate, real_tip);

        let verdict = check_chain_continuity(f.path()).unwrap();
        match verdict {
            ChainContinuity::Mismatch {
                anchor_tip,
                live_tip,
            } => {
                assert_eq!(anchor_tip, real_tip);
                assert_eq!(live_tip, live_after_truncate);
            }
            other => panic!("expected Mismatch, got {other:?}"),
        }

        let _ = std::fs::remove_file(anchor_path(f.path()));
    }

    #[test]
    fn check_chain_continuity_no_anchor_when_audit_log_missing() {
        // Fresh install: neither log nor anchor. Must be benign so the
        // first startup is not blocked.
        let dir = tempfile::tempdir().unwrap();
        let audit = dir.path().join("audit.jsonl");
        assert!(!audit.exists());
        let verdict = check_chain_continuity(&audit).unwrap();
        assert!(matches!(verdict, ChainContinuity::NoAnchor));
    }

    #[test]
    fn observer_plus_anchor_matches_live_tip_end_to_end() {
        // Models the full production lifecycle used by rustgate-server:
        //   1. HashChainWriter is constructed with an external tip observer.
        //   2. Records are written during the server's lifetime.
        //   3. On shutdown the observer is snapshotted to persist an anchor.
        //   4. On next startup, check_chain_continuity confirms the live tip
        //      matches the persisted anchor (no tampering between boots).
        let f = NamedTempFile::new().unwrap();
        let observer = Arc::new(ArcSwap::from_pointee(GENESIS_PREV.to_string()));
        {
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(f.path())
                .unwrap();
            let mut w = HashChainWriter::new(file, GENESIS_PREV.to_string())
                .with_tip_observer(Arc::clone(&observer));
            for rec in [r#"{"event":"a"}"#, r#"{"event":"b"}"#, r#"{"event":"c"}"#] {
                w.write_all(rec.as_bytes()).unwrap();
                w.write_all(b"\n").unwrap();
            }
            w.flush().unwrap();
        }
        // Simulate shutdown: snapshot observer → write anchor.
        let final_tip: String = (**observer.load()).clone();
        write_anchor(f.path(), &final_tip).unwrap();
        // Simulate next startup: continuity check reads both live log and anchor.
        let verdict = check_chain_continuity(f.path()).unwrap();
        match verdict {
            ChainContinuity::Match { tip } => assert_eq!(tip, final_tip),
            other => panic!("expected Match, got {other:?}"),
        }
        // Full-chain verification must agree on the same tip and record count.
        let report = verify_audit_log(f.path()).unwrap();
        assert_eq!(report.tip, final_tip);
        assert_eq!(report.records, 3);
        let _ = std::fs::remove_file(anchor_path(f.path()));
    }

    #[test]
    fn read_chain_tip_refuses_when_tail_has_no_records() {
        // File is larger than REWIND_BUDGET and the trailing window contains
        // no newline — simulating a hostile log or a single record larger
        // than the budget. Startup must refuse rather than loop.
        let f = NamedTempFile::new().unwrap();
        let mut big = vec![b'X'; (REWIND_BUDGET as usize) + 4096];
        // Ensure a valid record exists BEFORE our budget window, so we can
        // confirm the code deliberately refuses to reach for it rather than
        // incidentally finding nothing.
        let valid = br#"{"event":"a","prev_sha256":"0000","sha256":"abc"}"#;
        big[..valid.len()].copy_from_slice(valid);
        big[valid.len()] = b'\n';
        std::fs::write(f.path(), &big).unwrap();

        let err = read_chain_tip(f.path()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(
            err.to_string()
                .contains("no complete records within REWIND_BUDGET"),
            "expected budget error, got: {err}"
        );
    }

    #[test]
    fn read_chain_tip_recovers_from_large_prefix() {
        // Prefix well beyond REWIND_BUDGET of valid-looking lines, then a
        // valid trailing record. The tip should be returned from the tail
        // without ever reading the prefix. We measure "did not read the
        // prefix" by timing — the old full-file walk would be ~10× slower
        // — but we rely on logic here: read_chain_tip must succeed.
        let f = NamedTempFile::new().unwrap();
        {
            let mut file = OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(f.path())
                .unwrap();
            // Pad with enough bytes to push real records past REWIND_BUDGET.
            // Each filler line is ~64 bytes; write ~20 MiB of filler.
            let filler_line = vec![b'x'; 63];
            let mut count_bytes: u64 = 0;
            while count_bytes < REWIND_BUDGET + (2 * 1024 * 1024) {
                file.write_all(&filler_line).unwrap();
                file.write_all(b"\n").unwrap();
                count_bytes += 64;
            }
            // Now a real chain. The HashChainWriter is used so the last line
            // has a valid `sha256`.
            let mut w = HashChainWriter::new(file, GENESIS_PREV.to_string());
            w.write_all(br#"{"event":"final"}"#).unwrap();
            w.write_all(b"\n").unwrap();
            w.flush().unwrap();
        }
        let tip = read_chain_tip(f.path()).unwrap();
        assert_ne!(tip, GENESIS_PREV);
    }

    #[test]
    fn read_chain_tip_recovers_torn_write_after_large_prefix() {
        // Large prefix of filler bytes (past REWIND_BUDGET) followed by a
        // valid chain, then a torn partial trailing record. The recovery
        // must truncate the torn tail and return the previous valid tip.
        let f = NamedTempFile::new().unwrap();
        {
            let mut file = OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(f.path())
                .unwrap();
            let filler_line = vec![b'y'; 63];
            let mut count_bytes: u64 = 0;
            while count_bytes < REWIND_BUDGET + (1024 * 1024) {
                file.write_all(&filler_line).unwrap();
                file.write_all(b"\n").unwrap();
                count_bytes += 64;
            }
        }
        // Append a real chain via HashChainWriter.
        {
            let file = OpenOptions::new().append(true).open(f.path()).unwrap();
            let mut w = HashChainWriter::new(file, GENESIS_PREV.to_string());
            w.write_all(br#"{"event":"a"}"#).unwrap();
            w.write_all(b"\n").unwrap();
            w.write_all(br#"{"event":"b"}"#).unwrap();
            w.write_all(b"\n").unwrap();
            w.flush().unwrap();
        }
        let good_tip = read_chain_tip(f.path()).unwrap();

        // Append a torn trailing line (no newline).
        {
            let mut file = OpenOptions::new().append(true).open(f.path()).unwrap();
            file.write_all(b"{\"event\":\"c\",\"prev_sha2").unwrap();
            file.flush().unwrap();
        }

        let recovered = read_chain_tip(f.path()).unwrap();
        assert_eq!(recovered, good_tip);
    }

    /// Extract the `seq` field from every record in an audit log. Used by
    /// the sequence-number tests below.
    fn seqs_of(path: &Path) -> Vec<Option<u64>> {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| {
                let v: serde_json::Value = serde_json::from_str(l).unwrap();
                v.get("seq").and_then(|s| s.as_u64())
            })
            .collect()
    }

    #[test]
    fn writer_injects_monotonic_seq_from_genesis() {
        let f = NamedTempFile::new().unwrap();
        write_records(
            f.path(),
            &[r#"{"event":"a"}"#, r#"{"event":"b"}"#, r#"{"event":"c"}"#],
        );
        assert_eq!(seqs_of(f.path()), vec![Some(0), Some(1), Some(2)]);
        // Chain still verifies end-to-end — seq is inside the canonical
        // JSON so the hash chain protects it.
        let report = verify_audit_log(f.path()).unwrap();
        assert_eq!(report.records, 3);
    }

    #[test]
    fn writer_overwrites_caller_supplied_seq() {
        // If a caller sneaks a `seq` field into the pre-chain record, the
        // writer must replace it: the chain owns the counter so downstream
        // consumers can trust it.
        let f = NamedTempFile::new().unwrap();
        write_records(
            f.path(),
            &[r#"{"event":"a","seq":9999}"#, r#"{"event":"b","seq":123}"#],
        );
        assert_eq!(seqs_of(f.path()), vec![Some(0), Some(1)]);
        // And verification must still succeed against the overwritten seq.
        let report = verify_audit_log(f.path()).unwrap();
        assert_eq!(report.records, 2);
    }

    #[test]
    fn read_chain_state_resumes_seq_across_restart() {
        // Simulates a process restart: write three records, close the
        // writer, read the state back, continue with a second writer and
        // confirm the sequence kept advancing (0,1,2,3,4) rather than
        // restarting from 0.
        let f = NamedTempFile::new().unwrap();
        write_records(
            f.path(),
            &[r#"{"event":"a"}"#, r#"{"event":"b"}"#, r#"{"event":"c"}"#],
        );
        let (tip, next_seq) = read_chain_state(f.path()).unwrap();
        assert_ne!(tip, GENESIS_PREV);
        assert_eq!(next_seq, 3);

        let file = OpenOptions::new().append(true).open(f.path()).unwrap();
        let mut w = HashChainWriter::new(file, tip.clone()).with_next_seq(next_seq);
        w.write_all(br#"{"event":"d"}"#).unwrap();
        w.write_all(b"\n").unwrap();
        w.write_all(br#"{"event":"e"}"#).unwrap();
        w.write_all(b"\n").unwrap();
        w.flush().unwrap();

        assert_eq!(
            seqs_of(f.path()),
            vec![Some(0), Some(1), Some(2), Some(3), Some(4)]
        );
        // And the chain as a whole still verifies.
        let report = verify_audit_log(f.path()).unwrap();
        assert_eq!(report.records, 5);
    }

    #[test]
    fn read_chain_state_returns_genesis_on_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("never-created.log");
        let (tip, next_seq) = read_chain_state(&missing).unwrap();
        assert_eq!(tip, GENESIS_PREV);
        assert_eq!(next_seq, 0);
    }

    #[test]
    fn read_chain_state_reports_next_seq_zero_for_legacy_records() {
        // Simulates an audit log written by a pre-seq build: hand-craft
        // records that chain correctly but carry no `seq` field. A new
        // writer resuming from here must start at seq=0 so forward
        // records are still monotonic, even if a gap detector will see
        // the older records as unnumbered.
        let f = NamedTempFile::new().unwrap();
        let path = f.path();

        // Replay the old pre-seq algorithm: hash(prev || canonical_without_chain_fields),
        // no seq injection.
        let rec1_map: BTreeMap<&str, serde_json::Value> =
            [("event", serde_json::Value::String("legacy-a".into()))]
                .into_iter()
                .collect();
        let rec1_canonical = serde_json::to_vec(&rec1_map).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(GENESIS_PREV.as_bytes());
        hasher.update(&rec1_canonical);
        let rec1_hash = hex_encode(&hasher.finalize());
        let rec1 = format!(
            r#"{{"event":"legacy-a","prev_sha256":"{}","sha256":"{}"}}"#,
            GENESIS_PREV, rec1_hash
        );

        let rec2_map: BTreeMap<&str, serde_json::Value> =
            [("event", serde_json::Value::String("legacy-b".into()))]
                .into_iter()
                .collect();
        let rec2_canonical = serde_json::to_vec(&rec2_map).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(rec1_hash.as_bytes());
        hasher.update(&rec2_canonical);
        let rec2_hash = hex_encode(&hasher.finalize());
        let rec2 = format!(
            r#"{{"event":"legacy-b","prev_sha256":"{}","sha256":"{}"}}"#,
            rec1_hash, rec2_hash
        );

        std::fs::write(path, format!("{rec1}\n{rec2}\n")).unwrap();
        // Sanity-check: the hand-written legacy log is itself valid.
        let report = verify_audit_log(path).unwrap();
        assert_eq!(report.records, 2);
        assert_eq!(report.tip, rec2_hash);

        let (tip, next_seq) = read_chain_state(path).unwrap();
        assert_eq!(tip, rec2_hash);
        // Pre-seq records had no `seq` field → the counter restarts at 0
        // so forward records are monotonic among themselves. The hash
        // chain carries across the boundary unchanged.
        assert_eq!(next_seq, 0);
    }

    #[test]
    fn tampering_with_injected_seq_is_detected_by_hash_chain() {
        // Sanity: because the writer-injected `seq` is part of the
        // canonical JSON hashed into `sha256`, editing it post-hoc must
        // invalidate verify_audit_log.
        let f = NamedTempFile::new().unwrap();
        write_records(
            f.path(),
            &[r#"{"event":"a"}"#, r#"{"event":"b"}"#, r#"{"event":"c"}"#],
        );

        // Replace the middle record's seq=1 with seq=42 without rebuilding
        // its sha256. The hash check must fire.
        let contents = std::fs::read_to_string(f.path()).unwrap();
        let mutated = contents.replacen("\"seq\":1", "\"seq\":42", 1);
        assert_ne!(contents, mutated, "test fixture must mutate the file");
        std::fs::write(f.path(), mutated).unwrap();

        let err = verify_audit_log(f.path()).unwrap_err();
        assert!(
            matches!(err, VerifyError::HashMismatch { line: 2, .. }),
            "expected HashMismatch on line 2, got {err:?}"
        );
    }
}
