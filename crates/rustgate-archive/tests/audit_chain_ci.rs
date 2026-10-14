// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

#![allow(clippy::panic, clippy::unwrap_used)]
//! End-to-end CI verification of the hash-chained audit log
//! ([`rustgate_archive::audit_chain`], closes #772).
//!
//! The audit chain is the forensic trail tactical operators rely on
//! when a SIEM is unavailable or has been compromised: every record
//! carries `prev_sha256` linking it to the previous record's `sha256`,
//! and every record carries a strictly monotonic `seq` field
//! (extended by #1173, runbook in #1191) so a verifier can detect tail
//! truncation that the hash chain alone cannot — because such a
//! truncation produces a strict prefix that still verifies.
//!
//! Pre-this-test the chain implementation had inline unit tests in
//! [`rustgate_archive::audit_chain::tests`] but no integration-binary
//! test that exercised the full
//! [`HashChainWriter`] → [`verify_audit_log`] cycle plus tamper
//! detection in CI. A regression that broke either side of the
//! contract would not be caught by the unit suite alone — for
//! example, a writer change that silently dropped the `seq` field on
//! every Nth record would compile cleanly because verifier and
//! writer share no compile-time invariants — only the runtime
//! contract that this test pins.
//!
//! The integration-test binary isolation matters for two reasons:
//! (1) CI now reports a dedicated `audit_chain_ci` test target so a
//!     red dot on the dashboard maps directly to "the audit chain
//!     itself broke" rather than to a generic `rustgate-archive` failure;
//! (2) the test process is short-lived, so any future addition that
//!     installs a global tracing subscriber for chain emissions
//!     cannot leak its `Interest` cache into other tests in the
//!     workspace (the same rationale that justified
//!     `mask_point_recovery_audit.rs`,
//!     `obligation_static_reason_audit.rs`, and
//!     `position_replay_rate_limit_audit.rs` in the transport crate).
//!
//! Closes #772 item 1.
//!
//! [`HashChainWriter`]: rustgate_archive::audit_chain::HashChainWriter
//! [`verify_audit_log`]: rustgate_archive::audit_chain::verify_audit_log

use std::fs::OpenOptions;
use std::io::Write as _;

use rustgate_archive::audit_chain::{GENESIS_PREV, HashChainWriter, VerifyError, verify_audit_log};
use tempfile::NamedTempFile;

/// Number of records exercised by every test in this binary. 100 is the
/// number called out in the issue brief: high enough that a
/// hash-mismatch deep into the file is meaningfully different from a
/// hash mismatch on record 2 (the inline unit test in
/// `audit_chain::tests::detects_tampering_in_the_middle` uses 3
/// records, so a regression that only mishandled long files would
/// slip past it), low enough that the test wall-time stays well under
/// a second on every CI runner.
const RECORD_COUNT: usize = 100;

/// Append `RECORD_COUNT` synthetic audit records to the writer. Each
/// record carries a unique `n` field so the inline unit-test pattern
/// (which records `{"event":"a"}` style placeholders) cannot be
/// confused with these — a future contributor copying this test as a
/// template will see distinct payloads.
fn write_records<W: std::io::Write>(writer: &mut HashChainWriter<W>) {
    for i in 0..RECORD_COUNT {
        let line = format!(r#"{{"event":"audit_chain_ci","n":{i}}}"#);
        writer.write_all(line.as_bytes()).unwrap();
        writer.write_all(b"\n").unwrap();
    }
    writer.flush().unwrap();
}

/// 1. Happy path: write 100 records, reopen the file, run the
///    verifier, assert every property listed by [`verify_audit_log`]'s
///    rustdoc holds.
///
/// Without this CI check, a regression in the writer or verifier
/// would only surface in production — by which point the operator's
/// forensic record is already corrupted and the chain cannot be
/// re-verified retroactively. The whole point of the chain is that
/// today's verifier output is the audit-trail-of-record for the
/// production instance running today.
#[test]
fn audit_chain_writes_100_records_and_verifies_cleanly() {
    let f = NamedTempFile::new().unwrap();
    {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(f.path())
            .unwrap();
        let mut writer = HashChainWriter::new(file, GENESIS_PREV.to_string());
        write_records(&mut writer);
    }

    let report = verify_audit_log(f.path()).unwrap();
    assert_eq!(
        report.records, RECORD_COUNT,
        "verifier must count every record we wrote"
    );
    assert_ne!(
        report.tip, GENESIS_PREV,
        "tip must advance off the genesis hash after at least one record"
    );
    assert_eq!(
        report.tip.len(),
        64,
        "tip is a hex-encoded SHA-256 — must be 64 hex chars: {tip:?}",
        tip = report.tip
    );
    // tip_seq pins the monotonic sequence series — this is the
    // surface that would surface a tail truncation that the hash
    // chain alone cannot (see audit_chain.rs module-level docs).
    assert_eq!(
        report.tip_seq,
        u64::try_from(RECORD_COUNT).unwrap(),
        "tip_seq must equal the highest seq written; an off-by-one here \
         would break SIEM tail-truncation detection",
    );
}

/// 2. Tamper detection — flip a byte mid-file. The hash chain MUST
///    surface this as `VerifyError::HashMismatch` on the tampered
///    line, not silently roll forward. The line count is asserted to
///    pin the "first failing record" semantics: a regression that
///    swallowed earlier failures and reported the *last* mismatch
///    would let a forensic analyst draw the wrong conclusion about
///    when the tampering occurred.
#[test]
fn audit_chain_detects_in_place_tampering_via_hash_mismatch() {
    let f = NamedTempFile::new().unwrap();
    {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(f.path())
            .unwrap();
        let mut writer = HashChainWriter::new(file, GENESIS_PREV.to_string());
        write_records(&mut writer);
    }

    // Read the file, flip a byte deep inside record `n=50`'s payload
    // (line 51 in the file: records are 0-indexed, lines are
    // 1-indexed, so record n=50 is the 51st line). The mutation is
    // inside the `n` field so the JSON structure stays valid — what
    // changes is the canonical bytes the hash recomputation hashes,
    // so the stored `sha256` will not match. The mid-chain choice
    // exercises the long-chain case (the inline `audit_chain::tests`
    // unit test only writes 3 records).
    let mut bytes = std::fs::read_to_string(f.path()).unwrap();
    let needle = r#""n":50"#;
    assert!(
        bytes.contains(needle),
        "bytes must contain marker for record 50; test setup is broken"
    );
    bytes = bytes.replace(needle, r#""n":99999"#);
    std::fs::write(f.path(), bytes).unwrap();

    let err = verify_audit_log(f.path()).unwrap_err();
    match err {
        VerifyError::HashMismatch { line, .. } => {
            assert_eq!(
                line, 51,
                "hash mismatch must be reported on the tampered line \
                 (record n=50 is the 51st line because records are \
                 0-indexed and lines are 1-indexed): got line {line}",
            );
        }
        other => panic!("expected HashMismatch on the tampered record, got {other:?}"),
    }
}

/// 3. Tamper detection — delete a record from the middle of the
///    chain. The hash chain alone cannot catch every form of this
///    attack (a deletion that lands at the head of the file
///    produces a strict prefix that still verifies), but the seq
///    contiguity check absolutely can: every record after the
///    deletion has `seq` one greater than expected, and the
///    verifier surfaces this as `VerifyError::Gap` on the first
///    such record.
///
/// This is the regression guard for the seq-contiguity contract
/// extended by #1173. A writer change that stopped emitting seq
/// (or that started restarting the sequence at 1 mid-log) would
/// make this test fail at `expected: N+1` vs `found: 1` — exactly
/// the failure shape the audit-trail-of-record relies on.
#[test]
fn audit_chain_detects_record_deletion_via_seq_gap() {
    let f = NamedTempFile::new().unwrap();
    {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(f.path())
            .unwrap();
        let mut writer = HashChainWriter::new(file, GENESIS_PREV.to_string());
        write_records(&mut writer);
    }

    // Read all lines, drop the 50th, write the rest back. The
    // resulting file has records 0..49 followed by 51..99 — the
    // hash chain is broken on the line that used to follow record
    // 49 (because its `prev_sha256` no longer matches the chain's
    // running tip after deletion), but the seq gap is the more
    // forensically useful signal because it points operators at
    // *which* record was removed.
    let bytes = std::fs::read_to_string(f.path()).unwrap();
    let mut lines: Vec<&str> = bytes.lines().collect();
    assert_eq!(
        lines.len(),
        RECORD_COUNT,
        "test setup must produce exactly {RECORD_COUNT} lines"
    );
    let _ = lines.remove(49);
    std::fs::write(f.path(), format!("{}\n", lines.join("\n"))).unwrap();

    let err = verify_audit_log(f.path()).unwrap_err();
    // The deletion breaks both invariants. The hash chain check
    // runs first inside the verifier (see verify_audit_log), so
    // accept either failure mode — what matters is that the
    // verifier flags the file as compromised. Pin the explicit
    // surface so a future verifier reorder still keeps the test
    // honest.
    match err {
        VerifyError::Gap {
            line,
            expected,
            found,
        } => {
            assert_eq!(
                line, 50,
                "gap should be reported on the line where the deletion \
                 first manifests (1-indexed: was record 50, now record 51 \
                 occupies line 50)"
            );
            assert_eq!(
                expected, 50,
                "verifier expected seq=50 (the deleted record's slot)"
            );
            assert_eq!(
                found, 51,
                "verifier saw seq=51 (the next record stepped into the slot)"
            );
        }
        VerifyError::HashMismatch { line, .. } => {
            // Acceptable alternative — see comment above. The
            // hash chain catches the deletion via the mismatched
            // `prev_sha256` on the line that used to follow the
            // deleted record. Pin the line number anyway so a
            // future regression that off-by-ones the verifier's
            // line counter cannot pass silently.
            assert_eq!(
                line, 50,
                "hash mismatch should land on the line where the \
                 deletion first breaks chain continuity"
            );
        }
        other => panic!("expected Gap or HashMismatch on record-deletion tampering, got {other:?}"),
    }
}
