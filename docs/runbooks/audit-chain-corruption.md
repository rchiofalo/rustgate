# Runbook: Audit Chain Corruption

## Overview

`rustgate-core::audit_chain` writes audit events to a newline-delimited
JSON log where every record carries a SHA-256 chain (`prev_sha256`,
`sha256`) and a strictly monotonic `seq` counter. The chain proves
in-place integrity; the `seq` counter proves completeness (it catches
tail truncation followed by anchor rewrite, which the hash chain alone
cannot). When verification fails, this runbook walks the operator from
detection through forensic preservation.

The implementation is in `crates/rustgate-core/src/audit_chain.rs`.
Public surface: `HashChainWriter`, `verify_audit_log`, `read_chain_tip`,
`read_chain_state`, `write_anchor`, `GENESIS_PREV`, `VerifyError`,
`VerifyReport`.

## Symptoms

- Startup fails with `audit log tip unrecoverable within REWIND_BUDGET`
  or `audit log last record has no `seq` field`.
- An offline `verify_audit_log()` run returns `VerifyError::HashMismatch`,
  `VerifyError::PrevMismatch`, `VerifyError::MissingSeq`,
  `VerifyError::Gap`, or `VerifyError::InvalidSeq`.
- A SIEM consumer that tracks the highest `seq` it has forwarded sees a
  later record drop below that watermark, or sees a gap.
- Logs contain audit records with `sha256` values that do not match
  what an offline recompute produces.

## Detection

1. Run an offline verify against the live audit log:
   ```bash
   rustgate-audit-verify /var/log/rustgate/audit.jsonl
   ```

2. Check the last seq the SIEM has forwarded against the current tip
   reported by `read_chain_state`:
   ```bash
   rustgate-audit-tip /var/log/rustgate/audit.jsonl
   # prints (tip_hash, next_seq); compare next_seq - 1 to SIEM watermark
   ```

3. Compare the on-disk anchor file (`<path>.anchor`) against the
   current tip. A divergence means either the anchor is stale
   (acceptable; anchors are written on rotation, not per-record) or
   the chain has been rewritten since the anchor was pinned (suspicious).

4. Subscribe a SIEM rule to the `audit_chain_corrupt` event class so a
   verifier failure pages on-call rather than waiting for the next
   manual run.

## Diagnosis

Three causes produce verifier failures. Walk them in this order — the
remediation differs sharply.

### Step 1: Torn write from an unexpected shutdown

A crash, OOM kill, or power loss mid-write leaves a partial last
record. `read_chain_tip` already truncates a torn trailing line within
the rewind budget, but if the operator runs `verify_audit_log()`
directly against an un-cleaned file, the partial line surfaces as
`InvalidJson` on the absolute last record.

**Indicators:**
- The verifier fails on the LAST record only.
- The last line is shorter than a typical record, or ends mid-token
  (no closing `}`).
- The pod restarted unexpectedly around the time of the partial line
  (`kubectl describe pod` shows `OOMKilled` or `Error`).

**This is recoverable.** Skip to [Recovery: Torn write](#torn-write).

### Step 2: External rotation event

If the audit file was rotated externally (logrotate, manual `mv`,
file-system-level snapshot replay), the on-disk file no longer
contains the chain it was written against — the new "first" record is
stranded with no genesis predecessor.

**Indicators:**
- The verifier fails on a record near the start of the file with
  `PrevMismatch` (its `prev_sha256` does not match `GENESIS_PREV`).
- The `seq` of the first record is not `1`.
- File timestamps or access logs show a rotation around the time the
  divergence appears.
- The previous segment exists at `<path>.1`, `<path>-YYYYMMDD`, or in
  the rotation backup directory.

**This is recoverable but invalidates the chain across the seam.** Skip
to [Recovery: Rotation seam](#rotation-seam).

### Step 3: Tamper or hardware corruption

A `HashMismatch` or `PrevMismatch` inside a continuous write window —
no crash, no rotation event — means a record's bytes were changed
after the chain was written. A `Gap` or out-of-order `seq` inside the
same window means records were deleted or reordered. Either is
evidence of a deliberate or accidental modification of an
append-only log.

**Indicators:**
- The verifier fails on a record in the MIDDLE of the file, not the
  first or last.
- No restart, OOM, or rotation event in the affected window.
- File timestamps (`stat -c %y`) show modification times outside the
  expected append-only pattern.
- The chain breaks at exactly one record and resumes consistently
  afterwards (classic in-place edit).

**This is NOT silently recoverable.** Skip to
[Recovery: Tamper or hardware corruption](#tamper-or-hardware-corruption).

## Offline Verification

A standalone verifier is the correct first response to any suspicion.
It does not modify the file and produces a deterministic
`VerifyReport`.

```rust
use rustgate_core::audit_chain::{verify_audit_log, VerifyError};
use std::path::Path;

fn main() -> Result<(), VerifyError> {
    let report = verify_audit_log(Path::new("/var/log/rustgate/audit.jsonl"))?;
    println!("records validated: {}", report.records);
    println!("chain tip:        {}", report.tip);
    println!("last seq:         {}", report.tip_seq);
    Ok(())
}
```

Example output on a healthy log:

```text
records validated: 14237
chain tip:        9b1e82a4f7c0...d3e1
last seq:         14237
```

Example output on a torn-write file (the partial last record):

```text
Error: InvalidJson { line: 14238, source: ... unexpected end of input }
```

Example output on a tampered file (a byte flipped at line 8412):

```text
Error: HashMismatch { line: 8412, expected: "ab12...", actual: "cd34..." }
```

To assert the chain still extends correctly after recovery, feed the
file to a fresh `HashChainWriter` and verify the tip matches:

```rust
use rustgate_core::audit_chain::{read_chain_state, HashChainWriter};
let (tip, next_seq) = read_chain_state(Path::new("audit.jsonl"))?;
let mut writer = HashChainWriter::new(io::sink(), tip).with_next_seq(next_seq);
// writer.next_seq() and writer.tip() now match the verifier's report.
```

## Recovery

### Torn write

`read_chain_tip` performs the truncation automatically when called
during writer startup, but for a one-off offline cleanup:

1. Stop the rustgate process so nothing is appending.
2. Find the byte offset of the last newline in the file:
   ```bash
   LAST_NL=$(grep -bo $'\n' /var/log/rustgate/audit.jsonl | tail -1 | cut -d: -f1)
   ```
3. Truncate to one byte past that newline:
   ```bash
   truncate -s $((LAST_NL + 1)) /var/log/rustgate/audit.jsonl
   ```
4. Re-run `verify_audit_log()` to confirm the chain is intact.
5. Restart rustgate. The writer resumes from `read_chain_state`,
   continuing the existing `seq` series.

### Rotation seam

A clean rotation requires anchoring the previous segment's tip and
starting a fresh chain on the new segment. If the rotation already
happened without that discipline, the seam cannot be repaired
in-place — the new segment's chain starts from `GENESIS_PREV` whether
the operator intended that or not.

1. Stop the rustgate process.
2. Identify the previous segment (e.g. `/var/log/rustgate/audit.jsonl.1`)
   and verify it independently:
   ```bash
   rustgate-audit-verify /var/log/rustgate/audit.jsonl.1
   ```
3. Pin the previous segment's tip to its anchor file:
   ```bash
   rustgate-audit-anchor /var/log/rustgate/audit.jsonl.1
   # writes /var/log/rustgate/audit.jsonl.1.anchor
   ```
4. Archive the previous segment + anchor to immutable storage.
5. Confirm the current segment's first record is a fresh genesis
   (`prev_sha256` = 64 zero hex chars, `seq` = 1). If not, the rotation
   produced an inconsistent segment — escalate to
   [Tamper or hardware corruption](#tamper-or-hardware-corruption).
6. Document the cutover (timestamp, previous tip, new genesis seq) in
   the operator's secondary log so the SIEM can correlate the seam.
7. Restart rustgate.

### Tamper or hardware corruption

Treat this as a security incident. Do NOT continue writing to the file —
appending after a corrupt record buries forensic evidence and
contaminates the new chain with bytes that may already be inadmissible.

1. Stop the rustgate process immediately.
2. Preserve the file with metadata intact:
   ```bash
   cp --preserve=all /var/log/rustgate/audit.jsonl \
      /var/log/rustgate/audit.jsonl.forensic.$(date -u +%Y%m%dT%H%M%SZ)
   ```
3. Capture file-system metadata for chain-of-custody:
   ```bash
   stat /var/log/rustgate/audit.jsonl > audit.forensic.stat.txt
   sha256sum /var/log/rustgate/audit.jsonl > audit.forensic.sha256
   ```
4. Escalate to the security team with the verifier report
   (`VerifyError` variant, line number, expected vs actual hash) and
   the preserved copy.
5. Move the corrupt file aside and start a fresh audit log at a new
   path. The new chain begins at `GENESIS_PREV` with `seq` = 1; pin
   the prior segment's last-known-good tip to an anchor file before
   the suspect window.
6. Restart rustgate pointed at the new path.
7. Do NOT reuse the corrupt path until the security team has signed
   off — even an empty file at the same path can mask the gap when
   reviewers pull the directory listing later.

## SIEM Alert Design

The audit chain only catches what something is watching for. Two
complementary alerts cover the failure modes:

- **`audit_chain_corrupt` — page on-call security.** Trigger on any
  `VerifyError` variant emitted by an offline or startup verifier
  pass. This is the high-severity alert: a successful corruption
  detection always means something the chain was designed to catch
  has happened.
- **`verify_audit_log_failure_count > 0 over 5m` — secondary.** If the
  primary alert is suppressed (paging fatigue, maintenance window),
  the count-based rule fires from periodic verifier sweeps. Five
  minutes balances detection latency against the cost of a full-log
  walk on a multi-gigabyte audit file.
- **`audit_seq_regression` — high-severity.** A SIEM consumer
  forwarding records out of `audit.jsonl` should remember the highest
  `seq` it has seen. If a later record's `seq` drops below that
  watermark, or a new record's `seq` is not exactly `prev_seq + 1`,
  fire immediately. This catches the tail-truncation-and-rewrite
  attack the hash chain alone cannot.

Cross-reference with the existing audit-event alerts that operators
likely already have (`authz_denied`, `tls_handshake_failed`,
`enrollment_auth_failed`, `crl_reload_failed`) — those fire on
in-band security events; the audit-chain alerts fire on the
trustworthiness of the log itself.

## Cross-References

- `crates/rustgate-core/src/audit_chain.rs` — implementation,
  `HashChainWriter`, `verify_audit_log`, `read_chain_state`,
  `write_anchor`, `REWIND_BUDGET`, `GENESIS_PREV`.
- [Disaster Recovery](../disaster-recovery.md) — broader recovery
  procedures for rustgate state.
- [Observability](../observability.md) — audit event taxonomy and
  the SIEM integration surface.
- Sibling runbooks in `docs/runbooks/` for related operator concerns.
