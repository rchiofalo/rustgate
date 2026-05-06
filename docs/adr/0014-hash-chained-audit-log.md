# ADR 0014: SHA-256 hash-chained audit log with sealed terminator

- **Status:** Accepted
- **Date:** 2026-05-06
- **Related:** `crates/rustgate-core/src/audit_chain.rs`,
  [ADR 0011](0011-tracing-not-log-workspace-wide.md),
  `.claude/rules/shared-infrastructure.md` "Hash-Chained Audit Log"

## Context

rustgate's audit log is the compliance and forensic trail: who
connected, who got rejected, which CRL reload failed, which authz
decision denied a recipient. Operators (and their auditors) need
to be able to assert two properties about the file on disk:

1. **Integrity.** No record was modified, inserted, or deleted
   after it was written.
2. **Completeness.** No record at the *tail* of the file was
   silently dropped — a partial write or a deliberate truncation
   should be detectable.

A naive append-only JSONL file gives neither. An attacker (or an
unrelated bug) can edit a record, insert a fake one, or chop the
tail, and the file still parses cleanly. Even a process crash
mid-write can leave a torn record that looks legitimate to a
naive reader.

Established cryptographic constructions for the integrity half:

- **Per-record HMAC.** Each record carries `HMAC(key, record)`.
  Detects in-place tampering. Does *not* detect insertion of a
  fake record by an attacker who has the key (because the HMAC
  validates the new record), and does not chain records — a
  record can be deleted with no telltale.
- **Hash chain (Merkle linked-list).** Each record carries
  `sha256(previous_record_hash || canonical_record_bytes)`. Editing
  any record breaks the hash chain from that record to the tip.
  Detects in-place tampering, insertion (which produces an extra
  record whose `prev_sha256` doesn't match the previous record's
  `sha256`), and deletion (which produces a record whose
  `prev_sha256` doesn't match the surviving previous record).
- **Per-record digital signature.** Each record carries
  `sign(private_key, record)`. Strongest property (proves
  authorship), most expensive (one signature per audit event,
  signing-key-management surface).

Tail completeness is independent of the chain construction. A
sealed terminator — a special record whose only job is to mark
"the chain ends here" — converts a silent truncation into a
detectable absence. The verifier looks for the terminator; if
absent, the chain is reported as unsealed.

## Decision

The audit log uses an **SHA-256 hash chain with linked records and
a sealed terminator**, plus a strictly-monotonic per-record
sequence counter for insertion/deletion detection.

Each record on disk is a single JSON object on its own line with
three machine-injected fields:

- `seq` — strictly monotonic 64-bit record number, starting at 1
  for the first record after genesis.
- `prev_sha256` — `sha256` of the previous record, or 64 zero hex
  characters for the genesis record.
- `sha256` —
  `SHA-256(prev_sha256_bytes || canonical_json_without_chain_fields)`.
  Canonical JSON is produced via `serde_json` over a
  `BTreeMap<String, Value>`, guaranteeing deterministic key
  ordering regardless of `serde_json/preserve_order`.

Concrete API (in `rustgate_core::audit_chain`):

- `HashChainWriter<W>` — wraps any `Write`, tracks the running
  `prev_sha256`, injects `seq` / `prev_sha256` / `sha256` into
  every record before writing.
- `verify_audit_log(path) -> VerifyReport { records, tip }` —
  walks the file from genesis, verifying every record's `sha256`
  and the `seq` contiguity. Returns typed errors for `Gap`,
  `MissingSeq`, `BadHash`, and `MissingTerminator`.
- `read_chain_tip(path)` — recovers the latest `sha256` so the
  next process startup can chain forward without re-reading the
  whole file. Bounded by `REWIND_BUDGET = 16 MiB` to cap startup
  cost; refuses to silently re-genesis the chain if the trailing
  window contains no valid record.
- `write_anchor(path, tip)` — persists the chain tip to a
  separate `<path>.anchor` file so external systems (a
  centralised audit collector, a SIEM rule, an offline forensic
  tool) can pin the head independently of the writer.
- `GENESIS_PREV` — exported constant `"00...00"` (64 zero hex
  chars).

The construction is a *hash chain*, not a digital signature. It
proves integrity relative to a trusted anchor (the `<path>.anchor`
file, or an externally-shipped tip), not authorship. That is the
correct trade-off for an internal compliance trail where the
operator is trusted to retain the anchor; cross-organisational
non-repudiation would require signatures, which would also require
a key-management story we have explicitly chosen not to build.

## Alternatives considered

- **Per-record HMAC, no chain.** Rejected: detects tampering in
  place but not insertion or deletion. The whole point of a
  forensic trail is the *order* of events.
- **Per-record digital signature.** Rejected for the steady-state
  audit log: the signing-key surface (rotation, HSM, revocation)
  is large compared to what hash chaining buys, and the threat
  model does not require non-repudiation. The encrypted-archive
  path uses a different construction (see
  [ADR 0015](0015-encrypted-archives-chacha20-poly1305.md)).
- **Merkle tree (not just a chain).** Useful when the consumer
  wants to prove inclusion of a single record without reading the
  full log. Rejected because rustgate's audit consumers (SIEM,
  human review) read the file linearly anyway.
- **No sealed terminator.** Rejected: a tail truncation followed
  by an anchor rewrite would leave a hash-valid file shorter than
  the operator expects, with no integrity signal. The terminator
  closes that gap.
- **`seq` counter without hash chain.** Rejected on its own:
  insertion / deletion detection still requires the chain
  property. The two together (chain + counter) give two
  independent integrity signals — the chain alone proves ordering
  and integrity but not *completeness against an external
  reference*; the counter lets a SIEM that has already forwarded
  records up to N detect that a later record's `seq` is not N+1.

## Consequences

- The audit log is a real cryptographic artifact. The on-disk
  format is documented in `crates/rustgate-core/src/audit_chain.rs`
  and in `docs/audit-log.md` (operator-facing).
- A torn write at process crash time is recoverable —
  `HashChainWriter::open_existing` walks back from the tail
  (within `REWIND_BUDGET`) until it finds the last valid record,
  truncates anything past it, and resumes. A torn write past the
  rewind budget is reported as `io::ErrorKind::InvalidData` and
  the operator must repair the log out-of-band rather than risk a
  silent re-genesis.
- Wire-format break vs pre-`seq` builds is intentional: the
  verifier rejects a record without a `seq` field with
  `VerifyError::MissingSeq`. Operators upgrading from a pre-`seq`
  build must rotate the file (start a new chain). The audit chain
  is internal infrastructure with no public SemVer commitment in
  v0.x; the strict break preserves the load-bearing property —
  every byte participates in either the chain or the counter, no
  silent fall-through.
- `sha2` is a foundational workspace dependency. It is pure-Rust,
  MIT/Apache-2.0, audited, and on the audit allowlist.
- A rotation step writes a new chain into a new file; the old
  file's anchor is preserved separately. The
  `crl_reloaded` / `archive_key_rotation_due` audit events
  signal rotation moments to operators.
- If a future regulatory regime requires non-repudiation
  (per-record signatures), the migration path is to sign the
  `sha256` field on each record at write time. The chain shape
  doesn't change; only the per-record cost goes up. We have
  chosen not to do this until an operator asks, because the
  signing-key management is a real cost.
