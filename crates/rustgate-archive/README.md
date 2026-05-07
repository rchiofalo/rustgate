# rustgate-archive

Encrypted hash-chained archives for tamper-evident audit and
store-and-forward.

## Role in the workspace

`rustgate-archive` consolidates the archive-side cryptography (streaming
ChaCha20-Poly1305 with per-chunk AAD) and the SHA-256 hash-chained audit
log writer/verifier into one crate. These modules previously lived in
`rustgate-core` (`encrypted`, `audit_chain`) and `rustgate-server`
(`archive`, `archive_rotation`); pulling them out scopes the crypto +
KDF + arc-swap dep footprint to the consumers that actually use it
([rustgate-server](../rustgate-server/README.md),
[rustgate-http](../rustgate-http/README.md), and
[rustgate-guard](../rustgate-guard/README.md)) instead of every crate
that touches `rustgate-core`. Depends only on
[rustgate-core](../rustgate-core/README.md) for the shared `Identity`,
`RoutableMessage`, audit emission, and secret-file reader. Closes #892.

## Public API surface

- `audit_chain::{HashChainWriter, GENESIS_PREV, verify_audit_log,
  read_chain_tip, read_chain_state, write_anchor, write_anchor_with_seq,
  read_anchor_with_seq, check_chain_continuity, ChainContinuity,
  AuditChainError, VerifyError, VerifyReport}` — append-only audit
  writer that injects `sha256` + `prev` fields into every JSON record so
  insertion, deletion, and modification are detectable; verifier with a
  `seq` monotonicity check that catches tail truncation the hash chain
  alone cannot
- `encrypted::{KeyRing, KeyFile, Derivation, Argon2Params, HkdfParams,
  EncryptedWriter, SharedEncryptedWriter, decrypt_file, EncryptError,
  MAGIC, FORMAT_VERSION}` — streaming ChaCha20-Poly1305 AEAD with
  per-chunk nonce binding and a sealed terminator chunk; supports raw,
  HKDF-SHA256, and Argon2id key derivation paths
- `archive::CotArchiver` — daily-rotated JSONL archiver with optional
  encryption that wraps `EncryptedWriter` when constructed via
  `with_encryption(dir, key_ring)`
- `archive_rotation::{RotationConfig, RotationStats, OnRotationStats,
  spawn, run_pass}` — size- and time-based retention task. The optional
  `OnRotationStats` callback is the integration point for the server
  binary's `rustgate_archive_bytes` Prometheus gauge — this crate stays
  Prometheus-free

## Feature flags

| Name | Purpose | Default-on? |
|---|---|---|
| `metrics` | Reserved for future archive-side Prometheus instrumentation. Today the per-pass `bytes_after` gauge wires through `RotationConfig::on_stats`; this flag is preserved so future archive-side metrics keep one feature surface. | No |

## Wire format

Every on-disk byte sequence is unchanged from the pre-extraction
layout. Files written by `rustgate-server` ≤ 0.7 — encrypted archive
chunks (`MAGIC = b"RGENC1\0\0"`, `FORMAT_VERSION = 2`), audit-log JSON
records, and anchor files — remain readable. The migration is purely a
Rust-side reorganisation.

## Where to look first

- `crates/rustgate-archive/src/audit_chain.rs` — chain semantics,
  torn-write recovery, sealed-terminator handling
- `crates/rustgate-archive/src/encrypted.rs` — AEAD framing, key
  derivation, rotation hygiene audit emission
- `crates/rustgate-archive/src/archive_rotation.rs` — retention sweep
  and the `OnRotationStats` callback shape
