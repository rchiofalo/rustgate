# ADR 0015: ChaCha20-Poly1305 with per-chunk AAD for archive encryption

- **Status:** Accepted
- **Date:** 2026-05-06
- **Related:** `crates/rustgate-core/src/encrypted.rs`,
  [ADR 0009](0009-zeroizing-and-subtle-for-secrets.md),
  [ADR 0014](0014-hash-chained-audit-log.md),
  `.claude/rules/shared-infrastructure.md` "Encrypted Archives"

## Context

rustgate writes two classes of long-lived file artifacts that need
at-rest encryption:

- **Store-and-forward queues** — per-client backlog held in
  `client_queue.redb` until a slow consumer reconnects (see
  [ADR 0006](0006-redb-over-sled-for-store-and-forward.md)).
  Contents include CoT XML position payloads, MAVLink frames,
  and any other in-flight message body.
- **Audit log archives** — the rotated tail of the hash-chained
  audit log (see [ADR 0014](0014-hash-chained-audit-log.md)).

Both files can sit on disk for hours or days while operators are
disconnected. The threat model treats disk media (machine swap,
backup tapes, decommissioned drives, an operator's lost laptop) as
hostile.

A streaming encryption scheme for append-friendly files needs:

1. **Authenticated encryption.** Plaintext recovery only on a valid
   tag — silent corruption must surface as a hard error.
2. **Key rotation without re-encryption.** Operators rotate keys
   periodically. Old archives encrypted under retired keys must
   still be readable.
3. **Detectable reordering.** An attacker who shuffles encrypted
   chunks within a file must not be able to produce a valid plaintext.
4. **Detectable tail truncation.** An attacker (or a torn write)
   that chops the tail must surface as a verification failure, not
   as a silent shorter plaintext.
5. **No `unsafe` code.** The workspace lints `unsafe_code = "forbid"`.
6. **Pure Rust.** A C dependency (libsodium, OpenSSL) fights the
   FIPS / post-quantum / MUSL CI matrix.

## Decision

Files encrypted by `rustgate_core::encrypted::EncryptedWriter` use
**ChaCha20-Poly1305 streaming AEAD with per-chunk Associated
Authenticated Data (AAD)**, framed as:

```
+-----------+--------------+--------------+ ... +--------------+
| Header    | Chunk 0      | Chunk 1      |     | Terminator   |
| (MAGIC +  | (kind=0x00,  | (kind=0x00,  |     | (kind=0x01,  |
|  version) |  index=0,    |  index=1,    |     |  index=N,    |
|           |  AEAD tag)   |  AEAD tag)   |     |  AEAD tag)   |
+-----------+--------------+--------------+ ... +--------------+
```

Concretely:

- `MAGIC = b"RGENC1\0\0"`, `FORMAT_VERSION = 2`. The header
  carries the active key id (so a multi-key `KeyRing` can dispatch
  decryption) and an 8-byte random nonce base.
- Each chunk's nonce is `nonce_base (8 bytes) || counter (4 bytes)`,
  giving 2^32 chunks per file safely under the same key. The
  counter resets per file because the base is random per file.
- Each chunk's AAD is a 13-byte tuple: `kind (1) || chunk_index (8) ||
  format_version (4)`. The `kind` distinguishes a payload chunk
  (`0x00`) from the sealed terminator (`0x01`). Binding the index
  detects intra-file reordering; binding the kind prevents an
  attacker from chopping the terminator and re-encoding a payload
  chunk in its place.
- The sealed terminator (`kind = 0x01`) carries a fixed empty
  plaintext but a real AEAD tag. Its presence is mandatory; a
  reader that does not see the terminator surfaces
  `DecryptError::MissingTerminator`.
- The `KeyRing` is a multi-key store loaded from a JSON config
  with `active_key_id` plus an arbitrary number of named keys
  retained for historical decryption. New writes use the active
  key; reads dispatch on the header's key id.
- Keys are wrapped in `Arc<Zeroizing<[u8; 32]>>`. The `KeyRing`'s
  custom `Debug` redacts every byte. Per
  [ADR 0009](0009-zeroizing-and-subtle-for-secrets.md), key
  material is zeroized on drop.

Three IKM-source modes feed the `KeyRing`:

- **Raw hex** — 64-character lowercase hex string in the config
  file. Legacy / tests; not recommended for production.
- **HKDF-SHA256** — extract-and-expand over a high-entropy root
  secret (KMS blob, HSM output, another rustgate deployment's
  master key). Requires ≥128 bits of IKM entropy.
- **Argon2id** — memory-hard derivation for low-entropy
  passphrases. OWASP defaults: m_cost = 19 MiB, t_cost = 2,
  p_cost = 1.

Each key id may carry an optional `not_after` (unix-seconds since
epoch). When the active key has expired, `EncryptedWriter::create`
refuses to open a new file. Historical archives encrypted under the
expired key remain readable.

## Alternatives considered

- **AES-256-GCM via `aes-gcm`.** A reasonable alternative; pure
  Rust and well-audited. Rejected because:
  1. ChaCha20-Poly1305 has constant-time software performance on
     CPUs without hardware AES (the FIPS / MUSL build targets we
     care about).
  2. The 96-bit nonce surface is identical, but ChaCha20's
     12-byte nonce + 64-byte block is more forgiving of the
     "random base + counter" split we use (no risk of running
     into AES-GCM's collision-prone short-nonce regime).
- **Whole-file encryption (encrypt the buffer, write once).**
  Rejected: the store-and-forward queue is appended to as
  messages overflow the per-session bound. A whole-file scheme
  would require re-encrypting on every append. Streaming AEAD
  with per-chunk tags is the natural fit for append-only files.
- **No per-chunk AAD.** Rejected: without AAD bound to the chunk
  index and kind, an attacker could reorder chunks (each one
  decrypts cleanly because the key and nonce derivation are
  index-aware, but the *plaintext* is reassembled in the wrong
  order) or chop the terminator. Both attacks become detectable
  with the AAD construction.
- **No sealed terminator.** Rejected for the same reason the
  audit log has one (see
  [ADR 0014](0014-hash-chained-audit-log.md)): silent tail
  truncation must surface.
- **A bespoke key-management story** (rotating master keys via a
  KMS, online attestation). Rejected as out of scope for the
  embedded-server use case. The `KeyRing` shape lets operators
  who *do* run a KMS feed it via `ikm_from_env` or
  `ikm_from_file` and rotate by adding a new key id and flipping
  `active_key_id`.

## Consequences

- `chacha20poly1305`, `hkdf`, `argon2`, and `sha2` are
  foundational workspace dependencies. All four are pure-Rust,
  MIT/Apache-2.0, audited, and on the audit allowlist.
- The on-disk format is versioned (`FORMAT_VERSION = 2`); a future
  format change increments the version and dispatches at the
  reader. Pre-version-2 archives (the original v1 format that
  lacked per-chunk AAD) require a one-shot offline migration
  documented in `docs/runbooks/encrypted-archives.md`.
- Adding a key is a JSON-config edit followed by SIGHUP. The
  reload picks up the new key id; new writes use it as soon as
  the operator sets `active_key_id`. Old keys remain in the
  `KeyRing` for read-side decryption.
- A 14-day expiration warning on the active key emits an
  `archive_key_rotation_due` audit event. Operators who ignore it
  get a hard refusal at the next file open
  (`EncryptError::ActiveKeyExpired`); historical reads continue
  to work.
- Authors who add a new long-lived file artifact reach for
  `EncryptedWriter` rather than rolling their own. The store-
  and-forward queue and the audit-log archive are the two current
  consumers; future ones (dead-letter queue, federation replay
  cache) follow the same shape.
- The construction does not provide non-repudiation. An attacker
  who steals the active key can produce a valid archive that the
  reader will accept. This is acceptable for the at-rest threat
  model (the key is the secret; if it leaks, the archive is
  compromised) but means the encrypted archive is *not* a
  substitute for the hash-chained audit log's tamper trail.
