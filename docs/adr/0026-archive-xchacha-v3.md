# ADR 0026: Wider-nonce v3 archive format (XChaCha20-Poly1305)

- **Status:** Proposed
- **Date:** 2026-06-25
- **Deciders:** rchiofalo
- **Related:** #1506 (archive 64-bit base-nonce reuse), `rustgate-archive`
  (`encrypted.rs`), ADR on encrypted archives

> **Review status — sound; the cryptographic decision is the standard fix.**
> One **build-breaking factual error** in the first draft is corrected below
> (the `xchacha20poly1305` cargo feature does not exist). See
> [Required revisions](#required-revisions-from-adversarial-review).

## Context

`rustgate-archive` streams CoT-archive / audit / DLQ data as a fixed header plus
length-prefixed ChaCha20-Poly1305 chunks. The per-chunk nonce is `base_nonce (8
random bytes) || counter_be (4 bytes)` (`chunk_nonce()` at `encrypted.rs:1206`),
with `MAGIC = b"RGENC1\0\0"` and `FORMAT_VERSION = 2`.

The base nonce is only **64 bits** and is the *only* per-file randomness (the
counter is deterministic). Under one key, distinct files draw independent 64-bit
bases; by the birthday bound, at ~2³² files two files sharing a base becomes
non-negligible. Two files with the same base reuse the identical nonce sequence,
and ChaCha20-Poly1305 under `(key, nonce)` reuse is **catastrophic** — keystream
XOR leaks plaintext and the Poly1305 one-time key is exposed, breaking
confidentiality *and* integrity. The module doc even *claims* "the same key may
safely be reused across many files," the false premise #1506 flags. This is
reachable: the DLQ and audit sinks create many per-rotation-window files under
one long-lived `KeyRing` active key.

**Constraints.** No `unsafe`/`unwrap`/`panic` in prod; secrets in `Zeroizing`;
standard constructions only (no homegrown crypto); `chacha20poly1305 0.10` is
already the sole AEAD dep. Existing v2 files on disk (DLQ spools, audit archives)
**must stay decryptable** — `decrypt_file` is operator-facing forensics tooling.
The 32-bit chunk counter already hard-errors on per-file rollover, so only the
**cross-file base** needs widening.

## Decision

Introduce a **v3** on-disk format using **XChaCha20-Poly1305** (192-bit
`XNonce`) with a 24-byte base nonce = **20 random bytes || 4 counter bytes**
(`xnonce[20..24] = counter_be`). This makes the per-file random component 160
bits, pushing the base-collision birthday bound to ~2⁸⁰ files — astronomically
beyond any deployment — while reusing the exact chunk/AAD/terminator framing.
Bump `FORMAT_VERSION` 2→3; `MAGIC` is unchanged (it identifies "a rustgate
archive"; the version byte selects cipher/nonce width).

Concrete changes in `encrypted.rs`:

- `FORMAT_VERSION = 3`; keep `FORMAT_VERSION_V2 = 2`; `BASE_NONCE_LEN_V2 = 8`,
  `BASE_NONCE_LEN_V3 = 24`.
- Import `chacha20poly1305::{XChaCha20Poly1305, XNonce}` (**already exported** —
  see revision 1). `EncryptedWriter.cipher: XChaCha20Poly1305`,
  `base_nonce: [u8; 24]`.
- In `create()`: `getrandom(&mut base[..20])?` leaving `base[20..24] = 0`; write
  version 3 + the 24-byte base into the header.
- New `chunk_xnonce(base, counter) -> [u8; 24]` (copies base, overwrites
  `[20..24]` with `counter.to_be_bytes()`). The v2 `chunk_nonce` stays for the v2
  read path only.
- **Reader dispatch by version.** `decrypt_file` reads MAGIC, then the version
  byte, then branches: v3 → 24-byte base + `XChaCha20Poly1305`; v2 → 8-byte base
  + `ChaCha20Poly1305` (the current path). Factor the shared
  AAD/terminator/trailing-byte loop into **one** helper generic over the `Aead`
  cipher + a nonce-builder closure, so v2/v3 cannot drift in truncation
  detection. Other versions → existing `Header("unsupported version …")`.
- `KeyRing` is untouched — XChaCha20-Poly1305 uses the same 32-byte key, so
  multi-key / rotation / HKDF / Argon2id all carry over. A v2 and a v3 file can
  reference the same key id and both decrypt (version is per-file, orthogonal to
  key).
- Fix the false module-doc claim and add a "File format (version 3)" section.

**v3 is the default and only write path** — there is no flag to keep writing v2
(an opt-out would let an operator keep the vulnerability). Reads transparently
accept both. This is a one-way writer bump with a **permanently retained v2
reader**.

## Alternatives considered

- **Widen the base inside plain ChaCha20-Poly1305 (steal counter bits).**
  Rejected — the 96-bit nonce is fixed; an 88-bit base leaves only 8 counter bits
  (256 chunks/file), and any usable counter caps the base at ≤72 bits (~2³⁶
  bound, still a documented-limit footgun). XChaCha gives 160 random bits *and* a
  full 32-bit counter for the cost of one import.
- **Per-file HKDF subkey (issue's 2nd suggestion).** Sound and the documented
  fallback if RFC-blessed-only primitives are required, but heavier (an HKDF call
  per `create()`, a salt header field, a second derivation path interleaving with
  `KeyRing`). XChaCha is the standard single-primitive answer to nonce-width
  extension.
- **AES-256-GCM-SIV (misuse-resistant).** Rejected — strongest misuse resistance
  but adds a new crate + AES into a deliberately ChaCha-only stack (no HW-AES
  assumption on tactical edge). XChaCha eliminates the collision at the source.
- **Document-and-enforce a per-key file-count limit (no format change).**
  Rejected — needs durable cross-file state the stateless writer lacks; a restart
  loses the count and silently exceeds the cap.
- **New MAGIC, break v2 reads.** Rejected — existing DLQ/audit spools would
  become unreadable until migrated; retaining the v2 reader is a few dozen lines
  and zero ongoing cost.

## Consequences

Existing v2 files remain fully decryptable forever via the retained v2 read
branch — **no operator migration step is required to read old data**. There is no
in-place upgrade; the model is already "new file per rotation window," so the
fleet ages over to v3 naturally. Mixed-version directories are normal and
supported (per-file dispatch).

What gets harder: two cipher types / nonce widths now coexist in one codebase;
the read path keeps the v2 branch indefinitely. The **shared generic-over-`Aead`
loop is the single highest-risk artifact** — if it drifts in trailing-byte /
terminator handling, v2 and v3 silently diverge in truncation detection. The
tamper/reorder/truncate mirror tests plus a **checked-in golden v2 fixture** are
mandatory (revision 3).

## Required revisions (from adversarial review)

Verdict **sound_with_changes** — three corrections before implementation:

1. **DELETE the proposed `Cargo.toml` change — it does not compile.** The first
   draft said to add `features = ["xchacha20poly1305"]`; chacha20poly1305 0.10.1
   has **no such feature** (its features are `alloc, getrandom, heapless,
   rand_core, reduced-round, std, stream`), so that yields a hard "unknown
   feature" cargo error. `XChaCha20Poly1305` / `XNonce` are exported
   **unconditionally** and are already available with the current
   `default-features=false, features=["alloc","getrandom"]`. Just add the import.
   This also means **there is no dependency-surface delta** — drop the "re-run
   `cargo hack` feature-powerset / `cargo deny` because a default-off feature is
   enabled" rationale; this is a smaller change than first advertised.
2. **Make the version bump and the v2 read branch atomic in one commit.**
   `decrypt_file` currently hard-rejects any version ≠ `FORMAT_VERSION`, so
   bumping to 3 *without* the v2 branch in the same commit would instantly brick
   every existing v2 file (`Header("unsupported version 2")`).
3. **Require a CHECKED-IN golden v2 fixture** (a binary v2 file committed to the
   repo) for the back-compat test — **not** one regenerated by a retained
   v2-writer helper, which could co-drift with the shared generic helper and mask
   a regression. Keep a v2 writer only under `#[cfg(test)]` to emit that fixture
   once. Add explicit assertions that the v3 header `base[20..24] == 0` and that
   a zero-data-chunk (immediate `finish()`) v3 file round-trips. Add a
   truncated-v3-header test (short read → `Io`, not panic).

ADR number **0026** (next free after 0025; the review confirmed 0023 is the last
on disk). No external tooling parses the 8-byte base-nonce offset (verified), so
the layout change is contained.

## Test plan

Unit (`encrypted.rs`, `#[cfg(test)]`): v3 round-trip single/multi/zero-chunk;
nonce uniqueness (`[20..24] == counter`, `base[20..24] == 0`); tamper/reorder/
truncate mirrored from the v2 suite onto v3; key rotation (v3 under key A,
decrypt with a ring whose active key is B but contains A → ok; remove A →
`UnknownKeyId`); HKDF + Argon2id derived keys produce readable v3. **Back-compat
(load-bearing):** the checked-in golden v2 fixture decrypts through the
dispatching `decrypt_file`; a mixed directory (one v2, one v3, same key id)
decrypts both; unknown version → `Header`. Integration: `rustgate-http` DLQ
end-to-end (`SharedEncryptedWriter::create` now v3 + `dlq_reader` round-trip).

## Open questions

- Confirm XChaCha20-Poly1305 is acceptable despite lacking a single authoritative
  RFC (it is a libsodium-compatible de-facto standard). If RFC-8439-only
  primitives are required, fall back to the HKDF-subkey alternative.
- Any operator runbooks/tools that assume the 8-byte base-nonce offset? (Review
  found none in-repo.)
