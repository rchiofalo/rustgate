# ADR 0034: Multi-tenant at-rest crypto isolation for archives

- **Status:** Proposed
- **Date:** 2026-07-03
- **Deciders:** rchiofalo
- **Related:** #1538 (per-tenant archive keys), epic #885, #859 (per-tenant
  archive path namespacing), `rustgate-archive` (`encrypted.rs`,
  `archive.rs`), [ADR 0015](0015-encrypted-archives-chacha20-poly1305.md),
  [ADR 0026](0026-archive-xchacha-v3.md)

## Context

Archives are already **path**-namespaced per tenant. `resolve_tenant_bucket`
(`archive.rs`) derives a bucket from the source certificate's `O` field and
writes each tenant's data under `<archive-dir>/<tenant>/…` (#859). But every
tenant's file is encrypted with the **same** `active_key_id` from the shared
`KeyRing`. A single leaked or compromised archive key therefore exposes
*every* tenant's data at rest — the path split is an operational convenience,
not a cryptographic boundary.

The `KeyRing` already has the machinery to fix this: multiple named keys
indexed by id, per-key expiration, and HKDF-SHA256 / Argon2id derivations
(ADR 0015). What is missing is a **resolver** from a tenant id to the key id
its archives should use, plus write-path plumbing to pass the tenant through
to the writer.

The full scope epic #885 lists three at-rest isolation gaps: archives
(shared key), store-and-forward (`store_forward.rs` — one redb file, one
global HMAC key, keyed by CN only), and the position cache (`cache.rs` —
`HashMap<CN, _>` with no tenant dimension). Tackling all three in one change
would mean a redb schema migration, per-tenant key rotation semantics, and a
nonce-domain-separation analysis all landing together — too large, and the
riskiest parts (nonce reuse across tenants that share a key id) would land
under-reviewed.

**Constraints.** No `unsafe`/`unwrap`/`panic` in prod; secrets in
`Zeroizing`; the on-disk key-file format and every existing
`EncryptedWriter::create` caller (`rustgate-http` `dlq.rs` /
`dlq_reader.rs`) must be byte-for-byte unchanged; no new dependencies
(`serde`/`zeroize`/`BTreeMap` are already in the crate).

## Decision

Ship the **archive tenant → key-id resolution seam** as the first,
non-breaking slice, and sequence the store-forward and position-cache slices
in this ADR rather than attempting them now.

Concrete changes in `rustgate-archive/src/encrypted.rs` (this slice):

- Add an optional `tenant_key_map: BTreeMap<String, String>` field to
  `KeyFile` and `KeyRing`. `serde(default, skip_serializing_if =
  "BTreeMap::is_empty")` so an empty map — the default for every existing key
  file — omits the field on serialize and reproduces today's single-key
  behaviour exactly. `from_bytes` validates that every mapped key id exists
  in the ring (fail-closed at load, not at first write).
- `KeyRing::key_id_for_tenant(&self, tenant: Option<&str>) -> &str` — returns
  the mapped key id, or falls back to `active_key_id` for an unmapped tenant
  or `None`. The returned `&str` borrows `&self` (either the map entry or the
  active-key field), so resolution allocates nothing.
- `KeyRing::key_for_tenant(&self, tenant: Option<&str>) -> Result<Arc<Zeroizing<[u8; 32]>>, EncryptError>`
  — resolves the id and returns that key's material, built on the existing
  `key(&id)`.
- `EncryptedWriter::create_for_tenant(path, key_ring, tenant: Option<&str>)`
  and the mirroring `SharedEncryptedWriter::create_for_tenant` — resolve the
  key id (and its expiry gate) by tenant. The existing `create` is preserved
  and re-expressed as `create_for_tenant(path, key_ring, None)`, so all
  current callers are unchanged.

**This slice deliberately does NOT wire the resolver into the archive write
path.** `archive.rs` still calls the tenant-less entry points; passing
`resolve_tenant_bucket`'s tenant into the writer is the next slice. The seam
is inert until then and changes no on-disk bytes.

## Alternatives considered

- **Wire the write path in this slice too.** Rejected for now — it would land
  the nonce-domain and misconfiguration risks (below) unreviewed. The
  resolver is a thin, testable, behaviour-neutral change; the wiring deserves
  its own focused review.
- **A separate `KeyRing` per tenant.** Rejected — duplicates the load /
  rotation / expiry / KDF machinery per tenant and fragments the operator's
  single key-file mental model. A tenant→id map over one ring reuses all of
  it.
- **Derive a per-tenant subkey via HKDF with the tenant id as `info`.**
  Attractive (one root secret, deterministic per-tenant keys) and compatible
  with the existing `Derivation::HkdfSha256` path, but it makes *every*
  tenant's key a function of one root — the blast radius on root compromise
  is the whole fleet again. An explicit id map lets an operator provision
  genuinely independent keys (e.g. distinct KMS blobs) for tenants that
  require it, and still *use* HKDF-derived entries as map targets if they
  prefer. The map is the more general seam.
- **Do all three subsystems at once.** Rejected — see Context; three
  subsystems, a redb migration, and a nonce analysis in one change is not
  reviewable.

## Consequences

The key-file wire format is unchanged for existing deployments (empty map
omitted). All current `EncryptedWriter::create` callers and on-disk archives
are untouched. There is **no runtime behavior change** in this slice because
the resolver is not on the archive hot path.

The **risks are deferred to the wiring slice** and must be addressed there,
not silently inherited:

1. **Nonce reuse across tenants that share a key id.** Two tenants mapped to
   the same key id (or both falling back to the active key) still get
   independent per-file base nonces — the v3 XChaCha base is 160 random bits
   per file (ADR 0026), so sharing a key id across tenants is *safe* for
   confidentiality. The wiring slice must nonetheless confirm no code path
   reuses a `(key, base_nonce)` pair across the tenant split, and document
   that path-namespacing plus per-file random bases — not the key id — is
   what prevents cross-file nonce collision.
2. **Misconfiguration falling back to the shared key.** A tenant absent from
   `tenant_key_map` resolves to the shared active key. That is the intended
   default, but it means a typo in a tenant id silently drops that tenant
   back onto the shared key with no isolation. The wiring slice should emit
   an operator-facing signal (audit or startup summary) enumerating which
   tenants are isolated vs. sharing the active key, so a missing mapping is
   visible rather than silent.
3. **Per-tenant key rotation and expiry.** `create_for_tenant` already gates
   new-write admission on the *resolved* key's `not_after`, so a tenant
   pinned to a rotated-out key fails closed. The wiring slice must define the
   operator runbook for rotating a single tenant's key without disturbing
   others.

## Out of scope for this branch (sequenced follow-ups)

- **Archive write-path wiring.** Thread `resolve_tenant_bucket`'s tenant into
  `EncryptedWriter::create_for_tenant` at the `archive.rs` write site
  (`archive.rs:170` region). This is where risks 1–3 above land and get
  reviewed.
- **Store-and-forward tenant namespacing.** `store_forward.rs` uses a single
  redb file and one global HMAC integrity key, keyed by CN. Per-tenant
  isolation there needs either a per-tenant redb table/prefix or per-tenant
  files, plus a per-tenant (or tenant-domain-separated) HMAC key. This is a
  redb schema change and must migrate existing spools.
- **Position-cache tenant dimension.** `cache.rs` is `HashMap<CN, _>`; a
  tenant-scoped cache needs the tenant folded into the key so one tenant's
  replay cannot leak another's last position.

## Test plan

Unit (`encrypted.rs`, `#[cfg(test)]`): `key_id_for_tenant` maps a present
tenant and falls back to `active_key_id` for an unmapped tenant and `None`;
a key file with no `tenant_key_map` deserializes (serde default) and behaves
as today, with the empty map omitted on serialize; a `tenant_key_map` naming
an unknown key id is rejected at load; `create_for_tenant(.., Some("tenant-a"))`
on a two-key ring encrypts under tenant-a's key such that `decrypt_file`
succeeds with the full ring and fails (`UnknownKeyId`) with a ring lacking
that key — proving cross-tenant keys are cryptographically independent;
`create(..)` and `create_for_tenant(.., None)` produce equivalent output. ADR
+ CHANGELOG are docs-only. No integration test in this slice since the write
path is intentionally not wired.

## Open questions

- Should the operator-facing "which tenants are isolated" signal live in the
  wiring slice or ship earlier as a `KeyRing` diagnostic? Deferred to the
  wiring slice for now.
- For tenants requiring genuinely independent keys, is an explicit id map the
  final ergonomics, or should a future slice add an HKDF-`info`-per-tenant
  convenience mode layered on the same map? Left open.
