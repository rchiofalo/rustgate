# ADR 0025: Live certificate-revocation lifecycle

- **Status:** Accepted (all three pieces implemented)
- **Date:** 2026-06-25
- **Deciders:** rchiofalo
- **Related:** #1496 (revocation restart-gated), `rustgate-tls`
  (`DynamicCertVerifier`, `CertReloader`), ADR on TLS verifier

> **Review status — sound, with four required changes** (see
> [Required revisions](#required-revisions-from-adversarial-review)). All new
> behavior is **off by default**, so a default deployment is byte-for-byte
> unchanged.

## Context

Client-cert revocation in rustgate is effectively **restart-gated**, and the
codebase actively misleads operators that it is live. Three defects, verified in
source:

**H-10 — CRLs frozen at boot.** Production wires the *static* verifier:
`setup.rs:289` calls `build_default_verifier()`, which bakes `self.crls` into a
plain `WebPkiClientVerifier`. `DynamicCertVerifier` is **never constructed in
production**, and even it reuses the construction-time CRL list on every rebuild.
Nothing swaps CRLs into the live rustls `ServerConfig`. The SIGHUP path admits
this in its own log string: `reload_crl_file` only re-parses and emits *"CRL
re-parsed (restart server to apply changes to active listener)"*. Meanwhile the
enrollment server exposes `/api/revoke` and `/api/crl`, so operators believe
revocation is live. (CLAUDE.md's "CRL: hot-swapped via verifier rebuild" note is
false and must be corrected.)

**M-10 — a stale CRL fails open, ungoverned.** `with_crls` discards the freshness
result (`let _ = check_crl_freshness(&crls)`); an expired CRL installs with only
a `warn!`. webpki then enforces only the serials the stale list happened to
contain, blind to anything revoked since. No flag refuses such a CRL.

**M-15 — no active disconnect.** Certs are verified only at handshake. A
long-lived tactical session (the common case) survives mid-session revocation
*and* cert expiry indefinitely. The router already tracks every session by CN in
`RouterState.sessions` with `register`/`unregister`, and `run_session_loops` is a
`tokio::select!` — a natural seam for an "evict" branch. `Identity` already
carries `fingerprint`, and in `attributes` the `cert_serial` (lowercase hex) and
`issuer_cn` needed to match a session against CRL entries.

**Constraints.** rustls is the sole TLS provider; no blocking I/O on the
handshake worker thread; `Zeroizing` secrets; `subtle` for credential compares;
**operational blast radius matters** — a tactical mesh cannot have all peers
dropped because one CRL publisher stalled, so fail-closed must be opt-in and
bounded.

## Decision

Build a revocation lifecycle on the **existing** `DynamicCertVerifier` +
`CertReloader` patterns. Three cooperating pieces in `rustgate-tls` +
`rustgate-server`. No wire/on-disk format change.

**Piece 1 — CRLs become a hot-swappable, generation-counted source.** New
`CrlStore` (`rustgate-tls/src/crl_store.rs`): holds the parsed CRL list + a
generation counter + a `CrlHealth` (stalest `nextUpdate`, `all_stale`,
`parsed_count`). `reload()` SHA-256 change-detects and bumps the generation;
`spawn_watcher` mirrors `CertReloader::spawn_watcher`. `DynamicCertVerifier`
gains a `crl_provider` (symmetric to its existing root-store provider) and folds
the CRL generation into its rebuild decision, so the **live** verifier observes
new CRLs on the next handshake with zero `ServerConfig` rebuild. Production
wiring at `setup.rs:289`: when `--crl` is set, construct a `CrlStore`, build a
`DynamicCertVerifier`, and `spawn_watcher` at `--crl-refresh-interval` — finally
giving `DynamicCertVerifier` a production caller.

**Piece 2 — fail-closed staleness.** `--crl-fail-closed` (default false →
`Warn`, today's behavior). When set and the CRL is all-stale/missing, the
verifier rejects **all** client-cert handshakes (an `AtomicBool deny_all`
checked in `verify_client_cert` before delegating) until a fresh CRL loads.
Loudly audited; recovery automatic.

**Piece 3 — active mid-session disconnect.** Add a per-session `evict:
Arc<Notify>` to `SessionHandle` + `request_evict()`; `run_session_loops` gains a
biased `_ = evict.notified() => Err(DisconnectRevoked)` branch that drops into
the existing `unregister` + `client_disconnected` teardown. A new
`RevocationSweeper` background task (`--revocation-sweep-interval`, default 0)
each tick snapshots the revoked set + registered sessions and evicts any session
whose cert is revoked **or** expired (`cert_not_after < now`), with an
id-match stale-guard so it never evicts a replacement session.

**Defaults: all OFF** (`--crl-refresh-interval=0`, `--crl-fail-closed=false`,
`--revocation-sweep-interval=0`) — strict back-compat; operators opt into
liveness.

### Implementation notes (Piece 3)

- The sweeper lives in `rustgate-router` (`revocation_sweep.rs`), not
  `rustgate-server`, because it only needs the session registry. The server
  supplies the revoked set as a callback over `CrlStore::revoked_set()`.
- The revoked `(issuer, serial)` encoding is defined once, in
  `rustgate-core::revocation`, and used by both the CRL side and the identity
  extractor. Both serials go through `BigUint::to_bytes_be`, so a high-bit
  serial matches (revision 3).
- The stale-guard is structural: each `SessionHandle` owns its own `Notify`,
  so signalling a snapshot handle can never reach a replacement session for the
  same CN. This is why the sweeper does not reuse `Router::disconnect_client`,
  which works by CN and only closes the writer side.
- The router's session map holds one session per CN, so a newer connection
  with the same certificate displaces an older one that stays connected. The
  router also keeps every live session by id, and the sweep reads that set, so
  displaced sessions are evicted too.
- Each session also records the `(issuer, serial)` of every CA certificate
  among those the client presented that is on some issuer path from the leaf
  (`chain_revocation_keys`, at most 32), so revoking an intermediate evicts
  the leaves under it. A certificate counts only when its key verifies the
  signature of one already on a path, and the search follows every branch.
  It is capped at 100 signature verifications (webpki's per-handshake
  budget) and 32 recorded certificates; a chain that hits either cap is
  rejected at connect rather than recorded partially, so same-named padding
  or self-signed twins minted with the intermediate's key cannot hide the
  copy that chains to the anchor. Byte-identical repeats are ignored. Recording
  every branch is fail-closed: a session with a valid alternate path through
  a revoked certificate (e.g. a cross-signed intermediate) is evicted too.
  Intermediates configured as trust anchors in `--ca` rather than sent by the
  client are not covered.
- Matching uses the issuer CN, not the full issuer name or key identifier, so
  two CAs with the same CN and overlapping serials are not told apart. An
  issuer CN that is not a plain string type (e.g. BMPString) yields no key and
  never matches.
- Expiry eviction is skipped for a sweep when the wall clock has moved more
  than 30 s away from monotonic time since the previous sweep
  (`revocation.sweep_clock_skew`). Revocation checks still run, because they do
  not depend on the clock. The next sweep takes the new time as its baseline,
  so a lasting clock change delays expiry eviction by one interval rather than
  blocking it; new handshakes are judged by the same clock.
- Without `--crl` and a non-zero `--crl-refresh-interval` there is no CRL
  store, so the sweep runs in expiry-only mode and logs a warning.
- MQTT sessions skip the will message on eviction and, on MQTT 5, send
  DISCONNECT with reason `0x98` (administrative action). WebSocket and TLS
  sessions close.

## Alternatives considered

- **Rebuild the whole `ServerConfig` + acceptor on CRL change.** Rejected —
  heavier and racier; folding CRL generation into `DynamicCertVerifier` reuses an
  audited rebuild path and touches one crate.
- **Lean on client-cert OCSP instead.** Rejected — OCSP is fail-open by design,
  disabled under `--air-gap` (the primary tactical deployment), and only checks
  at handshake (does nothing for M-15). CRL is the air-gap revocation story;
  OCSP stays a complementary opt-in.
- **Tear the TLS stream from the sweeper directly.** Rejected — the stream is
  owned by `run_session_loops` after `split()`; a `Notify` is the idiomatic
  cross-task wakeup and lets the existing teardown run unchanged.
- **Make `--crl-fail-closed` the default.** Rejected — unacceptable blast radius
  for a tactical mesh; matches the repo's fail-open precedents
  (`--authz-fail-open`, OCSP Tier-1).
- **Disconnect on revocation only, not expiry.** Rejected — the sweeper already
  iterates sessions with `now` in hand; expiry is the other half of M-15.

## Consequences

Revocation becomes genuinely live when opted in: a `/api/revoke` or CRL-file
update takes effect within one refresh interval at the handshake and one sweep
interval for established sessions, no restart. The false "hot-swapped" docs are
corrected. `DynamicCertVerifier` retires its "never constructed in production"
dead-path smell.

New invariants: the verifier now has **two** generation sources (root-store +
CRL) that must both drive rebuilds — pinned by a test. The sweeper depends on
`cert_serial` and CRL serials canonicalizing identically (see revision 3).
`cert_not_after` is new (small) attribute surface in the Identity bag.

Back-compat: fully backward compatible (all knobs default off; CRLs are public,
read via plain fs, no `KeyRing` interaction; no federation-wire interop concern).
The `/api/crl/status` `revocation` field is additive (serialize-only).

## Required revisions (from adversarial review)

Verdict **sound_with_changes**:

1. **Issuer-scope the sweep.** Match revoked `(issuer, serial)`, **not serial
   alone** — X.509 serials are unique only per-issuer, and `RootCertStore` is
   plural; flat-serial matching would wrongfully disconnect a still-valid live
   peer whose cert has the same serial under a different CA. `Identity` already
   carries `issuer_cn`. (Drop the `subtle::ConstantTimeEq`-on-serials idea —
   serials are public; constant-time adds nothing and obscures the tuple compare.)
2. **Fix the fail-closed blast-radius contradiction.** The design assumes
   single-CA (Piece 1) yet leans on `all_stale`-not-`any_stale` for blast-radius
   bounding (Piece 2) — but single-CA ⇒ single CRL ⇒ `all_stale == any_stale`,
   so the bound evaporates for the common case. Either add a **grace window**
   (honor a stale CRL for a bounded period before engaging `deny_all`) or
   document plainly that `--crl-fail-closed` on a single-CRL deployment is
   all-or-nothing. Clear `deny_all` **synchronously** in the reload path on a
   fresh-generation bump (not lazily on the next handshake), so a recovered
   server stops rejecting even with no inbound traffic.
3. **Harden the serial round-trip test.** A simple issue/revoke/match test passes
   even with a latent leading-zero divergence. Both paths must go through
   `BigUint::to_bytes_be`; add a serial with a **leading `0x00` DER pad / high
   bit set** and assert `cert_serial` and the CRL canonicalization agree. Also
   test that an **empty-but-fresh CRL (zero revoked serials) is healthy** and must
   NOT engage `deny_all`.
4. **Plumbing + safety details.** The evict `Notify` is **cross-crate plumbing**
   (new `SessionHandle` field/accessor in `rustgate-router` + new
   `run_session_loops` parameter in `rustgate-server`), not a 3-line change. Add
   a **saturating-i64 clamp** for `cert_not_after` (ASN.1 2050 / pre-epoch edge
   cases, no `unwrap`) and a **clock-skew guard** before any active disconnect
   (a backwards clock could otherwise mass-evict valid sessions). Pin the OCSP
   composition: with `--features ocsp`, an OCSP "good" verdict must **not**
   override inner `deny_all` (fail-closed wins). Decide whether `reload_crl_file`
   (the misleading SIGHUP path) becomes a thin shim over `CrlStore::reload` or is
   removed; fix its now-false log string.

## Test plan

Unit (rustgate-tls): `CrlStore::reload` change-detection (identical bytes →
no bump); health (`generate_expired_crl` → `all_stale`; mixed → not); dual-gen
rebuild (bump only CRL gen → verifier rebuilds + new serials enforced); fail-closed
(all-stale → `Err` before delegating; fresh sibling keeps gate open; refresh
clears `deny_all`). Integration (rustgate-server): revocation round-trip (issue →
session → drop CRL revoking it → sweeper evicts via the new branch); the
hardened serial case (revision 3); expiry disconnect; stale-guard (don't evict a
reconnected replacement); **live CRL handshake** (revoked cert rejected after a
hot swap, no restart — the exact H-10 gap); empty-but-fresh CRL = healthy; OCSP
composition (revision 4). Migration: all flags default → `build_default_verifier`
still used, behavior unchanged. `cargo hack` powerset (metrics on/off).

## Open questions

1. Should `--crl` imply a sane default refresh interval (vs 0)? Leaning **no**
   (strict back-compat).
2. One combined `--revocation-check-interval` vs separate refresh/sweep knobs?
   Leaning **separate** (they cover different latency surfaces).
3. Should fail-closed also cover missing-file-**at-boot** (refuse to start), or
   only mid-run staleness (current design: mid-run; boot still errors via
   `with_crls`)?
