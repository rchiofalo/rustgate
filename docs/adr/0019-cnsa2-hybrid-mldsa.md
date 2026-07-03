# ADR 0019: CNSA 2.0 with Composite ML-DSA hybrid certificates

- **Status:** Accepted
- **Date:** 2026-05-19
- **Deciders:** rchiofalo
- **Related:** #500 (ML-DSA package signature verification),
  #501 (ML-DSA TLS cert verification),
  #502 (ML-DSA cert + CRL issuance),
  #503 (hybrid dual-signature certs),
  #504 (`--cnsa2` CLI flag),
  #873 (CNSA 2.0 PQ alignment umbrella),
  #731 (MAVLink PQ umbrella),
  [aws-lc-rs #964](https://github.com/aws/aws-lc-rs/issues/964) — upstream FIPS/ML-DSA mutual exclusion

## Implementation status

- **#502 (2026-07, this scaffold).** Landed the honest first slice of ML-DSA
  cert/CRL issuance in `rustgate-enrollment`: a `CaAlgorithm` enum
  (`ecdsa-p256`, `rsa-2048`, `ml-dsa-44`, `ml-dsa-65`, `ml-dsa-87`) with
  `is_post_quantum()` / `is_composite_required()` predicates; an empty
  `post-quantum` feature gate; and a **fail-closed** issuance guard. Selecting
  any ML-DSA algorithm returns an actionable error
  (`signing::issue_mldsa_unavailable`) citing the upstream blockers
  ([aws-lc-rs #964](https://github.com/aws/aws-lc-rs/issues/964) + composite
  OID finalization) rather than silently issuing a classical or a pure-ML-DSA
  certificate. A `fips_pq_conflict()` guard rejects ML-DSA on a `fips` build.
  **No** unstable rcgen feature is enabled and **no** cert format changes — the
  scaffold intentionally does not wire the `--cnsa2` CLI flag (that couples to
  #504's `--cnsa2`). This unblocks #503/#504 having a stable enum + public
  surface to build against.

## Context

The NSA's [CNSA 2.0 Algorithm Suite](https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF) (September 2022, finalized 2024) is the post-quantum migration target for DoD National Security Systems. The deadline for general adoption is **2030**; for high-priority systems including TLS, **2035** is the latest acceptable migration target. Tactical mTLS routers are squarely in scope.

The CNSA 2.0 algorithm suite requires:

| Category | Algorithm | NIST Level |
|---|---|---|
| Key exchange | ML-KEM-1024 | 5 |
| Digital signatures | ML-DSA-87 | 5 |
| Symmetric encryption | AES-256 | — |
| Hash | SHA-384 or stronger | — |
| TLS version | 1.3 only | — |

rustgate already ships partial readiness:

- **ML-KEM-768 hybrid key exchange** is available via the `post-quantum` feature (rustls + aws-lc-rs `X25519MLKEM768`, shipped 2025). NIST Level 3 hybrid — not yet Level 5.
- **No ML-DSA signature support** today: rustls's certificate verifier path does not yet accept ML-DSA signatures (the upstream PR landing is blocked behind the FIPS/ML-DSA mutual exclusion at aws-lc-rs).
- **No CNSA 2.0 mode switch** today: operators wanting CNSA 2.0 would have to set `--kx-groups`, `--tls-min-version`, and a future `--enrollment-ca-algorithm` independently and trust them to converge.

The forcing function for THIS ADR is twofold:

1. **#504 needs a public surface today even though the implementation is partial.** Operators deploying rustgate into airgapped DoD environments need to start asking "does this support CNSA 2.0?" — that conversation is easier if rustgate has a `--cnsa2` flag with an honest "what works today / what's blocked upstream" diagnostic.
2. **The hybrid Composite signature direction needs a written commitment** before #501/#502/#503 can land. CNSA 2.0 prefers direct PQ adoption over hybrid, but DoD's actual rollout path uses Composite ML-DSA (RFC 9655 draft / IETF LAMPS hybrid signatures) for the 2027–2030 transition because deploying pure ML-DSA before legacy verifiers go offline breaks compatibility.

## Decision

**rustgate will implement CNSA 2.0 via the Composite ML-DSA hybrid certificate path**, with the following commitments:

1. **Hybrid composite signature pairs** (per the IETF LAMPS Hybrid Signature draft):
   - Primary path: **Composite ML-DSA-87 + ECDSA-P384** for CNSA 2.0 Level 5 deployments.
   - Lower-tier path: **Composite ML-DSA-65 + ECDSA-P256** for Level 3 deployments where ML-DSA-87 is unavailable or oversized for the wire budget (some tactical radios).
   - The classical half of the composite is the **fallback verifier** for peers that have not yet adopted ML-DSA, and the **secondary verifier** for crypto-agility per CNSA 2.0 § 4.

2. **The `--cnsa2` flag** (#504) is the operator's single switch for "give me the CNSA 2.0 target." Implementation lands in phases:
   - **Phase 1 — scaffold (this batch, K1)**: flag exists, errors if `--features post-quantum` missing, emits a startup diagnostic naming the gap between requested and delivered config. No certificate or key-exchange behavior change.
   - **Phase 2 — partial PQ KEX (`--features post-quantum`)**: when set, `--cnsa2` forces `--tls-min-version 1.3` and overrides `--kx-groups` to prefer MLKEM-1024 (when aws-lc-rs ships it; today only MLKEM-768 is in the FIPS-disallowed `unstable` module). Logs "key exchange is NIST L5 PQ; signatures are still classical."
   - **Phase 3 — full CNSA 2.0**: ML-DSA-87 hybrid certs via #503; ML-DSA-87 verification via #501; ML-DSA-87 issuance via #502. The `--cnsa2` flag's runtime asserts all three are available and refuses to start if any are missing.

3. **rustls is the only TLS provider** (per ADR 0xxx / workspace policy). The implementation path for #501/#502/#503 is whatever the upstream rustls roadmap supports — currently Composite ML-DSA via the same `CryptoProvider` extension point that landed X25519MLKEM768. **The workspace will not fork rustls.**

4. **The fips and post-quantum features stay separate compile-time gates.** A future release can require BOTH for `--cnsa2 --enforce`, but the build profile will be permissive (post-quantum without FIPS for early CNSA 2.0 testing) until aws-lc-rs resolves [#964](https://github.com/aws/aws-lc-rs/issues/964).

5. **ML-DSA-65/87 package signature verification** ships *independently* of the TLS path (#500). The offline / non-TLS code paths (Zarf package signing, audit log archive signing, release artifact signing) can adopt ML-DSA today via the `fips204` Pure Rust crate — no rustls dependency, no FIPS conflict. This is the lowest-hanging fruit on the CNSA 2.0 migration and lands in K3.

## Alternatives considered

- **Pure ML-DSA-87 without hybrid composite.** CNSA 2.0 prefers this; NSA documentation explicitly calls hybrid "tolerated but not the target end state." Rejected for the 2026–2030 window because legacy peers (older rustgate releases, partner federations, TAK clients) cannot verify ML-DSA signatures. Composite ML-DSA is the migration runway, not the destination — when 95%+ of the federation accepts ML-DSA, a future ADR can supersede this one and migrate to pure ML-DSA-87.

- **Wait for the upstream rustls + aws-lc-rs convergence before any flag.** Rejected because #504 needs a public surface NOW for operators planning CNSA 2.0 deployments in 2027–2029. The scaffolding flag with an honest diagnostic is cheaper than the wait.

- **Adopt CRYSTALS-Dilithium directly (not ML-DSA).** Rejected — NIST finalized ML-DSA (FIPS 204) as the standardized name in 2024. The Dilithium → ML-DSA rename was non-cosmetic: round-2 Dilithium key sizes were tightened. Implementations targeting Dilithium proper are not compliant.

- **Compose hybrid signatures with Ed25519 (not ECDSA).** Considered. Ed25519 is faster and has smaller keys. Rejected because CNSA 2.0 specifies ECDSA-P384 (and the lower-tier ECDSA-P256 / SECP384R1 paths). Ed25519 is not in the CNSA 2.0 algorithm suite. A future ADR could add Ed25519 hybrid for non-DoD deployments, but not under the `--cnsa2` umbrella.

- **Ship rustgate-mldsa as a separate crate that wraps `fips204`.** This is what happens for #500 (K3 in the next PR). For the TLS path it's NOT the design — TLS signature verification belongs to rustls's `CryptoProvider` abstraction, and a side-channel verifier would be a workspace-level fork.

## Consequences

**What the codebase now looks like.**

- A new `--cnsa2` CLI flag in `rustgate-server`, dormant until `--features post-quantum` is compiled in.
- A new ADR (this one) documenting the architectural direction.
- The five sub-issues (#500 / #501 / #502 / #503 / #504) become the implementation menu — each is a separate PR with this ADR as its north star.
- The workspace's `post-quantum` feature gains a sub-set semantics: PQ key exchange today; PQ signatures when upstream lands.

**New constraints on future work.**

- Any new TLS code path that hard-codes a classical signature algorithm must be flagged for CNSA 2.0 review.
- Certificate issuance (`rustgate-enrollment`) must accept ML-DSA-65/87 OIDs even when the runtime can't yet verify them — store-and-forward.
- The audit-log archive signature path (introduced in #14) is an early adopter for #500's ML-DSA-65 package signatures.

**What is now harder.**

- Operators who want CNSA 2.0 today get a partial answer (NIST L3 hybrid KEX + classical certs). The diagnostic on `--cnsa2` is what makes this honest; without it, an operator could believe they have full CNSA 2.0 when they don't.
- The hybrid Composite ML-DSA implementation will require careful interop testing with peers that have not adopted ML-DSA — the "classical fallback" path must round-trip cleanly.

**What is now easier.**

- Operators can start writing `--cnsa2` in their config files NOW. When the upstream pieces land, the flag's behavior expands without requiring config changes.
- New PQ-related issues have a written context to reference. #500 / #501 / #502 / #503 do not each need to re-litigate "why Composite ML-DSA and not pure ML-DSA."
- A future ADR superseding this one (pure ML-DSA migration) has a clear pointer to "this is what we decided in 2026 and why."

**Migration path.** When CNSA 2.0 + rustls + aws-lc-rs converge (expected 2027–2028), the four sub-PRs (#501/#502/#503 plus the wiring) flip the `--cnsa2` flag from "scaffold" to "full enforcement." This ADR's status becomes **Accepted**; if NSA revises the algorithm suite before then, this ADR's body remains the historical record and a new ADR supersedes.

## CNSA 2.0 residual-gap tracker

This section extends ADR 0019 to serve as the umbrella tracker for #873.
It maps each CNSA 2.0 requirement to the current code state with
symbol-anchored `file:line` evidence and the owning sub-issue, and it
names the two residual items #873 uniquely owns beyond the #500–#504
menu. The full mapping table lives in
[`docs/cnsa2-gap-analysis.md`](../cnsa2-gap-analysis.md); the checklist
below is the implementation menu.

**Two corrections to the #873 issue body.** The issue's status table is
directionally correct but carries two stale claims that this tracker
supersedes:

1. **#500 did NOT deliver ML-DSA package-signature verification.** #500
   closed on a *classical* scaffold. The landed `verify_signature()` in
   `rustgate-enrollment/src/datapackage.rs` (symbol at the `fn
   verify_signature` definition, ~line 423) tries **ECDSA-P256-SHA256**
   then falls back to **RSA-PSS-SHA256** — no ML-DSA path, and no
   `fips204` dependency anywhere in the tree. ADR 0019 § Decision (5)
   already flags the `fips204` work as landing "in K3 in the next PR";
   #500 closed on the classical scaffold, so ML-DSA package signing is
   still an open residual item.
2. **Federation JWT is NOT "HS256".** The `Algorithm` enum in
   `rustgate-federation/src/jwt.rs` (symbol `enum Algorithm`, ~line 130)
   supports **HS256 / ES256 / EdDSA**. It is still classical-only — there
   is no ML-DSA (PQ) option — but characterizing it as HS256-only is
   wrong.

**Residual items #873 uniquely owns** (not covered by #500–#504):

- **PQ federation JWT.** `enum Algorithm` in
  `rustgate-federation/src/jwt.rs` has no ML-DSA variant. Adding one is
  deferred: no ML-DSA signing crate is wired, and forcing an ML-DSA
  federation JWT with no peer-verifier ecosystem breaks interop — the
  same pure-PQ-too-early anti-pattern this ADR rejects for the TLS path
  (§ Alternatives, "Pure ML-DSA-87 without hybrid composite"). Blocked on
  the same `fips204`-adoption prerequisite as #500.
- **PQ-signed CI release artifacts.** `.github/workflows/release.yml`
  signs container images with **classical cosign keyless** (Sigstore /
  OIDC — see the `cosign sign` step, ~line 109). CNSA 2.0's 2025
  software-signing milestone wants quantum-resistant artifact signatures;
  this is gated on a cosign PQ provider plus the same `fips204` scaffold.

### Implementation checklist

- [x] PQ TLS key exchange — `X25519MLKEM768` preferred
      (`rustgate-tls/src/config.rs`, ~line 491 / kx-group match ~line
      550). NIST L3 hybrid; L5 (`MLKEM1024`) pending upstream.
- [x] `--cnsa2` CLI flag scaffold (#504) —
      `rustgate-server/src/cli.rs`, ~line 300 (`pub(crate) cnsa2: bool`).
- [ ] ML-DSA package-signature verification (#500 residual) — extend
      `verify_signature()` in `rustgate-enrollment/src/datapackage.rs`
      once `fips204` is wired. **Blocked** on `fips204` adoption.
- [ ] ML-DSA TLS certificate verification (#501, open) — via rustls
      `CryptoProvider` extension point; no workspace fork.
- [ ] ML-DSA certificate + CRL issuance (#502, open) —
      `rustgate-enrollment` must accept ML-DSA-65/87 OIDs (store-and-
      forward even before runtime verification lands).
- [ ] Hybrid dual-signature (Composite ML-DSA) certificates (#503, open).
- [ ] **PQ federation JWT (#873)** — add an ML-DSA variant to `enum
      Algorithm` in `rustgate-federation/src/jwt.rs`. **Deferred** until a
      peer-verifier ecosystem exists (interop risk).
- [ ] **PQ-signed CI release artifacts (#873)** — migrate
      `.github/workflows/release.yml` cosign signing to a PQ provider.
      **Blocked** on cosign PQ support + `fips204`.

**Sequencing.** `fips204` adoption (the #500 K3 follow-up) is the
unblocking prerequisite for the ML-DSA package-signing, PQ-JWT, and
PQ-artifact-signing items — they all need a wired Pure-Rust ML-DSA
signer before any code lands. The TLS-path items (#501/#502/#503) are
gated instead on the upstream rustls + aws-lc-rs convergence per this
ADR's migration path. No code, config, or behavior changes here — this
is a design note and an implementation menu; each checkbox is a separate
sub-PR with this ADR as its north star.
