# Post-Quantum Cryptography Battle Plan

This is the working tracker for rustgate's CNSA 2.0 / post-quantum
migration. The architectural decision — Composite ML-DSA + ECDSA hybrid
certificates, **not** pure ML-DSA — is set in
[ADR 0019](adr/0019-cnsa2-hybrid-mldsa.md). This document tracks the
phased implementation against that decision.

## Phases

The `--cnsa2` operator surface (#504) lands in phases, mirroring ADR 0019
§2:

- **Phase 1 — scaffold flag.** `--cnsa2` exists, errors without
  `--features post-quantum`, emits a startup diagnostic naming the gap
  between requested and delivered config. No crypto behavior change.
- **Phase 2 — partial PQ key exchange.** `--cnsa2` forces TLS 1.3 and
  prefers ML-KEM key exchange when `--features post-quantum` is compiled
  in. Signatures are still classical.
- **Phase 3 — full CNSA 2.0.** ML-DSA-87 hybrid certs (#503), ML-DSA
  verification (#501), and ML-DSA issuance (#502). `--cnsa2` refuses to
  start if any of the three is unavailable.

## Phase 3A — issuance scaffold (#502, landed)

Phase 3 is gated on upstream crypto (rustls + aws-lc-rs) that is not yet
available: rcgen's ML-DSA path is behind `aws_lc_rs_unstable`, is mutually
exclusive with `fips` ([aws-lc-rs #964][awslc964]), and emits **pure**
ML-DSA certificates — the format ADR 0019 explicitly rejects for the
2026–2030 transition. The composite ML-DSA OIDs are not finalized until
late 2026.

Rather than wait, **Phase 3A** lands the honest, fail-closed first slice
in `rustgate-enrollment` so #503/#504 have a stable public surface to
build against:

- **`CaAlgorithm` enum** (`ca_algorithm.rs`): `ecdsa-p256`, `rsa-2048`,
  `ml-dsa-44`, `ml-dsa-65`, `ml-dsa-87` with `FromStr`/`Display`, serde
  kebab-case, and `is_post_quantum()` / `is_composite_required()`
  predicates.
- **`post-quantum` feature gate** (empty): does **not** enable rcgen's
  unstable path — that would break FIPS builds and emit the wrong cert
  format.
- **Fail-closed issuance** (`signing.rs`): `CsrSigner::sign_csr_with_algorithm`
  routes every ML-DSA selection to `issue_mldsa_unavailable`, which
  returns an actionable error pointing at the upstream blockers and ADR
  0019. It never silently issues a classical or pure-ML-DSA certificate.
- **FIPS conflict guard** (`fips_pq_conflict`): rejects ML-DSA on a `fips`
  build.

Deliberately **out of scope** for Phase 3A: the `--cnsa2` CLI flag wiring
into `rustgate-server` (couples to #504's flag) and any change to the
classical issuance path (byte-for-byte unchanged).

### What unblocks Phase 3B

- rustls certificate verifier accepts Composite ML-DSA signatures (#501).
- aws-lc-rs resolves the FIPS / ML-DSA mutual exclusion ([#964][awslc964]).
- IETF LAMPS composite ML-DSA OIDs finalized.

When those land, `issue_mldsa_unavailable` is replaced by the real
composite-issuance path behind the `post-quantum` gate, and the `--cnsa2`
runtime assertion (Phase 3) can require it.

[awslc964]: https://github.com/aws/aws-lc-rs/issues/964
