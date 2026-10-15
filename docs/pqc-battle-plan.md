# Post-Quantum Cryptography Battle Plan

This is the working tracker for rustgate's CNSA 2.0 / post-quantum
migration. The architectural decision — Composite ML-DSA + ECDSA hybrid
certificates, **not** pure ML-DSA — is set in
[ADR 0019](adr/0019-cnsa2-hybrid-mldsa.md). This document tracks the
phased implementation against that decision.

## Phases

> **Update ([ADR 0037](adr/0037-aws-lc-rs-post-quantum-default.md)).**
> Hybrid ML-KEM key exchange and ML-DSA verification are now on in every
> build, so the `post-quantum` feature no longer gates anything below.
> `--cnsa2` logs a readiness report; `--kx-groups MLKEM1024` and
> `--tls-min-version 1.3` apply the CNSA 2.0 key-exchange settings.

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

## Phase 3A — pure ML-DSA-87 issuance (#502, delivered)

`rcgen` cannot emit ML-DSA: its path is behind `aws_lc_rs_unstable`, is
mutually exclusive with `fips` ([aws-lc-rs #964][awslc964]), and produces a
cert shape rustgate does not control. **Phase 3A** therefore delivers real
**pure** ML-DSA-87 issuance (RFC 9881) in `rustgate-enrollment` without
rcgen — the `mldsa` module hand-assembles the X.509 structures with
`x509-cert`/`der` and signs the DER with the pure-Rust `fips204` crate:

- **`CaAlgorithm` enum** (`ca_algorithm.rs`): `ecdsa-p256`, `rsa-2048`,
  `ml-dsa-44`, `ml-dsa-65`, `ml-dsa-87` with `FromStr`/`Display`,
  **explicit per-variant serde renames** (not `rename_all = "kebab-case"`,
  which would drop the digit separators), and `is_post_quantum()` /
  `is_composite_required()` predicates.
- **`post-quantum` feature gate**: pulls `fips204` + `x509-cert`/`der` and
  compiles the `mldsa` issuance module. Does **not** enable rcgen's unstable
  path.
- **Pure ML-DSA-87 issuance** (`mldsa.rs`): `MlDsaCa::verify_csr_pop`
  verifies the ML-DSA proof-of-possession over the DER-encoded
  `CertReqInfo`; `issue_leaf` mirrors the classical allowlist hardening
  (authenticated-username CN, random serial, `CA:FALSE` /
  `digitalSignature` / `clientAuth`, no SANs); `issue_crl` emits an
  ML-DSA-signed CRL with a monotonic `crlNumber`. `CsrSigner::with_mldsa_ca`
  + `sign_csr_with_algorithm` and `RevocationStore::new_mldsa` route to it.
- **Fail-closed fallback** (`signing.rs`): `ml-dsa-44`/`-65`, an absent
  ML-DSA CA, or a non-`post-quantum` build still route to
  `issue_mldsa_unavailable`.
- **FIPS conflict guard** (`fips_pq_conflict`): rejects any ML-DSA selection
  on a `fips` build.

Deliberately **out of scope** for Phase 3A: the `--cnsa2` CLI flag wiring
into `rustgate-server` (couples to #504's flag) and any change to the
classical issuance path (byte-for-byte unchanged).

### What unblocks Phase 3B (Composite ML-DSA)

- rustls certificate verifier accepts Composite ML-DSA signatures (#501).
- aws-lc-rs resolves the FIPS / ML-DSA mutual exclusion ([#964][awslc964]).
- IETF LAMPS `draft-ietf-lamps-pq-composite-sigs` becomes an RFC and the
  composite ML-DSA OIDs are finalized.

When those land, the composite (hybrid ML-DSA + ECDSA) issuance path is
added behind the `post-quantum` gate alongside the pure path, and the
`--cnsa2` runtime assertion (Phase 3) can require it.

[awslc964]: https://github.com/aws/aws-lc-rs/issues/964
