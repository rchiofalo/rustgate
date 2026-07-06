# CNSA 2.0 gap analysis

> **Umbrella issue:** #873 — CNSA 2.0 post-quantum cryptography alignment.
> **North-star ADR:** [`docs/adr/0019-cnsa2-hybrid-mldsa.md`](adr/0019-cnsa2-hybrid-mldsa.md).
>
> This note maps each NSA
> [CNSA 2.0](https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF)
> requirement to the **current** rustgate code state, with
> symbol-anchored `file:line` evidence and the owning sub-issue. Line
> numbers are approximate and drift as sub-issues land — each claim is
> anchored to a **symbol name** (`verify_signature`, `enum Algorithm`,
> the `X25519MLKEM768` kx-group match) so it can be re-located by grep
> even after the line moves.
>
> This is a **design note and an implementation menu**. It records no
> code, config, or behavior change; each open item is a separate sub-PR
> with ADR 0019 as its north star.

## CNSA 2.0 target algorithm suite

| Category | CNSA 2.0 algorithm | NIST level |
|---|---|---|
| Key exchange | ML-KEM-1024 (FIPS 203) | 5 |
| Digital signatures | ML-DSA-87 (FIPS 204) | 5 |
| Symmetric | AES-256 | — |
| Hash | SHA-384 or stronger | — |
| TLS | 1.3 only | — |

CNSA 2.0 milestones relevant here: **2025** — software/firmware signing
must be quantum-resistant; **2027** — new deployments must support
ML-KEM key exchange; **2030/2035** — full mandate (2035 is the latest
acceptable TLS migration target). ADR 0019 targets the DoD rollout path,
which uses **Composite ML-DSA hybrid** signatures for the transition
rather than pure ML-DSA (see ADR 0019 § Decision).

## Requirement → current state

| CNSA 2.0 requirement | Status | Evidence (symbol @ `file:line`) | Owner |
|---|---|---|---|
| PQ TLS key exchange (ML-KEM) | **Done (L3 hybrid)** | `X25519MLKEM768` kx-group match @ `crates/rustgate-tls/src/config.rs:550` (preferred-group doc @ ~491). L5 `MLKEM1024` pending upstream. | shipped |
| `--cnsa2` operator switch | **Done (scaffold)** | `pub(crate) cnsa2: bool` @ `crates/rustgate-server/src/cli.rs:300` | #504 (closed) |
| ML-DSA package-signature verification | **Missing** | `fn verify_signature` @ `crates/rustgate-enrollment/src/datapackage.rs:423` tries `ECDSA_P256_SHA256_ASN1` (line 432) then `RSA_PSS_2048_8192_SHA256` (line 441) — no ML-DSA, no `fips204` dep in tree | #500 (closed on classical scaffold — residual) |
| ML-DSA TLS certificate verification | **Missing** | rustls `CryptoProvider` verifier path accepts no ML-DSA signatures yet (upstream-blocked) | #501 (open) |
| ML-DSA certificate + CRL issuance | **Missing** | `rustgate-enrollment` issues classical certs only | #502 (open) |
| Hybrid dual-signature (Composite ML-DSA) certs | **Missing** | — | #503 (open) |
| Hybrid mode fallback (classical when peer lacks PQ) | **Partial** | KEX negotiates down to X25519; signature side is classical-only, so effectively classical certs today | #501/#503 |
| **PQ federation JWT** | **Missing** | `enum Algorithm` @ `crates/rustgate-federation/src/jwt.rs:130` = `{ Hs256, Es256, EdDsa }` — classical-only, no ML-DSA variant | **#873** |
| **PQ-signed CI release artifacts** | **Missing** | `cosign sign --yes` @ `.github/workflows/release.yml:111` — classical Sigstore keyless (OIDC), no PQ provider | **#873** |

## Corrections to the #873 issue body

The issue's status table has two stale claims that this analysis
supersedes:

1. **#500 did not deliver ML-DSA package-signature verification.** The
   issue treats #500 as landed ML-DSA verification, but the merged
   `verify_signature()` at `datapackage.rs:423` is **ECDSA-P256 +
   RSA-PSS only** — no ML-DSA path, no `fips204` in the dependency tree.
   ADR 0019 § Decision (5) itself schedules the `fips204` work for "K3 in
   the next PR"; #500 closed on the classical scaffold. ML-DSA package
   signing is therefore still an **open residual item**, not done.
2. **Federation JWT is not "HS256".** The issue says "Federation JWT uses
   HS256." The `Algorithm` enum at `jwt.rs:130` actually supports
   **HS256 / ES256 / EdDSA**. It is still classical-only (no PQ option),
   but the HS256-only characterization is wrong.

## Residual items owned by #873

Beyond the #500–#504 menu, #873 uniquely owns:

- **PQ federation JWT** — add an ML-DSA variant to `enum Algorithm`
  (`jwt.rs:130`). **Deferred:** no ML-DSA signing crate is wired, and
  forcing an ML-DSA federation JWT before a peer-verifier ecosystem
  exists breaks interop — the same pure-PQ-too-early anti-pattern ADR
  0019 rejects for the TLS path. Blocked on the same `fips204` adoption
  prerequisite as #500.
- **PQ-signed CI release artifacts** — migrate the `cosign sign` step in
  `release.yml` from classical keyless to a PQ-capable provider. Gated on
  cosign PQ support plus the `fips204` scaffold.

## Sequencing

`fips204` adoption (the #500 K3 follow-up) is the single unblocking
prerequisite for the three signature-side residual items — ML-DSA
package signing, PQ federation JWT, and PQ artifact signing — because all
three need a wired Pure-Rust ML-DSA signer before any code lands. The
TLS-path items (#501 / #502 / #503) are gated instead on the upstream
rustls + aws-lc-rs convergence per ADR 0019's migration path.

The live implementation checklist is maintained in
[ADR 0019 § CNSA 2.0 residual-gap tracker](adr/0019-cnsa2-hybrid-mldsa.md#cnsa-20-residual-gap-tracker).
