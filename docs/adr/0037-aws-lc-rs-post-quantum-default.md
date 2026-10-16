<!-- SPDX-FileCopyrightText: 2026 Roberto Chiofalo -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# ADR 0037: aws-lc-rs as the TLS crypto provider, with hybrid post-quantum key exchange by default

- **Status:** Accepted
- **Date:** 2026-10-14
- **Deciders:** rchiofalo
- **Related:** #1729 (rustls 0.23.46), #1730 (ML-DSA under FIPS), #501
  (ML-DSA certificate verification), ADR 0019 (CNSA 2.0)

## Context

rustgate selected `ring` as its default rustls crypto provider. Nothing in
the repository records why; it predates rustls switching its own default
to aws-lc-rs. `ring` has no post-quantum key exchange and no ML-DSA, so a
default build negotiates classical key exchange only, and post-quantum
support lived behind two opt-in features (`post-quantum`, `mldsa-certs`),
a runtime flag (`--mldsa-client-certs`), and provider-composition code in
`rustgate-server`'s startup and `rustgate-tls`.

Three things changed:

- rustls 0.23.46's default provider is aws-lc-rs with `prefer-post-quantum`:
  it offers X25519MLKEM768 first and verifies ML-DSA-44/65/87 certificate
  signatures.
- aws-lc-rs builds without cmake, Go or clang outside FIPS mode. A probe in
  the release builder image (`rust:*-alpine` with only `musl-dev make`)
  compiled it in 46 seconds.
- The ML-DSA opt-in protects little. webpki checks the issuer key's
  algorithm before verifying a signature
  (`rustls-webpki` `signed_data.rs`), so ML-DSA code only runs for a chain
  anchored at an ML-DSA CA the operator configured with `--ca`.

## Decision

Every rustgate build uses the aws-lc-rs provider, and the upstream rustls
defaults apply: X25519MLKEM768 preferred, classical fallback, ML-DSA
certificate verification on.

- The workspace enables `rustls/aws_lc_rs` and `rustls/prefer-post-quantum`.
  Dependencies that pulled in `rustls/ring` (`tokio-rustls`, `reqwest`,
  `tonic`, `kube`, `ocsp-stapler`) select their aws-lc-rs or no-provider
  variants, so rustls sees a single provider and auto-selects it.
- `rustgate-server` installs the provider explicitly at startup: the FIPS
  provider with `--features fips`, otherwise aws-lc-rs with the
  `--kx-groups` order if one is given.
- `--kx-groups` is available in every build. On bandwidth-constrained links,
  `--kx-groups X25519` keeps the handshake classical (an X25519MLKEM768 key
  share adds about 1.2 KB in each direction).
- The `post-quantum` and `mldsa-certs` Cargo features remain as empty
  compatibility features. `--mldsa-client-certs` and `--prefer-post-quantum`
  remain accepted (they are also TOML config keys, and config parsing rejects
  unknown keys) and log that they no longer change anything.
- The ML-DSA strip (`aws_lc_rs_provider()`), the `mldsa_certs` module and the
  `fips` + `mldsa-certs` `compile_error!` are removed. Under the AWS-LC-FIPS
  4.x module, ML-DSA verifies and the provider still reports FIPS mode.
- `rustgate-enrollment`'s separate `post-quantum` feature (ML-DSA-87
  certificate *issuance* via `fips204`) is unchanged.

## Alternatives considered

- **Keep `ring` as the default and post-quantum opt-in.** Rejected: the
  default build would keep offering classical-only key exchange, which is
  exposed to harvest-now-decrypt-later, while rustls itself has moved on.
  The original reasons for `ring` (no C build, smaller binary) are either
  gone or small (see Consequences).
- **Make aws-lc-rs the default but keep the ML-DSA opt-in.** Rejected: it
  needs provider-stripping code kept in sync with every rustls release, for
  a gate that only affects operators who already configured an ML-DSA CA.
  It also blocked ML-DSA on rustgate's outbound connections (federation,
  HTTP egress), because the provider is process-wide.
- **Offer both providers behind a feature.** Rejected: two providers in one
  build stops rustls auto-selecting, so every TLS entry point would need an
  explicit provider, and the test matrix doubles.

## Consequences

- Every build negotiates hybrid post-quantum key exchange with peers that
  support it, and falls back to X25519 with peers that do not.
- Handshakes with post-quantum peers are larger. Operators on constrained
  tactical links should set `--kx-groups X25519`; `docs/post-quantum.md`
  says so.
- A C compiler is required to build rustgate (aws-lc-sys compiles C). cmake
  and Go are required only for `--features fips`.
- The binary grows by the size of aws-lc: the release binary with the standard
  operator features went from 14.8 MB to 16.5 MB (+1.8 MB, +12%; macOS
  arm64, measured when this ADR was written).
- `ring` was still linked for non-TLS primitives (federation JWT,
  data-package signing, random numbers, and `rcgen` outside `fips`). #1735
  moved those to aws-lc-rs and switched `rcgen` to its aws-lc-rs backend, so
  `ring` is no longer in the dependency graph: the binary has one crypto
  library, and in `fips` builds those primitives run in the FIPS module.
- Reversing this means restoring `ring` in the dependency features listed
  above and reintroducing provider selection; no data or wire format
  depends on the choice.
