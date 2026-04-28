# ADR 0004: `rcgen` for test certificate generation

- **Status:** Accepted
- **Date:** 2026-04-27
- **Related:** `docs/x509-stack.md`, `crates/rustgate-test-utils`

## Context

Every rustgate test that exercises mTLS — listener, router, federation,
WebSocket, MQTT, enrollment — needs ephemeral certificates: a CA, one
or more client certs with specific SAN/OU contents, expired and
revoked variants, and matching CRLs. Hand-rolling these via `openssl`
shell-out at test time is too slow for nextest's parallelism and too
brittle for cross-platform CI; checking pre-generated PEM fixtures
into the repo is worse because expirations drift, secrets leak into
the git history, and rotating a fixture cascades through hundreds of
tests.

The Rust ecosystem has three viable X.509 stacks (catalogued in
`docs/x509-stack.md`):

- **`rcgen`** — high-level cert generation. Builds a CA, issues
  client/server certs, generates CRLs. PEM-out by default.
- **`x509-cert` + `der` + `cms`** — RustCrypto family. Lower-level
  ASN.1 builder; required for the EST RFC 7030 CMS bag work in
  `rustgate-enrollment`.
- **`x509-parser`** — read-only field extraction on the mTLS hot
  path; used by `rustgate-transport::extract` to pull CN / OU / SAN
  out of a presented client cert.

For test fixtures we want generation, not parsing or low-level
ASN.1 building. The choice is between `rcgen` (issue) and
`x509-cert` (build from primitives).

## Decision

`rustgate-test-utils` uses `rcgen` for all test certificate
generation. The `TestCa` type wraps an `rcgen` issuer; helpers like
`issue_client_cert`, `issue_server_cert`, `issue_expired_client_cert`,
and `issue_crl` are thin wrappers around `rcgen` builders that
encode our SAN/OU conventions.

`rcgen` is the only X.509 stack used in `rustgate-test-utils` —
`x509-cert` and `der` are not pulled in by this crate. The
contribution gate documented in `docs/x509-stack.md` keeps this
boundary intact.

## Alternatives considered

- **`x509-cert` + `der` for test cert building.** Rejected: the API
  is several layers lower than what tests need. We would write
  scaffolding in every test crate to replicate what `rcgen` ships
  for free, and we would still need `rcgen`'s CRL builder (or an
  equivalent we'd write ourselves).
- **OpenSSL shell-out at test setup.** Rejected: cross-platform
  drift (BoringSSL/LibreSSL/OpenSSL each behave slightly
  differently), startup cost in nextest's parallel jobs, and the
  PEM output requires re-parsing — we'd hand back the bytes to
  rustls anyway.
- **Pre-generated PEM fixtures committed to the repo.** Rejected:
  expirations drift over a project's lifetime, fixture rotation
  cascades through every test that consumes them, and the CI
  matrix (FIPS, post-quantum, MSRV) duplicates the surface that has
  to be re-generated.

## Consequences

- `rustgate-test-utils` is the single source of truth for test
  certs. The crate's `[lints.clippy]` block relaxes `panic =
  "allow"` because setup-failure-as-panic is the right shape for
  test fixtures (see the crate's `Cargo.toml`).
- No production crate may take an `rcgen` dependency. Cert *signing*
  in production lives in `rustgate-enrollment::signing`, which is
  the only production caller of `rcgen` — the boundary is documented
  in `docs/x509-stack.md` and enforced by reviewers.
- Tests do not check fixture PEMs into the repo. Every test calls
  `TestCa::new(...)` and issues fresh certs at `setup`. This makes
  every test fixture self-contained; the tradeoff is some startup
  cost amortized over the test suite.
- `rcgen`'s CRL surface is rich enough to cover the revocation
  tests in `rustgate-transport::crl_integration` without a custom
  ASN.1 builder.
- If `rcgen` ever goes unmaintained, the migration target is the
  `RustCrypto/formats` family (`x509-cert`, `der`, `cms`). The
  surface area is concentrated in `rustgate-test-utils` so the
  migration would be confined to one crate.
