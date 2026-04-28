# rustgate-enrollment

HTTPS certificate enrollment endpoint for client self-provisioning.

## Role in the workspace

`rustgate-enrollment` runs an HTTPS service (no client cert required at the
listener; the service authenticates via username/password) that signs PKCS#10
CSRs with the operator's CA key and returns the resulting client certificate.
It lets a TAK-style client self-provision without manual `.p12` distribution.
Depends on [rustgate-core](../rustgate-core/README.md) (PEM parsing, audit,
secret-file reader) and [rustgate-resilience](../rustgate-resilience/README.md)
(per-IP sliding-window rate limit). Wired into
[rustgate-server](../rustgate-server/README.md) under `--features enrollment`.

## Public API surface

- `EnrollmentServer` — listener that owns the hyper service, the rate
  limiter, the CSR signer, and the data-package store
- `Credentials` — username / password verifier with constant-time comparison
  via `subtle::ConstantTimeEq` (no `==` for secrets)
- `CsrSigner` — wraps the CA key and signs PKCS#10 requests with the
  authenticated username pinned into the issued cert's Subject DN
- `RevocationStore` — append-only revocation database that backs the CRL
  generator and the `/api/revoke` endpoint
- `DataPackageStore` — Marti sync API package storage (upload, download,
  search, optional signature verification)
- `ContactInfo`, `ContactsProvider`, `cached_contacts_provider` — directory
  service backing the Marti contacts API
- `EnrollmentError` — typed error enum covering CSR parsing, signing,
  revocation, auth, and rate-limit failures
- `RateLimitCallback`, `DEFAULT_SIGN_RATE_LIMIT`, `DEFAULT_SIGN_RATE_WINDOW` —
  hooks and defaults for the per-IP sliding-window admission gate

## Feature flags

| Name | Purpose | Default-on? |
|---|---|---|
| `est` | EST (RFC 7030) endpoints + CMS PKCS#7 signature wrapping for `simpleenroll` / `simplereenroll` / `cacerts`; pulls in `cms`, `der`, `x509-cert` | No |
| `fips` | Forwards `rcgen/fips` so the CSR signer uses aws-lc-rs in FIPS mode | No |

## Topology / deployment notes

Subject DN enforcement: the issued certificate carries the authenticated
username verbatim in the CN, which prevents a caller from impersonating
another user by submitting a CSR with a fabricated subject — the signing
path overwrites the CSR's subject with the auth-time identity. CA private
keys are loaded via `rustgate_core::secrets::read_secret_file` (size cap,
mode `0o077` permissions gate, `Zeroizing<String>` return).

## Where to look first

- `crates/rustgate-enrollment/src/server.rs` — listener, route table, and
  rate-limit wiring
- `crates/rustgate-enrollment/src/signing.rs` — CSR signer and the Subject DN
  enforcement contract
