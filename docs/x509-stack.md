# X.509 Stack Scoping

The workspace uses three distinct X.509 ecosystems concurrently. Each has a
narrow, documented scope and is the only crate family permitted for that role.
This document is the contribution gate: pulling one of these ecosystems into a
crate not listed below — or introducing a fourth X.509 stack — requires
discussion before the change lands.

## Overview

| Ecosystem | Role | Why this stack |
|---|---|---|
| `rcgen` | Cert + CSR generation | Ergonomic builder API for issuing certificates and CSRs in tests and at the CA signing path |
| `x509-parser` | Read-side cert parsing on the mTLS hot path | Zero-copy DER parser, low allocation overhead, OID registry covers the SAN / EKU / DN fields the verifier needs |
| `x509-cert` + `der` + `cms` | CMS signature wrapping for EST | The only Rust ecosystem with first-class RFC 5652 (CMS) support, required for RFC 7030 (EST) endpoints |

Each ecosystem is intentionally scoped to its role. Cross-pollination — e.g.
parsing a cert with `x509-cert` in the verifier, or generating one with
`x509-cert` instead of `rcgen` — is a design smell; a contributor reaching for
a different stack in an existing role should expect review pushback.

## Per-ecosystem scoping

### `rcgen`

| Field | Value |
|---|---|
| Workspace dep | `rcgen = { version = "0.14", features = ["x509-parser", "zeroize"] }` |
| Used in | `rustgate-test-utils::certs`, `rustgate-enrollment::signing` |
| Role | Generate test certificate authorities, client certs, server certs, and CSRs; sign incoming CSRs at the enrollment CA |
| Out of scope | Reading existing certs, parsing SANs/EKUs, validating chains |

### `x509-parser`

| Field | Value |
|---|---|
| Workspace dep | `x509-parser = "0.18"` |
| Used in | `rustgate-transport::extract`, `rustgate-transport::config`, `rustgate-transport::cert_reloader`, `rustgate-transport::spiffe`, `rustgate-federation::trust_store`, `rustgate-federation::v2::server`, `rustgate-http::pinning`, `rustgate-server::diagnostics::*`, `rustgate-server::mgmt_api`, `rustgate-server::metrics`, `rustgate-enrollment::revocation`, `rustgate-enrollment::handlers::revoke` |
| Role | Read-side parsing of presented client certs on the mTLS hot path: extract CN, OU, SANs, EKU, fingerprint; CRL parsing; cert-expiry diagnostics |
| Out of scope | Generating certs, signing CSRs, encoding CMS structures |

### `x509-cert` + `der` + `cms`

| Field | Value |
|---|---|
| Workspace deps | `x509-cert = "0.2"`, `der = "0.7"`, `cms = "0.2.3"` |
| Feature flag | `est` on `rustgate-enrollment` (`est = ["dep:cms", "dep:der", "dep:x509-cert"]`) |
| Used in | `rustgate-enrollment::cms_bag`, `rustgate-enrollment::est` |
| Role | Build degenerate PKCS#7 certs-only `SignedData` bags for EST `/cacerts` and `/simpleenroll`; decode CMS `ContentInfo` envelopes; parse CSR DER for CN extraction in EST handlers |
| Out of scope | Generating certs (use `rcgen`); routine cert parsing on the mTLS hot path (use `x509-parser`) |

## Decision tree

"I need to do X with a certificate, which crate do I reach for?"

| Task | Use |
|---|---|
| Generate a CA, client cert, or server cert in tests | `rcgen` (via `rustgate-test-utils::TestCa`) |
| Generate a CSR in production code | `rcgen` |
| Sign an incoming CSR at the enrollment CA | `rcgen` |
| Read CN / OU / SAN / EKU from a presented client cert | `x509-parser` |
| Compute a SHA-256 fingerprint of a presented cert | `x509-parser` (parse) + `sha2` (hash) |
| Parse and verify a CRL | `x509-parser` |
| Validate a cert chain on the mTLS hot path | `rustls` (delegates to `webpki`) — neither `x509-parser` nor `x509-cert` |
| Diagnose cert expiry / dump cert info for a runbook | `x509-parser` |
| Extract a CSR's CN inside an EST handler | `x509-cert` + `der` |
| Build a PKCS#7 `SignedData` certs-only bag for EST | `x509-cert` + `cms` + `der` |
| Decode an incoming `application/pkcs7-mime` body | `cms` + `der` |

If none of the above match the task, that is the cue to open a discussion
issue before introducing a new dependency or expanding an existing one.

## Constraints

1. **Scoped use only.** None of these ecosystems may be used outside its
   documented role without prior discussion. A PR that adds `rcgen` to a
   transport-side parser, or `x509-parser` to a CSR-issuing path, should be
   rejected on review and redirected here.
2. **No fourth ecosystem.** The workspace will not adopt a fourth X.509
   crate (`openssl`, `picky`, `webpki-roots`-direct usage, etc.) without a
   tracking issue that documents why the existing three cannot serve.
3. **`webpki` is not a separate stack.** Chain validation is delegated to
   `rustls` / `webpki` and is not in scope for this document — that is a
   transport-layer choice, not a parsing choice.
4. **Zeroize secrets.** When a CA private key is loaded for signing
   (`rustgate-enrollment::signing`), the key material must be wrapped in
   `zeroize::Zeroizing<T>` per the workspace secret-handling rule.

## Migration notes

If any of the three ecosystems becomes unmaintained, the replacement search
should start with the `RustCrypto` family (which already provides `x509-cert`,
`der`, and `cms`):

- **`rcgen` replacement** — `RustCrypto/formats` does not currently ship a
  generation-side equivalent; the closest alternative is to drive `x509-cert`
  + `der` directly to construct certs, accepting a more verbose builder
  surface. `picky` is a viable second option but pulls in `serde_json` and a
  larger dependency footprint.
- **`x509-parser` replacement** — `x509-cert` can parse DER certs and is
  already in the workspace; the migration is mechanically straightforward
  but not free, because the `x509-parser::oid_registry` constants and the
  `GeneralName` enum shape would need to be rewritten across every transport
  + diagnostics caller.
- **`x509-cert` / `der` / `cms` replacement** — no Rust-native alternative
  with comparable CMS support exists today. If the `RustCrypto` cms crate
  stalls, the realistic fallback is to vendor or fork the needed subset of
  RFC 5652 encoding/decoding rather than introduce a C-FFI dependency.

Refs: #803 (F-91 — this document), #803 (F-93 — reqwest audit),
#803 (F-94 — dep isolation).
