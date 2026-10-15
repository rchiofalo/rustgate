# FIPS 140-3 Support

rustgate supports FIPS 140-3 cryptography via the `fips` feature flag. When enabled, all TLS operations use the [aws-lc-rs](https://github.com/aws/aws-lc-rs) crypto provider, backed by the AWS-LC FIPS module, instead of the default `ring` backend. Check [the module's NIST certification status](#module-version-and-certification-status) before relying on it for compliance.

## Module version and certification status

NIST certifies a specific version of the AWS-LC FIPS module, not rustgate.
`--features fips` builds whichever module `aws-lc-fips-sys` (pinned in
`Cargo.lock`) compiles:

| rustgate | aws-lc-rs | AWS-LC-FIPS module | NIST CMVP status (checked 2026-10-15) |
|---|---|---|---|
| before #1729 | 1.16.x | 3.0.x | Certified: [#5298](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5298) (dynamic), [#5314](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5314) (static) |
| from #1729 | 1.18.x | 4.x | Submitted to NIST by AWS; no certificate issued yet |

The move to 4.x was forced: rustls 0.23.44 and later require aws-lc-rs 1.18,
which only builds the 4.x module, and the rustls fixes it brings (RUSTSEC-2026-0285
among them) apply to FIPS builds too.

If your deployment requires a module that already holds a CMVP certificate,
check the [CMVP database](https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules/search)
for AWS-LC-FIPS 4.x first. `--fips-required` confirms the provider is running
in FIPS mode; it does not check certification.

## Build Prerequisites

The `fips` feature requires additional build tooling because aws-lc-rs compiles a native C library:

- **Go** (1.20+) — required by aws-lc's build system
- **cmake** (3.12+) — required to compile the C library
- **C compiler** (gcc/clang) — standard build-essential

### Install on Ubuntu/Debian

```bash
sudo apt-get install -y cmake golang build-essential
```

### Install on macOS

```bash
brew install cmake go
```

## Building with FIPS

```bash
cargo build --release --features fips
```

To build with all features including FIPS:

```bash
cargo build --release --all-features
```

## Runtime Usage

When built with `--features fips`, the FIPS crypto provider is installed automatically at startup before any TLS operations. No additional runtime configuration is needed.

### Enforcing FIPS Mode

Use `--fips-required` (or `RUSTGATE_FIPS_REQUIRED=true`) to fail startup if the FIPS provider is not active:

```bash
rustgate --cert server.pem --key server-key.pem --ca ca.pem --fips-required
```

This prevents a non-FIPS binary from running in an environment that expects FIPS compliance. If the binary was not built with `--features fips`, startup will fail with an error:

```
--fips-required is set but FIPS crypto provider is not active.
Build with --features fips to enable FIPS 140-3 mode.
```

## What FIPS Mode Changes

| Aspect | Default (ring) | FIPS (aws-lc-rs) |
|---|---|---|
| Crypto library | ring | AWS-LC FIPS module (see certification status above) |
| TLS cipher suites | ring defaults | FIPS-approved only |
| Key exchange | X25519, ECDHE | FIPS-approved ECDHE |
| Hash algorithms | SHA-2 family | SHA-2 family (FIPS) |
| Certificate signing (enrollment) | rcgen + ring | rcgen + aws-lc-rs (FIPS) |
| PKCS#12 salt generation | OS CSPRNG (via rustls provider) | FIPS CSPRNG (via aws-lc-rs) |

The FIPS provider restricts cipher suites to the FIPS-approved set automatically via rustls. No manual cipher suite configuration is needed.

## TLS Session Resumption

TLS session resumption is **disabled** regardless of FIPS mode. This forces a full TLS handshake with certificate verification on every connection, ensuring that CRL checks are enforced and revoked certificates cannot bypass verification via cached sessions.

## CRL Support

Certificate Revocation Lists work identically in FIPS mode. Use `--crl` to load a PEM-encoded CRL file:

```bash
rustgate --cert server.pem --key server-key.pem --ca ca.pem \
    --crl revoked.pem --fips-required
```

Revoked certificates are rejected at the TLS handshake before reaching the application layer.

## Testing

FIPS tests are gated behind `#[cfg(feature = "fips")]` and live in `crates/rustgate-transport/tests/fips.rs`:

```bash
cargo nextest run -p rustgate-transport --features fips
```

Tests cover:
- FIPS provider installation and post-install verification
- `is_fips_provider_active()` reports true after install
- Provider self-reports FIPS mode via `CryptoProvider::fips()`
- Full mTLS handshake under the FIPS provider
- Negotiated cipher suite is FIPS-approved (AES-based)
- CRL revocation enforcement under FIPS

## CI

The CI pipeline includes a dedicated `fips` job that:
- Runs clippy on FIPS code paths (`rustgate-transport`, `rustgate-server`)
- Builds the full server binary with FIPS + federation features
- Runs FIPS-specific tests

This requires runners with Go and cmake installed.

## Licensing

A FIPS build links **AWS-LC** through the `aws-lc-fips-sys` crate. Parts of
AWS-LC are covered by the OpenSSL License and the original SSLeay License,
which the Free Software Foundation considers incompatible with the GPL family
of licenses, including rustgate's `AGPL-3.0-only`.

rustgate's [`NOTICE`](https://github.com/rchiofalo/rustgate/blob/main/NOTICE)
therefore grants an **additional permission under AGPL-3.0 section 7**: you may
convey a build that combines rustgate with AWS-LC. When you distribute such a
build in non-source form, the Corresponding Source you provide must include the
source of the AWS-LC parts used as well as rustgate's own source.

The default build uses `ring` (`Apache-2.0 AND ISC`) and does not rely on this
permission.

## Known Limitations

- **Ring is still linked**: When `fips` is enabled, aws-lc-rs is added as the crypto provider but ring remains compiled in as a workspace dependency. The FIPS provider is installed as the process-default, and all TLS code paths (including federation) use `CryptoProvider::get_default()` to ensure the FIPS provider is used at runtime.
- **SHA-1/SHA-2 for PKCS#12**: The PKCS#12 MAC uses `sha1` / `sha2` pure-Rust crates for HMAC-SHA1 and KDF operations. These are outside the FIPS boundary but only protect the P12 bundle integrity with a well-known password — they do not protect data in transit.
- **No OCSP support**: Revocation checking is CRL-only. OCSP stapling is not supported by rustls.
- **CRL freshness**: CRL `nextUpdate` timestamps are not validated. Operators should rotate CRL files on a regular schedule.
- **TLS 1.2 enabled**: Both TLS 1.2 and 1.3 are available. For maximum FIPS strictness, TLS 1.3 is preferred.
