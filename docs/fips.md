# FIPS 140-3 Support

rustgate supports FIPS 140-3 validated cryptography via the `fips` feature flag. When enabled, all TLS operations use the [aws-lc-rs](https://github.com/aws/aws-lc-rs) crypto provider (backed by AWS-LC, a FIPS 140-3 validated module) instead of the default `ring` backend.

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
| Crypto library | ring | aws-lc (FIPS validated) |
| TLS cipher suites | ring defaults | FIPS-approved only |
| Key exchange | X25519, ECDHE | FIPS-approved ECDHE |
| Hash algorithms | SHA-2 family | SHA-2 family (FIPS) |

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

## Known Limitations

- **Ring is still linked**: When `fips` is enabled, aws-lc-rs is added as the crypto provider but ring remains compiled in as a workspace dependency. The FIPS provider is installed as the process-default, and all TLS code paths (including federation) use `CryptoProvider::get_default()` to ensure the FIPS provider is used at runtime.
- **No OCSP support**: Revocation checking is CRL-only. OCSP stapling is not supported by rustls.
- **CRL freshness**: CRL `nextUpdate` timestamps are not validated. Operators should rotate CRL files on a regular schedule.
- **TLS 1.2 enabled**: Both TLS 1.2 and 1.3 are available. For maximum FIPS strictness, TLS 1.3 is preferred.
