# Crypto Agility Strategy

This document describes rustgate's approach to cryptographic algorithm migration,
ensuring the system can adopt new algorithms (including post-quantum) without
breaking backward compatibility or requiring coordinated fleet-wide upgrades.

## Design Principles

1. **Feature-gated backends** — cryptographic backends are selected at compile
   time via feature flags, not hard-coded. Deployments choose the backend that
   matches their compliance requirements.
2. **Negotiation over configuration** — TLS cipher suites and key exchange
   groups are negotiated per-connection, not globally mandated. Clients and
   peers that support newer algorithms use them automatically; those that
   don't fall back to classical algorithms.
3. **Additive migration** — new algorithms are added alongside existing ones,
   never replacing them in a single step. Removal happens only after the
   entire fleet has migrated.
4. **No protocol-level algorithm pinning** — rustgate does not enforce
   specific cipher suites via configuration. Algorithm selection is delegated
   to rustls, which follows best-practice defaults and preference ordering.

## Cryptographic Backend Selection

rustgate delegates all cryptographic operations to [rustls](https://docs.rs/rustls/),
which supports pluggable `CryptoProvider` backends:

| Feature Flag | Backend | Use Case |
|---|---|---|
| _(default)_ | `ring` | Standard deployments, broadest platform support |
| `fips` | `aws-lc-rs` (FIPS 140-3) | Government and regulated environments |
| `post-quantum` _(planned)_ | `aws-lc-rs` | Post-quantum hybrid key exchange |

Backend selection is compile-time only — a single binary uses exactly one
`CryptoProvider`. This avoids runtime complexity and ensures the entire
binary is auditable against a single cryptographic library.

### Switching Backends

To migrate from `ring` to `aws-lc-rs` (for FIPS or post-quantum):

1. Rebuild with the appropriate feature flag (`--features fips` or
   `--features post-quantum`).
2. Deploy the new binary. No configuration changes are needed — the binary
   installs its `CryptoProvider` at startup via `install_fips_provider()`.
3. Existing clients reconnect and negotiate cipher suites with the new
   backend. No client-side changes are required.

## TLS Negotiation Strategy

### Cipher Suites

rustls selects cipher suites based on the installed `CryptoProvider`.
Both backends support:

- **TLS 1.3:** AES-256-GCM, AES-128-GCM, ChaCha20-Poly1305
- **TLS 1.2** (when permitted by `--tls-min-version`): ECDHE+AES-GCM,
  ECDHE+ChaCha20-Poly1305

The server presents all supported suites in preference order. The client
and server negotiate the strongest mutually supported suite. There is no
configuration to restrict cipher suites — rustls's defaults are considered
the secure baseline.

### Key Exchange Groups

| Backend | Key Exchange Groups (preference order) |
|---|---|
| `ring` | X25519, secp256r1, secp384r1 |
| `aws-lc-rs` | X25519, secp256r1, secp384r1 |
| `aws-lc-rs` + PQ _(planned)_ | X25519MLKEM768, X25519, secp256r1, secp384r1 |

When post-quantum support is enabled, the hybrid `X25519MLKEM768` group is
placed first in preference order. Clients that support ML-KEM negotiate
post-quantum key exchange; clients that don't silently fall back to X25519.
This is the core mechanism for zero-downtime PQ migration.

### TLS Version Control

The `--tls-min-version` flag (default: `1.2`) controls the minimum accepted
TLS protocol version:

- `1.2` — accepts TLS 1.2 and 1.3 (broadest compatibility)
- `1.3` — TLS 1.3 only (recommended for new deployments)

TLS 1.3 is preferred because it removes legacy cipher suites, mandates
forward secrecy, and reduces handshake round-trips.

## Certificate Algorithm Migration

Certificates use RSA or ECDSA signatures. Migration to post-quantum
signature algorithms (ML-DSA / FIPS 204) is blocked on ecosystem support:

- rustls does not yet support PQ signature verification
- CA tooling (`openssl`, `rcgen`) does not yet support ML-DSA
- Client devices must support PQ certificates

When these blockers are resolved, the migration path is:

1. **Hybrid certificates** — issue certificates with both classical and PQ
   signatures (dual-signature or composite). Clients that support PQ verify
   the PQ signature; others verify the classical signature.
2. **PQ-only certificates** — once the fleet has fully migrated, issue
   PQ-only certificates and remove classical signature support.

Certificate migration is independent of key exchange migration — a
deployment can use PQ key exchange with classical certificates, providing
confidentiality protection against harvest-now-decrypt-later attacks without
waiting for the certificate ecosystem to catch up.

## Federation Crypto Alignment

Federation connections (V1 mTLS and V2 gRPC) use the same TLS stack as
client connections. Algorithm negotiation works identically:

- **V1 federation** — direct TLS connection, negotiates cipher suite and
  key exchange group per-connection.
- **V2 federation** — gRPC over TLS via `tonic`, inherits the same
  `CryptoProvider` and negotiation behavior.
- **JWT authentication** (HA mode) — uses HMAC-SHA256 for claim tokens.
  This is quantum-resistant (symmetric algorithm) and does not require
  migration.

Federation peers can run different rustgate versions with different
backends. A FIPS peer connecting to a non-FIPS peer will negotiate the
strongest mutually supported suite. This enables rolling upgrades across
a federation without coordinated downtime.

## Migration Playbook

### Adding a New Algorithm

1. Verify rustls and the target `CryptoProvider` support the algorithm.
2. Add the algorithm to the provider's preference list (higher priority
   than the algorithm it replaces).
3. Gate behind a feature flag if the algorithm requires a different backend
   or has significant binary size impact.
4. Deploy incrementally — new binaries negotiate the new algorithm with
   each other while remaining compatible with older binaries.

### Removing a Deprecated Algorithm

1. Confirm all clients and federation peers have upgraded past the
   algorithm.
2. Check Prometheus metrics and connection logs to verify no connections
   are still using the deprecated algorithm.
3. Remove the algorithm from the provider's preference list or bump
   `--tls-min-version` to exclude it (e.g., `1.3` removes all TLS 1.2
   cipher suites).
4. Deploy and monitor for connection failures.

### Emergency Algorithm Disable

If a vulnerability is discovered in a specific algorithm:

1. Rebuild with a patched rustls or `CryptoProvider` that removes the
   vulnerable algorithm.
2. Deploy the patched binary. Clients will negotiate a different algorithm
   on the next connection.
3. If the vulnerability is in a key exchange group, existing sessions are
   not affected (TLS key exchange is per-session).
4. If the vulnerability is in a cipher suite used by active sessions,
   restart the server to force renegotiation.

## Related Documentation

- [Post-Quantum TLS Migration Roadmap](post-quantum.md) — phased PQ
  migration plan with timelines and blockers
- [TLS Certificates](tls-certificates.md) — certificate generation and
  requirements
- [FIPS 140-3 Support](fips.md) — building and deploying with the FIPS
  backend
- [Security Posture](security-posture.md) — NIST 800-53 control mappings
  including SC-12 (Cryptographic Key Establishment) and SC-13
  (Cryptographic Protection)
