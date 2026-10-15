# Post-Quantum TLS

This document describes rustgate's post-quantum (PQ) protection and what is
still outstanding.

## Current Status

Every rustgate build uses **rustls** with the **aws-lc-rs** crypto provider
([ADR 0037](https://github.com/rchiofalo/rustgate/blob/main/docs/adr/0037-aws-lc-rs-post-quantum-default.md)). With no
configuration:

- **Key exchange:** X25519MLKEM768 (X25519 + ML-KEM-768) is offered first.
  Peers that do not support it negotiate X25519, P-256 or P-384.
- **Certificate verification:** ML-DSA-44, ML-DSA-65 and ML-DSA-87 signatures
  are verified, alongside the classical ECDSA, Ed25519 and RSA schemes.
- **Symmetric ciphers:** AES-256-GCM, AES-128-GCM, ChaCha20-Poly1305. Grover's
  algorithm halves effective key strength; 256-bit keys remain secure.

The provider is process-wide, so the same settings apply to client mTLS
connections, federation (V1 mTLS and V2 gRPC) and HTTP egress.

## Why Post-Quantum Matters

The primary risk is **harvest-now-decrypt-later (HNDL)**: an adversary records
encrypted traffic today and decrypts it once a cryptographically relevant
quantum computer (CRQC) exists. Message confidentiality in tactical systems may
need to hold for years, so HNDL matters before a CRQC exists. Hybrid key
exchange closes this gap for traffic negotiated today.

Authentication is different: forging a signature requires a CRQC at the time
of the handshake, so classical certificates are not exposed to HNDL. The
long-lived credential worth migrating first is the CA (see below).

## Key Exchange

X25519MLKEM768 is a hybrid: the session is secure if either X25519 or ML-KEM-768
holds. No client-side changes are required; a client that does not offer the
hybrid group negotiates classical X25519.

`--kx-groups` (`RUSTGATE_KX_GROUPS`) replaces the offered groups and their
order. Accepted names: `X25519MLKEM768`, `SECP256R1MLKEM768`, `MLKEM768`,
`MLKEM1024`, `X25519`, `secp256r1`, `secp384r1` (case-insensitive,
comma-separated).

| Setting | Use |
|---|---|
| _(unset)_ | Hybrid PQ preferred, classical fallback. The right default. |
| `--kx-groups X25519` | Bandwidth-constrained links. An X25519MLKEM768 key share adds about 1.2 KB to each direction of the handshake. |
| `--kx-groups MLKEM1024` | CNSA 2.0 key establishment. Peers without ML-KEM-1024 cannot connect. |

`--prefer-post-quantum` is deprecated: hybrid key exchange is already
preferred. It is still accepted and logs that it changes nothing.

## Certificate Authentication

**Issuance (#502):** the `post-quantum` feature of `rustgate-enrollment`
issues pure ML-DSA-87 certificates and CRLs (RFC 9881) using the pure-Rust
`fips204` crate.

**Verification (#501):** on in every build. A chain is only verified with
ML-DSA when its issuer key is ML-DSA, which means a trust anchor the operator
configured with `--ca`. `--mldsa-client-certs` is deprecated and changes
nothing.

### Recommended deployment: ML-DSA-87 issuer, classical leaves

The migration shape worth adopting first is a **post-quantum root CA signing
classical (ECDSA P-384) leaves**:

- A root CA has a 10–20 year lifetime, so it is the credential exposed to
  harvest-now-forge-later. Leaves rotate in days or months.
- It works with **every existing client, unmodified**, because the client
  still signs with its classical key.
- It lets the PKI migrate on its own schedule, independent of endpoint fleets.

A pure ML-DSA-87 *leaf* is also accepted, with the constraints below.

### Constraints

| Constraint | Detail |
|---|---|
| **TLS 1.3 only in practice** | TLS 1.2's `ClientCertificateType` registry has no ML-DSA entry, so a TLS 1.2 CertificateRequest cannot coherently ask for an ML-DSA credential. |
| **rustgate-client cannot present a pure ML-DSA leaf** | rustls cannot yet *produce* an ML-DSA signature. Peers built on stacks that can (OpenSSL 3.5+, BoringSSL) can. |
| **Preference order** | ML-DSA schemes are advertised **after** every classical scheme, so dual-credential peers do not send a ~7 KB ML-DSA credential where a ~100-byte ECDSA one suffices. |

An ML-DSA-87 public key is 2592 bytes and a signature is 4627 bytes. On
constrained links an ML-DSA-signed chain measurably increases handshake size,
which is a further reason to start with the issuer-only migration.

## FIPS

`--features fips` uses the AWS-LC FIPS module. Hybrid key exchange and ML-DSA
verification work under it, and the provider still reports FIPS mode. Which
module version a build links, and its certification status, is in
[fips.md](fips.md).

## Remaining Work

- ML-DSA client-side *signing* (a `rustls::crypto::signer::SigningKey`
  implementation), required before `rustgate-client` can present a pure
  ML-DSA leaf.
- Composite (hybrid dual-signature) certificates, #503, blocked on
  `draft-ietf-lamps-pq-composite-sigs` becoming an RFC.
- Full CNSA 2.0, tracked in [ADR 0019](https://github.com/rchiofalo/rustgate/blob/main/docs/adr/0019-cnsa2-hybrid-mldsa.md).
  `--cnsa2` logs a readiness report at startup.

## NIST PQ Standards Reference

| Standard | Algorithm | Use | Status |
|----------|-----------|-----|--------|
| FIPS 203 | ML-KEM (Kyber) | Key encapsulation | Finalized (2024) |
| FIPS 204 | ML-DSA (Dilithium) | Digital signatures | Finalized (2024) |
| FIPS 205 | SLH-DSA (SPHINCS+) | Stateless hash-based signatures | Finalized (2024) |

## Further Reading

- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [Rustls Post-Quantum Support](https://docs.rs/rustls/latest/rustls/)
- [CISA Post-Quantum Guidance](https://www.cisa.gov/quantum)
