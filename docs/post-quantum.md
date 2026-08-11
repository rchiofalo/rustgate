# Post-Quantum TLS Migration Roadmap

This document outlines rustgate's path to post-quantum (PQ) cryptographic protection.

## Current Status

rustgate uses **rustls** for all TLS operations. The default backend is `ring`, with optional FIPS 140-3 support via `aws-lc-rs` (`--features fips`).

- **Key exchange:** X25519 (ECDHE) — vulnerable to future quantum computers capable of running Shor's algorithm.
- **Authentication:** RSA or ECDSA certificates — also quantum-vulnerable, but requires the attacker to be present at handshake time (no harvest-now-decrypt-later risk for authentication).
- **Symmetric ciphers:** AES-256-GCM, ChaCha20-Poly1305 — quantum-resistant (Grover's algorithm halves effective key strength; 256-bit keys remain secure).

## Why Post-Quantum Matters

The primary risk is **harvest-now-decrypt-later (HNDL)**: an adversary records encrypted traffic today and decrypts it once a cryptographically relevant quantum computer (CRQC) exists. For tactical communication systems, message confidentiality may need to persist for years or decades, making HNDL a relevant concern even before CRQCs are available.

## Migration Plan

### Phase 1: Hybrid Key Exchange (Shipped: v0.7.0)

Enable **X25519MLKEM768** (X25519 + ML-KEM 768) hybrid key exchange in rustls. This provides quantum resistance for key exchange while maintaining classical security as a fallback.

**Requirements:**
- rustls 0.23.22+ (already supports hybrid PQ key exchange)
- The `aws-lc-rs` crypto backend — PQ key exchange is **not available** in the `ring` backend. rustgate already uses `aws-lc-rs` for its `fips` feature, so the build tooling (Go, cmake) is already supported.
- No client-side changes required — clients that don't support PQ will negotiate classical X25519
- Feature-gated behind a `post-quantum` feature flag initially

**Implementation:**
1. Add `rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768` to the `CryptoProvider` key exchange group list
2. Place PQ groups first in preference order so PQ-capable clients negotiate PQ
3. The `post-quantum` feature flag will depend on the `aws-lc-rs` backend (same as `fips`), since `ring` does not support PQ. Deployments that want PQ without FIPS compliance will get a separate `aws-lc-rs` dependency path.
4. Gate behind `#[cfg(feature = "post-quantum")]` to avoid increasing binary size for deployments that don't need it

### Phase 2: PQ Certificate Authentication (Partially shipped)

**Issuance shipped (#502):** the `post-quantum` feature of `rustgate-enrollment`
issues pure ML-DSA-87 certificates and CRLs (RFC 9881) using the pure-Rust
`fips204` crate.

**Verification shipped (#501):** the `mldsa-certs` feature of `rustgate-tls`
lets the server *authenticate* peers whose certificate chain is signed with
ML-DSA-87.

```bash
cargo build -p rustgate-server --features mldsa-certs
rustgate --mldsa-client-certs …      # or RUSTGATE_MLDSA_CLIENT_CERTS=1
```

The build flag alone changes nothing: the runtime flag is required, because
enabling this widens the set of certificates the process will accept.

#### Recommended deployment: ML-DSA-87 issuer, classical leaves

The migration shape worth adopting first is a **post-quantum root CA signing
classical (ECDSA P-384) leaves**. This is not a compromise — it targets the
actual exposure:

- A root CA has a 10–20 year lifetime, so it is the credential genuinely
  exposed to harvest-now-forge-later. Leaves rotate in days or months.
- It works with **every existing client, unmodified** — no client-side ML-DSA
  support is needed, because the client still signs with its classical key.
- It lets the PKI migrate on its own schedule, independent of endpoint fleets.

A pure ML-DSA-87 *leaf* is also accepted, but note the constraint below.

#### Constraints

| Constraint | Detail |
|---|---|
| **Mutually exclusive with FIPS** | ML-DSA is outside the AWS-LC FIPS submission. `--features fips,mldsa-certs` fails to build, and the provider reports `fips() == false`, so `--fips-required` cannot be combined with it. |
| **TLS 1.3 only in practice** | TLS 1.2's `ClientCertificateType` registry has no ML-DSA entry, so a TLS 1.2 CertificateRequest cannot coherently ask for an ML-DSA credential. |
| **rustgate-client cannot present a pure ML-DSA leaf** | rustls cannot yet *produce* an ML-DSA signature. The scheme is advertised for interop with stacks that can (OpenSSL 3.5+, BoringSSL). |
| **Preference order** | ML-DSA-87 is advertised **last**, behind every classical scheme, so dual-credential peers do not send a ~7 KB ML-DSA credential where a ~100-byte ECDSA one suffices. |

#### Wire-size note for constrained links

An ML-DSA-87 public key is 2592 bytes and a signature is 4627 bytes. On
bandwidth-constrained tactical links, an ML-DSA-signed chain measurably
increases handshake size — a further reason the issuer-only migration above is
the sensible default.

**Remaining work:**
- ML-DSA client-side *signing* (a `rustls::crypto::signer::SigningKey`
  implementation) — required before `rustgate-client` can present a pure
  ML-DSA leaf.
- Composite (hybrid dual-signature) certificates, #503 — blocked on
  `draft-ietf-lamps-pq-composite-sigs` becoming an RFC.
- FIPS convergence — blocked on rustls-webpki adopting the AWS-LC FIPS 4.0
  ML-DSA scope.

### Phase 3: PQ Federation (Future)

Extend PQ key exchange to federation connections (V1 mTLS and V2 gRPC). This depends on Phase 1 for the TLS layer and on `tonic`/`hyper` supporting PQ-capable TLS configurations.

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
