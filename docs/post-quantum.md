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

### Phase 1: Hybrid Key Exchange (Target: v0.6.0)

Enable **X25519Kyber768Draft00** (X25519 + ML-KEM 768) hybrid key exchange in rustls. This provides quantum resistance for key exchange while maintaining classical security as a fallback.

**Requirements:**
- rustls 0.23.22+ (already supports hybrid PQ key exchange)
- No client-side changes required — clients that don't support PQ will negotiate classical X25519
- Feature-gated behind a `post-quantum` feature flag initially

**Implementation:**
1. Add `rustls::crypto::ring::kx_group::X25519Kyber768Draft00` to the `CryptoProvider` key exchange group list
2. Place PQ groups first in preference order so PQ-capable clients negotiate PQ
3. Gate behind `#[cfg(feature = "post-quantum")]` to avoid increasing binary size for deployments that don't need it

### Phase 2: PQ Certificate Authentication (Future)

Once NIST finalizes ML-DSA (FIPS 204) and the X.509 ecosystem supports PQ signature algorithms, migrate server and client certificates to hybrid or pure PQ signatures.

**Blockers:**
- Rustls PQ signature support is not yet available
- CA tooling (e.g., `openssl`, `rcgen`) needs ML-DSA support
- Client devices must support PQ certificates

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
