# Threat Model

This document uses the STRIDE methodology to identify threats against rustgate, map existing mitigations, and highlight residual risks.

## System Overview

rustgate is an mTLS message router that accepts connections from clients over four transport paths:

1. **TLS (port 4433)** — primary client path, mutual TLS required
2. **WebSocket (port 8443)** — wss:// with mutual TLS, same auth as TLS
3. **Federation (ports 9000/9001)** — server-to-server, mutual TLS with optional JWT
4. **NATS (port 4222)** — broker-mediated, optional TLS

## Trust Boundaries

```
┌─────────────────────────────────────┐
│          Trusted Zone               │
│                                     │
│  ┌───────────┐   ┌──────────────┐  │
│  │  rustgate  │──>│ Position     │  │
│  │  process   │   │ Cache (mem)  │  │
│  └─────┬─────┘   └──────────────┘  │
│        │                            │
└────────┼────────────────────────────┘
         │
    ─────┼───── Trust boundaries ─────
         │
   ┌─────┴─────────────────────────────────────────┐
   │            Untrusted Zone                      │
   │                                                │
   │  ┌──────────┐  ┌──────────┐  ┌──────────────┐│
   │  │  Client   │  │ Federation│  │ NATS Broker  ││
   │  │ (mTLS)   │  │  Peer     │  │              ││
   │  └──────────┘  └──────────┘  └──────────────┘│
   │                                                │
   │  ┌──────────┐  ┌──────────┐                   │
   │  │ Plaintext│  │ Metrics  │                   │
   │  │ TCP/UDP  │  │ Scraper  │                   │
   │  └──────────┘  └──────────┘                   │
   └────────────────────────────────────────────────┘
```

## STRIDE Analysis

### Spoofing

| Threat | Description | Mitigation | Status |
|--------|-------------|------------|--------|
| S1 | Attacker impersonates a legitimate client | mTLS: client must present a certificate signed by the trusted CA | Mitigated |
| S2 | Attacker uses a revoked certificate | CRL checking at TLS handshake (`--crl`) rejects revoked certs before application layer | Mitigated |
| S3 | Attacker spoofs identity on plaintext listener | Plaintext connections are assigned a fixed synthetic identity (`--plaintext-cn`); group isolation limits blast radius | Partially mitigated |
| S4 | Attacker impersonates a federation peer | Federation uses mTLS with separate trust store (`--federation-trust-store-dir`); optional per-peer CN pinning (`trust_cert_cn`) | Mitigated |
| S5 | Enrollment server issues cert to unauthorized user | HTTP Basic Auth on enrollment endpoint; Subject DN enforcement (CN set from authenticated username, CSR subject ignored) | Mitigated |

### Tampering

| Threat | Description | Mitigation | Status |
|--------|-------------|------------|--------|
| T1 | Message modified in transit (client path) | TLS encryption and integrity protection on all client transports | Mitigated |
| T2 | Message modified in transit (federation) | mTLS on all federation connections; provenance tracking detects unexpected hops | Mitigated |
| T3 | Message modified in transit (NATS) | Optional TLS for NATS connections (`--nats-tls-*`); NATS auth via credentials file | Configurable |
| T4 | Attacker modifies CRL file on disk | CRL is read at startup from a file path; operators must protect the file via OS permissions | Operator responsibility |
| T5 | Attacker modifies federation peers file | Peers file is read from disk; operators must protect via OS permissions or use External Secrets | Operator responsibility |

### Repudiation

| Threat | Description | Mitigation | Status |
|--------|-------------|------------|--------|
| R1 | Client denies sending a message | Structured audit logging with client CN, fingerprint, and timestamp; optional CoT archival (`--archive-dir`) | Mitigated |
| R2 | Federation peer denies forwarding a message | Provenance metadata records each hop with server ID | Mitigated |

### Information Disclosure

| Threat | Description | Mitigation | Status |
|--------|-------------|------------|--------|
| I1 | Metrics endpoint leaks session topology | Metrics served on unauthenticated HTTP; exposes session counts, routing stats | Residual risk — firewall the metrics port |
| I2 | Cross-group message leakage | Router enforces group membership checks; sender must be a member of the target group | Mitigated |
| I3 | Position cache exposes stale locations | Cache entries have configurable TTL; sweep task removes expired entries | Mitigated |
| I4 | Certificate enrollment exposes CA key | CA key loaded from disk at startup; never transmitted over the network | Operator responsibility (file permissions) |

### Denial of Service

| Threat | Description | Mitigation | Status |
|--------|-------------|------------|--------|
| D1 | TLS handshake flood | Handshake concurrency semaphore (`--max-concurrent-handshakes`, default 100) | Mitigated |
| D2 | Connection exhaustion | Connection limit (`--max-connections`, default 1024); semaphore-based admission control | Mitigated |
| D3 | Oversized message | 16 MB maximum frame size enforced in all codecs | Mitigated |
| D4 | Per-client message flood | Token bucket rate limiter (`--client-message-rate`, `--client-burst`) | Mitigated (when configured) |
| D5 | Message replay attack | Anti-replay filter (`--replay-window`, default 300 seconds) | Mitigated |
| D6 | Federation amplification | Hop count limit (`--federation-max-hops`); loop detection via provenance | Mitigated |
| D7 | Metrics endpoint abuse | Connection limit (128), per-connection timeout, header read timeout (5s) | Mitigated |

### Elevation of Privilege

| Threat | Description | Mitigation | Status |
|--------|-------------|------------|--------|
| E1 | Client injects groups via certificate | Groups derived exclusively from certificate OU fields; enrollment strips CSR SANs and custom extensions | Mitigated |
| E2 | Memory-safety exploit | `unsafe_code = "forbid"` workspace-wide; all code is safe Rust | Mitigated |
| E3 | Container escape | Non-root (UID 10001), read-only root filesystem, all capabilities dropped, Pod Security Standards restricted profile | Mitigated |
| E4 | Dependency vulnerability | `cargo-deny` + `cargo-audit` in CI; Trivy container scan; OpenSSF Scorecard | Mitigated (continuous) |

## Residual Risks

| Risk | Severity | Description | Recommended Action |
|------|----------|-------------|-------------------|
| I1 | Medium | Unauthenticated metrics endpoint | Firewall metrics port; bind to localhost or private interface |
| S3 | Medium | Plaintext listeners accept unauthenticated traffic | Only enable on trusted networks; document security implications |
| T3 | Low | NATS connection may be unencrypted | Enable NATS TLS in production (`--nats-tls-*` flags) |
| T4/T5 | Low | On-disk config files could be tampered | Use read-only filesystem; External Secrets Operator in K8s |

## Relevant Documentation

- [Security Posture](security-posture.md) — NIST 800-53 control mapping
- [TLS Certificates](tls-certificates.md) — certificate requirements and management
- [FIPS 140-3](fips.md) — FIPS crypto provider setup
- [Deployment](deployment.md) — container hardening and network policies
- [SECURITY.md](../SECURITY.md) — vulnerability reporting policy
