# Threat Model

This document uses the STRIDE methodology to identify threats against rustgate, map existing mitigations, and highlight residual risks.

## System Overview

rustgate is an mTLS message router that accepts connections from clients over four transport paths:

1. **TLS (port 4433)** — primary client path, mutual TLS required
2. **WebSocket (port 8443)** — wss:// with mutual TLS, same auth as TLS
3. **Federation (ports 9000/9001)** — server-to-server, mutual TLS with optional JWT
4. **NATS (port 4222)** — broker-mediated, optional TLS

Beyond the data-plane transports, rustgate exposes a **management plane** and
consumes **peer-discovery inputs**. Both are attack surfaces in their own right
and are enumerated in the STRIDE analysis below:

- **Admin / management HTTP API** — served on the same HTTP listener as the
  metrics endpoint. All `/api/*` management routes (`/api/acl/`,
  `/api/federation/`, `/api/cert/`, `/api/crl/`, `/api/clients/`,
  `/api/packages/`, `/api/reload`, `/api/drain`, and the read-only
  `/api/config`, `/api/version`, `/api/metrics/summary`, `/api/audit/verify`)
  are gated by a bearer token compared in constant time. Distinct from the
  unauthenticated `/metrics` scrape path on the same port.
- **Enrollment + EST HTTP API** — certificate issuance and revocation
  (`/.well-known/est/cacerts`, `/.well-known/est/simpleenroll`,
  `/.well-known/est/simplereenroll`, `/api/revoke`, `/api/crl`,
  `/api/revoked`). Issuance is authenticated with HTTP Basic auth and a
  per-IP sliding-window rate limiter.
- **Federation peer discovery** — optional DNS-SD, Consul, or etcd backends
  that supply candidate peer addresses to `FederationManager::swap_peers`.
  A poisoned discovery record can only *propose* an address; the outbound
  federation connection is still gated by mTLS chain validation plus CN
  pinning (S4).

## Trust Boundaries

```
┌─────────────────────────────────────┐
│          Trusted Zone               │
│                                     │
│  ┌───────────┐   ┌──────────────┐   │
│  │  rustgate │──>│ Position     │   │
│  │  process  │   │ Cache (mem)  │   │
│  └─────┬─────┘   └──────────────┘   │
│        │                            │
└────────┼────────────────────────────┘
         │
    ─────┼───── Trust boundaries ─────
         │
   ┌─────┴───────────────────────────────────────── ┐
   │            Untrusted Zone                      │
   │                                                │
   │  ┌──────────┐  ┌──────────┐  ┌──────────────┐  │
   │  │  Client  │  │Federation│  │ NATS Broker  │  │
   │  │ (mTLS)   │  │   Peer   │  │              │  │
   │  └──────────┘  └──────────┘  └──────────────┘  │
   │                                                │
   │  ┌──────────┐  ┌──────────┐  ┌──────────────┐  │
   │  │ Plaintext│  │ Metrics  │  │ Admin API    │  │
   │  │ TCP/UDP  │  │ Scraper  │  │ (bearer tok) │  │
   │  └──────────┘  └──────────┘  └──────────────┘  │
   │                                                │
   │  ┌──────────────┐  ┌─────────────────────────┐ │
   │  │ Enrollment/  │  │ Peer discovery          │ │
   │  │ EST (Basic)  │  │ (DNS-SD / Consul / etcd) │ │
   │  └──────────────┘  └─────────────────────────┘ │
   └────────────────────────────────────────────────┘
```

## STRIDE Analysis

### Spoofing

| Threat | Description | Mitigation | Status |
|--------|-------------|------------|--------|
| S1 | Attacker impersonates a legitimate client | mTLS: client must present a certificate signed by the trusted CA | Mitigated |
| S2 | Attacker uses a revoked certificate | CRL checking at TLS handshake (`--crl`) rejects revoked certs before application layer | Mitigated |
| S3 | Attacker spoofs identity on plaintext listener | Plaintext connections are assigned a fixed synthetic identity (`--plaintext-cn`); group isolation limits blast radius | Partially mitigated |
| S4 | Attacker impersonates a federation peer | Federation uses mTLS with a separate trust store (`--federation-trust-store-dir`). Chain validation alone does not bind a connection to a peer *identity*, so outbound clients additionally **pin the peer certificate CN** (SEC-1): per-peer `trust_cert_cn`, or every peer's `id` under `--federation-require-peer-cn-match`; mismatch fails closed. Enforced on **both** V1 (post-handshake CN check) and V2 (gRPC, via a CN-pinning TLS verifier on the channel). | Mitigated |
| S5 | Enrollment server issues cert to unauthorized user | HTTP Basic Auth on enrollment/EST endpoints (`/.well-known/est/simpleenroll`, `simplereenroll`); Subject DN enforcement (CN set from authenticated username, CSR subject ignored). Both credential comparisons run in constant time (`subtle::ConstantTimeEq`) so timing cannot distinguish "wrong username" from "wrong password" | Mitigated |
| S6 | Attacker invokes admin/management API without authorization | All `/api/*` management routes (`/api/acl/`, `/api/federation/`, `/api/cert/`, `/api/crl/`, `/api/clients/`, `/api/packages/`, `/api/reload`, `/api/drain`, read-only `/api/config`, `/api/version`, `/api/metrics/summary`, `/api/audit/verify`) require an `Authorization: Bearer <token>` header matched against the configured token in constant time. Missing/mismatched token → `401` with `WWW-Authenticate: Bearer`. When no token is configured, management routes are refused rather than served open (unlike `/metrics`) | Mitigated |
| S7 | Attacker poisons federation peer discovery (DNS-SD/Consul/etcd) to redirect an outbound connection | Discovery backends only supply *candidate* addresses to `FederationManager::swap_peers`; the actual connection is still gated by mTLS chain validation against the federation trust store plus CN pinning (see S4). A poisoned record cannot present a valid peer certificate, so the handshake fails closed. Discovery HTTP responses are size-bounded to limit resource abuse | Mitigated |

**Note on WebSocket (port 8443):** The WebSocket listener uses the same mTLS handshake as the primary TLS path — all spoofing mitigations (S1–S5) apply identically. The WebSocket upgrade occurs over the already-authenticated TLS connection, so no additional origin header checking is needed.

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
| I1 | Metrics endpoint leaks deployment topology | Metrics served on unauthenticated HTTP (`/metrics`, distinct from the bearer-gated `/api/*` routes on the same port). `rustgate_sessions_active` reveals live client count; per-CN `identity_cn`-labeled counters (handshake failures, bytes sent/received, per-identity routing) enumerate connected identities; federation peer-labeled gauges reveal peer fan-out. Together these disclose deployment topology — see residual-risk note (ties to SEC-20) | Residual risk — firewall the metrics port |
| I2 | Cross-group message leakage | Router enforces group membership checks; sender must be a member of the target group | Mitigated |
| I3 | Position cache exposes stale locations | Cache entries have configurable TTL; sweep task removes expired entries | Mitigated |
| I4 | Certificate enrollment exposes CA key | CA key loaded from disk at startup; never transmitted over the network | Operator responsibility (file permissions) |
| I5 | Revocation state disclosed via enrollment API | `GET /api/crl`, `GET /api/revoked`, and the EST `cacerts` endpoint expose CA/CRL material by design (public trust-anchor distribution); no client-identity fields are returned. Issuance/revocation *mutations* (`/simpleenroll`, `/api/revoke`) remain authenticated | Mitigated (by design) |

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
| D8 | Per-IP rate limit bypass via NAT/proxy | Per-IP rate limiters (WebSocket, MQTT, enrollment) use the raw TCP peer address. Behind NAT or a load balancer, all clients share one IP. See residual risks below | Partially mitigated |
| D9 | Enrollment signing flood | Per-IP sliding-window rate limiter (`SlidingWindowLimiter`) caps `simpleenroll`/`simplereenroll`/`/api/revoke` signing operations; rejections emit `audit::security_rate_limited`. Malformed requests (wrong media type) are refused `415` before consuming a slot | Mitigated |
| D10 | Admin API abuse (reload/drain storm) | Management routes share the metrics HTTP listener limits (connection cap, per-connection and header read timeouts) and require a valid bearer token before any handler runs, so unauthenticated request floods are rejected at the auth gate | Mitigated |

### Elevation of Privilege

| Threat | Description | Mitigation | Status |
|--------|-------------|------------|--------|
| E1 | Client injects groups via certificate | Groups derived exclusively from certificate OU fields; enrollment strips CSR SANs and custom extensions | Mitigated |
| E2 | Memory-safety exploit | `unsafe_code = "forbid"` workspace-wide; all code is safe Rust | Mitigated |
| E3 | Container escape | Non-root (UID 10001), read-only root filesystem, all capabilities dropped, Pod Security Standards restricted profile | Mitigated |
| E4 | Dependency vulnerability | `cargo-deny` + `cargo-audit` in CI; Trivy container scan; OpenSSF Scorecard | Mitigated (continuous) |
| E5 | Admin API mutates server state (ACL/cert/reload/drain) without authorization | Every state-changing management route (`/api/acl/*`, `/api/cert/*`, `/api/crl/*`, `/api/reload`, `/api/drain`, `/api/clients/{cn}/disconnect`, `/api/packages/*`) is bearer-token gated (constant-time compare) before the handler executes; there is no unauthenticated write path. Operators should bind the admin/metrics listener to a private interface in addition to the token | Mitigated |

## Residual Risks

| Risk | Severity | Description | Recommended Action |
|------|----------|-------------|-------------------|
| I1 | Medium | Unauthenticated `/metrics` endpoint discloses **deployment topology**: `rustgate_sessions_active` (live client count), per-CN `identity_cn`-labeled counters (which identities are connected, their traffic volume), and federation peer-labeled gauges (peer fan-out, queue depth, latency). An attacker scraping this learns identity counts and the federation graph without any credential. Ties to **SEC-20** | Firewall the metrics port; bind to localhost or a private interface. When the same listener also serves `/api/*`, keep the management bearer token set so only `/metrics` is open. Consider disabling per-CN `identity_cn` labels in high-sensitivity deployments |
| S3 | Medium | Plaintext listeners accept unauthenticated traffic | Only enable on trusted networks; document security implications |
| T3 | Low | NATS connection may be unencrypted | Enable NATS TLS in production (`--nats-tls-*` flags) |
| D8 | Medium | Per-IP rate limiting uses raw TCP peer address; behind NAT/LB all clients share one IP and can starve each other, while attackers with multiple IPs bypass limits entirely | Use client-IP-preserving load balancers (DSR, IP passthrough); set per-IP limits above expected NAT fan-out; global handshake concurrency limit (`--max-concurrent-handshakes`) still applies regardless of IP |
| T4/T5 | Low | On-disk config files could be tampered | Use read-only filesystem; External Secrets Operator in K8s |

## Relevant Documentation

- [Security Posture](security-posture.md) — NIST 800-53 control mapping
- [TLS Certificates](tls-certificates.md) — certificate requirements and management
- [FIPS 140-3](fips.md) — FIPS crypto provider setup
- [Deployment](deployment.md) — container hardening and network policies
- [SECURITY.md](../SECURITY.md) — vulnerability reporting policy
