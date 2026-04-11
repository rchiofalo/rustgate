# Security Posture

This document maps rustgate's existing security controls to NIST SP 800-53 (Rev. 5) control families. All controls listed here are implemented and enforced — this is not a roadmap.

## NIST 800-53 Control Mapping

### SC — System and Communications Protection

| Control | Implementation |
|---------|---------------|
| SC-8 Transmission Confidentiality | mTLS on all client and federation connections. TLS 1.2+ with certificate verification. |
| SC-12 Cryptographic Key Management | X.509 certificates for identity. PKCS#12 enrollment with CSR signing. CA-signed client and server certificates. |
| SC-13 Cryptographic Protection | Default: `ring` (rustls). Optional: FIPS 140-3 validated `aws-lc-rs` via `--features fips` and `--fips-required` flag. |
| SC-17 PKI Certificates | Certificate enrollment server with Subject DN enforcement — enrolled certificates carry the authenticated username. |
| SC-23 Session Authenticity | TLS session resumption disabled. Every connection performs a full handshake with CRL check. |

### IA — Identification and Authentication

| Control | Implementation |
|---------|---------------|
| IA-3 Device Identification | Client certificates provide identity: CN → callsign, OU → group membership, SHA-256 fingerprint. |
| IA-5 Authenticator Management | CRL-based revocation via `--crl`. Revoked certificates rejected at the TLS handshake before application layer. |

### AC — Access Control

| Control | Implementation |
|---------|---------------|
| AC-3 Access Enforcement | Group-based message routing derived from certificate OU fields. Clients only receive messages for their groups. |
| AC-4 Information Flow Enforcement | Federation loop detection with provenance tracking and configurable hop limits (`--federation-max-hops`). |
| AC-17 Remote Access | All remote access requires mutual TLS. Plaintext listeners (`--tcp-bind`, `--udp-bind`) are opt-in for trusted networks only. |

### AU — Audit and Accountability

| Control | Implementation |
|---------|---------------|
| AU-2 Event Logging | Structured `tracing` logs for connection lifecycle, authentication, routing decisions, and federation events. |
| AU-3 Content of Audit Records | CoT archival (`--archive-dir`) writes received events as structured JSONL with timestamps and client identity. |
| AU-14 Session Audit | Per-client message rate tracking via `--client-message-rate` and `--client-burst`. |

### SI — System and Information Integrity

| Control | Implementation |
|---------|---------------|
| SI-2 Flaw Remediation | `cargo-deny` checks advisories (RustSec) and `cargo-audit` runs in CI on every push. |
| SI-7 Software Integrity | Release binaries signed with [cosign](https://github.com/sigstore/cosign) (keyless OIDC). SLSA build provenance attestation via `actions/attest-build-provenance`. SHA-256 checksums for all release artifacts. |

### SA — System and Services Acquisition

| Control | Implementation |
|---------|---------------|
| SA-11 Developer Testing | 1400+ tests across 13 crates. `cargo-nextest` in CI. Feature-gated test suites for FIPS, post-quantum, NATS, federation, Cedar authz. |
| SA-12 Supply Chain Protection | SBOM (SPDX) generated for both source and container on every release. `cargo-deny` enforces license allowlist and dependency bans. All CI action versions pinned to full SHA hashes. |

### CM — Configuration Management

| Control | Implementation |
|---------|---------------|
| CM-6 Configuration Settings | `unsafe_code = "forbid"` workspace-wide. `clippy::panic = "deny"`, `clippy::unwrap_used = "deny"` in production code. All warnings are errors (`RUSTFLAGS = -Dwarnings`). |
| CM-7 Least Functionality | Single static binary. No runtime dependencies. Feature flags control which subsystems are compiled in. |

### Container Hardening

| Control | Implementation |
|---------|---------------|
| Non-root execution | Container runs as UID 10001 |
| Read-only filesystem | Recommended via `readOnlyRootFilesystem: true` in Helm chart (Pod Security Standards restricted profile) |
| Graceful shutdown | `STOPSIGNAL SIGTERM` with connection draining |
| Vulnerability scanning | Trivy (CRITICAL/HIGH) on container image at release, SARIF uploaded to GitHub Security tab |
| Health monitoring | `/health/live` (liveness), `/health/ready` (readiness), and `/health/startup` (startup) endpoints |

### CP — Contingency Planning

| Control | Implementation |
|---------|---------------|
| CP-2 Contingency Plan | Subsystem failures degrade gracefully — see [graceful-degradation.md](graceful-degradation.md). NATS disconnect: local routing continues. Federation peer failure: circuit breaker skips unhealthy peers. |
| CP-9 System Backup | Position cache is ephemeral (in-memory). Federation peer state persists to `--federation-store-path` (JSON file). Operators should back up TLS certificates, CRL files, and federation peers configuration. |
| CP-10 System Recovery | Automatic recovery for NATS (reconnect) and federation (circuit breaker half-open probe). Certificate and key issues require restart after fix. |

### IR — Incident Response

| Control | Implementation |
|---------|---------------|
| IR-4 Incident Handling | Structured JSON logs with client identity, peer addresses, and timestamps. Audit events for TLS failures, connection rejections, circuit breaker trips, and federation errors. |
| IR-5 Incident Monitoring | Prometheus metrics for real-time alerting: `connections_rejected`, `accept_errors`, `federation_circuit_breaker_trips`. OpenTelemetry trace export for distributed investigation. |
| IR-6 Incident Reporting | CoT archival (`--archive-dir`) produces JSONL records with full message provenance for forensic analysis. |

### RA — Risk Assessment

| Control | Implementation |
|---------|---------------|
| RA-3 Risk Assessment | STRIDE-based threat model documented in [threat-model.md](threat-model.md). Covers all four transport paths, trust boundaries, and residual risks. |
| RA-5 Vulnerability Monitoring | `cargo-deny` (RustSec advisories), `cargo-audit`, Trivy container scanning, OpenSSF Scorecard (weekly). Dependabot alerts enabled on the repository. |

### CA — Security Assessment

| Control | Implementation |
|---------|---------------|
| CA-2 Control Assessments | CI pipeline runs 12 jobs on every push: commit-lint, lint, clippy, feature powerset, tests (1400+), coverage, FIPS, post-quantum, dependency-review, audit, Helm lint, Docker build. |
| CA-7 Continuous Monitoring | OpenSSF Scorecard runs weekly and on push to main. Dependabot monitors dependency vulnerabilities continuously. |
| CA-8 Penetration Testing | Fuzz testing via `cargo-fuzz` targets for CoT parsing, XML stream codec, and TAK frame codec. |

## Automated Security Checks

| Check | Frequency | Tool |
|-------|-----------|------|
| Dependency advisories | Every push | `cargo-deny`, `cargo-audit` |
| License compliance | Every push | `cargo-deny` (allowlist in `deny.toml`) |
| Unused dependencies | Every push | `cargo-machete` |
| Container CVE scan | Every release | Trivy |
| Supply chain score | Weekly + push to main | OpenSSF Scorecard |
| Binary signing | Every release | cosign (keyless OIDC) |
| Build provenance | Every release | SLSA (attest-build-provenance) |
| SBOM generation | Every release | Anchore syft (SPDX) |

## Relevant Documentation

- [Threat Model](threat-model.md) — STRIDE-based threat analysis
- [Graceful Degradation](graceful-degradation.md) — Subsystem failure behavior and recovery
- [Post-Quantum Roadmap](post-quantum.md) — PQ TLS migration plan
- [FIPS 140-3](fips.md) — FIPS crypto provider setup and limitations
- [TLS Certificates](tls-certificates.md) — Certificate requirements and management
- [SECURITY.md](../SECURITY.md) — Vulnerability reporting policy
