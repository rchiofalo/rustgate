# cATO Evidence Template

This document is a fill-in-the-blanks evidence inventory for a [Continuous
Authority To Operate (cATO)](https://dodcio.defense.gov/Portals/0/Documents/Library/MemoContinuousATO.pdf)
package. It maps the [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
controls that apply to a tactical mTLS message router to the rustgate-emitted
artifacts that satisfy them: which audit events fire, which CI artifact
contains the evidence, and where an auditor should look on a running
deployment.

A cATO package additionally requires (a) a system security plan, (b) a POA&M
(plan of action and milestones), and (c) a continuous monitoring strategy.
Those are operator-owned documents; this file provides the input data for
them.

## How to Read This Document

Each row maps:

- **Control** — the NIST 800-53 control identifier and short name.
- **Evidence** — the rustgate code path, audit event, metric, or document
  that demonstrates the control is operating.
- **Artifact** — where to retrieve the evidence (file path, CI artifact name,
  GitHub release asset, audit-log query).
- **Cadence** — how often fresh evidence is produced (continuous, daily,
  per-release).

For each control marked **Operator-supplied**, the operator must produce the
evidence themselves; rustgate does not generate it directly.

## AC — Access Control

| Control | Evidence | Artifact | Cadence |
|---|---|---|---|
| AC-2 Account Management | Connected client list available via `GET /api/clients` (admin API). Audit events `client.connected` / `client.disconnected` record every account-equivalent action. | `audit::client_connected`, `audit::client_disconnected`; `crates/rustgate-admin/src/management_api.rs`. | Continuous |
| AC-3 Access Enforcement | Group-based ACL (`rustgate-router::GroupAclPolicy`) enforced before message delivery. Cedar policy engine for ABAC. Audit event `authz.denied` records every rejection. | `audit::authz_denied` events in `--audit-log`; CLI `--authz-policy-file`, `--acl-file`. | Continuous |
| AC-4 Information Flow Enforcement | Federation provenance tracking with hop counts and loop detection (`rustgate-federation::provenance`). `--federation-max-hops` caps. CJADC2 routing decisions logged. | `audit::mesh_loop_detected`, `audit::mesh_ttl_expired`, `audit::mesh_no_route_to_destination`. | Continuous |
| AC-5 Separation of Duties | Workspace splits authorization, routing, enrollment, and federation across independent crates. CA signing and message routing run as separate processes when the enrollment server is bound to a separate port. | `crates/rustgate-authz/`, `crates/rustgate-router/`, `crates/rustgate-enrollment/`. | Per-release |
| AC-6 Least Privilege | Container runs as UID 10001 with `readOnlyRootFilesystem: true`, all Linux capabilities dropped, `allowPrivilegeEscalation: false`. | `Dockerfile`, `helm/values.yaml` `securityContext` block. | Per-release |
| AC-7 Unsuccessful Logon Attempts | Per-IP rate limiters (`rustgate-resilience::conn_rate_limiter`) trip after configurable threshold. | `audit::security_rate_limited` events. | Continuous |
| AC-12 Session Termination | TLS handshake idle timeout `HANDSHAKE_TIMEOUT = 10s`; read timeout `READ_TIMEOUT = 5min`; write timeout `WRITE_TIMEOUT = 30s`. | `rustgate_core::constants`. | Continuous |
| AC-17 Remote Access | All remote access uses mTLS. Plaintext listeners (`--tcp-bind`, `--udp-bind`) are opt-in and documented as trusted-network-only. | `audit::client_connected` (records peer address, CN, fingerprint). | Continuous |
| AC-18 Wireless Access | **Operator-supplied** — wireless link encryption is the network operator's concern. rustgate enforces application-layer mTLS regardless of L2 medium. | — | — |

## AU — Audit and Accountability

| Control | Evidence | Artifact | Cadence |
|---|---|---|---|
| AU-2 Event Logging | rustgate emits 90+ structured audit events spanning connection lifecycle, authorization decisions, federation, enrollment, certificate rotation, store-and-forward, mesh routing, classification handling, hardware identity, JWKS rotation, MQTT will, NATS DLQ, and tenant isolation. Full enumeration in `crates/rustgate-core/src/audit.rs`. | `--audit-log <path>` produces an append-only JSONL file. | Continuous |
| AU-3 Content of Audit Records | Each record carries `event_type`, `action`, `result`, the actor (CN, peer ID, peer address), the resource (group, message UID, target name), and the SHA-256 of the previous record (hash chain). | `crates/rustgate-core/src/audit.rs` macro `audit!`; sample records in `docs/observability.md`. | Continuous |
| AU-4 Audit Log Storage Capacity | `--audit-log` writer rotates by size (`--audit-log-max-bytes`) and by age (`--audit-log-max-age-secs`). Encrypted segments are sealed with a terminator chunk to prevent silent truncation. | `rustgate-archive::audit_chain`; `--audit-log-rotate-interval`. | Continuous |
| AU-5 Response to Audit Logging Process Failures | A failed audit write does not crash the server (best-effort); the writer task emits `tracing::error!` and records the failure as an audit event in the next successful flush. | `audit::chain_anchor_persist_failed`. | Continuous |
| AU-6 Audit Record Review | OTel exporter (`--otel-endpoint`) streams audit events to a SIEM. The hash chain (`rustgate verify-audit`) confirms the records have not been tampered with. | `rustgate verify-audit <path>` exits 0 on success, non-zero on chain break. | Daily / per-incident |
| AU-7 Audit Reduction and Report Generation | Audit events are JSON; tooling (`jq`, Splunk, Loki) consumes them directly. The `target=audit` tracing filter separates audit from operational logs. | Operator-supplied dashboards. | Operator-defined |
| AU-8 Time Stamps | Every audit record carries `timestamp` derived from `SystemTime::now()`. | `audit!` macro; sample records in `docs/observability.md`. | Continuous |
| AU-9 Protection of Audit Information | Hash-chained log (SHA-256 chain) makes tampering detectable. Optional ChaCha20-Poly1305 encryption (`--audit-log-key-file`) protects confidentiality at rest. | ADR-0014 (`docs/adr/0014-hash-chained-audit-log.md`); ADR-0015 (`docs/adr/0015-encrypted-archives-chacha20-poly1305.md`). | Continuous |
| AU-12 Audit Generation | Audit events emitted at `INFO` level with `target = "audit"` so they can be routed to a separate sink via tracing-subscriber filters. | `crates/rustgate-core/src/audit.rs`. | Continuous |
| AU-14 Session Audit | Per-client message rate tracking via `--client-message-rate`, `--client-burst`. Per-CN store-and-forward queue depth. | `audit::store_forward_dropped`; `crates/rustgate-router/src/throttle.rs`. | Continuous |

## CA — Assessment, Authorization, and Monitoring

| Control | Evidence | Artifact | Cadence |
|---|---|---|---|
| CA-2 Control Assessments | CI pipeline runs 11 jobs on every push: commit-lint, lint, clippy, feature powerset (`cargo hack`), tests (`cargo nextest`, 1400+), coverage (`cargo tarpaulin`), FIPS, post-quantum, audit (`cargo deny` + `cargo audit`), helm, docker. | `.github/workflows/ci.yml`. | Per-push |
| CA-7 Continuous Monitoring | OpenSSF Scorecard runs weekly + on push to main. Dependabot monitors dependency vulnerabilities continuously. | `.github/workflows/scorecard.yml`. | Weekly |
| CA-8 Penetration Testing | Fuzz testing via `cargo-fuzz` for CoT parsing, XML stream codec, TAK frame codec, MAVLink v1/v2, MQTT, ASTERIX, NFFI, OGC SensorThings observation, STANAG 4586, CoT obligation apply. Weekly fuzz job in CI. | `fuzz/`; `.github/workflows/weekly-fuzz.yml`. | Weekly |

## CM — Configuration Management

| Control | Evidence | Artifact | Cadence |
|---|---|---|---|
| CM-2 Baseline Configuration | The `Cli` struct in `crates/rustgate-server/src/cli.rs` is the authoritative configuration baseline. Every flag is documented inline. `rustgate --print-config` dumps the merged config. | `rustgate --print-config`. | Continuous |
| CM-3 Configuration Change Control | ACL hot-reload via SIGHUP and `POST /api/config/reload`. Authz reload (`audit::authz_reload_success`). Federation peer reload (`audit::federation_config_changed`). | `audit::authz_reload_success`, `audit::federation_config_changed`. | Continuous |
| CM-4 Impact Analyses | PRs require review per CODEOWNERS. CHANGELOG entries describe blast radius. Conventional commits (`feat`, `fix`, `refactor`, `breaking`) classify changes. | `CONTRIBUTING.md`; `CHANGELOG.md`. | Per-PR |
| CM-5 Access Restrictions for Change | GitHub branch protection on `main`. CODEOWNERS gates security-sensitive paths. | GitHub repo settings; `.github/CODEOWNERS`. | Continuous |
| CM-6 Configuration Settings | `unsafe_code = "forbid"` workspace-wide. `clippy::panic = "deny"`, `clippy::unwrap_used = "deny"`. `RUSTFLAGS = -Dwarnings`. | Workspace `Cargo.toml`; `clippy.toml`. | Per-build |
| CM-7 Least Functionality | Single static binary, no runtime plugin loading. Feature flags control which subsystems are compiled in. `--air-gap` refuses every external endpoint. | `crates/rustgate-server/Cargo.toml` features. | Continuous |
| CM-8 System Component Inventory | SBOM (SPDX + CycloneDX) generated on every release. Workspace dependency inheritance keeps the inventory in `Cargo.toml`. | `rustgate.cdx.json` / `rustgate.cdx.xml` release assets; `sbom-container-*.spdx.json`. | Per-release |

## CP — Contingency Planning

| Control | Evidence | Artifact | Cadence |
|---|---|---|---|
| CP-2 Contingency Plan | Subsystem failures degrade gracefully — see `docs/graceful-degradation.md`. NATS disconnect → local routing continues. Federation peer failure → circuit breaker skips unhealthy peer. | `docs/graceful-degradation.md`. | Per-release |
| CP-9 System Backup | Position cache is ephemeral. Federation peer state persists to `--federation-store-path`. Audit log archive is operator-rotatable. | Operator-supplied backup procedure. | Operator-defined |
| CP-10 System Recovery | Automatic recovery for NATS (reconnect with backoff), federation (circuit breaker half-open probe), HTTP egress (DLQ + circuit recovery). | `audit::http_circuit_recovered`, `audit::federation_circuit_recovered`. | Continuous |

## IA — Identification and Authentication

| Control | Evidence | Artifact | Cadence |
|---|---|---|---|
| IA-2 Identification (Organizational Users) | mTLS with CA-signed client certificates. CN is the user identifier, OU fields are the group memberships. | `audit::client_connected`. | Continuous |
| IA-3 Device Identification and Authentication | Client certificates provide identity: CN → callsign, OU → group membership, SHA-256 fingerprint. SPIFFE workload identity via `--spiffe`. | `audit::spiffe_svid_refresh_success`. | Continuous |
| IA-4 Identifier Management | Enrollment server (`--enrollment-bind`) issues client certs with operator-supplied CN. Subject DN enforcement: CN set from authenticated username, CSR subject is overridden. | `audit::enrollment_certificate_issued`, `audit::enrollment_certificate_revoked`. | Per-issuance |
| IA-5 Authenticator Management | Cert rotation via `--cert-reload-interval` (atomic swap, zero downtime). CRL refresh via `audit::crl_reload_success`. SPIFFE refresh task. JWKS rotation (`audit::jwks_key_added` / `audit::jwks_key_removed`). | Audit events listed; `crates/rustgate-tls/src/cert_reloader.rs`. | Continuous |
| IA-7 Cryptographic Module Authentication | When `--features fips`, `aws-lc-rs` uses the AWS-LC FIPS cryptographic module. Module version and NIST CMVP status: [fips.md](../fips.md#module-version-and-certification-status). | `--fips-required` flag aborts startup if not active. | Per-build |
| IA-8 Identification (Non-Organizational Users) | Plaintext listeners assign a fixed synthetic identity (`--plaintext-cn`); group isolation limits blast radius. Anonymous-identity sessions are explicitly tagged in audit. | `audit::client_connected` with `cn = "<plaintext-cn>"`. | Continuous |

## IR — Incident Response

| Control | Evidence | Artifact | Cadence |
|---|---|---|---|
| IR-4 Incident Handling | Structured JSON audit records with full provenance per message. Hash chain detects tampering. | `--audit-log`; `rustgate verify-audit`. | Continuous |
| IR-5 Incident Monitoring | Prometheus metrics for real-time alerting: `rustgate_connections_rejected_total`, `rustgate_accept_errors_total`, `rustgate_federation_circuit_breaker_trips_total`. OTel trace export. | `--metrics-bind` endpoint; `--otel-endpoint`. | Continuous |
| IR-6 Incident Reporting | CoT archival (`--archive-dir`) produces JSONL records with full message provenance for forensic analysis. Audit log records the operator-side actions. | Per-tenant archive subdirectories under `--archive-dir`. | Continuous |

## RA — Risk Assessment

| Control | Evidence | Artifact | Cadence |
|---|---|---|---|
| RA-3 Risk Assessment | STRIDE-based threat model in `docs/threat-model.md` covers all four transport paths, trust boundaries, and residual risks. | `docs/threat-model.md`. | Per-release (refresh) |
| RA-5 Vulnerability Monitoring | `cargo-deny` (RustSec advisories), `cargo-audit`, Trivy container scan, OpenSSF Scorecard. Dependabot enabled. | `.github/workflows/ci.yml` audit job; weekly Scorecard. | Continuous |

## SA — System and Services Acquisition

| Control | Evidence | Artifact | Cadence |
|---|---|---|---|
| SA-11 Developer Testing and Evaluation | 1400+ tests across the workspace; `cargo nextest` in CI. Feature-gated suites for FIPS, post-quantum, NATS, federation, Cedar authz. | `.github/workflows/ci.yml` test job. | Per-push |
| SA-12 Supply Chain Risk Management | SBOM (SPDX + CycloneDX) generated for both source and container on every release. `cargo-deny` enforces license allowlist and dependency bans. All CI action versions pinned to full SHA hashes. | `deny.toml`; `.github/workflows/release.yml`. | Per-release |

## SC — System and Communications Protection

| Control | Evidence | Artifact | Cadence |
|---|---|---|---|
| SC-7 Boundary Protection | Air-gap mode (`--air-gap`) refuses non-private endpoints at startup; emits `audit::air_gap_violation` for any rejected URL. NetworkPolicy in the Helm chart restricts ingress to listed namespaces. | `audit::air_gap_violation`. | Continuous |
| SC-8 Transmission Confidentiality | mTLS on all client and federation connections; TLS 1.2+ with certificate verification. | `audit::client_connected`, `audit::tls_handshake_failed`. | Continuous |
| SC-12 Cryptographic Key Establishment | X.509 certificates for identity. PKCS#12 enrollment with CSR signing. CA-signed client and server certs. | `audit::enrollment_certificate_issued`. | Per-issuance |
| SC-13 Cryptographic Protection | Default: AWS-LC via `aws-lc-rs` (rustls), with hybrid post-quantum X25519MLKEM768 preferred. Optional: the AWS-LC FIPS module via `--features fips`; certification status in [fips.md](../fips.md#module-version-and-certification-status). | `--fips-required` flag; ADR-0009. | Per-build |
| SC-17 PKI Certificates | Certificate enrollment server with Subject DN enforcement — enrolled certs carry the authenticated username. | `audit::enrollment_certificate_issued`, `audit::enrollment_sign_failed`. | Per-issuance |
| SC-23 Session Authenticity | TLS session resumption disabled. Every connection performs a full handshake with CRL check. | `tls_handshake_failed` audit events count failed handshakes. | Continuous |
| SC-28 Protection of Information at Rest | ChaCha20-Poly1305 AEAD on audit-log archives, store-and-forward queues, and HTTP DLQ files. | `crates/rustgate-core/src/encrypted.rs`. | Continuous |

## SI — System and Information Integrity

| Control | Evidence | Artifact | Cadence |
|---|---|---|---|
| SI-2 Flaw Remediation | `cargo-deny` checks RustSec advisories and `cargo-audit` runs in CI on every push. Dependabot opens PRs for available updates. | CI audit job; Dependabot PRs. | Per-push |
| SI-3 Malicious Code Protection | All code is safe Rust (`unsafe_code = "forbid"`). Container image scanned by Trivy on every release. | Trivy SARIF in GitHub Security. | Per-release |
| SI-4 System Monitoring | Prometheus metrics exposed via `--metrics-bind`. OTel trace export via `--otel-endpoint`. | Operator-supplied dashboards. | Continuous |
| SI-7 Software, Firmware, and Information Integrity | Release binaries signed with cosign keyless OIDC. SLSA L3 build provenance attestation. SHA-256 checksums for all release artifacts. | `cosign verify-attestation --type slsaprovenance <image>`. | Per-release |
| SI-10 Information Input Validation | Strict deserialization with `deny_unknown_fields`. NFC-normalized identifier inputs. Constant-time credential comparison via `subtle`. | `crates/rustgate-core/src/sanitize.rs`. | Continuous |
| SI-12 Information Management and Retention | Audit log rotation (`--audit-log-max-bytes`, `--audit-log-max-age-secs`). Per-tenant archive directories. Encrypted-archive sealing prevents silent truncation. | `audit::store_forward_key_rotated`; ADR-0015. | Continuous |

## Audit Event Inventory

The following table enumerates every audit event the running binary can emit.
This is the canonical input for AU-2 / AU-3 evidence; an auditor reviewing the
`--audit-log` output knows exactly which events to expect and what actor /
result fields each carries.

| Event Type | Actor | Resource | Action | Result Vocabulary |
|---|---|---|---|---|
| `client.connected` | CN, peer addr, fingerprint, session ID | — | `connect` | `success` |
| `client.disconnected` | CN, session ID | — | `disconnect` | `success` |
| `client.rejected` | peer addr | reason | `connect` | `rejected` |
| `client.tls_error` | peer addr | error | `tls_handshake` | `failure` |
| `client.negotiation` | CN, protocol | — | `negotiate` | `success` / `failure` |
| `federation.connected` | peer ID, peer CN | direction | `connect` | `success` |
| `federation.disconnected` | peer ID | reason | `disconnect` | — |
| `federation.circuit_tripped` | peer ID | trip count | `circuit_breaker` | `open` |
| `federation.circuit_recovered` | peer ID | — | `circuit_breaker` | `closed` |
| `federation.connect_failed` | peer ID | error | `connect` | `failure` |
| `federation.peer_rejected` | remote addr | reason | `connect` | `rejected` |
| `federation.group_claim_rejected` | peer CN, origin CN | claimed groups | `claim_groups` | `rejected` |
| `federation.event_received` | RPC, peer CN | — | `receive` | `success` |
| `federation.event_rejected` | RPC, peer CN | reason | `receive` | `rejected` |
| `enrollment.signed` | username, client UID | — | `sign_csr` | `success` |
| `enrollment.sign_failed` | username, client UID | error | `sign_csr` | `failure` |
| `enrollment.auth_failed` | peer addr | — | `authenticate` | `failure` |
| `enrollment.certificate_issued` | username, client UID, serial | — | `issue` | `success` |
| `enrollment.certificate_revoked` | serial, revoked_by | reason | `revoke` | `success` |
| `crl.reload_success` | source | — | `reload` | `success` |
| `crl.reload_failed` | source | error | `reload` | `failure` |
| `tls_handshake_failed` | peer addr | reason, stage | `tls_handshake` | `failure` |
| `cert_rotation_success` | cert path, new serial | — | `rotate` | `success` |
| `cert_rotation_failed` | cert path | error | `rotate` | `failure` |
| `spiffe.svid_refresh_success` | SPIFFE ID, trust domain, expiry | — | `refresh_svid` | `success` |
| `spiffe.svid_refresh_failure` | error | — | `refresh_svid` | `failure` |
| `authz.denied` | (resource), subject | reason | `evaluate` | `denied` |
| `authz.classified_delivery` | source CN, dest CN | classification | `deliver` | `success` |
| `authz.obligation_failed` | sink, obligation | reason | `apply_obligation` | `failure` |
| `authz.reload_success` | path, policy ID, rule count | — | `reload` | `success` |
| `authz.reload_failed` | path, stage | error | `reload` | `failure` |
| `authz.reload_rollback` | reason | previous policy ID | `reload` | `rollback` |
| `chain.discontinuity` | record offset | hash mismatch | `verify` | `failure` |
| `chain.anchor_persisted` | audit path, tip | — | `persist_anchor` | `success` |
| `chain.anchor_persist_failed` | audit path | error | `persist_anchor` | `failure` |
| `server_started` | bind, version | — | `start` | `success` |
| `air_gap.violation` | subsystem, endpoint | reason | `load_external_endpoint` | `rejected` |
| `egress.obligation_applied` | sink, obligation type, recipient class | — | `apply_obligation` | `success` |
| `http.publish_failed` | target, status | error | `publish` | `failure` |
| `http.circuit_tripped` | target | — | `circuit_breaker` | `open` |
| `http.circuit_recovered` | target | — | `circuit_breaker` | `closed` |
| `verifier_rebuild_failed` | error | — | `rebuild` | `failure` |
| `store_forward.dropped` | CN | reason | `store` | `dropped` |
| `store_forward.key_rotated` | path, depth | reason | `rotate_key` | `success` |
| `store_forward.drain_panic` | session hash | error | `drain` | `panic` |
| `mavlink.heartbeat_received` | system ID, component ID | — | `receive` | `success` |
| `mqtt.will_published` | CN, topic, group, retain | — | `publish_will` | `success` |
| `nats.poison_message_dlq` | subject, msg ID | reason, attempts | `dlq` | `dead_lettered` |
| `archive.key_rotation_due` | KID, days remaining | — | `key_rotation` | `pending` |
| `admin.drain_triggered` | source | — | `drain` | `triggered` |
| `mgmt_api.accessed` | endpoint, identity | — | `access` | `success` |
| `client.force_disconnected` | CN, by_operator, sessions closed | — | `disconnect` | `forced` |
| `hw_identity.loaded` | backend | — | `load_hw_identity` | `success` |
| `hw_identity.unavailable` | backend | reason | `load_hw_identity` | `failure` |
| `hw_identity.sign_failed` | backend | reason | `sign` | `failure` |
| `jwks.refresh_success` | URL, key count | — | `refresh` | `success` |
| `jwks.refresh_failed` | URL | reason | `refresh` | `failure` |
| `jwks.key_added` | URL, KID, alg | — | `add_key` | `success` |
| `jwks.key_removed` | URL, KID | — | `remove_key` | `success` |
| `jwt.using_retiring_kid` | KID, retiring duration | — | `verify_jwt` | `degraded` |
| `message.delivered` | source CN, dest CN, msg UID | — | `deliver` | `success` |
| `message.dropped` | source CN, dest CN, msg UID | reason | `deliver` | `dropped` |
| `udp.multicast_joined` | group, interface | — | `join` | `success` |
| `udp.multicast_publish` | group, msg UID | — | `publish` | `success` |
| `federation.traceparent_invalid` | peer CN | reason | `parse_traceparent` | `failure` |
| `classification.denied` | source CN, dest CN | classification | `deliver` | `denied` |
| `classification.missing_marking` | source CN, msg UID, source protocol | — | `validate` | `rejected` |
| `mesh.route_added` | destination, next hop | metric | `update_route_table` | `added` |
| `mesh.route_removed` | destination | reason | `update_route_table` | `removed` |
| `mesh.route_updated` | destination, next hop | new metric | `update_route_table` | `updated` |
| `mesh.forwarded` | destination, next hop | hops | `forward` | `success` |
| `mesh.loop_detected` | destination | hops | `forward` | `dropped` |
| `mesh.ttl_expired` | destination | hops, max hops | `forward` | `dropped` |
| `mesh.no_route_to_destination` | destination | — | `forward` | `dropped` |
| `tenant.isolation_label_overflow` | metric | distinct tenants | `metric_label_emit` | `overflow_to_reserved_label` |
| `security.rate_limited` | peer, endpoint, limit | — | `rate_limit` | `triggered` |

## Auditor-Facing Quick Reference

To produce a continuous-monitoring report from a running deployment:

```bash
# Verify the audit-log chain is intact (AU-9, AU-12).
rustgate verify-audit /var/log/rustgate/audit.jsonl

# Emit the running configuration as auditable JSON (CM-2).
rustgate --print-config

# Cosign-verify the image's signature and SLSA provenance (SI-7).
cosign verify-attestation --type slsaprovenance ghcr.io/rchiofalo/rustgate@sha256:<digest>
cosign verify-attestation --type spdxjson      ghcr.io/rchiofalo/rustgate@sha256:<digest>

# Scrape the metrics endpoint for SI-4 telemetry. The auditor's
# allowed-IP list is enforced by the operator via NetworkPolicy.
curl https://<host>:9090/metrics | head -20

# Filter the audit log for high-severity events.
jq -c 'select(.event_type | test("denied|failed|rejected|violation"))' \
   /var/log/rustgate/audit.jsonl
```

## Out of Scope

- **System Security Plan (SSP)** — operator-owned. This document provides the
  rustgate-side inputs.
- **POA&M** — operator-owned. The "TODO(operator)" markers in `Dockerfile`
  and `zarf.yaml` enumerate the residual work that a deployment-specific
  POA&M should track (Iron Bank base swap, cosign keyset, Zarf publish
  target).
- **Continuous Monitoring Strategy** — operator-owned. The auditor-facing
  quick reference above is the rustgate-side input.

## Relevant Documentation

- [Security Posture](../security-posture.md) — NIST 800-53 control mapping (this is the long-form companion).
- [Threat Model](../threat-model.md) — STRIDE methodology, mitigations, residual risks.
- [STIG Mapping](stig-mapping.md) — DISA STIG control mapping.
- [Observability](../observability.md) — structured logging, metrics, distributed tracing.
- [FIPS 140-3](../fips.md) — FIPS crypto provider setup.
- [Configuration](../configuration.md) — every CLI flag and env var.
