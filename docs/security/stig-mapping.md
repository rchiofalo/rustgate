# STIG Compliance Mapping

This document maps the [Defense Information Systems Agency (DISA) Security Technical
Implementation Guide (STIG)](https://public.cyber.mil/stigs/) controls that apply to
rustgate to the configuration knobs, code paths, and CI artifacts that satisfy them.

The mapping is scoped to the controls that actually apply to a single-binary,
unprivileged, headless TLS service running inside a Linux container. STIGs
authored for desktop operating systems (smart-card readers, screen savers,
banner displays for interactive sessions) are not in scope and are explicitly
called out as **N/A** below so an auditor reviewing this document does not have
to re-derive that conclusion.

The reference STIGs consulted are:

- DISA Application Security and Development STIG (V6R1)
- DISA RHEL 8 STIG (V2R3) — applies to the runtime host and container
- DISA Container Image and Deployment Guide v2r0
- DISA TLS STIG (DRAFT) — informational

## How to Read This Document

Each row maps:

- **STIG-ID** — the canonical DISA control identifier.
- **Requirement** — a one-line summary of the control text.
- **rustgate Implementation** — the code path, configuration flag, or CI
  artifact that satisfies the requirement. Always includes a file path or a
  CLI flag so an auditor can verify in-tree.
- **Verification** — how an auditor can verify the control is in effect on a
  running deployment.

## Application Security and Development (ASD)

| STIG-ID | Requirement | rustgate Implementation | Verification |
|---|---|---|---|
| APSC-DV-000460 | The application must use FIPS-validated cryptography. | `--features fips` selects the `aws-lc-rs` FIPS 140-3 provider. `--fips-required` aborts startup if the provider is not active. See `docs/fips.md`. | `rustgate --version --fips-required` exits non-zero when FIPS is not active. |
| APSC-DV-000470 | Cryptographic modules must be NIST-validated. | `--features fips` builds the AWS-LC FIPS module pinned in `Cargo.lock` (`aws-lc-fips-sys`). Its NIST CMVP status is tracked in [fips.md](../fips.md#module-version-and-certification-status); confirm the module version holds a certificate before claiming this control. | Start with `--fips-required` (startup fails unless FIPS mode is active), then match the `aws-lc-fips-sys` version in `Cargo.lock` against the CMVP certificate. |
| APSC-DV-001740 | The application must use multi-factor authentication for privileged accounts. | mTLS is mandatory on every primary listener (`--cert`, `--key`, `--ca`). The CA-signed client cert is the second factor (the first is the network path / VPN). Enrollment additionally requires HTTP Basic auth. | `openssl s_client` without a client cert is rejected; check audit log `client.tls_error`. |
| APSC-DV-001620 | The application must enforce role-based access control. | `rustgate-authz` Cedar engine and `rustgate-router` `GroupAclPolicy`. See `docs/authorization.md`. | Submit a CoT message from a CN whose group is denied; observe `authz.denied` audit event. |
| APSC-DV-001480 | The application must encrypt all data in transit. | TLS 1.2+ enforced via `--tls-min-version`. Federation, NATS, HTTP egress, and WebSocket all use TLS by default. | `nmap --script ssl-enum-ciphers -p 4433 <host>` confirms minimum protocol. |
| APSC-DV-001490 | The application must encrypt sensitive data at rest. | Audit log archive (`rustgate-archive::audit_chain`), store-and-forward queue, and HTTP DLQ all use ChaCha20-Poly1305 via `rustgate-core::encrypted::EncryptedWriter`. See `crates/rustgate-core/src/encrypted.rs`. | Inspect the on-disk archive — header magic `RGENC1\0\0` indicates an encrypted file. |
| APSC-DV-002030 | The application must invalidate session identifiers upon logout. | TLS sessions are stateless; CRL revocation triggers re-handshake. SPIFFE SVID rotation reloads atomically. | Revoke a client cert, refresh CRL, observe `client.tls_error` for that CN's next handshake. |
| APSC-DV-001580 | The application must implement security functions as separate modules. | Workspace splits authorization (`rustgate-authz`), routing (`rustgate-router`), enrollment (`rustgate-enrollment`), federation (`rustgate-federation`) into independent crates. | `cargo metadata --no-deps` confirms 39 separate crates. |
| APSC-DV-002470 | The application must require user identification before allowing access. | Connection without a verified mTLS chain is rejected before any application code runs. The CN is the user identifier. | Audit log `client.connected` records the CN of every accepted connection. |
| APSC-DV-001870 | The application must protect against buffer overflows. | `unsafe_code = "forbid"` workspace-wide. All code is safe Rust. `MAX_FRAME_SIZE = 16 MiB` caps framing inputs. | `cargo geiger` reports zero `unsafe` blocks across the workspace. |
| APSC-DV-002240 | The application must terminate idle sessions. | Connection-level read timeout `READ_TIMEOUT = 5min`, write timeout `WRITE_TIMEOUT = 30s`. Set in `rustgate-core::constants`. | `tcpdump` on a live deployment confirms FIN sent after 5 minutes of read silence. |
| APSC-DV-002250 | The application must terminate sessions after inactivity period. | See APSC-DV-002240. | Same as above. |
| APSC-DV-002330 | The application must validate certificates before use. | TLS handshake validates the full chain via `webpki`/`rustls`. CRL is checked at handshake time when `--crl` is set. Subject DN and SAN are extracted via `rustgate-tls::extract`. | Submit an expired cert; observe `tls_handshake_failed` audit event. |
| APSC-DV-002770 | The application must not expose internal info in error messages. | Errors implement custom `Debug` that redacts secrets (see `rustgate-core::sanitize`). Audit events sanitize CR/LF to prevent log forging. | Submit a malformed cert containing a newline in the CN; observe sanitized output in audit log. |
| APSC-DV-002870 | The application must protect log records from unauthorized access. | Audit log uses hash-chained SHA-256 (`rustgate-core::audit_chain`); tamper attempts surface as `chain.discontinuity` events. | Modify a record; run `rustgate verify-audit <path>` and observe failure. |
| APSC-DV-002900 | The application must use cryptographic mechanisms to protect log integrity. | Hash-chained audit log; each record carries the SHA-256 of the previous record. See ADR-0014 (`docs/adr/0014-hash-chained-audit-log.md`). | `rustgate verify-audit` walks the chain and reports any break. |
| APSC-DV-003110 | The application must back up audit records on demand. | Operators copy the rotating audit log file (`--audit-log`). The hash chain provides tamper evidence; the encrypted-archive option (`--audit-log-key-file`) protects confidentiality at rest. | `cp` the audit-log directory; verify the chain on the copy. |
| APSC-DV-003245 | The application must remove old software components after upgrade. | Single static binary, no runtime plugin loading. Container images are rebuilt from scratch on every release. | `docker image inspect <tag> --format='{{.RootFS.Layers}}'` shows minimal layer count. |
| APSC-DV-003330 | The application must remove invalidated authentication credentials. | CRL revocation rejects revoked certs at handshake (`--crl`). Federation peer removal via `rustgate-server::federation_reloader`. | Revoke a cert, refresh CRL, observe `crl.reload_success` and subsequent `tls_handshake_failed` for that cert. |

## RHEL 8 STIG — Container Runtime

| STIG-ID | Requirement | rustgate Implementation | Verification |
|---|---|---|---|
| V-RHEL-08-010040 | Banner must display before logon. | **N/A** — rustgate is a headless service with no interactive logon path. | — |
| V-RHEL-08-010370 | TLS implementations must use TLS 1.2 or higher. | `--tls-min-version 1.2` is the default. `--tls-min-version 1.3` available. Earlier versions are not compiled in (rustls does not implement them). | `openssl s_client -tls1_1 -connect <host>:4433` is rejected. |
| V-RHEL-08-010460 | The system must use FIPS-validated SSH. | **N/A** — rustgate does not embed SSH; deployment uses standard Kubernetes / Docker channels. | — |
| V-RHEL-08-020330 | The system must lock accounts after 3 unsuccessful logon attempts. | **N/A for the service**. Per-IP rate limiters (`rustgate-resilience::conn_rate_limiter`) provide functional equivalent for connection floods. | Observe `security.rate_limited` audit events under load. |
| V-RHEL-08-040030 | The system must implement DoD-approved encryption. | When built with `--features fips`, `aws-lc-rs` restricts TLS to FIPS-approved suites (module certification status: [fips.md](../fips.md#module-version-and-certification-status)). Default build uses `ring` (non-FIPS but DoD-approved for non-classified). | See APSC-DV-000460. |
| V-RHEL-08-040160 | The system must enforce SSH client / server idle timeout. | **N/A** — no SSH. rustgate's own connection idle timeouts are described in APSC-DV-002240. | — |
| V-RHEL-08-040170 | The system must implement a host-based firewall. | **Operator responsibility** at the orchestration layer. The Helm chart's `NetworkPolicy` example restricts inbound traffic to listed namespaces (`helm/templates/networkpolicy.yaml`). Pod Security Standards `restricted` profile enforced. | `kubectl get networkpolicy -n rustgate` shows the active policy. |
| V-RHEL-08-040190 | The system must use a centralized log server. | OTel exporter (`--otel-endpoint`), structured JSON logs to stdout (collected by Fluentd / Vector). Audit events emitted on `target=audit`. | Inspect log shipper config; verify rustgate stdout is routed. |
| V-RHEL-08-040340 | DNS must be configured to a known good source. | **Operator responsibility** at the orchestration layer. Air-gap mode (`--air-gap`) refuses non-private endpoints regardless of DNS. | `kubectl get cm coredns -n kube-system` (operator-owned). |
| V-RHEL-08-040360 | The system must disable unauthenticated access to file systems. | The container runs as UID 10001 with `readOnlyRootFilesystem: true` enforced by the Pod Security Standards `restricted` profile (`helm/values.yaml`). No filesystem is exported. | `kubectl describe pod <name>` shows the security context. |
| V-RHEL-08-040380 | All ports, protocols, and services must be allowed by the PPSM. | All listeners are explicit CLI flags (`--bind`, `--websocket-bind`, `--metrics-bind`, etc). No service binds to a port without an explicit flag. | `rustgate --print-config` enumerates every active listener. |

## Container Image and Deployment

| STIG-ID | Requirement | rustgate Implementation | Verification |
|---|---|---|---|
| CTR-DI-000020 | Container images must be signed. | Container images signed with cosign (keyless via Sigstore OIDC) on every release; see `.github/workflows/release.yml`. | `cosign verify <image>` confirms the signature. |
| CTR-DI-000040 | Container images must include an SBOM. | Anchore syft generates SPDX SBOM; `cargo-cyclonedx` generates CycloneDX SBOM. Both are attached as release artifacts. See `.github/workflows/release.yml`. | `cosign download attestation --predicate-type spdxjson <image>` returns the SBOM. |
| CTR-DI-000050 | Container images must be scanned for vulnerabilities. | Trivy with `severity: CRITICAL,HIGH` and `exit-code: 1` gates every release; SARIF results uploaded to GitHub Security. | Open the GitHub Security tab → Code scanning alerts. |
| CTR-DI-000060 | Container base images must be approved. | Default base is the upstream `rust:1.95-alpine`; the `Dockerfile` carries a `TODO(operator)` block for swapping to Iron Bank `registry1.dso.mil/ironbank/redhat/ubi/ubi9-minimal:9.x` when an operator has Platform One credentials. | `docker image inspect <image>` reports the base. |
| CTR-DI-000070 | Container images must not run as root. | `USER 10001:10001` enforced in the `Dockerfile`; PSS `restricted` profile additionally enforces `runAsNonRoot: true`. | `docker run --rm <image> id` reports `uid=10001`. |
| CTR-DI-000080 | Container images must drop all unnecessary Linux capabilities. | Helm chart drops `ALL` capabilities by default. `securityContext.capabilities.drop: ["ALL"]`. | `kubectl describe pod <name>` shows the dropped capabilities. |
| CTR-DI-000090 | Container images must enable read-only root filesystem. | Helm chart sets `readOnlyRootFilesystem: true`. The `Dockerfile` tip recommends `--read-only --tmpfs /tmp` for raw `docker run`. | `kubectl describe pod <name>` shows the flag. |
| CTR-DI-000100 | Container images must not include SUID/SGID binaries. | `Dockerfile` runtime stage runs `find / -xdev -type f -perm /6000 -delete` before the `USER` switch. | `docker run --rm <image> find / -perm /6000 -type f` returns empty. |
| CTR-DI-000110 | Container images must not expose unnecessary ports. | Only the listeners enabled by CLI flags are bound. `EXPOSE` directives in the `Dockerfile` are documentation only. | `nmap <pod-ip>` after install confirms only configured ports are open. |
| CTR-DI-000120 | Container images must prohibit privilege escalation. | Helm chart sets `allowPrivilegeEscalation: false`. PSS `restricted` profile additionally enforces this. | `kubectl describe pod <name>` shows the flag. |
| CTR-DI-000130 | Container images must use a defined healthcheck. | `HEALTHCHECK` directive in the `Dockerfile` probes `/healthz` and falls back to a TCP probe on the primary listener. Helm chart uses `livenessProbe`, `readinessProbe`, and `startupProbe`. | `docker inspect <image>` shows the healthcheck. |

## TLS-Specific Controls

| STIG-ID | Requirement | rustgate Implementation | Verification |
|---|---|---|---|
| TLS-001 | TLS 1.2 must be the minimum protocol version. | `--tls-min-version 1.2` (default). | `openssl s_client -tls1_1` is rejected. |
| TLS-002 | TLS 1.0 and 1.1 must be disabled. | rustls does not compile in TLS 1.0/1.1. | Same as TLS-001. |
| TLS-003 | Strong ciphers (AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305) must be used. | rustls default ciphersuites; further restricted under `--features fips`. | `nmap --script ssl-enum-ciphers` enumerates allowed suites. |
| TLS-004 | Server certificates must use SHA-256 or stronger digest. | rustls rejects SHA-1 certs. | `openssl x509 -in server.pem -noout -text` shows signature algorithm. |
| TLS-005 | DH key exchange must use ≥2048-bit primes; ECDHE preferred. | rustls only supports ECDHE; classical X25519 / P-256 / P-384 plus optional X25519MLKEM768 PQ hybrid via `--prefer-post-quantum`. | `Wireshark` capture shows the negotiated key exchange. |
| TLS-006 | Mutual TLS must be enabled for server-to-server. | Federation listener requires client certificate (`--federation-trust-store-dir`). | Connect a federation client without a cert; observe rejection. |
| TLS-007 | OCSP stapling or CRL must be configured. | `--ocsp-stapling` and `--client-ocsp` available. CRL via `--crl`. Air-gap mode (`--air-gap`) disables OCSP and falls back to CRL only. | Capture the TLS handshake; the OCSP staple appears in the `Certificate Status` extension when stapling is on. |
| TLS-008 | Session tickets must be rotated. | rustls regenerates session ticket keys at every cert reload (`--cert-reload-interval`). Sessions are not resumed across rotations. | Force a cert reload; previously issued tickets are invalidated. |

## CI / Build Provenance

| STIG-ID | Requirement | rustgate Implementation | Verification |
|---|---|---|---|
| ASD-CI-001 | The build pipeline must produce attested provenance. | `actions/attest-build-provenance@v4` runs on every release. SLSA L3 provenance attached as a cosign predicate. | `cosign verify-attestation --type slsaprovenance` confirms the attestation. |
| ASD-CI-002 | Build artifacts must be signed. | cosign keyless OIDC signs every container image; release binaries also signed (see `release-binary.yml`). | See APSC-DV-000460. |
| ASD-CI-003 | Build dependencies must be SBOM-tracked. | `cargo-cyclonedx` produces a CycloneDX SBOM; `anchore/sbom-action` produces an SPDX SBOM. Both attached to the release. | Download from the GitHub release page; validate with `cyclonedx validate` or `spdx-tools`. |
| ASD-CI-004 | The pipeline must enforce code review for every change. | GitHub branch protection on `main`; PR review required by CODEOWNERS. | GitHub UI → Settings → Branches. |
| ASD-CI-005 | The pipeline must run static analysis. | `cargo clippy` with `-D warnings`, `cargo deny check`, `cargo audit`. See `.github/workflows/ci.yml`. | Open any successful CI run and observe the clippy / deny / audit jobs. |
| ASD-CI-006 | The pipeline must run vulnerability scanning. | Trivy on every release. OpenSSF Scorecard runs weekly + on push. | GitHub Security tab. |

## Configuration Hardening

The following non-default flags are recommended for STIG-aligned deployments:

```bash
rustgate \
    --cert /etc/rustgate/server.pem \
    --key /etc/rustgate/server-key.pem \
    --ca /etc/rustgate/ca.pem \
    --crl /etc/rustgate/crl.pem \
    --tls-min-version 1.3 \
    --fips-required \
    --air-gap \
    --max-connections 1024 \
    --max-concurrent-handshakes 256 \
    --client-message-rate 1000 \
    --client-burst 100 \
    --replay-window 300 \
    --audit-log /var/log/rustgate/audit.jsonl \
    --audit-log-key-file /etc/rustgate/audit-key.json
```

The `--air-gap` flag is mandatory in a STIG-aligned air-gapped environment;
it refuses every external endpoint at startup and emits an
`audit::air_gap_violation` event for any operator-supplied URL that points
outside the private/loopback/link-local set.

## Out of Scope

- **STIG Benchmark XML / SCAP** — this document is the markdown form of the
  mapping. Producing a machine-checkable SCAP-format Benchmark is a separate
  deliverable and tracked under future work.
- **Operator-side deployment STIGs** — this document covers what rustgate
  itself does. The host OS, container runtime, network, and physical security
  STIGs are operator concerns.
- **STIG remediation for plaintext listeners** (`--tcp-bind`, `--udp-bind`) —
  these listeners are explicitly opt-in and documented as
  `S3 Partially mitigated` in `docs/threat-model.md`. STIG-aligned
  deployments must not enable them.

## Relevant Documentation

- [Security Posture](../security-posture.md) — NIST 800-53 control mapping.
- [Threat Model](../threat-model.md) — STRIDE methodology, mitigations, residual risks.
- [cATO Evidence Template](cato-evidence-template.md) — NIST 800-53 evidence inventory.
- [FIPS 140-3](../fips.md) — FIPS crypto provider setup.
- [TLS Certificates](../tls-certificates.md) — certificate requirements and management.
- [Configuration](../configuration.md) — every CLI flag and env var.
