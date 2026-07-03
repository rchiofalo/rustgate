# DoD Zero Trust Seven Pillars — Alignment Mapping

## What this document is

A customer-facing alignment mapping showing how rustgate's existing
capabilities relate to the DoD Zero Trust Architecture (DoD ZTA v2.0,
DISA/NSA, November 2022) Seven Pillars (User, Device, Application,
Data, Network, Automation, Visibility), what gaps exist, and the
GitHub issues tracking each gap. The ZTA 2.0 framework defines 152
activities across the seven pillars, with FY2027 as the DoD-wide
compliance mandate for all DoD components.

## Audience

- **Customer evaluators** running a procurement-stage capability
  matrix against rustgate.
- **Accreditation auditors** preparing an ATO / cATO package and
  needing a control-by-control feature-to-requirement crosswalk.
- **rustgate operators** deciding which compensating controls the
  hosting platform must supply (e.g., MFA front-ends, MDM, DLP).

## What this document does NOT claim

This is **informational only**. rustgate carries **no formal compliance
certification** against DoD ZTA, FedRAMP, FISMA, CMMC, or any other
framework. Formal accreditation requires an independent assessment
(third-party assessor or government-led C&A package) — this document
is not a substitute for that assessment.

The mapping below is honest about gaps. Capabilities marked
"implemented" can be traced to source in the repository; capabilities
marked "gap" are either planned (with a tracking issue) or explicitly
out-of-scope for this codebase (e.g., MDM integration, which is the
province of the hosting platform, not the message gateway).

## Related documents

- [`../SECURITY.md`](../SECURITY.md) — overall security posture and
  vulnerability disclosure process.
- [`threat-model.md`](threat-model.md) — STRIDE analysis and trust
  boundaries.
- [`authorization.md`](authorization.md) — group ACL + Cedar ABAC
  reference.
- [`concurrency-model.md`](concurrency-model.md) — locking, hot-reload,
  and shutdown invariants.
- [`runbooks/audit-chain-corruption.md`](runbooks/audit-chain-corruption.md)
  — operator response to a tampered or torn audit chain.
- [`security-posture.md`](security-posture.md) — companion NIST 800-53
  SC/IA/AC control inventory.
- [`federation.md`](federation.md) — peer authentication and forwarding
  controls.

---

## Summary at a glance

| Pillar | Coverage | Key gaps |
|---|---|---|
| 1. User | **High** — mTLS + SPIFFE + JWT ABAC claims | No MFA for human operators; no CAC/PIV integration |
| 2. Device | **Medium** — cert-bound identity, rotation, CRL/OCSP | No TPM/HSM attestation; no device-compliance score |
| 3. Application & Workload | **High** — FIPS crypto, constant-time auth, no unsafe code | No runtime app integrity beyond compile-time `unsafe_code = "forbid"` |
| 4. Data | **Medium** — mTLS in transit, ChaCha20-Poly1305 at rest, hash-chained audit | No classification tagging on `Metadata`; no DLP |
| 5. Network & Environment | **High** — group ACLs, Cedar ABAC, backpressure, rate limits | Micro-segmentation relies on the hosting platform (K8s NetworkPolicy, etc.) |
| 6. Automation & Orchestration | **Medium** — SIGHUP hot reload, circuit breakers, store-and-forward | No SOAR integration; no automated incident response |
| 7. Visibility & Analytics | **High** — Prometheus, OTLP, structured audit, CoT replay buffer | No W3C `traceparent` propagation across federation hops |

---

## Pillar 1 — User

DoD ZTA requires every user action to be authenticated to an identity
proofing authority, authorized against role-based and attribute-based
policies, and bound to cryptographic credentials under continuous
validation. The target state is fully phishing-resistant authentication
with risk-adaptive policy enforcement.

### Implemented

- **mTLS-based identity** (`rustgate-transport::listener`,
  `rustgate-transport::extract`) — every connection presents a CA-signed
  X.509 client certificate. Identity is derived from the certificate
  subject (CN) and cert-bound, not transport-bound: a stolen IP grants
  nothing, and a stolen session token does not exist because there are
  no bearer tokens in the client path.
- **Phishing-resistant credentials** — private keys never leave the
  client. The enrollment server (`rustgate-enrollment`) issues
  CA-signed certificates via CSR-only flows (PKCS#12 and EST/RFC 7030);
  the server never sees, stores, or transmits private key material.
- **SPIFFE/SPIRE integration** (`rustgate-transport::spiffe`, feature
  `spiffe`) — workload identities via the SPIFFE Workload API with
  automatic SVID rotation. Private keys held in `Zeroizing<String>`,
  rotated via atomic `CertReloader` swaps, wipe on drop.
- **Federation peer identity via JWT + mTLS layering**
  (`rustgate-federation::jwt`, feature `federation-ha`) — federation
  connections carry per-connection JWTs signed with HS256, ES256, or
  Ed25519 (EdDSA, RFC 8037). Private signing keys held by the issuer;
  public verifier keys registered per-`kid` at every relying peer.
  A compromised verifier cannot forge tokens. Algorithm-confusion
  attacks (HS256-with-RSA-public-key) are rejected before the
  signature check via the `kid`→algorithm binding.
- **ABAC claims** — JWT claims carry `groups`, `iss`, `sub`, `jti`
  (revocation), `exp` (lifetime), `iat` (freshness). Revocation is
  O(1) via an LRU-bounded cache with amortised expired-entry sweeps.
- **Cedar policy engine** (`rustgate-authz`, feature `cedar`) — full
  attribute-based authorization with subject attribute caching (dual
  128-bit hash) and hot-reloadable `.cedar` policy files.
- **CN normalization** — subject CNs are NFC-normalized and lowercased
  before ACL matching, defending against Unicode equivalence attacks.

### Gaps

- **MFA for human operators** — the management HTTP API
  (`rustgate-server::acl_api`) authenticates with a bearer token
  (constant-time compared via `subtle::ConstantTimeEq`). There is no
  TOTP, WebAuthn, or FIDO2 enforcement layer. Operator workflows
  requiring MFA should front the management API with an authenticating
  reverse proxy (e.g., oauth2-proxy, Pomerium).
- **CAC/PIV integration** — no built-in support for DoD CAC or PIV
  smart-card authentication. Client certificates follow a conventional
  PKI model; deployments requiring CAC/PIV must issue certificates
  from a DoD-accepted CA and provision them to the smart card
  out-of-band.
- **Risk-adaptive policy** — authorization decisions are deterministic
  given the policy bundle. There is no risk-scoring layer that
  elevates required assurance based on behavior analytics.

### NIST 800-53 mapping

IA-2 (Identification and Authentication), IA-5 (Authenticator
Management), AC-2 (Account Management), AC-3 (Access Enforcement),
AC-6 (Least Privilege).

---

## Pillar 2 — Device

DoD ZTA requires every device (user endpoint, workload, network
element) to be enumerated, inventoried, posture-checked, and tied to
its identity via a hardware root of trust.

### Implemented

- **Certificate-bound device identity** — client certificates bind the
  device (or workload) to a SHA-256 fingerprint recorded in every
  audit event. The fingerprint is stable across restarts and independent
  of IP or hostname changes.
- **Certificate rotation without downtime**
  (`rustgate-transport::cert_reloader`) — atomic certificate swap via
  `ArcSwap` on SIGHUP or filesystem-watch; existing connections drain
  cleanly while new connections use the rotated material.
- **Revocation enforcement** —
  - **CRL** at the TLS handshake layer (`rustgate-transport::listener`
    with `WebPkiClientVerifier`). Revoked certificates are rejected
    before any application code runs.
  - **OCSP stapling** (feature `ocsp`) — server certificates can staple
    OCSP responses for relying parties.
- **Short-lived credentials** — SPIFFE SVIDs rotate automatically via
  the Workload API. Federation JWTs have configurable expiry (default
  1 hour) and are rotated via the JWT authority's `issue()` path.
- **Private-key hygiene** — all key material wrapped in
  `Zeroizing<T>` and wiped on drop. No private key is ever logged,
  serialized to audit, or included in `Debug` output (custom `Debug`
  impls emit `[REDACTED]` for every field that could hold key
  material).

### Gaps

- **TPM / HSM attestation** — there is no built-in TPM-backed key
  attestation or HSM-rooted signing. Workloads running on TPM-equipped
  hardware cannot today prove to rustgate that their signing key lives
  in the TPM. This is tracked in issue #856 (Hardware-rooted identity
  — TPM, PKCS#11, YubiKey).
- **Device-compliance score** — there is no "device posture" input to
  authorization decisions. Policy is attribute-based on the cert
  subject; a compromised device with a valid cert is indistinguishable
  from a healthy device with the same cert until the cert is revoked.
  Integration with MDM/CDM systems (Tanium, Flexera, CrowdStrike) is
  the responsibility of the hosting platform.
- **Device enumeration** — the management API exposes connected
  clients but does not integrate with an asset-inventory source of
  truth. Operators can list currently-connected CNs via
  `GET /api/clients` (when feature `api` is enabled).

### NIST 800-53 mapping

IA-3 (Device Identification), IA-4 (Identifier Management), SC-17 (PKI
Certificates), CM-8 (Information System Component Inventory — partial).

---

## Pillar 3 — Application & Workload

DoD ZTA requires every application and workload to be secured, tied
to a software bill of materials, monitored for integrity at runtime,
and authenticated to the network independently of any human user.

### Implemented

- **Memory safety** — `unsafe_code = "forbid"` workspace-wide, no
  exceptions. Every dependency added to the workspace is screened
  against a banned list (`deny.toml`) that includes `openssl`,
  `openssl-sys`, and `native-tls`. rustls is the sole TLS provider.
- **Panic/unwrap discipline** — `clippy::panic = "deny"` and
  `clippy::unwrap_used = "deny"` in production code. All failure
  paths propagate `Result<T, E>` or structured error types derived
  via `thiserror`.
- **FIPS 140-3 validated cryptography** (feature `fips`) — the `aws-lc-rs`
  crypto provider is drop-in replaceable for `ring`; the
  `--fips-required` CLI flag hard-fails startup if FIPS mode is not
  active. See [`fips.md`](fips.md).
- **Post-quantum key exchange** (feature `post-quantum`) — ML-KEM /
  X25519-MLKEM hybrid key exchange available for TLS. See
  [`post-quantum.md`](post-quantum.md).
- **Constant-time authentication** — every credential comparison uses
  `subtle::ConstantTimeEq`; the `(user_ok & pass_ok).into()` pattern
  in `enrollment::auth` and `server::acl_api` ensures both
  comparisons execute regardless of which fails, so timing cannot
  distinguish "wrong user" from "wrong password".
- **Reproducible builds** — `Cargo.lock` is committed; `cargo deny
  check` gates every PR on license compliance and advisory status;
  the `--locked` flag is used in every CI build.
- **Container hardening** — Helm chart runs as non-root with a
  read-only root filesystem, drops all Linux capabilities, and sets
  a seccomp profile. See [`deployment.md`](deployment.md).
- **Zero trust to the dependency graph** — `cargo deny` enforces an
  allow-list of crates.io as the sole source registry; no git deps,
  no unpublished overrides.

### Gaps

- **Runtime application integrity** — there is no built-in runtime
  attestation (remote attestation, Intel TDX / AMD SEV-SNP
  confidential-compute signals). Integrity verification relies on
  the host platform (signed images, SBOM generation in CI, container
  admission controllers such as Sigstore cosign + Kyverno).
- **SBOM generation** — SBOM production happens in CI but is not
  embedded in the binary. See issue #871 (DevSecOps packaging —
  Iron Bank base image, Zarf, cATO evidence).

### NIST 800-53 mapping

SA-11 (Developer Security Testing), SC-13 (Cryptographic Protection),
SI-7 (Software, Firmware, and Information Integrity — partial), RA-5
(Vulnerability Monitoring).

---

## Pillar 4 — Data

DoD ZTA requires data to be discovered, classified, tagged with
sensitivity metadata, encrypted at rest and in transit, and subject
to DLP enforcement that follows the data across trust boundaries.

### Implemented

- **Encryption in transit** — mTLS with TLS 1.2+ and configurable
  cipher suites. Federation connections use the same TLS stack; no
  plaintext fallback path exists. See
  [`tls-certificates.md`](tls-certificates.md).
- **Encryption at rest** (`rustgate-core::encrypted`) — archive files
  (store-and-forward queues, DLQ, audit archives) encrypted with
  ChaCha20-Poly1305 AEAD. Format version 2 with per-chunk associated
  data binding chunk index and kind (prevents reordering), sealed
  terminator chunk (prevents silent tail truncation), and nonces
  constructed as base(8) + counter(4) for ≤2³² chunks per file.
- **Key derivation** — HKDF-SHA256 derives per-archive subkeys from a
  single high-entropy root secret (RFC 5869). Derivations honor
  `key_expirations` entries identically to raw keys. Argon2id for
  low-entropy passphrase-derived keys is not implemented (HKDF adds
  no work factor and is unsuitable for passphrases).
- **Key rotation** — `KeyRing` supports multiple keys by ID with an
  active key for new writes; historical keys retained for decrypt.
  Per-key expiration timestamps supported.
- **Tamper-evident audit** (`rustgate-core::audit_chain`) — every
  audit record includes the SHA-256 hash of the previous record,
  forming a chain. Canonical JSON ordering via `BTreeMap` ensures
  deterministic hashing. Torn writes are auto-truncated at the last
  complete record. A sealed terminator record prevents silent tail
  truncation.
- **PII/credential masking in logs** (`rustgate-core::masking`,
  `rustgate-core::sanitize`) — CNs hashed to a 48-bit correlation
  token for structured logs; IPs partially redacted (last octet);
  credentials show first 2 chars only; cert serials show first 4 +
  last 4. Control characters and newlines in user-supplied strings
  replaced with U+FFFD before logging to defend against log-forging
  attacks.
- **Secret zeroization** — all secret material (private keys,
  JWT signing keys, HMAC secrets, encryption keys, EST
  enrollment credentials) wrapped in `Zeroizing<T>` and wiped on
  drop. Custom `Debug` impls emit `[REDACTED]` for any field that
  could hold secret material.

### Gaps

- **Classification tagging on `Metadata`** — the `RoutableMessage`
  `Metadata` struct carries `received_at`, `source_protocol`,
  `message_type`, and `ttl`, but no `classification: Option<String>`
  field. CAPCO format ("TS/SCI", "S//NOFORN") cannot be stamped on
  messages at the gateway today. Tracked in issue #849 (Classification
  Marking Engine, CAPCO format).
- **DLP enforcement** — there is no content-inspection layer that
  blocks classified data from crossing a boundary based on detected
  patterns (regex, ML-based PII detection). Deployments requiring DLP
  must front rustgate with a dedicated inspection proxy or use a
  downstream SIEM with real-time alerting.
- **Data discovery & mapping** — rustgate routes messages; it does
  not enumerate or catalog data sources. CoT message routing is
  subject-prefix-based via ACLs, not content-based.

### NIST 800-53 mapping

SC-8 (Transmission Confidentiality), SC-12 (Cryptographic Key
Management), SC-13 (Cryptographic Protection), SC-28 (Protection of
Information at Rest), AU-10 (Non-repudiation — via hash-chained
audit), AU-11 (Audit Record Retention — configurable), MP-3 (Media
Marking — partial; gap), MP-4 (Media Storage).

---

## Pillar 5 — Network & Environment

DoD ZTA requires network segmentation at the application-flow
granularity, least-privilege traffic policies, and dynamic
reconfiguration driven by authentication and authorization decisions.

### Implemented

- **Group-based message routing** (`rustgate-transport::acl`) —
  access to a group is opt-in via deny-first / default-deny policies
  loaded from a single file. Clients only receive messages for groups
  they are explicitly authorized for.
- **Attribute-based authorization** (`rustgate-authz`) — Send-PEP and
  Receive-PEP hooks fire on every message admission; decisions are
  cached with dual-hash (128-bit) collision resistance to defeat
  adversarial subject injection at scale.
- **Federation hop limits** — loop prevention via provenance tracking.
  Each federated event carries a hop count; configurable
  `MAX_FEDERATION_HOPS` (default 8). At-limit events are accepted;
  over-limit events are rejected with `continue` (streaming path does
  not break the subscription).
- **Peer allowlist** — federation peer group memberships are tracked
  per-peer and re-checked on every forward. No "trusted by proximity"
  path exists.
- **Rate limits with audit** —
  - Per-IP sliding-window connection limiter
    (`rustgate-resilience::conn_rate_limiter`) on every plaintext
    listener.
  - Per-target token bucket (`rustgate-resilience::token_bucket`) for
    outbound HTTP / federation traffic.
  - Per-IP enrollment rate limiter on the enrollment endpoint.
  - Per-tenant quota tracking (`rustgate-transport::quota`) keyed by
    cert Organization (O) field.
  - Every rejection emits `audit::security_rate_limited`.
- **Backpressure & graceful degradation** —
  - Global admission gate (`BackpressureGate`) with high/low water
    marks on total queued bytes.
  - Per-session bounded `mpsc` channels; overflow drops to
    store-and-forward or dead-letter queue.
  - Store-and-forward queues are redb-backed, per-client, durable
    across restarts, with global byte cap and drop-oldest FIFO
    eviction. Queues re-check ACL + authz on drain (policy may
    have changed while client was offline).
- **TCP socket hardening** (`rustgate-core::net`) — every accepted
  TCP stream is configured with keepalive + `TCP_NODELAY` to defeat
  NAT-middlebox disappearance and avoid the Nagle+DELACK latency
  stall. Enforced by a CI drift check.
- **Plaintext listeners are opt-in** — `--tcp-bind` and `--udp-bind`
  require an explicit `--plaintext-allowed-groups` allowlist and are
  marked for trusted networks only.

### Gaps

- **Micro-segmentation below the gateway** — network-layer
  segmentation (between hosts, between namespaces) relies on the
  hosting platform's primitives (Kubernetes NetworkPolicy, Cilium
  eBPF, Istio, Calico). rustgate does not orchestrate at the
  network-layer fabric.
- **SDN integration** — no direct integration with SDN controllers
  (OpenDaylight, ONOS). Authorization decisions at the message layer
  do not re-program lower-layer network policy.

### NIST 800-53 mapping

AC-4 (Information Flow Enforcement), AC-17 (Remote Access), SC-7
(Boundary Protection), SC-10 (Network Disconnect — via heartbeat
timeout), SC-32 (Information System Partitioning — via group ACL).

---

## Pillar 6 — Automation & Orchestration

DoD ZTA requires automated response to policy violations, continuous
integration of security telemetry with orchestration (SOAR), and
automated enforcement of policy changes without human intervention.

### Implemented

- **Hot-reload of policy** —
  - ACL (`rustgate-transport::router` via
    `ArcSwap<Option<GroupAclPolicy>>`) hot-swaps on SIGHUP or via
    `POST /api/acl/reload`.
  - Authz policy (`ArcSwap<Option<Arc<dyn PolicyEngine>>>`)
    hot-swaps similarly.
  - CRL hot-reloads via atomic `WebPkiClientVerifier` rebuild.
  - Federation peer list hot-reloads via file-watch or discovery
    backend (DNS-SD, Consul, etcd).
  - All reload paths emit success/failure audit events and update
    Prometheus gauges.
- **Circuit breakers with automatic recovery**
  (`rustgate-resilience::circuit`) — three-state breaker (Closed →
  Open → HalfOpen) with probe-window re-testing after a cooldown.
  The HTTP egress and federation forwarder both wire circuit breakers
  per-target. Breaker state transitions emit audit events and drive
  a `rustgate_http_circuit_state{target}` Prometheus gauge.
- **Automatic reconnection** — federation V2 client and NATS bridge
  use deterministic exponential backoff (`rustgate-resilience::reconnect`)
  on connection loss, with audit events on every transition.
- **Store-and-forward recovery** — offline clients re-receive queued
  messages on reconnect. ACL + authz are re-evaluated at drain time
  so a policy change during the outage is respected.
- **Automated test coverage** — proptest suites over CoT parsing,
  codec round-trips, identity normalization, and policy decisions;
  fuzz targets for `cot_parse`, `xml_stream_codec`, `tak_frame_codec`;
  `cargo nextest` as the CI default runner.

### Gaps

- **SOAR integration** — no built-in connector to SOAR platforms
  (Splunk SOAR, Microsoft Sentinel, IBM Resilient). Automated
  response is limited to rustgate's internal primitives (circuit
  trip, rate-limit, drop). External SOAR integration happens via
  SIEM ingestion of the structured audit log.
- **Automated incident response** — there is no "if condition X,
  execute remediation Y" engine beyond the circuit breaker. Complex
  response playbooks (revoke cert, rotate key, page on-call) are the
  responsibility of a SOAR platform consuming the audit stream.
- **Configuration drift detection** — rustgate validates config at
  load time but does not emit a "drift detected vs. desired state"
  signal. GitOps tools (ArgoCD, Flux) close this gap for the broader
  platform.

### NIST 800-53 mapping

CM-3 (Configuration Change Control — partial), IR-4 (Incident Handling
— partial), SI-4 (Information System Monitoring).

---

## Pillar 7 — Visibility & Analytics

DoD ZTA requires comprehensive telemetry, analytics-driven detection,
and cross-pillar correlation. The target state is unified visibility
across all authentication, authorization, and data flow events.

### Implemented

- **Structured audit log** (`rustgate-core::audit`) — 28+ structured
  audit event types covering client connections, TLS handshakes,
  federation peer state transitions, enrollment outcomes,
  authorization decisions, HTTP egress failures, CRL reloads,
  certificate rotations, SPIFFE refreshes, and rate-limit rejections.
  Every event carries a timestamp, event type, and event-specific
  fields. Emitted at `tracing::info` level with target `"audit"` for
  straightforward sink filtering.
- **Tamper-evident audit chain** (`rustgate-core::audit_chain`) —
  each record carries the SHA-256 of the previous record; chain
  verification is a single pass via `verify_audit_log`. The chain
  tip is anchored to disk for continuity across restarts.
- **Prometheus metrics** — every crate that emits operational
  telemetry registers metrics through the workspace-wide
  `OnceLock + init() + accessor` pattern. Coverage: connections,
  messages routed, TLS handshake duration, circuit state, federation
  heartbeat RTT, NATS publishes, HTTP egress outcomes, MQTT session
  state, dedup cache size, store-and-forward queue depth.
- **OpenTelemetry** (feature `otel`) — OTLP exporter for traces and
  metrics. See [`observability.md`](observability.md).
- **CoT replay buffer** — a sliding-window replay filter
  (`rustgate-transport::dedup`) with SHA-256 keyed by
  `(uid || 0x00 || time_le || 0x00 || payload)` and an LRU bound.
  Duplicates fire an `OnDuplicate` callback for metrics emission.
- **Access log PII guard** — `hash_cn()` hashes client identity
  before logging to the `access` target; a `tracing::enabled!`
  guard avoids allocating expensive fields when the target is
  disabled.
- **Health & readiness probes** — the metrics HTTP server exposes
  liveness and readiness endpoints for platform orchestrators.

### Gaps

- **W3C `traceparent` propagation across federation**
  — federation forwards do not thread a W3C trace context header, so
  a CoT event traversing two federated peers generates two disjoint
  traces in the OpenTelemetry backend rather than a single
  end-to-end span chain. Tracked in issue #852 (W3C Distributed Trace
  Context propagation across federation).
- **Behavioral analytics** — audit events are structured, but no
  built-in UEBA (User and Entity Behavior Analytics) module
  fingerprints baseline behavior and flags deviations. SIEM
  integration covers this gap when the audit stream is shipped
  to a capable backend (Splunk ES, Microsoft Sentinel, Elastic
  Security).
- **Cross-pillar correlation** — correlation requires SIEM-side work;
  rustgate emits the raw primitives (correlation hashes on CNs,
  stable peer IDs, cert fingerprints) but does not itself compute
  risk scores that join User + Device + Network signals.

### NIST 800-53 mapping

AU-2 (Audit Events), AU-3 (Content of Audit Records), AU-4 (Audit
Storage Capacity), AU-6 (Audit Review, Analysis, and Reporting), AU-9
(Protection of Audit Information), AU-10 (Non-repudiation), CA-7
(Continuous Monitoring), SI-4 (Information System Monitoring).

---

## Activity coverage matrix (abbreviated)

The ZTA 2.0 reference catalog defines 152 activities across the seven
pillars. A full activity-by-activity mapping is maintained out-of-tree
in the compliance evidence package (cATO submission artifact —
see #871). This section captures the highest-priority activities that
rustgate implements directly.

| ZTA Activity | Pillar | rustgate control |
|---|---|---|
| 1.2.1 User Inventory | User | mTLS cert CN directory via enrollment server |
| 1.4.1 Enterprise Identity Lifecycle | User | EST / PKCS#12 enrollment + CRL |
| 1.5.1 Organizational MFA/IDP | User | (gap — front with oauth2-proxy) |
| 1.6.1 Least Privilege Access | User | Group ACL + Cedar ABAC, deny-first |
| 1.8.1 Continuous Authentication | User | JWT expiry + refresh, SPIFFE SVID rotation |
| 2.1.1 Device Inventory | Device | Cert fingerprint in every audit record |
| 2.2.1 Device Detection / Compliance | Device | (gap — integrate with MDM) |
| 2.3.1 Entity Activity Monitoring | Device | Per-CN access log with hashed identity |
| 2.7.1 Device Authorization with Real Time Inspection | Device | CRL + OCSP at TLS handshake |
| 3.1.1 Application Inventory | App | Feature-flag inventory in config |
| 3.3.1 Software Risk Management | App | `cargo deny` advisories, SBOM in CI |
| 3.4.1 Resource Authorization & Integration | App | Cedar ABAC, hot-reloadable |
| 3.5.1 Continuous Monitoring and Ongoing Authorizations | App | Prometheus + audit chain |
| 4.1.1 Data Catalog Risk Assessment | Data | (gap — DLP/classification tagging) |
| 4.2.1 DoD Enterprise Data Governance | Data | Encrypted archives, hash-chained audit |
| 4.4.1 Data Labeling & Tagging | Data | (gap — `Metadata.classification`) |
| 4.5.1 Data Monitoring & Sensing | Data | Audit chain + Prometheus per-target counters |
| 4.6.1 DLP Enforcement Points | Data | (gap — front with CDR or DLP gateway) |
| 4.7.1 DRM Enforcement | Data | (gap — scope) |
| 5.1.1 Data Flow Mapping | Network | Group ACL + Cedar + forwarding traces |
| 5.2.1 Software-Defined Networking | Network | (gap — platform responsibility) |
| 5.3.1 Macro-Segmentation | Network | Federation peer allowlist + group ACL |
| 5.4.1 Micro-Segmentation | Network | (partial — message-layer segmentation; network layer via hosting platform) |
| 6.1.1 Policy Decision Point | Orchestration | Authz engine + ACL policy, hot-reloadable |
| 6.2.1 Critical Process Automation | Orchestration | Circuit breakers + store-and-forward |
| 6.3.1 Machine Learning | Orchestration | (gap — SIEM-side) |
| 6.4.1 AI | Orchestration | (gap — SIEM-side) |
| 6.5.1 Security Orchestration, Automation & Response (SOAR) | Orchestration | (gap — integrate via audit stream) |
| 7.1.1 Log All Traffic | Visibility | Structured `access` log target |
| 7.2.1 SIEM | Visibility | Audit log ingestable as JSON Lines |
| 7.3.1 Common Security & Risk Analytics | Visibility | (gap — SIEM-side) |
| 7.4.1 User & Entity Behavior Analytics | Visibility | (gap — SIEM-side) |
| 7.5.1 Threat Intelligence | Visibility | (gap — SIEM-side) |
| 7.6.1 Automated Dynamic Policies | Visibility | Hot-reload via `/api/acl/reload` + SIGHUP |

Activities marked "(gap — SIEM-side)" are intentionally out of scope
for a message gateway. rustgate's contribution is to emit high-quality
structured telemetry; analytics and response are SIEM-layer concerns.

---

## NIST 800-53 control mapping

A summary cross-reference of the most operationally relevant NIST
800-53 Rev 5 controls and the rustgate features that satisfy them.
This is a digest of the more detailed inventory in
[`security-posture.md`](security-posture.md).

| Control | Title | rustgate feature |
|---|---|---|
| AC-3 | Access Enforcement | Group ACL deny-first policy + Cedar ABAC PEP hooks (Send + Receive) |
| AC-4 | Information Flow Enforcement | Per-message authorization, federation hop-count cap, peer allowlist |
| AC-6 | Least Privilege | Group ACL opt-in membership, per-tenant quota by cert Organization |
| AU-2 | Audit Events | 28+ structured event types via `rustgate-core::audit` |
| AU-3 | Content of Audit Records | Canonical JSON ordering, event-typed fields, hashed CN correlation |
| AU-9 | Protection of Audit Information | SHA-256 hash chain, sealed terminator, torn-write recovery |
| AU-10 | Non-repudiation | Hash-chained audit log; tip anchor for cross-restart continuity |
| AU-11 | Audit Record Retention | Configurable retention; encrypted at-rest archives |
| IA-2 | Identification and Authentication (Users) | mTLS client certificates, SPIFFE workload identity, JWT for federation peers |
| IA-3 | Device Identification and Authentication | Cert-bound SHA-256 fingerprint per connection, recorded in every audit event |
| IA-4 | Identifier Management | Enrollment server (PKCS#12, EST/RFC 7030), CRL, OCSP stapling |
| IA-5 | Authenticator Management | `Zeroizing<T>` private-key handling, redacted `Debug` impls, key rotation via `KeyRing` |
| SC-7 | Boundary Protection | Backpressure gate, per-IP rate limiter, plaintext listener allowlist gate |
| SC-8 | Transmission Confidentiality | mTLS (TLS 1.2+), no plaintext fallback path on the federation/client surface |
| SC-12 | Cryptographic Key Management | HKDF-SHA256 per-archive subkeys, per-key expiration, rotation via `KeyRing` |
| SC-13 | Cryptographic Protection | rustls + aws-lc-rs (FIPS-validated under `--fips-required`), ChaCha20-Poly1305 AEAD at rest |
| SC-28 | Protection of Information at Rest | Encrypted archive format v2 (per-chunk AAD, sealed terminator) |

For the full per-control inventory, including the controls that are
explicitly out of scope (e.g., physical-environment controls
PE-* delegated to the hosting facility), see
[`security-posture.md`](security-posture.md).

---

## Gap remediation roadmap

Each gap surfaced in the per-pillar mapping above is tracked against
a GitHub issue. This document is intentionally **informational only**:
no gap below is a commitment to a delivery date, and the absence of a
gap row does not constitute a certification claim.

| Gap | Pillar | Tracking issue |
|---|---|---|
| Hardware-rooted identity — trait + fail-closed resolver + reference stub (shipped) | User, Device | [#856](https://github.com/rchiofalo/rustgate/issues/856) — `feat(enrollment): Hardware-rooted identity — TPM, PKCS#11, YubiKey` (the `HardwareIdentity` trait, `HardwareIdentityResolver`, and `Pkcs11StubBackend` in `rustgate-transport::hw_identity`) |
| Hardware-rooted identity — real TPM2 / PKCS#11 / YubiKey driver bodies | Device | [#1539](https://github.com/rchiofalo/rustgate/issues/1539) — `roadmap: TPM/HSM hardware-rooted identity (rustgate-tpm)`. The `rustgate-tpm` crate now exists as the driver home: it re-exports the transport trait surface and reserves the fail-closed `tpm` / `pkcs11` / `yubikey` feature stubs. See [ADR 0028](adr/0028-hardware-rooted-identity.md). |
| Classification tagging (CAPCO format) on `RoutableMessage::Metadata` | Data | [#849](https://github.com/rchiofalo/rustgate/issues/849) — `feat: Classification Marking Engine (CAPCO format)` |
| W3C `traceparent` propagation across federation hops | Visibility | [#852](https://github.com/rchiofalo/rustgate/issues/852) — `feat: W3C Distributed Trace Context propagation across federation` |
| Kubernetes operator + one-command deployment (closes platform-side gaps in Network and Automation pillars) | Network, Automation | [#874](https://github.com/rchiofalo/rustgate/issues/874) — `feat: Kubernetes operator + one-command deployment` |
| Cross-domain content inspection / DLP guard | Data | [#857](https://github.com/rchiofalo/rustgate/issues/857) — Cross-domain content inspection guard |
| Ed25519 JWT + JWKS URL + `kid` rotation state machine (parts 2 and 3) | User | [#952](https://github.com/rchiofalo/rustgate/issues/952) — JWKS fetching and rotation |
| DevSecOps packaging — Iron Bank, Zarf, cATO evidence | Application | [#871](https://github.com/rchiofalo/rustgate/issues/871) — DevSecOps packaging |

Out-of-scope items — by design, not by omission — include MDM
integration, SDN controller integration, behavioral analytics (UEBA),
and SOAR playbook orchestration. rustgate emits the structured
telemetry these systems consume; the systems themselves are the
hosting platform's responsibility.

---

## References

- DISA / NSA, *Department of Defense Zero Trust Reference Architecture
  Version 2.0*, July 2022. The authoritative source for the
  Seven Pillars taxonomy and the 152-activity catalog.
- DoD CIO, *DoD Zero Trust Strategy*, October 2022. The FY2027
  compliance mandate.
- DoD CIO, *DoD Zero Trust Capability Execution Roadmap (COA 1)*,
  January 2023. Activity-by-activity sequencing guidance.
- NIST SP 800-207, *Zero Trust Architecture*, August 2020. The
  foundational tenets cited by the DoD ZTA Reference Architecture.
- NIST SP 800-53 Rev 5, *Security and Privacy Controls for
  Information Systems and Organizations*. The control-family
  reference used in the per-pillar NIST mappings above.
- CNSSI 1253, *Security Categorization and Control Selection for
  National Security Systems*. The DoD overlay applied to NIST 800-53
  for national-security workloads.

---

## Disclaimer

This mapping is **informational only**. It documents how rustgate's
implemented features relate to the DoD ZTA v2.0 Seven Pillars; it does
**not** assert formal compliance, certification, or accreditation.
A production deployment seeking ATO, cATO, or any equivalent
authorization decision must commission an independent assessment
covering the deployment as a whole — software, hosting platform,
operational procedures, and supply chain. rustgate is one component
of such a system, not the whole.
