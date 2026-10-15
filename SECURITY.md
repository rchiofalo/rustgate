# Security Policy

This document describes the rustgate threat model: what the project is
designed to defend against, what it explicitly is not, the per-crate
attack surface, supported data classifications, known-safe deployment
patterns, and how to report a vulnerability.

It is intended for operators evaluating rustgate for tactical or
mission-critical deployments and for downstream integrators who embed
the crates directly. For implementation-side discipline used to uphold
the properties below, see
[`.claude/rules/shared-infrastructure.md`](.claude/rules/shared-infrastructure.md).
A more detailed STRIDE breakdown lives in
[`docs/threat-model.md`](docs/threat-model.md); this file is the
high-level customer-facing companion.

## Trust Model

rustgate is a mutual-TLS message router. Every trust decision flows
from the certificate the peer presents at the TLS handshake. Once a
peer is authenticated, downstream subsystems route messages according
to identity attributes extracted from that certificate; they do not
re-authenticate.

| What rustgate trusts | Why |
|---|---|
| The configured CA bundle | All client and federation certs must chain to it; signs the entire trust graph |
| The configured CRL (when supplied) | Hot-reloadable revocation list; rejects revoked serials at handshake before the application layer sees the connection |
| The local filesystem for secrets | Server private key, CA bundle, JWT signing key, archive key file: all read at startup with operator-managed permissions |
| The host clock | Used for cert validity windows, dedup TTL, JWT exp/nbf, audit timestamps |
| Code linked into the binary | rustgate is `unsafe_code = "forbid"` workspace-wide and CI gates dependency licenses and advisories via `cargo deny` |

| What rustgate does NOT trust | Implication |
|---|---|
| Wire bytes from any peer | All inputs are length-bounded, parsed with `Result`, and fuzzed |
| Identity claims inside the payload | Routing identity comes from the cert, never the message body |
| Federation peer assertions about origin identity | V2 federation re-validates origin CN against per-peer allowlists; group-claim mismatches emit `audit::federation_group_claim_rejected` |
| Plaintext-listener peers | Assigned a synthetic identity (`__plaintext__` group, `--plaintext-cn`); cannot reach mTLS-only groups |
| Logs and config files at runtime | Log fields from user input are sanitized; config reload is restricted to SIGHUP + verifier rebuild |

### The mTLS / route-dispatch boundary

The mTLS handshake is the only authentication boundary in the system.
Once the rustls verifier accepts the peer cert and (if configured) the
CRL/OCSP/SPIFFE checks pass, the connection is admitted to the internal
router as an `Identity` (`crates/rustgate-core/src/identity.rs`):

```rust
pub struct Identity {
    pub cn: String,
    pub fingerprint: CertFingerprint,
    pub groups: Vec<GroupId>,
    pub tenant: Option<String>,
    pub spiffe_id: Option<String>,
    pub attributes: HashMap<String, AttrValue>,
}
```

Everything past that point — the router, ACL engine, dedup cache,
position cache, store-and-forward queue, federation forwarder — operates
on `RoutableMessage` envelopes whose source identity was set at admit
time. There is no path that mints a new identity from payload bytes.
This boundary is what makes the per-crate review tractable: a bug in
the MAVLink decoder cannot escalate to a federation peer impersonation
because the federation layer only sees `Identity` values produced by
its own mTLS handshake.

### SPIFFE workload identity (feature `spiffe`)

When the `spiffe` feature is enabled, rustgate fetches its serving SVID
from the SPIFFE Workload API rather than from disk, and rotates
atomically via `CertReloader`. This shifts the trust root from a
file-permission-protected key to whatever attestation the SPIFFE
agent performs (typically Kubernetes SA tokens, systemd unit identity,
or platform metadata). The mTLS handshake itself is unchanged; SPIFFE
only changes how the server obtains its key material.

### Federation peer authentication

Two protocol versions are supported:

| Version | Authentication | Authorization |
|---|---|---|
| V1 (length-prefixed, port 9000) | mTLS only — peer cert must chain to `--federation-trust-store-dir`, optional CN pinning via `trust_cert_cn` | Implicit: any authenticated peer may forward |
| V2 (gRPC tonic, port 9001) | mTLS plus a JWT signed by the configured federation authority | Explicit per-RPC checks; group-claim assertions cross-checked against origin CN |

Federation peers are first-class principals; they are not implicitly
trusted just because they exist on a configured allowlist. JWT
verification (`rustgate-federation/src/jwt.rs`) validates issuer,
audience, expiry, and the signing key; `JwtAuthority` implements
custom `Debug` to redact key material.

## In-Scope Attacker Capabilities

rustgate is designed to mitigate the following threats. Each row links
the threat to a concrete mitigation in the codebase.

### Network-level adversary (passive eavesdropping, MITM)

Defended by mTLS on every transport that carries operational data: the
TLS listener, WebSocket upgrade, MQTT broker, federation V1/V2, and the
optional NATS-TLS bridge. Cipher selection is delegated to rustls
(default) or aws-lc-rs in FIPS 140-3 mode. Plaintext listeners are
opt-in, isolated to a synthetic group, and cannot mix with mTLS
traffic.

### Compromised peer (revoked or expired cert, malformed wire bytes)

| Attack | Mitigation |
|---|---|
| Replay a revoked cert | CRL is read at startup and reload, applied at handshake by the rustls verifier; revoked peers never reach the application layer |
| Present an expired cert | rustls validity-window check rejects before handshake completes |
| Send malformed protocol bytes | All decoders are length-bounded by `MAX_FRAME_SIZE` (16 MiB) and use `Result` on every parse step; oversized frames emit a structured error and close the connection |
| Send malformed CoT XML | `quick-xml` parser with `fuzz/fuzz_targets/cot_parse.rs` and `cot_mask_strip_coordinates.rs` coverage; events that fail to parse are dropped, not partially routed |
| Send oversized MQTT packet | Broker advertises `Maximum Packet Size` in CONNACK and emits DISCONNECT 0x95 on oversized PUBLISH (closes #753) |
| Forge a federation message | Origin CN must match the V2 peer's allowlisted assertion; mismatches emit `audit::federation_group_claim_rejected` and are dropped |

### Resource-exhaustion attacks

| Attack | Mitigation |
|---|---|
| Slowloris / connection-holding | `HANDSHAKE_TIMEOUT` (10s), `READ_TIMEOUT` (5min), `WRITE_TIMEOUT` (30s) shared across all listeners |
| Flood of new TCP connections from one IP | `rustgate_resilience::conn_rate_limiter::ConnRateLimiter` — sliding window per-IP rejection, emits `audit::security_rate_limited` |
| Large queued backlog from a slow consumer | Two-tier backpressure: `BackpressureGate` (global high/low watermark on queued bytes) + per-session bounded `mpsc` with overflow to durable store-and-forward |
| Per-tenant unbounded resource use | `TenantQuotaTracker` with per-tenant connection and rate caps keyed by certificate Organization (O) field |
| Federation circuit hammering an unhealthy peer | `rustgate_resilience::circuit::CircuitBreaker` three-state breaker with probe limiting and `audit::federation_circuit_tripped` events |
| Dedup-bypass attempt (replaying messages with permuted payload) | SHA-256 keyed by `(uid \|\| 0x00 \|\| time_le \|\| 0x00 \|\| payload)` with bounded LRU; non-CoT payloads fall back to pure content-hash |

### Log injection / log forging

User-supplied strings (CN, group names, error messages) are passed
through `rustgate_core::sanitize::sanitize_for_log` before they reach a
`tracing` field. Control characters and newlines are replaced with
U+FFFD, preventing CR/LF log-forging in JSON or syslog sinks. PII is
masked via `rustgate_core::masking::{hash_cn, mask_ip, mask_credential,
mask_cert_serial}`.

### Timing side-channels in credential comparison

All credential comparisons use `subtle::ConstantTimeEq`. Username and
password are compared independently; the result is combined with `&` so
that the comparison time does not reveal which field failed. This
applies to enrollment HTTP Basic Auth (`crates/rustgate-enrollment/src/auth.rs`)
and the ACL admin API (`crates/rustgate-server/src/acl_api.rs`).

### Wire-format fuzzing

The `fuzz/fuzz_targets/` directory contains 22 cargo-fuzz targets
covering every parser at the trust boundary: CoT XML, length-prefixed
codec, WebSocket frames, MAVLink v2 frames, ASTERIX CAT-021/CAT-062,
STANAG 4586 vehicle position, federation frames, JWT, CSR, CRL, NATS
wire events, authz policy/eval, and protobuf round-trip. New parsers
are required to ship with a fuzz target.

## Out-of-Scope

rustgate explicitly does not defend against the following. Operators
must address them at a higher layer.

- **Compromised host OS or container runtime.** rustgate trusts the
  process it runs in. A kernel- or runtime-level attacker can read
  the server private key from memory regardless of what the binary
  does.
- **Side-channel attacks on the underlying CPU** (Spectre, Meltdown,
  Rowhammer, microarchitectural timing). These are mitigated by the
  CPU vendor and the OS, not by rustgate.
- **Operator misconfiguration.** Examples: handing out the CA private
  key, disabling CRL refresh, deploying with `--authz-fail-open` in a
  production tenant, copying the federation JWT signing key into a
  shared bucket. rustgate ships safe defaults but cannot recover from
  operator mistakes that hand an attacker a valid credential.
- **Insider threats with admin-level CLI access.** Anyone who can run
  `rustgate decrypt-archive` or read the configured archive key file
  can read everything rustgate has written. Privileged-access
  management is the operator's responsibility.
- **Physical attacks on network equipment.** Tap-and-replay defense at
  the cable level is out of scope; mTLS provides confidentiality and
  integrity end to end, but a determined physical attacker on a
  trusted host can still extract keys.
- **Volumetric DDoS at the network-infrastructure level.** rustgate is
  a router, not a DDoS scrubber. Per-IP connection rate limits and
  per-tenant quotas mitigate slow application-layer attacks but will
  not absorb a Tbps flood. Place rustgate behind a network-level
  scrubber if exposed to the public internet.
- **Higher-than-CUI classifications without additional controls.** See
  the data-classification section below.

## Attack Surface by Crate

The table maps the externally reachable surface of each crate. "Trust
boundary" means bytes from a peer enter here and are validated.

| Crate | External surface | Validated inputs | Notable hardening |
|---|---|---|---|
| `rustgate-transport` | TCP/TLS listener (default port 4433) | mTLS handshake, length-prefixed frames, CoT XML stream, CRL, OCSP staple | `MAX_FRAME_SIZE`, `HANDSHAKE_TIMEOUT`, ACL policy enforcement, dedup, position cache, store-and-forward, ArcSwap hot-reload of verifier and ACL |
| `rustgate-mqtt` | MQTT 5.0 / 3.1.1 broker | CONNECT/SUBSCRIBE/PUBLISH packet parsing, topic filter validation, will-message bytes | `Maximum Packet Size` advertised in CONNACK, DISCONNECT 0x95 on oversize, topic-policy enforcement, retain-store quotas, will-publish audit |
| `rustgate-websocket` | wss:// upgrade | HTTP Upgrade headers, WebSocket frame parsing | mTLS underneath; `ws_frame.rs` fuzz target; `HANDSHAKE_TIMEOUT` applied before upgrade |
| `rustgate-federation` | gRPC tonic V2 (port 9001), length-prefixed V1 (port 9000) | mTLS, JWT (V2), origin-CN cross-check, hop limits | `JwtAuthority` redacted Debug, peer allowlists, circuit breaker per peer, group-claim mismatch audit |
| `rustgate-enrollment` | HTTPS endpoints (CSR sign, EST RFC 7030, PKCS#12 bundle) | HTTP Basic Auth (constant-time), CSR DER parsing, EST request bodies | Rate limiter per IP, CSR fuzz target, file permissions on issued bundles, structured `enrollment_*` audit events |
| `rustgate-http` | Outbound only (egress webhooks) | Response status, signature verification when bidirectional | `AuthState` redacted Debug, HMAC signing, circuit breaker, request retry with jitter |
| `rustgate-nats` | NATS publish/subscribe, optional TLS | Subject string sanitization (NFC + token validation), credentials file | `sanitize_nats_token` defends against Unicode-equivalence subject spoofing; constants for max subject length |
| `rustgate-cot` | XML parsing of CoT events | quick-xml streaming parser, mask/strip-coordinates transforms | `cot_parse.rs` and `cot_mask_strip_coordinates.rs` fuzz targets, delta-encoder soundness checked round-trip |
| `rustgate-asterix` | UDP boundary for surveillance feeds | CAT-021 ADS-B and CAT-062 system-track decoders | `asterix_cat021.rs` and `asterix_cat062.rs` fuzz targets; bounded length/category prefix validation |
| `rustgate-stanag4586` | LOI 2-4 telemetry / command frames | Vehicle-position decoder, sensor-pointing, mission-abort, GCS-handover, route-upload, payload-control | `stanag4586_vehicle_position.rs` fuzz target, frame length bounds, structured rejection on malformed LOI |
| `rustgate-mavlink` | v1 / v2 frame codec | Header signature, payload length, CRC | `mavlink_v2_frame.rs` fuzz target; transport primitives separated from listener wiring |
| `rustgate-authz` | Cedar policy load and evaluation | Policy file syntax, attribute coercion | `authz_policy_parse.rs` and `authz_eval.rs` fuzz targets; dual-hash 128-bit subject cache to defend against adversarial collision |
| `rustgate-proto` | Protobuf XML <-> proto translation | prost decoders, schema validation | `proto_roundtrip.rs` fuzz target; size cap from `MAX_FRAME_SIZE` |
| `rustgate-server` | CLI entrypoint, metrics HTTP, ACL admin API | Argument parsing, ACL admin auth (constant-time) | All listeners pass through `configure_tactical_socket` for keepalive + `TCP_NODELAY` |

## Data Classification Guidance

rustgate is designed for **encryption-in-transit** of tactical and SBU
data. The router itself does not classify or label messages; it
forwards what authenticated peers send and enforces group-based
authorization.

| Classification | Posture | Notes |
|---|---|---|
| Tactical operational data (positions, sensor pointing, vehicle commands, chat) | Supported | Primary design target. mTLS + group ACL is sufficient when CA, CRL, and federation peer allowlists are correctly managed |
| Sensitive But Unclassified / Controlled Unclassified Information (SBU / CUI) | Supported with operator discretion | mTLS + group authz + audit-chain logging + at-rest archive encryption (`--archive-key-file`) provide the defense-in-depth profile expected for CUI-equivalent data. Operators are responsible for the deployment environment (air gap, auditor access, retention) |
| Secret / Top Secret / SCI | **Explicit non-goal** | rustgate does not enforce classification labels, does not perform cross-domain filtering, and does not produce certified audit. Operators handling these classifications must layer cross-domain guards, classification-marking engines (see issue #849), and certified storage in front of and behind rustgate |

When in doubt, the rule is: rustgate provides **transport security and
identity-bound routing**. It does not provide **classification
enforcement, cross-domain control, or certified separation**. The
latter requires accredited components above and below rustgate.

## Known-Safe Deployment Patterns

The patterns below are the configurations the project tests in CI and
recommends for production. Deviations are supported but require the
operator to understand the implications.

### Listener configuration

- mTLS required on every operational listener (TLS 4433, WebSocket
  8443, MQTT 8883, federation 9000/9001).
- CRL configured with `--crl <path>` and reloaded via SIGHUP or the
  CRL refresher.
- `ConnRateLimiter` enabled with a per-IP cap appropriate for the
  expected client population.
- Plaintext listener disabled, or scoped to a synthetic group with no
  ACL overlap to operational groups.

```bash
# Representative production invocation
rustgate-server \
  --tls-bind 0.0.0.0:4433 \
  --tls-cert /run/secrets/server.pem --tls-key /run/secrets/server.key \
  --ca-cert /run/secrets/ca.pem \
  --crl /run/secrets/ca.crl --crl-refresh-secs 300 \
  --acl /etc/rustgate/acl.toml --authz-policy /etc/rustgate/policies.cedar \
  --conn-rate-limit-per-ip 10 \
  --dedup-cache-size 100000 --dedup-ttl-secs 60 \
  --archive-dir /var/lib/rustgate/archive \
  --archive-key-file /run/secrets/archive-keys.json \
  --audit-log /var/log/rustgate/audit.jsonl
```

### Federation

- Peer allowlists explicit. No implicit trust between regions.
- V2 federation enabled when JWT-bound peer assertions are required.
- Per-peer CN pinning via `trust_cert_cn` for high-value peers.
- Federation circuit breaker enabled; `audit::federation_circuit_*`
  events shipped to the central audit sink.

### Logging and audit

- Log sanitization is on by default — there is no opt-out.
- For environments that require tamper-evident audit, enable the
  hash-chained writer (`HashChainWriter` in
  `crates/rustgate-core/src/audit_chain.rs`) and persist the chain
  tip via `write_anchor`.
- Structured `audit::*` calls are emitted at `info` with target
  `audit`; route them to a separate log stream from operational
  `tracing::info`.

### Cryptographic agility

- Default rustls provider for non-FIPS environments.
- `fips` feature for FIPS 140-3 (aws-lc-rs) deployments. See
  [`docs/fips.md`](docs/fips.md).
- Hybrid post-quantum key exchange (X25519MLKEM768) preferred in every
  build, against harvest-now-decrypt-later. See
  [`docs/post-quantum.md`](docs/post-quantum.md).
- All keys held in memory wrapped in `zeroize::Zeroizing<T>`; types
  containing key material implement custom redacted `Debug`.

### Resource sizing

- `jemalloc` feature on Linux for high-connection-count deployments
  (reduces fragmentation under churn).
- Per-tenant quotas configured via `TenantQuotaTracker` for
  multi-tenant or shared-CA environments.
- Backpressure watermarks set so the high watermark is reachable
  before the OS-level send buffer saturates; otherwise the gate is
  ineffective.

## Reporting a Vulnerability

If you discover a security vulnerability in rustgate, please report it
responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, use one of the following methods:

1. **GitHub Security Advisories** (preferred): Navigate to the
   [Security Advisories](https://github.com/rchiofalo/rustgate/security/advisories)
   page and click "Report a vulnerability."
2. **Email**: `security@rustgate.example` (placeholder — substitute the
   maintainer's published contact when distributing this file).

### What to include

- Description of the vulnerability
- Steps to reproduce, ideally with a minimal proof-of-concept
- Affected versions
- Potential impact and any known mitigations or workarounds

### Response timeline

- **Acknowledgment**: within 48 hours
- **Initial assessment**: within 1 week
- **Fix or mitigation**: depends on severity, targeting 30 days for
  critical issues

### What is in scope

- Authentication or authorization bypass
- Certificate validation failures, CRL handling bugs
- Message routing to unauthorized recipients
- Denial of service via resource exhaustion exploitable from a
  pre-authenticated peer or anonymous network position
- Information disclosure (e.g., leaking client identities or positions)
- Injection attacks (XML, command, log forging, subject-string spoofing)
- Cryptographic failures (downgrade, weak parameters, nonce reuse)

### What is generally not a security issue

- Bugs that require local shell access to the server host
- Issues in dependencies that do not affect rustgate's usage of them
- Feature requests for additional security controls (open as normal issues)

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.7.x   | Yes                |
| 0.6.x   | Security fixes only|
| 0.5.x   | No                 |
| 0.4.x   | No                 |
| < 0.4   | No                 |

## At-Rest Encryption

The CoT archive (`--archive-dir`) and JSON audit log (`--audit-log`)
can be encrypted with ChaCha20-Poly1305 by supplying
`--archive-key-file <path>`. Each output file is sealed under a
per-file random nonce using the active key from the supplied JSON
key ring; key rotation is supported by adding new key ids without
removing old ones, so historical files remain decryptable.

Operational guidance:

- Store the key file on a tmpfs or hardware-protected mount; treat it
  with the same care as the server's TLS private key.
- Rotate keys periodically by adding a new id and updating
  `active_key_id`. Old keys must remain in the file until every file
  written under them has been migrated or expired.
- Encryption is independent of full-disk encryption (FDE) and is
  intended for environments that require application-level protection
  (classified, regulated, or multi-tenant deployments). FDE alone does
  not protect against an operator with shell access reading archive
  files.
- Use `rustgate decrypt-archive --in <enc> --out <plaintext> --key-file <path>`
  to export historical files for inspection or backup. The decrypted
  output is plaintext and should be deleted when no longer needed.

### Nonce-collision bound and key rotation cadence

Each encrypted file uses an 8-byte random base nonce concatenated with a
4-byte chunk counter to form the 96-bit ChaCha20-Poly1305 nonce. Because
the base nonce is random rather than a counter, the dominant safety
limit is the birthday bound on the base nonce across files written
under the same key: 2^32 files per key gives a ~50% chance of
collision, 2^16 keeps it below ~2^-32. Recommendation: rotate the
active key before any single key has been used to write more than ~2^16
files (~65k). A future enhancement under consideration is
XChaCha20-Poly1305, whose 24-byte nonce removes the birthday bound as
an operational concern.

---

This document originated from the audit finding tracked as
**IMPROVEMENT-ANALYSIS.md F-29** ("no customer-facing threat model"),
opened as issue #808. The implementation-side discipline used to uphold
the properties above is documented in
[`.claude/rules/shared-infrastructure.md`](.claude/rules/shared-infrastructure.md).
