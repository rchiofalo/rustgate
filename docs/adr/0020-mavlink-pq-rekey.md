# ADR 0020: MAVLink integration with ML-KEM-768 rekey channel

- **Status:** Proposed
- **Date:** 2026-05-22
- **Deciders:** rchiofalo
- **Related:** #731 (MAVLink + PQ umbrella),
  ADR 0019 (CNSA 2.0 with Composite ML-DSA hybrid certificates),
  ADR 0009 (Zeroizing + subtle for secrets),
  ADR 0013 (tactical TCP socket hardening),
  ADR 0015 (encrypted archives — ChaCha20-Poly1305 wire-format precedent),
  [FIPS 203](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf) (ML-KEM),
  [MAVLink v2 signing spec](https://mavlink.io/en/guide/message_signing.html)

## Context

`rustgate-mavlink` already ships a hand-rolled v1/v2 frame codec, a
`MavlinkEntityCodec` that crosswalks frames to the protocol-agnostic
`Entity` shape (refs #847), and CLI flags `--mavlink-require-signing` /
`--mavlink-allow-v1` with default-secure values. The remaining five PRs
in #731 — UDP/TCP listener, HMAC signing, ML-KEM-768 rekey channel,
obligations, server wiring — depend on a set of design questions that
are not answered by the existing CLI flags or by ADR 0019. Before code
lands, those questions need a written commitment so the five PRs can be
reviewed against a single moving target rather than re-litigated
individually.

Three forcing functions:

1. **Identity over UDP.** rustgate is mTLS-identity end-to-end. MAVLink
   over UDP has no TLS, so a new identity primitive is required —
   without it the Router cannot apply ACL or authz to MAVLink traffic
   and the integration is "wide-open ingress with policy bypass," which
   is worse than no integration at all.
2. **Post-quantum forward secrecy.** MAVLink v2 signing keys are
   symmetric 32-byte values. Operators today distribute them
   out-of-band (USB, scp, K8s secret) and rotate manually. An attacker
   who records the bootstrap-time distribution channel can recover
   today's traffic in 2035 once classical ECDH is broken. The CNSA 2.0
   target (ADR 0019) demands a PQ-secured distribution story.
3. **Algorithm agility.** CNSA 2.0 §4 expects an algorithm identifier
   on every PQ wire envelope so ML-KEM-768 → ML-KEM-1024 (Level 3 →
   Level 5) can land without breaking interop. The MAVLink rekey
   envelope is the first PQ-only wire format in the codebase and sets
   the precedent for #501/#502/#503.

`aws-lc-rs 1.16.3` is already in `Cargo.lock` and exposes
`kem::ML_KEM_768` as a stable, FIPS 203-aligned API. No new external
dependency is required to implement this ADR; the existing
`chacha20poly1305`, `hkdf`, `hmac`, `sha2`, `subtle`, and `zeroize`
workspace crates cover the rest.

## Decision

**rustgate will implement MAVLink integration with the wire-format
commitments below.** The decision answers seven distinct design
questions; each one is binding on the five remaining code PRs in #731.

### 1. UDP MAVLink identity is the v2 signing `link_id`

MAVLink v2 frames carry a 1-byte `link_id` in the signing block. The
listener treats each `link_id` as a separate identity, keyed by a
TOML-defined link manifest:

```toml
[mavlink.links]
# link_id (1 byte) → identity + signing key
[mavlink.links.0x42]
cn = "drone-007"
groups = ["tactical/uav", "ops/team-alpha"]
signing_key_hex = "…64 hex chars…"      # 32-byte HMAC-SHA256 key
```

The manifest path is `--mavlink-signing-key-file`. The file is loaded
at startup, the entire content wrapped in `Zeroizing<String>` until
keys are extracted into `Zeroizing<[u8; 32]>` slots. Manifest reload on
SIGHUP follows the existing ArcSwap hot-reload pattern (ADR 0003).

**MAVLink v1 ingress is rejected by default.** v1 has no native signing
and therefore no identity primitive. Operators who must accept v1 set
`--mavlink-allow-v1` (already present) AND configure a
`--mavlink-v1-fallback-cn` (added in PR 2); the fallback CN is then
shared across all v1 traffic from that listener, with a startup
warning + audit event documenting the degraded identity posture.

### 2. Destination is per-listener configuration

The listener config carries the target `Destination`. Frames from a
given listener route as that destination:

```toml
[[mavlink.listeners]]
bind = "0.0.0.0:14550"
protocol = "udp"
destination = { kind = "group", value = "tactical/uav" }
```

Supported `destination.kind` values: `group`, `broadcast`. `direct` and
`multicast` are rejected at config parse — neither has a sensible
mapping for telemetry. This is the **only** decision the operator
makes about how MAVLink frames enter the routing graph; system_id and
component_id are not consulted for routing.

CLI flag form: `--mavlink-bind ADDR:PORT --mavlink-group GROUP_ID`
maps to a single-listener config equivalent to the above. Multiple
listeners require the TOML form.

### 3. Replay protection: bounded LRU per (system_id, component_id, link_id)

Timestamp HWMs are stored in a per-listener
`HashMap<(u8, u8, u8), u64>` with LRU eviction. The bound is
`--mavlink-replay-cache-size` (default 1024 entries). Eviction policy:
oldest-not-touched, evaluated lazily on insert when the cache is at
capacity. Eviction is **not** a security event — when an entry is
evicted, the next frame from that tuple is admitted as the new
baseline. Operators who want stricter behavior raise the cap.

The 8-byte MAVLink v2 timestamp counts 10-µs intervals since 2015-01-01
UTC and is monotonic per-tuple. We require strict greater-than (>) for
admission. Wraparound is not a near-term concern (2.92 million years
at 10 µs granularity).

### 4. ML-KEM-768 wrap with HKDF + ChaCha20-Poly1305

Algorithm choice: **ML-KEM-768** (FIPS 203 Level 3-equivalent) via
`aws-lc-rs::kem::ML_KEM_768`.

ML-KEM-1024 (Level 5) is rejected at this layer because the 1568-byte
ciphertext fragments at typical tactical-network MTUs (1500 bytes) and
the rekey envelope is sent over UDP in PR 4. CNSA 2.0 §4 admits Level 3
hybrid as the transitional target; a future ADR can migrate to ML-KEM-1024
by allocating a new algorithm-id byte (see §5 below).

Wrap key derivation:

```text
shared_secret  = ML-KEM-768::decapsulate(bootstrap_decap_key, mlkem_ct)
                 // 32 bytes
wrap_key       = HKDF-SHA256(
                    salt = bootstrap_secret,           // 32 bytes from disk
                    ikm  = shared_secret,
                    info = "rustgate-mavlink-rekey-v1",
                    length = 32 bytes)
```

The bootstrap secret is **only** used as the HKDF salt — it
authenticates the wrap (an attacker without it cannot derive
`wrap_key` even with a valid ML-KEM ciphertext) but is not the session
key. Forward secrecy is guaranteed by ML-KEM: compromising the
bootstrap secret tomorrow does not reveal past session keys, because
those derive from ephemeral ML-KEM decapsulations.

### 5. Wire format with algorithm-id prefix

The MAVLink rekey envelope is a single contiguous byte sequence:

```text
offset  size      field
------  --------  -------------------------------------------------
0       1         algorithm_id   (0x01 = ML-KEM-768)
1       1088      mlkem_ct       (ML-KEM-768 ciphertext)
1089    12        nonce          (ChaCha20-Poly1305 nonce, random)
1101    var       aead_ct        (encrypted MavlinkRekeyPayload)
1101+N  16        aead_tag       (ChaCha20-Poly1305 tag, appended)
```

`MavlinkRekeyPayload` (CBOR-encoded inside the AEAD ciphertext):

```text
- timestamp:   u64    (10-µs since 2015-01-01, same epoch as MAVLink v2)
- link_id:     u8     (target signing slot)
- new_key:     [u8;32]  (new HMAC-SHA256 signing key)
- key_epoch:   u32    (monotonic per link_id, replay defense)
```

AAD over the ChaCha20-Poly1305 step is the 1-byte `algorithm_id`
concatenated with `SHA-256(mlkem_ct)[:8]` — binds the wrapping to a
specific KEM output and to the algorithm slot. Defense in depth against
algorithm confusion attacks; a future migration to ML-KEM-1024 changes
`algorithm_id` and the AAD shape, refusing cross-version replay.

Algorithm-id allocation table:

| ID | Algorithm | Status |
|----|-----------|--------|
| `0x00` | reserved | rejected at parse |
| `0x01` | ML-KEM-768 + HKDF-SHA256 + ChaCha20-Poly1305 | this ADR |
| `0x02` | ML-KEM-1024 + HKDF-SHA384 + ChaCha20-Poly1305 | future ADR |
| `0x03–0x7F` | reserved | unassigned |
| `0x80–0xFF` | vendor / experimental | rejected by default |

### 6. Bootstrap secret provisioning

Operator provides a single 32-byte secret in a file on disk, mode 0400,
loaded at startup via `--mavlink-pq-bootstrap-file`. The file contains
the raw 32 bytes — no header, no PEM, no JSON. `std::fs::read` →
`Zeroizing<Vec<u8>>` → length check → copy into
`Zeroizing<[u8; 32]>`. SIGHUP reloads the file via ArcSwap.

Provisioning is **out of band**. Initial deployment options recognized
in the operator docs:

- **Production:** Kubernetes Secret mounted as a tmpfs file, or a
  SPIFFE-bridged Workload API path (future, not in MVP).
- **Field:** USB transfer, in-person handoff, mode-0400 file on the
  rustgate host.
- **Lab:** any source; the audit log records the file path and load
  time but not the contents.

Bootstrap rotation cadence is operator-controlled. The audit event
`mavlink_pq_bootstrap_loaded` fires on load with the file's SHA-256
fingerprint (truncated to 64 bits) so a rotation can be observed in
the audit trail without exposing the secret.

### 7. Outbound cross-protocol drop is honest-silent

`MavlinkEntityCodec::encode` already returns
`MavlinkEntityError::UnsupportedEntityKind` for non-Position entities
(CoT chat, alerts, free-form messages). On the MAVLink egress path:

- The Router PEP catches the error.
- Frame is dropped (not delivered).
- Audit event `mavlink_egress_unsupported` fires once per drop, with
  the source CN and entity kind.
- Metric `rustgate_mavlink_egress_dropped_unsupported_total{kind=…}`
  increments.

Operators get observability into the gap without any silent fallback
to a "stub HEARTBEAT" frame. A future flag could add the stub fallback
opt-in, but the MVP default is honest-drop because the alternative
(emitting a HEARTBEAT in place of a chat message) is confusing
operational behavior.

## Alternatives considered

- **TLS-over-UDP for MAVLink (DTLS).** DTLS 1.3 is the natural answer
  but rustls does not yet ship a DTLS implementation. Bolting a
  separate DTLS stack would add a second TLS provider to the workspace
  (ADR 0xxx workspace policy: rustls is the only TLS provider).
  Revisit when rustls ships DTLS upstream.

- **ML-KEM-1024 instead of ML-KEM-768.** Higher security margin (NIST
  L5) but the 1568-byte ciphertext fragments on tactical 1500-byte MTU
  networks, and CNSA 2.0 §4 admits Level 3 hybrid as the transitional
  target. The algorithm-id byte means we can migrate without a wire
  break.

- **X25519MLKEM768 hybrid (matching rustls TLS).** Reasonable for the
  TLS handshake path (ADR 0019) but unnecessarily complex for a
  symmetric-key distribution channel where the classical fallback path
  adds attack surface (an adversary who breaks X25519 today can
  forge rekeys) without proportional benefit. Pure ML-KEM-768 here.

- **Per-frame signature instead of HMAC.** MAVLink v2 signing is
  HMAC-SHA256 by spec — adopting a non-spec signature scheme (Ed25519,
  ML-DSA) would mean rustgate can't talk to off-the-shelf MAVProxy /
  PX4. HMAC-SHA256 stays for wire compatibility; ML-KEM-768 secures
  the key distribution rather than the per-frame signature.

- **Reuse the audit-log encryption keys (ADR 0015) as bootstrap.**
  Tempting because the same key-loading machinery would apply.
  Rejected because the audit-log keys are long-lived archive-scope and
  conflating them with per-link MAVLink rekey would couple two
  unrelated rotation cadences.

- **MAVLink v1 as first-class.** Rejected by default. v1 has no
  signing primitive; admitting it as a first-class identity-bearing
  protocol would force a "trust the network" model that contradicts
  the rest of rustgate. The `--mavlink-allow-v1` escape hatch is
  retained for lab and legacy environments with a clear startup
  warning.

## Consequences

**What the codebase looks like after the five #731 code PRs:**

- `rustgate-mavlink::signing` module with `SigningKeyStore`,
  `verify_v2_signature`, `sign_v2_frame`, per-tuple replay HWM cache.
- `rustgate-mavlink::rekey` module with the wire-format
  encode/decode, ML-KEM-768 wrap/unwrap, HKDF, ChaCha20-Poly1305 AEAD.
- `rustgate-mavlink::listener::{udp, tcp}` modules.
- `rustgate-mavlink::obligations` with `MaskPoint`, `MaskPayload`,
  `MaskCommand` actuators.
- Three new CLI flags: `--mavlink-bind`, `--mavlink-signing-key-file`,
  `--mavlink-pq-bootstrap-file`. Existing `--mavlink-require-signing`
  and `--mavlink-allow-v1` retain their current semantics.
- Six new audit events: `mavlink_signature_rejected`,
  `mavlink_replay_rejected`, `mavlink_v1_admitted`,
  `mavlink_egress_unsupported`, `mavlink_pq_bootstrap_loaded`,
  `mavlink_pq_rekey_completed`.
- Eight new Prometheus metrics (per-link counts, signature failures,
  replay rejections, rekey events, dropped egress, replay-cache size).
- `docs/mavlink.md` operator guide referencing this ADR.

**New constraints on future work:**

- Any change to the rekey wire format must allocate a new
  `algorithm_id` byte and ship as a new ADR. The byte-offset table in
  §5 is load-bearing.
- New PQ-only wire formats elsewhere in the workspace (e.g. the
  ML-DSA-65 package signature in K3) should follow the same
  algorithm-id-prefix convention. This ADR sets the precedent.
- The MAVLink v1 fallback CN cannot be a real client CN — it must be
  a configured shared identity. Documentation must call this out.

**What is now harder:**

- Operators wanting MAVLink ingestion must understand the link manifest
  + bootstrap secret model. This is a higher operational burden than
  "open a UDP port" — by design.
- Adding a third MAVLink listener variant (e.g. serial line, custom
  framing) means deciding how the new transport plumbs the identity
  primitive — the link_id-as-identity model is wire-format specific.

**What is now easier:**

- The five #731 code PRs each have a single source of truth for design
  decisions. Reviewers can hold "is this consistent with ADR 0020?" as
  the bar.
- A future MAVLink + ML-DSA path (sign individual frames with ML-DSA
  instead of HMAC) inherits the algorithm-id-byte convention.
- A future CNSA 2.0 Level-5 upgrade for the rekey channel is a single
  algorithm-id allocation, not a wire-format break.

**Migration path.** If the upstream MAVLink spec adopts a different
signing primitive (e.g. Ed25519 in v3), this ADR's body remains the
historical record and a new ADR supersedes. The wire-format
algorithm-id reservation table extends to accommodate the new
identifier; old rustgate releases reject the unknown byte at parse and
the operator sees a clean "algorithm not supported" diagnostic.
