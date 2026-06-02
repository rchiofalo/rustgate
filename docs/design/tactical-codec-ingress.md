# Design note: live network ingress for tactical protocol codecs (#1473)

- **Status:** Decisions resolved (security-first) — design only, no code.
  All five decisions and the four prior open questions are resolved below
  under the maintainer directive "make the MOST SECURE choices, with
  efficiency." Implementation lands as follow-up PRs (the guard #1464 →
  #1457 precedent); a short ADR records the seam once the first wave ships.
- **Date:** 2026-05-31
- **Issue:** #1473
- **Author:** rchiofalo

> **Guiding principle (resolved).** rustgate's posture governs every
> choice here: *fail-closed* admission, *default-deny*, a *single audited
> ingress path* (the guard lesson — fail-open-by-omission is the enemy),
> *never let unauthenticated wire data influence authorization or identity*
> ("identity from the cert, never from the wire"), *one source of truth*
> for decode, and *audit every rejection*. Where two options were equally
> secure, the tie-break is shared-crate reuse (the guard ADR 0022 rule).

> This is a design note, not an ADR. It exists so the ingress seam and
> its trade-offs are agreed **before** code touches a network-facing
> path. Once the approach is signed off, the implementation lands as one
> or more PRs and a short ADR records the decision.

## Problem

rustgate ships codecs for nine tactical protocols (~40K LOC) but only
**CoT** and **MAVLink** can actually receive and route traffic. The rest
fall into two tiers:

- **Entity-registry-only** — DIS, ASTERIX, STANAG 4586 are registered in
  the `EntityCodecRegistry` (so the router can decode them to a canonical
  `Entity` for dedup / correlation / audit *if* a message is already
  tagged with their `source_protocol`), but **nothing produces those
  tags** because there is no listener for them.
- **Library-only** — Link 16, VMF, SAPIENT, NFFI, Meshtastic have codecs
  and tests but **zero references** in any transport/server/router
  source. They cannot enter the system at all.

Net: a deployment cannot push DIS/ASTERIX/VMF/Link16/SAPIENT/NFFI/
Meshtastic traffic through a running rustgate. This is the "codec breadth
≫ ingress depth" gap. Each codec is the MAVLink #731 story stopped after
the codec PR and before the listener PR.

## What exists today (verified)

### The MAVLink ingress template (reference pattern)

`rustgate-mavlink::listener` + `rustgate-server::mavlink` establish the
pattern every new ingress follows:

1. raw UDP/TCP datagram → framing decode
2. (MAVLink only) v2 signature + replay check → identity from `link_id`
3. build a `RoutableMessage` (`source_protocol`, `MessageType`, synthetic
   or wire-derived `Identity`, payload `Bytes`, `Metadata`)
4. hand off to the router via an `Arc<dyn Fn(RoutableMessage) + Send +
   Sync>` sink (no `listener → router` dependency edge); the server wires
   the sink to `Router::route` and dispatches via `spawn_background`.

### The generic UDP CoT listener (`rustgate-transport::udp`)

`UdpInput` / `UdpInputConfig` already implement everything a no-TLS
datagram ingress needs — but hardcoded to CoT via `rustgate_cot::
MessageBuilder` and tagging `source_protocol = "udp"`:

- **Synthetic identity** — `cn = "udp-anonymous"` (configurable prefix),
  per-datagram, since UDP has no TLS/mTLS.
- **Per-IP rate limit** — `SlidingWindowLimiter` (pps), drops excess.
- **CIDR allowlist** — optional `allowed_cidrs` source filter.
- **Identity cap** — `max_identities` LRU bound so spoofed source IPs
  cannot exhaust memory.
- **Lifecycle** — `run()` binds the socket and loops; integrates with the
  server's `SubsystemHandle` graceful-shutdown set.

A multicast sibling (`udp_multicast.rs`) carries the same controls plus
group-membership and rebroadcast handling (ASTERIX and Link 16 JREAP-A
are multicast in the field).

### The codec trait surface (`rustgate-core`)

- **`Codec`** (`codec.rs`) — frame boundary detection + payload
  encode/decode on raw `Bytes`; `framing()` declares the strategy;
  `detect(prefix) -> f32` scores auto-detection. Used by the TCP session
  layer.
- **`EntityCodec`** / **`DynEntityCodec`** / **`EntityCodecRegistry`**
  (`entity.rs`) — wire bytes ↔ protocol-agnostic `Entity`. The registry
  maps `Metadata.source_protocol` → `Arc<dyn DynEntityCodec>` and is
  already consulted on the router dispatch path (#847) to surface
  `entity_kind` to audit and to feed dedup/correlation. **All eight
  unwired codecs already implement `EntityCodec`.**

## Decisions (resolved — the reason for this note)

### D1 — The generic listener seam — RESOLVED: generalize `UdpInput`

**Decision: generalize the existing `UdpInput` into a codec-pluggable
listener rather than write N bespoke listeners.** The listener keeps every
existing UDP control (rate limit, CIDR allowlist, identity cap, multicast
variant) and swaps only the *per-datagram validate + tag* step, which is
the sole CoT-specific part today.

**Why this is the most secure option, not merely the efficient one.** The
guard work (ADR 0022) established that a *single audited path* is "complete
by construction," whereas N parallel paths are "fail-open by omission" —
every bespoke listener is one more place to forget the rate limit, the
CIDR check, the identity cap, or the audit-on-drop. One hardened ingress
that all datagram protocols share means the controls are written, reviewed,
and fuzzed **once**. Security and efficiency coincide; the reuse tie-break
never has to be invoked.

The per-datagram step is parameterized **not** by a new trait but by reuse
of the existing `EntityCodecRegistry` (see Q3). The listener is constructed
with `(source_protocol_key, message_type, Arc<dyn DynEntityCodec>)` — the
codec instance is the *same* one the router holds, looked up from the
shared registry at startup. Per datagram it: applies the IP/rate/CIDR gate
→ validates by decoding with that codec (D2) → on success builds
`RoutableMessage { source: synthetic identity (D3), payload: raw datagram
Bytes, metadata: Metadata::new(now, source_protocol, message_type) }` →
emits on the sink. The listener does **not** re-serialize and does **not**
attach the decoded entity; the router re-decodes via the registry for
dedup/correlation (single source of routing truth).

**Alternative rejected — per-protocol listeners (the literal MAVLink
pattern), one crate + server module each.** Rejected for the datagram
protocols on *both* security and cost grounds: ~8× the network-facing code
to secure/fuzz/maintain, and it would copy the rate-limit / CIDR /
identity-cap logic into every crate (drift risk — the worst kind for a
security control). MAVLink earned a bespoke listener because it has a
*unique identity and crypto model* (v2 signing `link_id` = identity,
ML-KEM rekey); the datagram protocols here have **no** per-message
identity, so they share one anonymous-identity seam cleanly. Bespoke
listeners remain the right call for the stream-framed protocols (see
Scope), but those too will reuse the same admission controls.

### D2 — Decode policy — RESOLVED: validate-and-drop, validation IS the decode

**Decision: D2b — validate-and-drop at the edge, and the validation is the
*full* `EntityCodec` decode succeeding (not a cheaper structural check).**
A malformed or hostile datagram dies at the boundary, before it consumes
rate-limit budget downstream, a fan-out attempt, or a routing-table touch
— fail-closed admission control, exactly as the MAVLink listener drops bad
frames. The decoded `Entity` is **discarded** at the edge; the router
re-decodes via the registry for dedup/correlation. Every drop emits an
audit event keyed by the masked peer (see Hardening).

Two sub-decisions, both on the secure side:

- **Full decode, not a structural pre-check.** A "cheap header parse"
  could admit a datagram that is malformed-but-plausible at the header and
  only fails deeper in. The strongest edge filter is "does this decode to
  a valid `Entity`?" — if it does not fully decode, it does not enter. The
  decode cost for these protocols is a bounded parse of a single
  small datagram; it is dominated by the syscall, not the parse.
- **Discard-and-re-decode, not decode-and-attach (D2c).** Attaching the
  edge-decoded `Entity` to the message would avoid the router's re-decode,
  but it makes ingress a *trusted producer of entities* and widens a core
  type (`RoutableMessage`/`Metadata`) with an optional pre-decoded entity.
  Keeping the **router as the single source of routing truth** (it alone
  decodes for dedup/correlation/authz-relevant fields) is the cleaner
  security boundary: edge = admission, router = truth. The double-decode
  is the deliberate price. **D2c is deferred as a profiling-gated
  optimization only** — adopted only if the double-decode is ever measured
  to matter on a real workload, and even then behind the same codec so the
  edge and router cannot disagree.

**D2a (pass-through) rejected:** routing attacker-controlled garbage into
the pipeline so the router's lazy decode fails later is the opposite of a
boundary — it spends resources on input we already know how to reject.

### D3 — Identity model (no mTLS) — RESOLVED: synthetic CN only, wire IDs never authorize

UDP datagram protocols carry no transport-level authentication. Identity
is therefore **synthetic and transport-derived**, mirroring the CoT UDP
path: `cn = "<proto>-anonymous"` (configurable prefix, peer folded in the
same bounded/masked way the CoT UDP listener already does, under the
`max_identities` LRU cap) and a single operator-configured ingress group.
**ACL and authz still apply** to the routed message, so an operator gates
these flows by group exactly as for plaintext CoT — that group is the only
trust decision, and it is operator-assigned, never wire-derived.

**Hard line (resolved on Q4): wire identifiers never enter the CN or any
authorization input.** DIS site/app/entity IDs, VMF URNs, and ASTERIX
track numbers are spoofable, unauthenticated bytes. rustgate's first
identity rule is "identity comes from the cert, never from the wire (or
IP)." Folding a wire identifier into the CN would let an attacker-chosen
field steer ACL/authz group matching and forge audit attribution — a
privilege/attribution bypass. So the CN stays purely synthetic; the wire
identifier survives **only** inside the decoded `Entity` (its `id` /
attributes), which correlation and dedup key off, is run through
`sanitize_for_log` before it ever reaches a log line, and is **never** an
ACL/authz key. See Q4 for the full resolution.

### D4 — Unicast and multicast — RESOLVED: both, reusing existing controls

ASTERIX and Link 16 JREAP-A are multicast in real deployments; DIS is
often broadcast/multicast on an exercise LAN. The generic seam binds
**both** unicast (`udp.rs`) and multicast (`udp_multicast.rs`) — the
multicast path already carries group membership, TTL, loopback, and
rebroadcast controls plus the same rate-limit/CIDR/identity-cap, so the
codec-pluggable validate+tag step drops into both unchanged. No new
multicast security surface is introduced; the existing reviewed controls
are reused (the D1 single-path argument again).

### D5 — Config / CLI — RESOLVED: explicit per-protocol blocks, fail-fast

**Decision: per-protocol `[ingress.<proto>]` TOML blocks + `--<proto>-bind`
CLI flags, with `#[serde(deny_unknown_fields, rename_all = "kebab-case")]`
and a `validate()` — matching MAVLink / SensorThings / guard.** The config
*struct* is shared (one `UdpIngressConfig` instantiated per protocol), so
the implementation stays DRY while the surface stays explicit:

```toml
[ingress.dis]
bind = "0.0.0.0:3000"          # unicast; or multicast-group = "239.x.x.x:3000"
group = "dis-feed"             # routing destination group (ACL/authz apply)
rate-limit-pps = 5000          # secure default applied if omitted (Hardening)
allowed-cidrs = ["10.0.0.0/8"] # strongly recommended; loud warn if absent
max-identities = 1024
```

**Why explicit blocks over a generic `[[ingress]]` array (most secure):** a
generic array keyed by `protocol = "..."` invites a silent failure — a typo
`protocol = "dat"` binds a port to nothing (or errors only at runtime),
and it is harder for an auditor to see at a glance which protocols are
exposed on which ports. Named blocks + `deny_unknown_fields` make a
misconfiguration a **startup error** (fail-closed config), and make the
exposed-surface inventory greppable. Off by default — a protocol's ingress
exists only if its `--<proto>-bind` is set (default-deny), exactly like
every other listener. This resolves prior open question Q2.

## Threat model & scope boundary

- **No-mTLS ingress.** These listeners accept unauthenticated datagrams
  from anyone who can reach the port. Identity is synthetic; **the only
  trust controls are the CIDR allowlist, per-IP rate limit, and the
  ACL/authz applied on the routed message.** This is the same posture as
  the existing plaintext/UDP CoT listener and is documented in the
  operator guide with the same "trusted-network only" guidance (PR 2).
- **Wire identifiers are not credentials.** DIS entity IDs, VMF URNs, and
  ASTERIX track numbers are spoofable and must never gate trust — only
  group-level ACL/authz does.
- **Edge validation is a DoS control, not an authn control** (D2b): it
  bounds the work a malformed-input flood can cause, but a valid-looking
  flood is still bounded only by the rate limiter.
- **Out of scope here:** any per-message authentication or encryption for
  these protocols (none is defined by the wire formats; MAVLink-style
  signing does not exist for DIS/ASTERIX/VMF). If a deployment needs
  authenticated transport, it tunnels these over the mTLS/federation legs,
  which is a separate concern.

### Mandatory hardening (resolved)

These are not optional knobs — they are the conditions under which an
unauthenticated ingress is allowed to exist at all:

- **Secure-default rate limit.** Unlike the CoT UDP listener (where the
  rate limit is optional), a tactical-codec ingress applies a non-zero
  `rate-limit-pps` **by default** when the operator omits it; the limiter
  is never simply off. The reason: every one of these ports is an
  unauthenticated amplification/DoS surface, so "no limit" is not a safe
  default.
- **Loud warning without a CIDR allowlist.** If `allowed-cidrs` is unset,
  the listener starts but emits a prominent `warn!` (the #1456 fail-loud
  pattern) naming the exposed protocol/port — an unauthenticated tactical
  feed open to the whole network is a posture the operator must see, not
  discover.
- **Datagram size cap.** Reject any datagram larger than the shared
  `rustgate_core::constants::MAX_FRAME_SIZE` (and any tighter per-protocol
  bound) before decode — no unbounded buffering.
- **Bounded fan-out parse.** Where one datagram may carry many sub-records
  (ASTERIX datablocks, multi-PDU DIS), cap the count parsed per datagram
  so a single packet cannot trigger allocation amplification or a
  fan-out storm. Over-cap datagrams are dropped + audited.
- **Audit every drop class.** CIDR-blocked → `audit::connection_rejected`;
  rate-limited → `audit::security_rate_limited`; malformed/undecodable →
  a `tactical_ingress_rejected`-style audit event. All keyed by
  `mask_ip(peer)` — never the raw peer, never an unsanitized wire field.
- **No panics on hostile input.** Decode is fallible (`Result` + `?`),
  per workspace policy; a fuzz target per first-wave protocol's ingest
  path is part of PR 2.

## Per-protocol applicability

| Protocol | Crate | Wire transport | Framing | First wave? | Notes |
|---|---|---|---|---|---|
| **DIS** | rustgate-dis | UDP (≈3000), often multicast | per-PDU, fixed 12-byte header | **yes** | already in `EntityCodecRegistry`; 1 datagram = 1 PDU |
| **ASTERIX** | rustgate-asterix | UDP, multicast + unicast | datablock (CAT + 16-bit len + FSPEC) | **yes** | already registered; a datagram may carry >1 datablock — split at the edge |
| **VMF** | rustgate-vmf | UDP (≈1581) | bit-stream (FPI/FRI/GPI presence) | **yes** | already registered; 1 datagram = 1 VMF message |
| Link 16 (JREAP-C) | rustgate-link16 | **TCP** 1639 (and JREAP-A multicast) | 16-byte header + body | follow-up | stream-framed: bespoke TCP listener, JREAP-A multicast reuses the seam |
| STANAG 4586 | rustgate-stanag4586 | UDP **or** TCP (deployment-specific) | caller-provided boundaries | follow-up | registered; needs a framing decision per deployment |
| SAPIENT | rustgate-sapient | TCP / MQTT / gRPC | protobuf varint length-prefix | follow-up | stream-framed; MQTT path could reuse the MQTT adapter |
| NFFI | rustgate-nffi | DDS / SOAP / REST | XML document | follow-up | not a datagram protocol; rides the HTTP/DDS legs |
| Meshtastic | rustgate-meshtastic | LoRa mesh / serial | compact protobuf (≤237 B) | follow-up | radio/serial transport — a distinct ingress, not UDP |

The **first wave** (DIS, ASTERIX, VMF) is exactly the set already wired
into the `EntityCodecRegistry`, so end-to-end routing, dedup, and
correlation light up the moment a listener tags their `source_protocol`.

## Proposed PR breakdown

1. **This design note** (docs only) — agree the seam, D2 policy, identity
   model, config shape.
2. **Generic UDP codec ingress + DIS/ASTERIX/VMF** — generalize
   `UdpInput`/`udp_multicast` to validate+tag via a shared
   `Arc<dyn DynEntityCodec>` from the `EntityCodecRegistry` (no new trait),
   wire the three first-wave codecs, add the per-protocol CLI/TOML, wire
   `start_*` in the server, register the routing sink. Tests: a crafted
   datagram per protocol is accepted → routed with the right
   `source_protocol`; a malformed datagram is dropped + audited;
   over-cap/oversized datagrams are dropped; the rate-limit / CIDR /
   identity-cap controls behave as for CoT UDP; a fuzz target per ingest
   path. New `docs/tactical-ingress.md` operator guide (with the
   trusted-network threat-model guidance) + CHANGELOG.
3. **Stream-framed protocols** (Link 16 TCP, STANAG 4586, SAPIENT) — one
   PR per protocol or grouped by transport; reuse the seam where multicast
   applies.
4. **Meshtastic LoRa/serial ingress** — distinct transport, separate PR.
5. **ADR** recording D1 (generic seam), D2 (validate-and-drop), D3
   (synthetic identity / no-mTLS posture), once the first wave lands.

## Resolved decisions (security-first)

All four prior open questions are resolved on the most-secure axis (with
efficiency as the tie-break), per the maintainer directive:

1. **Decode policy (was Q1/D2) — validate-and-drop, and the validation is
   the *full* `EntityCodec` decode.** Malformed/hostile datagrams die at
   the boundary; the decoded entity is discarded and the router re-decodes
   (single source of routing truth). Pass-through (D2a) rejected;
   decode-and-attach (D2c) deferred as a profiling-gated optimization only.
2. **Config surface (was Q2) — explicit per-protocol `[ingress.<proto>]`
   blocks + `--<proto>-bind` flags, `deny_unknown_fields`, off by
   default.** A generic `[[ingress]]` array is rejected because a typo'd
   `protocol` key fails silently; named blocks make misconfiguration a
   startup error and keep the exposed surface greppable. Shared config
   struct, explicit per-protocol instantiation.
3. **Ingest trait vs reuse `EntityCodec` (was Q3) — reuse the
   `EntityCodecRegistry`; no new trait.** The edge validates with the
   *exact same* `Arc<dyn DynEntityCodec>` the router uses, eliminating any
   parser-differential between "what the edge admits" and "what the router
   can decode." Single source of truth and minimal surface — the secure
   *and* DRY choice, so the reuse tie-break and the security axis agree.
   The small per-protocol facts (`source_protocol` key, `MessageType`) are
   plain config, not a trait.
4. **Synthetic CN (was Q4) — never fold wire identifiers into the CN.**
   CN stays purely synthetic/transport-derived; the spoofable wire id
   (DIS entity ID / VMF URN / ASTERIX track) lives only in the decoded
   `Entity` for correlation/dedup, is `sanitize_for_log`-cleaned before
   logging, and is **never** an ACL/authz key. Letting attacker-controlled
   bytes steer authorization or audit attribution is the one line rustgate
   does not cross.

See the Mandatory hardening subsection above for the rate-limit default,
no-allowlist warning, size/fan-out caps, and per-drop-class audit — all
part of "most secure," not optional knobs.

## Sign-off

Decisions are recorded; this note needs maintainer acknowledgement (not a
re-litigation of the four questions) before PR 2 begins. The ADR (PR 5)
will lift D1–D3 and the hardening invariants into the permanent record
once the first wave ships.
