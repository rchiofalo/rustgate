# Design note: live network ingress for tactical protocol codecs (#1473)

- **Status:** Draft for review — design only, no code. Implementation
  lands as follow-up PRs once the seam below is signed off (the guard
  #1464 → #1457 precedent).
- **Date:** 2026-05-31
- **Issue:** #1473
- **Author:** rchiofalo

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

## Decisions needed (the reason for this note)

### D1 — The generic listener seam

**Proposal: generalize the existing `UdpInput` into a codec-pluggable
listener rather than write N bespoke listeners.** The listener keeps every
existing UDP control (rate limit, CIDR allowlist, identity cap, multicast
variant) and swaps only the *per-datagram decode + tag* step, which is the
sole CoT-specific part today.

Concretely, parameterize the per-datagram step over a small ingress trait
(working name `DatagramIngestCodec`) that the protocol crate implements
(or that adapts the existing `EntityCodec`):

```text
trait DatagramIngestCodec:
    source_protocol() -> &'static str          // "dis" | "asterix" | "vmf"
    message_type()    -> MessageType
    validate(&[u8])   -> Result<(), IngressError>   // see D2
```

The listener then: applies the IP/rate/CIDR gate → `validate`s the
datagram → builds a `RoutableMessage { source: synthetic identity,
payload: raw datagram Bytes, metadata: Metadata::new(now,
codec.source_protocol(), codec.message_type()) }` → emits it on the sink.
The router's existing `EntityCodecRegistry` does the actual `Entity`
extraction downstream — the listener does **not** re-serialize.

This keeps the `transport → cot` coupling out of the generic path (the CoT
listener stays as a thin specialization or a registered ingest codec), and
any future datagram protocol is "implement the trait + register it," not
"write a listener."

**Alternative considered — per-protocol listeners (the literal MAVLink
pattern), one crate + server module each.** Rejected for the datagram
protocols: it is ~8× the network-facing code to secure and maintain, and
it would copy the rate-limit / CIDR / identity-cap logic into every crate
(or force each to depend on `rustgate-transport`). MAVLink earned a
bespoke listener because it has a *unique identity and crypto model* (v2
signing `link_id` = identity, ML-KEM rekey); the datagram protocols here
have **no** per-message identity, so they share one anonymous-identity
seam cleanly. Bespoke listeners remain the right call for the
stream-framed protocols (see Scope).

### D2 — Validate-on-ingress vs pass-through

The listener needs a decode policy. Options:

- **(D2a) Pass-through** — frame the datagram, tag `source_protocol`,
  route the raw bytes; never decode at the edge. Cheapest, but routes
  attacker garbage into the pipeline (the router's lazy decode just fails
  later, after rate-limit accounting and a fan-out attempt).
- **(D2b) Validating decode (proposed)** — run the protocol's cheap
  structural check (`validate`, backed by the `EntityCodec` decode or a
  lighter header parse) and **drop undecodable datagrams at the edge**
  with an audit event, exactly as the MAVLink listener drops bad frames.
  The decoded `Entity` is **discarded**; the router re-decodes via the
  registry for dedup/correlation. One extra decode per accepted datagram,
  but the edge stops malformed/hostile input before it consumes routing
  resources — the right posture for a network boundary.
- **(D2c) Decode-and-attach** — decode once at the edge and attach the
  `Entity` to the message so the router skips re-decode. Fastest steady
  state, but widens `RoutableMessage`/`Metadata` to carry an optional
  pre-decoded `Entity` and couples ingress to the entity shape. Deferred
  as an optimization if profiling shows the double-decode matters.

**Proposed: D2b** — validate-and-drop at the edge, discard the entity,
let the router re-decode. Security-first; revisit with D2c only if the
double-decode is measurable.

### D3 — Identity model (no mTLS)

UDP datagram protocols carry no transport-level authentication. Identity
is therefore **synthetic and per-datagram**, mirroring the CoT UDP path:
`cn = "<proto>-anonymous"` (configurable prefix) under a configured
ingress group. **ACL and authz still apply** to the routed message, so an
operator gates these flows by group exactly as for plaintext CoT. Some
wire formats embed a soft identifier (DIS site/app/entity ID, VMF URN,
ASTERIX track number) — these MAY be folded into the synthetic CN for
correlation/audit, but they are **not** authenticated and must never be
treated as a trust boundary. The threat model below states this.

### D4 — Unicast and multicast

ASTERIX and Link 16 JREAP-A are multicast in real deployments; DIS is
often broadcast/multicast on an exercise LAN. The generic seam must bind
**both** unicast (`udp.rs`) and multicast (`udp_multicast.rs`) — the
multicast path already carries group membership, TTL, loopback, and
rebroadcast controls, so the codec-pluggable step drops into both.

### D5 — Config / CLI

Follow the established per-listener flag + TOML pattern (MAVLink,
SensorThings, guard). Proposed shape — one block per enabled protocol:

```toml
[ingress.dis]
bind = "0.0.0.0:3000"          # unicast; or multicast-group = "239.x.x.x:3000"
group = "dis-feed"             # routing destination group (ACL/authz apply)
rate-limit-pps = 5000
allowed-cidrs = ["10.0.0.0/8"]
max-identities = 1024
```

CLI mirrors it (`--dis-bind`, `--asterix-bind`, `--vmf-bind`, …) so the 12-
factor / env-var story matches every other listener. Whether to expose
one generic `[[ingress]]` array vs per-protocol blocks is an open question
(below).

## Threat model & scope boundary

- **No-mTLS ingress.** These listeners accept unauthenticated datagrams
  from anyone who can reach the port. Identity is synthetic; **the only
  trust controls are the CIDR allowlist, per-IP rate limit, and the
  ACL/authz applied on the routed message.** This is the same posture as
  the existing plaintext/UDP CoT listener and must be documented in the
  operator guide with the same "trusted-network only" guidance.
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
   `UdpInput`/`udp_multicast` over the ingest trait, implement it for the
   three first-wave codecs, add CLI/TOML, wire `start_*` in the server,
   register the routing sink. Tests: a crafted datagram per protocol is
   accepted → routed with the right `source_protocol`; a malformed
   datagram is dropped + audited; the rate-limit / CIDR / identity-cap
   controls behave as for CoT UDP. New `docs/tactical-ingress.md` operator
   guide (with the trusted-network threat-model guidance) + CHANGELOG.
3. **Stream-framed protocols** (Link 16 TCP, STANAG 4586, SAPIENT) — one
   PR per protocol or grouped by transport; reuse the seam where multicast
   applies.
4. **Meshtastic LoRa/serial ingress** — distinct transport, separate PR.
5. **ADR** recording D1 (generic seam), D2 (validate-and-drop), D3
   (synthetic identity / no-mTLS posture), once the first wave lands.

## Open questions for sign-off

1. **D2 decode policy** — validate-and-drop at the edge (D2b, proposed) vs
   pass-through (D2a)? Confirm the security-first default.
2. **Config surface** — per-protocol `[ingress.<proto>]` blocks +
   `--<proto>-bind` flags (proposed, matches every other listener) vs a
   single generic `[[ingress]]` array keyed by `protocol = "..."`?
3. **Ingest trait vs reuse `EntityCodec`** — introduce a thin
   `DatagramIngestCodec` (source_protocol + message_type + validate) or
   have the listener call `EntityCodecRegistry::get(proto)` directly and
   treat a successful `to_entity` as the validation? The latter is less
   new surface but couples ingress validation to full entity decode.
4. **Synthetic CN enrichment** — fold the wire identifier (DIS entity ID /
   VMF URN / ASTERIX track) into the synthetic CN for correlation, or keep
   the CN purely `<proto>-anonymous-<peer>` and let correlation key off the
   decoded `Entity`?
