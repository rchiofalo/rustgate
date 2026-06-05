# ADR 0023: Tactical codec ingress seam

- **Status:** Accepted
- **Date:** 2026-06-04
- **Deciders:** rchiofalo
- **Related:** #1473 (live network ingress for tactical protocol codecs),
  #1475 (generic UDP listener + live DIS),
  #1476 (ASTERIX + VMF),
  #1482 (generic TCP listener + live SAPIENT),
  #1483 (Link 16 / JREAP-C),
  #1484 (STANAG 4586),
  [`docs/design/tactical-codec-ingress.md`](../design/tactical-codec-ingress.md)
  (datagram design note),
  [`docs/design/tactical-stream-ingress.md`](../design/tactical-stream-ingress.md)
  (stream design note),
  ADR 0013 (`configure_tactical_socket` for every TCP stream),
  ADR 0018 (schema-first codec design)

## Context

rustgate ships codecs for a dozen tactical wire formats (DIS, ASTERIX,
VMF, SAPIENT, Link 16, STANAG 4586, MAVLink, CoT, …), but until #1473 most
existed only as **libraries**: a deployment could decode these protocols
only if some other transport happened to hand them bytes. An operator could
not point a DIS exercise LAN or a SAPIENT sensor at a port and have the
traffic routed. Closing that gap means giving each codec a **live network
ingress**.

The naive shape is one bespoke listener per protocol. That is exactly the
shape to avoid: every listener would re-implement the same security-critical
plumbing — source admission, rate limiting, identity synthesis, audit, frame
bounding — and any one of them getting it subtly wrong is a new attack
surface on an **unauthenticated, unencrypted** path. These ingress legs have
no mTLS by construction (the wire formats carry no transport identity), so
the edge controls *are* the security boundary; they cannot be allowed to
drift per protocol.

The decision is therefore the **shape of the ingress seam** and its
**security model**, taken under a maintainer directive to choose the *most
secure* option first and, only on a security tie, the most efficient /
least-duplicated one. The two design notes hold the full analysis; this ADR
records the load-bearing decisions and why they were selected.

## Decision

**D1 — Two generic, codec-pluggable listeners in `rustgate-transport`, not
per-protocol listeners.** A datagram listener
`codec_ingress::CodecUdpInput` (one datagram = one message) and a
stream listener `codec_tcp_ingress::CodecTcpInput` (a byte stream delimited
into frames) carry *all* protocols. Each is parameterized by a
`DynEntityCodec` (the validating decoder) plus, for TCP, a `FramingFactory`
(`Arc<dyn Fn() -> FramedCodec>`). The **server** owns no socket logic: each
protocol is a few lines in `crates/rustgate-server/src/tactical_ingress.rs`
(`start_dis` / `start_sapient` / …) that fill a `ProtocolIngress` /
`TcpProtocolIngress` struct and hand it to the shared `spawn` / `spawn_tcp`.
Adding a protocol adds *config wiring*, never a new listener.

**D2 — Validate-and-drop at the edge with the *same* codec the router
re-decodes with.** Every datagram / frame is decoded at the boundary with
the identical `DynEntityCodec` instance registered in the router's
`EntityCodecRegistry`. Anything that does not decode to a well-formed entity
is dropped at the edge and audited; it never enters the routing pipeline.
Using the *same* codec at the edge and in the router is the point: it
guarantees there is **no parser differential** — no input the edge accepts
that the router would later reject (or vice-versa), which is the class of bug
that turns a validating boundary into a bypass.

**D3 — Synthetic, transport-derived identity; wire identifiers never reach
authz.** Each accepted message is routed under a synthetic identity
(`<proto>-anonymous-<peer>`). The **destination group is the only trust
decision**, and it is operator-assigned via `--<proto>-group`, never derived
from the wire. Spoofable in-band identifiers — DIS entity/site/application
IDs, Link 16 track numbers, STANAG vehicle IDs — are **never** folded into
the CN or used as an authorization input; they survive only *inside* the
decoded entity, for correlation and dedup. A wire identifier that could
influence an ACL decision is a privilege-escalation primitive on an
unauthenticated port, so the seam forbids it structurally.

**D4 — Mandatory, secure-default admission via one shared gate.** Both
listeners run the *same* `udp_common::UdpAdmission` in the *same* order:
source-CIDR allowlist → per-IP rate limit → synthetic-identity-cap LRU →
size cap (TCP applies the rate limit and identity cap once, at accept, as a
connection-accept rate). Each rejection is audited by class
(`cidr_not_allowed` / `identity_cap_reached` / `datagram_too_large` /
`malformed_*`, plus `security.rate_limited`). The rate limit is **never
truly off**: an unset / `0` `--<proto>-rate-limit-pps` applies the built-in
default (`DEFAULT_INGRESS_MAX_PPS`), not "unlimited" — the opposite of the
legacy plaintext CoT-UDP listener's permissive default. Starting without an
allowlist binds the port but logs a prominent warning.

**D5 — Framing as a length-bounded-before-allocation `FramedCodec` enum.**
Stream framing is a single `tokio_util` `Decoder`/`Encoder` enum
(`LengthPrefixed`, `XmlStream`, `LineDelimited`, `VarintDelimited` for
SAPIENT, `HeaderLength` for Link 16, `TakProtobuf`, `Mavlink`). Every variant
bounds the decoded frame length against `rustgate_core::constants::MAX_FRAME_SIZE`
**before** reserving any buffer, so a hostile length field cannot drive an
allocation. Where the wire header is protocol-owned (`HeaderLength`), the
variant is **decode-only** — `Encoder` returns `Unsupported` rather than
inventing a framing rustgate does not own.

**D6 — TCP gets connection-scoped hardening the UDP path does not need.**
`CodecTcpInput` adds a per-connection slow-loris read timeout
(`READ_TIMEOUT`), a concurrent-connection cap (a `Semaphore`, the
`--<proto>-max-connections` knob), and a deliberate split: a single
malformed *frame* is dropped and audited **without** killing the connection,
while a framing-level error (an un-decodable length prefix — the stream is
now desynchronized) **closes** it. Every accepted stream is run through
`configure_tactical_socket` per ADR 0013.

**D7 — Transport is chosen per protocol; three ingress shapes are deferred,
not designed away.** Datagram protocols bind UDP; connection-oriented
protocols bind TCP. Three cases are explicitly deferred with their reasons
recorded: **stream-framed STANAG 4586** (its frame size is
message-type-dependent — no self-delimiting length prefix — so a stream
needs a per-deployment framing decision; the datagram leg ships in #1484),
**multicast** ingress (ASTERIX/DIS exercise LANs, Link 16 JREAP-A — reuses
the same `UdpAdmission` controls on a multicast listener), and **Meshtastic**
(LoRa/serial — a distinct radio path, not a socket).

## Alternatives considered

- **One bespoke listener per protocol.** Rejected as the primary
  anti-goal. It duplicates admission, rate-limiting, identity synthesis,
  audit, and frame-bounding N times on an unauthenticated boundary, where a
  single copy drifting is a security regression. The generic listener makes
  the edge controls a single, reviewed code path; a new protocol cannot
  *accidentally* ship a weaker boundary.

- **A lighter "looks plausible" pre-check at the edge instead of the full
  codec (D2).** Rejected: any edge validator weaker than the router's real
  decoder reintroduces a parser differential — the exact gap an attacker
  probes. The full decode is not free, but it runs *after* CIDR + rate +
  identity admission has already shed hostile volume, so the cost lands only
  on traffic that already passed the cheap gates.

- **Fold the wire identifier into the CN for traceability (D3).** Rejected:
  it reads as a convenience (per-emitter audit) but makes a spoofable,
  unauthenticated field an authorization input. The decoded entity already
  carries the identifier for correlation without it ever touching authz.

- **Rate-limit off by default, matching the legacy CoT-UDP listener (D4).**
  Rejected: these are *new* exposed surfaces, not a grandfathered one. A
  default of "unlimited" is a footgun on an unauthenticated port; a
  secure-by-default cap that an operator can *raise* is the correct polarity.

- **Listeners in `rustgate-server` instead of `rustgate-transport` (D1).**
  Rejected: sockets, framing, and the admission primitives already live in
  `rustgate-transport`; the server's job is to translate config into a codec
  + group + bind. Keeping the listener in transport lets `rustgate-client`
  and tests reuse it without depending on the server binary.

- **Design the deferred shapes (stream STANAG, multicast, Meshtastic) now
  (D7).** Deferred, not rejected: each has a real open decision (STANAG
  framing is deployment-specific; Meshtastic is a non-socket transport) and
  none requires a wire or config break to add later on top of this seam.

## Consequences

- **A new socket protocol is config, not code.** Register its codec in the
  `EntityCodecRegistry`, add a `start_<proto>` that fills the ingress struct,
  and add the `--<proto>-{bind,group,rate-limit-pps,allowed-cidrs,max-identities}`
  flags (`+ max-connections` for TCP). It inherits admission, identity
  synthesis, audit, frame bounding, and socket hardening for free. STANAG
  4586 (#1484) is the proof: pure server wiring, zero transport change.

- **The edge controls are reviewed once.** `UdpAdmission`, the
  validate-and-drop step, and the `FramedCodec` bounds are single code paths
  exercised by every protocol, so a hardening fix (or an audit-class
  addition) lands everywhere at once.

- **One invariant to hold: edge codec == router codec.** D2's no-differential
  guarantee rests on the edge decoding with the *same* registered
  `DynEntityCodec` the router uses. A future change that gives a protocol a
  separate, lighter edge validator would silently reopen the differential;
  this must be held by review.

- **Unauthenticated by design, and documented as such.** These legs carry no
  transport identity and are gated only by network reachability + CIDR
  allowlist + group ACL. The posture (trusted-segment-only, off by default,
  loud warning without an allowlist) is stated in `docs/tactical-ingress.md`
  and is *not* a substitute for mTLS — protocols needing cryptographic
  identity use the mTLS transports instead.

- **Zero cost when unused.** Every leg is off until its `--<proto>-bind` is
  set; an unconfigured protocol spawns no listener and binds no port.

- **Reversible per protocol.** Each leg is an independent `start_<proto>` +
  flag set + `SubsystemHandle`; removing one is deleting its wiring. The
  generic listeners stay as long as any protocol uses them.
