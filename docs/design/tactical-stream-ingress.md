# Design note: stream-framed tactical ingress (Link 16 / STANAG 4586 / SAPIENT / NFFI) (#1473)

- **Status:** Decisions resolved (security-first) — design only, no code.
  Companion to [`tactical-codec-ingress.md`](tactical-codec-ingress.md)
  (the datagram wave: DIS / ASTERIX / VMF, shipped in #1475/#1476). This
  note extends that effort to the **connection-oriented, stream-framed**
  tactical protocols. Implementation lands as follow-up PRs; a short ADR
  records the seam once the first stream protocol ships.
- **Date:** 2026-06-02
- **Issue:** #1473
- **Author:** rchiofalo

> **Inherited philosophy.** Every security decision from the datagram note
> carries over verbatim — *fail-closed* admission, *default-deny*, a
> *single audited path*, *validate-and-drop with the router's own codec*
> (no parser-differential), *wire identifiers never authorize*, *audit
> every rejection*, shared-crate reuse on a security tie. This note only
> resolves what is *new* about the stream shape: who owns frame
> delimitation, and per-connection (vs per-datagram) admission.

## Problem

The datagram wave gave DIS / ASTERIX / VMF a generic UDP listener where
**one datagram = one message**. The remaining tactical codecs are
**stream-framed** — a single TCP connection carries a continuous byte
stream that must be *delimited* into frames before any per-message decode:

| Protocol | Wire framing | Transport |
|---|---|---|
| **Link 16** (JREAP-C, STANAG 5518) | 16-byte header carrying a body length at a fixed offset | TCP (JREAP-C); multicast (JREAP-A) |
| **STANAG 4586** (UCS) | length-bearing header, frame size payload-dependent | TCP or UDP (deployment-specific) |
| **SAPIENT** (BSI Flex 335) | protobuf varint length-delimited (no magic prefix) | TCP / MQTT / gRPC |
| **NFFI** (STANAG 5527) | XML document boundary (`</nffi>`) | TCP / DDS / SOAP |
| *(Meshtastic)* | compact protobuf over **LoRa / serial** | radio — **out of scope** here |

The crux: **none of these crates ship a stream `Decoder`.** Each exposes
only an `EntityCodec` / `decode(&[u8])` that assumes the caller has
*already* delimited exactly one frame (verified against `link16`,
`stanag4586`, `sapient`, `nffi` `lib.rs`). So the ingress layer must own
frame delimitation — the new work the datagram listener never needed.

## What exists today (verified)

- **Reference TCP listener — MAVLink** (`rustgate-mavlink/src/listener.rs`):
  `accept()` → per-connection task → `BytesMut` accumulator →
  `codec.decode(&mut buf)` loop until `Ok(None)` → `READ_TIMEOUT` guard →
  graceful drain via `Arc<Notify>` → sink callback. This is the
  connection-oriented analogue of the UDP listener and the pattern to
  follow.
- **Generic framing dispatcher** (`rustgate-transport/src/codec.rs`):
  `FramedCodec` implements `tokio_util::codec::Decoder`, dispatching over
  `FramingStrategy::{LengthPrefixed, XmlStream, LineDelimited, TakProtobuf,
  Mavlink}` and yielding delimited `Bytes`. It already covers **NFFI**
  (`XmlStream`) cleanly; it does **not** cleanly cover the others (see D2).
- **Shared admission** (`rustgate-transport/src/udp_common.rs`):
  `UdpAdmission` (CIDR → per-IP rate limit → identity-cap LRU) is keyed by
  peer IP and is reusable **once per connection at accept time**.
- **Per-connection primitives**: `configure_tactical_socket`,
  `READ_TIMEOUT` / `HANDSHAKE_TIMEOUT` constants, `BackpressureGate`
  (per-connection byte quota), `rustgate_resilience::conn_rate_limiter`,
  `SubsystemHandle` for drainable tasks.

## Decisions (resolved — security-first)

### D1 — One generic framed-TCP listener, parameterized by framer + codec

**Decision: a single generic `CodecTcpInput` listener** (sibling to the
datagram `CodecUdpInput`), parameterized by **(a)** a frame *delimiter* —
a `tokio_util::codec::Decoder<Item = Bytes>` — and **(b)** the protocol's
`DynEntityCodec` *validator* (the same instance the router re-decodes
with). Per accepted connection it runs the MAVLink-style read loop:
`read_buf → delimiter.decode → for each frame: EntityCodec validate-and-drop
→ route`. One audited listener for all stream protocols — the guard-lesson
single path, not N hand-rolled read loops that each forget a control.

This keeps the **two responsibilities cleanly split**, mirroring the
existing `FramedCodec` (delimit) vs `Codec`/`EntityCodec` (decode)
separation:

- **Delimiter** owns "where does one frame end in this byte stream" — it
  must be DoS-safe (bounded look-ahead, `MAX_FRAME_SIZE` cap, never buffer
  unboundedly waiting for a terminator).
- **Validator** owns "is this delimited frame a well-formed message" — the
  `EntityCodec`, identical to datagram validate-and-drop.

### D2 — Frame delimitation: reuse where it fits, add a `Decoder` where it does not — RESOLVED

The framing does **not** uniformly reuse the existing `FramingStrategy`
variants. Per protocol:

| Protocol | Delimiter | Why |
|---|---|---|
| **NFFI** | reuse `FramedCodec::XmlStream` | XML document boundary is exactly what `XmlStreamCodec` finds. Zero new framing code. |
| **SAPIENT** | **new** `VarintDelimitedCodec` | Plain protobuf varint length-delimited with **no magic prefix**; `TakProtobuf` requires the `0xBF` magic, so it cannot be reused. A small, well-bounded varint-length `Decoder` (cap the length to `MAX_FRAME_SIZE` *before* allocating). |
| **Link 16** | **new** `Jreap16HeaderCodec` (in `rustgate-link16`) | The body length lives *inside* a 16-byte header at a fixed offset — not a leading length prefix — so no generic variant fits. The crate owns the header parse it already has; the `Decoder` is a thin "read 16 bytes → extract length → await header+body" wrapper. |
| **STANAG 4586** | **new** per-message `Decoder` (in `rustgate-stanag4586`) | Frame size is payload/message-type dependent; the crate must own delimitation because only it knows the per-message length rule. |

**Why protocol crates own their non-trivial delimiters (not a god-enum):**
adding `Link16`/`Stanag4586` arms to the core `FramingStrategy` enum would
drag protocol specifics into `rustgate-core`/`rustgate-transport` and grow
a switch every protocol must touch. Instead, the generic listener takes a
boxed `Decoder<Item = Bytes>`; each crate provides its own (or reuses a
shared `VarintDelimitedCodec` / `XmlStreamCodec`). This is the same
"codec lives in its crate, listener is generic" split the datagram wave
used, applied to delimitation. **Security upside:** the delimiter and the
`EntityCodec` for a protocol live in the *same* crate and are tested
together, so "what the framer hands over" and "what the decoder expects"
cannot drift.

### D3 — Per-connection admission (the new dimension) — RESOLVED

A datagram is admitted per-packet; a TCP connection is admitted **once at
`accept()`**, then trusted for its lifetime — so the controls move to
connection granularity and gain two stream-only guards:

1. **At accept** (before spawning the per-connection task): reuse
   `UdpAdmission::admit(peer.ip())` — CIDR allowlist → per-IP *connection*
   rate limit → identity-cap LRU. Same shared gate, called per-connection
   instead of per-datagram. A rejected peer's socket is closed immediately
   and audited by class.
2. **Concurrent-connection cap** (stream-only): a bounded count of
   simultaneous connections, total and per-IP, so a peer cannot exhaust
   FDs/memory by holding many idle sockets. Reject-not-evict at the cap.
3. **Per-connection liveness + size bounds** (stream-only): `READ_TIMEOUT`
   on each read (a stalled sender cannot park a connection forever — the
   slow-loris defense), the `MAX_FRAME_SIZE` cap enforced **inside the
   delimiter** before allocation, and a per-connection `BackpressureGate`
   byte quota so a fast sender cannot outrun routing.

Identity stays **synthetic and transport-derived** (`<proto>-anonymous`),
exactly as for datagrams; **wire identifiers (Link 16 track numbers,
SAPIENT node UUIDs, …) never enter the CN or any authz input** (D3 of the
datagram note, unchanged). Every frame is still validate-and-drop via the
`EntityCodec`; a connection that sends a single malformed frame has that
frame dropped + audited but is **not** torn down for one bad frame
(connections are long-lived; one bad frame is not necessarily hostile) —
**unless** the malformed-frame rate on a connection crosses a threshold,
which trips a fail-closed disconnect + audit (bounded-garbage defense).

### D4 — Multicast (JREAP-A / STANAG over UDP-multicast) — RESOLVED: reuse the datagram path

Link 16 **JREAP-A** and some STANAG 4586 deployments are UDP-multicast,
not TCP. Those reuse the **existing datagram listener** (`CodecUdpInput` +
the multicast variant) with the protocol's `EntityCodec`, exactly like
DIS/ASTERIX — no new code beyond a delimiter-free `EntityCodec`
registration. Only the **TCP/stream** legs need `CodecTcpInput`. This note
is about the stream legs; the multicast legs are a config line on the
listener that already exists.

### D5 — Config / CLI — RESOLVED: same explicit per-protocol shape

Per-protocol `[ingress.<proto>]` blocks + `--<proto>-bind` flags with
`deny_unknown_fields`, identical to the datagram protocols, plus the two
stream-only knobs (`--<proto>-max-connections`, and the read-timeout which
defaults to the shared `READ_TIMEOUT`). Off by default. To keep the
top-level `Cli` from growing further (it already hit a libtest
thread-stack ceiling at the DIS/ASTERIX/VMF additions, mitigated by
`RUST_MIN_STACK` in CI), the **ingress flags should be flattened into a
`#[command(flatten)]` sub-struct** as part of the first stream PR — the
hygiene fix already queued.

## Threat model & scope boundary

- **Unauthenticated, trusted-network-only** — identical posture to the
  datagram listeners (no mTLS on these legs). The operator gates by group
  ACL/authz; the CIDR allowlist + connection rate/cap + read timeout are
  the only pre-routing controls. Documented in the operator guide.
- **Slow-loris / connection-exhaustion** is the new stream-specific threat
  the datagram path never had; D3's read timeout + concurrent-connection
  cap + per-connection backpressure are its mitigations.
- **Out of scope:** per-message authentication/encryption (none defined by
  these wire formats); the **Meshtastic LoRa/serial** ingress (a radio
  transport, not a socket — a separate note); gRPC SAPIENT (the TCP and
  MQTT legs cover the MVP).

## Proposed PR breakdown

1. **This design note** (docs only).
2. **Generic `CodecTcpInput` + the first stream protocol** — add the
   generic framed-TCP listener (MAVLink-pattern read loop, per-connection
   `UdpAdmission` at accept, connection cap, read timeout, backpressure,
   per-frame validate-and-drop), the shared `VarintDelimitedCodec`, and
   wire **SAPIENT** (cleanest framing) or **NFFI** (zero new framing —
   reuses `XmlStream`) end-to-end. Flatten the ingress `Cli` flags into a
   sub-struct in this PR. Tests: framing boundary cases (split across
   reads, oversized, partial), validate-and-drop, admission, slow-loris
   timeout. Operator-guide + CHANGELOG.
3. **Link 16 (JREAP-C TCP)** — add `Jreap16HeaderCodec` in `rustgate-link16`
   + wire it on the generic listener.
4. **STANAG 4586 (TCP)** — add its per-message `Decoder` + wire it; the
   UDP/multicast leg reuses the datagram listener.
5. **JREAP-A / STANAG multicast** — register on the existing datagram
   multicast listener (no new listener).
6. **ADR** recording D1 (generic framed-TCP seam), D2 (delimiter ownership),
   D3 (per-connection admission), once the first stream protocol ships.

Meshtastic (LoRa/serial) is deliberately excluded — it is a radio
transport, not a socket listener, and earns its own design note.

## Sign-off

Decisions are recorded; this note needs maintainer acknowledgement (not a
re-litigation) before PR 2 begins. The ADR will lift D1–D3 into the
permanent record once the first stream protocol ships.
