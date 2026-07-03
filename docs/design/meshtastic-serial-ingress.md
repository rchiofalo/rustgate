# Design note: Meshtastic LoRa / serial ingress (#1491)

- **Status:** Decisions surfaced — design only, one genuine transport fork
  left **open** for the maintainer. Companion to
  [`tactical-codec-ingress.md`](tactical-codec-ingress.md) (the datagram
  wave: DIS / ASTERIX / VMF) and
  [`tactical-stream-ingress.md`](tactical-stream-ingress.md) (the
  stream-framed wave: Link 16 / STANAG 4586 / SAPIENT / NFFI). Those two
  notes each explicitly deferred Meshtastic — the datagram note's
  PR-breakdown item 4 ("**Meshtastic LoRa/serial ingress** — distinct
  transport, separate PR") and the applicability table row ("radio/serial
  transport — a distinct ingress, not UDP"). This note picks that thread
  up. Implementation lands as follow-up PRs; ADR 0032 records the seam once
  the transport fork below is signed off.
- **Date:** 2026-07-03
- **Issue:** #1491
- **Author:** rchiofalo

> **Inherited philosophy.** Every security decision from the two prior
> ingress notes carries over verbatim — *fail-closed* admission,
> *default-deny* (a listener exists only if its bind/port is explicitly
> configured), a *single audited path*, *validate-and-drop with the
> router's own codec* (no parser-differential), *wire identifiers never
> authorize* ("identity comes from the cert, never from the wire"), *audit
> every rejection*, shared-crate reuse on a security tie. This note resolves
> only what is **new** about the Meshtastic shape: the transport itself
> (LoRa mesh over a local serial radio, not an IP socket), who owns
> mesh-frame de-encapsulation and link-layer decryption, and — because the
> transport is not IP — a **non-IP admission model**, since the shared
> `UdpAdmission` gate is keyed on the source `IpAddr`.

## Problem

`rustgate-meshtastic` ships a pure codec (`codec.rs` / `proto.rs`) for the
Meshtastic `TAKPacket` compact-protobuf application payload and implements
the canonical `EntityCodec` trait, so the codec **is** registered in the
`EntityCodecRegistry` (the router can decode a Meshtastic-tagged message for
dedup / correlation / audit). But — exactly like the library-only tier in
the datagram note before #1475 — **nothing produces that tag**: there is no
listener, no `start_meshtastic` in `tactical_ingress.rs`, and no transport
that turns a physical mesh radio into `RoutableMessage`s. A deployment
cannot point rustgate at a Meshtastic radio and route its traffic.

Meshtastic is materially different from every protocol handled by the two
prior notes, and those differences are *why* it was deferred, not an
oversight:

1. **The transport is a local serial device, not an IP socket.** A
   Meshtastic node is a LoRa radio reached over USB/UART (a serial port) or,
   in some field kits, over a small TCP/UDP "bridge" the radio's companion
   firmware exposes. The datagram/stream seams both start from
   `TcpListener` / `UdpSocket`; neither reads a `/dev/tty*` serial device.

2. **The application payload is wrapped in a mesh-frame envelope the codec
   deliberately does not parse.** `lib.rs` is explicit under "What is
   deliberately absent": the Meshtastic mesh-frame envelope (PHY header,
   routing fields, **AES key-wrap / link-layer encryption AAD**) is the
   *transport's* responsibility; the codec consumes only the inner decrypted
   `TAKPacket` bytes. So an ingress cannot just hand raw radio bytes to the
   codec — something must first de-encapsulate the mesh frame and decrypt
   the link-layer payload.

3. **There is no source IP to key admission on.** `UdpAdmission`
   (`udp_common.rs`) — the shared CIDR-allowlist + per-IP rate-limit +
   per-IP identity-LRU gate that both prior seams reuse — is keyed on the
   datagram's source `IpAddr`. A serial radio has no source IP; a mesh
   sender is identified by a Meshtastic **node ID** (a spoofable wire field,
   which under D3 must *never* authorize). The admission model has to be
   re-keyed on something the transport actually has.

## What exists today (verified)

- **Codec + registry.** `rustgate-meshtastic` = `codec.rs` (`EntityCodec`
  impl), `proto.rs` (typed `TakPacket` / `Pli` / `GeoChat`, symmetric
  `decode_tak_packet` / `encode_tak_packet` over `&[u8]`), `error.rs`
  (`MeshtasticError`, thiserror, `#[non_exhaustive]`, no panics). No I/O.
- **Registry wiring done.** The codec is constructed and registered in the
  `EntityCodecRegistry` (per #1530), so the *decode* half of end-to-end
  routing already exists — only the ingress that produces the
  `source_protocol` tag is missing.
- **No transport dep.** The workspace `Cargo.toml` carries **no**
  `tokio-serial` / `serialport` dependency, and `deny.toml` has no entry
  for one. Adding a serial dep is a supply-chain decision that needs a
  `cargo deny` review — it is *out of scope for this note* and belongs to
  the follow-up implementation PR.
- **The two ingress seams.** The generic datagram listener
  (`codec_ingress::CodecUdpInput`) and stream listener
  (`codec_tcp_ingress::CodecTcpInput`) both live in `rustgate-transport`,
  are parameterized by a `DynEntityCodec` from the shared registry, and
  reuse `UdpAdmission` / the TCP admission path. **A serial transport reuses
  the *validate-and-drop + synthetic-identity + audit* half of that seam but
  not the socket half.**

## Decisions

### D1 — Transport source — **OPEN FORK, deferred to the maintainer**

This is the one genuine, un-pre-committed decision in this note. There are
two defensible transports, and they trade a new supply-chain dependency
against a wire-contract we own:

- **D1a — Direct serial reader (`tokio-serial`).** rustgate opens the
  radio's serial device (`/dev/ttyUSB0`, `COM3`, …) directly, speaks the
  Meshtastic serial framing (the firmware's `0x94 0xc3` magic +
  16-bit length prefix wrapping a `FromRadio` protobuf), de-encapsulates the
  mesh frame, and decrypts the link-layer payload (D2). *Pros:* no extra
  process in the field kit; the radio plugs straight into the host.
  *Cons:* a **new `tokio-serial` workspace dependency** (pulls `serialport`
  + `nix`/`libudev` on Linux, platform `serialport` glue on macOS/Windows) —
  a supply-chain surface that must clear `cargo deny`; platform-specific
  device enumeration; and rustgate now owns the Meshtastic serial framing +
  AES link-layer crypto (D2), a non-trivial security-sensitive parser on an
  **unauthenticated** input.

- **D1b — Defined "Meshtastic bridge" wire contract (UDP/TCP).** rustgate
  defines a small, documented bridge contract: an external adapter (the
  Meshtastic Python/`meshtasticd` companion, or a thin field-kit shim)
  owns the serial device, de-encapsulates + decrypts the mesh frame, and
  forwards **already-decrypted `TAKPacket` payloads** to rustgate over a
  local UDP or TCP socket. rustgate then reuses the **existing** datagram or
  stream ingress seam almost verbatim — the codec is already registered; the
  only new work is a Meshtastic `source_protocol` tag and the non-IP
  admission twist (D3). *Pros:* **zero new dependency**; the serial +
  link-layer-crypto surface lives in a separate, replaceable process
  (defense in depth — a serial-parser bug cannot crash the router);
  reuses a seam that is already written, reviewed, and fuzzed. *Cons:* an
  extra process in the field kit; a bridge contract to document and version;
  the operator must run the bridge.

**Recommendation (non-binding).** D1b (bridge contract) is the more secure
*and* the lower-blast-radius choice by the two prior notes' own tie-break
rules: it adds **no** supply-chain dependency, keeps the security-sensitive
serial/AES parsing out of the router process, and reuses an already-hardened
ingress seam rather than writing a new socket path. D1a's single advantage
is "one fewer process," which is an ergonomics win, not a security one. But
this is a genuine field-ergonomics-vs-supply-chain trade the maintainer
owns — the scaffold in this branch commits to **neither**, and adds **no**
dependency, precisely so the fork stays open. **ADR 0032 records this as
`Deferred`, not decided**, until sign-off.

### D2 — Mesh-frame de-encapsulation + link-layer AES decryption — RESOLVED: transport-owned, out of the codec

Wherever the bytes are read (D1a serial or D1b bridge), the component that
owns the physical radio also owns **mesh-frame de-encapsulation and
link-layer AES decryption**, and the codec keeps consuming only the inner
decrypted `TAKPacket`. This is not a new decision so much as the codec's
existing contract (`lib.rs` "What is deliberately absent") made load-bearing:

- Under **D1a**, that component is a new module *inside* rustgate — so the
  serial reader must hold the channel's pre-shared AES key
  (`Zeroizing`-wrapped, per the workspace secret rule) and decrypt before
  handing the plaintext `TAKPacket` to the codec.
- Under **D1b**, that component is the external bridge — the AES key never
  enters rustgate at all, which is the stronger key-handling posture.

Either way the codec crate stays a pure, I/O-free, key-free decoder. The
edge still **validates-and-drops** by running the full `EntityCodec` decode
(D2b from the datagram note) on the decrypted payload; a payload that does
not decode to a valid `Entity` never enters, and the drop is audited.

### D3 — Non-IP admission model — RESOLVED: re-key the gate on the transport channel, never on the node ID

`UdpAdmission` is IP-keyed; a serial radio has no IP. The admission model is
re-keyed on **the ingress channel the operator configured**, not on any wire
field:

- **Rate limit + fan-out cap are per-ingress (per-configured-source), not
  per-peer.** A single serial device / bridge socket is *one* configured
  ingress; its whole stream shares one operator-set `rate-limit-pps` budget
  (a secure non-zero default when omitted, as in the datagram note's
  mandatory hardening) and the shared `MAX_FRAME_SIZE` / bounded-fan-out
  caps. There is no per-source-IP LRU because there is no source IP; the
  identity-cap dimension collapses to "this one configured ingress."
- **Under D1b the bridge socket still gets the IP controls.** If the bridge
  forwards over UDP/TCP, the existing `UdpAdmission` CIDR allowlist +
  per-IP rate limit still apply to the bridge's socket (bind it to
  loopback / a pinned bridge host), giving back the IP-keyed layer for free
  on top of the per-ingress budget.
- **The Meshtastic node ID is a decoded-`Entity` attribute, never an
  admission or ACL/authz key.** Exactly as DIS entity IDs / VMF URNs are
  handled (datagram note D3 / Q4): the spoofable mesh node ID survives only
  inside the decoded `Entity` for correlation/dedup, is `sanitize_for_log`
  -cleaned before any log line, and is **never** folded into the CN or any
  authorization input. The synthetic CN stays `cn = "meshtastic-anonymous"`
  (configurable prefix) with a single operator-assigned ingress group that
  ACL/authz gate on — the only trust decision, operator-assigned, never
  wire-derived.

### Config shape (follows the prior notes, not re-litigated)

An explicit `[ingress.meshtastic]` TOML block + `--meshtastic-*` CLI flag,
`#[serde(deny_unknown_fields, rename_all = "kebab-case")]`, off by default —
identical discipline to the datagram note's D5. The block's transport keys
depend on the D1 fork (a `serial-device` path for D1a vs a `bridge-bind`
socket for D1b); the scaffold's `MeshIngressConfig` carries the
transport-agnostic fields (group, rate limit, ingress key) now and leaves
the transport-specific field for the implementation PR once D1 is chosen.

## Threat model & scope boundary

- **Unauthenticated ingress.** A Meshtastic feed carries no transport
  identity rustgate can trust; the mesh link-layer AES key authenticates the
  *channel*, not a per-message sender rustgate can map to a cert. Identity is
  synthetic (D3); the only trust controls are the per-ingress rate/fan-out
  caps, the ACL/authz on the routed message, and — under D1b — the bridge
  socket's CIDR allowlist. Same "trusted-network / trusted-bridge only"
  posture the operator guide documents for the other no-mTLS legs.
- **The mesh node ID is not a credential.** Spoofable; correlation/dedup
  only; never gates trust.
- **Link-layer AES key handling** (D1a only) must use `Zeroizing`;
  constant-time compares are not relevant (it is a decryption key, not a
  compared secret), but the key must never be logged and must live behind a
  redacted `Debug`. D1b keeps the key out of rustgate entirely — the
  stronger posture, and one input to the D1 recommendation.
- **Out of scope here:** the live serial reader / bridge listener itself
  (the follow-up PR gated on D1), any Meshtastic firmware admin/control
  frames (rustgate ingests position + chat + detail only), and the goTenna
  Pro X2 binding (`lib.rs` documents it as codec-compatible; a separate
  follow-up).

## Proposed PR breakdown

1. **This design note + ADR 0032 + a compile-safe scaffold** (this PR) —
   agree the seam, surface the D1 fork, and land the first real slice: a
   feature-gated (`meshtastic-ingress`, off by default) stub
   `transport.rs` in `rustgate-meshtastic` defining the ingress-config
   type (`MeshIngressConfig`), the `MeshIngressError` thiserror enum, and
   the non-IP admission-key type (`MeshIngressKey`). **No I/O, no new
   dependency, no live wiring** — the stub compiles with and without the
   flag and does nothing at runtime.
2. **Live transport** (gated on the D1 sign-off) — implement the chosen
   transport (D1a serial reader **or** D1b bridge listener), wire
   `start_meshtastic` in `tactical_ingress.rs`, add the `[ingress.meshtastic]`
   config + CLI, register the routing sink, add the operator-guide section.
   Under D1a this PR is where `tokio-serial` enters the workspace
   `Cargo.toml` + `deny.toml` (with a `cargo deny` review). Tests mirror the
   datagram note's PR 2 set: a crafted payload is accepted → routed with
   `source_protocol = "meshtastic"`; a malformed/undecodable payload is
   dropped + audited; over-cap / oversized payloads are dropped; the
   per-ingress rate/fan-out caps behave; a fuzz target on the ingest path.
3. **goTenna Pro X2 binding** — separate follow-up, codec already
   documented as compatible.

## Sign-off

The one open decision (**D1 — serial reader vs bridge contract**) needs a
maintainer call before PR 2 begins; D2 and D3 are resolved on the
most-secure axis and inherited from the two prior notes. ADR 0032 records
D2 (transport-owned de-encapsulation/decryption) and D3 (non-IP admission,
node ID never authorizes) now, and records **D1 as `Deferred`** until
sign-off. The scaffold in PR 1 commits to neither transport and adds no
dependency, so accepting this note does not foreclose the fork.
