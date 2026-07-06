# ADR 0032: Meshtastic LoRa / serial ingress seam

- **Status:** Proposed
- **Date:** 2026-07-03
- **Deciders:** rchiofalo
- **Related:** #1491 (Meshtastic LoRa/serial ingress),
  [`docs/design/meshtastic-serial-ingress.md`](../design/meshtastic-serial-ingress.md)
  (design note),
  [ADR 0023](0023-tactical-codec-ingress-seam.md) (tactical codec ingress seam —
  this ADR extends its non-mTLS admission model to a non-IP transport),
  [`docs/design/tactical-codec-ingress.md`](../design/tactical-codec-ingress.md)
  (datagram design note, PR-breakdown item 4 deferred Meshtastic here),
  [`docs/design/tactical-stream-ingress.md`](../design/tactical-stream-ingress.md)
  (stream design note),
  ADR 0018 (schema-first codec design)

## Context

`rustgate-meshtastic` ships a pure `TAKPacket` codec that implements the
canonical `EntityCodec` trait and is registered in the
`EntityCodecRegistry` — so the router can already *decode* a
Meshtastic-tagged message — but there is no ingress that produces the tag.
Both prior ingress notes deferred Meshtastic on purpose: it is neither a
UDP datagram (the DIS/ASTERIX/VMF wave) nor a TCP stream (the Link 16 /
STANAG 4586 / SAPIENT wave). Its transport is a **local LoRa serial radio**,
its application payload is wrapped in a **mesh frame with link-layer AES
encryption** that the codec deliberately does not parse, and its sender has
**no source IP** — so the shared `UdpAdmission` gate (keyed on `IpAddr`)
does not apply.

This ADR records the seam for that transport. It inherits every security
decision from ADR 0023 (fail-closed admission, validate-and-drop with the
router's own codec, wire identifiers never authorize, audit every
rejection) and only resolves what is new: ownership of mesh-frame
de-encapsulation / decryption, the non-IP admission model, and the
transport source. The full analysis is in the design note; this ADR records
the load-bearing decisions.

## Decision

**D2 (de-encapsulation + decryption) — transport-owned, out of the codec.**
Whichever component owns the physical radio (a serial reader or an external
bridge) also owns mesh-frame de-encapsulation and link-layer AES
decryption; the codec crate stays a pure, I/O-free, key-free decoder of the
inner decrypted `TAKPacket`. The edge still validates-and-drops by running
the full `EntityCodec` decode on the decrypted payload (ADR 0023 D2), and
every drop is audited.

**D3 (non-IP admission) — re-key the gate on the configured ingress
channel, never on the mesh node ID.** A serial radio has no source IP, so
the rate-limit and bounded-fan-out budgets are **per-configured-ingress**
(one serial device / one bridge socket = one budget) with a secure non-zero
rate-limit default, rather than the per-source-IP LRU of `UdpAdmission`. The
identity stays synthetic (`cn = "meshtastic-anonymous"`, configurable
prefix, one operator-assigned ingress group that ACL/authz gate on). The
spoofable Meshtastic node ID lives only inside the decoded `Entity` for
correlation/dedup, is `sanitize_for_log`-cleaned, and is **never** an
ACL/authz or CN input — the ADR 0023 "wire identifiers never authorize"
line, applied to a non-IP transport.

**D1 (transport source) — DEFERRED, not decided.** The design note surfaces
a genuine fork the maintainer owns: **D1a** a direct serial reader (a new
`tokio-serial` workspace dependency, rustgate owns the serial framing + AES
crypto) versus **D1b** a defined UDP/TCP "Meshtastic bridge" wire contract
(no new dependency, an external adapter owns the serial + crypto, rustgate
reuses the existing datagram/stream seam). The recommendation is D1b on
security-and-blast-radius grounds (no supply-chain add, crypto out of the
router process, reuse of an already-hardened seam), but this is deferred to
sign-off. **The scaffold in the first PR commits to neither and adds no
dependency**, so accepting this ADR does not foreclose the choice.

The first slice is a compile-safe, no-I/O stub in `rustgate-meshtastic`
(`transport.rs`), behind an off-by-default `meshtastic-ingress` Cargo
feature: `MeshIngressConfig` (transport-agnostic fields only),
`MeshIngressError` (thiserror), and `MeshIngressKey` (the non-IP admission
key). No live listener, no `start_meshtastic` — those are PR 2, gated on D1.

## Alternatives considered

- **Serial reader in-process (D1a) as the recorded decision.** Rejected as
  *the recorded default* — not on merit (it is a legitimate option the
  maintainer may still pick) but because pre-committing it would (a) pull a
  new `tokio-serial` supply-chain dependency this branch cannot `cargo deny`
  -review, and (b) put security-sensitive serial-framing + AES parsing of
  unauthenticated input inside the router process. Recording it as
  `Deferred` keeps the fork honest.

- **Reuse `UdpAdmission` unchanged.** Rejected: it is IP-keyed and a serial
  radio has no source IP; forcing a synthetic IP would be a fiction that
  buys nothing. The per-ingress re-key (D3) is the honest model. (Under D1b
  the bridge *socket* still gets the real IP-keyed `UdpAdmission` layer for
  free.)

- **Let the codec parse the mesh frame + decrypt.** Rejected: it would
  widen the pure codec into an I/O-and-key-holding component, contradicting
  its documented "what is deliberately absent" contract and coupling
  decode to a transport concern. D2 keeps decode pure.

## Consequences

- The codec crate stays pure and key-free; the transport (serial reader or
  bridge) owns de-encapsulation/decryption. A future goTenna Pro X2 binding
  slots into the same seam.
- Admission for a non-IP transport is per-configured-ingress; operators size
  one rate/fan-out budget per radio/bridge, not per peer. Node IDs never
  reach an authorization or CN input, preserving the ADR 0023 attribution
  guarantee.
- Until D1 is signed off, no live Meshtastic listener exists — only an
  off-by-default, no-I/O, zero-dependency stub. The follow-up PR adds the
  chosen transport; under D1a it is also where `tokio-serial` enters the
  workspace `Cargo.toml` + `deny.toml` under a `cargo deny` review.
- This ADR is reversible on D1 (the fork is still open) and stable on D2/D3
  (they are inherited invariants). Flip **Status** to **Accepted** when the
  live transport PR lands.
