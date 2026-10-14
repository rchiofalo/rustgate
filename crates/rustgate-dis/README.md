# rustgate-dis

DIS (Distributed Interactive Simulation, IEEE 1278.1) binary codec.

## Role in the workspace

`rustgate-dis` is a pure decode/encode library for the IEEE 1278.1-compliant
DIS wire format used by Live, Virtual, and Constructive (LVC) training
simulators (e.g. VR-Forces, MAK ONESAF, BISim VBS, distributed JCATS
exercises). It deliberately depends on nothing else in the workspace —
only `bytes`, `thiserror`, and `rustgate-core` for the canonical `Entity`
shape — so it can be reused outside rustgate without dragging in
transport / routing concerns. The integration layer that maps decoded
PDUs into `rustgate_core::message::RoutableMessage` is intentionally
elsewhere (server registers `DisEntityCodec` via the
`EntityCodecRegistry`; refs #847).

## Public API surface

- `header::PduHeader` / `header::PduType` / `header::ProtocolFamily` —
  the 12-byte common DIS PDU header, decoded into typed fields with
  `decode` / `encode` helpers
- `entity_state::EntityStatePdu` / `entity_state::EntityId` /
  `entity_state::EntityType` / `entity_state::ForceId` /
  `entity_state::DeadReckoningParameters` /
  `entity_state::ArticulationParameter` — the Entity State PDU and its
  supporting types, with `decode` / `encode` round-trip
- `coord::ecef_to_wgs84` / `coord::wgs84_to_ecef` — closed-form
  WGS-84 ↔ ECEF (geocentric Cartesian) conversion using the Bowring
  family of algorithms; pinned to WGS-84 ellipsoid parameters
  (a = 6 378 137 m, f = 1/298.257223563)
- `codec::DisCodec` — implementation of
  [`rustgate_core::entity::EntityCodec`] that decodes Entity State PDUs
  into the canonical `Entity` shape and encodes back
- `error::DisError` — `thiserror`-derived failure modes: truncated
  buffers, unsupported PDU types, length-field mismatch, malformed
  marking strings

## Feature flags

_None._

## Spec version

Implements the wire format and field layouts defined by
**IEEE 1278.1-2012** ("Standard for Distributed Interactive Simulation —
Application Protocols"). The header structure (12 bytes: protocol
version, exercise ID, PDU type, protocol family, timestamp, length, two
padding bytes) and the Entity State PDU layout (variable length, ~144
bytes plus articulation parameters) are documented in IEEE 1278.1-2012
clauses 5.2.32 (PduHeader) and 5.3.3.1 (Entity State PDU).

## Scope of this MVP

The first PR ships **header parsing + Entity State PDU + ECEF↔WGS84 +
dead-reckoning algorithm passthrough**. The remaining 71 IEEE 1278.1
PDU types (Fire, Detonation, Collision, Resupply, Repair, Service
Request, Logistics, Radio Communications, Warfare, Simulation
Management, Distributed Emission Regeneration, Entity Information /
Interaction, Minefield, Synthetic Environment, Live Entity, Non-Real-
Time, …) are deliberately out of scope for the MVP and will land in
follow-up PRs. The dead-reckoning algorithm tag is decoded as a typed
enum; the 30 bytes of dead-reckoning parameters (linear / angular
acceleration vectors, secondary-orientation Euler triplet) are
preserved verbatim as opaque bytes for round-trip but not interpreted.

## Topology / deployment notes

DIS conventionally runs on UDP port 3000 (no transport security).
Multicast is common for site-internal exercises; unicast bridges across
WANs are the federation use-case rustgate is built for. Live UDP
listener wiring is **not** part of this PR — the codec is a pure
decode/encode library matching the pattern of `rustgate-asterix` and
`rustgate-stanag4586`.

## Where to look first

- `crates/rustgate-dis/src/header.rs` — the 12-byte PDU header (every
  PDU type starts with this); read this first to understand the
  framing pattern that follow-up PDU types will share
- `crates/rustgate-dis/src/entity_state.rs` — the Entity State PDU
  decode/encode round-trip
- `crates/rustgate-dis/src/coord.rs` — the closed-form ECEF↔WGS84
  conversion; ~40 lines including doc-comments and named constants for
  the WGS-84 ellipsoid

## License

AGPL-3.0-only, same as the rest of the workspace. See the workspace `LICENSE`
and `NOTICE`.
