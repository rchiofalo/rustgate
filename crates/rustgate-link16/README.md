# rustgate-link16

Link 16 / JREAP-C (STANAG 5518) tactical-data-link codec for rustgate.

## Role in the workspace

`rustgate-link16` is a pure decode/encode library for the **JREAP-C**
wire format — the TCP/IP framing of MIL-STD-6016 J-series messages
exchanged between Joint Range Extension (JRE) gateways and tactical
command-post systems on a garrison or coalition-grade IP backbone. It
deliberately depends on nothing else in the workspace beyond
`rustgate-core` (for the `EntityCodec` trait), `bytes`, and
`thiserror`, so it can be reused outside rustgate without dragging in
transport / routing concerns. The integration layer that wires a TCP
listener on port 4444 (and the TLS / HAIPE-encrypted enclave wrapping
that real coalition deployments sit behind) is intentionally elsewhere
— a future PR per issue #866 follow-ups will land it.

## MVP scope

This crate ships **JREAP-C frame header** decode/encode plus the
**J2.2 Air Track** J-series message bidirectionally — decode of a
wire frame into `J2_2AirTrack` and encode of one back to bytes. Other
J-series messages (J3.2 Air PPLI, J3.5 Land Point, J7.0 Track
Management, J13.2 Air Platform & System Status, …) decode into
`JseriesMessage::Other { label, body }` so a multi-message TCP stream
can still be framed and a follow-up PR can extend the typed coverage
one J-series message at a time. The placeholder-then-extend strategy
mirrors how `rustgate-asterix` grew from CAT-062 to add CAT-021 and
CAT-048: one message at a time, behind the same trait impl.

JREAP-C connection-management messages (link-connect, heartbeat,
link-disconnect) are surfaced as `JreapMessageType::Other(u8)` for
the same reason.

## Public API surface

- `Link16Codec` — `EntityCodec` impl bridging JREAP-C frames and the
  canonical `rustgate_core::entity::Entity` shape.
- `JreapFrame` — typed view over the 16-byte JREAP-C frame header.
- `JreapMessageType` — typed view over the JREAP-C message-type byte.
- `JseriesMessage` — enum carrying `J2_2AirTrack(...)` plus opaque
  `Other { label, body }` for non-MVP J-series.
- `J2_2AirTrack`, `IffCodes`, `JseriesKinematics`, `PlatformType` —
  typed views over the J2.2 wire form.
- `Link16Error`, `Link16EntityError` — typed error surfaces.
- `JREAP_DEFAULT_TCP_PORT = 4444` — default JREAP-C listener TCP port.
- `JREAP_C_VERSION = 0x03` — JREAP-C version byte.
- `JREAP_HEADER_LEN = 16` — JREAP-C frame header length.
- `LINK16_PREFIX = "link16."` — `Entity.attributes` key prefix.

## Feature flags

This crate has none of its own. The optional `link16` feature on the
workspace toggles the integration layer (TLS-wrapped TCP listener
wiring, registration in the codec registry) — that layer lands in a
follow-up PR.

## Wire layout

JREAP-C is TCP/IP-framed. Each frame begins with a fixed 16-byte
big-endian header followed by a body of `body_length` bytes. The
header layout is:

| Offset | Size | Field        | Notes                                        |
|--------|------|--------------|----------------------------------------------|
| 0      | 1    | version      | `0x03` for JREAP-C                           |
| 1      | 1    | message_type | `0x01` = J-series data                       |
| 2      | 1    | exercise_id  | Coalition exercise group (site-defined)      |
| 3      | 1    | reserved     | Reserved (zero on encode, preserved on decode)|
| 4      | 4    | sequence     | Per-connection monotonic counter             |
| 8      | 4    | timestamp    | Seconds since UNIX epoch (sender clock)      |
| 12     | 4    | body_length  | Bytes following the header                   |

The J2.2 body shape is documented in `src/jseries/j2_2.rs` — 29 bytes
total comprising the 0x22 label, a 32-bit track number, signed
microdegree latitude / longitude, signed metre altitude, the platform
type, IFF status byte and Mode-3/A code, and three-field kinematics
(speed in cm/s, course in centidegrees, climb rate in dm/s).

## Spec assumptions

STANAG 5518 (JREAP) and MIL-STD-6016 (Link 16 J-series) are
restricted-distribution documents. The wire shapes pinned in this MVP
are the layered subset published in open-literature interoperability
guides (NATO STANAG 5602 cross-references, AFRL technical reports,
vendor integration manuals for the open-source SIMPLE / JREAP test
harnesses) plus the layout pinned by issue #866. Where open
literature leaves a field ambiguous (most often the bit-vs-byte
alignment of optional sub-fields), the codec uses the most common
width and documents the choice inline. A reviewer with access to the
closed spec can correct individual widths without touching the codec
scaffolding.

The MVP keeps every J2.2 field byte-aligned for parser simplicity. A
follow-up PR can layer the bit-packed MIL-STD-6016 wire form behind
the same `J2_2AirTrack` struct shape if a deployment needs the
on-radio bit-packed form.

## Out of scope (deferred to follow-up issues)

- TLS / HAIPE-encrypted enclave handling for classified-network
  deployments.
- TCP listener wiring on port 4444; codec registration in
  `rustgate-server`.
- Other J-series messages (J3.2 Air PPLI, J3.5 Land Point, J7.0
  Track Management, J13.2 Air Platform & System Status, full J-series
  catalogue).
- JREAP-A (multicast) and JREAP-B (serial / SATCOM) variants.
- IFF code lookup tables — the codec preserves raw IFF bytes; the
  resolution against the at-issue NATO IFF table is a deployment
  configuration concern.
- Mapping `Entity` → `RoutableMessage` (issue #847).
