# rustgate-vmf

VMF (Variable Message Format, MIL-STD-6017) bit-level codec for rustgate.

## Role in the workspace

`rustgate-vmf` is a pure decode/encode library for the VMF wire format
used by Army/USMC tactical radios (SINCGARS-ASIP, EPLRS, NTDR). It
deliberately depends on nothing else in the workspace beyond
`rustgate-core` (for the `EntityCodec` trait), `bytes`, and
`thiserror`, so it can be reused outside rustgate without dragging in
transport / routing concerns. The integration layer that wires a UDP
listener on port 1581 and feeds decoded frames into the router is
intentionally elsewhere (future PR per issue #868 follow-ups).

## MVP scope

This crate ships **K05.1 Position Report** bidirectionally — decode of
a wire frame into `K051PositionReport` and encode of one back to
bytes. The MIL-STD-2045-47001 application header (URN, DTG, message
type, classification, addressing) decodes/encodes for every K-series
message; non-MVP K-series surface as `VmfMessage::Unknown { body, … }`
so a follow-up PR can extend the crate without breaking call sites.

K01.x (General C2), K02.x (Intelligence), K04.x (Land Combat
Operations), K06.x (Fire Support), K00.x (Free Text) message bodies
are deferred to subsequent issues. The placeholder-then-extend
strategy mirrors how `rustgate-asterix` grew from CAT-062 to add
CAT-021 and CAT-048: one K-series at a time, behind the same trait
impl.

## Public API surface

- `VmfCodec` — `EntityCodec` impl bridging VMF wire frames and the
  canonical `rustgate_core::entity::Entity` shape.
- `VmfMessage` — enum of typed `K05_1(K051PositionReport)` plus
  opaque `Unknown { message_type, body }` for non-MVP K-series.
- `decode_message` / `encode_k05_1` — lower-level entry points for
  callers that want the raw header and body without the `Entity`
  round-trip.
- `VmfHeader`, `K051PositionReport`, `MessageId`, `Classification`,
  `Dtg` — typed views over the wire format.
- `BitReader`, `BitWriter` — minimal big-endian bit-level helpers
  used by the codec (re-exported in case downstream code wants them).
- `VmfError`, `VmfEntityError` — typed error surfaces.
- `VMF_DEFAULT_UDP_PORT = 1581` — IANA-registered VMF UDP port.

## Feature flags

_None._ This crate is always built when included as a workspace member.
The optional `vmf` feature on `rustgate-server` toggles the integration
layer (UDP listener wiring, metrics) — that layer lands in a follow-up
PR.

## Spec assumptions

MIL-STD-6017 is not freely available. The wire form pinned in this MVP
is the layered subset published in open-literature references (FM 6-99
"U.S. Army Report and Message Formats", NATO STANAG 5616
cross-references, JPL/Caltech VMF interop notes), plus the layout
pinned by issue #868 (URN, DTG, message type, classification,
addressing). Where the open-literature shape leaves a field ambiguous
(e.g. exact bit width of the operation-indicator group), the codec
uses the most common width and documents the choice inline. A reviewer
with access to the closed spec can correct individual widths without
touching the codec scaffolding.

## Bit-level parsing approach

VMF is bit-oriented and uses three classes of presence indicator:

- **FPI (Field Presence Indicator)** — single bit gating an optional
  field.
- **FRI (Field Recurrence Indicator)** — single bit between repeated
  occurrences.
- **GPI / GRI (Group Presence / Recurrence Indicators)** — same as
  FPI/FRI but gating an entire group.

The codec uses an in-crate `BitReader`/`BitWriter` (≈100 lines, in
`src/bitstream.rs`) instead of a third-party `bitstream-io` dep — the
asterix and stanag4586 crates established the precedent of keeping
codec deps minimal, and the read/write surface needed here fits in
about a dozen methods. If a future K-series message needs >32-bit
single-field reads (UNIX-time timestamps with sub-microsecond carry,
large bitmaps), a `read_bits_u64` extension lands at that point.
