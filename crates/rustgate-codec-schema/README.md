# rustgate-codec-schema

Declarative schema format and generic codec for tactical wire-format
codec authoring without writing Rust per protocol.

## Role in the workspace

Tactical protocols (STANAG 4586, IEEE 1278.1 DIS, MAVLink, VMF, ASTERIX,
Link 16 JREAP) are well-specified fixed-offset binary formats. Writing
a hand-rolled Rust codec per protocol means maintaining N parallel
implementations of identical patterns. `rustgate-codec-schema` declares
the wire layout in YAML once and the shared `SchemaCodec` runtime drives
every protocol.

Inspired by the OMG XTCE (XML Telemetric and Command Exchange) spec
used by NASA / ESA mission control software (Yamcs, Open MCT) and the
spirit of CCSDS Space Packet Protocol descriptors. **This crate is not
a full XTCE implementation** — XTCE is a 200+ page standard with dozens
of optional features (algorithmic calibration, container inheritance,
parameter aggregation). This crate ships the 80% of practical
fixed-offset binary wire-format definitions in a much smaller surface.

The full grammar reference lives at
[`docs/codec-schema-grammar.md`](../../docs/codec-schema-grammar.md).
The architectural decision and the discipline for adding new grammar
features lives in [ADR
0018](../../docs/adr/0018-schema-first-codec-design.md).

## Public API surface

- `SchemaCodec::from_schema_text(yaml)` — parse + validate + construct
  in one call; the canonical entry point
- `SchemaCodec::new(schema)` — construct from an already-parsed
  `Schema` (use when the schema came from somewhere other than YAML)
- `SchemaCodec::to_entity(payload)` / `SchemaCodec::from_entity(entity)`
  — implements the `rustgate_core::entity::EntityCodec` trait for
  round-trip decode / encode
- `bitstream::shift_left(input, bit_shift)` /
  `bitstream::splice_at(header, header_end_bit, body, body_bit_count)`
  — bit-level helpers for composing two schemas at a non-byte-aligned
  boundary (the cheap alternative to full grammar-level schema
  chaining; see #1411)

## Grammar versions shipped

| Version | Feature | Issue |
|---|---|---|
| v1 | Fixed-offset primitives, linear calibration, range guards, `entity-path` | #1352 |
| v2 | Multi-message dispatch + `value-mapping` (typed enum projection) | #1370 |
| v3 | `present-if` sparse-projection, `repeat` (count-from arrays), single-byte bit-packing | #1383 / #1385 / #1387 / #1389 |
| v4 | Cross-byte bit spans (`bit_offset + bit_width > 8` now legal), bit-packed u16/u32/u64 | #1402 |
| v4.1 | Signed bit-packed types (`i8` / `i16` / `i32` / `i64`) with two's-complement sign-extension | #1404 |
| v5 | Variable-shift `present-if` (`shift-mode: collapse-when-absent`) for FPI cascades and FX continuation | #1408 |

Backward-compatible: every v3 schema continues to validate and produce
byte-identical wire output under v4 / v4.1 / v5.

## Feature flags

_None._ Always-on, pure-Rust, no FFI.

## Reference protocols using the grammar

Each tactical-protocol crate that ships a schema-parity test exercises
the grammar end-to-end. See the [reference protocols
table](../../README.md#schema-driven-codecs) in the workspace README
for the full list (currently 7 protocols across STANAG, DIS, MAVLink,
VMF, Link 16, ASTERIX).

## Topology / deployment notes

The crate is pure decode/encode — no transport, no async, no allocations
beyond the `Entity` it produces. `SchemaCodec` is `Send + Sync` (the
underlying `Schema` is immutable after construction), so the router can
hold one instance per protocol and share it across every routed
message.

VMF K05.1's production decode path (`rustgate-vmf::k05_1::K051PositionReport::decode`)
runs through `SchemaCodec` since #1427 — the first production-codec
migration that survived past parity-test stage. Other tactical-protocol
codecs still use their hand-rolled decoders with schema-parity tests
pinning the wire layout.
