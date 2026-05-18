# Codec Schema Grammar

`rustgate-codec-schema` lets you declare a binary wire format in YAML and
get a working encoder / decoder ([`SchemaCodec`]) without writing per-
protocol Rust. The grammar evolved across several feature additions
(referred to as v1 → v4.1 in this doc and in CHANGELOG entries); this page
is the single reference for what the grammar can express today.

This doc is informative — the authoritative grammar lives in
[`crates/rustgate-codec-schema/src/schema.rs`][schema-source] and is
validated at schema-load time. Use this page as a guide; if it disagrees
with the validator, the validator wins.

[`SchemaCodec`]: ../crates/rustgate-codec-schema/src/codec.rs
[schema-source]: ../crates/rustgate-codec-schema/src/schema.rs

## Why a schema-driven codec

Tactical wire formats (STANAG 4586, IEEE 1278.1 DIS, MAVLink, VMF,
ASTERIX, …) are well-defined fixed-offset structures. Writing a hand-
rolled Rust codec per protocol means maintaining parallel
implementations of identical patterns (big-endian integer reads, fixed
offsets, optional fields, …) and writing a parallel proptest harness
per crate. A declarative schema captures the wire layout once and the
shared `SchemaCodec` runtime drives every protocol.

Per-protocol Rust still lives on top of `SchemaCodec` — typed enums
(e.g. `FlightState::LaunchPreparation`) and domain-specific range checks
sit in a thin wrapper crate. The schema handles the byte layout.

## Top-level schema

```yaml
schema-version: "1"
protocol-name: "example.position-report"
discriminator-offset: 0          # optional, required for multi-message schemas
message-types:
  - name: "Position"
    id: 0x01                     # optional, required for multi-message schemas
    size-bytes: 20
    fields:
      - name: "latitude_deg"
        offset: 0
        field-type: { kind: f64 }
        endian: big
      # ... more fields
```

| Top-level key | Required | Notes |
|---|---|---|
| `schema-version` | yes | Always `"1"` today; placeholder for future grammar revisions |
| `protocol-name` | yes | Used to build the default `Entity::attributes` key prefix |
| `discriminator-offset` | conditionally | Required when `message-types` has 2+ entries |
| `message-types` | yes | List of one or more message variants |

Each message type carries:

| Message-type key | Required | Notes |
|---|---|---|
| `name` | yes | Internal identifier |
| `id` | conditionally | Required when there are 2+ message types; uniquely identifies this variant within the schema |
| `size-bytes` | yes | Fixed wire-format size (excluding any `repeat` tail) |
| `fields` | yes | Ordered list of field definitions |

## Field definitions

Every field has at minimum `name`, `offset`, and `field-type`:

```yaml
- name: "vehicle_id"
  offset: 0
  field-type: { kind: u32 }
  endian: big
```

All optional keys are documented in the sections below. Offsets are in
**bytes**; `bit-offset` (when used) is the byte-relative sub-byte
starting position.

### Primitive field types

| `kind` | Wire width | Decoded as | Notes |
|---|---|---|---|
| `u8` / `i8` | 1 byte | `Int(i64)` | `i8` is bit-cast through `u8` |
| `u16` / `i16` | 2 bytes | `Int(i64)` | Needs `endian: little \| big` |
| `u32` / `i32` | 4 bytes | `Int(i64)` | Needs `endian: little \| big` |
| `u64` / `i64` | 8 bytes | `Int(i64)` | Needs `endian: little \| big`; high bit preserved by bit-cast |
| `f32` | 4 bytes | `Float(f64)` | IEEE-754; encoder rejects NaN/inf (`OutOfRange`) |
| `f64` | 8 bytes | `Float(f64)` | IEEE-754; encoder rejects NaN/inf |
| `bytes` | variable | `Bytes` | Requires `length-bytes` OR `repeat` |
| `utf8` | variable | `Str(String)` | Requires `length-bytes`; trailing NULs stripped on decode |

### Endianness

```yaml
- name: "timestamp"
  offset: 4
  field-type: { kind: u32 }
  endian: big
```

`big` for NATO / MIL-STD-derived protocols; `little` for IEEE 1278.1
extensions and most network-byte-order-agnostic formats. Required for
all multi-byte primitive integer and float fields.

### Range constraints

Linear ranges enforce a domain on decode and (for non-calibrated fields)
on encode:

```yaml
- name: "latitude_deg"
  offset: 0
  field-type: { kind: f64 }
  endian: big
  range: { min: -90.0, max: 90.0 }
```

Range checks reject values outside `[min, max]` with
`SchemaCodecError::OutOfRange`. **NaN is not rejected by the range
guard** — `NaN < min || NaN > max` evaluates `false` in both halves.
Wrapper crates that need NaN-rejection layer an `is_nan()` check on top
(see `rustgate-stanag4586::vehicle_position::decode`).

### Calibration

Linear calibration converts raw integer wire values to physical units:

```yaml
- name: "altitude_msl_m"
  offset: 4
  field-type: { kind: u16 }
  endian: big
  calibration: { scale: 0.5, offset: -1000.0 }
  range: { min: -1000.0, max: 31767.5 }    # post-calibration range
```

Decode: `physical = raw * scale + offset`. Encode: `raw = (physical -
offset) / scale`. When calibration is present, range bounds refer to the
post-calibration physical value; the validator skips the
bit-width-capacity check on `range.max` because the physical max can
legitimately exceed the raw bit-width's capacity (a 1-bit field with
`scale: 10.0` produces `[0, 10]`).

### Entity-path projection

A field's decoded value defaults to landing in `Entity::attributes`
under the key `schema.<protocol>.<field>`. `entity-path` projects it
onto a first-class `Entity` shape field instead:

```yaml
- name: "latitude_deg"
  offset: 0
  field-type: { kind: f64 }
  endian: big
  entity-path: "position.lat"
```

Supported `entity-path` targets:
- `uid`
- `callsign`
- `mil_std_2525_sidc`
- `position.lat`, `position.lon`, `position.hae_meters`
- `velocity.speed_m_s`, `velocity.course_deg`
- Anything else starts with `attributes.` and survives in
  `Entity::attributes` under that key.

## v2: Multi-message dispatch

Schemas with 2+ `message-types` entries declare a 1-byte
`discriminator-offset`. On decode, the runtime reads the byte at that
offset and selects the matching `message-types[*].id`; the byte is
round-tripped through `Entity::attributes` under
`schema.<protocol>.__discriminator__`.

```yaml
schema-version: "1"
protocol-name: "dis.pdu"
discriminator-offset: 2
message-types:
  - name: "EntityState"
    id: 0x01
    size-bytes: 144
    fields: [ ... ]
  - name: "Fire"
    id: 0x02
    size-bytes: 96
    fields: [ ... ]
```

Validator rejects:
- Multi-message schemas without `discriminator-offset`
- Duplicate or missing `id` values
- `id` values outside `[0, 255]`

## v2: Value-mapping (enum projection)

`value-mapping` projects a wire byte to a typed label:

```yaml
- name: "force_id"
  offset: 6
  field-type: { kind: u8 }
  entity-path: "attributes.force_id"
  value-mapping:
    entries:
      0: "Other"
      1: "Friendly"
      2: "Opposing"
      3: "Neutral"
    default-raw: 0          # bytes not in entries decode as the "Other" label
                            # and re-encode as the default's raw value (0)
```

**Lossy by design**: with `default-raw` set, every unknown byte
collapses to the default's label. Re-encoding produces the default's
raw value, **not the original byte**. If your wrapper needs to round-
trip arbitrary bytes verbatim (e.g. forward-compat unknown-state
preservation), keep the field a raw `u8` and do the typed projection in
the Rust wrapper layer — STANAG 4586's `flight_state` and DIS's
`pdu_type` both take this route.

Validator rejects:
- `value-mapping` on non-integer types
- `value-mapping` combined with `calibration` or `range`
- `default-raw` pointing to a value not in `entries`

## v3: Present-if (sparse projection)

`present-if` makes a field's projection conditional on the value of an
earlier-decoded integer field. The bytes stay reserved on the wire
whether or not the predicate matches; only the entity projection
changes:

```yaml
- name: "altitude_fpi"
  offset: 7
  field-type: { kind: u8 }
- name: "altitude_msl_m"
  offset: 8
  field-type: { kind: u16 }
  endian: big
  present-if:
    field: "altitude_fpi"
    equals: 1
  entity-path: "position.hae_meters"
```

When `altitude_fpi == 0`, the `altitude_msl_m` bytes at offset 8..10
stay at their pre-filled zero value and the field is NOT projected
onto `position.hae_meters` (no attribute write on decode, no entity
read on encode).

**This is sparse-projection, not variable-shift.** The bytes are always
reserved on the wire. Variable-shift semantics (where the field
genuinely disappears and subsequent fields slide) are tracked as a v5
grammar feature — VMF K05.1's FPI cascade needs that.

Validator rejects:
- `present-if` referencing an unknown field
- `present-if` referencing a field at the same or later offset
- `present-if` referencing a non-integer field
- `present-if` combined with `value-mapping` on the same field (would
  need the predicate to know about the typed projection)

## v3: Repeat (variable-length arrays via count-from)

`repeat` declares a variable-length tail of fixed-size records, with
the element count carried in an earlier-decoded integer field:

```yaml
- name: "num_articulation_parameters"
  offset: 7
  field-type: { kind: u8 }
- name: "articulation_parameters"
  offset: 132
  field-type: { kind: bytes }
  repeat:
    count-from: "num_articulation_parameters"
    record-size-bytes: 16
```

Wire span = `record-size-bytes × count-from value`. The field extends
beyond the message's declared `size-bytes`; the runtime grows the
output buffer accordingly.

Validator rejects:
- `repeat` on non-`bytes` field types
- `count-from` referencing an unknown field
- `count-from` referencing a field at the same or later offset
- `count-from` referencing a non-integer field
- `repeat` combined with `length-bytes`
- `record-size-bytes: 0`

## v3 / v4 / v4.1: Bit-packing

Bit-packing extracts an integer sub-range from one or more bytes,
MSB-first. Use it for protocol bit-flag fields (FPI / FRI / GPI),
packed enums, and sub-byte typed fields.

```yaml
# v3: single-byte u8 — paint scheme is bit 7 of byte 3
- name: "paint_scheme"
  offset: 3
  field-type: { kind: u8 }
  bit-offset: 7
  bit-width: 1
```

| Grammar key | Range | Notes |
|---|---|---|
| `bit-offset` | `[0, 7]` | MSB-first index within the byte; `0` = byte's MSB, `7` = LSB |
| `bit-width` | `[1, 64]` | v3: ≤ 8 (single-byte); v4 extended to multi-byte spans |

### v3 (#1389): single-byte bit-packing

`bit-offset + bit-width ≤ 8`. Multiple fields can share the same byte
offset as long as their bit ranges don't overlap — this is the
canonical packed-flag-byte pattern:

```yaml
- name: "fpi_altitude"
  offset: 0
  field-type: { kind: u8 }
  bit-offset: 0
  bit-width: 1
- name: "fpi_speed"
  offset: 0
  field-type: { kind: u8 }
  bit-offset: 1
  bit-width: 1
- name: "category"
  offset: 0
  field-type: { kind: u8 }
  bit-offset: 2
  bit-width: 3
```

### v4 (#1402): cross-byte bit-packing

`bit-width` extends to `[1, 64]`. Fields may span multiple bytes:

```yaml
# 12-bit u16 starting mid-byte, spanning bytes 0 and 1
- name: "value"
  offset: 0
  field-type: { kind: u16 }
  bit-offset: 4
  bit-width: 12
```

Field types extended from `u8`-only to `u8 / u16 / u32 / u64`. Each
type pairs with a max `bit-width`:

| Type | Max `bit-width` |
|---|---|
| `u8` | 8 |
| `u16` | 16 |
| `u32` | 32 |
| `u64` | 64 |

### v4.1 (#1404): signed bit-packing

Signed types (`i8 / i16 / i32 / i64`) joined the bit-packed type list
with the same per-type width caps. Decode sign-extends via the standard
two's-complement formula:

```rust
// raw is the unsigned bit pattern read from the wire
if raw & (1 << (bit_width - 1)) != 0 {
    // MSB at field position is set → fill high bits above bit_width with 1s
    extended = raw | !((1 << bit_width) - 1)
}
```

Encode range-checks against `[-2^(N-1), 2^(N-1) - 1]` for `bit_width <
64`; for `bit_width = 64` every i64 fits trivially.

Example (representative of VMF K05.1 latitude):

```yaml
- name: "latitude"
  offset: 3
  field-type: { kind: i32 }
  bit-offset: 0
  bit-width: 25
```

### Bit-packing combinations and constraints

| Constraint | Why |
|---|---|
| `bit-offset + bit-width` may span multiple bytes (v4) | Validator checks the touched-byte range fits in `size-bytes` |
| Cannot combine with `length-bytes` | Each describes a different wire shape |
| Cannot combine with `repeat` | Bit-packing is a scalar projection; repeat is a count-driven array |
| Cannot combine with `value-mapping` | Mapping requires the raw integer to be the unit of projection |
| `range.max` ≤ `bit-width` capacity (unless calibrated) | Avoids unsatisfiable schemas |
| Wire-byte-overlap detection | Multiple bit-packed fields sharing bytes must not overlap bits |
| Signed range guard | `bit_width = N` signed has domain `[-2^(N-1), 2^(N-1) - 1]` |

## Validation rules summary

`Schema::validate()` runs at schema-load time and returns
`SchemaError::Validation { message }` with a descriptive error string
for every misconfiguration. Major classes:

- **Layout**: overlapping byte ranges, fields past `size-bytes`, zero-
  size variable-length fields
- **Type**: unknown field-type kind, missing `endian` on multi-byte
  primitives, missing `length-bytes` on `bytes`/`utf8` fields
- **Bit-packing**: `bit-offset ∉ [0, 7]`, `bit-width ∉ [1, 64]`,
  `bit_width` exceeds field type capacity, overlapping bit ranges,
  combination conflicts (with `length-bytes` / `repeat` /
  `value-mapping`)
- **Discriminator**: missing `discriminator-offset` on multi-message
  schemas, duplicate or missing `id`, `id` out of `[0, 255]`
- **Value-mapping**: combined with `calibration` or `range`, on non-
  integer fields, `default-raw` pointing nowhere
- **Present-if**: unknown / later / non-integer reference field,
  combined with `value-mapping` on same field
- **Repeat**: on non-`bytes` types, with unknown / later / non-integer
  count field, combined with `length-bytes`, with
  `record-size-bytes: 0`
- **Calibration**: non-finite `scale` / `offset`, `scale: 0`
- **Range**: non-finite `min` / `max`, `max < min`

The validator is a strict allowlist — anything not in the grammar fails
fast with a descriptive error rather than silently producing garbage at
decode/encode time.

## Backward compatibility

Every grammar feature is **additive**: a schema valid under v3 stays
valid under v4 and v4.1 with byte-identical wire output. The validator's
constraints only lift (never tighten):

- v3 → v4: `bit-offset + bit-width > 8` was a hard error; now valid with
  `u16/u32/u64` field types.
- v4 → v4.1: signed types `i8/i16/i32/i64` were rejected for bit-packed
  fields; now accepted with the same width caps as their unsigned
  counterparts.

If a future grammar revision needs to **break** an existing
interpretation, the `schema-version` value (currently always `"1"`) will
bump and the parser will require explicit consent.

## Known gaps (tracked)

| Issue | Gap | Workaround |
|---|---|---|
| [#1396](https://github.com/rchiofalo/rustgate/issues/1396) | VMF K05.1 body — needs **variable-shift `present-if`** (v5): when a gated field is absent, the bytes genuinely disappear from the wire and subsequent fields' positions slide | Keep the codec hand-rolled in `rustgate-vmf` |
| (v6 grammar follow-up) | Nested-record `repeat` — each repeat element is a typed sub-message with its own field list (not a raw N-byte blob) | Carry records as `bytes` blobs and project in the wrapper |
| (v6 grammar follow-up) | Schema chaining — header schema dispatches into one of N body schemas based on the header's discriminator | Compose at the call site in the wrapper |
| (v6 grammar follow-up) | Signed bit-packed with calibration — combine v4.1 sign-extension with `calibration.scale / offset` | Decompose into raw bit-packed field plus separate calibrated derived field |

## Reference protocols using the grammar

Each row links to the protocol's schema YAML and its schema-parity proptest.

| Protocol | Schema | Parity test | Grammar features used |
|---|---|---|---|
| STANAG 4586 vehicle position | [`vehicle_position.yaml`](../crates/rustgate-stanag4586/schemas/vehicle_position.yaml) | [`schema_parity.rs`](../crates/rustgate-stanag4586/tests/schema_parity.rs) | Fixed offsets, big-endian, range constraints |
| DIS PDU common header | [`pdu_header.yaml`](../crates/rustgate-dis/schemas/pdu_header.yaml) | [`schema_parity.rs`](../crates/rustgate-dis/tests/schema_parity.rs) | Fixed offsets, value-mapping (typed dispatch demo) |
| DIS Entity State body | [`entity_state.yaml`](../crates/rustgate-dis/schemas/entity_state.yaml) | [`schema_parity_entity_state.rs`](../crates/rustgate-dis/tests/schema_parity_entity_state.rs) | Variable-length `repeat` (`count-from`), composite `bytes` blobs |
| DIS Entity Appearance | [`entity_appearance.yaml`](../crates/rustgate-dis/schemas/entity_appearance.yaml) | [`schema_parity_entity_appearance.rs`](../crates/rustgate-dis/tests/schema_parity_entity_appearance.rs) | v3 bit-packing, multi-field-per-byte |
| MAVLink v1 header | [`v1_header.yaml`](../crates/rustgate-mavlink/schemas/v1_header.yaml) | [`schema_parity.rs`](../crates/rustgate-mavlink/tests/schema_parity.rs) | Fixed offsets, value-mapping (smoke test) |

## Adding a new protocol

1. Write a `schemas/<protocol>.yaml` next to the existing crate's source.
2. Cross-check the byte layout against the protocol spec; document any
   spec-version assumptions inline in the YAML's header comments.
3. Add a `tests/schema_parity_<protocol>.rs` proptest mirroring the
   patterns above. Use the **inline reference encoder** pattern from
   [#1397](https://github.com/rchiofalo/rustgate/pull/1397) so the
   parity check stays a genuine cross-implementation comparison even
   if the production codec migrates to a `SchemaCodec`-driven path.
4. Add the protocol to the reference-protocols table above when the PR
   lands.

The schema-parity test asserts byte-identical round-trip; the typed-
projection / domain-specific validation / typed enum mapping stays in
the wrapper crate.
