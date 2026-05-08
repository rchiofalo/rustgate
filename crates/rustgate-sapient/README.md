# rustgate-sapient

SAPIENT (BSI Flex 335, NATO/UK MOD) autonomous-sensor-network
protobuf codec. SAPIENT — *Sensors for Asset Protection using
Integrated Electronic Networked Technology* — is the UK MOD/Dstl
interface standard adopted across NATO for counter-UAS,
perimeter security, and autonomous-sensor exchange. The wire
form has been protobuf since v2.0 (March 2024); the schema lives
at <https://github.com/dstl/SAPIENT-Proto-Files> under Crown
Copyright.

## What this crate does

- Decodes a `SapientMessage` payload (`&[u8]`) into a typed
  [`SapientMessage`] envelope plus the active `oneof content` arm.
- Decodes the `DetectionReport` arm fully (location, classification
  list, ENU velocity, detection confidence, colour, identifier).
- Encodes a typed [`SapientMessage`] back into wire-format bytes
  with byte-exact round-trip for non-MVP arms via the opaque
  [`SapientPayload::Other`] variant.
- Implements the canonical [`rustgate_core::entity::EntityCodec`]
  trait so the workspace router can fan an entity out across
  SAPIENT alongside CoT XML, MAVLink, ASTERIX, STANAG-4586,
  Meshtastic, VMF, and DIS.

## Wire form (BSI Flex 335 v2.0)

```
SapientMessage {
    1 google.protobuf.Timestamp timestamp
    2 string                    node_id           (UUID)
    3 string                    destination_id    (UUID, optional)
    // oneof content:
    4..12 Registration / RegistrationAck / StatusReport
          / DetectionReport / Task / TaskAck / Alert
          / AlertAck / Error
    13 string                   additional_information
}

DetectionReport {
    1  string  report_id (ULID)
    2  string  object_id (ULID)
    3  string  task_id (ULID)
    4  string  state
    // oneof location_oneof:
    5  RangeBearing range_bearing
    6  Location     location
    7  float        detection_confidence
    11 DetectionReportClassification (repeated)
    19 ENUVelocity  enu_velocity
    22 string       colour
    23 string       id
}
```

Coordinate fields ride as IEEE-754 doubles (no integer scaling),
so same-codec round-trip is bit-exact for every wire-format
scalar. SAPIENT's `Location` puts longitude on `x` and latitude
on `y` — the codec exposes `Location::lat()` / `Location::lon()`
accessors so callers do not need to remember the convention.

## Why hand-rolled protobuf

The MVP scope (envelope + `DetectionReport`) is small enough that
adding a `build.rs` + `prost` dependency would dwarf the crate.
Hand-rolled wire-format parsing keeps the dependency footprint at
`bytes` + `thiserror` + `rustgate-core` and surfaces every wire-tag
mistake at the read site rather than behind generated code. The
parser is forward-compatible: unknown fields are skipped (the
canonical protobuf "ignore unknown" behaviour) and the seven
non-MVP `oneof content` arms ride opaque so a future schema
revision stays decodable.

## MVP scope

Fully decoded:

- `SapientMessage` envelope — every header field plus the
  `oneof content` discriminator.
- `DetectionReport` arm — the position-bearing surface that maps
  to the canonical `Entity` shape.

Carried opaque (round-trip preserving):

- `Registration`, `RegistrationAck`, `StatusReport`, `Task`,
  `TaskAck`, `Alert`, `AlertAck`, `Error` — ride as
  `SapientPayload::Other` with the field-number tag preserved.
- Inside `DetectionReport`: `track_info`, `object_info`,
  `behaviour`, `signal`, `prediction_location`,
  `associated_file`, `associated_detection`,
  `derived_detection` — skip cleanly on the read side; the
  canonical `Entity` shape does not surface them.

## Forward compatibility

Unknown protobuf fields are skipped by wire type (varint /
length-delimited / fixed32 / fixed64). Varint overflow (>10 bytes),
unknown wire types, invalid UTF-8 in string fields, and
length-delimited prefixes that exceed the payload cap surface as
typed `SapientError` variants rather than panicking.

## What is deliberately absent

- **Transport binding.** SAPIENT transports — TCP framing, MQTT
  topic envelope, gRPC body — are the responsibility of a listener
  crate. This codec consumes / emits the inner `SapientMessage`
  payload only.
- **Other content arms.** `Registration`, `StatusReport`, `Task`,
  `TaskAck`, `Alert`, `AlertAck`, `Error` decode/encode to typed
  structs — out of scope for the MVP. They round-trip verbatim
  through `SapientPayload::Other` but do not produce typed access
  today.
- **Validation against `proto_options` annotations.** BSI Flex 335
  annotates fields with `is_mandatory`, `is_uuid`, `is_ulid`
  semantic markers. This codec treats those as documentary —
  strict validation belongs in a follow-up policy layer.
- **`ENUVelocityUnits` honour.** The MVP assumes the SI default
  (m/s) for ENU velocity scalars.

## Companion protocols (issue #869)

Issue #869 covers three protocols. SAPIENT lands here as the MVP.
NFFI (STANAG 5527 — NATO Blue Force Tracking, XML over DDS / SOAP /
REST) and OGC SensorThings (REST + JSON + MQTT for IoT sensor
data) are deferred to follow-up issues; #869 stays open until both
land.
