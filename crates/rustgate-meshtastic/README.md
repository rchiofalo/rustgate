# rustgate-meshtastic

Meshtastic / LoRa **TAKPacket** compact-protobuf codec — the wire
format used by the ATAK ecosystem's most widely deployed mesh radio
platform (Meshtastic on T-Beam / Heltec / RAK hardware) and by
compatible bandwidth-constrained mesh transports (goTenna Pro X2).

## What this crate does

- Decodes a Meshtastic `TAKPacket` payload (`&[u8]`) into typed
  [`TakPacket`] / [`Pli`] / [`GeoChat`] structs.
- Encodes those structs back into a compact protobuf payload that
  fits the **237-byte** LoRa per-frame cap.
- Implements the canonical [`rustgate_core::entity::EntityCodec`]
  trait so the workspace router can fan an entity out across
  Meshtastic alongside CoT XML, MAVLink, ASTERIX, and STANAG-4586.

## Wire form

```
TAKPacket { is_compressed?, contact?, group?, status?,
            oneof payload_variant { Pli pli, GeoChat chat, bytes detail } }
PLI { latitude_i sfixed32 (lat × 1e7),
      longitude_i sfixed32,
      altitude int32 (metres),
      speed uint32 (cm/s),
      course uint32 (degrees × 100) }
```

All multi-byte numeric fields are **scaled integers** — no floating
point on the wire. The `1e7` lat/lon scale gives ≈ 1.1 cm precision
at the equator, fine for any tactical position. Course wraps modulo
360°; speed is centimetres per second.

## Why hand-rolled protobuf

The schema is small enough that adding a `build.rs` + `prost`
dependency would dwarf the crate. Hand-rolled wire-format parsing
keeps the dependency footprint at `bytes` + `thiserror` +
`rustgate-core`, and surfaces every wire-tag mistake at the read
site rather than behind generated code. The parser is forward-
compatible: unknown fields are skipped, so a future schema
revision that adds new fields stays decodable.

## Field pruning for the 237-byte cap

Encode is intentionally narrow: every optional field is omitted
when its source value is empty / default. The encoder rejects any
output that exceeds [`MAX_PAYLOAD_BYTES`] with
`MeshtasticError::PayloadTooLarge` rather than emit a frame the
LoRa transport will refuse.

This codec works WITH the existing
[`rustgate_cot::delta::DeltaEncoder`] (under the `full-detail`
feature) as a pre-filter — emit only the changed CoT XML fields,
then encode the resulting minimal entity through this codec. No
new delta machinery is needed inside this crate.

## Compatibility

- **Meshtastic firmware** — wire layout matches the upstream
  `Meshtastic-protobufs` `TAKPacket` schema verbatim.
- **goTenna Pro X2** — bandwidth-constrained mesh transport
  exposing the same `TAKPacket` / `PLI` schema. The codec
  decodes / encodes goTenna payloads identically; the
  transport binding is tracked as a follow-up and is a thin
  shim over the goTenna SDK that calls into this crate.

## Out of scope

- Mesh-frame headers, routing fields, and link-layer encryption
  (handled by the transport).
- UDP / serial listener wiring (separate follow-up, mirrors how
  the MAVLink crate gets a listener after its codec PR).
- Body compression behind the `is_compressed` flag (carried
  opaque — consumers that need it implement the upstream
  firmware's compression scheme separately).

## Quality gates

```
cargo +nightly fmt --all
cargo clippy --locked --workspace --all-targets \
    --features nats,enrollment,est,proto,full-detail,metrics,federation,federation-ha,websocket,mqtt,otel,http,meshtastic
cargo nextest run -p rustgate-meshtastic
```
