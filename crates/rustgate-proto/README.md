# rustgate-proto

TAK protocol-buffer translation and the TAK frame codec.

## Role in the workspace

`rustgate-proto` translates between CoT XML (the canonical payload format
used in `RoutableMessage`) and the TAK protobuf wire format, and provides
the `0xBF + varint` framing codec required by TAK clients that negotiate
to protobuf. It depends on [rustgate-core](../rustgate-core/README.md) for
the `Codec` trait and is consumed by
[rustgate-transport](../rustgate-transport/README.md),
[rustgate-http](../rustgate-http/README.md), and
[rustgate-nats](../rustgate-nats/README.md) (with `full-detail`) under the
`proto` feature.

## Public API surface

- `TakFrameCodec` — the `0xBF`-prefixed varint-length-delimited frame codec
  used between rustgate and protobuf-speaking clients
- `TakProtobufCodec` — implements `rustgate_core::codec::Codec` for the
  protobuf wire format, decoding into the canonical XML payload before
  routing
- `proto_to_xml`, `xml_to_proto` — bidirectional conversion functions used
  at session edges (inbound: protobuf → XML before routing; outbound: XML →
  protobuf after routing)
- `negotiate::*` — the TAK protocol-version handshake (`MIN_PROTO_VERSION`,
  `MAX_PROTO_VERSION`, `NegotiatedVersion`, `parse_tak_request`,
  `build_tak_response`, `read_tak_request_with_timeout`,
  `build_protocol_support_xml`, and the `DEFAULT_NEGOTIATION_TIMEOUT`)
- `xml_full::{parse_full, FullCotEvent}` — extended XML parser used when
  full TAK protobuf detail is required (gated by `full-detail` downstream)
- `tak_proto` — generated module containing the prost-derived TAK protobuf
  types
- `ProtoError` — typed error enum for codec, conversion, and negotiation
  failures

## Feature flags

_None._

## Topology / deployment notes

The crate has a `compile_error!` guard rejecting 32-bit targets — varint
decoding casts `u64 → usize`, and on a 32-bit platform that truncation
could bypass the workspace's `MAX_FRAME_SIZE` check. XML is the canonical
payload format inside `RoutableMessage`; this crate translates at the
session edge so the router only ever sees XML and obligations / authz /
dedup all key on the same shape regardless of which wire format the client
spoke.

## Where to look first

- `crates/rustgate-proto/src/convert.rs` — `proto_to_xml` and `xml_to_proto`
  conversion logic
- `crates/rustgate-proto/src/negotiate.rs` — the protocol-version handshake
  used to upgrade a session from XML to protobuf framing
