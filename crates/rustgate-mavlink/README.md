# rustgate-mavlink

MAVLink v1/v2 frame codec and transport primitives.

## Role in the workspace

`rustgate-mavlink` provides the wire-format primitives needed to ingest a
MAVLink feed through the same routing pipeline that handles CoT XML and TAK
protobuf. It depends on [rustgate-core](../rustgate-core/README.md) for the
`Codec` trait it implements and is consumed by
[rustgate-transport](../rustgate-transport/README.md) under
`--features mavlink`. The crate is intentionally narrow — it owns frame
slicing only. Listener bring-up (UDP / TCP) and v2 signing land in follow-up
PRs and are deliberately out of scope here.

## Public API surface

- `frame::MavlinkFrameCodec` — `tokio_util::codec::{Decoder, Encoder}` pair
  that slices complete MAVLink frames out of a byte stream; handles both
  v1 (`0xFE`) and v2 (`0xFD`) on the same link, disambiguated by magic byte
- `frame::MavlinkVersion` — `V1 | V2` discriminant returned alongside each
  decoded frame
- `frame::MAVLINK_V1_MAGIC`, `frame::MAVLINK_V2_MAGIC`,
  `frame::HEARTBEAT_MSG_ID` — wire-protocol constants
- `frame::OnMavlinkHeartbeat`, `frame::OnMavlinkRejection`,
  `frame::RejectionReason` — observation callbacks for metrics / audit
- `codec::MavlinkCodec` — implements [`rustgate_core::codec::Codec`] so the
  router can ingest MAVLink alongside CoT and protobuf; payloads are
  carried opaquely (full frame including magic, header, CRC, signature)
- `crc_extra::crc_extra` — per-message-id CRC seed lookup used by the
  signing path
- `error::MavlinkError` — typed error enum for frame-decode failures

## Feature flags

_None._

## Topology / deployment notes

The framer deliberately does not validate the CRC; that is the trust
boundary the signing module owns (see future PR), and discarding corrupt
frames here would hide classes of hostile-input bugs from the signing
layer. Message-ID interpretation is also out of scope — obligations and
filters that need a specific message ID look at header byte offsets
directly. Unlike [rustgate-proto](../rustgate-proto/README.md), MAVLink
frames are NOT transcoded to XML; they route opaquely.

## Where to look first

- `crates/rustgate-mavlink/src/frame.rs` — the `Decoder` / `Encoder`
  implementation and the v1-vs-v2 disambiguation
- `crates/rustgate-mavlink/src/codec.rs` — the `Codec` adapter that bridges
  the framer to the router pipeline
