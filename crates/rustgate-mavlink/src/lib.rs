// Copyright © 2026 Roberto Chiofalo.

//! MAVLink wire-format primitives for rustgate.
//!
//! This crate hosts the low-level MAVLink v1/v2 frame parser and the
//! [`rustgate_core::codec::Codec`] adapter that lets the rest of the
//! workspace treat MAVLink like any other transport. No session wiring
//! lives here — UDP and TCP listeners that drive the codec arrive in a
//! follow-up PR.
//!
//! # Scope
//!
//! Two concerns, deliberately no more:
//!
//! - [`frame::MavlinkFrameCodec`] — a `tokio_util::codec::Decoder` /
//!   `Encoder` pair that slices complete MAVLink frames out of a byte
//!   stream. Handles both v1 (`0xFE`) and v2 (`0xFD`) frames on the same
//!   link, disambiguated by magic byte. Does **not** validate the CRC:
//!   MAVLink v2 signing (see PR 3 of the parent epic) is the trust
//!   boundary; the framer's job is purely to extract bytes.
//! - [`codec::MavlinkCodec`] — implements [`rustgate_core::codec::Codec`]
//!   so the router can ingest MAVLink frames via the same pipeline that
//!   handles CoT XML and TAK protobuf. Payloads are carried opaquely
//!   (the full frame including magic/header/CRC/signature), matching the
//!   behaviour of `raw-length-prefixed`.
//!
//! # What is deliberately absent
//!
//! - **CRC verification.** Discarding corrupt frames here would hide
//!   classes of hostile-input bugs from the signing layer. Verification
//!   happens in the `signing` module (future PR) where it can also check
//!   replay-timestamp monotonicity.
//! - **Message-ID interpretation.** The framer does not know or care
//!   whether a frame is `HEARTBEAT` or `GLOBAL_POSITION_INT`. Obligation
//!   actuators and filters that need the message ID look at header byte
//!   offsets directly.
//! - **Payload transcoding.** Unlike `rustgate-proto`, MAVLink frames
//!   are **not** converted to XML. The canonical-payload-is-XML invariant
//!   documented on `Codec` only applies to codecs that target the CoT
//!   model; MAVLink is a peer wire format that routes opaquely.

pub mod codec;
pub mod error;
pub mod frame;

pub use codec::MavlinkCodec;
pub use error::MavlinkError;
pub use frame::{
    HEARTBEAT_MSG_ID, MAVLINK_V1_MAGIC, MAVLINK_V2_MAGIC, MavlinkFrameCodec, MavlinkVersion,
    OnMavlinkHeartbeat,
};
