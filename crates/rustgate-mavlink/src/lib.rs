// Copyright © 2026 Roberto Chiofalo.

//! MAVLink wire-format primitives for rustgate.
//!
//! This crate hosts the low-level MAVLink v1/v2 frame parser, the
//! [`rustgate_core::codec::Codec`] adapter that lets the rest of the
//! workspace treat MAVLink like any other transport, the v2 signing
//! trust boundary ([`signing`]), and the UDP/TCP listeners
//! ([`listener`]) that drive the codec and hand verified frames to the
//! router via a sink callback.
//!
//! # Scope
//!
//! Three concerns, deliberately no more:
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
//! - [`entity::MavlinkEntityCodec`] — implements
//!   [`rustgate_core::entity::EntityCodec`] so the workspace's
//!   protocol-agnostic `Entity` shape can carry MAVLink wire frames.
//!   Decodes HEARTBEAT (`MSG_ID = 0`) and GLOBAL_POSITION_INT
//!   (`MSG_ID = 33`) on the inbound path; encodes Position-bearing
//!   `Entity` values back to GLOBAL_POSITION_INT on the outbound path.
//!   Refs #847.
//!
//! # What is deliberately absent
//!
//! - **CRC verification.** Discarding corrupt frames here would hide
//!   classes of hostile-input bugs from the signing layer. Verification
//!   happens in the [`signing`] module where it also checks
//!   replay-timestamp monotonicity.
//! - **Message-ID interpretation.** The framer does not know or care
//!   whether a frame is `HEARTBEAT` or `GLOBAL_POSITION_INT`. Obligation
//!   actuators and filters that need the message ID look at header byte
//!   offsets directly.
//! - **Payload transcoding.** Unlike `rustgate-proto`, MAVLink frames
//!   are **not** converted to XML. The canonical-payload-is-XML invariant
//!   documented on `Codec` only applies to codecs that target the CoT
//!   model; MAVLink is a peer wire format that routes opaquely.
//!
//! # Error handling
//!
//! This crate's error type is [`error::MavlinkError`]; binary callers in
//! `rustgate-server` propagate it via `?` and map it through
//! `anyhow::Error` at the orchestration layer.
//! [`rustgate_core::error::RustgateError`] is the boundary aggregator for
//! the `rustgate-core` / `rustgate-transport` slice and is not
//! automatically constructed from [`error::MavlinkError`].

pub mod codec;
pub mod crc_extra;
pub mod entity;
pub mod error;
pub mod frame;
pub mod listener;
pub mod obligations;
#[cfg(feature = "mavlink-pq")]
pub mod rekey;
pub mod signing;

pub use codec::MavlinkCodec;
pub use crc_extra::crc_extra;
pub use entity::{GLOBAL_POSITION_INT_MSG_ID, MavlinkEntityCodec, MavlinkEntityError};
pub use error::MavlinkError;
pub use frame::{
    HEARTBEAT_MSG_ID, MAVLINK_V1_MAGIC, MAVLINK_V2_MAGIC, MavlinkFrameCodec, MavlinkVersion,
    OnMavlinkHeartbeat, OnMavlinkRejection, RejectionReason,
};
pub use listener::{
    LinkRegistry, MavlinkDestination, MavlinkListenerConfig, OnMavlinkMessage, spawn_tcp_listener,
    spawn_udp_listener,
};
pub use obligations::{
    COMMAND_INT_MSG_ID, COMMAND_LONG_MSG_ID, MANUAL_CONTROL_MSG_ID, frame_msg_id, is_command_frame,
    mask_as_heartbeat, mask_position,
};
#[cfg(feature = "mavlink-pq")]
pub use rekey::{
    ALG_ML_KEM_768, MavlinkRekeyPayload, RekeyError, RekeyReceiver, generate_keypair, seal,
};
pub use signing::{
    DEFAULT_REPLAY_CAPACITY, SIGNATURE_LEN, SIGNING_KEY_LEN, SigningError, SigningKey,
    SigningKeyStore, VerifiedFrame, compute_signature, signing_timestamp,
};
