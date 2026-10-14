// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Meshtastic / LoRa TAKPacket compact-protobuf codec.
//!
//! Meshtastic is a license-free LoRa mesh-radio platform widely
//! deployed across the ATAK ecosystem (small-unit reconnaissance,
//! border patrol, search-and-rescue, disaster response). Each
//! mesh frame carries up to 237 bytes of application payload after
//! LoRa PHY headers, mesh routing fields, and link-layer
//! encryption AAD; the application protocol used to fill that
//! budget is a compact protobuf message called `TAKPacket` that
//! mirrors the position-and-chat shape of CoT XML.
//!
//! This crate ships a pure encode/decode library for that wire
//! form. The transport layer (UDP / serial / mesh-radio bridge)
//! lives elsewhere — this crate accepts a `&[u8]` payload and
//! emits / decodes a [`crate::proto::TakPacket`] without any I/O.
//! The crate also implements the canonical
//! [`rustgate_core::entity::EntityCodec`] trait so the router can
//! fan an entity out across Meshtastic alongside CoT XML, MAVLink,
//! ASTERIX, and STANAG-4586.
//!
//! # Wire format summary
//!
//! ```text
//! TAKPacket {                     // ≤ 237 bytes total
//!     1 bool   is_compressed
//!     2 group  contact            // callsign + device callsign
//!     3 group  group              // role + team enums
//!     4 group  status             // battery percent
//!     // oneof payload_variant:
//!     5 PLI       pli             // position-location-information
//!     6 GeoChat   chat            // free-form addressed message
//!     7 bytes     detail          // opaque CoT detail blob
//! }
//!
//! PLI {
//!     1 sfixed32 latitude_i       // lat × 1e7 (≈ 1.1 cm at equator)
//!     2 sfixed32 longitude_i      // lon × 1e7
//!     3 int32    altitude         // metres HAE, signed
//!     4 uint32   speed            // cm/s
//!     5 uint32   course           // degrees × 100
//! }
//! ```
//!
//! All numeric fields are scaled integers — there is no floating-
//! point on the wire. The encoder applies the inverse scaling
//! (multiply by `1e7`, `100`, `100`) and clamps non-finite or
//! out-of-envelope values rather than panicking.
//!
//! # Field pruning
//!
//! Encode is intentionally narrow: every optional field is
//! omitted when its source value is empty / default. The
//! 237-byte transport cap means a redundant `is_compressed=false`
//! byte is wasted bandwidth that drops a real PLI report at the
//! tail of a busy window. The encoder rejects any output that
//! exceeds [`MAX_PAYLOAD_BYTES`] with a typed
//! [`MeshtasticError::PayloadTooLarge`].
//!
//! # Compatibility
//!
//! - **goTenna Pro X2** — the goTenna Pro X2 series exposes a
//!   similar bandwidth-constrained mesh transport; the same
//!   codec shape (compact protobuf, integer-scaled coordinates,
//!   field pruning to fit the per-frame cap) applies. Adding a
//!   goTenna binding is tracked as a follow-up; the codec
//!   crate's public API is stable enough that the binding
//!   layer can wire `MeshtasticCodec` directly once the
//!   transport-layer differences are settled. The protobuf
//!   schema match is one-to-one: see the `goTenna Pro X2 SDK`
//!   `TAKPacket` / `PLI` definitions which mirror the upstream
//!   Meshtastic firmware.
//! - **Delta compression** — this codec works WITH the existing
//!   `rustgate_cot::delta::DeltaEncoder` (when the `full-detail`
//!   feature is enabled on the CoT crate) as a pre-filter: emit
//!   only the changed CoT XML fields, then encode the resulting
//!   minimal entity through this codec. No new delta machinery
//!   is needed inside this crate.
//!
//! # Scope
//!
//! - [`codec::MeshtasticCodec`] — implementation of the canonical
//!   [`rustgate_core::entity::EntityCodec`] trait against the
//!   `Entity` shape defined in `rustgate-core`.
//! - [`proto::TakPacket`] / [`proto::Pli`] / [`proto::GeoChat`]
//!   — typed wire-format structs.
//! - [`proto::decode_tak_packet`] / [`proto::encode_tak_packet`]
//!   — symmetric round-trip primitives over `&[u8]` / `Vec<u8>`.
//! - [`error::MeshtasticError`] — typed failure modes (no panics).
//!
//! # What is deliberately absent
//!
//! - **Mesh-frame headers and link-layer encryption.** The
//!   Meshtastic mesh frame envelope (PHY header, routing fields,
//!   AES key wrap) is the transport's responsibility. This crate
//!   consumes / emits the inner application payload only.
//! - **Listener wiring.** The live serial / bridge transport lands
//!   in a follow-up change, mirroring how
//!   [`rustgate-mavlink`](../rustgate_mavlink/index.html) gets a
//!   listener in a follow-up to its codec PR. The ingress seam is
//!   designed in `docs/design/meshtastic-serial-ingress.md` /
//!   ADR 0032; the compile-safe, no-I/O scaffold (the `transport`
//!   module, behind the off-by-default `meshtastic-ingress` feature) is the
//!   first slice, and the live listener is gated on the design note's
//!   one open transport fork (serial reader vs bridge contract).
//! - **goTenna Pro X2 binding.** Documented as compatible above;
//!   the binding crate is a follow-up that depends on this crate
//!   and the goTenna SDK transport layer.
//! - **Compression of the chat body.** The `is_compressed` flag
//!   on [`proto::TakPacket`] is carried opaque — this codec does
//!   not implement the upstream firmware's body-compression
//!   scheme.
//!
//! # Error handling
//!
//! This crate's error type is [`error::MeshtasticError`]; binary
//! callers propagate it via `?` and map it through `anyhow::Error`
//! at the orchestration layer. The
//! `rustgate_core::error::RustgateError` boundary aggregator (used
//! in the `rustgate-core` / `rustgate-transport` slice) is not
//! automatically constructed from [`error::MeshtasticError`].

#![forbid(unsafe_code)]
#![doc(html_no_source)]

pub mod codec;
pub mod error;
pub mod proto;

/// Compile-safe, no-I/O scaffold for the Meshtastic ingress seam
/// (design note `docs/design/meshtastic-serial-ingress.md`, ADR 0032).
/// Off by default behind the `meshtastic-ingress` feature; the live
/// listener and any serial-transport dependency land in a follow-up PR.
#[cfg(feature = "meshtastic-ingress")]
pub mod transport;

pub use codec::MeshtasticCodec;
pub use error::MeshtasticError;
pub use proto::{
    COORD_SCALE, COURSE_SCALE_HUNDREDTHS_DEG, Contact, GeoChat, Group, MAX_PAYLOAD_BYTES,
    PayloadVariant, Pli, SPEED_SCALE_CM_PER_S, Status, TakPacket, decode_tak_packet,
    encode_tak_packet,
};
#[cfg(feature = "meshtastic-ingress")]
pub use transport::{
    DEFAULT_INGRESS_CN, DEFAULT_RATE_LIMIT_PPS, MeshIngressConfig, MeshIngressError, MeshIngressKey,
};
