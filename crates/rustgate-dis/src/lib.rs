// Copyright © 2026 Roberto Chiofalo.

#![forbid(unsafe_code)]

//! DIS (Distributed Interactive Simulation, IEEE 1278.1) binary codec
//! for rustgate.
//!
//! DIS is the IEEE 1278.1-compliant message set used by Live, Virtual,
//! and Constructive (LVC) training simulators (VR-Forces, MAK ONESAF,
//! BISim VBS, distributed JCATS exercises) to share entity state,
//! firing events, environmental conditions, and so on across a
//! federation of independently developed simulator instances. A live
//! DIS feed is a stream of *PDUs* (Protocol Data Units) on UDP — each
//! PDU starts with a fixed 12-byte common header followed by a body
//! whose shape depends on the PDU type. This crate implements the
//! decoder and encoder for the **Entity State PDU** — the workhorse
//! of every DIS exercise — plus the closed-form WGS-84 ↔ ECEF
//! coordinate conversion every consumer needs.
//!
//! # Scope of the MVP
//!
//! - [`header::PduHeader`] — the 12-byte common header that prefixes
//!   every PDU type, with `decode` / `encode_into` round-trip.
//! - [`entity_state::EntityStatePdu`] — the Entity State PDU body
//!   plus the supporting types ([`entity_state::EntityId`],
//!   [`entity_state::ForceId`], [`entity_state::EntityType`],
//!   [`entity_state::DeadReckoningParameters`],
//!   [`entity_state::ArticulationParameter`]).
//! - [`coord::ecef_to_wgs84`] / [`coord::wgs84_to_ecef`] — closed-form
//!   WGS-84 ↔ ECEF conversion, single-pass Bowring 1985 inverse.
//! - [`codec::DisCodec`] — implementation of
//!   [`rustgate_core::entity::EntityCodec`] for the cross-protocol
//!   `Entity` shape (refs #847).
//!
//! # Spec version
//!
//! Implements the wire format and PDU layouts defined by **IEEE
//! 1278.1-2012** ("Standard for Distributed Interactive Simulation —
//! Application Protocols"). The header structure and the Entity State
//! PDU body shape are documented in IEEE 1278.1-2012 clauses 5.2.32
//! and 5.3.3.1 respectively. SISO-REF-010 is the companion catalogue
//! for the [`entity_state::EntityType`] tuple values.
//!
//! # What is deliberately absent
//!
//! - **Other PDU types.** IEEE 1278.1 defines 72 PDU types across
//!   seven protocol families (Entity Information / Interaction,
//!   Warfare, Logistics, Simulation Management, Distributed Emission
//!   Regeneration, Radio Communications, Entity Management). The MVP
//!   only decodes Entity State; every other PDU type is preserved in
//!   the [`header::PduHeader`] but not parsed. Follow-up PRs land
//!   typed shapes for Fire, Detonation, Collision, Service Request,
//!   Resupply Offer / Received / Cancel, Repair Complete / Response,
//!   Radio Transmitter, Signal, Receiver, …
//! - **UDP listener wiring.** A real DIS feed lives on UDP port 3000
//!   (the [`header::DIS_DEFAULT_UDP_PORT`] constant); binding the
//!   socket and feeding the decoder is a follow-up concern — this
//!   crate is a pure decode / encode library matching the pattern of
//!   `rustgate-asterix` and `rustgate-stanag4586`.
//! - **Dead-reckoning algorithm execution.** The codec parses the
//!   algorithm tag and preserves the 30 bytes of parameters as
//!   opaque, but does not implement DRM_FPW / DRM_RPW / DRM_RVW /
//!   DRM_FVW / DRM_FPB / DRM_RPB / DRM_RVB / DRM_FVB. A future
//!   simulator-bridge PR can layer that on top of this crate.
//! - **Mapping to [`rustgate_core::message::RoutableMessage`].** The
//!   `EntityCodec` impl in [`codec::DisCodec`] yields the canonical
//!   [`rustgate_core::entity::Entity`] shape; the
//!   `Entity` → `RoutableMessage` integration belongs in the routing
//!   layer (issue #847).
//!
//! # Error handling
//!
//! This crate exposes two distinct error types:
//! [`error::DisError`] for wire-format-layer failures (truncated
//! buffers, length-field mismatch, malformed marking strings) and
//! [`codec::DisEntityError`] for the additional class of "this
//! Entity cannot be represented as a DIS Entity State PDU" failures
//! that surface from the [`rustgate_core::entity::EntityCodec`]
//! boundary. The split mirrors the per-category split in
//! `rustgate-asterix` so a SIEM that pages on
//! `dis.pdu_rejected` does not also page on the routine
//! `dis.entity.unsupported_entity_kind` signal during cross-protocol
//! fan-out.

pub mod codec;
pub mod coord;
pub mod entity_state;
pub mod error;
pub mod header;

pub use codec::{DIS_PREFIX, DisCodec, DisEntityError};
pub use coord::{WGS84_A, WGS84_B, WGS84_E2, WGS84_F, ecef_to_wgs84, wgs84_to_ecef};
pub use entity_state::{
    ArticulationParameter, DeadReckoningParameters, EntityId, EntityStatePdu, EntityType, ForceId,
};
pub use error::DisError;
pub use header::{DIS_DEFAULT_UDP_PORT, IEEE_1278_1_2012, PduHeader, PduType, ProtocolFamily};
