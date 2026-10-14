// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

#![forbid(unsafe_code)]

//! Link 16 / JREAP-C codec for rustgate.
//!
//! Link 16 is the tactical data link (TDL) used by NATO and U.S.
//! command-and-control systems to exchange a structured catalogue of
//! "J-series" messages over a TDMA radio waveform. Modern deployments
//! tunnel that same J-series catalogue over IP via JREAP — the **Joint
//! Range Extension Application Protocol** (STANAG 5518). This crate is
//! a pure decode/encode library for the **JREAP-C** variant — the
//! TCP/UDP framing of J-series messages used between Joint Range
//! Extension (JRE) gateways and tactical command-post systems on a
//! garrison or coalition-grade IP backbone.
//!
//! # Wire format primer
//!
//! A JREAP-C frame starts with a fixed 16-byte header followed by a
//! body whose shape depends on the message type carried. The body is
//! one or more J-series messages (J2.x position-and-track, J3.x
//! position reports, J7.x command-and-control, J13.x platform-and-
//! system-status, …) — each preserved verbatim by the lower-level
//! [`header::JreapFrame::decode`] entry point so a future PR can layer
//! typed-shape J-series support without reshuffling the frame layer.
//!
//! # MVP scope
//!
//! - [`header::JreapFrame`] — the 16-byte JREAP-C frame header
//!   (version, message_type, exercise_id, body length, sequence
//!   counter, timestamp) with `decode` / `encode_into` round-trip.
//! - [`jseries::JseriesMessage`] — enum carrying typed
//!   [`jseries::J2_2AirTrack`] plus opaque
//!   [`jseries::JseriesMessage::Other`] for non-MVP J-series messages
//!   so a follow-up PR can extend without breaking call sites.
//! - [`jseries::J2_2AirTrack`] — the J2.2 Air Track message:
//!   track number, geodetic position, IFF status, platform type, and
//!   kinematics. J2.2 is the canonical "where is that fighter / how
//!   fast is it going" payload of the network and is the workhorse of
//!   every Link 16 exercise.
//! - [`codec::Link16Codec`] — implementation of
//!   [`rustgate_core::entity::EntityCodec`] for the cross-protocol
//!   `Entity` shape (refs #847).
//!
//! # Spec version
//!
//! Implements the JREAP-C frame layout defined by **STANAG 5518**
//! ("Joint Range Extension Application Protocol") and the J-series
//! message layouts defined by **MIL-STD-6016** ("Tactical Data Link
//! 16 Message Standard"). STANAG 5518 and MIL-STD-6016 are both
//! restricted-distribution documents; the wire shapes pinned here are
//! the layered subset published in open-literature references
//! (NATO STANAG 5602 cross-references, AFRL technical reports, vendor
//! integration manuals for the open-source SIMPLE / JREAP test
//! harnesses) plus the layout pinned by issue #866. Where open
//! literature leaves a field ambiguous, the codec uses the most
//! common width and documents the choice inline (search for `MVP` in
//! [`crate::header`] and [`crate::jseries`]). A reviewer with access
//! to the closed spec can correct individual widths without touching
//! the codec scaffolding.
//!
//! # What is deliberately absent
//!
//! - **TLS / classified-network handling.** Real JREAP-C deployments
//!   ride on a HAIPE-encrypted enclave or an mTLS-wrapped TCP tunnel
//!   between coalition partners. The transport binding (TLS listener
//!   on port [`JREAP_DEFAULT_TCP_PORT`], JREAP-A multicast variant,
//!   JREAP-B serial variant) is out of scope for this crate; this MVP
//!   is a pure decode/encode library mirroring `rustgate-asterix`,
//!   `rustgate-stanag4586`, `rustgate-vmf`, and `rustgate-dis`.
//! - **Other J-series messages.** MIL-STD-6016 defines roughly 80
//!   J-series messages across initial-network entry (J0.x),
//!   precise-participant location and identification (J3.x),
//!   surveillance (J3.5), command (J7.x), platform-and-system-status
//!   (J13.x), and so on. The MVP only decodes J2.2; every other
//!   message is preserved as opaque [`jseries::JseriesMessage::Other`]
//!   so a multi-message frame can still be framed and the decoder can
//!   advance to the next message. Follow-up PRs land typed shapes for
//!   J3.2 (Air PPLI), J3.5 (Land Point), J7.0 (Track Management),
//!   J13.2 (Air Platform & System Status).
//! - **IFF code lookup tables.** The codec preserves the raw IFF
//!   fields (mode-1, mode-2, mode-3, mode-S, mode-5) but does not
//!   resolve them against the at-issue NATO IFF tables — that lookup
//!   is a deployment-specific configuration concern handled by the
//!   integration layer, not the wire-format library.
//! - **Mapping to [`rustgate_core::message::RoutableMessage`].** The
//!   `EntityCodec` impl in [`codec::Link16Codec`] yields the canonical
//!   [`rustgate_core::entity::Entity`] shape; the
//!   `Entity` → `RoutableMessage` integration belongs in the routing
//!   layer (issue #847).
//!
//! # Error handling
//!
//! This crate exposes two distinct error types:
//! [`error::Link16Error`] for wire-format-layer failures (truncated
//! buffers, length-field mismatch, unknown header version) and
//! [`codec::Link16EntityError`] for the additional class of "this
//! Entity cannot be represented as a JREAP-C frame" failures that
//! surface from the [`rustgate_core::entity::EntityCodec`] boundary.
//! The split mirrors the per-category split in `rustgate-dis` and
//! `rustgate-asterix` so a SIEM that pages on `link16.frame_rejected`
//! does not also page on the routine
//! `link16.entity.unsupported_entity_kind` signal during
//! cross-protocol fan-out.

pub mod codec;
pub mod error;
pub mod header;
pub mod jseries;

pub use codec::{LINK16_PREFIX, Link16Codec, Link16EntityError};
pub use error::Link16Error;
pub use header::{
    JREAP_C_VERSION, JREAP_DEFAULT_TCP_PORT, JREAP_HEADER_LEN, JreapFrame, JreapMessageType,
};
pub use jseries::{IffCodes, J2_2AirTrack, JseriesKinematics, JseriesMessage, PlatformType};
