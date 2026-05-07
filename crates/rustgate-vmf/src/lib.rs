// Copyright © 2026 Roberto Chiofalo.

//! VMF (Variable Message Format, MIL-STD-6017) bit-level codec for
//! rustgate. Closes #868 (MVP scope: K05.1 Position Report).
//!
//! VMF is the Army/USMC standard for digital tactical messaging on
//! SINCGARS and EPLRS radios. Blue Force Tracker position-location
//! information (PLI) rides on K05.1 Position Reports; broader
//! command-and-control (K01.x), intelligence (K02.x), land combat
//! (K04.x), fire support (K06.x), and free-text (K00.x) messages
//! share the same MIL-STD-2045-47001 application header and the
//! same FPI/FRI/GPI bit-packing discipline.
//!
//! # Scope of this deliverable (MVP)
//!
//! This crate ships **K05.1 Position Report** bidirectionally —
//! decode of a wire frame into [`crate::k05_1::K051PositionReport`]
//! and encode of one back to bytes. The
//! [`crate::header::VmfHeader`] decode/encode covers the
//! MIL-STD-2045-47001 application header (URN, DTG, message type,
//! classification, addressing) for every K-series message; non-MVP
//! K-series surface as [`VmfMessage::Unknown { body, … }`] so a
//! follow-up PR can extend this crate without breaking call sites.
//!
//! K01.x, K02.x, K04.x, K06.x, and K00.x message bodies are deferred
//! to subsequent issues. The placeholder-then-extend strategy
//! mirrors how `rustgate_asterix` grew from CAT-062 to add CAT-021
//! and CAT-048: one K-series at a time, behind the same trait impl.
//!
//! # FPI / FRI / GPI primer
//!
//! VMF's wire form is bit-oriented and uses three classes of
//! presence indicator that gate fields and groups:
//!
//! - **FPI (Field Presence Indicator)** — a single bit preceding an
//!   optional field. `1` means the field is present; `0` means the
//!   field is omitted and the next FPI (or unconditional field)
//!   follows immediately. Used for every "optional scalar" in the
//!   header and the K05.1 body.
//! - **FRI (Field Recurrence Indicator)** — a single bit between
//!   repeated occurrences of the same field. `1` means another
//!   instance follows; `0` terminates the repetition. The MVP does
//!   not exercise FRI (K05.1's MVP fields are all single-shot), but
//!   the [`crate::bitstream`] helpers support the pattern for
//!   forward-compatible follow-up issues.
//! - **GPI / GRI (Group Presence / Recurrence Indicators)** —
//!   identical semantics to FPI/FRI but gating an entire group of
//!   bits rather than a single field. Used by header subgroups
//!   (compression group, addressing group) and by K05.x recurrence
//!   blocks.
//!
//! # UDP wire transport
//!
//! VMF datagrams are delivered on UDP port 1581 (declared by
//! [`VMF_DEFAULT_UDP_PORT`]). Binding the socket and demultiplexing
//! datagrams to this codec is intentionally elsewhere — this crate
//! is a pure decode/encode library, mirroring `rustgate-asterix` and
//! `rustgate-mavlink` (each landed first as a pure codec, then
//! later as a wired listener).
//!
//! # Public API
//!
//! - [`VmfCodec`] — `EntityCodec` impl bridging VMF wire frames and
//!   the canonical [`rustgate_core::entity::Entity`] shape.
//! - [`VmfMessage`] — enum of typed K05.1 plus opaque
//!   [`VmfMessage::Unknown`] for non-MVP K-series.
//! - [`decode_message`] / [`encode_k05_1`] — lower-level entry
//!   points for callers that want the raw header and body without
//!   the `Entity` round-trip.
//! - [`VmfError`] — typed error surface with `Truncated`,
//!   `InvalidValue`, `Unsupported`, and `EncodeOverflow` variants.
//! - [`VmfEntityError`] — boundary error type returned by the
//!   `EntityCodec` implementation; wraps [`VmfError`] for decode
//!   failures and adds an `UnsupportedEntityKind` variant for the
//!   encode direction.
//! - [`VMF_DEFAULT_UDP_PORT`] — IANA-registered VMF UDP port.
//!
//! # Spec assumptions
//!
//! MIL-STD-6017 is not freely available. The wire form pinned in
//! this MVP is the layered subset published in open-literature
//! references (FM 6-99, NATO STANAG 5616 cross-references, JPL/Caltech
//! VMF interop notes). Where the open-literature shape leaves a
//! field ambiguous, the codec uses the most common width and
//! documents the choice inline (search for `MVP` in
//! `crate::header` and `crate::k05_1`). A reviewer with access to
//! the closed spec can correct individual widths without touching
//! the codec scaffolding.

#![forbid(unsafe_code)]

pub mod bitstream;
pub mod codec;
pub mod error;
pub mod header;
pub mod k05_1;

pub use bitstream::{BitReader, BitWriter};
pub use codec::{VMF_PREFIX, VmfCodec, VmfEntityError, VmfMessage, decode_message, encode_k05_1};
pub use error::VmfError;
pub use header::{Classification, Dtg, MessageId, VMF_HEADER_VERSION, VmfHeader};
pub use k05_1::K051PositionReport;

/// IANA-registered VMF UDP port used by SINCGARS-ASIP and EPLRS
/// tactical radios for application-layer message delivery.
///
/// A future PR will wire a UDP listener that demultiplexes datagrams
/// on this port to the [`VmfCodec`]; today this constant exists so
/// configuration scaffolding (issue #868 follow-ups) can pin the
/// port symbolically rather than re-declaring the magic number.
pub const VMF_DEFAULT_UDP_PORT: u16 = 1581;
