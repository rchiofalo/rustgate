// Copyright © 2026 Roberto Chiofalo.

//! ASTERIX (All Purpose STructured Eurocontrol suRveillance Information
//! eXchange) binary codec for rustgate.
//!
//! ASTERIX is the Eurocontrol-standardised wire format used by air-traffic
//! control and surveillance systems (primary radar, secondary radar, ADS-B,
//! multilateration, fused trackers, counter-UAS sensors). A live ASTERIX
//! feed is a stream of *datablocks* on UDP or TCP; each datablock carries
//! one or more *records* of a single *category*. This crate implements a
//! decoder for **CAT-062** ("SDPS Track Messages") — the system-track
//! update messages emitted by Surveillance Data Processing Systems and
//! by counter-UAS radar trackers.
//!
//! # Scope
//!
//! - [`cat062::decode_cat062`] — slices an ASTERIX datablock and returns
//!   one [`cat062::Cat062Track`] per record. A single datablock may
//!   contain N records of the same category per the CAT-062 specification
//!   (Eurocontrol document SUR.ET1.ST05.2000-STD-12-01, "Eurocontrol
//!   Standard Document for Surveillance Data Exchange — Part 9: Category
//!   062").
//! - [`cat062::Cat062Track`] — typed surveillance track with the
//!   issue-#1121 minimum-viable subset of fields decoded: track number,
//!   time-of-day, WGS-84 position, calculated track velocity (Cartesian
//!   vx/vy), Mode-3/A code, flight level (Mode-C), and track status.
//! - [`cat062::Cat062Error`] — `thiserror`-derived failure modes with
//!   precise variants so the session layer (a future PR wires UDP) can
//!   route truncated frames to a recoverable resync path and reject only
//!   the offending datablock.
//!
//! # Spec version
//!
//! Implements the wire format and Field Reference Numbers (FRNs) defined
//! by **ASTERIX CAT-062 v1.20** (Eurocontrol SUR.ET1.ST05.2000-STD-12-01,
//! Edition 1.20, March 2017). The header structure (CAT byte, 16-bit
//! big-endian length, FSPEC bitmap per record) is invariant across
//! ASTERIX categories — see Eurocontrol "Part 1: Generic ASTERIX
//! Concept" — so the framing code is straightforward to lift if a later
//! PR adds CAT-021 (ADS-B), CAT-048 (Mode-S radar), or other categories.
//!
//! # What is deliberately absent
//!
//! - **UDP listener wiring.** A real CAT-062 feed lives on UDP multicast
//!   (typically address `224.x.x.x` per local ANSP convention) but
//!   binding the socket and feeding the decoder is the next PR — this
//!   crate is a pure decode library with no I/O.
//! - **Encoder direction.** Production rustgate ingests ASTERIX, it does
//!   not synthesise it. A receive-only codec halves the surface area and
//!   removes the entire "what time/precision/bit-mask did the upstream
//!   sender use?" class of interop bugs.
//! - **Mapping to `rustgate_core::message::RoutableMessage` / Entity.**
//!   That belongs in the integration layer (issue #847) so this crate
//!   stays free of routing concepts. A consumer wires `Cat062Track →
//!   RoutableMessage` based on its own deployment (group derivation,
//!   tenant scoping, CoT translation).
//! - **Other categories.** CAT-001/002, CAT-021 (ADS-B), CAT-034/048
//!   (radar service / Mode-S), CAT-150 (mil track) all share the
//!   datablock framing but differ in field catalogue. They land as
//!   sibling modules behind the same `decode_*` entry point when
//!   operationally needed.
//! - **Field encoder direction for unsupported FRNs.** The decoder skips
//!   over fields it does not consume (forward-compatible) but cannot
//!   re-emit them; a future encoder PR would have to round-trip the
//!   entire catalogue.

pub mod cat021;
pub mod cat062;

pub use cat021::{Cat021Error, Cat021Report, decode_cat021};
pub use cat062::{Cat062Error, Cat062Track, ModeCCode, TrackStatus, decode_cat062};
