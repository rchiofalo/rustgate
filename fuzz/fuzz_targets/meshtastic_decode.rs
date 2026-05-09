// Copyright © 2026 Roberto Chiofalo.

#![no_main]
#![allow(clippy::panic, clippy::unwrap_used)]

//! Fuzz the Meshtastic LoRa TAKPacket decoder.
//!
//! `rustgate_meshtastic::decode_tak_packet` accepts an arbitrary byte
//! slice from the wire and returns a typed [`TakPacket`] or a
//! [`MeshtasticError`]. The decoder sits at the boundary between the
//! Meshtastic mesh-radio link and the rustgate router — every frame
//! that arrives off the LoRa transport runs through it before any
//! routing decision, so a panic here is a remote denial-of-service
//! reachable from any radio inside transmit range.
//!
//! # Why this surface earns a fuzzer
//!
//! - The wire format is a **hand-rolled protobuf** (no `prost` /
//!   no generated code). The implementation walks varints, length-
//!   delimited submessages, and a three-arm `oneof` on top of `bytes`
//!   primitives. A varint that exceeds the 10-byte maximum, a length
//!   prefix that declares more bytes than the buffer holds, or a
//!   field tag with an unsupported wire type all need to surface as
//!   typed `MeshtasticError` variants — never as a slice-index panic
//!   or an arithmetic overflow.
//! - The 237-byte `MAX_PAYLOAD_BYTES` cap is enforced **before** the
//!   parse loop runs; a regression that moved the check inside a
//!   submessage decoder would let an attacker craft a 237-byte outer
//!   frame whose inner length-delimited blob recursed into a multi-MB
//!   allocation. The fuzzer would surface that as either an OOM kill
//!   or a sanitiser complaint depending on the shape.
//! - The `oneof` discriminator (PLI vs GeoChat vs opaque detail) is
//!   selected by tag dispatch inside the loop — a malformed tag must
//!   surface as `UnknownWireType` rather than silently mis-assigning
//!   bytes to the wrong variant. The `Pli::from_position_floats`
//!   helper does float→int saturation; arbitrary `f64` bytes flowing
//!   in via `sfixed32` and reinterpreted as floats during entity
//!   conversion must not panic on `f64::NAN` / `f64::INFINITY`.
//!
//! # Failure modes the fuzzer would catch
//!
//! - A varint continuation chain that ran off the buffer end without
//!   returning `MeshtasticError::TruncatedVarint` (would surface as
//!   a slice-index panic on `bytes[0]`).
//! - A length-delimited submessage whose declared inner length was
//!   greater than the remaining buffer (must return `Truncated`,
//!   not panic at `&bytes[..len]`).
//! - A `wire_type = 3` (deprecated start-group) tag that wasn't
//!   rejected as `UnknownWireType` and instead fell through to a
//!   default arm with no cursor advance (would burn CPU in an
//!   infinite loop).
//!
//! The fuzz target is a single-shot decode: every input is treated
//! as exactly one wire-form TAKPacket, mirroring how the
//! transport-layer caller hands a length-stripped frame to the
//! codec. Only the absence of a panic / sanitiser complaint
//! matters; the `Result` is dropped.

use libfuzzer_sys::fuzz_target;
use rustgate_meshtastic::decode_tak_packet;

fuzz_target!(|data: &[u8]| {
    let _ = decode_tak_packet(data);
});
