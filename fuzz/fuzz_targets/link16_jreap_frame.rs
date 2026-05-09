// Copyright © 2026 Roberto Chiofalo.

#![no_main]
#![allow(clippy::panic, clippy::unwrap_used)]

//! Fuzz the Link 16 (JREAP-C, MIL-STD-3011) frame decoder.
//!
//! `rustgate_link16::Link16Codec::to_entity` walks an arbitrary byte
//! slice through three layered parsers — the 16-byte JREAP-C frame
//! header, a length-delimited body, and the J-series message dispatch
//! (J2.2 typed, everything else opaque) — before returning a typed
//! `Entity` or a `Link16EntityError`. The decoder sits behind the
//! JREAP-C TCP listener (default port 4500), so every connection
//! hits this surface; a panic is a remote DoS reachable from any
//! host that can establish a TCP session.
//!
//! # Why this surface earns a fuzzer
//!
//! - The 16-byte JREAP-C header carries a `body_length` field that
//!   declares how many trailing bytes form the J-series body. The
//!   decoder slices `payload[16..16 + body_length]`; a regression
//!   that didn't bound-check the addition for overflow or didn't
//!   verify the slice fits the buffer would panic on hostile input
//!   — `body_length = 0xFFFF_FFFF` plus a 16-byte buffer is the
//!   canonical attack.
//! - The `JreapMessageType` discriminator (data, ack, heartbeat,
//!   security, …) is a `u8`; only `JseriesData` proceeds to body
//!   decode. A regression that fell through to the body decoder for
//!   non-data types would walk a heartbeat's tiny payload through
//!   the full J-series parser and likely panic on length-mismatch.
//! - The J-series body's first byte is a label that selects
//!   `J2_2AirTrack` (typed) vs `Other` (opaque). The typed J2.2
//!   parse decodes a fixed 14-byte layout; an `Other` arm carries
//!   the raw bytes verbatim. A regression that declared a body
//!   `J2_2AirTrack` but only supplied 5 bytes must surface as
//!   `Link16Error::Truncated`, not panic at the byte index.
//! - The `track_number` is a `u24` (3 little-endian bytes); arbitrary
//!   bytes reinterpreted via `u32::from_le_bytes` need a `& 0x00FF_FFFF`
//!   mask. A regression that omitted the mask would not panic but
//!   would corrupt the UID — outside the fuzzer's scope but the
//!   panic on the cursor advance is.
//!
//! # Failure modes the fuzzer would catch
//!
//! - A JREAP-C header declaring a body length whose addition with
//!   the header size overflows `usize` (must surface as a typed
//!   error, never panic on `.checked_add(...)?`).
//! - A J2.2 dispatch with a body shorter than the documented 14-
//!   byte layout (must return `Link16Error::Truncated`).
//! - A version byte != JREAP_C_VERSION not surfaced as
//!   `UnsupportedVersion` early (would walk uninitialised state
//!   into the body parse).
//!
//! The fuzz target is a single-shot decode; only the absence of a
//! panic / sanitiser complaint matters.

use libfuzzer_sys::fuzz_target;
use rustgate_core::entity::EntityCodec;
use rustgate_link16::Link16Codec;

fuzz_target!(|data: &[u8]| {
    let _ = Link16Codec.to_entity(data);
});
