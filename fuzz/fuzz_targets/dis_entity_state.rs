// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

#![no_main]
#![allow(clippy::panic, clippy::unwrap_used)]

//! Fuzz the DIS (IEEE 1278.1-2012) Entity State PDU decoder.
//!
//! `rustgate_dis::EntityStatePdu::decode` accepts an arbitrary byte
//! slice and returns a typed `EntityStatePdu` or a `DisError`. The
//! decoder sits behind a UDP multicast listener in the typical
//! deployment, so every datagram on the simulation channel hits the
//! parser — a panic here is a remote DoS reachable from any host
//! that can join the multicast group.
//!
//! # Why this surface earns a fuzzer
//!
//! - The PDU starts with a 12-byte common PDU header that carries a
//!   16-bit big-endian `length` field declaring the **total** PDU
//!   size (header + body). The decoder must validate
//!   `buf.len() == declared_len` exactly — neither shorter (would
//!   over-read into uninitialised memory if the body parse trusted
//!   the header) nor longer (silent slack would mask a framing bug
//!   upstream). A regression that compared `>=` instead of `==` is
//!   in scope.
//! - The entity body is a fixed 132-byte layout followed by a
//!   variable-length array of `articulation_parameters`, each 16
//!   bytes. The count is an unchecked `u8` on the wire; a value of
//!   `255` declares 4080 bytes of trailing data the buffer may not
//!   actually contain. The decoder must surface `Truncated` rather
//!   than panicking at the slice index.
//! - The marking field is 11 bytes of ASCII-or-UTF-8 padded with
//!   nulls; arbitrary bytes (including invalid UTF-8) must surface
//!   as a typed error or be carried as raw bytes — a regression
//!   that called `std::str::from_utf8(...).unwrap()` would panic
//!   on hostile input.
//! - The ECEF location triplet is `[f64; 3]`; arbitrary bytes
//!   reinterpreted as IEEE-754 doubles can be NaN or infinity. The
//!   subsequent `ecef_to_wgs84` conversion uses `sqrt`, `atan2`,
//!   and division — a regression that produced a silent NaN-laden
//!   `Position` would not panic, but a sanity-check that asserted
//!   `lat.is_finite()` and panicked on failure would.
//!
//! # Failure modes the fuzzer would catch
//!
//! - A PDU header LEN field declaring more bytes than `buf.len()`
//!   without surfacing `LengthMismatch` (would panic inside the
//!   body slice).
//! - An articulation-parameter count that walks the cursor past
//!   the end of the buffer (must return `Truncated`).
//! - A `pdu_type` byte not matching `EntityState` not surfaced as
//!   `UnexpectedPduType` early (would do redundant work and
//!   potentially panic in the body parse).
//!
//! The fuzz target is a single-shot decode; only the absence of a
//! panic / sanitiser complaint matters.

use libfuzzer_sys::fuzz_target;
use rustgate_dis::EntityStatePdu;

fuzz_target!(|data: &[u8]| {
    let _ = EntityStatePdu::decode(data);
});
