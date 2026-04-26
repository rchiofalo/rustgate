// Copyright © 2026 Roberto Chiofalo.

#![no_main]
#![allow(clippy::panic, clippy::unwrap_used)]

//! Fuzz the ASTERIX CAT-021 ADS-B reports decoder.
//!
//! `rustgate_asterix::decode_cat021` accepts an arbitrary byte slice
//! from the wire (typically a UDP-multicast datagram from an SBS-3 /
//! BEAST receiver feeding ADS-B traffic into the routing layer) and
//! returns either `Vec<Cat021Report>` or a typed `Cat021Error`. CAT-021
//! sits on the receive boundary alongside CAT-062 (#1149); the same
//! ASTERIX framing semantics apply (CAT byte + 16-bit BE LEN +
//! per-record FSPEC with FX-chained extension octets), so fuzzing the
//! decoder shakes out the same class of bytes-level invariants:
//!
//! - Generic ASTERIX framing — an off-by-one on the LEN header or an
//!   FSPEC FX-chain that exceeds the documented depth would surface as
//!   either a panic or a silent buffer over-read; the decoder's
//!   `TruncatedDatablock`, `LengthMismatch`, and `TruncatedFspec`
//!   variants are the typed exits the fuzzer pins as the only
//!   acceptable failure modes.
//! - Per-record FSPEC walking is sequential — a record whose own
//!   FSPEC declares fields that exceed the declared datablock LEN
//!   must surface as a typed `TruncatedField` rather than walking
//!   past the LEN and into the next datablock.
//! - The 23-bit signed semicircle decoding for I021/130 (lat/lon)
//!   uses the standard "shift-up-shift-down" sign-extension trick on
//!   a 32-bit word; a regression that off-by-one'd the bit width
//!   would produce silently-wrong WGS-84 coordinates (catastrophic
//!   for a UAS detect-and-avoid stack), but the fuzzer can only
//!   verify *no panic* — semantic correctness on coordinate
//!   sign-extension is pinned by the unit tests.
//! - Compound items (Met Info, Trajectory Intent, Mode S MB Data,
//!   Data Ages — FRNs 31, 34, 39, 42) currently surface
//!   `TruncatedField` rather than silently desyncing the cursor; the
//!   fuzzer must observe that as a typed error rather than a panic
//!   when an FSPEC bit at one of those positions is set.
//! - The 6-bit packed callsign in I021/170 is decoded MSB-first
//!   across 6 bytes via byte-boundary-crossing bit gather; a
//!   regression that misaligned the bit gather could produce a
//!   panic via UTF-8 string construction from non-ASCII bytes (the
//!   decoder is documented to map unknown 6-bit codes to space, but
//!   the fuzzer is the right place to verify that contract holds
//!   under arbitrary input).
//!
//! The fuzz target is a single-shot decode: ASTERIX is
//! datagram-oriented and one input slice represents one wire
//! datagram. The `Result` is dropped — only the absence of a panic /
//! sanitiser complaint matters.

use libfuzzer_sys::fuzz_target;
use rustgate_asterix::decode_cat021;

fuzz_target!(|data: &[u8]| {
    // The decoder is documented to never panic on hostile input —
    // every error path returns a typed `Cat021Error`. Calling decode
    // with arbitrary bytes is therefore the entire fuzz contract.
    let _ = decode_cat021(data);
});
