// Copyright © 2026 Roberto Chiofalo.

#![no_main]
#![allow(clippy::panic, clippy::unwrap_used)]

//! Fuzz the ASTERIX CAT-062 surveillance-track decoder.
//!
//! `rustgate_asterix::decode_cat062` accepts an arbitrary byte slice
//! from the wire and returns a typed `Vec<Cat062Track>` or a
//! `Cat062Error`. The decoder is intricate — it sits on the boundary
//! between the receive socket (UDP multicast in the typical
//! deployment) and the routing / display layer:
//!
//! - The generic ASTERIX framing (CAT byte, 16-bit big-endian LEN,
//!   per-record FSPEC) is hand-rolled — an off-by-one on the LEN
//!   header or an FSPEC FX-chain that exceeds the documented depth
//!   would surface as either a panic or a silent buffer over-read.
//! - The FSPEC parser walks an extension-bit chain that can in
//!   principle be unbounded (each `FX=1` extends to one more octet);
//!   `Cat062Error::TruncatedFspec` is the typed exit when the chain
//!   runs off the buffer end, but a regression that did not bound
//!   the loop would burn CPU on a crafted multi-MB FSPEC.
//! - Multi-record datablocks walk records sequentially using the
//!   datablock LEN as the outer terminator — a record whose own
//!   FSPEC declares a length exceeding the remainder of the
//!   datablock must surface as `LengthMismatch` rather than walking
//!   past the LEN and into the next datablock.
//! - The Mode-C altitude field uses 15-bit two's-complement sign-
//!   extension via the standard "shift-up-shift-down" trick; a
//!   regression that off-by-one'd the bit width would produce
//!   silently-wrong altitudes (as opposed to a panic), so the fuzzer
//!   verifies *no panic* but cannot verify semantic correctness from
//!   arbitrary bytes — that is what the unit tests pin.
//! - Compound items currently surface `TruncatedField` rather than
//!   silently desyncing the cursor; the fuzzer must observe that as
//!   a typed error rather than a panic.
//!
//! The fuzz target is a single-shot decode: ASTERIX is datagram-
//! oriented and one input slice represents one wire datagram. The
//! `Result` is dropped and only the absence of a panic / sanitiser
//! complaint matters here.

use libfuzzer_sys::fuzz_target;
use rustgate_asterix::decode_cat062;

fuzz_target!(|data: &[u8]| {
    // The decoder is documented to never panic on hostile input —
    // every error path returns a typed `Cat062Error`. Calling decode
    // with arbitrary bytes is therefore the entire fuzz contract.
    let _ = decode_cat062(data);
});
