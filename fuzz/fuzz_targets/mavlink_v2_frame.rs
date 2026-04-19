// Copyright © 2026 Roberto Chiofalo.

#![no_main]
#![allow(clippy::panic, clippy::unwrap_used)]

//! Fuzz the MAVLink v1/v2 frame parser.
//!
//! `MavlinkFrameCodec` has several hand-rolled pieces that attract
//! attention under hostile input:
//!
//! - Byte-at-a-time resync when the current cursor is not pointing at a
//!   MAVLink magic byte (`0xFE` v1 / `0xFD` v2).
//! - `pending_total_len` state carried across `decode()` calls — a partial
//!   header on one call is completed on the next.
//! - INCOMPAT-flag validation: any v2 frame with an unknown `INCOMPAT` bit
//!   MUST be rejected (the signature trailer position depends on the flag,
//!   so a receiver that can't parse the flag can't locate the CRC either).
//! - Variable-length signature trailer (+13 bytes when `IFLAG_SIGNED` is
//!   set) and the 280-byte hard cap.
//!
//! The fuzzer drains frames in a loop so state transitions — invalid
//! INCOMPAT followed by a good frame, resync over random bytes between
//! frames, partial header reads — are exercised in a single run. The
//! iteration bound matches `data.len()` because every error path advances
//! the buffer by at least one byte, so the loop cannot spin.

use libfuzzer_sys::fuzz_target;
use rustgate_mavlink::MavlinkFrameCodec;
use tokio_util::bytes::BytesMut;
use tokio_util::codec::Decoder;

fuzz_target!(|data: &[u8]| {
    let mut codec = MavlinkFrameCodec::new();
    let mut buf = BytesMut::from(data);
    // Cap iterations at len+1: every decode() call either emits a frame
    // (advancing by >= header_len bytes), returns Err after a 1-byte
    // advance on a bad magic/INCOMPAT, or returns Ok(None) meaning more
    // bytes are needed. An upper bound of len+1 therefore cannot be
    // exceeded on a well-behaved implementation; a regression that did
    // loop forever would time out the fuzzer (libFuzzer `-timeout` flag)
    // rather than silently spin.
    for _ in 0..=data.len() {
        match codec.decode(&mut buf) {
            Ok(Some(_frame)) => continue,
            Ok(None) | Err(_) => break,
        }
    }
});
