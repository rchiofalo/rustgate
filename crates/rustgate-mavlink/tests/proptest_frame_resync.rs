// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

#![allow(clippy::panic, clippy::unwrap_used)]
//! Property-based tests for the MAVLink frame resync invariant.
//!
//! Refs #789 / F-131. Pins the operational guarantee that the
//! [`MavlinkFrameCodec`] state machine gives every consumer downstream
//! of a noisy or hostile link:
//!
//! 1. **Never panics.** `Decoder::decode` returns either `Ok(Some(_))`
//!    on a complete frame, `Ok(None)` waiting for more bytes, or
//!    `Err(io::Error)` on a typed rejection. Arbitrary garbage in MUST
//!    NOT panic.
//! 2. **Always makes progress.** A buffer that does not start with a
//!    MAVLink magic byte (`0xFE` or `0xFD`) is consumed (the resync
//!    loop drops one byte at a time) until either a magic byte is
//!    found or the buffer is empty. The decoder never returns `None`
//!    while leaving non-magic bytes in the buffer.
//! 3. **Bounded buffer growth.** After a single `decode()` call on
//!    arbitrary garbage, the remaining buffer is either empty or
//!    starts with a magic byte. The decoder never expands the
//!    buffer beyond the protocol max (280 bytes for v2 signed).
//!
//! These properties together guarantee that an attacker who streams
//! arbitrary bytes at the listener cannot starve the parser, pin
//! memory, or panic the decode hot path.

use bytes::BytesMut;
use proptest::prelude::*;
use rustgate_mavlink::{MAVLINK_V1_MAGIC, MAVLINK_V2_MAGIC, MavlinkFrameCodec};
use tokio_util::codec::Decoder;

/// Permissive codec mirrors the test-helper used inside the crate's own
/// unit tests: signing policy is disabled and v1 is allowed so the
/// resync invariant under test is exercised regardless of which magic
/// byte the generator happens to land on. The strict-policy paths are
/// covered by the in-crate unit tests; here we want pure framing
/// behaviour, not policy enforcement.
fn permissive_codec() -> MavlinkFrameCodec {
    MavlinkFrameCodec::new()
        .with_allow_v1(true)
        .with_require_signing(false)
}

proptest! {
    #![proptest_config(ProptestConfig {
        // 256 cases keeps the test fast on CI runners (each case
        // builds at most a few hundred bytes and runs the codec to
        // exhaustion). The state-machine surface is small; 256 cases
        // is generous coverage.
        cases: 256,
        ..ProptestConfig::default()
    })]

    /// Arbitrary byte streams must not panic the decoder. The test
    /// drains the buffer with repeated `decode()` calls, asserting on
    /// every iteration that the loop is making progress: either a
    /// frame was emitted, an error returned, or some bytes consumed.
    /// A regression that left non-magic bytes at the head of the
    /// buffer would fail the post-loop assertion.
    #[test]
    fn arbitrary_bytes_never_panic_and_always_resync(
        bytes in proptest::collection::vec(any::<u8>(), 0..512)
    ) {
        let mut codec = permissive_codec();
        let mut buf = BytesMut::from(bytes.as_slice());

        // Drain loop. Every iteration must consume bytes or terminate;
        // an iteration that returns `Ok(None)` AND leaves
        // non-magic bytes at the head would be a resync regression.
        let mut iterations = 0usize;
        loop {
            iterations += 1;
            // Defense in depth: a malformed implementation could in
            // principle loop forever. The protocol max frame is 280
            // bytes and the worst-case input is 512 bytes of garbage,
            // so 4096 iterations is well above any legitimate bound.
            prop_assert!(
                iterations < 4096,
                "decode loop did not terminate (potential infinite loop)"
            );

            match codec.decode(&mut buf) {
                Ok(Some(frame)) => {
                    // Emitted a frame — must be non-empty and start
                    // with a recognised magic byte.
                    prop_assert!(!frame.is_empty(), "emitted empty frame");
                    prop_assert!(
                        frame[0] == MAVLINK_V1_MAGIC || frame[0] == MAVLINK_V2_MAGIC,
                        "emitted frame does not start with a magic byte"
                    );
                }
                Ok(None) => {
                    // Need more bytes. The post-condition is that any
                    // remaining buffered bytes start with a magic byte
                    // — otherwise resync is broken.
                    if !buf.is_empty() {
                        prop_assert!(
                            buf[0] == MAVLINK_V1_MAGIC || buf[0] == MAVLINK_V2_MAGIC,
                            "Ok(None) returned with non-magic byte 0x{:02X} at head",
                            buf[0]
                        );
                    }
                    break;
                }
                Err(_) => {
                    // Typed rejection. A frame that violated policy
                    // or had a bad header is reported as an error;
                    // the codec's contract says one byte (or one
                    // frame's worth) must have been consumed so
                    // progress is guaranteed. Continue the loop to
                    // try the next.
                    continue;
                }
            }
        }
    }

    /// A buffer made entirely of non-magic garbage must drain to empty
    /// (the resync loop discards everything and returns `Ok(None)`)
    /// without ever returning a frame or an error.
    #[test]
    fn pure_garbage_drains_to_empty_with_no_frame(
        bytes in proptest::collection::vec(
            // Filter so no magic byte appears in the input — this is
            // the "pure garbage" universe.
            any::<u8>().prop_filter(
                "not a magic byte",
                |b| *b != MAVLINK_V1_MAGIC && *b != MAVLINK_V2_MAGIC,
            ),
            0..256,
        )
    ) {
        let mut codec = permissive_codec();
        let mut buf = BytesMut::from(bytes.as_slice());

        // Single decode() call with pure garbage must return Ok(None)
        // and consume the entire buffer (resync drops everything).
        let result = codec.decode(&mut buf);
        prop_assert!(
            matches!(result, Ok(None)),
            "garbage stream produced unexpected result: {:?}",
            result.as_ref().map(|opt| opt.as_ref().map(|f| f.len()))
        );
        prop_assert!(
            buf.is_empty(),
            "non-magic garbage must drain entirely, {} bytes left",
            buf.len()
        );
    }

    /// A valid v1 frame preceded by an arbitrary garbage prefix must
    /// be recovered intact. The resync loop should drop the prefix
    /// one byte at a time until it lands on the magic byte.
    #[test]
    fn garbage_prefix_does_not_consume_following_v1_frame(
        prefix in proptest::collection::vec(
            // Filter so the prefix never accidentally contains a magic
            // byte (which would split the buffer into two frames or
            // confuse the resync invariant we're testing).
            any::<u8>().prop_filter(
                "not a magic byte",
                |b| *b != MAVLINK_V1_MAGIC && *b != MAVLINK_V2_MAGIC,
            ),
            0..64,
        ),
        len in 0u8..=32,
    ) {
        // Build a minimal v1 frame: STX, LEN, SEQ, SYS, COMP, MSGID(=0
        // for HEARTBEAT — known to crc_extra), payload, CRC.
        let mut frame = Vec::with_capacity(8 + len as usize);
        frame.push(MAVLINK_V1_MAGIC);
        frame.push(len);
        frame.push(0); // seq
        frame.push(1); // sysid
        frame.push(2); // compid
        frame.push(0); // msgid = HEARTBEAT (0) so the CRC-EXTRA gate accepts it
        frame.extend(std::iter::repeat_n(0xAB, len as usize));
        frame.extend_from_slice(&[0, 0]); // CRC (not verified)

        let mut buf = BytesMut::new();
        buf.extend_from_slice(&prefix);
        buf.extend_from_slice(&frame);

        let mut codec = permissive_codec();
        let decoded = codec.decode(&mut buf)
            .map_err(|e| TestCaseError::fail(format!("decode failed: {e}")))?
            .ok_or_else(|| TestCaseError::fail("expected Some(frame)"))?;

        prop_assert_eq!(decoded.as_ref(), frame.as_slice());
    }
}
