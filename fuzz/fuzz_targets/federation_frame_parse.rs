#![no_main]
#![allow(clippy::panic, clippy::unwrap_used)]

//! Fuzz the V1 federation frame parser pipeline: a length-prefixed
//! (4-byte big-endian header) codec feeding into the heartbeat detector
//! that runs on every decoded payload before forwarding.

use libfuzzer_sys::fuzz_target;
use rustgate_core::protocol::HeaderSize;
use rustgate_federation::heartbeat::is_heartbeat;
use rustgate_transport::LengthPrefixedCodec;
use tokio_util::bytes::BytesMut;
use tokio_util::codec::Decoder;

fuzz_target!(|data: &[u8]| {
    // V1 federation always uses a 4-byte big-endian length prefix.
    let mut codec = LengthPrefixedCodec::new(HeaderSize::Four).with_max_frame_size(1 << 20);
    let mut buf = BytesMut::from(data);

    // Drain frames the same way the V1 read loop does, applying the
    // heartbeat classifier to each successfully decoded payload.
    loop {
        match codec.decode(&mut buf) {
            Ok(Some(frame)) => {
                let _ = is_heartbeat(&frame);
            }
            Ok(None) => break,
            Err(_) => break,
        }
    }

    // Also exercise the heartbeat fast-path classifier directly on raw
    // input so it sees inputs that never form a valid frame.
    let _ = is_heartbeat(data);
});
