// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

#![no_main]

use libfuzzer_sys::fuzz_target;
use rustgate_core::protocol::HeaderSize;
use rustgate_transport::LengthPrefixedCodec;
use tokio_util::bytes::BytesMut;
use tokio_util::codec::Decoder;

fuzz_target!(|data: &[u8]| {
    for header_size in [HeaderSize::One, HeaderSize::Two, HeaderSize::Four] {
        let mut codec = LengthPrefixedCodec::new(header_size);
        let mut buf = BytesMut::from(data);
        let _ = codec.decode(&mut buf);
    }
});
