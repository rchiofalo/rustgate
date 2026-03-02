#![no_main]

use libfuzzer_sys::fuzz_target;
use rustgate_proto::TakFrameCodec;
use tokio_util::bytes::BytesMut;
use tokio_util::codec::Decoder;

fuzz_target!(|data: &[u8]| {
    let mut codec = TakFrameCodec::new();
    let mut buf = BytesMut::from(data);
    let _ = codec.decode(&mut buf);
});
