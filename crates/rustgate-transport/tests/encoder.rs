//! Unit tests for Codec implementations.

use std::collections::BTreeSet;
use std::time::SystemTime;

use bytes::{Bytes, BytesMut};
use rustgate_core::codec::Codec;
use rustgate_core::identity::Identity;
use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};
use rustgate_transport::{CotCodec, RawCodec};

fn make_message(payload: &[u8], source_protocol: &str) -> RoutableMessage {
    RoutableMessage {
        source: Identity::new("test-client".into(), "aa:bb:cc".into(), BTreeSet::new())
            .expect("valid identity"),
        destination: Destination::Broadcast,
        payload: Bytes::from(payload.to_vec()),
        metadata: Metadata {
            received_at: SystemTime::now(),
            source_protocol: source_protocol.into(),
            message_type: MessageType::Position,
            ttl: None,
        },
    }
}

#[test]
fn raw_codec_preserves_payload() {
    let codec = RawCodec;
    let payload = b"<event uid='test'/>";
    let msg = make_message(payload, "cot");

    let encoded = codec.encode_payload(&msg).expect("encode should succeed");
    assert_eq!(encoded.as_ref(), payload);
}

#[test]
fn raw_codec_decode_preserves_bytes() {
    let codec = RawCodec;
    let input = BytesMut::from(&b"hello world"[..]);

    let decoded = codec
        .decode_payload(input.clone())
        .expect("decode should succeed");
    assert_eq!(decoded.as_ref(), input.as_ref());
}

#[test]
fn raw_codec_handles_binary() {
    let codec = RawCodec;
    let payload: &[u8] = &[0x00, 0x01, 0x02, 0xFF, 0xFE];
    let msg = make_message(payload, "binary");

    let encoded = codec.encode_payload(&msg).expect("encode should succeed");
    assert_eq!(encoded.as_ref(), payload);
}

#[test]
fn raw_codec_handles_empty_payload() {
    let codec = RawCodec;
    let msg = make_message(&[], "tcp");

    let encoded = codec.encode_payload(&msg).expect("encode should succeed");
    assert!(encoded.is_empty());
}

#[test]
fn cot_codec_passes_through_cot_payload() {
    let codec = CotCodec;
    let payload = b"<event uid='alpha' type='a-f-G'/>";
    let msg = make_message(payload, "cot");

    let encoded = codec.encode_payload(&msg).expect("encode should succeed");
    assert_eq!(encoded.as_ref(), payload);
}

#[test]
fn cot_codec_passes_through_non_cot_payload() {
    let codec = CotCodec;
    let payload = b"raw binary data";
    let msg = make_message(payload, "tcp");

    let encoded = codec.encode_payload(&msg).expect("encode should succeed");
    assert_eq!(encoded.as_ref(), payload);
}

#[test]
fn cot_codec_handles_empty_source_protocol() {
    let codec = CotCodec;
    let payload = b"test";
    let msg = make_message(payload, "");

    let encoded = codec.encode_payload(&msg).expect("encode should succeed");
    assert_eq!(encoded.as_ref(), payload);
}

#[test]
fn cot_codec_detects_xml() {
    let codec = CotCodec;
    assert!(codec.detect(b"<event/>") > 0.5);
    assert_eq!(codec.detect(b"\xBF\x01\x02"), 0.0);
}

#[test]
fn raw_codec_detect_returns_zero() {
    let codec = RawCodec;
    assert_eq!(codec.detect(b"anything"), 0.0);
}

#[test]
fn codecs_are_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<RawCodec>();
    assert_send_sync::<CotCodec>();
}

#[test]
fn raw_codec_protocol_id() {
    assert_eq!(RawCodec.protocol_id(), "raw");
}

#[test]
fn cot_codec_protocol_id() {
    assert_eq!(CotCodec.protocol_id(), "cot");
}
