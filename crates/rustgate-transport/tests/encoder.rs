// Copyright © 2026 Roberto Chiofalo.

//! Unit tests for Codec encode_payload implementations.

#![allow(clippy::panic, clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::time::SystemTime;

use bytes::Bytes;
use rustgate_core::codec::Codec;
use rustgate_core::identity::Identity;
use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};
use rustgate_transport::{RawLengthPrefixedCodec, RawLineCodec, TakXmlCodec};

fn make_message(payload: &[u8], source_protocol: &str) -> RoutableMessage {
    RoutableMessage {
        source: Identity::new("test-client".into(), "aa:bb:cc".into(), BTreeSet::new())
            .expect("valid identity"),
        destination: Destination::Broadcast,
        payload: Bytes::from(payload.to_vec()),
        metadata: Metadata::new(
            SystemTime::now(),
            source_protocol.into(),
            MessageType::Position,
        ),
        entity: None,
    }
}

#[test]
fn tak_xml_codec_preserves_payload() {
    let codec = TakXmlCodec;
    let payload = b"<event uid='test'/>";
    let msg = make_message(payload, "cot");

    let encoded = codec.encode_payload(&msg).expect("encode should succeed");
    assert_eq!(encoded.as_ref(), payload);
}

#[test]
fn raw_line_codec_handles_binary() {
    let codec = RawLineCodec;
    let payload: &[u8] = &[0x00, 0x01, 0x02, 0xFF, 0xFE];
    let msg = make_message(payload, "binary");

    let encoded = codec.encode_payload(&msg).expect("encode should succeed");
    assert_eq!(encoded.as_ref(), payload);
}

#[test]
fn raw_length_prefixed_codec_handles_empty_payload() {
    let codec = RawLengthPrefixedCodec;
    let msg = make_message(&[], "tcp");

    let encoded = codec.encode_payload(&msg).expect("encode should succeed");
    assert!(encoded.is_empty());
}

#[test]
fn tak_xml_codec_passes_through_cot_payload() {
    let codec = TakXmlCodec;
    let payload = b"<event uid='alpha' type='a-f-G'/>";
    let msg = make_message(payload, "cot");

    let encoded = codec.encode_payload(&msg).expect("encode should succeed");
    assert_eq!(encoded.as_ref(), payload);
}

#[test]
fn raw_line_codec_passes_through_non_xml_payload() {
    let codec = RawLineCodec;
    let payload = b"raw binary data";
    let msg = make_message(payload, "tcp");

    let encoded = codec.encode_payload(&msg).expect("encode should succeed");
    assert_eq!(encoded.as_ref(), payload);
}

#[test]
fn tak_xml_codec_handles_empty_source_protocol() {
    let codec = TakXmlCodec;
    let payload = b"test";
    let msg = make_message(payload, "");

    let encoded = codec.encode_payload(&msg).expect("encode should succeed");
    assert_eq!(encoded.as_ref(), payload);
}

#[test]
fn codecs_are_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<TakXmlCodec>();
    assert_send_sync::<RawLineCodec>();
    assert_send_sync::<RawLengthPrefixedCodec>();
}
