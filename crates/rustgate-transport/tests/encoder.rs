//! Unit tests for MessageEncoder implementations.

use std::collections::BTreeSet;
use std::time::SystemTime;

use bytes::Bytes;
use rustgate_core::identity::Identity;
use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};
use rustgate_transport::{CotEncoder, MessageEncoder, RawEncoder};

fn make_message(payload: &[u8], source_protocol: &str) -> RoutableMessage {
    RoutableMessage {
        source: Identity {
            cn: "test-client".into(),
            fingerprint: "aa:bb:cc".into(),
            groups: BTreeSet::new(),
        },
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
fn raw_encoder_preserves_payload() {
    let encoder = RawEncoder;
    let payload = b"<event uid='test'/>";
    let msg = make_message(payload, "cot");

    let encoded = encoder.encode(&msg).expect("encode should succeed");
    assert_eq!(encoded.as_ref(), payload);
}

#[test]
fn raw_encoder_handles_binary() {
    let encoder = RawEncoder;
    let payload: &[u8] = &[0x00, 0x01, 0x02, 0xFF, 0xFE];
    let msg = make_message(payload, "binary");

    let encoded = encoder.encode(&msg).expect("encode should succeed");
    assert_eq!(encoded.as_ref(), payload);
}

#[test]
fn raw_encoder_handles_empty_payload() {
    let encoder = RawEncoder;
    let msg = make_message(&[], "tcp");

    let encoded = encoder.encode(&msg).expect("encode should succeed");
    assert!(encoded.is_empty());
}

#[test]
fn cot_encoder_passes_through_cot_payload() {
    let encoder = CotEncoder;
    let payload = b"<event uid='alpha' type='a-f-G'/>";
    let msg = make_message(payload, "cot");

    let encoded = encoder.encode(&msg).expect("encode should succeed");
    assert_eq!(encoded.as_ref(), payload);
}

#[test]
fn cot_encoder_passes_through_non_cot_payload() {
    let encoder = CotEncoder;
    let payload = b"raw binary data";
    let msg = make_message(payload, "tcp");

    let encoded = encoder.encode(&msg).expect("encode should succeed");
    assert_eq!(encoded.as_ref(), payload);
}

#[test]
fn cot_encoder_handles_empty_source_protocol() {
    let encoder = CotEncoder;
    let payload = b"test";
    let msg = make_message(payload, "");

    let encoded = encoder.encode(&msg).expect("encode should succeed");
    assert_eq!(encoded.as_ref(), payload);
}

#[test]
fn encoders_are_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<RawEncoder>();
    assert_send_sync::<CotEncoder>();
}
