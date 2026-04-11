// Copyright © 2026 Roberto Chiofalo.

#![allow(clippy::panic, clippy::unwrap_used)]
//! Integration tests for TakFrameCodec and protocol negotiation.

use prost::Message;
use rustgate_core::constants::MAX_FRAME_SIZE;
use rustgate_proto::{
    NegotiatedVersion, TakFrameCodec, build_protocol_support_xml, build_tak_response,
    parse_tak_request, tak_proto,
};
use tokio_util::bytes::{BufMut, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

/// Decode a protobuf-style varint from a byte slice.
/// Returns `(value, bytes_consumed)` or `None` if incomplete.
fn decode_varint(buf: &[u8]) -> Option<(usize, usize)> {
    let mut result: u64 = 0;
    let mut shift = 0;
    for (i, &byte) in buf.iter().enumerate().take(5) {
        result |= u64::from(byte & 0x7F) << shift;
        if byte & 0x80 == 0 {
            return Some((result as usize, i + 1));
        }
        shift += 7;
    }
    None
}

/// Encode a length as a protobuf-style varint and append the payload.
/// Returns the wire frame (varint + payload) without the magic byte.
fn encode_varint_frame(payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::new();
    let mut v = payload.len() as u64;
    while v >= 0x80 {
        frame.push((v as u8) | 0x80);
        v >>= 7;
    }
    frame.push(v as u8);
    frame.extend_from_slice(payload);
    frame
}

// ---------------------------------------------------------------------------
// TakFrameCodec: encode/decode round-trips
// ---------------------------------------------------------------------------

#[test]
fn round_trip_minimal_proto_message() {
    let mut codec = TakFrameCodec::new();

    let msg = tak_proto::TakMessage {
        tak_control: None,
        cot_event: None,
    };
    let payload = BytesMut::from(msg.encode_to_vec().as_slice());

    let mut buf = BytesMut::new();
    codec.encode(payload.clone(), &mut buf).unwrap();

    let decoded = codec.decode(&mut buf).unwrap().unwrap();
    assert_eq!(decoded, payload);
}

#[test]
fn round_trip_with_tak_control() {
    let mut codec = TakFrameCodec::new();

    let msg = tak_proto::TakMessage {
        tak_control: Some(tak_proto::TakControl {
            min_proto_version: "1".into(),
            max_proto_version: "1".into(),
            contact_uid: "test-client".into(),
        }),
        cot_event: None,
    };
    let payload = BytesMut::from(msg.encode_to_vec().as_slice());

    let mut buf = BytesMut::new();
    codec.encode(payload.clone(), &mut buf).unwrap();

    let decoded = codec.decode(&mut buf).unwrap().unwrap();
    let roundtripped = tak_proto::TakMessage::decode(&decoded[..]).unwrap();
    let control = roundtripped.tak_control.unwrap();
    assert_eq!(control.min_proto_version, "1");
    assert_eq!(control.max_proto_version, "1");
    assert_eq!(control.contact_uid, "test-client");
}

#[test]
fn multiple_frames_in_single_stream() {
    let mut codec = TakFrameCodec::new();
    let mut buf = BytesMut::new();

    let payloads: Vec<BytesMut> = (0..5)
        .map(|i| BytesMut::from(vec![i as u8; 20 + i * 10].as_slice()))
        .collect();

    for p in &payloads {
        codec.encode(p.clone(), &mut buf).unwrap();
    }

    for expected in &payloads {
        let decoded = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(&decoded, expected);
    }

    // Buffer should be empty now
    assert!(buf.is_empty());
}

#[test]
fn partial_frame_buffering_returns_none_until_complete() {
    let mut codec = TakFrameCodec::new();

    let payload = BytesMut::from(&b"complete-payload"[..]);
    let mut encoded = BytesMut::new();
    codec.encode(payload.clone(), &mut encoded).unwrap();

    // Feed bytes one at a time
    let mut partial = BytesMut::new();
    let total = encoded.len();
    for i in 0..total {
        partial.extend_from_slice(&encoded[i..i + 1]);
        let result = codec.decode(&mut partial).unwrap();
        if i < total - 1 {
            assert!(result.is_none(), "should be None at byte {i}");
        } else {
            assert_eq!(result.unwrap(), payload);
        }
    }
}

#[test]
fn incomplete_varint_returns_none() {
    let mut codec = TakFrameCodec::new();

    // Magic byte + a continuation varint byte (high bit set, no terminator)
    let mut buf = BytesMut::new();
    buf.put_u8(0xBF);
    buf.put_u8(0x80); // continuation bit set, needs more bytes

    assert!(codec.decode(&mut buf).unwrap().is_none());
}

#[test]
fn invalid_magic_byte_returns_error() {
    let mut codec = TakFrameCodec::new();
    let mut buf = BytesMut::from(&[0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05][..]);

    let err = codec.decode(&mut buf).unwrap_err();
    assert!(err.to_string().contains("magic byte"));
}

#[test]
fn various_invalid_magic_bytes() {
    for bad_byte in [0x01, 0x42, 0xBE, 0xC0, 0xFF] {
        let mut codec = TakFrameCodec::new();
        let mut buf = BytesMut::from(&[bad_byte, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05][..]);
        let err = codec.decode(&mut buf).unwrap_err();
        assert!(
            err.to_string().contains("magic byte"),
            "byte 0x{bad_byte:02X} should be rejected: {err}"
        );
    }
}

#[test]
fn varint_exceeding_max_bytes_returns_error() {
    let mut codec = TakFrameCodec::new();

    // Magic byte + 6 continuation bytes (all with high bit set) - exceeds MAX_VARINT_BYTES
    let mut buf = BytesMut::new();
    buf.put_u8(0xBF);
    for _ in 0..6 {
        buf.put_u8(0x80);
    }

    let err = codec.decode(&mut buf).unwrap_err();
    assert!(
        err.to_string().contains("varint"),
        "should mention varint: {err}"
    );
}

#[test]
fn oversized_frame_rejected() {
    let mut codec = TakFrameCodec::new();

    // Build a frame header with an oversized length varint (no actual payload needed)
    let mut buf = BytesMut::new();
    buf.put_u8(0xBF);
    let mut v = (MAX_FRAME_SIZE + 1) as u64;
    while v >= 0x80 {
        buf.put_u8((v as u8) | 0x80);
        v >>= 7;
    }
    buf.put_u8(v as u8);

    let err = codec.decode(&mut buf).unwrap_err();
    assert!(
        err.to_string().contains("too large"),
        "should mention too large: {err}"
    );
}

#[test]
fn encode_rejects_oversized_payload() {
    let mut codec = TakFrameCodec::new();
    let payload = BytesMut::from(vec![0u8; MAX_FRAME_SIZE + 1].as_slice());
    let mut buf = BytesMut::new();

    let err = codec.encode(payload, &mut buf).unwrap_err();
    assert!(
        err.to_string().contains("too large"),
        "should mention too large: {err}"
    );
}

#[test]
fn empty_payload_round_trip() {
    let mut codec = TakFrameCodec::new();
    let payload = BytesMut::new();
    let mut buf = BytesMut::new();
    codec.encode(payload.clone(), &mut buf).unwrap();

    let decoded = codec.decode(&mut buf).unwrap().unwrap();
    assert!(decoded.is_empty());
}

#[test]
fn boundary_test_exactly_at_max_frame_size() {
    let mut codec = TakFrameCodec::new();
    let payload = BytesMut::from(vec![0xAB; MAX_FRAME_SIZE].as_slice());
    let mut buf = BytesMut::new();
    codec.encode(payload.clone(), &mut buf).unwrap();

    let decoded = codec.decode(&mut buf).unwrap().unwrap();
    assert_eq!(decoded.len(), MAX_FRAME_SIZE);
}

#[test]
fn state_reset_after_successful_decode() {
    let mut codec = TakFrameCodec::new();

    // First frame
    let p1 = BytesMut::from(&b"first"[..]);
    let mut buf = BytesMut::new();
    codec.encode(p1.clone(), &mut buf).unwrap();
    let d1 = codec.decode(&mut buf).unwrap().unwrap();
    assert_eq!(d1, p1);

    // Second frame - codec state should be clean
    let p2 = BytesMut::from(&b"second"[..]);
    codec.encode(p2.clone(), &mut buf).unwrap();
    let d2 = codec.decode(&mut buf).unwrap().unwrap();
    assert_eq!(d2, p2);

    // Buffer exhausted
    assert!(codec.decode(&mut buf).unwrap().is_none());
}

#[test]
fn payload_byte_preservation_including_null_bytes() {
    let mut codec = TakFrameCodec::new();

    // Payload with null bytes, high bytes, and various patterns
    let data: Vec<u8> = (0..=255).collect();
    let payload = BytesMut::from(data.as_slice());

    let mut buf = BytesMut::new();
    codec.encode(payload.clone(), &mut buf).unwrap();

    let decoded = codec.decode(&mut buf).unwrap().unwrap();
    assert_eq!(decoded, payload);
    assert_eq!(decoded.len(), 256);
    for (i, &b) in decoded.iter().enumerate() {
        assert_eq!(b, i as u8, "byte mismatch at index {i}");
    }
}

#[test]
fn empty_buffer_returns_none() {
    let mut codec = TakFrameCodec::new();
    let mut buf = BytesMut::new();
    assert!(codec.decode(&mut buf).unwrap().is_none());
}

#[test]
fn magic_byte_only_returns_none() {
    let mut codec = TakFrameCodec::new();
    let mut buf = BytesMut::from(&[0xBF][..]);
    assert!(codec.decode(&mut buf).unwrap().is_none());
}

// ---------------------------------------------------------------------------
// Protocol negotiation
// ---------------------------------------------------------------------------

#[test]
fn build_protocol_support_xml_contains_required_elements() {
    let xml = build_protocol_support_xml("test-server");
    let xml_str = std::str::from_utf8(&xml).unwrap();

    assert!(xml_str.starts_with("<event"));
    assert!(xml_str.ends_with("</event>"));
    assert!(xml_str.contains("type=\"t-x-takp-v\""));
    assert!(xml_str.contains("uid=\"test-server\""));
    assert!(xml_str.contains("<TakControl>"));
    assert!(xml_str.contains("<TakProtocolSupport version=\"2\""));
    assert!(xml_str.contains("<point"));
    assert!(xml_str.contains("<detail>"));
}

#[test]
fn build_protocol_support_xml_escapes_special_chars() {
    let xml = build_protocol_support_xml("server&\"<>'test");
    let xml_str = std::str::from_utf8(&xml).unwrap();

    assert!(xml_str.contains("&amp;"));
    assert!(xml_str.contains("&quot;"));
    assert!(xml_str.contains("&lt;"));
    assert!(xml_str.contains("&gt;"));
    assert!(xml_str.contains("&apos;"));
}

#[test]
fn build_protocol_support_xml_is_parseable() {
    let xml = build_protocol_support_xml("integration-test-uid");
    let mut reader = quick_xml::Reader::from_reader(xml.as_slice());
    let mut buf = Vec::new();
    let mut found_tak_control = false;

    loop {
        let event = reader.read_event_into(&mut buf).unwrap();
        match event {
            quick_xml::events::Event::Start(e) if e.name().as_ref() == b"TakControl" => {
                found_tak_control = true;
            }
            quick_xml::events::Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }
    assert!(found_tak_control, "XML must contain TakControl element");
}

#[test]
fn build_tak_response_starts_with_magic_byte() {
    let response = build_tak_response(NegotiatedVersion::V1);
    assert_eq!(response[0], 0xBF);
}

#[test]
fn build_tak_response_is_decodeable_as_tak_message() {
    let response = build_tak_response(NegotiatedVersion::V1);

    // Parse: magic + varint + payload
    let (payload_len, varint_bytes) = decode_varint(&response[1..]).unwrap();
    let payload_start = 1 + varint_bytes;
    let payload = &response[payload_start..payload_start + payload_len];

    let msg = tak_proto::TakMessage::decode(payload).unwrap();
    let control = msg.tak_control.unwrap();
    assert_eq!(control.min_proto_version, "1");
    assert_eq!(control.max_proto_version, "1");
    assert!(msg.cot_event.is_none());
}

#[test]
fn build_tak_response_total_length_matches() {
    let response = build_tak_response(NegotiatedVersion::V1);

    let (payload_len, varint_bytes) = decode_varint(&response[1..]).unwrap();
    let expected_total = 1 + varint_bytes + payload_len;
    assert_eq!(
        response.len(),
        expected_total,
        "response length must equal magic + varint + payload"
    );
}

#[test]
fn parse_tak_request_accepts_valid_v1() {
    let msg = tak_proto::TakMessage {
        tak_control: Some(tak_proto::TakControl {
            min_proto_version: "1".into(),
            max_proto_version: "1".into(),
            contact_uid: "client-uid".into(),
        }),
        cot_event: None,
    };
    let version = parse_tak_request(&msg.encode_to_vec()).unwrap();
    assert_eq!(version, NegotiatedVersion::V1);
}

#[test]
fn parse_tak_request_accepts_empty_versions() {
    let msg = tak_proto::TakMessage {
        tak_control: Some(tak_proto::TakControl {
            min_proto_version: String::new(),
            max_proto_version: String::new(),
            contact_uid: String::new(),
        }),
        cot_event: None,
    };
    let version = parse_tak_request(&msg.encode_to_vec()).unwrap();
    assert_eq!(version, NegotiatedVersion::V2);
}

#[test]
fn parse_tak_request_rejects_unsupported_version() {
    // min=3,max=4 has no overlap with server's [1..2]
    let msg = tak_proto::TakMessage {
        tak_control: Some(tak_proto::TakControl {
            min_proto_version: "3".into(),
            max_proto_version: "4".into(),
            contact_uid: String::new(),
        }),
        cot_event: None,
    };
    assert!(parse_tak_request(&msg.encode_to_vec()).is_err());
}

#[test]
fn parse_tak_request_rejects_missing_tak_control() {
    let msg = tak_proto::TakMessage {
        tak_control: None,
        cot_event: None,
    };
    let err = parse_tak_request(&msg.encode_to_vec()).unwrap_err();
    assert!(
        err.to_string().contains("missing field"),
        "should mention missing field: {err}"
    );
}

#[test]
fn parse_tak_request_rejects_garbage_bytes() {
    let garbage = vec![0xFF, 0xFE, 0xFD, 0xFC];
    assert!(parse_tak_request(&garbage).is_err());
}

#[test]
fn parse_tak_request_rejects_empty_input() {
    // Empty bytes decode to a TakMessage with all fields at defaults (None),
    // which means missing TakControl
    let result = parse_tak_request(&[]);
    // prost decodes empty bytes as default TakMessage (no fields set),
    // so TakControl will be None -> MissingField error
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Async negotiation via read_tak_request
// ---------------------------------------------------------------------------

#[tokio::test]
async fn read_tak_request_accepts_valid_frame() {
    use rustgate_proto::read_tak_request;

    let msg = tak_proto::TakMessage {
        tak_control: Some(tak_proto::TakControl {
            min_proto_version: "1".into(),
            max_proto_version: "1".into(),
            contact_uid: "async-client".into(),
        }),
        cot_event: None,
    };
    let proto_bytes = msg.encode_to_vec();

    // Build the wire frame without the magic byte (read_tak_request assumes it's consumed)
    let frame = encode_varint_frame(&proto_bytes);
    let mut cursor = std::io::Cursor::new(frame);
    let version = read_tak_request(&mut cursor).await.unwrap();
    assert_eq!(version, NegotiatedVersion::V1);
}

#[tokio::test]
async fn read_tak_request_rejects_missing_control() {
    use rustgate_proto::read_tak_request;

    let msg = tak_proto::TakMessage {
        tak_control: None,
        cot_event: None,
    };
    let proto_bytes = msg.encode_to_vec();

    let frame = encode_varint_frame(&proto_bytes);
    let mut cursor = std::io::Cursor::new(frame);
    assert!(read_tak_request(&mut cursor).await.is_err());
}
