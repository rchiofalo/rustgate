//! TAK protocol negotiation message builders.
//!
//! # Protocol Handshake
//!
//! TAK clients connect speaking XML. The server advertises protobuf support
//! with a `t-x-takp-v` event. If the client wants protobuf, it sends a
//! 0xBF-framed TakMessage containing TakControl. The server acknowledges
//! with the same, and both sides switch to protobuf framing.
//!
//! If the client never sends a TakRequest, the session stays XML.

use std::io;

use prost::Message;
use tokio::io::AsyncReadExt;
use tokio_util::bytes::BufMut;

use crate::error::ProtoError;
use crate::{codec, tak_proto};

/// Protocol version we advertise and accept.
const PROTO_VERSION: &str = "1";

/// Build the XML `<event type="t-x-takp-v">` advertisement sent to new clients.
///
/// This is a standard CoT event with the server's UID and a `<TakControl>` detail
/// element advertising protobuf version support. Timestamps use epoch zero since
/// the client only inspects the event type.
pub fn build_protocol_support_xml(server_uid: &str) -> Vec<u8> {
    let mut xml = Vec::with_capacity(256);
    xml.extend_from_slice(b"<event version=\"2.0\"");
    write_attr(&mut xml, "uid", server_uid);
    write_attr(&mut xml, "type", "t-x-takp-v");
    write_attr(&mut xml, "how", "m-g");
    write_attr(&mut xml, "time", "2020-01-01T00:00:00.000Z");
    write_attr(&mut xml, "start", "2020-01-01T00:00:00.000Z");
    write_attr(&mut xml, "stale", "2020-01-01T00:05:00.000Z");
    xml.extend_from_slice(b">");
    xml.extend_from_slice(
        b"<point lat=\"0.0\" lon=\"0.0\" hae=\"0.0\" ce=\"999999\" le=\"999999\"/>",
    );
    xml.extend_from_slice(b"<detail>");
    xml.extend_from_slice(b"<TakControl>");
    xml.extend_from_slice(b"<TakProtocolSupport version=\"");
    xml.extend_from_slice(PROTO_VERSION.as_bytes());
    xml.extend_from_slice(b"\"/>");
    xml.extend_from_slice(b"</TakControl>");
    xml.extend_from_slice(b"</detail>");
    xml.extend_from_slice(b"</event>");
    xml
}

/// Build a 0xBF-framed TakResponse (server's step-3 acknowledgement).
///
/// Returns the complete wire bytes: magic + varint + protobuf payload.
pub fn build_tak_response() -> Vec<u8> {
    let tak_message = tak_proto::TakMessage {
        tak_control: Some(tak_proto::TakControl {
            min_proto_version: PROTO_VERSION.into(),
            max_proto_version: PROTO_VERSION.into(),
            contact_uid: String::new(),
        }),
        cot_event: None,
    };

    let proto_bytes = tak_message.encode_to_vec();
    let mut out = Vec::with_capacity(1 + 5 + proto_bytes.len());
    out.put_u8(codec::MAGIC_BYTE);
    encode_varint(proto_bytes.len() as u64, &mut out);
    out.extend_from_slice(&proto_bytes);
    out
}

/// Validate a TakControl request from the client (step 2).
///
/// Decodes a TakMessage from raw protobuf bytes and checks that the
/// TakControl version fields indicate protocol version 1.
pub fn parse_tak_request(proto_bytes: &[u8]) -> Result<(), ProtoError> {
    let tak_message = tak_proto::TakMessage::decode(proto_bytes)?;
    let control = tak_message
        .tak_control
        .ok_or(ProtoError::MissingField("takControl"))?;

    // Accept if the client's version range includes "1"
    let min_ok = control.min_proto_version.is_empty() || control.min_proto_version == PROTO_VERSION;
    let max_ok = control.max_proto_version.is_empty() || control.max_proto_version == PROTO_VERSION;

    if !min_ok || !max_ok {
        return Err(ProtoError::MissingField(
            "unsupported protocol version (expected 1)",
        ));
    }

    Ok(())
}

/// Read and validate one TakRequest frame from an async reader.
///
/// Assumes the magic byte (0xBF) has already been consumed. Reads the varint
/// length, then the protobuf payload, and validates the TakControl fields.
///
/// Maximum frame size: 16 MB (same as TakFrameCodec).
pub async fn read_tak_request(reader: &mut (impl tokio::io::AsyncRead + Unpin)) -> io::Result<()> {
    const MAX_VARINT_BYTES: usize = 5;
    const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024;

    // Read varint length, one byte at a time
    let mut header_buf = [0u8; MAX_VARINT_BYTES];
    let mut header_len = 0;
    let payload_len;

    loop {
        let n = reader
            .read(&mut header_buf[header_len..header_len + 1])
            .await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "client disconnected during negotiation varint",
            ));
        }
        header_len += 1;

        if let Some((len, _consumed)) = codec::decode_varint(&header_buf[..header_len]) {
            payload_len = len;
            break;
        }

        if header_len >= MAX_VARINT_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid varint in negotiation frame",
            ));
        }
    }

    if payload_len > MAX_FRAME_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "negotiation frame too large",
        ));
    }

    // Read the protobuf payload
    let mut payload = vec![0u8; payload_len];
    if payload_len > 0 {
        let _ = reader.read_exact(&mut payload).await?;
    }

    // Validate the TakControl request
    parse_tak_request(&payload).map_err(io::Error::from)
}

fn write_attr(xml: &mut Vec<u8>, name: &str, value: &str) {
    xml.push(b' ');
    xml.extend_from_slice(name.as_bytes());
    xml.extend_from_slice(b"=\"");
    xml_escape_into(xml, value);
    xml.push(b'"');
}

fn xml_escape_into(buf: &mut Vec<u8>, s: &str) {
    for b in s.bytes() {
        match b {
            b'&' => buf.extend_from_slice(b"&amp;"),
            b'<' => buf.extend_from_slice(b"&lt;"),
            b'>' => buf.extend_from_slice(b"&gt;"),
            b'"' => buf.extend_from_slice(b"&quot;"),
            b'\'' => buf.extend_from_slice(b"&apos;"),
            _ => buf.push(b),
        }
    }
}

/// Encode a value as a protobuf-style varint into a Vec.
fn encode_varint(mut value: u64, dst: &mut Vec<u8>) {
    while value >= 0x80 {
        dst.push((value as u8) | 0x80);
        value >>= 7;
    }
    dst.push(value as u8);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_support_xml_is_valid_cot() {
        let xml = build_protocol_support_xml("rustgate-server");
        let xml_str = std::str::from_utf8(&xml).expect("utf8");

        assert!(xml_str.starts_with("<event"));
        assert!(xml_str.ends_with("</event>"));
        assert!(xml_str.contains("type=\"t-x-takp-v\""));
        assert!(xml_str.contains("uid=\"rustgate-server\""));
        assert!(xml_str.contains("<TakProtocolSupport version=\"1\""));
    }

    #[test]
    fn protocol_support_xml_parseable() {
        let xml = build_protocol_support_xml("test-uid");
        // Should be parseable by quick_xml
        let mut reader = quick_xml::Reader::from_reader(xml.as_slice());
        let mut found_event = false;
        let mut buf = Vec::new();
        loop {
            let event = reader.read_event_into(&mut buf).expect("valid XML");
            match event {
                quick_xml::events::Event::Start(e) if e.name().as_ref() == b"event" => {
                    found_event = true;
                }
                quick_xml::events::Event::Eof => break,
                _ => {}
            }
            buf.clear();
        }
        assert!(found_event);
    }

    #[test]
    fn tak_response_has_magic_byte() {
        let response = build_tak_response();
        assert_eq!(response[0], 0xBF, "first byte must be magic");
        assert!(response.len() > 2, "must have varint + payload");
    }

    #[test]
    fn tak_response_decodeable() {
        let response = build_tak_response();
        // Skip magic byte, decode varint to find payload
        let (payload_len, varint_bytes) = codec::decode_varint(&response[1..]).expect("varint");
        let payload_start = 1 + varint_bytes;
        let payload = &response[payload_start..payload_start + payload_len];

        let msg = tak_proto::TakMessage::decode(payload).expect("decode");
        let control = msg.tak_control.expect("takControl");
        assert_eq!(control.min_proto_version, "1");
        assert_eq!(control.max_proto_version, "1");
        assert!(msg.cot_event.is_none());
    }

    #[test]
    fn parse_tak_request_valid() {
        let msg = tak_proto::TakMessage {
            tak_control: Some(tak_proto::TakControl {
                min_proto_version: "1".into(),
                max_proto_version: "1".into(),
                contact_uid: "ATAK-client".into(),
            }),
            cot_event: None,
        };
        let bytes = msg.encode_to_vec();
        parse_tak_request(&bytes).expect("should accept valid request");
    }

    #[test]
    fn parse_tak_request_rejects_unsupported_version() {
        let msg = tak_proto::TakMessage {
            tak_control: Some(tak_proto::TakControl {
                min_proto_version: "2".into(),
                max_proto_version: "2".into(),
                contact_uid: String::new(),
            }),
            cot_event: None,
        };
        let bytes = msg.encode_to_vec();
        assert!(parse_tak_request(&bytes).is_err());
    }

    #[test]
    fn parse_tak_request_rejects_missing_control() {
        let msg = tak_proto::TakMessage {
            tak_control: None,
            cot_event: None,
        };
        let bytes = msg.encode_to_vec();
        assert!(parse_tak_request(&bytes).is_err());
    }

    #[test]
    fn parse_tak_request_accepts_empty_version() {
        // Some clients send empty version strings (proto3 default)
        let msg = tak_proto::TakMessage {
            tak_control: Some(tak_proto::TakControl {
                min_proto_version: String::new(),
                max_proto_version: String::new(),
                contact_uid: String::new(),
            }),
            cot_event: None,
        };
        let bytes = msg.encode_to_vec();
        parse_tak_request(&bytes).expect("empty version should be accepted");
    }

    #[test]
    fn xml_escapes_uid() {
        let xml = build_protocol_support_xml("test&<>server");
        let xml_str = std::str::from_utf8(&xml).expect("utf8");
        assert!(xml_str.contains("uid=\"test&amp;&lt;&gt;server\""));
    }
}
