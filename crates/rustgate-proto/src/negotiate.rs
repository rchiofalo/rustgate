// Copyright © 2026 Roberto Chiofalo.

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
use rustgate_core::constants::MAX_FRAME_SIZE;
use tokio::io::AsyncReadExt;
use tokio::time::{Duration, timeout};
use tokio_util::bytes::BufMut;

use crate::error::ProtoError;
use crate::{codec, tak_proto};

/// Maximum time to wait for a client to complete protocol negotiation.
///
/// If a client connects but does not send a valid negotiation frame within
/// this window, the connection is dropped to prevent resource exhaustion.
const NEGOTIATION_TIMEOUT: Duration = Duration::from_secs(30);

/// Minimum protocol version supported by this server.
pub const MIN_PROTO_VERSION: u32 = 1;

/// Maximum protocol version supported by this server.
pub const MAX_PROTO_VERSION: u32 = 2;

/// Result of a successful protocol version negotiation.
///
/// Determined by computing the intersection of the server's supported
/// range (`MIN_PROTO_VERSION..=MAX_PROTO_VERSION`) and the client's
/// advertised range, then selecting the highest mutually supported
/// version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NegotiatedVersion {
    /// Protocol version 1 (legacy XML/protobuf framing).
    V1,
    /// Protocol version 2 (extended capabilities).
    V2,
}

/// Build the XML `<event type="t-x-takp-v">` advertisement sent to new clients.
///
/// This is a standard CoT event with the server's UID and a `<TakControl>` detail
/// element advertising protobuf version support. Timestamps use epoch zero since
/// the client only inspects the event type. The `version` attribute carries
/// [`MAX_PROTO_VERSION`] so that capable clients know the upper bound, while
/// backward-compatible clients that only understand version "1" still parse the
/// attribute successfully.
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
    let version_str = MAX_PROTO_VERSION.to_string();
    xml.extend_from_slice(version_str.as_bytes());
    xml.extend_from_slice(b"\"/>");
    xml.extend_from_slice(b"</TakControl>");
    xml.extend_from_slice(b"</detail>");
    xml.extend_from_slice(b"</event>");
    xml
}

/// Build a 0xBF-framed TakResponse (server's step-3 acknowledgement).
///
/// The response includes the negotiated version so the client knows
/// which protocol semantics both sides agreed on.
///
/// Returns the complete wire bytes: magic + varint + protobuf payload.
pub fn build_tak_response(version: NegotiatedVersion) -> Vec<u8> {
    let v = match version {
        NegotiatedVersion::V1 => "1",
        NegotiatedVersion::V2 => "2",
    };
    let tak_message = tak_proto::TakMessage {
        tak_control: Some(tak_proto::TakControl {
            min_proto_version: v.into(),
            max_proto_version: v.into(),
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

/// Negotiate a protocol version from a TakControl request (step 2).
///
/// Decodes a TakMessage from raw protobuf bytes, extracts the client's
/// min/max version range, and computes the intersection with the
/// server's supported range. Returns the highest mutually supported
/// [`NegotiatedVersion`], or an error when there is no overlap.
pub fn parse_tak_request(proto_bytes: &[u8]) -> Result<NegotiatedVersion, ProtoError> {
    let tak_message = tak_proto::TakMessage::decode(proto_bytes)?;
    let control = tak_message
        .tak_control
        .ok_or(ProtoError::MissingField("takControl"))?;

    // Empty strings (proto3 default) are treated as "accepts anything"
    // for backward compatibility with clients that omit version fields.
    let client_min: u32 = if control.min_proto_version.is_empty() {
        MIN_PROTO_VERSION
    } else {
        control
            .min_proto_version
            .parse()
            .map_err(|_| ProtoError::MissingField("invalid min_proto_version"))?
    };

    let client_max: u32 = if control.max_proto_version.is_empty() {
        MAX_PROTO_VERSION
    } else {
        control
            .max_proto_version
            .parse()
            .map_err(|_| ProtoError::MissingField("invalid max_proto_version"))?
    };

    negotiate_version(client_min, client_max)
}

/// Compute the highest mutually supported version from a client's
/// [min..max] range and the server's [`MIN_PROTO_VERSION`]..=[`MAX_PROTO_VERSION`].
fn negotiate_version(client_min: u32, client_max: u32) -> Result<NegotiatedVersion, ProtoError> {
    // Intersection: max of mins .. min of maxes
    let effective_min = client_min.max(MIN_PROTO_VERSION);
    let effective_max = client_max.min(MAX_PROTO_VERSION);

    if effective_min > effective_max {
        return Err(ProtoError::MissingField(
            "no mutually supported protocol version",
        ));
    }

    // Select the highest version in the overlap
    match effective_max {
        1 => Ok(NegotiatedVersion::V1),
        2.. => Ok(NegotiatedVersion::V2),
        _ => Err(ProtoError::MissingField(
            "no mutually supported protocol version",
        )),
    }
}

/// Read and negotiate one TakRequest frame from an async reader.
///
/// Assumes the magic byte (0xBF) has already been consumed. Reads the varint
/// length, then the protobuf payload, and negotiates the protocol version.
///
/// Maximum frame size: 16 MB (same as TakFrameCodec).
///
/// A `NEGOTIATION_TIMEOUT` is enforced around the entire read so that a
/// slow or malicious client cannot hold the connection open indefinitely
/// during protocol negotiation.
///
/// Returns the [`NegotiatedVersion`] selected by version range intersection.
pub async fn read_tak_request(
    reader: &mut (impl tokio::io::AsyncRead + Unpin),
) -> io::Result<NegotiatedVersion> {
    timeout(NEGOTIATION_TIMEOUT, read_tak_request_inner(reader))
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "protocol negotiation timed out (client too slow)",
            )
        })?
}

/// Inner implementation of [`read_tak_request`] without the timeout wrapper.
async fn read_tak_request_inner(
    reader: &mut (impl tokio::io::AsyncRead + Unpin),
) -> io::Result<NegotiatedVersion> {
    const MAX_VARINT_BYTES: usize = 5;

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

    // Negotiate the protocol version from the TakControl request
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
#[allow(clippy::panic, clippy::unwrap_used)]
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
        assert!(xml_str.contains("<TakProtocolSupport version=\"2\""));
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
    fn tak_response_v1_has_magic_byte() {
        let response = build_tak_response(NegotiatedVersion::V1);
        assert_eq!(response[0], 0xBF, "first byte must be magic");
        assert!(response.len() > 2, "must have varint + payload");
    }

    #[test]
    fn tak_response_v1_decodeable() {
        let response = build_tak_response(NegotiatedVersion::V1);
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
    fn tak_response_v2_decodeable() {
        let response = build_tak_response(NegotiatedVersion::V2);
        let (payload_len, varint_bytes) = codec::decode_varint(&response[1..]).expect("varint");
        let payload_start = 1 + varint_bytes;
        let payload = &response[payload_start..payload_start + payload_len];

        let msg = tak_proto::TakMessage::decode(payload).expect("decode");
        let control = msg.tak_control.expect("takControl");
        assert_eq!(control.min_proto_version, "2");
        assert_eq!(control.max_proto_version, "2");
    }

    // ── Version negotiation tests ────────────────────────────────────

    #[test]
    fn v1_only_client_negotiates_v1() {
        let msg = tak_proto::TakMessage {
            tak_control: Some(tak_proto::TakControl {
                min_proto_version: "1".into(),
                max_proto_version: "1".into(),
                contact_uid: "ATAK-v1-client".into(),
            }),
            cot_event: None,
        };
        let bytes = msg.encode_to_vec();
        let version = parse_tak_request(&bytes).expect("should negotiate");
        assert_eq!(version, NegotiatedVersion::V1);
    }

    #[test]
    fn v2_capable_client_negotiates_v2() {
        let msg = tak_proto::TakMessage {
            tak_control: Some(tak_proto::TakControl {
                min_proto_version: "1".into(),
                max_proto_version: "2".into(),
                contact_uid: "ATAK-v2-client".into(),
            }),
            cot_event: None,
        };
        let bytes = msg.encode_to_vec();
        let version = parse_tak_request(&bytes).expect("should negotiate");
        assert_eq!(version, NegotiatedVersion::V2);
    }

    #[test]
    fn v2_only_client_negotiates_v2() {
        let msg = tak_proto::TakMessage {
            tak_control: Some(tak_proto::TakControl {
                min_proto_version: "2".into(),
                max_proto_version: "2".into(),
                contact_uid: String::new(),
            }),
            cot_event: None,
        };
        let bytes = msg.encode_to_vec();
        let version = parse_tak_request(&bytes).expect("should negotiate");
        assert_eq!(version, NegotiatedVersion::V2);
    }

    #[test]
    fn future_client_v3_only_fails() {
        let msg = tak_proto::TakMessage {
            tak_control: Some(tak_proto::TakControl {
                min_proto_version: "3".into(),
                max_proto_version: "3".into(),
                contact_uid: String::new(),
            }),
            cot_event: None,
        };
        let bytes = msg.encode_to_vec();
        assert!(
            parse_tak_request(&bytes).is_err(),
            "v3-only client has no overlap with server [1..2]"
        );
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
        // Some clients send empty version strings (proto3 default).
        // Empty strings are treated as "accepts anything", so the
        // server selects the highest version it supports (V2).
        let msg = tak_proto::TakMessage {
            tak_control: Some(tak_proto::TakControl {
                min_proto_version: String::new(),
                max_proto_version: String::new(),
                contact_uid: String::new(),
            }),
            cot_event: None,
        };
        let bytes = msg.encode_to_vec();
        let version = parse_tak_request(&bytes).expect("empty version should be accepted");
        assert_eq!(version, NegotiatedVersion::V2);
    }

    #[test]
    fn xml_escapes_uid() {
        let xml = build_protocol_support_xml("test&<>server");
        let xml_str = std::str::from_utf8(&xml).expect("utf8");
        assert!(xml_str.contains("uid=\"test&amp;&lt;&gt;server\""));
    }

    // ── Build/parse round-trip tests ─────────────────────────────────

    #[test]
    fn build_parse_round_trip_v1() {
        let response = build_tak_response(NegotiatedVersion::V1);
        let (payload_len, varint_bytes) = codec::decode_varint(&response[1..]).expect("varint");
        let payload_start = 1 + varint_bytes;
        let payload = &response[payload_start..payload_start + payload_len];
        let version = parse_tak_request(payload).expect("should parse");
        assert_eq!(version, NegotiatedVersion::V1);
    }

    #[test]
    fn build_parse_round_trip_v2() {
        let response = build_tak_response(NegotiatedVersion::V2);
        let (payload_len, varint_bytes) = codec::decode_varint(&response[1..]).expect("varint");
        let payload_start = 1 + varint_bytes;
        let payload = &response[payload_start..payload_start + payload_len];
        let version = parse_tak_request(payload).expect("should parse");
        assert_eq!(version, NegotiatedVersion::V2);
    }

    #[tokio::test]
    async fn read_tak_request_times_out_on_slow_client() {
        // A reader that never produces data simulates a slow/stalled client.
        let (reader, _writer) = tokio::io::duplex(64);
        let mut reader = tokio::io::BufReader::new(reader);

        // Override the timeout to something short for the test by calling
        // the inner function directly with a tight timeout.
        let result = timeout(
            Duration::from_millis(50),
            read_tak_request_inner(&mut reader),
        )
        .await;

        assert!(result.is_err(), "should time out on a stalled reader");
    }
}
