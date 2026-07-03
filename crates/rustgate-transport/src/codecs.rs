// Copyright © 2026 Roberto Chiofalo.

//! Built-in codec implementations for common wire protocols.
//!
//! These codecs implement the [`Codec`] trait from `rustgate-core`, providing
//! framing strategy declarations and payload transformation for each supported
//! wire format.

use std::io;

use bytes::{Bytes, BytesMut};
use rustgate_core::codec::Codec;
use rustgate_core::message::RoutableMessage;
use rustgate_core::protocol::{FramingStrategy, HeaderSize};

/// Codec for TAK CoT XML protocol.
///
/// Uses XML stream framing (tag-depth tracking). Payloads are already in
/// the canonical XML format, so both `decode_payload` and `encode_payload`
/// are passthrough operations.
#[derive(Debug, Default, Clone)]
pub struct TakXmlCodec;

impl Codec for TakXmlCodec {
    fn protocol_id(&self) -> &str {
        "tak-xml"
    }

    fn framing(&self) -> FramingStrategy {
        FramingStrategy::XmlStream
    }

    fn decode_payload(&self, frame: BytesMut) -> io::Result<Bytes> {
        Ok(frame.freeze())
    }

    fn encode_payload(&self, msg: &RoutableMessage) -> io::Result<Bytes> {
        Ok(msg.payload.clone())
    }

    fn detect(&self, prefix: &[u8]) -> f32 {
        if prefix.first() == Some(&b'<') {
            0.8
        } else {
            0.0
        }
    }
}

/// Codec for line-delimited raw payloads.
///
/// Uses newline-delimited framing. Payloads are passed through without
/// transformation.
#[derive(Debug, Default, Clone)]
pub struct RawLineCodec;

impl Codec for RawLineCodec {
    fn protocol_id(&self) -> &str {
        "raw-line"
    }

    fn framing(&self) -> FramingStrategy {
        FramingStrategy::LineDelimited
    }

    fn decode_payload(&self, frame: BytesMut) -> io::Result<Bytes> {
        Ok(frame.freeze())
    }

    fn encode_payload(&self, msg: &RoutableMessage) -> io::Result<Bytes> {
        Ok(msg.payload.clone())
    }

    fn detect(&self, _prefix: &[u8]) -> f32 {
        // Line-delimited is a fallback — low confidence without more context
        0.1
    }
}

/// Codec for length-prefixed raw payloads.
///
/// Uses 4-byte big-endian length prefix framing. Payloads are passed
/// through without transformation.
#[derive(Debug, Default, Clone)]
pub struct RawLengthPrefixedCodec;

impl Codec for RawLengthPrefixedCodec {
    fn protocol_id(&self) -> &str {
        "raw-length-prefixed"
    }

    fn framing(&self) -> FramingStrategy {
        FramingStrategy::LengthPrefixed {
            header_size: HeaderSize::Four,
        }
    }

    fn decode_payload(&self, frame: BytesMut) -> io::Result<Bytes> {
        Ok(frame.freeze())
    }

    fn encode_payload(&self, msg: &RoutableMessage) -> io::Result<Bytes> {
        Ok(msg.payload.clone())
    }

    fn detect(&self, _prefix: &[u8]) -> f32 {
        // Length-prefixed is ambiguous from prefix alone
        0.0
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use std::collections::BTreeSet;
    use std::time::SystemTime;

    use rustgate_core::identity::Identity;
    use rustgate_core::message::{Destination, MessageType, Metadata};

    use super::*;

    fn test_msg(payload: &[u8]) -> RoutableMessage {
        RoutableMessage {
            source: Identity::new(
                "test-cn".to_string(),
                "sha256:test".to_string(),
                BTreeSet::new(),
            )
            .unwrap(),
            destination: Destination::Broadcast,
            payload: Bytes::copy_from_slice(payload),
            metadata: Metadata::new(
                SystemTime::now(),
                "test".into(),
                MessageType::Other("test".into()),
            ),
            entity: None,
        }
    }

    #[test]
    fn tak_xml_codec_roundtrip() {
        let codec = TakXmlCodec;
        let xml = b"<event uid=\"test\" />";
        let decoded = codec.decode_payload(BytesMut::from(&xml[..])).unwrap();
        assert_eq!(&decoded[..], xml);

        let msg = test_msg(xml);
        let encoded = codec.encode_payload(&msg).unwrap();
        assert_eq!(&encoded[..], xml);
    }

    #[test]
    fn tak_xml_codec_protocol_id() {
        assert_eq!(TakXmlCodec.protocol_id(), "tak-xml");
    }

    #[test]
    fn tak_xml_codec_detect() {
        assert!(TakXmlCodec.detect(b"<event") > 0.5);
        assert_eq!(TakXmlCodec.detect(b"\xBF"), 0.0);
        assert_eq!(TakXmlCodec.detect(b""), 0.0);
    }

    #[test]
    fn raw_line_codec_roundtrip() {
        let codec = RawLineCodec;
        let data = b"hello world";
        let decoded = codec.decode_payload(BytesMut::from(&data[..])).unwrap();
        assert_eq!(&decoded[..], data);

        let msg = test_msg(data);
        let encoded = codec.encode_payload(&msg).unwrap();
        assert_eq!(&encoded[..], data);
    }

    #[test]
    fn raw_line_codec_protocol_id() {
        assert_eq!(RawLineCodec.protocol_id(), "raw-line");
    }

    #[test]
    fn raw_length_prefixed_codec_roundtrip() {
        let codec = RawLengthPrefixedCodec;
        let data = b"binary payload";
        let decoded = codec.decode_payload(BytesMut::from(&data[..])).unwrap();
        assert_eq!(&decoded[..], data);

        let msg = test_msg(data);
        let encoded = codec.encode_payload(&msg).unwrap();
        assert_eq!(&encoded[..], data);
    }

    #[test]
    fn raw_length_prefixed_codec_protocol_id() {
        assert_eq!(RawLengthPrefixedCodec.protocol_id(), "raw-length-prefixed");
    }

    #[test]
    fn framing_strategies_match() {
        assert!(matches!(TakXmlCodec.framing(), FramingStrategy::XmlStream));
        assert!(matches!(
            RawLineCodec.framing(),
            FramingStrategy::LineDelimited
        ));
        assert!(matches!(
            RawLengthPrefixedCodec.framing(),
            FramingStrategy::LengthPrefixed { .. }
        ));
    }
}
