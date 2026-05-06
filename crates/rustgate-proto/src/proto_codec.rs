// Copyright © 2026 Roberto Chiofalo.

//! Pluggable codec implementation for TAK protobuf wire format.
//!
//! Combines the 0xBF+varint framing with bidirectional protobuf ↔ XML
//! payload conversion. This unifies what was previously split across
//! `TakFrameCodec` and inline `proto_to_xml` calls
//! in the session layer.

use std::io;

use bytes::{Bytes, BytesMut};
use rustgate_core::codec::Codec;
use rustgate_core::message::RoutableMessage;
use rustgate_core::protocol::FramingStrategy;

/// Codec for TAK protobuf wire format (0xBF + varint + protobuf payload).
///
/// On decode, converts protobuf frames to canonical XML for internal routing.
/// On encode, converts XML payloads to protobuf for wire transmission.
#[derive(Debug, Default, Clone)]
pub struct TakProtobufCodec;

impl Codec for TakProtobufCodec {
    fn protocol_id(&self) -> &str {
        "tak-protobuf"
    }

    fn framing(&self) -> FramingStrategy {
        FramingStrategy::TakProtobuf
    }

    fn decode_payload(&self, frame: BytesMut) -> io::Result<Bytes> {
        let xml_bytes = crate::convert::proto_to_xml(&frame)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        Ok(Bytes::from(xml_bytes))
    }

    fn encode_payload(&self, msg: &RoutableMessage) -> io::Result<Bytes> {
        let proto_bytes = crate::convert::xml_to_proto(&msg.payload)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        Ok(Bytes::from(proto_bytes))
    }

    fn detect(&self, prefix: &[u8]) -> f32 {
        if prefix.first() == Some(&0xBF) {
            0.95
        } else {
            0.0
        }
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn protocol_id_matches_tak_protobuf() {
        // Wire contract: the codec registry keys off protocol_id, so
        // changing this breaks client routing tables and metrics labels.
        assert_eq!(TakProtobufCodec.protocol_id(), "tak-protobuf");
    }

    #[test]
    fn framing_returns_tak_protobuf_strategy() {
        let codec = TakProtobufCodec;
        assert!(matches!(codec.framing(), FramingStrategy::TakProtobuf));
    }

    #[test]
    fn detect_returns_high_confidence_on_tak_magic_byte() {
        // TAK protobuf frames start with 0xBF. A prefix that begins
        // with the magic byte must score >= 0.9 so auto-detection
        // prefers this codec over fallbacks.
        let codec = TakProtobufCodec;
        assert_eq!(codec.detect(&[0xBF]), 0.95);
        assert_eq!(codec.detect(&[0xBF, 0x01, 0x02]), 0.95);
    }

    #[test]
    fn detect_returns_zero_on_wrong_magic() {
        let codec = TakProtobufCodec;
        assert_eq!(codec.detect(&[0x00]), 0.0);
        assert_eq!(codec.detect(&[0xFF]), 0.0);
        // XML-like prefix must NOT score above 0 — keeps TAK-XML and
        // TAK-protobuf codecs from fighting at auto-detect.
        assert_eq!(codec.detect(b"<event"), 0.0);
    }

    #[test]
    fn detect_returns_zero_on_empty_prefix() {
        // An empty byte slice is reported as "unknown", not "confident
        // mismatch" — still 0.0 so auto-detection waits for more data.
        let codec = TakProtobufCodec;
        assert_eq!(codec.detect(&[]), 0.0);
    }

    #[test]
    fn codec_is_default_clone_and_debug() {
        // Router and listener code clone the codec onto each session;
        // the struct has no state so Default + Clone + Debug must all
        // work and produce a debug string that names the type.
        let codec = TakProtobufCodec;
        let cloned = codec.clone();
        let _default: TakProtobufCodec = TakProtobufCodec;
        let dbg = format!("{cloned:?}");
        assert!(
            dbg.contains("TakProtobufCodec"),
            "debug should name the type, got {dbg:?}"
        );
    }

    #[test]
    fn decode_payload_rejects_malformed_protobuf() {
        // Garbage bytes cannot be parsed as a CoT protobuf, so the
        // codec must surface an io::Error with InvalidData so upstream
        // framing code can drop the session cleanly.
        let codec = TakProtobufCodec;
        let frame = BytesMut::from(&[0xFF, 0xFF, 0xFF, 0xFF][..]);
        let err = codec.decode_payload(frame).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn encode_payload_rejects_malformed_xml() {
        use std::collections::BTreeSet;
        use std::time::SystemTime;

        use bytes::Bytes;
        use rustgate_core::identity::Identity;
        use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};

        let codec = TakProtobufCodec;
        let identity = Identity::new("sender".to_string(), "fp".to_string(), BTreeSet::new())
            .expect("valid test identity");
        let msg = RoutableMessage {
            source: identity,
            destination: Destination::Broadcast,
            payload: Bytes::from_static(b"<not xml at all"),
            metadata: Metadata::new(
                SystemTime::UNIX_EPOCH,
                "test".to_string(),
                MessageType::Other("test".to_string()),
            ),
        };
        let err = codec.encode_payload(&msg).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
