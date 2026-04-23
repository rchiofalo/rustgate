// Copyright © 2026 Roberto Chiofalo.

//! Pluggable protocol codec trait.
//!
//! The [`Codec`] trait unifies framing (message boundary detection) and
//! payload transformation (wire format ↔ canonical XML) into a single
//! abstraction. Each protocol gets one `Codec` implementation that knows
//! how to frame its wire format and convert payloads to/from the internal
//! [`RoutableMessage`] representation.
//!
//! The router is codec-agnostic — it only sees `RoutableMessage` with
//! canonical XML payloads. Codecs handle translation at session edges.
//!
//! # WebSocket
//!
//! The WebSocket transport (`rustgate-websocket`) handles framing via
//! tungstenite, not `FramedCodec`. It uses the `Codec` trait for outbound
//! encoding and inbound decoding, just like TLS/TCP sessions.
//!
//! # Legacy `Encoding` enum
//!
//! The `--encoding` CLI flag and its `Encoding` enum (`Raw`, `Cot`,
//! `TakProtobuf`) are preserved for backwards compatibility. The
//! `build_codec()` factory maps `(Framing, Encoding)` pairs to the
//! appropriate `Codec` implementation. `Encoding::Cot` and `Encoding::Raw`
//! are functionally identical since both use passthrough codecs.

use std::io;

use bytes::{Bytes, BytesMut};

use crate::message::RoutableMessage;
use crate::protocol::FramingStrategy;

/// Protocol codec for bidirectional message transformation.
///
/// Combines payload encoding (outbound) and decoding (inbound) for a
/// specific wire protocol. The framing layer (message boundary detection)
/// remains separate via [`FramingStrategy`] — the codec declares which
/// framing it needs, and the session layer constructs the appropriate
/// `FramedCodec` from it.
///
/// # Canonical format
///
/// The internal payload format in `RoutableMessage` is XML. Codecs that
/// use a different wire format (e.g., protobuf) must convert in both
/// directions: wire → XML on decode, XML → wire on encode.
pub trait Codec: Send + Sync + std::fmt::Debug {
    /// Human-readable protocol identifier (e.g., `"tak-xml"`, `"tak-protobuf"`).
    fn protocol_id(&self) -> &str;

    /// The framing strategy this codec uses for message boundary detection.
    ///
    /// The session layer uses this to construct the appropriate tokio-util
    /// `Decoder`/`Encoder` for the TCP stream.
    fn framing(&self) -> FramingStrategy;

    /// Transform raw framed bytes into canonical payload format (XML).
    ///
    /// Accepts `BytesMut` so passthrough codecs can call `frame.freeze()`
    /// for zero-copy conversion instead of allocating. Codecs that must
    /// transform the payload (e.g., protobuf → XML) will allocate
    /// regardless, so the owned buffer costs nothing extra.
    ///
    /// # Errors
    ///
    /// Returns an error if the frame cannot be decoded (e.g., malformed
    /// protobuf, invalid encoding).
    fn decode_payload(&self, frame: BytesMut) -> io::Result<Bytes>;

    /// Encode a [`RoutableMessage`]'s payload into wire-format bytes.
    ///
    /// For XML-native codecs, this passes through the payload. For protobuf
    /// codecs, this converts XML → protobuf.
    ///
    /// # Errors
    ///
    /// Returns an error if the message cannot be encoded for this protocol
    /// (e.g., XML that doesn't map to the target schema).
    fn encode_payload(&self, msg: &RoutableMessage) -> io::Result<Bytes>;

    /// Confidence score (0.0..=1.0) that the given prefix bytes belong to
    /// this protocol.
    ///
    /// Used for protocol auto-detection in future phases. Implementations
    /// should examine the first few bytes of a connection and return a
    /// confidence score. Returns 0.0 if the prefix does not match.
    fn detect(&self, prefix: &[u8]) -> f32;
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use std::collections::BTreeSet;
    use std::sync::Arc;
    use std::time::SystemTime;

    use bytes::{Bytes, BytesMut};

    use super::*;
    use crate::identity::Identity;
    use crate::message::{Destination, MessageType, Metadata, RoutableMessage};
    use crate::protocol::HeaderSize;

    /// A minimal `Codec` implementation that exercises the trait contract
    /// end-to-end without pulling in a real protocol crate. Lives only in
    /// this test module.
    #[derive(Debug)]
    struct StubCodec {
        id: &'static str,
        framing: FramingStrategy,
    }

    impl Codec for StubCodec {
        fn protocol_id(&self) -> &str {
            self.id
        }

        fn framing(&self) -> FramingStrategy {
            self.framing.clone()
        }

        fn decode_payload(&self, frame: BytesMut) -> std::io::Result<Bytes> {
            Ok(frame.freeze())
        }

        fn encode_payload(&self, msg: &RoutableMessage) -> std::io::Result<Bytes> {
            Ok(msg.payload.clone())
        }

        fn detect(&self, prefix: &[u8]) -> f32 {
            if prefix.first().copied() == Some(b'<') {
                1.0
            } else {
                0.0
            }
        }
    }

    fn make_message(payload: &'static [u8]) -> RoutableMessage {
        let identity = Identity::new(
            "tester".to_string(),
            "fingerprint".to_string(),
            BTreeSet::new(),
        )
        .unwrap();
        RoutableMessage {
            source: identity,
            destination: Destination::Broadcast,
            payload: Bytes::from_static(payload),
            metadata: Metadata {
                received_at: SystemTime::now(),
                source_protocol: "test".to_string(),
                message_type: MessageType::Other("test".to_string()),
                ttl: None,
            },
        }
    }

    #[test]
    fn codec_trait_is_object_safe_and_send_sync_debug() {
        fn assert_bounds<T: Send + Sync + std::fmt::Debug + ?Sized>() {}
        assert_bounds::<dyn Codec>();

        let boxed: Box<dyn Codec> = Box::new(StubCodec {
            id: "stub-xml",
            framing: FramingStrategy::XmlStream,
        });
        assert_eq!(boxed.protocol_id(), "stub-xml");

        let arced: Arc<dyn Codec> = Arc::from(boxed);
        assert!(matches!(arced.framing(), FramingStrategy::XmlStream));
    }

    #[test]
    fn codec_passthrough_decode_payload_is_zero_copy() {
        let codec = StubCodec {
            id: "stub",
            framing: FramingStrategy::LengthPrefixed {
                header_size: HeaderSize::Four,
            },
        };
        let mut buf = BytesMut::with_capacity(16);
        buf.extend_from_slice(b"hello world");
        let decoded = codec.decode_payload(buf).unwrap();
        assert_eq!(&decoded[..], b"hello world");
    }

    #[test]
    fn codec_encode_payload_reads_message_payload() {
        let codec = StubCodec {
            id: "stub",
            framing: FramingStrategy::LineDelimited,
        };
        let msg = make_message(b"<event/>");
        let encoded = codec.encode_payload(&msg).unwrap();
        assert_eq!(&encoded[..], b"<event/>");
    }

    #[test]
    fn codec_detect_returns_bounded_confidence_score() {
        let codec = StubCodec {
            id: "stub-xml",
            framing: FramingStrategy::XmlStream,
        };
        assert_eq!(codec.detect(b""), 0.0);
        assert_eq!(codec.detect(b"\x00\x01\x02"), 0.0);
        let confidence = codec.detect(b"<event");
        assert!(
            (0.0..=1.0).contains(&confidence),
            "confidence {confidence} outside documented [0.0, 1.0] range"
        );
        assert!(confidence > 0.0);
    }

    #[test]
    fn codec_framing_strategy_round_trips_through_trait() {
        let framings = [
            FramingStrategy::LengthPrefixed {
                header_size: HeaderSize::Two,
            },
            FramingStrategy::XmlStream,
            FramingStrategy::LineDelimited,
            FramingStrategy::TakProtobuf,
            FramingStrategy::Mavlink,
        ];
        for framing in framings {
            let codec: Box<dyn Codec> = Box::new(StubCodec {
                id: "stub",
                framing: framing.clone(),
            });
            let expected_name = format!("{framing:?}");
            let returned_name = format!("{:?}", codec.framing());
            assert_eq!(returned_name, expected_name);
        }
    }

    #[test]
    fn codec_debug_output_contains_stub_marker() {
        let codec = StubCodec {
            id: "stub-xml",
            framing: FramingStrategy::XmlStream,
        };
        let dbg = format!("{codec:?}");
        assert!(
            dbg.contains("StubCodec"),
            "Debug output missing type name: {dbg}"
        );
    }
}
