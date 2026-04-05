#![allow(clippy::panic, clippy::unwrap_used)]
//! Property-based tests for codec round-trips using proptest.
//!
//! Validates that encode/decode cycles preserve payloads for the
//! `LengthPrefixedCodec`, `XmlStreamCodec`, and `LineDelimitedCodec`.

use proptest::prelude::*;
use rustgate_core::protocol::HeaderSize;
use rustgate_transport::{LengthPrefixedCodec, LineDelimitedCodec, XmlStreamCodec};
use tokio_util::bytes::BytesMut;
use tokio_util::codec::{Decoder, Encoder};

// ── LengthPrefixedCodec ─────────────────────────────────────────────────

proptest! {
    /// Encoding then decoding with a 4-byte header preserves the payload.
    #[test]
    fn length_prefixed_four_roundtrip(payload in prop::collection::vec(any::<u8>(), 0..4096)) {
        let mut codec = LengthPrefixedCodec::new(HeaderSize::Four);
        let input = BytesMut::from(payload.as_slice());

        let mut encoded = BytesMut::new();
        codec.encode(input, &mut encoded).expect("encode should succeed");

        let decoded = codec.decode(&mut encoded)
            .expect("decode should succeed")
            .expect("should produce a frame");

        prop_assert_eq!(decoded.as_ref(), payload.as_slice());
    }

    /// Encoding then decoding with a 2-byte header preserves the payload
    /// for payloads that fit within u16::MAX.
    #[test]
    fn length_prefixed_two_roundtrip(payload in prop::collection::vec(any::<u8>(), 0..4096)) {
        let mut codec = LengthPrefixedCodec::new(HeaderSize::Two);
        let input = BytesMut::from(payload.as_slice());

        let mut encoded = BytesMut::new();
        codec.encode(input, &mut encoded).expect("encode should succeed");

        let decoded = codec.decode(&mut encoded)
            .expect("decode should succeed")
            .expect("should produce a frame");

        prop_assert_eq!(decoded.as_ref(), payload.as_slice());
    }

    /// Encoding then decoding with a 1-byte header preserves the payload
    /// for payloads that fit within u8::MAX (255 bytes).
    #[test]
    fn length_prefixed_one_roundtrip(payload in prop::collection::vec(any::<u8>(), 0..255)) {
        let mut codec = LengthPrefixedCodec::new(HeaderSize::One);
        let input = BytesMut::from(payload.as_slice());

        let mut encoded = BytesMut::new();
        codec.encode(input, &mut encoded).expect("encode should succeed");

        let decoded = codec.decode(&mut encoded)
            .expect("decode should succeed")
            .expect("should produce a frame");

        prop_assert_eq!(decoded.as_ref(), payload.as_slice());
    }
}

// ── XmlStreamCodec ──────────────────────────────────────────────────────

proptest! {
    /// A self-closing XML element with arbitrary attribute content round-trips.
    #[test]
    fn xml_self_closing_roundtrip(
        tag in "[a-z][a-z0-9]{0,15}",
        attr_val in "[a-zA-Z0-9 _-]{0,30}"
    ) {
        let xml = format!(r#"<{tag} val="{attr_val}"/>"#);
        let mut codec = XmlStreamCodec::new();
        let mut buf = BytesMut::from(xml.as_str());

        let decoded = codec.decode(&mut buf)
            .expect("decode should succeed")
            .expect("should produce a frame");

        prop_assert_eq!(decoded.as_ref(), xml.as_bytes());
    }

    /// An XML element with a body round-trips through encode/decode.
    #[test]
    fn xml_element_with_body_roundtrip(
        tag in "[a-z][a-z0-9]{0,15}",
        body in "[a-zA-Z0-9 ]{0,50}"
    ) {
        let xml = format!("<{tag}>{body}</{tag}>");
        let mut codec = XmlStreamCodec::new();

        // Encode
        let mut encoded = BytesMut::new();
        codec.encode(BytesMut::from(xml.as_str()), &mut encoded)
            .expect("encode should succeed");

        // Decode
        let decoded = codec.decode(&mut encoded)
            .expect("decode should succeed")
            .expect("should produce a frame");

        prop_assert_eq!(decoded.as_ref(), xml.as_bytes());
    }
}

// ── LineDelimitedCodec ──────────────────────────────────────────────────

proptest! {
    /// Line-delimited encode/decode round-trip: encoding adds a newline,
    /// decoding strips it, yielding the original payload.
    #[test]
    fn line_delimited_roundtrip(
        // Avoid newlines and carriage returns in the payload — they would
        // split the line prematurely.
        payload in prop::collection::vec(
            any::<u8>().prop_filter("no newlines", |b| *b != b'\n' && *b != b'\r'),
            0..4096
        )
    ) {
        let mut codec = LineDelimitedCodec::new();
        let input = BytesMut::from(payload.as_slice());

        let mut encoded = BytesMut::new();
        codec.encode(input, &mut encoded).expect("encode should succeed");

        let decoded = codec.decode(&mut encoded)
            .expect("decode should succeed")
            .expect("should produce a frame");

        prop_assert_eq!(decoded.as_ref(), payload.as_slice());
    }
}
