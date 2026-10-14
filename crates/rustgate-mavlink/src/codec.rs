// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! [`rustgate_core::codec::Codec`] adapter for MAVLink wire frames.
//!
//! The Codec trait's "canonical payload is XML" rule applies to codecs
//! that bridge different representations of the same message (CoT
//! protobuf ↔ CoT XML). MAVLink is a distinct wire format — frames are
//! carried opaquely, byte-identical to what arrived on the link, so
//! signing verification downstream can re-hash the same bytes.
//!
//! `decode_payload` and `encode_payload` are therefore passthrough; the
//! real work is done by [`crate::frame::MavlinkFrameCodec`] at the
//! framing layer.

use std::io;

use bytes::{Bytes, BytesMut};
use rustgate_core::codec::Codec;
use rustgate_core::message::RoutableMessage;
use rustgate_core::protocol::FramingStrategy;

use crate::frame::{MAVLINK_V1_MAGIC, MAVLINK_V2_MAGIC};

/// Codec for MAVLink wire frames.
///
/// Declares [`FramingStrategy::Mavlink`] so the session layer wires in
/// the dedicated [`crate::frame::MavlinkFrameCodec`] rather than a
/// generic length-prefixed codec. Payloads pass through unmodified.
#[derive(Debug, Default, Clone)]
pub struct MavlinkCodec;

impl MavlinkCodec {
    /// Construct a fresh codec. Stateless — every caller can share a
    /// single instance.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Codec for MavlinkCodec {
    fn protocol_id(&self) -> &str {
        "mavlink"
    }

    fn framing(&self) -> FramingStrategy {
        FramingStrategy::Mavlink
    }

    fn decode_payload(&self, frame: BytesMut) -> io::Result<Bytes> {
        // Payload is the complete frame (magic + header + payload + CRC
        // + optional signature). The router does not inspect MAVLink
        // bytes directly; downstream signing and obligation actuators
        // parse it in-place.
        Ok(frame.freeze())
    }

    fn encode_payload(&self, msg: &RoutableMessage) -> io::Result<Bytes> {
        // Payloads are already full MAVLink frames. Cloning an
        // `Arc<Bytes>` is ref-count only.
        Ok(msg.payload.clone())
    }

    fn detect(&self, prefix: &[u8]) -> f32 {
        match prefix.first() {
            // Both magic bytes are strong signals: no other protocol we
            // speak starts with them, and the byte position is fixed.
            Some(&MAVLINK_V1_MAGIC) | Some(&MAVLINK_V2_MAGIC) => 0.95,
            _ => 0.0,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use std::collections::BTreeSet;
    use std::time::SystemTime;

    use bytes::Bytes;
    use rustgate_core::identity::Identity;
    use rustgate_core::message::{Destination, MessageType, Metadata, SOURCE_MAVLINK};

    use super::*;
    use crate::frame::MavlinkVersion;

    /// Tests-only helper that anchors the protocol-id contract used by
    /// audit logs: the magic byte is enough to classify a frame version
    /// even when the rest of the header is not yet available.
    fn detect_version(prefix: &[u8]) -> Option<MavlinkVersion> {
        prefix.first().copied().and_then(MavlinkVersion::from_magic)
    }

    fn sample_msg(payload: &[u8]) -> RoutableMessage {
        RoutableMessage {
            source: Identity::new(
                "drone-01".to_string(),
                "sha256:abc".to_string(),
                BTreeSet::new(),
            )
            .unwrap(),
            destination: Destination::Broadcast,
            payload: Bytes::copy_from_slice(payload),
            metadata: Metadata::new(
                SystemTime::now(),
                SOURCE_MAVLINK.into(),
                MessageType::Mavlink,
            ),
            entity: None,
        }
    }

    #[test]
    fn protocol_id_is_stable() {
        // Audit logs and metrics label cardinality rely on this string
        // not drifting between releases.
        assert_eq!(MavlinkCodec::new().protocol_id(), "mavlink");
    }

    #[test]
    fn framing_strategy_is_mavlink() {
        assert!(matches!(
            MavlinkCodec::new().framing(),
            FramingStrategy::Mavlink
        ));
    }

    #[test]
    fn decode_payload_is_passthrough() {
        let codec = MavlinkCodec::new();
        let frame = BytesMut::from(&[0xFE, 0x00, 0x01, 0x02, 0x03, 0x04, 0x00, 0x00][..]);
        let decoded = codec.decode_payload(frame.clone()).unwrap();
        assert_eq!(&decoded[..], &frame[..]);
    }

    #[test]
    fn encode_payload_returns_message_bytes() {
        let codec = MavlinkCodec::new();
        let bytes = [0xFD, 0x05, 0x01, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00];
        let msg = sample_msg(&bytes);
        let encoded = codec.encode_payload(&msg).unwrap();
        assert_eq!(&encoded[..], &bytes[..]);
    }

    #[test]
    fn detect_scores_v1_magic_high() {
        let codec = MavlinkCodec::new();
        assert!(codec.detect(&[0xFE, 0x00]) > 0.9);
    }

    #[test]
    fn detect_scores_v2_magic_high() {
        let codec = MavlinkCodec::new();
        assert!(codec.detect(&[0xFD, 0x00]) > 0.9);
    }

    #[test]
    fn detect_scores_other_magics_zero() {
        let codec = MavlinkCodec::new();
        // TAK protobuf magic must NOT be claimed by MAVLink — both
        // protocols would otherwise fight for the same byte.
        assert_eq!(codec.detect(&[0xBF]), 0.0);
        assert_eq!(codec.detect(b"<e"), 0.0);
        assert_eq!(codec.detect(&[]), 0.0);
    }

    #[test]
    fn detect_version_helper_classifies_prefix() {
        assert_eq!(detect_version(&[0xFE]), Some(MavlinkVersion::V1));
        assert_eq!(detect_version(&[0xFD]), Some(MavlinkVersion::V2));
        assert_eq!(detect_version(&[0xBF]), None);
        assert_eq!(detect_version(&[]), None);
    }
}
