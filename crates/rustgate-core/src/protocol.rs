// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Framing protocol definitions for message boundary detection.
//!
//! rustgate supports multiple framing strategies to interoperate with
//! different client types. The [`FramingStrategy`] enum selects which
//! codec is used to split a TCP byte stream into discrete messages.

/// Describes how to detect message boundaries on a byte stream.
#[derive(Debug, Clone)]
pub enum FramingStrategy {
    /// First N bytes encode the message length.
    LengthPrefixed { header_size: HeaderSize },
    /// Read until an XML closing tag.
    XmlStream,
    /// Newline-delimited messages.
    LineDelimited,
    /// TAK protobuf: 0xBF magic + varint length + protobuf payload.
    TakProtobuf,
    /// MAVLink v1 (0xFE) or v2 (0xFD) frame.
    ///
    /// The frame length is encoded in a single `LEN` header byte; total
    /// frame size is derived from a fixed header size plus `LEN` plus a
    /// 2-byte CRC plus (for v2 signed frames) a 13-byte signature.
    /// Unlike length-prefixed framing, MAVLink can carry both v1 and v2
    /// frames on the same link, disambiguated by magic byte.
    Mavlink,
}

/// Valid header sizes for length-prefixed framing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderSize {
    One,
    Two,
    Four,
}

impl HeaderSize {
    pub fn byte_count(self) -> usize {
        match self {
            Self::One => 1,
            Self::Two => 2,
            Self::Four => 4,
        }
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn header_size_byte_count_matches_variant() {
        // Protocol contract: these values are serialized on the wire.
        // Changing them is a breaking protocol change.
        assert_eq!(HeaderSize::One.byte_count(), 1);
        assert_eq!(HeaderSize::Two.byte_count(), 2);
        assert_eq!(HeaderSize::Four.byte_count(), 4);
    }

    #[test]
    fn header_size_byte_count_is_const_per_variant() {
        // byte_count takes self by value (Copy), so calling twice
        // on the same variant returns the same number.
        let h = HeaderSize::Two;
        assert_eq!(h.byte_count(), h.byte_count());
    }

    #[test]
    fn header_size_is_copy_and_eq() {
        let a = HeaderSize::Four;
        let b = a; // Copy — a still usable below.
        assert_eq!(a, b);
        assert_eq!(a, HeaderSize::Four);
        assert_ne!(a, HeaderSize::One);
    }

    #[test]
    fn header_size_debug_output_includes_variant_name() {
        // Diagnostic contract: Debug output for a HeaderSize contains
        // the variant name verbatim so tracing fields are human-readable.
        assert!(format!("{:?}", HeaderSize::One).contains("One"));
        assert!(format!("{:?}", HeaderSize::Two).contains("Two"));
        assert!(format!("{:?}", HeaderSize::Four).contains("Four"));
    }

    #[test]
    fn framing_strategy_is_clone_and_debug() {
        // FramingStrategy is cloned into per-session codec state and
        // is logged at session setup; Clone + Debug must compile and
        // produce non-empty output for every variant.
        for strategy in [
            FramingStrategy::LengthPrefixed {
                header_size: HeaderSize::Four,
            },
            FramingStrategy::XmlStream,
            FramingStrategy::LineDelimited,
            FramingStrategy::TakProtobuf,
            FramingStrategy::Mavlink,
        ] {
            let cloned = strategy.clone();
            assert!(!format!("{cloned:?}").is_empty());
        }
    }

    #[test]
    fn framing_strategy_length_prefixed_preserves_header_size() {
        // The LengthPrefixed variant is the only non-unit variant.
        // Cloning must carry the inner HeaderSize through unchanged.
        let original = FramingStrategy::LengthPrefixed {
            header_size: HeaderSize::Two,
        };
        let cloned = original.clone();
        match cloned {
            FramingStrategy::LengthPrefixed { header_size } => {
                assert_eq!(header_size, HeaderSize::Two);
                assert_eq!(header_size.byte_count(), 2);
            }
            other => panic!("expected LengthPrefixed, got {other:?}"),
        }
    }
}
