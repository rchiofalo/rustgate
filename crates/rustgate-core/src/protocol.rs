// Copyright © 2026 Roberto Chiofalo.

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
