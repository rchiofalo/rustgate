// Copyright © 2026 Roberto Chiofalo.

//! JREAP-C frame header (STANAG 5518).
//!
//! Every JREAP-C frame on the wire starts with a fixed 16-byte header
//! followed by a body whose shape depends on the message type. The
//! header is the framing layer for back-to-back frames on a single
//! TCP connection: a receiver reads the `body_length` field, advances
//! the cursor by that many bytes, and repeats. The codec exposes the
//! header as a typed value so callers can dispatch on `message_type`
//! without re-parsing the body.
//!
//! # Wire layout (16 bytes, big-endian)
//!
//! | Offset | Size | Field          | Notes                                  |
//! |--------|------|----------------|----------------------------------------|
//! | 0      | 1    | version        | JREAP-C is [`JREAP_C_VERSION`] (`3`)   |
//! | 1      | 1    | message_type   | See [`JreapMessageType`]               |
//! | 2      | 1    | exercise_id    | Coalition exercise group; site-defined |
//! | 3      | 1    | reserved       | Reserved (zero on encode)              |
//! | 4      | 4    | sequence       | Monotonic per-connection counter       |
//! | 8      | 4    | timestamp      | Seconds since UNIX epoch (sender clock)|
//! | 12     | 4    | body_length    | Bytes following the header             |
//!
//! The 4-byte sequence and timestamp split keeps the header
//! 32-bit-aligned for the receivers that walk the byte buffer as
//! `u32` pairs. The 4-byte `body_length` field puts the framing cap
//! at 4 GiB per frame — practical deployments cap it far lower at
//! the listener layer.
//!
//! # Spec assumption (MVP)
//!
//! STANAG 5518 is a restricted-distribution document. The 16-byte
//! header layout above is the layered subset published in
//! open-literature interoperability guides plus the layout pinned by
//! issue #866. A reviewer with access to the closed spec can correct
//! individual field widths without touching the codec scaffolding.

use crate::error::Link16Error;

/// Total byte length of the JREAP-C frame header.
pub const JREAP_HEADER_LEN: usize = 16;

/// JREAP-C version byte. JREAP-A (broadcast multicast) is `0x01`,
/// JREAP-B (serial / SATCOM) is `0x02`, JREAP-C (TCP/IP) is `0x03`.
/// The codec only decodes JREAP-C; other variants surface as
/// [`Link16Error::UnsupportedVersion`].
pub const JREAP_C_VERSION: u8 = 0x03;

/// Default TCP port reserved by JREAP-C deployments. Listener wiring
/// is out of scope for this crate; the constant exists so a future
/// server-side adapter (issue #866 follow-ups) has a single audit
/// point.
///
/// IANA does not assign a well-known port for JREAP-C; vendor
/// integration manuals for the open-source SIMPLE / JREAP test
/// harnesses converge on `4444` for default TCP listener wiring.
pub const JREAP_DEFAULT_TCP_PORT: u16 = 4444;

/// Typed view of the JREAP-C `message_type` byte.
///
/// JREAP-C carries either a single J-series message body
/// ([`JreapMessageType::JseriesData`]) or one of a handful of
/// connection-management messages exchanged at session start (link
/// connect, heartbeat, link disconnect). Only `JseriesData` is
/// decoded into a typed body shape in the MVP; every other value is
/// preserved as [`JreapMessageType::Other`] so a multi-frame TCP
/// stream can still be framed and the decoder can advance past
/// keepalive frames it does not understand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JreapMessageType {
    /// J-series data frame. Body is a single J-series message
    /// (J2.x, J3.x, J7.x, …) whose shape depends on the J-series
    /// message label byte at body offset 0. The MVP decodes J2.2
    /// (Air Track) and preserves every other label as opaque bytes.
    JseriesData,
    /// Any JREAP-C message type the MVP does not yet decode. The
    /// wrapped byte is the wire value so callers can dispatch
    /// numerically while the follow-up PRs land typed shapes for
    /// link-connect, heartbeat, and link-disconnect messages.
    Other(u8),
}

impl JreapMessageType {
    /// Wire byte value for J-series data frames per STANAG 5518.
    pub const JSERIES_DATA: u8 = 0x01;

    /// Decode a wire byte into a typed [`JreapMessageType`].
    #[must_use]
    pub fn from_u8(byte: u8) -> Self {
        match byte {
            Self::JSERIES_DATA => Self::JseriesData,
            other => Self::Other(other),
        }
    }

    /// Convert back to the wire byte. Round-trips
    /// `from_u8(x).to_u8() == x` for every byte value.
    #[must_use]
    pub fn to_u8(self) -> u8 {
        match self {
            Self::JseriesData => Self::JSERIES_DATA,
            Self::Other(v) => v,
        }
    }
}

/// JREAP-C frame header.
///
/// Decoded from / encoded to the 16-byte wire shape via
/// [`Self::decode`] and [`Self::encode_into`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JreapFrame {
    /// Protocol version byte. Must be [`JREAP_C_VERSION`] (`3`); other
    /// values surface as [`Link16Error::UnsupportedVersion`].
    pub version: u8,
    /// JREAP-C message type. See [`JreapMessageType`].
    pub message_type: JreapMessageType,
    /// Exercise identifier. Each coalition exercise on a shared IP
    /// segment uses a distinct value so receivers can filter by
    /// exercise.
    pub exercise_id: u8,
    /// Reserved byte at offset 3. Preserved on decode so a same-codec
    /// round-trip is byte-exact even on senders that emit non-zero
    /// reserved bytes.
    pub reserved: u8,
    /// Monotonic per-connection sequence counter. Re-set to zero on
    /// each TCP connect; the receiver uses it to detect frame loss
    /// (gap detection) on lossy WAN paths between coalition partners.
    pub sequence: u32,
    /// Seconds since the UNIX epoch on the sender's clock. Coalition
    /// exercises align senders against a shared GPS / NTP source so
    /// the field is meaningful for cross-platform track correlation
    /// — but the codec preserves the raw `u32` and lets the
    /// integration layer apply any wall-clock anchor.
    pub timestamp: u32,
    /// Length of the body following the 16-byte header. Used by
    /// receivers to frame back-to-back JREAP-C frames on one TCP
    /// connection.
    pub body_length: u32,
}

impl JreapFrame {
    /// Build a new frame header with the given message type and body
    /// length, defaulting to [`JREAP_C_VERSION`], zero exercise /
    /// reserved / sequence / timestamp. Convenience constructor for
    /// encoders.
    #[must_use]
    pub fn new(message_type: JreapMessageType, body_length: u32) -> Self {
        Self {
            version: JREAP_C_VERSION,
            message_type,
            exercise_id: 0,
            reserved: 0,
            sequence: 0,
            timestamp: 0,
            body_length,
        }
    }

    /// Decode the 16-byte JREAP-C frame header from the start of `buf`.
    ///
    /// Returns the typed header on success. The cursor remains at byte
    /// 0 — callers slice `buf[JREAP_HEADER_LEN..]` to advance to the
    /// body.
    pub fn decode(buf: &[u8]) -> Result<Self, Link16Error> {
        if buf.len() < JREAP_HEADER_LEN {
            return Err(Link16Error::Truncated {
                field: "JreapFrame",
                needed: JREAP_HEADER_LEN,
                available: buf.len(),
            });
        }
        let version = buf[0];
        if version != JREAP_C_VERSION {
            return Err(Link16Error::UnsupportedVersion {
                got: version,
                expected: JREAP_C_VERSION,
            });
        }
        let message_type = JreapMessageType::from_u8(buf[1]);
        let exercise_id = buf[2];
        let reserved = buf[3];
        let sequence = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let timestamp = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let body_length = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);
        Ok(Self {
            version,
            message_type,
            exercise_id,
            reserved,
            sequence,
            timestamp,
            body_length,
        })
    }

    /// Encode the header into the supplied byte sink.
    ///
    /// Writes exactly [`JREAP_HEADER_LEN`] bytes. The caller is
    /// responsible for ensuring `out` has spare capacity.
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        out.push(self.version);
        out.push(self.message_type.to_u8());
        out.push(self.exercise_id);
        out.push(self.reserved);
        out.extend_from_slice(&self.sequence.to_be_bytes());
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        out.extend_from_slice(&self.body_length.to_be_bytes());
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn header_round_trips_through_decode_encode() {
        let header = JreapFrame {
            version: JREAP_C_VERSION,
            message_type: JreapMessageType::JseriesData,
            exercise_id: 7,
            reserved: 0,
            sequence: 0x0001_2345,
            timestamp: 0x6655_4433,
            body_length: 64,
        };
        let mut bytes = Vec::with_capacity(JREAP_HEADER_LEN);
        header.encode_into(&mut bytes);
        assert_eq!(bytes.len(), JREAP_HEADER_LEN);
        let decoded = JreapFrame::decode(&bytes).expect("decode");
        assert_eq!(decoded, header);
    }

    #[test]
    fn header_decode_rejects_truncated_input() {
        let bytes = [0u8; JREAP_HEADER_LEN - 1];
        let err = JreapFrame::decode(&bytes).expect_err("must fail");
        assert!(matches!(err, Link16Error::Truncated { needed: 16, .. }));
    }

    #[test]
    fn header_decode_rejects_non_jreap_c_version() {
        let mut bytes = vec![0u8; JREAP_HEADER_LEN];
        bytes[0] = 0x01; // JREAP-A
        let err = JreapFrame::decode(&bytes).expect_err("must fail");
        assert!(matches!(
            err,
            Link16Error::UnsupportedVersion {
                got: 0x01,
                expected: JREAP_C_VERSION
            }
        ));
    }

    #[test]
    fn message_type_round_trips_for_all_byte_values() {
        for byte in 0u8..=255u8 {
            assert_eq!(JreapMessageType::from_u8(byte).to_u8(), byte);
        }
    }

    #[test]
    fn message_type_jseries_data_byte_matches_stanag() {
        // Pin the wire byte for forward-compatibility with the
        // message-type → typed-shape dispatch table that future PRs
        // add for link-connect / heartbeat / link-disconnect frames.
        assert_eq!(JreapMessageType::JseriesData.to_u8(), 1);
    }

    #[test]
    fn header_new_uses_canonical_jreap_c_version() {
        let header = JreapFrame::new(JreapMessageType::JseriesData, 32);
        assert_eq!(header.version, JREAP_C_VERSION);
        assert_eq!(header.exercise_id, 0);
        assert_eq!(header.reserved, 0);
        assert_eq!(header.sequence, 0);
        assert_eq!(header.timestamp, 0);
        assert_eq!(header.body_length, 32);
    }

    #[test]
    fn header_decode_preserves_non_zero_reserved_byte() {
        // A sender that emits non-zero reserved bytes (sometimes seen
        // in legacy integrators) must round-trip byte-exactly through
        // the codec — the integration layer can choose to reject in
        // strict mode, but the header decoder is permissive.
        let mut bytes = vec![0u8; JREAP_HEADER_LEN];
        bytes[0] = JREAP_C_VERSION;
        bytes[1] = JreapMessageType::JSERIES_DATA;
        bytes[3] = 0x5A;
        let header = JreapFrame::decode(&bytes).expect("decode");
        assert_eq!(header.reserved, 0x5A);

        let mut out = Vec::with_capacity(JREAP_HEADER_LEN);
        header.encode_into(&mut out);
        assert_eq!(out, bytes);
    }
}
