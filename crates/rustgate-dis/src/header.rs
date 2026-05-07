// Copyright © 2026 Roberto Chiofalo.

//! IEEE 1278.1 PDU common header (clause 5.2.32).
//!
//! Every DIS PDU starts with a 12-byte common header. The header is
//! the framing layer for multi-PDU UDP datagrams: a receiver reads the
//! `length` field, advances the cursor by that many bytes, and
//! repeats. The codec exposes the header as a typed value so callers
//! can dispatch on `pdu_type` without re-parsing the body.
//!
//! # Wire layout (12 bytes, big-endian)
//!
//! | Offset | Size | Field            | Notes                             |
//! |--------|------|------------------|-----------------------------------|
//! | 0      | 1    | protocol_version | IEEE 1278.1-2012 → 7              |
//! | 1      | 1    | exercise_id      | Exercise group; site-defined      |
//! | 2      | 1    | pdu_type         | See [`PduType`]                   |
//! | 3      | 1    | protocol_family  | See [`ProtocolFamily`]            |
//! | 4      | 4    | timestamp        | Per IEEE 1278.1 § 5.2.32.5        |
//! | 8      | 2    | length           | Total PDU length (header + body)  |
//! | 10     | 2    | padding          | Reserved (zero on encode)         |

use crate::error::DisError;

/// Total byte length of the common header.
pub const HEADER_LEN: usize = 12;

/// IEEE 1278.1-2012 protocol version. Version `7` is the canonical
/// value emitted by every modern IEEE 1278.1 deployment; earlier
/// versions (`5` for IEEE 1278.1-1995, `6` for IEEE 1278.1A-1998)
/// remain interoperable with this codec at the wire level — the
/// encoder defaults to `7` but the decoder accepts any non-zero
/// version.
pub const IEEE_1278_1_2012: u8 = 7;

/// Default UDP port reserved by IEEE 1278.1 deployments. Listener
/// wiring is out of scope for this crate; the constant exists so a
/// future server-side adapter (issue #867 follow-ups) has a single
/// audit point.
pub const DIS_DEFAULT_UDP_PORT: u16 = 3000;

/// Typed view of the IEEE 1278.1 PDU type byte.
///
/// Only [`PduType::EntityState`] is decoded into a typed body shape
/// in the MVP; every other value is preserved as
/// [`PduType::Other`] so a multi-PDU datagram can still be framed and
/// the decoder can advance to the next header. The numeric values are
/// pinned per IEEE 1278.1-2012 Annex A (PDU enumeration).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PduType {
    /// Entity State PDU (`pdu_type = 1`). Decoded into
    /// [`crate::entity_state::EntityStatePdu`].
    EntityState,
    /// Any PDU type the MVP does not yet decode. The wrapped byte is
    /// the wire value so callers can dispatch numerically while the
    /// follow-up PRs land typed shapes.
    Other(u8),
}

impl PduType {
    /// Wire byte value for the Entity State PDU per IEEE 1278.1-2012
    /// Annex A.
    pub const ENTITY_STATE: u8 = 1;

    /// Decode a wire byte into a typed [`PduType`].
    #[must_use]
    pub fn from_u8(byte: u8) -> Self {
        match byte {
            Self::ENTITY_STATE => Self::EntityState,
            other => Self::Other(other),
        }
    }

    /// Convert back to the wire byte. Round-trips
    /// `from_u8(x).to_u8() == x` for every byte value.
    #[must_use]
    pub fn to_u8(self) -> u8 {
        match self {
            Self::EntityState => Self::ENTITY_STATE,
            Self::Other(v) => v,
        }
    }
}

/// Typed view of the IEEE 1278.1 protocol-family byte.
///
/// IEEE 1278.1 partitions the 72 standardised PDU types into seven
/// protocol families; the header carries the family byte alongside the
/// PDU type so receivers can route at the family granularity (e.g. a
/// gateway that bridges `EntityInformationInteraction` between two
/// federations may not need to bridge `Warfare`). Only the families
/// referenced by the MVP PDU types are explicitly named; everything
/// else rides on [`ProtocolFamily::Other`] for forward compatibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolFamily {
    /// Family 1: Entity Information / Interaction (Entity State,
    /// Collision, Collision-Elastic, Entity State Update, …).
    EntityInformationInteraction,
    /// Any family this codec does not enumerate explicitly. The
    /// wrapped byte is the wire value.
    Other(u8),
}

impl ProtocolFamily {
    /// Wire byte for the Entity Information / Interaction family.
    pub const ENTITY_INFORMATION_INTERACTION: u8 = 1;

    /// Decode a wire byte into a typed [`ProtocolFamily`].
    #[must_use]
    pub fn from_u8(byte: u8) -> Self {
        match byte {
            Self::ENTITY_INFORMATION_INTERACTION => Self::EntityInformationInteraction,
            other => Self::Other(other),
        }
    }

    /// Convert back to the wire byte.
    #[must_use]
    pub fn to_u8(self) -> u8 {
        match self {
            Self::EntityInformationInteraction => Self::ENTITY_INFORMATION_INTERACTION,
            Self::Other(v) => v,
        }
    }
}

/// IEEE 1278.1 PDU common header.
///
/// Decoded from / encoded to the 12-byte wire shape via [`Self::decode`]
/// and [`Self::encode_into`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PduHeader {
    /// Protocol version byte. `7` is IEEE 1278.1-2012; any non-zero
    /// value is accepted on decode for forward compatibility.
    pub protocol_version: u8,
    /// Exercise identifier. Each exercise on a shared LAN segment
    /// uses a distinct value so receivers can filter by exercise.
    pub exercise_id: u8,
    /// PDU type. See [`PduType`].
    pub pdu_type: PduType,
    /// Protocol family. See [`ProtocolFamily`].
    pub protocol_family: ProtocolFamily,
    /// Wire timestamp per IEEE 1278.1 § 5.2.32.5. The low bit
    /// distinguishes absolute vs. relative timestamps; the high 31
    /// bits are units of 1.6384 microseconds since the top of the
    /// hour. Rather than parsing that interpretation here (which
    /// requires sender / receiver clock alignment), the codec
    /// preserves the raw `u32` and lets the integration layer apply
    /// the wall-clock anchor.
    pub timestamp: u32,
    /// Total PDU length in bytes (header + body). Used by receivers
    /// to frame multi-PDU UDP datagrams.
    pub length: u16,
    /// Reserved padding bytes (zero on encode). Preserved on decode
    /// so a same-codec round-trip is byte-exact even on senders that
    /// emit non-zero padding.
    pub padding: u16,
}

impl PduHeader {
    /// Build a new header for the given PDU type and length, defaulting
    /// to IEEE 1278.1-2012 protocol version, zero exercise / timestamp
    /// / padding. Convenience constructor for encoders.
    #[must_use]
    pub fn new(pdu_type: PduType, protocol_family: ProtocolFamily, length: u16) -> Self {
        Self {
            protocol_version: IEEE_1278_1_2012,
            exercise_id: 0,
            pdu_type,
            protocol_family,
            timestamp: 0,
            length,
            padding: 0,
        }
    }

    /// Decode the 12-byte common header from the start of `buf`.
    ///
    /// Returns the typed header on success. The cursor remains at byte
    /// 0 — callers slice `buf[HEADER_LEN..]` to advance to the body.
    pub fn decode(buf: &[u8]) -> Result<Self, DisError> {
        if buf.len() < HEADER_LEN {
            return Err(DisError::Truncated {
                field: "PduHeader",
                needed: HEADER_LEN,
                available: buf.len(),
            });
        }
        let protocol_version = buf[0];
        let exercise_id = buf[1];
        let pdu_type = PduType::from_u8(buf[2]);
        let protocol_family = ProtocolFamily::from_u8(buf[3]);
        let timestamp = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let length = u16::from_be_bytes([buf[8], buf[9]]);
        let padding = u16::from_be_bytes([buf[10], buf[11]]);
        Ok(Self {
            protocol_version,
            exercise_id,
            pdu_type,
            protocol_family,
            timestamp,
            length,
            padding,
        })
    }

    /// Encode the header into the supplied byte sink.
    ///
    /// Writes exactly [`HEADER_LEN`] bytes. The caller is responsible
    /// for ensuring `out` has spare capacity.
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        out.push(self.protocol_version);
        out.push(self.exercise_id);
        out.push(self.pdu_type.to_u8());
        out.push(self.protocol_family.to_u8());
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        out.extend_from_slice(&self.length.to_be_bytes());
        out.extend_from_slice(&self.padding.to_be_bytes());
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn header_round_trips_through_decode_encode() {
        let header = PduHeader {
            protocol_version: IEEE_1278_1_2012,
            exercise_id: 42,
            pdu_type: PduType::EntityState,
            protocol_family: ProtocolFamily::EntityInformationInteraction,
            timestamp: 0xDEAD_BEEF,
            length: 144,
            padding: 0,
        };
        let mut bytes = Vec::with_capacity(HEADER_LEN);
        header.encode_into(&mut bytes);
        assert_eq!(bytes.len(), HEADER_LEN);
        let decoded = PduHeader::decode(&bytes).expect("decode");
        assert_eq!(decoded, header);
    }

    #[test]
    fn header_decode_rejects_truncated_input() {
        let bytes = [0u8; HEADER_LEN - 1];
        let err = PduHeader::decode(&bytes).expect_err("must fail");
        assert!(matches!(err, DisError::Truncated { needed: 12, .. }));
    }

    #[test]
    fn pdu_type_round_trips_for_all_byte_values() {
        for byte in 0u8..=255u8 {
            assert_eq!(PduType::from_u8(byte).to_u8(), byte);
        }
    }

    #[test]
    fn protocol_family_round_trips_for_all_byte_values() {
        for byte in 0u8..=255u8 {
            assert_eq!(ProtocolFamily::from_u8(byte).to_u8(), byte);
        }
    }

    #[test]
    fn pdu_type_entity_state_byte_matches_ieee_annex_a() {
        // Pin the wire byte for forward-compatibility with the
        // PDU-type → typed-shape dispatch table that future PRs add.
        assert_eq!(PduType::EntityState.to_u8(), 1);
    }

    #[test]
    fn protocol_family_entity_info_byte_matches_ieee_annex_a() {
        assert_eq!(ProtocolFamily::EntityInformationInteraction.to_u8(), 1);
    }

    #[test]
    fn header_new_uses_canonical_protocol_version() {
        // The convenience constructor must yield IEEE 1278.1-2012 by
        // default so encoders that do not override the version stay
        // compliant.
        let header = PduHeader::new(
            PduType::EntityState,
            ProtocolFamily::EntityInformationInteraction,
            64,
        );
        assert_eq!(header.protocol_version, IEEE_1278_1_2012);
        assert_eq!(header.exercise_id, 0);
        assert_eq!(header.timestamp, 0);
        assert_eq!(header.length, 64);
        assert_eq!(header.padding, 0);
    }

    #[test]
    fn header_decode_preserves_non_zero_padding() {
        // A sender that emits non-zero padding (sometimes seen in
        // legacy implementations) must round-trip byte-exactly through
        // the codec — the integration layer can choose to reject in
        // strict mode but the header decoder is permissive.
        let mut bytes = vec![0u8; HEADER_LEN];
        bytes[0] = IEEE_1278_1_2012;
        bytes[2] = PduType::ENTITY_STATE;
        bytes[3] = ProtocolFamily::ENTITY_INFORMATION_INTERACTION;
        bytes[10] = 0x12;
        bytes[11] = 0x34;
        let header = PduHeader::decode(&bytes).expect("decode");
        assert_eq!(header.padding, 0x1234);

        let mut out = Vec::with_capacity(HEADER_LEN);
        header.encode_into(&mut out);
        assert_eq!(out, bytes);
    }
}
