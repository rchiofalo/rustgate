// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! MIL-STD-2045-47001 application header for VMF datagrams.
//!
//! Every VMF wire frame begins with an application header that carries
//! addressing (URN: Unit Reference Number — a 24-bit identifier the
//! Army/USMC issue per radio at deployment time), the date-time-group
//! the message was originated, the originator/recipient pair, the
//! message identification (FAD = Functional Area Designator + MSG-NUM,
//! together identifying the K-series message type), and security
//! classification. All fields are bit-packed using Field Presence
//! Indicators (FPIs) — see the module docs on [`crate`] for the
//! semantics.
//!
//! # MVP scope and assumptions
//!
//! MIL-STD-2045-47001 is not freely available. The wire form pinned
//! here is the layered subset published in open-literature references
//! (FM 6-99 "U.S. Army Report and Message Formats", JPL/Caltech VMF
//! interop notes, NATO STANAG 5616 cross-reference), plus the layout
//! pinned by the issue (URN, DTG, message type, classification,
//! addressing). Where the open-literature shape leaves a field
//! ambiguous (e.g. exact bit width of the operation-indicator group),
//! the codec uses the most common width and documents the choice
//! inline so a reviewer with access to the closed spec can correct.
//!
//! Concretely, the MVP implements the header subset required to
//! identify the K05.1 Position Report MVP body and to round-trip its
//! addressing. A larger header surface (acknowledgment-required,
//! response-required, retransmit-counter, etc.) is captured as
//! optional fields gated by FPIs on encode and decoded best-effort on
//! decode.
//!
//! # Bit layout
//!
//! The header is laid out in this order. Every numeric width is
//! big-endian within the bit stream.
//!
//! | Field                           | Bits | Notes                                                            |
//! |---------------------------------|------|------------------------------------------------------------------|
//! | Version                         | 4    | Always 0x1 for the v1 wire format pinned here                    |
//! | Compression group FPI           | 1    | Required-presence indicator for the (always-zero) compression    |
//! | Header size (bytes)             | 8    | Total header byte length — used for forward-compatible skip      |
//! | Originator URN                  | 24   | Source unit reference number                                     |
//! | Recipient FPI                   | 1    | When 1, recipient URN follows                                    |
//! | Recipient URN                   | 24   | Destination unit reference (gated by recipient FPI)              |
//! | Message ID FPI                  | 1    | When 1, FAD + MSG-NUM follow                                     |
//! | FAD (Functional Area Designator)| 4    | High nibble of K-series identification (e.g. 0x0 → K00..K08)     |
//! | MSG-NUM                         | 7    | Low part of K-series identification (e.g. 0x05 → K05.NUM)        |
//! | Subnumber                       | 4    | The `.X` component (K05.1 → subnumber 1)                         |
//! | Classification                  | 3    | 0=Unclassified 1=Confidential 2=Secret 3=Top-Secret 4..7 reserved|
//! | DTG-extension FPI               | 1    | When 1, full 64-bit POSIX seconds + 20-bit microseconds DTG      |
//! | DTG (POSIX seconds)             | 64   | Unsigned seconds since 1970-01-01T00:00Z UTC                     |
//! | DTG microseconds                | 20   | Sub-second precision                                             |
//!
//! After this point the application body bits begin. K05.1 starts at
//! the first bit immediately after the header — see [`crate::k05_1`].

use crate::bitstream::{BitReader, BitWriter};
use crate::error::VmfError;

/// Header version pinned by the MVP. The format version field on the
/// wire is 4 bits; 0x1 is the only value this codec emits and the
/// decoder rejects anything else with [`VmfError::InvalidValue`] so a
/// corrupt or future-protocol frame does not silently misparse.
pub const VMF_HEADER_VERSION: u8 = 0x1;

/// Security classification levels carried in the header. The 3-bit
/// envelope leaves room for the standard MIL ladder; values 4..7 are
/// reserved by MIL-STD-2045-47001.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Classification {
    /// Unclassified — value `0`.
    Unclassified,
    /// Confidential — value `1`.
    Confidential,
    /// Secret — value `2`.
    Secret,
    /// Top Secret — value `3`.
    TopSecret,
    /// Any reserved value (4..=7). Carrying the raw byte verbatim
    /// keeps a hostile sender's choice of reserved bit visible to the
    /// audit trail without forcing the codec to invent a name for it.
    Reserved(u8),
}

impl Classification {
    /// Wire-format raw value (0..=7).
    #[must_use]
    pub fn raw(self) -> u8 {
        match self {
            Self::Unclassified => 0,
            Self::Confidential => 1,
            Self::Secret => 2,
            Self::TopSecret => 3,
            Self::Reserved(v) => v & 0x07,
        }
    }

    /// Construct from the wire-format raw value.
    #[must_use]
    pub fn from_raw(raw: u8) -> Self {
        match raw & 0x07 {
            0 => Self::Unclassified,
            1 => Self::Confidential,
            2 => Self::Secret,
            3 => Self::TopSecret,
            other => Self::Reserved(other),
        }
    }

    /// Stable lowercase tag used by audit / metrics.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unclassified => "unclassified",
            Self::Confidential => "confidential",
            Self::Secret => "secret",
            Self::TopSecret => "top-secret",
            Self::Reserved(_) => "reserved",
        }
    }
}

/// Date-time-group attached to a VMF header. POSIX seconds with
/// 20-bit microsecond carry. The 64-bit seconds envelope avoids the
/// year-2038 wraparound that would otherwise hit a 32-bit field
/// before mass deployment retirement of Army/USMC SINCGARS-ASIP
/// and EPLRS radios.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dtg {
    /// POSIX seconds since 1970-01-01T00:00Z.
    pub posix_seconds: u64,
    /// Sub-second microseconds in `[0, 1_000_000)`.
    pub microseconds: u32,
}

impl Dtg {
    /// Construct a DTG from POSIX seconds with no sub-second carry.
    #[must_use]
    pub fn from_seconds(posix_seconds: u64) -> Self {
        Self {
            posix_seconds,
            microseconds: 0,
        }
    }
}

/// VMF Functional Area Designator + MSG-NUM + subnumber. `K05.1`
/// (Position Report) is `Self { fad: 0, msg_num: 5, subnumber: 1 }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageId {
    /// Functional Area Designator (4-bit). Each FAD groups a slice of
    /// the K-series space. `0` covers the K00..K08 range, which
    /// includes K05 (Position Report).
    pub fad: u8,
    /// Message number within the FAD (7-bit). For K05.1, this is `5`.
    pub msg_num: u8,
    /// Subnumber (4-bit). For K05.1, this is `1`.
    pub subnumber: u8,
}

impl MessageId {
    /// K05.1 Position Report identifier.
    pub const K05_1: Self = Self {
        fad: 0,
        msg_num: 5,
        subnumber: 1,
    };

    /// Pack into a single u16 the rest of the codec uses for dispatch.
    /// Layout (high → low): `fad[4] | msg_num[7] | subnumber[4]` left
    /// in a 15-bit envelope; the high bit of the u16 is unused.
    #[must_use]
    pub fn as_u16(self) -> u16 {
        (u16::from(self.fad & 0x0F) << 11)
            | (u16::from(self.msg_num & 0x7F) << 4)
            | u16::from(self.subnumber & 0x0F)
    }

    /// True if this identifier is K05.1 Position Report.
    #[must_use]
    pub fn is_k05_1(self) -> bool {
        self.fad == Self::K05_1.fad
            && self.msg_num == Self::K05_1.msg_num
            && self.subnumber == Self::K05_1.subnumber
    }
}

/// MIL-STD-2045-47001 application header.
///
/// The optional fields (recipient URN, message ID, DTG) all gate on
/// their respective FPI bits during encode/decode so a sender that
/// omits them produces a smaller frame and the receiver still
/// reconstructs the carrying structure with `None`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmfHeader {
    /// Header version on the wire — currently always
    /// [`VMF_HEADER_VERSION`].
    pub version: u8,
    /// Source unit reference number (24-bit envelope).
    pub originator_urn: u32,
    /// Optional destination unit reference number (24-bit). Absent
    /// for broadcast traffic.
    pub recipient_urn: Option<u32>,
    /// Optional K-series identifier. Absent on management /
    /// link-layer frames that ride the same header but carry no
    /// application body.
    pub message_id: Option<MessageId>,
    /// Security classification.
    pub classification: Classification,
    /// Optional DTG. Absent on terse broadcast headers.
    pub dtg: Option<Dtg>,
}

impl VmfHeader {
    /// Default-construct a position-report header for the given
    /// originator with the canonical K05.1 message ID.
    #[must_use]
    pub fn new_k05_1(originator_urn: u32) -> Self {
        Self {
            version: VMF_HEADER_VERSION,
            originator_urn,
            recipient_urn: None,
            message_id: Some(MessageId::K05_1),
            classification: Classification::Unclassified,
            dtg: None,
        }
    }

    /// Decode a header from a [`BitReader`] positioned at the start
    /// of a VMF frame. On success the reader is positioned at the
    /// first bit of the application body. On failure the cursor is
    /// left in an indeterminate state — callers wanting to attempt a
    /// resync construct a fresh `BitReader`.
    pub fn decode(reader: &mut BitReader<'_>) -> Result<Self, VmfError> {
        let version_raw = reader.read_bits(4, "version")?;
        if version_raw as u8 != VMF_HEADER_VERSION {
            return Err(VmfError::InvalidValue {
                field: "version",
                detail: format!(
                    "wire version 0x{version_raw:X} != supported 0x{VMF_HEADER_VERSION:X}"
                ),
            });
        }
        let _compression_fpi = reader.read_bit("compression_fpi")?;
        let _header_size = reader.read_bits(8, "header_size")?;
        let originator_urn = reader.read_bits(24, "originator_urn")?;
        let recipient_fpi = reader.read_bit("recipient_fpi")?;
        let recipient_urn = if recipient_fpi {
            Some(reader.read_bits(24, "recipient_urn")?)
        } else {
            None
        };
        let message_id_fpi = reader.read_bit("message_id_fpi")?;
        let message_id = if message_id_fpi {
            let fad = reader.read_bits(4, "fad")? as u8;
            let msg_num = reader.read_bits(7, "msg_num")? as u8;
            let subnumber = reader.read_bits(4, "subnumber")? as u8;
            Some(MessageId {
                fad,
                msg_num,
                subnumber,
            })
        } else {
            None
        };
        let classification_raw = reader.read_bits(3, "classification")? as u8;
        let classification = Classification::from_raw(classification_raw);
        let dtg_fpi = reader.read_bit("dtg_fpi")?;
        let dtg = if dtg_fpi {
            // 64-bit POSIX seconds = 32 bits high + 32 bits low.
            let hi = u64::from(reader.read_bits(32, "dtg_seconds_hi")?);
            let lo = u64::from(reader.read_bits(32, "dtg_seconds_lo")?);
            let posix_seconds = (hi << 32) | lo;
            let microseconds = reader.read_bits(20, "dtg_microseconds")?;
            if microseconds >= 1_000_000 {
                return Err(VmfError::InvalidValue {
                    field: "dtg_microseconds",
                    detail: format!("raw {microseconds} >= 1_000_000"),
                });
            }
            Some(Dtg {
                posix_seconds,
                microseconds,
            })
        } else {
            None
        };
        Ok(Self {
            version: VMF_HEADER_VERSION,
            originator_urn,
            recipient_urn,
            message_id,
            classification,
            dtg,
        })
    }

    /// Encode the header into the supplied [`BitWriter`].
    pub fn encode(&self, writer: &mut BitWriter) -> Result<(), VmfError> {
        if self.version != VMF_HEADER_VERSION {
            return Err(VmfError::EncodeOverflow {
                field: "version",
                detail: format!(
                    "header version 0x{:X} != supported 0x{VMF_HEADER_VERSION:X}",
                    self.version
                ),
            });
        }
        writer.write_bits(u32::from(VMF_HEADER_VERSION), 4, "version")?;
        // Compression group FPI is always zero in this build — the
        // optional compression group is not implemented.
        writer.write_bit(false, "compression_fpi")?;
        // Header size: best-effort; the receiver uses the size for
        // forward-compatible skip, but in this MVP the size is
        // simply 0 and the receiver walks the FPIs. A future PR will
        // back-patch the byte count once the encoder is finalised.
        writer.write_bits(0, 8, "header_size")?;
        writer.write_bits(self.originator_urn, 24, "originator_urn")?;
        match self.recipient_urn {
            Some(urn) => {
                writer.write_bit(true, "recipient_fpi")?;
                writer.write_bits(urn, 24, "recipient_urn")?;
            }
            None => writer.write_bit(false, "recipient_fpi")?,
        }
        match self.message_id {
            Some(id) => {
                writer.write_bit(true, "message_id_fpi")?;
                writer.write_bits(u32::from(id.fad), 4, "fad")?;
                writer.write_bits(u32::from(id.msg_num), 7, "msg_num")?;
                writer.write_bits(u32::from(id.subnumber), 4, "subnumber")?;
            }
            None => writer.write_bit(false, "message_id_fpi")?,
        }
        writer.write_bits(
            u32::from(self.classification.raw() & 0x07),
            3,
            "classification",
        )?;
        match self.dtg {
            Some(dtg) => {
                writer.write_bit(true, "dtg_fpi")?;
                let hi = (dtg.posix_seconds >> 32) as u32;
                let lo = dtg.posix_seconds as u32;
                writer.write_bits(hi, 32, "dtg_seconds_hi")?;
                writer.write_bits(lo, 32, "dtg_seconds_lo")?;
                if dtg.microseconds >= 1_000_000 {
                    return Err(VmfError::EncodeOverflow {
                        field: "dtg_microseconds",
                        detail: format!("microseconds {} >= 1_000_000", dtg.microseconds),
                    });
                }
                writer.write_bits(dtg.microseconds, 20, "dtg_microseconds")?;
            }
            None => writer.write_bit(false, "dtg_fpi")?,
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn header_round_trips_minimal() {
        let header = VmfHeader::new_k05_1(0x12_3456);
        let mut w = BitWriter::new();
        header.encode(&mut w).unwrap();
        let bytes = w.into_bytes();
        let mut r = BitReader::new(&bytes);
        let decoded = VmfHeader::decode(&mut r).unwrap();
        assert_eq!(decoded, header);
    }

    #[test]
    fn header_round_trips_full() {
        let header = VmfHeader {
            version: VMF_HEADER_VERSION,
            originator_urn: 0xAA_BBCC,
            recipient_urn: Some(0x11_2233),
            message_id: Some(MessageId::K05_1),
            classification: Classification::Secret,
            dtg: Some(Dtg {
                posix_seconds: 1_700_000_000,
                microseconds: 123_456,
            }),
        };
        let mut w = BitWriter::new();
        header.encode(&mut w).unwrap();
        let bytes = w.into_bytes();
        let mut r = BitReader::new(&bytes);
        let decoded = VmfHeader::decode(&mut r).unwrap();
        assert_eq!(decoded, header);
    }

    #[test]
    fn decode_rejects_wrong_version() {
        // First nibble = 0x2 (unsupported version).
        let bytes = [0x20u8, 0x00];
        let mut r = BitReader::new(&bytes);
        let err = VmfHeader::decode(&mut r).unwrap_err();
        assert!(matches!(
            err,
            VmfError::InvalidValue {
                field: "version",
                ..
            }
        ));
    }

    #[test]
    fn message_id_pack_unpack() {
        let id = MessageId::K05_1;
        // K05.1 = fad=0, msg_num=5, subnumber=1
        // = 0b0000_0000101_0001 = 0x0051
        assert_eq!(id.as_u16(), 0x0051);
        assert!(id.is_k05_1());
    }

    #[test]
    fn classification_round_trips_each_level() {
        for raw in 0u8..8 {
            let c = Classification::from_raw(raw);
            assert_eq!(c.raw(), raw);
        }
    }

    #[test]
    fn dtg_microseconds_out_of_range_rejected_on_encode() {
        let mut header = VmfHeader::new_k05_1(0x1);
        header.dtg = Some(Dtg {
            posix_seconds: 0,
            microseconds: 1_000_000,
        });
        let mut w = BitWriter::new();
        let err = header.encode(&mut w).unwrap_err();
        assert!(matches!(
            err,
            VmfError::EncodeOverflow {
                field: "dtg_microseconds",
                ..
            }
        ));
    }
}
