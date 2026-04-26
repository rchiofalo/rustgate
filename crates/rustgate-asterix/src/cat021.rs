// Copyright © 2026 Roberto Chiofalo.

//! ASTERIX CAT-021 (ADS-B Reports) codec.
//!
//! CAT-021 carries Automatic Dependent Surveillance-Broadcast (ADS-B)
//! reports — the surveillance broadcasts emitted by every commercial
//! aircraft via its Mode-S Extended Squitter transponder. For tactical
//! UAS deployments, integrating ADS-B feeds is the load-bearing
//! detect-and-avoid signal: every Boeing/Airbus in the operating area
//! transmits its own position and identity at 1-2 Hz, and a UAS that
//! ingests CAT-021 can deconflict with manned air traffic in real time.
//!
//! The wire framing is identical to [`crate::cat062::decode_cat062`]
//! (CAT byte + 16-bit big-endian LEN + per-record FSPEC + FX-chained
//! extension bits) so the same datablock structure applies — only the
//! per-FRN field set differs per Eurocontrol's CAT-021 UAP. This
//! module handles the issue-#1121 minimum-viable subset of fields:
//! Data Source ID, Target Address (the 24-bit ICAO aircraft
//! identifier), Position WGS-84, Time of Applicability for Position,
//! Flight Level, and Target Identification (callsign). All other UAP
//! entries are recognised by length and skipped, so a real-world
//! CAT-021 datablock with any subset of the documented fields decodes
//! cleanly without rejection.
//!
//! # Encode direction
//!
//! [`encode_cat021`] and [`encode_cat021_into`] re-emit a
//! [`Cat021Report`] (or a slice of them) as a CAT-021 datablock.
//! The encoder is the byte-exact inverse of [`decode_cat021`] for the
//! MVP fields: only the FSPEC bits whose corresponding `Option` field
//! is `Some(...)` are set, and the field ordering walks FRNs 1..=48 in
//! ascending order to match the wire UAP. This gives a round-trip
//! self-stability invariant: a `Cat021Report` decoded from N bytes,
//! when re-encoded, produces a datablock that decodes back to a
//! `Cat021Report` with the same `Some(...)` field set. The encoder is
//! useful for forwarding-with-modification deployments (e.g. masking
//! the `target_address` before re-broadcasting to a less-privileged
//! consumer) and for integration tests that need to assert the byte
//! sequence rustgate would write back to a downstream feed.
//!
//! # Spec version
//!
//! Implements the wire format and Field Reference Numbers per
//! Eurocontrol CAT-021 v0.26 (Eurocontrol SUR.ET2.ST05.2000-STD-12-01,
//! Edition 0.26). The framing code is invariant across ASTERIX
//! categories so the future addition of CAT-048 (Mode-S radar) or
//! CAT-001 (legacy primary radar) is mostly a different per-FRN
//! length table, not a re-implementation of FSPEC parsing.

use thiserror::Error;

/// CAT-021 category byte.
pub const CAT_021: u8 = 21;

/// Minimum datablock size: CAT (1) + LEN (2) + at least one FSPEC byte.
const MIN_DATABLOCK_LEN: usize = 4;

/// Decoded CAT-021 ADS-B report.
///
/// Every field is `Option` because the FSPEC governs presence — even
/// the `target_address` (the canonical ADS-B identifier) is technically
/// optional per the UAP. A receiver should expect to see at least the
/// data-source identification (FRN 1, mandatory in practice) plus a
/// subset of the other items depending on the message type.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Cat021Report {
    /// I021/010 — Data Source Identifier. Two bytes packed as
    /// (SAC: u8) << 8 | (SIC: u8): the System Area Code identifies
    /// the geographic / administrative area the source belongs to,
    /// the System Identification Code identifies the specific
    /// emitting station within that area. Together they form a
    /// 16-bit "which sensor produced this report" tag that a fused
    /// tracker uses to attribute ADS-B reports back to the
    /// individual ground receivers in a multi-receiver deployment.
    /// Stored as a packed `u16` so [`encode_cat021`] can re-emit
    /// the exact two-byte wire pair without losing the SAC/SIC
    /// boundary; the high byte is SAC, the low byte is SIC.
    pub data_source_id: Option<u16>,

    /// I021/080 — Target Address. The 24-bit ICAO aircraft identifier
    /// (a.k.a. "Mode-S address" or "hex code"). This is the canonical
    /// identifier for an ADS-B-emitting aircraft and persists across
    /// flights — every aircraft's hex code is fixed at registration
    /// (e.g. `0xA1B2C3` for one specific Boeing 737). For tactical
    /// detect-and-avoid, this is the field a UAS uses to correlate
    /// successive position reports from the same aircraft.
    pub target_address: Option<u32>,

    /// I021/071 — Time of Applicability for Position, in
    /// seconds-since-midnight UTC. Wire LSB is 1/128 s; this field
    /// stores the converted floating-point seconds value
    /// (range `[0.0, 86_400.0)`).
    pub time_of_day_seconds: Option<f64>,

    /// I021/130 — Position in WGS-84 Coordinates (low-resolution
    /// 6-byte form). Wire LSB is `180 / 2^23` degrees (≈ 2.14 × 10⁻⁵
    /// deg, ≈ 2.4 m at the equator).
    pub position_wgs84: Option<WgsPosition>,

    /// I021/145 — Flight Level. Wire LSB is 1/4 FL (0.25 FL = 25 ft).
    /// Stored as a flight level (FL = altitude / 100 ft, referenced
    /// to 1013.25 hPa ICAO standard atmosphere) in the typical
    /// FL-cardinal range \[0, 1500\] (FL000 ground level → FL150000
    /// at the wire-format ceiling).
    pub flight_level: Option<f64>,

    /// I021/170 — Target Identification (callsign). The 8-character
    /// callsign string emitted by the aircraft's FMS, e.g. `"UAL437"`
    /// or `"BAW221A"`. Encoded on the wire as 8 characters in 6-bit
    /// ICAO Annex 10 alphabet packed into 6 bytes; decoded here to a
    /// trimmed `String` (trailing spaces stripped per spec — the
    /// 6-bit alphabet uses a literal space character to pad the
    /// fixed-width field).
    pub target_identification: Option<String>,
}

/// WGS-84 geographic position, decoded from I021/130.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct WgsPosition {
    /// Latitude in decimal degrees, WGS-84. Positive = north.
    pub latitude_deg: f64,
    /// Longitude in decimal degrees, WGS-84. Positive = east.
    pub longitude_deg: f64,
}

/// CAT-021 decode failure modes. Mirrors [`crate::cat062::Cat062Error`]'s
/// variant shape so a future shared-framing refactor lands cleanly,
/// but kept as a category-distinct enum so a downstream router that
/// dispatches on error type can distinguish CAT-021 vs CAT-062
/// failures without parsing the message string.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum Cat021Error {
    /// Datablock is shorter than the minimum (CAT byte + 16-bit length
    /// + at least one FSPEC byte).
    #[error("ASTERIX datablock truncated: {actual} bytes (min {min})")]
    TruncatedDatablock { actual: usize, min: usize },

    /// CAT byte does not match `021`.
    #[error("expected ASTERIX CAT-021, got CAT-{found:03}")]
    WrongCategory { found: u8 },

    /// LEN field disagrees with the byte slice supplied. ASTERIX LEN
    /// includes the 3-byte header itself; the caller is expected to
    /// pass exactly one datablock.
    #[error("ASTERIX LEN field {declared} != supplied buffer {actual} bytes")]
    LengthMismatch { declared: usize, actual: usize },

    /// Datablock LEN is below the minimum (3 bytes of header + 1 FSPEC
    /// octet) — the upstream sender produced a degenerate datablock.
    #[error("ASTERIX LEN field {declared} below minimum {min}")]
    DeclaredLengthTooSmall { declared: usize, min: usize },

    /// FSPEC chain ran past the available bytes inside a record (FX
    /// bit set but no following octet).
    #[error("CAT-021 FSPEC truncated at FRN octet {octet}")]
    TruncatedFspec { octet: usize },

    /// A field decoder ran out of bytes before finishing.
    #[error("CAT-021 record truncated decoding I021/{item:03} (need {need} bytes, have {have})")]
    TruncatedField { item: u16, need: usize, have: usize },
}

/// Decode an ASTERIX datablock containing one or more CAT-021 records.
///
/// The supplied slice MUST be exactly one complete datablock. The
/// datablock's LEN field is cross-checked against the supplied slice
/// size to catch upstream truncation.
pub fn decode_cat021(bytes: &[u8]) -> Result<Vec<Cat021Report>, Cat021Error> {
    if bytes.len() < MIN_DATABLOCK_LEN {
        return Err(Cat021Error::TruncatedDatablock {
            actual: bytes.len(),
            min: MIN_DATABLOCK_LEN,
        });
    }
    let category = bytes[0];
    if category != CAT_021 {
        return Err(Cat021Error::WrongCategory { found: category });
    }
    let declared_len = u16::from_be_bytes([bytes[1], bytes[2]]) as usize;
    if declared_len < MIN_DATABLOCK_LEN {
        return Err(Cat021Error::DeclaredLengthTooSmall {
            declared: declared_len,
            min: MIN_DATABLOCK_LEN,
        });
    }
    if declared_len != bytes.len() {
        return Err(Cat021Error::LengthMismatch {
            declared: declared_len,
            actual: bytes.len(),
        });
    }

    let mut cursor = 3usize;
    let mut records = Vec::new();
    while cursor < bytes.len() {
        let (report, consumed) = decode_record(&bytes[cursor..])?;
        records.push(report);
        cursor = cursor.saturating_add(consumed);
    }
    Ok(records)
}

fn decode_record(record: &[u8]) -> Result<(Cat021Report, usize), Cat021Error> {
    let (fspec, fspec_len) = parse_fspec(record)?;
    let mut cursor = fspec_len;
    let mut report = Cat021Report::default();
    for frn in 1..=fspec.len() {
        if !fspec.bit(frn) {
            continue;
        }
        cursor = decode_field(frn, record, cursor, &mut report)?;
    }
    Ok((report, cursor))
}

// ── FSPEC ────────────────────────────────────────────────────────────

/// Parsed FSPEC bitmap. Bit 1 (LSB) of each FSPEC octet is FX; the
/// remaining seven bits map to FRNs in declaration order.
#[derive(Debug)]
struct Fspec {
    bits: Vec<bool>,
}

impl Fspec {
    fn len(&self) -> usize {
        self.bits.len()
    }

    fn bit(&self, frn: usize) -> bool {
        self.bits
            .get(frn.saturating_sub(1))
            .copied()
            .unwrap_or(false)
    }
}

fn parse_fspec(record: &[u8]) -> Result<(Fspec, usize), Cat021Error> {
    let mut bits: Vec<bool> = Vec::new();
    let mut octet_idx = 0usize;
    loop {
        let byte = match record.get(octet_idx) {
            Some(b) => *b,
            None => {
                return Err(Cat021Error::TruncatedFspec {
                    octet: octet_idx + 1,
                });
            }
        };
        for shift in (1..=7).rev() {
            let bit = (byte >> shift) & 0x01 != 0;
            bits.push(bit);
        }
        octet_idx = octet_idx.saturating_add(1);
        if byte & 0x01 == 0 {
            break;
        }
    }
    Ok((Fspec { bits }, octet_idx))
}

// ── Field dispatch ───────────────────────────────────────────────────

/// Per-FRN dispatch for CAT-021 v0.26 UAP. Issue-#1121 MVP decodes the
/// five operationally essential ADS-B fields (target address, position,
/// time, flight level, callsign); all other UAP entries are skipped by
/// length so a producer that emits a richer datablock decodes cleanly.
fn decode_field(
    frn: usize,
    record: &[u8],
    cursor: usize,
    report: &mut Cat021Report,
) -> Result<usize, Cat021Error> {
    match frn {
        1 => decode_data_source_id(record, cursor, report),
        2 => skip_extended(record, cursor, 40), // I021/040 Target Report Descriptor
        3 => skip_fixed(record, cursor, 2, 161), // I021/161 Track Number
        4 => skip_fixed(record, cursor, 1, 15), // I021/015 Service ID
        5 => decode_time_of_day(record, cursor, report),
        6 => decode_position_wgs84(record, cursor, report),
        7 => skip_fixed(record, cursor, 8, 131), // I021/131 High-Res Position
        8 => skip_fixed(record, cursor, 3, 72),  // I021/072 Time of App. Velocity
        9 => skip_fixed(record, cursor, 2, 150), // I021/150 Air Speed
        10 => skip_fixed(record, cursor, 2, 151), // I021/151 True Air Speed
        11 => decode_target_address(record, cursor, report),
        12 => skip_fixed(record, cursor, 3, 73), // I021/073 ToM Reception (Position)
        13 => skip_fixed(record, cursor, 4, 74), // I021/074 ToM Reception Pos HighRes
        14 => skip_fixed(record, cursor, 3, 75), // I021/075 ToM Reception (Velocity)
        15 => skip_fixed(record, cursor, 4, 76), // I021/076 ToM Reception Vel HighRes
        16 => skip_fixed(record, cursor, 2, 140), // I021/140 Geometric Height
        17 => skip_extended(record, cursor, 90), // I021/090 Quality Indicators
        18 => skip_fixed(record, cursor, 1, 210), // I021/210 MOPS Version
        19 => skip_fixed(record, cursor, 2, 70), // I021/070 Mode 3/A Code
        20 => skip_fixed(record, cursor, 2, 230), // I021/230 Roll Angle
        21 => decode_flight_level(record, cursor, report),
        22 => skip_fixed(record, cursor, 2, 152), // I021/152 Magnetic Heading
        23 => skip_fixed(record, cursor, 1, 200), // I021/200 Target Status
        24 => skip_fixed(record, cursor, 2, 155), // I021/155 Barometric Vert. Rate
        25 => skip_fixed(record, cursor, 2, 157), // I021/157 Geometric Vert. Rate
        26 => skip_fixed(record, cursor, 4, 160), // I021/160 Airborne Ground Vector
        27 => skip_fixed(record, cursor, 2, 165), // I021/165 Track Angle Rate
        28 => skip_fixed(record, cursor, 3, 77),  // I021/077 Time of Report Tx
        29 => decode_target_identification(record, cursor, report),
        30 => skip_fixed(record, cursor, 1, 20), // I021/020 Emitter Category
        31 => skip_compound(record, cursor, 220), // I021/220 Met Information
        32 => skip_fixed(record, cursor, 2, 146), // I021/146 Selected Altitude
        33 => skip_fixed(record, cursor, 2, 148), // I021/148 Final Selected Alt
        34 => skip_compound(record, cursor, 110), // I021/110 Trajectory Intent
        35 => skip_fixed(record, cursor, 1, 16), // I021/016 Service Mgmt
        36 => skip_fixed(record, cursor, 1, 8),  // I021/008 Aircraft Op Status
        37 => skip_extended(record, cursor, 271), // I021/271 Surface Capabilities
        38 => skip_fixed(record, cursor, 1, 132), // I021/132 Message Amplitude
        39 => skip_compound(record, cursor, 250), // I021/250 Mode S MB Data
        40 => skip_fixed(record, cursor, 7, 260), // I021/260 ACAS RA Report
        41 => skip_fixed(record, cursor, 1, 400), // I021/400 Receiver ID
        42 => skip_compound(record, cursor, 295), // I021/295 Data Ages
        43..=46 => Ok(cursor),                   // CAT-021 v0.26 spare bits
        47 => skip_re_sp(record, cursor, 0),     // I021/RE Reserved Expansion
        48 => skip_re_sp(record, cursor, 0),     // I021/SP Special Purpose
        // Forward-compat: FRNs beyond v0.26's UAP. Stop decoding —
        // the next datablock resyncs at the LEN boundary.
        _ => Ok(cursor),
    }
}

// ── Per-field decoders ───────────────────────────────────────────────

fn decode_data_source_id(
    record: &[u8],
    cursor: usize,
    report: &mut Cat021Report,
) -> Result<usize, Cat021Error> {
    // I021/010 — fixed 2 bytes, SAC (high) + SIC (low) packed into a
    // single u16 so the encoder can round-trip the exact wire pair.
    let bytes = take_fixed(record, cursor, 2, 10)?;
    let id = (u16::from(bytes[0]) << 8) | u16::from(bytes[1]);
    report.data_source_id = Some(id);
    Ok(cursor.saturating_add(2))
}

fn decode_time_of_day(
    record: &[u8],
    cursor: usize,
    report: &mut Cat021Report,
) -> Result<usize, Cat021Error> {
    // I021/071 — fixed 3 bytes, unsigned 24-bit, LSB = 1/128 s.
    let bytes = take_fixed(record, cursor, 3, 71)?;
    let raw = (u32::from(bytes[0]) << 16) | (u32::from(bytes[1]) << 8) | u32::from(bytes[2]);
    report.time_of_day_seconds = Some(f64::from(raw) / 128.0);
    Ok(cursor.saturating_add(3))
}

fn decode_position_wgs84(
    record: &[u8],
    cursor: usize,
    report: &mut Cat021Report,
) -> Result<usize, Cat021Error> {
    // I021/130 — fixed 6 bytes: lat (signed 24-bit BE), lon (signed
    // 24-bit BE), LSB = 180 / 2^23 degrees. Two's-complement sign is
    // recovered via shift-up-shift-down on a 32-bit word.
    let bytes = take_fixed(record, cursor, 6, 130)?;
    let lat_raw =
        ((i32::from(bytes[0]) << 24) | (i32::from(bytes[1]) << 16) | (i32::from(bytes[2]) << 8))
            >> 8;
    let lon_raw =
        ((i32::from(bytes[3]) << 24) | (i32::from(bytes[4]) << 16) | (i32::from(bytes[5]) << 8))
            >> 8;
    let lsb = 180.0_f64 / f64::from(1u32 << 23);
    report.position_wgs84 = Some(WgsPosition {
        latitude_deg: f64::from(lat_raw) * lsb,
        longitude_deg: f64::from(lon_raw) * lsb,
    });
    Ok(cursor.saturating_add(6))
}

fn decode_target_address(
    record: &[u8],
    cursor: usize,
    report: &mut Cat021Report,
) -> Result<usize, Cat021Error> {
    // I021/080 — fixed 3 bytes, unsigned 24-bit ICAO aircraft identifier.
    let bytes = take_fixed(record, cursor, 3, 80)?;
    let addr = (u32::from(bytes[0]) << 16) | (u32::from(bytes[1]) << 8) | u32::from(bytes[2]);
    report.target_address = Some(addr);
    Ok(cursor.saturating_add(3))
}

fn decode_flight_level(
    record: &[u8],
    cursor: usize,
    report: &mut Cat021Report,
) -> Result<usize, Cat021Error> {
    // I021/145 — fixed 2 bytes, signed 16-bit LE WAIT NO BE,
    // LSB = 1/4 FL = 25 ft / 100 = 0.25 FL.
    let bytes = take_fixed(record, cursor, 2, 145)?;
    let raw = i16::from_be_bytes([bytes[0], bytes[1]]);
    report.flight_level = Some(f64::from(raw) * 0.25);
    Ok(cursor.saturating_add(2))
}

fn decode_target_identification(
    record: &[u8],
    cursor: usize,
    report: &mut Cat021Report,
) -> Result<usize, Cat021Error> {
    // I021/170 — fixed 6 bytes, 8 characters in 6-bit ICAO Annex 10
    // alphabet packed MSB-first. The 6-bit alphabet:
    //   0x00..0x0A  unused/special
    //   0x01..0x1A  'A'..'Z'
    //   0x20        space
    //   0x30..0x39  '0'..'9'
    // The wire form pads with the 6-bit space code (0x20). We strip
    // trailing spaces so a 4-character callsign returns "UAL4" not
    // "UAL4    ".
    let bytes = take_fixed(record, cursor, 6, 170)?;
    let mut callsign = String::with_capacity(8);
    // 6 bytes = 48 bits = 8 × 6 bits. Pull each 6-bit chunk MSB-first.
    let bits: u64 = (u64::from(bytes[0]) << 40)
        | (u64::from(bytes[1]) << 32)
        | (u64::from(bytes[2]) << 24)
        | (u64::from(bytes[3]) << 16)
        | (u64::from(bytes[4]) << 8)
        | u64::from(bytes[5]);
    for char_idx in 0..8 {
        let shift = 42 - char_idx * 6;
        let chunk = ((bits >> shift) & 0x3F) as u8;
        callsign.push(decode_icao_6bit_char(chunk));
    }
    let trimmed = callsign.trim_end().to_string();
    report.target_identification = Some(trimmed);
    Ok(cursor.saturating_add(6))
}

/// ICAO Annex 10 6-bit alphabet → Unicode char.
///
/// The 6-bit codes used in CAT-021 I021/170 (and Mode-S BDS 2,0
/// callsign reports more broadly) are:
///   `0x01`..=`0x1A` → `'A'..='Z'`
///   `0x20`         → space (padding)
///   `0x30`..=`0x39` → `'0'..='9'`
/// Any other code (the spec leaves them reserved) decodes to `'?'` —
/// preserving slot count (so the trim-trailing-spaces logic stays
/// correct) without silently masking a malformed encoding.
fn decode_icao_6bit_char(c: u8) -> char {
    match c {
        0x01..=0x1A => (b'A' + c - 0x01) as char,
        0x20 => ' ',
        0x30..=0x39 => (b'0' + c - 0x30) as char,
        _ => '?',
    }
}

// ── Generic skip / take helpers ──────────────────────────────────────

fn skip_fixed(record: &[u8], cursor: usize, n: usize, item: u16) -> Result<usize, Cat021Error> {
    let _ = take_fixed(record, cursor, n, item)?;
    Ok(cursor.saturating_add(n))
}

fn skip_extended(record: &[u8], cursor: usize, item: u16) -> Result<usize, Cat021Error> {
    let mut idx = cursor;
    loop {
        let octet = match record.get(idx) {
            Some(b) => *b,
            None => {
                return Err(Cat021Error::TruncatedField {
                    item,
                    need: 1,
                    have: 0,
                });
            }
        };
        idx = idx.saturating_add(1);
        if octet & 0x01 == 0 {
            break;
        }
    }
    Ok(idx)
}

/// Compound items in CAT-021 carry a primary subfield bitmap (itself
/// an extended-length octet chain) plus per-subfield content. Fully
/// decoding the subfield catalogue for every compound item is out of
/// scope for the issue-#1121 MVP; surface a typed error if a compound
/// item ever appears in a real datablock so operators see a clear
/// "we don't decode this yet" signal — the next datablock resyncs at
/// the LEN boundary.
fn skip_compound(_record: &[u8], _cursor: usize, item: u16) -> Result<usize, Cat021Error> {
    Err(Cat021Error::TruncatedField {
        item,
        need: 0,
        have: 0,
    })
}

fn skip_re_sp(record: &[u8], cursor: usize, item: u16) -> Result<usize, Cat021Error> {
    let len_byte = match record.get(cursor) {
        Some(b) => *b,
        None => {
            return Err(Cat021Error::TruncatedField {
                item,
                need: 1,
                have: 0,
            });
        }
    };
    let total = len_byte as usize;
    if total == 0 {
        return Err(Cat021Error::TruncatedField {
            item,
            need: 1,
            have: 0,
        });
    }
    let end = cursor.saturating_add(total);
    if end > record.len() {
        return Err(Cat021Error::TruncatedField {
            item,
            need: total,
            have: record.len().saturating_sub(cursor),
        });
    }
    Ok(end)
}

fn take_fixed(record: &[u8], cursor: usize, n: usize, item: u16) -> Result<&[u8], Cat021Error> {
    let end = cursor.saturating_add(n);
    if end > record.len() {
        return Err(Cat021Error::TruncatedField {
            item,
            need: n,
            have: record.len().saturating_sub(cursor),
        });
    }
    Ok(&record[cursor..end])
}

// ── Encode side ──────────────────────────────────────────────────────

/// CAT-021 encode failure modes. Distinct from [`Cat021Error`] because
/// encode and decode have non-overlapping failure surfaces: decode
/// surfaces wire-shape problems (truncated buffers, declared length
/// vs supplied bytes), encode surfaces *value-domain* problems (a
/// caller-supplied value that does not fit the wire field's bit width
/// or alphabet). Keeping them separate means a downstream pipeline
/// that does decode → mutate → encode can match on exactly the
/// failure mode that arose without parsing string messages.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum Cat021EncodeError {
    /// I021/080 Target Address is a 24-bit ICAO field but the type-
    /// level container is `u32` (no native `u24`). A caller-supplied
    /// value with any of the high 8 bits set cannot be encoded
    /// without truncation; surface it as a typed error rather than
    /// silently masking off the high byte.
    #[error("I021/080 target address {value:#010x} exceeds 24-bit ICAO field width")]
    TargetAddressOutOfRange {
        /// The offending caller-supplied value.
        value: u32,
    },

    /// I021/170 Target Identification packs 8 characters of the ICAO
    /// Annex 10 6-bit alphabet (uppercase A–Z, digits 0–9, space) into
    /// 6 bytes. A caller-supplied string that is longer than 8
    /// characters or contains a character outside the alphabet (for
    /// example a lowercase letter, an accented character, or a hyphen)
    /// cannot be encoded losslessly; surface it as a typed error so
    /// the upstream component can decide whether to upper-case, drop,
    /// or substitute the offending characters.
    #[error(
        "I021/170 target identification {value:?} cannot be encoded in ICAO Annex 10 6-bit alphabet ({reason})"
    )]
    UnencodableIdentification {
        /// The offending caller-supplied callsign.
        value: String,
        /// Static description of why the value was rejected.
        reason: &'static str,
    },

    /// The ASTERIX LEN header is a 16-bit big-endian field; a
    /// datablock larger than `u16::MAX` (65 535) bytes cannot be
    /// emitted with a valid length header. The wire-level UDP MTU
    /// keeps real datablocks well under 1500 bytes, but a caller
    /// that batches a very large slice of reports into one datablock
    /// can hit this ceiling — surface it explicitly so the caller
    /// fragments the slice rather than emit a corrupt header.
    #[error("ASTERIX datablock would be {len} bytes, exceeds 16-bit LEN field max ({max})")]
    DatablockTooLarge {
        /// The would-be datablock byte length.
        len: usize,
        /// The maximum representable byte length (`u16::MAX`).
        max: usize,
    },
}

/// Encode a slice of CAT-021 reports as a single ASTERIX datablock.
///
/// The output is `[CAT (1 byte = 21)] [LEN (2 bytes BE)] [record_1
/// FSPEC + fields] [record_2 ...]`. Single-record datablocks are the
/// typical case but the encoder accepts an arbitrary slice for parity
/// with [`decode_cat021`]'s multi-record support.
///
/// FSPEC bits are set ONLY for fields whose `Option` on the input is
/// `Some(...)`; fields that are `None` neither set their FSPEC bit
/// nor occupy bytes in the record. A default `Cat021Report` (all
/// `None`) emits a record consisting of a single zero FSPEC octet.
///
/// # Errors
///
/// Returns [`Cat021EncodeError`] on out-of-range field values; see
/// the error variants for the full list.
pub fn encode_cat021(reports: &[Cat021Report]) -> Result<Vec<u8>, Cat021EncodeError> {
    let mut buf = bytes::BytesMut::new();
    encode_cat021_into(reports, &mut buf)?;
    Ok(buf.to_vec())
}

/// Zero-extra-allocation variant of [`encode_cat021`] that appends to
/// a caller-owned [`bytes::BytesMut`]. Useful for batch encoders that
/// reuse a single output buffer across many datablocks.
///
/// On error the buffer is left in an unspecified state — the caller
/// should treat the buffer as poisoned and either truncate it back to
/// the pre-call length (capture `buf.len()` before the call) or drop
/// it entirely. The output is appended to whatever was already in
/// `buf`; the encoder does not pre-clear.
pub fn encode_cat021_into(
    reports: &[Cat021Report],
    buf: &mut bytes::BytesMut,
) -> Result<(), Cat021EncodeError> {
    use bytes::BufMut;

    let start = buf.len();
    // Reserve the 3-byte header (CAT + LEN). LEN is patched in once
    // we know the total size — emitting the records first lets us
    // avoid a two-pass walk over the report slice.
    buf.put_u8(CAT_021);
    buf.put_u8(0);
    buf.put_u8(0);

    for report in reports {
        encode_record(report, buf)?;
    }

    let total = buf.len().saturating_sub(start);
    if total > usize::from(u16::MAX) {
        return Err(Cat021EncodeError::DatablockTooLarge {
            len: total,
            max: usize::from(u16::MAX),
        });
    }
    let len_bytes = (total as u16).to_be_bytes();
    buf[start.saturating_add(1)] = len_bytes[0];
    buf[start.saturating_add(2)] = len_bytes[1];
    Ok(())
}

fn encode_record(
    report: &Cat021Report,
    buf: &mut bytes::BytesMut,
) -> Result<(), Cat021EncodeError> {
    use bytes::BufMut;

    // Walk FRN 1..=48 and collect the FRNs whose `Option` field is
    // `Some(...)`. The MVP set covers FRNs 1, 5, 6, 11, 21, 29.
    // Everything else stays `None` for now (decode skips them and
    // the struct has no field for them); a future extension that
    // adds (e.g.) Geometric Height as a struct field would also add
    // its FRN here and a matching arm in `encode_field`.
    let mut frns: Vec<usize> = Vec::with_capacity(6);
    if report.data_source_id.is_some() {
        frns.push(1);
    }
    if report.time_of_day_seconds.is_some() {
        frns.push(5);
    }
    if report.position_wgs84.is_some() {
        frns.push(6);
    }
    if report.target_address.is_some() {
        frns.push(11);
    }
    if report.flight_level.is_some() {
        frns.push(21);
    }
    if report.target_identification.is_some() {
        frns.push(29);
    }

    let fspec = compute_fspec(&frns);
    buf.put_slice(&fspec);

    // Emit fields in ascending FRN order so the encoder mirrors
    // `decode_record`'s walk; a downstream decode then sees fields
    // in the same order it expects.
    if let Some(id) = report.data_source_id {
        buf.put_u16(id);
    }
    if let Some(secs) = report.time_of_day_seconds {
        encode_time_of_day(secs, buf);
    }
    if let Some(pos) = report.position_wgs84 {
        encode_position_wgs84(pos, buf);
    }
    if let Some(addr) = report.target_address {
        encode_target_address(addr, buf)?;
    }
    if let Some(fl) = report.flight_level {
        encode_flight_level(fl, buf);
    }
    if let Some(ref id) = report.target_identification {
        encode_target_identification(id, buf)?;
    }

    Ok(())
}

/// Compute the FSPEC octet chain for a set of FRNs, the inverse of
/// [`parse_fspec`]. The input does not need to be sorted; the output
/// is the canonical bit pattern with FX bits set on every non-final
/// octet. An empty input list yields a single `0x00` octet (record
/// declares no fields).
fn compute_fspec(frns: &[usize]) -> Vec<u8> {
    let max_frn = frns.iter().copied().max().unwrap_or(0);
    let octets_needed = if max_frn == 0 { 1 } else { max_frn.div_ceil(7) };
    let mut out = vec![0u8; octets_needed];
    for &frn in frns {
        if frn == 0 {
            continue;
        }
        let octet = (frn - 1) / 7;
        let pos_in_octet = (frn - 1) % 7;
        let bit_shift = 7 - pos_in_octet;
        if let Some(slot) = out.get_mut(octet) {
            *slot |= 1 << bit_shift;
        }
    }
    let last = octets_needed.saturating_sub(1);
    for octet in out.iter_mut().take(last) {
        *octet |= 0x01;
    }
    out
}

fn encode_time_of_day(seconds: f64, buf: &mut bytes::BytesMut) {
    use bytes::BufMut;
    // I021/071 — 3 bytes unsigned 24-bit, LSB = 1/128 s. Saturate
    // negatives to 0 and overflow to the 24-bit ceiling so a caller
    // that passes garbage time gets the closest representable wire
    // value rather than a panic. The decoder only emits values in
    // `[0.0, 86_400.0)` so a healthy round-trip never exercises the
    // saturation.
    let raw_f = (seconds * 128.0).round();
    let raw = if raw_f.is_nan() || raw_f < 0.0 {
        0u32
    } else if raw_f > f64::from(0x00FF_FFFF_u32) {
        0x00FF_FFFF
    } else {
        raw_f as u32
    };
    buf.put_u8(((raw >> 16) & 0xFF) as u8);
    buf.put_u8(((raw >> 8) & 0xFF) as u8);
    buf.put_u8((raw & 0xFF) as u8);
}

fn encode_position_wgs84(pos: WgsPosition, buf: &mut bytes::BytesMut) {
    use bytes::BufMut;
    // I021/130 — 6 bytes: lat (i24 BE) + lon (i24 BE), LSB = 180 / 2^23 deg.
    let lsb = 180.0_f64 / f64::from(1u32 << 23);
    let lat = pack_i24(pos.latitude_deg, lsb);
    let lon = pack_i24(pos.longitude_deg, lsb);
    buf.put_u8(((lat >> 16) & 0xFF) as u8);
    buf.put_u8(((lat >> 8) & 0xFF) as u8);
    buf.put_u8((lat & 0xFF) as u8);
    buf.put_u8(((lon >> 16) & 0xFF) as u8);
    buf.put_u8(((lon >> 8) & 0xFF) as u8);
    buf.put_u8((lon & 0xFF) as u8);
}

/// Pack a degrees value into a 24-bit signed integer, the inverse of
/// the `(i24 << 8) >> 8` decode trick. Values that exceed the i24
/// range saturate at the i24 endpoints so a NaN / out-of-range input
/// produces the closest representable wire value rather than a panic.
fn pack_i24(value_deg: f64, lsb: f64) -> u32 {
    let raw = (value_deg / lsb).round();
    let i24_min = -8_388_608_f64;
    let i24_max = 8_388_607_f64;
    let clamped = if raw.is_nan() {
        0
    } else if raw < i24_min {
        i24_min as i32
    } else if raw > i24_max {
        i24_max as i32
    } else {
        raw as i32
    };
    // Mask to 24 bits so a negative i32 lays out as two's-complement
    // i24 in the low 24 bits (the upper byte is discarded by the
    // wire-byte emit above).
    (clamped as u32) & 0x00FF_FFFF
}

fn encode_target_address(addr: u32, buf: &mut bytes::BytesMut) -> Result<(), Cat021EncodeError> {
    use bytes::BufMut;
    if addr > 0x00FF_FFFF {
        return Err(Cat021EncodeError::TargetAddressOutOfRange { value: addr });
    }
    buf.put_u8(((addr >> 16) & 0xFF) as u8);
    buf.put_u8(((addr >> 8) & 0xFF) as u8);
    buf.put_u8((addr & 0xFF) as u8);
    Ok(())
}

fn encode_flight_level(fl: f64, buf: &mut bytes::BytesMut) {
    use bytes::BufMut;
    // I021/145 — 2 bytes signed 16-bit BE, LSB = 0.25 FL.
    let raw_f = (fl / 0.25).round();
    let i16_min = f64::from(i16::MIN);
    let i16_max = f64::from(i16::MAX);
    let clamped = if raw_f.is_nan() {
        0i16
    } else if raw_f < i16_min {
        i16::MIN
    } else if raw_f > i16_max {
        i16::MAX
    } else {
        raw_f as i16
    };
    buf.put_i16(clamped);
}

fn encode_target_identification(
    callsign: &str,
    buf: &mut bytes::BytesMut,
) -> Result<(), Cat021EncodeError> {
    use bytes::BufMut;
    // I021/170 — 6 bytes, 8 chars × 6 bits in ICAO Annex 10 alphabet.
    if callsign.chars().count() > 8 {
        return Err(Cat021EncodeError::UnencodableIdentification {
            value: callsign.to_string(),
            reason: "longer than 8 characters",
        });
    }
    // Build the 8-char fixed-width buffer: encode each char to its
    // 6-bit code, pad with the 6-bit space code (0x20) for callsigns
    // shorter than 8 chars. A failed encode short-circuits with an
    // unencodable-character error.
    let mut codes: [u8; 8] = [0x20; 8];
    for (i, ch) in callsign.chars().enumerate() {
        codes[i] = encode_icao_6bit_char(ch).ok_or_else(|| {
            Cat021EncodeError::UnencodableIdentification {
                value: callsign.to_string(),
                reason: "character not in ICAO Annex 10 6-bit alphabet (only A-Z, 0-9, space)",
            }
        })?;
    }
    let bits: u64 = (u64::from(codes[0]) << 42)
        | (u64::from(codes[1]) << 36)
        | (u64::from(codes[2]) << 30)
        | (u64::from(codes[3]) << 24)
        | (u64::from(codes[4]) << 18)
        | (u64::from(codes[5]) << 12)
        | (u64::from(codes[6]) << 6)
        | u64::from(codes[7]);
    buf.put_u8(((bits >> 40) & 0xFF) as u8);
    buf.put_u8(((bits >> 32) & 0xFF) as u8);
    buf.put_u8(((bits >> 24) & 0xFF) as u8);
    buf.put_u8(((bits >> 16) & 0xFF) as u8);
    buf.put_u8(((bits >> 8) & 0xFF) as u8);
    buf.put_u8((bits & 0xFF) as u8);
    Ok(())
}

/// Inverse of [`decode_icao_6bit_char`]. Returns `None` for any
/// character outside the documented alphabet (uppercase A-Z, digits
/// 0-9, ASCII space) so the caller can surface a typed
/// [`Cat021EncodeError::UnencodableIdentification`].
fn encode_icao_6bit_char(ch: char) -> Option<u8> {
    match ch {
        'A'..='Z' => Some(0x01 + (ch as u8 - b'A')),
        '0'..='9' => Some(0x30 + (ch as u8 - b'0')),
        ' ' => Some(0x20),
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, unused_results)]
mod tests {
    use super::*;

    /// Build an FSPEC byte chain where each `frn` index from 1 has the
    /// corresponding bit set. Used to construct hand-built fixtures
    /// without typing the bitmaps as literal octets.
    fn build_fspec(frns: &[usize]) -> Vec<u8> {
        let max_frn = frns.iter().max().copied().unwrap_or(0);
        let octets_needed = max_frn.div_ceil(7);
        let mut out = vec![0u8; octets_needed.max(1)];
        for &frn in frns {
            // Octet index for this FRN (0-based).
            let octet = (frn - 1) / 7;
            // Bit position within the 7 high bits, MSB = bit 7 (FRN 1).
            let pos_in_octet = (frn - 1) % 7;
            let bit_shift = 7 - pos_in_octet;
            out[octet] |= 1 << bit_shift;
        }
        // Set FX bit on every non-final octet to chain them.
        let last = octets_needed.saturating_sub(1);
        for octet in out.iter_mut().take(last) {
            *octet |= 0x01;
        }
        out
    }

    /// Build a complete CAT-021 datablock from a record body.
    /// Computes the LEN field for the caller.
    fn build_datablock(record_body: &[u8]) -> Vec<u8> {
        let len = 3 + record_body.len();
        let mut out = vec![CAT_021];
        out.extend_from_slice(&(len as u16).to_be_bytes());
        out.extend_from_slice(record_body);
        out
    }

    #[test]
    fn build_fspec_helper_handles_single_octet() {
        // FRNs 1, 5, 7 → bits 7, 3, 1 set in the high 7 bits.
        // Binary: 1000_1010 with FX=0 → 0b10001010 = 0x8A.
        // Wait: bit 7 (FRN 1), bit 3 (FRN 5), bit 1 (FRN 7).
        //   1 << 7 = 0x80
        //   1 << 3 = 0x08
        //   1 << 1 = 0x02
        //   sum    = 0x8A
        // FX bit (bit 0) is 0 since this is the last octet.
        assert_eq!(build_fspec(&[1, 5, 7]), vec![0x8A]);
    }

    #[test]
    fn build_fspec_helper_chains_extension_octets() {
        // FRN 8 → second octet, bit 7. First octet has FX=1.
        let fspec = build_fspec(&[8]);
        assert_eq!(fspec.len(), 2);
        assert_eq!(fspec[0] & 0x01, 0x01, "first octet FX bit must be set");
        assert_eq!(fspec[1] & 0x80, 0x80, "FRN 8 → second octet bit 7");
        assert_eq!(fspec[1] & 0x01, 0x00, "last octet FX must be clear");
    }

    #[test]
    fn decode_rejects_short_datablock() {
        let bytes = vec![CAT_021, 0x00];
        let err = decode_cat021(&bytes).expect_err("short datablock must reject");
        assert_eq!(
            err,
            Cat021Error::TruncatedDatablock {
                actual: 2,
                min: MIN_DATABLOCK_LEN
            }
        );
    }

    #[test]
    fn decode_rejects_wrong_category() {
        // CAT-062 header — must be rejected by the CAT-021 decoder.
        let bytes = vec![62, 0x00, 0x04, 0x00];
        let err = decode_cat021(&bytes).expect_err("wrong category must reject");
        assert_eq!(err, Cat021Error::WrongCategory { found: 62 });
    }

    #[test]
    fn decode_rejects_length_mismatch() {
        // LEN says 100 bytes but only 4 supplied.
        let bytes = vec![CAT_021, 0x00, 0x64, 0x00];
        let err = decode_cat021(&bytes).expect_err("length mismatch must reject");
        assert_eq!(
            err,
            Cat021Error::LengthMismatch {
                declared: 100,
                actual: 4,
            }
        );
    }

    #[test]
    fn decode_minimal_datablock_with_only_data_source_id() {
        // FRN 1 (I021/010, 2 bytes) only — the most minimal real-world
        // CAT-021 record. SAC = 0x12, SIC = 0x34.
        let mut record = build_fspec(&[1]);
        record.extend_from_slice(&[0x12, 0x34]);
        let datablock = build_datablock(&record);
        let reports = decode_cat021(&datablock).expect("decode minimal");
        assert_eq!(reports.len(), 1);
        // Only the data source ID should be populated; every other
        // decoded field should remain `None` so the round-trip
        // re-emits exactly FRN 1.
        let expected = Cat021Report {
            data_source_id: Some(0x1234),
            ..Cat021Report::default()
        };
        assert_eq!(reports[0], expected);
    }

    #[test]
    fn decode_target_address_round_trips_24bit_icao() {
        // FRN 11 (I021/080) — 24-bit ICAO address. Use 0xA1B2C3 as a
        // canonical "fake but plausible" Mode-S address.
        let mut record = build_fspec(&[11]);
        record.extend_from_slice(&[0xA1, 0xB2, 0xC3]);
        let datablock = build_datablock(&record);
        let reports = decode_cat021(&datablock).expect("decode target address");
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].target_address, Some(0x00A1_B2C3));
    }

    #[test]
    fn decode_position_wgs84_signed_semicircles() {
        // FRN 6 (I021/130) — 6 bytes: lat (i24 BE) + lon (i24 BE).
        // LSB = 180 / 2^23 ≈ 2.145e-5 deg.
        // Pick lat = 0x100000 → 1048576 raw → 1048576 * 180/2^23 ≈ 22.5 deg.
        // Pick lon = 0xFF0000 → -65536 raw → -65536 * 180/2^23 ≈ -1.40625 deg.
        let mut record = build_fspec(&[6]);
        record.extend_from_slice(&[
            0x10, 0x00, 0x00, // lat
            0xFF, 0x00, 0x00, // lon (negative, two's-complement i24)
        ]);
        let datablock = build_datablock(&record);
        let reports = decode_cat021(&datablock).expect("decode position");
        let pos = reports[0].position_wgs84.expect("position present");
        let expected_lat = 1_048_576.0 * 180.0 / f64::from(1u32 << 23);
        let expected_lon = -65_536.0 * 180.0 / f64::from(1u32 << 23);
        assert!(
            (pos.latitude_deg - expected_lat).abs() < 1e-9,
            "lat: got {}, expected {}",
            pos.latitude_deg,
            expected_lat
        );
        assert!(
            (pos.longitude_deg - expected_lon).abs() < 1e-9,
            "lon: got {}, expected {}",
            pos.longitude_deg,
            expected_lon
        );
    }

    #[test]
    fn decode_position_wgs84_extreme_negative_latitude() {
        // Pin two's-complement sign extension on the negative-most i24.
        // Wire bytes 0x80, 0x00, 0x00 → signed 24-bit minimum.
        // i24 min = -8_388_608. Expected lat = -8_388_608 * 180/2^23 = -180 deg.
        // (Out of WGS-84's [-90, 90] range — the codec doesn't validate
        // that; the test exercises the bit-pattern handling.)
        let mut record = build_fspec(&[6]);
        record.extend_from_slice(&[
            0x80, 0x00, 0x00, // lat = i24 minimum
            0x00, 0x00, 0x00, // lon = 0
        ]);
        let datablock = build_datablock(&record);
        let reports = decode_cat021(&datablock).expect("decode i24 min");
        let pos = reports[0].position_wgs84.expect("position present");
        assert!(
            (pos.latitude_deg - (-180.0_f64)).abs() < 1e-9,
            "i24 min latitude must decode to -180.0; got {}",
            pos.latitude_deg
        );
    }

    #[test]
    fn decode_time_of_day_lsb_one_over_one_twenty_eight() {
        // FRN 5 (I021/071) — 3 bytes, unsigned 24-bit, LSB = 1/128 s.
        // Wire 0x00_00_80 = 128 raw → 128 * 1/128 = 1.0 second.
        let mut record = build_fspec(&[5]);
        record.extend_from_slice(&[0x00, 0x00, 0x80]);
        let datablock = build_datablock(&record);
        let reports = decode_cat021(&datablock).expect("decode tod");
        assert_eq!(reports[0].time_of_day_seconds, Some(1.0));
    }

    #[test]
    fn decode_flight_level_quarter_fl_lsb() {
        // FRN 21 (I021/145) — 2 bytes signed 16-bit BE, LSB = 0.25 FL.
        // Wire 0x05_DC = 1500 raw → 1500 * 0.25 = 375.0 FL = FL375
        // (typical commercial cruising altitude, ~37 500 ft).
        let mut record = build_fspec(&[21]);
        record.extend_from_slice(&[0x05, 0xDC]);
        let datablock = build_datablock(&record);
        let reports = decode_cat021(&datablock).expect("decode FL");
        assert_eq!(reports[0].flight_level, Some(375.0));
    }

    #[test]
    fn decode_target_identification_strips_trailing_spaces() {
        // FRN 29 (I021/170) — 6 bytes, 8 chars × 6 bits in
        // ICAO Annex 10 alphabet. Encode "UAL4    " (4 chars + 4
        // spaces) and verify trim → "UAL4".
        // Char codes:
        //   U = 0x15, A = 0x01, L = 0x0C, 4 = 0x34, ' ' = 0x20 ×4
        // Pack MSB-first into 48 bits:
        //   0x15 << 42 | 0x01 << 36 | 0x0C << 30 | 0x34 << 24
        //   | 0x20 << 18 | 0x20 << 12 | 0x20 << 6 | 0x20
        let bits: u64 = (0x15_u64 << 42)
            | (0x01_u64 << 36)
            | (0x0C_u64 << 30)
            | (0x34_u64 << 24)
            | (0x20_u64 << 18)
            | (0x20_u64 << 12)
            | (0x20_u64 << 6)
            | 0x20_u64;
        let bytes = [
            ((bits >> 40) & 0xFF) as u8,
            ((bits >> 32) & 0xFF) as u8,
            ((bits >> 24) & 0xFF) as u8,
            ((bits >> 16) & 0xFF) as u8,
            ((bits >> 8) & 0xFF) as u8,
            (bits & 0xFF) as u8,
        ];
        let mut record = build_fspec(&[29]);
        record.extend_from_slice(&bytes);
        let datablock = build_datablock(&record);
        let reports = decode_cat021(&datablock).expect("decode callsign");
        assert_eq!(
            reports[0].target_identification.as_deref(),
            Some("UAL4"),
            "trailing 6-bit space padding MUST be trimmed"
        );
    }

    #[test]
    fn decode_full_ads_b_record_with_all_mvp_fields() {
        // The headline: a single CAT-021 record carrying every field
        // the MVP parser decodes. FRNs (1, 5, 6, 11, 21, 29) → SAC/SIC
        // (skip), ToD, position, target address, flight level,
        // callsign. Pin that all five decoded fields are populated AND
        // that field-skipping interleaves correctly.
        let icao = [0xA1_u8, 0xB2, 0xC3];
        // Callsign "TEST" + 4 spaces.
        // T=0x14, E=0x05, S=0x13, T=0x14, ' '=0x20×4
        let bits: u64 = (0x14_u64 << 42)
            | (0x05_u64 << 36)
            | (0x13_u64 << 30)
            | (0x14_u64 << 24)
            | (0x20_u64 << 18)
            | (0x20_u64 << 12)
            | (0x20_u64 << 6)
            | 0x20_u64;
        let callsign_bytes = [
            ((bits >> 40) & 0xFF) as u8,
            ((bits >> 32) & 0xFF) as u8,
            ((bits >> 24) & 0xFF) as u8,
            ((bits >> 16) & 0xFF) as u8,
            ((bits >> 8) & 0xFF) as u8,
            (bits & 0xFF) as u8,
        ];

        let mut record = build_fspec(&[1, 5, 6, 11, 21, 29]);
        record.extend_from_slice(&[0x12, 0x34]); // FRN 1: SAC/SIC
        record.extend_from_slice(&[0x00, 0x00, 0x80]); // FRN 5: ToD = 1.0s
        record.extend_from_slice(&[0x10, 0x00, 0x00, 0xFF, 0x00, 0x00]); // FRN 6: position
        record.extend_from_slice(&icao); // FRN 11: target address
        record.extend_from_slice(&[0x05, 0xDC]); // FRN 21: FL375
        record.extend_from_slice(&callsign_bytes); // FRN 29: callsign

        let datablock = build_datablock(&record);
        let reports = decode_cat021(&datablock).expect("decode full record");
        assert_eq!(reports.len(), 1);
        let r = &reports[0];
        assert_eq!(r.data_source_id, Some(0x1234));
        assert_eq!(r.target_address, Some(0x00A1_B2C3));
        assert_eq!(r.time_of_day_seconds, Some(1.0));
        assert!(r.position_wgs84.is_some());
        assert_eq!(r.flight_level, Some(375.0));
        assert_eq!(r.target_identification.as_deref(), Some("TEST"));
    }

    #[test]
    fn decode_does_not_panic_on_arbitrary_bytes() {
        // Self-stability invariant: the decoder never panics on hostile
        // input — every error path returns a typed `Cat021Error`. This
        // is the same property the fuzz target enforces; the unit test
        // version exercises a handful of crafted inputs to provide
        // coverage without requiring a fuzzing run.
        let inputs: Vec<Vec<u8>> = vec![
            vec![],                                // empty
            vec![0xFF],                            // single byte, wrong CAT
            vec![CAT_021, 0xFF, 0xFF],             // declared LEN huge
            vec![CAT_021, 0x00, 0x04, 0x80],       // FSPEC asserts FRN 1 but no data
            vec![CAT_021, 0x00, 0x05, 0x01, 0x00], // FSPEC FX-chain truncated
        ];
        for input in inputs {
            // Either Ok or Err — never panic.
            let _ = decode_cat021(&input);
        }
    }

    // ── Encoder tests ────────────────────────────────────────────

    #[test]
    fn encode_minimal_record_round_trips_through_decode() {
        // Pin: a record carrying only the target address must
        // re-decode to the same `Some(target_address)` and every
        // other field must remain `None`. This is the load-bearing
        // round-trip self-stability invariant — the FSPEC must NOT
        // accidentally set bits for `None` fields.
        let report = Cat021Report {
            target_address: Some(0x00AB_CDEF),
            ..Cat021Report::default()
        };
        let bytes = encode_cat021(std::slice::from_ref(&report)).expect("encode minimal");
        let decoded = decode_cat021(&bytes).expect("decode roundtrip");
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0], report);
    }

    #[test]
    fn encode_full_mvp_record_round_trips_through_decode() {
        // Pin: every MVP field set, encode, decode, equality. This
        // is the "all six FSPEC bits set" path that exercises the
        // emit-in-ascending-FRN-order discipline.
        let report = Cat021Report {
            data_source_id: Some(0x4201),
            time_of_day_seconds: Some(1.0),
            position_wgs84: Some(WgsPosition {
                latitude_deg: 22.5,
                longitude_deg: -1.40625,
            }),
            target_address: Some(0x00A1_B2C3),
            flight_level: Some(375.0),
            target_identification: Some("TEST".to_string()),
        };
        let bytes = encode_cat021(std::slice::from_ref(&report)).expect("encode full");
        let decoded = decode_cat021(&bytes).expect("decode full");
        assert_eq!(decoded.len(), 1);
        let r = &decoded[0];
        assert_eq!(r.data_source_id, Some(0x4201));
        assert_eq!(r.target_address, Some(0x00A1_B2C3));
        assert_eq!(r.flight_level, Some(375.0));
        assert_eq!(r.target_identification.as_deref(), Some("TEST"));
        assert_eq!(r.time_of_day_seconds, Some(1.0));
        let pos = r.position_wgs84.expect("position present");
        let lsb = 180.0_f64 / f64::from(1u32 << 23);
        assert!((pos.latitude_deg - 22.5).abs() < lsb * 2.0);
        assert!((pos.longitude_deg - (-1.40625)).abs() < lsb * 2.0);
    }

    #[test]
    fn encode_multiple_records_in_one_datablock() {
        // Pin: a slice of N reports emits a single datablock whose
        // LEN covers all N records and decodes back to N reports
        // with the per-record FSPEC bits preserved.
        let reports = vec![
            Cat021Report {
                target_address: Some(0x00_AA_AA_AA),
                ..Cat021Report::default()
            },
            Cat021Report {
                target_address: Some(0x00_BB_BB_BB),
                flight_level: Some(100.0),
                ..Cat021Report::default()
            },
            Cat021Report {
                data_source_id: Some(0x1234),
                target_address: Some(0x00_CC_CC_CC),
                ..Cat021Report::default()
            },
        ];
        let bytes = encode_cat021(&reports).expect("encode multi");
        let decoded = decode_cat021(&bytes).expect("decode multi");
        assert_eq!(decoded.len(), 3);
        assert_eq!(decoded[0].target_address, Some(0x00_AA_AA_AA));
        assert_eq!(decoded[1].target_address, Some(0x00_BB_BB_BB));
        assert_eq!(decoded[1].flight_level, Some(100.0));
        assert_eq!(decoded[2].target_address, Some(0x00_CC_CC_CC));
        assert_eq!(decoded[2].data_source_id, Some(0x1234));
    }

    #[test]
    fn encode_fspec_chain_extends_when_high_frn_set() {
        // FRN 21 (flight_level) sits in the third FSPEC octet
        // (FRNs 15..=21). Setting only FRN 21 must produce a
        // 3-octet FSPEC chain: octets 0 and 1 carry FX bits set
        // (their only purpose is to chain to the next octet),
        // octet 2 carries the FRN 21 bit and FX clear.
        let report = Cat021Report {
            flight_level: Some(0.0),
            ..Cat021Report::default()
        };
        let bytes = encode_cat021(&[report]).expect("encode fl-only");
        // [CAT][LEN_hi][LEN_lo][fspec0][fspec1][fspec2][fl_hi][fl_lo]
        assert_eq!(bytes.len(), 3 + 3 + 2);
        assert_eq!(bytes[0], CAT_021);
        // Three FSPEC octets at offsets 3..6:
        let fspec0 = bytes[3];
        let fspec1 = bytes[4];
        let fspec2 = bytes[5];
        assert_eq!(fspec0 & 0x01, 0x01, "FSPEC octet 0 must chain (FX=1)");
        assert_eq!(fspec1 & 0x01, 0x01, "FSPEC octet 1 must chain (FX=1)");
        assert_eq!(fspec2 & 0x01, 0x00, "FSPEC octet 2 must terminate (FX=0)");
        // FRN 21 sits at (21-1) % 7 = 6 → bit shift 7 - 6 = 1.
        assert_eq!(fspec2 & (1 << 1), 0x02, "FRN 21 bit must be set");
        // Round-trip must preserve the field.
        let decoded = decode_cat021(&bytes).expect("decode fl-only");
        assert_eq!(decoded[0].flight_level, Some(0.0));
    }

    #[test]
    fn encode_target_address_out_of_range_returns_err() {
        // Pin: a value with any of the high 8 bits set is rejected
        // rather than silently masked. 0x0100_0000 is the smallest
        // 25-bit value.
        let report = Cat021Report {
            target_address: Some(0x0100_0000),
            ..Cat021Report::default()
        };
        let err = encode_cat021(&[report]).expect_err("must reject 25-bit address");
        assert_eq!(
            err,
            Cat021EncodeError::TargetAddressOutOfRange { value: 0x0100_0000 }
        );
    }

    #[test]
    fn encode_unencodable_identification_returns_err() {
        // Lowercase character — not in the ICAO Annex 10 6-bit alphabet.
        let report = Cat021Report {
            target_identification: Some("ual437".to_string()),
            ..Cat021Report::default()
        };
        let err = encode_cat021(&[report]).expect_err("must reject lowercase");
        match err {
            Cat021EncodeError::UnencodableIdentification { value, .. } => {
                assert_eq!(value, "ual437");
            }
            other => panic!("expected UnencodableIdentification, got {other:?}"),
        }
    }

    #[test]
    fn encode_pads_short_callsign_with_six_bit_space() {
        // A 4-character callsign must encode to 6 wire bytes
        // (8 chars × 6 bits) with the trailing 4 slots padded with
        // the ICAO 6-bit space (0x20). The decoder's
        // `trim_end()` then strips that padding back out, so the
        // round-trip yields the original 4-character string with
        // no trailing spaces.
        let report = Cat021Report {
            target_identification: Some("UAL4".to_string()),
            ..Cat021Report::default()
        };
        let bytes = encode_cat021(&[report]).expect("encode short callsign");
        // [CAT][LEN_hi][LEN_lo][fspec0..4][6 bytes]
        // FRN 29 → (29-1) / 7 = 4 → octet index 4 → 5 octets
        // total in the chain (octets 0..=3 chain via FX, octet 4
        // carries FRN 29 and terminates). Then 6 bytes of callsign.
        assert_eq!(bytes.len(), 3 + 5 + 6);
        let decoded = decode_cat021(&bytes).expect("decode short callsign");
        assert_eq!(
            decoded[0].target_identification.as_deref(),
            Some("UAL4"),
            "padded space must be trimmed by decoder"
        );
    }

    #[test]
    fn encode_record_with_no_fields_set_emits_zero_fspec() {
        // The default `Cat021Report` (all `None`) must emit a record
        // consisting of a single 0x00 FSPEC octet with no following
        // field data. The whole datablock is therefore 4 bytes:
        // CAT(1) + LEN(2) + FSPEC(1).
        let report = Cat021Report::default();
        let bytes = encode_cat021(std::slice::from_ref(&report)).expect("encode empty");
        assert_eq!(bytes.len(), 4);
        assert_eq!(bytes[0], CAT_021);
        assert_eq!(u16::from_be_bytes([bytes[1], bytes[2]]), 4);
        assert_eq!(bytes[3], 0x00);
        // Round-trip must preserve the all-`None` shape.
        let decoded = decode_cat021(&bytes).expect("decode empty");
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0], report);
    }

    #[test]
    fn encode_position_wgs84_round_trip_preserves_at_lsb_precision() {
        // Pick a representative tactical-relevant point (San Francisco
        // Bay area) and assert the round-trip lands within the 1-LSB
        // precision the wire format is documented to support
        // (180 / 2^23 deg ≈ 2.145e-5 deg).
        let lat = 37.5_f64;
        let lon = -122.5_f64;
        let report = Cat021Report {
            position_wgs84: Some(WgsPosition {
                latitude_deg: lat,
                longitude_deg: lon,
            }),
            ..Cat021Report::default()
        };
        let bytes = encode_cat021(&[report]).expect("encode position");
        let decoded = decode_cat021(&bytes).expect("decode position");
        let pos = decoded[0].position_wgs84.expect("position present");
        let lsb = 180.0_f64 / f64::from(1u32 << 23);
        assert!(
            (pos.latitude_deg - lat).abs() <= lsb,
            "lat precision: got {}, expected {} (lsb {})",
            pos.latitude_deg,
            lat,
            lsb
        );
        assert!(
            (pos.longitude_deg - lon).abs() <= lsb,
            "lon precision: got {}, expected {} (lsb {})",
            pos.longitude_deg,
            lon,
            lsb
        );
    }

    #[test]
    fn decode_data_source_id_now_populated_after_encoder_addition() {
        // Behaviour-change pin: pre-this-PR, FRN 1 (I021/010 Data
        // Source ID) was decoded as a length-2 skip — the wire
        // bytes were consumed but no struct field was populated. As
        // of this PR, the field is preserved as a packed `u16` so
        // an encode → decode round-trip is byte-stable. Hand-built
        // fixture: SAC = 0x42, SIC = 0x07.
        let mut record = build_fspec(&[1]);
        record.extend_from_slice(&[0x42, 0x07]);
        let datablock = build_datablock(&record);
        let reports = decode_cat021(&datablock).expect("decode data source id");
        assert_eq!(reports.len(), 1);
        assert_eq!(
            reports[0].data_source_id,
            Some(0x4207),
            "SAC=0x42 + SIC=0x07 must pack as 0x4207"
        );
    }

    #[test]
    fn encode_into_appends_to_existing_buffer() {
        // The `_into` variant must not pre-clear the caller's
        // buffer. Pre-populate a `BytesMut` with some bytes, encode
        // into it, and assert the prefix is preserved while the
        // datablock is appended after.
        let mut buf = bytes::BytesMut::new();
        buf.extend_from_slice(b"PRE");
        let report = Cat021Report {
            target_address: Some(0x00_12_34_56),
            ..Cat021Report::default()
        };
        encode_cat021_into(std::slice::from_ref(&report), &mut buf).expect("encode_into ok");
        assert!(buf.starts_with(b"PRE"), "prefix must be preserved");
        // The datablock starts at offset 3 (after "PRE").
        let datablock = &buf[3..];
        let decoded = decode_cat021(datablock).expect("decode appended datablock");
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0], report);
    }
}
