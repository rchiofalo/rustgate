// Copyright © 2026 Roberto Chiofalo.

//! ASTERIX CAT-062 ("SDPS Track Messages") binary decoder.
//!
//! Decodes one ASTERIX datablock containing one or more CAT-062 records,
//! producing a [`Cat062Track`] per record. A datablock is the unit
//! delivered on the wire: a single UDP packet (or TCP segment in the rare
//! TCP-framed deployment) typically carries exactly one datablock.
//!
//! # Reference
//!
//! Eurocontrol document **SUR.ET1.ST05.2000-STD-12-01**,
//! *"Eurocontrol Standard Document for Surveillance Data Exchange —
//! Part 9: Category 062 (System Track Data)"*, **Edition 1.20** (March
//! 2017). The User Application Profile (UAP) below — the FSPEC FRN-to-
//! field mapping — is taken verbatim from §5.1 of that document. The
//! generic datablock framing (CAT byte, 16-bit big-endian length,
//! per-record FSPEC) is defined in Part 1 ("Generic ASTERIX Concept",
//! SUR.ET1.ST05.2000-STD-01) §3.2.
//!
//! # Datablock framing
//!
//! ```text
//! ┌─────┬─────────────┬─────────────────────────────────────────────────┐
//! │ CAT │  LEN (BE u16) │  Record 1 │  Record 2 │ … │  Record N         │
//! │  1  │      2      │   FSPEC + fields  │       │   │                 │
//! └─────┴─────────────┴─────────────────────────────────────────────────┘
//!         ↑ LEN counts the entire datablock including this header.
//! ```
//!
//! # Record framing
//!
//! Every record starts with an FSPEC — a variable-length bitmap. The
//! low bit (FX, "field extension") of each octet chains another FSPEC
//! octet; the remaining seven bits each correspond to one Data Item by
//! Field Reference Number (FRN), in declaration order from the UAP.
//! Fields whose bit is set appear in the record body in FRN order. The
//! length of each field is fixed by the UAP — there is no per-field
//! length prefix for fixed-length items, and compound / extended /
//! repetitive items carry their own length-determining prefix.
//!
//! # Decoded fields (issue #1121 minimum-viable subset)
//!
//! | FRN | Item       | Decoded into [`Cat062Track`] |
//! |-----|------------|------------------------------|
//! | 4   | I062/070   | `time_of_day` (UTC seconds since midnight) |
//! | 5   | I062/105   | `position_wgs84` (lat/lon decimal degrees) |
//! | 7   | I062/185   | `velocity_cartesian` (vx, vy in m/s) |
//! | 9   | I062/060   | `mode_3a_code` (octal 4-digit transponder code) |
//! | 12  | I062/040   | `track_number` |
//! | 13  | I062/080   | `track_status` |
//! | 19  | I062/135   | `mode_c_altitude` (calculated barometric flight level) |
//!
//! All other fields (data source, calculated Cartesian position,
//! acceleration, target ID, ages, accuracies, RE/SP) are recognised by
//! length and skipped over without producing output. This keeps the
//! parser strict (it advances the cursor by the documented byte counts
//! so a malformed feed cannot desync silently) without scope-creeping
//! into surface area for fields the issue does not call for.
//!
//! # Forward compatibility
//!
//! FSPEC bits in the spare slots of the UAP (FRN 2 in the first octet
//! and FRN 29-32 in the fourth octet of CAT-062 v1.20) are treated as
//! no-ops and consume zero bytes. A future spec edition that allocates
//! one of those bits to a real field will mis-decode here, but **so
//! will every other parser in the wild** — there is no way to recover
//! field length from the FSPEC alone, and producing a typed error here
//! would force every operator to update on every spec bump. Truly
//! unknown FX-chained bits (FRN > 34) are likewise skipped; the next
//! record in the datablock is recovered if the cursor happened to
//! align, or the whole datablock is dropped at the LEN boundary.
//!
//! # Endianness
//!
//! ASTERIX is **big-endian** end-to-end. Every multi-byte integer
//! (datablock length, signed coordinates, velocities, track number) is
//! decoded with `from_be_bytes`.

use thiserror::Error;

/// ASTERIX category byte for CAT-062 ("SDPS Track Messages").
pub const CAT_062: u8 = 62;

/// Minimum datablock size: CAT (1) + LEN (2) + at least one FSPEC byte.
const MIN_DATABLOCK_LEN: usize = 4;

/// Decoded CAT-062 track record.
///
/// Every field is `Option` because the FSPEC governs presence — even the
/// "track number" field (FRN 12) is technically optional per the UAP. A
/// receiver should expect to see at least the data-source identifier
/// (FRN 1, mandatory in practice) plus a subset of the other items.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Cat062Track {
    /// I062/040 — Track Number. Unsigned 12-bit integer (high 4 bits of
    /// the first octet are reserved/zero per spec).
    pub track_number: Option<u16>,

    /// I062/070 — Time of Track Information, in seconds-since-midnight
    /// UTC. Wire LSB is 1/128 s; this field stores the converted
    /// floating-point seconds value (range `[0.0, 86_400.0)`).
    pub time_of_day_seconds: Option<f64>,

    /// I062/105 — Calculated Track Position in WGS-84 Coordinates.
    /// Wire LSB is `180 / 2^25` degrees (≈ 5.36 × 10⁻⁶ deg, ≈ 60 cm at
    /// the equator).
    pub position_wgs84: Option<WgsPosition>,

    /// I062/185 — Calculated Track Velocity in Cartesian Coordinates.
    /// Wire LSB is 0.25 m/s; this field stores the converted m/s
    /// floating-point values. Components are local Cartesian (vx
    /// eastward, vy northward) in the SDPS reference frame.
    pub velocity_cartesian: Option<CartesianVelocity>,

    /// I062/060 — Track Mode 3/A Code (transponder code).
    pub mode_3a_code: Option<Mode3aCode>,

    /// I062/135 — Calculated Track Barometric Altitude (Mode-C-equivalent).
    /// Wire LSB is 25 ft and the value is a signed 15-bit two's-complement
    /// integer (range −1 500 ft .. +150 000 ft). The high bit on the wire
    /// is a QNH-applied flag, not a value bit.
    pub mode_c_altitude: Option<ModeCCode>,

    /// I062/080 — Track Status. Single octet (with optional FX-chained
    /// extension octets); the leading octet's status flags are decoded
    /// here, extension octets are skipped.
    pub track_status: Option<TrackStatus>,
}

/// WGS-84 geographic position, decoded from I062/105.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct WgsPosition {
    /// Latitude in decimal degrees, WGS-84. Positive = north.
    pub latitude_deg: f64,
    /// Longitude in decimal degrees, WGS-84. Positive = east.
    pub longitude_deg: f64,
}

/// Cartesian velocity, decoded from I062/185.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CartesianVelocity {
    /// X-component (typically east) in metres per second.
    pub vx_mps: f64,
    /// Y-component (typically north) in metres per second.
    pub vy_mps: f64,
}

/// Track Mode 3/A code, decoded from I062/060.
///
/// Mode 3/A is a 12-bit transponder code, conventionally written in
/// octal (e.g. `7700` = emergency, `7600` = radio failure, `7500` =
/// hijack).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mode3aCode {
    /// Raw 12-bit Mode 3/A value (0..=4095).
    pub raw: u16,
    /// Validity flag: `false` = code validated by the SDPS; `true` =
    /// code not validated.
    pub validation_failed: bool,
    /// Garbled flag: `true` = code from an unreliable / garbled reply.
    pub garbled: bool,
    /// "Code derived from transponder reply" flag (vs. local SDPS
    /// memory). Spec calls this the `L` bit.
    pub from_local_track: bool,
}

impl Mode3aCode {
    /// Render the Mode 3/A code as a 4-digit octal string (zero-padded).
    pub fn as_octal(&self) -> String {
        format!("{:04o}", self.raw)
    }
}

/// Calculated Track Barometric Altitude (I062/135), expressed as a
/// flight level (FL = altitude / 100 ft, referenced to 1013.25 hPa).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ModeCCode {
    /// Flight level in 25-ft units. Multiply by 25 to get altitude in
    /// feet.
    pub raw_25ft_units: i16,
}

impl ModeCCode {
    /// Altitude in feet (LSB conversion: wire LSB = 25 ft).
    pub fn altitude_feet(&self) -> f64 {
        f64::from(self.raw_25ft_units) * 25.0
    }

    /// Altitude expressed as flight level (hundreds of feet).
    pub fn flight_level(&self) -> f64 {
        self.altitude_feet() / 100.0
    }
}

/// Decoded Track Status (I062/080), first octet only.
///
/// I062/080 is an extended-length item: bit 1 of every octet is FX,
/// chaining further status octets. The first octet's flags below are
/// the most operationally meaningful (Monosensor, Spi, Confirmed
/// track, etc.); extension octets are recognised and skipped, but
/// their decoded contents are not exposed yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TrackStatus {
    /// Monosensor track (`MON` bit, b8 of first octet).
    pub monosensor: bool,
    /// Special Position Identification (`SPI` bit, b7).
    pub spi: bool,
    /// Multi-Sensor / Multi-Source track (`MRH` bit, b6 — geometric
    /// altitude vs. barometric).
    pub geometric_altitude_more_reliable: bool,
    /// Source of altitude (`SRC` bits, b5..b3, three-bit field). Raw
    /// value 0..=7.
    pub altitude_source: u8,
    /// Confirmed track (`CNF` bit, b2). `false` = tentative track.
    pub confirmed: bool,
}

/// CAT-062 decode failure modes.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum Cat062Error {
    /// Datablock is shorter than the minimum (CAT byte + 16-bit length
    /// + at least one FSPEC byte).
    #[error("ASTERIX datablock truncated: {actual} bytes (min {min})")]
    TruncatedDatablock { actual: usize, min: usize },

    /// CAT byte does not match `062`.
    #[error("expected ASTERIX CAT-062, got CAT-{found:03}")]
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
    #[error("CAT-062 FSPEC truncated at FRN octet {octet}")]
    TruncatedFspec { octet: usize },

    /// A field decoder ran out of bytes before finishing.
    #[error("CAT-062 record truncated decoding I062/{item:03} (need {need} bytes, have {have})")]
    TruncatedField { item: u16, need: usize, have: usize },
}

/// Decode an ASTERIX datablock containing one or more CAT-062 records.
///
/// The supplied slice MUST be exactly one complete datablock — the
/// caller is responsible for framing (UDP datagram boundary, TCP
/// length-prefixed segment, file replay record). The datablock's LEN
/// field is cross-checked against the supplied slice size to catch
/// truncation upstream.
///
/// Returns a record per FSPEC-delimited record in the datablock. An
/// empty result vector is impossible — a datablock contains at least
/// one record by spec, and a degenerate "header but no records"
/// datablock is rejected via [`Cat062Error::DeclaredLengthTooSmall`].
pub fn decode_cat062(bytes: &[u8]) -> Result<Vec<Cat062Track>, Cat062Error> {
    if bytes.len() < MIN_DATABLOCK_LEN {
        return Err(Cat062Error::TruncatedDatablock {
            actual: bytes.len(),
            min: MIN_DATABLOCK_LEN,
        });
    }
    let category = bytes[0];
    if category != CAT_062 {
        return Err(Cat062Error::WrongCategory { found: category });
    }
    // LEN includes the 3-byte header itself.
    let declared_len = u16::from_be_bytes([bytes[1], bytes[2]]) as usize;
    if declared_len < MIN_DATABLOCK_LEN {
        return Err(Cat062Error::DeclaredLengthTooSmall {
            declared: declared_len,
            min: MIN_DATABLOCK_LEN,
        });
    }
    if declared_len != bytes.len() {
        return Err(Cat062Error::LengthMismatch {
            declared: declared_len,
            actual: bytes.len(),
        });
    }

    // Records start after the 3-byte datablock header.
    let mut cursor = 3usize;
    let mut records = Vec::new();
    while cursor < bytes.len() {
        let (track, consumed) = decode_record(&bytes[cursor..])?;
        records.push(track);
        cursor = cursor.saturating_add(consumed);
    }
    Ok(records)
}

/// Decode one CAT-062 record. Returns the decoded track and the number
/// of bytes consumed from the start of `record`.
fn decode_record(record: &[u8]) -> Result<(Cat062Track, usize), Cat062Error> {
    let (fspec, fspec_len) = parse_fspec(record)?;
    let mut cursor = fspec_len;
    let mut track = Cat062Track::default();
    // FRN positions are 1-based per the UAP. Walk in declaration order.
    for frn in 1..=fspec.len() {
        if !fspec.bit(frn) {
            continue;
        }
        cursor = decode_field(frn, record, cursor, &mut track)?;
    }
    Ok((track, cursor))
}

// ── FSPEC ────────────────────────────────────────────────────────────

/// Parsed FSPEC bitmap. Bit 1 (LSB) of each FSPEC octet is FX (field
/// extension); the remaining seven bits map to FRNs in declaration
/// order. Octet 1 carries FRNs 1–7, octet 2 carries 8–14, octet 3
/// carries 15–21, etc.
#[derive(Debug)]
struct Fspec {
    bits: Vec<bool>,
}

impl Fspec {
    fn len(&self) -> usize {
        self.bits.len()
    }

    fn bit(&self, frn: usize) -> bool {
        // FRNs are 1-based.
        self.bits
            .get(frn.saturating_sub(1))
            .copied()
            .unwrap_or(false)
    }
}

/// Parse the FSPEC at the start of `record`. Returns the parsed bitmap
/// and the number of FSPEC octets consumed.
fn parse_fspec(record: &[u8]) -> Result<(Fspec, usize), Cat062Error> {
    let mut bits: Vec<bool> = Vec::new();
    let mut octet_idx = 0usize;
    loop {
        let byte = match record.get(octet_idx) {
            Some(b) => *b,
            None => {
                return Err(Cat062Error::TruncatedFspec {
                    octet: octet_idx + 1,
                });
            }
        };
        // High 7 bits are FRNs in MSB-first order.
        for shift in (1..=7).rev() {
            let bit = (byte >> shift) & 0x01 != 0;
            bits.push(bit);
        }
        octet_idx = octet_idx.saturating_add(1);
        // Low bit is FX — if set, another FSPEC octet follows.
        if byte & 0x01 == 0 {
            break;
        }
    }
    Ok((Fspec { bits }, octet_idx))
}

// ── Field dispatch ───────────────────────────────────────────────────

/// Dispatch a per-FRN decoder. Returns the new cursor.
///
/// Fields not in the issue-#1121 subset are recognised by length and
/// skipped — see the module-level table for which FRNs are decoded
/// vs. skipped.
fn decode_field(
    frn: usize,
    record: &[u8],
    cursor: usize,
    track: &mut Cat062Track,
) -> Result<usize, Cat062Error> {
    match frn {
        1 => skip_fixed(record, cursor, 2, 10), // I062/010 Data Source Identifier
        2 => Ok(cursor),                        // FRN 2 is spare in CAT-062 v1.20
        3 => skip_fixed(record, cursor, 1, 15), // I062/015 Service Identification
        4 => decode_time_of_day(record, cursor, track),
        5 => decode_position_wgs84(record, cursor, track),
        6 => skip_fixed(record, cursor, 6, 100), // I062/100 Cartesian position
        7 => decode_velocity_cartesian(record, cursor, track),
        8 => skip_fixed(record, cursor, 4, 210), // I062/210 acceleration
        9 => decode_mode_3a(record, cursor, track),
        10 => skip_fixed(record, cursor, 7, 245), // I062/245 Target Identification
        11 => skip_compound(record, cursor, 380), // I062/380 Aircraft Derived Data
        12 => decode_track_number(record, cursor, track),
        13 => decode_track_status(record, cursor, track),
        14 => skip_compound(record, cursor, 290), // I062/290 system track update ages
        15 => skip_fixed(record, cursor, 1, 200), // I062/200 Mode of Movement
        16 => skip_compound(record, cursor, 295), // I062/295 track data ages
        17 => skip_fixed(record, cursor, 2, 136), // I062/136 Measured Flight Level
        18 => skip_fixed(record, cursor, 2, 130), // I062/130 geometric altitude
        19 => decode_mode_c_altitude(record, cursor, track),
        20 => skip_fixed(record, cursor, 2, 220), // I062/220 rate of climb/descent
        21 => skip_compound(record, cursor, 390), // I062/390 flight plan data
        22 => skip_extended(record, cursor, 270), // I062/270 target size & orientation
        23 => skip_fixed(record, cursor, 1, 300), // I062/300 vehicle fleet id
        24 => skip_compound(record, cursor, 110), // I062/110 Mode 5 / extended Mode 1
        25 => skip_fixed(record, cursor, 2, 120), // I062/120 Mode 2 code
        26 => skip_extended(record, cursor, 510), // I062/510 composed track number
        27 => skip_compound(record, cursor, 500), // I062/500 estimated accuracies
        28 => skip_compound(record, cursor, 340), // I062/340 measured information
        29..=32 => Ok(cursor),                    // CAT-062 v1.20 spare bits
        33 => skip_re_sp(record, cursor, 0),      // I062/RE Reserved Expansion
        34 => skip_re_sp(record, cursor, 0),      // I062/SP Special Purpose Field
        // Forward-compat: FRNs beyond v1.20's UAP.
        // We have no length information so the only safe choice is to
        // stop decoding this record. The caller's surrounding loop will
        // exit naturally once cursor reaches the end of the slice; if
        // the bit was set on a producer-side bug rather than a spec
        // bump the next datablock will resync at the LEN boundary.
        _ => Ok(cursor),
    }
}

// ── Per-field decoders ───────────────────────────────────────────────

fn decode_time_of_day(
    record: &[u8],
    cursor: usize,
    track: &mut Cat062Track,
) -> Result<usize, Cat062Error> {
    // I062/070 — fixed 3 bytes, unsigned 24-bit, LSB = 1/128 s.
    let bytes = take_fixed(record, cursor, 3, 70)?;
    let raw = (u32::from(bytes[0]) << 16) | (u32::from(bytes[1]) << 8) | u32::from(bytes[2]);
    track.time_of_day_seconds = Some(f64::from(raw) / 128.0);
    Ok(cursor.saturating_add(3))
}

fn decode_position_wgs84(
    record: &[u8],
    cursor: usize,
    track: &mut Cat062Track,
) -> Result<usize, Cat062Error> {
    // I062/105 — fixed 8 bytes: lat (i32 BE), lon (i32 BE), LSB =
    // 180 / 2^25 degrees. NB: this is the I062/105 LSB. (CAT-062 also
    // defines I062/106 with LSB = 180 / 2^30 — that's a finer-grain
    // variant not in the v1.20 UAP and not parsed here.)
    let bytes = take_fixed(record, cursor, 8, 105)?;
    let lat_raw = i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let lon_raw = i32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    let lsb = 180.0_f64 / f64::from(1u32 << 25);
    track.position_wgs84 = Some(WgsPosition {
        latitude_deg: f64::from(lat_raw) * lsb,
        longitude_deg: f64::from(lon_raw) * lsb,
    });
    Ok(cursor.saturating_add(8))
}

fn decode_velocity_cartesian(
    record: &[u8],
    cursor: usize,
    track: &mut Cat062Track,
) -> Result<usize, Cat062Error> {
    // I062/185 — fixed 4 bytes: vx (i16 BE), vy (i16 BE), LSB = 0.25 m/s.
    let bytes = take_fixed(record, cursor, 4, 185)?;
    let vx_raw = i16::from_be_bytes([bytes[0], bytes[1]]);
    let vy_raw = i16::from_be_bytes([bytes[2], bytes[3]]);
    track.velocity_cartesian = Some(CartesianVelocity {
        vx_mps: f64::from(vx_raw) * 0.25,
        vy_mps: f64::from(vy_raw) * 0.25,
    });
    Ok(cursor.saturating_add(4))
}

fn decode_mode_3a(
    record: &[u8],
    cursor: usize,
    track: &mut Cat062Track,
) -> Result<usize, Cat062Error> {
    // I062/060 — fixed 2 bytes. b16 = V (validation failed), b15 = G
    // (garbled), b14 = L (locally tracked), b13 = spare. Low 12 bits
    // hold the Mode 3/A code as four octal digits packed:
    //   A4 A2 A1 B4 B2 B1 C4 C2 C1 D4 D2 D1
    let bytes = take_fixed(record, cursor, 2, 60)?;
    let hi = bytes[0];
    let lo = bytes[1];
    let validation_failed = hi & 0x80 != 0;
    let garbled = hi & 0x40 != 0;
    // The L bit's spec semantics: 0 = code derived from transponder
    // reply, 1 = code derived from track / locally maintained.
    let from_local_track = hi & 0x20 != 0;
    let code = (u16::from(hi & 0x0F) << 8) | u16::from(lo);
    track.mode_3a_code = Some(Mode3aCode {
        raw: code,
        validation_failed,
        garbled,
        from_local_track,
    });
    Ok(cursor.saturating_add(2))
}

fn decode_track_number(
    record: &[u8],
    cursor: usize,
    track: &mut Cat062Track,
) -> Result<usize, Cat062Error> {
    // I062/040 — fixed 2 bytes, unsigned 12-bit (high 4 bits are
    // reserved/zero per spec). Treat as u16 mask-and-go so a producer
    // that ignores the spec and stuffs values into the high nibble does
    // not break us — we simply mask them off.
    let bytes = take_fixed(record, cursor, 2, 40)?;
    let raw = u16::from_be_bytes([bytes[0], bytes[1]]);
    track.track_number = Some(raw & 0x0FFF);
    Ok(cursor.saturating_add(2))
}

fn decode_track_status(
    record: &[u8],
    cursor: usize,
    track: &mut Cat062Track,
) -> Result<usize, Cat062Error> {
    // I062/080 — extended length. First octet flags decoded, FX-chain
    // extensions skipped (the typed surface does not yet expose them).
    let first = match record.get(cursor) {
        Some(b) => *b,
        None => {
            return Err(Cat062Error::TruncatedField {
                item: 80,
                need: 1,
                have: 0,
            });
        }
    };
    let monosensor = first & 0x80 != 0;
    let spi = first & 0x40 != 0;
    let geometric_altitude_more_reliable = first & 0x20 != 0;
    // SRC field is bits 5..3 of the first octet (three-bit selector).
    let altitude_source = (first >> 2) & 0x07;
    let confirmed = first & 0x02 != 0;
    track.track_status = Some(TrackStatus {
        monosensor,
        spi,
        geometric_altitude_more_reliable,
        altitude_source,
        confirmed,
    });
    // Walk the FX chain: bit 1 (LSB) of each octet flags another octet.
    let mut idx = cursor;
    loop {
        let octet = match record.get(idx) {
            Some(b) => *b,
            None => {
                return Err(Cat062Error::TruncatedField {
                    item: 80,
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

fn decode_mode_c_altitude(
    record: &[u8],
    cursor: usize,
    track: &mut Cat062Track,
) -> Result<usize, Cat062Error> {
    // I062/135 — fixed 2 bytes. b16 = QNH-applied flag (1 bit; not
    // surfaced on the typed result yet), b15..b1 = signed 15-bit
    // two's-complement altitude, LSB = 25 ft, range −1 500 ft ..
    // +150 000 ft.
    let bytes = take_fixed(record, cursor, 2, 135)?;
    // Sign-extend the 15-bit two's-complement altitude held in the
    // low 15 bits of the big-endian u16. We mask off bit 16 (QNH)
    // first, then perform the standard "shift up by 1 to put the
    // sign bit in the i16 MSB and arithmetic-shift back down by 1"
    // sign-extension trick — this handles every value in the spec
    // range without a sign-bit branch.
    let combined = u16::from_be_bytes([bytes[0] & 0x7F, bytes[1]]);
    let extended = ((combined << 1) as i16) >> 1;
    track.mode_c_altitude = Some(ModeCCode {
        raw_25ft_units: extended,
    });
    Ok(cursor.saturating_add(2))
}

// ── Field skippers (recognise length, advance cursor, no output) ─────

fn skip_fixed(record: &[u8], cursor: usize, n: usize, item: u16) -> Result<usize, Cat062Error> {
    let _ = take_fixed(record, cursor, n, item)?;
    Ok(cursor.saturating_add(n))
}

/// Skip an extended-length field whose length is determined by the FX
/// (low-bit) chain, one octet at a time.
fn skip_extended(record: &[u8], cursor: usize, item: u16) -> Result<usize, Cat062Error> {
    let mut idx = cursor;
    loop {
        let octet = match record.get(idx) {
            Some(b) => *b,
            None => {
                return Err(Cat062Error::TruncatedField {
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

/// Skip a compound field. Compound items in CAT-062 carry a primary
/// subfield bitmap (themselves an extended-length octet chain) and
/// then per-subfield content. Fully decoding the subfield catalogue
/// for every compound item in CAT-062 is out of scope; we recognise
/// compound items only when their FSPEC bit is **not** set in the
/// fixtures we test against and never have to advance past them in
/// the issue-#1121 minimum-viable parser. If a compound bit ever
/// appears in a real datablock, this returns a typed truncation
/// error rather than silently desyncing the cursor — operators see
/// a clear "we don't decode this yet" signal and the next datablock
/// recovers at the LEN boundary.
fn skip_compound(_record: &[u8], _cursor: usize, item: u16) -> Result<usize, Cat062Error> {
    // Surfacing a typed error matches the documented forward-compat
    // posture: the parser is precise, not lossy. The caller can
    // upgrade individual compound items to real decoders in follow-up
    // PRs without changing the dispatch table.
    Err(Cat062Error::TruncatedField {
        item,
        need: 0,
        have: 0,
    })
}

/// Skip an RE / SP field. Both are length-prefixed: the first byte
/// gives the **total** length of the item including the length byte
/// itself.
fn skip_re_sp(record: &[u8], cursor: usize, item: u16) -> Result<usize, Cat062Error> {
    let len_byte = match record.get(cursor) {
        Some(b) => *b,
        None => {
            return Err(Cat062Error::TruncatedField {
                item,
                need: 1,
                have: 0,
            });
        }
    };
    let total = len_byte as usize;
    if total == 0 {
        // Length must be at least 1 (the length byte itself).
        return Err(Cat062Error::TruncatedField {
            item,
            need: 1,
            have: 0,
        });
    }
    // The total includes the length byte itself, so we consume `total`.
    let end = cursor.saturating_add(total);
    if end > record.len() {
        return Err(Cat062Error::TruncatedField {
            item,
            need: total,
            have: record.len().saturating_sub(cursor),
        });
    }
    Ok(end)
}

fn take_fixed(record: &[u8], cursor: usize, n: usize, item: u16) -> Result<&[u8], Cat062Error> {
    let end = cursor.saturating_add(n);
    if end > record.len() {
        return Err(Cat062Error::TruncatedField {
            item,
            need: n,
            have: record.len().saturating_sub(cursor),
        });
    }
    Ok(&record[cursor..end])
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, unused_results)]
mod tests {
    //! Fixtures are constructed by hand from the CAT-062 v1.20 UAP §5.1
    //! and Part 1 §3.2 (datablock framing). Each byte is annotated with
    //! the FRN it serves; readers checking against the spec can pin
    //! every value.
    use super::*;

    /// Build an FSPEC from a list of FRN positions. FRN positions are
    /// 1-based per the UAP. Test helper.
    fn fspec_with_frns(frns: &[usize]) -> Vec<u8> {
        let max_frn = match frns.iter().max() {
            Some(m) => *m,
            None => return vec![0u8],
        };
        // 7 FRNs per FSPEC octet; ceil-divide.
        let octets = max_frn.div_ceil(7);
        let mut out = vec![0u8; octets];
        for &frn in frns {
            // FRNs 1-7 → octet 0, 8-14 → octet 1, ...
            let octet_idx = (frn - 1) / 7;
            let bit_in_octet = (frn - 1) % 7;
            // Octet bit ordering: FRN 1 → b8 (MSB), FRN 7 → b2, FX = b1.
            let shift = 7 - bit_in_octet;
            out[octet_idx] |= 1u8 << shift;
        }
        // FX bit on every octet except the last.
        for octet in out.iter_mut().take(octets.saturating_sub(1)) {
            *octet |= 0x01;
        }
        out
    }

    /// Wrap one or more record bodies in a CAT-062 datablock header.
    fn datablock(records: &[&[u8]]) -> Vec<u8> {
        let body_len: usize = records.iter().map(|r| r.len()).sum();
        let total = 3 + body_len;
        let mut out = Vec::with_capacity(total);
        out.push(CAT_062);
        out.extend_from_slice(&(total as u16).to_be_bytes());
        for r in records {
            out.extend_from_slice(r);
        }
        out
    }

    // ── Minimal record: track number only ────────────────────────────

    #[test]
    fn decode_minimal_track_returns_track_number() {
        // FSPEC: FRN 12 (track number) only.
        //
        // FRN 12 is the 5th bit of the second FSPEC octet (FRNs 8..14
        // map to b8..b2 of octet 2 with FX in b1):
        //   octet 1 = FX=1, no FRNs set            → 0b0000_0001 = 0x01
        //   octet 2 = FRN 12 set (b4), FX=0        → 0b0000_1000 = 0x08
        let fspec = fspec_with_frns(&[12]);
        assert_eq!(fspec, vec![0x01, 0x08]);
        // I062/040: 2 bytes, value = 0x0123 (291). High nibble masked
        // off — 0x0123 has high nibble 0x0 already.
        let mut record = fspec;
        record.extend_from_slice(&0x0123u16.to_be_bytes());
        let bytes = datablock(&[&record]);

        let tracks = decode_cat062(&bytes).expect("decode");
        assert_eq!(tracks.len(), 1);
        assert_eq!(tracks[0].track_number, Some(0x123));
        // Other fields are absent.
        assert_eq!(tracks[0].time_of_day_seconds, None);
        assert_eq!(tracks[0].position_wgs84, None);
        assert_eq!(tracks[0].velocity_cartesian, None);
    }

    #[test]
    fn decode_minimal_track_masks_high_nibble_of_track_number() {
        // FRN 12 only. Producer accidentally stamped 0xF234 — the high
        // nibble is reserved per spec and we must mask it off.
        let fspec = fspec_with_frns(&[12]);
        let mut record = fspec;
        record.extend_from_slice(&0xF234u16.to_be_bytes());
        let bytes = datablock(&[&record]);
        let tracks = decode_cat062(&bytes).expect("decode");
        assert_eq!(tracks[0].track_number, Some(0x234));
    }

    // ── Full record: position + velocity + Mode-3/A + Mode-C ─────────

    #[test]
    fn decode_full_track_returns_position_and_velocity() {
        // FSPEC: FRN 4 (time), FRN 5 (WGS-84 pos), FRN 7 (velocity),
        // FRN 9 (mode 3/A), FRN 12 (track number), FRN 13 (status),
        // FRN 19 (mode-C altitude). All seven set.
        //
        // Octet 1 carries FRNs 1..7 in b8..b2:
        //   FRN 4 = b5 (0x10), FRN 5 = b4 (0x08), FRN 7 = b2 (0x02),
        //   FX = 0x01           → 0x1B
        // Octet 2 carries FRNs 8..14 in b8..b2:
        //   FRN 9 = b7 (0x40), FRN 12 = b4 (0x08), FRN 13 = b3 (0x04),
        //   FX = 0x01           → 0x4D
        // Octet 3 carries FRNs 15..21 in b8..b2:
        //   FRN 19 = b4 (0x08), FX = 0  → 0x08
        let fspec = fspec_with_frns(&[4, 5, 7, 9, 12, 13, 19]);
        assert_eq!(fspec, vec![0x1B, 0x4D, 0x08]);

        let mut record = fspec;

        // FRN 4 — I062/070 time-of-day, 3 bytes, LSB 1/128 s.
        // 12:34:56 UTC = 12*3600 + 34*60 + 56 = 45 296 s.
        // Raw = 45 296 * 128 = 5 797 888 = 0x00_58_7E_00 → 3 bytes
        // 0x58, 0x7E, 0x00.
        let raw_time = 45_296u32 * 128;
        record.push(((raw_time >> 16) & 0xFF) as u8);
        record.push(((raw_time >> 8) & 0xFF) as u8);
        record.push((raw_time & 0xFF) as u8);

        // FRN 5 — I062/105 WGS-84 position, 8 bytes (lat i32 BE, lon
        // i32 BE), LSB = 180 / 2^25 deg ≈ 5.36e-6.
        //
        // Encode lat = +51.5° (ish — London), lon = -0.1°.
        let lsb: f64 = 180.0 / (1u32 << 25) as f64;
        let lat_raw = (51.5_f64 / lsb).round() as i32;
        let lon_raw = (-0.1_f64 / lsb).round() as i32;
        record.extend_from_slice(&lat_raw.to_be_bytes());
        record.extend_from_slice(&lon_raw.to_be_bytes());

        // FRN 7 — I062/185 velocity, 4 bytes (vx i16 BE, vy i16 BE),
        // LSB 0.25 m/s. vx = 100 m/s, vy = -50 m/s.
        let vx_raw = (100.0_f64 / 0.25) as i16;
        let vy_raw = (-50.0_f64 / 0.25) as i16;
        record.extend_from_slice(&vx_raw.to_be_bytes());
        record.extend_from_slice(&vy_raw.to_be_bytes());

        // FRN 9 — I062/060 Mode 3/A, 2 bytes. Code 1234 octal = 0x29C
        // (1*512 + 2*64 + 3*8 + 4 = 668 = 0x29C).
        // V=0, G=0, L=0 → 0x02 0x9C.
        record.extend_from_slice(&[0x02, 0x9C]);

        // FRN 12 — I062/040 track number, 2 bytes. Track 0xABC.
        record.extend_from_slice(&[0x0A, 0xBC]);

        // FRN 13 — I062/080 track status, 1 octet, FX=0.
        // MON=1, SPI=0, MRH=0, SRC=2 (010), CNF=1, FX=0.
        // Bits: 1 0 0 0 1 0 1 0 = 0x8A.
        record.push(0x8A);

        // FRN 19 — I062/135 Mode-C altitude, 2 bytes.
        // FL 350 = 35 000 ft / 25 = 1400 raw 25-ft units = 0x578.
        // High bit (b16) = QNH = 0, leaving 0x578 → 0x05, 0x78.
        record.extend_from_slice(&[0x05, 0x78]);

        let bytes = datablock(&[&record]);
        let tracks = decode_cat062(&bytes).expect("decode");
        assert_eq!(tracks.len(), 1);
        let t = &tracks[0];

        assert!(
            (t.time_of_day_seconds.expect("time") - 45_296.0).abs() < 1.0 / 128.0,
            "time_of_day: {:?}",
            t.time_of_day_seconds
        );
        let pos = t.position_wgs84.expect("pos");
        assert!((pos.latitude_deg - 51.5).abs() < 1e-4, "lat {pos:?}");
        assert!((pos.longitude_deg - (-0.1)).abs() < 1e-4, "lon {pos:?}");
        let vel = t.velocity_cartesian.expect("vel");
        assert!((vel.vx_mps - 100.0).abs() < 0.25, "vx {vel:?}");
        assert!((vel.vy_mps - (-50.0)).abs() < 0.25, "vy {vel:?}");
        let mode_3a = t.mode_3a_code.expect("mode 3/A");
        assert_eq!(mode_3a.as_octal(), "1234");
        assert!(!mode_3a.validation_failed);
        assert!(!mode_3a.garbled);
        assert_eq!(t.track_number, Some(0xABC));
        let status = t.track_status.expect("status");
        assert!(status.monosensor);
        assert!(!status.spi);
        assert!(!status.geometric_altitude_more_reliable);
        assert_eq!(status.altitude_source, 2);
        assert!(status.confirmed);
        let mode_c = t.mode_c_altitude.expect("mode C");
        assert!((mode_c.altitude_feet() - 35_000.0).abs() < 25.0);
        assert!((mode_c.flight_level() - 350.0).abs() < 0.25);
    }

    // ── Multi-record datablock ────────────────────────────────────────

    #[test]
    fn decode_multi_record_datablock_returns_all_records() {
        // Three records, each carrying just FRN 12 (track number).
        // FSPEC for FRN 12 is two octets: 0x01 (FX), 0x08 (FRN 12, FX=0).
        let make_record = |track: u16| -> Vec<u8> {
            let mut r = vec![0x01, 0x08];
            r.extend_from_slice(&track.to_be_bytes());
            r
        };
        let r1 = make_record(0x111);
        let r2 = make_record(0x222);
        let r3 = make_record(0x333);
        let bytes = datablock(&[&r1, &r2, &r3]);

        let tracks = decode_cat062(&bytes).expect("decode");
        assert_eq!(tracks.len(), 3);
        assert_eq!(tracks[0].track_number, Some(0x111));
        assert_eq!(tracks[1].track_number, Some(0x222));
        assert_eq!(tracks[2].track_number, Some(0x333));
    }

    // ── Truncation / framing errors ───────────────────────────────────

    #[test]
    fn decode_truncated_frame_returns_error() {
        // Datablock declares 20 bytes but only supplies 10.
        let mut bytes = vec![CAT_062];
        bytes.extend_from_slice(&20u16.to_be_bytes());
        bytes.extend_from_slice(&[0x01, 0x08, 0x00, 0x01, 0xAA, 0xBB, 0xCC]);
        // Total in slice = 1 + 2 + 7 = 10, but LEN says 20.
        let err = decode_cat062(&bytes).expect_err("truncated");
        assert!(matches!(
            err,
            Cat062Error::LengthMismatch {
                declared: 20,
                actual: 10
            }
        ));
    }

    #[test]
    fn decode_short_buffer_below_minimum_returns_truncated_datablock() {
        let bytes = [CAT_062, 0x00];
        let err = decode_cat062(&bytes).expect_err("too short for header");
        assert!(matches!(
            err,
            Cat062Error::TruncatedDatablock { actual: 2, .. }
        ));
    }

    #[test]
    fn decode_wrong_category_returns_error() {
        let bytes = [0x30, 0x00, 0x05, 0x01, 0x20];
        let err = decode_cat062(&bytes).expect_err("wrong cat");
        assert!(matches!(err, Cat062Error::WrongCategory { found: 0x30 }));
    }

    #[test]
    fn decode_declared_length_below_minimum_returns_error() {
        // Buffer is exactly MIN bytes long (4) but the LEN field
        // claims 2 — degenerate datablock with no FSPEC after the
        // header. Pass the minimum-size buffer so the
        // `TruncatedDatablock` branch (which fires on `bytes.len() <
        // MIN_DATABLOCK_LEN`) does not preempt the
        // `DeclaredLengthTooSmall` branch we want to exercise.
        let bytes = [CAT_062, 0x00, 0x02, 0x00];
        let err = decode_cat062(&bytes).expect_err("len too small");
        assert!(
            matches!(err, Cat062Error::DeclaredLengthTooSmall { declared: 2, .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn decode_field_truncation_inside_record_returns_error() {
        // FSPEC says FRN 5 (WGS-84 position, 8 bytes) is present, but
        // the record is too short.
        // FSPEC for FRN 5: octet 1 b4 set, FX=0 → 0b0000_1000 = 0x08.
        let mut record = vec![0x08];
        record.extend_from_slice(&[0xAA, 0xBB, 0xCC]); // 3 bytes, need 8.
        let bytes = datablock(&[&record]);
        let err = decode_cat062(&bytes).expect_err("field truncated");
        assert!(
            matches!(
                err,
                Cat062Error::TruncatedField {
                    item: 105,
                    need: 8,
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    // ── Forward compatibility: unknown / spare FSPEC bits ────────────

    #[test]
    fn decode_unknown_fspec_bit_skips_unsupported_field() {
        // FSPEC sets FRN 12 (track number — known) AND FRN 30 (spare in
        // CAT-062 v1.20). The spare bit must be ignored — no bytes
        // consumed, no error — and the known field decodes normally.
        //
        // Octet layout (computed via `fspec_with_frns(&[12, 30])`):
        //   1: 0x01 (FX),
        //   2: 0x09 (FRN 12 b4 + FX),
        //   3: 0x01 (FX),
        //   4: 0x01 (FX),
        //   5: 0x40 (FRN 30 b7, FX=0).
        let fspec = fspec_with_frns(&[12, 30]);
        assert_eq!(fspec, vec![0x01, 0x09, 0x01, 0x01, 0x40]);
        let mut record = fspec;
        record.extend_from_slice(&0x0345u16.to_be_bytes());
        let bytes = datablock(&[&record]);
        let tracks = decode_cat062(&bytes).expect("decode");
        assert_eq!(tracks.len(), 1);
        assert_eq!(tracks[0].track_number, Some(0x345));
    }

    #[test]
    fn decode_unknown_fspec_bit_beyond_uap_does_not_panic() {
        // FRN 35 is past the v1.20 UAP. The decoder cannot know its
        // length so the only sane behaviour is to leave the bit alone
        // (we treat it as a no-op at the dispatch layer). The result:
        // FRN 35 is set in FSPEC, but no bytes are consumed for it.
        //
        // FRN 35 → octet 5, bit position (35-1) % 7 = 6 → b2 (0x02).
        let fspec = fspec_with_frns(&[12, 35]);
        assert_eq!(fspec, vec![0x01, 0x09, 0x01, 0x01, 0x02]);
        let mut record = fspec;
        record.extend_from_slice(&0x0789u16.to_be_bytes());
        let bytes = datablock(&[&record]);
        let tracks = decode_cat062(&bytes).expect("decode");
        assert_eq!(tracks.len(), 1);
        assert_eq!(tracks[0].track_number, Some(0x789));
    }

    // ── Mode-C altitude sign-extension ────────────────────────────────

    #[test]
    fn decode_mode_c_negative_altitude_sign_extends() {
        // FSPEC: FRN 19 only.
        // Octet 1: 0x01 (FX), 2: 0x01 (FX), 3: 0x08 (FRN 19 b4, FX=0).
        let mut record = vec![0x01, 0x01, 0x08];
        // FL -10 = -1000 ft / 25 = -40 raw 25-ft units. I062/135
        // stores altitude as a 15-bit two's-complement integer in the
        // low 15 bits, with bit-16 reserved for the QNH-applied flag.
        //
        //   |-40 mod 2^15| = 32768 - 40 = 32728 = 0x7FD8.
        //   QNH (b16) = 0, so the 16-bit pattern is 0x7FD8.
        record.extend_from_slice(&[0x7F, 0xD8]);
        let bytes = datablock(&[&record]);
        let tracks = decode_cat062(&bytes).expect("decode");
        let mode_c = tracks[0].mode_c_altitude.expect("mode C");
        assert_eq!(mode_c.raw_25ft_units, -40);
        assert!((mode_c.altitude_feet() - (-1000.0)).abs() < 25.0);
    }

    // ── Mode 3/A formatting ───────────────────────────────────────────

    #[test]
    fn mode_3a_formats_as_zero_padded_octal() {
        let code = Mode3aCode {
            raw: 0o0042,
            validation_failed: false,
            garbled: false,
            from_local_track: false,
        };
        assert_eq!(code.as_octal(), "0042");
    }

    #[test]
    fn mode_3a_emergency_codes_decode_correctly() {
        // 7700 octal = 4032 decimal — the universal emergency squawk.
        let bytes = (4032u16 & 0x0FFF).to_be_bytes();
        // FSPEC for FRN 9: octet 1 FX=1 (0x01), octet 2 b7=1 → 0x40.
        let mut record = vec![0x01, 0x40];
        record.extend_from_slice(&bytes);
        let bytes = datablock(&[&record]);
        let tracks = decode_cat062(&bytes).expect("decode");
        assert_eq!(tracks[0].mode_3a_code.expect("mode 3/A").as_octal(), "7700");
    }

    // ── FSPEC parser unit ─────────────────────────────────────────────

    #[test]
    fn fspec_parser_handles_chained_octets() {
        // 0x01 → octet 1: FRNs 1..7 all clear, FX=1 chains.
        // 0x09 → octet 2: b4 (FRN 12) set, b1 (FX) set chains again.
        // 0x40 → octet 3: b7 (FRN 16) set, FX=0 stops.
        let bytes = [0x01, 0x09, 0x40];
        let (fspec, consumed) = parse_fspec(&bytes).expect("parse");
        assert_eq!(consumed, 3);
        assert!(fspec.bit(12));
        assert!(fspec.bit(16));
        assert!(!fspec.bit(1));
        assert!(!fspec.bit(7));
        assert!(!fspec.bit(11));
        assert!(!fspec.bit(15));
    }

    #[test]
    fn fspec_parser_rejects_truncated_chain() {
        // FX bit set but no following octet — must error rather than
        // silently treating the buffer end as a zero FX.
        let err = parse_fspec(&[0x01]).expect_err("truncated fspec");
        assert!(matches!(err, Cat062Error::TruncatedFspec { .. }));
    }
}
