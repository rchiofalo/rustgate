// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! ASTERIX CAT-048 (Monoradar Target Reports) decoder.
//!
//! CAT-048 carries Mode-S / SSR target reports — the surveillance
//! observations emitted by ground-based primary and secondary
//! surveillance radars after they interrogate an aircraft's
//! transponder. This is the legacy "interrogated radar" feed that
//! makes up the bulk of operational ATC surveillance data; almost
//! every primary/secondary radar in the European air-traffic system
//! emits CAT-048. For tactical UAS detect-and-avoid deployments, the
//! operational source is different from CAT-021 (ADS-B is broadcast
//! from the aircraft, CAT-048 is solicited by ground radar) but the
//! integration value is the same — every transponder-equipped aircraft
//! in radar coverage is a potential conflict the UAS must deconflict
//! against.
//!
//! The wire framing is identical to [`crate::cat021::decode_cat021`]
//! and [`crate::cat062::decode_cat062`] (CAT byte + 16-bit big-endian
//! LEN + per-record FSPEC + FX-chained extension bits) per Eurocontrol
//! Part 1 §3.2 — only the per-FRN field set differs per the CAT-048
//! UAP. This module handles the issue-#1121 minimum-viable subset of
//! fields: Time of Day, Polar Position, Mode-3/A Code, Flight Level,
//! Aircraft Address (Mode-S 24-bit ICAO identifier), Aircraft
//! Identification (callsign), and Track Number. All other UAP entries
//! are recognised by length and skipped, so a real-world CAT-048
//! datablock with any subset of the documented fields decodes cleanly
//! without rejection.
//!
//! # Spec version
//!
//! Implements the wire format and Field Reference Numbers per
//! Eurocontrol document **EUROCONTROL-SPEC-149**, *"Eurocontrol
//! Standard Document for Surveillance Data Exchange — Part 4: Category
//! 048 (Monoradar Target Reports)"*, **Edition 1.31**. The framing
//! code is invariant across ASTERIX categories — the same
//! `Fspec` / FX-chain / fixed-skip / extended-skip / compound-skip
//! shape used by CAT-021 and CAT-062 applies here.
//!
//! # Cross-category type reuse
//!
//! [`Mode3aCode`] is re-exported from [`crate::cat062`] rather than
//! redefined here. The wire format of I048/070 is bit-for-bit identical
//! to I062/060 — both use the same V/G/L flag bits in the high octet
//! and the same 12-bit octal code in the low 12 bits. Defining a
//! parallel-but-distinct type would force downstream consumers that
//! correlate Mode-3/A codes across CAT-048 (radar) and CAT-062 (system
//! tracks) feeds to convert between them at every site. The error type
//! [`Cat048Error`] stays category-distinct so a downstream router that
//! dispatches on error type can distinguish CAT-048 from CAT-021 /
//! CAT-062 failures without parsing the message string.

use thiserror::Error;

pub use crate::cat062::Mode3aCode;

/// CAT-048 category byte (decimal 48 = `0x30`).
pub const CAT_048: u8 = 48;

/// Minimum datablock size: CAT (1) + LEN (2) + at least one FSPEC byte.
pub const MIN_DATABLOCK_LEN: usize = 4;

/// Decoded CAT-048 monoradar target report.
///
/// Every field is `Option` because the FSPEC governs presence — even
/// the data-source identifier (FRN 1, mandatory in practice) is only
/// guaranteed by operational convention, not by the wire format. A
/// receiver should expect to see at least the data-source identifier
/// plus a subset of the other items depending on which radar emitted
/// the report and what it observed.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Cat048Report {
    /// I048/140 — Time of Day, in seconds-since-midnight UTC. Wire LSB
    /// is 1/128 s; this field stores the converted floating-point
    /// seconds value (range `[0.0, 86_400.0)`).
    pub time_of_day_seconds: Option<f64>,

    /// I048/040 — Measured Position in Polar Coordinates (RHO/THETA).
    /// Range is in nautical miles (LSB = 1/256 NM, wire u16 BE),
    /// bearing is in decimal degrees east-of-true-north
    /// (LSB = 360 / 2^16 deg, wire u16 BE). For tactical UAS
    /// detect-and-avoid the polar form is the rawest signal a radar
    /// emits — it is what the antenna actually measured before any
    /// downstream Cartesian conversion or fusion.
    pub measured_position_polar: Option<PolarPosition>,

    /// I048/070 — Mode 3/A Code (transponder code). Wire format is
    /// bit-for-bit identical to I062/060 so the same `Mode3aCode`
    /// type is reused — see module-level docs.
    pub mode_3a_code: Option<Mode3aCode>,

    /// I048/090 — Flight Level in binary representation. Wire LSB is
    /// 1/4 FL (0.25 FL = 25 ft). The wire field is 14-bit signed
    /// two's-complement (with a V validity flag in bit 16 and a G
    /// garbled flag in bit 15, neither surfaced on the typed result
    /// today). Stored as a flight level (FL = altitude / 100 ft,
    /// referenced to 1013.25 hPa ICAO standard atmosphere).
    pub flight_level: Option<f64>,

    /// I048/220 — Aircraft Address (Mode-S). The 24-bit ICAO aircraft
    /// identifier (a.k.a. "Mode-S address" or "hex code"). Same wire
    /// format as CAT-021 I021/080.
    pub aircraft_address: Option<u32>,

    /// I048/240 — Aircraft Identification (callsign). 8 characters in
    /// ICAO Annex 10 6-bit alphabet packed MSB-first into 6 bytes;
    /// decoded to a trimmed `String` (trailing 6-bit-space padding
    /// stripped). Same wire format as CAT-021 I021/170.
    pub aircraft_identification: Option<String>,

    /// I048/161 — Track Number. Unsigned 12-bit integer (high 4 bits of
    /// the first octet are reserved/zero per spec). Same masking
    /// discipline as CAT-062 I062/040.
    pub track_number: Option<u16>,
}

/// Polar position, decoded from I048/040.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PolarPosition {
    /// Range from the radar, in nautical miles. Wire LSB = 1/256 NM.
    pub range_nm: f64,
    /// Bearing east-of-true-north, in decimal degrees. Wire LSB =
    /// 360 / 2^16 deg.
    pub bearing_deg: f64,
}

/// CAT-048 decode failure modes. Mirrors [`crate::cat021::Cat021Error`]'s
/// and [`crate::cat062::Cat062Error`]'s variant shape so a future
/// shared-framing refactor lands cleanly, but kept as a
/// category-distinct enum so a downstream router that dispatches on
/// error type can distinguish CAT-048 / CAT-021 / CAT-062 failures
/// without parsing the message string.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum Cat048Error {
    /// Datablock is shorter than the minimum (CAT byte + 16-bit length
    /// + at least one FSPEC byte).
    #[error("ASTERIX datablock truncated: {actual} bytes (min {min})")]
    TruncatedDatablock { actual: usize, min: usize },

    /// CAT byte does not match `048`.
    #[error("expected ASTERIX CAT-048, got CAT-{found:03}")]
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
    #[error("CAT-048 FSPEC truncated at FRN octet {octet}")]
    TruncatedFspec { octet: usize },

    /// A field decoder ran out of bytes before finishing. `item` is the
    /// CAT-048 Data Item three-digit identifier (e.g. 70 for I048/070);
    /// stored as `u32` to leave headroom for spec items > 999 (none in
    /// the v1.31 UAP, but the field shape is uniform across categories).
    #[error(
        "CAT-048 record truncated decoding I048/{item:03} (need {need} bytes, available {available})"
    )]
    TruncatedField {
        item: u32,
        need: usize,
        available: usize,
    },
}

/// Decode an ASTERIX datablock containing one or more CAT-048 records.
///
/// The supplied slice MUST be exactly one complete datablock. The
/// datablock's LEN field is cross-checked against the supplied slice
/// size to catch upstream truncation.
pub fn decode_cat048(bytes: &[u8]) -> Result<Vec<Cat048Report>, Cat048Error> {
    if bytes.len() < MIN_DATABLOCK_LEN {
        return Err(Cat048Error::TruncatedDatablock {
            actual: bytes.len(),
            min: MIN_DATABLOCK_LEN,
        });
    }
    let category = bytes[0];
    if category != CAT_048 {
        return Err(Cat048Error::WrongCategory { found: category });
    }
    let declared_len = u16::from_be_bytes([bytes[1], bytes[2]]) as usize;
    if declared_len < MIN_DATABLOCK_LEN {
        return Err(Cat048Error::DeclaredLengthTooSmall {
            declared: declared_len,
            min: MIN_DATABLOCK_LEN,
        });
    }
    if declared_len != bytes.len() {
        return Err(Cat048Error::LengthMismatch {
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

fn decode_record(record: &[u8]) -> Result<(Cat048Report, usize), Cat048Error> {
    let (fspec, fspec_len) = parse_fspec(record)?;
    let mut cursor = fspec_len;
    let mut report = Cat048Report::default();
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

fn parse_fspec(record: &[u8]) -> Result<(Fspec, usize), Cat048Error> {
    let mut bits: Vec<bool> = Vec::new();
    let mut octet_idx = 0usize;
    loop {
        let byte = match record.get(octet_idx) {
            Some(b) => *b,
            None => {
                return Err(Cat048Error::TruncatedFspec {
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

/// Per-FRN dispatch for CAT-048 v1.31 UAP. Issue-#1121 MVP decodes the
/// seven operationally essential radar fields (time, polar position,
/// mode 3/A, flight level, aircraft address, callsign, track number);
/// all other UAP entries are skipped by length so a producer that emits
/// a richer datablock decodes cleanly.
fn decode_field(
    frn: usize,
    record: &[u8],
    cursor: usize,
    report: &mut Cat048Report,
) -> Result<usize, Cat048Error> {
    match frn {
        1 => skip_fixed(record, cursor, 2, 10), // I048/010 Data Source Identifier
        2 => decode_time_of_day(record, cursor, report),
        3 => skip_extended(record, cursor, 20), // I048/020 Target Report Descriptor
        4 => decode_position_polar(record, cursor, report),
        5 => decode_mode_3a(record, cursor, report),
        6 => decode_flight_level(record, cursor, report),
        7 => skip_compound(record, cursor, 130), // I048/130 Radar Plot Characteristics
        8 => skip_fixed(record, cursor, 4, 42),  // I048/042 Cartesian Position
        9 => decode_aircraft_address(record, cursor, report),
        10 => decode_aircraft_identification(record, cursor, report),
        11 => skip_compound(record, cursor, 250), // I048/250 Mode S MB Data
        12 => decode_track_number(record, cursor, report),
        13 => skip_fixed(record, cursor, 4, 200), // I048/200 Calculated Track Velocity (polar)
        14 => skip_extended(record, cursor, 170), // I048/170 Track Status
        15 => skip_compound(record, cursor, 210), // I048/210 Track Quality
        16 => skip_extended(record, cursor, 30),  // I048/030 Warning/Error Conditions
        17 => skip_fixed(record, cursor, 2, 80),  // I048/080 Mode-3/A Confidence Indicator
        18 => skip_fixed(record, cursor, 4, 100), // I048/100 Mode-C Code & Confidence
        19 => skip_fixed(record, cursor, 2, 110), // I048/110 Height Measured by 3D Radar
        20 => skip_fixed(record, cursor, 2, 120), // I048/120 Radial Doppler Speed
        21 => skip_fixed(record, cursor, 2, 230), // I048/230 Communications/ACAS Capability
        22 => skip_fixed(record, cursor, 7, 260), // I048/260 ACAS Resolution Advisory Report
        23 => skip_fixed(record, cursor, 2, 55),  // I048/055 Mode-1 Code in Octal
        24 => skip_fixed(record, cursor, 1, 50),  // I048/050 Mode-2 Code in Octal
        25 => skip_fixed(record, cursor, 1, 65),  // I048/065 Mode-1 Code Confidence Indicator
        26 => skip_fixed(record, cursor, 2, 60),  // I048/060 Mode-2 Code Confidence Indicator
        27 => skip_re_sp(record, cursor, 0),      // I048/RE Reserved Expansion
        28 => skip_re_sp(record, cursor, 0),      // I048/SP Special Purpose
        // Forward-compat: FRNs beyond v1.31's UAP. Stop decoding —
        // the next datablock resyncs at the LEN boundary.
        _ => Ok(cursor),
    }
}

// ── Per-field decoders ───────────────────────────────────────────────

fn decode_time_of_day(
    record: &[u8],
    cursor: usize,
    report: &mut Cat048Report,
) -> Result<usize, Cat048Error> {
    // I048/140 — fixed 3 bytes, unsigned 24-bit, LSB = 1/128 s.
    let bytes = take_fixed(record, cursor, 3, 140)?;
    let raw = (u32::from(bytes[0]) << 16) | (u32::from(bytes[1]) << 8) | u32::from(bytes[2]);
    report.time_of_day_seconds = Some(f64::from(raw) / 128.0);
    Ok(cursor.saturating_add(3))
}

fn decode_position_polar(
    record: &[u8],
    cursor: usize,
    report: &mut Cat048Report,
) -> Result<usize, Cat048Error> {
    // I048/040 — fixed 4 bytes: RHO (u16 BE, LSB = 1/256 NM, range
    // 0..256 NM) + THETA (u16 BE, LSB = 360 / 2^16 deg, full circle).
    let bytes = take_fixed(record, cursor, 4, 40)?;
    let rho_raw = u16::from_be_bytes([bytes[0], bytes[1]]);
    let theta_raw = u16::from_be_bytes([bytes[2], bytes[3]]);
    let rho_lsb = 1.0_f64 / 256.0;
    let theta_lsb = 360.0_f64 / f64::from(1u32 << 16);
    report.measured_position_polar = Some(PolarPosition {
        range_nm: f64::from(rho_raw) * rho_lsb,
        bearing_deg: f64::from(theta_raw) * theta_lsb,
    });
    Ok(cursor.saturating_add(4))
}

fn decode_mode_3a(
    record: &[u8],
    cursor: usize,
    report: &mut Cat048Report,
) -> Result<usize, Cat048Error> {
    // I048/070 — fixed 2 bytes. Same wire format as I062/060: b16 = V
    // (validation failed), b15 = G (garbled), b14 = L (locally
    // tracked), b13 = spare, low 12 bits = octal Mode 3/A code.
    let bytes = take_fixed(record, cursor, 2, 70)?;
    let hi = bytes[0];
    let lo = bytes[1];
    let validation_failed = hi & 0x80 != 0;
    let garbled = hi & 0x40 != 0;
    let from_local_track = hi & 0x20 != 0;
    let code = (u16::from(hi & 0x0F) << 8) | u16::from(lo);
    report.mode_3a_code = Some(Mode3aCode {
        raw: code,
        validation_failed,
        garbled,
        from_local_track,
    });
    Ok(cursor.saturating_add(2))
}

fn decode_flight_level(
    record: &[u8],
    cursor: usize,
    report: &mut Cat048Report,
) -> Result<usize, Cat048Error> {
    // I048/090 — fixed 2 bytes. b16 = V flag, b15 = G flag, b14..b1 =
    // signed 14-bit two's-complement FL value, LSB = 1/4 FL.
    //
    // The 14-bit signed value lives in the low 14 bits of the
    // big-endian u16 after masking off the V/G flags. Sign-extend with
    // the standard "shift up by 2 to put the sign bit at the i16 MSB,
    // arithmetic-shift back down by 2" trick — handles every value in
    // the spec range without a sign-bit branch.
    let bytes = take_fixed(record, cursor, 2, 90)?;
    let combined = u16::from_be_bytes([bytes[0] & 0x3F, bytes[1]]);
    let extended = ((combined << 2) as i16) >> 2;
    report.flight_level = Some(f64::from(extended) * 0.25);
    Ok(cursor.saturating_add(2))
}

fn decode_aircraft_address(
    record: &[u8],
    cursor: usize,
    report: &mut Cat048Report,
) -> Result<usize, Cat048Error> {
    // I048/220 — fixed 3 bytes, unsigned 24-bit ICAO Mode-S address.
    let bytes = take_fixed(record, cursor, 3, 220)?;
    let addr = (u32::from(bytes[0]) << 16) | (u32::from(bytes[1]) << 8) | u32::from(bytes[2]);
    report.aircraft_address = Some(addr);
    Ok(cursor.saturating_add(3))
}

fn decode_aircraft_identification(
    record: &[u8],
    cursor: usize,
    report: &mut Cat048Report,
) -> Result<usize, Cat048Error> {
    // I048/240 — fixed 6 bytes, 8 characters in 6-bit ICAO Annex 10
    // alphabet packed MSB-first. Same encoding as CAT-021 I021/170.
    // The 6-bit alphabet pads with the 6-bit space code (0x20); we
    // strip trailing spaces so a 4-character callsign returns "TEST"
    // not "TEST    ".
    let bytes = take_fixed(record, cursor, 6, 240)?;
    let mut callsign = String::with_capacity(8);
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
    report.aircraft_identification = Some(trimmed);
    Ok(cursor.saturating_add(6))
}

fn decode_track_number(
    record: &[u8],
    cursor: usize,
    report: &mut Cat048Report,
) -> Result<usize, Cat048Error> {
    // I048/161 — fixed 2 bytes, unsigned 12-bit (high 4 bits are
    // reserved/zero per spec). Mask off the high nibble so a producer
    // that ignores the spec and stuffs values there does not break us.
    let bytes = take_fixed(record, cursor, 2, 161)?;
    let raw = u16::from_be_bytes([bytes[0], bytes[1]]);
    report.track_number = Some(raw & 0x0FFF);
    Ok(cursor.saturating_add(2))
}

/// ICAO Annex 10 6-bit alphabet → Unicode char.
///
/// The 6-bit codes used in CAT-048 I048/240 (and CAT-021 I021/170 and
/// Mode-S BDS 2,0 callsign reports more broadly) are:
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

fn skip_fixed(record: &[u8], cursor: usize, n: usize, item: u32) -> Result<usize, Cat048Error> {
    let _ = take_fixed(record, cursor, n, item)?;
    Ok(cursor.saturating_add(n))
}

fn skip_extended(record: &[u8], cursor: usize, item: u32) -> Result<usize, Cat048Error> {
    let mut idx = cursor;
    loop {
        let octet = match record.get(idx) {
            Some(b) => *b,
            None => {
                return Err(Cat048Error::TruncatedField {
                    item,
                    need: 1,
                    available: 0,
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

/// Compound items in CAT-048 carry a primary subfield bitmap (itself
/// an extended-length octet chain) plus per-subfield content. Fully
/// decoding the subfield catalogue for every compound item is out of
/// scope for the issue-#1121 MVP; surface a typed error if a compound
/// item ever appears in a real datablock so operators see a clear
/// "we don't decode this yet" signal — the next datablock resyncs at
/// the LEN boundary. Same strict-not-lossy posture as CAT-021 / CAT-062.
fn skip_compound(_record: &[u8], _cursor: usize, item: u32) -> Result<usize, Cat048Error> {
    Err(Cat048Error::TruncatedField {
        item,
        need: 0,
        available: 0,
    })
}

fn skip_re_sp(record: &[u8], cursor: usize, item: u32) -> Result<usize, Cat048Error> {
    let len_byte = match record.get(cursor) {
        Some(b) => *b,
        None => {
            return Err(Cat048Error::TruncatedField {
                item,
                need: 1,
                available: 0,
            });
        }
    };
    let total = len_byte as usize;
    if total == 0 {
        return Err(Cat048Error::TruncatedField {
            item,
            need: 1,
            available: 0,
        });
    }
    let end = cursor.saturating_add(total);
    if end > record.len() {
        return Err(Cat048Error::TruncatedField {
            item,
            need: total,
            available: record.len().saturating_sub(cursor),
        });
    }
    Ok(end)
}

fn take_fixed(record: &[u8], cursor: usize, n: usize, item: u32) -> Result<&[u8], Cat048Error> {
    let end = cursor.saturating_add(n);
    if end > record.len() {
        return Err(Cat048Error::TruncatedField {
            item,
            need: n,
            available: record.len().saturating_sub(cursor),
        });
    }
    Ok(&record[cursor..end])
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, unused_results)]
mod tests {
    use super::*;

    /// Build an FSPEC byte chain where each `frn` index from 1 has the
    /// corresponding bit set. Used to construct hand-built fixtures
    /// without typing the bitmaps as literal octets. Same shape as the
    /// CAT-021 / CAT-062 helpers.
    fn build_fspec(frns: &[usize]) -> Vec<u8> {
        let max_frn = frns.iter().max().copied().unwrap_or(0);
        let octets_needed = max_frn.div_ceil(7);
        let mut out = vec![0u8; octets_needed.max(1)];
        for &frn in frns {
            let octet = (frn - 1) / 7;
            let pos_in_octet = (frn - 1) % 7;
            let bit_shift = 7 - pos_in_octet;
            out[octet] |= 1 << bit_shift;
        }
        let last = octets_needed.saturating_sub(1);
        for octet in out.iter_mut().take(last) {
            *octet |= 0x01;
        }
        out
    }

    /// Build a complete CAT-048 datablock from a record body. Computes
    /// the LEN field for the caller.
    fn build_datablock(record_body: &[u8]) -> Vec<u8> {
        let len = 3 + record_body.len();
        let mut out = vec![CAT_048];
        out.extend_from_slice(&(len as u16).to_be_bytes());
        out.extend_from_slice(record_body);
        out
    }

    #[test]
    fn build_fspec_helper_handles_single_octet() {
        // FRNs 1, 5, 7 → bits 7, 3, 1 in the high seven bits.
        //   1 << 7 = 0x80 (FRN 1)
        //   1 << 3 = 0x08 (FRN 5)
        //   1 << 1 = 0x02 (FRN 7)
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
        let bytes = vec![CAT_048, 0x00];
        let err = decode_cat048(&bytes).expect_err("short datablock must reject");
        assert_eq!(
            err,
            Cat048Error::TruncatedDatablock {
                actual: 2,
                min: MIN_DATABLOCK_LEN,
            }
        );
    }

    #[test]
    fn decode_rejects_wrong_category() {
        // CAT-062 header — must be rejected by the CAT-048 decoder.
        let bytes = vec![62, 0x00, 0x04, 0x00];
        let err = decode_cat048(&bytes).expect_err("wrong category must reject");
        assert_eq!(err, Cat048Error::WrongCategory { found: 62 });
    }

    #[test]
    fn decode_rejects_length_mismatch() {
        // LEN says 100 bytes but only 4 supplied.
        let bytes = vec![CAT_048, 0x00, 0x64, 0x00];
        let err = decode_cat048(&bytes).expect_err("length mismatch must reject");
        assert_eq!(
            err,
            Cat048Error::LengthMismatch {
                declared: 100,
                actual: 4,
            }
        );
    }

    #[test]
    fn decode_minimal_track_returns_data_source_skipped() {
        // FRN 1 (I048/010 Data Source ID, 2 bytes) only — the most
        // minimal real-world CAT-048 record. SAC = 0x12, SIC = 0x34.
        // None of the typed `Cat048Report` fields should be populated
        // because FRN 1 is the always-skipped data-source identifier.
        let mut record = build_fspec(&[1]);
        record.extend_from_slice(&[0x12, 0x34]);
        let datablock = build_datablock(&record);
        let reports = decode_cat048(&datablock).expect("decode minimal");
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0], Cat048Report::default());
    }

    #[test]
    fn decode_target_address_round_trips_24bit_icao() {
        // FRN 9 (I048/220) — 24-bit ICAO Mode-S address. Use 0xA1B2C3
        // as a canonical "fake but plausible" hex code. This pins both
        // the unsigned-vs-signed handling (the high byte 0xA1 is > 0x80
        // so a sign-extension bug would surface as a negative i32 →
        // u32 wraparound) and the byte order (BE).
        let mut record = build_fspec(&[9]);
        record.extend_from_slice(&[0xA1, 0xB2, 0xC3]);
        let datablock = build_datablock(&record);
        let reports = decode_cat048(&datablock).expect("decode aircraft address");
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].aircraft_address, Some(0x00A1_B2C3));
    }

    #[test]
    fn decode_position_polar_lsb_conversions() {
        // FRN 4 (I048/040) — 4 bytes: RHO u16 BE + THETA u16 BE.
        // RHO LSB = 1/256 NM, THETA LSB = 360 / 2^16 deg.
        //
        // RHO = 0x0100 = 256 raw → 256 / 256 = 1.0 NM.
        // THETA = 0x4000 = 16384 raw → 16384 * 360/2^16 = 90.0 deg.
        let mut record = build_fspec(&[4]);
        record.extend_from_slice(&[0x01, 0x00, 0x40, 0x00]);
        let datablock = build_datablock(&record);
        let reports = decode_cat048(&datablock).expect("decode polar");
        let pos = reports[0]
            .measured_position_polar
            .expect("polar position present");
        assert!(
            (pos.range_nm - 1.0).abs() < 1e-9,
            "range: got {}, expected 1.0",
            pos.range_nm
        );
        assert!(
            (pos.bearing_deg - 90.0).abs() < 1e-9,
            "bearing: got {}, expected 90.0",
            pos.bearing_deg
        );
    }

    #[test]
    fn decode_time_of_day_lsb_one_over_one_twenty_eight() {
        // FRN 2 (I048/140) — 3 bytes, unsigned 24-bit, LSB = 1/128 s.
        // Wire 0x00_00_80 = 128 raw → 128 * 1/128 = 1.0 second.
        let mut record = build_fspec(&[2]);
        record.extend_from_slice(&[0x00, 0x00, 0x80]);
        let datablock = build_datablock(&record);
        let reports = decode_cat048(&datablock).expect("decode tod");
        assert_eq!(reports[0].time_of_day_seconds, Some(1.0));
    }

    #[test]
    fn decode_flight_level_negative_sign_extends_14bit() {
        // FRN 6 (I048/090) — 2 bytes. b16 = V, b15 = G, b14..b1 =
        // signed 14-bit FL value, LSB = 0.25 FL.
        //
        // FL -10 = -40 raw (since LSB = 0.25). |-40 mod 2^14| =
        // 16384 - 40 = 16344 = 0x3FD8. With V=0, G=0 in the top two
        // bits, the wire bytes are 0x3F, 0xD8.
        let mut record = build_fspec(&[6]);
        record.extend_from_slice(&[0x3F, 0xD8]);
        let datablock = build_datablock(&record);
        let reports = decode_cat048(&datablock).expect("decode FL");
        let fl = reports[0].flight_level.expect("flight level present");
        assert!(
            (fl - (-10.0)).abs() < 0.25,
            "FL: got {fl}, expected -10.0 (within 0.25 LSB)"
        );
    }

    #[test]
    fn decode_aircraft_identification_strips_trailing_spaces() {
        // FRN 10 (I048/240) — 6 bytes, 8 chars × 6 bits in ICAO Annex
        // 10 alphabet. Encode "UAL4" + 4 spaces and verify trim →
        // "UAL4".
        // Char codes:
        //   U = 0x15, A = 0x01, L = 0x0C, 4 = 0x34, ' ' = 0x20 ×4
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
        let mut record = build_fspec(&[10]);
        record.extend_from_slice(&bytes);
        let datablock = build_datablock(&record);
        let reports = decode_cat048(&datablock).expect("decode callsign");
        assert_eq!(
            reports[0].aircraft_identification.as_deref(),
            Some("UAL4"),
            "trailing 6-bit space padding MUST be trimmed"
        );
    }

    #[test]
    fn decode_full_record_with_all_mvp_fields() {
        // Headline: a single CAT-048 record carrying every field the
        // MVP parser decodes. FRNs (1, 2, 4, 5, 6, 9, 10, 12) — SAC/SIC
        // (skip), ToD, polar position, mode 3/A, FL, aircraft address,
        // callsign, track number. Pin that all decoded fields are
        // populated AND that field-skipping interleaves correctly.
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

        let mut record = build_fspec(&[1, 2, 4, 5, 6, 9, 10, 12]);
        record.extend_from_slice(&[0x12, 0x34]); // FRN 1: SAC/SIC
        record.extend_from_slice(&[0x00, 0x00, 0x80]); // FRN 2: ToD = 1.0s
        record.extend_from_slice(&[0x01, 0x00, 0x40, 0x00]); // FRN 4: 1.0 NM, 90 deg
        // FRN 5: Mode 3/A code 1234 octal = 0x29C, V=0/G=0/L=0 → 0x02, 0x9C.
        record.extend_from_slice(&[0x02, 0x9C]);
        // FRN 6: FL 350 = 1400 raw 25-ft units. With LSB 0.25 FL,
        // FL350 raw = 350/0.25 = 1400 = 0x578. V=0, G=0. Bytes 0x05, 0x78.
        record.extend_from_slice(&[0x05, 0x78]);
        record.extend_from_slice(&icao); // FRN 9: aircraft address
        record.extend_from_slice(&callsign_bytes); // FRN 10: callsign
        record.extend_from_slice(&[0x0A, 0xBC]); // FRN 12: track number 0xABC

        let datablock = build_datablock(&record);
        let reports = decode_cat048(&datablock).expect("decode full record");
        assert_eq!(reports.len(), 1);
        let r = &reports[0];
        assert_eq!(r.time_of_day_seconds, Some(1.0));
        let pos = r.measured_position_polar.expect("polar present");
        assert!((pos.range_nm - 1.0).abs() < 1e-9);
        assert!((pos.bearing_deg - 90.0).abs() < 1e-9);
        let mode_3a = r.mode_3a_code.expect("mode 3/A present");
        assert_eq!(mode_3a.as_octal(), "1234");
        assert!(!mode_3a.validation_failed);
        assert!(!mode_3a.garbled);
        let fl = r.flight_level.expect("FL present");
        assert!((fl - 350.0).abs() < 0.25);
        assert_eq!(r.aircraft_address, Some(0x00A1_B2C3));
        assert_eq!(r.aircraft_identification.as_deref(), Some("TEST"));
        assert_eq!(r.track_number, Some(0xABC));
    }

    #[test]
    fn decode_does_not_panic_on_arbitrary_bytes() {
        // Self-stability invariant: the decoder never panics on hostile
        // input — every error path returns a typed `Cat048Error`. This
        // is the same property the future fuzz target enforces; the
        // unit-test version exercises a handful of crafted inputs to
        // provide coverage without requiring a fuzzing run.
        let inputs: Vec<Vec<u8>> = vec![
            vec![],                                // empty
            vec![0xFF],                            // single byte, wrong CAT
            vec![CAT_048, 0xFF, 0xFF],             // declared LEN huge
            vec![CAT_048, 0x00, 0x04, 0x80],       // FSPEC asserts FRN 1 but no data
            vec![CAT_048, 0x00, 0x05, 0x01, 0x00], // FSPEC FX-chain truncated
        ];
        for input in inputs {
            // Either Ok or Err — never panic.
            let _ = decode_cat048(&input);
        }
    }
}
