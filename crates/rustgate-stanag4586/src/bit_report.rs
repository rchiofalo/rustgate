// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! STANAG 4586 LOI 2-3 BIT (Built-In Test) report message.
//!
//! Carries detailed per-subsystem fault information — the
//! longer-form companion to the 16-bit `bit_status_flags` summary
//! field in [`crate::system_state::SystemState`]. When a single bit
//! in `system_state.bit_status_flags` flips to `1`, the operator
//! needs to know *which* fault, *how severe*, *when it was first
//! detected*, and *when it was most recently observed* — a
//! `BitReport` carries exactly that detail for one subsystem at one
//! point in time.
//!
//! # Operational model
//!
//! `system_state` is the "summary stream" emitted at 1–2 Hz so an
//! operator's display can render an at-a-glance view of every
//! subsystem's go/no-go bit. `BitReport` is the "detail stream"
//! emitted **on transitions** — the platform sends one BIT report
//! per fault state change (a subsystem entering, escalating, or
//! clearing a fault). A typical mission carries a handful of BIT
//! reports total, not a continuous stream.
//!
//! Two BIT reports for the same subsystem with successive
//! `last_seen_unix_ms` values represent the operator-visible
//! "this fault is still active" signal — the equivalent of a
//! syslog line that the platform retransmits every N seconds while
//! the underlying fault persists.
//!
//! # Wire layout
//!
//! All multi-byte fields are big-endian (NATO convention). Total
//! frame size is fixed at [`BIT_REPORT_FRAME_LEN`] = 32 bytes.
//!
//! ```text
//! offset │ size │ field                   │ type
//! ───────┼──────┼─────────────────────────┼──────────────────────────
//!   0    │  4   │ vehicle_id              │ u32  big-endian
//!   4    │  1   │ subsystem_id            │ u8   enum value (see below)
//!   5    │  1   │ fault_severity          │ u8   enum value (see below)
//!   6    │  2   │ fault_code              │ u16  big-endian, vendor-specific
//!   8    │  8   │ detected_at_unix_ms     │ u64  big-endian (first detection)
//!  16    │  8   │ last_seen_unix_ms       │ u64  big-endian (most recent obs)
//!  24    │  8   │ reserved                │ zero-padded — must be 0 on encode
//! ```
//!
//! The reserved block is zero-filled on encode. The decoder does
//! NOT validate it — a future spec revision that allocates those
//! bytes (e.g. for vendor-specific extra context fields) stays
//! backward-compatible at the frame-length level.
//!
//! # Field semantics
//!
//! - `vehicle_id` — opaque platform identifier matching the
//!   `vehicle_id` carried by [`crate::vehicle_position::VehiclePosition`]
//!   and [`crate::system_state::SystemState`].
//! - `subsystem_id` — which subsystem reported the fault. The wire
//!   byte values match the named-bit constants in
//!   [`crate::system_state::BitStatusFlags`] so a deployment can
//!   correlate the summary bit with the detail report by direct
//!   byte comparison. See [`SubsystemId`].
//! - `fault_severity` — the platform's classification of how serious
//!   the fault is. See [`FaultSeverity`].
//! - `fault_code` — vendor-specific fault identifier within the
//!   subsystem. Not validated on decode (any 16-bit value is
//!   wire-valid; semantics are vendor-defined).
//! - `detected_at_unix_ms` — milliseconds since the Unix epoch when
//!   the fault was first observed.
//! - `last_seen_unix_ms` — milliseconds since the Unix epoch when
//!   the fault was most recently observed. For a fault that has
//!   cleared, the platform may either stop emitting BIT reports or
//!   emit a final report with `fault_severity = None` and the
//!   last-active timestamp here.

use bytes::{Buf, BufMut, BytesMut};

use crate::error::Stanag4586Error;

/// Fixed wire-format size of a BIT report frame.
pub const BIT_REPORT_FRAME_LEN: usize = 32;

// Wire-format field offsets. Kept private — callers should round-trip
// through `encode` / `decode` rather than poking individual fields.
const OFF_VEHICLE_ID: usize = 0;
const OFF_SUBSYSTEM_ID: usize = 4;
const OFF_FAULT_SEVERITY: usize = 5;
const OFF_FAULT_CODE: usize = 6;
const OFF_DETECTED_AT: usize = 8;
const OFF_LAST_SEEN: usize = 16;
// 24..32 reserved (8 bytes)

/// Which subsystem reported the fault.
///
/// The wire byte values are deliberately identical to the named-bit
/// constants in [`crate::system_state::BitStatusFlags`] so a deployment can correlate
/// `system_state.bit_status_flags` with `bit_report.subsystem_id`
/// by direct byte comparison — an operator UI that highlights the
/// `PROPULSION` bit in red can dispatch on
/// `subsystem_id == BitStatusFlags::PROPULSION as u8` to find the
/// matching detail report.
///
/// # Wire byte values
///
/// | byte (mask)  | variant            | matches `BitStatusFlags` |
/// |--------------|--------------------|--------------------------|
/// | `0x01`       | `Propulsion`       | `PROPULSION`             |
/// | `0x02`       | `Navigation`       | `NAVIGATION`             |
/// | `0x04`       | `Autopilot`        | `AUTOPILOT`              |
/// | `0x08`       | `Comms`            | `COMMS`                  |
/// | `0x10`       | `Payload`          | `PAYLOAD`                |
/// | `0x20`       | `Electrical`       | `ELECTRICAL`             |
/// | `0x40`       | `Hydraulic`        | `HYDRAULIC`              |
/// | `0x80`       | `FlightControls`   | `FLIGHT_CONTROLS`        |
/// | other        | `Other(byte)`      | future spec extension    |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SubsystemId {
    /// Propulsion (engine / motor / thruster).
    Propulsion,
    /// Navigation (GPS / IMU / INS).
    Navigation,
    /// Autopilot (FCS computer / control loop).
    Autopilot,
    /// Communications (radios, datalink).
    Comms,
    /// Payload (sensor turret, recorder).
    Payload,
    /// Electrical (battery, generator, bus).
    Electrical,
    /// Hydraulic (control surfaces, landing gear).
    Hydraulic,
    /// Flight controls (servos, actuators, control surfaces).
    FlightControls,
    /// Forward-compat catch-all for subsystem bytes the spec may
    /// allocate in a future revision.
    Other(u8),
}

impl SubsystemId {
    /// Map a wire byte into the typed enum.
    ///
    /// The byte values are the low byte of the corresponding u16
    /// mask in [`crate::system_state::BitStatusFlags`] — match by literal here for
    /// const-pattern compatibility, and pin the cross-frame
    /// equivalence via the unit test
    /// `subsystem_id_bytes_match_bit_status_flags_named_constants`
    /// so a future drift in either side fails locally.
    pub fn from_byte(b: u8) -> Self {
        match b {
            0x01 => Self::Propulsion,
            0x02 => Self::Navigation,
            0x04 => Self::Autopilot,
            0x08 => Self::Comms,
            0x10 => Self::Payload,
            0x20 => Self::Electrical,
            0x40 => Self::Hydraulic,
            0x80 => Self::FlightControls,
            _ => Self::Other(b),
        }
    }

    /// Map the typed enum back into its wire byte.
    pub fn to_byte(self) -> u8 {
        match self {
            Self::Propulsion => 0x01,
            Self::Navigation => 0x02,
            Self::Autopilot => 0x04,
            Self::Comms => 0x08,
            Self::Payload => 0x10,
            Self::Electrical => 0x20,
            Self::Hydraulic => 0x40,
            Self::FlightControls => 0x80,
            Self::Other(b) => b,
        }
    }
}

/// Severity classification for a BIT fault.
///
/// `None` is the spec-allowed sentinel for an informational BIT
/// report that carries timing/diagnostic detail without indicating
/// an active fault — useful when the platform wants to assert "this
/// subsystem was checked and is OK" or "this previously-active
/// fault has cleared".
///
/// # Wire byte values
///
/// | byte  | variant       |
/// |-------|---------------|
/// | `0x00`| `None`        |
/// | `0x01`| `Info`        |
/// | `0x02`| `Warning`     |
/// | `0x03`| `Error`       |
/// | `0x04`| `Critical`    |
/// | other | `Other(byte)` |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FaultSeverity {
    /// No active fault — informational report (cleared / OK ping).
    None,
    /// Informational; no operator action required.
    Info,
    /// Warning; operator should monitor.
    Warning,
    /// Error; subsystem is degraded, mission may need to abort.
    Error,
    /// Critical; immediate operator escalation, flight termination
    /// candidate.
    Critical,
    /// Forward-compat catch-all.
    Other(u8),
}

impl FaultSeverity {
    /// Map a wire byte into the typed enum.
    pub fn from_byte(b: u8) -> Self {
        match b {
            0x00 => Self::None,
            0x01 => Self::Info,
            0x02 => Self::Warning,
            0x03 => Self::Error,
            0x04 => Self::Critical,
            _ => Self::Other(b),
        }
    }

    /// Map the typed enum back into its wire byte.
    pub fn to_byte(self) -> u8 {
        match self {
            Self::None => 0x00,
            Self::Info => 0x01,
            Self::Warning => 0x02,
            Self::Error => 0x03,
            Self::Critical => 0x04,
            Self::Other(b) => b,
        }
    }
}

/// LOI 2-3 BIT (Built-In Test) report message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitReport {
    /// Platform identifier (matches
    /// [`crate::vehicle_position::VehiclePosition::vehicle_id`]).
    pub vehicle_id: u32,
    /// Which subsystem reported the fault.
    pub subsystem_id: SubsystemId,
    /// Severity classification.
    pub fault_severity: FaultSeverity,
    /// Vendor-specific fault code within the subsystem.
    pub fault_code: u16,
    /// Milliseconds since the Unix epoch when the fault was first
    /// observed.
    pub detected_at_unix_ms: u64,
    /// Milliseconds since the Unix epoch when the fault was most
    /// recently observed.
    pub last_seen_unix_ms: u64,
}

impl BitReport {
    /// Encode `self` into a freshly allocated `Vec<u8>`.
    pub fn encode_to_vec(&self) -> Vec<u8> {
        encode(self)
    }
}

/// Encode a BIT report frame into a freshly allocated `Vec<u8>`.
pub fn encode(msg: &BitReport) -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(BIT_REPORT_FRAME_LEN);
    encode_into(msg, &mut buf);
    buf.to_vec()
}

/// Encode appending to a caller-supplied [`BytesMut`].
pub fn encode_into(msg: &BitReport, buf: &mut BytesMut) {
    buf.put_u32(msg.vehicle_id);
    buf.put_u8(msg.subsystem_id.to_byte());
    buf.put_u8(msg.fault_severity.to_byte());
    buf.put_u16(msg.fault_code);
    buf.put_u64(msg.detected_at_unix_ms);
    buf.put_u64(msg.last_seen_unix_ms);
    buf.put_u64(0); // 8 reserved bytes
}

/// Decode a BIT report frame from a wire byte slice.
///
/// # Errors
///
/// - [`Stanag4586Error::FrameTooShort`] if `bytes.len() < 32`.
///
/// Unlike the sibling LOI 2-3 frames (`vehicle_position`,
/// `sensor_status`, `payload_status`, `system_state`), `BitReport`
/// has no floating-point fields and therefore no NaN-rejection or
/// range-check failure modes. The only structural failure is
/// truncation. Vendor-specific `fault_code` semantics are out of
/// scope for the codec; the typed enums absorb forward-compat
/// unknown bytes via `Other(byte)`.
pub fn decode(bytes: &[u8]) -> Result<BitReport, Stanag4586Error> {
    if bytes.len() < BIT_REPORT_FRAME_LEN {
        return Err(Stanag4586Error::FrameTooShort {
            actual: bytes.len(),
            expected: BIT_REPORT_FRAME_LEN,
        });
    }
    let mut cursor = &bytes[..BIT_REPORT_FRAME_LEN];
    let vehicle_id = cursor.get_u32();
    let subsystem_id = SubsystemId::from_byte(cursor.get_u8());
    let fault_severity = FaultSeverity::from_byte(cursor.get_u8());
    let fault_code = cursor.get_u16();
    let detected_at_unix_ms = cursor.get_u64();
    let last_seen_unix_ms = cursor.get_u64();
    let _ = cursor.get_u64(); // reserved

    debug_assert_eq!(cursor.remaining(), 0);
    let _ = OFF_VEHICLE_ID;
    let _ = OFF_SUBSYSTEM_ID;
    let _ = OFF_FAULT_SEVERITY;
    let _ = OFF_FAULT_CODE;
    let _ = OFF_DETECTED_AT;
    let _ = OFF_LAST_SEEN;

    Ok(BitReport {
        vehicle_id,
        subsystem_id,
        fault_severity,
        fault_code,
        detected_at_unix_ms,
        last_seen_unix_ms,
    })
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, unused_results)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::system_state::BitStatusFlags;

    fn fixture() -> BitReport {
        BitReport {
            vehicle_id: 0xCAFE_BABE,
            subsystem_id: SubsystemId::Comms,
            fault_severity: FaultSeverity::Error,
            fault_code: 0x1234,
            detected_at_unix_ms: 0xDEAD_BEEF_0000_0042,
            last_seen_unix_ms: 0xDEAD_BEEF_0000_0099,
        }
    }

    #[test]
    fn round_trip_full_fixture() {
        let msg = fixture();
        let bytes = encode(&msg);
        assert_eq!(bytes.len(), BIT_REPORT_FRAME_LEN);
        let decoded = decode(&bytes).expect("decode round-trip");
        assert_eq!(decoded, msg);
    }

    #[test]
    fn round_trip_zero_valued_fixture() {
        // All-zero is a valid frame: vehicle_id=0, subsystem and
        // severity default to Other(0) (forward-compat catch-all
        // preserves the byte), all other fields zero. The round-trip
        // must hold even at this corner.
        let msg = BitReport {
            vehicle_id: 0,
            subsystem_id: SubsystemId::Other(0),
            fault_severity: FaultSeverity::None,
            fault_code: 0,
            detected_at_unix_ms: 0,
            last_seen_unix_ms: 0,
        };
        let bytes = encode(&msg);
        assert_eq!(bytes, vec![0u8; BIT_REPORT_FRAME_LEN]);
        let decoded = decode(&bytes).expect("zero round-trip");
        assert_eq!(decoded, msg);
    }

    #[test]
    fn round_trip_max_valued_fixture() {
        // Pin the upper edges. A regression that swapped a u32 / u16
        // / u64 to a smaller type would silently truncate at the max
        // value and fail this test.
        let msg = BitReport {
            vehicle_id: u32::MAX,
            subsystem_id: SubsystemId::FlightControls,
            fault_severity: FaultSeverity::Critical,
            fault_code: u16::MAX,
            detected_at_unix_ms: u64::MAX,
            last_seen_unix_ms: u64::MAX,
        };
        let bytes = encode(&msg);
        let decoded = decode(&bytes).expect("max round-trip");
        assert_eq!(decoded, msg);
    }

    #[test]
    fn decode_known_fixture_matches_expected_bytes() {
        // Hand-built golden fixture that pins every field at its
        // documented byte offset. A regression that swapped to
        // little-endian could pass the proptest round-trip but
        // would still fail this check because the byte sequences
        // are pinned literally.
        let msg = BitReport {
            vehicle_id: 0x1122_3344,
            subsystem_id: SubsystemId::Navigation,  // 0x02
            fault_severity: FaultSeverity::Warning, // 0x02
            fault_code: 0xABCD,
            detected_at_unix_ms: 0x0123_4567_89AB_CDEF,
            last_seen_unix_ms: 0xFEDC_BA98_7654_3210,
        };
        let bytes = encode(&msg);
        let expected: [u8; BIT_REPORT_FRAME_LEN] = [
            // vehicle_id: 0x1122_3344
            0x11, 0x22, 0x33, 0x44, //
            // subsystem_id: 0x02 (Navigation)
            0x02, //
            // fault_severity: 0x02 (Warning)
            0x02, //
            // fault_code: 0xABCD
            0xAB, 0xCD, //
            // detected_at_unix_ms: 0x0123_4567_89AB_CDEF
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, //
            // last_seen_unix_ms: 0xFEDC_BA98_7654_3210
            0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, //
            // 8 reserved zero bytes
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(
            bytes.as_slice(),
            &expected[..],
            "encoded bytes must match the documented byte layout"
        );
        let decoded = decode(&expected).expect("golden decode");
        assert_eq!(decoded, msg);
    }

    #[test]
    fn decode_extra_trailing_bytes_are_ignored() {
        // A future protocol revision that appends a trailer must
        // not break consumers reading the documented prefix. Pin
        // that ANY trailer is tolerated.
        let msg = fixture();
        let mut bytes = encode(&msg);
        bytes.extend_from_slice(&[0xAA; 64]);
        let decoded = decode(&bytes).expect("trailing bytes must be ignored");
        assert_eq!(decoded, msg);
    }

    #[test]
    fn decode_truncation_sweep_returns_frame_too_short() {
        for &len in &[0_usize, 1, 4, 8, 16, 24, 31] {
            let bytes = vec![0u8; len];
            let err = decode(&bytes).expect_err("truncation must error");
            match err {
                Stanag4586Error::FrameTooShort { actual, expected } => {
                    assert_eq!(actual, len);
                    assert_eq!(expected, BIT_REPORT_FRAME_LEN);
                }
                other => panic!("expected FrameTooShort, got {other:?}"),
            }
        }
    }

    #[test]
    fn subsystem_id_known_variants_round_trip() {
        let cases: &[(SubsystemId, u8)] = &[
            (SubsystemId::Propulsion, 0x01),
            (SubsystemId::Navigation, 0x02),
            (SubsystemId::Autopilot, 0x04),
            (SubsystemId::Comms, 0x08),
            (SubsystemId::Payload, 0x10),
            (SubsystemId::Electrical, 0x20),
            (SubsystemId::Hydraulic, 0x40),
            (SubsystemId::FlightControls, 0x80),
        ];
        for (variant, byte) in cases {
            assert_eq!(variant.to_byte(), *byte);
            assert_eq!(SubsystemId::from_byte(*byte), *variant);
        }
    }

    #[test]
    fn subsystem_id_unknown_byte_preserved_as_other() {
        // Unknown bytes (not in the named-bit table) round-trip as
        // `Other(byte)` so a future spec revision allocating a new
        // subsystem stays decodable.
        for byte in [0x00, 0x03, 0x05, 0x42, 0xFF] {
            let id = SubsystemId::from_byte(byte);
            assert_eq!(id, SubsystemId::Other(byte));
            assert_eq!(id.to_byte(), byte);
        }
    }

    #[test]
    fn fault_severity_known_variants_round_trip() {
        let cases: &[(FaultSeverity, u8)] = &[
            (FaultSeverity::None, 0x00),
            (FaultSeverity::Info, 0x01),
            (FaultSeverity::Warning, 0x02),
            (FaultSeverity::Error, 0x03),
            (FaultSeverity::Critical, 0x04),
        ];
        for (variant, byte) in cases {
            assert_eq!(variant.to_byte(), *byte);
            assert_eq!(FaultSeverity::from_byte(*byte), *variant);
        }
    }

    #[test]
    fn fault_severity_unknown_byte_preserved_as_other() {
        for byte in [0x05, 0x42, 0xFE, 0xFF] {
            let s = FaultSeverity::from_byte(byte);
            assert_eq!(s, FaultSeverity::Other(byte));
            assert_eq!(s.to_byte(), byte);
        }
    }

    #[test]
    fn subsystem_id_bytes_match_bit_status_flags_named_constants() {
        // Cross-frame contract: a `bit_report.subsystem_id.to_byte()`
        // value MUST equal the corresponding `BitStatusFlags::FOO`
        // mask so an operator UI can correlate the summary bit and
        // the detail report by direct byte comparison without an
        // intermediate lookup table. A regression that drifted one
        // of these out of sync would silently break the operator's
        // bit-to-detail correlation logic.
        assert_eq!(
            SubsystemId::Propulsion.to_byte(),
            BitStatusFlags::PROPULSION as u8
        );
        assert_eq!(
            SubsystemId::Navigation.to_byte(),
            BitStatusFlags::NAVIGATION as u8
        );
        assert_eq!(
            SubsystemId::Autopilot.to_byte(),
            BitStatusFlags::AUTOPILOT as u8
        );
        assert_eq!(SubsystemId::Comms.to_byte(), BitStatusFlags::COMMS as u8);
        assert_eq!(
            SubsystemId::Payload.to_byte(),
            BitStatusFlags::PAYLOAD as u8
        );
        assert_eq!(
            SubsystemId::Electrical.to_byte(),
            BitStatusFlags::ELECTRICAL as u8
        );
        assert_eq!(
            SubsystemId::Hydraulic.to_byte(),
            BitStatusFlags::HYDRAULIC as u8
        );
        assert_eq!(
            SubsystemId::FlightControls.to_byte(),
            BitStatusFlags::FLIGHT_CONTROLS as u8
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn round_trip_via_proptest(
            vehicle_id in any::<u32>(),
            subsys_byte in any::<u8>(),
            severity_byte in any::<u8>(),
            fault_code in any::<u16>(),
            detected_at_unix_ms in any::<u64>(),
            last_seen_unix_ms in any::<u64>(),
        ) {
            let msg = BitReport {
                vehicle_id,
                subsystem_id: SubsystemId::from_byte(subsys_byte),
                fault_severity: FaultSeverity::from_byte(severity_byte),
                fault_code,
                detected_at_unix_ms,
                last_seen_unix_ms,
            };
            let bytes = encode(&msg);
            prop_assert_eq!(bytes.len(), BIT_REPORT_FRAME_LEN);
            let decoded = decode(&bytes).expect("decode round-trip");
            prop_assert_eq!(decoded, msg);
        }
    }
}
