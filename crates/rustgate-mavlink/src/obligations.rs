// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! MAVLink-specific actuators for the authz obligation chain (ADR 0020 §7).
//!
//! The router's Policy Enforcement Point applies authz obligations to a
//! message before egress. For CoT/XML payloads the redaction obligations
//! (`MaskPoint`, `MaskPayload`) are actuated by `rustgate-cot`; for
//! MAVLink frames they are actuated here, on the binary wire form:
//!
//! - **`MaskPoint`** → [`mask_position`] zeroes the `lat` / `lon` / `alt`
//!   / `relative_alt` fields of a `GLOBAL_POSITION_INT` (MSG_ID 33) frame.
//! - **`MaskPayload`** → [`mask_as_heartbeat`] replaces the frame with a
//!   benign zeroed `HEARTBEAT` (MSG_ID 0), preserving only the system /
//!   component IDs so the recipient still sees a live-but-contentless
//!   presence ping.
//! - **`MaskCommand`** (new in ADR 0020) → the PEP refuses to forward
//!   actuation frames; [`is_command_frame`] classifies
//!   `COMMAND_LONG` / `COMMAND_INT` / `MANUAL_CONTROL`.
//!
//! # CRC discipline
//!
//! Masking mutates the payload, so [`mask_position`] recomputes the
//! frame's CRC-16/MCRF4XX trailer and [`mask_as_heartbeat`] computes a
//! fresh one — the emitted frame is always CRC-valid. Any v2 signature
//! trailer the input carried is left in place but is now stale; the
//! egress re-signing path (`SigningKeyStore::resign`) is responsible for
//! re-signing a masked frame before it is delivered to another MAVLink
//! sink. When the masked frame is delivered to a non-MAVLink session it
//! rides as an opaque payload and neither CRC nor signature is consulted.

use bytes::Bytes;

use crate::crc_extra::crc_extra;
use crate::entity::GLOBAL_POSITION_INT_MSG_ID;
use crate::frame::{HEARTBEAT_MSG_ID, MAVLINK_V1_MAGIC, MAVLINK_V2_MAGIC};

/// `COMMAND_LONG` — MSG_ID 76. Carries a commanded action with up to
/// seven float parameters (arm/disarm, takeoff, mode change, …).
pub const COMMAND_LONG_MSG_ID: u32 = 76;

/// `COMMAND_INT` — MSG_ID 75. Like `COMMAND_LONG` but with scaled-integer
/// position parameters.
pub const COMMAND_INT_MSG_ID: u32 = 75;

/// `MANUAL_CONTROL` — MSG_ID 69. Direct joystick / stick-input control.
pub const MANUAL_CONTROL_MSG_ID: u32 = 69;

/// v2 header size: STX + LEN + INCOMPAT + COMPAT + SEQ + SYSID + COMPID + MSGID(3).
const V2_HEADER_LEN: usize = 10;
/// v1 header size: STX + LEN + SEQ + SYSID + COMPID + MSGID.
const V1_HEADER_LEN: usize = 6;
/// CRC-16/MCRF4XX trailer size.
const CRC_LEN: usize = 2;

/// HEARTBEAT payload size on the wire (custom_mode u32, type, autopilot,
/// base_mode, system_status, mavlink_version).
const HEARTBEAT_PAYLOAD_LEN: usize = 9;

/// GLOBAL_POSITION_INT position region: `lat`+`lon`+`alt`+`relative_alt`,
/// four `i32` fields starting at payload offset 4 (`time_boot_ms` is the
/// first field, offsets 0..4).
const GPI_POSITION_OFFSET: usize = 4;
const GPI_POSITION_LEN: usize = 16;

/// A minimal parsed view of a MAVLink frame header, enough to locate the
/// message ID and the CRC.
struct Header {
    system_id: u8,
    component_id: u8,
    msg_id: u32,
    payload_offset: usize,
    wire_payload_len: usize,
}

impl Header {
    /// Byte offset of the 2-byte CRC trailer.
    fn crc_offset(&self) -> usize {
        self.payload_offset + self.wire_payload_len
    }
}

/// Parse just enough of a frame header to find the message ID and CRC.
///
/// Returns `None` for an unrecognised magic byte or a frame shorter than
/// its own declared length (CRC trailer must be present).
fn parse_header(frame: &[u8]) -> Option<Header> {
    let (payload_offset, system_id, component_id, msg_id) = match frame.first().copied()? {
        MAVLINK_V1_MAGIC => {
            if frame.len() < V1_HEADER_LEN {
                return None;
            }
            (V1_HEADER_LEN, frame[3], frame[4], u32::from(frame[5]))
        }
        MAVLINK_V2_MAGIC => {
            if frame.len() < V2_HEADER_LEN {
                return None;
            }
            let msg_id =
                u32::from(frame[7]) | (u32::from(frame[8]) << 8) | (u32::from(frame[9]) << 16);
            (V2_HEADER_LEN, frame[5], frame[6], msg_id)
        }
        _ => return None,
    };

    let wire_payload_len = usize::from(frame[1]);
    let header = Header {
        system_id,
        component_id,
        msg_id,
        payload_offset,
        wire_payload_len,
    };
    // The CRC trailer must fit within the frame.
    if frame.len() < header.crc_offset() + CRC_LEN {
        return None;
    }
    Some(header)
}

/// CRC-16/MCRF4XX (the MAVLink frame checksum) over `data`, finishing
/// with the per-message `crc_extra` byte.
///
/// Accumulator matches the reference `crc_accumulate` from the MAVLink
/// spec / pymavlink: init `0xFFFF`, reflected, no final XOR.
fn crc16_mcrf4xx(data: &[u8], extra: u8) -> u16 {
    let mut crc: u16 = 0xFFFF;
    let mut accumulate = |byte: u8| {
        let mut tmp = byte ^ (crc as u8);
        tmp ^= tmp << 4;
        let tmp = u16::from(tmp);
        crc = (crc >> 8) ^ (tmp << 8) ^ (tmp << 3) ^ (tmp >> 4);
    };
    for &b in data {
        accumulate(b);
    }
    accumulate(extra);
    crc
}

/// Whether `frame` is a MAVLink actuation/command frame that the
/// `MaskCommand` obligation must refuse to forward.
///
/// Recognises `COMMAND_LONG` (76), `COMMAND_INT` (75), and
/// `MANUAL_CONTROL` (69). Returns `false` for any frame that cannot be
/// parsed — the caller decides the fail-closed posture for unparseable
/// input.
#[must_use]
pub fn is_command_frame(frame: &[u8]) -> bool {
    matches!(
        parse_header(frame).map(|h| h.msg_id),
        Some(COMMAND_LONG_MSG_ID | COMMAND_INT_MSG_ID | MANUAL_CONTROL_MSG_ID)
    )
}

/// The message ID of `frame`, if its header parses.
#[must_use]
pub fn frame_msg_id(frame: &[u8]) -> Option<u32> {
    parse_header(frame).map(|h| h.msg_id)
}

/// Zero the position fields of a `GLOBAL_POSITION_INT` frame and recompute
/// its CRC.
///
/// Returns `Some(masked_frame)` when `frame` is a parseable
/// `GLOBAL_POSITION_INT` (MSG_ID 33); the returned frame has `lat`,
/// `lon`, `alt`, and `relative_alt` zeroed and a freshly computed
/// CRC-16/MCRF4XX trailer. Returns `None` when the frame is not a
/// position report (nothing to mask) or cannot be parsed — the caller
/// then chooses whether to forward unmodified or escalate to
/// [`mask_as_heartbeat`].
#[must_use]
pub fn mask_position(frame: &[u8]) -> Option<Bytes> {
    let header = parse_header(frame)?;
    if header.msg_id != GLOBAL_POSITION_INT_MSG_ID {
        return None;
    }
    let extra = crc_extra(GLOBAL_POSITION_INT_MSG_ID)?;

    let mut buf = frame.to_vec();
    // Zero whichever of the 16 position bytes are actually present. MAVLink
    // v2 may truncate trailing zero bytes, so the on-wire payload can be
    // shorter than the full struct; any absent field is already zero.
    let start = header.payload_offset + GPI_POSITION_OFFSET;
    let end = (start + GPI_POSITION_LEN).min(header.crc_offset());
    if start < end {
        buf[start..end].fill(0);
    }

    // Recompute the CRC over LEN..end-of-payload + crc_extra.
    let crc = crc16_mcrf4xx(&buf[1..header.crc_offset()], extra);
    let crc_at = header.crc_offset();
    buf[crc_at] = (crc & 0xFF) as u8;
    buf[crc_at + 1] = (crc >> 8) as u8;

    Some(Bytes::from(buf))
}

/// Build a benign zeroed `HEARTBEAT` (MSG_ID 0) frame that replaces a
/// redacted payload.
///
/// The emitted frame is a well-formed MAVLink **v1** HEARTBEAT: a
/// universally understood presence ping with a zeroed payload and a valid
/// CRC. The originating frame's system and component IDs are preserved so
/// a fleet view still attributes the heartbeat to the right vehicle; if
/// the input cannot be parsed, IDs default to 0. v1 is chosen so the
/// placeholder carries no signature obligations of its own.
#[must_use]
pub fn mask_as_heartbeat(frame: &[u8]) -> Bytes {
    let (system_id, component_id) = parse_header(frame)
        .map(|h| (h.system_id, h.component_id))
        .unwrap_or((0, 0));

    // crc_extra(0) is always present (HEARTBEAT is pinned in the table);
    // fall back defensively to 50 (the spec value) if it were ever absent.
    let extra = crc_extra(HEARTBEAT_MSG_ID).unwrap_or(50);

    let mut buf = Vec::with_capacity(V1_HEADER_LEN + HEARTBEAT_PAYLOAD_LEN + CRC_LEN);
    buf.push(MAVLINK_V1_MAGIC); // STX
    buf.push(HEARTBEAT_PAYLOAD_LEN as u8); // LEN
    buf.push(0); // SEQ
    buf.push(system_id); // SYSID
    buf.push(component_id); // COMPID
    buf.push(HEARTBEAT_MSG_ID as u8); // MSGID
    buf.extend(std::iter::repeat_n(0u8, HEARTBEAT_PAYLOAD_LEN)); // zeroed payload

    let crc = crc16_mcrf4xx(&buf[1..], extra);
    buf.push((crc & 0xFF) as u8);
    buf.push((crc >> 8) as u8);

    Bytes::from(buf)
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, unused_results)]
mod tests {
    use super::*;

    /// Build a CRC-valid v2 GLOBAL_POSITION_INT frame with the given
    /// position values (unsigned, no signature trailer).
    fn gpi_frame(lat: i32, lon: i32, alt: i32) -> Vec<u8> {
        let mut payload = vec![0u8; 28];
        payload[0..4].copy_from_slice(&1234u32.to_le_bytes()); // time_boot_ms
        payload[4..8].copy_from_slice(&lat.to_le_bytes());
        payload[8..12].copy_from_slice(&lon.to_le_bytes());
        payload[12..16].copy_from_slice(&alt.to_le_bytes());
        payload[16..20].copy_from_slice(&77i32.to_le_bytes()); // relative_alt

        let mut buf = vec![
            MAVLINK_V2_MAGIC,
            payload.len() as u8, // LEN
            0,                   // INCOMPAT
            0,                   // COMPAT
            0,                   // SEQ
            7,                   // SYSID
            1,                   // COMPID
            (GLOBAL_POSITION_INT_MSG_ID & 0xFF) as u8,
            0,
            0,
        ];
        buf.extend_from_slice(&payload);
        let extra = crc_extra(GLOBAL_POSITION_INT_MSG_ID).unwrap();
        let crc = crc16_mcrf4xx(&buf[1..], extra);
        buf.push((crc & 0xFF) as u8);
        buf.push((crc >> 8) as u8);
        buf
    }

    fn cmd_frame(msg_id: u32) -> Vec<u8> {
        let mut buf = vec![
            MAVLINK_V2_MAGIC,
            0, // LEN (truncated to zero payload)
            0,
            0,
            0,
            3,
            1,
            (msg_id & 0xFF) as u8,
            ((msg_id >> 8) & 0xFF) as u8,
            ((msg_id >> 16) & 0xFF) as u8,
        ];
        buf.extend_from_slice(&[0, 0]); // CRC (opaque for these tests)
        buf
    }

    #[test]
    fn is_command_frame_recognises_actuation_ids() {
        assert!(is_command_frame(&cmd_frame(COMMAND_LONG_MSG_ID)));
        assert!(is_command_frame(&cmd_frame(COMMAND_INT_MSG_ID)));
        assert!(is_command_frame(&cmd_frame(MANUAL_CONTROL_MSG_ID)));
    }

    #[test]
    fn is_command_frame_false_for_telemetry_and_garbage() {
        assert!(!is_command_frame(&cmd_frame(GLOBAL_POSITION_INT_MSG_ID)));
        assert!(!is_command_frame(&cmd_frame(HEARTBEAT_MSG_ID)));
        assert!(!is_command_frame(&[0x00, 0x01, 0x02]));
        assert!(!is_command_frame(&[]));
    }

    #[test]
    fn mask_position_zeroes_coordinates_and_keeps_crc_valid() {
        let frame = gpi_frame(377_000_000, -1_223_000_000, 100_000);
        let masked = mask_position(&frame).expect("position frame should mask");

        let header = parse_header(&masked).unwrap();
        let p = header.payload_offset;
        // time_boot_ms preserved.
        assert_eq!(&masked[p..p + 4], &1234u32.to_le_bytes());
        // lat/lon/alt/relative_alt zeroed.
        assert_eq!(&masked[p + 4..p + 20], &[0u8; 16]);

        // CRC re-validates.
        let extra = crc_extra(GLOBAL_POSITION_INT_MSG_ID).unwrap();
        let crc = crc16_mcrf4xx(&masked[1..header.crc_offset()], extra);
        assert_eq!(masked[header.crc_offset()], (crc & 0xFF) as u8);
        assert_eq!(masked[header.crc_offset() + 1], (crc >> 8) as u8);
    }

    #[test]
    fn mask_position_returns_none_for_non_position_frame() {
        assert!(mask_position(&cmd_frame(COMMAND_LONG_MSG_ID)).is_none());
        assert!(mask_position(&[0xFD, 0x00]).is_none());
    }

    #[test]
    fn mask_as_heartbeat_is_a_valid_v1_heartbeat() {
        let frame = gpi_frame(1, 2, 3);
        let hb = mask_as_heartbeat(&frame);

        assert_eq!(hb[0], MAVLINK_V1_MAGIC);
        let header = parse_header(&hb).unwrap();
        assert_eq!(header.msg_id, HEARTBEAT_MSG_ID);
        // sys/comp preserved from the source frame.
        assert_eq!(header.system_id, 7);
        assert_eq!(header.component_id, 1);
        // payload zeroed.
        assert_eq!(
            &hb[6..6 + HEARTBEAT_PAYLOAD_LEN],
            &[0u8; HEARTBEAT_PAYLOAD_LEN]
        );
        // CRC valid.
        let extra = crc_extra(HEARTBEAT_MSG_ID).unwrap();
        let crc = crc16_mcrf4xx(&hb[1..header.crc_offset()], extra);
        assert_eq!(hb[header.crc_offset()], (crc & 0xFF) as u8);
        assert_eq!(hb[header.crc_offset() + 1], (crc >> 8) as u8);
    }

    #[test]
    fn mask_as_heartbeat_defaults_ids_for_unparseable_input() {
        let hb = mask_as_heartbeat(&[0x00, 0x01]);
        let header = parse_header(&hb).unwrap();
        assert_eq!(header.system_id, 0);
        assert_eq!(header.component_id, 0);
        assert_eq!(header.msg_id, HEARTBEAT_MSG_ID);
    }

    #[test]
    fn crc16_is_deterministic_and_nonzero() {
        let a = crc16_mcrf4xx(
            b"\x09\x00\x07\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            50,
        );
        let b = crc16_mcrf4xx(
            b"\x09\x00\x07\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            50,
        );
        assert_eq!(a, b);
        // A different extra byte yields a different CRC.
        assert_ne!(
            a,
            crc16_mcrf4xx(
                b"\x09\x00\x07\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                51
            )
        );
    }
}
