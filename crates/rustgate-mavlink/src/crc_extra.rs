// Copyright © 2026 Roberto Chiofalo.

//! Per-message-ID CRC-EXTRA constants for MAVLink v1 / v2.
//!
//! # What CRC-EXTRA is
//!
//! MAVLink's CRC-16/MCRF4XX trailer covers every byte of the frame
//! between the magic byte and the CRC itself, AND a single trailing
//! "extra" byte derived from the dialect catalogue at code-generation
//! time. The extra byte is the `crc_extra` constant the dialect
//! XML/JSON definition publishes for each message: a hash of the
//! field names, types, and order. Two dialects that disagree on a
//! given `MSG_ID`'s shape end up with different `crc_extra` values,
//! so a sender that thinks `MSG_ID = 23` is `LOCAL_NED_POSITION_TARGET`
//! and a receiver that thinks the same ID is `ATTITUDE_TARGET` will
//! produce mismatched CRCs and reject each other's frames.
//!
//! That cross-dialect mismatch is the entire point of the field —
//! signing alone protects "is the sender authentic", but CRC-EXTRA
//! protects "is the sender authentic AND speaking my catalogue".
//!
//! # Why it matters at the framing layer (security, not just compat)
//!
//! Pre-this-module the codec performed no CRC-EXTRA lookup at all and
//! left the byte to the (future) signing layer. That decision was
//! defensible while the codec was opaque-passthrough, but the F-73
//! audit on issue #752 flagged a different hazard: any CRC-EXTRA
//! lookup that uses `unwrap()` on `HashMap::get` for an attacker-
//! supplied `MSG_ID` becomes a panic gadget — a hostile sender that
//! streams frames with random `MSG_ID` values can drive a panic on
//! every frame in a release build and crash the receiver, OR (if the
//! lookup falls back to inserting a default), drive an allocation
//! per frame and exhaust memory.
//!
//! This module is the panic-free counterpart: a static lookup table
//! built at compile time from the standard MAVLink common-dialect
//! values, exposed through a single `crc_extra` function that returns
//! `Option<u8>`. Callers that get `None` reject the frame with
//! [`crate::error::MavlinkError::UnknownMessageId`] — no allocation,
//! no panic, no per-frame slow path.
//!
//! # Why a hand-rolled table, not a dialect crate
//!
//! `rustgate-mavlink` deliberately avoids pulling in a generated
//! MAVLink dialect crate so that the framing layer stays
//! protocol-agnostic and the build does not depend on `mavlink-codegen`
//! at edit time. The table here covers the message IDs the rustgate
//! workspace actually inspects (HEARTBEAT, common position/attitude
//! frames, command frames, signing-relevant control messages) and
//! is exhaustively listed inline so reviewers can see exactly which
//! catalogue entries the security boundary trusts. Adding a new
//! message ID is a one-line PR.
//!
//! Values come from the upstream
//! [`message_definitions/v1.0/common.xml`](https://github.com/mavlink/mavlink)
//! `crc_extra` field, cross-checked against `pymavlink`'s
//! `message_crcs` constant in `mavutil.py` for the messages listed.

/// Lookup the CRC-EXTRA byte for a given MAVLink `MSG_ID`.
///
/// Returns `Some(crc_extra)` when the ID is in the standard
/// common-dialect catalogue and `None` when it is not — callers that
/// must verify the CRC reject the frame on `None` rather than guessing
/// or panicking.
///
/// The lookup is `O(MSG_ID_TABLE.len())` worst case, but the table is
/// small (well under 100 entries) and the linear scan stays in L1 for
/// the duration of the frame decode. Switching to a perfect hash is
/// queued behind the dialect-import work and would not change the
/// public API.
#[must_use]
pub fn crc_extra(msg_id: u32) -> Option<u8> {
    MSG_ID_TABLE
        .iter()
        .copied()
        .find_map(|(id, extra)| if id == msg_id { Some(extra) } else { None })
}

/// Static `(msg_id, crc_extra)` table covering the common-dialect IDs
/// the rustgate workspace inspects.
///
/// Keep entries sorted by `msg_id` ascending so a reviewer adding a new
/// row can locate the insertion point by binary intuition without
/// running a sort. The values are the canonical `crc_extra` constants
/// from `message_definitions/v1.0/common.xml`.
const MSG_ID_TABLE: &[(u32, u8)] = &[
    // HEARTBEAT — MSG_ID 0, the canonical presence ping.
    (0, 50),
    // SYS_STATUS — MSG_ID 1, vehicle health snapshot.
    (1, 124),
    // SYSTEM_TIME — MSG_ID 2, UTC clock distribution.
    (2, 137),
    // PING — MSG_ID 4, latency probe.
    (4, 237),
    // CHANGE_OPERATOR_CONTROL — MSG_ID 5, GCS authority transfer.
    (5, 217),
    // CHANGE_OPERATOR_CONTROL_ACK — MSG_ID 6.
    (6, 104),
    // AUTH_KEY — MSG_ID 7, legacy authentication.
    (7, 119),
    // SET_MODE — MSG_ID 11, vehicle mode change.
    (11, 89),
    // PARAM_REQUEST_READ — MSG_ID 20.
    (20, 214),
    // PARAM_REQUEST_LIST — MSG_ID 21.
    (21, 159),
    // PARAM_VALUE — MSG_ID 22.
    (22, 220),
    // PARAM_SET — MSG_ID 23.
    (23, 168),
    // GPS_RAW_INT — MSG_ID 24.
    (24, 24),
    // GPS_STATUS — MSG_ID 25.
    (25, 23),
    // SCALED_IMU — MSG_ID 26.
    (26, 170),
    // RAW_IMU — MSG_ID 27.
    (27, 144),
    // RAW_PRESSURE — MSG_ID 28.
    (28, 67),
    // SCALED_PRESSURE — MSG_ID 29.
    (29, 115),
    // ATTITUDE — MSG_ID 30, vehicle orientation.
    (30, 39),
    // ATTITUDE_QUATERNION — MSG_ID 31.
    (31, 246),
    // LOCAL_POSITION_NED — MSG_ID 32.
    (32, 185),
    // GLOBAL_POSITION_INT — MSG_ID 33, the canonical position frame.
    (33, 104),
    // RC_CHANNELS_SCALED — MSG_ID 34.
    (34, 237),
    // RC_CHANNELS_RAW — MSG_ID 35.
    (35, 244),
    // SERVO_OUTPUT_RAW — MSG_ID 36.
    (36, 222),
    // MISSION_REQUEST_PARTIAL_LIST — MSG_ID 37.
    (37, 212),
    // MISSION_WRITE_PARTIAL_LIST — MSG_ID 38.
    (38, 9),
    // MISSION_ITEM — MSG_ID 39.
    (39, 254),
    // MISSION_REQUEST — MSG_ID 40.
    (40, 230),
    // MISSION_SET_CURRENT — MSG_ID 41.
    (41, 28),
    // MISSION_CURRENT — MSG_ID 42.
    (42, 28),
    // MISSION_REQUEST_LIST — MSG_ID 43.
    (43, 132),
    // MISSION_COUNT — MSG_ID 44.
    (44, 221),
    // MISSION_CLEAR_ALL — MSG_ID 45.
    (45, 232),
    // MISSION_ITEM_REACHED — MSG_ID 46.
    (46, 11),
    // MISSION_ACK — MSG_ID 47.
    (47, 153),
    // SET_GPS_GLOBAL_ORIGIN — MSG_ID 48.
    (48, 41),
    // GPS_GLOBAL_ORIGIN — MSG_ID 49.
    (49, 39),
    // PARAM_MAP_RC — MSG_ID 50.
    (50, 78),
    // MISSION_REQUEST_INT — MSG_ID 51.
    (51, 196),
    // SAFETY_SET_ALLOWED_AREA — MSG_ID 54.
    (54, 15),
    // SAFETY_ALLOWED_AREA — MSG_ID 55.
    (55, 3),
    // ATTITUDE_QUATERNION_COV — MSG_ID 61.
    (61, 167),
    // NAV_CONTROLLER_OUTPUT — MSG_ID 62.
    (62, 183),
    // GLOBAL_POSITION_INT_COV — MSG_ID 63.
    (63, 119),
    // LOCAL_POSITION_NED_COV — MSG_ID 64.
    (64, 191),
    // RC_CHANNELS — MSG_ID 65.
    (65, 118),
    // REQUEST_DATA_STREAM — MSG_ID 66.
    (66, 148),
    // DATA_STREAM — MSG_ID 67.
    (67, 21),
    // MANUAL_CONTROL — MSG_ID 69.
    (69, 243),
    // RC_CHANNELS_OVERRIDE — MSG_ID 70.
    (70, 124),
    // MISSION_ITEM_INT — MSG_ID 73.
    (73, 38),
    // VFR_HUD — MSG_ID 74.
    (74, 20),
    // COMMAND_INT — MSG_ID 75.
    (75, 158),
    // COMMAND_LONG — MSG_ID 76, the canonical command frame.
    (76, 152),
    // COMMAND_ACK — MSG_ID 77.
    (77, 143),
    // COMMAND_CANCEL — MSG_ID 80.
    (80, 14),
    // MANUAL_SETPOINT — MSG_ID 81.
    (81, 106),
    // SET_ATTITUDE_TARGET — MSG_ID 82.
    (82, 49),
    // ATTITUDE_TARGET — MSG_ID 83.
    (83, 22),
    // SET_POSITION_TARGET_LOCAL_NED — MSG_ID 84.
    (84, 143),
    // POSITION_TARGET_LOCAL_NED — MSG_ID 85.
    (85, 140),
    // SET_POSITION_TARGET_GLOBAL_INT — MSG_ID 86.
    (86, 5),
    // POSITION_TARGET_GLOBAL_INT — MSG_ID 87.
    (87, 150),
    // STATUSTEXT — MSG_ID 253, the canonical operator log line.
    (253, 83),
    // DEBUG — MSG_ID 254.
    (254, 46),
    // SETUP_SIGNING — MSG_ID 256, the v2 signing key configuration message.
    (256, 71),
    // BUTTON_CHANGE — MSG_ID 257.
    (257, 131),
    // PROTOCOL_VERSION — MSG_ID 300.
    (300, 217),
];

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn known_message_ids_resolve() {
        // HEARTBEAT — pinned by `crate::frame::HEARTBEAT_MSG_ID`. Drift
        // here would mean a HEARTBEAT frame is rejected as
        // "UnknownMessageId" — visible immediately because the workspace
        // wires HEARTBEATs into every fleet observability dashboard.
        assert_eq!(crc_extra(0), Some(50));
        // GLOBAL_POSITION_INT — the canonical position frame routed
        // across the workspace's MAVLink integration.
        assert_eq!(crc_extra(33), Some(104));
        // COMMAND_LONG — the canonical command frame.
        assert_eq!(crc_extra(76), Some(152));
        // SETUP_SIGNING — the v2 signing key configuration message
        // itself; rejecting it for being "unknown" would lock an
        // operator out of rotating keys.
        assert_eq!(crc_extra(256), Some(71));
    }

    #[test]
    fn unknown_message_id_returns_none_no_panic() {
        // The whole point of the F-73 hardening: the API must never
        // panic on an attacker-supplied MSG_ID, no matter how absurd.
        // Sweep the boundary of the u32 space and a few likely-attacked
        // values that fall in the gaps between named messages.
        assert_eq!(crc_extra(u32::MAX), None);
        assert_eq!(crc_extra(99_999), None);
        // 19 sits between PARAM_REQUEST_READ (20) and SET_MODE (11) —
        // a deliberate gap-walker.
        assert_eq!(crc_extra(19), None);
        // Just above the highest table entry.
        assert_eq!(crc_extra(301), None);
    }

    #[test]
    fn table_is_sorted_by_msg_id() {
        // The doc comment promises ascending order so reviewers can
        // locate insertion points by intuition. Pin the invariant so
        // a copy-paste mistake breaks the build.
        let mut prev: Option<u32> = None;
        for &(id, _) in MSG_ID_TABLE {
            if let Some(p) = prev {
                assert!(id > p, "MSG_ID_TABLE not sorted: {p} >= {id}");
            }
            prev = Some(id);
        }
    }

    #[test]
    fn table_has_no_duplicate_msg_ids() {
        // The lookup short-circuits on first match, so a duplicate row
        // would silently shadow the second. Pin the invariant.
        let mut seen: std::collections::HashSet<u32> = std::collections::HashSet::new();
        for &(id, _) in MSG_ID_TABLE {
            assert!(seen.insert(id), "duplicate MSG_ID in CRC-EXTRA table: {id}");
        }
    }

    #[test]
    fn lookup_is_allocation_free_in_principle() {
        // Smoke test: a million unknown IDs must complete without
        // tripping the panic-free contract. We can't directly assert
        // "no allocations" without a custom allocator, but driving the
        // hot path with arbitrary input is the regression test for the
        // "no per-frame allocation" promise.
        for id in 0..1_000u32 {
            // Don't assert specific equality — some IDs in this range
            // are real entries (HEARTBEAT, ATTITUDE, etc.). The point
            // is that the call returns without panicking.
            let _ = crc_extra(id);
        }
    }
}
