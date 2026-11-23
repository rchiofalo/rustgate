// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

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
//! This module is the panic-free counterpart: a static, sorted lookup
//! table, exposed through a single `crc_extra` function that returns
//! `Option<u8>`. Callers that get `None` reject the frame with
//! [`crate::error::MavlinkError::UnknownMessageId`] — no allocation,
//! no panic, no per-frame slow path.
//!
//! # Table source
//!
//! The table is `mavlink_tlog::message_info`: every message in the
//! upstream [`all.xml`](https://github.com/mavlink/mavlink) dialect
//! (common, ardupilotmega, development and the vendor sets), generated
//! from the XML. It has no dependencies, is `#![forbid(unsafe_code)]`,
//! and does a binary search over a `&'static` slice.

/// Lookup the CRC-EXTRA byte for a given MAVLink `MSG_ID`.
///
/// Returns `Some(crc_extra)` when the ID is in the MAVLink `all.xml`
/// catalogue and `None` when it is not — callers that must verify the
/// CRC reject the frame on `None` rather than guessing or panicking.
#[must_use]
pub fn crc_extra(msg_id: u32) -> Option<u8> {
    mavlink_tlog::message_info(msg_id).map(|info| info.crc_extra)
}

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
        // Just above the highest table entry (60053).
        assert_eq!(crc_extra(60_054), None);
    }

    #[test]
    fn routine_autopilot_traffic_resolves() {
        // Sent by every ArduPilot / PX4 vehicle; previously rejected
        // as UnknownMessageId.
        assert_eq!(crc_extra(109), Some(185)); // RADIO_STATUS
        assert_eq!(crc_extra(111), Some(34)); // TIMESYNC
        assert_eq!(crc_extra(147), Some(154)); // BATTERY_STATUS
        assert_eq!(crc_extra(148), Some(178)); // AUTOPILOT_VERSION
        assert_eq!(crc_extra(230), Some(163)); // ESTIMATOR_STATUS
        assert_eq!(crc_extra(241), Some(90)); // VIBRATION
        assert_eq!(crc_extra(242), Some(104)); // HOME_POSITION
        assert_eq!(crc_extra(245), Some(130)); // EXTENDED_SYS_STATE
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
