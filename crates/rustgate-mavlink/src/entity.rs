// Copyright © 2026 Roberto Chiofalo.

//! MAVLink implementation of the canonical
//! [`rustgate_core::entity::EntityCodec`] trait — refs #847.
//!
//! [`MavlinkEntityCodec`] decodes MAVLink v2 frames into the
//! protocol-agnostic `Entity` shape defined by `rustgate-core` and
//! re-encodes a `Position`-bearing `Entity` back into a synthetic
//! `GLOBAL_POSITION_INT` frame. This is the second concrete codec wired
//! against the abstraction layer (the CoT XML codec shipped via #1289);
//! the ASTERIX, STANAG-4586, and Link 16 implementations and the router
//! pivot tracked under #847 ship in subsequent PRs.
//!
//! # Mapping summary
//!
//! Inbound (MAVLink → `Entity`):
//!
//! | MAVLink frame                        | `Entity` field                                                        |
//! |--------------------------------------|------------------------------------------------------------------------|
//! | `system_id` + `component_id`         | `Entity.uid` (`"mavlink-{system_id}-{component_id}"`)                  |
//! | HEARTBEAT (`MSG_ID = 0`) `MAV_TYPE`  | `Entity.kind` (Aircraft / Ground / Marine / Sensor / Unknown)          |
//! | GLOBAL_POSITION_INT (`MSG_ID = 33`)  | `Entity.position` (lat/lon/alt) + `Entity.velocity` (speed/course)     |
//! | non-strict-subset payload bytes      | `Entity.attributes` under the `"mavlink."` key prefix                  |
//!
//! Outbound (`Entity` → MAVLink) is intentionally narrower: only
//! `Position`-bearing entities encode into a `GLOBAL_POSITION_INT`
//! frame. Entities without a position (e.g. a free-form alert that
//! happened to ride on a CoT envelope) cannot be represented as a
//! MAVLink frame and surface
//! [`MavlinkEntityError::UnsupportedEntityKind`] — the workspace
//! treats MAVLink as a kinematic protocol, not a general-purpose
//! transport. The CoT codec retains that role.
//!
//! # `MAV_TYPE` → `EntityKind` dispatch
//!
//! HEARTBEAT carries the `MAV_TYPE` byte at payload offset 4 (after
//! the size-descending reorder; see [`crate::frame`]). The dispatch is
//! deliberately coarse — fine-grained vehicle-type semantics live on
//! the `mavlink.heartbeat.vehicle_type` attribute so a future codec
//! version can lift them as first-class without breaking the wire form:
//!
//! | `MAV_TYPE` constant                                            | `EntityKind`                                |
//! |-----------------------------------------------------------------|---------------------------------------------|
//! | `FIXED_WING`(1) / `QUADROTOR`(2) / `COAXIAL`(3) / `HELICOPTER`(4) | [`EntityKind::Aircraft`]                  |
//! | `HEXAROTOR`(13) / `OCTOROTOR`(14) / `TRICOPTER`(15)              | [`EntityKind::Aircraft`]                  |
//! | `VTOL_TAILSITTER_DUOROTOR`(19) / `VTOL_TAILSITTER_QUADROTOR`(20) | [`EntityKind::Aircraft`]                  |
//! | `VTOL_TILTROTOR`(21) / `AIRSHIP`(7) / `KITE`(17)                 | [`EntityKind::Aircraft`]                  |
//! | `GROUND_ROVER`(10)                                              | [`EntityKind::Ground`]                      |
//! | `SURFACE_BOAT`(11) / `SUBMARINE`(12)                            | [`EntityKind::Marine`]                      |
//! | `ANTENNA_TRACKER`(5) / `GIMBAL`(26) / `CAMERA`(30)              | [`EntityKind::Sensor`]                      |
//! | anything else (`GENERIC`(0), `GCS`(6), …)                       | [`EntityKind::Unknown`] with the label tag  |
//!
//! The label on `EntityKind::Unknown` follows the format
//! `"mavlink-{:?}"` against an internal `MavType` enum so dashboards
//! can group on it without per-frame string allocation in the
//! steady-state Aircraft / Ground / Marine path.
//!
//! # Round-trip discipline
//!
//! Same-codec round-trip is preserved for the GLOBAL_POSITION_INT
//! subset: `to_entity(global_position_frame)` followed by
//! `from_entity(entity)` produces a frame whose system / component
//! identifiers and lat / lon / alt fields match the input. The frame
//! is **not** byte-identical: HEARTBEAT-only entities cannot encode
//! back through `from_entity`, the `time_boot_ms` field is recovered
//! from the `mavlink.global_position_int.time_boot_ms` attribute when
//! present (else zero), and CRC bytes are filled with zero placeholders
//! since the framing layer (see [`crate::frame::MavlinkFrameCodec`])
//! handles signing and CRC verification.
//!
//! # Out of scope
//!
//! - CRC verification (lives in the framing layer).
//! - Signature generation for v2 signed frames (signing module
//!   tracked separately in the parent epic).
//! - Decoding of message IDs other than HEARTBEAT and
//!   GLOBAL_POSITION_INT (those land via subsequent PRs as router
//!   integration demands them).

use std::collections::BTreeMap;
use std::time::SystemTime;

use bytes::{BufMut, Bytes, BytesMut};
use rustgate_core::entity::{AttributeValue, Entity, EntityCodec, EntityKind, Position, Velocity};

use crate::frame::{HEARTBEAT_MSG_ID, MAVLINK_V1_MAGIC, MAVLINK_V2_MAGIC, MavlinkVersion};

/// Attribute-key prefix used for every MAVLink-derived
/// [`AttributeValue`] entry. Keeps the namespace separated from
/// other codecs (CoT, ASTERIX, …) that share the [`Entity`] shape.
const MAVLINK_PREFIX: &str = "mavlink.";

/// MAVLink v2 message ID for `GLOBAL_POSITION_INT` (`33`).
///
/// This is the canonical position frame the dialect catalogue
/// publishes — every fleet management platform consumes it for
/// tracking. Pinned as a public constant so audit logs and tests can
/// classify a frame without re-deriving the magic number.
pub const GLOBAL_POSITION_INT_MSG_ID: u32 = 33;

/// Wire size of a `GLOBAL_POSITION_INT` payload after MAVLink's
/// field-size-descending reordering: `time_boot_ms` (u32) + 4 × i32 +
/// 3 × i16 + u16 = 28 bytes. v2 truncates trailing zero bytes on the
/// wire, so the on-wire payload may be shorter — but the encoder
/// emits the full 28 bytes so the receiver always recovers every
/// field.
const GLOBAL_POSITION_INT_PAYLOAD_LEN: usize = 28;

/// v2 header size: STX + LEN + INCOMPAT + COMPAT + SEQ + SYSID +
/// COMPID + MSGID(3). Mirrors the constant in [`crate::frame`] but
/// kept private so the entity codec stays self-contained.
const MAVLINK_V2_HEADER_LEN: usize = 10;

/// CRC-16/MCRF4XX trailer size, identical for v1 and v2.
const MAVLINK_CRC_LEN: usize = 2;

/// Errors surfaced by [`MavlinkEntityCodec::to_entity`] /
/// [`MavlinkEntityCodec::from_entity`].
///
/// Distinct from [`crate::error::MavlinkError`] (which covers framing-
/// layer policy decisions) because the codec's failure modes belong
/// to a different operational class — a SIEM that pages on
/// `mavlink.frame_rejected` should NOT page on
/// `mavlink.entity.unsupported_entity_kind`, which is a routine
/// "this entity has no MAVLink wire form" signal during cross-protocol
/// fan-out.
#[derive(Debug, thiserror::Error)]
pub enum MavlinkEntityError {
    /// Payload bytes do not parse as a MAVLink v1 or v2 frame. The
    /// inner string carries enough context for an operator log line
    /// without exposing the raw payload (which may be hostile or
    /// classified) — typical contents are "magic byte 0x00",
    /// "frame too short for v2 header", "payload truncated below
    /// declared LEN".
    #[error("malformed MAVLink frame: {0}")]
    InvalidFrame(String),

    /// The frame's `MSG_ID` is outside the subset this codec maps to
    /// the [`Entity`] shape. The codec deliberately rejects rather
    /// than silently storing the frame under
    /// `mavlink.unknown_message_id.*` because cross-protocol fan-out
    /// would then carry forward an opaque frame the receiver cannot
    /// interpret. Consumers that need ID coverage beyond HEARTBEAT
    /// and GLOBAL_POSITION_INT extend [`mav_msg_supported`] in a
    /// follow-up.
    #[error("MAVLink message ID {0} cannot be mapped to Entity")]
    UnsupportedMessage(u32),

    /// `from_entity` cannot represent the supplied `Entity` as a
    /// MAVLink wire frame. The string captures the cause for the
    /// audit trail — typical contents are
    /// `"entity has no Position"` (the most common case during
    /// cross-protocol fan-out) and `"unmapped EntityKind"` for
    /// future variants.
    #[error("Entity kind {0:?} cannot be mapped to MAVLink frame")]
    UnsupportedEntityKind(String),

    /// A MAVLink frame whose overall length passes the framing checks
    /// but whose payload is shorter than the strict-subset fields the
    /// codec needs — e.g. a HEARTBEAT truncated below offset 5 cannot
    /// surface `MAV_TYPE`, and a GLOBAL_POSITION_INT truncated below
    /// the 12 bytes covering `lat`/`lon`/`alt` cannot populate
    /// [`Entity::position`]. The string names the field so an
    /// operator log line can distinguish "fleet sender truncates
    /// past `lon`" from "fleet sender truncates past `vx`".
    #[error("MAVLink frame missing required field: {0}")]
    MissingField(&'static str),
}

/// MAVLink wire-format codec for the canonical [`Entity`] shape.
///
/// Stateless — the same instance is safe to reuse across every routed
/// message on every thread. The router holds an
/// `Arc<MavlinkEntityCodec>` per protocol slot.
#[derive(Debug, Default, Clone, Copy)]
pub struct MavlinkEntityCodec;

impl EntityCodec for MavlinkEntityCodec {
    type Error = MavlinkEntityError;

    fn to_entity(&self, payload: &[u8]) -> Result<Entity, Self::Error> {
        decode_frame(payload)
    }

    fn from_entity(&self, entity: &Entity) -> Result<Bytes, Self::Error> {
        encode_global_position_int(entity)
    }
}

/// Internal `MAV_TYPE` enum covering the subset of values whose
/// dispatch [`MavType::to_entity_kind`] makes a coarse decision on.
///
/// The variants line up with the standard MAVLink common-dialect
/// `MAV_TYPE` enum values published in `message_definitions/v1.0/
/// common.xml`. Anything outside this list folds into
/// [`MavType::Other`] and surfaces as
/// [`EntityKind::Unknown("mavlink-{:?}")`] so the downstream
/// dashboard can still group on the label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MavType {
    Generic,
    FixedWing,
    Quadrotor,
    Coaxial,
    Helicopter,
    AntennaTracker,
    Gcs,
    Airship,
    FreeBalloon,
    Rocket,
    GroundRover,
    SurfaceBoat,
    Submarine,
    Hexarotor,
    Octorotor,
    Tricopter,
    FlappingWing,
    Kite,
    OnboardController,
    VtolTailsitterDuorotor,
    VtolTailsitterQuadrotor,
    VtolTiltrotor,
    Gimbal,
    Camera,
    Other(u8),
}

impl MavType {
    /// Decode the byte at HEARTBEAT payload offset 4 into the typed
    /// enum. Unknown values pass through as [`MavType::Other`] so the
    /// classifier never panics on an attacker-supplied byte.
    fn from_byte(byte: u8) -> Self {
        match byte {
            0 => Self::Generic,
            1 => Self::FixedWing,
            2 => Self::Quadrotor,
            3 => Self::Coaxial,
            4 => Self::Helicopter,
            5 => Self::AntennaTracker,
            6 => Self::Gcs,
            7 => Self::Airship,
            8 => Self::FreeBalloon,
            9 => Self::Rocket,
            10 => Self::GroundRover,
            11 => Self::SurfaceBoat,
            12 => Self::Submarine,
            13 => Self::Hexarotor,
            14 => Self::Octorotor,
            15 => Self::Tricopter,
            16 => Self::FlappingWing,
            17 => Self::Kite,
            18 => Self::OnboardController,
            19 => Self::VtolTailsitterDuorotor,
            20 => Self::VtolTailsitterQuadrotor,
            21 => Self::VtolTiltrotor,
            26 => Self::Gimbal,
            30 => Self::Camera,
            other => Self::Other(other),
        }
    }

    /// Coarse [`EntityKind`] dispatch matching the table in the module
    /// docs. The returned variant set is deliberately narrow so the
    /// router can branch on `EntityKind` without growing a per-protocol
    /// lookup.
    fn to_entity_kind(self) -> EntityKind {
        match self {
            Self::FixedWing
            | Self::Quadrotor
            | Self::Coaxial
            | Self::Helicopter
            | Self::Airship
            | Self::Kite
            | Self::Hexarotor
            | Self::Octorotor
            | Self::Tricopter
            | Self::VtolTailsitterDuorotor
            | Self::VtolTailsitterQuadrotor
            | Self::VtolTiltrotor => EntityKind::Aircraft,
            Self::GroundRover => EntityKind::Ground,
            Self::SurfaceBoat | Self::Submarine => EntityKind::Marine,
            Self::AntennaTracker | Self::Gimbal | Self::Camera => EntityKind::Sensor,
            // Generic, GCS, FreeBalloon, Rocket, FlappingWing,
            // OnboardController, Other(_) — none of these are a clean
            // fit for the strict-subset variants. Surface them via a
            // labelled Unknown so dashboards can still group on the
            // raw `MAV_TYPE` while the dispatch stays coarse.
            other => EntityKind::Unknown(format!("mavlink-{other:?}")),
        }
    }
}

/// Decode a MAVLink frame into the canonical [`Entity`] shape.
///
/// Walks the framing header to recover system / component identifiers
/// and the `MSG_ID`, then dispatches per-message-ID into the field
/// extractor. Unsupported message IDs surface as
/// [`MavlinkEntityError::UnsupportedMessage`] — a hostile sender that
/// streams random IDs cannot drive a panic or per-frame allocation.
fn decode_frame(payload: &[u8]) -> Result<Entity, MavlinkEntityError> {
    let header = parse_header(payload)?;

    // Branch on the message ID before extracting payload-side fields.
    // The two supported IDs each have their own field map; everything
    // else surfaces a typed error so the cross-protocol fan-out path
    // does not silently carry an opaque frame.
    match header.msg_id {
        HEARTBEAT_MSG_ID => decode_heartbeat(&header, payload),
        GLOBAL_POSITION_INT_MSG_ID => decode_global_position_int(&header, payload),
        other => Err(MavlinkEntityError::UnsupportedMessage(other)),
    }
}

/// Strict-subset header fields shared by every supported message ID.
///
/// Computed once by [`parse_header`] so the per-message decoders can
/// stay focused on payload extraction without re-walking the wire
/// header.
struct FrameHeader {
    /// Originating system identifier (1-255 in well-formed traffic).
    system_id: u8,
    /// Originating component identifier on the system.
    component_id: u8,
    /// MAVLink message ID dispatched in [`decode_frame`].
    msg_id: u32,
    /// Wire-declared payload length (the `LEN` byte). v2 truncates
    /// trailing zero bytes so this MAY be lower than the catalogue
    /// payload size.
    wire_payload_len: usize,
    /// Byte offset where the payload starts in the original frame.
    payload_offset: usize,
}

/// Parse the v1 / v2 framing header so callers can dispatch on
/// `msg_id` without re-walking byte offsets.
///
/// Defense-in-depth: returns
/// [`MavlinkEntityError::InvalidFrame`] for unrecognised magic,
/// truncated headers, and frames whose declared length would extend
/// past the buffer end. Never panics on attacker-supplied input.
fn parse_header(frame: &[u8]) -> Result<FrameHeader, MavlinkEntityError> {
    let first = match frame.first() {
        Some(b) => *b,
        None => return Err(MavlinkEntityError::InvalidFrame("frame is empty".into())),
    };
    let version = MavlinkVersion::from_magic(first).ok_or_else(|| {
        MavlinkEntityError::InvalidFrame(format!("unrecognised magic byte 0x{first:02X}"))
    })?;

    match version {
        // v1: STX(0) LEN(1) SEQ(2) SYS(3) COMP(4) MSGID(5) PAYLOAD(6+)
        MavlinkVersion::V1 => {
            if frame.len() < 6 {
                return Err(MavlinkEntityError::InvalidFrame(
                    "frame shorter than v1 header".into(),
                ));
            }
            let len = frame[1] as usize;
            let total_min = 6 + len + MAVLINK_CRC_LEN;
            if frame.len() < total_min {
                return Err(MavlinkEntityError::InvalidFrame(format!(
                    "frame shorter than declared v1 length {total_min}"
                )));
            }
            Ok(FrameHeader {
                system_id: frame[3],
                component_id: frame[4],
                msg_id: u32::from(frame[5]),
                wire_payload_len: len,
                payload_offset: 6,
            })
        }
        // v2: STX(0) LEN(1) INCOMPAT(2) COMPAT(3) SEQ(4) SYS(5) COMP(6)
        //     MSGID_LO(7) MSGID_MID(8) MSGID_HI(9) PAYLOAD(10+)
        MavlinkVersion::V2 => {
            if frame.len() < MAVLINK_V2_HEADER_LEN {
                return Err(MavlinkEntityError::InvalidFrame(
                    "frame shorter than v2 header".into(),
                ));
            }
            let len = frame[1] as usize;
            let total_min = MAVLINK_V2_HEADER_LEN + len + MAVLINK_CRC_LEN;
            if frame.len() < total_min {
                return Err(MavlinkEntityError::InvalidFrame(format!(
                    "frame shorter than declared v2 length {total_min}"
                )));
            }
            let lo = u32::from(frame[7]);
            let mid = u32::from(frame[8]);
            let hi = u32::from(frame[9]);
            Ok(FrameHeader {
                system_id: frame[5],
                component_id: frame[6],
                msg_id: lo | (mid << 8) | (hi << 16),
                wire_payload_len: len,
                payload_offset: MAVLINK_V2_HEADER_LEN,
            })
        }
    }
}

/// Decode a HEARTBEAT (`MSG_ID = 0`) frame into an [`Entity`].
///
/// Surfaces `MAV_TYPE` (vehicle_type, payload offset 4) and `autopilot`
/// (offset 5) onto the `mavlink.heartbeat.*` attribute namespace and
/// dispatches [`EntityKind`] from the typed [`MavType`] enum. The
/// `Entity` carries no [`Position`] or [`Velocity`] — HEARTBEAT is a
/// presence ping, not a kinematic frame.
fn decode_heartbeat(header: &FrameHeader, frame: &[u8]) -> Result<Entity, MavlinkEntityError> {
    // Need at least 6 bytes of payload to surface vehicle_type +
    // autopilot. v2 may truncate later fields (base_mode,
    // system_status, mavlink_version) and we tolerate that.
    if header.wire_payload_len < 6 {
        return Err(MavlinkEntityError::MissingField("heartbeat.vehicle_type"));
    }
    let payload = match frame.get(header.payload_offset..) {
        Some(slice) => slice,
        None => {
            return Err(MavlinkEntityError::InvalidFrame(
                "payload offset past end of frame".into(),
            ));
        }
    };
    let vehicle_type_byte = match payload.get(4) {
        Some(b) => *b,
        None => return Err(MavlinkEntityError::MissingField("heartbeat.vehicle_type")),
    };
    let autopilot_byte = match payload.get(5) {
        Some(b) => *b,
        None => return Err(MavlinkEntityError::MissingField("heartbeat.autopilot")),
    };

    let mav_type = MavType::from_byte(vehicle_type_byte);
    let kind = mav_type.to_entity_kind();

    let mut attributes = base_attributes(header);
    let _ = attributes.insert(
        format!("{MAVLINK_PREFIX}heartbeat.vehicle_type"),
        AttributeValue::Int(i64::from(vehicle_type_byte)),
    );
    let _ = attributes.insert(
        format!("{MAVLINK_PREFIX}heartbeat.autopilot"),
        AttributeValue::Int(i64::from(autopilot_byte)),
    );

    Ok(Entity {
        uid: format_uid(header.system_id, header.component_id),
        kind,
        position: None,
        velocity: None,
        timestamp: SystemTime::now(),
        callsign: None,
        mil_std_2525_sidc: None,
        attributes,
    })
}

/// Decode a `GLOBAL_POSITION_INT` (`MSG_ID = 33`) frame into an
/// [`Entity`]. Recovers [`Position`] from the lat / lon / alt
/// fields and [`Velocity`] from `(vx, vy)` resolving to a polar
/// (speed, course) pair.
///
/// Field offsets (bytes within the payload, after MAVLink's
/// size-descending reorder):
///
/// - `time_boot_ms` (u32) at offset 0
/// - `lat` (i32, scaled by 1e7) at offset 4
/// - `lon` (i32, scaled by 1e7) at offset 8
/// - `alt` (i32, mm above MSL) at offset 12
/// - `relative_alt` (i32, mm above ground) at offset 16
/// - `vx` / `vy` / `vz` (i16 cm/s each) at offsets 20 / 22 / 24
/// - `hdg` (u16, cdeg, 65535 = unknown) at offset 26
fn decode_global_position_int(
    header: &FrameHeader,
    frame: &[u8],
) -> Result<Entity, MavlinkEntityError> {
    // The strict subset we extract starts at offset 0 (time_boot_ms)
    // and ends at offset 12+4 (alt high byte). Wire-truncation past
    // alt is uncommon but legal; we treat anything below 16 bytes as
    // missing the position fields outright.
    if header.wire_payload_len < 16 {
        return Err(MavlinkEntityError::MissingField(
            "global_position_int.position",
        ));
    }
    let payload = match frame.get(header.payload_offset..) {
        Some(slice) => slice,
        None => {
            return Err(MavlinkEntityError::InvalidFrame(
                "payload offset past end of frame".into(),
            ));
        }
    };

    let time_boot_ms = read_u32_le(payload, 0).ok_or(MavlinkEntityError::MissingField(
        "global_position_int.time_boot_ms",
    ))?;
    let lat_raw = read_i32_le(payload, 4)
        .ok_or(MavlinkEntityError::MissingField("global_position_int.lat"))?;
    let lon_raw = read_i32_le(payload, 8)
        .ok_or(MavlinkEntityError::MissingField("global_position_int.lon"))?;
    let alt_raw = read_i32_le(payload, 12)
        .ok_or(MavlinkEntityError::MissingField("global_position_int.alt"))?;

    // 1e-7 deg per LSB, 1e-3 m per LSB.
    let position = Position {
        lat: f64::from(lat_raw) / 1.0e7,
        lon: f64::from(lon_raw) / 1.0e7,
        hae_meters: Some(f64::from(alt_raw) / 1.0e3),
    };

    // Optional velocity: only emitted when (vx, vy, vz) are all in
    // the payload. The wire format truncates trailing zero bytes, so
    // a sender that legitimately omits vz / hdg is tolerated by
    // skipping the velocity carry.
    let velocity = decode_global_velocity(payload, header.wire_payload_len);

    let mut attributes = base_attributes(header);
    let _ = attributes.insert(
        format!("{MAVLINK_PREFIX}global_position_int.time_boot_ms"),
        AttributeValue::Int(i64::from(time_boot_ms)),
    );
    let _ = attributes.insert(
        format!("{MAVLINK_PREFIX}global_position_int.lat_e7"),
        AttributeValue::Int(i64::from(lat_raw)),
    );
    let _ = attributes.insert(
        format!("{MAVLINK_PREFIX}global_position_int.lon_e7"),
        AttributeValue::Int(i64::from(lon_raw)),
    );
    let _ = attributes.insert(
        format!("{MAVLINK_PREFIX}global_position_int.alt_mm"),
        AttributeValue::Int(i64::from(alt_raw)),
    );
    if header.wire_payload_len >= 20
        && let Some(rel) = read_i32_le(payload, 16)
    {
        let _ = attributes.insert(
            format!("{MAVLINK_PREFIX}global_position_int.relative_alt_mm"),
            AttributeValue::Int(i64::from(rel)),
        );
    }
    if header.wire_payload_len >= 22
        && let Some(vx) = read_i16_le(payload, 20)
    {
        let _ = attributes.insert(
            format!("{MAVLINK_PREFIX}global_position_int.vx_cm_s"),
            AttributeValue::Int(i64::from(vx)),
        );
    }
    if header.wire_payload_len >= 24
        && let Some(vy) = read_i16_le(payload, 22)
    {
        let _ = attributes.insert(
            format!("{MAVLINK_PREFIX}global_position_int.vy_cm_s"),
            AttributeValue::Int(i64::from(vy)),
        );
    }
    if header.wire_payload_len >= 26
        && let Some(vz) = read_i16_le(payload, 24)
    {
        let _ = attributes.insert(
            format!("{MAVLINK_PREFIX}global_position_int.vz_cm_s"),
            AttributeValue::Int(i64::from(vz)),
        );
    }
    if header.wire_payload_len >= 28
        && let Some(hdg) = read_u16_le(payload, 26)
    {
        let _ = attributes.insert(
            format!("{MAVLINK_PREFIX}global_position_int.hdg_cdeg"),
            AttributeValue::Int(i64::from(hdg)),
        );
    }

    Ok(Entity {
        uid: format_uid(header.system_id, header.component_id),
        // GLOBAL_POSITION_INT alone does not carry MAV_TYPE; default
        // to Track. A receiver that wants Aircraft / Ground / Marine
        // should pair this frame with the originator's HEARTBEAT —
        // the router crate's session layer (future PR) caches that
        // pairing per system_id.
        kind: EntityKind::Track,
        position: Some(position),
        velocity,
        timestamp: SystemTime::now(),
        callsign: None,
        mil_std_2525_sidc: None,
        attributes,
    })
}

/// Resolve `(vx, vy)` cm/s to a polar `(speed_m_s, course_deg)` pair.
/// Returns `None` if the payload truncates before vy.
///
/// `course_deg` is degrees clockwise from true north — atan2 yields
/// radians in `[-π, π]` from the +x axis, so we offset by 90° and
/// normalise to `[0, 360)`. `vz` is intentionally dropped: the
/// [`Velocity`] shape covers ground motion, and vertical-rate
/// telemetry rides on the `mavlink.global_position_int.vz_cm_s`
/// attribute for codecs that need it.
fn decode_global_velocity(payload: &[u8], wire_payload_len: usize) -> Option<Velocity> {
    if wire_payload_len < 24 {
        return None;
    }
    let vx = read_i16_le(payload, 20)?;
    let vy = read_i16_le(payload, 22)?;
    let vx_m_s = f64::from(vx) / 100.0;
    let vy_m_s = f64::from(vy) / 100.0;
    let speed = (vx_m_s * vx_m_s + vy_m_s * vy_m_s).sqrt();
    // MAVLink convention: vx is north, vy is east. Compass bearing
    // = atan2(east, north) in [-π, π]; normalise into [0, 360).
    let course_rad = vy_m_s.atan2(vx_m_s);
    let mut course_deg = course_rad.to_degrees();
    if course_deg < 0.0 {
        course_deg += 360.0;
    }
    if !course_deg.is_finite() {
        course_deg = 0.0;
    }
    Some(Velocity {
        speed_m_s: speed,
        course_deg,
    })
}

/// Build the base `mavlink.system_id` / `mavlink.component_id` /
/// `mavlink.msg_id` carry that every supported MSG_ID surfaces. Lets
/// the per-message decoders stay focused on the message-specific
/// extra fields.
fn base_attributes(header: &FrameHeader) -> BTreeMap<String, AttributeValue> {
    let mut attributes: BTreeMap<String, AttributeValue> = BTreeMap::new();
    let _ = attributes.insert(
        format!("{MAVLINK_PREFIX}system_id"),
        AttributeValue::Int(i64::from(header.system_id)),
    );
    let _ = attributes.insert(
        format!("{MAVLINK_PREFIX}component_id"),
        AttributeValue::Int(i64::from(header.component_id)),
    );
    let _ = attributes.insert(
        format!("{MAVLINK_PREFIX}msg_id"),
        AttributeValue::Int(i64::from(header.msg_id)),
    );
    attributes
}

/// Format the canonical Entity UID for a MAVLink originator.
fn format_uid(system_id: u8, component_id: u8) -> String {
    format!("mavlink-{system_id}-{component_id}")
}

/// Parse the `system_id` / `component_id` pair out of an Entity UID
/// previously formatted by [`format_uid`]. Returns `None` for any UID
/// that does not match the `mavlink-<sys>-<comp>` shape — the caller
/// of [`MavlinkEntityCodec::from_entity`] surfaces
/// [`MavlinkEntityError::UnsupportedEntityKind`] in that case.
fn parse_uid(uid: &str) -> Option<(u8, u8)> {
    let rest = uid.strip_prefix("mavlink-")?;
    let (sys_str, comp_str) = rest.split_once('-')?;
    let sys: u8 = sys_str.parse().ok()?;
    let comp: u8 = comp_str.parse().ok()?;
    Some((sys, comp))
}

/// Encode a position-bearing [`Entity`] as a `GLOBAL_POSITION_INT`
/// frame.
///
/// The encoder builds a v2 unsigned frame with zero CRC bytes and no
/// signature trailer — the framing layer (see
/// [`crate::frame::MavlinkFrameCodec`]) re-runs CRC and signature
/// generation when this frame egresses on a real link. Same-codec
/// round-trip preserves system / component identifiers and lat / lon
/// / alt values; the sequence number, `time_boot_ms` (when the
/// inbound carry is absent), and CRC are the only fields that may
/// not match byte-for-byte.
fn encode_global_position_int(entity: &Entity) -> Result<Bytes, MavlinkEntityError> {
    let position = entity.position.ok_or_else(|| {
        MavlinkEntityError::UnsupportedEntityKind("entity has no Position".into())
    })?;

    // `mavlink-{sys}-{comp}` is the canonical UID format the codec
    // emits on `to_entity`; any other shape can't be encoded back.
    let (system_id, component_id) = parse_uid(&entity.uid).ok_or_else(|| {
        MavlinkEntityError::UnsupportedEntityKind(format!(
            "entity uid `{}` does not match `mavlink-<sys>-<comp>`",
            entity.uid
        ))
    })?;

    let lat_e7 = scale_to_i32(position.lat, 1.0e7, "lat")?;
    let lon_e7 = scale_to_i32(position.lon, 1.0e7, "lon")?;
    let alt_mm = position
        .hae_meters
        .map(|m| scale_to_i32(m, 1.0e3, "hae_meters"))
        .transpose()?
        .unwrap_or(0);

    let time_boot_ms = match entity
        .attributes
        .get(&format!("{MAVLINK_PREFIX}global_position_int.time_boot_ms"))
    {
        // i64::try_into into u32 would silently wrap; clamp instead so
        // we never panic on a hostile attribute value.
        Some(AttributeValue::Int(v)) => u32::try_from(*v).unwrap_or(0),
        _ => 0,
    };
    let relative_alt_mm = match entity.attributes.get(&format!(
        "{MAVLINK_PREFIX}global_position_int.relative_alt_mm"
    )) {
        Some(AttributeValue::Int(v)) => i32::try_from(*v).unwrap_or(0),
        _ => alt_mm,
    };
    let (vx_cm_s, vy_cm_s, vz_cm_s, hdg_cdeg) = velocity_to_wire(entity);

    let mut payload = BytesMut::with_capacity(GLOBAL_POSITION_INT_PAYLOAD_LEN);
    payload.put_u32_le(time_boot_ms);
    payload.put_i32_le(lat_e7);
    payload.put_i32_le(lon_e7);
    payload.put_i32_le(alt_mm);
    payload.put_i32_le(relative_alt_mm);
    payload.put_i16_le(vx_cm_s);
    payload.put_i16_le(vy_cm_s);
    payload.put_i16_le(vz_cm_s);
    payload.put_u16_le(hdg_cdeg);

    let mut frame = BytesMut::with_capacity(
        MAVLINK_V2_HEADER_LEN + GLOBAL_POSITION_INT_PAYLOAD_LEN + MAVLINK_CRC_LEN,
    );
    frame.put_u8(MAVLINK_V2_MAGIC);
    // Defense-in-depth: the payload buffer was filled with exactly
    // GLOBAL_POSITION_INT_PAYLOAD_LEN (28) bytes; fits in u8.
    let payload_len = u8::try_from(payload.len())
        .map_err(|_| MavlinkEntityError::InvalidFrame("payload exceeds u8 LEN".into()))?;
    frame.put_u8(payload_len);
    frame.put_u8(0); // INCOMPAT (unsigned)
    frame.put_u8(0); // COMPAT
    frame.put_u8(0); // SEQ — sequence number is per-link state owned by the framer
    frame.put_u8(system_id);
    frame.put_u8(component_id);
    frame.put_u8((GLOBAL_POSITION_INT_MSG_ID & 0xFF) as u8);
    frame.put_u8(((GLOBAL_POSITION_INT_MSG_ID >> 8) & 0xFF) as u8);
    frame.put_u8(((GLOBAL_POSITION_INT_MSG_ID >> 16) & 0xFF) as u8);
    frame.extend_from_slice(&payload);
    frame.put_u16_le(0); // CRC placeholder — the framing layer re-computes

    Ok(frame.freeze())
}

/// Resolve `(speed_m_s, course_deg)` back into the wire-format
/// `(vx, vy, vz, hdg)` quadruple. The encoder reuses any
/// `mavlink.global_position_int.vx_cm_s` / `vy_cm_s` / `vz_cm_s` /
/// `hdg_cdeg` attributes from `to_entity` so a same-codec round-trip
/// recovers the original integer encoding without lossy float math.
fn velocity_to_wire(entity: &Entity) -> (i16, i16, i16, u16) {
    let from_attr_i = |key: &str| match entity.attributes.get(key) {
        Some(AttributeValue::Int(v)) => Some(*v),
        _ => None,
    };
    let vx = from_attr_i(&format!("{MAVLINK_PREFIX}global_position_int.vx_cm_s"));
    let vy = from_attr_i(&format!("{MAVLINK_PREFIX}global_position_int.vy_cm_s"));
    let vz = from_attr_i(&format!("{MAVLINK_PREFIX}global_position_int.vz_cm_s"));
    let hdg = from_attr_i(&format!("{MAVLINK_PREFIX}global_position_int.hdg_cdeg"));

    if let (Some(vx), Some(vy)) = (vx, vy) {
        // Round-trip case: integer wire values were carried on the
        // attributes bag by `to_entity`; reuse them verbatim.
        let vx_i = i16::try_from(vx).unwrap_or(0);
        let vy_i = i16::try_from(vy).unwrap_or(0);
        let vz_i = vz.and_then(|v| i16::try_from(v).ok()).unwrap_or(0);
        let hdg_u = hdg.and_then(|v| u16::try_from(v).ok()).unwrap_or(u16::MAX);
        return (vx_i, vy_i, vz_i, hdg_u);
    }

    // Lossy fallback: synthesise (vx, vy) from the (speed, course)
    // pair. This path runs when an Entity originated outside the
    // MAVLink codec (e.g. the router constructed it manually) and
    // round-trip discipline does not apply.
    let Some(velocity) = entity.velocity else {
        return (0, 0, 0, u16::MAX);
    };
    let course_rad = velocity.course_deg.to_radians();
    let vx_m_s = velocity.speed_m_s * course_rad.cos();
    let vy_m_s = velocity.speed_m_s * course_rad.sin();
    let vx_cm = (vx_m_s * 100.0).round();
    let vy_cm = (vy_m_s * 100.0).round();
    let hdg_cdeg = (velocity.course_deg.rem_euclid(360.0) * 100.0).round();
    let vx_i = clamp_to_i16(vx_cm);
    let vy_i = clamp_to_i16(vy_cm);
    let hdg_u = clamp_to_u16(hdg_cdeg);
    (vx_i, vy_i, 0, hdg_u)
}

/// Clamp an `f64` to the `i16` envelope without panicking on values
/// outside the representable range.
fn clamp_to_i16(v: f64) -> i16 {
    if !v.is_finite() {
        return 0;
    }
    if v >= f64::from(i16::MAX) {
        return i16::MAX;
    }
    if v <= f64::from(i16::MIN) {
        return i16::MIN;
    }
    v as i16
}

/// Clamp an `f64` to the `u16` envelope. Used for the `hdg_cdeg`
/// field which the MAVLink spec defines as `[0, 36000)` plus the
/// 65535 sentinel for "unknown".
fn clamp_to_u16(v: f64) -> u16 {
    if !v.is_finite() || v < 0.0 {
        return 0;
    }
    if v >= f64::from(u16::MAX) {
        return u16::MAX;
    }
    v as u16
}

/// Scale an `f64` value by `scale` and round to `i32` without
/// panicking on values outside the representable range. Used for the
/// `lat_e7` / `lon_e7` / `alt_mm` fields.
fn scale_to_i32(v: f64, scale: f64, field: &'static str) -> Result<i32, MavlinkEntityError> {
    if !v.is_finite() {
        return Err(MavlinkEntityError::UnsupportedEntityKind(format!(
            "non-finite {field}"
        )));
    }
    let scaled = (v * scale).round();
    if scaled >= f64::from(i32::MAX) {
        return Ok(i32::MAX);
    }
    if scaled <= f64::from(i32::MIN) {
        return Ok(i32::MIN);
    }
    Ok(scaled as i32)
}

fn read_u32_le(buf: &[u8], offset: usize) -> Option<u32> {
    let bytes: [u8; 4] = buf.get(offset..offset + 4)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

fn read_i32_le(buf: &[u8], offset: usize) -> Option<i32> {
    let bytes: [u8; 4] = buf.get(offset..offset + 4)?.try_into().ok()?;
    Some(i32::from_le_bytes(bytes))
}

fn read_i16_le(buf: &[u8], offset: usize) -> Option<i16> {
    let bytes: [u8; 2] = buf.get(offset..offset + 2)?.try_into().ok()?;
    Some(i16::from_le_bytes(bytes))
}

fn read_u16_le(buf: &[u8], offset: usize) -> Option<u16> {
    let bytes: [u8; 2] = buf.get(offset..offset + 2)?.try_into().ok()?;
    Some(u16::from_le_bytes(bytes))
}

/// Returns `true` for the `MSG_ID` values this codec maps into the
/// [`Entity`] shape. Exposed so call sites can pre-filter without
/// invoking the full decode path; kept in sync with the `match` in
/// `decode_frame`.
#[must_use]
pub fn mav_msg_supported(msg_id: u32) -> bool {
    msg_id == HEARTBEAT_MSG_ID || msg_id == GLOBAL_POSITION_INT_MSG_ID
}

// justification: pin the v1 magic to keep the lint surface honest. The
// decoder path keys on `MavlinkVersion::from_magic` rather than the raw
// byte, so the constant looks unused in this module. The codec's
// contract documents that v1 frames are supported on the inbound path,
// so the constant carry is intentional even though it does not appear
// in a `match` arm here.
#[allow(dead_code)]
const _MAVLINK_V1_MAGIC_USED: u8 = MAVLINK_V1_MAGIC;

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    /// Build a v2 unsigned HEARTBEAT frame with the given header /
    /// payload fields. CRC bytes are zeroed — the entity codec does
    /// not verify them. Mirrors the helper in `frame::tests` but
    /// scoped to the entity-decoder test surface.
    fn v2_heartbeat(sys: u8, comp: u8, autopilot: u8, vehicle_type: u8) -> Vec<u8> {
        let payload_len: u8 = 9;
        let total = MAVLINK_V2_HEADER_LEN + payload_len as usize + MAVLINK_CRC_LEN;
        let mut buf = Vec::with_capacity(total);
        buf.push(MAVLINK_V2_MAGIC);
        buf.push(payload_len);
        buf.push(0); // INCOMPAT (unsigned)
        buf.push(0); // COMPAT
        buf.push(0); // SEQ
        buf.push(sys);
        buf.push(comp);
        buf.push(0); // MSGID lo (HEARTBEAT = 0)
        buf.push(0); // MSGID mid
        buf.push(0); // MSGID hi
        // HEARTBEAT payload: custom_mode(0..4), type(4), autopilot(5),
        // base_mode(6), system_status(7), mavlink_version(8).
        buf.extend_from_slice(&0u32.to_le_bytes()); // custom_mode
        buf.push(vehicle_type);
        buf.push(autopilot);
        buf.push(0); // base_mode
        buf.push(0); // system_status
        buf.push(0); // mavlink_version
        buf.push(0); // CRC lo
        buf.push(0); // CRC hi
        buf
    }

    /// Build a v2 unsigned GLOBAL_POSITION_INT frame from the
    /// strict-subset wire fields. Used by the `to_entity` /
    /// `from_entity` round-trip tests.
    #[allow(clippy::too_many_arguments)]
    fn v2_global_position_int(
        sys: u8,
        comp: u8,
        time_boot_ms: u32,
        lat_e7: i32,
        lon_e7: i32,
        alt_mm: i32,
        relative_alt_mm: i32,
        vx: i16,
        vy: i16,
        vz: i16,
        hdg: u16,
    ) -> Vec<u8> {
        let payload_len: u8 = u8::try_from(GLOBAL_POSITION_INT_PAYLOAD_LEN).unwrap();
        let total = MAVLINK_V2_HEADER_LEN + payload_len as usize + MAVLINK_CRC_LEN;
        let mut buf = Vec::with_capacity(total);
        buf.push(MAVLINK_V2_MAGIC);
        buf.push(payload_len);
        buf.push(0); // INCOMPAT
        buf.push(0); // COMPAT
        buf.push(0); // SEQ
        buf.push(sys);
        buf.push(comp);
        buf.push((GLOBAL_POSITION_INT_MSG_ID & 0xFF) as u8);
        buf.push(((GLOBAL_POSITION_INT_MSG_ID >> 8) & 0xFF) as u8);
        buf.push(((GLOBAL_POSITION_INT_MSG_ID >> 16) & 0xFF) as u8);
        buf.extend_from_slice(&time_boot_ms.to_le_bytes());
        buf.extend_from_slice(&lat_e7.to_le_bytes());
        buf.extend_from_slice(&lon_e7.to_le_bytes());
        buf.extend_from_slice(&alt_mm.to_le_bytes());
        buf.extend_from_slice(&relative_alt_mm.to_le_bytes());
        buf.extend_from_slice(&vx.to_le_bytes());
        buf.extend_from_slice(&vy.to_le_bytes());
        buf.extend_from_slice(&vz.to_le_bytes());
        buf.extend_from_slice(&hdg.to_le_bytes());
        buf.push(0); // CRC lo
        buf.push(0); // CRC hi
        buf
    }

    #[test]
    fn mavlink_heartbeat_round_trips_through_entity_codec() {
        // HEARTBEAT entities cannot encode back through `from_entity`
        // (no Position) — round-trip is "to_entity preserves uid +
        // kind across two decodes of the same wire bytes".
        let codec = MavlinkEntityCodec;
        let frame = v2_heartbeat(7, 1, 12, 2);
        let e1 = codec.to_entity(&frame).expect("decode 1");
        let e2 = codec.to_entity(&frame).expect("decode 2");
        assert_eq!(e1.uid, e2.uid);
        assert_eq!(e1.kind, e2.kind);
        assert_eq!(e1.uid, "mavlink-7-1");
        assert_eq!(e1.kind, EntityKind::Aircraft);
        assert!(e1.position.is_none());
        // `from_entity` on a HEARTBEAT-only entity must surface the
        // typed unsupported error rather than silently emitting an
        // empty GLOBAL_POSITION_INT frame.
        let err = codec.from_entity(&e1).expect_err("from_entity");
        assert!(matches!(err, MavlinkEntityError::UnsupportedEntityKind(_)));
    }

    #[test]
    fn mavlink_global_position_int_to_entity_extracts_position() {
        // 42.0°N / -71.0°W / 100 m HAE — the canonical Massachusetts
        // coordinates the issue prescribes.
        let codec = MavlinkEntityCodec;
        let frame = v2_global_position_int(
            1,
            1,
            0,
            42 * 10_000_000,
            -71 * 10_000_000,
            100_000,
            100_000,
            0,
            0,
            0,
            u16::MAX,
        );
        let entity = codec.to_entity(&frame).expect("decode");
        let position = entity.position.expect("position present");
        assert!((position.lat - 42.0).abs() < 1e-9);
        assert!((position.lon - -71.0).abs() < 1e-9);
        assert_eq!(position.hae_meters, Some(100.0));
    }

    #[test]
    fn mavlink_global_position_int_to_entity_extracts_velocity() {
        // vx = 500 cm/s north, vy = 0 cm/s east → 5 m/s on a
        // bearing of 0° (true north). The (vx, vy) → (speed, course)
        // resolver inverts the polar conversion the encoder uses.
        let codec = MavlinkEntityCodec;
        let frame = v2_global_position_int(1, 1, 0, 0, 0, 0, 0, 500, 0, 0, u16::MAX);
        let entity = codec.to_entity(&frame).expect("decode");
        let velocity = entity.velocity.expect("velocity present");
        assert!((velocity.speed_m_s - 5.0).abs() < 1e-6);
        assert!(velocity.course_deg.abs() < 1e-6);
    }

    #[test]
    fn mavlink_uid_format_includes_system_and_component_id() {
        let codec = MavlinkEntityCodec;
        let frame = v2_heartbeat(1, 1, 0, 2);
        let entity = codec.to_entity(&frame).expect("decode");
        assert_eq!(entity.uid, "mavlink-1-1");
    }

    #[test]
    fn mavlink_heartbeat_quadrotor_maps_to_aircraft() {
        // MAV_TYPE_QUADROTOR (2) → EntityKind::Aircraft.
        let codec = MavlinkEntityCodec;
        let frame = v2_heartbeat(1, 1, 12, 2);
        let entity = codec.to_entity(&frame).expect("decode");
        assert_eq!(entity.kind, EntityKind::Aircraft);
    }

    #[test]
    fn mavlink_heartbeat_ground_rover_maps_to_ground() {
        // MAV_TYPE_GROUND_ROVER (10) → EntityKind::Ground.
        let codec = MavlinkEntityCodec;
        let frame = v2_heartbeat(1, 1, 12, 10);
        let entity = codec.to_entity(&frame).expect("decode");
        assert_eq!(entity.kind, EntityKind::Ground);
    }

    #[test]
    fn mavlink_heartbeat_unknown_type_maps_to_unknown_with_label() {
        // MAV_TYPE_GENERIC (0) → EntityKind::Unknown("mavlink-Generic").
        let codec = MavlinkEntityCodec;
        let frame = v2_heartbeat(1, 1, 0, 0);
        let entity = codec.to_entity(&frame).expect("decode");
        assert_eq!(entity.kind, EntityKind::Unknown("mavlink-Generic".into()));
    }

    #[test]
    fn mavlink_invalid_frame_returns_error() {
        let codec = MavlinkEntityCodec;
        // Empty buffer
        let err = codec.to_entity(&[]).expect_err("must fail on empty");
        assert!(matches!(err, MavlinkEntityError::InvalidFrame(_)));
        // Bogus magic byte
        let err = codec.to_entity(&[0x00, 0x01, 0x02]).expect_err("bad magic");
        assert!(matches!(err, MavlinkEntityError::InvalidFrame(_)));
    }

    #[test]
    fn mavlink_unsupported_message_returns_error() {
        // STATUSTEXT (MSG_ID 253) — present in the CRC-EXTRA table but
        // not mapped to Entity. The entity codec must surface the
        // typed error so the cross-protocol fan-out path knows the
        // frame has no canonical shape.
        let codec = MavlinkEntityCodec;
        let payload_len: u8 = 1;
        let total = MAVLINK_V2_HEADER_LEN + payload_len as usize + MAVLINK_CRC_LEN;
        let mut buf = Vec::with_capacity(total);
        buf.push(MAVLINK_V2_MAGIC);
        buf.push(payload_len);
        buf.push(0); // INCOMPAT
        buf.push(0); // COMPAT
        buf.push(0); // SEQ
        buf.push(1); // sys
        buf.push(1); // comp
        buf.push(253); // MSGID lo
        buf.push(0); // MSGID mid
        buf.push(0); // MSGID hi
        buf.push(0); // 1-byte payload
        buf.push(0); // CRC lo
        buf.push(0); // CRC hi
        let err = codec.to_entity(&buf).expect_err("unsupported");
        match err {
            MavlinkEntityError::UnsupportedMessage(id) => assert_eq!(id, 253),
            other => panic!("expected UnsupportedMessage(253), got {other:?}"),
        }
    }

    #[test]
    fn entity_with_no_position_emits_unsupported_for_from_entity() {
        // A free-form Entity with no Position has no MAVLink wire
        // representation. The codec must surface
        // UnsupportedEntityKind so the cross-protocol fan-out path
        // does not emit a malformed frame.
        let codec = MavlinkEntityCodec;
        let entity = Entity {
            uid: "mavlink-1-1".into(),
            kind: EntityKind::Unknown("text-only".into()),
            position: None,
            velocity: None,
            timestamp: SystemTime::UNIX_EPOCH,
            callsign: None,
            mil_std_2525_sidc: None,
            attributes: BTreeMap::new(),
        };
        let err = codec.from_entity(&entity).expect_err("must fail");
        assert!(matches!(err, MavlinkEntityError::UnsupportedEntityKind(_)));
    }

    #[test]
    fn entity_to_mavlink_emits_global_position_int() {
        // Encode a position-bearing Entity, then decode it back; the
        // round-trip preserves system / component identifiers and
        // lat / lon / alt to the resolution of the wire encoding.
        let codec = MavlinkEntityCodec;
        let frame = v2_global_position_int(
            5,
            1,
            1234,
            42 * 10_000_000,
            -71 * 10_000_000,
            100_000,
            100_000,
            500,
            0,
            0,
            u16::MAX,
        );
        let e1 = codec.to_entity(&frame).expect("decode 1");
        let bytes = codec.from_entity(&e1).expect("encode");
        let e2 = codec.to_entity(&bytes).expect("decode 2");
        assert_eq!(e1.uid, e2.uid);
        assert_eq!(e1.kind, e2.kind);
        assert_eq!(e1.position, e2.position);
        assert_eq!(e1.velocity, e2.velocity);
        // Verify the encoded frame parses as GLOBAL_POSITION_INT.
        let header = parse_header(&bytes).expect("header");
        assert_eq!(header.msg_id, GLOBAL_POSITION_INT_MSG_ID);
        assert_eq!(header.system_id, 5);
        assert_eq!(header.component_id, 1);
    }

    #[test]
    fn mav_msg_supported_covers_the_two_mapped_ids() {
        // Defense-in-depth on the public predicate: keep the helper in
        // sync with the `match` in `decode_frame` so a future PR that
        // extends one without the other fails here loudly.
        assert!(mav_msg_supported(HEARTBEAT_MSG_ID));
        assert!(mav_msg_supported(GLOBAL_POSITION_INT_MSG_ID));
        assert!(!mav_msg_supported(253));
    }

    #[test]
    fn mav_type_byte_dispatch_covers_every_documented_branch() {
        // Pin the table from the module docs. Adding a new variant
        // without documenting it would require touching this list.
        assert_eq!(MavType::from_byte(1).to_entity_kind(), EntityKind::Aircraft);
        assert_eq!(MavType::from_byte(2).to_entity_kind(), EntityKind::Aircraft);
        assert_eq!(MavType::from_byte(3).to_entity_kind(), EntityKind::Aircraft);
        assert_eq!(MavType::from_byte(4).to_entity_kind(), EntityKind::Aircraft);
        assert_eq!(
            MavType::from_byte(13).to_entity_kind(),
            EntityKind::Aircraft
        );
        assert_eq!(
            MavType::from_byte(14).to_entity_kind(),
            EntityKind::Aircraft
        );
        assert_eq!(
            MavType::from_byte(20).to_entity_kind(),
            EntityKind::Aircraft
        );
        assert_eq!(MavType::from_byte(10).to_entity_kind(), EntityKind::Ground);
        assert_eq!(MavType::from_byte(11).to_entity_kind(), EntityKind::Marine);
        assert_eq!(MavType::from_byte(12).to_entity_kind(), EntityKind::Marine);
        assert_eq!(MavType::from_byte(5).to_entity_kind(), EntityKind::Sensor);
        assert_eq!(MavType::from_byte(26).to_entity_kind(), EntityKind::Sensor);
        assert_eq!(MavType::from_byte(30).to_entity_kind(), EntityKind::Sensor);
        // Unknown carries the typed label tag.
        assert_eq!(
            MavType::from_byte(0).to_entity_kind(),
            EntityKind::Unknown("mavlink-Generic".into())
        );
        assert_eq!(
            MavType::from_byte(99).to_entity_kind(),
            EntityKind::Unknown("mavlink-Other(99)".into())
        );
    }
}
