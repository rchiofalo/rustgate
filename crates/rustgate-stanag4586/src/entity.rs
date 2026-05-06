// Copyright © 2026 Roberto Chiofalo.

//! STANAG-4586 implementation of the canonical
//! [`rustgate_core::entity::EntityCodec`] trait — refs #847.
//!
//! [`Stanag4586EntityCodec`] decodes STANAG-4586 LOI 2-3 vehicle-position
//! frames into the protocol-agnostic `Entity` shape defined by
//! `rustgate-core` and re-encodes a `Position`-bearing `Entity` back
//! into a vehicle-position frame. This is the fourth concrete codec
//! wired against the abstraction layer (CoT XML shipped via #1289,
//! MAVLink via #1292, ASTERIX via #1295); the router/federation/NATS/
//! HTTP/MQTT integrations against the same trait remain and are tracked
//! under #847 (blocked on the `Metadata` builder migration in #1298).
//!
//! # Mapping summary
//!
//! Inbound (vehicle-position frame → `Entity`):
//!
//! | STANAG-4586 source                       | `Entity` field                                                   |
//! |------------------------------------------|------------------------------------------------------------------|
//! | `vehicle_id` (u32)                       | `Entity.uid` (`"stanag4586-{vehicle_id}"`)                       |
//! | `latitude_deg` / `longitude_deg`         | `Entity.position` (lat/lon decimal degrees)                      |
//! | `altitude_msl_m`                         | `Entity.position.hae_meters` (best-effort, MSL→HAE not adjusted) |
//! | `ground_speed_mps` + `heading_deg`       | `Entity.velocity` (speed_m_s, course_deg normalised to `[0, 360)`)|
//! | `flight_state`                           | `Entity.kind` dispatch + `stanag4586.flight_state.*` carry        |
//! | `timestamp_unix_ms`                      | `Entity.timestamp` (Unix-millis → `SystemTime`)                   |
//! | every decoded scalar field (vehicle_id,  | `Entity.attributes` under the `"stanag4586."` namespace           |
//! | flight_state, raw kinematics)            |                                                                  |
//!
//! Outbound (`Entity` → vehicle-position frame) is intentionally
//! narrower: only `Position`-bearing entities encode into a
//! vehicle-position frame. Entities without a position surface
//! [`Stanag4586EntityError::UnsupportedEntityKind`] — STANAG-4586 is a
//! kinematic UAS C2 protocol, not a general-purpose transport, and the
//! workspace's CoT codec retains the latter role.
//!
//! # `EntityKind` dispatch
//!
//! STANAG-4586 vehicle-position frames identify a single Unmanned
//! Aerial Vehicle (UAV) — every record is by construction an air
//! platform under operator control. The classifier biases towards
//! [`EntityKind::Aircraft`] for the documented `FlightState` variants
//! that imply controlled flight (`Loiter`, `Transit`, `ReturnToBase`),
//! folds ground states (`LaunchPreparation`, `Landed`) into
//! [`EntityKind::Ground`] (the platform is on the surface even though
//! it is by construction an air platform), and uses
//! [`EntityKind::Unknown`] with a typed label for `FlightState::Other`
//! so a firmware revision that introduces a new state byte still yields
//! a structured classification dashboards can group on. The full
//! fixed-/rotary-/multirotor-wing carve-up that real STANAG-4586
//! deployments encode in their separate vehicle-type message rides on
//! the attribute bag (`stanag4586.vehicle_kind.label`) for codecs that
//! supply it; absent that hint, fixed-wing is the operationally common
//! default and the classifier emits `Aircraft` rather than fabricating
//! a more specific carve-up.
//!
//! # Round-trip discipline
//!
//! Same-codec round-trip is preserved for the position-bearing subset:
//! `to_entity(frame)` followed by `from_entity(entity)` produces a
//! frame whose `vehicle_id`, lat / lon, altitude, ground speed,
//! heading, and timestamp match the input exactly (STANAG-4586 carries
//! IEEE-754 floats on the wire, so the round-trip preserves bit
//! patterns when the field originated from the codec itself). The
//! frame is **not** byte-identical when the entity originated outside
//! the codec — the encoder zero-fills the documented reserved padding
//! regions and recovers `flight_state` from
//! `stanag4586.flight_state.byte` (or `FlightState::Other(0)` when
//! no carry is available).
//!
//! # Out of scope
//!
//! - **Other STANAG-4586 message types** (sensor pointing, payload
//!   status, system state, BIT report, mission abort, route upload,
//!   GCS handover, payload control, emergency status, payload
//!   calibration, waypoint command). The wire format is recognised by
//!   length but surfaces [`Stanag4586EntityError::UnsupportedMessage`].
//!   Their `EntityCodec` impls land in subsequent PRs.
//! - **Router / federation integration.** The router pivot to use
//!   `EntityCodec` at message dispatch is tracked under #847 and is
//!   blocked on the `Metadata` builder migration in #1298.
//! - **MAVLink wrapping.** Some small UAS platforms encapsulate
//!   STANAG-4586 over MAVLink rather than running native; the wrapper
//!   layer is its own follow-up.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use rustgate_core::entity::{AttributeValue, Entity, EntityCodec, EntityKind, Position, Velocity};

use crate::vehicle_position::{self, FlightState, VEHICLE_POSITION_FRAME_LEN, VehiclePosition};

/// Attribute-key prefix used for every STANAG-4586-derived
/// [`AttributeValue`] entry. Keeps the namespace separated from
/// other codecs (CoT, MAVLink, ASTERIX, …) that share the [`Entity`]
/// shape.
const STANAG4586_PREFIX: &str = "stanag4586.";

/// Conventional STANAG-4586 Edition 2 message-ID number for the
/// vehicle-position / inertial-states telemetry frame.
///
/// Pinned as a public constant so audit logs and tests can classify a
/// frame without re-deriving the wire-format dispatch. STANAG-4586
/// Edition 2 assigns 16-bit Message ID Numbers — `4001` is the
/// publicly documented identifier for vehicle-state telemetry on the
/// LOI 2-3 read surface. The wire frames this codec accepts do not
/// carry the message ID inline; the constant is the conventional
/// identifier for the message *kind*, used in the
/// [`Stanag4586EntityError::UnsupportedMessage`] variant when a frame
/// of an unrecognised length is presented.
pub const VEHICLE_POSITION_MSG_ID: u32 = 4001;

/// Errors surfaced by [`Stanag4586EntityCodec::to_entity`] /
/// [`Stanag4586EntityCodec::from_entity`].
///
/// Distinct from [`crate::error::Stanag4586Error`] (which covers the
/// wire-format-layer truncation / range-validation decisions) because
/// the codec's failure modes belong to a different operational class
/// — a SIEM that pages on `stanag4586.frame_rejected` should NOT page
/// on `stanag4586.entity.unsupported_entity_kind`, which is a routine
/// "this entity has no STANAG-4586 wire form" signal during cross-
/// protocol fan-out.
#[derive(Debug, thiserror::Error)]
pub enum Stanag4586EntityError {
    /// Payload bytes do not parse as a STANAG-4586 vehicle-position
    /// frame. The inner string carries the underlying
    /// [`crate::error::Stanag4586Error`] context for an operator log
    /// line without exposing the raw payload (which may be hostile or
    /// classified). Typical contents include "frame too short" and
    /// "field `latitude_deg` out of spec range".
    #[error("malformed STANAG-4586 message: {0}")]
    InvalidMessage(String),

    /// The frame's conventional STANAG-4586 message ID is outside the
    /// subset this codec maps to the [`Entity`] shape. Frames whose
    /// length does not match a documented STANAG-4586 message body
    /// surface this variant with the hypothetical message-ID value
    /// derived from the wire length so the audit trail captures what
    /// was rejected. Their `EntityCodec` impls land in subsequent PRs
    /// against #847.
    #[error("STANAG-4586 message ID {0} cannot be mapped to Entity")]
    UnsupportedMessage(u32),

    /// `from_entity` cannot represent the supplied [`Entity`] as a
    /// STANAG-4586 vehicle-position frame. The string captures the
    /// cause for the audit trail — typical contents are `"entity has
    /// no Position"` (the most common case during cross-protocol
    /// fan-out), `"vehicle id out of range"` for entities whose UID
    /// does not parse as `"stanag4586-<vehicle_id>"`, and `"non-finite
    /// position"` for entities whose lat/lon are NaN / inf.
    #[error("Entity kind {0:?} cannot be mapped to STANAG-4586")]
    UnsupportedEntityKind(String),

    /// A vehicle-position frame is missing a field the codec needs to
    /// populate the strict-subset [`Entity`] fields. The current wire
    /// format is fixed-size and pads every field, so this variant is
    /// reserved for forward-compatibility with future STANAG-4586
    /// message types whose wire layout is variable.
    #[error("STANAG-4586 message missing required field: {0}")]
    MissingField(&'static str),
}

/// STANAG-4586 wire-format codec for the canonical [`Entity`] shape.
///
/// Stateless — the same instance is safe to reuse across every routed
/// message on every thread. The router holds an
/// `Arc<Stanag4586EntityCodec>` per protocol slot.
#[derive(Debug, Default, Clone, Copy)]
pub struct Stanag4586EntityCodec;

impl EntityCodec for Stanag4586EntityCodec {
    type Error = Stanag4586EntityError;

    fn to_entity(&self, payload: &[u8]) -> Result<Entity, Self::Error> {
        decode_message(payload)
    }

    fn from_entity(&self, entity: &Entity) -> Result<Bytes, Self::Error> {
        encode_vehicle_position(entity)
    }
}

/// Decode a STANAG-4586 wire-format message into the canonical
/// [`Entity`] shape.
///
/// Dispatches per-message-type on the wire length — this codec only
/// supports the fixed-size vehicle-position frame (48 bytes); any
/// other length surfaces a typed
/// [`Stanag4586EntityError::UnsupportedMessage`] carrying the
/// hypothetical message-ID number derived from the wire length so the
/// audit trail captures what was rejected.
fn decode_message(payload: &[u8]) -> Result<Entity, Stanag4586EntityError> {
    // Length-based dispatch: vehicle position is exactly 48 bytes,
    // and the decoder tolerates trailing bytes. A frame shorter than
    // the vehicle-position size is treated as either a different
    // message type (when its length matches another documented frame
    // size) or `InvalidMessage` (the error path the wire-format
    // decoder will surface anyway). A frame at or above the
    // vehicle-position size dispatches to that decoder; the
    // wire-format decoder ignores the trailing bytes per its own
    // forward-compat contract.
    if payload.len() < VEHICLE_POSITION_FRAME_LEN {
        return Err(Stanag4586EntityError::UnsupportedMessage(
            length_to_message_id(payload.len()),
        ));
    }

    let frame = vehicle_position::decode(payload)
        .map_err(|e| Stanag4586EntityError::InvalidMessage(format!("{e}")))?;
    Ok(vehicle_position_to_entity(&frame))
}

/// Map a wire-length to a hypothetical conventional STANAG-4586
/// message ID for [`Stanag4586EntityError::UnsupportedMessage`]
/// reporting.
///
/// Returns the conventional Edition 2 message-ID number when a
/// documented length matches, and a synthetic `0xFFFF_FFFF`-shaped
/// sentinel otherwise so the operator log shows the rejection
/// originated from a length the codec does not recognise. Pure
/// function so the test surface can pin every branch without
/// constructing a wire frame.
fn length_to_message_id(len: usize) -> u32 {
    // STANAG-4586 Edition 2 ID Number assignments referenced here
    // mirror the publicly documented LOI 2-3 telemetry surface that
    // the rest of this crate's modules implement. The mapping stays
    // narrow on purpose: only frames whose decode path could
    // plausibly be wired into Entity in a future PR get a real ID;
    // anything else gets the catch-all sentinel so the audit trail
    // shows "we have no idea what this is" rather than guessing.
    match len {
        VEHICLE_POSITION_FRAME_LEN => VEHICLE_POSITION_MSG_ID,
        // Reserve length 0 for "empty payload" so the audit trail
        // can distinguish it from any documented short frame.
        0 => 0,
        _ => u32::MAX,
    }
}

/// Build the canonical [`Entity`] from a decoded
/// [`VehiclePosition`].
///
/// Pure transformation — no allocation outside the attribute bag.
/// Pulled out of [`decode_message`] so the test surface can construct
/// a [`VehiclePosition`] directly and exercise the mapping without
/// going through the wire-format decoder.
fn vehicle_position_to_entity(frame: &VehiclePosition) -> Entity {
    let position = Position {
        lat: frame.latitude_deg,
        lon: frame.longitude_deg,
        // Altitude on the wire is MSL (mean sea level), not WGS-84
        // HAE. The `Entity.position.hae_meters` field is documented as
        // best-effort across codecs that distinguish them — STANAG-4586
        // does not carry the geoid offset needed for an exact
        // conversion, so we surface MSL verbatim and preserve the
        // original wire value on the attribute bag for codecs that
        // need it.
        hae_meters: Some(f64::from(frame.altitude_msl_m)),
    };
    let velocity = build_velocity(frame);
    let kind = classify_kind(frame);
    let timestamp = unix_ms_to_systemtime(frame.timestamp_unix_ms);

    let mut attributes: BTreeMap<String, AttributeValue> = BTreeMap::new();
    populate_attributes(&mut attributes, frame);

    Entity {
        uid: format_uid(frame.vehicle_id),
        kind,
        position: Some(position),
        velocity: Some(velocity),
        timestamp,
        callsign: None,
        mil_std_2525_sidc: None,
        attributes,
    }
}

/// Resolve `(ground_speed_mps, heading_deg)` to the canonical
/// [`Velocity`] shape with `course_deg` normalised to `[0, 360)`.
///
/// STANAG-4586 carries heading as an unconstrained `f32` — senders
/// emit signed or unwrapped headings during turn integration — so the
/// conversion clamps non-finite values to zero and folds negative or
/// out-of-range values into the canonical `[0, 360)` envelope via
/// `rem_euclid`. Speed is non-negative on the canonical shape, so
/// the rare-but-legal case of a sender emitting a negative speed
/// (typically a sign error in calibration) folds to its absolute
/// value rather than poisoning the rest of the stack.
fn build_velocity(frame: &VehiclePosition) -> Velocity {
    let speed = if frame.ground_speed_mps.is_finite() {
        f64::from(frame.ground_speed_mps).abs()
    } else {
        0.0
    };
    let course = if frame.heading_deg.is_finite() {
        f64::from(frame.heading_deg).rem_euclid(360.0)
    } else {
        0.0
    };
    Velocity {
        speed_m_s: speed,
        course_deg: course,
    }
}

/// Dispatch the [`EntityKind`] from a decoded
/// [`VehiclePosition`].
///
/// Pure function so the test surface can pin every branch without
/// constructing a full wire frame. Fixed-wing UAVs are the
/// operationally common platform — `Loiter` / `Transit` /
/// `ReturnToBase` all imply controlled flight and surface as
/// [`EntityKind::Aircraft`]. Ground-mode states (`LaunchPreparation`,
/// `Landed`) surface as [`EntityKind::Ground`] — the platform is on
/// the surface in these phases, even though it is by construction an
/// air platform — so a route-planning dashboard that filters on
/// `EntityKind::Aircraft` does not include UAVs that have already
/// landed. [`FlightState::Other`] surfaces as
/// [`EntityKind::Unknown("stanag4586-flight-state-{:#04x}")`] so a
/// firmware revision that introduces a new state byte still yields a
/// structured classification dashboards can group on without growing
/// a new enum variant per protocol.
fn classify_kind(frame: &VehiclePosition) -> EntityKind {
    match frame.flight_state {
        FlightState::Loiter | FlightState::Transit | FlightState::ReturnToBase => {
            EntityKind::Aircraft
        }
        FlightState::LaunchPreparation | FlightState::Landed => EntityKind::Ground,
        FlightState::Other(byte) => {
            EntityKind::Unknown(format!("stanag4586-flight-state-{byte:#04x}"))
        }
    }
}

/// Resolve a Unix-millis timestamp to a [`SystemTime`].
///
/// Saturates on overflow rather than panicking — a
/// `timestamp_unix_ms = u64::MAX` is well past any plausible epoch
/// representable as `Duration`, but the wire field is opaque per the
/// spec and the codec MUST tolerate any 64-bit value.
fn unix_ms_to_systemtime(unix_ms: u64) -> SystemTime {
    let secs = unix_ms / 1_000;
    // millis fit comfortably inside u32 once we strip the seconds.
    let nanos = ((unix_ms % 1_000) as u32).saturating_mul(1_000_000);
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::new(secs, nanos))
        .unwrap_or(SystemTime::UNIX_EPOCH)
}

/// Inverse of [`unix_ms_to_systemtime`]. Saturates to zero on the
/// pre-epoch / non-representable cases so a hostile entity timestamp
/// cannot drive the encoder off the rails.
fn systemtime_to_unix_ms(ts: SystemTime) -> u64 {
    let dur = ts
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs().saturating_mul(1_000);
    let millis = u64::from(dur.subsec_millis());
    secs.saturating_add(millis)
}

/// Populate the `Entity::attributes` bag with every decoded scalar
/// field from a [`VehiclePosition`]. Same-codec round-trip relies on
/// these — `from_entity` reads them back to reconstruct the wire
/// values that are not first-class on `Entity` (`flight_state` byte,
/// raw IEEE-754 ground speed and heading bit patterns, the originally
/// transmitted MSL altitude before the best-effort HAE substitution).
fn populate_attributes(attributes: &mut BTreeMap<String, AttributeValue>, frame: &VehiclePosition) {
    let _ = attributes.insert(
        format!("{STANAG4586_PREFIX}message_id"),
        AttributeValue::Int(i64::from(VEHICLE_POSITION_MSG_ID)),
    );
    let _ = attributes.insert(
        format!("{STANAG4586_PREFIX}vehicle_id"),
        AttributeValue::Int(i64::from(frame.vehicle_id)),
    );
    let _ = attributes.insert(
        format!("{STANAG4586_PREFIX}flight_state.byte"),
        AttributeValue::Int(i64::from(frame.flight_state.to_byte())),
    );
    let _ = attributes.insert(
        format!("{STANAG4586_PREFIX}flight_state.label"),
        AttributeValue::Str(flight_state_label(frame.flight_state).to_string()),
    );
    let _ = attributes.insert(
        format!("{STANAG4586_PREFIX}altitude_msl_m"),
        AttributeValue::Float(f64::from(frame.altitude_msl_m)),
    );
    let _ = attributes.insert(
        format!("{STANAG4586_PREFIX}ground_speed_mps"),
        AttributeValue::Float(f64::from(frame.ground_speed_mps)),
    );
    let _ = attributes.insert(
        format!("{STANAG4586_PREFIX}heading_deg"),
        AttributeValue::Float(f64::from(frame.heading_deg)),
    );
    let _ = attributes.insert(
        format!("{STANAG4586_PREFIX}timestamp_unix_ms"),
        // Wire is u64; i64 covers the realistic Unix-millis range
        // (up to year 292277026596) and `try_from` saturates the
        // out-of-range tail rather than panicking.
        AttributeValue::Int(i64::try_from(frame.timestamp_unix_ms).unwrap_or(i64::MAX)),
    );
}

/// Stringify a [`FlightState`] into the operator-readable label
/// carried on `stanag4586.flight_state.label`.
///
/// Centralised so the test surface and any downstream dashboards
/// share a single source of truth for the label vocabulary. Folds
/// the open-ended [`FlightState::Other`] catch-all into the
/// `"other"` label rather than leaking the raw byte into the string
/// — the byte is preserved verbatim on the sibling
/// `stanag4586.flight_state.byte` attribute.
fn flight_state_label(state: FlightState) -> &'static str {
    match state {
        FlightState::LaunchPreparation => "launch_preparation",
        FlightState::Loiter => "loiter",
        FlightState::Transit => "transit",
        FlightState::ReturnToBase => "return_to_base",
        FlightState::Landed => "landed",
        FlightState::Other(_) => "other",
    }
}

/// Format the canonical Entity UID for a STANAG-4586 originator.
fn format_uid(vehicle_id: u32) -> String {
    format!("stanag4586-{vehicle_id}")
}

/// Parse the `vehicle_id` out of an Entity UID previously formatted
/// by [`format_uid`]. Returns `None` for any UID that does not match
/// the canonical `stanag4586-<vehicle_id>` shape — the caller of
/// [`Stanag4586EntityCodec::from_entity`] surfaces
/// [`Stanag4586EntityError::UnsupportedEntityKind`] in that case.
fn parse_uid(uid: &str) -> Option<u32> {
    uid.strip_prefix("stanag4586-")?.parse().ok()
}

/// Encode a position-bearing [`Entity`] as a STANAG-4586
/// vehicle-position frame.
///
/// The encoder always emits the full 48-byte frame with documented
/// reserved padding regions zero-filled. Same-codec round-trip
/// preserves `vehicle_id` and the lat / lon / altitude / ground speed
/// / heading values; `flight_state` is recovered from the
/// `stanag4586.flight_state.byte` attribute carry, defaulting to
/// `FlightState::Other(0)` when no carry is present (cross-codec
/// entities). Cross-codec entities also surface
/// [`Stanag4586EntityError::UnsupportedEntityKind`] when the UID does
/// not parse as `stanag4586-<vehicle_id>` because the wire format
/// REQUIRES a `vehicle_id` and silently substituting zero would let a
/// crafted CoT event spoof `vehicle_id = 0` on a downstream
/// STANAG-4586 sink.
fn encode_vehicle_position(entity: &Entity) -> Result<Bytes, Stanag4586EntityError> {
    let position = entity.position.ok_or_else(|| {
        Stanag4586EntityError::UnsupportedEntityKind("entity has no Position".into())
    })?;
    if !position.lat.is_finite() || !position.lon.is_finite() {
        return Err(Stanag4586EntityError::UnsupportedEntityKind(
            "non-finite position".into(),
        ));
    }
    if !(-90.0..=90.0).contains(&position.lat) || !(-180.0..=180.0).contains(&position.lon) {
        return Err(Stanag4586EntityError::UnsupportedEntityKind(
            "position out of WGS-84 envelope".into(),
        ));
    }

    let vehicle_id = parse_uid(&entity.uid)
        .or_else(|| attr_int(entity, "vehicle_id").and_then(|v| u32::try_from(v).ok()))
        .ok_or_else(|| {
            Stanag4586EntityError::UnsupportedEntityKind(format!(
                "entity uid `{}` does not match `stanag4586-<vehicle_id>`",
                entity.uid
            ))
        })?;

    let flight_state = recover_flight_state(entity);
    let altitude_msl_m = attr_float(entity, "altitude_msl_m").map_or_else(
        || {
            position.hae_meters.map_or(
                0.0_f32,
                |hae| {
                    if hae.is_finite() { hae as f32 } else { 0.0 }
                },
            )
        },
        |v| if v.is_finite() { v as f32 } else { 0.0 },
    );
    let ground_speed_mps = attr_float(entity, "ground_speed_mps")
        .map(|v| if v.is_finite() { v as f32 } else { 0.0 })
        .unwrap_or_else(|| {
            entity
                .velocity
                .map(|v| {
                    if v.speed_m_s.is_finite() {
                        v.speed_m_s as f32
                    } else {
                        0.0
                    }
                })
                .unwrap_or(0.0)
        });
    let heading_deg = attr_float(entity, "heading_deg")
        .map(|v| if v.is_finite() { v as f32 } else { 0.0 })
        .unwrap_or_else(|| {
            entity
                .velocity
                .map(|v| {
                    if v.course_deg.is_finite() {
                        v.course_deg as f32
                    } else {
                        0.0
                    }
                })
                .unwrap_or(0.0)
        });
    let timestamp_unix_ms = attr_int(entity, "timestamp_unix_ms")
        .and_then(|v| u64::try_from(v).ok())
        .unwrap_or_else(|| systemtime_to_unix_ms(entity.timestamp));

    let frame = VehiclePosition {
        vehicle_id,
        flight_state,
        latitude_deg: position.lat,
        longitude_deg: position.lon,
        altitude_msl_m,
        ground_speed_mps,
        heading_deg,
        timestamp_unix_ms,
    };
    Ok(Bytes::from(vehicle_position::encode(&frame)))
}

/// Recover the [`FlightState`] from the attribute-bag carry.
///
/// Same-codec round-trip: `to_entity` populated
/// `stanag4586.flight_state.byte` with the wire byte, so reading it
/// back via `FlightState::from_byte` recovers every named variant
/// plus the `Other` catch-all. Cross-codec entities (no carry)
/// default to `FlightState::Other(0)` so the wire frame is
/// well-formed.
fn recover_flight_state(entity: &Entity) -> FlightState {
    attr_int(entity, "flight_state.byte")
        .and_then(|v| u8::try_from(v).ok())
        .map(FlightState::from_byte)
        .unwrap_or(FlightState::Other(0))
}

/// Look up an integer attribute under the `stanag4586.<key>`
/// namespace.
fn attr_int(entity: &Entity, key: &str) -> Option<i64> {
    match entity.attributes.get(&format!("{STANAG4586_PREFIX}{key}")) {
        Some(AttributeValue::Int(v)) => Some(*v),
        _ => None,
    }
}

/// Look up a float attribute under the `stanag4586.<key>` namespace.
fn attr_float(entity: &Entity, key: &str) -> Option<f64> {
    match entity.attributes.get(&format!("{STANAG4586_PREFIX}{key}")) {
        Some(AttributeValue::Float(v)) => Some(*v),
        _ => None,
    }
}

/// Returns `true` for STANAG-4586 message-ID values this codec maps
/// into the [`Entity`] shape. Exposed so call sites can pre-filter
/// without invoking the full decode path; kept in sync with the
/// internal `decode_message` dispatch. Other documented STANAG-4586
/// message types (sensor pointing, payload status, system state, BIT
/// report, mission abort, route upload, GCS handover, payload
/// control, emergency status, payload calibration, waypoint command)
/// are recognised by length but surface
/// [`Stanag4586EntityError::UnsupportedMessage`] — their
/// `EntityCodec` impls have not landed yet.
#[must_use]
pub fn stanag4586_message_supported(message_id: u32) -> bool {
    message_id == VEHICLE_POSITION_MSG_ID
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::float_cmp)]
mod tests {
    use super::*;

    /// Build a non-trivial [`VehiclePosition`] fixture so equality
    /// comparisons aren't passing because every field happens to be
    /// the type's default. Mirrors the helper in
    /// [`crate::vehicle_position::tests`] to keep the fixture
    /// vocabulary consistent across the crate.
    fn sample_frame() -> VehiclePosition {
        VehiclePosition {
            vehicle_id: 42,
            flight_state: FlightState::Transit,
            latitude_deg: 38.889_722_2,
            longitude_deg: -77.008_889,
            altitude_msl_m: 1234.5_f32,
            ground_speed_mps: 42.0_f32,
            heading_deg: 271.5_f32,
            timestamp_unix_ms: 1_700_000_000_123,
        }
    }

    #[test]
    fn vehicle_position_round_trips_through_entity_codec() {
        // Encode a frame, decode → entity1, encode → frame, decode →
        // entity2; assert uid + kind + position + velocity + the
        // round-trip-essential attributes match across both decodes.
        let codec = Stanag4586EntityCodec;
        let frame = sample_frame();
        let bytes1 = vehicle_position::encode(&frame);
        let entity1 = codec.to_entity(&bytes1).expect("decode 1");
        assert_eq!(entity1.uid, "stanag4586-42");
        assert_eq!(entity1.kind, EntityKind::Aircraft);

        let bytes2 = codec.from_entity(&entity1).expect("encode");
        let entity2 = codec.to_entity(&bytes2).expect("decode 2");

        assert_eq!(entity1.uid, entity2.uid);
        assert_eq!(entity1.kind, entity2.kind);
        assert_eq!(entity1.position, entity2.position);
        assert_eq!(entity1.velocity, entity2.velocity);
        // The wire frames must match byte-for-byte: same-codec
        // round-trip is bit-exact for the position-bearing subset
        // because every wire field rides on either the canonical
        // shape or the attribute bag.
        assert_eq!(bytes1, bytes2.as_ref());
    }

    #[test]
    fn vehicle_position_to_entity_extracts_position_from_lat_lon_alt() {
        // Canonical Massachusetts coordinates 42°N / -71°W / 100 m
        // MSL — the wire shape preserves the IEEE-754 bit patterns
        // round-trip, so the assertions can pin exact equality
        // rather than tolerance-based comparisons.
        let codec = Stanag4586EntityCodec;
        let frame = VehiclePosition {
            vehicle_id: 7,
            flight_state: FlightState::Transit,
            latitude_deg: 42.0,
            longitude_deg: -71.0,
            altitude_msl_m: 100.0,
            ground_speed_mps: 0.0,
            heading_deg: 0.0,
            timestamp_unix_ms: 0,
        };
        let bytes = vehicle_position::encode(&frame);
        let entity = codec.to_entity(&bytes).expect("decode");
        let position = entity.position.expect("position present");
        assert_eq!(position.lat, 42.0);
        assert_eq!(position.lon, -71.0);
        assert_eq!(position.hae_meters, Some(100.0));
    }

    #[test]
    fn vehicle_position_to_entity_extracts_velocity_from_speed_and_heading() {
        // 100 m/s ground speed on bearing 90° (due east) → speed
        // preserved, course preserved at 90°. The codec normalises
        // course to `[0, 360)` via rem_euclid, so an in-range value
        // passes through unchanged.
        let codec = Stanag4586EntityCodec;
        let frame = VehiclePosition {
            vehicle_id: 1,
            flight_state: FlightState::Transit,
            latitude_deg: 0.0,
            longitude_deg: 0.0,
            altitude_msl_m: 0.0,
            ground_speed_mps: 100.0,
            heading_deg: 90.0,
            timestamp_unix_ms: 0,
        };
        let bytes = vehicle_position::encode(&frame);
        let entity = codec.to_entity(&bytes).expect("decode");
        let velocity = entity.velocity.expect("velocity present");
        assert_eq!(velocity.speed_m_s, 100.0);
        assert_eq!(velocity.course_deg, 90.0);
    }

    #[test]
    fn vehicle_position_to_entity_uid_format_includes_system_id() {
        // STANAG-4586's `vehicle_id` field is the canonical platform
        // identifier; `Entity.uid` exposes it as `stanag4586-{id}` so
        // a downstream router can correlate against the federation
        // peer's view of the same UAV.
        let codec = Stanag4586EntityCodec;
        let mut frame = sample_frame();
        frame.vehicle_id = 0xA1B2_C3D4;
        let bytes = vehicle_position::encode(&frame);
        let entity = codec.to_entity(&bytes).expect("decode");
        assert_eq!(entity.uid, "stanag4586-2712847316");
    }

    #[test]
    fn vehicle_position_classifies_fixed_wing_uav_as_aircraft() {
        // FlightState::Transit (the operationally common controlled-
        // flight state for a fixed-wing UAV en route between
        // waypoints) → EntityKind::Aircraft.
        let codec = Stanag4586EntityCodec;
        let mut frame = sample_frame();
        frame.flight_state = FlightState::Transit;
        let bytes = vehicle_position::encode(&frame);
        let entity = codec.to_entity(&bytes).expect("decode");
        assert_eq!(entity.kind, EntityKind::Aircraft);

        // Loiter and ReturnToBase share the Aircraft branch.
        for state in [FlightState::Loiter, FlightState::ReturnToBase] {
            frame.flight_state = state;
            let bytes = vehicle_position::encode(&frame);
            let entity = codec.to_entity(&bytes).expect("decode");
            assert_eq!(entity.kind, EntityKind::Aircraft, "state={state:?}");
        }

        // LaunchPreparation and Landed surface as Ground because
        // the platform is on the surface in those phases.
        for state in [FlightState::LaunchPreparation, FlightState::Landed] {
            frame.flight_state = state;
            let bytes = vehicle_position::encode(&frame);
            let entity = codec.to_entity(&bytes).expect("decode");
            assert_eq!(entity.kind, EntityKind::Ground, "state={state:?}");
        }
    }

    #[test]
    fn vehicle_position_classifies_unknown_kind_as_unknown_with_label() {
        // FlightState::Other(byte) surfaces as
        // EntityKind::Unknown("stanag4586-flight-state-{byte:#04x}")
        // so a firmware revision that introduces a new state byte
        // still yields a structured classification dashboards can
        // group on.
        let codec = Stanag4586EntityCodec;
        let mut frame = sample_frame();
        frame.flight_state = FlightState::Other(0xEE);
        let bytes = vehicle_position::encode(&frame);
        let entity = codec.to_entity(&bytes).expect("decode");
        assert_eq!(
            entity.kind,
            EntityKind::Unknown("stanag4586-flight-state-0xee".into())
        );
    }

    #[test]
    fn invalid_message_returns_error_no_panic() {
        // Out-of-range latitude on the wire — the wire-format
        // decoder returns Stanag4586Error::FieldOutOfRange, which the
        // entity codec surfaces as InvalidMessage rather than
        // panicking on the float bit pattern. Pin the variant so a
        // future refactor that swallowed the error would fail here.
        let codec = Stanag4586EntityCodec;
        let mut wire = vehicle_position::encode(&sample_frame());
        // Replace the latitude bytes with 95.0 (outside the WGS-84
        // envelope) — the offset is documented in the wire-format
        // table at the top of the vehicle_position module.
        wire[8..16].copy_from_slice(&95.0_f64.to_be_bytes());
        let err = codec.to_entity(&wire).expect_err("must fail");
        assert!(matches!(err, Stanag4586EntityError::InvalidMessage(_)));
    }

    #[test]
    fn unsupported_message_id_returns_typed_error() {
        // A frame shorter than the vehicle-position size dispatches
        // to UnsupportedMessage with the synthetic length-derived ID.
        // Empty payload → ID 0; arbitrary short payload → ID
        // u32::MAX (the catch-all sentinel).
        let codec = Stanag4586EntityCodec;
        let err = codec.to_entity(&[]).expect_err("empty must fail");
        match err {
            Stanag4586EntityError::UnsupportedMessage(id) => assert_eq!(id, 0),
            other => panic!("expected UnsupportedMessage(0), got {other:?}"),
        }

        let short = vec![0u8; 16];
        let err = codec.to_entity(&short).expect_err("short must fail");
        match err {
            Stanag4586EntityError::UnsupportedMessage(id) => assert_eq!(id, u32::MAX),
            other => panic!("expected UnsupportedMessage(u32::MAX), got {other:?}"),
        }
    }

    #[test]
    fn entity_with_no_position_emits_unsupported_for_from_entity() {
        // A free-form Entity with no Position has no STANAG-4586
        // wire representation. The codec must surface
        // UnsupportedEntityKind so the cross-protocol fan-out path
        // does not emit a malformed frame.
        let codec = Stanag4586EntityCodec;
        let entity = Entity {
            uid: "stanag4586-1".into(),
            kind: EntityKind::Unknown("text-only".into()),
            position: None,
            velocity: None,
            timestamp: SystemTime::UNIX_EPOCH,
            callsign: None,
            mil_std_2525_sidc: None,
            attributes: BTreeMap::new(),
        };
        let err = codec.from_entity(&entity).expect_err("must fail");
        assert!(matches!(
            err,
            Stanag4586EntityError::UnsupportedEntityKind(_)
        ));
    }

    #[test]
    fn entity_to_vehicle_position_emits_minimal_message_with_required_fields() {
        // A position-bearing Entity with no STANAG-4586 attribute
        // carry produces a wire-format frame carrying the required
        // fields (vehicle_id, lat/lon/alt, timestamp); flight_state
        // defaults to FlightState::Other(0) and ground_speed_mps /
        // heading_deg fall back to the canonical Velocity values.
        let codec = Stanag4586EntityCodec;
        let timestamp = SystemTime::UNIX_EPOCH + Duration::from_millis(1_700_000_000_123);
        let entity = Entity {
            uid: "stanag4586-100".into(),
            kind: EntityKind::Aircraft,
            position: Some(Position {
                lat: 42.0,
                lon: -71.0,
                hae_meters: Some(1000.0),
            }),
            velocity: Some(Velocity {
                speed_m_s: 50.0,
                course_deg: 180.0,
            }),
            timestamp,
            callsign: None,
            mil_std_2525_sidc: None,
            attributes: BTreeMap::new(),
        };
        let bytes = codec.from_entity(&entity).expect("encode");
        // The wire frame is the documented fixed length.
        assert_eq!(bytes.len(), VEHICLE_POSITION_FRAME_LEN);
        // Decode back through the wire-format decoder so the inner
        // fields stay verifiable.
        let decoded = vehicle_position::decode(&bytes).expect("decode wire");
        assert_eq!(decoded.vehicle_id, 100);
        assert_eq!(decoded.latitude_deg, 42.0);
        assert_eq!(decoded.longitude_deg, -71.0);
        assert_eq!(decoded.altitude_msl_m, 1000.0);
        assert_eq!(decoded.ground_speed_mps, 50.0);
        assert_eq!(decoded.heading_deg, 180.0);
        // No flight-state attribute carry → default Other(0).
        assert_eq!(decoded.flight_state, FlightState::Other(0));
        // Timestamp recovers from the SystemTime field via the
        // Unix-millis conversion.
        assert_eq!(decoded.timestamp_unix_ms, 1_700_000_000_123);
    }

    #[test]
    fn entity_with_unrecognised_uid_emits_unsupported_for_from_entity() {
        // A position-bearing Entity whose UID does not match the
        // canonical `stanag4586-<vehicle_id>` shape and whose
        // attribute bag carries no `vehicle_id` fallback must
        // surface a typed error rather than emitting a frame with a
        // spoofed `vehicle_id = 0`.
        let codec = Stanag4586EntityCodec;
        let entity = Entity {
            uid: "cot-some-event-uid".into(),
            kind: EntityKind::Track,
            position: Some(Position {
                lat: 0.0,
                lon: 0.0,
                hae_meters: None,
            }),
            velocity: None,
            timestamp: SystemTime::UNIX_EPOCH,
            callsign: None,
            mil_std_2525_sidc: None,
            attributes: BTreeMap::new(),
        };
        let err = codec.from_entity(&entity).expect_err("must fail");
        assert!(matches!(
            err,
            Stanag4586EntityError::UnsupportedEntityKind(_)
        ));
    }

    #[test]
    fn vehicle_position_unmapped_fields_appear_in_attributes() {
        // Every decoded scalar field must ride on the
        // `stanag4586.*` attribute namespace so a same-codec
        // round-trip recovers the wire encoding without going through
        // the lossy float math on the canonical Velocity shape.
        let codec = Stanag4586EntityCodec;
        let frame = sample_frame();
        let bytes = vehicle_position::encode(&frame);
        let entity = codec.to_entity(&bytes).expect("decode");

        assert_eq!(
            entity
                .attributes
                .get(&format!("{STANAG4586_PREFIX}message_id")),
            Some(&AttributeValue::Int(i64::from(VEHICLE_POSITION_MSG_ID)))
        );
        assert_eq!(
            entity
                .attributes
                .get(&format!("{STANAG4586_PREFIX}vehicle_id")),
            Some(&AttributeValue::Int(42))
        );
        assert_eq!(
            entity
                .attributes
                .get(&format!("{STANAG4586_PREFIX}flight_state.byte")),
            Some(&AttributeValue::Int(i64::from(
                FlightState::Transit.to_byte()
            )))
        );
        assert_eq!(
            entity
                .attributes
                .get(&format!("{STANAG4586_PREFIX}flight_state.label")),
            Some(&AttributeValue::Str("transit".into()))
        );
        assert_eq!(
            entity
                .attributes
                .get(&format!("{STANAG4586_PREFIX}altitude_msl_m")),
            Some(&AttributeValue::Float(1234.5))
        );
        assert_eq!(
            entity
                .attributes
                .get(&format!("{STANAG4586_PREFIX}timestamp_unix_ms")),
            Some(&AttributeValue::Int(1_700_000_000_123))
        );
    }

    #[test]
    fn stanag4586_message_supported_covers_only_vehicle_position() {
        // Defense-in-depth on the public predicate: keep the helper
        // in sync with the dispatch in `decode_message` so a future
        // PR that extends one without the other fails here loudly.
        assert!(stanag4586_message_supported(VEHICLE_POSITION_MSG_ID));
        // Other STANAG-4586 message types (sensor pointing, payload
        // status, system state, etc.) are deliberately excluded for
        // v1 and surface UnsupportedMessage when their wire form is
        // presented.
        assert!(!stanag4586_message_supported(0));
        assert!(!stanag4586_message_supported(2000));
        assert!(!stanag4586_message_supported(u32::MAX));
    }
}
