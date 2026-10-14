// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Implementation of the canonical [`EntityCodec`] trait for the
//! SAPIENT (BSI Flex 335) wire format.
//!
//! [`SapientCodec`] decodes a `SapientMessage` (the inner payload,
//! after the transport's framing has been stripped) into the
//! protocol-agnostic [`rustgate_core::entity::Entity`] shape and
//! re-encodes a position-bearing entity into a `DetectionReport`-arm
//! envelope.
//!
//! # Round-trip discipline
//!
//! Same-codec round-trip preserves the position to IEEE-754 double
//! precision (the wire form), the classification list (carried on
//! the attribute bag with one entry per candidate type +
//! confidence pair), and the detection-report metadata (`report_id`,
//! `object_id`, `task_id`, `state`, `colour`, `id`,
//! `additional_information`). Cross-codec entities (e.g. a CoT event
//! encoded through the SAPIENT codec) lose any field the canonical
//! `Entity` shape does not surface — that is the documented
//! `EntityCodec` contract.
//!
//! # Entity classification
//!
//! `DetectionReport`-bearing frames classify by the topmost
//! classification candidate's `kind`:
//!
//! - `"UAV"`, `"drone"`, `"aircraft"`, `"helicopter"` →
//!   [`EntityKind::Aircraft`]
//! - `"vehicle"`, `"car"`, `"truck"`, `"person"`, `"pedestrian"` →
//!   [`EntityKind::Ground`]
//! - `"vessel"`, `"boat"`, `"ship"` → [`EntityKind::Marine`]
//! - `"projectile"`, `"munition"`, `"missile"` →
//!   [`EntityKind::Munition`]
//! - everything else → [`EntityKind::Sensor`] with the verbatim
//!   classification kind in `Entity.attributes`.
//!
//! Frames that arrive without a position-bearing `Location` arm
//! (`RangeBearing` is carried opaque, see
//! [`crate::proto::DetectionLocation`]) classify as
//! [`EntityKind::Sensor`] with no position — the canonical entity
//! is still surfaced for audit / metrics, just without lat/lon.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use rustgate_core::entity::{AttributeValue, Entity, EntityCodec, EntityKind, Position, Velocity};

use crate::MAX_PAYLOAD_BYTES;
use crate::error::SapientError;
use crate::proto::{
    Classification, DetectionLocation, DetectionReport, EnuVelocity, Location,
    LocationCoordinateSystem, LocationDatum, SapientMessage, SapientPayload, Timestamp,
    decode_sapient_message, encode_sapient_message,
};

/// Attribute-key prefix for every SAPIENT-derived entry. Keeps the
/// attribute namespace separated from other codecs (CoT, MAVLink,
/// ASTERIX, STANAG-4586, Meshtastic, VMF, DIS) that share the
/// [`Entity`] shape.
const SAPIENT_PREFIX: &str = "sapient.";

/// UID prefix for entities lifted from SAPIENT detections. The
/// prefix keeps SAPIENT-derived entities namespace-separated from
/// other codecs in a multi-protocol ingestion path; the suffix is
/// the SAPIENT `object_id` ULID, which is the spec-mandated stable
/// identifier across the lifetime of the tracked object.
const UID_PREFIX: &str = "sapient-";

/// UID assigned when the wire frame supplies neither an `object_id`
/// nor a `report_id`. Real SAPIENT detection reports always carry
/// at least one — the BSI spec marks both as `is_mandatory: true` —
/// so this is a fallback for fixtures and forward-compat schema
/// revisions where the identifier arrives in a field this codec
/// version does not recognise.
const UID_FALLBACK: &str = "sapient-anonymous";

/// Stateless wire-format codec for the SAPIENT (BSI Flex 335) schema.
///
/// Holds no state — the same instance is safe to reuse across every
/// routed message on every thread. Construct with `Default::default()`
/// or [`SapientCodec::new`].
#[derive(Debug, Default, Clone, Copy)]
pub struct SapientCodec;

impl SapientCodec {
    /// Construct a fresh codec instance. Equivalent to
    /// `SapientCodec::default()`.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl EntityCodec for SapientCodec {
    type Error = SapientError;

    fn to_entity(&self, payload: &[u8]) -> Result<Entity, Self::Error> {
        let msg = decode_sapient_message(payload)?;
        Ok(message_to_entity(msg))
    }

    fn from_entity(&self, entity: &Entity) -> Result<Bytes, Self::Error> {
        let msg = entity_to_message(entity)?;
        let bytes = encode_sapient_message(&msg)?;
        // Defense in depth — encode_sapient_message already enforces
        // the cap, but a future refactor could land a code path that
        // bypasses it (e.g. an alternate encoder for benchmarking).
        if bytes.len() > MAX_PAYLOAD_BYTES {
            return Err(SapientError::PayloadTooLarge { bytes: bytes.len() });
        }
        Ok(Bytes::from(bytes))
    }
}

/// Map a decoded [`SapientMessage`] into the canonical [`Entity`]
/// shape. Non-DetectionReport arms surface as
/// [`EntityKind::Sensor`] with the opaque payload bytes carried on
/// the attribute bag — they are still flowable through the router
/// for audit / metrics.
fn message_to_entity(msg: SapientMessage) -> Entity {
    let SapientMessage {
        timestamp,
        node_id,
        destination_id,
        content,
        additional_information,
    } = msg;

    let mut attributes: BTreeMap<String, AttributeValue> = BTreeMap::new();
    if !node_id.is_empty() {
        let _ = attributes.insert(
            format!("{SAPIENT_PREFIX}node_id"),
            AttributeValue::Str(node_id.clone()),
        );
    }
    if !destination_id.is_empty() {
        let _ = attributes.insert(
            format!("{SAPIENT_PREFIX}destination_id"),
            AttributeValue::Str(destination_id),
        );
    }
    if !additional_information.is_empty() {
        let _ = attributes.insert(
            format!("{SAPIENT_PREFIX}additional_information"),
            AttributeValue::Str(additional_information),
        );
    }

    let entity_timestamp = timestamp_to_system_time(timestamp.as_ref());

    match content {
        Some(SapientPayload::DetectionReport(dr)) => {
            detection_report_to_entity(*dr, attributes, entity_timestamp, &node_id)
        }
        Some(SapientPayload::Other {
            field_number,
            bytes,
        }) => {
            let _ = attributes.insert(
                format!("{SAPIENT_PREFIX}other.field_number"),
                AttributeValue::Int(i64::from(field_number)),
            );
            let _ = attributes.insert(
                format!("{SAPIENT_PREFIX}other.bytes_len"),
                AttributeValue::Int(i64::try_from(bytes.len()).unwrap_or(i64::MAX)),
            );
            let uid = if !node_id.is_empty() {
                format!("{UID_PREFIX}{node_id}")
            } else {
                UID_FALLBACK.into()
            };
            Entity {
                uid,
                kind: EntityKind::Sensor,
                position: None,
                velocity: None,
                timestamp: entity_timestamp,
                callsign: None,
                mil_std_2525_sidc: None,
                attributes,
                taskings: Default::default(),
                files: Default::default(),
            }
        }
        // Decoder rejects content-less frames with `MissingContent`,
        // so this arm is unreachable on a real decode path. We emit
        // a defensive sensor-shaped entity rather than panicking on a
        // future internal caller that constructs a `SapientMessage`
        // by hand.
        None => Entity {
            uid: UID_FALLBACK.into(),
            kind: EntityKind::Sensor,
            position: None,
            velocity: None,
            timestamp: entity_timestamp,
            callsign: None,
            mil_std_2525_sidc: None,
            attributes,
            taskings: Default::default(),
            files: Default::default(),
        },
    }
}

fn detection_report_to_entity(
    dr: DetectionReport,
    mut attributes: BTreeMap<String, AttributeValue>,
    timestamp: SystemTime,
    node_id: &str,
) -> Entity {
    let DetectionReport {
        report_id,
        object_id,
        task_id,
        state,
        location,
        detection_confidence,
        classification,
        enu_velocity,
        colour,
        id,
    } = dr;

    if !report_id.is_empty() {
        let _ = attributes.insert(
            format!("{SAPIENT_PREFIX}report_id"),
            AttributeValue::Str(report_id.clone()),
        );
    }
    if !object_id.is_empty() {
        let _ = attributes.insert(
            format!("{SAPIENT_PREFIX}object_id"),
            AttributeValue::Str(object_id.clone()),
        );
    }
    if !task_id.is_empty() {
        let _ = attributes.insert(
            format!("{SAPIENT_PREFIX}task_id"),
            AttributeValue::Str(task_id),
        );
    }
    if !state.is_empty() {
        let _ = attributes.insert(format!("{SAPIENT_PREFIX}state"), AttributeValue::Str(state));
    }
    if !colour.is_empty() {
        let _ = attributes.insert(
            format!("{SAPIENT_PREFIX}colour"),
            AttributeValue::Str(colour),
        );
    }
    if !id.is_empty() {
        let _ = attributes.insert(format!("{SAPIENT_PREFIX}id"), AttributeValue::Str(id));
    }
    if let Some(c) = detection_confidence {
        let _ = attributes.insert(
            format!("{SAPIENT_PREFIX}detection_confidence"),
            AttributeValue::Float(f64::from(c)),
        );
    }

    populate_classification_attributes(&mut attributes, &classification);
    if let Some(loc) = &location {
        populate_location_attributes(&mut attributes, loc);
    }
    if let Some(v) = &enu_velocity {
        populate_velocity_attributes(&mut attributes, v);
    }

    let position = location.as_ref().and_then(detection_location_to_position);
    let velocity = enu_velocity.as_ref().map(|v| {
        let (speed_m_s, course_deg) = v.to_speed_course();
        Velocity {
            speed_m_s,
            course_deg,
        }
    });

    let kind = classify_entity_kind(&classification, position.is_some());
    let uid = derive_uid(&object_id, &report_id, node_id);

    Entity {
        uid,
        kind,
        position,
        velocity,
        timestamp,
        callsign: None,
        mil_std_2525_sidc: None,
        attributes,
        taskings: Default::default(),
        files: Default::default(),
    }
}

fn populate_classification_attributes(
    attributes: &mut BTreeMap<String, AttributeValue>,
    classification: &[Classification],
) {
    if classification.is_empty() {
        return;
    }
    // Top-level classification kind / confidence carries — the most
    // common dashboard query is "what kind of thing is this and how
    // sure are we?", so promote those to flat keys.
    if let Some(top) = classification.first() {
        if !top.kind.is_empty() {
            let _ = attributes.insert(
                format!("{SAPIENT_PREFIX}classification.top.kind"),
                AttributeValue::Str(top.kind.clone()),
            );
        }
        if let Some(c) = top.confidence {
            let _ = attributes.insert(
                format!("{SAPIENT_PREFIX}classification.top.confidence"),
                AttributeValue::Float(f64::from(c)),
            );
        }
    }
    // Full list ride for round-trip preservation: `classification.0.kind`,
    // `classification.0.confidence`, `classification.1.kind`, …
    for (i, cls) in classification.iter().enumerate() {
        if !cls.kind.is_empty() {
            let _ = attributes.insert(
                format!("{SAPIENT_PREFIX}classification.{i}.kind"),
                AttributeValue::Str(cls.kind.clone()),
            );
        }
        if let Some(c) = cls.confidence {
            let _ = attributes.insert(
                format!("{SAPIENT_PREFIX}classification.{i}.confidence"),
                AttributeValue::Float(f64::from(c)),
            );
        }
    }
}

fn populate_location_attributes(
    attributes: &mut BTreeMap<String, AttributeValue>,
    location: &DetectionLocation,
) {
    match location {
        DetectionLocation::Location(loc) => {
            let _ = attributes.insert(
                format!("{SAPIENT_PREFIX}location.x"),
                AttributeValue::Float(loc.x),
            );
            let _ = attributes.insert(
                format!("{SAPIENT_PREFIX}location.y"),
                AttributeValue::Float(loc.y),
            );
            if let Some(z) = loc.z {
                let _ = attributes.insert(
                    format!("{SAPIENT_PREFIX}location.z"),
                    AttributeValue::Float(z),
                );
            }
            let _ = attributes.insert(
                format!("{SAPIENT_PREFIX}location.coordinate_system"),
                AttributeValue::Int(i64::from(loc.coordinate_system.to_wire())),
            );
            let _ = attributes.insert(
                format!("{SAPIENT_PREFIX}location.datum"),
                AttributeValue::Int(i64::from(loc.datum.to_wire())),
            );
            if !loc.utm_zone.is_empty() {
                let _ = attributes.insert(
                    format!("{SAPIENT_PREFIX}location.utm_zone"),
                    AttributeValue::Str(loc.utm_zone.clone()),
                );
            }
        }
        DetectionLocation::RangeBearing(bytes) => {
            // Carry the opaque bytes' size only — round-tripping the
            // bytes themselves through `AttributeValue::Str` would
            // require base64 / hex encoding which the v1 attribute
            // shape (see `rustgate-core::entity`) deliberately
            // avoids. A future codec revision that lifts
            // `RangeBearing` typing can then surface the fields
            // without a wire-format change.
            let _ = attributes.insert(
                format!("{SAPIENT_PREFIX}location.range_bearing.bytes_len"),
                AttributeValue::Int(i64::try_from(bytes.len()).unwrap_or(i64::MAX)),
            );
        }
    }
}

fn populate_velocity_attributes(
    attributes: &mut BTreeMap<String, AttributeValue>,
    v: &EnuVelocity,
) {
    let _ = attributes.insert(
        format!("{SAPIENT_PREFIX}velocity.east_rate"),
        AttributeValue::Float(v.east_rate),
    );
    let _ = attributes.insert(
        format!("{SAPIENT_PREFIX}velocity.north_rate"),
        AttributeValue::Float(v.north_rate),
    );
    if let Some(up) = v.up_rate {
        let _ = attributes.insert(
            format!("{SAPIENT_PREFIX}velocity.up_rate"),
            AttributeValue::Float(up),
        );
    }
}

fn detection_location_to_position(loc: &DetectionLocation) -> Option<Position> {
    match loc {
        DetectionLocation::Location(l) => match l.coordinate_system {
            LocationCoordinateSystem::LatLngDegM => Some(Position {
                lat: l.y,
                lon: l.x,
                hae_meters: l.z,
            }),
            LocationCoordinateSystem::LatLngRadM => Some(Position {
                lat: l.y.to_degrees(),
                lon: l.x.to_degrees(),
                hae_meters: l.z,
            }),
            // UTM and Unspecified do not lift cleanly into a
            // lat/lon `Position` without a zone-resolving conversion
            // step — that work belongs in a follow-up rather than
            // here. The attribute bag still carries the raw values.
            _ => None,
        },
        DetectionLocation::RangeBearing(_) => None,
    }
}

fn classify_entity_kind(classification: &[Classification], has_position: bool) -> EntityKind {
    if !has_position {
        return EntityKind::Sensor;
    }
    let Some(top) = classification.first() else {
        return EntityKind::Sensor;
    };
    let lower = top.kind.to_ascii_lowercase();
    match lower.as_str() {
        "uav" | "drone" | "aircraft" | "helicopter" | "fixed_wing" | "rotary_wing" => {
            EntityKind::Aircraft
        }
        "vehicle" | "car" | "truck" | "tank" | "person" | "pedestrian" | "human" | "dismount" => {
            EntityKind::Ground
        }
        "vessel" | "boat" | "ship" | "submarine" => EntityKind::Marine,
        "projectile" | "munition" | "missile" | "rocket" => EntityKind::Munition,
        "" => EntityKind::Sensor,
        other => EntityKind::Unknown(other.to_string()),
    }
}

fn derive_uid(object_id: &str, report_id: &str, node_id: &str) -> String {
    if !object_id.is_empty() {
        return format!("{UID_PREFIX}{object_id}");
    }
    if !report_id.is_empty() {
        return format!("{UID_PREFIX}{report_id}");
    }
    if !node_id.is_empty() {
        return format!("{UID_PREFIX}{node_id}");
    }
    UID_FALLBACK.into()
}

fn timestamp_to_system_time(ts: Option<&Timestamp>) -> SystemTime {
    let Some(ts) = ts else {
        return SystemTime::now();
    };
    if ts.seconds < 0 {
        // Pre-epoch timestamps fall back to UNIX_EPOCH; SAPIENT does
        // not model pre-1970 detections in any documented deployment.
        return SystemTime::UNIX_EPOCH;
    }
    let secs = ts.seconds as u64;
    let nanos = if ts.nanos >= 0 { ts.nanos as u32 } else { 0 };
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::new(secs, nanos))
        .unwrap_or(SystemTime::UNIX_EPOCH)
}

fn system_time_to_timestamp(t: SystemTime) -> Timestamp {
    match t.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(d) => Timestamp {
            seconds: i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
            nanos: i32::try_from(d.subsec_nanos()).unwrap_or(0),
        },
        Err(_) => Timestamp::default(),
    }
}

/// Encode an [`Entity`] into a [`SapientMessage`] with a
/// `DetectionReport` content arm.
///
/// Position-bearing entities map to a `Location` (lat/lng-deg-m,
/// WGS-84 ellipsoid by default) plus optional `ENUVelocity` from the
/// entity's [`Velocity`] vector. Entities without a position surface
/// [`SapientError::UnsupportedEntity`] rather than silently emit a
/// content-less frame the SAPIENT spec would reject.
fn entity_to_message(entity: &Entity) -> Result<SapientMessage, SapientError> {
    let position = entity.position.ok_or_else(|| {
        SapientError::UnsupportedEntity(format!(
            "entity `{}` has no Position; SAPIENT DetectionReport requires a location arm",
            entity.uid
        ))
    })?;

    let coordinate_system = attr_int(entity, "location.coordinate_system")
        .and_then(|v| i32::try_from(v).ok())
        .map(LocationCoordinateSystem::from_wire)
        .unwrap_or(LocationCoordinateSystem::LatLngDegM);
    let datum = attr_int(entity, "location.datum")
        .and_then(|v| i32::try_from(v).ok())
        .map(LocationDatum::from_wire)
        .unwrap_or(LocationDatum::Wgs84Ellipsoid);
    // Prefer the raw x/y carries from the attribute bag (these
    // round-trip the wire bytes byte-exact); fall back to the
    // canonical Position when absent.
    let x = attr_float(entity, "location.x").unwrap_or(position.lon);
    let y = attr_float(entity, "location.y").unwrap_or(position.lat);
    let z = attr_float(entity, "location.z").or(position.hae_meters);
    let utm_zone = attr_str(entity, "location.utm_zone").unwrap_or_default();

    let location = Location {
        x,
        y,
        z,
        x_error: None,
        y_error: None,
        z_error: None,
        coordinate_system,
        datum,
        utm_zone,
    };

    // ENU velocity: prefer raw east/north/up carries, fall back to
    // the canonical Velocity (speed/course).
    let east_attr = attr_float(entity, "velocity.east_rate");
    let north_attr = attr_float(entity, "velocity.north_rate");
    let up_attr = attr_float(entity, "velocity.up_rate");
    let enu_velocity = if let (Some(east), Some(north)) = (east_attr, north_attr) {
        Some(EnuVelocity {
            east_rate: east,
            north_rate: north,
            up_rate: up_attr,
        })
    } else {
        entity.velocity.map(|v| {
            let mut e = EnuVelocity::from_speed_course(v.speed_m_s, v.course_deg);
            if let Some(up) = up_attr {
                e.up_rate = Some(up);
            }
            e
        })
    };

    // Classification bag: prefer the same-codec round-trip carries
    // (`classification.0.kind`, etc.); fall back to the top-level
    // promoted keys; fall back to `EntityKind` lifted into a
    // synthetic classification.
    let classification = build_classification_list(entity);

    let detection_confidence = attr_float(entity, "detection_confidence").map(|v| v as f32);

    let dr = DetectionReport {
        report_id: attr_str(entity, "report_id").unwrap_or_default(),
        object_id: attr_str(entity, "object_id").unwrap_or_default(),
        task_id: attr_str(entity, "task_id").unwrap_or_default(),
        state: attr_str(entity, "state").unwrap_or_default(),
        location: Some(DetectionLocation::Location(location)),
        detection_confidence,
        classification,
        enu_velocity,
        colour: attr_str(entity, "colour").unwrap_or_default(),
        id: attr_str(entity, "id").unwrap_or_default(),
    };

    Ok(SapientMessage {
        timestamp: Some(system_time_to_timestamp(entity.timestamp)),
        node_id: attr_str(entity, "node_id").unwrap_or_default(),
        destination_id: attr_str(entity, "destination_id").unwrap_or_default(),
        content: Some(SapientPayload::DetectionReport(Box::new(dr))),
        additional_information: attr_str(entity, "additional_information").unwrap_or_default(),
    })
}

fn build_classification_list(entity: &Entity) -> Vec<Classification> {
    // First try the same-codec round-trip carry pattern:
    // `classification.0.kind`, `classification.0.confidence`,
    // `classification.1.kind`, ...
    let mut indexed: Vec<Classification> = Vec::new();
    let mut i = 0_usize;
    loop {
        let kind = attr_str(entity, &format!("classification.{i}.kind"));
        let conf = attr_float(entity, &format!("classification.{i}.confidence")).map(|v| v as f32);
        match (kind, conf) {
            (None, None) => break,
            (kind, conf) => {
                indexed.push(Classification {
                    kind: kind.unwrap_or_default(),
                    confidence: conf,
                });
                i += 1;
                if i > 64 {
                    // Defensive cap — SAPIENT classification lists
                    // are typically 1-3 entries; an attribute bag
                    // with 64+ entries is a misuse and we should not
                    // unbounded-loop on it.
                    break;
                }
            }
        }
    }
    if !indexed.is_empty() {
        return indexed;
    }
    // Fall back to the top-level promoted keys.
    let kind = attr_str(entity, "classification.top.kind");
    let conf = attr_float(entity, "classification.top.confidence").map(|v| v as f32);
    if let Some(kind) = kind {
        return vec![Classification {
            kind,
            confidence: conf,
        }];
    }
    // Final fallback — lift `EntityKind` back into a synthetic
    // classification so a cross-codec entity still emits a
    // human-readable `kind`.
    match &entity.kind {
        EntityKind::Aircraft => vec![Classification {
            kind: "aircraft".into(),
            confidence: None,
        }],
        EntityKind::Ground => vec![Classification {
            kind: "vehicle".into(),
            confidence: None,
        }],
        EntityKind::Marine => vec![Classification {
            kind: "vessel".into(),
            confidence: None,
        }],
        EntityKind::Munition => vec![Classification {
            kind: "munition".into(),
            confidence: None,
        }],
        EntityKind::Sensor | EntityKind::Track => Vec::new(),
        EntityKind::Unknown(label) => vec![Classification {
            kind: label.clone(),
            confidence: None,
        }],
    }
}

fn attr_str(entity: &Entity, key: &str) -> Option<String> {
    match entity.attributes.get(&format!("{SAPIENT_PREFIX}{key}")) {
        Some(AttributeValue::Str(v)) => Some(v.clone()),
        _ => None,
    }
}

fn attr_int(entity: &Entity, key: &str) -> Option<i64> {
    match entity.attributes.get(&format!("{SAPIENT_PREFIX}{key}")) {
        Some(AttributeValue::Int(v)) => Some(*v),
        _ => None,
    }
}

fn attr_float(entity: &Entity, key: &str) -> Option<f64> {
    match entity.attributes.get(&format!("{SAPIENT_PREFIX}{key}")) {
        Some(AttributeValue::Float(v)) => Some(*v),
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::float_cmp, unused_results)]
mod tests {
    use super::*;
    use crate::proto::{LocationCoordinateSystem, LocationDatum};

    fn detection_entity() -> Entity {
        let mut attrs: BTreeMap<String, AttributeValue> = BTreeMap::new();
        let _ = attrs.insert(
            format!("{SAPIENT_PREFIX}node_id"),
            AttributeValue::Str("11111111-2222-3333-4444-555555555555".into()),
        );
        let _ = attrs.insert(
            format!("{SAPIENT_PREFIX}object_id"),
            AttributeValue::Str("01H1OBJECT".into()),
        );
        let _ = attrs.insert(
            format!("{SAPIENT_PREFIX}report_id"),
            AttributeValue::Str("01H1REPORT".into()),
        );
        let _ = attrs.insert(
            format!("{SAPIENT_PREFIX}detection_confidence"),
            AttributeValue::Float(0.81),
        );
        let _ = attrs.insert(
            format!("{SAPIENT_PREFIX}classification.0.kind"),
            AttributeValue::Str("UAV".into()),
        );
        let _ = attrs.insert(
            format!("{SAPIENT_PREFIX}classification.0.confidence"),
            AttributeValue::Float(0.78),
        );
        let _ = attrs.insert(
            format!("{SAPIENT_PREFIX}location.coordinate_system"),
            AttributeValue::Int(i64::from(LocationCoordinateSystem::LatLngDegM.to_wire())),
        );
        let _ = attrs.insert(
            format!("{SAPIENT_PREFIX}location.datum"),
            AttributeValue::Int(i64::from(LocationDatum::Wgs84Ellipsoid.to_wire())),
        );
        Entity {
            uid: "sapient-01H1OBJECT".into(),
            kind: EntityKind::Aircraft,
            position: Some(Position {
                lat: 38.889_722_2,
                lon: -77.008_889,
                hae_meters: Some(50.0),
            }),
            velocity: Some(Velocity {
                speed_m_s: 5.0,
                course_deg: 90.0,
            }),
            timestamp: SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
            callsign: None,
            mil_std_2525_sidc: None,
            attributes: attrs,
            taskings: Default::default(),
            files: Default::default(),
        }
    }

    #[test]
    fn entity_round_trips_through_sapient_codec() {
        let codec = SapientCodec;
        let original = detection_entity();
        let bytes = codec.from_entity(&original).expect("encode");
        let decoded = codec.to_entity(&bytes).expect("decode");
        assert_eq!(decoded.uid, original.uid);
        assert_eq!(decoded.kind, EntityKind::Aircraft);
        let p1 = original.position.unwrap();
        let p2 = decoded.position.unwrap();
        // SAPIENT carries lat/lon as IEEE-754 double — same-codec
        // round-trip is bit-exact.
        assert_eq!(p1.lat, p2.lat);
        assert_eq!(p1.lon, p2.lon);
        assert_eq!(p1.hae_meters, p2.hae_meters);
        assert_eq!(decoded.timestamp, original.timestamp);
    }

    #[test]
    fn entity_without_position_returns_unsupported() {
        let codec = SapientCodec;
        let entity = Entity {
            uid: "sapient-anonymous".into(),
            kind: EntityKind::Track,
            position: None,
            velocity: None,
            timestamp: SystemTime::UNIX_EPOCH,
            callsign: None,
            mil_std_2525_sidc: None,
            attributes: BTreeMap::new(),
            taskings: Default::default(),
            files: Default::default(),
        };
        let err = codec.from_entity(&entity).expect_err("must fail");
        assert!(matches!(err, SapientError::UnsupportedEntity(_)));
    }

    #[test]
    fn classification_kind_drives_entity_kind() {
        let codec = SapientCodec;
        let cases: &[(&str, EntityKind)] = &[
            ("UAV", EntityKind::Aircraft),
            ("drone", EntityKind::Aircraft),
            ("helicopter", EntityKind::Aircraft),
            ("vehicle", EntityKind::Ground),
            ("person", EntityKind::Ground),
            ("vessel", EntityKind::Marine),
            ("missile", EntityKind::Munition),
            ("dustparticle", EntityKind::Unknown("dustparticle".into())),
        ];
        for (kind_str, expected) in cases {
            let mut entity = detection_entity();
            // Replace the classification with the test case.
            entity
                .attributes
                .insert(
                    format!("{SAPIENT_PREFIX}classification.0.kind"),
                    AttributeValue::Str((*kind_str).into()),
                )
                .expect("existing key replaced");
            let bytes = codec.from_entity(&entity).expect("encode");
            let decoded = codec.to_entity(&bytes).expect("decode");
            assert_eq!(decoded.kind, *expected, "kind={kind_str}");
        }
    }

    #[test]
    fn truncated_payload_returns_typed_error() {
        let codec = SapientCodec;
        let err = codec.to_entity(&[0x0A]).expect_err("must fail");
        assert!(matches!(
            err,
            SapientError::TruncatedVarint | SapientError::Truncated
        ));
    }

    #[test]
    fn missing_content_returns_typed_error() {
        let codec = SapientCodec;
        // A buffer containing only `node_id` (tag 2 length-delimited
        // = 0x12, length 6, "node-x") and no content arm. The
        // decoder must surface MissingContent.
        let frame: Vec<u8> = vec![0x12, 0x06, b'n', b'o', b'd', b'e', b'-', b'x'];
        let err = codec.to_entity(&frame).expect_err("must fail");
        assert!(matches!(err, SapientError::MissingContent));
    }

    #[test]
    fn velocity_round_trips_through_speed_course() {
        let codec = SapientCodec;
        let mut entity = detection_entity();
        // Strip the canonical Velocity to force the encoder to use
        // the attribute bag carries.
        entity.velocity = None;
        let east = 10.0_f64;
        let north = 0.0_f64;
        entity.attributes.insert(
            format!("{SAPIENT_PREFIX}velocity.east_rate"),
            AttributeValue::Float(east),
        );
        entity.attributes.insert(
            format!("{SAPIENT_PREFIX}velocity.north_rate"),
            AttributeValue::Float(north),
        );
        let bytes = codec.from_entity(&entity).unwrap();
        let decoded = codec.to_entity(&bytes).unwrap();
        let v = decoded.velocity.unwrap();
        // Pure east → speed 10, course 90.
        assert!((v.speed_m_s - 10.0).abs() < 1e-9);
        assert!((v.course_deg - 90.0).abs() < 1e-6);
    }

    #[test]
    fn over_cap_payload_returns_typed_error() {
        let codec = SapientCodec;
        let oversized = vec![0u8; MAX_PAYLOAD_BYTES + 1];
        let err = codec.to_entity(&oversized).expect_err("must fail");
        assert!(matches!(err, SapientError::PayloadTooLarge { .. }));
    }
}
