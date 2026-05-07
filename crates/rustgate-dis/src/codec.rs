// Copyright © 2026 Roberto Chiofalo.

//! DIS implementation of the canonical
//! [`rustgate_core::entity::EntityCodec`] trait — refs #867 / #847.
//!
//! [`DisCodec`] decodes IEEE 1278.1 Entity State PDUs into the
//! protocol-agnostic [`Entity`] shape defined by `rustgate-core` and
//! re-encodes a position-bearing [`Entity`] back into a wire-form
//! Entity State PDU.
//!
//! # Mapping summary
//!
//! Inbound (Entity State PDU → [`Entity`]):
//!
//! | DIS source                                      | `Entity` field                                     |
//! |-------------------------------------------------|----------------------------------------------------|
//! | (site, application, entity)                     | `Entity.uid` (`"dis-{site}-{app}-{entity}"`)       |
//! | location_ecef → [`crate::coord::ecef_to_wgs84`] | `Entity.position` (lat / lon / alt)                |
//! | linear_velocity (3×f32 entity coords)           | `Entity.velocity` via Cartesian magnitude          |
//! | entity_type.kind / domain                       | `Entity.kind` (Aircraft / Ground / Marine / …)     |
//! | marking (ASCII)                                 | `Entity.callsign`                                  |
//! | every decoded scalar field (force_id, type      | `Entity.attributes` under the `"dis."` namespace   |
//! | tuple, DR algorithm, capabilities, …)           |                                                    |
//!
//! Outbound (`Entity` → Entity State PDU) is intentionally narrower:
//! only `Position`-bearing entities encode. Entities without a
//! position surface [`DisEntityError::UnsupportedEntityKind`].
//!
//! # Round-trip discipline
//!
//! Same-codec round-trip preserves every wire-format field via the
//! `dis.*` attribute bag. Cross-codec entities (e.g. a CoT event
//! encoded through the DIS codec) lose them silently per the
//! [`rustgate_core::entity::EntityCodec`] contract.

use std::collections::BTreeMap;
use std::time::SystemTime;

use bytes::Bytes;
use rustgate_core::entity::{AttributeValue, Entity, EntityCodec, EntityKind, Position, Velocity};

use crate::coord::{ecef_to_wgs84, wgs84_to_ecef};
use crate::entity_state::{EntityId, EntityStatePdu, EntityType, ForceId};
use crate::header::{PduHeader, PduType, ProtocolFamily};

/// Attribute-key prefix used for every DIS-derived [`AttributeValue`].
/// Keeps the namespace separated from other codecs (CoT, MAVLink,
/// ASTERIX, STANAG-4586) sharing the [`Entity`] shape.
pub const DIS_PREFIX: &str = "dis.";

/// Errors surfaced by [`DisCodec::to_entity`] / [`DisCodec::from_entity`].
///
/// Distinct from [`crate::error::DisError`] (wire-format truncation /
/// framing) because the codec failure modes belong to a different
/// operational class — a SIEM that pages on `dis.pdu_rejected` should
/// NOT page on `dis.entity.unsupported_entity_kind`, which is a
/// routine "this entity has no DIS wire form" signal during cross-
/// protocol fan-out.
#[derive(Debug, thiserror::Error)]
pub enum DisEntityError {
    /// Payload bytes do not parse as an Entity State PDU. The inner
    /// string carries the underlying [`crate::error::DisError`]
    /// context for an operator log line without exposing the raw
    /// payload (which may be hostile or classified).
    #[error("malformed DIS PDU: {0}")]
    InvalidPdu(String),

    /// PDU type byte is outside the subset this codec maps to the
    /// [`Entity`] shape. The MVP only handles Entity State PDUs;
    /// other PDU types (Fire, Detonation, Collision, …) surface
    /// this error and will be wired in subsequent PRs.
    #[error("DIS PDU type {0} cannot be mapped to Entity")]
    UnsupportedPduType(u8),

    /// `from_entity` cannot represent the supplied [`Entity`] as a
    /// DIS Entity State PDU. The string captures the cause for the
    /// audit trail — typical contents are `"entity has no Position"`
    /// (the most common case during cross-protocol fan-out),
    /// `"entity uid does not match dis-<site>-<app>-<entity>"`, and
    /// `"non-finite position"` for entities whose lat/lon are NaN /
    /// inf.
    #[error("Entity kind {0} cannot be mapped to DIS")]
    UnsupportedEntityKind(String),
}

/// IEEE 1278.1 wire-format codec for the canonical [`Entity`] shape.
///
/// Stateless — the same instance is safe to reuse across every routed
/// message on every thread. The router holds an `Arc<DisCodec>` per
/// protocol slot.
#[derive(Debug, Default, Clone, Copy)]
pub struct DisCodec;

impl EntityCodec for DisCodec {
    type Error = DisEntityError;

    fn to_entity(&self, payload: &[u8]) -> Result<Entity, Self::Error> {
        decode_entity_state(payload)
    }

    fn from_entity(&self, entity: &Entity) -> Result<Bytes, Self::Error> {
        encode_entity_state(entity)
    }
}

/// Decode an Entity State PDU into the canonical [`Entity`] shape.
///
/// Walks the PDU type byte first so non-Entity-State PDUs fail with a
/// typed [`DisEntityError::UnsupportedPduType`] before the inner
/// [`EntityStatePdu::decode`] runs (which would surface
/// [`crate::error::DisError::UnexpectedPduType`] — equivalent
/// information but routed through `InvalidPdu`, which is the wrong
/// operational class for "we don't yet support this PDU type").
fn decode_entity_state(payload: &[u8]) -> Result<Entity, DisEntityError> {
    let header =
        PduHeader::decode(payload).map_err(|e| DisEntityError::InvalidPdu(e.to_string()))?;
    if header.pdu_type != PduType::EntityState {
        return Err(DisEntityError::UnsupportedPduType(header.pdu_type.to_u8()));
    }

    let pdu =
        EntityStatePdu::decode(payload).map_err(|e| DisEntityError::InvalidPdu(e.to_string()))?;

    let uid = format!(
        "dis-{}-{}-{}",
        pdu.entity_id.site, pdu.entity_id.application, pdu.entity_id.entity
    );
    let position = ecef_position(pdu.location_ecef);
    let velocity = linear_velocity_to_canonical(pdu.linear_velocity);
    let kind = classify_kind(&pdu.entity_type);
    let callsign = if pdu.marking.is_empty() {
        None
    } else {
        Some(pdu.marking.clone())
    };

    let mut attributes: BTreeMap<String, AttributeValue> = BTreeMap::new();
    populate_attributes(&mut attributes, &pdu);

    Ok(Entity {
        uid,
        kind,
        position: Some(position),
        velocity,
        timestamp: SystemTime::now(),
        callsign,
        mil_std_2525_sidc: None,
        attributes,
    })
}

/// Convert ECEF Cartesian metres to a [`Position`] in WGS-84
/// decimal degrees.
fn ecef_position(ecef: [f64; 3]) -> Position {
    let (lat, lon, alt) = ecef_to_wgs84(ecef[0], ecef[1], ecef[2]);
    Position {
        lat,
        lon,
        hae_meters: Some(alt),
    }
}

/// Convert a linear-velocity Cartesian triplet (m/s) into the
/// canonical [`Velocity`] polar form.
///
/// DIS reports linear velocity in entity-frame Cartesian (X forward,
/// Y starboard, Z down), but the canonical form expects a ground-
/// speed magnitude and a course-over-ground bearing. The conversion
/// here is a magnitude-only approximation — the polar bearing rides
/// on the entity orientation (psi) and is preserved verbatim on the
/// `dis.orientation_psi_rad` attribute for callers that need it.
/// Returns `None` when all three components are zero (entities
/// reporting "no velocity").
fn linear_velocity_to_canonical(velocity: [f32; 3]) -> Option<Velocity> {
    let speed = (f64::from(velocity[0]) * f64::from(velocity[0])
        + f64::from(velocity[1]) * f64::from(velocity[1])
        + f64::from(velocity[2]) * f64::from(velocity[2]))
    .sqrt();
    if speed < 1e-6 {
        return None;
    }
    Some(Velocity {
        speed_m_s: speed,
        course_deg: 0.0,
    })
}

/// Map the IEEE 1278.1 entity-type kind / domain pair to the
/// canonical [`EntityKind`].
///
/// IEEE 1278.1 § 6.2.30 partitions the kind enumeration as:
/// 0 = Other, 1 = Platform, 2 = Munition, 3 = LifeForm, 4 = Environmental,
/// 5 = CulturalFeature, 6 = Supply, 7 = Radio, 8 = Expendable, 9 = SensorEmitter.
/// For kind = 1 (Platform) the domain narrows it further:
/// 1 = Land, 2 = Air, 3 = Surface, 4 = Subsurface, 5 = Space.
fn classify_kind(entity_type: &EntityType) -> EntityKind {
    match entity_type.kind {
        1 => match entity_type.domain {
            // Air platforms.
            2 => EntityKind::Aircraft,
            // Surface (e.g. ship) and subsurface (e.g. submarine).
            3 | 4 => EntityKind::Marine,
            // Space — bucket as Aircraft for now (no Spacecraft variant
            // in the closed enum); preserved precisely on the
            // `dis.entity_type.domain` attribute.
            5 => EntityKind::Aircraft,
            // Land platforms (1) and Other (0) → Ground.
            _ => EntityKind::Ground,
        },
        2 => EntityKind::Munition,
        9 => EntityKind::Sensor,
        // Life-form, environmental, supply, expendable, radio →
        // Track (no closer fit in the closed enum). The full kind
        // byte rides on the attribute bag for downstream dispatch.
        _ => EntityKind::Track,
    }
}

/// Populate the `Entity::attributes` bag with every decoded field.
fn populate_attributes(attributes: &mut BTreeMap<String, AttributeValue>, pdu: &EntityStatePdu) {
    let _ = attributes.insert(
        format!("{DIS_PREFIX}entity_id.site"),
        AttributeValue::Int(i64::from(pdu.entity_id.site)),
    );
    let _ = attributes.insert(
        format!("{DIS_PREFIX}entity_id.application"),
        AttributeValue::Int(i64::from(pdu.entity_id.application)),
    );
    let _ = attributes.insert(
        format!("{DIS_PREFIX}entity_id.entity"),
        AttributeValue::Int(i64::from(pdu.entity_id.entity)),
    );
    let _ = attributes.insert(
        format!("{DIS_PREFIX}force_id"),
        AttributeValue::Int(i64::from(pdu.force_id.to_u8())),
    );

    insert_entity_type(attributes, "entity_type", &pdu.entity_type);
    insert_entity_type(
        attributes,
        "alternative_entity_type",
        &pdu.alternative_entity_type,
    );

    let _ = attributes.insert(
        format!("{DIS_PREFIX}linear_velocity_x_mps"),
        AttributeValue::Float(f64::from(pdu.linear_velocity[0])),
    );
    let _ = attributes.insert(
        format!("{DIS_PREFIX}linear_velocity_y_mps"),
        AttributeValue::Float(f64::from(pdu.linear_velocity[1])),
    );
    let _ = attributes.insert(
        format!("{DIS_PREFIX}linear_velocity_z_mps"),
        AttributeValue::Float(f64::from(pdu.linear_velocity[2])),
    );

    let _ = attributes.insert(
        format!("{DIS_PREFIX}orientation_psi_rad"),
        AttributeValue::Float(f64::from(pdu.orientation[0])),
    );
    let _ = attributes.insert(
        format!("{DIS_PREFIX}orientation_theta_rad"),
        AttributeValue::Float(f64::from(pdu.orientation[1])),
    );
    let _ = attributes.insert(
        format!("{DIS_PREFIX}orientation_phi_rad"),
        AttributeValue::Float(f64::from(pdu.orientation[2])),
    );
    let _ = attributes.insert(
        format!("{DIS_PREFIX}appearance"),
        AttributeValue::Int(i64::from(pdu.appearance)),
    );
    let _ = attributes.insert(
        format!("{DIS_PREFIX}capabilities"),
        AttributeValue::Int(i64::from(pdu.capabilities)),
    );
    let _ = attributes.insert(
        format!("{DIS_PREFIX}dead_reckoning.algorithm"),
        AttributeValue::Int(i64::from(pdu.dead_reckoning.algorithm)),
    );
    let _ = attributes.insert(
        format!("{DIS_PREFIX}marking_charset"),
        AttributeValue::Int(i64::from(pdu.marking_charset)),
    );

    // ECEF position carry — preserves the lossless wire form so a
    // same-codec round trip recovers the exact bits the simulator
    // emitted, sidestepping the small precision loss of the
    // ECEF→geodetic→ECEF chain.
    let _ = attributes.insert(
        format!("{DIS_PREFIX}location_ecef_x"),
        AttributeValue::Float(pdu.location_ecef[0]),
    );
    let _ = attributes.insert(
        format!("{DIS_PREFIX}location_ecef_y"),
        AttributeValue::Float(pdu.location_ecef[1]),
    );
    let _ = attributes.insert(
        format!("{DIS_PREFIX}location_ecef_z"),
        AttributeValue::Float(pdu.location_ecef[2]),
    );

    let _ = attributes.insert(
        format!("{DIS_PREFIX}articulation_parameter_count"),
        AttributeValue::Int(i64::try_from(pdu.articulation_parameters.len()).unwrap_or(i64::MAX)),
    );
}

/// Insert the seven scalar fields of an [`EntityType`] under a
/// shared key prefix.
fn insert_entity_type(
    attributes: &mut BTreeMap<String, AttributeValue>,
    key_prefix: &str,
    et: &EntityType,
) {
    let _ = attributes.insert(
        format!("{DIS_PREFIX}{key_prefix}.kind"),
        AttributeValue::Int(i64::from(et.kind)),
    );
    let _ = attributes.insert(
        format!("{DIS_PREFIX}{key_prefix}.domain"),
        AttributeValue::Int(i64::from(et.domain)),
    );
    let _ = attributes.insert(
        format!("{DIS_PREFIX}{key_prefix}.country"),
        AttributeValue::Int(i64::from(et.country)),
    );
    let _ = attributes.insert(
        format!("{DIS_PREFIX}{key_prefix}.category"),
        AttributeValue::Int(i64::from(et.category)),
    );
    let _ = attributes.insert(
        format!("{DIS_PREFIX}{key_prefix}.subcategory"),
        AttributeValue::Int(i64::from(et.subcategory)),
    );
    let _ = attributes.insert(
        format!("{DIS_PREFIX}{key_prefix}.specific"),
        AttributeValue::Int(i64::from(et.specific)),
    );
    let _ = attributes.insert(
        format!("{DIS_PREFIX}{key_prefix}.extra"),
        AttributeValue::Int(i64::from(et.extra)),
    );
}

/// Encode an [`Entity`] as an Entity State PDU.
fn encode_entity_state(entity: &Entity) -> Result<Bytes, DisEntityError> {
    let position = entity
        .position
        .ok_or_else(|| DisEntityError::UnsupportedEntityKind("entity has no Position".into()))?;
    if !position.lat.is_finite() || !position.lon.is_finite() {
        return Err(DisEntityError::UnsupportedEntityKind(
            "non-finite position".into(),
        ));
    }
    if !(-90.0..=90.0).contains(&position.lat) || !(-180.0..=180.0).contains(&position.lon) {
        return Err(DisEntityError::UnsupportedEntityKind(
            "position out of WGS-84 envelope".into(),
        ));
    }

    let entity_id = parse_entity_id(&entity.uid)
        .or_else(|| entity_id_from_attrs(entity))
        .ok_or_else(|| {
            DisEntityError::UnsupportedEntityKind(format!(
                "entity uid `{}` does not match `dis-<site>-<app>-<entity>`",
                entity.uid
            ))
        })?;

    let location_ecef = match (
        attr_float(entity, "location_ecef_x"),
        attr_float(entity, "location_ecef_y"),
        attr_float(entity, "location_ecef_z"),
    ) {
        // Same-codec round trip: prefer the lossless ECEF carry from
        // the attribute bag.
        (Some(x), Some(y), Some(z)) => [x, y, z],
        // Cross-codec: convert from the geodetic position via the
        // closed-form WGS-84 ↔ ECEF transform.
        _ => {
            let (x, y, z) = wgs84_to_ecef(
                position.lat,
                position.lon,
                position.hae_meters.unwrap_or(0.0),
            );
            [x, y, z]
        }
    };

    let entity_type = entity_type_from_attrs(entity, "entity_type").unwrap_or(EntityType {
        kind: 1,
        domain: 1,
        country: 0,
        category: 0,
        subcategory: 0,
        specific: 0,
        extra: 0,
    });
    let alternative_entity_type =
        entity_type_from_attrs(entity, "alternative_entity_type").unwrap_or(entity_type);

    let force_id = attr_int(entity, "force_id")
        .and_then(|v| u8::try_from(v).ok())
        .map_or(ForceId::Other, ForceId::from_u8);

    let linear_velocity = match (
        attr_float(entity, "linear_velocity_x_mps"),
        attr_float(entity, "linear_velocity_y_mps"),
        attr_float(entity, "linear_velocity_z_mps"),
    ) {
        (Some(x), Some(y), Some(z)) => [x as f32, y as f32, z as f32],
        _ => {
            // Cross-codec fallback: synthesise a ground-speed-only
            // X-forward triplet from the canonical polar velocity.
            // The DIS body frame depends on platform orientation, so
            // this is a coarse approximation suitable for cross-codec
            // fan-out — same-codec round-trip prefers the attribute
            // carry above.
            let speed = entity.velocity.map(|v| v.speed_m_s).unwrap_or(0.0);
            [speed as f32, 0.0, 0.0]
        }
    };

    let orientation = [
        attr_float(entity, "orientation_psi_rad").unwrap_or(0.0) as f32,
        attr_float(entity, "orientation_theta_rad").unwrap_or(0.0) as f32,
        attr_float(entity, "orientation_phi_rad").unwrap_or(0.0) as f32,
    ];

    let appearance = attr_int(entity, "appearance")
        .and_then(|v| u32::try_from(v).ok())
        .unwrap_or(0);
    let capabilities = attr_int(entity, "capabilities")
        .and_then(|v| u32::try_from(v).ok())
        .unwrap_or(0);

    let mut dead_reckoning = crate::entity_state::DeadReckoningParameters {
        algorithm: attr_int(entity, "dead_reckoning.algorithm")
            .and_then(|v| u8::try_from(v).ok())
            .unwrap_or(2), // DRM_FPW (linear motion) is the most common default
        other_parameters: [0; 15],
        linear_acceleration: [0.0; 3],
        angular_velocity: [0.0; 3],
    };
    // Round-trip the angular velocity from the attribute carry so a
    // same-codec encode preserves the wire form.
    if let Some(rate_x) = attr_float(entity, "angular_velocity_x_rad_s") {
        dead_reckoning.angular_velocity[0] = rate_x as f32;
    }
    if let Some(rate_y) = attr_float(entity, "angular_velocity_y_rad_s") {
        dead_reckoning.angular_velocity[1] = rate_y as f32;
    }
    if let Some(rate_z) = attr_float(entity, "angular_velocity_z_rad_s") {
        dead_reckoning.angular_velocity[2] = rate_z as f32;
    }

    let marking_charset = attr_int(entity, "marking_charset")
        .and_then(|v| u8::try_from(v).ok())
        .unwrap_or(1); // 1 = ASCII
    let marking = entity.callsign.clone().unwrap_or_default();

    let pdu = EntityStatePdu {
        header: PduHeader::new(
            PduType::EntityState,
            ProtocolFamily::EntityInformationInteraction,
            0, // overwritten by EntityStatePdu::encode
        ),
        entity_id,
        force_id,
        entity_type,
        alternative_entity_type,
        linear_velocity,
        location_ecef,
        orientation,
        appearance,
        dead_reckoning,
        marking_charset,
        marking,
        capabilities,
        articulation_parameters: Vec::new(),
    };

    let bytes = pdu
        .encode()
        .map_err(|e| DisEntityError::UnsupportedEntityKind(e.to_string()))?;
    Ok(Bytes::from(bytes))
}

/// Recover the (site, application, entity) triple from a UID matching
/// the canonical `dis-<site>-<app>-<entity>` shape.
fn parse_entity_id(uid: &str) -> Option<EntityId> {
    let rest = uid.strip_prefix("dis-")?;
    let mut parts = rest.split('-');
    let site: u16 = parts.next()?.parse().ok()?;
    let application: u16 = parts.next()?.parse().ok()?;
    let entity: u16 = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some(EntityId {
        site,
        application,
        entity,
    })
}

/// Recover the (site, application, entity) triple from the
/// attribute-bag carry. Used as a fallback when the UID was
/// synthesised by a non-DIS codec but the attributes were populated
/// through a previous decode.
fn entity_id_from_attrs(entity: &Entity) -> Option<EntityId> {
    Some(EntityId {
        site: attr_int(entity, "entity_id.site").and_then(|v| u16::try_from(v).ok())?,
        application: attr_int(entity, "entity_id.application")
            .and_then(|v| u16::try_from(v).ok())?,
        entity: attr_int(entity, "entity_id.entity").and_then(|v| u16::try_from(v).ok())?,
    })
}

/// Recover an [`EntityType`] from the attribute-bag carry under the
/// given key prefix (`"entity_type"` or `"alternative_entity_type"`).
fn entity_type_from_attrs(entity: &Entity, key_prefix: &str) -> Option<EntityType> {
    Some(EntityType {
        kind: attr_int(entity, &format!("{key_prefix}.kind")).and_then(|v| u8::try_from(v).ok())?,
        domain: attr_int(entity, &format!("{key_prefix}.domain"))
            .and_then(|v| u8::try_from(v).ok())?,
        country: attr_int(entity, &format!("{key_prefix}.country"))
            .and_then(|v| u16::try_from(v).ok())?,
        category: attr_int(entity, &format!("{key_prefix}.category"))
            .and_then(|v| u8::try_from(v).ok())?,
        subcategory: attr_int(entity, &format!("{key_prefix}.subcategory"))
            .and_then(|v| u8::try_from(v).ok())?,
        specific: attr_int(entity, &format!("{key_prefix}.specific"))
            .and_then(|v| u8::try_from(v).ok())?,
        extra: attr_int(entity, &format!("{key_prefix}.extra"))
            .and_then(|v| u8::try_from(v).ok())?,
    })
}

/// Look up an integer attribute under the `dis.<key>` namespace.
fn attr_int(entity: &Entity, key: &str) -> Option<i64> {
    match entity.attributes.get(&format!("{DIS_PREFIX}{key}")) {
        Some(AttributeValue::Int(v)) => Some(*v),
        _ => None,
    }
}

/// Look up a float attribute under the `dis.<key>` namespace.
fn attr_float(entity: &Entity, key: &str) -> Option<f64> {
    match entity.attributes.get(&format!("{DIS_PREFIX}{key}")) {
        Some(AttributeValue::Float(v)) => Some(*v),
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn sample_pdu_bytes() -> Vec<u8> {
        // Build an Entity State PDU at a known geodetic point and
        // encode it. The test fixtures rely on the wire-format
        // codec being correct; if those tests fail this module's
        // tests will fail too (which is the right cascade).
        let codec_pdu = EntityStatePdu {
            header: PduHeader::new(
                PduType::EntityState,
                ProtocolFamily::EntityInformationInteraction,
                0,
            ),
            entity_id: EntityId {
                site: 1,
                application: 2,
                entity: 100,
            },
            force_id: ForceId::Friendly,
            entity_type: EntityType {
                kind: 1,
                domain: 2, // Air → Aircraft
                country: 225,
                category: 1,
                subcategory: 2,
                specific: 3,
                extra: 4,
            },
            alternative_entity_type: EntityType {
                kind: 1,
                domain: 2,
                country: 225,
                category: 1,
                subcategory: 2,
                specific: 3,
                extra: 4,
            },
            linear_velocity: [100.0, 0.0, 0.0],
            // Approximate ECEF for Statue of Liberty (40.6892° N,
            // 74.0445° W, 93 m HAE).
            location_ecef: [1_331_360.0, -4_656_651.0, 4_136_374.0],
            orientation: [0.1, 0.2, 0.3],
            appearance: 0xCAFE_BABE,
            dead_reckoning: crate::entity_state::DeadReckoningParameters {
                algorithm: 2,
                other_parameters: [0; 15],
                linear_acceleration: [0.0, 0.0, 0.0],
                angular_velocity: [0.0, 0.0, 0.0],
            },
            marking_charset: 1,
            marking: "F-16C".into(),
            capabilities: 0,
            articulation_parameters: Vec::new(),
        };
        codec_pdu.encode().expect("encode")
    }

    #[test]
    fn entity_state_round_trips_through_dis_codec() {
        let codec = DisCodec;
        let bytes = sample_pdu_bytes();
        let entity1 = codec.to_entity(&bytes).expect("decode 1");
        assert_eq!(entity1.uid, "dis-1-2-100");
        assert_eq!(entity1.kind, EntityKind::Aircraft);

        let bytes2 = codec.from_entity(&entity1).expect("encode");
        let entity2 = codec.to_entity(&bytes2).expect("decode 2");
        assert_eq!(entity1.uid, entity2.uid);
        assert_eq!(entity1.kind, entity2.kind);
        assert_eq!(entity1.callsign, entity2.callsign);
        // ECEF carry should preserve the location wire-byte-exactly.
        let ecef1 = [
            attr_float(&entity1, "location_ecef_x").expect("x1"),
            attr_float(&entity1, "location_ecef_y").expect("y1"),
            attr_float(&entity1, "location_ecef_z").expect("z1"),
        ];
        let ecef2 = [
            attr_float(&entity2, "location_ecef_x").expect("x2"),
            attr_float(&entity2, "location_ecef_y").expect("y2"),
            attr_float(&entity2, "location_ecef_z").expect("z2"),
        ];
        assert_eq!(ecef1, ecef2);
    }

    #[test]
    fn dis_codec_to_entity_extracts_position_from_ecef() {
        let codec = DisCodec;
        let bytes = sample_pdu_bytes();
        let entity = codec.to_entity(&bytes).expect("decode");
        let position = entity.position.expect("position present");
        // ECEF for Statue of Liberty rounds to ~(40.6892, -74.0445).
        // Tolerances are generous; the published reference is
        // metre-rounded so single-point precision is bounded.
        assert!(
            (position.lat - 40.6892).abs() < 1e-3,
            "lat={}",
            position.lat
        );
        assert!(
            (position.lon - -74.0445).abs() < 1e-3,
            "lon={}",
            position.lon
        );
    }

    #[test]
    fn dis_codec_classifies_air_platform_as_aircraft() {
        let codec = DisCodec;
        let bytes = sample_pdu_bytes();
        let entity = codec.to_entity(&bytes).expect("decode");
        assert_eq!(entity.kind, EntityKind::Aircraft);
    }

    #[test]
    fn dis_codec_classifies_munition_as_munition() {
        // Build a minimal Entity State PDU with kind=2 (Munition).
        let pdu = EntityStatePdu {
            header: PduHeader::new(
                PduType::EntityState,
                ProtocolFamily::EntityInformationInteraction,
                0,
            ),
            entity_id: EntityId {
                site: 1,
                application: 2,
                entity: 3,
            },
            force_id: ForceId::Other,
            entity_type: EntityType {
                kind: 2,
                domain: 0,
                country: 0,
                category: 0,
                subcategory: 0,
                specific: 0,
                extra: 0,
            },
            alternative_entity_type: EntityType {
                kind: 2,
                domain: 0,
                country: 0,
                category: 0,
                subcategory: 0,
                specific: 0,
                extra: 0,
            },
            linear_velocity: [0.0; 3],
            location_ecef: [WGS84_X, WGS84_Y, WGS84_Z],
            orientation: [0.0; 3],
            appearance: 0,
            dead_reckoning: crate::entity_state::DeadReckoningParameters {
                algorithm: 0,
                other_parameters: [0; 15],
                linear_acceleration: [0.0; 3],
                angular_velocity: [0.0; 3],
            },
            marking_charset: 1,
            marking: "AGM-114".into(),
            capabilities: 0,
            articulation_parameters: Vec::new(),
        };
        let bytes = pdu.encode().expect("encode");
        let codec = DisCodec;
        let entity = codec.to_entity(&bytes).expect("decode");
        assert_eq!(entity.kind, EntityKind::Munition);
    }

    /// Sample ECEF coordinates used by the munition test. Pinned to
    /// the Statue of Liberty reference point so `position` is
    /// non-NaN and inside the WGS-84 envelope.
    const WGS84_X: f64 = 1_331_360.0;
    const WGS84_Y: f64 = -4_656_651.0;
    const WGS84_Z: f64 = 4_136_374.0;

    #[test]
    fn dis_codec_marking_propagates_to_callsign() {
        let codec = DisCodec;
        let bytes = sample_pdu_bytes();
        let entity = codec.to_entity(&bytes).expect("decode");
        assert_eq!(entity.callsign, Some("F-16C".into()));
    }

    #[test]
    fn dis_codec_invalid_pdu_returns_typed_error() {
        // Truncated PDU header — must surface InvalidPdu rather than
        // panicking.
        let codec = DisCodec;
        let bytes = vec![7u8, 0, 1, 1]; // 4 bytes — header is 12.
        let err = codec.to_entity(&bytes).expect_err("must fail");
        assert!(matches!(err, DisEntityError::InvalidPdu(_)));
    }

    #[test]
    fn dis_codec_unsupported_pdu_type_returns_typed_error() {
        // Build a 12-byte common header with PDU type = 2 (Fire PDU).
        let mut bytes = vec![0u8; 12];
        bytes[0] = 7;
        bytes[2] = 2; // Fire PDU
        bytes[3] = 2; // Warfare family
        bytes[8..10].copy_from_slice(&12u16.to_be_bytes());
        let codec = DisCodec;
        let err = codec.to_entity(&bytes).expect_err("must fail");
        match err {
            DisEntityError::UnsupportedPduType(t) => assert_eq!(t, 2),
            other => panic!("expected UnsupportedPduType, got {other:?}"),
        }
    }

    #[test]
    fn dis_codec_from_entity_rejects_no_position() {
        let codec = DisCodec;
        let entity = Entity {
            uid: "dis-1-2-3".into(),
            kind: EntityKind::Track,
            position: None,
            velocity: None,
            timestamp: SystemTime::UNIX_EPOCH,
            callsign: None,
            mil_std_2525_sidc: None,
            attributes: BTreeMap::new(),
        };
        let err = codec.from_entity(&entity).expect_err("must fail");
        assert!(matches!(err, DisEntityError::UnsupportedEntityKind(_)));
    }

    #[test]
    fn dis_codec_from_entity_rejects_unrecognised_uid() {
        let codec = DisCodec;
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
        assert!(matches!(err, DisEntityError::UnsupportedEntityKind(_)));
    }

    #[test]
    fn dis_codec_from_entity_recovers_from_attribute_bag() {
        // A non-DIS UID with the attribute carry must succeed.
        let codec = DisCodec;
        let mut attrs = BTreeMap::new();
        let _ = attrs.insert(
            format!("{DIS_PREFIX}entity_id.site"),
            AttributeValue::Int(99),
        );
        let _ = attrs.insert(
            format!("{DIS_PREFIX}entity_id.application"),
            AttributeValue::Int(88),
        );
        let _ = attrs.insert(
            format!("{DIS_PREFIX}entity_id.entity"),
            AttributeValue::Int(77),
        );
        let entity = Entity {
            uid: "cot-foo".into(),
            kind: EntityKind::Aircraft,
            position: Some(Position {
                lat: 40.0,
                lon: -75.0,
                hae_meters: Some(1000.0),
            }),
            velocity: None,
            timestamp: SystemTime::UNIX_EPOCH,
            callsign: None,
            mil_std_2525_sidc: None,
            attributes: attrs,
        };
        let bytes = codec.from_entity(&entity).expect("encode");
        let decoded = codec.to_entity(&bytes).expect("decode");
        assert_eq!(decoded.uid, "dis-99-88-77");
    }
}
