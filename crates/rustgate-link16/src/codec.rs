// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Link 16 / JREAP-C implementation of the canonical
//! [`rustgate_core::entity::EntityCodec`] trait — refs #866 / #847.
//!
//! [`Link16Codec`] decodes a JREAP-C frame whose body is a J2.2 Air
//! Track into the protocol-agnostic [`Entity`] shape and re-encodes a
//! position-bearing [`Entity`] back into a wire-form JREAP-C frame
//! carrying a J2.2 body.
//!
//! # Mapping summary
//!
//! Inbound (JREAP-C frame → [`Entity`]):
//!
//! | JREAP-C / J2.2 source             | `Entity` field                                           |
//! |-----------------------------------|----------------------------------------------------------|
//! | track_number                      | `Entity.uid` (`"link16-{track_number:08x}"`)             |
//! | latitude_micro_deg / longitude    | `Entity.position` (lat / lon decimal degrees)            |
//! | altitude_m                        | `Entity.position.hae_meters`                             |
//! | speed_cm_s + course_centideg      | `Entity.velocity` (m/s + degrees CW from true north)     |
//! | platform_type                     | `Entity.kind` (Aircraft / Munition / Track)              |
//! | every wire-format field           | `Entity.attributes` under the `"link16."` namespace      |
//!
//! Outbound (`Entity` → JREAP-C frame) is intentionally narrower:
//! only `Position`-bearing entities encode. Entities without a
//! position surface
//! [`Link16EntityError::UnsupportedEntityKind`].
//!
//! # Round-trip discipline
//!
//! Same-codec round-trip preserves every J2.2 wire-format field via
//! the `link16.*` attribute bag — including the raw integer carries
//! (`link16.j2_2.latitude_micro_deg`, `link16.j2_2.speed_cm_s`,
//! `link16.j2_2.course_centideg`) so the encoder can recover the
//! exact bits the originating platform emitted, sidestepping any
//! precision loss in the integer ↔ float conversion. Cross-codec
//! entities (e.g. a CoT event encoded through the Link 16 codec)
//! fall back to deriving the integer carries from the float fields
//! per the [`rustgate_core::entity::EntityCodec`] contract.

use std::collections::BTreeMap;
use std::time::SystemTime;

use bytes::Bytes;
use rustgate_core::entity::{AttributeValue, Entity, EntityCodec, EntityKind, Position, Velocity};

use crate::error::Link16Error;
use crate::header::{JREAP_HEADER_LEN, JreapFrame, JreapMessageType};
use crate::jseries::{IffCodes, J2_2AirTrack, JseriesKinematics, JseriesMessage, PlatformType};

/// Attribute-key prefix used for every Link 16 / JREAP-C-derived
/// [`AttributeValue`]. Keeps the namespace separated from other
/// codecs (CoT, MAVLink, ASTERIX, STANAG-4586, DIS, VMF, Meshtastic)
/// sharing the [`Entity`] shape.
pub const LINK16_PREFIX: &str = "link16.";

/// Errors surfaced by [`Link16Codec::to_entity`] /
/// [`Link16Codec::from_entity`].
///
/// Distinct from [`crate::error::Link16Error`] (wire-format
/// truncation / framing) because the codec failure modes belong to a
/// different operational class — a SIEM that pages on
/// `link16.frame_rejected` should NOT page on
/// `link16.entity.unsupported_entity_kind`, which is a routine
/// "this entity has no Link 16 wire form" signal during cross-
/// protocol fan-out.
#[derive(Debug, thiserror::Error)]
pub enum Link16EntityError {
    /// Payload bytes do not parse as a JREAP-C frame carrying a
    /// J-series body. The inner string carries the underlying
    /// [`Link16Error`] context for an operator log line without
    /// exposing the raw payload (which may be hostile or classified).
    #[error("malformed JREAP-C frame: {0}")]
    InvalidFrame(String),

    /// JREAP-C `message_type` is outside the subset this codec maps
    /// to the [`Entity`] shape. The MVP only handles
    /// [`JreapMessageType::JseriesData`] frames carrying a J2.2 body;
    /// link-connect / heartbeat / link-disconnect frames surface this
    /// error and will be wired in subsequent PRs.
    #[error("JREAP-C message type {0:#04x} cannot be mapped to Entity")]
    UnsupportedMessageType(u8),

    /// The frame body is a non-J2.2 J-series message label. Preserved
    /// in the lower-level [`JseriesMessage::Other`] variant; the
    /// codec surfaces this so the integration layer can route the
    /// frame as opaque bytes (or, after a follow-up PR lands, as a
    /// typed shape).
    #[error("J-series message label {0:#04x} cannot yet be mapped to Entity")]
    UnsupportedJseriesLabel(u8),

    /// `from_entity` cannot represent the supplied [`Entity`] as a
    /// J2.2 Air Track. The string captures the cause for the audit
    /// trail — typical contents are `"entity has no Position"` (the
    /// most common case during cross-protocol fan-out),
    /// `"non-finite position"` for entities whose lat/lon are NaN /
    /// inf, and `"entity uid does not parse as link16-<hex>"`.
    #[error("Entity kind {0} cannot be mapped to Link 16")]
    UnsupportedEntityKind(String),
}

/// JREAP-C wire-format codec for the canonical [`Entity`] shape.
///
/// Stateless — the same instance is safe to reuse across every routed
/// message on every thread. The router holds an `Arc<Link16Codec>`
/// per protocol slot.
#[derive(Debug, Default, Clone, Copy)]
pub struct Link16Codec;

impl EntityCodec for Link16Codec {
    type Error = Link16EntityError;

    fn to_entity(&self, payload: &[u8]) -> Result<Entity, Self::Error> {
        decode_jreap_c(payload)
    }

    fn from_entity(&self, entity: &Entity) -> Result<Bytes, Self::Error> {
        encode_jreap_c(entity)
    }
}

/// Decode a JREAP-C frame carrying a J2.2 Air Track into the
/// canonical [`Entity`] shape.
fn decode_jreap_c(payload: &[u8]) -> Result<Entity, Link16EntityError> {
    let header =
        JreapFrame::decode(payload).map_err(|e| Link16EntityError::InvalidFrame(e.to_string()))?;
    if header.message_type != JreapMessageType::JseriesData {
        return Err(Link16EntityError::UnsupportedMessageType(
            header.message_type.to_u8(),
        ));
    }

    let body_start = JREAP_HEADER_LEN;
    let body_end = body_start
        .checked_add(header.body_length as usize)
        .ok_or_else(|| {
            Link16EntityError::InvalidFrame("body length overflow on add".to_string())
        })?;
    if payload.len() < body_end {
        return Err(Link16EntityError::InvalidFrame(
            Link16Error::BodyLengthMismatch {
                declared: header.body_length as usize,
                actual: payload.len().saturating_sub(body_start),
            }
            .to_string(),
        ));
    }
    let body = &payload[body_start..body_end];

    let message =
        JseriesMessage::decode(body).map_err(|e| Link16EntityError::InvalidFrame(e.to_string()))?;
    let track = match message {
        JseriesMessage::J2_2AirTrack(t) => t,
        JseriesMessage::Other { label, .. } => {
            return Err(Link16EntityError::UnsupportedJseriesLabel(label));
        }
    };

    let uid = format!("link16-{:08x}", track.track_number);
    let position = Some(Position {
        lat: track.latitude_deg(),
        lon: track.longitude_deg(),
        hae_meters: Some(f64::from(track.altitude_m)),
    });
    let velocity = if track.kinematics.speed_cm_s == 0 {
        None
    } else {
        Some(Velocity {
            speed_m_s: f64::from(track.kinematics.speed_cm_s) / 100.0,
            course_deg: f64::from(track.kinematics.course_centideg) / 100.0,
        })
    };
    let kind = match track.platform_type {
        PlatformType::Aircraft | PlatformType::Helicopter => EntityKind::Aircraft,
        PlatformType::Missile => EntityKind::Munition,
        PlatformType::Unknown => EntityKind::Track,
        PlatformType::Other(_) => EntityKind::Track,
    };

    let mut attributes: BTreeMap<String, AttributeValue> = BTreeMap::new();
    populate_attributes(&mut attributes, &header, &track);

    Ok(Entity {
        uid,
        kind,
        position,
        velocity,
        timestamp: SystemTime::now(),
        callsign: None,
        mil_std_2525_sidc: None,
        attributes,
        taskings: Default::default(),
        files: Default::default(),
    })
}

/// Encode a position-bearing [`Entity`] as a JREAP-C frame carrying a
/// J2.2 Air Track.
fn encode_jreap_c(entity: &Entity) -> Result<Bytes, Link16EntityError> {
    let position = entity
        .position
        .ok_or_else(|| Link16EntityError::UnsupportedEntityKind("entity has no Position".into()))?;
    if !position.lat.is_finite() || !position.lon.is_finite() {
        return Err(Link16EntityError::UnsupportedEntityKind(
            "non-finite position".into(),
        ));
    }
    if !(-90.0..=90.0).contains(&position.lat) || !(-180.0..=180.0).contains(&position.lon) {
        return Err(Link16EntityError::UnsupportedEntityKind(
            "position out of WGS-84 envelope".into(),
        ));
    }

    let track_number = lookup_int(&entity.attributes, "j2_2.track_number")
        .and_then(|v| u32::try_from(v).ok())
        .unwrap_or_else(|| derive_track_number_from_uid(&entity.uid));

    // Pre-compute the fallback values for the J2.2 integer carries.
    // The `as` casts below are the documented codec contract for
    // cross-codec entities (entities arriving without explicit
    // `link16.j2_2.*` integer attributes); the values are bounded by
    // the wire envelope and round-trip through `J2_2AirTrack::decode`.
    // justification: lat/lon are in `[-180, 180]`, scaling by 1e6
    // yields a value comfortably inside the `i32` range. The cast is
    // the saturating-cast contract callers expect for cross-codec
    // entities; an out-of-envelope value is rejected upstream by the
    // `position.lat`/`position.lon` envelope check, so the cast cannot
    // truncate in practice.
    #[allow(clippy::cast_possible_truncation)]
    let fallback_latitude_micro_deg = (position.lat * 1_000_000.0) as i32;
    // justification: same bound as latitude — `[-180, 180]` × 1e6 fits
    // `i32` comfortably; documented saturating-cast contract.
    #[allow(clippy::cast_possible_truncation)]
    let fallback_longitude_micro_deg = (position.lon * 1_000_000.0) as i32;
    // justification: altitudes outside the `i32` range are physically
    // implausible (Earth-radius scale); the saturating cast is the
    // documented codec behaviour when no explicit
    // `link16.j2_2.altitude_m` attribute is attached and the resulting
    // bytes round-trip through `J2_2AirTrack::decode`.
    #[allow(clippy::cast_possible_truncation)]
    let fallback_altitude_m = position.hae_meters.unwrap_or(0.0) as i32;
    let fallback_speed_cm_s = match entity.velocity {
        Some(v) => {
            // justification: Velocity speeds are bounded by the J2.2
            // wire envelope (ground speed in cm/s fits `u32` to
            // ~430,000 km/h, comfortably above the geostationary
            // velocity scale); the saturating cast is the documented
            // codec behaviour for cross-codec entities whose speed
            // attribute was not explicitly carried, and the value
            // round-trips through `J2_2AirTrack::decode` because the
            // wire field is `u32`.
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let cm_s = (v.speed_m_s * 100.0).max(0.0) as u32;
            cm_s
        }
        None => 0,
    };
    let fallback_course_centideg = match entity.velocity {
        Some(v) => {
            // justification: course is normalised to `[0, 360)` first,
            // then multiplied by 100 to yield a value in `[0, 36000)`
            // that fits `u16` by construction. The saturating cast is
            // the documented codec behaviour and the value round-trips
            // through `J2_2AirTrack::decode` because the wire field is
            // `u16` with the same `[0, 36000)` envelope.
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let centideg = (v.course_deg.rem_euclid(360.0) * 100.0) as u16;
            centideg.min(35_999)
        }
        None => 0,
    };

    let latitude_micro_deg = lookup_int(&entity.attributes, "j2_2.latitude_micro_deg")
        .and_then(|v| i32::try_from(v).ok())
        .unwrap_or(fallback_latitude_micro_deg);
    let longitude_micro_deg = lookup_int(&entity.attributes, "j2_2.longitude_micro_deg")
        .and_then(|v| i32::try_from(v).ok())
        .unwrap_or(fallback_longitude_micro_deg);
    let altitude_m = lookup_int(&entity.attributes, "j2_2.altitude_m")
        .and_then(|v| i32::try_from(v).ok())
        .unwrap_or(fallback_altitude_m);
    let speed_cm_s = lookup_int(&entity.attributes, "j2_2.speed_cm_s")
        .and_then(|v| u32::try_from(v).ok())
        .unwrap_or(fallback_speed_cm_s);
    let course_centideg = lookup_int(&entity.attributes, "j2_2.course_centideg")
        .and_then(|v| u16::try_from(v).ok())
        .unwrap_or(fallback_course_centideg);
    let climb_rate_dm_s = lookup_int(&entity.attributes, "j2_2.climb_rate_dm_s")
        .and_then(|v| i16::try_from(v).ok())
        .unwrap_or(0);

    let fallback_platform_type = match entity.kind {
        EntityKind::Aircraft => PlatformType::Aircraft,
        EntityKind::Munition => PlatformType::Missile,
        _ => PlatformType::Unknown,
    };
    let platform_type = lookup_int(&entity.attributes, "j2_2.platform_type")
        .and_then(|v| u8::try_from(v).ok())
        .map_or(fallback_platform_type, PlatformType::from_u8);

    let iff_status_byte = lookup_int(&entity.attributes, "j2_2.iff.status_byte")
        .and_then(|v| u8::try_from(v).ok())
        .unwrap_or(0);
    let iff_mode_3_code = lookup_int(&entity.attributes, "j2_2.iff.mode_3_code")
        .and_then(|v| u16::try_from(v).ok())
        .unwrap_or(0);

    let track = J2_2AirTrack {
        track_number,
        latitude_micro_deg,
        longitude_micro_deg,
        altitude_m,
        platform_type,
        iff: IffCodes {
            status_byte: iff_status_byte,
            mode_3_code: iff_mode_3_code,
        },
        kinematics: JseriesKinematics {
            speed_cm_s,
            course_centideg,
            climb_rate_dm_s,
        },
    };

    let mut body: Vec<u8> = Vec::with_capacity(J2_2AirTrack::BODY_LEN);
    track
        .encode_into(&mut body)
        .map_err(|e| Link16EntityError::UnsupportedEntityKind(e.to_string()))?;

    let header = JreapFrame {
        version: crate::header::JREAP_C_VERSION,
        message_type: JreapMessageType::JseriesData,
        exercise_id: lookup_int(&entity.attributes, "frame.exercise_id")
            .and_then(|v| u8::try_from(v).ok())
            .unwrap_or(0),
        reserved: 0,
        sequence: lookup_int(&entity.attributes, "frame.sequence")
            .and_then(|v| u32::try_from(v).ok())
            .unwrap_or(0),
        timestamp: lookup_int(&entity.attributes, "frame.timestamp")
            .and_then(|v| u32::try_from(v).ok())
            .unwrap_or(0),
        body_length: body.len() as u32,
    };

    let mut out: Vec<u8> = Vec::with_capacity(JREAP_HEADER_LEN + body.len());
    header.encode_into(&mut out);
    out.extend_from_slice(&body);
    Ok(Bytes::from(out))
}

fn lookup_int(attributes: &BTreeMap<String, AttributeValue>, suffix: &str) -> Option<i64> {
    let key = format!("{LINK16_PREFIX}{suffix}");
    match attributes.get(&key) {
        Some(AttributeValue::Int(v)) => Some(*v),
        _ => None,
    }
}

fn derive_track_number_from_uid(uid: &str) -> u32 {
    if let Some(rest) = uid.strip_prefix("link16-")
        && let Ok(parsed) = u32::from_str_radix(rest, 16)
    {
        return parsed;
    }
    // justification: the cross-codec fallback hashes the UID into the
    // u32 track-number space deterministically so encode is total —
    // the alternative would require the EntityCodec contract to fail
    // on every cross-codec entity, defeating the cross-protocol
    // fan-out purpose of #847. The fold preserves diversity well
    // enough for the routing layer's correlation needs and any
    // round-trip concern is sidestepped by the explicit
    // `link16.j2_2.track_number` attribute path consulted earlier.
    let mut acc: u32 = 0x811C_9DC5;
    for byte in uid.as_bytes() {
        acc = acc.wrapping_mul(0x0100_0193) ^ u32::from(*byte);
    }
    acc
}

fn populate_attributes(
    attributes: &mut BTreeMap<String, AttributeValue>,
    header: &JreapFrame,
    track: &J2_2AirTrack,
) {
    let _ = attributes.insert(
        format!("{LINK16_PREFIX}frame.version"),
        AttributeValue::Int(i64::from(header.version)),
    );
    let _ = attributes.insert(
        format!("{LINK16_PREFIX}frame.message_type"),
        AttributeValue::Int(i64::from(header.message_type.to_u8())),
    );
    let _ = attributes.insert(
        format!("{LINK16_PREFIX}frame.exercise_id"),
        AttributeValue::Int(i64::from(header.exercise_id)),
    );
    let _ = attributes.insert(
        format!("{LINK16_PREFIX}frame.sequence"),
        AttributeValue::Int(i64::from(header.sequence)),
    );
    let _ = attributes.insert(
        format!("{LINK16_PREFIX}frame.timestamp"),
        AttributeValue::Int(i64::from(header.timestamp)),
    );

    let _ = attributes.insert(
        format!("{LINK16_PREFIX}j2_2.track_number"),
        AttributeValue::Int(i64::from(track.track_number)),
    );
    let _ = attributes.insert(
        format!("{LINK16_PREFIX}j2_2.latitude_micro_deg"),
        AttributeValue::Int(i64::from(track.latitude_micro_deg)),
    );
    let _ = attributes.insert(
        format!("{LINK16_PREFIX}j2_2.longitude_micro_deg"),
        AttributeValue::Int(i64::from(track.longitude_micro_deg)),
    );
    let _ = attributes.insert(
        format!("{LINK16_PREFIX}j2_2.altitude_m"),
        AttributeValue::Int(i64::from(track.altitude_m)),
    );
    let _ = attributes.insert(
        format!("{LINK16_PREFIX}j2_2.platform_type"),
        AttributeValue::Int(i64::from(track.platform_type.to_u8())),
    );
    let _ = attributes.insert(
        format!("{LINK16_PREFIX}j2_2.iff.status_byte"),
        AttributeValue::Int(i64::from(track.iff.status_byte)),
    );
    let _ = attributes.insert(
        format!("{LINK16_PREFIX}j2_2.iff.mode_3_code"),
        AttributeValue::Int(i64::from(track.iff.mode_3_code)),
    );
    let _ = attributes.insert(
        format!("{LINK16_PREFIX}j2_2.speed_cm_s"),
        AttributeValue::Int(i64::from(track.kinematics.speed_cm_s)),
    );
    let _ = attributes.insert(
        format!("{LINK16_PREFIX}j2_2.course_centideg"),
        AttributeValue::Int(i64::from(track.kinematics.course_centideg)),
    );
    let _ = attributes.insert(
        format!("{LINK16_PREFIX}j2_2.climb_rate_dm_s"),
        AttributeValue::Int(i64::from(track.kinematics.climb_rate_dm_s)),
    );
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::header::JREAP_C_VERSION;

    fn sample_track() -> J2_2AirTrack {
        J2_2AirTrack {
            track_number: 0x1234_5678,
            latitude_micro_deg: 40_689_247,
            longitude_micro_deg: -74_044_502,
            altitude_m: 12_500,
            platform_type: PlatformType::Aircraft,
            iff: IffCodes {
                status_byte: 0b0000_0011,
                mode_3_code: 0o1200,
            },
            kinematics: JseriesKinematics {
                speed_cm_s: 25_000,
                course_centideg: 9000,
                climb_rate_dm_s: -50,
            },
        }
    }

    fn build_frame(track: &J2_2AirTrack) -> Bytes {
        let mut body: Vec<u8> = Vec::new();
        track.encode_into(&mut body).expect("encode body");
        let header = JreapFrame::new(JreapMessageType::JseriesData, body.len() as u32);
        let mut out: Vec<u8> = Vec::new();
        header.encode_into(&mut out);
        out.extend_from_slice(&body);
        Bytes::from(out)
    }

    #[test]
    fn to_entity_decodes_position_velocity_and_kind() {
        let frame = build_frame(&sample_track());
        let entity = Link16Codec.to_entity(&frame).expect("decode");
        let pos = entity.position.expect("position present");
        assert!((pos.lat - 40.689247).abs() < 1e-9);
        assert!((pos.lon - (-74.044502)).abs() < 1e-9);
        assert!((pos.hae_meters.expect("alt") - 12_500.0).abs() < 1e-9);
        let v = entity.velocity.expect("velocity present");
        assert!((v.speed_m_s - 250.0).abs() < 1e-9);
        assert!((v.course_deg - 90.0).abs() < 1e-9);
        assert_eq!(entity.kind, EntityKind::Aircraft);
        assert_eq!(entity.uid, "link16-12345678");
    }

    #[test]
    fn round_trip_preserves_wire_form_via_attributes() {
        let track = sample_track();
        let frame = build_frame(&track);
        let entity = Link16Codec.to_entity(&frame).expect("decode");
        let re_encoded = Link16Codec.from_entity(&entity).expect("encode");
        assert_eq!(re_encoded.as_ref(), frame.as_ref());
    }

    #[test]
    fn from_entity_rejects_entity_without_position() {
        let entity = Entity {
            uid: "link16-deadbeef".into(),
            kind: EntityKind::Aircraft,
            position: None,
            velocity: None,
            timestamp: SystemTime::now(),
            callsign: None,
            mil_std_2525_sidc: None,
            attributes: BTreeMap::new(),
            taskings: Default::default(),
            files: Default::default(),
        };
        let err = Link16Codec.from_entity(&entity).expect_err("must fail");
        assert!(matches!(err, Link16EntityError::UnsupportedEntityKind(_)));
    }

    #[test]
    fn from_entity_rejects_non_finite_position() {
        let entity = Entity {
            uid: "link16-deadbeef".into(),
            kind: EntityKind::Aircraft,
            position: Some(Position {
                lat: f64::NAN,
                lon: 0.0,
                hae_meters: None,
            }),
            velocity: None,
            timestamp: SystemTime::now(),
            callsign: None,
            mil_std_2525_sidc: None,
            attributes: BTreeMap::new(),
            taskings: Default::default(),
            files: Default::default(),
        };
        let err = Link16Codec.from_entity(&entity).expect_err("must fail");
        assert!(matches!(err, Link16EntityError::UnsupportedEntityKind(_)));
    }

    #[test]
    fn to_entity_rejects_unsupported_message_type() {
        let mut frame = vec![0u8; JREAP_HEADER_LEN];
        frame[0] = JREAP_C_VERSION;
        frame[1] = 0xFE; // Other message type
        let err = Link16Codec.to_entity(&frame).expect_err("must fail");
        assert!(matches!(
            err,
            Link16EntityError::UnsupportedMessageType(0xFE)
        ));
    }

    #[test]
    fn to_entity_rejects_unsupported_jseries_label() {
        let mut body: Vec<u8> = vec![0u8; J2_2AirTrack::BODY_LEN];
        body[0] = 0x35; // J3.5 label
        let header = JreapFrame::new(JreapMessageType::JseriesData, body.len() as u32);
        let mut out: Vec<u8> = Vec::new();
        header.encode_into(&mut out);
        out.extend_from_slice(&body);
        let err = Link16Codec.to_entity(&out).expect_err("must fail");
        assert!(matches!(
            err,
            Link16EntityError::UnsupportedJseriesLabel(0x35)
        ));
    }

    #[test]
    fn to_entity_rejects_truncated_body() {
        let track = sample_track();
        let mut body: Vec<u8> = Vec::new();
        track.encode_into(&mut body).expect("encode");
        let header = JreapFrame::new(JreapMessageType::JseriesData, body.len() as u32);
        let mut out: Vec<u8> = Vec::new();
        header.encode_into(&mut out);
        // Body deliberately truncated.
        out.extend_from_slice(&body[..body.len() - 2]);
        let err = Link16Codec.to_entity(&out).expect_err("must fail");
        assert!(matches!(err, Link16EntityError::InvalidFrame(_)));
    }

    #[test]
    fn velocity_zero_speed_decodes_as_none() {
        let mut track = sample_track();
        track.kinematics.speed_cm_s = 0;
        let frame = build_frame(&track);
        let entity = Link16Codec.to_entity(&frame).expect("decode");
        assert!(entity.velocity.is_none());
    }

    #[test]
    fn missile_platform_maps_to_munition_kind() {
        let mut track = sample_track();
        track.platform_type = PlatformType::Missile;
        let frame = build_frame(&track);
        let entity = Link16Codec.to_entity(&frame).expect("decode");
        assert_eq!(entity.kind, EntityKind::Munition);
    }

    #[test]
    fn unknown_platform_maps_to_track_kind() {
        let mut track = sample_track();
        track.platform_type = PlatformType::Unknown;
        let frame = build_frame(&track);
        let entity = Link16Codec.to_entity(&frame).expect("decode");
        assert_eq!(entity.kind, EntityKind::Track);
    }
}
