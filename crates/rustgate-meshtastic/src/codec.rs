// Copyright © 2026 Roberto Chiofalo.

//! Implementation of the canonical [`EntityCodec`] trait for the
//! Meshtastic LoRa TAKPacket wire format.
//!
//! [`MeshtasticCodec`] decodes a TAKPacket payload (the inner
//! protobuf body, after the mesh-frame header has been stripped by
//! the transport layer) into the protocol-agnostic
//! [`rustgate_core::entity::Entity`] shape and re-encodes a
//! position-bearing or chat-bearing entity back into a TAKPacket
//! that fits the [`crate::MAX_PAYLOAD_BYTES`] LoRa transport cap.
//! The codec plugs into the workspace's `EntityCodecRegistry`
//! (closes #847) so the router can fan an entity out across
//! Meshtastic alongside CoT XML, MAVLink, ASTERIX, and STANAG-4586.
//!
//! # Round-trip discipline
//!
//! Same-codec round-trip preserves the position to LSB precision
//! (≈ 1.1 cm at the equator), the wire-format scaled-integer
//! representations (carried on the attribute bag for round-trip
//! reconstruction), and the contact / group / status fields when
//! present. Cross-codec entities (e.g. a CoT event encoded through
//! the Meshtastic codec) lose any field the canonical `Entity`
//! shape does not surface — that is the documented `EntityCodec`
//! contract.
//!
//! # Field pruning for the 237-byte cap
//!
//! Encode is intentionally narrow: every optional field is omitted
//! when its source value is empty / default, and the encoder
//! checks the final size against [`crate::MAX_PAYLOAD_BYTES`] and
//! returns [`MeshtasticError::PayloadTooLarge`] rather than emit a
//! frame the LoRa transport will refuse. Callers that need to
//! shed more bytes (e.g. dropping a long callsign on a sustained
//! tail of a busy window) can pre-prune the entity's `attributes`
//! before invoking the codec.

use std::collections::BTreeMap;
use std::time::SystemTime;

use bytes::Bytes;
use rustgate_core::entity::{AttributeValue, Entity, EntityCodec, EntityKind, Position, Velocity};

use crate::MAX_PAYLOAD_BYTES;
use crate::error::MeshtasticError;
use crate::proto::{
    COORD_SCALE, COURSE_SCALE_HUNDREDTHS_DEG, Contact, GeoChat, Group, PayloadVariant, Pli,
    SPEED_SCALE_CM_PER_S, Status, TakPacket, decode_tak_packet, encode_tak_packet,
};

/// Attribute-key prefix for every Meshtastic-derived entry. Keeps
/// the attribute namespace separated from other codecs (CoT,
/// MAVLink, ASTERIX, STANAG-4586) that share the [`Entity`] shape.
const MESHTASTIC_PREFIX: &str = "meshtastic.";

/// UID prefix used when the wire frame supplies a device callsign;
/// keeps Meshtastic-derived entities namespace-separated from
/// other codecs in a multi-protocol ingestion path.
const UID_PREFIX_DEVICE: &str = "meshtastic-";

/// UID prefix used when the wire frame omits a device callsign and
/// only the operator callsign is available; the latter is not
/// guaranteed unique across deployments but is the best stable
/// handle the codec has when the device-callsign field is absent.
const UID_PREFIX_CALLSIGN: &str = "meshtastic-cs-";

/// UID assigned when the wire frame supplies neither a contact nor
/// any payload that carries a sender identity. Real Meshtastic
/// frames always carry a sender, so this is essentially a fallback
/// for fixtures and forward-compat schema revisions where the
/// contact arrives in a field this codec version does not
/// recognise; the placeholder UID keeps the entity flowable through
/// the router rather than being rejected at the codec boundary.
const UID_FALLBACK: &str = "meshtastic-anonymous";

/// Stateless wire-format codec for the Meshtastic TAKPacket schema.
///
/// Holds no state — the same instance is safe to reuse across every
/// routed message on every thread. Construct with `Default::default()`
/// or [`MeshtasticCodec::new`].
#[derive(Debug, Default, Clone, Copy)]
pub struct MeshtasticCodec;

impl MeshtasticCodec {
    /// Construct a fresh codec instance. Equivalent to
    /// `MeshtasticCodec::default()`.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl EntityCodec for MeshtasticCodec {
    type Error = MeshtasticError;

    fn to_entity(&self, payload: &[u8]) -> Result<Entity, Self::Error> {
        let packet = decode_tak_packet(payload)?;
        Ok(packet_to_entity(packet))
    }

    fn from_entity(&self, entity: &Entity) -> Result<Bytes, Self::Error> {
        let packet = entity_to_packet(entity)?;
        let bytes = encode_tak_packet(&packet)?;
        // Defense in depth — encode_tak_packet already enforces the
        // cap, but a future refactor could land a code path that
        // bypasses it (e.g. an alternate encoder for benchmarking).
        // The redundant check here is cheap.
        if bytes.len() > MAX_PAYLOAD_BYTES {
            return Err(MeshtasticError::PayloadTooLarge { bytes: bytes.len() });
        }
        Ok(Bytes::from(bytes))
    }
}

/// Map a decoded [`TakPacket`] into the canonical [`Entity`] shape.
///
/// The classifier favours [`EntityKind::Ground`] for PLI-bearing
/// frames (the typical Meshtastic deployment is dismounted operators
/// and ground vehicles), [`EntityKind::Track`] for chat-only frames,
/// and [`EntityKind::Unknown`] with a typed label for the opaque
/// `detail` arm so a future codec version can lift fine-grained CoT
/// dispatch without breaking the wire form.
fn packet_to_entity(packet: TakPacket) -> Entity {
    let TakPacket {
        is_compressed,
        contact,
        group,
        status,
        payload_variant,
    } = packet;

    let mut attributes: BTreeMap<String, AttributeValue> = BTreeMap::new();
    if is_compressed {
        let _ = attributes.insert(
            format!("{MESHTASTIC_PREFIX}is_compressed"),
            AttributeValue::Bool(true),
        );
    }
    if let Some(group) = &group {
        let _ = attributes.insert(
            format!("{MESHTASTIC_PREFIX}group.role"),
            AttributeValue::Int(i64::from(group.role)),
        );
        let _ = attributes.insert(
            format!("{MESHTASTIC_PREFIX}group.team"),
            AttributeValue::Int(i64::from(group.team)),
        );
    }
    if let Some(status) = &status {
        let _ = attributes.insert(
            format!("{MESHTASTIC_PREFIX}status.battery"),
            AttributeValue::Int(i64::from(status.battery)),
        );
    }

    let callsign = contact
        .as_ref()
        .map(|c| c.callsign.clone())
        .filter(|s| !s.is_empty());
    if let Some(contact) = &contact
        && !contact.device_callsign.is_empty()
    {
        let _ = attributes.insert(
            format!("{MESHTASTIC_PREFIX}contact.device_callsign"),
            AttributeValue::Str(contact.device_callsign.clone()),
        );
    }

    let uid = derive_uid(contact.as_ref());

    let (kind, position, velocity) = match payload_variant {
        Some(PayloadVariant::Pli(pli)) => {
            populate_pli_attributes(&mut attributes, &pli);
            let (lat, lon, alt, speed_m_s, course_deg) = pli.to_position_floats();
            (
                EntityKind::Ground,
                Some(Position {
                    lat,
                    lon,
                    hae_meters: Some(alt),
                }),
                Some(Velocity {
                    speed_m_s,
                    course_deg,
                }),
            )
        }
        Some(PayloadVariant::Chat(chat)) => {
            populate_chat_attributes(&mut attributes, &chat);
            (EntityKind::Track, None, None)
        }
        Some(PayloadVariant::Detail(detail)) => {
            let _ = attributes.insert(
                format!("{MESHTASTIC_PREFIX}detail.bytes_len"),
                AttributeValue::Int(i64::try_from(detail.len()).unwrap_or(i64::MAX)),
            );
            (EntityKind::Unknown("meshtastic-detail".into()), None, None)
        }
        None => (EntityKind::Track, None, None),
    };

    Entity {
        uid,
        kind,
        position,
        velocity,
        timestamp: SystemTime::now(),
        callsign,
        mil_std_2525_sidc: None,
        attributes,
    }
}

/// Construct a stable UID for the [`Entity`] from the wire-format
/// contact identity. Prefers `device_callsign` (hardware-rooted,
/// stable across operator handoffs) and falls back to the
/// operator callsign or a synthetic constant when neither is
/// supplied.
fn derive_uid(contact: Option<&Contact>) -> String {
    let Some(contact) = contact else {
        return UID_FALLBACK.into();
    };
    if !contact.device_callsign.is_empty() {
        return format!("{UID_PREFIX_DEVICE}{}", contact.device_callsign);
    }
    if !contact.callsign.is_empty() {
        return format!("{UID_PREFIX_CALLSIGN}{}", contact.callsign);
    }
    UID_FALLBACK.into()
}

fn populate_pli_attributes(attributes: &mut BTreeMap<String, AttributeValue>, pli: &Pli) {
    // Raw scaled-integer carries: same-codec round-trip recovers the
    // exact wire bytes through these.
    let _ = attributes.insert(
        format!("{MESHTASTIC_PREFIX}pli.latitude_i"),
        AttributeValue::Int(i64::from(pli.latitude_i)),
    );
    let _ = attributes.insert(
        format!("{MESHTASTIC_PREFIX}pli.longitude_i"),
        AttributeValue::Int(i64::from(pli.longitude_i)),
    );
    let _ = attributes.insert(
        format!("{MESHTASTIC_PREFIX}pli.altitude"),
        AttributeValue::Int(i64::from(pli.altitude)),
    );
    let _ = attributes.insert(
        format!("{MESHTASTIC_PREFIX}pli.speed_cm_s"),
        AttributeValue::Int(i64::from(pli.speed)),
    );
    let _ = attributes.insert(
        format!("{MESHTASTIC_PREFIX}pli.course_centideg"),
        AttributeValue::Int(i64::from(pli.course)),
    );
}

fn populate_chat_attributes(attributes: &mut BTreeMap<String, AttributeValue>, chat: &GeoChat) {
    if !chat.message.is_empty() {
        let _ = attributes.insert(
            format!("{MESHTASTIC_PREFIX}chat.message"),
            AttributeValue::Str(chat.message.clone()),
        );
    }
    if !chat.to.is_empty() {
        let _ = attributes.insert(
            format!("{MESHTASTIC_PREFIX}chat.to"),
            AttributeValue::Str(chat.to.clone()),
        );
    }
    if !chat.to_callsign.is_empty() {
        let _ = attributes.insert(
            format!("{MESHTASTIC_PREFIX}chat.to_callsign"),
            AttributeValue::Str(chat.to_callsign.clone()),
        );
    }
}

/// Encode an [`Entity`] into a [`TakPacket`].
///
/// Position-bearing entities map to a `Pli` payload, chat-bearing
/// entities (recognised by the presence of a
/// `meshtastic.chat.message` attribute or the absence of a position
/// when a callsign-targeted message attribute set is present) map
/// to a `GeoChat` payload, and entities that supply neither
/// surface [`MeshtasticError::UnsupportedEntity`] rather than
/// silently emit an empty frame.
fn entity_to_packet(entity: &Entity) -> Result<TakPacket, MeshtasticError> {
    let mut packet = TakPacket::default();

    // Contact: prefer the explicit callsign field; the
    // device-callsign rides on the attribute bag.
    let device_callsign = attr_str(entity, "contact.device_callsign").unwrap_or_default();
    let callsign = entity.callsign.clone().unwrap_or_default();
    if !callsign.is_empty() || !device_callsign.is_empty() {
        packet.contact = Some(Contact {
            callsign,
            device_callsign,
        });
    }

    // Group: use attribute carries, default to absent.
    let role = attr_int(entity, "group.role")
        .and_then(|v| i32::try_from(v).ok())
        .unwrap_or(0);
    let team = attr_int(entity, "group.team")
        .and_then(|v| i32::try_from(v).ok())
        .unwrap_or(0);
    if role != 0 || team != 0 {
        packet.group = Some(Group { role, team });
    }

    // Status.
    let battery = attr_int(entity, "status.battery")
        .and_then(|v| u32::try_from(v).ok())
        .unwrap_or(0);
    if battery > 0 {
        packet.status = Some(Status { battery });
    }

    // Compressed-payload flag is opaque carry; honour the attribute
    // when present.
    if attr_bool(entity, "is_compressed").unwrap_or(false) {
        packet.is_compressed = true;
    }

    // Payload variant. Position wins when present (PLI is the most
    // common Meshtastic payload by traffic volume); chat wins when
    // a chat message attribute is present without a position;
    // otherwise the entity has no Meshtastic wire form.
    if let Some(position) = entity.position {
        let pli = build_pli(entity, position);
        packet.payload_variant = Some(PayloadVariant::Pli(pli));
    } else if let Some(message) = attr_str(entity, "chat.message") {
        let chat = GeoChat {
            message,
            to: attr_str(entity, "chat.to").unwrap_or_default(),
            to_callsign: attr_str(entity, "chat.to_callsign").unwrap_or_default(),
        };
        packet.payload_variant = Some(PayloadVariant::Chat(chat));
    } else {
        return Err(MeshtasticError::UnsupportedEntity(format!(
            "entity `{}` has no Meshtastic-mappable payload (need Position or chat.message attribute)",
            entity.uid
        )));
    }

    Ok(packet)
}

/// Build a [`Pli`] from an [`Entity`]'s [`Position`] and (optional)
/// [`Velocity`], preferring same-codec attribute-bag carries when
/// they are present so a round-trip preserves the exact wire bytes.
fn build_pli(entity: &Entity, position: Position) -> Pli {
    // Prefer the raw scaled-integer carry from the attribute bag
    // when present — that is the only way to round-trip the wire
    // bytes byte-exact.
    let lat_attr = attr_int(entity, "pli.latitude_i").and_then(|v| i32::try_from(v).ok());
    let lon_attr = attr_int(entity, "pli.longitude_i").and_then(|v| i32::try_from(v).ok());
    let alt_attr = attr_int(entity, "pli.altitude").and_then(|v| i32::try_from(v).ok());
    let speed_attr = attr_int(entity, "pli.speed_cm_s").and_then(|v| u32::try_from(v).ok());
    let course_attr = attr_int(entity, "pli.course_centideg").and_then(|v| u32::try_from(v).ok());

    if let (Some(lat), Some(lon)) = (lat_attr, lon_attr) {
        return Pli {
            latitude_i: lat,
            longitude_i: lon,
            altitude: alt_attr
                .unwrap_or_else(|| position.hae_meters.map(clamp_to_i32).unwrap_or_default()),
            speed: speed_attr.unwrap_or_else(|| {
                entity
                    .velocity
                    .map(|v| clamp_to_u32(v.speed_m_s * SPEED_SCALE_CM_PER_S))
                    .unwrap_or(0)
            }),
            course: course_attr.unwrap_or_else(|| {
                entity
                    .velocity
                    .map(|v| {
                        let normalised = v.course_deg.rem_euclid(360.0);
                        clamp_to_u32(normalised * COURSE_SCALE_HUNDREDTHS_DEG)
                    })
                    .unwrap_or(0)
            }),
        };
    }

    let altitude =
        alt_attr.unwrap_or_else(|| position.hae_meters.map(clamp_to_i32).unwrap_or_default());
    let speed = speed_attr.unwrap_or_else(|| {
        entity
            .velocity
            .map(|v| clamp_to_u32(v.speed_m_s * SPEED_SCALE_CM_PER_S))
            .unwrap_or(0)
    });
    let course = course_attr.unwrap_or_else(|| {
        entity
            .velocity
            .map(|v| {
                let normalised = v.course_deg.rem_euclid(360.0);
                clamp_to_u32(normalised * COURSE_SCALE_HUNDREDTHS_DEG)
            })
            .unwrap_or(0)
    });

    Pli {
        latitude_i: clamp_to_i32(position.lat * COORD_SCALE),
        longitude_i: clamp_to_i32(position.lon * COORD_SCALE),
        altitude,
        speed,
        course,
    }
}

fn attr_str(entity: &Entity, key: &str) -> Option<String> {
    match entity.attributes.get(&format!("{MESHTASTIC_PREFIX}{key}")) {
        Some(AttributeValue::Str(v)) => Some(v.clone()),
        _ => None,
    }
}

fn attr_int(entity: &Entity, key: &str) -> Option<i64> {
    match entity.attributes.get(&format!("{MESHTASTIC_PREFIX}{key}")) {
        Some(AttributeValue::Int(v)) => Some(*v),
        _ => None,
    }
}

fn attr_bool(entity: &Entity, key: &str) -> Option<bool> {
    match entity.attributes.get(&format!("{MESHTASTIC_PREFIX}{key}")) {
        Some(AttributeValue::Bool(v)) => Some(*v),
        _ => None,
    }
}

fn clamp_to_i32(v: f64) -> i32 {
    if !v.is_finite() {
        return 0;
    }
    let r = v.round();
    if r >= f64::from(i32::MAX) {
        return i32::MAX;
    }
    if r <= f64::from(i32::MIN) {
        return i32::MIN;
    }
    r as i32
}

fn clamp_to_u32(v: f64) -> u32 {
    if !v.is_finite() || v <= 0.0 {
        return 0;
    }
    let r = v.round();
    if r >= f64::from(u32::MAX) {
        return u32::MAX;
    }
    r as u32
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::float_cmp, unused_results)]
mod tests {
    use super::*;
    use crate::MAX_PAYLOAD_BYTES;

    fn pli_entity() -> Entity {
        Entity {
            uid: "meshtastic-!a1b2c3d4".into(),
            kind: EntityKind::Ground,
            position: Some(Position {
                lat: 38.889_722_2,
                lon: -77.008_889,
                hae_meters: Some(50.0),
            }),
            velocity: Some(Velocity {
                speed_m_s: 5.0,
                course_deg: 90.0,
            }),
            timestamp: SystemTime::UNIX_EPOCH,
            callsign: Some("Bravo-1".into()),
            mil_std_2525_sidc: None,
            attributes: {
                let mut m: BTreeMap<String, AttributeValue> = BTreeMap::new();
                let _ = m.insert(
                    format!("{MESHTASTIC_PREFIX}contact.device_callsign"),
                    AttributeValue::Str("!a1b2c3d4".into()),
                );
                m
            },
        }
    }

    #[test]
    fn entity_round_trips_through_meshtastic_codec() {
        let codec = MeshtasticCodec;
        let original = pli_entity();
        let bytes = codec.from_entity(&original).expect("encode");
        assert!(
            bytes.len() <= MAX_PAYLOAD_BYTES,
            "encoded {} > cap {MAX_PAYLOAD_BYTES}",
            bytes.len()
        );
        let decoded = codec.to_entity(&bytes).expect("decode");

        assert_eq!(decoded.uid, original.uid);
        assert_eq!(decoded.callsign, original.callsign);
        let p1 = original.position.expect("p1");
        let p2 = decoded.position.expect("p2");
        // sfixed32 LSB ≈ 1e-7 deg.
        assert!((p1.lat - p2.lat).abs() < 1e-6);
        assert!((p1.lon - p2.lon).abs() < 1e-6);
    }

    #[test]
    fn entity_without_position_or_chat_returns_unsupported() {
        let codec = MeshtasticCodec;
        let entity = Entity {
            uid: "anonymous".into(),
            kind: EntityKind::Track,
            position: None,
            velocity: None,
            timestamp: SystemTime::UNIX_EPOCH,
            callsign: None,
            mil_std_2525_sidc: None,
            attributes: BTreeMap::new(),
        };
        let err = codec.from_entity(&entity).expect_err("must fail");
        assert!(matches!(err, MeshtasticError::UnsupportedEntity(_)));
    }

    #[test]
    fn chat_only_entity_encodes_to_geochat_payload() {
        let codec = MeshtasticCodec;
        let mut attrs: BTreeMap<String, AttributeValue> = BTreeMap::new();
        let _ = attrs.insert(
            format!("{MESHTASTIC_PREFIX}chat.message"),
            AttributeValue::Str("rendezvous at 1730".into()),
        );
        let _ = attrs.insert(
            format!("{MESHTASTIC_PREFIX}chat.to_callsign"),
            AttributeValue::Str("Charlie-2".into()),
        );
        let entity = Entity {
            uid: "meshtastic-!feedface".into(),
            kind: EntityKind::Track,
            position: None,
            velocity: None,
            timestamp: SystemTime::UNIX_EPOCH,
            callsign: Some("Bravo-1".into()),
            mil_std_2525_sidc: None,
            attributes: attrs,
        };
        let bytes = codec.from_entity(&entity).expect("encode chat");
        let decoded = codec.to_entity(&bytes).expect("decode chat");
        assert_eq!(decoded.kind, EntityKind::Track);
        let recovered = decoded
            .attributes
            .get(&format!("{MESHTASTIC_PREFIX}chat.message"))
            .expect("message attr");
        match recovered {
            AttributeValue::Str(s) => assert_eq!(s, "rendezvous at 1730"),
            other => panic!("unexpected attr variant: {other:?}"),
        }
    }

    #[test]
    fn pli_payload_classifies_entity_as_ground() {
        let codec = MeshtasticCodec;
        let bytes = codec.from_entity(&pli_entity()).expect("encode");
        let decoded = codec.to_entity(&bytes).expect("decode");
        assert_eq!(decoded.kind, EntityKind::Ground);
    }

    #[test]
    fn truncated_payload_returns_typed_error() {
        let codec = MeshtasticCodec;
        // Single byte `0x0A` declares a length-delimited field
        // (tag for field 1) but no length byte follows.
        let err = codec.to_entity(&[0x0A]).expect_err("must fail");
        assert!(matches!(
            err,
            MeshtasticError::TruncatedVarint | MeshtasticError::Truncated
        ));
    }

    #[test]
    fn over_cap_payload_returns_typed_error() {
        let codec = MeshtasticCodec;
        let oversized = vec![0u8; MAX_PAYLOAD_BYTES + 1];
        let err = codec.to_entity(&oversized).expect_err("must fail");
        assert!(matches!(err, MeshtasticError::PayloadTooLarge { .. }));
    }
}
