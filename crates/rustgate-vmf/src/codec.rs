// Copyright © 2026 Roberto Chiofalo.

//! [`EntityCodec`] implementation for VMF — refs #847, closes #868.
//!
//! [`VmfCodec`] decodes VMF wire frames into the protocol-agnostic
//! `Entity` shape defined by `rustgate-core` and re-encodes a position
//! -bearing `Entity` back into a K05.1 Position Report on the wire.
//! Today only K05.1 is bidirectional — every other K-series message
//! decodes its header and surfaces the body bytes via the
//! `VmfMessage::Unknown` variant; encoding for non-K05.1 returns
//! [`VmfError::Unsupported`].
//!
//! # Mapping summary
//!
//! Inbound (K05.1 datagram → `Entity`):
//!
//! | VMF source                            | `Entity` field                                          |
//! |---------------------------------------|---------------------------------------------------------|
//! | K05.1 reporting URN                   | `Entity.uid` (`"vmf-{urn:08x}"`)                        |
//! | K05.1 latitude / longitude            | `Entity.position.lat` / `lon`                           |
//! | K05.1 altitude (when present)         | `Entity.position.hae_meters` (best-effort, see below)   |
//! | K05.1 speed / course                  | `Entity.velocity` (speed_m_s, course_deg)               |
//! | K05.1 unit identifier                 | `Entity.callsign`                                       |
//! | Header URN, classification, DTG,      | `Entity.attributes` under the `"vmf."` namespace        |
//! | message ID                            |                                                         |
//!
//! Outbound (`Entity` → K05.1 datagram) is intentionally narrower:
//! only `Position`-bearing entities encode into a K05.1 frame
//! carrying the strict required subset (URN + lat/lon) plus optional
//! altitude/speed/course/identifier when those carry values are
//! present. Entities without a position surface
//! [`VmfEntityError::UnsupportedEntityKind`] — VMF is a kinematic
//! tactical messaging protocol and the workspace's CoT codec retains
//! the general-purpose role.
//!
//! # Round-trip discipline
//!
//! Same-codec round-trip is preserved for the position-bearing
//! subset: `to_entity(frame)` followed by `from_entity(entity)`
//! produces a frame whose decoded position matches the input to the
//! resolution of the wire encoding (≈ 5.4 × 10⁻⁶ deg latitude). The
//! frame is **not** byte-identical because the encoder always emits
//! a fresh DTG of `None` (the codec does not invent one) and the
//! header-size byte is back-patched only when the future encoder
//! finalises the layout.
//!
//! # Out of scope
//!
//! - **Other K-series messages.** K01.x (General C2), K02.x
//!   (Intelligence), K04.x (Land Combat Operations), K06.x (Fire
//!   Support), K00.x (Free Text) are recognised by the header's
//!   message-id field and surface as
//!   [`VmfMessage::Unknown`] on decode; their encode direction
//!   surfaces [`VmfError::Unsupported`]. Subsequent PRs against #868
//!   land them as siblings under the same trait impl.
//! - **UDP listener wiring.** A real K05.1 feed lives on UDP port
//!   1581 (declared by [`crate::VMF_DEFAULT_UDP_PORT`]) but binding
//!   the socket and feeding the codec is the next PR — this crate
//!   is a pure decode/encode library with no I/O.
//! - **MIL-STD-2525 SIDC dispatch.** VMF unit identifiers are
//!   free-form ASCII; deriving a SIDC requires the deployment's
//!   unit catalogue and lives in the integration layer (issue
//!   #847).

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use rustgate_core::entity::{AttributeValue, Entity, EntityCodec, EntityKind, Position, Velocity};

use crate::bitstream::{BitReader, BitWriter};
use crate::error::VmfError;
use crate::header::{Classification, Dtg, MessageId, VmfHeader};
use crate::k05_1::K051PositionReport;

/// Attribute-key prefix used for every VMF-derived attribute. Mirrors
/// the `asterix.` / `mavlink.` prefixes elsewhere in the workspace.
pub const VMF_PREFIX: &str = "vmf.";

/// Decoded VMF message variant returned by [`decode_message`]. Only
/// K05.1 is currently typed; every other message surfaces as
/// [`VmfMessage::Unknown`] with the residual body bytes intact for a
/// future-PR upgrade path.
#[derive(Debug, Clone, PartialEq)]
pub enum VmfMessage {
    /// K05.1 Position Report (Position Location Information).
    K05_1(K051PositionReport),
    /// Any other K-series message. The header has been decoded; the
    /// body remains as opaque bytes for forward-compatible storage.
    /// `message_type` is the packed identifier from
    /// [`MessageId::as_u16`] so a session-layer log can pin which
    /// K-series flavour the unknown was without re-walking the
    /// header.
    Unknown {
        /// Packed K-series identifier (see [`MessageId::as_u16`]).
        /// `0` when the header omitted the message-id FPI.
        message_type: u16,
        /// Body bytes captured verbatim from the wire (unaligned
        /// suffix is dropped on the bit-to-byte boundary).
        body: Bytes,
    },
}

/// Errors surfaced by [`VmfCodec::to_entity`] / [`VmfCodec::from_entity`].
#[derive(Debug, thiserror::Error)]
pub enum VmfEntityError {
    /// The wire-format payload failed to parse.
    #[error("malformed VMF frame: {0}")]
    Decode(#[from] VmfError),
    /// The supplied [`Entity`] cannot be expressed as a K05.1 wire
    /// frame (no position, missing required fields).
    #[error("Entity cannot be mapped to VMF: {0}")]
    UnsupportedEntityKind(String),
}

/// VMF wire-format codec for the canonical [`Entity`] shape.
///
/// Stateless — the same instance is safe to reuse across every routed
/// message on every thread. The router holds an `Arc<VmfCodec>` per
/// protocol slot.
#[derive(Debug, Default, Clone, Copy)]
pub struct VmfCodec;

impl EntityCodec for VmfCodec {
    type Error = VmfEntityError;

    fn to_entity(&self, payload: &[u8]) -> Result<Entity, Self::Error> {
        let (header, message) = decode_message(payload)?;
        match message {
            VmfMessage::K05_1(body) => Ok(k05_1_to_entity(&header, &body)),
            VmfMessage::Unknown { message_type, .. } => Err(VmfEntityError::UnsupportedEntityKind(
                format!("VMF message type 0x{message_type:04X} not yet mapped to Entity"),
            )),
        }
    }

    fn from_entity(&self, entity: &Entity) -> Result<Bytes, Self::Error> {
        encode_k05_1_from_entity(entity)
    }
}

/// Decode the next VMF frame. Returns the header plus the typed body
/// (or [`VmfMessage::Unknown`] for non-MVP message types).
pub fn decode_message(payload: &[u8]) -> Result<(VmfHeader, VmfMessage), VmfError> {
    let mut reader = BitReader::new(payload);
    let header = VmfHeader::decode(&mut reader)?;
    let dispatch = header.message_id.unwrap_or(MessageId {
        fad: 0,
        msg_num: 0,
        subnumber: 0,
    });
    if dispatch.is_k05_1() {
        let body = K051PositionReport::decode(&mut reader)?;
        return Ok((header, VmfMessage::K05_1(body)));
    }
    // Capture remaining bytes (byte-aligned). The bit cursor may sit
    // mid-byte if the header used a non-multiple-of-8 layout; we round
    // up the cursor to the next byte boundary so the captured body
    // stays a clean byte slice for forward-compatible passthrough.
    let bit_pos = reader.position_bits();
    let byte_pos = bit_pos.div_ceil(8);
    let body = payload.get(byte_pos..).unwrap_or(&[]);
    Ok((
        header,
        VmfMessage::Unknown {
            message_type: dispatch.as_u16(),
            body: Bytes::copy_from_slice(body),
        },
    ))
}

/// Encode a header + K05.1 body pair into a wire frame.
pub fn encode_k05_1(header: &VmfHeader, body: &K051PositionReport) -> Result<Bytes, VmfError> {
    if let Some(id) = header.message_id
        && !id.is_k05_1()
    {
        return Err(VmfError::Unsupported {
            message_type: id.as_u16(),
        });
    }
    let mut writer = BitWriter::with_capacity(64);
    header.encode(&mut writer)?;
    body.encode(&mut writer)?;
    Ok(Bytes::from(writer.into_bytes()))
}

/// Build an [`Entity`] from a decoded K05.1 frame.
fn k05_1_to_entity(header: &VmfHeader, body: &K051PositionReport) -> Entity {
    let uid = format!("vmf-{:08x}", body.reporting_urn);
    let position = Some(Position {
        lat: body.latitude_deg,
        lon: body.longitude_deg,
        hae_meters: body.altitude_m.map(f64::from),
    });
    let velocity = match (body.speed_m_per_s, body.course_deg) {
        (Some(speed), Some(course)) => Some(Velocity {
            speed_m_s: speed,
            course_deg: course,
        }),
        _ => None,
    };
    let timestamp = header
        .dtg
        .map(dtg_to_systemtime)
        .unwrap_or_else(SystemTime::now);
    let kind = classify_kind(body);

    let mut attributes: BTreeMap<String, AttributeValue> = BTreeMap::new();
    populate_attributes(&mut attributes, header, body);

    Entity {
        uid,
        kind,
        position,
        velocity,
        timestamp,
        callsign: body.unit_identifier.clone(),
        mil_std_2525_sidc: None,
        attributes,
    }
}

/// Encode a position-bearing [`Entity`] as a K05.1 wire frame.
fn encode_k05_1_from_entity(entity: &Entity) -> Result<Bytes, VmfEntityError> {
    let position = entity
        .position
        .ok_or_else(|| VmfEntityError::UnsupportedEntityKind("entity has no Position".into()))?;
    let reporting_urn = parse_uid(&entity.uid)
        .or_else(|| attr_int(entity, "reporting_urn").and_then(|v| u32::try_from(v).ok()))
        .ok_or_else(|| {
            VmfEntityError::UnsupportedEntityKind(format!(
                "entity uid `{}` does not match `vmf-<8 hex chars>`",
                entity.uid
            ))
        })?;
    let originator_urn = attr_int(entity, "originator_urn")
        .and_then(|v| u32::try_from(v).ok())
        .unwrap_or(reporting_urn);

    let altitude_m = position
        .hae_meters
        .map(|m| m.round())
        .filter(|m| m.is_finite() && (-32_768.0..=32_767.0).contains(m))
        .map(|m| m as i16);

    let (speed, course) = match entity.velocity {
        Some(v) => (Some(v.speed_m_s), Some(v.course_deg)),
        None => (None, None),
    };

    let body = K051PositionReport {
        reporting_urn,
        latitude_deg: position.lat,
        longitude_deg: position.lon,
        altitude_m,
        speed_m_per_s: speed,
        course_deg: course,
        unit_identifier: entity.callsign.clone(),
    };
    let header = VmfHeader {
        version: crate::header::VMF_HEADER_VERSION,
        originator_urn,
        recipient_urn: attr_int(entity, "recipient_urn").and_then(|v| u32::try_from(v).ok()),
        message_id: Some(MessageId::K05_1),
        classification: attr_int(entity, "classification")
            .and_then(|v| u8::try_from(v).ok())
            .map(Classification::from_raw)
            .unwrap_or(Classification::Unclassified),
        dtg: attr_int(entity, "dtg_posix_seconds")
            .and_then(|v| u64::try_from(v).ok())
            .map(Dtg::from_seconds),
    };

    encode_k05_1(&header, &body).map_err(VmfEntityError::Decode)
}

/// Walk header + body and dump every decoded scalar into the
/// `vmf.*` attribute namespace so a same-codec round-trip recovers
/// the values that are not first-class on `Entity`.
fn populate_attributes(
    attributes: &mut BTreeMap<String, AttributeValue>,
    header: &VmfHeader,
    body: &K051PositionReport,
) {
    let _ = attributes.insert(
        format!("{VMF_PREFIX}originator_urn"),
        AttributeValue::Int(i64::from(header.originator_urn)),
    );
    if let Some(urn) = header.recipient_urn {
        let _ = attributes.insert(
            format!("{VMF_PREFIX}recipient_urn"),
            AttributeValue::Int(i64::from(urn)),
        );
    }
    let _ = attributes.insert(
        format!("{VMF_PREFIX}classification"),
        AttributeValue::Int(i64::from(header.classification.raw())),
    );
    let _ = attributes.insert(
        format!("{VMF_PREFIX}classification_label"),
        AttributeValue::Str(header.classification.as_str().to_string()),
    );
    if let Some(id) = header.message_id {
        let _ = attributes.insert(
            format!("{VMF_PREFIX}message_type"),
            AttributeValue::Int(i64::from(id.as_u16())),
        );
        let _ = attributes.insert(
            format!("{VMF_PREFIX}fad"),
            AttributeValue::Int(i64::from(id.fad)),
        );
        let _ = attributes.insert(
            format!("{VMF_PREFIX}msg_num"),
            AttributeValue::Int(i64::from(id.msg_num)),
        );
        let _ = attributes.insert(
            format!("{VMF_PREFIX}subnumber"),
            AttributeValue::Int(i64::from(id.subnumber)),
        );
    }
    if let Some(dtg) = header.dtg {
        // i64 envelope is sufficient; the wire field is u64 but POSIX
        // seconds will not exceed i64::MAX in any deployment lifetime.
        let _ = attributes.insert(
            format!("{VMF_PREFIX}dtg_posix_seconds"),
            AttributeValue::Int(i64::try_from(dtg.posix_seconds).unwrap_or(i64::MAX)),
        );
        let _ = attributes.insert(
            format!("{VMF_PREFIX}dtg_microseconds"),
            AttributeValue::Int(i64::from(dtg.microseconds)),
        );
    }
    let _ = attributes.insert(
        format!("{VMF_PREFIX}reporting_urn"),
        AttributeValue::Int(i64::from(body.reporting_urn)),
    );
}

/// Coarse `EntityKind` classification for a K05.1 report. K05.1 is a
/// position-bearing PLI, so the dispatch favours `Ground` (the
/// majority of BFT traffic comes from dismounts and vehicles) and
/// flips to `Aircraft` when the altitude carry indicates flight.
fn classify_kind(body: &K051PositionReport) -> EntityKind {
    match body.altitude_m {
        // Above 1500 m MSL → almost certainly an air platform; this
        // matches the open-literature heuristic the BFT/JCR clients
        // use for icon dispatch when the wire format does not carry
        // a unit-type field.
        Some(alt) if alt > 1500 => EntityKind::Aircraft,
        _ => EntityKind::Ground,
    }
}

/// Recover the reporting URN from a `vmf-<8 hex>` UID. Returns `None`
/// for any UID that does not match the canonical shape.
fn parse_uid(uid: &str) -> Option<u32> {
    let rest = uid.strip_prefix("vmf-")?;
    if rest.len() != 8 {
        return None;
    }
    u32::from_str_radix(rest, 16).ok()
}

/// Look up an integer attribute under the `vmf.<key>` namespace.
fn attr_int(entity: &Entity, key: &str) -> Option<i64> {
    match entity.attributes.get(&format!("{VMF_PREFIX}{key}")) {
        Some(AttributeValue::Int(v)) => Some(*v),
        _ => None,
    }
}

/// Convert a wire-format DTG into a [`SystemTime`].
fn dtg_to_systemtime(dtg: Dtg) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(dtg.posix_seconds))
        .and_then(|t| t.checked_add(Duration::from_micros(u64::from(dtg.microseconds))))
        .unwrap_or(SystemTime::UNIX_EPOCH)
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::header::Classification;

    #[test]
    fn k05_1_round_trips_through_codec() {
        let codec = VmfCodec;
        let header = VmfHeader {
            version: crate::header::VMF_HEADER_VERSION,
            originator_urn: 0x12_3456,
            recipient_urn: None,
            message_id: Some(MessageId::K05_1),
            classification: Classification::Unclassified,
            dtg: Some(Dtg {
                posix_seconds: 1_700_000_000,
                microseconds: 0,
            }),
        };
        let body = K051PositionReport {
            reporting_urn: 0x12_3456,
            latitude_deg: 38.5,
            longitude_deg: -77.0,
            altitude_m: Some(100),
            speed_m_per_s: Some(5.0),
            course_deg: Some(45.0),
            unit_identifier: Some("ALPHA1".into()),
        };
        let bytes = encode_k05_1(&header, &body).unwrap();

        let entity = codec.to_entity(&bytes).unwrap();
        assert_eq!(entity.uid, "vmf-00123456");
        assert_eq!(entity.callsign.as_deref(), Some("ALPHA1"));
        let p = entity.position.unwrap();
        assert!((p.lat - 38.5).abs() < 1e-4);
        assert!((p.lon + 77.0).abs() < 1e-4);
        let v = entity.velocity.unwrap();
        assert!((v.speed_m_s - 5.0).abs() < 0.1);
        assert!((v.course_deg - 45.0).abs() < 1.0);

        let bytes2 = codec.from_entity(&entity).unwrap();
        let entity2 = codec.to_entity(&bytes2).unwrap();
        assert_eq!(entity.uid, entity2.uid);
        let p2 = entity2.position.unwrap();
        assert!((p.lat - p2.lat).abs() < 1e-4);
        assert!((p.lon - p2.lon).abs() < 1e-4);
    }

    #[test]
    fn unknown_message_type_decodes_header_only() {
        // Build a header for a non-K05.1 message (e.g. K01.1 General C2).
        let header = VmfHeader {
            version: crate::header::VMF_HEADER_VERSION,
            originator_urn: 0x42,
            recipient_urn: None,
            message_id: Some(MessageId {
                fad: 0,
                msg_num: 1,
                subnumber: 1,
            }),
            classification: Classification::Unclassified,
            dtg: None,
        };
        let mut w = BitWriter::new();
        header.encode(&mut w).unwrap();
        // Append a 5-byte free-form body to round-trip.
        w.write_bytes(&[0xDE, 0xAD, 0xBE, 0xEF, 0x42]);
        let bytes = w.into_bytes();
        let (decoded_header, message) = decode_message(&bytes).unwrap();
        assert_eq!(decoded_header.originator_urn, 0x42);
        match message {
            VmfMessage::Unknown { message_type, body } => {
                assert_ne!(message_type, MessageId::K05_1.as_u16());
                // Body bytes captured (post header alignment).
                assert!(!body.is_empty());
            }
            other => panic!("expected Unknown, got {other:?}"),
        }
    }

    #[test]
    fn entity_with_no_position_returns_unsupported() {
        let codec = VmfCodec;
        let entity = Entity {
            uid: "vmf-00000001".into(),
            kind: EntityKind::Unknown("text-only".into()),
            position: None,
            velocity: None,
            timestamp: SystemTime::UNIX_EPOCH,
            callsign: None,
            mil_std_2525_sidc: None,
            attributes: BTreeMap::new(),
        };
        let err = codec.from_entity(&entity).unwrap_err();
        assert!(matches!(err, VmfEntityError::UnsupportedEntityKind(_)));
    }

    #[test]
    fn entity_with_unrecognised_uid_returns_unsupported() {
        let codec = VmfCodec;
        let entity = Entity {
            uid: "cot-some-event".into(),
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
        let err = codec.from_entity(&entity).unwrap_err();
        assert!(matches!(err, VmfEntityError::UnsupportedEntityKind(_)));
    }

    #[test]
    fn entity_classifies_high_altitude_as_aircraft() {
        let codec = VmfCodec;
        let header = VmfHeader::new_k05_1(0x10);
        let body = K051PositionReport {
            reporting_urn: 0x10,
            latitude_deg: 38.0,
            longitude_deg: -77.0,
            altitude_m: Some(3000),
            speed_m_per_s: None,
            course_deg: None,
            unit_identifier: None,
        };
        let bytes = encode_k05_1(&header, &body).unwrap();
        let entity = codec.to_entity(&bytes).unwrap();
        assert_eq!(entity.kind, EntityKind::Aircraft);
    }

    #[test]
    fn entity_classifies_ground_default() {
        let codec = VmfCodec;
        let header = VmfHeader::new_k05_1(0x10);
        let body = K051PositionReport::new(0x10, 38.0, -77.0);
        let bytes = encode_k05_1(&header, &body).unwrap();
        let entity = codec.to_entity(&bytes).unwrap();
        assert_eq!(entity.kind, EntityKind::Ground);
    }

    #[test]
    fn unmapped_fields_appear_in_attributes() {
        let codec = VmfCodec;
        let header = VmfHeader {
            version: crate::header::VMF_HEADER_VERSION,
            originator_urn: 0xAA_BBCC,
            recipient_urn: Some(0x11_2233),
            message_id: Some(MessageId::K05_1),
            classification: Classification::Secret,
            dtg: Some(Dtg {
                posix_seconds: 1_700_000_000,
                microseconds: 250_000,
            }),
        };
        let body = K051PositionReport::new(0x12_3456, 38.5, -77.0);
        let bytes = encode_k05_1(&header, &body).unwrap();
        let entity = codec.to_entity(&bytes).unwrap();
        assert_eq!(
            entity
                .attributes
                .get(&format!("{VMF_PREFIX}originator_urn")),
            Some(&AttributeValue::Int(0xAA_BBCC))
        );
        assert_eq!(
            entity.attributes.get(&format!("{VMF_PREFIX}recipient_urn")),
            Some(&AttributeValue::Int(0x11_2233))
        );
        assert_eq!(
            entity
                .attributes
                .get(&format!("{VMF_PREFIX}classification_label")),
            Some(&AttributeValue::Str("secret".into()))
        );
        assert_eq!(
            entity
                .attributes
                .get(&format!("{VMF_PREFIX}dtg_posix_seconds")),
            Some(&AttributeValue::Int(1_700_000_000))
        );
        assert_eq!(
            entity
                .attributes
                .get(&format!("{VMF_PREFIX}dtg_microseconds")),
            Some(&AttributeValue::Int(250_000))
        );
    }

    #[test]
    fn truncated_frame_returns_typed_error() {
        let codec = VmfCodec;
        // Single byte cannot even cover the version + compression FPI.
        let bytes = [0x10u8];
        let err = codec.to_entity(&bytes).unwrap_err();
        assert!(matches!(
            err,
            VmfEntityError::Decode(VmfError::Truncated { .. })
        ));
    }
}
