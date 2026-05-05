// Copyright © 2026 Roberto Chiofalo.

//! Protocol-agnostic canonical entity representation — refs #847.
//!
//! `Entity` is the lingua franca between the workspace's protocol-specific
//! codecs (CoT XML, MAVLink, ASTERIX, STANAG-4586, Link 16, …). Every
//! protocol the router speaks decodes inbound messages into an `Entity`
//! and re-encodes outbound `Entity` values back into its native wire
//! format. The router itself, the position cache, dedup, ACL, and authz
//! layers can then operate on a single normalized shape rather than
//! dispatching on protocol-specific payload types.
//!
//! # Scope of this deliverable
//!
//! This module ships **only** the `Entity` value type, its supporting
//! enums (`EntityKind`, `Position`, `Velocity`, `AttributeValue`), and
//! the [`EntityCodec`] trait that protocol crates implement. The CoT
//! [`EntityCodec`] implementation lives in `rustgate-cot::entity`. The
//! MAVLink, ASTERIX, STANAG-4586, and federation/router integrations
//! tracked under #847 ship in subsequent PRs — this is the foundational
//! scaffold every future codec converges on.
//!
//! # Wire format and serde
//!
//! `Entity` derives `Serialize` / `Deserialize` directly so the canonical
//! form serialises to JSON, MsgPack, bincode, etc. without an
//! intermediate representation. The protobuf wire shape (for the
//! `rustgate-proto` crate) is intentionally deferred to a follow-up:
//! v1 is purely an in-memory Rust value backed by `serde` for tests
//! and snapshot persistence.
//!
//! # Backward compatibility
//!
//! `Entity` is a *new* abstraction — it does not replace
//! [`crate::message::RoutableMessage`] or any existing wire-format
//! type. The router continues to carry `payload: Bytes` today; future
//! work will optionally attach an `Entity` alongside `payload` so the
//! workspace can migrate codec by codec without a breaking flag day.

use std::collections::BTreeMap;
use std::time::SystemTime;

use bytes::Bytes;
use serde::{Deserialize, Serialize};

/// Canonical, protocol-agnostic representation of a tracked entity.
///
/// Every protocol crate decodes its native wire format into one of
/// these and re-encodes from one of these. Fields are deliberately a
/// strict subset of the union of CoT, MAVLink, ASTERIX, STANAG-4586,
/// and Link 16 — anything that does not fit the strict subset goes
/// into [`Entity::attributes`] under a protocol-specific key so a
/// future round-trip can recover it. The strict-subset choice is what
/// lets the router, position cache, dedup, ACL, and authz layers
/// operate on a single shape regardless of inbound protocol.
///
/// # Round-trip discipline
///
/// A codec MUST preserve enough information in [`Entity::attributes`]
/// to round-trip its own format losslessly when [`EntityCodec::from_entity`]
/// runs against the result of [`EntityCodec::to_entity`]. Attributes
/// from a different codec are tolerated but not required to round-trip
/// — `EntityCodec::from_entity` is allowed to drop attributes it does
/// not understand. This keeps the cross-protocol fan-out cheap (no
/// universal lossless wire format) while preserving same-protocol
/// fidelity.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Entity {
    /// Stable identifier for this entity within its source protocol.
    ///
    /// For CoT this is the `<event uid="…">` attribute; for MAVLink
    /// it is typically the `system_id`/`component_id` tuple stringified;
    /// for ASTERIX it is the track number. Codecs that lack a native
    /// stable identifier (e.g. fire-and-forget telemetry frames) may
    /// synthesize one — but then they cannot meaningfully round-trip.
    pub uid: String,

    /// Coarse type classification used for dispatch and dashboards.
    ///
    /// Fine-grained protocol-specific types (e.g. the full CoT
    /// `a-f-G-U-C` string or the MIL-STD-2525 SIDC) are preserved on
    /// [`Entity::attributes`] and on [`Entity::mil_std_2525_sidc`]
    /// rather than encoded into this enum so the variant set stays
    /// stable across releases.
    pub kind: EntityKind,

    /// Geographic position in WGS-84 decimal degrees with optional
    /// height-above-ellipsoid in metres. `None` for entities whose
    /// source frame did not carry a position (e.g. a chat message
    /// that happens to ride on the same envelope).
    pub position: Option<Position>,

    /// Linear motion vector. `None` when the source frame did not
    /// carry kinematics. Speed is metres-per-second; course is
    /// degrees clockwise from true north `[0, 360)`.
    pub velocity: Option<Velocity>,

    /// When the source frame was captured. Codecs MAY override this
    /// with the wire-format timestamp (CoT `<event time>`, MAVLink
    /// `time_boot_ms` resolved against a clock anchor) or fall back
    /// to `SystemTime::now()` when the wire format does not carry
    /// one. The router treats this field as authoritative for
    /// position-cache TTL decisions.
    pub timestamp: SystemTime,

    /// Human-readable callsign or label, when the wire format
    /// carries one. CoT populates this from
    /// `<contact callsign="…"/>`; MAVLink leaves it `None`.
    pub callsign: Option<String>,

    /// MIL-STD-2525C / 2525D Symbol Identification Code (SIDC) for
    /// downstream symbol rendering. The 15-character form is the
    /// 2525C representation; some codecs emit the 20- or 30-character
    /// 2525D extension — both are stored verbatim and the consumer
    /// is responsible for length-based dispatch.
    pub mil_std_2525_sidc: Option<String>,

    /// Free-form per-codec attribute bag. Used both for protocol
    /// extensions that do not fit the strict-subset fields above and
    /// for round-trip preservation of fields a future version of the
    /// `Entity` shape may adopt as first-class. Keys are
    /// codec-specific (e.g. `"cot.event_type"`, `"cot.how"`,
    /// `"mavlink.system_id"`) — codecs MUST namespace their keys to
    /// avoid collisions in a multi-codec ingestion path.
    pub attributes: BTreeMap<String, AttributeValue>,
}

/// Coarse entity classification used for routing and dashboards.
///
/// The variant set is deliberately narrow. Anything that does not fit
/// is encoded as [`EntityKind::Unknown`] with a free-form label so the
/// classifier on the router can still group on the label without
/// requiring a new enum variant per protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum EntityKind {
    /// Generic track without a more specific classification.
    Track,
    /// Sensor reading (radar return, IR detection, …).
    Sensor,
    /// Air platform.
    Aircraft,
    /// Ground platform (vehicle, dismount, fixed installation).
    Ground,
    /// Surface or sub-surface marine platform.
    Marine,
    /// Munition (missile, projectile, ordnance).
    Munition,
    /// Anything that does not fit the variants above. The label is
    /// codec-specific and is preserved verbatim so dashboards can
    /// group on it without a new enum variant per protocol.
    Unknown(String),
}

/// Geographic position in WGS-84 decimal degrees.
///
/// `lat` is in `[-90, 90]`; `lon` is in `[-180, 180]`. The codec is
/// responsible for validating these ranges before constructing the
/// `Position` — the type itself does not validate on construction so
/// the `EntityCodec::from_entity` round-trip never fails on a value
/// that was produced by a (validated) `to_entity` call.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Position {
    /// Latitude in WGS-84 decimal degrees, `[-90, 90]`.
    pub lat: f64,
    /// Longitude in WGS-84 decimal degrees, `[-180, 180]`.
    pub lon: f64,
    /// Height above WGS-84 ellipsoid in metres, when the source
    /// frame carries one. Codecs that distinguish HAE from
    /// mean-sea-level altitude convert to HAE on decode (or drop
    /// the value if no conversion is possible).
    pub hae_meters: Option<f64>,
}

/// Linear motion vector in SI units.
///
/// `course_deg` is degrees clockwise from true north in `[0, 360)`.
/// `speed_m_s` is metres per second and is non-negative; codecs that
/// emit signed range-rates split direction onto `course_deg` and
/// keep `speed_m_s` unsigned.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Velocity {
    /// Ground speed in metres per second, non-negative.
    pub speed_m_s: f64,
    /// Course over ground in degrees clockwise from true north,
    /// `[0, 360)`.
    pub course_deg: f64,
}

/// Free-form attribute value attached to an [`Entity`].
///
/// The variant set covers the four scalar shapes that every codec on
/// the workspace's roadmap emits today; richer structured shapes
/// (nested maps, arrays of structs) are out of scope for v1 — codecs
/// that need them flatten their data into multiple
/// `AttributeValue::Str` entries with a key prefix (e.g.
/// `"detail.takv.os"` rather than nesting a `takv` map under
/// `"detail"`). The flat-with-prefixes shape keeps the wire form
/// trivial to inspect with `jq` or a dashboard query language.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum AttributeValue {
    /// UTF-8 string value.
    Str(String),
    /// Signed 64-bit integer value.
    Int(i64),
    /// IEEE-754 double-precision float value.
    Float(f64),
    /// Boolean value.
    Bool(bool),
}

/// Bidirectional codec between a wire format and the canonical
/// [`Entity`] shape.
///
/// Implementors live in protocol crates: `rustgate-cot` ships the
/// CoT XML implementation today; MAVLink, ASTERIX, STANAG-4586, and
/// Link 16 implementations land in subsequent PRs against the same
/// trait. A codec is stateless by contract — implementors MUST be
/// `Send + Sync` so the router can hold one instance per protocol
/// and reuse it across every routed message without locking.
///
/// # Error handling
///
/// `Self::Error` is intentionally an associated type rather than a
/// shared workspace error so each codec can keep its own typed enum
/// (`rustgate_cot::ParseError`, etc.) without forcing a wrapping
/// boundary. The router crate that consumes this trait holds an
/// `Arc<dyn EntityCodec<Error = …>>` per protocol and maps the
/// codec-specific error into `RustgateError` at the boundary.
pub trait EntityCodec: Send + Sync {
    /// Codec-specific error type returned by [`Self::to_entity`] and
    /// [`Self::from_entity`]. Implementors should already have a
    /// typed `*Error` enum (`thiserror::Error`) for their own parser;
    /// the same enum is the right `Error` here.
    type Error;

    /// Decode a wire-format payload into the canonical [`Entity`].
    ///
    /// Implementors are responsible for validation (range checks on
    /// lat/lon, well-formed UTF-8, attribute-budget limits, …) and
    /// MUST return a typed `Self::Error` rather than panicking on
    /// hostile or malformed input.
    fn to_entity(&self, payload: &[u8]) -> Result<Entity, Self::Error>;

    /// Encode an [`Entity`] into the codec's native wire format.
    ///
    /// Round-trip discipline (see the [`Entity`] doc comment): a
    /// codec MUST preserve same-protocol fidelity when encoding the
    /// result of its own [`Self::to_entity`]. Cross-codec attributes
    /// (e.g. encoding a MAVLink entity through the CoT codec) MAY be
    /// dropped silently — no universal lossless wire format is
    /// promised by this layer.
    // justification: `from_entity` is the directional pair of `to_entity`
    // and reads naturally as the trait's encode arrow; the
    // `wrong_self_convention` lint targets `from_*` constructors that
    // confusingly take `&self`, but here the trait is the encoder and
    // `&self` is required so the codec instance can carry a future
    // configuration handle without a breaking signature change.
    #[allow(clippy::wrong_self_convention)]
    fn from_entity(&self, entity: &Entity) -> Result<Bytes, Self::Error>;
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn entity_roundtrips_through_serde_json() {
        let mut attrs = BTreeMap::new();
        let _ = attrs.insert(
            "cot.event_type".to_string(),
            AttributeValue::Str("a-f-G-U-C".into()),
        );
        let _ = attrs.insert("count".to_string(), AttributeValue::Int(42));
        let _ = attrs.insert("confidence".to_string(), AttributeValue::Float(0.95));
        let _ = attrs.insert("verified".to_string(), AttributeValue::Bool(true));

        let entity = Entity {
            uid: "GOLF-1".into(),
            kind: EntityKind::Ground,
            position: Some(Position {
                lat: 38.0,
                lon: -77.0,
                hae_meters: Some(100.0),
            }),
            velocity: Some(Velocity {
                speed_m_s: 12.0,
                course_deg: 270.0,
            }),
            timestamp: SystemTime::UNIX_EPOCH,
            callsign: Some("alpha".into()),
            mil_std_2525_sidc: Some("SFGPUCI-----".into()),
            attributes: attrs,
        };

        let json = serde_json::to_string(&entity).expect("serialise");
        let decoded: Entity = serde_json::from_str(&json).expect("deserialise");
        assert_eq!(entity, decoded);
    }

    #[test]
    fn entity_kind_unknown_carries_label() {
        let kind = EntityKind::Unknown("custom-protocol-thing".into());
        let json = serde_json::to_string(&kind).expect("serialise");
        let decoded: EntityKind = serde_json::from_str(&json).expect("deserialise");
        assert_eq!(kind, decoded);
    }

    #[test]
    fn position_without_hae_serialises_as_null() {
        let pos = Position {
            lat: 0.0,
            lon: 0.0,
            hae_meters: None,
        };
        let json = serde_json::to_string(&pos).expect("serialise");
        assert!(json.contains("\"hae_meters\":null"));
    }
}
