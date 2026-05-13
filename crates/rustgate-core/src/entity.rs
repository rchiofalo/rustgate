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

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
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

    /// Taskings this entity is involved in. Routing-graph artifact
    /// only — rustgate does not own task state, it just carries
    /// references through the routing pipeline so consumers can
    /// correlate. Additive, `#[serde(default)]`: pre-tasking Entity
    /// values deserialize with an empty vector and any codec that
    /// does not emit taskings sees the same shape on the wire as
    /// before.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub taskings: Vec<Tasking>,

    /// File / media attachments associated with this entity (image,
    /// video clip, document, CoT data-package, …). rustgate stores
    /// only the URI + metadata; the bytes live at whatever sink the
    /// URI points at. Mission-file storage proper is off-mission.
    /// Additive, `#[serde(default)]` — same back-compat shape as
    /// [`Self::taskings`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<FileRef>,
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

impl EntityKind {
    /// Stable lowercase ASCII tag for use as a Prometheus label value.
    ///
    /// The vocabulary is closed: every variant maps to one of
    /// `"aircraft"`, `"ground"`, `"marine"`, `"sensor"`, `"track"`,
    /// `"munition"`, `"unknown"`. The free-form label inside
    /// [`EntityKind::Unknown`] is **not** surfaced here so cardinality
    /// stays bounded — operators wanting the codec-specific label use
    /// the `Entity.attributes` map directly. Closes #847.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Aircraft => "aircraft",
            Self::Ground => "ground",
            Self::Marine => "marine",
            Self::Sensor => "sensor",
            Self::Track => "track",
            Self::Munition => "munition",
            Self::Unknown(_) => "unknown",
        }
    }
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

/// A tasking this entity is involved in.
///
/// rustgate does NOT own mission / tasking state — that's the
/// off-mission concern an upstream C2 platform owns. [`Tasking`]
/// carries a *reference* to an external task so the routing graph
/// can correlate entities to taskings without taking on the
/// state-management burden. The contract is "this entity is involved
/// in task T in state S in role R"; the upstream system that owns
/// task T is responsible for transitions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tasking {
    /// Opaque identifier set by the originating system.
    pub task_id: String,
    /// What state the task is in, as observed from this entity's
    /// perspective.
    pub state: TaskingState,
    /// What role this entity plays in the task.
    pub role: TaskingRole,
    /// Optional human-readable task name / mission code (e.g.
    /// `"OP IRON HAMMER"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// State of a [`Tasking`]. Closed vocabulary; loose progression is
/// `Assigned → Acknowledged → Executing → (Complete | Failed | Cancelled)`,
/// skips permitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum TaskingState {
    /// Task has been issued but not yet acknowledged.
    #[default]
    Assigned,
    /// Assignee has acknowledged the task but not started.
    Acknowledged,
    /// Assignee is actively working on the task.
    Executing,
    /// Task has been completed successfully.
    Complete,
    /// Task could not be completed.
    Failed,
    /// Task has been cancelled before completion.
    Cancelled,
}

impl TaskingState {
    /// Stable lowercase tag for Prometheus labels and `tracing` fields.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Assigned => "assigned",
            Self::Acknowledged => "acknowledged",
            Self::Executing => "executing",
            Self::Complete => "complete",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }
}

/// Role a [`Tasking`] entity plays in its task. Closed vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum TaskingRole {
    /// This entity is the subject the task is acting upon.
    #[default]
    Subject,
    /// This entity has been assigned to execute the task.
    Assignee,
    /// This entity is the target of the task.
    Target,
    /// This entity is reporting on / observing the task.
    Observer,
}

impl TaskingRole {
    /// Stable lowercase tag for Prometheus labels and `tracing` fields.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Subject => "subject",
            Self::Assignee => "assignee",
            Self::Target => "target",
            Self::Observer => "observer",
        }
    }
}

/// Reference to an external file / media artifact attached to an
/// entity.
///
/// rustgate stores ONLY the URI + metadata. The file bytes live at
/// whatever sink the URI points at (HTTPS endpoint, S3 bucket,
/// content-addressed store, on-platform filesystem). Storing the
/// bytes themselves is a state-management concern, and is off-mission
/// for rustgate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileRef {
    /// Where the file lives. Common schemes: `https://...`,
    /// `s3://...`, `content://<algo>/<hex>`, `file://...`.
    pub uri: String,
    /// File size in bytes when known by the producer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
    /// IANA media type (`image/jpeg`, `video/mp4`, …) when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime: Option<String>,
    /// Strong-hash digest for content-addressed retrieval and
    /// integrity verification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash: Option<FileHash>,
    /// Human-readable display label (the file's display name).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

/// Cryptographic digest of a [`FileRef`]'s contents.
///
/// Algorithm + lowercase hex digest. `"sha256"` is the recommended
/// default — every modern object store and TAK client supports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileHash {
    /// Hash algorithm identifier (`"sha256"`, `"sha1"`, …).
    pub algorithm: String,
    /// Lowercase hex digest of the file contents.
    pub hex: String,
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

/// Boxed-error type returned by the object-safe [`DynEntityCodec`]
/// trait. Per-impl `EntityCodec::Error` variants are erased here so a
/// heterogeneous registry (CoT + MAVLink + ASTERIX + STANAG-4586 + …)
/// can be held under a single `dyn` type. The router crate that consumes
/// the registry maps this back into its own typed error at the boundary
/// when needed, but for the dispatch path the loss of typing is an
/// acceptable trade — the router only logs decode failures and falls
/// back to wire-format delivery, so a `Display`-able message is
/// sufficient.
pub type DynEntityCodecError = Box<dyn std::error::Error + Send + Sync>;

/// Object-safe variant of [`EntityCodec`] for heterogeneous registries.
///
/// `EntityCodec::Error` is an associated type to keep per-codec typing
/// (`rustgate_cot::ParseError`, `rustgate_mavlink::MavlinkEntityError`,
/// …) at the codec boundary, but a registry that holds many codecs
/// behind one `dyn` slot needs a single error type. This trait erases
/// the per-impl error into [`DynEntityCodecError`] via a blanket impl
/// (`impl<T: EntityCodec> DynEntityCodec for T`), so callers do not
/// need to write any boxing boilerplate at the codec implementation
/// site.
///
/// Closes #847 — the router consumes
/// `Arc<dyn DynEntityCodec>` per registered `source_protocol` and looks
/// the codec up by string at message-dispatch time.
pub trait DynEntityCodec: Send + Sync {
    /// Object-safe equivalent of [`EntityCodec::to_entity`]. The
    /// per-impl error is boxed into [`DynEntityCodecError`].
    fn to_entity_dyn(&self, payload: &[u8]) -> Result<Entity, DynEntityCodecError>;

    /// Object-safe equivalent of [`EntityCodec::from_entity`]. The
    /// per-impl error is boxed into [`DynEntityCodecError`].
    // justification: directional pair of `to_entity_dyn`. The
    // `wrong_self_convention` lint targets `from_*` constructors that
    // confusingly take `&self`; this is the encode arrow on the codec
    // trait and `&self` is required for object-safety.
    #[allow(clippy::wrong_self_convention)]
    fn from_entity_dyn(&self, entity: &Entity) -> Result<Bytes, DynEntityCodecError>;
}

impl<T> DynEntityCodec for T
where
    T: EntityCodec + Send + Sync,
    T::Error: std::error::Error + Send + Sync + 'static,
{
    fn to_entity_dyn(&self, payload: &[u8]) -> Result<Entity, DynEntityCodecError> {
        self.to_entity(payload).map_err(|e| Box::new(e) as _)
    }

    fn from_entity_dyn(&self, entity: &Entity) -> Result<Bytes, DynEntityCodecError> {
        self.from_entity(entity).map_err(|e| Box::new(e) as _)
    }
}

/// Registry mapping a [`crate::message::Metadata::source_protocol`]
/// string to the [`DynEntityCodec`] that knows how to decode the
/// matching wire format into an [`Entity`].
///
/// The router consumes this at message-dispatch time: when a routed
/// message's `source_protocol` matches a registered key, the codec is
/// invoked best-effort to produce an [`Entity`] surface for audit /
/// metrics / track-correlation hooks. A miss (unknown protocol) or a
/// decode failure is logged at `tracing::debug!` but never blocks
/// delivery of the underlying wire payload — the entity surface is a
/// cross-cutting concern, not a gating one.
///
/// Lookup is `HashMap<String, Arc<dyn …>>` so the hot path is a single
/// hash + clone-Arc and the registry is `Send + Sync` for the
/// `Arc<Router>` shape used across worker threads. There is no
/// per-message lock — the registry is built once at server startup,
/// stored behind `Arc`, and never mutated; a future hot-reload story
/// would wrap it in `ArcSwap` matching the existing `acl` / `authz`
/// patterns. Closes #847.
#[derive(Default)]
pub struct EntityCodecRegistry {
    codecs: HashMap<String, Arc<dyn DynEntityCodec>>,
}

impl std::fmt::Debug for EntityCodecRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Render only the registered keys — the `dyn` codec itself is
        // not Debug, and the keys are the operationally interesting
        // signal anyway (an operator dump shows which protocols have
        // an Entity codec wired and which fall through to wire-format-
        // only routing).
        f.debug_struct("EntityCodecRegistry")
            .field("protocols", &self.codecs.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl EntityCodecRegistry {
    /// Create an empty registry. Use [`Self::register`] to populate.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a codec under the given `source_protocol` string.
    ///
    /// The string is matched verbatim against
    /// [`crate::message::Metadata::source_protocol`] at dispatch time.
    /// Subsequent registrations of the same key replace the previous
    /// codec — the registry is expected to be built once at startup,
    /// so the silent replacement avoids a panicking `expect_unique`
    /// API in cases where the server binary registers duplicate
    /// codecs across feature-flag overlap.
    pub fn register(&mut self, source_protocol: &str, codec: Arc<dyn DynEntityCodec>) {
        let _ = self.codecs.insert(source_protocol.to_string(), codec);
    }

    /// Look up the codec for the given `source_protocol`. Returns
    /// `None` if no codec is registered. The hot path on a registered
    /// hit is a hash lookup plus an `Arc::clone` — no allocation.
    pub fn get(&self, source_protocol: &str) -> Option<Arc<dyn DynEntityCodec>> {
        self.codecs.get(source_protocol).map(Arc::clone)
    }

    /// Return `true` when the registry has no codecs registered. The
    /// router uses this to short-circuit the dispatch-path lookup on
    /// builds where the operator has not opted into entity decoding.
    pub fn is_empty(&self) -> bool {
        self.codecs.is_empty()
    }

    /// Number of codecs currently registered. Surfaced for diagnostics
    /// and tests.
    pub fn len(&self) -> usize {
        self.codecs.len()
    }
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
            taskings: Default::default(),
            files: Default::default(),
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

    #[test]
    fn entity_kind_as_str_pins_closed_label_vocabulary() {
        // Closes #847. The label vocabulary is closed and lowercase
        // ASCII so a Prometheus counter labelled by `kind` cannot
        // explode in cardinality. Pin all variants — adding a new
        // variant must update this test (forces an explicit decision
        // at the metrics level).
        assert_eq!(EntityKind::Aircraft.as_str(), "aircraft");
        assert_eq!(EntityKind::Ground.as_str(), "ground");
        assert_eq!(EntityKind::Marine.as_str(), "marine");
        assert_eq!(EntityKind::Sensor.as_str(), "sensor");
        assert_eq!(EntityKind::Track.as_str(), "track");
        assert_eq!(EntityKind::Munition.as_str(), "munition");
        assert_eq!(
            EntityKind::Unknown("custom-protocol-thing".into()).as_str(),
            "unknown",
            "Unknown variant must collapse the inner label to keep \
             Prometheus cardinality bounded",
        );
    }

    /// Trivial codec used to exercise the [`DynEntityCodec`] blanket
    /// impl and the [`EntityCodecRegistry`] dispatch path without
    /// pulling in any real wire-format crate.
    #[derive(Debug, Clone)]
    struct TestCodec(EntityKind);

    #[derive(Debug, thiserror::Error)]
    #[error("test codec failure: {0}")]
    struct TestCodecError(String);

    impl EntityCodec for TestCodec {
        type Error = TestCodecError;

        fn to_entity(&self, payload: &[u8]) -> Result<Entity, Self::Error> {
            // Empty payload is a "decode failure" — used by the
            // registry-wraps-error tests.
            if payload.is_empty() {
                return Err(TestCodecError("empty".into()));
            }
            Ok(Entity {
                uid: "test-uid".into(),
                kind: self.0.clone(),
                position: None,
                velocity: None,
                timestamp: SystemTime::UNIX_EPOCH,
                callsign: None,
                mil_std_2525_sidc: None,
                attributes: BTreeMap::new(),
                taskings: Default::default(),
                files: Default::default(),
            })
        }

        fn from_entity(&self, _entity: &Entity) -> Result<Bytes, Self::Error> {
            Ok(Bytes::from_static(b"encoded"))
        }
    }

    #[test]
    fn dyn_entity_codec_blanket_impl_boxes_typed_error() {
        // Pins the blanket `impl<T: EntityCodec> DynEntityCodec for T`:
        // a typed `TestCodecError` must round-trip through the boxed
        // `Box<dyn std::error::Error + Send + Sync>` shape.
        let codec: Arc<dyn DynEntityCodec> = Arc::new(TestCodec(EntityKind::Aircraft));
        let err = codec
            .to_entity_dyn(b"")
            .expect_err("empty payload must decode-fail");
        assert!(
            err.to_string().contains("test codec failure"),
            "boxed error must preserve Display output, got {err}",
        );
    }

    #[test]
    fn dyn_entity_codec_round_trip_works_through_arc_dyn() {
        // Pins that a real (non-erroring) call site stays usable
        // through the `Arc<dyn DynEntityCodec>` shape — encoder and
        // decoder both succeed and the encode-then-decode round trip
        // recovers the source `kind`.
        let codec: Arc<dyn DynEntityCodec> = Arc::new(TestCodec(EntityKind::Marine));
        let entity = codec
            .to_entity_dyn(b"non-empty")
            .expect("non-empty payload decodes");
        assert_eq!(entity.kind, EntityKind::Marine);
        let bytes = codec.from_entity_dyn(&entity).expect("encode round trip");
        assert_eq!(bytes.as_ref(), b"encoded");
    }

    #[test]
    fn entity_codec_registry_get_returns_some_when_registered() {
        let mut registry = EntityCodecRegistry::new();
        registry.register("test", Arc::new(TestCodec(EntityKind::Sensor)));
        assert!(!registry.is_empty());
        assert_eq!(registry.len(), 1);

        let codec = registry.get("test").expect("registered codec");
        let entity = codec
            .to_entity_dyn(b"non-empty")
            .expect("registered codec decodes");
        assert_eq!(entity.kind, EntityKind::Sensor);
    }

    #[test]
    fn entity_codec_registry_get_returns_none_for_unknown_protocol() {
        let registry = EntityCodecRegistry::new();
        assert!(registry.is_empty());
        assert!(registry.get("nonexistent").is_none());
    }

    #[test]
    fn entity_codec_registry_register_replaces_existing_key() {
        let mut registry = EntityCodecRegistry::new();
        registry.register("test", Arc::new(TestCodec(EntityKind::Sensor)));
        // Re-register under the same key — silent replacement so the
        // server binary's feature-flag overlap (e.g. the MAVLink crate
        // registering a frame codec and a downstream extension
        // registering a richer one) does not panic at startup.
        registry.register("test", Arc::new(TestCodec(EntityKind::Aircraft)));
        assert_eq!(registry.len(), 1);

        let codec = registry.get("test").expect("registered codec");
        let entity = codec
            .to_entity_dyn(b"non-empty")
            .expect("registered codec decodes");
        assert_eq!(
            entity.kind,
            EntityKind::Aircraft,
            "second register call must replace the first",
        );
    }

    #[test]
    fn entity_codec_registry_supports_multiple_protocols() {
        let mut registry = EntityCodecRegistry::new();
        registry.register("cot", Arc::new(TestCodec(EntityKind::Ground)));
        registry.register("mavlink", Arc::new(TestCodec(EntityKind::Aircraft)));
        registry.register("asterix", Arc::new(TestCodec(EntityKind::Track)));
        registry.register("stanag4586", Arc::new(TestCodec(EntityKind::Aircraft)));

        assert_eq!(registry.len(), 4);

        // Each protocol resolves to its own codec — pins that the
        // registry does not collapse keys or share Arc storage
        // unintentionally.
        assert_eq!(
            registry
                .get("cot")
                .expect("cot")
                .to_entity_dyn(b"x")
                .expect("decode")
                .kind,
            EntityKind::Ground,
        );
        assert_eq!(
            registry
                .get("mavlink")
                .expect("mavlink")
                .to_entity_dyn(b"x")
                .expect("decode")
                .kind,
            EntityKind::Aircraft,
        );
        assert_eq!(
            registry
                .get("asterix")
                .expect("asterix")
                .to_entity_dyn(b"x")
                .expect("decode")
                .kind,
            EntityKind::Track,
        );
    }

    #[test]
    fn entity_codec_registry_debug_renders_protocols_only() {
        // The custom Debug impl exists so an operator dump of the
        // registry shape is readable. Pin that the rendering
        // includes the protocol keys (and not, e.g., a placeholder
        // string with no diagnostic value).
        let mut registry = EntityCodecRegistry::new();
        registry.register("cot", Arc::new(TestCodec(EntityKind::Ground)));
        let dbg = format!("{registry:?}");
        assert!(
            dbg.contains("cot"),
            "Debug must include registered protocol keys, got {dbg}",
        );
    }

    // ----- Tasking / FileRef tests -----

    #[test]
    fn entity_default_taskings_and_files_are_empty() {
        let entity = Entity {
            uid: "uid-1".into(),
            kind: EntityKind::Track,
            position: None,
            velocity: None,
            timestamp: SystemTime::UNIX_EPOCH,
            callsign: None,
            mil_std_2525_sidc: None,
            attributes: BTreeMap::new(),
            taskings: Vec::new(),
            files: Vec::new(),
        };
        assert!(entity.taskings.is_empty());
        assert!(entity.files.is_empty());
    }

    #[test]
    fn pre_extension_json_round_trips_with_empty_taskings_and_files() {
        // Verifies the additive-with-defaults back-compat contract:
        // an Entity JSON document that pre-dates the Tasking / FileRef
        // fields must deserialize cleanly with empty vectors and
        // re-serialize identically (the new fields are
        // `skip_serializing_if = Vec::is_empty`).
        let json = r#"{
            "uid": "uid-1",
            "kind": {"type": "track"},
            "position": null,
            "velocity": null,
            "timestamp": {"secs_since_epoch": 0, "nanos_since_epoch": 0},
            "callsign": null,
            "mil_std_2525_sidc": null,
            "attributes": {}
        }"#;
        let entity: Entity = serde_json::from_str(json).unwrap();
        assert!(entity.taskings.is_empty());
        assert!(entity.files.is_empty());

        let reserialised = serde_json::to_string(&entity).unwrap();
        assert!(!reserialised.contains("taskings"));
        assert!(!reserialised.contains("files"));
    }

    #[test]
    fn tasking_round_trips_through_serde_json() {
        let tasking = Tasking {
            task_id: "T-001".into(),
            state: TaskingState::Executing,
            role: TaskingRole::Assignee,
            name: Some("OP IRON HAMMER".into()),
        };
        let json = serde_json::to_string(&tasking).unwrap();
        let back: Tasking = serde_json::from_str(&json).unwrap();
        assert_eq!(back, tasking);
        assert!(json.contains(r#""state":"executing""#));
        assert!(json.contains(r#""role":"assignee""#));
    }

    #[test]
    fn tasking_state_as_str_pins_closed_label_vocabulary() {
        assert_eq!(TaskingState::Assigned.as_str(), "assigned");
        assert_eq!(TaskingState::Acknowledged.as_str(), "acknowledged");
        assert_eq!(TaskingState::Executing.as_str(), "executing");
        assert_eq!(TaskingState::Complete.as_str(), "complete");
        assert_eq!(TaskingState::Failed.as_str(), "failed");
        assert_eq!(TaskingState::Cancelled.as_str(), "cancelled");
    }

    #[test]
    fn tasking_role_as_str_pins_closed_label_vocabulary() {
        assert_eq!(TaskingRole::Subject.as_str(), "subject");
        assert_eq!(TaskingRole::Assignee.as_str(), "assignee");
        assert_eq!(TaskingRole::Target.as_str(), "target");
        assert_eq!(TaskingRole::Observer.as_str(), "observer");
    }

    #[test]
    fn tasking_state_default_is_assigned() {
        assert_eq!(TaskingState::default(), TaskingState::Assigned);
    }

    #[test]
    fn tasking_role_default_is_subject() {
        assert_eq!(TaskingRole::default(), TaskingRole::Subject);
    }

    #[test]
    fn fileref_minimal_skips_optional_fields_on_wire() {
        let fr = FileRef {
            uri: "https://example.com/image.jpg".into(),
            size_bytes: None,
            mime: None,
            hash: None,
            label: None,
        };
        let json = serde_json::to_string(&fr).unwrap();
        // Only `uri` should appear; the other four fields have
        // `skip_serializing_if = Option::is_none`.
        assert!(json.contains("\"uri\":\"https://example.com/image.jpg\""));
        assert!(!json.contains("size_bytes"));
        assert!(!json.contains("\"mime\""));
        assert!(!json.contains("\"hash\""));
        assert!(!json.contains("\"label\""));
    }

    #[test]
    fn fileref_full_round_trips() {
        let fr = FileRef {
            uri: "s3://tactical-images/abc.jpg".into(),
            size_bytes: Some(1024),
            mime: Some("image/jpeg".into()),
            hash: Some(FileHash {
                algorithm: "sha256".into(),
                hex: "abc123".into(),
            }),
            label: Some("Target photo".into()),
        };
        let json = serde_json::to_string(&fr).unwrap();
        let back: FileRef = serde_json::from_str(&json).unwrap();
        assert_eq!(back, fr);
    }

    #[test]
    fn entity_with_taskings_and_files_round_trips() {
        let entity = Entity {
            uid: "track-1".into(),
            kind: EntityKind::Ground,
            position: None,
            velocity: None,
            timestamp: SystemTime::UNIX_EPOCH,
            callsign: Some("BRAVO-2".into()),
            mil_std_2525_sidc: None,
            attributes: BTreeMap::new(),
            taskings: vec![Tasking {
                task_id: "T-007".into(),
                state: TaskingState::Acknowledged,
                role: TaskingRole::Target,
                name: None,
            }],
            files: vec![FileRef {
                uri: "content://sha256/deadbeef".into(),
                size_bytes: Some(2048),
                mime: Some("image/png".into()),
                hash: Some(FileHash {
                    algorithm: "sha256".into(),
                    hex: "deadbeef".into(),
                }),
                label: None,
            }],
        };
        let json = serde_json::to_string(&entity).unwrap();
        let back: Entity = serde_json::from_str(&json).unwrap();
        assert_eq!(back.taskings.len(), 1);
        assert_eq!(back.files.len(), 1);
        assert_eq!(back.taskings[0].task_id, "T-007");
        assert_eq!(back.files[0].uri, "content://sha256/deadbeef");
    }

    #[test]
    fn multiple_taskings_with_different_roles_round_trip() {
        let entity = Entity {
            uid: "vehicle-1".into(),
            kind: EntityKind::Ground,
            position: None,
            velocity: None,
            timestamp: SystemTime::UNIX_EPOCH,
            callsign: None,
            mil_std_2525_sidc: None,
            attributes: BTreeMap::new(),
            taskings: vec![
                Tasking {
                    task_id: "MOVE-1".into(),
                    state: TaskingState::Executing,
                    role: TaskingRole::Assignee,
                    name: Some("Patrol Charlie".into()),
                },
                Tasking {
                    task_id: "OBS-2".into(),
                    state: TaskingState::Acknowledged,
                    role: TaskingRole::Observer,
                    name: None,
                },
            ],
            files: Vec::new(),
        };
        let json = serde_json::to_string(&entity).unwrap();
        let back: Entity = serde_json::from_str(&json).unwrap();
        assert_eq!(back.taskings.len(), 2);
        let roles: Vec<TaskingRole> = back.taskings.iter().map(|t| t.role).collect();
        assert!(roles.contains(&TaskingRole::Assignee));
        assert!(roles.contains(&TaskingRole::Observer));
    }
}
