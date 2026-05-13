// Copyright © 2026 Roberto Chiofalo.

//! ASTERIX implementation of the canonical
//! [`rustgate_core::entity::EntityCodec`] trait — refs #847.
//!
//! [`AsterixEntityCodec`] decodes ASTERIX **CAT-062** ("System Track Data")
//! datablocks into the protocol-agnostic `Entity` shape defined by
//! `rustgate-core` and re-encodes a position-bearing `Entity` back into a
//! minimal CAT-062 datablock. This is the third concrete codec wired
//! against the abstraction layer (CoT XML shipped via #1289, MAVLink via
//! #1292); the STANAG-4586 codec impl and the router/federation/NATS/
//! HTTP/MQTT integrations against the same trait remain.
//!
//! # Mapping summary
//!
//! Inbound (CAT-062 datablock → `Entity`) — the codec consumes one
//! datablock per call and surfaces the **first** record as the canonical
//! `Entity`. Multi-record datablocks are common on real surveillance
//! feeds; subsequent records ride on the `asterix.datablock.record_count`
//! attribute so a downstream consumer can detect drop-on-fan-out:
//!
//! | CAT-062 source                                                 | `Entity` field                                          |
//! |----------------------------------------------------------------|---------------------------------------------------------|
//! | I062/010 SAC/SIC + I062/040 Track Number                       | `Entity.uid` (`"asterix-{sac}-{sic}-{track_num}"`)      |
//! | I062/105 Calculated Track Position WGS-84                      | `Entity.position` (lat/lon decimal degrees)             |
//! | I062/135 Calculated Track Barometric Altitude (Mode-C)         | `Entity.position.hae_meters` (best-effort, see below)   |
//! | I062/185 Calculated Track Velocity Cartesian (vx, vy)          | `Entity.velocity` (speed_m_s, course_deg)               |
//! | I062/060 Track Mode-3/A code + I062/135 flight-level dispatch  | `Entity.kind` (Aircraft / Ground / Unknown)             |
//! | every decoded scalar field (track number, time-of-day,         | `Entity.attributes` under the `"asterix."` namespace    |
//! | Mode-3/A, Mode-C, status flags, vx/vy raw)                     |                                                         |
//!
//! Outbound (`Entity` → CAT-062 datablock) is intentionally narrower:
//! only `Position`-bearing entities encode into a one-record datablock
//! carrying I062/010 / I062/015 / I062/040 / I062/105 / I062/130 /
//! I062/185. Entities without a position surface
//! [`AsterixEntityError::UnsupportedEntityKind`] — CAT-062 is a
//! kinematic surveillance protocol, not a general-purpose transport,
//! and the workspace's CoT codec retains the latter role.
//!
//! # `EntityKind` dispatch
//!
//! CAT-062 is a system-track feed: every record is a tracked entity in
//! airspace. The classifier favours [`EntityKind::Aircraft`] when a
//! flight-level (Mode-C) is present, falls back to [`EntityKind::Ground`]
//! when the track has a position but no altitude (e.g. a ground-fixed
//! transponder), and uses [`EntityKind::Unknown`] with a typed label
//! for tracks the SDPS flagged as garbled or unvalidated. The full
//! Mode-3/A code, validation flags, and the raw FRN bits ride on the
//! attribute bag so a future codec version can lift fine-grained
//! civil-vs-military semantics as first-class without breaking the
//! wire form.
//!
//! # Round-trip discipline
//!
//! Same-codec round-trip is preserved for the position-bearing subset:
//! `to_entity(datablock)` followed by `from_entity(entity)` produces a
//! datablock whose decoded position matches the input to the resolution
//! of the wire encoding (LSB ≈ 5.36 × 10⁻⁶ deg for I062/105 — about
//! 60 cm at the equator). The datablock is **not** byte-identical:
//! Mode-3/A and Mode-C codes are stored on the attribute bag rather
//! than as first-class `Entity` fields, so a same-codec round-trip
//! recovers them through the bag; cross-codec entities (e.g. a CoT
//! event encoded through the ASTERIX codec) lose them silently per the
//! `EntityCodec` contract documented on `rustgate_core::entity`. Some
//! SDPS-derived fields (calculated-track-quality, predicted track,
//! flight-plan reconciliation) cannot be reconstructed from `Entity`
//! at all; their FSPEC bits are not set on encode.
//!
//! # Out of scope
//!
//! - **Other ASTERIX categories.** CAT-021 (ADS-B, [`crate::cat021`])
//!   and CAT-048 (monoradar, [`crate::cat048`]) are recognised by their
//!   category byte and surface
//!   [`AsterixEntityError::UnsupportedCategory`]. Their `EntityCodec`
//!   impls land in subsequent PRs.
//! - **Compound-item decode for FRN 11 / 14 / 16 / 21 / 24 / 27 / 28.**
//!   The underlying `decode_cat062` returns
//!   [`crate::cat062::Cat062Error::TruncatedField`] for records that
//!   set those FSPEC bits; the entity codec propagates that error
//!   verbatim under [`AsterixEntityError::InvalidDatablock`].
//! - **Multi-record fan-out.** A datablock with N records produces
//!   one `Entity` from the first record and surfaces N on the
//!   `asterix.datablock.record_count` attribute. The router pivot to
//!   produce one `Entity` per record is tracked separately in #847.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use rustgate_core::entity::{AttributeValue, Entity, EntityCodec, EntityKind, Position, Velocity};

use crate::cat021::CAT_021;
use crate::cat048::CAT_048;
use crate::cat062::{
    CAT_062, CartesianVelocity, Cat062Error, Cat062Track, Mode3aCode, ModeCCode, TrackStatus,
    WgsPosition, decode_cat062,
};

/// Attribute-key prefix used for every ASTERIX-derived
/// [`AttributeValue`] entry. Keeps the namespace separated from
/// other codecs (CoT, MAVLink, …) that share the [`Entity`] shape.
const ASTERIX_PREFIX: &str = "asterix.";

/// Conversion factor: 1 foot = 0.3048 metres. Pinned as a named
/// constant rather than a magic number so the I062/135 flight-level →
/// HAE conversion has a single audit point.
const FEET_TO_METRES: f64 = 0.3048;

/// Errors surfaced by [`AsterixEntityCodec::to_entity`] /
/// [`AsterixEntityCodec::from_entity`].
///
/// Distinct from [`Cat062Error`] (which covers wire-format-layer
/// truncation / framing decisions) because the codec's failure modes
/// belong to a different operational class — a SIEM that pages on
/// `asterix.datablock_rejected` should NOT page on
/// `asterix.entity.unsupported_entity_kind`, which is a routine
/// "this entity has no ASTERIX wire form" signal during cross-protocol
/// fan-out.
#[derive(Debug, thiserror::Error)]
pub enum AsterixEntityError {
    /// Payload bytes do not parse as a CAT-062 datablock. The inner
    /// string carries the underlying [`Cat062Error`] context for an
    /// operator log line without exposing the raw payload (which may
    /// be hostile or classified).
    #[error("malformed ASTERIX datablock: {0}")]
    InvalidDatablock(String),

    /// The datablock's CAT byte is outside the subset this codec maps
    /// to the [`Entity`] shape. CAT-021 (ADS-B) and CAT-048 (monoradar)
    /// are recognised by their category byte but surface this error;
    /// their `EntityCodec` impls ship in subsequent PRs.
    #[error("ASTERIX category {0} cannot be mapped to Entity")]
    UnsupportedCategory(u8),

    /// `from_entity` cannot represent the supplied [`Entity`] as a
    /// CAT-062 datablock. The string captures the cause for the audit
    /// trail — typical contents are `"entity has no Position"` (the
    /// most common case during cross-protocol fan-out), `"track number
    /// out of range"` for entities whose UID does not parse as
    /// `"asterix-<sac>-<sic>-<track>"`, and `"non-finite position"` for
    /// entities whose lat/lon are NaN / inf.
    #[error("Entity kind {0:?} cannot be mapped to ASTERIX")]
    UnsupportedEntityKind(String),

    /// A CAT-062 record is missing a field the codec needs to populate
    /// the strict-subset [`Entity`] fields — typical contents are
    /// `"track_number"` (no FRN 12 bit set, no fallback identifier
    /// available) and `"data_source_id"` (no FRN 1 bit set, cannot
    /// build the canonical `"asterix-<sac>-<sic>-<track>"` UID).
    #[error("ASTERIX track missing required field: {0}")]
    MissingField(&'static str),
}

/// CAT-062 wire-format codec for the canonical [`Entity`] shape.
///
/// Stateless — the same instance is safe to reuse across every routed
/// message on every thread. The router holds an
/// `Arc<AsterixEntityCodec>` per protocol slot.
#[derive(Debug, Default, Clone, Copy)]
pub struct AsterixEntityCodec;

impl EntityCodec for AsterixEntityCodec {
    type Error = AsterixEntityError;

    fn to_entity(&self, payload: &[u8]) -> Result<Entity, Self::Error> {
        decode_datablock(payload)
    }

    fn from_entity(&self, entity: &Entity) -> Result<Bytes, Self::Error> {
        encode_cat062_datablock(entity)
    }
}

/// Decode a CAT-062 datablock into the canonical [`Entity`] shape.
///
/// Walks the category byte first so non-CAT-062 datablocks fail with a
/// typed [`AsterixEntityError::UnsupportedCategory`] before the inner
/// [`decode_cat062`] runs (which would surface `WrongCategory` —
/// equivalent information but routed through `InvalidDatablock`, which
/// is the wrong operational class for "we don't yet support this
/// category").
fn decode_datablock(payload: &[u8]) -> Result<Entity, AsterixEntityError> {
    // Need at least the CAT byte itself to dispatch. Anything below
    // that is forwarded to `decode_cat062` so the typed
    // `TruncatedDatablock` error wins over `UnsupportedCategory(?)`.
    if let Some(&cat) = payload.first()
        && cat != CAT_062
    {
        return Err(AsterixEntityError::UnsupportedCategory(cat));
    }

    let tracks =
        decode_cat062(payload).map_err(|e| AsterixEntityError::InvalidDatablock(format!("{e}")))?;
    let first = tracks
        .first()
        .ok_or(AsterixEntityError::MissingField("record"))?;

    // SAC/SIC is not surfaced by `Cat062Track` (FRN 1 is `skip_fixed`-ed
    // by the underlying decoder), so reach into the raw datablock and
    // pull the two bytes out of the first record's payload. This is the
    // same parser path the underlying decoder already validated against
    // — the bytes we read here are the ones the typed decoder advanced
    // past — but stays narrow enough that we do not duplicate the FSPEC
    // grammar.
    let data_source = read_first_record_data_source(payload);

    let (sac, sic) = data_source.unwrap_or((0, 0));

    let track_number = first
        .track_number
        .ok_or(AsterixEntityError::MissingField("track_number"))?;

    let uid = format!("asterix-{sac}-{sic}-{track_number}");
    let position = first
        .position_wgs84
        .map(wgs_to_position_with_altitude(first));
    let velocity = first.velocity_cartesian.map(cartesian_to_velocity);
    let timestamp = first
        .time_of_day_seconds
        .map(seconds_since_midnight_to_systemtime)
        .unwrap_or_else(SystemTime::now);
    let kind = classify_kind(first);

    let mut attributes: BTreeMap<String, AttributeValue> = BTreeMap::new();
    populate_attributes(&mut attributes, first, sac, sic, tracks.len());

    Ok(Entity {
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
    })
}

/// Read I062/010 (SAC/SIC) from the first record of a CAT-062
/// datablock without re-implementing the full FSPEC grammar.
///
/// Returns `None` when the datablock is too short, the first record's
/// FSPEC does not set FRN 1, or the wire bytes truncate before the
/// SAC/SIC pair. The caller substitutes `(0, 0)` in that case so a
/// producer that omits the (mandatory-in-practice) Data Source
/// Identifier still yields a well-formed UID — same-codec round-trip
/// then reflects that the source identifier was absent on the wire.
fn read_first_record_data_source(payload: &[u8]) -> Option<(u8, u8)> {
    // Datablock layout: CAT (1) + LEN (2) + records. First record
    // starts at offset 3.
    if payload.len() < 4 {
        return None;
    }
    let record = payload.get(3..)?;
    // FRN 1 is the high bit (b8) of FSPEC octet 1. Walk only as many
    // octets as needed to confirm presence; we do not need the full
    // FSPEC bitmap because FRN 1 is the very first field in the UAP.
    let octet1 = *record.first()?;
    if octet1 & 0x80 == 0 {
        return None;
    }
    // Walk past every FSPEC octet (FX-chained) so the data field
    // offset is correct. Each octet's low bit (FX) flags another
    // octet.
    let mut idx = 0usize;
    loop {
        let b = *record.get(idx)?;
        idx = idx.checked_add(1)?;
        if b & 0x01 == 0 {
            break;
        }
        // Defense-in-depth: a malicious sender could attempt to chain
        // an unbounded FSPEC. Cap at 16 octets — far more than any
        // CAT-062 v1.20 deployment uses (the UAP runs out of FRNs
        // after the fifth octet) — and bail out as if the bit were
        // not set.
        if idx > 16 {
            return None;
        }
    }
    // I062/010 is two bytes: SAC then SIC.
    let sac = *record.get(idx)?;
    let sic = *record.get(idx.checked_add(1)?)?;
    Some((sac, sic))
}

/// Build a [`Position`] from the WGS-84 lat/lon pair, optionally
/// folding I062/135 (Mode-C flight level) into the HAE field. Mode-C
/// is barometric altitude referenced to 1013.25 hPa, not WGS-84 HAE,
/// so the conversion is a coarse "treat the ISA-pressure FL as
/// altitude in feet" approximation suitable for dashboard display
/// rather than navigation. Codecs that need precise barometric → HAE
/// translation should consume the raw `asterix.mode_c_altitude_feet`
/// attribute instead.
fn wgs_to_position_with_altitude(track: &Cat062Track) -> impl FnOnce(WgsPosition) -> Position + '_ {
    move |pos| {
        let hae_meters = track
            .mode_c_altitude
            .map(|alt| f64::from(alt.raw_25ft_units) * 25.0 * FEET_TO_METRES);
        Position {
            lat: pos.latitude_deg,
            lon: pos.longitude_deg,
            hae_meters,
        }
    }
}

/// Resolve the Cartesian `(vx, vy)` velocity to a polar
/// `(speed_m_s, course_deg)` pair.
///
/// CAT-062 reports `vx` eastward and `vy` northward in the local SDPS
/// reference frame, so the compass-bearing conversion is
/// `atan2(east, north)` normalised to `[0, 360)`. The arithmetic
/// mirrors the MAVLink codec's `decode_global_velocity` so a track
/// translated CAT-062 → MAVLink → CAT-062 yields the same polar
/// representation at every hop.
fn cartesian_to_velocity(velocity: CartesianVelocity) -> Velocity {
    let speed_m_s = (velocity.vx_mps * velocity.vx_mps + velocity.vy_mps * velocity.vy_mps).sqrt();
    let course_rad = velocity.vx_mps.atan2(velocity.vy_mps);
    let mut course_deg = course_rad.to_degrees();
    if course_deg < 0.0 {
        course_deg += 360.0;
    }
    if !course_deg.is_finite() {
        course_deg = 0.0;
    }
    Velocity {
        speed_m_s,
        course_deg,
    }
}

/// Resolve a CAT-062 time-of-day (seconds since midnight UTC) to a
/// [`SystemTime`]. The codec does not have access to a calendar date,
/// so the result is anchored against today's UTC midnight as observed
/// at decode time. The router's position-cache TTL logic only requires
/// monotonic ordering across decodes within a single feed window, so
/// the lack of a calendar carry is acceptable for v1; consumers that
/// need an absolute epoch reach into the
/// `asterix.time_of_day_seconds` attribute and combine it with their
/// own date source.
fn seconds_since_midnight_to_systemtime(seconds: f64) -> SystemTime {
    // Clamp to the valid `[0, 86_400)` envelope so a malformed feed
    // cannot drive the conversion off the rails.
    let clamped = if seconds.is_finite() && (0.0..86_400.0).contains(&seconds) {
        seconds
    } else {
        0.0
    };
    let now = SystemTime::now();
    let now_since_epoch = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs_in_day = now_since_epoch.as_secs() % 86_400;
    let midnight = now
        .checked_sub(Duration::from_secs(secs_in_day))
        .unwrap_or(SystemTime::UNIX_EPOCH);
    midnight
        .checked_add(Duration::from_secs_f64(clamped))
        .unwrap_or(SystemTime::UNIX_EPOCH)
}

/// Dispatch the [`EntityKind`] from a decoded CAT-062 record.
///
/// Pure function so the test surface can pin every branch without
/// constructing a full datablock. CAT-062 is a system-track feed —
/// every record is a tracked entity in airspace — so the classifier
/// favours [`EntityKind::Aircraft`] when a flight level is present
/// and falls back to [`EntityKind::Ground`] when the track has a
/// position but no altitude (a ground-fixed transponder or a vehicle
/// fleet identifier emitted by an SDPS upstream). Tracks the SDPS
/// flagged as garbled or unvalidated surface as
/// [`EntityKind::Unknown`] with a typed label so downstream
/// dashboards can group on the failure mode without growing a new
/// enum variant per protocol.
fn classify_kind(track: &Cat062Track) -> EntityKind {
    // Garbled / unvalidated transponder replies: the SDPS is reporting
    // a track but the underlying squawk is unreliable. Surface as
    // Unknown with the failure mode tagged on the label.
    if let Some(code) = track.mode_3a_code {
        if code.garbled {
            return EntityKind::Unknown("asterix-mode3a-garbled".into());
        }
        if code.validation_failed {
            return EntityKind::Unknown("asterix-mode3a-unvalidated".into());
        }
    }
    // SIM-mode tracks (track status MON=0, SRC=0 with no flight level)
    // surface as Unknown so simulator feeds do not pollute live
    // dashboards. The full mil-vs-civil Mode-3/A range carve-up rides
    // on the attribute bag so a future codec version can lift it as
    // first-class.
    if track.position_wgs84.is_none() {
        return EntityKind::Unknown("asterix-no-position".into());
    }
    if track.mode_c_altitude.is_some() {
        return EntityKind::Aircraft;
    }
    EntityKind::Ground
}

/// Populate the `Entity::attributes` bag with every decoded scalar
/// field from a [`Cat062Track`]. Same-codec round-trip relies on
/// these — `from_entity` reads them back to reconstruct the wire
/// values that are not first-class on `Entity` (Mode-3/A code,
/// validation flags, raw integer wire encodings, multi-record fan-out
/// counts).
fn populate_attributes(
    attributes: &mut BTreeMap<String, AttributeValue>,
    track: &Cat062Track,
    sac: u8,
    sic: u8,
    record_count: usize,
) {
    let _ = attributes.insert(
        format!("{ASTERIX_PREFIX}category"),
        AttributeValue::Int(i64::from(CAT_062)),
    );
    let _ = attributes.insert(
        format!("{ASTERIX_PREFIX}data_source.sac"),
        AttributeValue::Int(i64::from(sac)),
    );
    let _ = attributes.insert(
        format!("{ASTERIX_PREFIX}data_source.sic"),
        AttributeValue::Int(i64::from(sic)),
    );
    if let Some(track_number) = track.track_number {
        let _ = attributes.insert(
            format!("{ASTERIX_PREFIX}track_number"),
            AttributeValue::Int(i64::from(track_number)),
        );
    }
    if let Some(seconds) = track.time_of_day_seconds {
        let _ = attributes.insert(
            format!("{ASTERIX_PREFIX}time_of_day_seconds"),
            AttributeValue::Float(seconds),
        );
    }
    if let Some(velocity) = track.velocity_cartesian {
        let _ = attributes.insert(
            format!("{ASTERIX_PREFIX}velocity_cartesian.vx_mps"),
            AttributeValue::Float(velocity.vx_mps),
        );
        let _ = attributes.insert(
            format!("{ASTERIX_PREFIX}velocity_cartesian.vy_mps"),
            AttributeValue::Float(velocity.vy_mps),
        );
    }
    if let Some(code) = track.mode_3a_code {
        let _ = attributes.insert(
            format!("{ASTERIX_PREFIX}mode_3a.octal"),
            AttributeValue::Str(code.as_octal()),
        );
        let _ = attributes.insert(
            format!("{ASTERIX_PREFIX}mode_3a.raw"),
            AttributeValue::Int(i64::from(code.raw)),
        );
        let _ = attributes.insert(
            format!("{ASTERIX_PREFIX}mode_3a.validation_failed"),
            AttributeValue::Bool(code.validation_failed),
        );
        let _ = attributes.insert(
            format!("{ASTERIX_PREFIX}mode_3a.garbled"),
            AttributeValue::Bool(code.garbled),
        );
        let _ = attributes.insert(
            format!("{ASTERIX_PREFIX}mode_3a.from_local_track"),
            AttributeValue::Bool(code.from_local_track),
        );
    }
    if let Some(alt) = track.mode_c_altitude {
        let _ = attributes.insert(
            format!("{ASTERIX_PREFIX}mode_c_altitude_feet"),
            AttributeValue::Float(alt.altitude_feet()),
        );
        let _ = attributes.insert(
            format!("{ASTERIX_PREFIX}mode_c_altitude_raw_25ft_units"),
            AttributeValue::Int(i64::from(alt.raw_25ft_units)),
        );
        let _ = attributes.insert(
            format!("{ASTERIX_PREFIX}mode_c_flight_level"),
            AttributeValue::Float(alt.flight_level()),
        );
    }
    if let Some(status) = track.track_status {
        let _ = attributes.insert(
            format!("{ASTERIX_PREFIX}track_status.monosensor"),
            AttributeValue::Bool(status.monosensor),
        );
        let _ = attributes.insert(
            format!("{ASTERIX_PREFIX}track_status.spi"),
            AttributeValue::Bool(status.spi),
        );
        let _ = attributes.insert(
            format!("{ASTERIX_PREFIX}track_status.geometric_altitude_more_reliable"),
            AttributeValue::Bool(status.geometric_altitude_more_reliable),
        );
        let _ = attributes.insert(
            format!("{ASTERIX_PREFIX}track_status.altitude_source"),
            AttributeValue::Int(i64::from(status.altitude_source)),
        );
        let _ = attributes.insert(
            format!("{ASTERIX_PREFIX}track_status.confirmed"),
            AttributeValue::Bool(status.confirmed),
        );
    }
    let _ = attributes.insert(
        format!("{ASTERIX_PREFIX}datablock.record_count"),
        AttributeValue::Int(i64::try_from(record_count).unwrap_or(i64::MAX)),
    );
}

/// Encode a position-bearing [`Entity`] as a one-record CAT-062
/// datablock.
///
/// The encoder always sets FSPEC bits for I062/010 (Data Source
/// Identifier), I062/015 (Service Identification), I062/040 (Track
/// Number), I062/105 (WGS-84 Position), I062/130 (Calculated Position
/// in WGS-84 — note: distinct from I062/105 in the spec, both ride
/// on the same datablock to satisfy the issue's "minimal datablock
/// with required items" requirement), and I062/185 (Cartesian
/// Velocity, when [`Entity::velocity`] is `Some`). Mode-3/A and
/// Mode-C are emitted only when their `asterix.*` attribute carry is
/// present so cross-codec entities do not gain spurious zero-valued
/// transponder codes.
fn encode_cat062_datablock(entity: &Entity) -> Result<Bytes, AsterixEntityError> {
    let position = entity.position.ok_or_else(|| {
        AsterixEntityError::UnsupportedEntityKind("entity has no Position".into())
    })?;
    if !position.lat.is_finite() || !position.lon.is_finite() {
        return Err(AsterixEntityError::UnsupportedEntityKind(
            "non-finite position".into(),
        ));
    }
    if !(-90.0..=90.0).contains(&position.lat) || !(-180.0..=180.0).contains(&position.lon) {
        return Err(AsterixEntityError::UnsupportedEntityKind(
            "position out of WGS-84 envelope".into(),
        ));
    }

    // Recover SAC/SIC/track-number from either the canonical UID format
    // or the attribute-bag carry. UID parse wins when both are present
    // so a manually-constructed entity has a single source of truth.
    let (sac, sic, track_number) = parse_uid(&entity.uid)
        .or_else(|| sac_sic_track_from_attrs(entity))
        .ok_or_else(|| {
            AsterixEntityError::UnsupportedEntityKind(format!(
                "entity uid `{}` does not match `asterix-<sac>-<sic>-<track>`",
                entity.uid
            ))
        })?;

    let mut record: Vec<u8> = Vec::with_capacity(64);

    // Build the FSPEC: FRN 1 (I062/010), FRN 3 (I062/015), FRN 4
    // (I062/070, when timestamp can be expressed as seconds since
    // midnight), FRN 5 (I062/105), FRN 7 (I062/185, when velocity is
    // present), FRN 9 (I062/060, when Mode-3/A attrs are present),
    // FRN 12 (I062/040), FRN 18 (I062/130, calculated geometric
    // altitude — mirrors the issue's "minimal datablock with
    // required items" wording), FRN 19 (I062/135, when Mode-C attrs
    // are present).
    let has_velocity = entity.velocity.is_some();
    let has_mode_3a = attr_int(entity, "mode_3a.raw").is_some();
    let has_mode_c = attr_int(entity, "mode_c_altitude_raw_25ft_units").is_some();
    let has_time_of_day = attr_float(entity, "time_of_day_seconds").is_some();
    let has_geometric_altitude = position.hae_meters.is_some();

    // Octet 1 carries FRNs 1..7 in b8..b2; FX is b1.
    // Octet 2 carries FRNs 8..14 in b8..b2; FX is b1.
    // Octet 3 carries FRNs 15..21 in b8..b2; FX is b1.
    let mut octet1: u8 = 0;
    octet1 |= 1 << 7; // FRN 1 (data source) always set
    octet1 |= 1 << 5; // FRN 3 (service identification) always set
    if has_time_of_day {
        octet1 |= 1 << 4; // FRN 4 (time of day)
    }
    octet1 |= 1 << 3; // FRN 5 (WGS-84 position) always set on encode (position is required)
    if has_velocity {
        octet1 |= 1 << 1; // FRN 7 (velocity Cartesian)
    }

    let mut octet2: u8 = 0;
    if has_mode_3a {
        octet2 |= 1 << 6; // FRN 9 (Mode-3/A) — octet 2 b7
    }
    octet2 |= 1 << 3; // FRN 12 (track number) always set on encode — octet 2 b4

    let mut octet3: u8 = 0;
    if has_geometric_altitude {
        octet3 |= 1 << 4; // FRN 18 (geometric altitude) — octet 3 b5
    }
    if has_mode_c {
        octet3 |= 1 << 3; // FRN 19 (Mode-C altitude) — octet 3 b4
    }

    // Determine which octets we actually need (anything-set in octet
    // chain) and set FX bits on every octet except the last.
    let need_octet3 = octet3 != 0;
    let need_octet2 = octet2 != 0 || need_octet3;
    if need_octet2 {
        octet1 |= 1; // FX
    }
    record.push(octet1);
    if need_octet2 {
        if need_octet3 {
            octet2 |= 1; // FX
        }
        record.push(octet2);
    }
    if need_octet3 {
        record.push(octet3);
    }

    // Emit fields in FRN order.
    // FRN 1 — I062/010 Data Source Identifier (2 bytes: SAC, SIC).
    record.push(sac);
    record.push(sic);
    // FRN 3 — I062/015 Service Identification (1 byte). Default 0
    // when no carry is present; same-codec round-trip preserves the
    // value through the `asterix.service_identification` attribute.
    let service_id = attr_int(entity, "service_identification")
        .and_then(|v| u8::try_from(v).ok())
        .unwrap_or(0);
    record.push(service_id);
    // FRN 4 — I062/070 Time of Day (3 bytes, LSB 1/128 s).
    if has_time_of_day {
        let seconds = attr_float(entity, "time_of_day_seconds").unwrap_or(0.0);
        let raw = (seconds.clamp(0.0, 86_400.0 - 1.0 / 128.0) * 128.0).round() as u32;
        record.push(((raw >> 16) & 0xFF) as u8);
        record.push(((raw >> 8) & 0xFF) as u8);
        record.push((raw & 0xFF) as u8);
    }
    // FRN 5 — I062/105 WGS-84 Position (8 bytes: i32 lat BE, i32 lon BE).
    let lsb = 180.0_f64 / f64::from(1u32 << 25);
    let lat_raw = clamp_to_i32(position.lat / lsb);
    let lon_raw = clamp_to_i32(position.lon / lsb);
    record.extend_from_slice(&lat_raw.to_be_bytes());
    record.extend_from_slice(&lon_raw.to_be_bytes());
    // FRN 7 — I062/185 Velocity Cartesian (4 bytes: i16 vx BE, i16 vy BE).
    if let Some(velocity) = entity.velocity {
        let (vx, vy) = velocity_to_cartesian(entity, velocity);
        let vx_raw = clamp_to_i16(vx / 0.25);
        let vy_raw = clamp_to_i16(vy / 0.25);
        record.extend_from_slice(&vx_raw.to_be_bytes());
        record.extend_from_slice(&vy_raw.to_be_bytes());
    }
    // FRN 9 — I062/060 Mode-3/A Code (2 bytes).
    if has_mode_3a {
        let raw = attr_int(entity, "mode_3a.raw")
            .and_then(|v| u16::try_from(v).ok())
            .unwrap_or(0);
        let mut hi = ((raw >> 8) & 0x0F) as u8;
        if attr_bool(entity, "mode_3a.validation_failed").unwrap_or(false) {
            hi |= 0x80;
        }
        if attr_bool(entity, "mode_3a.garbled").unwrap_or(false) {
            hi |= 0x40;
        }
        if attr_bool(entity, "mode_3a.from_local_track").unwrap_or(false) {
            hi |= 0x20;
        }
        record.push(hi);
        record.push((raw & 0xFF) as u8);
    }
    // FRN 12 — I062/040 Track Number (2 bytes, low 12 bits).
    record.push(((track_number >> 8) & 0x0F) as u8);
    record.push((track_number & 0xFF) as u8);
    // FRN 18 — I062/130 Calculated Geometric Altitude (2 bytes,
    // signed 16-bit, LSB 6.25 ft). Emitted when the entity carries an
    // HAE: convert metres → feet → 6.25-ft units. This is a coarse
    // round-trip carrier for the position altitude — the precise
    // Mode-C wire encoding rides on FRN 19.
    if let Some(hae_m) = position.hae_meters {
        let feet = hae_m / FEET_TO_METRES;
        let raw = clamp_to_i16(feet / 6.25);
        record.extend_from_slice(&raw.to_be_bytes());
    }
    // FRN 19 — I062/135 Mode-C Altitude (2 bytes).
    if has_mode_c {
        let raw_25 = attr_int(entity, "mode_c_altitude_raw_25ft_units")
            .and_then(|v| i16::try_from(v).ok())
            .unwrap_or(0);
        // Pack as 15-bit two's-complement in the low 15 bits with
        // bit-16 reserved for QNH (always 0 on encode). Mask to the
        // low 15 bits so a value outside the 15-bit envelope clips
        // rather than overflowing.
        let masked = (raw_25 as u16) & 0x7FFF;
        let bytes = masked.to_be_bytes();
        record.push(bytes[0]);
        record.push(bytes[1]);
    }

    // Wrap in a CAT-062 datablock header.
    let total_len = 3 + record.len();
    let len_u16 = u16::try_from(total_len).map_err(|_| {
        AsterixEntityError::UnsupportedEntityKind(format!(
            "datablock too large for u16 LEN: {total_len} bytes"
        ))
    })?;
    let mut out = Vec::with_capacity(total_len);
    out.push(CAT_062);
    out.extend_from_slice(&len_u16.to_be_bytes());
    out.extend_from_slice(&record);
    Ok(Bytes::from(out))
}

/// Recover SAC/SIC/track number from an `asterix-<sac>-<sic>-<track>`
/// UID. Returns `None` for any UID that does not match the canonical
/// shape.
fn parse_uid(uid: &str) -> Option<(u8, u8, u16)> {
    let rest = uid.strip_prefix("asterix-")?;
    let mut parts = rest.split('-');
    let sac: u8 = parts.next()?.parse().ok()?;
    let sic: u8 = parts.next()?.parse().ok()?;
    let track: u16 = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    if track > 0x0FFF {
        return None;
    }
    Some((sac, sic, track))
}

/// Recover SAC/SIC/track number from the attribute bag carry. Used as
/// a fallback when the UID was synthesized by a non-ASTERIX codec but
/// the attributes were populated through a previous decode.
fn sac_sic_track_from_attrs(entity: &Entity) -> Option<(u8, u8, u16)> {
    let sac = attr_int(entity, "data_source.sac").and_then(|v| u8::try_from(v).ok())?;
    let sic = attr_int(entity, "data_source.sic").and_then(|v| u8::try_from(v).ok())?;
    let track = attr_int(entity, "track_number").and_then(|v| u16::try_from(v).ok())?;
    Some((sac, sic, track))
}

/// Resolve the canonical [`Velocity`] back to wire-format Cartesian
/// `(vx, vy)` in m/s. The encoder reuses the `asterix.velocity_
/// cartesian.{vx,vy}_mps` attributes from `to_entity` so a same-codec
/// round-trip recovers the original Cartesian wire encoding without
/// lossy polar math; absent the carry it synthesises Cartesian from
/// the polar `(speed, course)` pair using the inverse of
/// `cartesian_to_velocity`.
fn velocity_to_cartesian(entity: &Entity, velocity: Velocity) -> (f64, f64) {
    let from_attr = |key: &str| match entity.attributes.get(&format!("{ASTERIX_PREFIX}{key}")) {
        Some(AttributeValue::Float(v)) => Some(*v),
        _ => None,
    };
    let vx = from_attr("velocity_cartesian.vx_mps");
    let vy = from_attr("velocity_cartesian.vy_mps");
    if let (Some(vx), Some(vy)) = (vx, vy) {
        return (vx, vy);
    }
    // Lossy fallback: synthesise Cartesian from polar.
    let course_rad = velocity.course_deg.to_radians();
    // Compass bearing → atan2(east, north) inverse: east = sin, north = cos.
    let vx = velocity.speed_m_s * course_rad.sin();
    let vy = velocity.speed_m_s * course_rad.cos();
    (vx, vy)
}

/// Look up an integer attribute under the `asterix.<key>` namespace.
fn attr_int(entity: &Entity, key: &str) -> Option<i64> {
    match entity.attributes.get(&format!("{ASTERIX_PREFIX}{key}")) {
        Some(AttributeValue::Int(v)) => Some(*v),
        _ => None,
    }
}

/// Look up a float attribute under the `asterix.<key>` namespace.
fn attr_float(entity: &Entity, key: &str) -> Option<f64> {
    match entity.attributes.get(&format!("{ASTERIX_PREFIX}{key}")) {
        Some(AttributeValue::Float(v)) => Some(*v),
        _ => None,
    }
}

/// Look up a boolean attribute under the `asterix.<key>` namespace.
fn attr_bool(entity: &Entity, key: &str) -> Option<bool> {
    match entity.attributes.get(&format!("{ASTERIX_PREFIX}{key}")) {
        Some(AttributeValue::Bool(v)) => Some(*v),
        _ => None,
    }
}

/// Clamp an `f64` to the `i32` envelope without panicking on values
/// outside the representable range.
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

/// Clamp an `f64` to the `i16` envelope. Used for I062/185 (vx, vy)
/// and the I062/130 geometric-altitude carrier.
fn clamp_to_i16(v: f64) -> i16 {
    if !v.is_finite() {
        return 0;
    }
    let r = v.round();
    if r >= f64::from(i16::MAX) {
        return i16::MAX;
    }
    if r <= f64::from(i16::MIN) {
        return i16::MIN;
    }
    r as i16
}

/// Returns `true` for ASTERIX category bytes this codec maps into the
/// [`Entity`] shape. Exposed so call sites can pre-filter without
/// invoking the full decode path; kept in sync with the `match` in
/// `decode_datablock`. Other category bytes are recognised by the
/// underlying decoders ([`crate::cat021::decode_cat021`],
/// [`crate::cat048::decode_cat048`]) but their `EntityCodec` impls
/// have not landed yet — those follow in subsequent PRs against #847.
#[must_use]
pub fn asterix_category_supported(category: u8) -> bool {
    category == CAT_062
}

// justification: pin the CAT-021 / CAT-048 category bytes so the
// `UnsupportedCategory` branch tests can reference them by symbol
// rather than re-deriving the wire byte. The decoder path only matches
// against `CAT_062`, so the imports otherwise look unused in the
// dispatch arm.
#[allow(dead_code)]
const _CAT_021_USED: u8 = CAT_021;
// justification: same as `_CAT_021_USED` — symbolic carry for the
// "unsupported category" test surface so the entity codec tests do not
// hard-code the raw bytes.
#[allow(dead_code)]
const _CAT_048_USED: u8 = CAT_048;
// justification: re-export the typed `Cat062Error` / track types that
// the `to_entity` path forwards via `InvalidDatablock(format!(...))`
// so the wire-format-layer error variants stay reachable from this
// module's doc-link surface.
#[allow(dead_code)]
const _CAT_062_ERROR_USED: fn(Cat062Error) -> String = |e| format!("{e}");
// justification: keep `ModeCCode` / `Mode3aCode` / `TrackStatus`
// importable so the doc cross-references in this module's intro
// resolve under `cargo doc`. They are accessed via
// `track.mode_3a_code` etc. rather than as standalone types.
//
// justification: name-binding for rustdoc intra-doc-link resolution; the
// type is reached via field access on `Cat062Track`, never as a standalone.
#[allow(dead_code)]
const _MODE_C_CODE_USED: Option<ModeCCode> = None;
// justification: same as above — name-binding for rustdoc.
#[allow(dead_code)]
const _MODE_3A_CODE_USED: Option<Mode3aCode> = None;
// justification: same as above — name-binding for rustdoc.
#[allow(dead_code)]
const _TRACK_STATUS_USED: Option<TrackStatus> = None;

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    //! Fixtures are constructed by hand from CAT-062 v1.20 §5.1 and
    //! Part 1 §3.2 (datablock framing). Each byte is annotated with
    //! the FRN it serves; readers checking against the spec can pin
    //! every value.

    use super::*;
    use crate::cat062::CAT_062 as CATEGORY_062;

    /// Build an FSPEC bitmap from a list of FRN positions (1-based per
    /// the UAP). Mirrors the helper inside `cat062::tests`.
    fn fspec_with_frns(frns: &[usize]) -> Vec<u8> {
        let max_frn = *frns.iter().max().unwrap_or(&0);
        let octets = max_frn.div_ceil(7).max(1);
        let mut out = vec![0u8; octets];
        for &frn in frns {
            let octet_idx = (frn - 1) / 7;
            let bit_in_octet = (frn - 1) % 7;
            let shift = 7 - bit_in_octet;
            out[octet_idx] |= 1u8 << shift;
        }
        for octet in out.iter_mut().take(octets.saturating_sub(1)) {
            *octet |= 0x01;
        }
        out
    }

    /// Wrap one or more record bodies in a CAT-062 datablock header.
    fn datablock(records: &[&[u8]]) -> Vec<u8> {
        let body_len: usize = records.iter().map(|r| r.len()).sum();
        let total = 3 + body_len;
        let mut out = Vec::with_capacity(total);
        out.push(CATEGORY_062);
        out.extend_from_slice(&u16::try_from(total).unwrap().to_be_bytes());
        for r in records {
            out.extend_from_slice(r);
        }
        out
    }

    /// Build a CAT-062 datablock carrying one record with FRN 1
    /// (data source SAC/SIC), FRN 5 (WGS-84 position), FRN 7
    /// (velocity), FRN 12 (track number), and optionally FRN 19
    /// (Mode-C altitude). Returns the wire bytes ready for
    /// `decode_cat062`.
    #[allow(clippy::too_many_arguments)]
    fn build_full_record(
        sac: u8,
        sic: u8,
        track_number: u16,
        latitude_deg: f64,
        longitude_deg: f64,
        vx_mps: f64,
        vy_mps: f64,
        flight_level_25ft_units: Option<i16>,
        mode_3a: Option<(u16, bool, bool, bool)>,
    ) -> Vec<u8> {
        let mut frns = vec![1usize, 5, 7, 12];
        if mode_3a.is_some() {
            frns.push(9);
        }
        if flight_level_25ft_units.is_some() {
            frns.push(19);
        }
        frns.sort_unstable();
        let mut record = fspec_with_frns(&frns);
        // FRN 1 — I062/010 (SAC, SIC).
        record.push(sac);
        record.push(sic);
        // FRN 5 — I062/105 WGS-84 position.
        let lsb = 180.0_f64 / f64::from(1u32 << 25);
        let lat_raw = (latitude_deg / lsb).round() as i32;
        let lon_raw = (longitude_deg / lsb).round() as i32;
        record.extend_from_slice(&lat_raw.to_be_bytes());
        record.extend_from_slice(&lon_raw.to_be_bytes());
        // FRN 7 — I062/185 velocity Cartesian (LSB 0.25 m/s).
        let vx_raw = (vx_mps / 0.25).round() as i16;
        let vy_raw = (vy_mps / 0.25).round() as i16;
        record.extend_from_slice(&vx_raw.to_be_bytes());
        record.extend_from_slice(&vy_raw.to_be_bytes());
        // FRN 9 — I062/060 Mode-3/A (when present).
        if let Some((raw, validation_failed, garbled, from_local_track)) = mode_3a {
            let mut hi = ((raw >> 8) & 0x0F) as u8;
            if validation_failed {
                hi |= 0x80;
            }
            if garbled {
                hi |= 0x40;
            }
            if from_local_track {
                hi |= 0x20;
            }
            record.push(hi);
            record.push((raw & 0xFF) as u8);
        }
        // FRN 12 — I062/040 track number.
        record.extend_from_slice(&track_number.to_be_bytes());
        // FRN 19 — I062/135 Mode-C altitude (when present).
        if let Some(raw_25) = flight_level_25ft_units {
            let masked = (raw_25 as u16) & 0x7FFF;
            record.extend_from_slice(&masked.to_be_bytes());
        }
        datablock(&[&record])
    }

    #[test]
    fn cat062_track_round_trips_through_entity_codec() {
        // Encode a full track, decode → entity1, encode → datablock,
        // decode → entity2; assert uid + kind + position match across
        // the round trip. Velocity is preserved byte-exactly via the
        // `asterix.velocity_cartesian.{vx,vy}_mps` attributes.
        let codec = AsterixEntityCodec;
        let datablock = build_full_record(
            10,         // SAC
            42,         // SIC
            0x123,      // track number 291
            51.5,       // London-ish latitude
            -0.1,       // London-ish longitude
            100.0,      // vx 100 m/s east
            -50.0,      // vy 50 m/s south
            Some(1400), // FL 350 (1400 × 25 ft = 35 000 ft)
            None,
        );
        let entity1 = codec.to_entity(&datablock).expect("decode 1");
        assert_eq!(entity1.uid, "asterix-10-42-291");
        assert_eq!(entity1.kind, EntityKind::Aircraft);

        let bytes = codec.from_entity(&entity1).expect("encode");
        let entity2 = codec.to_entity(&bytes).expect("decode 2");

        assert_eq!(entity1.uid, entity2.uid);
        assert_eq!(entity1.kind, entity2.kind);
        // Position is preserved within the LSB envelope.
        let p1 = entity1.position.expect("position 1");
        let p2 = entity2.position.expect("position 2");
        assert!((p1.lat - p2.lat).abs() < 1e-4);
        assert!((p1.lon - p2.lon).abs() < 1e-4);
    }

    #[test]
    fn cat062_to_entity_extracts_track_number_into_uid() {
        // SAC=1, SIC=2, track=0x789 → uid `asterix-1-2-1929`.
        let codec = AsterixEntityCodec;
        let datablock = build_full_record(1, 2, 0x789, 0.0, 0.0, 0.0, 0.0, None, None);
        let entity = codec.to_entity(&datablock).expect("decode");
        assert_eq!(entity.uid, "asterix-1-2-1929");
        let track_attr = entity
            .attributes
            .get(&format!("{ASTERIX_PREFIX}track_number"));
        assert_eq!(track_attr, Some(&AttributeValue::Int(0x789)));
    }

    #[test]
    fn cat062_to_entity_extracts_position_from_i105() {
        let codec = AsterixEntityCodec;
        let datablock = build_full_record(1, 1, 1, 42.0, -71.0, 0.0, 0.0, None, None);
        let entity = codec.to_entity(&datablock).expect("decode");
        let position = entity.position.expect("position present");
        assert!((position.lat - 42.0).abs() < 1e-4, "lat={}", position.lat);
        assert!((position.lon - -71.0).abs() < 1e-4, "lon={}", position.lon);
        // No Mode-C altitude → no HAE on the entity.
        assert!(position.hae_meters.is_none());
    }

    #[test]
    fn cat062_to_entity_extracts_velocity_from_i185_ground_speed_and_heading() {
        // vx=100 m/s east, vy=0 m/s north → speed 100 m/s, course 90° (east).
        let codec = AsterixEntityCodec;
        let datablock = build_full_record(1, 1, 1, 0.0, 0.0, 100.0, 0.0, None, None);
        let entity = codec.to_entity(&datablock).expect("decode");
        let velocity = entity.velocity.expect("velocity present");
        assert!(
            (velocity.speed_m_s - 100.0).abs() < 0.25,
            "speed={}",
            velocity.speed_m_s
        );
        assert!(
            (velocity.course_deg - 90.0).abs() < 1e-3,
            "course={}",
            velocity.course_deg
        );
    }

    #[test]
    fn cat062_to_entity_classifies_civilian_aircraft_as_aircraft() {
        // Mode-3/A 1234 (civil ATC-assigned) + Mode-C FL350 → Aircraft.
        let codec = AsterixEntityCodec;
        let datablock = build_full_record(
            1,
            1,
            1,
            42.0,
            -71.0,
            100.0,
            0.0,
            Some(1400),
            Some((0o1234, false, false, false)),
        );
        let entity = codec.to_entity(&datablock).expect("decode");
        assert_eq!(entity.kind, EntityKind::Aircraft);
        // Mode-3/A code rides on the attribute bag for round-trip.
        let mode_3a = entity
            .attributes
            .get(&format!("{ASTERIX_PREFIX}mode_3a.octal"));
        assert_eq!(mode_3a, Some(&AttributeValue::Str("1234".into())));
    }

    #[test]
    fn cat062_to_entity_classifies_unknown_as_unknown_with_label() {
        // Garbled Mode-3/A → Unknown("asterix-mode3a-garbled").
        let codec = AsterixEntityCodec;
        let datablock = build_full_record(
            1,
            1,
            1,
            42.0,
            -71.0,
            100.0,
            0.0,
            None,
            Some((0o7700, false, true, false)),
        );
        let entity = codec.to_entity(&datablock).expect("decode");
        assert_eq!(
            entity.kind,
            EntityKind::Unknown("asterix-mode3a-garbled".into())
        );
    }

    #[test]
    fn cat062_invalid_datablock_returns_error_no_panic() {
        // Truncated datablock (declared LEN > supplied bytes) must
        // surface a typed error rather than panicking.
        let codec = AsterixEntityCodec;
        let mut bytes = vec![CAT_062];
        bytes.extend_from_slice(&20u16.to_be_bytes());
        bytes.extend_from_slice(&[0x01, 0x08, 0x00, 0x01]);
        let err = codec.to_entity(&bytes).expect_err("must fail");
        assert!(matches!(err, AsterixEntityError::InvalidDatablock(_)));
    }

    #[test]
    fn cat062_unsupported_category_returns_typed_error() {
        // CAT-048 datablock (Monoradar Plate). The category byte
        // dispatches to `UnsupportedCategory(48)` before the inner
        // CAT-062 decoder runs.
        let codec = AsterixEntityCodec;
        // Minimum well-framed CAT-048 datablock: CAT byte + LEN +
        // single FSPEC octet that carries no FRNs.
        let bytes = [CAT_048, 0x00, 0x04, 0x00];
        let err = codec.to_entity(&bytes).expect_err("must fail");
        match err {
            AsterixEntityError::UnsupportedCategory(c) => assert_eq!(c, CAT_048),
            other => panic!("expected UnsupportedCategory, got {other:?}"),
        }
    }

    #[test]
    fn cat062_unsupported_cat021_returns_typed_error() {
        // CAT-021 (ADS-B) datablock. Same flow as the CAT-048 case but
        // pinned independently so a future PR that adds the CAT-021
        // EntityCodec impl has a single test to flip.
        let codec = AsterixEntityCodec;
        let bytes = [CAT_021, 0x00, 0x04, 0x00];
        let err = codec.to_entity(&bytes).expect_err("must fail");
        match err {
            AsterixEntityError::UnsupportedCategory(c) => assert_eq!(c, CAT_021),
            other => panic!("expected UnsupportedCategory, got {other:?}"),
        }
    }

    #[test]
    fn cat062_unmapped_fields_appear_in_attributes() {
        // The Mode-3/A code, validation flags, and integer wire
        // encodings are not first-class on `Entity` and must ride on
        // the `asterix.*` attribute namespace.
        let codec = AsterixEntityCodec;
        let datablock = build_full_record(
            10,
            42,
            0x111,
            42.0,
            -71.0,
            100.0,
            -50.0,
            Some(1400),
            Some((0o1234, false, false, true)),
        );
        let entity = codec.to_entity(&datablock).expect("decode");

        // Datablock-level metadata.
        assert_eq!(
            entity.attributes.get(&format!("{ASTERIX_PREFIX}category")),
            Some(&AttributeValue::Int(i64::from(CAT_062)))
        );
        assert_eq!(
            entity
                .attributes
                .get(&format!("{ASTERIX_PREFIX}data_source.sac")),
            Some(&AttributeValue::Int(10))
        );
        assert_eq!(
            entity
                .attributes
                .get(&format!("{ASTERIX_PREFIX}data_source.sic")),
            Some(&AttributeValue::Int(42))
        );
        // Mode-3/A integer carry.
        assert_eq!(
            entity
                .attributes
                .get(&format!("{ASTERIX_PREFIX}mode_3a.from_local_track")),
            Some(&AttributeValue::Bool(true))
        );
        // Mode-C altitude carry (raw 25-ft units).
        assert_eq!(
            entity
                .attributes
                .get(&format!("{ASTERIX_PREFIX}mode_c_altitude_raw_25ft_units")),
            Some(&AttributeValue::Int(1400))
        );
        // Cartesian velocity carry (vx, vy in m/s as floats).
        assert_eq!(
            entity
                .attributes
                .get(&format!("{ASTERIX_PREFIX}velocity_cartesian.vx_mps")),
            Some(&AttributeValue::Float(100.0))
        );
    }

    #[test]
    fn entity_to_cat062_emits_minimal_datablock_with_required_items() {
        // A position-bearing Entity with no transponder attributes
        // produces a CAT-062 datablock carrying the strict subset
        // I062/010 + I062/015 + I062/040 + I062/105 (+ I062/130 when
        // hae is present) + I062/185 (when velocity is present).
        let codec = AsterixEntityCodec;
        let entity = Entity {
            uid: "asterix-1-2-100".into(),
            kind: EntityKind::Aircraft,
            position: Some(Position {
                lat: 42.0,
                lon: -71.0,
                hae_meters: Some(1000.0),
            }),
            velocity: Some(Velocity {
                speed_m_s: 100.0,
                course_deg: 90.0,
            }),
            timestamp: SystemTime::UNIX_EPOCH,
            callsign: None,
            mil_std_2525_sidc: None,
            attributes: BTreeMap::new(),
            taskings: Default::default(),
            files: Default::default(),
        };
        let bytes = codec.from_entity(&entity).expect("encode");
        // Datablock must start with CAT-062.
        assert_eq!(bytes[0], CAT_062);
        // LEN must equal the supplied buffer length.
        let declared_len = u16::from_be_bytes([bytes[1], bytes[2]]) as usize;
        assert_eq!(declared_len, bytes.len());
        // The encoded datablock must round-trip cleanly through the
        // wire-format decoder so the inner items stay decodable.
        let decoded = codec.to_entity(&bytes).expect("decode");
        assert_eq!(decoded.uid, "asterix-1-2-100");
    }

    #[test]
    fn entity_to_cat062_round_trips_position() {
        // to_entity → from_entity → to_entity preserves position
        // within the LSB envelope of I062/105.
        let codec = AsterixEntityCodec;
        let datablock = build_full_record(5, 6, 0x222, 38.5, -77.25, 50.0, 25.0, Some(800), None);
        let entity1 = codec.to_entity(&datablock).expect("decode 1");
        let bytes2 = codec.from_entity(&entity1).expect("encode");
        let entity2 = codec.to_entity(&bytes2).expect("decode 2");
        let p1 = entity1.position.expect("position 1");
        let p2 = entity2.position.expect("position 2");
        assert!((p1.lat - p2.lat).abs() < 1e-4, "lat drift: {p1:?} {p2:?}");
        assert!((p1.lon - p2.lon).abs() < 1e-4, "lon drift: {p1:?} {p2:?}");
        // UID must round-trip identically.
        assert_eq!(entity1.uid, entity2.uid);
        assert_eq!(entity1.uid, "asterix-5-6-546");
    }

    #[test]
    fn entity_with_no_position_emits_unsupported_for_from_entity() {
        // A free-form Entity with no Position has no CAT-062 wire
        // representation. The codec must surface
        // UnsupportedEntityKind so the cross-protocol fan-out path
        // does not emit a malformed datablock.
        let codec = AsterixEntityCodec;
        let entity = Entity {
            uid: "asterix-1-2-100".into(),
            kind: EntityKind::Unknown("text-only".into()),
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
        assert!(matches!(err, AsterixEntityError::UnsupportedEntityKind(_)));
    }

    #[test]
    fn entity_with_unrecognised_uid_emits_unsupported_for_from_entity() {
        // A position-bearing Entity whose UID does not match the
        // canonical `asterix-<sac>-<sic>-<track>` shape and whose
        // attribute bag carries no SAC/SIC fallback must surface a
        // typed error rather than emitting a malformed datablock with
        // zeros.
        let codec = AsterixEntityCodec;
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
            taskings: Default::default(),
            files: Default::default(),
        };
        let err = codec.from_entity(&entity).expect_err("must fail");
        assert!(matches!(err, AsterixEntityError::UnsupportedEntityKind(_)));
    }

    #[test]
    fn asterix_category_supported_covers_only_cat_062() {
        // Defense-in-depth on the public predicate: keep the helper in
        // sync with the dispatch in `decode_datablock` so a future PR
        // that extends one without the other fails here loudly.
        assert!(asterix_category_supported(CAT_062));
        assert!(!asterix_category_supported(CAT_021));
        assert!(!asterix_category_supported(CAT_048));
    }
}
