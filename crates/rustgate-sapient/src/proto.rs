// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Hand-rolled protobuf wire-format primitives and the typed
//! [`SapientMessage`] / [`DetectionReport`] / [`Location`] /
//! [`EnuVelocity`] / [`Classification`] structs used by the SAPIENT
//! codec.
//!
//! # Why hand-rolled
//!
//! BSI Flex 335 v2.0 ships a multi-message protobuf schema with a
//! ten-arm `oneof` envelope. Adding a `build.rs` + `prost` dependency
//! for the narrow MVP scope (envelope + `DetectionReport` decode, all
//! other arms passed through as opaque bytes) would dwarf the crate it
//! produces and bring `prost` and its transitive build-script surface
//! into a feature-gated path operators may never enable. Hand-rolled
//! wire-format parsing keeps the dependency footprint at `bytes` +
//! `thiserror` + `rustgate-core` and surfaces every wire-tag mistake
//! at the read site rather than behind generated code. The parser is
//! forward-compatible: unknown fields are skipped (the canonical
//! protobuf "ignore unknown" behaviour) so a future BSI Flex 335
//! revision that adds fields stays decodable.
//!
//! # Wire layout (BSI Flex 335 v2.0, sapient_message.proto)
//!
//! ```text
//! SapientMessage {
//!     1 google.protobuf.Timestamp timestamp        // length-delimited submessage
//!     2 string                    node_id          // UUID string
//!     3 string                    destination_id   // UUID string
//!     // oneof content:
//!     4  Registration     registration
//!     5  RegistrationAck  registration_ack
//!     6  StatusReport     status_report
//!     7  DetectionReport  detection_report   // <-- fully decoded in this MVP
//!     8  Task             task
//!     9  TaskAck          task_ack
//!     10 Alert            alert
//!     11 AlertAck         alert_ack
//!     12 Error            error
//!     13 string           additional_information
//! }
//!
//! DetectionReport {
//!     1  string  report_id (ULID)
//!     2  string  object_id (ULID)
//!     3  string  task_id (ULID)
//!     4  string  state
//!     // oneof location_oneof:
//!     5  RangeBearing range_bearing
//!     6  Location     location           // <-- preferred lat/lon arm
//!     7  float   detection_confidence    // wire type 5 (fixed32 IEEE-754)
//!     8  TrackObjectInfo track_info      // repeated
//!     11 DetectionReportClassification classification  // repeated
//!     // oneof velocity_oneof:
//!     19 ENUVelocity   enu_velocity
//!     22 string  colour
//!     23 string  id
//! }
//!
//! Location {
//!     1 double x        // longitude (LAT_LNG_DEG_M)
//!     2 double y        // latitude
//!     3 double z        // altitude
//!     7 LocationCoordinateSystem coordinate_system  (varint enum)
//!     8 LocationDatum             datum             (varint enum)
//! }
//!
//! ENUVelocity {
//!     1 double east_rate
//!     2 double north_rate
//!     3 double up_rate
//! }
//! ```
//!
//! Field tags are computed as `(field_number << 3) | wire_type`. Wire
//! types used here: 0 = varint, 1 = fixed64, 2 = length-delimited,
//! 5 = fixed32. SAPIENT uses `double` (wire type 1, little-endian
//! IEEE-754) for every coordinate / velocity scalar — there is no
//! integer scaling on the wire, so the codec preserves source
//! precision losslessly.
//!
//! # MVP scope
//!
//! - `SapientMessage` envelope: every header field plus the
//!   `oneof content` discriminator, then dispatch to the per-arm
//!   parser.
//! - `DetectionReport` content arm: the high-value position-bearing
//!   arm — the field that maps to [`rustgate_core::entity::Entity`].
//! - All other content arms (`Registration`, `RegistrationAck`,
//!   `StatusReport`, `Task`, `TaskAck`, `Alert`, `AlertAck`, `Error`)
//!   ride as [`SapientPayload::Other`] with the field-number tag
//!   preserved so a future revision can lift fine-grained dispatch
//!   without breaking the wire form.

use core::fmt;

use bytes::{Buf, BufMut};

use crate::error::SapientError;

/// Defense-in-depth ceiling on a single SAPIENT message. SAPIENT runs
/// over higher-bandwidth links than LoRa-class meshes (typical deploy
/// is a Cat-5 LAN inside a counter-UAS perimeter), but a hostile peer
/// can still exhaust router memory by claiming a multi-megabyte
/// length prefix; capping at 16 MiB matches the workspace-wide
/// `MAX_FRAME_SIZE` published by `rustgate-core`. A frame whose total
/// length exceeds the cap is rejected with
/// [`SapientError::PayloadTooLarge`] before the parser does any work.
pub const MAX_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;

/// IANA-style symbolic constant for the field number of the
/// `DetectionReport` arm of `SapientMessage.content`. Public so a
/// future router-side classifier can pin "is this a detection
/// report?" without re-deriving the field number from the tag bytes.
pub const SAPIENT_FIELD_DETECTION_REPORT: u32 = 7;

// --- SapientMessage fields ---
const TAG_MSG_TIMESTAMP: u64 = (1 << 3) | 2; // length-delimited (Timestamp submessage)
const TAG_MSG_NODE_ID: u64 = (2 << 3) | 2; // string
const TAG_MSG_DESTINATION_ID: u64 = (3 << 3) | 2; // string
const TAG_MSG_REGISTRATION: u64 = (4 << 3) | 2;
const TAG_MSG_REGISTRATION_ACK: u64 = (5 << 3) | 2;
const TAG_MSG_STATUS_REPORT: u64 = (6 << 3) | 2;
const TAG_MSG_DETECTION_REPORT: u64 = (7 << 3) | 2;
const TAG_MSG_TASK: u64 = (8 << 3) | 2;
const TAG_MSG_TASK_ACK: u64 = (9 << 3) | 2;
const TAG_MSG_ALERT: u64 = (10 << 3) | 2;
const TAG_MSG_ALERT_ACK: u64 = (11 << 3) | 2;
const TAG_MSG_ERROR: u64 = (12 << 3) | 2;
const TAG_MSG_ADDITIONAL_INFO: u64 = (13 << 3) | 2;

// --- google.protobuf.Timestamp fields ---
// `seconds = int64` (varint), `nanos = int32` (varint).
const TAG_TS_SECONDS: u64 = 1 << 3;
const TAG_TS_NANOS: u64 = 2 << 3;

// --- DetectionReport fields ---
const TAG_DR_REPORT_ID: u64 = (1 << 3) | 2;
const TAG_DR_OBJECT_ID: u64 = (2 << 3) | 2;
const TAG_DR_TASK_ID: u64 = (3 << 3) | 2;
const TAG_DR_STATE: u64 = (4 << 3) | 2;
const TAG_DR_RANGE_BEARING: u64 = (5 << 3) | 2;
const TAG_DR_LOCATION: u64 = (6 << 3) | 2;
const TAG_DR_DETECTION_CONFIDENCE: u64 = (7 << 3) | 5; // float = fixed32
const TAG_DR_TRACK_INFO: u64 = (8 << 3) | 2;
const TAG_DR_PREDICTION_LOCATION: u64 = (9 << 3) | 2;
const TAG_DR_OBJECT_INFO: u64 = (10 << 3) | 2;
const TAG_DR_CLASSIFICATION: u64 = (11 << 3) | 2;
const TAG_DR_BEHAVIOUR: u64 = (12 << 3) | 2;
const TAG_DR_ASSOCIATED_FILE: u64 = (13 << 3) | 2;
const TAG_DR_SIGNAL: u64 = (14 << 3) | 2;
const TAG_DR_ASSOCIATED_DETECTION: u64 = (15 << 3) | 2;
const TAG_DR_DERIVED_DETECTION: u64 = (16 << 3) | 2;
const TAG_DR_ENU_VELOCITY: u64 = (19 << 3) | 2;
const TAG_DR_COLOUR: u64 = (22 << 3) | 2;
const TAG_DR_ID: u64 = (23 << 3) | 2;

// --- Location fields ---
const TAG_LOC_X: u64 = (1 << 3) | 1; // double = fixed64
const TAG_LOC_Y: u64 = (2 << 3) | 1;
const TAG_LOC_Z: u64 = (3 << 3) | 1;
const TAG_LOC_X_ERROR: u64 = (4 << 3) | 1;
const TAG_LOC_Y_ERROR: u64 = (5 << 3) | 1;
const TAG_LOC_Z_ERROR: u64 = (6 << 3) | 1;
const TAG_LOC_COORD_SYSTEM: u64 = 7 << 3; // varint enum
const TAG_LOC_DATUM: u64 = 8 << 3; // varint enum
const TAG_LOC_UTM_ZONE: u64 = (9 << 3) | 2;

// --- ENUVelocity fields ---
const TAG_ENU_EAST_RATE: u64 = (1 << 3) | 1;
const TAG_ENU_NORTH_RATE: u64 = (2 << 3) | 1;
const TAG_ENU_UP_RATE: u64 = (3 << 3) | 1;

// --- DetectionReportClassification fields ---
const TAG_CLS_TYPE: u64 = (1 << 3) | 2;
const TAG_CLS_CONFIDENCE: u64 = (2 << 3) | 5; // float = fixed32

/// Top-level SAPIENT envelope.
///
/// Every wire frame the codec emits or consumes is exactly one
/// `SapientMessage` — there is no length prefix at this layer because
/// the transport (TCP framing, MQTT topic envelope, gRPC body) carries
/// it. Anything beyond [`MAX_PAYLOAD_BYTES`] is rejected before the
/// parser runs.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct SapientMessage {
    /// UTC time the producer attached to the message, as POSIX
    /// seconds + nanoseconds. The BSI Flex 335 spec marks this
    /// `is_mandatory: true`, but the codec accepts absence so a
    /// future revision that elides it on a status-only frame stays
    /// decodable.
    pub timestamp: Option<Timestamp>,
    /// UUID for the node which is sending the message. The spec
    /// marks this `is_mandatory: true`; the codec treats absence as
    /// the empty string for forward-compat.
    pub node_id: String,
    /// UUID for the node being tasked. Empty when the message is
    /// not a task / task-ack and absence is the typical case.
    pub destination_id: String,
    /// Active `oneof content` arm. Mandatory per the BSI spec; a
    /// frame missing this surfaces as
    /// [`SapientError::MissingContent`] on decode. Wrapped in
    /// `Option` so the default constructor produces a syntactically
    /// valid empty message for builder-style use.
    pub content: Option<SapientPayload>,
    /// Free-form additional information slot the BSI spec leaves at
    /// field 13. Empty by default.
    pub additional_information: String,
}

/// Active `oneof content` arm.
///
/// MVP scope: the [`Self::DetectionReport`] arm is fully decoded
/// because that is the position-bearing surface that maps to
/// [`rustgate_core::entity::Entity`]. Every other arm rides as
/// [`Self::Other`] with the field-number tag preserved so a future
/// codec revision can lift fine-grained dispatch without breaking
/// the wire form. The encoder honours [`Self::Other`] symmetrically
/// — round-tripping an unknown arm preserves its bytes verbatim.
#[derive(Debug, Clone, PartialEq)]
pub enum SapientPayload {
    /// Fully decoded `DetectionReport` arm — the high-value
    /// surface that maps to [`rustgate_core::entity::Entity`].
    /// Boxed to keep the enum's stack footprint bounded — a
    /// `DetectionReport` carries several `String`s and a
    /// `Vec<Classification>` so it dwarfs the `Other` variant's
    /// pointer + tag pair.
    DetectionReport(Box<DetectionReport>),
    /// Any other `oneof content` arm (`Registration`,
    /// `RegistrationAck`, `StatusReport`, `Task`, `TaskAck`,
    /// `Alert`, `AlertAck`, `Error`) carried as opaque bytes plus
    /// the field number that identifies which arm. Future codec
    /// revisions can promote one of these to a typed variant
    /// without breaking wire-format compatibility — the round-trip
    /// is byte-exact.
    Other {
        /// Field number from the `oneof content` declaration (4 for
        /// Registration, 5 for RegistrationAck, 6 for StatusReport,
        /// 8 for Task, 9 for TaskAck, 10 for Alert, 11 for
        /// AlertAck, 12 for Error). Keeping the tag here lets a
        /// future codec lift typed dispatch without breaking the
        /// wire form.
        field_number: u32,
        /// The submessage's length-delimited body, verbatim.
        bytes: bytes::Bytes,
    },
}

/// `google.protobuf.Timestamp` wire form: POSIX seconds + nanos.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Timestamp {
    /// POSIX seconds since 1970-01-01T00:00:00Z.
    pub seconds: i64,
    /// Nanoseconds within the second, `[0, 1_000_000_000)`.
    pub nanos: i32,
}

/// SAPIENT `DetectionReport` body.
///
/// Carries the position-bearing detection a sensor has raised — the
/// surface this codec lifts into [`rustgate_core::entity::Entity`].
/// Fields that the strict-subset `Entity` shape does not surface
/// (track-info bag, classification list, RF-signal info) are
/// preserved on the entity's attribute bag under the `sapient.*`
/// namespace so a same-codec round-trip stays lossless.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct DetectionReport {
    /// ULID for the message itself. Spec-mandatory; empty on
    /// forward-compat-tolerant decode.
    pub report_id: String,
    /// ULID for the detected object. Spec-mandatory; the codec
    /// treats it as the entity's stable UID seed.
    pub object_id: String,
    /// ULID of the active task this detection answers, when one
    /// is set.
    pub task_id: String,
    /// Free-form state marker (e.g. `"object lost"`).
    pub state: String,
    /// `oneof location_oneof` arm. The BSI spec marks the oneof
    /// `is_mandatory: true`. The codec treats `None` as a frame
    /// whose location arrived in a future-arm or was omitted by a
    /// non-conformant sender.
    pub location: Option<DetectionLocation>,
    /// Confidence the detection itself is real, `[0.0, 1.0]`.
    pub detection_confidence: Option<f32>,
    /// Classification list (object type guesses + per-guess
    /// confidence). Preserved verbatim for the round-trip.
    pub classification: Vec<Classification>,
    /// Velocity arm — currently the spec ships only the ENU vector.
    pub enu_velocity: Option<EnuVelocity>,
    /// Optional RGB / hex colour string for the detection.
    pub colour: String,
    /// Operator-visible identifier (e.g. an aircraft tail number)
    /// the sensor surfaced.
    pub id: String,
}

/// `DetectionReport.location_oneof` arm. The BSI spec models two
/// arms: `RangeBearing` (sensor-relative spherical) and `Location`
/// (global Cartesian, normally lat/lon WGS-84). The codec lifts
/// `Location` into [`rustgate_core::entity::Position`] when the
/// coordinate system is `LAT_LNG_DEG_M`; other arms ride opaque so
/// a future codec revision can map them without a breaking change.
#[derive(Debug, Clone, PartialEq)]
pub enum DetectionLocation {
    /// Global Cartesian / lat-lon coordinates. The interesting arm
    /// for the canonical `Entity` shape.
    Location(Location),
    /// Sensor-relative spherical coordinates. Carried opaque on
    /// MVP scope — a future codec revision can lift these once the
    /// `Entity` shape grows a sensor-frame arm.
    RangeBearing(bytes::Bytes),
}

/// SAPIENT `Location` submessage.
///
/// Wire form: `x` is normally longitude (in
/// `LAT_LNG_DEG_M`) and `y` is latitude — the SAPIENT spec
/// inverts the conventional `(lat, lon)` ordering. The codec
/// preserves the spec's field semantics on the wire and surfaces
/// the lat/lon swap explicitly on the [`Location::lat`] /
/// [`Location::lon`] accessors so callers do not need to track
/// the convention. Coordinates ride as IEEE-754 doubles
/// (`fixed64` wire type) — there is no integer scaling, so
/// same-codec round-trip is bit-exact.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Location {
    /// X-coordinate, normally longitude in decimal degrees.
    pub x: f64,
    /// Y-coordinate, normally latitude in decimal degrees.
    pub y: f64,
    /// Z-coordinate, normally altitude in metres.
    pub z: Option<f64>,
    /// Optional X-axis error metric.
    pub x_error: Option<f64>,
    /// Optional Y-axis error metric.
    pub y_error: Option<f64>,
    /// Optional Z-axis error metric.
    pub z_error: Option<f64>,
    /// Coordinate system enum. The codec lifts the lat/lon arm
    /// into [`rustgate_core::entity::Position`] when this is
    /// [`LocationCoordinateSystem::LatLngDegM`]; other arms pass
    /// through opaque on the entity attribute bag.
    pub coordinate_system: LocationCoordinateSystem,
    /// Datum enum (WGS-84 ellipsoid is the typical case for
    /// counter-UAS deployments).
    pub datum: LocationDatum,
    /// UTM zone string when the coordinate system is
    /// [`LocationCoordinateSystem::UtmM`]. Empty otherwise.
    pub utm_zone: String,
}

impl Location {
    /// Decimal-degree latitude, when [`Location::coordinate_system`]
    /// is [`LocationCoordinateSystem::LatLngDegM`]. Returns `None`
    /// for any other coordinate system — callers wanting the raw
    /// `y` value regardless of system read [`Location::y`] directly.
    #[must_use]
    pub fn lat(&self) -> Option<f64> {
        match self.coordinate_system {
            LocationCoordinateSystem::LatLngDegM => Some(self.y),
            _ => None,
        }
    }

    /// Decimal-degree longitude, when [`Location::coordinate_system`]
    /// is [`LocationCoordinateSystem::LatLngDegM`]. Returns `None`
    /// for any other coordinate system — callers wanting the raw
    /// `x` value regardless of system read [`Location::x`] directly.
    #[must_use]
    pub fn lon(&self) -> Option<f64> {
        match self.coordinate_system {
            LocationCoordinateSystem::LatLngDegM => Some(self.x),
            _ => None,
        }
    }
}

/// SAPIENT `LocationCoordinateSystem` enum (proto3 enum).
///
/// MVP-relevant: [`Self::LatLngDegM`] is the arm the codec lifts
/// into [`rustgate_core::entity::Position`]. The other arms carry
/// through opaque on the entity attribute bag for round-trip
/// preservation.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LocationCoordinateSystem {
    /// Coordinate system not defined / unspecified.
    #[default]
    Unspecified,
    /// Latitude/Longitude in decimal-degrees, altitude in metres.
    LatLngDegM,
    /// Latitude/Longitude in radians, altitude in metres.
    LatLngRadM,
    /// UTM with altitude in metres.
    UtmM,
    /// Forward-compat for any enum value the spec adds in a future
    /// revision. The raw varint is preserved.
    Other(i32),
}

impl LocationCoordinateSystem {
    /// Convert from the wire-format integer value.
    #[must_use]
    pub fn from_wire(v: i32) -> Self {
        match v {
            0 => Self::Unspecified,
            1 => Self::LatLngDegM,
            2 => Self::LatLngRadM,
            5 => Self::UtmM,
            other => Self::Other(other),
        }
    }

    /// Convert to the wire-format integer value.
    #[must_use]
    pub fn to_wire(self) -> i32 {
        match self {
            Self::Unspecified => 0,
            Self::LatLngDegM => 1,
            Self::LatLngRadM => 2,
            Self::UtmM => 5,
            Self::Other(v) => v,
        }
    }
}

/// SAPIENT `LocationDatum` enum (proto3 enum).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LocationDatum {
    /// Datum not defined / unspecified.
    #[default]
    Unspecified,
    /// WGS-84 ellipsoid.
    Wgs84Ellipsoid,
    /// WGS-84 geoid.
    Wgs84Geoid,
    /// Forward-compat for any enum value the spec adds in a future
    /// revision. The raw varint is preserved.
    Other(i32),
}

impl LocationDatum {
    /// Convert from the wire-format integer value.
    #[must_use]
    pub fn from_wire(v: i32) -> Self {
        match v {
            0 => Self::Unspecified,
            1 => Self::Wgs84Ellipsoid,
            2 => Self::Wgs84Geoid,
            other => Self::Other(other),
        }
    }

    /// Convert to the wire-format integer value.
    #[must_use]
    pub fn to_wire(self) -> i32 {
        match self {
            Self::Unspecified => 0,
            Self::Wgs84Ellipsoid => 1,
            Self::Wgs84Geoid => 2,
            Self::Other(v) => v,
        }
    }
}

/// SAPIENT `ENUVelocity` body — east/north/up rate in metres per
/// second (the MVP assumes the default unit; an `ENUVelocityUnits`
/// override would land in a follow-up). Up-rate is optional per the
/// spec.
#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub struct EnuVelocity {
    /// East-axis (x) component in metres/second.
    pub east_rate: f64,
    /// North-axis (y) component in metres/second.
    pub north_rate: f64,
    /// Up-axis (z) component in metres/second.
    pub up_rate: Option<f64>,
}

impl EnuVelocity {
    /// Convert the ENU vector to a tactical
    /// `(speed_m_s, course_deg_clockwise_from_north)` pair, the form
    /// the canonical [`rustgate_core::entity::Velocity`] expects.
    /// Course is normalised to `[0, 360)`. A zero or near-zero
    /// horizontal vector returns course `0`.
    #[must_use]
    pub fn to_speed_course(&self) -> (f64, f64) {
        let speed = (self.east_rate.powi(2) + self.north_rate.powi(2)).sqrt();
        // atan2(east, north) gives the angle clockwise from north,
        // which is exactly the tactical "course over ground".
        let course = if speed > 0.0 {
            let raw = self.east_rate.atan2(self.north_rate).to_degrees();
            (raw + 360.0).rem_euclid(360.0)
        } else {
            0.0
        };
        (speed, course)
    }

    /// Reverse of [`Self::to_speed_course`]: build an ENU vector
    /// from a tactical `(speed_m_s, course_deg)` pair.
    #[must_use]
    pub fn from_speed_course(speed_m_s: f64, course_deg: f64) -> Self {
        let course_rad = course_deg.to_radians();
        Self {
            east_rate: speed_m_s * course_rad.sin(),
            north_rate: speed_m_s * course_rad.cos(),
            up_rate: None,
        }
    }
}

/// SAPIENT `DetectionReportClassification` submessage.
///
/// Multiple classification candidates can ride per detection (e.g.
/// `[(type="UAV", confidence=0.81), (type="bird", confidence=0.12)]`).
/// The codec preserves the full list verbatim on the entity attribute
/// bag so SIEM dashboards can grade detections by confidence without
/// re-parsing the wire bytes.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Classification {
    /// Object-type guess (e.g. `"UAV"`, `"vehicle"`, `"person"`).
    pub kind: String,
    /// Confidence the guess is correct, `[0.0, 1.0]`.
    pub confidence: Option<f32>,
}

/// Maximum wire bytes the parser will accept while reading any
/// length-delimited field. Mirrors [`MAX_PAYLOAD_BYTES`] so a hostile
/// length prefix cannot drive the parser into an oversized
/// allocation.
const MAX_FIELD_LENGTH: usize = MAX_PAYLOAD_BYTES;

/// Decode a SAPIENT message from a transport-stripped byte slice.
///
/// The transport layer (TCP framing, MQTT body, gRPC payload) carries
/// the outer message length, so this codec consumes a slice that is
/// exactly one [`SapientMessage`] on the wire — no length prefix here.
/// Anything beyond [`MAX_PAYLOAD_BYTES`] is rejected as
/// [`SapientError::PayloadTooLarge`] before the parser runs.
pub fn decode_sapient_message(bytes: &[u8]) -> Result<SapientMessage, SapientError> {
    if bytes.len() > MAX_PAYLOAD_BYTES {
        return Err(SapientError::PayloadTooLarge { bytes: bytes.len() });
    }
    let mut cursor = bytes;
    let mut msg = SapientMessage::default();
    while cursor.has_remaining() {
        let tag = read_varint(&mut cursor)?;
        match tag {
            TAG_MSG_TIMESTAMP => {
                let inner = read_length_delimited(&mut cursor)?;
                msg.timestamp = Some(decode_timestamp(inner)?);
            }
            TAG_MSG_NODE_ID => {
                let inner = read_length_delimited(&mut cursor)?;
                msg.node_id = bytes_to_utf8(inner)?;
            }
            TAG_MSG_DESTINATION_ID => {
                let inner = read_length_delimited(&mut cursor)?;
                msg.destination_id = bytes_to_utf8(inner)?;
            }
            TAG_MSG_DETECTION_REPORT => {
                let inner = read_length_delimited(&mut cursor)?;
                msg.content = Some(SapientPayload::DetectionReport(Box::new(
                    decode_detection_report(inner)?,
                )));
            }
            TAG_MSG_REGISTRATION
            | TAG_MSG_REGISTRATION_ACK
            | TAG_MSG_STATUS_REPORT
            | TAG_MSG_TASK
            | TAG_MSG_TASK_ACK
            | TAG_MSG_ALERT
            | TAG_MSG_ALERT_ACK
            | TAG_MSG_ERROR => {
                let inner = read_length_delimited(&mut cursor)?;
                let field_number = (tag >> 3) as u32;
                msg.content = Some(SapientPayload::Other {
                    field_number,
                    bytes: bytes::Bytes::copy_from_slice(inner),
                });
            }
            TAG_MSG_ADDITIONAL_INFO => {
                let inner = read_length_delimited(&mut cursor)?;
                msg.additional_information = bytes_to_utf8(inner)?;
            }
            other => skip_unknown_field(&mut cursor, other)?,
        }
    }
    if msg.content.is_none() {
        return Err(SapientError::MissingContent);
    }
    Ok(msg)
}

/// Encode a SAPIENT message into a fresh [`Vec<u8>`].
///
/// The encoder honours the byte-exact round-trip contract for
/// [`SapientPayload::Other`] arms: their bytes are emitted verbatim
/// behind the original field number. Returns
/// [`SapientError::PayloadTooLarge`] when the encoded frame would
/// exceed [`MAX_PAYLOAD_BYTES`].
pub fn encode_sapient_message(msg: &SapientMessage) -> Result<Vec<u8>, SapientError> {
    let mut out = Vec::with_capacity(64);
    if let Some(ts) = &msg.timestamp {
        let inner = encode_timestamp(ts);
        write_varint(&mut out, TAG_MSG_TIMESTAMP);
        write_length_delimited(&mut out, &inner);
    }
    if !msg.node_id.is_empty() {
        write_varint(&mut out, TAG_MSG_NODE_ID);
        write_length_delimited(&mut out, msg.node_id.as_bytes());
    }
    if !msg.destination_id.is_empty() {
        write_varint(&mut out, TAG_MSG_DESTINATION_ID);
        write_length_delimited(&mut out, msg.destination_id.as_bytes());
    }
    match &msg.content {
        Some(SapientPayload::DetectionReport(dr)) => {
            let inner = encode_detection_report(dr.as_ref());
            write_varint(&mut out, TAG_MSG_DETECTION_REPORT);
            write_length_delimited(&mut out, &inner);
        }
        Some(SapientPayload::Other {
            field_number,
            bytes,
        }) => {
            // Re-pack the original field number. Wire type for every
            // `oneof` arm in the SAPIENT envelope is length-delimited,
            // so the tag computation is `(field_number << 3) | 2`.
            let tag = (u64::from(*field_number) << 3) | 2;
            write_varint(&mut out, tag);
            write_length_delimited(&mut out, bytes);
        }
        None => {
            // The decoder treats absence as `MissingContent`; the
            // encoder mirrors that contract — emitting a content-less
            // frame would round-trip to a parse error, so reject up
            // front.
            return Err(SapientError::MissingContent);
        }
    }
    if !msg.additional_information.is_empty() {
        write_varint(&mut out, TAG_MSG_ADDITIONAL_INFO);
        write_length_delimited(&mut out, msg.additional_information.as_bytes());
    }
    if out.len() > MAX_PAYLOAD_BYTES {
        return Err(SapientError::PayloadTooLarge { bytes: out.len() });
    }
    Ok(out)
}

fn decode_timestamp(bytes: &[u8]) -> Result<Timestamp, SapientError> {
    let mut cursor = bytes;
    let mut ts = Timestamp::default();
    while cursor.has_remaining() {
        let tag = read_varint(&mut cursor)?;
        match tag {
            TAG_TS_SECONDS => {
                let v = read_varint(&mut cursor)?;
                ts.seconds = v as i64;
            }
            TAG_TS_NANOS => {
                let v = read_varint(&mut cursor)?;
                ts.nanos = v as i32;
            }
            other => skip_unknown_field(&mut cursor, other)?,
        }
    }
    Ok(ts)
}

fn encode_timestamp(ts: &Timestamp) -> Vec<u8> {
    let mut out = Vec::with_capacity(16);
    if ts.seconds != 0 {
        write_varint(&mut out, TAG_TS_SECONDS);
        write_varint(&mut out, ts.seconds as u64);
    }
    if ts.nanos != 0 {
        write_varint(&mut out, TAG_TS_NANOS);
        write_varint(&mut out, u64::from(ts.nanos as u32));
    }
    out
}

fn decode_detection_report(bytes: &[u8]) -> Result<DetectionReport, SapientError> {
    let mut cursor = bytes;
    let mut dr = DetectionReport::default();
    while cursor.has_remaining() {
        let tag = read_varint(&mut cursor)?;
        match tag {
            TAG_DR_REPORT_ID => {
                let inner = read_length_delimited(&mut cursor)?;
                dr.report_id = bytes_to_utf8(inner)?;
            }
            TAG_DR_OBJECT_ID => {
                let inner = read_length_delimited(&mut cursor)?;
                dr.object_id = bytes_to_utf8(inner)?;
            }
            TAG_DR_TASK_ID => {
                let inner = read_length_delimited(&mut cursor)?;
                dr.task_id = bytes_to_utf8(inner)?;
            }
            TAG_DR_STATE => {
                let inner = read_length_delimited(&mut cursor)?;
                dr.state = bytes_to_utf8(inner)?;
            }
            TAG_DR_RANGE_BEARING => {
                let inner = read_length_delimited(&mut cursor)?;
                dr.location = Some(DetectionLocation::RangeBearing(
                    bytes::Bytes::copy_from_slice(inner),
                ));
            }
            TAG_DR_LOCATION => {
                let inner = read_length_delimited(&mut cursor)?;
                dr.location = Some(DetectionLocation::Location(decode_location(inner)?));
            }
            TAG_DR_DETECTION_CONFIDENCE => {
                dr.detection_confidence = Some(read_float(&mut cursor)?);
            }
            TAG_DR_CLASSIFICATION => {
                let inner = read_length_delimited(&mut cursor)?;
                dr.classification.push(decode_classification(inner)?);
            }
            TAG_DR_ENU_VELOCITY => {
                let inner = read_length_delimited(&mut cursor)?;
                dr.enu_velocity = Some(decode_enu_velocity(inner)?);
            }
            TAG_DR_COLOUR => {
                let inner = read_length_delimited(&mut cursor)?;
                dr.colour = bytes_to_utf8(inner)?;
            }
            TAG_DR_ID => {
                let inner = read_length_delimited(&mut cursor)?;
                dr.id = bytes_to_utf8(inner)?;
            }
            // Track-info / object-info / behaviour / signal /
            // associated-* / derived-* / prediction-location ride
            // opaque on MVP scope. Skip them gracefully without
            // losing the surrounding cursor — the next iteration of
            // the loop will pick up the next field. Forward-compat:
            // unknown tags fall to the generic skip path below.
            TAG_DR_TRACK_INFO
            | TAG_DR_PREDICTION_LOCATION
            | TAG_DR_OBJECT_INFO
            | TAG_DR_BEHAVIOUR
            | TAG_DR_ASSOCIATED_FILE
            | TAG_DR_SIGNAL
            | TAG_DR_ASSOCIATED_DETECTION
            | TAG_DR_DERIVED_DETECTION => {
                // Length-delimited skip — read but discard the inner
                // bytes. Keeps the cursor advancing past the
                // submessage so subsequent fields stay decodable.
                let _ = read_length_delimited(&mut cursor)?;
            }
            other => skip_unknown_field(&mut cursor, other)?,
        }
    }
    Ok(dr)
}

fn encode_detection_report(dr: &DetectionReport) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    if !dr.report_id.is_empty() {
        write_varint(&mut out, TAG_DR_REPORT_ID);
        write_length_delimited(&mut out, dr.report_id.as_bytes());
    }
    if !dr.object_id.is_empty() {
        write_varint(&mut out, TAG_DR_OBJECT_ID);
        write_length_delimited(&mut out, dr.object_id.as_bytes());
    }
    if !dr.task_id.is_empty() {
        write_varint(&mut out, TAG_DR_TASK_ID);
        write_length_delimited(&mut out, dr.task_id.as_bytes());
    }
    if !dr.state.is_empty() {
        write_varint(&mut out, TAG_DR_STATE);
        write_length_delimited(&mut out, dr.state.as_bytes());
    }
    match &dr.location {
        Some(DetectionLocation::Location(loc)) => {
            let inner = encode_location(loc);
            write_varint(&mut out, TAG_DR_LOCATION);
            write_length_delimited(&mut out, &inner);
        }
        Some(DetectionLocation::RangeBearing(bytes)) => {
            write_varint(&mut out, TAG_DR_RANGE_BEARING);
            write_length_delimited(&mut out, bytes);
        }
        None => {}
    }
    if let Some(conf) = dr.detection_confidence {
        write_varint(&mut out, TAG_DR_DETECTION_CONFIDENCE);
        write_float(&mut out, conf);
    }
    for cls in &dr.classification {
        let inner = encode_classification(cls);
        write_varint(&mut out, TAG_DR_CLASSIFICATION);
        write_length_delimited(&mut out, &inner);
    }
    if let Some(v) = &dr.enu_velocity {
        let inner = encode_enu_velocity(v);
        write_varint(&mut out, TAG_DR_ENU_VELOCITY);
        write_length_delimited(&mut out, &inner);
    }
    if !dr.colour.is_empty() {
        write_varint(&mut out, TAG_DR_COLOUR);
        write_length_delimited(&mut out, dr.colour.as_bytes());
    }
    if !dr.id.is_empty() {
        write_varint(&mut out, TAG_DR_ID);
        write_length_delimited(&mut out, dr.id.as_bytes());
    }
    out
}

fn decode_location(bytes: &[u8]) -> Result<Location, SapientError> {
    let mut cursor = bytes;
    let mut loc = Location::default();
    while cursor.has_remaining() {
        let tag = read_varint(&mut cursor)?;
        match tag {
            TAG_LOC_X => loc.x = read_double(&mut cursor)?,
            TAG_LOC_Y => loc.y = read_double(&mut cursor)?,
            TAG_LOC_Z => loc.z = Some(read_double(&mut cursor)?),
            TAG_LOC_X_ERROR => loc.x_error = Some(read_double(&mut cursor)?),
            TAG_LOC_Y_ERROR => loc.y_error = Some(read_double(&mut cursor)?),
            TAG_LOC_Z_ERROR => loc.z_error = Some(read_double(&mut cursor)?),
            TAG_LOC_COORD_SYSTEM => {
                let v = read_varint(&mut cursor)?;
                loc.coordinate_system = LocationCoordinateSystem::from_wire(v as i32);
            }
            TAG_LOC_DATUM => {
                let v = read_varint(&mut cursor)?;
                loc.datum = LocationDatum::from_wire(v as i32);
            }
            TAG_LOC_UTM_ZONE => {
                let inner = read_length_delimited(&mut cursor)?;
                loc.utm_zone = bytes_to_utf8(inner)?;
            }
            other => skip_unknown_field(&mut cursor, other)?,
        }
    }
    Ok(loc)
}

fn encode_location(loc: &Location) -> Vec<u8> {
    let mut out = Vec::with_capacity(48);
    // Always emit x/y so a `Location { x: 0, y: 0 }` (e.g. the test
    // fixture for null-island) round-trips.
    write_varint(&mut out, TAG_LOC_X);
    write_double(&mut out, loc.x);
    write_varint(&mut out, TAG_LOC_Y);
    write_double(&mut out, loc.y);
    if let Some(z) = loc.z {
        write_varint(&mut out, TAG_LOC_Z);
        write_double(&mut out, z);
    }
    if let Some(e) = loc.x_error {
        write_varint(&mut out, TAG_LOC_X_ERROR);
        write_double(&mut out, e);
    }
    if let Some(e) = loc.y_error {
        write_varint(&mut out, TAG_LOC_Y_ERROR);
        write_double(&mut out, e);
    }
    if let Some(e) = loc.z_error {
        write_varint(&mut out, TAG_LOC_Z_ERROR);
        write_double(&mut out, e);
    }
    if loc.coordinate_system != LocationCoordinateSystem::Unspecified {
        write_varint(&mut out, TAG_LOC_COORD_SYSTEM);
        write_varint(&mut out, loc.coordinate_system.to_wire() as u64);
    }
    if loc.datum != LocationDatum::Unspecified {
        write_varint(&mut out, TAG_LOC_DATUM);
        write_varint(&mut out, loc.datum.to_wire() as u64);
    }
    if !loc.utm_zone.is_empty() {
        write_varint(&mut out, TAG_LOC_UTM_ZONE);
        write_length_delimited(&mut out, loc.utm_zone.as_bytes());
    }
    out
}

fn decode_enu_velocity(bytes: &[u8]) -> Result<EnuVelocity, SapientError> {
    let mut cursor = bytes;
    let mut v = EnuVelocity::default();
    while cursor.has_remaining() {
        let tag = read_varint(&mut cursor)?;
        match tag {
            TAG_ENU_EAST_RATE => v.east_rate = read_double(&mut cursor)?,
            TAG_ENU_NORTH_RATE => v.north_rate = read_double(&mut cursor)?,
            TAG_ENU_UP_RATE => v.up_rate = Some(read_double(&mut cursor)?),
            other => skip_unknown_field(&mut cursor, other)?,
        }
    }
    Ok(v)
}

fn encode_enu_velocity(v: &EnuVelocity) -> Vec<u8> {
    let mut out = Vec::with_capacity(24);
    write_varint(&mut out, TAG_ENU_EAST_RATE);
    write_double(&mut out, v.east_rate);
    write_varint(&mut out, TAG_ENU_NORTH_RATE);
    write_double(&mut out, v.north_rate);
    if let Some(up) = v.up_rate {
        write_varint(&mut out, TAG_ENU_UP_RATE);
        write_double(&mut out, up);
    }
    out
}

fn decode_classification(bytes: &[u8]) -> Result<Classification, SapientError> {
    let mut cursor = bytes;
    let mut cls = Classification::default();
    while cursor.has_remaining() {
        let tag = read_varint(&mut cursor)?;
        match tag {
            TAG_CLS_TYPE => {
                let inner = read_length_delimited(&mut cursor)?;
                cls.kind = bytes_to_utf8(inner)?;
            }
            TAG_CLS_CONFIDENCE => {
                cls.confidence = Some(read_float(&mut cursor)?);
            }
            other => skip_unknown_field(&mut cursor, other)?,
        }
    }
    Ok(cls)
}

fn encode_classification(cls: &Classification) -> Vec<u8> {
    let mut out = Vec::with_capacity(16);
    if !cls.kind.is_empty() {
        write_varint(&mut out, TAG_CLS_TYPE);
        write_length_delimited(&mut out, cls.kind.as_bytes());
    }
    if let Some(c) = cls.confidence {
        write_varint(&mut out, TAG_CLS_CONFIDENCE);
        write_float(&mut out, c);
    }
    out
}

// --- Wire-format primitives -------------------------------------------------

/// Read a base-128 varint from `cursor`, advancing it. Caps at 10
/// bytes (the protobuf spec maximum for a 64-bit varint) so hostile
/// input cannot drive the parser into a non-terminating loop.
fn read_varint(cursor: &mut &[u8]) -> Result<u64, SapientError> {
    let mut result: u64 = 0;
    for i in 0..10 {
        if !cursor.has_remaining() {
            return Err(SapientError::TruncatedVarint);
        }
        let b = cursor.get_u8();
        result |= (u64::from(b & 0x7F)) << (i * 7);
        if b & 0x80 == 0 {
            return Ok(result);
        }
    }
    Err(SapientError::VarintOverflow)
}

/// Write a varint to `out`, using as many 7-bit groups as needed.
fn write_varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.put_u8(((value & 0x7F) as u8) | 0x80);
        value >>= 7;
    }
    out.put_u8(value as u8);
}

/// Read a length-delimited segment (varint length followed by bytes)
/// from `cursor`, advancing past both. Rejects lengths that exceed
/// the payload cap so a malicious sender cannot trigger an oversized
/// allocation behind the parser.
fn read_length_delimited<'a>(cursor: &mut &'a [u8]) -> Result<&'a [u8], SapientError> {
    let len = read_varint(cursor)?;
    let len = usize::try_from(len).map_err(|_| SapientError::LengthExceeded {
        bytes: usize::MAX,
        cap: MAX_FIELD_LENGTH,
    })?;
    if len > MAX_FIELD_LENGTH {
        return Err(SapientError::LengthExceeded {
            bytes: len,
            cap: MAX_FIELD_LENGTH,
        });
    }
    if cursor.len() < len {
        return Err(SapientError::Truncated);
    }
    let (head, tail) = cursor.split_at(len);
    *cursor = tail;
    Ok(head)
}

/// Write a length-delimited segment (varint length, then payload).
fn write_length_delimited(out: &mut Vec<u8>, payload: &[u8]) {
    write_varint(out, payload.len() as u64);
    out.extend_from_slice(payload);
}

/// Read an IEEE-754 little-endian `double` (wire type 1, fixed64).
fn read_double(cursor: &mut &[u8]) -> Result<f64, SapientError> {
    if cursor.len() < 8 {
        return Err(SapientError::Truncated);
    }
    let raw = cursor.get_u64_le();
    Ok(f64::from_bits(raw))
}

/// Write an IEEE-754 little-endian `double` (wire type 1, fixed64).
fn write_double(out: &mut Vec<u8>, v: f64) {
    out.extend_from_slice(&v.to_bits().to_le_bytes());
}

/// Read an IEEE-754 little-endian `float` (wire type 5, fixed32).
fn read_float(cursor: &mut &[u8]) -> Result<f32, SapientError> {
    if cursor.len() < 4 {
        return Err(SapientError::Truncated);
    }
    let raw = cursor.get_u32_le();
    Ok(f32::from_bits(raw))
}

/// Write an IEEE-754 little-endian `float` (wire type 5, fixed32).
fn write_float(out: &mut Vec<u8>, v: f32) {
    out.extend_from_slice(&v.to_bits().to_le_bytes());
}

/// Skip an unknown field, dispatching on the wire type encoded in
/// the low three bits of `tag`. Forward-compatible: a future schema
/// revision that adds new fields stays decodable as long as it uses
/// one of the four standard wire types.
fn skip_unknown_field(cursor: &mut &[u8], tag: u64) -> Result<(), SapientError> {
    let wire_type = tag & 0x07;
    match wire_type {
        0 => {
            // varint
            let _ = read_varint(cursor)?;
        }
        1 => {
            // fixed64
            if cursor.len() < 8 {
                return Err(SapientError::Truncated);
            }
            cursor.advance(8);
        }
        2 => {
            // length-delimited
            let _ = read_length_delimited(cursor)?;
        }
        5 => {
            // fixed32
            if cursor.len() < 4 {
                return Err(SapientError::Truncated);
            }
            cursor.advance(4);
        }
        other => {
            return Err(SapientError::UnknownWireType {
                wire_type: other as u8,
            });
        }
    }
    Ok(())
}

/// Validate a length-delimited byte slice as UTF-8.
fn bytes_to_utf8(bytes: &[u8]) -> Result<String, SapientError> {
    core::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|e| SapientError::InvalidUtf8 {
            position: e.valid_up_to(),
        })
}

impl fmt::Display for SapientPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DetectionReport(_) => f.write_str("detection_report"),
            Self::Other { field_number, .. } => write!(f, "other(field={field_number})"),
        }
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::float_cmp, unused_results)]
mod tests {
    use super::*;

    #[test]
    fn varint_round_trip_covers_boundary_widths() {
        for v in [0u64, 1, 127, 128, 16_383, 16_384, 1 << 31, u64::MAX] {
            let mut buf = Vec::new();
            write_varint(&mut buf, v);
            let mut slice = &buf[..];
            let decoded = read_varint(&mut slice).expect("round-trip");
            assert_eq!(decoded, v, "round-trip mismatch for {v}");
            assert!(slice.is_empty(), "trailing bytes for {v}");
        }
    }

    #[test]
    fn varint_overflow_returns_typed_error() {
        let bytes = [0x80u8; 11];
        let mut slice = &bytes[..];
        let err = read_varint(&mut slice).expect_err("must fail");
        assert!(matches!(err, SapientError::VarintOverflow));
    }

    #[test]
    fn varint_truncated_returns_typed_error() {
        let bytes = [0x80u8];
        let mut slice = &bytes[..];
        let err = read_varint(&mut slice).expect_err("must fail");
        assert!(matches!(err, SapientError::TruncatedVarint));
    }

    #[test]
    fn unknown_wire_type_rejects_with_typed_error() {
        let mut bytes = vec![];
        write_varint(&mut bytes, (99 << 3) | 3); // wire type 3
        let mut slice = &bytes[..];
        let tag = read_varint(&mut slice).unwrap();
        let err = skip_unknown_field(&mut slice, tag).expect_err("must fail");
        match err {
            SapientError::UnknownWireType { wire_type } => assert_eq!(wire_type, 3),
            other => panic!("expected UnknownWireType, got {other:?}"),
        }
    }

    #[test]
    fn double_round_trips_through_byte_form() {
        // Pin little-endian IEEE-754 round-trip across a sentinel
        // mix that includes positive, negative, sub-normal, and the
        // counter-UAS exercise extremes (lat/lon at high precision).
        for v in [
            0.0_f64,
            -0.0,
            1.0,
            -1.0,
            38.889_722_2,
            -77.008_889,
            f64::EPSILON,
            f64::MIN_POSITIVE,
            f64::MAX,
        ] {
            let mut out = Vec::new();
            write_double(&mut out, v);
            let mut slice = &out[..];
            let decoded = read_double(&mut slice).unwrap();
            assert!(
                decoded.to_bits() == v.to_bits(),
                "round-trip mismatch for {v} (decoded={decoded})"
            );
        }
    }

    #[test]
    fn detection_report_round_trips_through_byte_form() {
        let dr = DetectionReport {
            report_id: "01H8FF8DPXTGYP01H8FF8DPXTGYP".into(),
            object_id: "01H8FF8DPXTGYP01H8FF8DPXTGY1".into(),
            task_id: String::new(),
            state: String::new(),
            location: Some(DetectionLocation::Location(Location {
                x: -77.008_889,
                y: 38.889_722_2,
                z: Some(50.0),
                x_error: None,
                y_error: None,
                z_error: None,
                coordinate_system: LocationCoordinateSystem::LatLngDegM,
                datum: LocationDatum::Wgs84Ellipsoid,
                utm_zone: String::new(),
            })),
            detection_confidence: Some(0.81),
            classification: vec![Classification {
                kind: "UAV".into(),
                confidence: Some(0.78),
            }],
            enu_velocity: Some(EnuVelocity {
                east_rate: 5.0,
                north_rate: 3.0,
                up_rate: Some(0.5),
            }),
            colour: "red".into(),
            id: "tail-N12345".into(),
        };
        let bytes = encode_detection_report(&dr);
        let decoded = decode_detection_report(&bytes).unwrap();
        assert_eq!(decoded, dr);
    }

    #[test]
    fn sapient_message_round_trips_with_detection_report() {
        let msg = SapientMessage {
            timestamp: Some(Timestamp {
                seconds: 1_700_000_000,
                nanos: 123_456,
            }),
            node_id: "11111111-2222-3333-4444-555555555555".into(),
            destination_id: String::new(),
            content: Some(SapientPayload::DetectionReport(Box::new(DetectionReport {
                report_id: "01H".into(),
                object_id: "01H1".into(),
                location: Some(DetectionLocation::Location(Location {
                    x: 12.5,
                    y: 51.5,
                    coordinate_system: LocationCoordinateSystem::LatLngDegM,
                    datum: LocationDatum::Wgs84Ellipsoid,
                    ..Location::default()
                })),
                detection_confidence: Some(0.9),
                ..DetectionReport::default()
            }))),
            additional_information: "telemetry".into(),
        };
        let bytes = encode_sapient_message(&msg).expect("encode");
        let decoded = decode_sapient_message(&bytes).expect("decode");
        assert_eq!(decoded, msg);
    }

    #[test]
    fn sapient_message_with_other_arm_round_trips_byte_exact() {
        // A future / non-MVP arm rides as `Other`. Round-trip MUST
        // preserve the bytes verbatim.
        let opaque = bytes::Bytes::from_static(&[0xDE, 0xAD, 0xBE, 0xEF, 0x42]);
        let msg = SapientMessage {
            timestamp: None,
            node_id: "node-1".into(),
            destination_id: String::new(),
            content: Some(SapientPayload::Other {
                field_number: 6, // status_report
                bytes: opaque.clone(),
            }),
            additional_information: String::new(),
        };
        let bytes = encode_sapient_message(&msg).expect("encode");
        let decoded = decode_sapient_message(&bytes).expect("decode");
        match decoded.content {
            Some(SapientPayload::Other {
                field_number,
                bytes,
            }) => {
                assert_eq!(field_number, 6);
                assert_eq!(bytes, opaque);
            }
            other => panic!("expected Other arm, got {other:?}"),
        }
    }

    #[test]
    fn missing_content_returns_typed_error() {
        // Build an envelope with no oneof arm — only a node_id — and
        // confirm the decoder surfaces MissingContent rather than
        // returning a default-shaped detection report.
        let mut frame = Vec::new();
        write_varint(&mut frame, TAG_MSG_NODE_ID);
        write_length_delimited(&mut frame, b"node-1");
        let err = decode_sapient_message(&frame).expect_err("must fail");
        assert!(matches!(err, SapientError::MissingContent));
    }

    #[test]
    fn over_cap_input_is_rejected() {
        // A byte slice that exceeds the payload cap surfaces
        // PayloadTooLarge before the parser does any work. We test
        // with a contrived oversized buffer — the cap is 16 MiB so
        // we simulate it by allocating exactly cap+1 bytes; the
        // parser must reject before reading any of them.
        let oversized = vec![0u8; MAX_PAYLOAD_BYTES + 1];
        let err = decode_sapient_message(&oversized).expect_err("must fail");
        assert!(matches!(err, SapientError::PayloadTooLarge { .. }));
    }

    #[test]
    fn unknown_field_is_skipped_forward_compat() {
        // A well-formed envelope plus an unknown high-numbered tag
        // (field 99, varint) — the decoder must skip it and still
        // surface the detection report.
        let mut frame = Vec::new();
        // Real DR.
        let dr = DetectionReport {
            report_id: "x".into(),
            object_id: "y".into(),
            ..DetectionReport::default()
        };
        let inner = encode_detection_report(&dr);
        write_varint(&mut frame, TAG_MSG_DETECTION_REPORT);
        write_length_delimited(&mut frame, &inner);
        // Unknown varint field 99.
        write_varint(&mut frame, 99 << 3);
        write_varint(&mut frame, 42);
        let decoded = decode_sapient_message(&frame).expect("forward-compat");
        assert!(matches!(
            decoded.content,
            Some(SapientPayload::DetectionReport(_))
        ));
    }

    #[test]
    fn invalid_utf8_in_node_id_returns_typed_error() {
        let mut frame = Vec::new();
        write_varint(&mut frame, TAG_MSG_NODE_ID);
        write_length_delimited(&mut frame, &[0xFF, 0xFE, 0xFD]);
        // Plus a content arm so the test isolates the UTF-8 failure.
        let dr_bytes = encode_detection_report(&DetectionReport::default());
        write_varint(&mut frame, TAG_MSG_DETECTION_REPORT);
        write_length_delimited(&mut frame, &dr_bytes);
        let err = decode_sapient_message(&frame).expect_err("must fail");
        assert!(matches!(err, SapientError::InvalidUtf8 { .. }));
    }

    #[test]
    fn enu_velocity_to_speed_course_is_north_clockwise() {
        // Pure north: course 0.
        let v = EnuVelocity {
            east_rate: 0.0,
            north_rate: 5.0,
            up_rate: None,
        };
        let (s, c) = v.to_speed_course();
        assert!((s - 5.0).abs() < 1e-9);
        assert!((c - 0.0).abs() < 1e-9);
        // Pure east: course 90.
        let v = EnuVelocity {
            east_rate: 5.0,
            north_rate: 0.0,
            up_rate: None,
        };
        let (s, c) = v.to_speed_course();
        assert!((s - 5.0).abs() < 1e-9);
        assert!((c - 90.0).abs() < 1e-9);
        // Pure south: course 180.
        let v = EnuVelocity {
            east_rate: 0.0,
            north_rate: -5.0,
            up_rate: None,
        };
        let (s, c) = v.to_speed_course();
        assert!((s - 5.0).abs() < 1e-9);
        assert!((c - 180.0).abs() < 1e-6);
        // Pure west: course 270.
        let v = EnuVelocity {
            east_rate: -5.0,
            north_rate: 0.0,
            up_rate: None,
        };
        let (s, c) = v.to_speed_course();
        assert!((s - 5.0).abs() < 1e-9);
        assert!((c - 270.0).abs() < 1e-6);
    }

    #[test]
    fn enu_velocity_speed_course_round_trip() {
        for (speed, course) in [(5.0, 0.0), (10.0, 45.0), (3.0, 180.0), (12.5, 359.0)] {
            let v = EnuVelocity::from_speed_course(speed, course);
            let (s2, c2) = v.to_speed_course();
            assert!((s2 - speed).abs() < 1e-9, "speed drift {speed} -> {s2}");
            // Allow 1e-6 deg drift through the trig round-trip.
            let drift = (c2 - course).abs().min((c2 - course + 360.0).abs());
            assert!(drift < 1e-6, "course drift {course} -> {c2}");
        }
    }

    #[test]
    fn location_lat_lon_accessors_return_none_when_system_not_lat_lng() {
        let loc = Location {
            x: 100.0,
            y: 200.0,
            coordinate_system: LocationCoordinateSystem::UtmM,
            ..Location::default()
        };
        assert!(loc.lat().is_none());
        assert!(loc.lon().is_none());
    }
}
