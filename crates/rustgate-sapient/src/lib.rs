// Copyright © 2026 Roberto Chiofalo.

//! SAPIENT (BSI Flex 335) autonomous-sensor-network protobuf codec.
//!
//! SAPIENT — *Sensors for Asset Protection using Integrated
//! Electronic Networked Technology* — is the UK MOD/Dstl interface
//! standard adopted across NATO for counter-UAS, perimeter-security,
//! and autonomous-sensor exchange. Since v2.0 (March 2024) the
//! standard is published as BSI Flex 335 with open-source protobuf
//! schemas at <https://github.com/dstl/SAPIENT-Proto-Files> under
//! Crown Copyright.
//!
//! This crate ships a pure encode/decode library for that wire form.
//! The transport layer (TCP / MQTT / gRPC bridge) lives elsewhere —
//! this crate accepts a `&[u8]` payload and emits / decodes a
//! [`crate::proto::SapientMessage`] without any I/O. The crate also
//! implements the canonical [`rustgate_core::entity::EntityCodec`]
//! trait so the router can fan an entity out across SAPIENT
//! alongside CoT XML, MAVLink, ASTERIX, STANAG-4586, Meshtastic,
//! VMF, and DIS.
//!
//! # Wire-format summary (BSI Flex 335 v2.0)
//!
//! ```text
//! SapientMessage {                        // ≤ 16 MiB defense-in-depth cap
//!     1 google.protobuf.Timestamp timestamp
//!     2 string                    node_id           (UUID)
//!     3 string                    destination_id    (UUID, optional)
//!     // oneof content (mandatory):
//!     4  Registration     registration
//!     5  RegistrationAck  registration_ack
//!     6  StatusReport     status_report
//!     7  DetectionReport  detection_report   // <-- fully decoded
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
//!     2  string  object_id (ULID)         // entity UID seed
//!     3  string  task_id (ULID)
//!     4  string  state
//!     // oneof location_oneof (mandatory):
//!     5  RangeBearing     range_bearing
//!     6  Location         location          // <-- preferred lat/lon arm
//!     7  float            detection_confidence
//!     11 DetectionReportClassification (repeated)
//!     19 ENUVelocity      enu_velocity
//!     22 string           colour
//!     23 string           id
//! }
//! ```
//!
//! Coordinate fields ride as IEEE-754 doubles (no integer scaling),
//! so same-codec round-trip is bit-exact for every wire-format scalar.
//!
//! # MVP scope
//!
//! - **Fully decoded:** [`proto::SapientMessage`] envelope with
//!   every header field plus the `oneof content` discriminator,
//!   and the [`proto::DetectionReport`] arm with location,
//!   classification list, and ENU velocity.
//! - **Carried opaque (round-trip preserving):** every other
//!   `oneof content` arm — `Registration`, `RegistrationAck`,
//!   `StatusReport`, `Task`, `TaskAck`, `Alert`, `AlertAck`, and
//!   `Error` — rides as [`proto::SapientPayload::Other`] with the
//!   field-number tag preserved. The encoder honours `Other`
//!   symmetrically so a future codec revision can lift typed
//!   dispatch without breaking the wire form.
//! - **Carried opaque inside DetectionReport:**
//!   `track_info`, `object_info`, `behaviour`, `signal`,
//!   `prediction_location`, `associated_file`,
//!   `associated_detection`, and `derived_detection` skip cleanly
//!   on the read side; the canonical `Entity` shape does not
//!   surface them. A follow-up can lift any of these without a
//!   breaking change at the codec boundary.
//!
//! # Forward compatibility
//!
//! Unknown protobuf fields are skipped by wire type (varint /
//! length-delimited / fixed32 / fixed64) so a future BSI Flex 335
//! revision that adds new fields stays decodable. Varint overflow
//! (>10 bytes), unknown wire types (3, 4, 6, 7), invalid UTF-8 in
//! string fields, and length-delimited prefixes that exceed the
//! payload cap surface as typed [`error::SapientError`] variants
//! rather than panicking.
//!
//! # What is deliberately absent
//!
//! - **Transport binding.** SAPIENT transports — TCP framing,
//!   MQTT topic envelope, gRPC body — are the responsibility of a
//!   listener crate. This codec consumes / emits the inner
//!   `SapientMessage` payload only.
//! - **Other content arms.** `Registration`, `StatusReport`,
//!   `Task`, `TaskAck`, `Alert`, `AlertAck`, `Error` decode/encode
//!   to typed structs — out of scope for the MVP. They round-trip
//!   verbatim through [`proto::SapientPayload::Other`] but do not
//!   produce typed access today.
//! - **Validation against `proto_options` annotations.** The BSI
//!   Flex 335 schema annotates fields with `is_mandatory`,
//!   `is_uuid`, `is_ulid` semantic markers. This codec treats
//!   those as documentary — a `node_id` value that is not a
//!   well-formed UUID is decoded but not rejected. Strict
//!   validation belongs in a follow-up policy layer.
//! - **`ENUVelocityUnits` honour.** The MVP assumes the SI default
//!   (m/s) for ENU velocity scalars. A frame that overrides the
//!   units via `ENUVelocityUnits` will be accepted but the
//!   speed/course conversion will assume m/s. A follow-up can
//!   thread units through.
//!
//! # Error handling
//!
//! This crate's error type is [`error::SapientError`]; binary
//! callers propagate it via `?` and map it through `anyhow::Error`
//! at the orchestration layer. The
//! `rustgate_core::error::RustgateError` boundary aggregator (used
//! in the `rustgate-core` / `rustgate-transport` slice) is not
//! automatically constructed from [`error::SapientError`].

#![forbid(unsafe_code)]
#![doc(html_no_source)]

pub mod codec;
pub mod error;
pub mod proto;

pub use codec::SapientCodec;
pub use error::SapientError;
pub use proto::{
    Classification, DetectionLocation, DetectionReport, EnuVelocity, Location,
    LocationCoordinateSystem, LocationDatum, MAX_PAYLOAD_BYTES, SAPIENT_FIELD_DETECTION_REPORT,
    SapientMessage, SapientPayload, Timestamp, decode_sapient_message, encode_sapient_message,
};
