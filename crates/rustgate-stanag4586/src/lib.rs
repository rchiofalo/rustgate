// Copyright © 2026 Roberto Chiofalo.

//! STANAG 4586 telemetry codec for NATO UAS interoperability.
//!
//! STANAG 4586 ("Standard Interfaces of UAV Control System (UCS) for
//! NATO UAV Interoperability") defines the message set used by Ground
//! Control Stations (GCS) and Vehicle Specific Modules (VSM) to talk
//! to Unmanned Aerial Systems across vendor boundaries. The standard
//! is organised around five Levels of Interoperability (LOI):
//!
//! - **LOI 1** — indirect receipt of payload data (no UCS interaction)
//! - **LOI 2** — direct receipt of payload data (telemetry passthrough)
//! - **LOI 3** — control and monitoring of the UAV payload (sensor pointing)
//! - **LOI 4** — control and monitoring of the UAV itself (waypoint upload)
//! - **LOI 5** — full UAV launch / recovery responsibility
//!
//! This crate implements **LOI 2-3 telemetry** — the inbound vehicle
//! state stream that any LOI 2 deployment needs to display, log, and
//! relay — plus the **first three LOI 4 commands** (waypoint upload
//! via [`waypoint_command`], sensor pointing via
//! [`sensor_pointing_command`], and mission abort via
//! [`mission_abort_command`]). The remainder of the LOI 4 command
//! set (GCS handover, payload control, route upload) is deliberately
//! out of scope and lands in follow-up PRs.
//!
//! # Scope
//!
//! - [`vehicle_position::VehiclePosition`] — the most common LOI 2-3
//!   telemetry frame: lat/lon/alt, ground speed, heading, flight
//!   state, vehicle id, and a Unix-millis timestamp.
//! - [`vehicle_position::FlightState`] — the discrete vehicle states
//!   the spec enumerates for the `flight_state` field, plus a
//!   forward-compatible [`FlightState::Other`] catch-all so a future
//!   firmware revision that emits a state byte we do not yet
//!   recognise survives the decoder rather than being rejected.
//! - [`vehicle_position::encode`] /
//!   [`vehicle_position::decode`] — symmetric round-trip: every
//!   typed field is preserved across `decode(encode(v)) == v`,
//!   pinned by a property test.
//!
//! # What is deliberately absent
//!
//! - **Remaining LOI 4+ command messages** (GCS handover, payload
//!   control, route upload) — separate follow-up PRs. The first
//!   three LOI 4 commands (waypoint upload via [`waypoint_command`],
//!   sensor pointing via [`sensor_pointing_command`], and mission
//!   abort via [`mission_abort_command`]) ship in this crate.
//! - **Other LOI 2-3 telemetry message types** beyond vehicle
//!   position — sensor status, payload status, system state, BIT
//!   reports. Those use the same big-endian/typed-field approach but
//!   each ships with its own fixture set, so they are sequenced as
//!   independent PRs.
//! - **UDP/TCP listener wiring.** This crate is pure encode/decode
//!   over `&[u8]`; the network glue (mirroring how
//!   [`rustgate-mavlink`](../rustgate_mavlink/index.html) gets a
//!   listener in a follow-up to its codec PR) is a separate change.
//! - **MAVLink wrapping.** Some small UAS platforms encapsulate
//!   STANAG 4586 over MAVLink rather than running native; the
//!   wrapper layer is a follow-up that depends on both this crate
//!   and `rustgate-mavlink`. This PR ships the native wire format
//!   only.
//!
//! # Spec accessibility caveat
//!
//! The full STANAG 4586 specification is NATO-restricted and not
//! publicly distributed. The wire layout used here mirrors the
//! publicly documented vehicle-state telemetry structure (field set
//! and ordering as cited in NATO UCS interoperability technical
//! references and open-source vendor implementations) using NATO's
//! standard big-endian byte order. Specific byte offsets are
//! documented inline in [`vehicle_position`] so a deployment that
//! has access to the controlled spec can verify each field against
//! their authoritative copy. See `CHANGELOG.md` for the full
//! provenance note.

#![doc(html_no_source)]

pub mod bit_report;
pub mod error;
pub mod mission_abort_command;
pub mod payload_status;
pub mod sensor_pointing_command;
pub mod sensor_status;
pub mod system_state;
pub mod vehicle_position;
pub mod waypoint_command;

pub use bit_report::{BitReport, FaultSeverity, SubsystemId};
pub use error::Stanag4586Error;
pub use mission_abort_command::{AbortBehaviour, MissionAbortCommand, Priority};
pub use payload_status::{PayloadKind, PayloadStatus, RecordingState, StreamingState};
pub use sensor_pointing_command::{PointingMode, SensorPointingCommand};
pub use sensor_status::{OperationalState, SensorStatus, SensorType};
pub use system_state::{BitStatusFlags, MissionPhase, OperatingMode, SystemState};
pub use vehicle_position::{FlightState, VehiclePosition};
pub use waypoint_command::{CommandKind, WaypointCommand};
