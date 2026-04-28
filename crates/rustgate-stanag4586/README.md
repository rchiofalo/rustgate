# rustgate-stanag4586

STANAG 4586 LOI 2-3 telemetry codec for NATO UAS interoperability.

## Role in the workspace

`rustgate-stanag4586` is a pure encode/decode library over `&[u8]` for the
NATO STANAG 4586 ("Standard Interfaces of UAV Control System (UCS) for NATO
UAV Interoperability") message set. It depends on nothing else in the
workspace — only `bytes` and `thiserror` — so it stays a drop-in codec
that the eventual session layer (UDP / TCP listener wiring) can drive
without forcing a transport dependency back here. The MAVLink-wrapped
variant lives in a follow-up PR that depends on both this crate and
[rustgate-mavlink](../rustgate-mavlink/README.md).

## Public API surface

- `vehicle_position::{VehiclePosition, FlightState, encode, decode}` —
  the most common LOI 2-3 inbound telemetry frame: lat / lon / alt,
  ground speed, heading, flight state, vehicle id, Unix-millis timestamp;
  symmetric round-trip pinned by a property test
- `sensor_status::{SensorStatus, SensorType, OperationalState}` — sensor
  health and operational state telemetry
- `payload_status::{PayloadStatus, PayloadKind, RecordingState, StreamingState}` —
  payload state telemetry (camera / EO-IR / SIGINT)
- `system_state::{SystemState, OperatingMode, MissionPhase, BitStatusFlags}` —
  system-level state telemetry
- `bit_report::{BitReport, FaultSeverity, SubsystemId}` — built-in test
  reports for fault diagnosis
- LOI 4 commands: `waypoint_command::{WaypointCommand, CommandKind}`,
  `sensor_pointing_command::{SensorPointingCommand, PointingMode}`,
  `mission_abort_command::{MissionAbortCommand, AbortBehaviour, Priority}`,
  `gcs_handover_command::{GcsHandoverCommand, HandoverKind}`,
  `route_upload_command::{RouteUploadCommand, RouteKind, MAX_ROUTE_WAYPOINTS}`,
  `payload_control_command::{PayloadControlCommand, ControlAction, QualityPreset}`,
  `emergency_status_request::{EmergencyStatusRequest, RequestKind, UrgencyLevel}`,
  `payload_calibration_command::{PayloadCalibrationCommand, CalibrationKind, Mode}`
- `error::Stanag4586Error` — typed error enum for decode failures

## Feature flags

_None._

## Topology / deployment notes

The crate is encode/decode only; UDP / TCP listener wiring is a separate
PR (mirroring how [rustgate-mavlink](../rustgate-mavlink/README.md) gets
its listener after the codec PR). The full STANAG 4586 specification is
NATO-restricted and not publicly distributed; the wire layout used here
mirrors the publicly documented vehicle-state structure and ordering
cited in NATO UCS interoperability technical references and open-source
vendor implementations, in NATO's standard big-endian byte order.
Specific byte offsets are documented inline in each module so a
deployment with access to the controlled spec can verify each field
against their authoritative copy.

## Where to look first

- `crates/rustgate-stanag4586/src/vehicle_position.rs` — the highest-rate
  telemetry frame and the round-trip property test that pins decode/encode
  symmetry
- `crates/rustgate-stanag4586/src/lib.rs` — module map, LOI scope, and
  the spec-accessibility caveat
