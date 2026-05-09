// Copyright © 2026 Roberto Chiofalo.

#![no_main]
#![allow(clippy::panic, clippy::unwrap_used)]

//! Fuzz the SAPIENT (DSTL Generic Sensor Interface) message decoder.
//!
//! `rustgate_sapient::decode_sapient_message` accepts an arbitrary
//! byte slice and returns a typed `SapientMessage` or a
//! `SapientError`. SAPIENT messages arrive over MQTT, gRPC, or raw
//! TCP from autonomous-sensor edge nodes; every payload runs through
//! the codec before any sensor-fusion or routing decision, so a
//! panic here is reachable from any compromised sensor on the
//! coalition network.
//!
//! # Why this surface earns a fuzzer
//!
//! - Like the Meshtastic codec, SAPIENT uses a **hand-rolled
//!   protobuf** parser (no `prost`); varint, length-delimited, and
//!   nested-submessage handling are all in scope for the same kind
//!   of regressions Meshtastic could hit (truncated varint chains,
//!   over-declared length prefixes, unknown wire types). The two
//!   codecs share the failure modes but live in different crates
//!   with different copy-pasted helper code, so a fuzzer pass on
//!   one does not cover the other.
//! - The `content` field is a tagged-union `oneof` with seven arms
//!   (DetectionReport, StatusReport, TaskRequest, …). The MVP only
//!   types `DetectionReport`; the other six arms ride as opaque
//!   `SapientPayload::Other { field_number, bytes }`. A regression
//!   in the dispatch that mis-classified a `DetectionReport` as
//!   `Other` would not panic, but a regression that walked the
//!   body of a non-DetectionReport tag through the typed
//!   DetectionReport parser would.
//! - The nested DetectionReport carries a `Location` with a
//!   coordinate-system enum and a datum enum; arbitrary bytes
//!   reinterpreted as enum tags must surface as a typed
//!   `SapientError::UnknownEnumValue` — never as an
//!   `unreachable!()` panic on the dispatch arm.
//! - The `confidence: f64` fields take arbitrary IEEE-754 doubles;
//!   NaN / infinity / subnormal must flow through without panicking
//!   the entity-conversion path that uses these in arithmetic.
//!
//! # Failure modes the fuzzer would catch
//!
//! - A varint continuation chain that exceeds 10 bytes (must return
//!   `TruncatedVarint`, not panic).
//! - A length-delimited submessage whose declared length exceeds
//!   the remaining buffer (must return `Truncated`, not panic at
//!   the slice).
//! - A tag with `wire_type = 6` or `7` (reserved/unused) not
//!   surfaced as `UnknownWireType` and instead falling through to
//!   a default arm with no cursor advance (would burn CPU in an
//!   infinite loop).
//!
//! The fuzz target is a single-shot decode; only the absence of a
//! panic / sanitiser complaint matters.

use libfuzzer_sys::fuzz_target;
use rustgate_sapient::decode_sapient_message;

fuzz_target!(|data: &[u8]| {
    let _ = decode_sapient_message(data);
});
