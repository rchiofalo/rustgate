// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

#![no_main]
#![allow(clippy::panic, clippy::unwrap_used)]

//! Fuzz the OGC SensorThings v1.0 Observation / ObservationsPage
//! JSON decoder.
//!
//! The polling client deserialises every HTTP response from a
//! configured SensorThings endpoint via `serde_json::from_slice` into
//! `ObservationsPage`. The endpoints are commonly third-party (city
//! IoT pilots, weather networks, partner sensor cooperatives) and
//! therefore lower-trust than the rustgate-internal codecs. A panic
//! in deserialisation is a remote DoS reachable from any
//! SensorThings server the operator subscribes to.
//!
//! # Why this surface earns a fuzzer
//!
//! - `serde_json` itself is hardened against the classic JSON
//!   pitfalls (deeply nested objects panic with a typed error, not
//!   stack overflow up to the documented `recursion_limit`), but
//!   the **`serde` derive on the typed structs** introduces its
//!   own failure modes: a `Vec<Observation>` whose elements
//!   individually deserialise but whose total memory exceeds the
//!   configured limits (no limits today — the polling MVP relies
//!   on the upstream `?$top=` cap), an `@iot.id` field declared
//!   `i64` but received as a string with a numeric value, etc.
//!   The fuzzer can also surface non-canonical UTF-8 bytes in
//!   attribute strings.
//! - The `result` field is `serde_json::Value` (opaque
//!   passthrough); arbitrary nested structures, including
//!   floating-point edge cases (NaN-as-string, Infinity-as-string,
//!   numbers whose magnitude exceeds `f64::MAX`), must
//!   deserialise to a `Value::Number` without panic. The
//!   downstream `mapper::observation_to_entity` re-interprets
//!   `result` for the entity attribute bag; that path is not
//!   fuzzed here directly but a panic at the deserialisation
//!   boundary would block it from running at all.
//! - Floats in the SensorThings spec are mostly bounded (lat/lon,
//!   altitude, speed) but the wire format does not enforce
//!   bounds; a NaN or infinity flowing through `feature.geometry`
//!   in an expanded `Datastream` must deserialise without panic
//!   even if the downstream entity-conversion later surfaces a
//!   typed error.
//!
//! # Failure modes the fuzzer would catch
//!
//! - A deeply nested `result` object exceeding the serde recursion
//!   limit — must surface as `serde_json::Error`, not panic.
//! - A `value` array whose element count is inconsistent with the
//!   `@iot.count` field — must deserialise; coherence is the
//!   caller's job.
//! - A `phenomenonTime` field with a non-string value (e.g.
//!   `null`, an integer) — must surface as a typed
//!   `serde_json::Error` rather than panic.
//! - Non-UTF-8 bytes inside string fields (since `from_slice`
//!   validates UTF-8 lazily during string deserialisation) — must
//!   surface as a typed error.
//!
//! The fuzz target is a single-shot decode; only the absence of a
//! panic / sanitiser complaint matters. Both shapes (single
//! `Observation` and the `ObservationsPage` wrapper) are exercised
//! so that wrapper-vs-element type confusion does not slip through.

use libfuzzer_sys::fuzz_target;
use rustgate_ogc_sensorthings::{Observation, ObservationsPage};

fuzz_target!(|data: &[u8]| {
    // Try both deserialisation shapes — a hostile server could send
    // either a top-level Observation or a paginated wrapper, and the
    // polling client deserialises the wrapper while the test fixtures
    // exercise the bare Observation.
    let _ = serde_json::from_slice::<ObservationsPage>(data);
    let _ = serde_json::from_slice::<Observation>(data);
});
