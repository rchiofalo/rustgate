// Copyright © 2026 Roberto Chiofalo.

//! Strict-subset wire types for the OGC SensorThings v1.0 REST API.
//!
//! The full SensorThings v1.0 schema covers nine entity types
//! (`Things`, `Datastreams`, `Sensors`, `ObservedProperties`,
//! `Observations`, `Locations`, `HistoricalLocations`,
//! `FeaturesOfInterest`, `MultiDatastreams`) with extensive
//! cross-references and a SensorML metadata layer. This module
//! intentionally models **only** the shapes the polling MVP
//! consumes:
//!
//! - [`Observation`] — a single measurement
//! - [`Datastream`] — the metadata for the stream the observation
//!   came from (used when the polling client requested
//!   `?$expand=Datastream`)
//! - [`Thing`] — the physical sensor station, used as the parent
//!   of `Locations` (when the polling client requested
//!   `?$expand=Datastream/Thing`)
//! - [`Location`] — the geospatial position. The MVP only
//!   understands GeoJSON `Point` geometries; everything else is
//!   carried opaque on the entity attribute bag.
//! - [`ObservationsPage`] — the wrapper a SensorThings server
//!   emits when responding to a list query (`@iot.count`,
//!   `@iot.nextLink`, `value` array).
//!
//! Extending the wire surface to additional fields is additive: add
//! the new field as an `Option<…>` with `#[serde(default)]` and the
//! existing call sites continue to compile.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A single SensorThings v1.0 `Observation` document.
///
/// The strict-subset fields the mapper consumes are typed; the rest
/// (e.g. `resultQuality`, `validTime`, `parameters`) ride on the
/// raw JSON `result` plus the `expanded_datastream` field, where
/// applicable. SensorThings places the canonical entity id under
/// `@iot.id` (a number) and the navigation URL under `@iot.selfLink`
/// — both are preserved so the mapper can synthesize a stable
/// `Entity::uid` and the audit trail can correlate against the
/// upstream SensorThings tenant.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct Observation {
    /// Server-assigned numeric id. SensorThings serializes this as
    /// an integer; the mapper synthesizes
    /// `Entity::uid = "sensorthings-observation-{id}"` from it.
    #[serde(rename = "@iot.id")]
    pub iot_id: i64,

    /// Self-referential URL — useful for audit correlation. Optional
    /// because some servers omit it.
    #[serde(rename = "@iot.selfLink", default)]
    pub iot_self_link: Option<String>,

    /// ISO 8601 timestamp of when the phenomenon was observed. The
    /// MVP carries this verbatim onto the entity attribute bag
    /// rather than parsing it — the entity's own `timestamp` field
    /// is set to the wall-clock at receipt time, so a downstream
    /// consumer that needs the originating instant reads it from
    /// `attributes.sensorthings.phenomenon_time`.
    #[serde(rename = "phenomenonTime")]
    pub phenomenon_time: String,

    /// Optional ISO 8601 timestamp recording when the value was
    /// computed by the server. Some sensor stacks set
    /// `resultTime == phenomenonTime`; others leave it null or set
    /// it to the time the measurement reached the SensorThings
    /// server.
    #[serde(rename = "resultTime", default)]
    pub result_time: Option<String>,

    /// The measurement value. SensorThings allows scalars (number,
    /// string, boolean) and structured shapes (object, array); the
    /// MVP carries it as an opaque [`serde_json::Value`] and
    /// stringifies on the entity attribute bag.
    pub result: Value,

    /// Datastream the observation belongs to — populated only when
    /// the polling URL included `?$expand=Datastream` (or
    /// `?$expand=Datastream/Thing/Locations`). Omitted otherwise.
    #[serde(rename = "Datastream", default)]
    pub expanded_datastream: Option<Datastream>,
}

/// A SensorThings v1.0 `Datastream` document — metadata for the
/// measurement stream an observation came from.
///
/// Only the fields the mapper actually projects onto an entity are
/// modelled: the numeric id (used for the entity's `uid` namespace),
/// the human-readable name (used as the entity callsign), and the
/// optional embedded `Thing` (which carries the `Location`).
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct Datastream {
    /// Server-assigned numeric id.
    #[serde(rename = "@iot.id")]
    pub iot_id: i64,
    /// Self-referential URL.
    #[serde(rename = "@iot.selfLink", default)]
    pub iot_self_link: Option<String>,
    /// Human-readable name — projected onto the entity callsign
    /// when present.
    #[serde(default)]
    pub name: Option<String>,
    /// Operator-readable description.
    #[serde(default)]
    pub description: Option<String>,
    /// Stringified `unitOfMeasurement.symbol`, when the upstream
    /// `unitOfMeasurement` object is shaped that way. The full
    /// `unitOfMeasurement` block is not modelled — the mapper
    /// looks for `unitOfMeasurement.symbol` and rides the rest
    /// opaque on the `attributes.sensorthings.*` bag.
    #[serde(rename = "unitOfMeasurement", default)]
    pub unit_of_measurement: Option<Value>,
    /// Embedded `Thing` — populated only when the polling URL
    /// included `?$expand=Datastream/Thing` or deeper.
    #[serde(rename = "Thing", default)]
    pub expanded_thing: Option<Thing>,
}

/// A SensorThings v1.0 `Thing` document — the physical sensor
/// station that owns the datastream.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct Thing {
    /// Server-assigned numeric id.
    #[serde(rename = "@iot.id")]
    pub iot_id: i64,
    /// Self-referential URL.
    #[serde(rename = "@iot.selfLink", default)]
    pub iot_self_link: Option<String>,
    /// Human-readable name.
    #[serde(default)]
    pub name: Option<String>,
    /// Operator-readable description.
    #[serde(default)]
    pub description: Option<String>,
    /// Embedded `Locations` array — populated only when the
    /// polling URL included `?$expand=Datastream/Thing/Locations`.
    /// The MVP picks the first entry in the array (SensorThings
    /// allows multiple but for fixed stations it is almost always
    /// length one).
    #[serde(rename = "Locations", default)]
    pub expanded_locations: Vec<Location>,
}

/// A SensorThings v1.0 `Location` document.
///
/// SensorThings models the `location` field as a polymorphic shape:
/// the operator declares `encodingType` (typically
/// `application/vnd.geo+json`) and `location` is then a GeoJSON
/// document. The MVP reads `location` as an opaque
/// [`serde_json::Value`] and the mapper extracts a lat/lon when the
/// shape is a GeoJSON `Point` (i.e. `{"type":"Point","coordinates":
/// [lon, lat]}`). All other shapes (`LineString`, `Polygon`,
/// `MultiPoint`, …) are valid wire-format but the MVP does not
/// project them onto the entity `position` field — they ride
/// opaque on the attribute bag.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct Location {
    /// Server-assigned numeric id.
    #[serde(rename = "@iot.id")]
    pub iot_id: i64,
    /// Self-referential URL.
    #[serde(rename = "@iot.selfLink", default)]
    pub iot_self_link: Option<String>,
    /// Human-readable name. Sometimes the only useful identifier
    /// on a `Location` document — fixed buoys often have a
    /// `name` like `"Bay 12 Met Tower"` and an empty `description`.
    #[serde(default)]
    pub name: Option<String>,
    /// SensorThings encoding type — typically
    /// `"application/vnd.geo+json"` for the GeoJSON path the MVP
    /// understands. Other encodings are valid wire-format but not
    /// projected onto the entity `position`.
    #[serde(rename = "encodingType", default)]
    pub encoding_type: Option<String>,
    /// Polymorphic location payload. The MVP reads the GeoJSON
    /// `Point` shape; everything else rides opaque.
    #[serde(default)]
    pub location: Option<Value>,
}

/// Wrapper a SensorThings server returns when responding to a
/// list-style query (e.g.
/// `…/Datastreams(N)/Observations?$top=100`).
///
/// The `value` array is the documents. `@iot.count` is the total
/// number of matches (servers MAY omit it on cost grounds).
/// `@iot.nextLink` is the URL of the next page, when pagination is
/// in play; the MVP polling client does not chase pagination — each
/// poll is one round trip and the per-poll bound is the
/// configured `?$top=` value.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ObservationsPage {
    /// Total count, when the server included one. The MVP polling
    /// client does not consume this — it is preserved for tests
    /// and future use.
    #[serde(rename = "@iot.count", default)]
    pub iot_count: Option<i64>,
    /// URL of the next page in a paginated result set. The MVP
    /// does not chase it — operators bias `?$top=` instead.
    #[serde(rename = "@iot.nextLink", default)]
    pub iot_next_link: Option<String>,
    /// The observations themselves.
    pub value: Vec<Observation>,
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn observation_round_trips_through_serde() {
        let json = r#"{
            "@iot.id": 12345,
            "@iot.selfLink": "https://example.org/SensorThings/v1.0/Observations(12345)",
            "phenomenonTime": "2026-05-08T10:30:00Z",
            "resultTime": "2026-05-08T10:30:01Z",
            "result": 23.5
        }"#;
        let obs: Observation = serde_json::from_str(json).expect("parse");
        assert_eq!(obs.iot_id, 12345);
        assert_eq!(obs.phenomenon_time, "2026-05-08T10:30:00Z");
        assert_eq!(
            obs.result_time.as_deref(),
            Some("2026-05-08T10:30:01Z"),
            "resultTime should round-trip when present"
        );
        assert_eq!(obs.result, serde_json::json!(23.5));
        assert!(
            obs.expanded_datastream.is_none(),
            "no Datastream when not expanded"
        );

        let re = serde_json::to_string(&obs).expect("re-serialize");
        let obs2: Observation = serde_json::from_str(&re).expect("re-parse");
        assert_eq!(obs, obs2);
    }

    #[test]
    fn observation_accepts_missing_optional_self_link() {
        // A few SensorThings server stacks omit `@iot.selfLink`. The
        // mapper does not depend on it; pin that decode succeeds.
        let json = r#"{
            "@iot.id": 1,
            "phenomenonTime": "2026-05-08T10:30:00Z",
            "result": "OK"
        }"#;
        let obs: Observation = serde_json::from_str(json).expect("parse");
        assert!(obs.iot_self_link.is_none());
        assert!(obs.result_time.is_none());
    }

    #[test]
    fn observations_page_decodes_canonical_shape() {
        let json = r#"{
            "@iot.count": 2,
            "@iot.nextLink": "https://example.org/.../Observations?$skip=2",
            "value": [
                { "@iot.id": 1, "phenomenonTime": "2026-05-08T10:30:00Z", "result": 1.0 },
                { "@iot.id": 2, "phenomenonTime": "2026-05-08T10:30:01Z", "result": 2.0 }
            ]
        }"#;
        let page: ObservationsPage = serde_json::from_str(json).expect("parse");
        assert_eq!(page.iot_count, Some(2));
        assert_eq!(page.value.len(), 2);
        assert_eq!(page.value[0].iot_id, 1);
        assert_eq!(page.value[1].iot_id, 2);
        assert!(page.iot_next_link.is_some());
    }

    #[test]
    fn observation_with_expanded_datastream_thing_locations_round_trips() {
        // Pin the deep-expand shape the MVP uses — a single round
        // trip pulls Datastream → Thing → Locations alongside each
        // observation so the mapper can resolve the lat/lon
        // without follow-up GETs. See client::poll for where the
        // expand string is composed.
        let json = r#"{
            "@iot.id": 7,
            "phenomenonTime": "2026-05-08T10:30:00Z",
            "result": 12.3,
            "Datastream": {
                "@iot.id": 42,
                "name": "Air Temperature",
                "description": "outdoor air temp at met tower #5",
                "unitOfMeasurement": { "symbol": "degC", "name": "degree Celsius" },
                "Thing": {
                    "@iot.id": 99,
                    "name": "Met Tower 5",
                    "description": "fixed met tower at Pier 9",
                    "Locations": [
                        {
                            "@iot.id": 1001,
                            "name": "Pier 9",
                            "encodingType": "application/vnd.geo+json",
                            "location": {
                                "type": "Point",
                                "coordinates": [-77.0365, 38.8977]
                            }
                        }
                    ]
                }
            }
        }"#;
        let obs: Observation = serde_json::from_str(json).expect("parse");
        let ds = obs.expanded_datastream.expect("Datastream expanded");
        assert_eq!(ds.iot_id, 42);
        assert_eq!(ds.name.as_deref(), Some("Air Temperature"));
        let thing = ds.expanded_thing.expect("Thing expanded");
        assert_eq!(thing.iot_id, 99);
        assert_eq!(thing.expanded_locations.len(), 1);
        assert_eq!(
            thing.expanded_locations[0].encoding_type.as_deref(),
            Some("application/vnd.geo+json")
        );
        let geom = thing.expanded_locations[0]
            .location
            .as_ref()
            .expect("location payload present");
        assert_eq!(geom["type"], serde_json::json!("Point"));
        assert_eq!(geom["coordinates"][0], serde_json::json!(-77.0365));
        assert_eq!(geom["coordinates"][1], serde_json::json!(38.8977));
    }

    #[test]
    fn observation_with_string_result_decodes() {
        // Sensors that report enumerated states (`"OK"`, `"FAULT"`)
        // emit string `result` values. Pin the decode path so the
        // generic `serde_json::Value` carry stays correct.
        let json = r#"{
            "@iot.id": 1,
            "phenomenonTime": "2026-05-08T10:30:00Z",
            "result": "OK"
        }"#;
        let obs: Observation = serde_json::from_str(json).expect("parse");
        assert_eq!(obs.result, serde_json::json!("OK"));
    }

    #[test]
    fn observation_with_array_result_decodes() {
        // SensorThings allows the `result` to be a JSON array (e.g.
        // a vector observation like wind `[u, v]`). Pin that the
        // shape rides through opaque.
        let json = r#"{
            "@iot.id": 1,
            "phenomenonTime": "2026-05-08T10:30:00Z",
            "result": [3.1, 4.2]
        }"#;
        let obs: Observation = serde_json::from_str(json).expect("parse");
        assert_eq!(obs.result, serde_json::json!([3.1, 4.2]));
    }
}
