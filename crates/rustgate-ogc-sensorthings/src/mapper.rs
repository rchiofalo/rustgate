// Copyright © 2026 Roberto Chiofalo.

//! Mapping from a SensorThings v1.0 [`Observation`] to a canonical
//! [`rustgate_core::entity::Entity`].
//!
//! The mapping is **lossy by design** — only the strict subset of
//! SensorThings fields the router and downstream codecs can usefully
//! act on are projected onto the typed entity slots. The full
//! upstream JSON is preserved on the entity attribute bag under the
//! `sensorthings.*` namespace so an audit consumer that needs the
//! original document can recover everything that mattered.
//!
//! # What gets projected
//!
//! - `Observation.@iot.id` → `Entity::uid` (as
//!   `"sensorthings-observation-{id}"`).
//! - `Observation.Datastream.Thing.Locations[0].location` →
//!   `Entity::position` when the `location` is a GeoJSON `Point`
//!   with a 2-element `coordinates` array `[lon, lat]` (or
//!   3-element `[lon, lat, alt]`). Other GeoJSON shapes ride opaque.
//! - `Observation.Datastream.name` →  `Entity::callsign` when
//!   present.
//! - `Observation.phenomenonTime` →
//!   `attributes.sensorthings.phenomenon_time` (as a string — the
//!   mapper does not parse it; the wall-clock at receipt is the
//!   `Entity::timestamp`).
//! - `Observation.result` →
//!   `attributes.sensorthings.result` when scalar (string / number /
//!   bool); `attributes.sensorthings.result_json` (stringified) when
//!   the result is an object or array.
//! - `Observation.Datastream.@iot.id` →
//!   `attributes.sensorthings.datastream_id`.
//! - `Observation.Datastream.unitOfMeasurement.symbol` →
//!   `attributes.sensorthings.unit_symbol` when the `unitOfMeasurement`
//!   block is shaped like that.
//! - `Observation.Datastream.Thing.@iot.id` →
//!   `attributes.sensorthings.thing_id`.
//! - `Observation.Datastream.Thing.name` →
//!   `attributes.sensorthings.thing_name`.
//! - `Observation.@iot.selfLink` →
//!   `attributes.sensorthings.self_link` when present.
//!
//! # `EntityKind`
//!
//! The caller passes the
//! [`rustgate_core::entity::EntityKind`] explicitly (defaulting to
//! [`EntityKind::Sensor`] at the wiring layer). SensorThings does
//! not classify observations; the kind is a deployment decision.

use std::collections::BTreeMap;
use std::time::SystemTime;

use rustgate_core::entity::{AttributeValue, Entity, EntityKind, Position};

use crate::types::{Datastream, Location, Observation, Thing};

/// Project an [`Observation`] onto a canonical
/// [`Entity`] with the configured [`EntityKind`].
///
/// The function is pure — no I/O, no allocation beyond the entity
/// itself, no panics on malformed input. Fields the SensorThings
/// document omits (everything outside the strict subset) ride
/// opaque on the attribute bag; downstream consumers that need
/// the full upstream document fetch it via the
/// `attributes.sensorthings.self_link` URL.
pub fn observation_to_entity(observation: &Observation, kind: EntityKind) -> Entity {
    let mut attributes: BTreeMap<String, AttributeValue> = BTreeMap::new();

    let _ = attributes.insert(
        "sensorthings.observation_id".into(),
        AttributeValue::Int(observation.iot_id),
    );
    let _ = attributes.insert(
        "sensorthings.phenomenon_time".into(),
        AttributeValue::Str(observation.phenomenon_time.clone()),
    );
    if let Some(rt) = observation.result_time.as_ref() {
        let _ = attributes.insert(
            "sensorthings.result_time".into(),
            AttributeValue::Str(rt.clone()),
        );
    }
    if let Some(link) = observation.iot_self_link.as_ref() {
        let _ = attributes.insert(
            "sensorthings.self_link".into(),
            AttributeValue::Str(link.clone()),
        );
    }

    project_result(&observation.result, &mut attributes);

    let mut callsign: Option<String> = None;
    let mut position: Option<Position> = None;
    if let Some(ds) = observation.expanded_datastream.as_ref() {
        project_datastream(ds, &mut attributes, &mut callsign, &mut position);
    }

    Entity {
        uid: format!("sensorthings-observation-{}", observation.iot_id),
        kind,
        position,
        velocity: None,
        timestamp: SystemTime::now(),
        callsign,
        mil_std_2525_sidc: None,
        attributes,
    }
}

/// Project the `result` field onto the attribute bag. Scalars carry
/// as their typed [`AttributeValue`] variant; structured shapes
/// (object, array) ride as a stringified JSON value under
/// `sensorthings.result_json`.
fn project_result(result: &serde_json::Value, attributes: &mut BTreeMap<String, AttributeValue>) {
    match result {
        serde_json::Value::Null => {
            // Some sensors emit explicit nulls when they cannot
            // measure (e.g. an out-of-water buoy). Carry the null
            // signal as an attribute so a downstream filter can
            // distinguish "no value" from "value not in this
            // observation".
            let _ = attributes.insert(
                "sensorthings.result_null".into(),
                AttributeValue::Bool(true),
            );
        }
        serde_json::Value::Bool(b) => {
            let _ = attributes.insert("sensorthings.result".into(), AttributeValue::Bool(*b));
        }
        serde_json::Value::Number(n) => {
            // Integer-shaped numbers ride as `Int`; floats ride as
            // `Float`. SensorThings does not constrain the shape;
            // both variants are valid for downstream consumption.
            if let Some(i) = n.as_i64() {
                let _ = attributes.insert("sensorthings.result".into(), AttributeValue::Int(i));
            } else if let Some(f) = n.as_f64() {
                let _ = attributes.insert("sensorthings.result".into(), AttributeValue::Float(f));
            } else {
                // Unrepresentable number (e.g. very large u64 with
                // no f64 round trip) — preserve the lexical form.
                let _ = attributes.insert(
                    "sensorthings.result".into(),
                    AttributeValue::Str(n.to_string()),
                );
            }
        }
        serde_json::Value::String(s) => {
            let _ = attributes.insert("sensorthings.result".into(), AttributeValue::Str(s.clone()));
        }
        serde_json::Value::Array(_) | serde_json::Value::Object(_) => {
            // Vector / structured shapes ride as a JSON string. The
            // attribute-bag is a flat map; codecs that need
            // structured projection flatten the JSON themselves.
            let _ = attributes.insert(
                "sensorthings.result_json".into(),
                AttributeValue::Str(result.to_string()),
            );
        }
    }
}

/// Project the expanded `Datastream` onto the entity. The
/// `Datastream.@iot.id`, `name`, and `unitOfMeasurement.symbol`
/// fields populate attributes; the `name` doubles as the entity
/// callsign when present.
fn project_datastream(
    ds: &Datastream,
    attributes: &mut BTreeMap<String, AttributeValue>,
    callsign: &mut Option<String>,
    position: &mut Option<Position>,
) {
    let _ = attributes.insert(
        "sensorthings.datastream_id".into(),
        AttributeValue::Int(ds.iot_id),
    );
    if let Some(name) = ds.name.as_ref() {
        *callsign = Some(name.clone());
        let _ = attributes.insert(
            "sensorthings.datastream_name".into(),
            AttributeValue::Str(name.clone()),
        );
    }
    if let Some(desc) = ds.description.as_ref() {
        let _ = attributes.insert(
            "sensorthings.datastream_description".into(),
            AttributeValue::Str(desc.clone()),
        );
    }
    if let Some(uom) = ds.unit_of_measurement.as_ref() {
        if let Some(symbol) = uom.get("symbol").and_then(|v| v.as_str()) {
            let _ = attributes.insert(
                "sensorthings.unit_symbol".into(),
                AttributeValue::Str(symbol.to_string()),
            );
        }
        if let Some(name) = uom.get("name").and_then(|v| v.as_str()) {
            let _ = attributes.insert(
                "sensorthings.unit_name".into(),
                AttributeValue::Str(name.to_string()),
            );
        }
    }
    if let Some(thing) = ds.expanded_thing.as_ref() {
        project_thing(thing, attributes, position);
    }
}

/// Project the expanded `Thing` onto the entity. The `Thing.@iot.id`
/// and `name` populate attributes; the first `Locations` entry
/// drives the entity `position` field when its `location` is a
/// GeoJSON `Point`.
fn project_thing(
    thing: &Thing,
    attributes: &mut BTreeMap<String, AttributeValue>,
    position: &mut Option<Position>,
) {
    let _ = attributes.insert(
        "sensorthings.thing_id".into(),
        AttributeValue::Int(thing.iot_id),
    );
    if let Some(name) = thing.name.as_ref() {
        let _ = attributes.insert(
            "sensorthings.thing_name".into(),
            AttributeValue::Str(name.clone()),
        );
    }
    if let Some(desc) = thing.description.as_ref() {
        let _ = attributes.insert(
            "sensorthings.thing_description".into(),
            AttributeValue::Str(desc.clone()),
        );
    }

    if let Some(first) = thing.expanded_locations.first()
        && let Some(pos) = location_to_position(first, attributes)
    {
        *position = Some(pos);
    }
}

/// Project the first `Location` document onto an
/// [`rustgate_core::entity::Position`] when its `location` payload
/// is a GeoJSON `Point` shape with valid coordinates.
///
/// SensorThings allows arbitrary GeoJSON in `Location.location`;
/// the MVP only understands `Point`. Other shapes (`LineString`,
/// `Polygon`, `MultiPoint`, …) ride opaque under
/// `sensorthings.location_geojson` so a downstream consumer that
/// understands the richer shape can recover it.
fn location_to_position(
    loc: &Location,
    attributes: &mut BTreeMap<String, AttributeValue>,
) -> Option<Position> {
    let _ = attributes.insert(
        "sensorthings.location_id".into(),
        AttributeValue::Int(loc.iot_id),
    );
    if let Some(name) = loc.name.as_ref() {
        let _ = attributes.insert(
            "sensorthings.location_name".into(),
            AttributeValue::Str(name.clone()),
        );
    }
    if let Some(encoding) = loc.encoding_type.as_ref() {
        let _ = attributes.insert(
            "sensorthings.location_encoding".into(),
            AttributeValue::Str(encoding.clone()),
        );
    }
    let geom = loc.location.as_ref()?;
    let _ = attributes.insert(
        "sensorthings.location_geojson".into(),
        AttributeValue::Str(geom.to_string()),
    );

    let geom_type = geom.get("type")?.as_str()?;
    if geom_type != "Point" {
        // Non-Point shapes ride opaque on the attribute bag — the
        // entity position stays `None`.
        return None;
    }
    let coords = geom.get("coordinates")?.as_array()?;
    if coords.len() < 2 {
        return None;
    }
    let lon = coords.first()?.as_f64()?;
    let lat = coords.get(1)?.as_f64()?;

    if !(-90.0..=90.0).contains(&lat) || !(-180.0..=180.0).contains(&lon) {
        // Out-of-range coordinates — log via the wiring's tracing
        // path is not available here (this is a pure function);
        // return `None` so the position field stays empty rather
        // than carrying a poisoned value into the rest of the
        // workspace.
        return None;
    }

    let hae_meters = coords.get(2).and_then(|v| v.as_f64());
    Some(Position {
        lat,
        lon,
        hae_meters,
    })
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::types::{Datastream, Location, Observation, Thing};

    fn observation_with_full_expand() -> Observation {
        serde_json::from_str(
            r#"{
                "@iot.id": 7,
                "@iot.selfLink": "https://example.org/SensorThings/v1.0/Observations(7)",
                "phenomenonTime": "2026-05-08T10:30:00Z",
                "resultTime": "2026-05-08T10:30:01Z",
                "result": 23.5,
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
                                    "coordinates": [-77.0365, 38.8977, 12.5]
                                }
                            }
                        ]
                    }
                }
            }"#,
        )
        .expect("parse")
    }

    #[test]
    fn expanded_observation_projects_full_strict_subset() {
        let obs = observation_with_full_expand();
        let entity = observation_to_entity(&obs, EntityKind::Sensor);

        assert_eq!(entity.uid, "sensorthings-observation-7");
        assert_eq!(entity.kind, EntityKind::Sensor);
        assert_eq!(entity.callsign.as_deref(), Some("Air Temperature"));

        let pos = entity.position.expect("position projected");
        assert!((pos.lat - 38.8977).abs() < 1e-9, "lat must round-trip");
        assert!((pos.lon - (-77.0365)).abs() < 1e-9, "lon must round-trip");
        assert_eq!(pos.hae_meters, Some(12.5));

        // attribute bag spot-checks
        assert_eq!(
            entity.attributes.get("sensorthings.observation_id"),
            Some(&AttributeValue::Int(7))
        );
        assert_eq!(
            entity.attributes.get("sensorthings.datastream_id"),
            Some(&AttributeValue::Int(42))
        );
        assert_eq!(
            entity.attributes.get("sensorthings.thing_id"),
            Some(&AttributeValue::Int(99))
        );
        assert_eq!(
            entity.attributes.get("sensorthings.unit_symbol"),
            Some(&AttributeValue::Str("degC".into()))
        );
        assert_eq!(
            entity.attributes.get("sensorthings.phenomenon_time"),
            Some(&AttributeValue::Str("2026-05-08T10:30:00Z".into()))
        );
        assert_eq!(
            entity.attributes.get("sensorthings.result_time"),
            Some(&AttributeValue::Str("2026-05-08T10:30:01Z".into()))
        );
        assert!(
            entity.attributes.contains_key("sensorthings.self_link"),
            "self_link should be preserved when present"
        );

        // Float result rides as Float.
        match entity.attributes.get("sensorthings.result") {
            Some(AttributeValue::Float(f)) => assert!((f - 23.5).abs() < 1e-9),
            other => panic!("expected float result, got {:?}", other),
        }
    }

    #[test]
    fn observation_without_expand_produces_position_none_callsign_none() {
        let obs: Observation = serde_json::from_str(
            r#"{
                "@iot.id": 1,
                "phenomenonTime": "2026-05-08T10:30:00Z",
                "result": 1.0
            }"#,
        )
        .expect("parse");
        let entity = observation_to_entity(&obs, EntityKind::Sensor);
        assert_eq!(entity.uid, "sensorthings-observation-1");
        assert!(entity.position.is_none());
        assert!(entity.callsign.is_none());
        assert!(
            entity
                .attributes
                .contains_key("sensorthings.observation_id"),
            "observation id is always set"
        );
    }

    #[test]
    fn integer_result_carries_as_int_attribute() {
        let obs: Observation = serde_json::from_str(
            r#"{
                "@iot.id": 1,
                "phenomenonTime": "2026-05-08T10:30:00Z",
                "result": 42
            }"#,
        )
        .expect("parse");
        let entity = observation_to_entity(&obs, EntityKind::Sensor);
        assert_eq!(
            entity.attributes.get("sensorthings.result"),
            Some(&AttributeValue::Int(42))
        );
    }

    #[test]
    fn string_result_carries_as_str_attribute() {
        let obs: Observation = serde_json::from_str(
            r#"{
                "@iot.id": 1,
                "phenomenonTime": "2026-05-08T10:30:00Z",
                "result": "OK"
            }"#,
        )
        .expect("parse");
        let entity = observation_to_entity(&obs, EntityKind::Sensor);
        assert_eq!(
            entity.attributes.get("sensorthings.result"),
            Some(&AttributeValue::Str("OK".into()))
        );
    }

    #[test]
    fn boolean_result_carries_as_bool_attribute() {
        let obs: Observation = serde_json::from_str(
            r#"{
                "@iot.id": 1,
                "phenomenonTime": "2026-05-08T10:30:00Z",
                "result": false
            }"#,
        )
        .expect("parse");
        let entity = observation_to_entity(&obs, EntityKind::Sensor);
        assert_eq!(
            entity.attributes.get("sensorthings.result"),
            Some(&AttributeValue::Bool(false))
        );
    }

    #[test]
    fn array_result_carries_as_result_json_string() {
        let obs: Observation = serde_json::from_str(
            r#"{
                "@iot.id": 1,
                "phenomenonTime": "2026-05-08T10:30:00Z",
                "result": [3.1, 4.2]
            }"#,
        )
        .expect("parse");
        let entity = observation_to_entity(&obs, EntityKind::Sensor);
        assert!(!entity.attributes.contains_key("sensorthings.result"));
        match entity.attributes.get("sensorthings.result_json") {
            Some(AttributeValue::Str(s)) => {
                assert!(s.contains("3.1"));
                assert!(s.contains("4.2"));
            }
            other => panic!("expected stringified JSON, got {:?}", other),
        }
    }

    #[test]
    fn null_result_carries_as_result_null_attribute() {
        let obs: Observation = serde_json::from_str(
            r#"{
                "@iot.id": 1,
                "phenomenonTime": "2026-05-08T10:30:00Z",
                "result": null
            }"#,
        )
        .expect("parse");
        let entity = observation_to_entity(&obs, EntityKind::Sensor);
        assert_eq!(
            entity.attributes.get("sensorthings.result_null"),
            Some(&AttributeValue::Bool(true))
        );
        assert!(!entity.attributes.contains_key("sensorthings.result"));
    }

    #[test]
    fn non_point_geojson_does_not_populate_position() {
        // GeoJSON LineString rides opaque; the entity position
        // stays `None` and the raw GeoJSON is preserved on the
        // attribute bag.
        let obs: Observation = serde_json::from_str(
            r#"{
                "@iot.id": 1,
                "phenomenonTime": "2026-05-08T10:30:00Z",
                "result": 1.0,
                "Datastream": {
                    "@iot.id": 1,
                    "Thing": {
                        "@iot.id": 1,
                        "Locations": [
                            {
                                "@iot.id": 1,
                                "encodingType": "application/vnd.geo+json",
                                "location": {
                                    "type": "LineString",
                                    "coordinates": [[-77.0, 38.0], [-77.1, 38.1]]
                                }
                            }
                        ]
                    }
                }
            }"#,
        )
        .expect("parse");
        let entity = observation_to_entity(&obs, EntityKind::Sensor);
        assert!(
            entity.position.is_none(),
            "non-Point geometry must not populate position"
        );
        assert!(
            entity
                .attributes
                .contains_key("sensorthings.location_geojson"),
            "raw GeoJSON should ride opaque"
        );
    }

    #[test]
    fn out_of_range_coordinates_drop_position() {
        // A GeoJSON Point with lat outside [-90, 90] is rejected;
        // the entity position stays `None`.
        let mut obs = observation_with_full_expand();
        let ds = obs.expanded_datastream.as_mut().expect("ds");
        let thing = ds.expanded_thing.as_mut().expect("thing");
        let loc = thing.expanded_locations.first_mut().expect("location");
        loc.location = Some(serde_json::json!({
            "type": "Point",
            "coordinates": [-77.0, 999.0]
        }));
        let entity = observation_to_entity(&obs, EntityKind::Sensor);
        assert!(entity.position.is_none());
    }

    #[test]
    fn entity_kind_is_taken_from_caller() {
        let obs: Observation = serde_json::from_str(
            r#"{
                "@iot.id": 1,
                "phenomenonTime": "2026-05-08T10:30:00Z",
                "result": 1.0
            }"#,
        )
        .expect("parse");
        let entity = observation_to_entity(&obs, EntityKind::Track);
        assert_eq!(entity.kind, EntityKind::Track);
    }

    #[test]
    fn unit_of_measurement_without_symbol_does_not_populate_unit_symbol() {
        // Some upstream stacks emit `unitOfMeasurement` as just a
        // string (non-canonical but observed in the wild).
        // Pin that the projection does not crash and skips the
        // unit_symbol attribute.
        let obs: Observation = serde_json::from_str(
            r#"{
                "@iot.id": 1,
                "phenomenonTime": "2026-05-08T10:30:00Z",
                "result": 1.0,
                "Datastream": {
                    "@iot.id": 42,
                    "unitOfMeasurement": "degC"
                }
            }"#,
        )
        .expect("parse");
        let entity = observation_to_entity(&obs, EntityKind::Sensor);
        assert!(!entity.attributes.contains_key("sensorthings.unit_symbol"));
    }

    #[test]
    fn empty_locations_array_leaves_position_none() {
        let obs = Observation {
            iot_id: 1,
            iot_self_link: None,
            phenomenon_time: "2026-05-08T10:30:00Z".into(),
            result_time: None,
            result: serde_json::json!(1.0),
            expanded_datastream: Some(Datastream {
                iot_id: 1,
                iot_self_link: None,
                name: None,
                description: None,
                unit_of_measurement: None,
                expanded_thing: Some(Thing {
                    iot_id: 1,
                    iot_self_link: None,
                    name: None,
                    description: None,
                    expanded_locations: vec![],
                }),
            }),
        };
        let entity = observation_to_entity(&obs, EntityKind::Sensor);
        assert!(entity.position.is_none());
        assert!(entity.callsign.is_none());
    }

    #[test]
    fn point_without_altitude_produces_two_dim_position() {
        let obs: Observation = serde_json::from_str(
            r#"{
                "@iot.id": 1,
                "phenomenonTime": "2026-05-08T10:30:00Z",
                "result": 1.0,
                "Datastream": {
                    "@iot.id": 1,
                    "Thing": {
                        "@iot.id": 1,
                        "Locations": [
                            {
                                "@iot.id": 1,
                                "encodingType": "application/vnd.geo+json",
                                "location": {
                                    "type": "Point",
                                    "coordinates": [-77.0, 38.0]
                                }
                            }
                        ]
                    }
                }
            }"#,
        )
        .expect("parse");
        let entity = observation_to_entity(&obs, EntityKind::Sensor);
        let pos = entity.position.expect("position projected");
        assert_eq!(pos.lat, 38.0);
        assert_eq!(pos.lon, -77.0);
        assert!(pos.hae_meters.is_none());
    }

    #[test]
    fn skipping_location_helper_directly_builds_point_position() {
        // Direct test on the helper so coverage stays explicit.
        let mut attrs = BTreeMap::new();
        let loc = Location {
            iot_id: 1,
            iot_self_link: None,
            name: Some("buoy 7".into()),
            encoding_type: Some("application/vnd.geo+json".into()),
            location: Some(serde_json::json!({
                "type": "Point",
                "coordinates": [10.0, 20.0]
            })),
        };
        let pos = location_to_position(&loc, &mut attrs).expect("point projected");
        assert_eq!(pos.lat, 20.0);
        assert_eq!(pos.lon, 10.0);
        assert_eq!(
            attrs.get("sensorthings.location_name"),
            Some(&AttributeValue::Str("buoy 7".into()))
        );
    }
}
