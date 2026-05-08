// Copyright © 2026 Roberto Chiofalo.

//! Dotted-path projection between [`rustgate_core::entity::Entity`] and
//! the Foundry property bag.
//!
//! Operators declare projection rules in the
//! [`crate::config::PropertyMap`] table. This module evaluates them.
//!
//! # Supported entity-side dotted paths
//!
//! - `uid`
//! - `callsign`
//! - `mil_std_2525_sidc`
//! - `position.lat` / `position.lon` / `position.hae_meters`
//! - `velocity.speed_m_s` / `velocity.course_deg`
//! - `attributes.<key>` — looks up a single entry in
//!   [`rustgate_core::entity::Entity::attributes`]. Everything after
//!   the first `.` is the attribute key, so `attributes.cot.event_type`
//!   resolves to the `cot.event_type` attribute (codec keys carry
//!   internal dots — the wiring's responsibility is to namespace).
//!
//! Anything else surfaces as
//! [`crate::error::FoundryError::PathNotFound`] at evaluation time,
//! which makes a config typo visible the first time a real entity
//! flows through.
//!
//! # Reverse direction
//!
//! [`PropertyMapper::foundry_to_entity_overlay`] reverses the
//! projection: given a Foundry property bag and the same
//! [`crate::config::PropertyMap`] list, it returns a partial overlay
//! `(uid, callsign, position, velocity, attributes)` the inbound
//! wiring layers onto a freshly-minted entity. The reverse direction
//! is intentionally lossy — Foundry properties not listed in the
//! map stay on the Foundry side, and entity fields not covered by
//! the map default to `None` / empty.

use std::collections::BTreeMap;

use rustgate_core::entity::{AttributeValue, Entity, Position, Velocity};
use serde_json::{Map, Value};

use crate::config::PropertyMap;
use crate::error::FoundryError;

/// Stateless evaluator for the property-map projection.
///
/// Holds the [`PropertyMap`] list cloned from the configured
/// [`crate::config::ObjectTypeMapping`]; lookups are O(N) over the
/// list, which is the right shape because (a) N is small (typically
/// fewer than 20) and (b) the wiring already paid for the entity
/// lookup with a hash on `entity-type`. A future optimisation might
/// pre-compute a `HashMap<&str, &str>` for both directions; for the
/// MVP the linear scan keeps the surface area small and the
/// determinism of evaluation order obvious.
#[derive(Debug, Clone)]
pub struct PropertyMapper {
    rules: Vec<PropertyMap>,
}

/// Reverse-direction overlay produced by
/// [`PropertyMapper::foundry_to_entity_overlay`]. The inbound wiring
/// layers this onto a freshly-minted [`Entity`] before forwarding to
/// the router. Fields the property map did not cover stay `None` /
/// empty so the consumer can apply its own defaults.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct EntityOverlay {
    /// Optional UID — populated when the property map lists `uid`.
    pub uid: Option<String>,
    /// Optional callsign — populated when the property map lists
    /// `callsign`.
    pub callsign: Option<String>,
    /// Optional 2525 SIDC — populated when the property map lists
    /// `mil_std_2525_sidc`.
    pub mil_std_2525_sidc: Option<String>,
    /// Optional position — populated when at least one of
    /// `position.lat` / `position.lon` is present in the property
    /// map AND in the inbound Foundry properties. Missing
    /// `hae_meters` stays `None`.
    pub position: Option<Position>,
    /// Optional velocity — populated when at least one of
    /// `velocity.speed_m_s` / `velocity.course_deg` is present.
    pub velocity: Option<Velocity>,
    /// Attribute overlay — `attributes.<key>` rules deposit here.
    pub attributes: BTreeMap<String, AttributeValue>,
}

impl PropertyMapper {
    /// Construct a mapper from the configured rule list.
    pub fn new(rules: Vec<PropertyMap>) -> Self {
        Self { rules }
    }

    /// Number of configured rules. Surfaced for diagnostics.
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Returns `true` when the rule list is empty.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Project an entity onto a Foundry property bag.
    ///
    /// Unresolved paths surface as
    /// [`FoundryError::PathNotFound`] — the wiring catches this and
    /// emits at `tracing::warn!` so a config typo or a wire-format
    /// shape that does not carry the field is visible.
    /// Optional-source paths (`position.lat` on an entity with no
    /// position) are silently skipped — this is the common case
    /// when the same property map serves entities of varying
    /// completeness.
    pub fn entity_to_foundry(&self, entity: &Entity) -> Result<Value, FoundryError> {
        let mut bag = Map::new();
        for rule in &self.rules {
            match resolve_entity_path(entity, &rule.entity)? {
                Some(value) => {
                    let _ = bag.insert(rule.foundry.clone(), value);
                }
                None => {
                    // Optional source field absent — skip silently.
                    // The wiring would log every miss otherwise and
                    // bury the signal a real "PathNotFound" surfaces.
                }
            }
        }
        Ok(Value::Object(bag))
    }

    /// Reverse projection: inbound Foundry → partial entity overlay.
    pub fn foundry_to_entity_overlay(&self, props: &Value) -> EntityOverlay {
        let mut overlay = EntityOverlay::default();
        let Some(map) = props.as_object() else {
            return overlay;
        };
        for rule in &self.rules {
            let Some(value) = map.get(&rule.foundry) else {
                continue;
            };
            apply_overlay(&mut overlay, &rule.entity, value);
        }
        overlay
    }
}

/// Resolve a dotted path against an entity into a JSON value.
///
/// Returns `Ok(None)` for paths whose source field is absent on the
/// entity (e.g. `position.lat` on an entity with `position: None`)
/// — this is normal and the caller skips the projection silently.
/// Returns `Err(PathNotFound)` for paths the schema does not
/// recognise — this is a config typo and the caller surfaces it.
fn resolve_entity_path(entity: &Entity, path: &str) -> Result<Option<Value>, FoundryError> {
    match path {
        "uid" => Ok(Some(Value::String(entity.uid.clone()))),
        "callsign" => Ok(entity.callsign.clone().map(Value::String)),
        "mil_std_2525_sidc" => Ok(entity.mil_std_2525_sidc.clone().map(Value::String)),
        "position.lat" => Ok(entity.position.as_ref().map(|p| json_number(p.lat))),
        "position.lon" => Ok(entity.position.as_ref().map(|p| json_number(p.lon))),
        "position.hae_meters" => Ok(entity
            .position
            .as_ref()
            .and_then(|p| p.hae_meters)
            .map(json_number)),
        "velocity.speed_m_s" => Ok(entity.velocity.as_ref().map(|v| json_number(v.speed_m_s))),
        "velocity.course_deg" => Ok(entity.velocity.as_ref().map(|v| json_number(v.course_deg))),
        other => {
            if let Some(key) = other.strip_prefix("attributes.") {
                Ok(entity.attributes.get(key).map(attribute_to_json))
            } else {
                Err(FoundryError::PathNotFound {
                    path: path.to_string(),
                })
            }
        }
    }
}

/// Apply a single inbound rule by writing the value into the
/// matching slot on the overlay. Best-effort — values that do not
/// match the slot's expected JSON shape are dropped silently
/// because the inbound wiring has no recourse for a malformed
/// upstream payload, and the partial overlay still produces a
/// usable downstream entity.
fn apply_overlay(overlay: &mut EntityOverlay, path: &str, value: &Value) {
    match path {
        "uid" => {
            if let Some(s) = value.as_str() {
                overlay.uid = Some(s.to_string());
            }
        }
        "callsign" => {
            if let Some(s) = value.as_str() {
                overlay.callsign = Some(s.to_string());
            }
        }
        "mil_std_2525_sidc" => {
            if let Some(s) = value.as_str() {
                overlay.mil_std_2525_sidc = Some(s.to_string());
            }
        }
        "position.lat" => {
            if let Some(n) = value.as_f64() {
                let pos = overlay.position.get_or_insert(Position {
                    lat: 0.0,
                    lon: 0.0,
                    hae_meters: None,
                });
                pos.lat = n;
            }
        }
        "position.lon" => {
            if let Some(n) = value.as_f64() {
                let pos = overlay.position.get_or_insert(Position {
                    lat: 0.0,
                    lon: 0.0,
                    hae_meters: None,
                });
                pos.lon = n;
            }
        }
        "position.hae_meters" => {
            if let Some(n) = value.as_f64() {
                let pos = overlay.position.get_or_insert(Position {
                    lat: 0.0,
                    lon: 0.0,
                    hae_meters: None,
                });
                pos.hae_meters = Some(n);
            }
        }
        "velocity.speed_m_s" => {
            if let Some(n) = value.as_f64() {
                let vel = overlay.velocity.get_or_insert(Velocity {
                    speed_m_s: 0.0,
                    course_deg: 0.0,
                });
                vel.speed_m_s = n;
            }
        }
        "velocity.course_deg" => {
            if let Some(n) = value.as_f64() {
                let vel = overlay.velocity.get_or_insert(Velocity {
                    speed_m_s: 0.0,
                    course_deg: 0.0,
                });
                vel.course_deg = n;
            }
        }
        other => {
            if let Some(key) = other.strip_prefix("attributes.")
                && let Some(attr) = json_to_attribute(value)
            {
                let _ = overlay.attributes.insert(key.to_string(), attr);
            }
        }
    }
}

fn json_number(n: f64) -> Value {
    serde_json::Number::from_f64(n)
        .map(Value::Number)
        .unwrap_or(Value::Null)
}

fn attribute_to_json(attr: &AttributeValue) -> Value {
    match attr {
        AttributeValue::Str(s) => Value::String(s.clone()),
        AttributeValue::Int(i) => Value::Number((*i).into()),
        AttributeValue::Float(f) => json_number(*f),
        AttributeValue::Bool(b) => Value::Bool(*b),
    }
}

fn json_to_attribute(v: &Value) -> Option<AttributeValue> {
    match v {
        Value::String(s) => Some(AttributeValue::Str(s.clone())),
        Value::Bool(b) => Some(AttributeValue::Bool(*b)),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Some(AttributeValue::Int(i))
            } else {
                n.as_f64().map(AttributeValue::Float)
            }
        }
        Value::Null | Value::Array(_) | Value::Object(_) => None,
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use std::time::SystemTime;

    use rustgate_core::entity::EntityKind;

    use super::*;

    fn sample_entity() -> Entity {
        let mut attrs = BTreeMap::new();
        let _ = attrs.insert(
            "cot.event_type".to_string(),
            AttributeValue::Str("a-f-G-U-C".into()),
        );
        let _ = attrs.insert("battery".to_string(), AttributeValue::Int(87));
        Entity {
            uid: "GOLF-1".into(),
            kind: EntityKind::Ground,
            position: Some(Position {
                lat: 38.5,
                lon: -77.25,
                hae_meters: Some(120.0),
            }),
            velocity: Some(Velocity {
                speed_m_s: 7.5,
                course_deg: 270.0,
            }),
            timestamp: SystemTime::UNIX_EPOCH,
            callsign: Some("alpha".into()),
            mil_std_2525_sidc: Some("SFGPUCI-----".into()),
            attributes: attrs,
        }
    }

    fn rule(entity: &str, foundry: &str) -> PropertyMap {
        PropertyMap {
            entity: entity.to_string(),
            foundry: foundry.to_string(),
        }
    }

    #[test]
    fn forward_projection_covers_every_supported_path() {
        let rules = vec![
            rule("uid", "rustgate.uid"),
            rule("callsign", "callSign"),
            rule("mil_std_2525_sidc", "sidc"),
            rule("position.lat", "lat"),
            rule("position.lon", "lon"),
            rule("position.hae_meters", "hae"),
            rule("velocity.speed_m_s", "speed"),
            rule("velocity.course_deg", "course"),
            rule("attributes.cot.event_type", "cotType"),
            rule("attributes.battery", "battery"),
        ];
        let mapper = PropertyMapper::new(rules);
        let bag = mapper.entity_to_foundry(&sample_entity()).expect("project");
        let obj = bag.as_object().unwrap();
        assert_eq!(obj["rustgate.uid"], "GOLF-1");
        assert_eq!(obj["callSign"], "alpha");
        assert_eq!(obj["sidc"], "SFGPUCI-----");
        assert_eq!(obj["lat"].as_f64(), Some(38.5));
        assert_eq!(obj["lon"].as_f64(), Some(-77.25));
        assert_eq!(obj["hae"].as_f64(), Some(120.0));
        assert_eq!(obj["speed"].as_f64(), Some(7.5));
        assert_eq!(obj["course"].as_f64(), Some(270.0));
        assert_eq!(obj["cotType"], "a-f-G-U-C");
        assert_eq!(obj["battery"].as_i64(), Some(87));
    }

    #[test]
    fn forward_projection_skips_optional_missing_fields() {
        // Entity has no position / velocity / callsign / sidc /
        // attributes — only `uid` resolves. The other rules are
        // skipped silently.
        let rules = vec![
            rule("uid", "rustgate.uid"),
            rule("callsign", "callSign"),
            rule("position.lat", "lat"),
            rule("velocity.speed_m_s", "speed"),
            rule("attributes.missing", "missing"),
        ];
        let mapper = PropertyMapper::new(rules);
        let bare = Entity {
            uid: "X".into(),
            kind: EntityKind::Track,
            position: None,
            velocity: None,
            timestamp: SystemTime::UNIX_EPOCH,
            callsign: None,
            mil_std_2525_sidc: None,
            attributes: BTreeMap::new(),
        };
        let bag = mapper.entity_to_foundry(&bare).expect("project");
        let obj = bag.as_object().unwrap();
        assert_eq!(obj.len(), 1);
        assert_eq!(obj["rustgate.uid"], "X");
    }

    #[test]
    fn forward_projection_surfaces_typo_as_path_not_found() {
        // `positon.lat` (typo: missing `i`) is not in the supported
        // path vocabulary AND does not have the `attributes.`
        // prefix, so it surfaces as PathNotFound.
        let mapper = PropertyMapper::new(vec![rule("positon.lat", "lat")]);
        let err = mapper.entity_to_foundry(&sample_entity()).unwrap_err();
        match err {
            FoundryError::PathNotFound { path } => assert_eq!(path, "positon.lat"),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn reverse_projection_layers_overlay() {
        let rules = vec![
            rule("uid", "rustgate.uid"),
            rule("callsign", "callSign"),
            rule("position.lat", "lat"),
            rule("position.lon", "lon"),
            rule("velocity.speed_m_s", "speed"),
            rule("attributes.battery", "battery"),
        ];
        let mapper = PropertyMapper::new(rules);
        let props = serde_json::json!({
            "rustgate.uid": "INBOUND-1",
            "callSign": "bravo",
            "lat": 41.0,
            "lon": -71.5,
            "speed": 12.0,
            "battery": 64,
            "ignored": "stays-on-foundry-side",
        });
        let overlay = mapper.foundry_to_entity_overlay(&props);
        assert_eq!(overlay.uid.as_deref(), Some("INBOUND-1"));
        assert_eq!(overlay.callsign.as_deref(), Some("bravo"));
        let pos = overlay.position.unwrap();
        assert_eq!(pos.lat, 41.0);
        assert_eq!(pos.lon, -71.5);
        let vel = overlay.velocity.unwrap();
        assert_eq!(vel.speed_m_s, 12.0);
        assert_eq!(
            overlay.attributes.get("battery"),
            Some(&AttributeValue::Int(64))
        );
    }

    #[test]
    fn round_trip_through_property_map_preserves_listed_fields() {
        // Same property map applied forward then reverse should
        // recover the listed fields verbatim. Cross-codec attributes
        // not in the map drop, by design.
        let rules = vec![
            rule("uid", "rustgate.uid"),
            rule("callsign", "callSign"),
            rule("position.lat", "lat"),
            rule("position.lon", "lon"),
            rule("attributes.battery", "battery"),
        ];
        let mapper = PropertyMapper::new(rules);
        let entity = sample_entity();
        let bag = mapper.entity_to_foundry(&entity).expect("forward");
        let overlay = mapper.foundry_to_entity_overlay(&bag);
        assert_eq!(overlay.uid.as_deref(), Some("GOLF-1"));
        assert_eq!(overlay.callsign.as_deref(), Some("alpha"));
        let pos = overlay.position.unwrap();
        assert_eq!(pos.lat, 38.5);
        assert_eq!(pos.lon, -77.25);
        assert_eq!(
            overlay.attributes.get("battery"),
            Some(&AttributeValue::Int(87))
        );
        // Velocity / sidc / cot.event_type / hae were NOT in the
        // map — they drop on the round-trip. This is the
        // by-design behaviour documented at the module top.
        assert!(overlay.velocity.is_none());
        assert!(overlay.mil_std_2525_sidc.is_none());
        assert!(!overlay.attributes.contains_key("cot.event_type"));
    }
}
