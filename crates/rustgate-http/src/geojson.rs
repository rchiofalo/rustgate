// Copyright © 2026 Roberto Chiofalo.

//! GeoJSON ([RFC 7946]) output for HTTP egress targets.
//!
//! Converts a [`RoutableMessage`] into a `Feature` whose geometry is the
//! `Point` parsed out of the embedded CoT `<point>` element when the
//! payload is CoT XML, or `null` (geometry-less Feature, allowed by
//! RFC 7946 §3.2) when the payload is non-CoT or has no position.
//! `properties` carry enough identity / metadata that a downstream
//! consumer can rebuild the original [`RoutableMessage`] without
//! re-parsing the XML payload.
//!
//! When [`crate::config::TargetConfig::batch_enabled`] is set, the
//! per-message Features are framed into a `FeatureCollection` (RFC 7946
//! §3.3) — a first-class GIS-tool input that Leaflet, Mapbox, Kepler.gl,
//! QGIS, and ArcGIS load directly.
//!
//! The content-type for both the per-message and batched paths is the
//! IANA-registered `application/geo+json`.
//!
//! [RFC 7946]: https://datatracker.ietf.org/doc/html/rfc7946

use bytes::Bytes;
use rustgate_core::message::RoutableMessage;
use serde_json::{Map, Value, json};

use crate::error::HttpError;
use crate::payload::format_destination;

/// Content-Type for GeoJSON output, per RFC 7946 §12 (IANA registration).
pub(crate) const GEOJSON_CONTENT_TYPE: &str = "application/geo+json";

/// Build a single-message GeoJSON `Feature` body.
///
/// Returns `(body, content_type)` where `body` is a serialized JSON
/// object of `type = "Feature"`. Suitable for the non-batched per-
/// message HTTP path.
pub(crate) fn serialize_feature(
    msg: &RoutableMessage,
    instance_id: &str,
) -> Result<(Bytes, &'static str), HttpError> {
    let feature = build_feature(msg, instance_id);
    let body = serde_json::to_vec(&feature).map_err(|e| HttpError::Serialize { source: e })?;
    Ok((Bytes::from(body), GEOJSON_CONTENT_TYPE))
}

/// Frame already-serialized per-message Feature bodies into a
/// `FeatureCollection` body.
///
/// Each `feature_body` MUST already be a valid JSON Feature object
/// (typically produced by [`serialize_feature`]); the helper does not
/// re-parse or re-validate the inputs.
///
/// An empty input slice produces a well-formed, empty
/// `FeatureCollection` (`{"type":"FeatureCollection","features":[]}`).
/// Operators are expected to avoid flushing an empty batch in practice
/// — the [`Batcher`](crate::batch::Batcher) only yields flush payloads
/// when at least one message is buffered — but the helper is total so
/// the drain-on-shutdown path stays panic-free if it ever sees one.
pub(crate) fn render_feature_collection(feature_bodies: &[Bytes]) -> (Bytes, &'static str) {
    if feature_bodies.is_empty() {
        return (
            Bytes::from_static(br#"{"type":"FeatureCollection","features":[]}"#),
            GEOJSON_CONTENT_TYPE,
        );
    }
    // Exact-size preallocation: prefix + sum-of-feature-lengths + (n-1)
    // commas + closing bracket + closing brace.
    let prefix = br#"{"type":"FeatureCollection","features":["#;
    let suffix = b"]}";
    let total: usize = feature_bodies.iter().map(|b| b.len()).sum();
    let cap = prefix.len() + total + feature_bodies.len().saturating_sub(1) + suffix.len();
    let mut buf = Vec::with_capacity(cap);
    buf.extend_from_slice(prefix);
    for (i, body) in feature_bodies.iter().enumerate() {
        if i > 0 {
            buf.push(b',');
        }
        buf.extend_from_slice(body);
    }
    buf.extend_from_slice(suffix);
    (Bytes::from(buf), GEOJSON_CONTENT_TYPE)
}

/// Build the JSON `Value` representation of a single Feature.
fn build_feature(msg: &RoutableMessage, instance_id: &str) -> Value {
    let geometry = build_geometry(&msg.payload);
    let properties = build_properties(msg, instance_id);
    json!({
        "type": "Feature",
        "geometry": geometry,
        "properties": properties,
    })
}

/// Parse the CoT payload (if any) and extract a GeoJSON `Point`
/// geometry. Returns `Value::Null` when the payload is not parseable
/// CoT or carries no position — RFC 7946 §3.2 explicitly permits a
/// `Feature` with `"geometry": null`.
fn build_geometry(payload: &[u8]) -> Value {
    let Ok(event) = rustgate_cot::parse(payload) else {
        return Value::Null;
    };
    let Some(pos) = event.position else {
        return Value::Null;
    };
    // RFC 7946 §3.1.1: coordinates are [lon, lat] or [lon, lat, alt].
    // Altitude is metres above the WGS-84 ellipsoid for `hae` —
    // matches the CoT `<point hae="…">` semantic exactly.
    json!({
        "type": "Point",
        "coordinates": [pos.lon, pos.lat, pos.hae],
    })
}

/// Build the `properties` object for a Feature.
///
/// Round-trip contract: every field a downstream consumer needs to
/// rebuild the original [`RoutableMessage`] (without re-parsing the
/// XML) lands here. Adding fields is backwards-compatible for
/// consumers that ignore unknown keys (the GIS-tool default); removing
/// or renaming is a wire-format break.
fn build_properties(msg: &RoutableMessage, instance_id: &str) -> Value {
    // `Map::insert` returns the previous value at the key. Every key
    // we set here is fresh — the workspace `unused_results = "warn"`
    // lint flags the discarded `Option` so each insert is wrapped in
    // `let _ =` to make the intentional drop explicit.
    let mut props: Map<String, Value> = Map::new();
    let _ = props.insert("source_cn".into(), Value::String(msg.source.cn.to_string()));
    let _ = props.insert(
        "source_groups".into(),
        Value::Array(
            msg.source
                .groups
                .iter()
                .map(|g| Value::String(g.to_string()))
                .collect(),
        ),
    );
    let _ = props.insert(
        "destination".into(),
        Value::String(format_destination(&msg.destination)),
    );
    let _ = props.insert(
        "message_type".into(),
        Value::String(msg.metadata.message_type.to_string()),
    );
    let _ = props.insert(
        "source_protocol".into(),
        Value::String(msg.metadata.source_protocol.to_string()),
    );
    let _ = props.insert(
        "received_at".into(),
        Value::String(format_timestamp(msg.metadata.received_at)),
    );
    let _ = props.insert("instance_id".into(), Value::String(instance_id.to_string()));

    // CoT-derived properties (best-effort — non-CoT payloads simply
    // omit these; consumers must guard on `cot_uid` presence).
    if let Ok(event) = rustgate_cot::parse(&msg.payload) {
        let _ = props.insert("cot_uid".into(), Value::String(event.uid));
        let _ = props.insert("cot_type".into(), Value::String(event.event_type));
        if let rustgate_cot::CotDestination::Callsign(callsign) = &event.destination {
            let _ = props.insert("cot_callsign".into(), Value::String(callsign.clone()));
        }
    }

    Value::Object(props)
}

/// Format a SystemTime as ISO 8601 / RFC 3339 UTC. Mirrors the helper
/// in [`crate::payload`] — kept private to that module so we duplicate
/// the (six-line) formatter here rather than promote it to a third
/// shared spot for one extra caller.
fn format_timestamp(t: std::time::SystemTime) -> String {
    let format = time::format_description::well_known::Iso8601::DEFAULT;
    match time::OffsetDateTime::from(t).format(&format) {
        Ok(s) => s,
        Err(_) => match t.duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => d.as_secs().to_string(),
            Err(_) => "0".to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use std::collections::BTreeSet;
    use std::sync::Arc;
    use std::time::SystemTime;

    use bytes::Bytes;
    use rustgate_core::identity::Identity;
    use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};

    use super::*;

    const COT_POSITION: &[u8] = br#"<event version="2.0" uid="ALPHA-1" type="a-f-G-U-C" time="2026-01-01T00:00:00Z" start="2026-01-01T00:00:00Z" stale="2026-01-01T01:00:00Z" how="m-g"><point lat="38.8977" lon="-77.0365" hae="100.5" ce="9999999" le="9999999"/><detail><__group name="Cyan" role="Team Member"/><contact callsign="ALPHA-1"/></detail></event>"#;

    fn make_msg(payload: &[u8]) -> RoutableMessage {
        RoutableMessage {
            source: Identity {
                cn: "alpha-operator".into(),
                fingerprint: Default::default(),
                groups: {
                    let mut s = BTreeSet::new();
                    let _ = s.insert("blue".to_string());
                    s
                },
                tenant: None,
                spiffe_id: None,
                attributes: Arc::new(Default::default()),
            },
            destination: Destination::Broadcast,
            payload: Bytes::from(payload.to_vec()),
            metadata: Metadata::new(SystemTime::now(), "tcp".to_string(), MessageType::Position),
        }
    }

    #[test]
    fn feature_has_rfc7946_required_top_level_keys() {
        let msg = make_msg(COT_POSITION);
        let (body, ct) = serialize_feature(&msg, "inst-01").unwrap();
        assert_eq!(ct, "application/geo+json");
        let parsed: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["type"], "Feature");
        assert!(parsed.get("geometry").is_some(), "geometry key required");
        assert!(
            parsed.get("properties").is_some(),
            "properties key required"
        );
    }

    #[test]
    fn feature_geometry_is_point_with_lon_lat_alt_order() {
        // RFC 7946 §3.1.1: coordinates are `[longitude, latitude, altitude]`
        // — longitude FIRST. A regression that swapped the order would
        // silently put every entity in the wrong hemisphere on every
        // downstream map.
        let msg = make_msg(COT_POSITION);
        let (body, _) = serialize_feature(&msg, "inst").unwrap();
        let parsed: Value = serde_json::from_slice(&body).unwrap();
        let geom = &parsed["geometry"];
        assert_eq!(geom["type"], "Point");
        let coords = geom["coordinates"].as_array().expect("array");
        assert_eq!(coords.len(), 3, "lon, lat, alt");
        assert!(
            (coords[0].as_f64().unwrap() - (-77.0365)).abs() < 1e-9,
            "lon first"
        );
        assert!(
            (coords[1].as_f64().unwrap() - 38.8977).abs() < 1e-9,
            "lat second"
        );
        assert!(
            (coords[2].as_f64().unwrap() - 100.5).abs() < 1e-9,
            "alt third"
        );
    }

    #[test]
    fn feature_properties_carry_round_trip_identity_metadata_and_cot_uid() {
        let msg = make_msg(COT_POSITION);
        let (body, _) = serialize_feature(&msg, "inst-07").unwrap();
        let parsed: Value = serde_json::from_slice(&body).unwrap();
        let props = &parsed["properties"];
        assert_eq!(props["source_cn"], "alpha-operator");
        assert_eq!(props["source_protocol"], "tcp");
        assert_eq!(props["message_type"], "position");
        assert_eq!(props["destination"], "broadcast");
        assert_eq!(props["instance_id"], "inst-07");
        assert_eq!(props["cot_uid"], "ALPHA-1");
        assert_eq!(props["cot_type"], "a-f-G-U-C");
        let groups = props["source_groups"].as_array().unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0], "blue");
    }

    #[test]
    fn non_cot_payload_emits_feature_with_null_geometry() {
        // RFC 7946 §3.2 explicitly permits `"geometry": null` for a
        // Feature with no spatial information. Pin that the renderer
        // does NOT panic / drop / synthesise a fake geometry when a
        // non-CoT payload (e.g. plain text) flows through the GeoJSON
        // path — the Feature must still serialise with the three
        // required top-level keys.
        let msg = make_msg(b"not-cot-just-bytes");
        let (body, _) = serialize_feature(&msg, "inst").unwrap();
        let parsed: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["type"], "Feature");
        assert!(parsed["geometry"].is_null(), "geometry must be JSON null");
        // Properties must still carry identity / metadata.
        assert_eq!(parsed["properties"]["source_cn"], "alpha-operator");
    }

    #[test]
    fn render_feature_collection_wraps_features_in_rfc7946_collection_envelope() {
        let bodies = vec![
            Bytes::from_static(br#"{"type":"Feature","geometry":null,"properties":{}}"#),
            Bytes::from_static(br#"{"type":"Feature","geometry":null,"properties":{}}"#),
        ];
        let (body, ct) = render_feature_collection(&bodies);
        assert_eq!(ct, "application/geo+json");
        let parsed: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["type"], "FeatureCollection");
        let features = parsed["features"].as_array().expect("features array");
        assert_eq!(features.len(), 2);
        for f in features {
            assert_eq!(f["type"], "Feature");
        }
    }

    #[test]
    fn render_feature_collection_empty_input_emits_well_formed_empty_collection() {
        // Total / panic-free contract — drain-on-shutdown could
        // theoretically observe an empty bodies vec; the renderer
        // must still emit a syntactically valid FeatureCollection.
        let (body, ct) = render_feature_collection(&[]);
        assert_eq!(ct, "application/geo+json");
        assert_eq!(&body[..], br#"{"type":"FeatureCollection","features":[]}"#);
        let parsed: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["type"], "FeatureCollection");
        assert!(parsed["features"].as_array().unwrap().is_empty());
    }

    #[test]
    fn content_type_is_application_geo_plus_json_exact_string() {
        // `application/geo+json` is the IANA-registered media type
        // (RFC 7946 §12). Pin the literal so a "normalisation" refactor
        // to `application/json` would fail here rather than silently
        // route GeoJSON through every receiver's plain-JSON content
        // negotiation pipeline (which would drop the `+json` suffix
        // and likely break tools that use it for spatial-aware
        // dispatch).
        let msg = make_msg(COT_POSITION);
        let (_, ct) = serialize_feature(&msg, "inst").unwrap();
        assert_eq!(ct, "application/geo+json");
        let (_, batch_ct) = render_feature_collection(&[]);
        assert_eq!(batch_ct, "application/geo+json");
    }

    #[test]
    fn feature_collection_preserves_feature_bytes_byte_for_byte() {
        // The renderer is format-agnostic about feature contents; it
        // only frames them. Pin that no escaping / mutation happens
        // along the way — the wrapped feature bytes must survive
        // verbatim between `[` and `]`.
        let f1 = Bytes::from_static(br#"{"type":"Feature","id":1}"#);
        let f2 = Bytes::from_static(br#"{"type":"Feature","id":2}"#);
        let (body, _) = render_feature_collection(&[f1.clone(), f2.clone()]);
        let s = std::str::from_utf8(&body).unwrap();
        assert!(s.contains(r#"{"type":"Feature","id":1}"#));
        assert!(s.contains(r#"{"type":"Feature","id":2}"#));
        // And — the sequence must be ordered.
        let i1 = s.find(r#""id":1"#).unwrap();
        let i2 = s.find(r#""id":2"#).unwrap();
        assert!(i1 < i2, "feature order must be preserved");
    }

    #[test]
    fn cot_destination_callsign_propagates_to_properties_cot_callsign() {
        // CoT `<marti><dest callsign="..."/></marti>` lands as
        // `event.destination = CotDestination::Callsign(...)` in the
        // parser. Pin that this surfaces in `properties.cot_callsign`
        // so a GIS dashboard can label the feature with the operator-
        // visible callsign rather than the cert CN.
        const COT_WITH_CALLSIGN: &[u8] = br#"<event version="2.0" uid="ALPHA-1" type="a-f-G-U-C" time="2026-01-01T00:00:00Z" start="2026-01-01T00:00:00Z" stale="2026-01-01T01:00:00Z" how="m-g"><point lat="38.0" lon="-77.0" hae="0.0" ce="9999999" le="9999999"/><detail><marti><dest callsign="BRAVO-2"/></marti></detail></event>"#;
        let msg = make_msg(COT_WITH_CALLSIGN);
        let (body, _) = serialize_feature(&msg, "inst").unwrap();
        let parsed: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["properties"]["cot_callsign"], "BRAVO-2");
    }
}
