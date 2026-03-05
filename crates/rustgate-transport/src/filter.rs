//! Message filtering by CoT type prefix and geographic bounding box.
//!
//! Filters are applied before routing — messages that don't pass the
//! filter are silently dropped. Each filter is optional; when not
//! configured, all messages of that category pass through.

use rustgate_core::message::{MessageType, RoutableMessage};

/// Filter configuration for message routing.
///
/// An empty filter (default) allows all messages. When one or more
/// criteria are set, a message must satisfy all configured criteria
/// to pass through (AND logic).
#[derive(Debug, Clone, Default)]
pub struct MessageFilter {
    /// CoT type prefixes to allow (e.g., "a-f" for friendly atoms).
    /// Empty means all types are allowed.
    type_prefixes: Vec<String>,

    /// Geographic bounding box (south, west, north, east) in degrees.
    /// Only messages with lat/lon within the box are forwarded.
    geo_bounds: Option<GeoBounds>,
}

/// Geographic bounding box defined by corners in WGS84 degrees.
#[derive(Debug, Clone)]
pub struct GeoBounds {
    pub south: f64,
    pub west: f64,
    pub north: f64,
    pub east: f64,
}

impl GeoBounds {
    /// Check if a lat/lon point falls within this bounding box.
    pub fn contains(&self, lat: f64, lon: f64) -> bool {
        lat >= self.south && lat <= self.north && lon >= self.west && lon <= self.east
    }
}

impl MessageFilter {
    /// Create a new empty filter (allows everything).
    pub fn new() -> Self {
        Self::default()
    }

    /// Add allowed CoT type prefixes.
    ///
    /// When set, only messages whose CoT type starts with one of these
    /// prefixes will pass. For example, `"a-f"` matches all friendly
    /// atoms, `"b-a"` matches all alerts.
    pub fn with_type_prefixes(mut self, prefixes: Vec<String>) -> Self {
        self.type_prefixes = prefixes;
        self
    }

    /// Set a geographic bounding box filter.
    pub fn with_geo_bounds(mut self, bounds: GeoBounds) -> Self {
        self.geo_bounds = Some(bounds);
        self
    }

    /// Check if a message passes this filter.
    ///
    /// Returns `true` if the message should be forwarded.
    pub fn matches(&self, msg: &RoutableMessage) -> bool {
        if !self.matches_type(msg) {
            return false;
        }
        if !self.matches_geo(msg) {
            return false;
        }
        true
    }

    /// Check type prefix filter.
    fn matches_type(&self, msg: &RoutableMessage) -> bool {
        if self.type_prefixes.is_empty() {
            return true;
        }

        let cot_type = extract_cot_type(&msg.payload);
        let Some(cot_type) = cot_type else {
            // Non-CoT messages pass type filters if the message type
            // matches a known mapping.
            return self.matches_message_type(&msg.metadata.message_type);
        };

        self.type_prefixes
            .iter()
            .any(|prefix| cot_type.starts_with(prefix.as_str()))
    }

    /// Fallback type matching using the parsed MessageType enum.
    fn matches_message_type(&self, msg_type: &MessageType) -> bool {
        self.type_prefixes.iter().any(|prefix| match msg_type {
            MessageType::Position => prefix.starts_with("a-"),
            MessageType::Chat => prefix.starts_with("b-t"),
            MessageType::Alert => prefix.starts_with("b-a"),
            MessageType::Status => prefix.starts_with("t-"),
            _ => false,
        })
    }

    /// Check geographic bounding box filter.
    fn matches_geo(&self, msg: &RoutableMessage) -> bool {
        let Some(ref bounds) = self.geo_bounds else {
            return true;
        };

        // Extract lat/lon from CoT XML <point> element
        let Some((lat, lon)) = extract_point(&msg.payload) else {
            // Messages without coordinates pass the geo filter
            // (e.g., chat messages have no position).
            return true;
        };

        bounds.contains(lat, lon)
    }
}

/// Extract the CoT event type attribute from XML payload.
///
/// Looks for `type="..."` in the `<event>` element. This is a fast
/// substring scan that avoids full XML parsing for the common case.
fn extract_cot_type(payload: &[u8]) -> Option<&str> {
    let text = std::str::from_utf8(payload).ok()?;

    // Find <event ... type="...">
    let event_start = text.find("<event ")?;
    let event_end = text[event_start..].find('>')? + event_start;
    let event_tag = &text[event_start..event_end];

    // Find type="value"
    let type_start = event_tag.find("type=\"")? + 6;
    let type_end = event_tag[type_start..].find('"')? + type_start;
    Some(&event_tag[type_start..type_end])
}

/// Extract lat/lon from CoT XML `<point>` element.
///
/// Looks for `lat="..."` and `lon="..."` attributes. Uses substring
/// scanning for performance — avoids XML parser overhead on every message.
fn extract_point(payload: &[u8]) -> Option<(f64, f64)> {
    let text = std::str::from_utf8(payload).ok()?;

    let point_start = text.find("<point ")?;
    let point_end = text[point_start..]
        .find("/>")
        .or_else(|| text[point_start..].find('>'))?
        + point_start;
    let point_tag = &text[point_start..point_end];

    let lat = extract_attr(point_tag, "lat")?;
    let lon = extract_attr(point_tag, "lon")?;

    Some((lat, lon))
}

/// Extract a numeric attribute value from an XML tag string.
fn extract_attr(tag: &str, name: &str) -> Option<f64> {
    let needle = format!("{name}=\"");
    let start = tag.find(&needle)? + needle.len();
    let end = tag[start..].find('"')? + start;
    tag[start..end].parse().ok()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::time::SystemTime;

    use bytes::Bytes;
    use rustgate_core::identity::Identity;
    use rustgate_core::message::{Destination, Metadata, RoutableMessage};

    use super::*;

    fn make_msg(payload: &str) -> RoutableMessage {
        RoutableMessage {
            source: Identity {
                cn: "test".to_string(),
                fingerprint: "fp".to_string(),
                groups: BTreeSet::new(),
            },
            destination: Destination::Broadcast,
            payload: Bytes::from(payload.to_string()),
            metadata: Metadata {
                received_at: SystemTime::now(),
                source_protocol: "cot".to_string(),
                message_type: MessageType::Position,
                ttl: None,
            },
        }
    }

    #[test]
    fn empty_filter_allows_all() {
        let filter = MessageFilter::new();
        let msg = make_msg("<event type=\"a-f-G\" />");
        assert!(filter.matches(&msg));
    }

    #[test]
    fn type_prefix_matches() {
        let filter = MessageFilter::new().with_type_prefixes(vec!["a-f".to_string()]);
        let msg =
            make_msg(r#"<event type="a-f-G-U-C" uid="test"><point lat="0" lon="0" /></event>"#);
        assert!(filter.matches(&msg));
    }

    #[test]
    fn type_prefix_rejects() {
        let filter = MessageFilter::new().with_type_prefixes(vec!["a-f".to_string()]);
        let msg = make_msg(r#"<event type="a-h-G" uid="test"><point lat="0" lon="0" /></event>"#);
        assert!(!filter.matches(&msg));
    }

    #[test]
    fn multiple_type_prefixes() {
        let filter =
            MessageFilter::new().with_type_prefixes(vec!["a-f".to_string(), "b-a".to_string()]);
        let friendly = make_msg(r#"<event type="a-f-G" uid="test" />"#);
        let alert = make_msg(r#"<event type="b-a-o" uid="test" />"#);
        let hostile = make_msg(r#"<event type="a-h-G" uid="test" />"#);

        assert!(filter.matches(&friendly));
        assert!(filter.matches(&alert));
        assert!(!filter.matches(&hostile));
    }

    #[test]
    fn geo_bounds_contains() {
        let bounds = GeoBounds {
            south: 30.0,
            west: -100.0,
            north: 40.0,
            east: -80.0,
        };
        assert!(bounds.contains(35.0, -90.0));
        assert!(!bounds.contains(50.0, -90.0));
        assert!(!bounds.contains(35.0, -110.0));
    }

    #[test]
    fn geo_filter_passes_within_bounds() {
        let filter = MessageFilter::new().with_geo_bounds(GeoBounds {
            south: 30.0,
            west: -100.0,
            north: 40.0,
            east: -80.0,
        });
        let msg = make_msg(
            r#"<event type="a-f-G" uid="test"><point lat="35.0" lon="-90.0" hae="0" ce="0" le="0" /></event>"#,
        );
        assert!(filter.matches(&msg));
    }

    #[test]
    fn geo_filter_rejects_outside_bounds() {
        let filter = MessageFilter::new().with_geo_bounds(GeoBounds {
            south: 30.0,
            west: -100.0,
            north: 40.0,
            east: -80.0,
        });
        let msg = make_msg(
            r#"<event type="a-f-G" uid="test"><point lat="50.0" lon="-90.0" hae="0" ce="0" le="0" /></event>"#,
        );
        assert!(!filter.matches(&msg));
    }

    #[test]
    fn geo_filter_passes_no_point() {
        let filter = MessageFilter::new().with_geo_bounds(GeoBounds {
            south: 30.0,
            west: -100.0,
            north: 40.0,
            east: -80.0,
        });
        // Chat message with no <point> element
        let msg = make_msg(r#"<event type="b-t-f" uid="test"><detail /></event>"#);
        assert!(filter.matches(&msg));
    }

    #[test]
    fn extract_cot_type_works() {
        let xml = br#"<event type="a-f-G-U-C" uid="test" />"#;
        assert_eq!(extract_cot_type(xml), Some("a-f-G-U-C"));
    }

    #[test]
    fn extract_cot_type_missing() {
        let xml = b"not xml at all";
        assert_eq!(extract_cot_type(xml), None);
    }

    #[test]
    fn extract_point_works() {
        let xml = br#"<event type="a-f-G"><point lat="35.5" lon="-90.1" hae="0" /></event>"#;
        let (lat, lon) = extract_point(xml).expect("should extract point");
        assert!((lat - 35.5).abs() < f64::EPSILON);
        assert!((lon - (-90.1)).abs() < f64::EPSILON);
    }

    #[test]
    fn extract_point_missing() {
        let xml = br#"<event type="b-t-f"><detail /></event>"#;
        assert!(extract_point(xml).is_none());
    }
}
