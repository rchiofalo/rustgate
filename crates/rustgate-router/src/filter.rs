// Copyright © 2026 Roberto Chiofalo.

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
///
/// Uses direct substring search followed by a `="` suffix check to
/// avoid heap-allocating a needle string on every call.
fn extract_attr(tag: &str, name: &str) -> Option<f64> {
    let mut search_from = 0;
    while search_from < tag.len() {
        let name_pos = tag[search_from..].find(name)? + search_from;
        let eq_quote = name_pos + name.len();
        // Verify the attribute name is followed by `="`
        if tag[eq_quote..].starts_with("=\"") {
            let value_start = eq_quote + 2;
            let value_end = tag[value_start..].find('"')? + value_start;
            return tag[value_start..value_end].parse().ok();
        }
        search_from = name_pos + name.len();
    }
    None
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
            source: Identity::new("test".to_string(), "fp".to_string(), BTreeSet::new())
                .expect("valid identity"),
            destination: Destination::Broadcast,
            payload: Bytes::from(payload.to_string()),
            metadata: Metadata::new(SystemTime::now(), "cot".to_string(), MessageType::Position),
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

    /// Compile-time pins that `MessageFilter` and `GeoBounds` satisfy
    /// the `Debug + Clone + Send + Sync + 'static` bound set via a
    /// single generic helper. `MessageFilter` is cloned into `Router`
    /// configuration and shared across async tasks; a regression that
    /// added a non-`Send` field (an `Rc`, a `RefCell`, a raw pointer)
    /// would silently compile at the definition site but fail at the
    /// first transitive send boundary in the router, so the test pins
    /// the contract at the module surface. The generic helper trips at
    /// test-compile time on any narrowing.
    #[test]
    fn message_filter_and_geo_bounds_implement_debug_clone_send_sync_static() {
        fn bounds<T: std::fmt::Debug + Clone + Send + Sync + 'static>() {}
        bounds::<MessageFilter>();
        bounds::<GeoBounds>();
    }

    /// `MessageFilter::new()` is advertised by the module doc as a
    /// shorthand for `MessageFilter::default()`. Pin the two-way
    /// equivalence by building both, feeding both through `matches`
    /// against the same message, and asserting agreement — a regression
    /// where `new()` silently diverged from `default()` (e.g. by starting
    /// with a non-empty `type_prefixes` allow-list) would cause every
    /// `new()`-built router to reject traffic the tests expect to pass,
    /// but only in production where operators rely on the no-op shape.
    #[test]
    fn new_and_default_produce_observably_identical_filters() {
        let a = MessageFilter::new();
        let b = MessageFilter::default();
        let msg = make_msg(r#"<event type="a-f-G" uid="test"><point lat="0" lon="0" /></event>"#);
        assert_eq!(
            a.matches(&msg),
            b.matches(&msg),
            "new() and default() must agree on matches() output"
        );
        assert!(a.matches(&msg), "empty filter must allow anything");
        // Pin the Debug renderings diverge only in struct name (they
        // don't — both render as `MessageFilter { … }`), so equality of
        // the two renderings is the tightest pin on "observably
        // identical" at the Debug surface.
        assert_eq!(format!("{a:?}"), format!("{b:?}"));
    }

    /// `matches_type` has a currently-uncovered fallback branch: when
    /// the payload is *not* CoT XML (so `extract_cot_type` returns
    /// `None`) but the metadata carries a mapped `MessageType`, the
    /// filter routes through `matches_message_type` to decide pass/fail.
    /// This pins that branch by sending a non-XML payload (raw binary)
    /// with `MessageType::Position` and a type-prefix filter for `a-`
    /// (which `Position` maps to), asserting the filter passes. A
    /// regression that dropped the fallback and unconditionally rejected
    /// non-XML payloads would silently drop every protobuf/binary
    /// position message at the filter stage.
    #[test]
    fn matches_type_fallback_routes_through_message_type_for_non_xml_payload() {
        let filter = MessageFilter::new().with_type_prefixes(vec!["a-".to_string()]);
        let msg = RoutableMessage {
            source: Identity::new("test".to_string(), "fp".to_string(), BTreeSet::new())
                .expect("valid identity"),
            destination: Destination::Broadcast,
            payload: Bytes::from_static(&[0x00, 0x01, 0x02, 0x03]),
            metadata: Metadata::new(
                SystemTime::now(),
                "protobuf".to_string(),
                MessageType::Position,
            ),
        };
        assert!(
            filter.matches(&msg),
            "Position + prefix a- must pass via the metadata fallback path"
        );
    }

    /// The `matches_message_type` dispatch table has a `_ => false`
    /// catch-all that rejects every `MessageType` variant without a
    /// documented prefix mapping — `MessageType::File` and
    /// `MessageType::Other(...)` both fall through to it. Pin the
    /// behaviour by driving both through a filter with a broad
    /// type-prefix (`a-`) and asserting rejection. A regression that
    /// turned the catch-all into `_ => true` would silently admit every
    /// file-transfer or unknown-kind message past every configured
    /// type filter.
    #[test]
    fn matches_message_type_rejects_file_and_other_variants_via_catchall() {
        let filter = MessageFilter::new().with_type_prefixes(vec!["a-".to_string()]);
        for mtype in [MessageType::File, MessageType::Other("mystery".to_string())] {
            let msg = RoutableMessage {
                source: Identity::new("test".to_string(), "fp".to_string(), BTreeSet::new())
                    .expect("valid identity"),
                destination: Destination::Broadcast,
                payload: Bytes::from_static(&[0x00]),
                metadata: Metadata::new(SystemTime::now(), "binary".to_string(), mtype.clone()),
            };
            assert!(
                !filter.matches(&msg),
                "unmapped message type {mtype:?} must fail the catchall and be rejected"
            );
        }
    }

    /// `GeoBounds::contains` uses `>=` / `<=` on all four axes, so the
    /// bounding box is inclusive at the corners. Pin the inclusivity by
    /// checking the exact-corner points (SW, SE, NW, NE) plus the
    /// centre. A regression that flipped any edge to strict `>` / `<`
    /// would silently narrow every configured bounding box by the
    /// floating-point ULP at its boundary, dropping traffic exactly at
    /// operator-configured latitude/longitude limits.
    #[test]
    fn geo_bounds_contains_is_inclusive_at_all_four_corners() {
        let bounds = GeoBounds {
            south: 30.0,
            west: -100.0,
            north: 40.0,
            east: -80.0,
        };
        assert!(bounds.contains(30.0, -100.0), "SW corner must be inside");
        assert!(bounds.contains(30.0, -80.0), "SE corner must be inside");
        assert!(bounds.contains(40.0, -100.0), "NW corner must be inside");
        assert!(bounds.contains(40.0, -80.0), "NE corner must be inside");
        assert!(bounds.contains(35.0, -90.0), "centre must be inside");
    }

    /// Pin that a NaN coordinate is rejected by `contains`. IEEE 754
    /// NaN comparisons always return `false`, so a NaN lat or lon will
    /// naturally fall outside every finite bounding box — but pinning
    /// this at the filter surface defends against a future refactor
    /// that switched to `total_cmp`-based ordering (which *does* place
    /// NaN in the sort order and could silently admit NaN points).
    #[test]
    fn geo_bounds_contains_rejects_nan_coordinates() {
        let bounds = GeoBounds {
            south: 30.0,
            west: -100.0,
            north: 40.0,
            east: -80.0,
        };
        assert!(
            !bounds.contains(f64::NAN, -90.0),
            "NaN lat must be rejected"
        );
        assert!(!bounds.contains(35.0, f64::NAN), "NaN lon must be rejected");
        assert!(
            !bounds.contains(f64::NAN, f64::NAN),
            "NaN/NaN must be rejected"
        );
    }

    /// `extract_cot_type` calls `std::str::from_utf8(payload).ok()?` as
    /// the first step; a non-UTF-8 payload must fall through to `None`
    /// rather than panicking. Pin the defensive contract by feeding a
    /// hostile byte sequence (`[0xff, 0xfe, 0xfd]`) and asserting
    /// `None`. A regression that unwrapped the `Result<&str, _>` would
    /// panic every tokio worker handling a malformed wire payload,
    /// taking down the transport for every connected client.
    #[test]
    fn extract_cot_type_returns_none_for_non_utf8_payload() {
        let payload: &[u8] = &[0xff, 0xfe, 0xfd, 0x00, 0x80];
        assert_eq!(extract_cot_type(payload), None);
    }

    /// `extract_point` chains `extract_attr` for `lat` then `lon`, and
    /// the `parse::<f64>().ok()?` inside `extract_attr` must route
    /// non-numeric values through to `None`. Pin the contract by
    /// feeding `lat="not-a-number"` and asserting the whole extraction
    /// returns `None` — a regression that silently coerced to `0.0`
    /// would bypass every configured bounding box filter on malformed
    /// payloads.
    #[test]
    fn extract_point_returns_none_when_lat_is_non_numeric() {
        let xml =
            br#"<event type="a-f-G"><point lat="not-a-number" lon="-90.0" hae="0" /></event>"#;
        assert!(
            extract_point(xml).is_none(),
            "non-numeric lat must cause the whole point extraction to fail"
        );
    }

    /// A partial point (lat present, lon missing) must return `None`.
    /// Pin this explicitly — `extract_point` calls `extract_attr` for
    /// `lat` first, then `lon`, and a regression that silently defaulted
    /// the missing coordinate to `0.0` would let partial points through
    /// the geo filter on `(lat, 0.0)`.
    #[test]
    fn extract_point_returns_none_when_lon_is_missing() {
        let xml = br#"<event type="a-f-G"><point lat="35.5" hae="0" /></event>"#;
        assert!(
            extract_point(xml).is_none(),
            "missing lon must cause the whole point extraction to fail"
        );
    }

    /// `extract_attr` steps past false-match positions by advancing
    /// `search_from` past the matched name. Pin the disambiguation
    /// contract by feeding `<point latitude="50" />` and searching for
    /// `lat`: the scanner must *not* match the `lat` prefix of
    /// `latitude` (since the `="` suffix check fails), and must return
    /// `None`. A regression that dropped the `="` suffix check would
    /// silently extract `50` for `lat` from `latitude="50"`, which
    /// would feed the geo filter the wrong value every time a CoT
    /// payload used the unofficial `latitude`/`longitude` attribute
    /// spelling.
    #[test]
    fn extract_attr_does_not_confuse_prefix_attributes() {
        assert_eq!(
            extract_attr(r#"<point latitude="50" />"#, "lat"),
            None,
            "lat must not match the `lat` prefix of `latitude`"
        );
        assert_eq!(
            extract_attr(r#"<point lat="35.5" />"#, "lat"),
            Some(35.5),
            "exact lat= must still match after the disambiguation check"
        );
    }

    /// `with_type_prefixes(vec![])` must produce a permissive filter —
    /// the empty-list case falls through the `if self.type_prefixes
    /// .is_empty() { return true; }` guard in `matches_type`. Pin this
    /// at the public API so a regression that silently flipped "empty
    /// list means reject all" would break every operator who configured
    /// an empty prefix list as a sentinel for "type filtering
    /// disabled".
    #[test]
    fn empty_type_prefixes_vec_is_equivalent_to_no_filter() {
        let filter = MessageFilter::new().with_type_prefixes(vec![]);
        let msg = make_msg(r#"<event type="a-f-G" uid="test" />"#);
        assert!(
            filter.matches(&msg),
            "empty prefix list must be equivalent to no type filter"
        );
    }
}
