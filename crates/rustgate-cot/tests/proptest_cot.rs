// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

#![allow(clippy::panic, clippy::unwrap_used)]
//! Property-based tests for CoT XML parsing using proptest.
//!
//! Validates that any valid CoT XML that parses successfully maintains
//! structural invariants (uid present, event_type present, etc.).

use bytes::Bytes;
use proptest::prelude::*;
use rustgate_cot::{CotDestination, parse};

/// Strategy to generate valid CoT XML strings with arbitrary field values.
fn cot_xml_strategy() -> impl Strategy<Value = String> {
    (
        "[a-zA-Z0-9_-]{1,32}",     // uid
        "[a-z]-[a-z]-[A-Z]-[A-Z]", // event_type pattern
        -90.0f64..90.0,             // lat
        -180.0f64..180.0,           // lon
        -500.0f64..50000.0,         // hae
        prop::option::of("[a-zA-Z]{1,16}"), // optional group name
        prop::option::of("[a-zA-Z0-9_-]{1,32}"), // optional dest callsign
        prop::option::of("[a-zA-Z]{1,16}"), // optional dest group
    )
        .prop_map(
            |(uid, event_type, lat, lon, hae, group, dest_callsign, dest_group)| {
                let mut detail_inner = String::new();

                if let Some(g) = &group {
                    detail_inner.push_str(&format!(r#"<__group name="{g}"/>"#));
                }

                if let Some(cs) = &dest_callsign {
                    detail_inner.push_str(&format!(r#"<dest callsign="{cs}"/>"#));
                } else if let Some(dg) = &dest_group {
                    detail_inner.push_str(&format!(r#"<dest group="{dg}"/>"#));
                }

                format!(
                    r#"<event uid="{uid}" type="{event_type}" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z"><point lat="{lat}" lon="{lon}" hae="{hae}"/><detail>{detail_inner}</detail></event>"#
                )
            },
        )
}

proptest! {
    /// Any CoT XML generated from valid components should parse successfully,
    /// and the parsed result should preserve the uid and event_type.
    #[test]
    fn cot_parse_preserves_uid_and_type(xml in cot_xml_strategy()) {
        let result = parse(xml.as_bytes());
        prop_assert!(result.is_ok(), "parse failed: {:?}", result.err());
        let event = result.unwrap();
        prop_assert!(!event.uid.is_empty(), "uid should not be empty");
        prop_assert!(!event.event_type.is_empty(), "event_type should not be empty");
    }

    /// Parsed position coordinates should be finite numbers when present.
    #[test]
    fn cot_parse_position_is_finite(xml in cot_xml_strategy()) {
        let event = parse(xml.as_bytes()).unwrap();
        if let Some(pos) = event.position {
            prop_assert!(pos.lat.is_finite(), "lat should be finite");
            prop_assert!(pos.lon.is_finite(), "lon should be finite");
            prop_assert!(pos.hae.is_finite(), "hae should be finite");
        }
    }

    /// Destination parsing is consistent with the detail elements:
    /// callsign produces Callsign, group produces Group, neither produces Broadcast.
    #[test]
    fn cot_destination_matches_detail(
        uid in "[a-zA-Z0-9_-]{1,16}",
        dest_variant in 0u8..3,
    ) {
        let (detail, expected_variant) = match dest_variant {
            0 => (r#"<dest callsign="target"/>"#.to_string(), 0u8),
            1 => (r#"<dest group="alpha"/>"#.to_string(), 1),
            _ => (String::new(), 2),
        };

        let xml = format!(
            r#"<event uid="{uid}" type="a-f-G-U-C" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z"><point lat="0" lon="0" hae="0"/><detail>{detail}</detail></event>"#
        );

        let event = parse(xml.as_bytes()).unwrap();

        match expected_variant {
            0 => prop_assert!(matches!(event.destination, CotDestination::Callsign(_))),
            1 => prop_assert!(matches!(event.destination, CotDestination::Group(_))),
            _ => prop_assert!(matches!(event.destination, CotDestination::Broadcast)),
        }
    }

    /// The MessageBuilder should not panic on any valid CoT payload.
    #[test]
    fn cot_message_builder_never_panics(xml in cot_xml_strategy()) {
        let identity = rustgate_core::identity::Identity::plaintext(
            "test-user".to_string(),
            std::collections::BTreeSet::new(),
        )
        .unwrap();

        let mut builder = rustgate_cot::MessageBuilder::new();
        let payload = Bytes::from(xml);
        // Should not panic regardless of content
        let _msg = builder.build(&identity, payload, "test");
    }
}
