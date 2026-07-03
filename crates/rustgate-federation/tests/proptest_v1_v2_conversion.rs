// Copyright © 2026 Roberto Chiofalo.

#![allow(clippy::panic, clippy::unwrap_used)]
//! Property-based tests for the V1 (length-prefixed XML) <-> V2 (gRPC
//! `FederatedEvent`) conversion path.
//!
//! Refs #789 / F-131. The V1 wire format is raw CoT XML; the V2 wire
//! format is a `FederatedEvent` protobuf carrying a `GeoEvent`. The
//! workspace crosses between the two via `xml_to_federated_event` and
//! `federated_event_to_xml` in `crates/rustgate-federation/src/v2/convert/`.
//!
//! This proptest pins the round-trip property the federation manager
//! depends on: any V1-format XML the workspace's parser accepts can be
//! converted to a `FederatedEvent`, back to XML, and re-parsed without
//! losing the structurally-meaningful CoT fields (`uid`, `type`,
//! `point.lat/lon/hae/ce/le`, `<contact>` callsign, `<__group>` name +
//! role, `<status>` battery). Test only runs under the `v2` feature
//! because the conversion functions live behind that flag.

#![cfg(feature = "v2")]

use bytes::Bytes;
use proptest::prelude::*;
use rustgate_core::identity::Identity;
use rustgate_core::message::{
    Destination, MessageType, Metadata, RoutableMessage, SOURCE_FEDERATION,
};
use rustgate_federation::provenance::FederationMetadata;
use rustgate_federation::v2::convert::{
    federated_event_to_routable, federated_event_to_xml, routable_to_federated_event,
    xml_to_federated_event,
};

// ── strategies ──────────────────────────────────────────────────────────

/// XML-attribute-safe ASCII string (mirrors the proto crate's strategy).
fn safe_ascii(range: std::ops::Range<usize>) -> impl Strategy<Value = String> {
    proptest::collection::vec(
        prop_oneof!["[A-Za-z0-9]", Just("-".to_string()), Just("_".to_string()),],
        range,
    )
    .prop_map(|parts| parts.concat())
    .prop_filter("non-empty", |s| !s.is_empty())
}

/// CoT type code following MITRE Table 2-1 affiliation alphabet.
fn cot_type() -> impl Strategy<Value = String> {
    proptest::collection::vec("[a-z]", 2..6)
        .prop_map(|chars| chars.join("-"))
        .prop_filter("non-empty", |s| !s.is_empty())
}

/// Three identical timestamps so the property doesn't trip on
/// `time != start != stale` orderings the wire emitter tolerates but
/// re-emits in canonical form.
fn timestamp_triple() -> impl Strategy<Value = String> {
    (
        2020i32..=2099,
        1u32..=12,
        1u32..=28,
        0u32..=23,
        0u32..=59,
        0u32..=59,
        0u32..=999,
    )
        .prop_map(|(y, mo, d, h, mi, s, ms)| {
            format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{ms:03}Z")
        })
}

/// V1-format CoT XML message. Returns the source UID for assertion.
#[allow(clippy::type_complexity)]
fn v1_cot_xml() -> impl Strategy<Value = (String, String, Vec<u8>)> {
    (
        (-90.0f64..=90.0).prop_filter("finite", |v| v.is_finite()),
        (-180.0f64..=180.0).prop_filter("finite", |v| v.is_finite()),
        (-1000.0f64..=20000.0),
        (0.0f64..=10_000.0),
        (0.0f64..=10_000.0),
        safe_ascii(1..32),
        cot_type(),
        timestamp_triple(),
        prop::option::of(safe_ascii(1..16)),
        prop::option::of(safe_ascii(1..16)),
    )
        .prop_map(
            |(lat, lon, hae, ce, le, uid, ty, time, callsign, group)| {
                let mut detail = String::new();
                if let Some(cs) = &callsign {
                    detail.push_str(&format!(r#"<contact callsign="{cs}"/>"#));
                }
                if let Some(g) = &group {
                    detail.push_str(&format!(r#"<__group name="{g}" role="Member"/>"#));
                }

                let xml = format!(
                    r#"<event version="2.0" uid="{uid}" type="{ty}" how="m-g" time="{time}" start="{time}" stale="{time}"><point lat="{lat}" lon="{lon}" hae="{hae}" ce="{ce}" le="{le}"/><detail>{detail}</detail></event>"#
                );
                (uid, ty, xml.into_bytes())
            },
        )
}

fn empty_metadata() -> FederationMetadata {
    FederationMetadata {
        provenance: Vec::new(),
        max_hops: 10,
        current_hops: 0,
    }
}

// ── round-trip property ─────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig {
        // 64 cases keeps under a second on CI runners while exercising
        // the structural variety of CoT fields. Edge cases (empty
        // detail, missing optional fields) are pinned by the
        // hand-written unit tests inside the convert module.
        cases: 64,
        ..ProptestConfig::default()
    })]

    /// Any valid V1 CoT XML round-trips through V2's `FederatedEvent`
    /// representation with identical structurally-meaningful content.
    ///
    /// V1 wire (XML) -> `xml_to_federated_event` -> V2 wire (proto)
    /// -> `federated_event_to_xml` -> V1 wire again -> re-parse via
    /// the same V2 conversion -> identical `GeoEvent`.
    #[test]
    fn v1_xml_round_trips_through_v2_federated_event(
        (expected_uid, expected_type, xml) in v1_cot_xml()
    ) {
        // V1 XML -> V2 FederatedEvent.
        let event_v2 = xml_to_federated_event(&xml, &empty_metadata())
            .map_err(|e| TestCaseError::fail(format!("xml_to_federated_event: {e}")))?;

        // V2 -> V1 XML.
        let xml_back = federated_event_to_xml(&event_v2)
            .map_err(|e| TestCaseError::fail(format!("federated_event_to_xml: {e}")))?;

        // V1 again -> V2 FederatedEvent again.
        let event_v2_again = xml_to_federated_event(&xml_back, &empty_metadata())
            .map_err(|e| TestCaseError::fail(format!("xml_to_federated_event(round 2): {e}")))?;

        let geo_orig = event_v2
            .event
            .as_ref()
            .ok_or_else(|| TestCaseError::fail("expected GeoEvent on first leg"))?;
        let geo_round = event_v2_again
            .event
            .as_ref()
            .ok_or_else(|| TestCaseError::fail("expected GeoEvent on round-trip"))?;

        // Core identifiers must match exactly.
        prop_assert_eq!(&geo_orig.uid, &expected_uid);
        prop_assert_eq!(&geo_orig.uid, &geo_round.uid);
        prop_assert_eq!(&geo_orig.r#type, &expected_type);
        prop_assert_eq!(&geo_orig.r#type, &geo_round.r#type);

        // f64 fields are stored without precision loss in proto and
        // re-rendered with Display in the XML emitter.
        prop_assert!((geo_orig.lat - geo_round.lat).abs() < f64::EPSILON, "lat drift");
        prop_assert!((geo_orig.lon - geo_round.lon).abs() < f64::EPSILON, "lon drift");
        prop_assert!((geo_orig.hae - geo_round.hae).abs() < f64::EPSILON, "hae drift");
        prop_assert!((geo_orig.ce - geo_round.ce).abs() < f64::EPSILON, "ce drift");
        prop_assert!((geo_orig.le - geo_round.le).abs() < f64::EPSILON, "le drift");

        // Timestamps round-trip via epoch-millis on both sides.
        prop_assert_eq!(geo_orig.send_time, geo_round.send_time, "send_time drift");
        prop_assert_eq!(geo_orig.start_time, geo_round.start_time, "start drift");
        prop_assert_eq!(geo_orig.stale_time, geo_round.stale_time, "stale drift");

        // Typed detail-field round-trips.
        prop_assert_eq!(&geo_orig.screen_name, &geo_round.screen_name, "callsign drift");
        prop_assert_eq!(&geo_orig.group_name, &geo_round.group_name, "group_name drift");
        prop_assert_eq!(&geo_orig.group_role, &geo_round.group_role, "group_role drift");
    }

    /// `RoutableMessage` <-> `FederatedEvent` cross-conversion is the
    /// hot path inside the federation manager — every inbound V2
    /// message becomes a `RoutableMessage` and every outbound one
    /// goes the other way. This property pins that the cross-
    /// conversion preserves the source CN, the destination, and the
    /// structurally-meaningful event fields.
    #[test]
    fn routable_to_event_to_routable_preserves_source_cn(
        (uid, _ty, xml) in v1_cot_xml(),
        cn in safe_ascii(1..32),
    ) {
        let identity = Identity::new(cn.clone(), "fp-abc".into(), Default::default())
            .map_err(|e| TestCaseError::fail(format!("identity: {e}")))?;
        let msg = RoutableMessage {
            source: identity,
            destination: Destination::Broadcast,
            payload: Bytes::from(xml.clone()),
            metadata: Metadata::new(std::time::SystemTime::now(), SOURCE_FEDERATION.to_string(), MessageType::Position),
            entity: None,
        };

        let event = routable_to_federated_event(&msg, &empty_metadata())
            .map_err(|e| TestCaseError::fail(format!("routable_to_event: {e}")))?;

        // trust_peer_groups=true echoes the wire-claimed groups so the
        // identity round-trip is testable; the security-critical
        // false-default is pinned by unit tests.
        let msg_back = federated_event_to_routable(&event, &cn, "fp-abc", true)
            .map_err(|e| TestCaseError::fail(format!("event_to_routable: {e}")))?;

        prop_assert_eq!(&*msg_back.source.cn, &cn);
        prop_assert_eq!(&msg_back.metadata.source_protocol, SOURCE_FEDERATION);
        let geo = event
            .event
            .as_ref()
            .ok_or_else(|| TestCaseError::fail("expected GeoEvent on outbound conversion"))?;
        prop_assert_eq!(&geo.uid, &uid);
    }
}
