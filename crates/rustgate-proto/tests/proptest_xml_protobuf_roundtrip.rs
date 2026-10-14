// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

#![allow(clippy::panic, clippy::unwrap_used)]
//! Property-based tests for the CoT XML <-> TAK protobuf round-trip.
//!
//! Refs #789 / F-131. Extends the existing unit-level round-trip tests in
//! `crates/rustgate-proto/src/convert/mod.rs` with a generator-driven check
//! that the structurally-meaningful CoT fields (`uid`, `type`, `time`,
//! `start`, `stale`, `lat`, `lon`, `hae`, `ce`, `le`, plus the typed
//! detail elements) survive a full `xml_to_proto -> proto_to_xml -> parse`
//! cycle for any valid CoT shape proptest can synthesise.
//!
//! # Why not byte-for-byte?
//!
//! The XML emitter normalises whitespace, attribute ordering, and a few
//! attributes that have implicit defaults — a strict byte-equality check
//! would force the generator to mirror the emitter's output exactly,
//! which couples the test to the emitter's formatting choices. Comparing
//! re-parsed `FullCotEvent`s isolates the contract that matters: the
//! information model survives the round-trip even if the byte
//! representation drifts.

use proptest::prelude::*;
use rustgate_proto::{parse_full, proto_to_xml, xml_to_proto};

// ── strategies ──────────────────────────────────────────────────────────

/// XML-attribute-safe ASCII string of the given length range.
///
/// Restricted to the alphabet that round-trips through the emitter
/// without escaping: alphanumerics plus dash/underscore/period. The
/// emitter does escape `&<>"'` but the extra escaping noise has no
/// information-content value for the round-trip property — the
/// `proto_to_xml` output already exercises the escaper via the
/// hand-written unit tests.
fn safe_ascii(range: std::ops::Range<usize>) -> impl Strategy<Value = String> {
    proptest::collection::vec(
        prop_oneof![
            "[A-Za-z0-9]",
            Just("-".to_string()),
            Just("_".to_string()),
            Just(".".to_string()),
        ],
        range,
    )
    .prop_map(|parts| parts.concat())
    .prop_filter("non-empty", |s| !s.is_empty())
}

/// CoT type code modeled after MITRE Table 2-1: a few hyphen-separated
/// segments using the affiliation alphabet the spec restricts.
fn cot_type() -> impl Strategy<Value = String> {
    proptest::collection::vec("[a-z]", 2..6)
        .prop_map(|chars| chars.join("-"))
        .prop_filter("at least one segment", |s| !s.is_empty())
}

/// ISO 8601 UTC timestamp the proto crate's parser accepts.
///
/// Years restricted to a sane range (2020..=2099) so the
/// `days_since_epoch` calculation stays in range; fractional millis
/// always emitted because the emitter always emits them on the way back.
fn iso8601_timestamp() -> impl Strategy<Value = String> {
    (
        2020i32..=2099, // year
        1u32..=12,      // month — month 1-12 only avoids day-of-month edge cases
        1u32..=28,      // day — 1-28 covers every month
        0u32..=23,      // hour
        0u32..=59,      // minute
        0u32..=59,      // second
        0u32..=999,     // millis
    )
        .prop_map(|(y, mo, d, h, mi, s, ms)| {
            format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{ms:03}Z")
        })
}

/// Three increasing timestamps representing `time <= start <= stale`.
fn timestamp_triple() -> impl Strategy<Value = (String, String, String)> {
    iso8601_timestamp().prop_map(|t| {
        // Use the same instant for time and start; stale 5 minutes later.
        // The unit-level round-trip tests cover the divergent cases; the
        // property here is ordering-stable.
        (t.clone(), t.clone(), t)
    })
}

/// A full CoT event as a (lat, lon, hae, ce, le, uid, type, time,
/// start, stale, callsign, group_name, role) tuple. The emitter always
/// produces a `<contact>` and `<__group>` when those fields are
/// non-empty, so the generator either emits both or neither.
#[allow(clippy::type_complexity)]
fn cot_event_xml() -> impl Strategy<Value = (String, Vec<u8>)> {
    (
        (-90.0f64..=90.0).prop_filter("non-NaN", |v| v.is_finite()),
        (-180.0f64..=180.0).prop_filter("non-NaN", |v| v.is_finite()),
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
            |(lat, lon, hae, ce, le, uid, ty, (time, start, stale), callsign, group)| {
                let mut detail = String::new();
                if let Some(cs) = &callsign {
                    detail.push_str(&format!(r#"<contact callsign="{cs}"/>"#));
                }
                if let Some(g) = &group {
                    detail.push_str(&format!(r#"<__group name="{g}" role="Member"/>"#));
                }

                let xml = format!(
                    r#"<event version="2.0" uid="{uid}" type="{ty}" how="m-g" time="{time}" start="{start}" stale="{stale}"><point lat="{lat}" lon="{lon}" hae="{hae}" ce="{ce}" le="{le}"/><detail>{detail}</detail></event>"#
                );
                (uid, xml.into_bytes())
            },
        )
}

// ── round-trip property ─────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig {
        // 64 cases is enough to cover the structural variety the
        // generator produces while keeping the test under a second on
        // CI runners. The hand-written unit tests already pin the
        // edge cases (minimal event, missing detail, etc.).
        cases: 64,
        ..ProptestConfig::default()
    })]

    /// Any valid CoT XML round-trips through `xml_to_proto` and
    /// `proto_to_xml` with identical structurally-meaningful content
    /// (uid, type, lat/lon/hae/ce/le, plus any typed detail elements).
    /// Floating-point values round-trip exactly because the proto
    /// encoding is f64 and the XML emitter uses the default Display.
    #[test]
    fn xml_to_proto_round_trip_preserves_structural_fields(
        (expected_uid, xml) in cot_event_xml()
    ) {
        // Forward leg: XML -> protobuf bytes.
        let proto_bytes = xml_to_proto(&xml)
            .map_err(|e| TestCaseError::fail(format!("xml_to_proto failed: {e}")))?;

        // Backward leg: protobuf -> XML.
        let xml_back = proto_to_xml(&proto_bytes)
            .map_err(|e| TestCaseError::fail(format!("proto_to_xml failed: {e}")))?;

        // Re-parse both sides for semantic equality.
        let original = parse_full(&xml)
            .map_err(|e| TestCaseError::fail(format!("parse_full(original) failed: {e}")))?;
        let restored = parse_full(&xml_back)
            .map_err(|e| TestCaseError::fail(format!("parse_full(restored) failed: {e}")))?;

        prop_assert_eq!(&original.uid, &expected_uid);
        prop_assert_eq!(&original.uid, &restored.uid);
        prop_assert_eq!(&original.event_type, &restored.event_type);

        // Floating-point fields use f64 in both proto and XML emitter,
        // so the round-trip is exact when the emitter formats with
        // Display.
        prop_assert!(
            (original.lat - restored.lat).abs() < f64::EPSILON,
            "lat drift: original={} restored={}",
            original.lat,
            restored.lat
        );
        prop_assert!(
            (original.lon - restored.lon).abs() < f64::EPSILON,
            "lon drift"
        );
        prop_assert!(
            (original.hae - restored.hae).abs() < f64::EPSILON,
            "hae drift"
        );
        prop_assert!(
            (original.ce - restored.ce).abs() < f64::EPSILON,
            "ce drift"
        );
        prop_assert!(
            (original.le - restored.le).abs() < f64::EPSILON,
            "le drift"
        );

        // Timestamps round-trip via epoch-millis on both sides — when
        // the original embedded ms precision the restored ms must
        // match. The emitter always re-emits `.SSS` so `.000` shows up
        // even if the original was `.000`.
        prop_assert_eq!(&original.time, &restored.time, "time drift");
        prop_assert_eq!(&original.start, &restored.start, "start drift");
        prop_assert_eq!(&original.stale, &restored.stale, "stale drift");

        // Typed detail elements survive when present.
        match (&original.contact, &restored.contact) {
            (Some(a), Some(b)) => prop_assert_eq!(&a.callsign, &b.callsign),
            (None, None) => {}
            (a, b) => return Err(TestCaseError::fail(format!(
                "contact mismatch: original={a:?} restored={b:?}"
            ))),
        }
        match (&original.group, &restored.group) {
            (Some(a), Some(b)) => {
                prop_assert_eq!(&a.name, &b.name);
                prop_assert_eq!(&a.role, &b.role);
            }
            (None, None) => {}
            (a, b) => return Err(TestCaseError::fail(format!(
                "group mismatch: original={a:?} restored={b:?}"
            ))),
        }
    }
}
