// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Public-API integration tests for `rustgate-nffi`.
//!
//! These tests pin the cross-module public-API surface — they run
//! every assertion against the re-exported items at the crate root
//! rather than reaching into private modules, so a future module
//! reshuffle that breaks the integration shape fails here.

#![allow(clippy::unwrap_used, clippy::panic)]

use std::collections::BTreeMap;
use std::time::SystemTime;

use bytes::Bytes;
use rustgate_core::entity::{AttributeValue, Entity, EntityCodec, EntityKind, Position, Velocity};
use rustgate_nffi::{
    Affiliation, AppSixA, BattleDimension, NffiCodec, NffiError, NffiTrack, UnknownElement,
    decode_document, encode_document,
};

const GOLDEN_NFFI: &[u8] = br#"<nffi xmlns="urn:nato:stanag:5527:nffi:2.0:1">
  <track>
    <positionalData>
      <wgs84Position lat="38.0" lon="-77.0" alt="100"/>
      <kinematics speed="12.5" course="270" accuracy="5"/>
      <datetime>2026-05-08T12:00:00Z</datetime>
    </positionalData>
    <identificationData>
      <sidc>SFGPUCI-----C--</sidc>
      <unitName>Alpha-1</unitName>
      <nationality>USA</nationality>
    </identificationData>
  </track>
</nffi>"#;

#[test]
fn golden_decode_extracts_full_track() {
    // Pins the canonical wire form against the typed
    // `NffiTrack` shape. If the spec layout changes (e.g. a
    // future revision moves `<datetime>` outside
    // `<positionalData>`) this fixture will fail and force an
    // explicit decision rather than silently dropping data.
    let doc = decode_document(GOLDEN_NFFI).expect("decode");
    assert_eq!(
        doc.namespace.as_deref(),
        Some("urn:nato:stanag:5527:nffi:2.0:1")
    );
    assert_eq!(doc.tracks.len(), 1);
    let t = &doc.tracks[0];
    assert_eq!(t.unit_name.as_deref(), Some("Alpha-1"));
    assert_eq!(t.nationality.as_deref(), Some("USA"));
    assert_eq!(t.sidc.as_deref(), Some("SFGPUCI-----C--"));
    let pos = t.position.expect("position");
    assert_eq!(pos.lat, 38.0);
    assert_eq!(pos.lon, -77.0);
    assert_eq!(pos.hae_meters, Some(100.0));
    let k = t.kinematics.expect("kinematics");
    assert_eq!(k.speed_m_s, 12.5);
    assert_eq!(k.course_deg, 270.0);
    assert_eq!(k.accuracy_m, Some(5.0));
}

#[test]
fn entity_round_trip_via_codec_preserves_payload_shape() {
    let codec = NffiCodec::new();
    let e1 = codec.to_entity(GOLDEN_NFFI).expect("decode 1");
    let bytes = codec.from_entity(&e1).expect("encode");
    let e2 = codec.to_entity(&bytes).expect("decode 2");
    assert_eq!(e1, e2, "same-codec round trip must be lossless");
}

#[test]
fn document_round_trip_preserves_unknown_element() {
    // The MVP carries `<operStatusData>` (and any future
    // unrecognised sibling) opaque through `UnknownElement`.
    let xml = br#"<nffi xmlns="urn:nato:stanag:5527:nffi:2.0:1"><track><positionalData><wgs84Position lat="0" lon="0"/></positionalData><identificationData><unitName>Bravo</unitName></identificationData><operStatusData>50%</operStatusData></track></nffi>"#;
    let doc = decode_document(xml).expect("decode");
    assert_eq!(doc.tracks.len(), 1);
    let t = &doc.tracks[0];
    assert_eq!(t.unknown.len(), 1);
    assert_eq!(t.unknown[0].name, "operStatusData");
    assert_eq!(t.unknown[0].body.as_deref(), Some("50%"));

    let bytes = encode_document(&doc).expect("encode");
    let doc2 = decode_document(&bytes).expect("re-decode");
    assert_eq!(doc.tracks[0].unknown, doc2.tracks[0].unknown);
}

#[test]
fn malformed_xml_is_rejected_with_typed_error() {
    // Mismatched closing tag — `quick-xml` strict mode rejects
    // `<nffi>...</different>` with a typed error.
    let bad = b"<nffi><track></notatrack></nffi>";
    let err = decode_document(bad).expect_err("must reject");
    assert!(
        matches!(err, NffiError::Xml(_)),
        "expected NffiError::Xml, got {err:?}"
    );
}

#[test]
fn invalid_lat_attribute_value_rejected() {
    let xml = br#"<nffi><track><positionalData><wgs84Position lat="not-a-number" lon="0"/></positionalData></track></nffi>"#;
    let err = decode_document(xml).expect_err("must reject");
    assert!(
        matches!(
            err,
            NffiError::InvalidFloat {
                element: "wgs84Position",
                attribute: "lat",
            }
        ),
        "expected InvalidFloat, got {err:?}"
    );
}

#[test]
fn out_of_range_latitude_rejected() {
    let xml = br#"<nffi><track><positionalData><wgs84Position lat="200" lon="0"/></positionalData></track></nffi>"#;
    let err = decode_document(xml).expect_err("must reject");
    assert!(matches!(err, NffiError::OutOfRange { field: "lat", .. }));
}

#[test]
fn appsix_a_parses_canonical_sidc() {
    // SFGPUCI-----C-- from the golden fixture: Warfighting /
    // Friend / Ground / Present.
    let parsed = AppSixA::parse("SFGPUCI-----C--").expect("parse");
    assert_eq!(parsed.affiliation, Affiliation::Friend);
    assert_eq!(parsed.battle_dimension, BattleDimension::Ground);
    assert_eq!(parsed.entity_kind(), EntityKind::Ground);
}

#[test]
fn appsix_a_rejects_wrong_length() {
    let err = AppSixA::parse("FRIENDLY").expect_err("must reject");
    assert!(matches!(err, NffiError::InvalidSidcLength { actual: 8 }));
}

#[test]
fn empty_document_decodes_then_codec_rejects_no_tracks() {
    let xml = br#"<nffi xmlns="urn:nato:stanag:5527:nffi:2.0:1"></nffi>"#;
    let doc = decode_document(xml).expect("decode");
    assert!(doc.tracks.is_empty());
    let codec = NffiCodec::new();
    let err = codec.to_entity(xml).expect_err("must reject");
    assert!(matches!(err, NffiError::NoTracks));
}

#[test]
fn programmatic_entity_encodes_to_valid_nffi() {
    // Build an entity by hand (simulating cross-codec fan-out:
    // CoT → entity → NFFI) and pin that the encoder produces a
    // round-trippable document. The encoder must synthesise a
    // namespace and a `<datetime>` body when the source entity
    // does not carry them.
    let mut attrs = BTreeMap::new();
    let _ = attrs.insert(
        "nffi.nationality".to_string(),
        AttributeValue::Str("GBR".to_string()),
    );
    let entity = Entity {
        uid: "nffi-Charlie".to_string(),
        kind: EntityKind::Aircraft,
        position: Some(Position {
            lat: 51.5,
            lon: -0.1,
            hae_meters: Some(2500.0),
        }),
        velocity: Some(Velocity {
            speed_m_s: 250.0,
            course_deg: 90.0,
        }),
        timestamp: SystemTime::UNIX_EPOCH,
        callsign: Some("Charlie".to_string()),
        mil_std_2525_sidc: Some("SFAPMFFJ-------".to_string()),
        attributes: attrs,
        taskings: Default::default(),
        files: Default::default(),
    };
    let codec = NffiCodec::new();
    let bytes = codec.from_entity(&entity).expect("encode");
    // Re-decode and pin the structural fields are preserved.
    let doc = decode_document(&bytes).expect("re-decode");
    assert_eq!(doc.tracks.len(), 1);
    let t = &doc.tracks[0];
    assert_eq!(t.unit_name.as_deref(), Some("Charlie"));
    assert_eq!(t.nationality.as_deref(), Some("GBR"));
    assert_eq!(t.sidc.as_deref(), Some("SFAPMFFJ-------"));
    let pos = t.position.expect("position");
    assert_eq!(pos.lat, 51.5);
    assert_eq!(pos.lon, -0.1);
}

#[test]
fn unknown_element_struct_fields_are_public() {
    // Pin the public-field shape of `UnknownElement` so a
    // downstream consumer that constructs one by hand keeps
    // compiling on minor revisions of the crate. The encoder
    // path uses a hand-built `UnknownElement` for the
    // "synthesise an NFFI track from scratch" use case.
    let elem = UnknownElement {
        name: "communicationsStatus".to_string(),
        attributes: vec![("link".to_string(), "up".to_string())],
        body: Some("ok".to_string()),
    };
    assert_eq!(elem.name, "communicationsStatus");
    assert_eq!(elem.attributes.len(), 1);
    assert_eq!(elem.body.as_deref(), Some("ok"));
}

#[test]
fn nffi_track_default_is_empty() {
    // The `Default` impl is used by the parser to allocate a
    // fresh in-progress track when it sees an opening
    // `<track>` tag. Pin that the default is observably empty
    // — a future edit that, say, defaults `unit_name` to the
    // literal `"unknown"` would silently corrupt every parsed
    // track.
    let t = NffiTrack::default();
    assert!(t.unit_name.is_none());
    assert!(t.nationality.is_none());
    assert!(t.sidc.is_none());
    assert!(t.position.is_none());
    assert!(t.kinematics.is_none());
    assert!(t.datetime.is_none());
    assert!(t.datetime_raw.is_none());
    assert!(t.unknown.is_empty());
}

#[test]
fn bytes_returned_by_encode_is_zero_copy_compatible() {
    // The codec returns `Bytes` (not `Vec<u8>`) so an outbound
    // routing path can clone-share without re-allocating. Pin
    // that contract here — if a future refactor changes the
    // return type, this test breaks visibly.
    let codec = NffiCodec::new();
    let e = codec.to_entity(GOLDEN_NFFI).expect("decode");
    let bytes: Bytes = codec.from_entity(&e).expect("encode");
    let cloned = bytes.clone();
    assert_eq!(bytes, cloned);
}
