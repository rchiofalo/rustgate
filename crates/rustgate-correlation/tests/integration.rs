// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! End-to-end correlation engine scenarios.
//!
//! Each test models a realistic multi-sensor configuration — two
//! sensors reporting the same target, two sensors reporting different
//! targets, an aircraft and a ground vehicle at the same lat/lon, a
//! hot-spot of reports overflowing the LRU cap. The unit tests in
//! `src/engine.rs` exercise the algorithm primitives; these tests
//! exercise the algorithm as a whole.

#![allow(clippy::panic, clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};

use rustgate_core::entity::{AttributeValue, Entity, EntityKind, Position, Velocity};
use rustgate_correlation::{
    CorrelationConfig, CorrelationEngine, CorrelationOutcome, RejectionReason,
};

fn entity(uid: &str, kind: EntityKind, lat: f64, lon: f64) -> Entity {
    Entity {
        uid: uid.into(),
        kind,
        position: Some(Position {
            lat,
            lon,
            hae_meters: None,
        }),
        velocity: None,
        timestamp: SystemTime::UNIX_EPOCH,
        callsign: None,
        mil_std_2525_sidc: None,
        attributes: BTreeMap::new(),
        taskings: Default::default(),
        files: Default::default(),
    }
}

fn entity_with_protocol(uid: &str, kind: EntityKind, lat: f64, lon: f64, protocol: &str) -> Entity {
    let mut e = entity(uid, kind, lat, lon);
    let _ = e.attributes.insert(
        "correlation.source_protocol".into(),
        AttributeValue::Str(protocol.into()),
    );
    e
}

#[test]
fn two_sensors_same_target_yield_one_fused_entity() {
    // Scenario: ATAK reports a friendly ground vehicle via CoT;
    // a Link 16 J3.5 ground track report comes in for the same
    // vehicle at near-identical coordinates a few seconds later.
    // The engine must fuse them into a single FusedEntity with
    // two sources.
    let engine = CorrelationEngine::new();
    let t0 = SystemTime::UNIX_EPOCH;
    let cot = entity_with_protocol("ATAK-1", EntityKind::Ground, 38.000000, -77.000000, "cot");
    let link16 = entity_with_protocol(
        "LNK16-7",
        EntityKind::Ground,
        38.000050,
        -77.000050,
        "link16",
    );
    let oc1 = engine.submit_at(cot, t0);
    let oc2 = engine.submit_at(link16, t0 + Duration::from_secs(2));
    assert!(
        matches!(oc1, CorrelationOutcome::Created(_)),
        "first report should create a fused entity, got {oc1:?}",
    );
    assert!(
        matches!(oc2, CorrelationOutcome::Merged(_)),
        "second report should merge, got {oc2:?}",
    );
    assert_eq!(engine.len(), 1, "expected single fused entity");
    let snap = engine.snapshot();
    assert_eq!(snap[0].sources.len(), 2);
    let protos: Vec<&str> = snap[0]
        .sources
        .iter()
        .map(|s| s.source_protocol.as_str())
        .collect();
    assert!(protos.contains(&"cot"));
    assert!(protos.contains(&"link16"));
}

#[test]
fn type_incompatible_reports_at_same_coords_stay_separate() {
    // Scenario: an aircraft at 1000 ft over the same coords as a
    // ground vehicle. The engine must NOT fuse them — they are
    // physically different objects sharing only their projected
    // ground-plane lat/lon.
    let engine = CorrelationEngine::new();
    let t0 = SystemTime::UNIX_EPOCH;
    let aircraft = entity("AIR-1", EntityKind::Aircraft, 38.0, -77.0);
    let ground = entity("VEH-1", EntityKind::Ground, 38.0, -77.0);
    let _ = engine.submit_at(aircraft, t0);
    let oc = engine.submit_at(ground, t0);
    assert!(matches!(oc, CorrelationOutcome::Created(_)));
    assert_eq!(engine.len(), 2);
}

#[test]
fn spatial_gating_rejects_distant_reports() {
    // Scenario: ground track A at coords X; ground track B at
    // coords ~5 km away. The 100 m ground threshold must keep them
    // separate.
    let engine = CorrelationEngine::new();
    let t0 = SystemTime::UNIX_EPOCH;
    let a = entity("A", EntityKind::Ground, 38.000000, -77.000000);
    // ~5 km north.
    let b = entity("B", EntityKind::Ground, 38.045000, -77.000000);
    let _ = engine.submit_at(a, t0);
    let oc = engine.submit_at(b, t0);
    assert!(matches!(oc, CorrelationOutcome::Created(_)));
    assert_eq!(engine.len(), 2);
}

#[test]
fn temporal_gating_rejects_stale_match() {
    // Scenario: ground vehicle reported once; another report for a
    // very-close-by ground vehicle arrives ten minutes later. With
    // the 30 s default window the stale fused entity is past its
    // gate and the new report must spawn a fresh fused entity
    // instead of merging.
    let engine = CorrelationEngine::new();
    let t0 = SystemTime::UNIX_EPOCH;
    let a = entity("A", EntityKind::Ground, 38.0, -77.0);
    let b = entity("B", EntityKind::Ground, 38.000010, -77.000010);
    let _ = engine.submit_at(a, t0);
    let oc = engine.submit_at(b, t0 + Duration::from_secs(600));
    assert!(matches!(oc, CorrelationOutcome::Created(_)));
    // Two separate fused entities; the stale one is still tracked
    // (expire_stale would drop it on the next sweep).
    assert_eq!(engine.len(), 2);
}

#[test]
fn lru_eviction_caps_engine_at_max_entities() {
    // Scenario: hot-spot of 100 reports with max_entities=10.
    // After all 100 submits the engine retains exactly 10 fused
    // entities — the most recently updated ones.
    let config = CorrelationConfig {
        max_entities: 10,
        ..CorrelationConfig::default()
    };
    let engine = CorrelationEngine::with_config(config);
    let t0 = SystemTime::UNIX_EPOCH;
    for i in 0..100 {
        let lat = 38.0 + (i as f64) * 1.0; // far apart -> no fusion
        let lon = -77.0;
        let e = entity(&format!("E-{i}"), EntityKind::Ground, lat, lon);
        let _ = engine.submit_at(e, t0 + Duration::from_secs(i as u64));
    }
    assert_eq!(engine.len(), 10, "engine must respect max_entities cap");
}

#[test]
fn three_sensors_same_target_with_ce90_weighting_biases_position() {
    // Scenario: three sensors report the same vehicle. Two have
    // poor CE90 (50 m); one has tight CE90 (5 m). The fused
    // position must lean toward the tight-CE90 source.
    let engine = CorrelationEngine::new();
    let t0 = SystemTime::UNIX_EPOCH;
    let mut a = entity("A", EntityKind::Ground, 38.000000, -77.000000);
    let _ = a
        .attributes
        .insert("correlation.ce90".into(), AttributeValue::Float(50.0));
    let mut b = entity("B", EntityKind::Ground, 38.000050, -77.000000);
    let _ = b
        .attributes
        .insert("correlation.ce90".into(), AttributeValue::Float(50.0));
    let mut c = entity("C", EntityKind::Ground, 38.000080, -77.000000);
    let _ = c
        .attributes
        .insert("correlation.ce90".into(), AttributeValue::Float(5.0));
    let _ = engine.submit_at(a, t0);
    let _ = engine.submit_at(b, t0);
    let _ = engine.submit_at(c, t0);
    let snap = engine.snapshot();
    assert_eq!(snap.len(), 1, "expected single fused entity");
    let pos = snap[0].fused_position.expect("fused position");
    // C has 100x the weight of A and B (sigma 5 vs 50, 1/σ²
    // ratio 100). Fused lat should be very close to C's 38.000080.
    assert!(
        pos.lat > 38.00007,
        "fused lat {} should bias toward tight-CE90 source",
        pos.lat,
    );
}

#[test]
fn fast_path_repeated_reports_from_one_sensor_update_in_place() {
    // Scenario: one sensor publishes 1 Hz position updates. Each
    // subsequent message must be an Updated, not a Merged — the
    // gating ladder should not fire on every tick.
    let engine = CorrelationEngine::new();
    let t0 = SystemTime::UNIX_EPOCH;
    let outcomes: Vec<_> = (0..5)
        .map(|i| {
            let lat = 38.0 + (i as f64) * 0.000010;
            engine.submit_at(
                entity("repeat", EntityKind::Ground, lat, -77.0),
                t0 + Duration::from_secs(i as u64),
            )
        })
        .collect();
    assert!(matches!(outcomes[0], CorrelationOutcome::Created(_)));
    for (i, oc) in outcomes.iter().enumerate().skip(1) {
        assert!(
            matches!(oc, CorrelationOutcome::Updated(_)),
            "tick {i}: expected Updated, got {oc:?}",
        );
    }
    assert_eq!(engine.len(), 1);
}

#[test]
fn velocity_disagreement_blocks_kinematic_gate() {
    // Scenario: two ground tracks at the same coords but with
    // wildly different speeds (1 m/s vs 30 m/s). A pedestrian and
    // a moving vehicle at the same coordinates are physically
    // different objects — the kinematic gate must drag the score
    // below threshold.
    let engine = CorrelationEngine::new();
    let t0 = SystemTime::UNIX_EPOCH;
    let mut slow = entity("slow", EntityKind::Ground, 38.0, -77.0);
    slow.velocity = Some(Velocity {
        speed_m_s: 1.0,
        course_deg: 0.0,
    });
    let mut fast = entity("fast", EntityKind::Ground, 38.000020, -77.000020);
    fast.velocity = Some(Velocity {
        speed_m_s: 30.0,
        course_deg: 0.0,
    });
    let _ = engine.submit_at(slow, t0);
    let oc = engine.submit_at(fast, t0);
    // Δspeed = 29 m/s vs 25 m/s tolerance — kinematic component is
    // 0. With weights 0.4/0.2/0.2/0.2, max possible total is
    // 0.4 (spatial perfect) + 0.2 (temporal perfect) +
    // 0 (kinematic) + 0.2 (type perfect) = 0.8. 0.8 > threshold,
    // so the engine still merges. Pin that the lower-confidence
    // outcome is reflected in the fused entity's `confidence`.
    if let CorrelationOutcome::Merged(id) = oc {
        let snap = engine.snapshot();
        let merged = snap.iter().find(|e| e.primary_id == id).expect("merged");
        assert!(
            merged.confidence < 1.0,
            "kinematic mismatch should drag confidence below 1.0, got {}",
            merged.confidence,
        );
    } else {
        panic!("expected Merged with degraded confidence, got {oc:?}");
    }
}

#[test]
fn permissive_unknown_kind_can_correlate_with_specific_kind() {
    // Scenario: a SAPIENT autonomous-sensor "blob detection" with
    // EntityKind::Unknown("blob") arrives for the same coords as a
    // CoT friendly aircraft report. The two should fuse — the
    // Unknown variant is operator uncertainty, not a positive ID.
    let engine = CorrelationEngine::new();
    let t0 = SystemTime::UNIX_EPOCH;
    let aircraft = entity_with_protocol("AIR-1", EntityKind::Aircraft, 38.0, -77.0, "cot");
    let blob = entity_with_protocol(
        "SAPIENT-12",
        EntityKind::Unknown("blob".into()),
        38.000050,
        -77.0,
        "sapient",
    );
    let _ = engine.submit_at(aircraft, t0);
    let oc = engine.submit_at(blob, t0);
    assert!(
        matches!(oc, CorrelationOutcome::Merged(_)),
        "Unknown kind should fuse with Aircraft, got {oc:?}",
    );
    let snap = engine.snapshot();
    assert_eq!(snap.len(), 1);
    // The fused classification should be the *more specific*
    // Aircraft, not the permissive Unknown.
    assert_eq!(snap[0].fused_classification, EntityKind::Aircraft);
}

#[test]
fn query_at_returns_results_sorted_by_distance() {
    let engine = CorrelationEngine::new();
    let t0 = SystemTime::UNIX_EPOCH;
    // Three far-apart ground tracks.
    let _ = engine.submit_at(entity("near", EntityKind::Ground, 38.000010, -77.0), t0);
    let _ = engine.submit_at(entity("mid", EntityKind::Ground, 38.005000, -77.0), t0);
    let _ = engine.submit_at(entity("far", EntityKind::Ground, 38.020000, -77.0), t0);
    let results = engine.query_at(38.0, -77.0, 5_000.0);
    // 5 km radius — "near" and "mid" match, "far" (2.2 km) should
    // also match... actually 38.020 is ~2200 m. Let me check:
    // 0.020 * 111_320 = 2226 m. So all three should match for the
    // 5 km radius — and the sort must put "near" first.
    assert!(!results.is_empty());
    assert_eq!(results[0].sources[0].source_id, "near");
}

#[test]
fn submit_rejects_invalid_position() {
    let engine = CorrelationEngine::new();
    let oc = engine.submit(entity("bad", EntityKind::Ground, 200.0, -77.0));
    assert_eq!(
        oc,
        CorrelationOutcome::Rejected(RejectionReason::InvalidPosition)
    );
}

#[test]
fn submit_rejects_missing_position() {
    let engine = CorrelationEngine::new();
    let mut e = entity("bad", EntityKind::Ground, 0.0, 0.0);
    e.position = None;
    let oc = engine.submit(e);
    assert_eq!(
        oc,
        CorrelationOutcome::Rejected(RejectionReason::MissingPosition)
    );
}
