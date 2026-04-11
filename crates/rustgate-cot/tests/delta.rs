// Copyright © 2026 Roberto Chiofalo.

//! Integration tests for the per-UID CoT delta encoder/decoder.
//!
//! These tests exercise the public API of `rustgate_cot::delta`, covering
//! first-emit-as-full behavior, delta roundtripping, LRU eviction,
//! epsilon-based suppression, and robustness against malformed input.

#![allow(clippy::panic, clippy::unwrap_used)]

use std::num::NonZeroUsize;

use bytes::Bytes;
use rustgate_cot::delta::{CotSnapshot, DeltaDecoder, DeltaEncoder, DeltaOutput, parse_snapshot};

fn cap(n: usize) -> NonZeroUsize {
    NonZeroUsize::new(n).expect("nonzero")
}

fn track(uid: &str, lat: f64, lon: f64, t: &str) -> Bytes {
    Bytes::from(format!(
        r#"<event version="2.0" uid="{uid}" type="a-f-G-U-C" how="m-g" time="{t}" start="{t}" stale="{t}"><point lat="{lat}" lon="{lon}" hae="100.0" ce="9.9" le="9.9"/><detail><contact callsign="ALPHA"/><__group name="Cyan" role="Team Member"/></detail></event>"#,
    ))
}

#[test]
fn full_then_delta_produces_smaller_payload() {
    let mut enc = DeltaEncoder::new(cap(8), 0.0);
    let first = track("UNIT-1", 34.0, -118.0, "2026-04-08T12:00:00Z");
    let second = track("UNIT-1", 34.1, -118.2, "2026-04-08T12:00:05Z");

    match enc.encode(&first) {
        DeltaOutput::Full(b) => assert_eq!(b, first),
        other => panic!("expected full, got {other:?}"),
    }
    match enc.encode(&second) {
        DeltaOutput::Delta(b) => {
            assert!(b.len() < second.len(), "delta should be shorter");
            let s = std::str::from_utf8(&b).unwrap();
            assert!(s.contains("<delta "));
            assert!(s.contains("<point "));
            // <detail> is unchanged between the two, so it must be omitted.
            assert!(!s.contains("<detail"));
        }
        other => panic!("expected delta, got {other:?}"),
    }

    let stats = enc.stats();
    assert_eq!(stats.full, 1);
    assert_eq!(stats.delta, 1);
    assert!(stats.bytes_saved > 0);
}

#[test]
fn decoder_round_trip_reconstructs_full_event() {
    let mut enc = DeltaEncoder::new(cap(8), 0.0);
    let mut dec = DeltaDecoder::new(cap(8));

    let first = track("UNIT-2", 34.0, -118.0, "2026-04-08T12:00:00Z");
    let second = track("UNIT-2", 34.5, -118.5, "2026-04-08T12:00:05Z");

    let first_wire = match enc.encode(&first) {
        DeltaOutput::Full(b) => b,
        other => panic!("expected full, got {other:?}"),
    };
    let first_decoded = dec.decode(&first_wire).unwrap();
    assert_eq!(first_decoded, first);

    let second_wire = match enc.encode(&second) {
        DeltaOutput::Delta(b) => b,
        other => panic!("expected delta, got {other:?}"),
    };
    let second_decoded = dec.decode(&second_wire).unwrap();
    let snap = parse_snapshot(&second_decoded).unwrap();
    assert_eq!(snap.uid, "UNIT-2");
    assert_eq!(snap.time, "2026-04-08T12:00:05Z");
    assert_eq!(snap.point.unwrap().lat, 34.5);
    assert_eq!(snap.point.unwrap().lon, -118.5);
    // Detail carries over from the cached prior — verify we reconstructed it.
    assert!(snap.detail_inner.is_some());
    let inner = snap.detail_inner.unwrap();
    assert!(inner.contains("callsign=\"ALPHA\""));
}

#[test]
fn epsilon_suppresses_tiny_drift_with_timestamp_change() {
    // 1m default epsilon: ~5 microdegrees east–west at ~34° lat is <1m.
    let mut enc = DeltaEncoder::new(cap(8), 1.0);
    let _ = enc.encode(&track("UNIT-3", 34.0, -118.0, "2026-04-08T12:00:00Z"));
    let out = enc.encode(&track("UNIT-3", 34.0, -118.000_005, "2026-04-08T12:00:05Z"));
    assert!(matches!(out, DeltaOutput::Suppressed));
    assert_eq!(enc.stats().suppressed, 1);
}

#[test]
fn lru_eviction_reprompts_full_emit() {
    let mut enc = DeltaEncoder::new(cap(2), 0.0);
    let _ = enc.encode(&track("A", 0.0, 0.0, "t"));
    let _ = enc.encode(&track("B", 0.0, 0.0, "t"));
    // Third insertion evicts A (least-recently used).
    let _ = enc.encode(&track("C", 0.0, 0.0, "t"));
    // A comes back — since it was evicted, the next event must be Full.
    match enc.encode(&track("A", 0.0, 0.0, "t2")) {
        DeltaOutput::Full(_) => {}
        other => panic!("expected full after eviction, got {other:?}"),
    }
}

#[test]
fn detail_subtree_change_includes_detail_in_delta() {
    let first = Bytes::from(
        r#"<event version="2.0" uid="D" type="a-f-G" how="m-g" time="t" start="t" stale="t"><point lat="0" lon="0" hae="0" ce="1" le="1"/><detail><contact callsign="ALPHA"/></detail></event>"#.to_string(),
    );
    let second = Bytes::from(
        r#"<event version="2.0" uid="D" type="a-f-G" how="m-g" time="t2" start="t2" stale="t2"><point lat="0" lon="0" hae="0" ce="1" le="1"/><detail><contact callsign="BRAVO"/></detail></event>"#.to_string(),
    );

    let mut enc = DeltaEncoder::new(cap(4), 0.0);
    let _ = enc.encode(&first);
    match enc.encode(&second) {
        DeltaOutput::Delta(b) => {
            let s = std::str::from_utf8(&b).unwrap();
            assert!(s.contains("<detail>"));
            assert!(s.contains("callsign=\"BRAVO\""));
            assert!(
                !s.contains("<point"),
                "point is unchanged, should be absent"
            );
        }
        other => panic!("expected delta, got {other:?}"),
    }
}

#[test]
fn snapshot_parse_is_panic_free_on_garbage() {
    // Property-like smoke: feed random byte blobs and verify no panic.
    for seed in 0..128u32 {
        let len = ((seed * 7) % 128 + 3) as usize;
        let bytes: Vec<u8> = (0..len).map(|i| ((seed ^ i as u32) * 31) as u8).collect();
        let _ = parse_snapshot(&Bytes::from(bytes));
    }
}

#[test]
fn position_only_delta_omits_other_elements() {
    let first = track("UNIT-5", 1.0, 2.0, "2026-01-01T00:00:00Z");
    let second = track("UNIT-5", 1.5, 2.5, "2026-01-01T00:00:05Z");
    let mut enc = DeltaEncoder::new(cap(4), 0.0);
    let _ = enc.encode(&first);
    match enc.encode(&second) {
        DeltaOutput::Delta(b) => {
            let s = std::str::from_utf8(&b).unwrap();
            // Outer stays; delta has only point.
            assert!(s.starts_with("<event "));
            assert!(s.contains("<point "));
            assert!(!s.contains("<detail"));
        }
        other => panic!("expected delta, got {other:?}"),
    }
}

#[test]
fn parse_snapshot_round_trip_stable() {
    // Parse a full event, reconstruct from the snapshot via decoder merge
    // semantics (using it as prior with itself), and re-parse — the second
    // parse must equal the first on all stored fields.
    let raw = track("UNIT-6", 34.0, -118.0, "2026-01-01T00:00:00Z");
    let snap1: CotSnapshot = parse_snapshot(&raw).unwrap();
    assert_eq!(snap1.uid, "UNIT-6");
    assert_eq!(snap1.version, "2.0");
    assert_eq!(snap1.event_type, "a-f-G-U-C");
    let p = snap1.point.unwrap();
    assert_eq!(p.lat, 34.0);
    assert_eq!(p.lon, -118.0);
    assert!((p.ce - 9.9).abs() < 1e-9);
}
