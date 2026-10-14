// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Integration tests for the cross-domain guard — refs #857.
//!
//! Covers the metrics-feature surface and end-to-end audit-log
//! correctness across multiple `evaluate` calls. The `metrics` feature
//! is off by default; tests in this file that depend on it are gated
//! behind `#[cfg(feature = "metrics")]`.

#![allow(clippy::panic, clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::SystemTime;

use bytes::Bytes;
use rustgate_core::identity::Identity;
use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};
#[cfg(feature = "metrics")]
use rustgate_guard::GuardError;
use rustgate_guard::{CrossDomainGuard, GuardConfig, GuardDirection};
use tempfile::TempDir;

fn cot_with_marking(uid: &str, marking: &str) -> Bytes {
    let xml = format!(
        r#"<event uid="{uid}" type="a-f-G-U-C" start="2026-05-04T12:00:00Z" stale="2026-05-04T12:05:00Z"><point lat="38.9" lon="-77.0" hae="125.0"/><detail><marking value="{marking}"/><contact callsign="ALPHA-1"/></detail></event>"#,
    );
    Bytes::from(xml)
}

fn make_message(payload: Bytes) -> RoutableMessage {
    RoutableMessage {
        source: Identity {
            cn: Arc::<str>::from("integration-tester"),
            fingerprint: "fp".to_string(),
            groups: BTreeSet::new(),
            tenant: None,
            spiffe_id: None,
            attributes: Arc::new(std::collections::BTreeMap::new()),
        },
        destination: Destination::Broadcast,
        payload,
        metadata: Metadata::new(SystemTime::now(), "tcp".into(), MessageType::Position),
        entity: None,
    }
}

fn config(tmp: &TempDir, low_bps: u64, high_bps: u64, mandatory: bool) -> GuardConfig {
    GuardConfig {
        low_to_high_max_bps: low_bps,
        high_to_low_max_bps: high_bps,
        mandatory_marking: mandatory,
        audit_log_path: tmp.path().join("boundary-audit.jsonl"),
        direction: GuardDirection::Bidirectional,
        warmup_log_only: false,
        audit_chain_fail_open: false,
    }
}

#[test]
fn audit_log_grows_one_record_per_evaluate_regardless_of_outcome() {
    // Pin the "exactly once" contract: every `evaluate` call — admit or
    // deny — emits exactly one record. The audit chain's `seq` field
    // is monotonic across the calls so a SIEM can detect missed
    // records via gap detection.
    let tmp = TempDir::new().unwrap();
    let cfg = config(&tmp, 1_000_000, 1_000_000, true);
    let path = cfg.audit_log_path.clone();
    let mut g = CrossDomainGuard::new(cfg).unwrap();
    // Three admits.
    for i in 0..3 {
        let msg = make_message(cot_with_marking(&format!("admit-{i}"), "//SECRET//"));
        let _ = g.evaluate(&msg, GuardDirection::LowToHigh).unwrap();
    }
    // Two denies (missing marking).
    let plain = Bytes::from_static(
        b"<event uid=\"deny-1\"><detail><contact callsign=\"X\"/></detail></event>",
    );
    let msg = make_message(plain.clone());
    let _ = g.evaluate(&msg, GuardDirection::LowToHigh);
    let msg = make_message(plain);
    let _ = g.evaluate(&msg, GuardDirection::LowToHigh);
    drop(g);
    let report = rustgate_archive::audit_chain::verify_audit_log(&path).unwrap();
    assert_eq!(report.records, 5);
    let contents = std::fs::read_to_string(&path).unwrap();
    let line_count = contents.lines().count();
    assert_eq!(line_count, 5, "5 records on 5 calls");
}

#[cfg(feature = "metrics")]
#[test]
fn evaluations_metric_increments_on_decision() {
    use prometheus::Encoder;
    // Re-init metrics into a fresh registry attempt; if `init()` was
    // already called by another test in the binary, the OnceLock is
    // sealed and we just observe the existing counters. Call init()
    // and ignore the "AlreadyReg" error path.
    let _ = rustgate_guard::metrics::init();
    let tmp = TempDir::new().unwrap();
    let cfg = config(&tmp, 1_000_000, 1_000_000, false);
    let mut g = CrossDomainGuard::new(cfg).unwrap();
    let msg = make_message(cot_with_marking("u-allow", "//SECRET//"));
    let before = rustgate_guard::metrics::evaluations_total()
        .with_label_values(&["low_to_high", "allow"])
        .get();
    let _ = g.evaluate(&msg, GuardDirection::LowToHigh).unwrap();
    let after = rustgate_guard::metrics::evaluations_total()
        .with_label_values(&["low_to_high", "allow"])
        .get();
    assert_eq!(
        after,
        before + 1,
        "evaluations_total{{direction=low_to_high,decision=allow}} must increment"
    );
    // Smoke-test that the registry can scrape without error.
    let mut buf = Vec::new();
    let encoder = prometheus::TextEncoder::new();
    encoder
        .encode(&prometheus::default_registry().gather(), &mut buf)
        .unwrap();
    let scraped = String::from_utf8(buf).unwrap();
    assert!(scraped.contains("rustgate_guard_evaluations_total"));
}

#[cfg(feature = "metrics")]
#[test]
fn throughput_bps_metric_reflects_consumption() {
    let _ = rustgate_guard::metrics::init();
    let tmp = TempDir::new().unwrap();
    // Tight cap so a single message visibly drops the level.
    let cfg = config(&tmp, 4 * 1024, 4 * 1024, false);
    let mut g = CrossDomainGuard::new(cfg).unwrap();
    let msg = make_message(cot_with_marking("u-bps", "//SECRET//"));
    let _ = g.evaluate(&msg, GuardDirection::LowToHigh).unwrap();
    let level = rustgate_guard::metrics::throughput_bps()
        .with_label_values(&["low_to_high"])
        .get();
    // After consuming one message, the level must be below the cap.
    assert!(
        level < 4 * 1024,
        "bucket level must drop after consumption; got {level}"
    );
    assert!(level >= 0, "level must be non-negative; got {level}");
}

#[cfg(feature = "metrics")]
#[test]
fn rejections_metric_labels_by_reason() {
    let _ = rustgate_guard::metrics::init();
    let tmp = TempDir::new().unwrap();
    let cfg = config(&tmp, 1_000_000, 1_000_000, true);
    let mut g = CrossDomainGuard::new(cfg).unwrap();
    let plain = Bytes::from_static(
        b"<event uid=\"rej\"><detail><contact callsign=\"X\"/></detail></event>",
    );
    let msg = make_message(plain);
    let before = rustgate_guard::metrics::rejections_total()
        .with_label_values(&["low_to_high", "missing_marking"])
        .get();
    let err = g.evaluate(&msg, GuardDirection::LowToHigh);
    assert!(matches!(err, Err(GuardError::MissingMarking)));
    let after = rustgate_guard::metrics::rejections_total()
        .with_label_values(&["low_to_high", "missing_marking"])
        .get();
    assert_eq!(
        after,
        before + 1,
        "rejections_total{{reason=missing_marking}} must increment"
    );
}

#[test]
fn output_hash_changes_when_obligation_applied_pre_guard() {
    // The guard does not chain transforms inside `evaluate` — by
    // contract, the input/output hashes are over the same bytes. But
    // when an obligation actuator (e.g. `strip_pii`) runs UPSTREAM and
    // mutates the payload before it reaches the guard, the audit log
    // for the boundary call captures the post-transform bytes via
    // `input_sha256 == output_sha256 == sha256(post-transform)`. Pin
    // that the transformed bytes produce a DIFFERENT hash than the
    // pre-transform bytes — i.e. the guard is observing the actual
    // bytes-on-the-wire, not a stale upstream copy.
    use rustgate_cot::cdi::strip_pii;
    let original = cot_with_marking("u-x", "//SECRET//");
    let stripped = strip_pii(&original).unwrap();
    assert_ne!(
        original, stripped,
        "strip_pii should mutate the test fixture"
    );

    let tmp = TempDir::new().unwrap();
    let cfg = config(&tmp, 1_000_000, 1_000_000, false);
    let path = cfg.audit_log_path.clone();
    let mut g = CrossDomainGuard::new(cfg).unwrap();
    let msg = make_message(stripped.clone());
    let _ = g.evaluate(&msg, GuardDirection::LowToHigh).unwrap();
    drop(g);

    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(&original);
    let original_hex = hex::encode(h.finalize());
    let mut h = Sha256::new();
    h.update(&stripped);
    let stripped_hex = hex::encode(h.finalize());
    assert_ne!(original_hex, stripped_hex);

    let contents = std::fs::read_to_string(&path).unwrap();
    assert!(
        contents.contains(&stripped_hex),
        "audit must record the post-transform hash, got {contents}"
    );
    assert!(
        !contents.contains(&original_hex),
        "audit must NOT contain the pre-transform hash"
    );
}
