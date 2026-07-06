// Copyright © 2026 Roberto Chiofalo.

#![allow(unused_results)]
#![allow(clippy::panic, clippy::unwrap_used)]
//! Integration tests for the cross-domain inspection obligation
//! scaffold (refs #857).
//!
//! These tests pin the dispatcher-level contract for the three CDI
//! obligation variants `StripPii`, `DegradePosition`, and
//! `InjectMarking`:
//!
//! - Each variant transforms the payload as documented when applied to
//!   well-formed CoT XML.
//! - Each variant is a pass-through on non-CoT (binary) payloads, with
//!   the standard non-XML audit emission.
//! - Each variant fail-closes (erase the body) when the payload is
//!   XML-intent but the parser trips, so a crafted partial document
//!   cannot leak pre-redaction bytes via pass-through recovery.
//! - The three variants compose associatively under the canonical
//!   chaining order.
//! - Audit events are emitted with the `apply_obligation`/`success`
//!   action+result pair via [`audit::egress_obligation_applied`] when
//!   the full egress path is exercised; the dispatcher-level entrypoint
//!   exercised here pins the shape of [`audit::authz_obligation_failed`]
//!   on the recovery paths.
//!
//! This binary lives separately from `obligation_static_reason_audit.rs`
//! for the same reason: tracing's per-callsite Interest cache is
//! process-wide, so each in-process audit-subscriber test must own its
//! own binary to avoid cache pollution from sibling tests.

use std::collections::BTreeSet;
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use bytes::Bytes;
use rustgate_authz::Obligation;
use rustgate_core::identity::Identity;
use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};
use rustgate_router::obligations::{UnknownObligationPolicy, apply_obligations};
use tracing_subscriber::Layer;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt;

const COT_WITH_PII: &[u8] = br#"<event uid="u1" type="a-f-G-U-C" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z"><point lat="38.8977" lon="-77.0365" hae="125.4"/><detail><contact callsign="ALPHA-1" phone="+1-555-0100" email="alpha@example.test"/></detail></event>"#;

#[derive(Clone, Default)]
struct SharedBuf(Arc<Mutex<Vec<u8>>>);

impl SharedBuf {
    fn snapshot(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

impl Write for SharedBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for SharedBuf {
    type Writer = SharedBuf;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

fn build_msg(payload: &'static [u8], source_protocol: &str) -> RoutableMessage {
    let id =
        Identity::new("alice".into(), "abc123".into(), BTreeSet::new()).expect("valid identity");
    RoutableMessage {
        source: id,
        destination: Destination::Broadcast,
        payload: Bytes::from_static(payload),
        metadata: Metadata::new(
            SystemTime::now(),
            source_protocol.to_string(),
            MessageType::Other("xml".into()),
        ),
        entity: None,
    }
}

fn apply(msg: &mut RoutableMessage, obligations: &[Obligation]) {
    apply_obligations(msg, obligations, UnknownObligationPolicy::FailClosed)
        .expect("known obligations always apply under FailClosed");
}

fn capture_audit<F: FnOnce()>(body: F) -> String {
    let buf = SharedBuf::default();
    let layer = tracing_subscriber::fmt::layer()
        .json()
        .with_writer(buf.clone())
        .with_filter(Targets::new().with_target("audit", tracing::Level::INFO));
    let subscriber = tracing_subscriber::registry().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);
    body();
    drop(_guard);
    buf.snapshot()
}

// ── StripPii ────────────────────────────────────────────────────────

#[test]
fn strip_pii_removes_callsign_from_cot_detail() {
    let mut msg = build_msg(COT_WITH_PII, "cot");
    apply(&mut msg, &[Obligation::StripPii]);
    let s = std::str::from_utf8(&msg.payload).unwrap();
    assert!(
        s.contains(r#"callsign="""#),
        "callsign attribute not blanked: {s}",
    );
    assert!(!s.contains("ALPHA-1"), "callsign value leaked: {s}");
    // Phone and email are also identity-linked and must be stripped.
    assert!(!s.contains("555-0100"), "phone leaked: {s}");
    assert!(!s.contains("alpha@example.test"), "email leaked: {s}");
    // Envelope metadata still survives (uid, type) so the document is
    // forwardable.
    assert!(s.contains(r#"uid="u1""#), "envelope uid removed: {s}");
}

#[test]
fn strip_pii_passes_non_cot_payload_through_unchanged() {
    // First byte 0xFD = MAVLink v2 magic — not XML, so the helper must
    // forward verbatim and the dispatcher must NOT erase the body.
    let frame: &'static [u8] = &[0xFD, 0x09, 0x00, 0x00, 0x00, 0x01, 0x01];
    let mut msg = build_msg(frame, "mavlink");
    let before = msg.payload.clone();
    apply(&mut msg, &[Obligation::StripPii]);
    assert_eq!(
        msg.payload, before,
        "binary payload mutated: {:?}",
        msg.payload
    );
}

#[test]
fn strip_pii_handles_malformed_xml_gracefully() {
    // XML-intent (starts with `<`) but truncated mid-document. The
    // dispatcher must fail-closed (empty body) rather than forward the
    // already-leaked PII bytes that preceded the parse error.
    let malformed: &'static [u8] =
        br#"<event><detail><contact callsign="X" phone="Y"/><unterminated"#;
    let mut msg = build_msg(malformed, "cot");
    apply(&mut msg, &[Obligation::StripPii]);
    assert!(
        msg.payload.is_empty(),
        "malformed payload must be erased on parse failure: {:?}",
        msg.payload,
    );
    assert_eq!(
        msg.metadata.message_type,
        MessageType::Other("masked".into()),
        "message type must be coerced to masked on fail-closed",
    );
}

// ── DegradePosition ─────────────────────────────────────────────────

#[test]
fn degrade_position_rounds_lat_lon_to_kilometer_precision() {
    let mut msg = build_msg(COT_WITH_PII, "cot");
    apply(
        &mut msg,
        &[Obligation::DegradePosition {
            precision_meters: 1000,
        }],
    );
    let s = std::str::from_utf8(&msg.payload).unwrap();
    // Raw coordinate values must NOT survive byte-for-byte at km
    // precision.
    assert!(!s.contains("38.8977"), "raw lat leaked: {s}");
    assert!(!s.contains("-77.0365"), "raw lon leaked: {s}");
    // Rounded coordinate prefix must be present (38.8 or 38.9 / -77.0
    // or -77.1 depending on grid alignment) so a downstream consumer
    // sees a coarse but parseable position.
    assert!(
        s.contains(r#"lat="38.8"#) || s.contains(r#"lat="38.9"#),
        "lat not rounded near 38.9: {s}",
    );
    assert!(
        s.contains(r#"lon="-77.0"#) || s.contains(r#"lon="-77.1"#),
        "lon not rounded near -77.0: {s}",
    );
}

#[test]
fn degrade_position_preserves_other_cot_attributes() {
    let mut msg = build_msg(COT_WITH_PII, "cot");
    apply(
        &mut msg,
        &[Obligation::DegradePosition {
            precision_meters: 1000,
        }],
    );
    let s = std::str::from_utf8(&msg.payload).unwrap();
    // Envelope and detail children remain untouched — degrade_position
    // only rewrites <point lat lon>. PII strip is a separate obligation
    // that may chain after this one; alone, DegradePosition must not
    // touch <contact>.
    assert!(s.contains(r#"uid="u1""#));
    assert!(s.contains(r#"type="a-f-G-U-C""#));
    assert!(s.contains(r#"callsign="ALPHA-1""#));
    // hae passes through (altitude degradation is not in scope for the
    // scaffold).
    assert!(s.contains(r#"hae="125.4""#));
}

#[test]
fn degrade_position_no_op_on_non_cot_payload() {
    let frame: &'static [u8] = &[0xBF, 0x01, 0x02, 0x03];
    let mut msg = build_msg(frame, "tak-protobuf");
    let before = msg.payload.clone();
    apply(
        &mut msg,
        &[Obligation::DegradePosition {
            precision_meters: 1000,
        }],
    );
    assert_eq!(msg.payload, before, "non-XML payload mutated by degrade");
}

// ── InjectMarking ───────────────────────────────────────────────────

#[test]
fn inject_marking_adds_capco_marking_to_detail() {
    let mut msg = build_msg(COT_WITH_PII, "cot");
    apply(
        &mut msg,
        &[Obligation::InjectMarking {
            marking: "//SECRET//NOFORN".to_string(),
        }],
    );
    let s = std::str::from_utf8(&msg.payload).unwrap();
    assert!(
        s.contains(r#"<marking value="//SECRET//NOFORN""#),
        "marking element not injected: {s}",
    );
    // Existing <detail> children survive.
    assert!(s.contains(r#"callsign="ALPHA-1""#), "contact lost: {s}");
}

#[test]
fn inject_marking_replaces_existing_marking_if_present() {
    // A document that already carries a `<marking>` (e.g. from a
    // previous CDI hop) must have it replaced rather than accumulating
    // multiple banners — the most recent CDI transition is the
    // operational truth.
    let xml: &'static [u8] = br#"<event uid="u1"><detail><marking value="//OLD//"/><contact callsign="A"/></detail></event>"#;
    let mut msg = build_msg(xml, "cot");
    apply(
        &mut msg,
        &[Obligation::InjectMarking {
            marking: "//NEW//SECRET".to_string(),
        }],
    );
    let s = std::str::from_utf8(&msg.payload).unwrap();
    assert!(
        s.contains(r#"<marking value="//NEW//SECRET""#),
        "new marking not injected: {s}",
    );
    assert!(!s.contains("//OLD//"), "old marking survived: {s}");
    // Sibling detail elements remain.
    assert!(s.contains(r#"callsign="A""#), "sibling lost: {s}");
}

#[test]
fn inject_marking_no_op_on_non_xml_payload() {
    let frame: &'static [u8] = &[0xFD, 0x09, 0x00, 0x00, 0x01];
    let mut msg = build_msg(frame, "mavlink");
    let before = msg.payload.clone();
    apply(
        &mut msg,
        &[Obligation::InjectMarking {
            marking: "//SECRET//NOFORN".to_string(),
        }],
    );
    assert_eq!(msg.payload, before, "non-XML payload mutated by inject");
}

// ── Composition ─────────────────────────────────────────────────────

#[test]
fn apply_chain_strip_pii_then_degrade_position_is_associative() {
    // The dispatcher applies obligations in canonical chaining order.
    // The composition contract from #882 (extended with the #857 CDI
    // variants in the same Group 1 bucket) requires that two
    // permutations of the same set produce byte-identical output.
    let perm_a = [
        Obligation::StripPii,
        Obligation::DegradePosition {
            precision_meters: 1000,
        },
    ];
    let perm_b = [
        Obligation::DegradePosition {
            precision_meters: 1000,
        },
        Obligation::StripPii,
    ];
    let mut msg_a = build_msg(COT_WITH_PII, "cot");
    let mut msg_b = build_msg(COT_WITH_PII, "cot");
    apply(&mut msg_a, &perm_a);
    apply(&mut msg_b, &perm_b);
    assert_eq!(
        msg_a.payload, msg_b.payload,
        "canonical chaining must produce byte-identical output regardless of input order",
    );
    // Sanity: PII gone, position degraded.
    let s = std::str::from_utf8(&msg_a.payload).unwrap();
    assert!(!s.contains("ALPHA-1"));
    assert!(!s.contains("38.8977"));
}

// ── Audit ───────────────────────────────────────────────────────────

#[test]
fn obligation_audit_event_carries_obligation_type() {
    // The dispatcher emits `authz.obligation_failed` with the
    // obligation name (e.g. `"StripPii"`) when a CDI obligation lands
    // on a non-XML payload. Pin both the event_type and the
    // obligation field shape so SIEM rules keyed on either can rely
    // on the contract. Use a binary payload to drive the non-XML
    // recovery path — that's the audit emission the dispatcher fires
    // unconditionally.
    let frame: &'static [u8] = &[0xFD, 0x09, 0x00, 0x00, 0x01];
    let log = capture_audit(|| {
        let mut msg = build_msg(frame, "mavlink");
        apply(&mut msg, &[Obligation::StripPii]);
    });
    assert!(
        log.contains(r#""event_type":"authz.obligation_failed""#),
        "expected event_type=authz.obligation_failed, got: {log}",
    );
    assert!(
        log.contains(r#""obligation":"StripPii""#),
        "expected obligation=StripPii in audit, got: {log}",
    );
    assert!(
        log.contains(r#""reason":"cdi_non_xml""#),
        "expected reason=cdi_non_xml, got: {log}",
    );
}
