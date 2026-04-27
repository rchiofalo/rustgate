// Copyright © 2026 Roberto Chiofalo.

#![allow(unused_results)]
#![allow(clippy::panic, clippy::unwrap_used)]
//! Audit-trail regression test for the `MaskPoint` non-XML pass-through
//! recovery-token vocabulary (issue #742).
//!
//! `apply_mask_point` (in `rustgate_transport::obligations`) splits its
//! audit emission across three forensic buckets when the payload is not
//! XML-intent: `forwarded_binary` for known binary framings (MAVLink, TAK
//! protobuf, ASTERIX), `forwarded_unmasked` for `source_protocol`
//! claiming XML/CoT but the payload not parseable, and
//! `forwarded_unknown` for unrecognised `source_protocol` values. Pre
//! issue #742 the dispatcher emitted the same `forwarded_unmasked` token
//! for every non-XML payload, which collapsed the three cases into a
//! single audit string and forced operators to re-derive the
//! distinction by hand.
//!
//! This test pins the on-the-wire shape of the new audit emission so a
//! SIEM correlation tool can rely on the field names AND the recovery
//! token strings being stable.
//!
//! Lives in its own integration-test binary so the thread-local audit
//! subscriber installed here cannot race subscribers installed by other
//! in-process tests — tracing caches per-callsite `Interest` globally,
//! so once any test in the same binary emits an `audit!` event without
//! a subscriber installed, the default no-op subscriber returns
//! `Interest::never()` for that callsite and the result is cached
//! process-wide, blocking subsequent thread-local subscribers from
//! reaching it. Same rationale as `store_forward_dwell_audit.rs` and
//! `position_replay_rate_limit_audit.rs`.

use std::collections::BTreeSet;
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use bytes::Bytes;
use rustgate_authz::Obligation;
use rustgate_core::identity::Identity;
use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};
use rustgate_transport::obligations::{UnknownObligationPolicy, apply_obligations};
use tracing_subscriber::Layer;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt;

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

fn build_message(payload: &'static [u8], source_protocol: &str) -> RoutableMessage {
    let id =
        Identity::new("alice".into(), "abc123".into(), BTreeSet::new()).expect("valid identity");
    RoutableMessage {
        source: id,
        destination: Destination::Broadcast,
        payload: Bytes::from_static(payload),
        metadata: Metadata {
            received_at: SystemTime::now(),
            source_protocol: source_protocol.to_string(),
            message_type: MessageType::Other("binary".into()),
            ttl: None,
        },
    }
}

/// Drive `apply_mask_point` end-to-end with the supplied
/// `source_protocol` and return the captured audit JSON output. The
/// payload is hard-coded to a non-XML byte sequence so the dispatcher
/// always lands in the pass-through branch and emits exactly one audit
/// record.
fn run_and_capture(payload: &'static [u8], source_protocol: &str) -> String {
    let buf = SharedBuf::default();
    let layer = tracing_subscriber::fmt::layer()
        .json()
        .with_writer(buf.clone())
        .with_filter(Targets::new().with_target("audit", tracing::Level::INFO));
    let subscriber = tracing_subscriber::registry().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    let mut msg = build_message(payload, source_protocol);
    apply_obligations(
        &mut msg,
        &[Obligation::MaskPoint],
        UnknownObligationPolicy::FailClosed,
    )
    .expect("known obligation must not error under FailClosed");

    // Drop the guard so any async writers flush; explicit drop here is
    // defensive — the `_guard` already covers the synchronous emission.
    drop(_guard);
    buf.snapshot()
}

#[test]
fn apply_mask_point_emits_forwarded_binary_for_mavlink() {
    // A MAVLink frame is a binary payload that cannot host a CoT
    // `<point>` element. The dispatcher passes it through unmasked
    // (correct by design) and the audit token must be
    // `forwarded_binary` so an analyst can distinguish this from the
    // higher-severity unparseable-XML case.
    let mavlink_frame: &[u8] = &[0xFD, 0x09, 0x00, 0x00, 0x00, 0x01, 0x01];
    // Leak to 'static so the helper signature stays simple — every
    // call-site here uses small fixed byte sequences.
    let leaked: &'static [u8] = Box::leak(mavlink_frame.to_vec().into_boxed_slice());
    let log = run_and_capture(leaked, "mavlink");

    assert!(
        log.contains(r#""recovery":"forwarded_binary""#),
        "expected recovery=forwarded_binary in audit, got: {log}"
    );
    assert!(
        log.contains(r#""source_protocol":"mavlink""#),
        "expected source_protocol=mavlink in audit, got: {log}"
    );
    assert!(
        log.contains(r#""event_type":"authz.obligation_failed""#),
        "expected event_type=authz.obligation_failed in audit, got: {log}"
    );
}

#[test]
fn apply_mask_point_emits_forwarded_binary_for_tak_protobuf() {
    // TAK protobuf frames start with the 0xBF magic byte. Same forensic
    // bucket as MAVLink — known binary framing, position masking N/A.
    let tak_frame: &[u8] = &[0xBF, 0x01, 0x02, 0x03];
    let leaked: &'static [u8] = Box::leak(tak_frame.to_vec().into_boxed_slice());
    let log = run_and_capture(leaked, "tak_protobuf");

    assert!(
        log.contains(r#""recovery":"forwarded_binary""#),
        "expected recovery=forwarded_binary in audit, got: {log}"
    );
    assert!(
        log.contains(r#""source_protocol":"tak_protobuf""#),
        "expected source_protocol=tak_protobuf in audit, got: {log}"
    );
}

#[test]
fn apply_mask_point_emits_forwarded_binary_for_tak_protobuf_hyphenated() {
    // `Codec::protocol_id()` returns `"tak-protobuf"` (with hyphen),
    // while older config keys spelled the same wire format
    // `"tak_protobuf"`. Both forms must bucket identically so a
    // federation hop that round-trips the protocol identifier through
    // a hyphen-preferring layer does not flip the recovery token.
    let tak_frame: &[u8] = &[0xBF, 0x01, 0x02, 0x03];
    let leaked: &'static [u8] = Box::leak(tak_frame.to_vec().into_boxed_slice());
    let log = run_and_capture(leaked, "tak-protobuf");

    assert!(
        log.contains(r#""recovery":"forwarded_binary""#),
        "expected recovery=forwarded_binary in audit, got: {log}"
    );
}

#[test]
fn apply_mask_point_emits_forwarded_binary_for_asterix() {
    // ASTERIX (CAT-021/048/062) is a Eurocontrol surveillance binary
    // wire format. Same forensic bucket as MAVLink and TAK protobuf.
    let asterix_frame: &[u8] = &[0x3E, 0x00, 0x10, 0x00];
    let leaked: &'static [u8] = Box::leak(asterix_frame.to_vec().into_boxed_slice());
    let log = run_and_capture(leaked, "asterix");

    assert!(
        log.contains(r#""recovery":"forwarded_binary""#),
        "expected recovery=forwarded_binary in audit, got: {log}"
    );
}

#[test]
fn apply_mask_point_emits_forwarded_unmasked_for_unparseable_xml() {
    // A `source_protocol` claiming `cot` (or `xml`) means the upstream
    // SAID this would be CoT — but the payload's first non-whitespace
    // byte is not `<`, so the dispatcher could not parse it. Position
    // MAY be in the bytes and the masker bypassed inspection. This is
    // the higher-severity audit token, preserved from the pre-issue-
    // #742 vocabulary so SIEM rules keyed on `forwarded_unmasked`
    // continue to fire on exactly this case.
    //
    // Note: a payload that DOES start with `<` but fails to parse
    // takes the fail-closed path with `recovery=dropped` instead;
    // that's a different forensic case covered by the unit tests in
    // `obligations.rs`.
    let log = run_and_capture(b"truncated-cot-payload", "cot");

    assert!(
        log.contains(r#""recovery":"forwarded_unmasked""#),
        "expected recovery=forwarded_unmasked in audit, got: {log}"
    );
    assert!(
        log.contains(r#""source_protocol":"cot""#),
        "expected source_protocol=cot in audit, got: {log}"
    );
}

#[test]
fn apply_mask_point_emits_forwarded_unknown_for_unrecognized_protocol() {
    // Anything not in the known-binary or known-XML lists — a
    // misconfigured upstream, a transport whose identifier this build
    // does not yet recognise, or a deliberate operator-defined label —
    // surfaces in the operator-visibility unknown bucket. Keeps the
    // higher-severity unparseable-XML and N/A-binary cases distinct.
    let log = run_and_capture(b"some random bytes", "unknown_proto_xyz");

    assert!(
        log.contains(r#""recovery":"forwarded_unknown""#),
        "expected recovery=forwarded_unknown in audit, got: {log}"
    );
    assert!(
        log.contains(r#""source_protocol":"unknown_proto_xyz""#),
        "expected source_protocol=unknown_proto_xyz in audit, got: {log}"
    );
}
