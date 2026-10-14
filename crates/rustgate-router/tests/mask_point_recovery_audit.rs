// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

#![allow(unused_results)]
#![allow(clippy::panic, clippy::unwrap_used)]
//! Audit-trail + payload regression test for `MaskPoint` recovery on
//! non-XML payloads (issues #742, #1545 / SEC-18).
//!
//! `apply_mask_point` (in `rustgate_router::obligations`) can mask two
//! payload shapes — CoT XML and MAVLink. Every other position-bearing
//! protocol (DIS, Link 16, ASTERIX, VMF, SAPIENT, NFFI, STANAG 4586,
//! Meshtastic, TAK protobuf) has no registered coordinate masker.
//!
//! Before #1545 those payloads were **forwarded unmasked** with a
//! `forwarded_binary` / `forwarded_unmasked` / `forwarded_unknown` audit
//! token — so a `MaskPoint` obligation meant to strip location did
//! nothing and the original coordinates egressed intact. #1545 makes the
//! non-XML branch **fail closed**: the body is erased (the same terminal
//! state the XML-parse-failure path produces) and the audit token is
//! `recovery = "dropped"`. See ADR 0027.
//!
//! This test pins both halves of that contract: the on-the-wire audit
//! shape (field names + the `dropped` token a SIEM correlates on) AND
//! the post-condition that the payload is actually erased, not just
//! audited. MAVLink is exercised separately — it has a masker, and a
//! frame it cannot place (a short non-position frame) is genuinely
//! point-less and still forwards as `forwarded_binary`.
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
use rustgate_router::obligations::{UnknownObligationPolicy, apply_obligations};
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
        metadata: Metadata::new(
            SystemTime::now(),
            source_protocol.to_string(),
            MessageType::Other("binary".into()),
        ),
        entity: None,
    }
}

/// Drive `apply_mask_point` end-to-end with the supplied
/// `source_protocol` and return the captured audit JSON output together
/// with the (possibly mutated) message so callers can assert both the
/// audit token and the payload post-condition. The payload is a non-XML
/// byte sequence so the dispatcher lands in the non-XML branch and emits
/// exactly one audit record.
fn run_and_capture(payload: &'static [u8], source_protocol: &str) -> (String, RoutableMessage) {
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
    (buf.snapshot(), msg)
}

/// Assert the shared fail-closed post-condition: the audit record carries
/// `recovery = "dropped"`, names the source protocol, and the payload was
/// actually erased to the `other:masked` terminal state.
fn assert_dropped_and_erased(log: &str, msg: &RoutableMessage, source_protocol: &str) {
    assert!(
        log.contains(r#""recovery":"dropped""#),
        "expected recovery=dropped in audit, got: {log}"
    );
    assert!(
        log.contains(&format!(r#""source_protocol":"{source_protocol}""#)),
        "expected source_protocol={source_protocol} in audit, got: {log}"
    );
    assert!(
        log.contains(r#""event_type":"authz.obligation_failed""#),
        "expected event_type=authz.obligation_failed in audit, got: {log}"
    );
    assert!(
        msg.payload.is_empty(),
        "fail-closed must erase the payload, but {} bytes survived",
        msg.payload.len()
    );
    assert_eq!(
        msg.metadata.message_type,
        MessageType::Other("masked".into()),
        "erased payload must be typed other:masked"
    );
}

#[test]
fn mask_point_forwards_pointless_mavlink_frame() {
    // MAVLink has a registered masker; a short frame `mask_position`
    // cannot place is genuinely point-less and still forwards unmasked,
    // audited `forwarded_binary` so an analyst can distinguish it from
    // the fail-closed drop below. This path is deliberately unchanged by
    // #1545 (which scopes to non-MAVLink protocols).
    let mavlink_frame: &[u8] = &[0xFD, 0x09, 0x00, 0x00, 0x00, 0x01, 0x01];
    // Leak to 'static so the helper signature stays simple — every
    // call-site here uses small fixed byte sequences.
    let leaked: &'static [u8] = Box::leak(mavlink_frame.to_vec().into_boxed_slice());
    let (log, msg) = run_and_capture(leaked, "mavlink");

    assert!(
        log.contains(r#""recovery":"forwarded_binary""#),
        "expected recovery=forwarded_binary in audit, got: {log}"
    );
    assert!(
        log.contains(r#""source_protocol":"mavlink""#),
        "expected source_protocol=mavlink in audit, got: {log}"
    );
    // Point-less MAVLink frame is forwarded, not erased.
    assert_eq!(
        msg.payload.as_ref(),
        leaked,
        "point-less MAVLink frame must forward unmodified"
    );
}

#[test]
fn mask_point_fails_closed_for_tak_protobuf() {
    // TAK protobuf frames carry position in binary fields, not a CoT
    // `<point>`. Pre-#1545 they forwarded unmasked (a leak); now the
    // body is erased.
    let tak_frame: &[u8] = &[0xBF, 0x01, 0x02, 0x03];
    let leaked: &'static [u8] = Box::leak(tak_frame.to_vec().into_boxed_slice());
    let (log, msg) = run_and_capture(leaked, "tak_protobuf");
    assert_dropped_and_erased(&log, &msg, "tak_protobuf");
}

#[test]
fn mask_point_fails_closed_for_tak_protobuf_hyphenated() {
    // `Codec::protocol_id()` returns `"tak-protobuf"` (hyphen) while
    // older config keys spelled it `"tak_protobuf"`. Both forms must
    // reach the same fail-closed drop so a federation hop that
    // round-trips the identifier cannot flip the outcome back to a leak.
    let tak_frame: &[u8] = &[0xBF, 0x01, 0x02, 0x03];
    let leaked: &'static [u8] = Box::leak(tak_frame.to_vec().into_boxed_slice());
    let (log, msg) = run_and_capture(leaked, "tak-protobuf");
    assert_dropped_and_erased(&log, &msg, "tak-protobuf");
}

#[test]
fn mask_point_fails_closed_for_asterix() {
    // ASTERIX (CAT-021/048/062) is a Eurocontrol surveillance binary
    // format whose tracks carry lat/lon. The single most serious leak
    // from the #1545 audit — now erased rather than forwarded.
    let asterix_frame: &[u8] = &[0x3E, 0x00, 0x10, 0x00];
    let leaked: &'static [u8] = Box::leak(asterix_frame.to_vec().into_boxed_slice());
    let (log, msg) = run_and_capture(leaked, "asterix");
    assert_dropped_and_erased(&log, &msg, "asterix");
}

#[test]
fn mask_point_fails_closed_for_protocol_claiming_cot() {
    // A `source_protocol` claiming `cot` whose payload does not start
    // with `<` cannot be parsed for a `<point>` element — position MAY
    // be in the bytes and the masker was bypassed. Pre-#1545 this was
    // `forwarded_unmasked`; now it fails closed like every other
    // unmaskable non-XML payload.
    //
    // Note: a payload that DOES start with `<` but fails to parse takes
    // the XML-intent fail-closed path, also `recovery=dropped`; that
    // case is covered by the unit tests in `obligations.rs`.
    let (log, msg) = run_and_capture(b"truncated-cot-payload", "cot");
    assert_dropped_and_erased(&log, &msg, "cot");
}

#[test]
fn mask_point_fails_closed_for_unrecognized_protocol() {
    // An unrecognised `source_protocol` — a misconfigured upstream or a
    // transport this build does not yet know — is treated as
    // potentially position-bearing and erased. Default-deny: we cannot
    // prove the payload is position-free, so we do not forward it.
    let (log, msg) = run_and_capture(b"some random bytes", "unknown_proto_xyz");
    assert_dropped_and_erased(&log, &msg, "unknown_proto_xyz");
}
