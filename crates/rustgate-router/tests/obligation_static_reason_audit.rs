// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

#![allow(unused_results)]
#![allow(clippy::panic, clippy::unwrap_used)]
//! Audit-trail regression test for the static `reason` vocabulary
//! emitted by [`audit::authz_obligation_failed`] and
//! [`audit::authz_obligation_unknown`] (issue #775).
//!
//! Pre-this-fix the obligation dispatcher emitted the underlying error
//! message into a `error` audit field — so SIEM dashboards grouped on
//! either prose strings (e.g. `"<point> attribute count exceeded
//! masking budget of 64"`) that drift across releases, or on
//! `quick_xml::Error::Display` fragments that can echo
//! payload-derived tag names. Issue #775 extends the static-label
//! discipline established by issue #1205 (MaskPoint recovery tokens)
//! to every obligation `%err` audit site: each call now emits a stable
//! `reason` token drawn from a documented vocabulary defined in
//! `rustgate_core::audit`.
//!
//! The tests below pin the on-the-wire shape of those emissions so a
//! SIEM correlation tool can rely on the field names AND the literal
//! strings being stable. The `MaskError::Io` variant is unreachable
//! under normal operation (the writer is a `Vec<u8>`) so the test
//! constructs the audit emission directly via the audit API rather
//! than trying to drive a synthetic I/O failure through the masker —
//! the audit-shape assertion is identical.
//!
//! Lives in its own integration-test binary so the thread-local audit
//! subscriber installed here cannot race subscribers installed by other
//! in-process tests — tracing caches per-callsite `Interest` globally,
//! so once any test in the same binary emits an `audit!` event without
//! a subscriber installed, the default no-op subscriber returns
//! `Interest::never()` for that callsite and the result is cached
//! process-wide, blocking subsequent thread-local subscribers from
//! reaching it. Same rationale as `mask_point_recovery_audit.rs`,
//! `store_forward_dwell_audit.rs`, and
//! `position_replay_rate_limit_audit.rs`.

use std::collections::BTreeSet;
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use bytes::Bytes;
use rustgate_authz::Obligation;
use rustgate_core::audit;
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
            MessageType::Other("xml".into()),
        ),
        entity: None,
    }
}

/// Install a thread-local audit-only JSON subscriber, run `body`, and
/// return the captured JSON-line output. The subscriber's filter is
/// pinned to `target = "audit"` at INFO so operational `tracing::debug!`
/// noise from inside the dispatcher does not pollute the captured
/// stream.
fn capture_audit<F>(body: F) -> String
where
    F: FnOnce(),
{
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

/// 1. Issue #775: `MaskError::Xml` (an XML-intent payload that trips
///    `quick_xml`) MUST emit `reason = "mask_point_xml_error"`. The
///    pre-issue-#775 code emitted the `MaskError::kind()` discriminant
///    directly under a misleadingly-named `error` field; the new
///    contract names the field `reason` and pins it to the documented
///    vocabulary so SIEM groupings cannot drift if a future refactor
///    renames the discriminant.
#[test]
fn audit_obligation_failed_emits_static_reason_label_for_xml_error() {
    // Truncated XML — first byte is `<`, so the dispatcher takes the
    // XML-intent branch and surfaces a `MaskError::Xml` from quick_xml.
    let malformed: &'static [u8] =
        br#"<event><point lat="38.8977" lon="-77.0365" hae="125.4"/><unterminated"#;

    let log = capture_audit(|| {
        let mut msg = build_message(malformed, "cot");
        apply_obligations(
            &mut msg,
            &[Obligation::MaskPoint],
            UnknownObligationPolicy::FailClosed,
        )
        .expect("known obligation must not error under FailClosed");
    });

    assert!(
        log.contains(r#""reason":"mask_point_xml_error""#),
        "expected reason=mask_point_xml_error in audit, got: {log}"
    );
    assert!(
        log.contains(r#""recovery":"dropped""#),
        "expected recovery=dropped (XML-intent fail-closed), got: {log}"
    );
    assert!(
        log.contains(r#""event_type":"authz.obligation_failed""#),
        "expected event_type=authz.obligation_failed, got: {log}"
    );
    // Negative-shape assertion: the old field name MUST NOT be present.
    // A regression that re-introduced `error` would also re-introduce
    // the SIEM grouping drift this issue closed.
    assert!(
        !log.contains(r#""error""#),
        "old `error` field must not appear in audit emission: {log}"
    );
}

/// 2. Issue #775: `MaskError::Io` MUST map to
///    `reason = "mask_point_io_error"`. The masker's writer is a
///    `Vec<u8>` so the I/O path is unreachable from real traffic; we
///    construct the emission directly through the audit API to pin
///    the on-the-wire shape that a future streaming-writer build
///    would surface.
#[test]
fn audit_obligation_failed_emits_static_reason_label_for_io_error() {
    let log = capture_audit(|| {
        // Drive the same shape `apply_mask_point` would produce if
        // `MaskError::Io` were observable: kind() returns `"io_error"`
        // and the dispatcher passes it through
        // `obligation_reason_for_mask_error_kind`.
        let reason = audit::obligation_reason_for_mask_error_kind("io_error");
        audit::authz_obligation_failed(
            "alice",
            "MaskPoint",
            reason,
            audit::MASK_RECOVERY_DROPPED,
            "cot",
            "broadcast",
            "policy-v1",
        );
    });

    assert!(
        log.contains(r#""reason":"mask_point_io_error""#),
        "expected reason=mask_point_io_error in audit, got: {log}"
    );
    assert!(
        log.contains(r#""event_type":"authz.obligation_failed""#),
        "expected event_type=authz.obligation_failed, got: {log}"
    );
    assert!(
        !log.contains(r#""error""#),
        "old `error` field must not appear in audit emission: {log}"
    );
}

/// 3. Issue #775: `MaskError::AttrBudgetExceeded` (a `<point>` element
///    with more than `MAX_POINT_ATTRIBUTES` attributes) MUST emit
///    `reason = "mask_point_attr_budget_exceeded"`. Drives the masker
///    end-to-end with a crafted payload so the test exercises the same
///    code path a hostile sender would hit.
#[test]
fn audit_obligation_failed_emits_static_reason_label_for_attr_budget_exceeded() {
    use rustgate_cot::mask::MAX_POINT_ATTRIBUTES;
    let mut xml = String::from(
        r#"<event uid="u1" type="a-f-G-U-C" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z"><point lat="38.8977" lon="-77.0365" hae="125.4""#,
    );
    for i in 0..=MAX_POINT_ATTRIBUTES {
        xml.push_str(&format!(r#" x{i}="v""#));
    }
    xml.push_str("/></event>");
    let leaked: &'static [u8] = Box::leak(xml.into_bytes().into_boxed_slice());

    let log = capture_audit(|| {
        let mut msg = build_message(leaked, "cot");
        apply_obligations(
            &mut msg,
            &[Obligation::MaskPoint],
            UnknownObligationPolicy::FailClosed,
        )
        .expect("known obligation must not error under FailClosed");
    });

    assert!(
        log.contains(r#""reason":"mask_point_attr_budget_exceeded""#),
        "expected reason=mask_point_attr_budget_exceeded in audit, got: {log}"
    );
    assert!(
        log.contains(r#""recovery":"dropped""#),
        "expected recovery=dropped (XML-intent fail-closed), got: {log}"
    );
    assert!(
        log.contains(r#""event_type":"authz.obligation_failed""#),
        "expected event_type=authz.obligation_failed, got: {log}"
    );
    // Pre-issue-#775 prose ("attribute count exceeded masking budget of 64")
    // could have leaked into the audit field. The new emission MUST
    // not contain any digits derived from the masker's limit constant.
    assert!(
        !log.contains("attribute count exceeded"),
        "audit reason must not embed Display prose: {log}"
    );
}

/// 4. Issue #775: an unknown obligation variant MUST emit
///    `reason = "unknown_variant"` regardless of which specific
///    `#[non_exhaustive]` variant fired. The token is fixed because
///    the `obligation` field already carries the `{:?}` rendering;
///    `reason` exists so SIEM rules can group every unknown-variant
///    event under a single alerting key.
///
/// `Obligation` is `#[non_exhaustive]` and the transport crate cannot
/// construct synthetic variants from outside `rustgate-authz`. We
/// drive the audit emission directly through the audit API, which is
/// what `apply_obligations_with_limiter` would pass under the
/// fail-closed policy when the policy engine returns an unfamiliar
/// variant — same on-the-wire shape, same vocabulary contract.
#[test]
fn audit_obligation_unknown_emits_static_reason_label() {
    let log = capture_audit(|| {
        audit::authz_obligation_unknown(
            "alice",
            "TransformPayload",
            "cot",
            "broadcast",
            "policy-v1",
        );
    });

    assert!(
        log.contains(r#""reason":"unknown_variant""#),
        "expected reason=unknown_variant in audit, got: {log}"
    );
    assert!(
        log.contains(r#""event_type":"authz.obligation_unknown""#),
        "expected event_type=authz.obligation_unknown, got: {log}"
    );
    assert!(
        log.contains(r#""obligation":"TransformPayload""#),
        "expected obligation field to carry the variant name, got: {log}"
    );
    assert!(
        log.contains(r#""destination_kind":"broadcast""#),
        "expected destination_kind=broadcast, got: {log}"
    );
}
