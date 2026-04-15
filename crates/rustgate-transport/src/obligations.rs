// Copyright © 2026 Roberto Chiofalo.

//! Data-plane actuation for authz obligations.
//!
//! The authz engine returns [`DecisionOutcome::obligations`] alongside an
//! allow verdict (see [`rustgate_authz::Obligation`]). This module is the
//! central dispatcher that translates the obligation list into mutations
//! on the outbound [`RoutableMessage`] copy destined for a specific
//! recipient.
//!
//! [`DecisionOutcome::obligations`]: rustgate_authz::DecisionOutcome::obligations
//!
//! # Scope
//!
//! Only obligations with data-plane side effects are handled here:
//!
//! - [`Obligation::MaskPoint`] — CoT `<point>` coordinates (`lat`, `lon`,
//!   `hae`) are zeroed via [`rustgate_cot::mask::strip_coordinates`].
//!   Non-XML payloads pass through unmodified; XML-intent payloads that
//!   fail to parse fall back to [`Obligation::MaskPayload`]-equivalent
//!   erasure so malformed input cannot leak coordinates.
//! - [`Obligation::MaskPayload`] — the payload body is replaced with an
//!   empty [`Bytes`] and the classified message type is coerced to
//!   [`MessageType::Other`] with a `"masked"` tag so downstream caches
//!   and dedup do not mistake it for the real event.
//!
//! [`Obligation::TagClassified`] and [`Obligation::AuditExtended`] are
//! audit-shaped obligations that do not mutate the wire payload:
//!
//! - `TagClassified` — emitted at the PEP call site via
//!   [`rustgate_core::audit::authz_classified_delivery`] so each
//!   delivery of a classified artefact produces one hash-chained audit
//!   record.
//! - `AuditExtended` — reserved for future expanded audit records; no
//!   data-plane side effect today. See `docs/authorization.md`.
//!
//! [`apply_obligations`] therefore skips both variants. Unknown
//! variants (the [`Obligation`] enum is `#[non_exhaustive]`) also
//! fall through to no-op delivery but emit
//! [`rustgate_core::audit::authz_obligation_unknown`] so operators
//! running a stale transport build against a newer authz policy can
//! detect the skew via the audit trail.
//!
//! # Failure mode
//!
//! [`Obligation::MaskPoint`] distinguishes two recovery modes:
//!
//! - Payload does not announce itself as XML (first non-whitespace byte
//!   is not `<`) → forward unmodified. The masker is named for CoT; a
//!   policy that attaches it to a MAVLink or protobuf stream is a
//!   mis-configuration, not a leak.
//! - Payload starts with `<` but fails to parse or trips the attribute
//!   budget → **fail-closed**: empty the body and coerce the message
//!   type to `Other("masked")`, the same state [`Obligation::MaskPayload`]
//!   would have produced. A crafted payload that aborts parsing
//!   immediately after its `<point>` element was emitted must not leak
//!   coordinates via pass-through recovery.
//!
//! Both recovery paths emit
//! [`rustgate_core::audit::authz_obligation_failed`] so operators see
//! the policy hint was not honoured. The operational log stays at
//! DEBUG so a high-rate stream of bad payloads cannot amplify into a
//! logging DoS.

use bytes::Bytes;
use rustgate_authz::Obligation;
use rustgate_core::audit;
use rustgate_core::message::{MessageType, RoutableMessage};

/// Return `true` when the obligation slice contains at least one
/// variant that mutates the wire payload.
///
/// Callers use this to skip the clone-out-of-`Arc` performed by
/// [`crate::router::RoutedMessage::with_obligations`] when the authz
/// decision carries only audit-shaped obligations like
/// [`Obligation::TagClassified`] or [`Obligation::AuditExtended`]. On a
/// broadcast to N recipients with a policy that only requires
/// classified-delivery audit (not masking), this turns N `clone() +
/// Arc::new()` into N cheap `Arc::clone()`.
///
/// Unknown variants are treated as payload-mutating out of caution —
/// if a future authz upgrade adds `Obligation::TransformPayload`, the
/// transport crate's stale build should NOT short-circuit the
/// payload-clone path and deliver the unmodified original. The audit
/// record emitted by [`apply_obligations`] for unknown variants still
/// fires on delivery.
pub(crate) fn obligations_mutate_payload(obligations: &[Obligation]) -> bool {
    obligations.iter().any(|o| match o {
        Obligation::MaskPoint | Obligation::MaskPayload => true,
        Obligation::TagClassified | Obligation::AuditExtended => false,
        // `#[non_exhaustive]` — unknown variants default to "mutates"
        // so the clone-out path runs and `apply_obligations` gets a
        // chance to emit the unknown-variant audit event.
        _ => true,
    })
}

/// Apply every data-plane obligation in `obligations` to `msg` in place.
///
/// Obligations are applied in the order they appear in the slice. The
/// order only matters when two obligations could interact — in practice
/// [`Obligation::MaskPayload`] supersedes [`Obligation::MaskPoint`]
/// because it replaces the payload entirely, so callers should tolerate
/// either ordering.
///
/// Obligations without a data-plane side effect
/// ([`Obligation::TagClassified`], [`Obligation::AuditExtended`]) are
/// skipped silently. The caller handles those via audit events at the
/// PEP site. Unknown variants emit
/// [`audit::authz_obligation_unknown`] so stale-transport / new-policy
/// skew is visible in the audit stream.
pub fn apply_obligations(msg: &mut RoutableMessage, obligations: &[Obligation]) {
    for obligation in obligations {
        match obligation {
            Obligation::MaskPoint => apply_mask_point(msg),
            Obligation::MaskPayload => apply_mask_payload(msg),
            // Audit-only obligations handled at the call site.
            Obligation::TagClassified | Obligation::AuditExtended => {}
            // `#[non_exhaustive]` Obligation — future variants fall
            // through to no-op delivery but emit an audit record so
            // operators running a stale transport build against a
            // newer authz policy can detect the skew. DEBUG-level
            // operational log (not WARN) to prevent a hostile sender
            // under a misconfigured policy from amplifying into a
            // logging DoS; audit has its own sink with stricter
            // retention.
            other => {
                tracing::debug!(
                    obligation = ?other,
                    "unknown obligation variant, no data-plane action taken"
                );
                audit::authz_obligation_unknown(
                    &msg.source.cn,
                    &format!("{other:?}"),
                    &msg.metadata.source_protocol,
                    msg.destination.kind_str(),
                );
            }
        }
    }
}

/// Zero CoT `<point>` coordinates on `msg.payload` with fail-closed
/// recovery on XML-intent parse errors.
///
/// Recovery rules:
///
/// 1. **Non-XML payload** (first non-whitespace byte is not `<`) — pass
///    through unmodified. `MaskPoint` is a CoT-specific control; a
///    policy attached to a MAVLink/protobuf stream is a
///    mis-configuration and the dispatcher must not silently drop the
///    traffic. An audit record is still emitted with
///    `recovery = "forwarded_unmasked"`.
///
/// 2. **XML-intent parse failure** (payload starts with `<` but
///    quick_xml errors, or the `<point>` attribute budget is exceeded)
///    — **fail-closed**: empty the body and coerce the message type to
///    `Other("masked")`, the same state [`Obligation::MaskPayload`]
///    would produce. This is the security boundary: a crafted payload
///    that aborts parsing immediately after `<point>` was already
///    copied to the writer must NOT leak coordinates via pass-through.
///    Audit emitted with `recovery = "dropped"`.
///
/// The operational log stays at DEBUG for both recovery paths so a
/// hostile or mis-configured sender cannot amplify a single bad
/// payload into thousands of WARN records per second. Audit records
/// carry the forensic detail.
fn apply_mask_point(msg: &mut RoutableMessage) {
    // XML-intent is decided from the payload itself: first
    // non-whitespace byte is `<`. Non-XML payloads cannot host a
    // `<point>` element — forward unmodified but still audit so
    // operators see the policy hint landed on traffic it cannot mask.
    let is_xml_intent = msg
        .payload
        .iter()
        .find(|b| !b.is_ascii_whitespace())
        .is_some_and(|b| *b == b'<');

    if !is_xml_intent {
        tracing::debug!(
            source_protocol = %msg.metadata.source_protocol,
            message_type = %msg.metadata.message_type,
            "mask_point obligation: non-XML payload, forwarding unmasked"
        );
        audit::authz_obligation_failed(
            &msg.source.cn,
            "MaskPoint",
            "payload is not XML",
            "forwarded_unmasked",
            &msg.metadata.source_protocol,
            msg.destination.kind_str(),
        );
        return;
    }

    match rustgate_cot::mask::strip_coordinates(&msg.payload) {
        Ok(masked) => {
            msg.payload = masked;
        }
        Err(e) => {
            // Fail-closed: XML-intent payload whose parse failed (or
            // attribute-budget trip). Drop the payload rather than
            // leaking unmasked coordinates — a crafted sender could
            // otherwise emit `<event><point lat="…"…/>` and cut the
            // document so quick_xml errors after `<point>` was
            // already copied to the writer.
            tracing::debug!(
                error = %e,
                source_protocol = %msg.metadata.source_protocol,
                message_type = %msg.metadata.message_type,
                "mask_point obligation: XML-intent parse failed, erasing payload"
            );
            audit::authz_obligation_failed(
                &msg.source.cn,
                "MaskPoint",
                &format!("{e}"),
                "dropped",
                &msg.metadata.source_protocol,
                msg.destination.kind_str(),
            );
            apply_mask_payload(msg);
        }
    }
}

/// Replace the payload body with empty bytes and coerce the message type
/// to `other:masked`.
///
/// The outbound [`RoutableMessage`] still carries its original envelope
/// fields (source identity, destination, TTL, received_at) so consumers
/// can still see that *something* was delivered — it's just the payload
/// body that's been stripped. This matches XACML-style "reduce to
/// metadata" semantics.
fn apply_mask_payload(msg: &mut RoutableMessage) {
    msg.payload = Bytes::new();
    msg.metadata.message_type = MessageType::Other("masked".into());
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use std::collections::BTreeSet;
    use std::time::SystemTime;

    use rustgate_core::identity::Identity;
    use rustgate_core::message::{Destination, Metadata};

    use super::*;

    const SAMPLE_COT: &[u8] = br#"<event uid="u1" type="a-f-G-U-C" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z"><point lat="38.8977" lon="-77.0365" hae="125.4"/></event>"#;

    fn sample_msg(payload: &'static [u8], message_type: MessageType) -> RoutableMessage {
        let id = Identity::new("alice".into(), "abc123".into(), BTreeSet::new()).unwrap();
        RoutableMessage {
            source: id,
            destination: Destination::Broadcast,
            payload: Bytes::from_static(payload),
            metadata: Metadata {
                received_at: SystemTime::now(),
                source_protocol: "tcp".into(),
                message_type,
                ttl: None,
            },
        }
    }

    #[test]
    fn mask_point_zeroes_point_coordinates() {
        let mut msg = sample_msg(SAMPLE_COT, MessageType::Position);
        apply_obligations(&mut msg, &[Obligation::MaskPoint]);

        let s = std::str::from_utf8(&msg.payload).unwrap();
        assert!(s.contains(r#"lat="0.0""#), "lat not zeroed: {s}");
        assert!(s.contains(r#"lon="0.0""#), "lon not zeroed: {s}");
        assert!(s.contains(r#"hae="0.0""#), "hae not zeroed: {s}");
        assert!(!s.contains("38.8977"), "raw lat leaked: {s}");
    }

    #[test]
    fn mask_point_on_non_cot_passes_through_unchanged() {
        // Not XML at all. MaskPoint is best-effort — the payload should
        // be forwarded intact rather than dropped.
        let mut msg = sample_msg(b"not xml at all", MessageType::Chat);
        apply_obligations(&mut msg, &[Obligation::MaskPoint]);
        assert_eq!(msg.payload.as_ref(), b"not xml at all");
        // Message type unchanged: masking is a payload-level op.
        assert_eq!(msg.metadata.message_type, MessageType::Chat);
    }

    #[test]
    fn mask_payload_replaces_body_and_message_type() {
        let mut msg = sample_msg(SAMPLE_COT, MessageType::Position);
        apply_obligations(&mut msg, &[Obligation::MaskPayload]);
        assert!(msg.payload.is_empty(), "payload should be empty");
        assert_eq!(
            msg.metadata.message_type,
            MessageType::Other("masked".into())
        );
    }

    #[test]
    fn mask_payload_preserves_envelope_fields() {
        let mut msg = sample_msg(SAMPLE_COT, MessageType::Alert);
        let original_source_cn = msg.source.cn.clone();
        let original_proto = msg.metadata.source_protocol.clone();

        apply_obligations(&mut msg, &[Obligation::MaskPayload]);

        // Envelope survives — only payload + classified type were touched.
        assert_eq!(msg.source.cn, original_source_cn);
        assert_eq!(msg.metadata.source_protocol, original_proto);
        assert!(matches!(msg.destination, Destination::Broadcast));
    }

    #[test]
    fn tag_classified_is_noop_on_payload() {
        // The data-plane dispatcher ignores TagClassified — audit
        // tracking is handled at the PEP call site. Verify no mutation.
        let mut msg = sample_msg(SAMPLE_COT, MessageType::Position);
        let before = msg.payload.clone();
        apply_obligations(&mut msg, &[Obligation::TagClassified]);
        assert_eq!(msg.payload, before);
        assert_eq!(msg.metadata.message_type, MessageType::Position);
    }

    #[test]
    fn audit_extended_is_noop_on_payload() {
        let mut msg = sample_msg(SAMPLE_COT, MessageType::Position);
        let before = msg.payload.clone();
        apply_obligations(&mut msg, &[Obligation::AuditExtended]);
        assert_eq!(msg.payload, before);
    }

    #[test]
    fn empty_obligation_list_is_noop() {
        let mut msg = sample_msg(SAMPLE_COT, MessageType::Position);
        let before = msg.payload.clone();
        apply_obligations(&mut msg, &[]);
        assert_eq!(msg.payload, before);
        assert_eq!(msg.metadata.message_type, MessageType::Position);
    }

    #[test]
    fn multiple_obligations_compose() {
        // MaskPoint then MaskPayload — payload gets cleared regardless of
        // whether the initial mask succeeded. Final state: empty body.
        let mut msg = sample_msg(SAMPLE_COT, MessageType::Position);
        apply_obligations(&mut msg, &[Obligation::MaskPoint, Obligation::MaskPayload]);
        assert!(msg.payload.is_empty());
        assert_eq!(
            msg.metadata.message_type,
            MessageType::Other("masked".into())
        );
    }

    #[test]
    fn mask_payload_then_mask_point_does_not_error() {
        // Opposite order — after MaskPayload the body is empty, so
        // MaskPoint sees a non-CoT payload and passes through (staying
        // empty). The dispatcher must not panic or error on this path.
        let mut msg = sample_msg(SAMPLE_COT, MessageType::Position);
        apply_obligations(&mut msg, &[Obligation::MaskPayload, Obligation::MaskPoint]);
        assert!(msg.payload.is_empty());
    }

    #[test]
    fn mask_point_xml_intent_malformed_payload_is_fail_closed() {
        // Security-critical: an XML-intent payload that trips the parser
        // partway through must NOT fall back to pass-through. A sender
        // could otherwise leak coordinates by terminating the document
        // mid-element after `<point>` was already emitted.
        let malformed: &'static [u8] =
            br#"<event><point lat="38.8977" lon="-77.0365" hae="125.4"/><unterminated"#;
        let mut msg = sample_msg(malformed, MessageType::Position);
        apply_obligations(&mut msg, &[Obligation::MaskPoint]);
        // Fail-closed: payload erased, message type coerced.
        assert!(
            msg.payload.is_empty(),
            "payload not erased: {:?}",
            msg.payload
        );
        assert_eq!(
            msg.metadata.message_type,
            MessageType::Other("masked".into())
        );
    }

    #[test]
    fn mask_point_on_attribute_budget_trip_is_fail_closed() {
        // Crafted `<point>` with more than MAX_POINT_ATTRIBUTES — the
        // masker returns AttrBudgetExceeded. Because the payload is
        // XML-intent, the dispatcher must erase it rather than forward
        // unmasked.
        use rustgate_cot::mask::MAX_POINT_ATTRIBUTES;
        let mut xml = String::from(
            r#"<event uid="u1" type="a-f-G-U-C" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z"><point lat="38.8977" lon="-77.0365" hae="125.4""#,
        );
        for i in 0..=MAX_POINT_ATTRIBUTES {
            xml.push_str(&format!(r#" x{i}="v""#));
        }
        xml.push_str("/></event>");

        // Leak the String to a &'static [u8] so sample_msg (which is
        // static-bound for convenience in the rest of the suite) works.
        let leaked: &'static [u8] = Box::leak(xml.into_bytes().into_boxed_slice());
        let mut msg = sample_msg(leaked, MessageType::Position);
        apply_obligations(&mut msg, &[Obligation::MaskPoint]);
        assert!(
            msg.payload.is_empty(),
            "attribute-budget trip must erase payload"
        );
        assert_eq!(
            msg.metadata.message_type,
            MessageType::Other("masked".into())
        );
    }

    #[test]
    fn mask_point_on_uppercase_element_masks_coordinates() {
        // Case-variant: <Point> must be masked even though the byte
        // sequence is not `b"point"`. Earlier implementations bypassed
        // this case.
        let xml: &'static [u8] = br#"<event uid="u1" type="a-f-G-U-C" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z"><Point lat="38.8977" lon="-77.0365" hae="125.4"/></event>"#;
        let mut msg = sample_msg(xml, MessageType::Position);
        apply_obligations(&mut msg, &[Obligation::MaskPoint]);
        let s = std::str::from_utf8(&msg.payload).unwrap();
        assert!(s.contains(r#"lat="0.0""#), "case-variant not masked: {s}");
        assert!(!s.contains("38.8977"), "raw lat leaked: {s}");
    }

    #[test]
    fn mask_point_on_namespaced_element_masks_coordinates() {
        let xml: &'static [u8] = br#"<event xmlns:cot="urn:cot" uid="u1" type="a-f-G-U-C" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z"><cot:point lat="38.8977" lon="-77.0365" hae="125.4"/></event>"#;
        let mut msg = sample_msg(xml, MessageType::Position);
        apply_obligations(&mut msg, &[Obligation::MaskPoint]);
        let s = std::str::from_utf8(&msg.payload).unwrap();
        assert!(
            s.contains(r#"lat="0.0""#),
            "namespaced element not masked: {s}"
        );
        assert!(!s.contains("38.8977"), "raw lat leaked: {s}");
    }

    #[test]
    fn obligations_mutate_payload_reports_mask_variants_true() {
        assert!(obligations_mutate_payload(&[Obligation::MaskPoint]));
        assert!(obligations_mutate_payload(&[Obligation::MaskPayload]));
        assert!(obligations_mutate_payload(&[
            Obligation::MaskPoint,
            Obligation::TagClassified
        ]));
    }

    #[test]
    fn obligations_mutate_payload_reports_audit_only_variants_false() {
        assert!(!obligations_mutate_payload(&[]));
        assert!(!obligations_mutate_payload(&[Obligation::TagClassified]));
        assert!(!obligations_mutate_payload(&[Obligation::AuditExtended]));
        assert!(!obligations_mutate_payload(&[
            Obligation::TagClassified,
            Obligation::AuditExtended
        ]));
    }
}
