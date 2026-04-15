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
//! - [`Obligation::MaskGeo`] — CoT `<point>` coordinates are zeroed via
//!   [`rustgate_cot::mask::strip_coordinates`].
//! - [`Obligation::MaskPayload`] — the payload body is replaced with an
//!   empty [`Bytes`] and the classified message type is coerced to
//!   [`MessageType::Other("masked")`] so downstream caches and dedup do
//!   not mistake it for the real event.
//!
//! [`Obligation::TagClassified`] and [`Obligation::AuditExtended`] are
//! audit-only obligations. They are handled at the call site via
//! `audit::authz_classified_delivery` / `audit::authz_extended` rather
//! than mutating the wire payload, so [`apply_obligations`] intentionally
//! ignores them.
//!
//! # Failure mode
//!
//! [`Obligation::MaskGeo`] on a non-CoT payload returns an error from the
//! parser. The dispatcher logs at DEBUG and passes the payload through
//! unchanged — masking is a best-effort leak-prevention mechanism, not a
//! hard security gate. An operator whose policy predates a payload-type
//! change must not see messages dropped wholesale because the masker
//! refuses to parse them.
//!
//! DEBUG (not WARN) is deliberate: a high-rate stream of non-CoT payloads
//! under a `MaskGeo` policy must not amplify into a logging DoS. Operators
//! who need visibility should rely on metrics and audit events, not the
//! operational log stream.

use bytes::Bytes;
use rustgate_authz::Obligation;
use rustgate_core::message::{MessageType, RoutableMessage};

/// Apply every data-plane obligation in `obligations` to `msg` in place.
///
/// Obligations are applied in the order they appear in the slice. The
/// order only matters when two obligations could interact — in practice
/// [`Obligation::MaskPayload`] supersedes [`Obligation::MaskGeo`] because
/// it replaces the payload entirely, so callers should tolerate either
/// ordering.
///
/// Obligations without a data-plane side effect
/// ([`Obligation::TagClassified`], [`Obligation::AuditExtended`]) are
/// skipped silently. The caller handles those via audit events at the
/// PEP site.
pub fn apply_obligations(msg: &mut RoutableMessage, obligations: &[Obligation]) {
    for obligation in obligations {
        match obligation {
            Obligation::MaskGeo => apply_mask_geo(msg),
            Obligation::MaskPayload => apply_mask_payload(msg),
            // Audit-only obligations handled at the call site.
            Obligation::TagClassified | Obligation::AuditExtended => {}
            // `#[non_exhaustive]` Obligation — future variants fall
            // through to no-op so a stale dispatcher never silently drops
            // a payload. Emit a DEBUG so operators running a stale build
            // against a newer authz engine can detect the skew via log
            // correlation, without amplifying under hostile traffic.
            other => {
                tracing::debug!(
                    obligation = ?other,
                    "unknown obligation variant, no data-plane action taken"
                );
            }
        }
    }
}

/// Zero CoT `<point>` coordinates on `msg.payload`.
///
/// If the payload is not well-formed CoT XML (most often because policy
/// was written for a non-CoT transport, or because the `<point>` element
/// exceeded the masker's attribute budget), the payload is passed through
/// unchanged and the failure is logged at DEBUG. Callers that care about
/// strict leak prevention should gate delivery via the policy `Deny`
/// path, not via [`Obligation::MaskGeo`].
///
/// The log level is DEBUG (not WARN) on purpose: a hostile or
/// mis-configured sender under a `MaskGeo` policy could otherwise
/// amplify a single bad payload into thousands of WARN records per
/// second. Operational visibility for mask failures belongs in metrics
/// and audit, not the default log stream.
fn apply_mask_geo(msg: &mut RoutableMessage) {
    match rustgate_cot::mask::strip_coordinates(&msg.payload) {
        Ok(masked) => {
            msg.payload = masked;
        }
        Err(e) => {
            tracing::debug!(
                error = %e,
                source_protocol = %msg.metadata.source_protocol,
                message_type = %msg.metadata.message_type,
                "mask_geo obligation: payload not CoT-maskable, forwarding unmasked"
            );
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
    fn mask_geo_zeroes_point_coordinates() {
        let mut msg = sample_msg(SAMPLE_COT, MessageType::Position);
        apply_obligations(&mut msg, &[Obligation::MaskGeo]);

        let s = std::str::from_utf8(&msg.payload).unwrap();
        assert!(s.contains(r#"lat="0.0""#), "lat not zeroed: {s}");
        assert!(s.contains(r#"lon="0.0""#), "lon not zeroed: {s}");
        assert!(s.contains(r#"hae="0.0""#), "hae not zeroed: {s}");
        assert!(!s.contains("38.8977"), "raw lat leaked: {s}");
    }

    #[test]
    fn mask_geo_on_non_cot_passes_through_unchanged() {
        // Not XML at all. MaskGeo is best-effort — the payload should be
        // forwarded intact rather than dropped.
        let mut msg = sample_msg(b"not xml at all", MessageType::Chat);
        apply_obligations(&mut msg, &[Obligation::MaskGeo]);
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
        // MaskGeo then MaskPayload — payload gets cleared regardless of
        // whether the initial mask succeeded. Final state: empty body.
        let mut msg = sample_msg(SAMPLE_COT, MessageType::Position);
        apply_obligations(&mut msg, &[Obligation::MaskGeo, Obligation::MaskPayload]);
        assert!(msg.payload.is_empty());
        assert_eq!(
            msg.metadata.message_type,
            MessageType::Other("masked".into())
        );
    }

    #[test]
    fn mask_payload_then_mask_geo_does_not_error() {
        // Opposite order — after MaskPayload the body is empty, so
        // MaskGeo sees a non-CoT payload and passes through (staying
        // empty). The dispatcher must not panic or error on this path.
        let mut msg = sample_msg(SAMPLE_COT, MessageType::Position);
        apply_obligations(&mut msg, &[Obligation::MaskPayload, Obligation::MaskGeo]);
        assert!(msg.payload.is_empty());
    }
}
