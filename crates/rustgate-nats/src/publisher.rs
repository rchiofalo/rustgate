// Copyright © 2026 Roberto Chiofalo.

//! Publishes inbound CoT messages to NATS subjects.

use std::borrow::Cow;
use std::sync::Arc;

use async_nats::Client;
use bytes::Bytes;
#[cfg(not(feature = "full-detail"))]
use rustgate_core::message::MessageType;
use rustgate_core::message::RoutableMessage;
use rustgate_resilience::backpressure::{BackpressureGate, BackpressurePermit};
use tracing::Instrument;
use unicode_normalization::UnicodeNormalization;

use crate::config::NatsConfig;
use crate::serde_compat::WireEvent;

/// Publishes routable messages from local TAK sessions to NATS.
///
/// Designed to be called from the routing path. Publishing is fire-and-forget
/// with error logging; a NATS outage does not block local routing.
#[derive(Debug, Clone)]
pub struct NatsPublisher {
    client: Client,
    config: NatsConfig,
    /// Optional global backpressure gate. When configured, each `publish`
    /// call reserves a byte permit sized to the payload for the duration
    /// of the two in-flight awaits (live subject + JetStream history).
    /// A NATS outage or slow broker then pressures the shared gate rather
    /// than silently piling up inside the async-nats client's buffers.
    gate: Option<Arc<BackpressureGate>>,
}

impl NatsPublisher {
    pub fn new(client: Client, config: NatsConfig) -> Self {
        Self {
            client,
            config,
            gate: None,
        }
    }

    /// Attach a shared [`BackpressureGate`] so NATS egress participates in
    /// global admission control.
    ///
    /// When configured, every message that passes echo-prevention and
    /// position-unknown filtering acquires a byte permit sized to its
    /// payload before the first publish await. The permit lives until the
    /// JetStream history publish completes (or errors out) so the gate
    /// sees accurate outstanding byte accounting across both publishes.
    ///
    /// If the gate is already parked over the high-water mark when
    /// `publish` is called, the message is shed immediately rather than
    /// waiting — NATS publish is fire-and-forget and must not block the
    /// router's dispatch task.
    #[must_use]
    pub fn with_backpressure(mut self, gate: Arc<BackpressureGate>) -> Self {
        self.gate = Some(gate);
        self
    }

    /// Return a clone of the underlying NATS client handle.
    ///
    /// Used by readiness checks to inspect connection state without
    /// affecting the publisher's own operations.
    pub fn client(&self) -> Client {
        self.client.clone()
    }

    /// Returns `true` when the NATS connection is fully established.
    ///
    /// This encapsulates the `async_nats::connection::State` check so
    /// callers do not need a direct dependency on `async-nats`.
    pub fn is_connected(&self) -> bool {
        matches!(
            self.client.connection_state(),
            async_nats::connection::State::Connected
        )
    }

    /// Returns `true` when the NATS client is in the process of
    /// (re-)connecting but has not yet established a session.
    pub fn is_pending(&self) -> bool {
        matches!(
            self.client.connection_state(),
            async_nats::connection::State::Pending
        )
    }

    /// Publish a routable message to NATS.
    ///
    /// With the `full-detail` feature, publishes all CoT types with full
    /// detail fields. Without it, only position messages are published.
    pub async fn publish(&self, msg: &RoutableMessage) {
        // Echo prevention: don't re-publish messages that came from NATS.
        // Compared case-insensitively so a federated message whose
        // `source_protocol` was normalized to "NATS" or "Nats" by an
        // upstream peer still trips the guard. Mirrors the HTTP
        // publisher's discipline.
        if msg.metadata.source_protocol.eq_ignore_ascii_case("nats") {
            tracing::debug!(
                source_protocol = %msg.metadata.source_protocol,
                "skipping NATS publish to prevent echo loop"
            );
            return;
        }

        // Global admission check: if the shared gate is parked over the
        // high-water mark, shed the publish so backpressure flows upstream
        // instead of silently buffering inside the async-nats client.
        let _permit: Option<BackpressurePermit> = match self.gate.as_ref() {
            Some(gate) => {
                if !gate.is_admitting() {
                    tracing::warn!(
                        source_cn = %msg.source.cn,
                        "NATS backpressure gate over high-water, dropping message"
                    );
                    return;
                }
                Some(gate.acquire(msg.payload.len()))
            }
            None => None,
        };

        let span = tracing::debug_span!(
            "nats_publish",
            source_cn = %msg.source.cn,
        );

        self.publish_inner(msg).instrument(span).await;
        // `_permit` drops here, releasing the gate's reservation.
    }

    /// Inner publish logic, separated so the caller can `.instrument()` a span
    /// around this future without holding an `EnteredSpan` across `.await`.
    async fn publish_inner(&self, msg: &RoutableMessage) {
        // Without full-detail, only publish position messages
        #[cfg(not(feature = "full-detail"))]
        if msg.metadata.message_type != MessageType::Position {
            return;
        }

        let raw_group = msg
            .source
            .groups
            .iter()
            .next()
            .map(String::as_str)
            .unwrap_or("");

        let group =
            sanitize_nats_token(raw_group).unwrap_or(Cow::Borrowed(&self.config.default_group));

        // #859: tenant subject prefix. Off by default — operators who
        // opt in (`tenant_subject_prefix = true`) and whose messages
        // carry a populated `tenant_id` see the live and JetStream
        // history subjects prefixed with `tenant.<sanitized-tenant>.`.
        // Sanitisation reuses `sanitize_nats_token` so a hostile cert
        // Organization field cannot inject NATS subject separators.
        let tenant_prefix = tenant_prefix_for(msg, &self.config);

        let subject = match &tenant_prefix {
            Some(t) => format!(
                "tenant.{}.{}.{}.update",
                t, self.config.subject_prefix, group
            ),
            None => format!("{}.{}.update", self.config.subject_prefix, group),
        };

        let wire_event = match self.build_wire_event(&msg.payload) {
            Some(event) => event,
            None => return,
        };

        // Drop reports whose position is marked unknown via the
        // ce/le large-magic-value convention (see
        // `WireEvent::is_position_unknown`). Historically the filter
        // matched `lat == 0 && lon == 0`, which dropped legitimate
        // equatorial reports from the Gulf of Guinea and similar
        // ocean tracks.
        if wire_event.is_position_unknown() {
            return;
        }

        let json = match serde_json::to_vec(&wire_event) {
            Ok(j) => j,
            Err(e) => {
                tracing::warn!(error = %e, "failed to serialize NATS message");
                return;
            }
        };

        let payload = Bytes::from(json);

        let mut headers = async_nats::HeaderMap::new();
        headers.insert("X-Rustgate-Instance", self.config.instance_id.as_str());

        // Publish to live subject
        if let Err(e) = self
            .client
            .publish_with_headers(subject, headers.clone(), payload.clone())
            .await
        {
            tracing::warn!(group = %group, error = %e, "NATS publish failed");
        }

        // Publish to JetStream history stream (reuse serialized bytes)
        if let Some(uid) = sanitize_nats_token(&wire_event.uid) {
            let history_subject = match &tenant_prefix {
                Some(t) => format!(
                    "tenant.{}.{}.{}",
                    t, self.config.jetstream_subject_prefix, uid
                ),
                None => format!("{}.{}", self.config.jetstream_subject_prefix, uid),
            };
            if let Err(e) = self
                .client
                .publish_with_headers(history_subject, headers, payload)
                .await
            {
                tracing::debug!(uid = %uid, error = %e, "JetStream history publish failed");
            }
        } else {
            tracing::debug!(uid = %wire_event.uid, "invalid UID for JetStream subject, skipping history publish");
        }
    }

    /// Build a WireEvent from raw CoT XML payload.
    ///
    /// With `full-detail`, uses the full XML parser to extract all detail fields.
    /// Without it, uses the minimal parser for position-only data.
    fn build_wire_event(&self, payload: &[u8]) -> Option<WireEvent> {
        #[cfg(feature = "full-detail")]
        {
            match rustgate_proto::xml_full::parse_full(payload) {
                Ok(full_cot) => Some(WireEvent::from_full_cot(&full_cot)),
                Err(e) => {
                    tracing::debug!(error = %e, "full CoT parse failed, skipping NATS publish");
                    None
                }
            }
        }
        #[cfg(not(feature = "full-detail"))]
        {
            match rustgate_cot::parse(payload) {
                Ok(cot) => Some(WireEvent::from_cot(&cot)),
                Err(e) => {
                    tracing::debug!(error = ?e, "CoT parse failed, skipping NATS publish");
                    None
                }
            }
        }
    }
}

/// Maximum length in bytes for a single NATS subject token.
///
/// NATS does not mandate a per-token limit, but excessively long tokens
/// waste memory and can indicate malicious input. 256 bytes is generous
/// enough for legitimate identifiers while bounding resource usage.
const MAX_TOKEN_LENGTH: usize = 256;

/// Compute the per-message tenant prefix for the publish path.
///
/// Returns `Some(sanitised_tenant)` when the publisher is configured
/// with `tenant_subject_prefix = true` AND the message carries a
/// non-empty `tenant_id`. Returns `None` otherwise — the legacy /
/// pre-#859 wire format. Extracted from
/// [`NatsPublisher::publish_inner`] so the prefix decision is
/// testable without standing up a real NATS broker.
fn tenant_prefix_for<'a>(msg: &'a RoutableMessage, config: &NatsConfig) -> Option<Cow<'a, str>> {
    if !config.tenant_subject_prefix {
        return None;
    }
    msg.metadata.tenant_id().and_then(sanitize_nats_token)
}

/// Sanitize a string into a valid single NATS subject token.
///
/// Returns `None` if the input cannot be sanitized into a valid token
/// (i.e. the result is empty after all transformations).
///
/// # Rules
/// - NFC normalization is applied first for consistent handling of
///   equivalent Unicode representations
/// - NATS wildcards (`*`, `>`) are stripped
/// - NATS subject separator (`.`) is replaced with `_` to prevent
///   subject injection
/// - ASCII control characters (0x00-0x1F, 0x7F) are stripped
/// - Non-ASCII characters are stripped (NATS subjects must be ASCII-safe)
/// - Whitespace (space, tab, etc.) is stripped
/// - Empty results return `None`
/// - Result is capped at [`MAX_TOKEN_LENGTH`] bytes
///
/// Returns `Cow::Borrowed` on the fast path (input already valid) and
/// `Cow::Owned` when any transformation was needed.
///
/// This is one of four sanitization helpers in the workspace; see the
/// matrix in [`rustgate_core::sanitize`] for the full set of helpers
/// and the rationale for why their rules differ. Output bytes for any
/// given input are pinned by `sanitize_nats_token_byte_stable_for_known_inputs`.
fn sanitize_nats_token(s: &str) -> Option<Cow<'_, str>> {
    if s.is_empty() {
        return None;
    }

    // Fast path: already valid printable ASCII with no reserved characters.
    // Valid bytes are 0x21..=0x7E excluding '.', '>', '*'.
    if s.len() <= MAX_TOKEN_LENGTH
        && s.bytes()
            .all(|b| b > 0x20 && b < 0x7F && !matches!(b, b'.' | b'>' | b'*'))
    {
        return Some(Cow::Borrowed(s));
    }

    // Slow path: NFC-normalize then strip/replace character-by-character.
    let sanitized: String = s
        .nfc()
        .filter(|c| c.is_ascii()) // strip non-ASCII
        .filter(|c| !c.is_ascii_control()) // strip control chars (0x00-0x1F, 0x7F)
        .filter(|c| !c.is_ascii_whitespace()) // strip whitespace
        .filter(|c| *c != '*' && *c != '>') // strip NATS wildcards
        .map(|c| if c == '.' { '_' } else { c }) // replace separator
        // `.take()` counts chars, but at this point only ASCII survives
        // (non-ASCII was stripped above), so chars == bytes. Reordering the
        // filter chain would break this invariant.
        .take(MAX_TOKEN_LENGTH) // cap length
        .collect();

    if sanitized.is_empty() {
        None
    } else {
        Some(Cow::Owned(sanitized))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]
    use super::*;

    fn make_msg(tenant: Option<&str>) -> RoutableMessage {
        let id = rustgate_core::identity::Identity::new(
            "alice".to_string(),
            "fp".to_string(),
            std::collections::BTreeSet::new(),
        )
        .expect("valid identity");
        let mut meta = rustgate_core::message::Metadata::new(
            std::time::SystemTime::now(),
            "tcp".to_string(),
            rustgate_core::message::MessageType::Position,
        );
        if let Some(t) = tenant {
            meta = meta.with_tenant_id(t);
        }
        RoutableMessage {
            source: id,
            destination: rustgate_core::message::Destination::Broadcast,
            payload: bytes::Bytes::new(),
            metadata: meta,
        }
    }

    // ── #859: tenant subject prefix coverage ────────────────────────

    #[test]
    fn tenant_prefix_off_by_default_returns_none_even_with_tenant() {
        // Pre-#859 wire-compat: with `tenant_subject_prefix = false`
        // (the default) a populated tenant on the message MUST NOT
        // surface in the subject. Operators must explicitly opt in.
        let cfg = NatsConfig {
            tenant_subject_prefix: false,
            ..NatsConfig::default()
        };
        let msg = make_msg(Some("acme"));
        assert!(
            tenant_prefix_for(&msg, &cfg).is_none(),
            "off-by-default must override tenant on the message",
        );
    }

    #[test]
    fn tenant_prefix_on_returns_sanitised_tenant() {
        // Opt-in path: with the flag on and a populated tenant, the
        // helper returns the sanitised tenant token. Sanitisation
        // reuses `sanitize_nats_token` so subject-injection
        // characters are stripped/replaced.
        let cfg = NatsConfig {
            tenant_subject_prefix: true,
            ..NatsConfig::default()
        };
        let msg = make_msg(Some("acme"));
        assert_eq!(tenant_prefix_for(&msg, &cfg).as_deref(), Some("acme"));
        // Subject-injection defence: a tenant id like `evil.>` must
        // not produce a wildcard publish subject.
        let msg = make_msg(Some("evil.>"));
        assert_eq!(tenant_prefix_for(&msg, &cfg).as_deref(), Some("evil_"));
    }

    #[test]
    fn tenant_prefix_on_returns_none_when_message_has_no_tenant() {
        // Opt-in path with no tenant on the message: the publisher
        // falls back to the legacy subject — no `tenant.…` prefix
        // and no wedging on a `None` tenant.
        let cfg = NatsConfig {
            tenant_subject_prefix: true,
            ..NatsConfig::default()
        };
        let msg = make_msg(None);
        assert!(tenant_prefix_for(&msg, &cfg).is_none());
    }

    #[test]
    fn sanitize_normal_input_unchanged() {
        assert_eq!(sanitize_nats_token("Cyan").as_deref(), Some("Cyan"));
        assert_eq!(sanitize_nats_token("__ANON__").as_deref(), Some("__ANON__"));
        assert_eq!(
            sanitize_nats_token("track-uid-123").as_deref(),
            Some("track-uid-123")
        );
        assert_eq!(
            sanitize_nats_token("alpha-team").as_deref(),
            Some("alpha-team")
        );
    }

    #[test]
    fn sanitize_ascii_returns_borrowed() {
        let result = sanitize_nats_token("hello");
        assert!(matches!(result, Some(Cow::Borrowed(_))));
    }

    #[test]
    fn sanitize_strips_nats_separator() {
        // Dots are replaced with underscores to prevent subject injection
        assert_eq!(
            sanitize_nats_token("group.subgroup").as_deref(),
            Some("group_subgroup")
        );
        assert_eq!(sanitize_nats_token("a.b.c.d").as_deref(), Some("a_b_c_d"));
    }

    #[test]
    fn sanitize_strips_wildcards() {
        assert_eq!(sanitize_nats_token("group*").as_deref(), Some("group"));
        assert_eq!(sanitize_nats_token("a>b").as_deref(), Some("ab"));
        assert_eq!(sanitize_nats_token("a*b").as_deref(), Some("ab"));
        // Pure wildcards sanitize to empty → None
        assert_eq!(sanitize_nats_token(">").as_deref(), None);
        assert_eq!(sanitize_nats_token("*").as_deref(), None);
        assert_eq!(sanitize_nats_token(">*").as_deref(), None);
    }

    #[test]
    fn sanitize_strips_control_chars() {
        assert_eq!(sanitize_nats_token("a\nb").as_deref(), Some("ab"));
        assert_eq!(sanitize_nats_token("a\0b").as_deref(), Some("ab"));
        assert_eq!(sanitize_nats_token("a\x01b").as_deref(), Some("ab"));
        assert_eq!(sanitize_nats_token("a\x7Fb").as_deref(), Some("ab"));
        assert_eq!(sanitize_nats_token("a\tb").as_deref(), Some("ab"));
    }

    #[test]
    fn sanitize_strips_non_ascii() {
        // Non-ASCII characters are stripped, ASCII remainder is preserved
        assert_eq!(sanitize_nats_token("caf\u{00e9}").as_deref(), Some("caf"));
        assert_eq!(
            sanitize_nats_token("\u{1F600}hello").as_deref(),
            Some("hello")
        );
        // Pure non-ASCII → empty → None
        assert_eq!(sanitize_nats_token("\u{00e9}\u{00e9}").as_deref(), None);
    }

    #[test]
    fn sanitize_rejects_empty() {
        assert_eq!(sanitize_nats_token("").as_deref(), None);
        // Dots only → all replaced with underscores, so this is valid
        assert_eq!(sanitize_nats_token("...").as_deref(), Some("___"));
    }

    #[test]
    fn sanitize_rejects_whitespace_only() {
        assert_eq!(sanitize_nats_token("   ").as_deref(), None);
        assert_eq!(sanitize_nats_token("\t\t").as_deref(), None);
    }

    #[test]
    fn sanitize_strips_whitespace() {
        // Whitespace is stripped entirely (not just trimmed)
        assert_eq!(sanitize_nats_token("a b").as_deref(), Some("ab"));
        assert_eq!(sanitize_nats_token("  group  ").as_deref(), Some("group"));
    }

    #[test]
    fn sanitize_caps_length() {
        let long_input = "a".repeat(MAX_TOKEN_LENGTH + 100);
        let result = sanitize_nats_token(&long_input);
        assert!(result.is_some());
        assert_eq!(result.as_deref().map(str::len), Some(MAX_TOKEN_LENGTH));
    }

    #[test]
    fn sanitize_accepts_max_length_token() {
        let token = "a".repeat(MAX_TOKEN_LENGTH);
        assert_eq!(sanitize_nats_token(&token).as_deref(), Some(token.as_str()));
    }

    #[test]
    fn sanitize_unicode_confusable() {
        // Cyrillic 'а' (U+0430) looks like Latin 'a' but is non-ASCII → stripped
        assert_eq!(sanitize_nats_token("te\u{0430}m").as_deref(), Some("tem"));
        // Mixed: Latin 'a' stays, Cyrillic 'а' stripped
        assert_eq!(sanitize_nats_token("a\u{0430}b").as_deref(), Some("ab"));
    }

    #[test]
    fn sanitize_nfc_consistent_for_equivalent_inputs() {
        // Both representations of "é" are non-ASCII and stripped, leaving "caf"
        let nfc = sanitize_nats_token("caf\u{00e9}");
        let nfd = sanitize_nats_token("caf\u{0065}\u{0301}");
        assert_eq!(nfc, nfd);
    }

    #[test]
    fn sanitize_combined_attack_vector() {
        // A crafted input combining multiple injection vectors
        assert_eq!(
            sanitize_nats_token("admin.*.>\x00\u{0430}team").as_deref(),
            Some("admin__team")
        );
    }

    #[test]
    fn sanitize_nats_token_byte_stable_for_known_inputs() {
        // Pins the exact output bytes for a corpus of inputs spanning
        // every documented behavior class of `sanitize_nats_token`. The
        // matrix in `rustgate_core::sanitize` claims byte-stable output;
        // any wire-visible change to a NATS subject token here would
        // break downstream subscribers that filter on these subjects.
        let cases: &[(&str, Option<&str>)] = &[
            ("plain", Some("plain")),
            ("__ANON__", Some("__ANON__")),
            ("track-uid-123", Some("track-uid-123")),
            ("group.subgroup", Some("group_subgroup")),
            ("a.b.c.d", Some("a_b_c_d")),
            ("group*", Some("group")),
            ("a>b", Some("ab")),
            ("a\nb", Some("ab")),
            ("a\tb", Some("ab")),
            ("a\x7Fb", Some("ab")),
            ("caf\u{00e9}", Some("caf")),
            ("caf\u{0065}\u{0301}", Some("caf")),
            ("\u{1F600}hello", Some("hello")),
            ("a\u{0430}b", Some("ab")),
            ("", None),
            (">", None),
            ("...", Some("___")),
            ("admin.*.>\x00\u{0430}team", Some("admin__team")),
        ];
        for (input, expected) in cases {
            assert_eq!(
                sanitize_nats_token(input).as_deref(),
                *expected,
                "byte-stable output regression for input {input:?}"
            );
        }
    }

    #[test]
    fn matrix_invariant_sanitize_nats_token_does_nfc_normalize() {
        // Pinned axis from the module-doc matrix in `rustgate_core::sanitize`:
        // `sanitize_nats_token` DOES NFC-normalize (in contrast to
        // `sanitize_for_log`). Inputs that are NFC/NFD variants of the
        // same logical string must produce identical output. A regression
        // that dropped the `.nfc()` step would let a Unicode-equivalence
        // spoof on the input side slip through to the NATS subject.
        let nfd = "caf\u{0065}\u{0301}\u{0061}"; // "caféa" with combining acute
        let nfc = "caf\u{00e9}\u{0061}"; // same in NFC
        assert_ne!(
            nfd, nfc,
            "NFD and NFC variants must differ at the byte level"
        );
        assert_eq!(
            sanitize_nats_token(nfd).as_deref(),
            sanitize_nats_token(nfc).as_deref(),
            "NFC normalization must collapse equivalent forms"
        );
    }

    #[test]
    fn matrix_invariant_sanitize_nats_token_strips_non_ascii() {
        // Pinned axis from the module-doc matrix: `sanitize_nats_token`
        // STRIPS non-ASCII (in contrast to `sanitize_for_log` which
        // preserves it). This is structural — NATS subjects must be
        // ASCII-safe — so a regression here would produce subjects the
        // NATS server rejects.
        assert_eq!(sanitize_nats_token("\u{4e16}\u{754c}").as_deref(), None);
        assert_eq!(
            sanitize_nats_token("a\u{1F600}b").as_deref(),
            Some("ab"),
            "non-ASCII characters must be dropped, not replaced"
        );
    }
}
