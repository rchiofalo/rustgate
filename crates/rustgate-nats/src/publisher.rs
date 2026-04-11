//! Publishes inbound CoT messages to NATS subjects.

use std::borrow::Cow;

use async_nats::Client;
use bytes::Bytes;
#[cfg(not(feature = "full-detail"))]
use rustgate_core::message::MessageType;
use rustgate_core::message::RoutableMessage;
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
}

impl NatsPublisher {
    pub fn new(client: Client, config: NatsConfig) -> Self {
        Self { client, config }
    }

    /// Publish a routable message to NATS.
    ///
    /// With the `full-detail` feature, publishes all CoT types with full
    /// detail fields. Without it, only position messages are published.
    pub async fn publish(&self, msg: &RoutableMessage) {
        // Echo prevention: don't re-publish messages that came from NATS
        if msg.metadata.source_protocol == "nats" {
            return;
        }

        let span = tracing::debug_span!(
            "nats_publish",
            source_cn = %msg.source.cn,
        );

        self.publish_inner(msg).instrument(span).await;
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

        let subject = format!("{}.{}.update", self.config.subject_prefix, group);

        let wire_event = match self.build_wire_event(&msg.payload) {
            Some(event) => event,
            None => return,
        };

        // Filter 0,0 positions (CoT spec: position unknown)
        if wire_event.point.lat == 0.0 && wire_event.point.lon == 0.0 {
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
            let history_subject = format!("{}.{}", self.config.jetstream_subject_prefix, uid);
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
/// - Leading/trailing whitespace in the result is trimmed
/// - Empty results return `None`
/// - Result is capped at [`MAX_TOKEN_LENGTH`] bytes
///
/// Returns `Cow::Borrowed` on the fast path (input already valid) and
/// `Cow::Owned` when any transformation was needed.
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
        .take(MAX_TOKEN_LENGTH) // cap length
        .collect();

    let trimmed = sanitized.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(Cow::Owned(trimmed.to_string()))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]
    use super::*;

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
}
