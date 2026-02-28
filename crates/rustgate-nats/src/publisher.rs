//! Publishes inbound CoT messages to NATS subjects.

use async_nats::Client;
use bytes::Bytes;
#[cfg(not(feature = "full-detail"))]
use rustgate_core::message::MessageType;
use rustgate_core::message::RoutableMessage;

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

        let group = sanitize_nats_token(raw_group)
            .unwrap_or(self.config.default_group.as_str());

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
        headers.insert(
            "X-Rustgate-Instance",
            self.config.instance_id.as_str(),
        );

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

/// Validate a string for safe use as a single NATS subject token.
///
/// NATS subjects require printable ASCII (0x21..=0x7E) excluding the
/// reserved characters `.` (level separator), `>` (full wildcard),
/// and `*` (partial wildcard). Rejects control chars, space, DEL,
/// and non-ASCII bytes.
fn sanitize_nats_token(s: &str) -> Option<&str> {
    if s.is_empty() {
        return None;
    }
    if s.bytes().any(|b| b <= 0x20 || b >= 0x7F || matches!(b, b'.' | b'>' | b'*')) {
        return None;
    }
    Some(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_valid_tokens() {
        assert_eq!(sanitize_nats_token("Cyan"), Some("Cyan"));
        assert_eq!(sanitize_nats_token("__ANON__"), Some("__ANON__"));
        assert_eq!(sanitize_nats_token("track-uid-123"), Some("track-uid-123"));
    }

    #[test]
    fn sanitize_rejects_invalid() {
        assert_eq!(sanitize_nats_token(""), None);
        assert_eq!(sanitize_nats_token("a.b"), None);
        assert_eq!(sanitize_nats_token("a>b"), None);
        assert_eq!(sanitize_nats_token("a*b"), None);
        assert_eq!(sanitize_nats_token("a b"), None);
        assert_eq!(sanitize_nats_token("a\tb"), None);
        assert_eq!(sanitize_nats_token("a\0b"), None);
        // Control characters and DEL
        assert_eq!(sanitize_nats_token("a\x01b"), None);
        assert_eq!(sanitize_nats_token("a\x7Fb"), None);
        // Non-ASCII (NATS subjects are ASCII-only)
        assert_eq!(sanitize_nats_token("caf\u{00e9}"), None);
    }
}
