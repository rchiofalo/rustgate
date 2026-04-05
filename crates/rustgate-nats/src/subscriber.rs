//! Subscribes to NATS for messages destined to locally connected clients.
//!
//! Includes periodic stats logging for backpressure observability. The
//! subscriber processes messages sequentially, providing natural
//! backpressure — when routing is slow, `next().await` pauses intake
//! from the NATS subscription buffer. When that buffer fills, the
//! `async_nats` client emits a slow consumer event (configured via
//! [`NatsConfig::subscription_capacity`]).

use std::sync::Arc;

use async_nats::Client;
use futures::StreamExt;
use rustgate_transport::Router;
use tracing::Instrument;

use crate::config::NatsConfig;
use crate::serde_compat::WireEvent;

/// Receives messages from NATS and delivers them to local sessions.
///
/// Runs as a background task. Subscribes to `{prefix}.>` and converts
/// incoming JSON wire events to RoutableMessages for local delivery.
#[derive(Debug)]
pub struct NatsSubscriber {
    client: Client,
    config: NatsConfig,
}

impl NatsSubscriber {
    pub fn new(client: Client, config: NatsConfig) -> Self {
        Self { client, config }
    }

    /// Run the subscriber loop. This is a long-running future that processes
    /// messages until the subscription ends or the runtime shuts down.
    ///
    /// Tracks processed and dropped message counts and emits periodic stats
    /// logs (every 60 seconds) for backpressure observability.
    pub async fn run(self, router: Arc<Router>) -> Result<(), async_nats::Error> {
        let subject = format!("{}.>", self.config.subject_prefix);
        let mut subscription = self.client.subscribe(subject.clone()).await?;

        tracing::info!(
            subject = %subject,
            subscription_capacity = self.config.subscription_capacity,
            "NATS subscriber started"
        );

        let mut processed: u64 = 0;
        let mut dropped: u64 = 0;
        let mut last_stats_log = tokio::time::Instant::now();
        let stats_interval = std::time::Duration::from_secs(60);

        while let Some(msg) = subscription.next().await {
            // Echo prevention: skip messages published by this instance
            if let Some(headers) = &msg.headers
                && let Some(origin) = headers.get("X-Rustgate-Instance")
                && origin.as_str() == self.config.instance_id
            {
                continue;
            }

            if self.config.max_payload_bytes > 0
                && msg.payload.len() > self.config.max_payload_bytes
            {
                tracing::debug!(
                    len = msg.payload.len(),
                    max = self.config.max_payload_bytes,
                    subject = %msg.subject,
                    "dropping oversized NATS message"
                );
                dropped += 1;
                continue;
            }

            let span = tracing::debug_span!(
                "nats_recv",
                subject = %msg.subject,
            );

            let routable = {
                let _guard = span.enter();

                let group = extract_group_from_subject(
                    msg.subject.as_str(),
                    &self.config.subject_prefix,
                    &self.config.default_group,
                );

                let wire_event: WireEvent = match serde_json::from_slice(&msg.payload) {
                    Ok(e) => e,
                    Err(e) => {
                        tracing::debug!(error = %e, subject = %msg.subject, "failed to parse NATS message");
                        dropped += 1;
                        continue;
                    }
                };

                if wire_event.is_position_unknown() {
                    dropped += 1;
                    continue;
                }

                match wire_event.into_routable(&group, msg.payload.clone()) {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::warn!(error = %e, "invalid NATS message identity");
                        dropped += 1;
                        continue;
                    }
                }
                // _guard dropped here — before the .await below
            };

            router.route(routable).instrument(span).await;
            processed += 1;

            // Periodic stats logging for backpressure observability
            if last_stats_log.elapsed() >= stats_interval {
                tracing::info!(processed, dropped, "NATS subscriber stats");
                last_stats_log = tokio::time::Instant::now();
            }
        }

        tracing::info!(processed, dropped, "NATS subscriber ended");
        Ok(())
    }
}

/// Extract the group segment from a NATS subject.
///
/// Expected format: `"{prefix}.{group}.{action}"` (e.g., `"points.ALPHA.update"`).
/// Returns `"__ANON__"` if the subject has no group segment or doesn't match.
fn extract_group_from_subject(subject: &str, prefix: &str, default: &str) -> String {
    subject
        .strip_prefix(prefix)
        .and_then(|s| s.strip_prefix('.'))
        .and_then(|rest| {
            // Need at least "group.action" (two segments) to have a group
            let dot = rest.find('.')?;
            let group = &rest[..dot];
            if group.is_empty() { None } else { Some(group) }
        })
        .unwrap_or(default)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_group_standard() {
        assert_eq!(
            extract_group_from_subject("points.Cyan.update", "points", "__ANON__"),
            "Cyan"
        );
    }

    #[test]
    fn extract_group_anon() {
        assert_eq!(
            extract_group_from_subject("points.__ANON__.update", "points", "__ANON__"),
            "__ANON__"
        );
    }

    #[test]
    fn extract_group_two_segment_subject() {
        // "points.update" has no group segment — should return default
        assert_eq!(
            extract_group_from_subject("points.update", "points", "__ANON__"),
            "__ANON__"
        );
    }

    #[test]
    fn extract_group_no_prefix_match() {
        assert_eq!(
            extract_group_from_subject("cot.Cyan.update", "points", "__ANON__"),
            "__ANON__"
        );
    }

    #[test]
    fn extract_group_empty_group_segment() {
        // "points..update" has an empty group — should return default
        assert_eq!(
            extract_group_from_subject("points..update", "points", "__ANON__"),
            "__ANON__"
        );
    }

    #[test]
    fn extract_group_uses_custom_default() {
        assert_eq!(
            extract_group_from_subject("points.update", "points", "CUSTOM"),
            "CUSTOM"
        );
    }
}
