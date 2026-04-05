//! Subscribes to NATS for messages destined to locally connected clients.
//!
//! Uses a JetStream pull consumer for real backpressure — when processing
//! is slow, the consumer simply stops fetching new messages. The NATS
//! server retains them in the stream until the consumer catches up.
//! Messages are explicitly acknowledged after successful processing.

use std::sync::Arc;

use async_nats::jetstream;
use async_nats::jetstream::consumer::AckPolicy;
use async_nats::jetstream::stream::RetentionPolicy;
use futures::StreamExt;
use rustgate_transport::Router;
use tracing::Instrument;

use crate::config::NatsConfig;
use crate::serde_compat::WireEvent;

/// Receives messages from NATS via a JetStream pull consumer and delivers
/// them to local sessions.
///
/// Runs as a background task. Creates (or fetches) a JetStream stream
/// capturing `{prefix}.>` subjects, then creates a durable pull consumer
/// for explicit-ACK message delivery with real backpressure.
#[derive(Debug)]
pub struct NatsSubscriber {
    client: async_nats::Client,
    config: NatsConfig,
}

impl NatsSubscriber {
    pub fn new(client: async_nats::Client, config: NatsConfig) -> Self {
        Self { client, config }
    }

    /// Ensure the live-update JetStream stream exists, creating it if needed.
    ///
    /// The stream captures all subjects matching `{subject_prefix}.>` with
    /// a limits-based retention policy and reasonable defaults.
    async fn ensure_stream(
        &self,
        js: &jetstream::Context,
    ) -> Result<jetstream::stream::Stream, async_nats::Error> {
        let subjects = vec![format!("{}.>", self.config.subject_prefix)];
        let config = jetstream::stream::Config {
            name: self.config.live_stream.clone(),
            subjects,
            retention: RetentionPolicy::Limits,
            max_messages: 1_000_000,
            max_age: std::time::Duration::from_secs(3600), // 1 hour
            ..Default::default()
        };

        let stream = js.get_or_create_stream(config).await?;
        tracing::info!(
            stream = %self.config.live_stream,
            "JetStream live stream ready"
        );
        Ok(stream)
    }

    /// Create (or bind to) a durable pull consumer on the live stream.
    ///
    /// The consumer name is derived from the instance ID so each server
    /// instance gets its own consumer. Uses explicit ACK policy so messages
    /// are only removed from the pending set after successful processing.
    async fn ensure_consumer(
        &self,
        stream: &jetstream::stream::Stream,
    ) -> Result<jetstream::consumer::Consumer<jetstream::consumer::pull::Config>, async_nats::Error>
    {
        let consumer_name = format!("rustgate-sub-{}", self.config.instance_id);
        let config = jetstream::consumer::pull::Config {
            durable_name: Some(consumer_name.clone()),
            ack_policy: AckPolicy::Explicit,
            max_ack_pending: self.config.max_ack_pending,
            deliver_policy: jetstream::consumer::DeliverPolicy::New,
            filter_subject: format!("{}.>", self.config.subject_prefix),
            ..Default::default()
        };

        let consumer = stream
            .get_or_create_consumer(&consumer_name, config)
            .await?;
        tracing::info!(
            consumer = %consumer_name,
            max_ack_pending = self.config.max_ack_pending,
            "JetStream pull consumer ready"
        );
        Ok(consumer)
    }

    /// Run the subscriber loop. This is a long-running future that processes
    /// messages until shutdown or an unrecoverable error.
    ///
    /// Tracks processed and dropped message counts and emits periodic stats
    /// logs (every 60 seconds) for backpressure observability.
    pub async fn run(self, router: Arc<Router>) -> Result<(), async_nats::Error> {
        let js = jetstream::new(self.client.clone());
        let stream = self.ensure_stream(&js).await?;
        let consumer = self.ensure_consumer(&stream).await?;

        let mut messages = consumer.messages().await?;

        tracing::info!(
            stream = %self.config.live_stream,
            subject_filter = %format!("{}.>", self.config.subject_prefix),
            max_ack_pending = self.config.max_ack_pending,
            "NATS JetStream pull subscriber started"
        );

        let mut processed: u64 = 0;
        let mut dropped: u64 = 0;
        let mut last_stats_log = tokio::time::Instant::now();
        let stats_interval = std::time::Duration::from_secs(60);

        while let Some(msg_result) = messages.next().await {
            let msg = match msg_result {
                Ok(m) => m,
                Err(e) => {
                    tracing::warn!(error = %e, "JetStream message receive error");
                    continue;
                }
            };

            // Echo prevention: skip messages published by this instance
            if let Some(headers) = &msg.headers
                && let Some(origin) = headers.get("X-Rustgate-Instance")
                && origin.as_str() == self.config.instance_id
            {
                // ACK to advance the consumer past echo messages
                if let Err(e) = msg.ack().await {
                    tracing::debug!(error = %e, "failed to ACK echo message");
                }
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
                // ACK to prevent redelivery of garbage
                if let Err(e) = msg.ack().await {
                    tracing::debug!(error = %e, "failed to ACK oversized message");
                }
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
                        // ACK to prevent redelivery of unparseable data
                        if let Err(ack_err) = msg.ack().await {
                            tracing::debug!(error = %ack_err, "failed to ACK unparseable message");
                        }
                        continue;
                    }
                };

                if wire_event.is_position_unknown() {
                    dropped += 1;
                    if let Err(e) = msg.ack().await {
                        tracing::debug!(error = %e, "failed to ACK zero-position message");
                    }
                    continue;
                }

                match wire_event.into_routable(&group, msg.payload.clone()) {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::warn!(error = %e, "invalid NATS message identity");
                        dropped += 1;
                        if let Err(ack_err) = msg.ack().await {
                            tracing::debug!(error = %ack_err, "failed to ACK invalid message");
                        }
                        continue;
                    }
                }
                // _guard dropped here — before the .await below
            };

            router.route(routable).instrument(span).await;
            processed += 1;

            // ACK after successful processing
            if let Err(e) = msg.ack().await {
                tracing::warn!(error = %e, "failed to ACK processed message");
            }

            // Periodic stats logging for backpressure observability
            if last_stats_log.elapsed() >= stats_interval {
                tracing::info!(processed, dropped, "NATS subscriber stats");
                last_stats_log = tokio::time::Instant::now();
            }
        }

        tracing::info!(processed, dropped, "NATS JetStream subscriber ended");
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
