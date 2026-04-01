//! JetStream history replay for situational awareness bootstrap.
//!
//! On startup, fetches the latest position per track from the TRACKS_HISTORY
//! stream and populates the Router's PositionCache. This ensures new TAK
//! clients get a full SA picture even if local positions haven't been received
//! yet via the live NATS subscription.

use std::sync::Arc;
use std::time::Duration;

use async_nats::jetstream;
use futures::StreamExt;
use rustgate_transport::Router;

use crate::config::NatsConfig;
use crate::serde_compat::WireEvent;

/// Replays the latest position per track from JetStream into the Router cache.
#[derive(Debug)]
pub struct JetStreamReplay {
    client: async_nats::Client,
    config: NatsConfig,
}

impl JetStreamReplay {
    pub fn new(client: async_nats::Client, config: NatsConfig) -> Self {
        Self { client, config }
    }

    /// Fetch latest position per track from the TRACKS_HISTORY stream and
    /// populate the router's position cache.
    ///
    /// Creates an ephemeral ordered consumer with `DeliverLastPerSubject`
    /// policy. Returns the number of positions loaded.
    pub async fn replay(
        &self,
        router: Arc<Router>,
    ) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
        let js = jetstream::new(self.client.clone());

        // Look up the existing stream (don't create it — stream config is external)
        let stream = js.get_stream(&self.config.jetstream_stream).await?;

        // Ordered consumer that delivers the last message per subject
        // (one per track UID). This gives us latest-state-per-entity.
        let consumer = stream
            .create_consumer(jetstream::consumer::push::OrderedConfig {
                deliver_subject: self.client.new_inbox(),
                filter_subject: format!("{}.>", self.config.jetstream_subject_prefix),
                deliver_policy: jetstream::consumer::DeliverPolicy::LastPerSubject,
                replay_policy: jetstream::consumer::ReplayPolicy::Instant,
                ..Default::default()
            })
            .await?;

        let mut messages = consumer.messages().await?;
        let mut count = 0usize;

        // Drain with a timeout — once we stop receiving messages, replay is done.
        // The 5-second per-message timeout balances startup latency against
        // resilience to transient NATS delivery pauses. For very large track
        // counts (10k+), consider increasing via a config field.
        loop {
            let next = tokio::time::timeout(Duration::from_secs(5), messages.next()).await;

            match next {
                Ok(Some(Ok(msg))) => {
                    if self.config.max_payload_bytes > 0
                        && msg.payload.len() > self.config.max_payload_bytes
                    {
                        tracing::debug!(
                            len = msg.payload.len(),
                            max = self.config.max_payload_bytes,
                            "dropping oversized JetStream replay message"
                        );
                        continue;
                    }

                    let wire_event: WireEvent = match serde_json::from_slice(&msg.payload) {
                        Ok(e) => e,
                        Err(e) => {
                            tracing::debug!(error = %e, "failed to parse JetStream replay message");
                            continue;
                        }
                    };

                    if wire_event.is_position_unknown() {
                        continue;
                    }

                    // Group affiliation is not preserved in history subjects
                    // (TRACKS.HISTORY.{uid}), so replayed positions use the
                    // default group. This is acceptable for SA bootstrap —
                    // group-aware routing applies to subsequent live messages.
                    let group = self.config.default_group.clone();
                    let routable = match wire_event.into_routable(&group, msg.payload.clone()) {
                        Ok(r) => r,
                        Err(e) => {
                            tracing::warn!(error = %e, "invalid JetStream replay identity");
                            continue;
                        }
                    };

                    // Store directly into cache (no sessions connected yet during replay)
                    router.cache().store(routable).await;
                    count += 1;

                    if self.config.max_replay_count > 0 && count >= self.config.max_replay_count {
                        tracing::info!(
                            count,
                            limit = self.config.max_replay_count,
                            "JetStream replay hit count limit"
                        );
                        break;
                    }
                }
                Ok(Some(Err(e))) => {
                    tracing::warn!(error = %e, "JetStream replay message error");
                    break;
                }
                Ok(None) => break, // Stream ended
                Err(_) => break,   // Timeout — done receiving
            }
        }

        tracing::info!(count, stream = %self.config.jetstream_stream, "JetStream SA replay complete");
        Ok(count)
    }
}
