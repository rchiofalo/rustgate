// Copyright © 2026 Roberto Chiofalo.

//! JetStream history replay for situational awareness bootstrap.
//!
//! On startup, fetches the latest position per track from the TRACKS_HISTORY
//! stream and populates the Router's PositionCache. This ensures new TAK
//! clients get a full SA picture even if local positions haven't been received
//! yet via the live NATS subscription.
//!
//! When a checkpoint path is configured, the replayer persists the last
//! processed stream sequence number to disk. On subsequent restarts it
//! resumes from that sequence instead of replaying the entire history,
//! avoiding unnecessary re-processing.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_nats::jetstream;
use futures::StreamExt;
use rustgate_transport::Router;

use crate::config::NatsConfig;
use crate::serde_compat::WireEvent;

/// Persists the last processed JetStream sequence number to disk.
///
/// On graceful shutdown or after replay completes, the current
/// sequence is written to a file. On restart, replay resumes from
/// the checkpoint instead of re-reading the entire stream.
#[derive(Debug)]
struct Checkpoint {
    path: PathBuf,
}

impl Checkpoint {
    /// Create a new checkpoint backed by the given file path.
    fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Load the last saved sequence number, or `None` if no checkpoint exists.
    async fn load(&self) -> Option<u64> {
        let data = tokio::fs::read_to_string(&self.path).await.ok()?;
        data.trim().parse().ok()
    }

    /// Save the current sequence number to disk.
    async fn save(&self, seq: u64) -> std::io::Result<()> {
        if let Some(parent) = self.path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::write(&self.path, seq.to_string()).await
    }
}

/// Replays the latest position per track from JetStream into the Router cache.
#[derive(Debug)]
pub struct JetStreamReplay {
    client: async_nats::Client,
    config: NatsConfig,
    checkpoint_path: Option<PathBuf>,
}

impl JetStreamReplay {
    /// Create a new replay handle.
    ///
    /// When `checkpoint_path` is `Some`, the replayer will persist and resume
    /// from the last processed sequence number on disk.
    pub fn new(
        client: async_nats::Client,
        config: NatsConfig,
        checkpoint_path: Option<PathBuf>,
    ) -> Self {
        Self {
            client,
            config,
            checkpoint_path,
        }
    }

    /// Fetch latest position per track from the TRACKS_HISTORY stream and
    /// populate the router's position cache.
    ///
    /// When a checkpoint path is configured and a previous checkpoint exists,
    /// uses `DeliverPolicy::ByStartSequence` to resume from the last
    /// processed sequence. Otherwise falls back to `DeliverLastPerSubject`
    /// for a full SA bootstrap.
    ///
    /// Returns the number of positions loaded.
    pub async fn replay(
        &self,
        router: Arc<Router>,
    ) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
        let js = jetstream::new(self.client.clone());

        // Look up the existing stream (don't create it — stream config is external)
        let stream = js.get_stream(&self.config.jetstream_stream).await?;

        // If a checkpoint exists, resume from the saved sequence number.
        // Otherwise, deliver the last message per subject (full SA bootstrap).
        let checkpoint = self
            .checkpoint_path
            .as_ref()
            .map(|p| Checkpoint::new(p.clone()));
        let saved_seq = if let Some(ref cp) = checkpoint {
            cp.load().await
        } else {
            None
        };

        let deliver_policy = if let Some(seq) = saved_seq {
            tracing::info!(seq, "resuming JetStream replay from checkpoint");
            jetstream::consumer::DeliverPolicy::ByStartSequence {
                start_sequence: seq + 1,
            }
        } else {
            tracing::info!("no checkpoint found, replaying last per subject");
            jetstream::consumer::DeliverPolicy::LastPerSubject
        };

        // Ordered consumer using the chosen deliver policy.
        let consumer = stream
            .create_consumer(jetstream::consumer::push::OrderedConfig {
                deliver_subject: self.client.new_inbox(),
                filter_subject: format!("{}.>", self.config.jetstream_subject_prefix),
                deliver_policy,
                replay_policy: jetstream::consumer::ReplayPolicy::Instant,
                ..Default::default()
            })
            .await?;

        let mut messages = consumer.messages().await?;
        let mut count = 0usize;
        let mut last_seq: Option<u64> = None;

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

                    // Extract sequence early but only checkpoint after
                    // successful processing to avoid skipping failed messages
                    // on restart.
                    let seq = msg.info().ok().map(|i| i.stream_sequence);

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

                    // Checkpoint only after the message was successfully processed
                    if let Some(s) = seq {
                        last_seq = Some(s);
                    }

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

        // Persist the last processed sequence so the next restart can resume.
        if let (Some(cp), Some(seq)) = (&checkpoint, last_seq) {
            if let Err(e) = cp.save(seq).await {
                tracing::warn!(error = %e, seq, "failed to save JetStream checkpoint");
            } else {
                tracing::info!(seq, "saved JetStream replay checkpoint");
            }
        }

        tracing::info!(count, stream = %self.config.jetstream_stream, "JetStream SA replay complete");
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use super::*;

    #[tokio::test]
    async fn checkpoint_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("checkpoint");
        let checkpoint = Checkpoint::new(path);

        // No checkpoint initially
        assert!(checkpoint.load().await.is_none());

        // Save and reload
        checkpoint.save(42).await.unwrap();
        assert_eq!(checkpoint.load().await, Some(42));

        // Overwrite
        checkpoint.save(100).await.unwrap();
        assert_eq!(checkpoint.load().await, Some(100));
    }

    #[tokio::test]
    async fn checkpoint_invalid_content_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("checkpoint");
        tokio::fs::write(&path, "not-a-number").await.unwrap();

        let checkpoint = Checkpoint::new(path);
        assert!(checkpoint.load().await.is_none());
    }

    #[tokio::test]
    async fn checkpoint_missing_file_returns_none() {
        let checkpoint = Checkpoint::new(PathBuf::from("/nonexistent/path/checkpoint"));
        assert!(checkpoint.load().await.is_none());
    }
}
