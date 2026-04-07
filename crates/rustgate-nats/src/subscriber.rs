//! Subscribes to NATS for messages destined to locally connected clients.
//!
//! Uses a JetStream pull consumer for real backpressure — when processing
//! is slow, the consumer simply stops fetching new messages. The NATS
//! server retains them in the stream until the consumer catches up.
//! Messages are explicitly acknowledged after successful processing.

use std::sync::Arc;
use std::time::Duration;

use async_nats::jetstream;
use async_nats::jetstream::consumer::AckPolicy;
use async_nats::jetstream::stream::RetentionPolicy;
use futures::StreamExt;
use rustgate_transport::Router;
use tracing::Instrument;

use crate::config::NatsConfig;
use crate::serde_compat::WireEvent;

/// Default interval between JetStream consumer lag polls.
const DEFAULT_LAG_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Snapshot of JetStream pull-consumer lag indicators.
///
/// Captured periodically from `consumer.info()` and forwarded to a
/// caller-supplied [`LagCallback`] so the `rustgate-nats` crate can stay
/// free of any Prometheus / metrics dependency.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LagSnapshot {
    /// Messages pending delivery to the consumer (`num_pending`).
    pub num_pending: u64,
    /// Number of messages that have been redelivered.
    pub num_redelivered: u64,
    /// Stream sequence of the highest contiguous ACK
    /// (`ack_floor.stream_seq`).
    pub ack_floor_stream_seq: u64,
}

/// Callback invoked with the latest [`LagSnapshot`] each poll cycle.
///
/// Wired by the binary crate to publish the values as Prometheus gauges,
/// keeping `rustgate-nats` agnostic of the metrics backend.
pub type LagCallback = Arc<dyn Fn(LagSnapshot) + Send + Sync>;

/// Callback invoked with the wall-clock duration of each `consumer.info()`
/// poll, regardless of success or failure. Wired by the binary crate to
/// observe a Prometheus histogram so the `rustgate-nats` crate stays free
/// of metrics dependencies.
pub type LatencyCallback = Arc<dyn Fn(Duration) + Send + Sync>;

/// Receives messages from NATS via a JetStream pull consumer and delivers
/// them to local sessions.
///
/// Runs as a background task. Creates (or fetches) a JetStream stream
/// capturing `{prefix}.>` subjects, then creates a durable pull consumer
/// for explicit-ACK message delivery with real backpressure.
pub struct NatsSubscriber {
    client: async_nats::Client,
    config: NatsConfig,
    lag_callback: Option<LagCallback>,
    latency_callback: Option<LatencyCallback>,
    lag_poll_interval: Duration,
}

impl std::fmt::Debug for NatsSubscriber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NatsSubscriber")
            .field("config", &self.config)
            .field("lag_callback", &self.lag_callback.is_some())
            .field("latency_callback", &self.latency_callback.is_some())
            .field("lag_poll_interval", &self.lag_poll_interval)
            .finish()
    }
}

impl NatsSubscriber {
    pub fn new(client: async_nats::Client, config: NatsConfig) -> Self {
        Self {
            client,
            config,
            lag_callback: None,
            latency_callback: None,
            lag_poll_interval: DEFAULT_LAG_POLL_INTERVAL,
        }
    }

    /// Register a callback that observes the wall-clock duration of every
    /// `consumer.info()` poll, including ones that returned an error. The
    /// binary crate wires this to a Prometheus histogram.
    pub fn with_latency_callback(mut self, callback: LatencyCallback) -> Self {
        self.latency_callback = Some(callback);
        self
    }

    /// Register a callback that will receive a [`LagSnapshot`] every
    /// `interval` while the subscriber is running. Pass `None` for
    /// `interval` to use the default polling cadence.
    pub fn with_lag_callback(mut self, callback: LagCallback, interval: Option<Duration>) -> Self {
        self.lag_callback = Some(callback);
        if let Some(i) = interval {
            self.lag_poll_interval = i;
        }
        self
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

        // Spawn the lag-poll task before draining messages so the first
        // observation lands shortly after startup. The task is aborted
        // when the subscriber returns.
        let lag_task = self.lag_callback.as_ref().map(|cb| {
            spawn_lag_poller(
                consumer.clone(),
                Arc::clone(cb),
                self.latency_callback.as_ref().map(Arc::clone),
                self.lag_poll_interval,
            )
        });
        let _lag_guard = lag_task.map(LagPollerGuard);

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

/// Aborts the lag-poll task on drop so it cannot outlive the subscriber.
struct LagPollerGuard(tokio::task::JoinHandle<()>);

impl Drop for LagPollerGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Spawn a background task that periodically calls `consumer.info()` and
/// forwards the lag indicators to `lag_callback`.
///
/// Transient failures (including JetStream timeouts and temporary
/// disconnects) are logged at `warn` and the loop continues to the next
/// tick — they must NOT kill the lag poller. The optional
/// `latency_callback` observes the wall-clock duration of every poll,
/// regardless of outcome.
fn spawn_lag_poller(
    mut consumer: jetstream::consumer::Consumer<jetstream::consumer::pull::Config>,
    lag_callback: LagCallback,
    latency_callback: Option<LatencyCallback>,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            let _ = ticker.tick().await;
            let started = tokio::time::Instant::now();
            let result = consumer.info().await;
            let elapsed = started.elapsed();
            handle_lag_poll_result(
                result.map(|info| LagSnapshot {
                    num_pending: info.num_pending,
                    num_redelivered: info.num_redelivered as u64,
                    ack_floor_stream_seq: info.ack_floor.stream_sequence,
                }),
                elapsed,
                &lag_callback,
                latency_callback.as_ref(),
            );
        }
    })
}

/// Process the outcome of a single `consumer.info()` poll.
///
/// Factored out so it can be unit-tested without a live JetStream
/// consumer. Transient errors are logged at `warn` and the caller is
/// expected to continue to the next tick — a single failed poll must
/// NOT kill the lag poller.
fn handle_lag_poll_result<E: std::fmt::Display>(
    result: Result<LagSnapshot, E>,
    elapsed: Duration,
    lag_callback: &LagCallback,
    latency_callback: Option<&LatencyCallback>,
) {
    if let Some(cb) = latency_callback {
        cb(elapsed);
    }
    match result {
        Ok(snapshot) => lag_callback(snapshot),
        Err(e) => {
            tracing::warn!(error = %e, "consumer.info() failed; will retry");
        }
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
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn lag_snapshot_fields_round_trip() {
        let snap = LagSnapshot {
            num_pending: 42,
            num_redelivered: 7,
            ack_floor_stream_seq: 1234,
        };
        let copy = snap;
        assert_eq!(copy.num_pending, 42);
        assert_eq!(copy.num_redelivered, 7);
        assert_eq!(copy.ack_floor_stream_seq, 1234);
    }

    #[test]
    fn lag_callback_invoked_with_snapshot() {
        use std::sync::Mutex;
        let captured: Arc<Mutex<Option<LagSnapshot>>> = Arc::new(Mutex::new(None));
        let captured_cb = Arc::clone(&captured);
        let cb: LagCallback = Arc::new(move |snap| {
            *captured_cb.lock().unwrap() = Some(snap);
        });
        cb(LagSnapshot {
            num_pending: 9,
            num_redelivered: 1,
            ack_floor_stream_seq: 100,
        });
        let got = captured.lock().unwrap().unwrap();
        assert_eq!(got.num_pending, 9);
        assert_eq!(got.num_redelivered, 1);
        assert_eq!(got.ack_floor_stream_seq, 100);
    }

    #[test]
    fn handle_lag_poll_result_error_then_ok_keeps_going() {
        use std::sync::Mutex;

        // Lag callback records every successful snapshot it receives.
        let lag_seen: Arc<Mutex<Vec<LagSnapshot>>> = Arc::new(Mutex::new(Vec::new()));
        let lag_seen_cb = Arc::clone(&lag_seen);
        let lag_cb: LagCallback = Arc::new(move |snap| {
            lag_seen_cb.lock().unwrap().push(snap);
        });

        // Latency callback fires on every poll, success or failure.
        let latency_count: Arc<Mutex<usize>> = Arc::new(Mutex::new(0));
        let latency_count_cb = Arc::clone(&latency_count);
        let lat_cb: LatencyCallback = Arc::new(move |_d| {
            *latency_count_cb.lock().unwrap() += 1;
        });

        // Simulate two ticks: the first poll fails (transient error), the
        // second succeeds. Both must invoke the latency callback, only the
        // success must invoke the lag callback, and the helper must not
        // panic on the error path.
        let results: Vec<Result<LagSnapshot, &'static str>> = vec![
            Err("connection reset by peer"),
            Ok(LagSnapshot {
                num_pending: 5,
                num_redelivered: 1,
                ack_floor_stream_seq: 99,
            }),
        ];
        for r in results {
            handle_lag_poll_result(r, Duration::from_millis(3), &lag_cb, Some(&lat_cb));
        }

        assert_eq!(*latency_count.lock().unwrap(), 2);
        let seen = lag_seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].num_pending, 5);
        assert_eq!(seen[0].num_redelivered, 1);
        assert_eq!(seen[0].ack_floor_stream_seq, 99);
    }

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
