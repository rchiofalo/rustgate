// Copyright © 2026 Roberto Chiofalo.

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
use rustgate_core::egress::{OnFederationForward, OnHttpForward, OnNatsPublish};
use rustgate_core::message::RoutableMessage;
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

rustgate_core::on_callback!(
    /// Callback invoked with the latest [`LagSnapshot`] each poll cycle.
    ///
    /// Wired by the binary crate to publish the values as Prometheus gauges,
    /// keeping `rustgate-nats` agnostic of the metrics backend.
    pub LagCallback,
    LagSnapshot
);

rustgate_core::on_callback!(
    /// Callback invoked with the wall-clock duration of each `consumer.info()`
    /// poll, regardless of success or failure. Wired by the binary crate to
    /// observe a Prometheus histogram so the `rustgate-nats` crate stays free
    /// of metrics dependencies.
    pub LatencyCallback,
    Duration
);

/// Receives messages from NATS via a JetStream pull consumer and delivers
/// them to local sessions.
///
/// Runs as a background task. Creates (or fetches) a JetStream stream
/// capturing `{prefix}.>` subjects, then creates a durable pull consumer
/// for explicit-ACK message delivery with real backpressure.
///
/// The subscriber drives every inbound message through
/// [`Router::route_for_egress`] (not `Router::route`) so any Send-PEP
/// obligations (e.g.
/// [`MaskPoint`](rustgate_transport::rustgate_authz::Obligation::MaskPoint))
/// are applied to the dispatched envelope before the optional
/// federation / HTTP / NATS-publish fan-out callbacks observe it. This
/// closes the second sub-item of #737: a NATS-bridged message arriving
/// locally must reach external sinks (federation peers, webhook /
/// SIEM targets) in the same post-Send-PEP form a directly-connected
/// client would produce. Each forward callback is independent — a
/// `None` field is a no-op and never allocates.
///
/// **Echo prevention.** The subscriber stamps
/// `metadata.source_protocol = "nats"` on the envelope it constructs
/// from each NATS message (see
/// [`WireEvent::into_routable`](crate::WireEvent::into_routable)). The
/// NATS publisher checks that field with a case-insensitive
/// `eq_ignore_ascii_case("nats")` guard and short-circuits, so wiring
/// the optional `nats_publish` callback here cannot form a publish
/// loop — it is included for completeness so every transport that
/// fans out shares the exact same `MqttForwardingHooks`-shaped
/// surface.
pub struct NatsSubscriber {
    client: async_nats::Client,
    config: NatsConfig,
    lag_callback: Option<LagCallback>,
    latency_callback: Option<LatencyCallback>,
    lag_poll_interval: Duration,
    /// Optional NATS-publish forward — fired once per message after
    /// `Router::route_for_egress` returns the post-Send-PEP envelope.
    /// In this transport the publisher's case-insensitive
    /// `source_protocol == "nats"` echo guard short-circuits every
    /// invocation; the field exists so the wiring shape is identical
    /// across MQTT / NATS-subscriber / WebSocket transports.
    nats_publish: Option<OnNatsPublish>,
    /// Optional federation forward — fan-out to peer rustgate
    /// instances over the federation mesh. `None` skips the fan-out at
    /// no runtime cost.
    federation_forward: Option<OnFederationForward>,
    /// Optional HTTP egress forward — fan-out to webhook / SIEM
    /// targets. `None` skips the fan-out at no runtime cost.
    http_forward: Option<OnHttpForward>,
}

impl std::fmt::Debug for NatsSubscriber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let fmt_cb = |present: bool| if present { "Some(<cb>)" } else { "None" };
        f.debug_struct("NatsSubscriber")
            .field("config", &self.config)
            .field("lag_callback", &fmt_cb(self.lag_callback.is_some()))
            .field("latency_callback", &fmt_cb(self.latency_callback.is_some()))
            .field("lag_poll_interval", &self.lag_poll_interval)
            .field("nats_publish", &fmt_cb(self.nats_publish.is_some()))
            .field(
                "federation_forward",
                &fmt_cb(self.federation_forward.is_some()),
            )
            .field("http_forward", &fmt_cb(self.http_forward.is_some()))
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
            nats_publish: None,
            federation_forward: None,
            http_forward: None,
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

    /// Wire an optional NATS-publish forward callback fired after the
    /// router applies any Send-PEP obligations.
    ///
    /// Included for shape parity with the MQTT / WebSocket forwarder
    /// bundles. The publisher's case-insensitive `source_protocol ==
    /// "nats"` echo guard short-circuits every invocation in practice
    /// (see #1192), but the field exists so the binary crate can plug
    /// the same `OnNatsPublish` closure into every transport that
    /// fans out.
    #[must_use]
    pub fn with_nats_publish(mut self, callback: OnNatsPublish) -> Self {
        self.nats_publish = Some(callback);
        self
    }

    /// Wire an optional federation forwarder. Fired once per
    /// successfully-routed inbound NATS message after Send-PEP
    /// obligations have been applied to the dispatched envelope.
    #[must_use]
    pub fn with_federation_forward(mut self, callback: OnFederationForward) -> Self {
        self.federation_forward = Some(callback);
        self
    }

    /// Wire an optional HTTP egress forwarder. Fired once per
    /// successfully-routed inbound NATS message after Send-PEP
    /// obligations have been applied to the dispatched envelope.
    #[must_use]
    pub fn with_http_forward(mut self, callback: OnHttpForward) -> Self {
        self.http_forward = Some(callback);
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
        let (consumer_name, config) = build_consumer_config(&self.config);

        let consumer = stream
            .get_or_create_consumer(&consumer_name, config)
            .await?;
        tracing::info!(
            consumer = %consumer_name,
            max_ack_pending = self.config.max_ack_pending,
            max_deliver = self.config.max_deliver,
            "JetStream pull consumer ready"
        );
        Ok(consumer)
    }

    /// Handle a poison message: emit the structured audit event and,
    /// if `dead_letter_subject` is configured, republish the original
    /// payload there with diagnostic headers.
    ///
    /// The audit emission and the DLQ publish are independent surfaces:
    ///
    /// - The audit event (`nats.poison_dlq`) ALWAYS fires when a drop
    ///   path is taken, regardless of whether the optional DLQ subject
    ///   is wired. Operators get a structured SIEM signal even on
    ///   deployments that never opt in to DLQ. This closes the
    ///   "silent ACK on poison" gap called out in sub-item 3 of #883.
    /// - The DLQ publish is strictly opt-in. The original payload is
    ///   forwarded unchanged so operators can inspect whatever garbage
    ///   arrived. Diagnostic context travels in headers:
    ///
    ///   - `X-Rustgate-DLQ-Reason` — short slug identifying which drop
    ///     path fired (`oversized`, `unparseable`, `unknown-position`,
    ///     `invalid-identity`).
    ///   - `X-Rustgate-DLQ-Original-Subject` — the live-stream subject
    ///     the poison message arrived on, so a forensic viewer can
    ///     tell one group or tenant's garbage from another's.
    ///   - `X-Rustgate-DLQ-Timestamp` — Unix millis at DLQ publish
    ///     time, useful for correlating with other logs when the
    ///     original message has no timestamp of its own.
    ///
    /// **Best-effort DLQ.** A failed DLQ publish is logged at `warn`
    /// but does NOT propagate an error to the caller — the whole point
    /// of DLQ is to unblock the consumer past stuck sequences, so we
    /// never let a transient NATS publish error keep the original
    /// message in the pending set. The audit event has already fired
    /// by the time the publish runs, so SIEM still sees the drop.
    async fn handle_poison_message(
        &self,
        reason: &str,
        original_subject: &str,
        msg_id: &str,
        attempts: u32,
        original_payload: bytes::Bytes,
    ) {
        rustgate_core::audit::nats_poison_message_dlq(original_subject, msg_id, reason, attempts);

        let Some(ref dlq_subject) = self.config.dead_letter_subject else {
            return;
        };

        let mut headers = async_nats::HeaderMap::new();
        headers.insert("X-Rustgate-DLQ-Reason", reason);
        headers.insert("X-Rustgate-DLQ-Original-Subject", original_subject);
        let ts_millis = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let ts_str = ts_millis.to_string();
        headers.insert("X-Rustgate-DLQ-Timestamp", ts_str.as_str());

        if let Err(e) = self
            .client
            .publish_with_headers(dlq_subject.to_string(), headers, original_payload)
            .await
        {
            tracing::warn!(
                dlq_subject = %dlq_subject,
                reason,
                original_subject,
                error = %e,
                "failed to publish to dead-letter subject; original message will still be ACKed"
            );
        }
    }

    /// Run the subscriber loop. This is a long-running future that processes
    /// messages until shutdown or an unrecoverable error.
    ///
    /// Tracks processed and dropped message counts and emits periodic stats
    /// logs (every 60 seconds) for backpressure observability.
    ///
    /// Each successfully decoded inbound message is dispatched through
    /// [`Router::route_for_egress`] so any Send-PEP obligations apply
    /// to the envelope before the optional `nats_publish` /
    /// `federation_forward` / `http_forward` callbacks observe it
    /// (refs #737).
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
                let (msg_id, attempts) = poison_metadata(&msg);
                // Preserve the original payload on the DLQ (if configured)
                // so operators can inspect the oversized garbage — we're
                // about to ACK and lose it from the stream forever. The
                // audit event fires regardless of whether DLQ is wired.
                self.handle_poison_message(
                    "oversized",
                    msg.subject.as_str(),
                    &msg_id,
                    attempts,
                    msg.payload.clone(),
                )
                .await;
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
                        let (msg_id, attempts) = poison_metadata(&msg);
                        // Preserve original bytes on DLQ before ACK — the
                        // point of DLQ is that operators can see exactly
                        // what malformed payload arrived. The audit
                        // event fires regardless of whether DLQ is
                        // wired.
                        self.handle_poison_message(
                            "unparseable",
                            msg.subject.as_str(),
                            &msg_id,
                            attempts,
                            msg.payload.clone(),
                        )
                        .await;
                        // ACK to prevent redelivery of unparseable data
                        if let Err(ack_err) = msg.ack().await {
                            tracing::debug!(error = %ack_err, "failed to ACK unparseable message");
                        }
                        continue;
                    }
                };

                if wire_event.is_position_unknown() {
                    dropped += 1;
                    let (msg_id, attempts) = poison_metadata(&msg);
                    self.handle_poison_message(
                        "unknown-position",
                        msg.subject.as_str(),
                        &msg_id,
                        attempts,
                        msg.payload.clone(),
                    )
                    .await;
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
                        let (msg_id, attempts) = poison_metadata(&msg);
                        self.handle_poison_message(
                            "invalid-identity",
                            msg.subject.as_str(),
                            &msg_id,
                            attempts,
                            msg.payload.clone(),
                        )
                        .await;
                        if let Err(ack_err) = msg.ack().await {
                            tracing::debug!(error = %ack_err, "failed to ACK invalid message");
                        }
                        continue;
                    }
                }
                // _guard dropped here — before the .await below
            };

            // Egress fan-out: drive the message through `route_for_egress`
            // so Send-PEP obligations land on the envelope every external
            // sink observes. A `None` return means the router dropped
            // the message (dedup, TTL expiry, Send-PEP deny, oversize
            // multicast) and every fan-out MUST be skipped to keep the
            // external sinks consistent with the local fanout.
            let routed = router.route_for_egress(routable).instrument(span).await;
            if let Some(routed) = routed.as_ref() {
                fire_forwarding(
                    self.nats_publish.as_ref(),
                    self.federation_forward.as_ref(),
                    self.http_forward.as_ref(),
                    routed,
                );
            }
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

/// Extract a `(msg_id, attempts)` pair from a JetStream message for
/// the [`rustgate_core::audit::nats_poison_message_dlq`] audit event.
///
/// `msg_id` is the JetStream stream sequence rendered as a decimal
/// string when [`async_nats::jetstream::Message::info`] succeeds —
/// this is the canonical correlation token a forensic operator uses
/// to point JetStream's `nats consumer` admin tooling at the exact
/// stuck record. When `info()` fails (a malformed reply subject is
/// the documented failure mode), the audit must still fire so SIEM
/// alerting on `nats.poison_dlq` is not gated by JetStream
/// availability — the helper returns `("unknown", 0)` and the
/// downstream sanitizer guards against the literal `"unknown"` string
/// in case a future caller threads operator-controlled context here.
///
/// `attempts` is the JetStream delivery-attempt count for this stream
/// sequence — the value of `info.delivered` at the moment the
/// subscriber gave up. Saturates at `u32::MAX` for the (effectively
/// impossible) case of a delivered count that overflows `u32`; the
/// signed-to-unsigned cast also clamps the rare case of a JetStream
/// server returning a negative `delivered` value (we have not seen
/// this in practice, but defensive clamping costs one branch per
/// poison drop).
fn poison_metadata(msg: &async_nats::jetstream::Message) -> (String, u32) {
    match msg.info() {
        Ok(info) => {
            let attempts = u32::try_from(info.delivered).unwrap_or(u32::MAX);
            (info.stream_sequence.to_string(), attempts)
        }
        Err(_) => ("unknown".to_string(), 0),
    }
}

/// Fan out the post-Send-PEP routed message to NATS / federation /
/// HTTP egress sinks (refs #737).
///
/// Mirrors the MQTT fan-out helper in `rustgate_mqtt::session` so an
/// inbound NATS message that survives the router's obligations is
/// visible to every external sink in exactly the same way an MQTT
/// PUBLISH would be. Each sink is independent — a `None` field is a
/// no-op and never allocates.
///
/// The publisher's case-insensitive `source_protocol == "nats"` echo
/// guard catches the `nats_publish` callback because every envelope
/// constructed from a NATS-bridged message stamps
/// `metadata.source_protocol = "nats"` in
/// [`WireEvent::into_routable`](crate::WireEvent::into_routable). The
/// `nats_publish` field is therefore safe to wire even though it
/// short-circuits in this transport.
fn fire_forwarding(
    nats_publish: Option<&OnNatsPublish>,
    federation_forward: Option<&OnFederationForward>,
    http_forward: Option<&OnHttpForward>,
    routed: &Arc<RoutableMessage>,
) {
    if let Some(cb) = nats_publish {
        // Echo guard inside the NATS publisher itself short-circuits
        // these calls; we still fire so the wiring shape matches MQTT
        // and a future change to the echo discipline only needs one
        // edit at the publisher.
        cb(routed.as_ref().clone());
    }
    if let Some(fwd) = federation_forward {
        let groups: Vec<String> = routed.source.groups.iter().cloned().collect();
        fwd(routed.payload.clone(), groups, routed.metadata.clone());
    }
    if let Some(fwd) = http_forward {
        fwd(routed.as_ref().clone());
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

/// Build the JetStream pull-consumer config from a `NatsConfig`.
///
/// Extracted from `ensure_consumer` so the wiring from `NatsConfig` fields
/// onto the `pull::Config` struct can be pinned by unit tests without
/// requiring a live NATS server. `ensure_consumer` only adds the server
/// RPC on top of this pure projection.
fn build_consumer_config(config: &NatsConfig) -> (String, jetstream::consumer::pull::Config) {
    let consumer_name = format!("rustgate-sub-{}", config.instance_id);
    // JetStream accepts either `filter_subject` (singular, one pattern) or
    // `filter_subjects` (plural, many) but not both at once. Picking the
    // right wire is driven by `NatsConfig::subject_filters`:
    //
    // - empty  → back-compat `{prefix}.>` wildcard (single pattern)
    // - one    → that exact pattern in `filter_subject`
    // - many   → `filter_subjects` (requires server 2.10+, enabled via the
    //            `server_2_10` feature on the workspace `async-nats` dep)
    let (filter_subject, filter_subjects) = match config.subject_filters.as_slice() {
        [] => (format!("{}.>", config.subject_prefix), Vec::new()),
        [one] => (one.clone(), Vec::new()),
        many => (String::new(), many.to_vec()),
    };
    let pull_config = jetstream::consumer::pull::Config {
        durable_name: Some(consumer_name.clone()),
        ack_policy: AckPolicy::Explicit,
        max_ack_pending: config.max_ack_pending,
        max_deliver: config.max_deliver,
        deliver_policy: jetstream::consumer::DeliverPolicy::New,
        filter_subject,
        filter_subjects,
        ..Default::default()
    };
    (consumer_name, pull_config)
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

    #[test]
    fn build_consumer_config_carries_max_deliver_from_nats_config() {
        // Pin that a positive `max_deliver` in NatsConfig round-trips into
        // the JetStream pull::Config. A regression here silently reopens
        // the poison-message gap called out in #883.
        let nats_config = NatsConfig {
            instance_id: "test-instance".to_string(),
            max_deliver: 5,
            ..Default::default()
        };
        let (name, pull_config) = build_consumer_config(&nats_config);
        assert_eq!(name, "rustgate-sub-test-instance");
        assert_eq!(pull_config.max_deliver, 5);
        // Other fields still plumbed as before.
        assert_eq!(pull_config.max_ack_pending, nats_config.max_ack_pending);
        assert_eq!(pull_config.durable_name, Some(name));
        assert_eq!(
            pull_config.filter_subject,
            format!("{}.>", nats_config.subject_prefix)
        );
    }

    #[test]
    fn build_consumer_config_default_max_deliver_is_workspace_poison_cap() {
        // Default `max_deliver = 5` is the workspace poison-message
        // handling standard (refs #883 sub-item 3). The pull-consumer
        // wiring must round-trip the new default verbatim — anything
        // else silently re-opens the poison-redelivery gap on every
        // fresh deployment.
        let nats_config = NatsConfig {
            instance_id: "test-instance".to_string(),
            ..Default::default()
        };
        assert_eq!(nats_config.max_deliver, 5);
        let (_, pull_config) = build_consumer_config(&nats_config);
        assert_eq!(pull_config.max_deliver, 5);
    }

    #[test]
    fn build_consumer_config_explicit_zero_max_deliver_passes_through() {
        // The legacy-compat opt-in: `max_deliver = 0` is the JetStream
        // wire sentinel for "unlimited redelivery". The pull-consumer
        // wiring must pass it through verbatim so an operator who
        // explicitly opted out of the new default sees the pre-#883
        // semantics.
        let nats_config = NatsConfig {
            instance_id: "test-instance".to_string(),
            max_deliver: 0,
            ..Default::default()
        };
        let (_, pull_config) = build_consumer_config(&nats_config);
        assert_eq!(pull_config.max_deliver, 0);
    }

    #[test]
    fn build_consumer_config_high_max_deliver_round_trips() {
        // Pin that the wiring does not clamp, sign-flip, or otherwise
        // mangle large positive values — the `i64` field is trusted as
        // given, so a silent `min(x, 100)` or similar would be visible here.
        let nats_config = NatsConfig {
            instance_id: "test-instance".to_string(),
            max_deliver: 1_000,
            ..Default::default()
        };
        let (_, pull_config) = build_consumer_config(&nats_config);
        assert_eq!(pull_config.max_deliver, 1_000);
    }

    // ------------------------------------------------------------------
    // `DEFAULT_LAG_POLL_INTERVAL` const — module docs name 5s as the
    // lag-polling cadence, and the binary crate's Prometheus
    // dashboards assume the gauge is refreshed at that rate. A silent
    // bump would skew every dashboard's smoothing window.
    // ------------------------------------------------------------------

    #[test]
    fn default_lag_poll_interval_is_five_seconds() {
        assert_eq!(
            DEFAULT_LAG_POLL_INTERVAL,
            Duration::from_secs(5),
            "DEFAULT_LAG_POLL_INTERVAL must stay 5s — Prometheus dashboards depend on this cadence",
        );
    }

    // ------------------------------------------------------------------
    // `LagSnapshot` type-surface pins — `Copy + Clone + Debug +
    // PartialEq + Eq` is the bound set the binary crate relies on for
    // caching the latest snapshot in atomic slots and comparing
    // before/after values in tests. A refactor that added a non-`Copy`
    // field (e.g. a stream-name `String`) would trip the assertion
    // below rather than at the first cache-store call site.
    // ------------------------------------------------------------------

    #[test]
    fn lag_snapshot_has_copy_clone_debug_eq_bounds() {
        fn assert_bounds<T: Copy + Clone + std::fmt::Debug + PartialEq + Eq>() {}
        assert_bounds::<LagSnapshot>();
    }

    #[test]
    fn lag_snapshot_equality_distinguishes_every_field() {
        let base = LagSnapshot {
            num_pending: 1,
            num_redelivered: 2,
            ack_floor_stream_seq: 3,
        };
        let diff_pending = LagSnapshot {
            num_pending: 99,
            num_redelivered: 2,
            ack_floor_stream_seq: 3,
        };
        let diff_redelivered = LagSnapshot {
            num_pending: 1,
            num_redelivered: 99,
            ack_floor_stream_seq: 3,
        };
        let diff_ack = LagSnapshot {
            num_pending: 1,
            num_redelivered: 2,
            ack_floor_stream_seq: 99,
        };
        assert_eq!(base, base, "identical snapshots must be equal");
        assert_ne!(base, diff_pending, "num_pending delta must flip equality");
        assert_ne!(
            base, diff_redelivered,
            "num_redelivered delta must flip equality",
        );
        assert_ne!(
            base, diff_ack,
            "ack_floor_stream_seq delta must flip equality",
        );
    }

    #[test]
    fn lag_snapshot_debug_exposes_all_three_field_values() {
        let snap = LagSnapshot {
            num_pending: 11,
            num_redelivered: 22,
            ack_floor_stream_seq: 33,
        };
        let rendered = format!("{snap:?}");
        // Operators grep for these field names in log output when
        // triaging backpressure — a custom Debug impl that dropped a
        // field would fail here rather than in a live incident.
        assert!(rendered.contains("num_pending"));
        assert!(rendered.contains("num_redelivered"));
        assert!(rendered.contains("ack_floor_stream_seq"));
        assert!(rendered.contains("11"));
        assert!(rendered.contains("22"));
        assert!(rendered.contains("33"));
    }

    // ------------------------------------------------------------------
    // `LagCallback` / `LatencyCallback` alias bounds — both are
    // cloned into the lag-poll task (which is spawned via
    // `tokio::spawn`), so they must stay `Send + Sync + Clone`. A
    // regression that narrowed either alias from the documented
    // `Arc<dyn Fn(...) + Send + Sync>` pattern would trip here at
    // test-compile rather than at the first spawn site.
    // ------------------------------------------------------------------

    #[test]
    fn callback_aliases_are_send_sync_clone() {
        fn assert_bounds<T: Send + Sync + Clone>() {}
        assert_bounds::<LagCallback>();
        assert_bounds::<LatencyCallback>();
    }

    // ------------------------------------------------------------------
    // `handle_lag_poll_result` callback ordering — on success, the
    // latency histogram MUST fire before the lag gauge so the
    // histogram counts include the current poll. A silent reorder
    // would lag the histogram one tick behind the gauge and hide
    // spike patterns in Grafana.
    // ------------------------------------------------------------------

    #[test]
    fn handle_lag_poll_result_invokes_latency_before_lag_on_success() {
        use std::sync::Mutex;
        let order: Arc<Mutex<Vec<&'static str>>> = Arc::new(Mutex::new(Vec::new()));
        let order_for_lag = Arc::clone(&order);
        let order_for_lat = Arc::clone(&order);
        let lag_cb: LagCallback = Arc::new(move |_snap| {
            order_for_lag.lock().unwrap().push("lag");
        });
        let lat_cb: LatencyCallback = Arc::new(move |_d| {
            order_for_lat.lock().unwrap().push("latency");
        });
        let ok: Result<LagSnapshot, &'static str> = Ok(LagSnapshot {
            num_pending: 0,
            num_redelivered: 0,
            ack_floor_stream_seq: 0,
        });
        handle_lag_poll_result(ok, Duration::from_millis(1), &lag_cb, Some(&lat_cb));
        let calls = order.lock().unwrap();
        assert_eq!(
            *calls,
            vec!["latency", "lag"],
            "latency histogram must fire before lag gauge on success",
        );
    }

    // ------------------------------------------------------------------
    // `handle_lag_poll_result` error path — latency still fires so
    // the histogram includes failed polls (they count against the
    // backend's SLO), but the lag gauge must NOT fire so the gauge
    // retains its last-known-good value instead of decaying to zero
    // on every transient failure.
    // ------------------------------------------------------------------

    #[test]
    fn handle_lag_poll_result_error_fires_latency_but_not_lag() {
        use std::sync::Mutex;
        let lag_count: Arc<Mutex<usize>> = Arc::new(Mutex::new(0));
        let lag_count_cb = Arc::clone(&lag_count);
        let lag_cb: LagCallback = Arc::new(move |_snap| {
            *lag_count_cb.lock().unwrap() += 1;
        });
        let latency_count: Arc<Mutex<usize>> = Arc::new(Mutex::new(0));
        let latency_count_cb = Arc::clone(&latency_count);
        let lat_cb: LatencyCallback = Arc::new(move |_d| {
            *latency_count_cb.lock().unwrap() += 1;
        });
        let err: Result<LagSnapshot, &'static str> = Err("boom");
        handle_lag_poll_result(err, Duration::from_millis(1), &lag_cb, Some(&lat_cb));
        assert_eq!(
            *lag_count.lock().unwrap(),
            0,
            "lag callback must not fire on error",
        );
        assert_eq!(
            *latency_count.lock().unwrap(),
            1,
            "latency callback must fire on every poll, including errors",
        );
    }

    // ------------------------------------------------------------------
    // `handle_lag_poll_result` with `latency_callback = None` — the
    // binary crate may wire only the lag gauge. Helper must still
    // invoke the lag callback on `Ok` without panicking on the
    // absent-histogram branch.
    // ------------------------------------------------------------------

    #[test]
    fn handle_lag_poll_result_without_latency_callback_still_invokes_lag() {
        use std::sync::Mutex;
        let captured: Arc<Mutex<Option<LagSnapshot>>> = Arc::new(Mutex::new(None));
        let captured_cb = Arc::clone(&captured);
        let lag_cb: LagCallback = Arc::new(move |snap| {
            *captured_cb.lock().unwrap() = Some(snap);
        });
        let ok: Result<LagSnapshot, &'static str> = Ok(LagSnapshot {
            num_pending: 77,
            num_redelivered: 3,
            ack_floor_stream_seq: 1_000,
        });
        handle_lag_poll_result(ok, Duration::from_millis(1), &lag_cb, None);
        let snap = captured
            .lock()
            .unwrap()
            .expect("lag callback must have fired");
        assert_eq!(snap.num_pending, 77);
        assert_eq!(snap.num_redelivered, 3);
        assert_eq!(snap.ack_floor_stream_seq, 1_000);
    }

    // ------------------------------------------------------------------
    // `handle_lag_poll_result` duration pass-through — the helper
    // receives `elapsed` already-measured by the caller so the
    // histogram value matches the actual poll duration. A refactor
    // that recomputed elapsed internally (e.g. from `Instant::now()`
    // at entry) would drift from the caller's measurement.
    // ------------------------------------------------------------------

    #[test]
    fn handle_lag_poll_result_passes_elapsed_duration_verbatim() {
        use std::sync::Mutex;
        let seen: Arc<Mutex<Option<Duration>>> = Arc::new(Mutex::new(None));
        let seen_cb = Arc::clone(&seen);
        let lag_cb: LagCallback = Arc::new(|_snap| {});
        let lat_cb: LatencyCallback = Arc::new(move |d| {
            *seen_cb.lock().unwrap() = Some(d);
        });
        let ok: Result<LagSnapshot, &'static str> = Ok(LagSnapshot {
            num_pending: 0,
            num_redelivered: 0,
            ack_floor_stream_seq: 0,
        });
        handle_lag_poll_result(ok, Duration::from_millis(137), &lag_cb, Some(&lat_cb));
        assert_eq!(
            seen.lock()
                .unwrap()
                .expect("latency callback must have fired"),
            Duration::from_millis(137),
            "latency callback must receive the caller-supplied elapsed duration verbatim",
        );
    }

    // ------------------------------------------------------------------
    // `LagPollerGuard` drop-aborts the wrapped task so the lag poller
    // cannot outlive the subscriber. A regression that made Drop a
    // no-op would leak a tokio task per reconnect (and eventually
    // flood tokio's task registry on long-running deployments). The
    // test proves the abort happened by observing the future's Drop
    // side-effect via a shared AtomicBool.
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn lag_poller_guard_aborts_wrapped_task_on_drop() {
        use std::sync::atomic::{AtomicBool, Ordering};

        struct DropProbe(Arc<AtomicBool>);
        impl Drop for DropProbe {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let future_dropped = Arc::new(AtomicBool::new(false));
        let dropped_for_task = Arc::clone(&future_dropped);
        let handle = tokio::spawn(async move {
            let _probe = DropProbe(dropped_for_task);
            std::future::pending::<()>().await;
        });

        // Ensure the task is actually polled and parked on `pending`
        // before we drop the guard.
        tokio::task::yield_now().await;
        assert!(
            !future_dropped.load(Ordering::SeqCst),
            "task future must still be live before guard drop",
        );

        let guard = LagPollerGuard(handle);
        drop(guard);

        // Give the runtime a handful of yields to process the abort
        // and drop the future. Aborted tasks drop their futures.
        for _ in 0..50 {
            tokio::task::yield_now().await;
            if future_dropped.load(Ordering::SeqCst) {
                break;
            }
        }
        assert!(
            future_dropped.load(Ordering::SeqCst),
            "LagPollerGuard::drop must abort the wrapped task (future must be dropped)",
        );
    }

    // ------------------------------------------------------------------
    // `extract_group_from_subject` edge cases — the helper funnels
    // every inbound NATS message into the group-ACL pipeline. Any
    // miscategorisation here silently routes messages under the
    // wrong group (or the fallback group). The existing suite covers
    // the standard cases; these pin the deeper parsing invariants.
    // ------------------------------------------------------------------

    #[test]
    fn extract_group_deep_subject_returns_first_segment_only() {
        // Subjects with four or more segments must still yield only
        // the group token, never the full action tail.
        assert_eq!(
            extract_group_from_subject("points.CYAN.position.update.v2", "points", "__ANON__"),
            "CYAN",
        );
    }

    #[test]
    fn extract_group_subject_equal_to_prefix_returns_default() {
        // Bare prefix with no trailing dot has no group — must fall
        // back to default rather than e.g. returning the prefix.
        assert_eq!(
            extract_group_from_subject("points", "points", "__ANON__"),
            "__ANON__",
        );
    }

    #[test]
    fn extract_group_subject_is_prefix_plus_trailing_dot_returns_default() {
        // `"points."` strips to `""`, which has no interior dot →
        // must fall back to default, not yield an empty group.
        assert_eq!(
            extract_group_from_subject("points.", "points", "__ANON__"),
            "__ANON__",
        );
    }

    #[test]
    fn extract_group_handles_multi_segment_prefix() {
        // The prefix may itself contain dots (e.g. `"cot.live"`). The
        // helper must strip the whole prefix, not just the first
        // segment — otherwise a `"cot.live.BRAVO.update"` subject
        // would mis-route to group `"live"`.
        assert_eq!(
            extract_group_from_subject("cot.live.BRAVO.update", "cot.live", "__ANON__"),
            "BRAVO",
        );
    }

    #[test]
    fn extract_group_rejects_byte_prefix_that_is_not_a_segment() {
        // `"pointsx.GROUP.action"` has `"points"` as a byte prefix
        // but `"pointsx"` is a different segment. The helper's
        // `.strip_prefix('.')` guard must reject this and fall back
        // to default — otherwise any namespace with a common byte
        // prefix (e.g. `tracks` vs `tracks_hist`) would silently
        // leak messages across.
        assert_eq!(
            extract_group_from_subject("pointsx.GROUP.action", "points", "__ANON__"),
            "__ANON__",
        );
    }

    // ------------------------------------------------------------------
    // `build_consumer_config` — the pull-consumer wiring pins we
    // care about beyond the `max_deliver` covered above: ACK
    // policy, deliver policy, durable/consumer-name agreement,
    // multi-segment prefix in `filter_subject`, and idempotence
    // across repeated calls. Any silent drift here reshapes the
    // delivery semantics on the NATS side.
    // ------------------------------------------------------------------

    #[test]
    fn build_consumer_config_sets_ack_policy_explicit() {
        // AckPolicy::Explicit is the whole point — switching to
        // `None` (fire-and-forget) or `All` (ack-all-prior) would
        // silently break at-least-once delivery.
        let nats_config = NatsConfig {
            instance_id: "test-instance".to_string(),
            ..Default::default()
        };
        let (_, pull_config) = build_consumer_config(&nats_config);
        assert!(
            matches!(pull_config.ack_policy, AckPolicy::Explicit),
            "ack_policy must be Explicit so each message is individually acknowledged",
        );
    }

    #[test]
    fn build_consumer_config_sets_deliver_policy_new() {
        // DeliverPolicy::New — a regression to ::All would replay
        // every message ever stored on restart, causing a
        // backpressure storm. ::Last would only deliver the
        // latest. Neither is a valid substitute.
        let nats_config = NatsConfig {
            instance_id: "test-instance".to_string(),
            ..Default::default()
        };
        let (_, pull_config) = build_consumer_config(&nats_config);
        assert!(
            matches!(
                pull_config.deliver_policy,
                jetstream::consumer::DeliverPolicy::New
            ),
            "deliver_policy must be New so the consumer starts from the current stream head",
        );
    }

    #[test]
    fn build_consumer_config_durable_name_matches_returned_consumer_name() {
        // The helper returns the consumer name it intends to use;
        // pull_config.durable_name must match so the caller's
        // `get_or_create_consumer(&name, pull_config)` call sees a
        // self-consistent pair.
        let nats_config = NatsConfig {
            instance_id: "alpha".to_string(),
            ..Default::default()
        };
        let (name, pull_config) = build_consumer_config(&nats_config);
        assert_eq!(name, "rustgate-sub-alpha");
        assert_eq!(
            pull_config.durable_name,
            Some(name),
            "durable_name in pull_config must equal the returned consumer name",
        );
    }

    #[test]
    fn build_consumer_config_filter_subject_handles_multi_segment_prefix() {
        // Embedded-dot prefix `"cot.live"` must produce
        // `"cot.live.>"` verbatim. A refactor that normalised the
        // prefix or quoted the dots would silently change the
        // subscription pattern.
        let nats_config = NatsConfig {
            instance_id: "x".to_string(),
            subject_prefix: "cot.live".to_string(),
            ..Default::default()
        };
        let (_, pull_config) = build_consumer_config(&nats_config);
        assert_eq!(pull_config.filter_subject, "cot.live.>");
    }

    #[test]
    fn build_consumer_config_is_idempotent_across_repeated_calls() {
        // Two successive calls with identical inputs must produce
        // identical outputs. A regression that seeded a non-
        // deterministic field (e.g. a timestamp suffix on the
        // durable name) would break JetStream's
        // `get_or_create_consumer` idempotence and leak a consumer
        // per call.
        let nats_config = NatsConfig {
            instance_id: "alpha".to_string(),
            max_deliver: 7,
            ..Default::default()
        };
        let (n1, c1) = build_consumer_config(&nats_config);
        let (n2, c2) = build_consumer_config(&nats_config);
        assert_eq!(n1, n2);
        assert_eq!(c1.durable_name, c2.durable_name);
        assert_eq!(c1.max_ack_pending, c2.max_ack_pending);
        assert_eq!(c1.max_deliver, c2.max_deliver);
        assert_eq!(c1.filter_subject, c2.filter_subject);
    }

    // ── Subject-filter wiring (issue #907) ─────────────────────────────
    //
    // JetStream forbids setting `filter_subject` and `filter_subjects`
    // on the same consumer — it's an XOR. `build_consumer_config` owns
    // the dispatch between the two wires and must stay deterministic:
    //
    //  empty subject_filters → `filter_subject = "{prefix}.>"`, plural empty
    //  [one]                 → `filter_subject = one`, plural empty
    //  [a, b, ...]           → `filter_subject = ""`, plural carries the vec
    //
    // Each test below pins one arm of that dispatch so a refactor that
    // accidentally double-populates (which NATS rejects at consumer-
    // create time with a non-obvious error) fails here instead.

    #[test]
    fn build_consumer_config_empty_filters_falls_back_to_wildcard() {
        // Back-compat contract: a config that doesn't opt in to
        // `subject_filters` must produce the exact `{prefix}.>` filter
        // that every existing deployment relies on. Plural must stay
        // empty so NATS doesn't reject the consumer for setting both.
        let nats_config = NatsConfig {
            instance_id: "default-filter".to_string(),
            subject_prefix: "points".to_string(),
            subject_filters: Vec::new(),
            ..Default::default()
        };
        let (_, pull_config) = build_consumer_config(&nats_config);
        assert_eq!(pull_config.filter_subject, "points.>");
        assert!(
            pull_config.filter_subjects.is_empty(),
            "filter_subjects must be empty when the singular field is populated",
        );
    }

    #[test]
    fn build_consumer_config_single_filter_uses_singular_field() {
        // A single-entry filter must land in `filter_subject` (not
        // `filter_subjects`) so we stay compatible with NATS servers
        // that don't understand the plural field.
        let nats_config = NatsConfig {
            instance_id: "single".to_string(),
            subject_prefix: "points".to_string(),
            subject_filters: vec!["points.ALPHA.>".to_string()],
            ..Default::default()
        };
        let (_, pull_config) = build_consumer_config(&nats_config);
        assert_eq!(pull_config.filter_subject, "points.ALPHA.>");
        assert!(pull_config.filter_subjects.is_empty());
    }

    #[test]
    fn build_consumer_config_multi_filter_uses_plural_field() {
        // Two or more patterns require `filter_subjects` — and the
        // singular `filter_subject` must be the empty string, not the
        // previous default wildcard. NATS treats a non-empty `filter_
        // subject` alongside a non-empty `filter_subjects` as a config
        // error at consumer-create time.
        let nats_config = NatsConfig {
            instance_id: "multi".to_string(),
            subject_prefix: "points".to_string(),
            subject_filters: vec![
                "points.ALPHA.>".to_string(),
                "points.BRAVO.position".to_string(),
                "points.*.update.v2".to_string(),
            ],
            ..Default::default()
        };
        let (_, pull_config) = build_consumer_config(&nats_config);
        assert_eq!(
            pull_config.filter_subject, "",
            "filter_subject must be empty when filter_subjects is populated",
        );
        assert_eq!(pull_config.filter_subjects.len(), 3);
        assert_eq!(pull_config.filter_subjects[0], "points.ALPHA.>");
        assert_eq!(pull_config.filter_subjects[1], "points.BRAVO.position");
        assert_eq!(pull_config.filter_subjects[2], "points.*.update.v2");
    }

    #[test]
    fn build_consumer_config_filter_subjects_preserves_order() {
        // Downstream observability (consumer info / JetStream admin tooling)
        // displays filter_subjects in insertion order. Shuffling them on the
        // wire would make operator dashboards inconsistent with the config.
        let nats_config = NatsConfig {
            instance_id: "order".to_string(),
            subject_prefix: "points".to_string(),
            subject_filters: vec![
                "points.zulu.>".to_string(),
                "points.alpha.>".to_string(),
                "points.mike.>".to_string(),
            ],
            ..Default::default()
        };
        let (_, pull_config) = build_consumer_config(&nats_config);
        let got: Vec<&str> = pull_config
            .filter_subjects
            .iter()
            .map(String::as_str)
            .collect();
        assert_eq!(
            got,
            vec!["points.zulu.>", "points.alpha.>", "points.mike.>"]
        );
    }

    #[test]
    fn build_consumer_config_single_filter_exact_prefix_wildcard_round_trips() {
        // `subject_filters = ["{prefix}.>"]` is a valid explicit spelling
        // of the default. Must not be rewritten, normalised, or de-duped
        // — operators who opt in this way deserve the exact wire they
        // asked for.
        let nats_config = NatsConfig {
            instance_id: "exact-wildcard".to_string(),
            subject_prefix: "points".to_string(),
            subject_filters: vec!["points.>".to_string()],
            ..Default::default()
        };
        let (_, pull_config) = build_consumer_config(&nats_config);
        assert_eq!(pull_config.filter_subject, "points.>");
        assert!(pull_config.filter_subjects.is_empty());
    }
}
