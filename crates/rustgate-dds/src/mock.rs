// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! In-memory [`crate::bridge::DdsBridge`] implementation for tests.
//!
//! `MockDdsBridge` is the reference implementation against which a
//! real DDS SDK adapter (`dds-real`) is written. It exercises every
//! code path in the wiring without any DDS domain participant:
//!
//! - `subscribe_topic` returns a `BroadcastStream` filtered to the
//!   requested topic. Late-joining subscribers do NOT see prior
//!   samples (matching `Durability::Volatile`); historic replay is
//!   intentionally absent — the real-SDK adapter wires durability
//!   semantics against the underlying SDK's policy bag.
//! - `publish_sample` deposits into an in-memory keyed-by-topic log
//!   (for test inspection) AND broadcasts to every subscriber on
//!   the topic.
//! - `shutdown` flips the bridge into a terminal state — every
//!   subsequent method surfaces
//!   [`crate::error::DdsError::ParticipantUnavailable`] so the
//!   wiring's offline path is exercised end-to-end.
//! - The `set_unavailable(true)` knob is the test-driven equivalent
//!   for transient unavailability without a permanent shutdown.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use futures::stream::BoxStream;
use parking_lot::Mutex;
use tokio::sync::broadcast;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::BroadcastStream;

use crate::bridge::{DdsBridge, DdsSample, QosProfile};
use crate::error::DdsError;

/// Capacity of the per-topic broadcast channel. 256 is large enough
/// that every realistic test scenario fits comfortably; lagged
/// receivers are skipped (the broadcast channel returns
/// `Lagged(_)`) and the inbound wiring task logs and continues.
const CHANNEL_CAPACITY: usize = 256;

/// In-memory mock bridge.
///
/// Cheap to clone — every shared piece of state is wrapped in
/// `Arc`. Individual test scenarios can hold a clone for assertions
/// (the in-memory log survives wiring teardown so the test can
/// inspect what reached the bridge) while another clone is handed
/// to the wiring tasks.
#[derive(Clone)]
pub struct MockDdsBridge {
    inner: Arc<Inner>,
}

struct Inner {
    /// Append-only log of every published sample, keyed by topic.
    /// Tests inspect this to assert that an outbound publish reached
    /// the bridge.
    log: Mutex<HashMap<String, Vec<DdsSample>>>,
    /// Per-topic broadcast channels. Constructed lazily on first
    /// subscriber or first publish.
    channels: Mutex<HashMap<String, broadcast::Sender<DdsSample>>>,
    /// Transient-unavailability kill-switch — flipping to `true`
    /// causes every method to surface `DdsError::ParticipantUnavailable`.
    unavailable: Mutex<bool>,
    /// Permanent-shutdown kill-switch — once set, the bridge is in
    /// the terminal state and only `shutdown()` returns `Ok(())`.
    shutdown: Mutex<bool>,
}

impl std::fmt::Debug for MockDdsBridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockDdsBridge")
            .field("unavailable", &*self.inner.unavailable.lock())
            .field("shutdown", &*self.inner.shutdown.lock())
            .field("topic_count", &self.inner.channels.lock().len())
            .field(
                "logged_samples",
                &self.inner.log.lock().values().map(Vec::len).sum::<usize>(),
            )
            .finish()
    }
}

impl Default for MockDdsBridge {
    fn default() -> Self {
        Self::new()
    }
}

impl MockDdsBridge {
    /// Construct a fresh bridge in the available state.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Inner {
                log: Mutex::new(HashMap::new()),
                channels: Mutex::new(HashMap::new()),
                unavailable: Mutex::new(false),
                shutdown: Mutex::new(false),
            }),
        }
    }

    /// Toggle the transient-unavailable kill-switch. When `true`,
    /// every trait method other than `shutdown` surfaces
    /// [`DdsError::ParticipantUnavailable`]. Used by tests to drive
    /// the offline-replay path in the outbound wiring without
    /// permanently tearing the participant down.
    pub fn set_unavailable(&self, unavailable: bool) {
        *self.inner.unavailable.lock() = unavailable;
    }

    /// Returns `true` when the bridge is currently in the transient-
    /// unavailable state.
    pub fn is_unavailable(&self) -> bool {
        *self.inner.unavailable.lock()
    }

    /// Returns `true` once `shutdown()` has been called.
    pub fn is_shutdown(&self) -> bool {
        *self.inner.shutdown.lock()
    }

    /// Inspect the per-topic publish log. Used by tests to assert
    /// that an outbound publish reached the bridge.
    pub fn published(&self, topic: &str) -> Vec<DdsSample> {
        self.inner
            .log
            .lock()
            .get(topic)
            .cloned()
            .unwrap_or_default()
    }

    /// Total samples logged across every topic.
    pub fn published_count(&self) -> usize {
        self.inner.log.lock().values().map(Vec::len).sum()
    }

    /// Inject a synthetic sample. Used by tests to drive the inbound
    /// wiring's reverse-projection path. Subscribers that joined
    /// before the call observe the sample; the in-memory log is
    /// also updated so subsequent `published()` queries reflect the
    /// injected state.
    pub fn inject_sample(&self, sample: DdsSample) {
        let topic = sample.topic.clone();
        self.inner
            .log
            .lock()
            .entry(topic.clone())
            .or_default()
            .push(sample.clone());
        let sender = self.channel_for(&topic);
        // Send is best-effort: a `SendError` here means there are
        // no live subscribers, which is fine — the test can sub
        // before injecting.
        let _ = sender.send(sample);
    }

    fn channel_for(&self, topic: &str) -> broadcast::Sender<DdsSample> {
        self.inner
            .channels
            .lock()
            .entry(topic.to_string())
            .or_insert_with(|| broadcast::channel(CHANNEL_CAPACITY).0)
            .clone()
    }

    fn check_available(&self) -> Result<(), DdsError> {
        if *self.inner.shutdown.lock() {
            return Err(DdsError::ParticipantUnavailable {
                reason: "mock bridge has been shut down".to_string(),
            });
        }
        if *self.inner.unavailable.lock() {
            return Err(DdsError::ParticipantUnavailable {
                reason: "mock bridge marked unavailable".to_string(),
            });
        }
        Ok(())
    }
}

#[async_trait]
impl DdsBridge for MockDdsBridge {
    async fn subscribe_topic(
        &self,
        topic: &str,
        _qos: QosProfile,
    ) -> Result<BoxStream<'static, DdsSample>, DdsError> {
        self.check_available()?;
        let sender = self.channel_for(topic);
        let receiver = sender.subscribe();
        let stream = BroadcastStream::new(receiver).filter_map(|res| res.ok());
        Ok(Box::pin(stream))
    }

    async fn publish_sample(&self, topic: &str, sample: DdsSample) -> Result<(), DdsError> {
        self.check_available()?;
        // Force the outgoing topic to match the dispatch arg so the
        // wiring can rely on `sample.topic == topic` invariant on
        // the inbound side.
        let mut sample = sample;
        sample.topic = topic.to_string();
        self.inner
            .log
            .lock()
            .entry(topic.to_string())
            .or_default()
            .push(sample.clone());
        let sender = self.channel_for(topic);
        let _ = sender.send(sample);
        Ok(())
    }

    async fn shutdown(&self) -> Result<(), DdsError> {
        *self.inner.shutdown.lock() = true;
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use std::time::SystemTime;

    use bytes::Bytes;
    use futures::StreamExt;

    use super::*;

    fn sample(topic: &str, payload: &[u8]) -> DdsSample {
        DdsSample {
            topic: topic.to_string(),
            source_guid: [1; 16],
            timestamp: SystemTime::UNIX_EPOCH,
            payload: Bytes::copy_from_slice(payload),
        }
    }

    #[tokio::test]
    async fn subscribe_then_publish_reaches_subscriber() {
        let bridge = MockDdsBridge::new();
        let mut stream = bridge
            .subscribe_topic("nav", QosProfile::default())
            .await
            .unwrap();
        bridge
            .publish_sample("nav", sample("nav", b"{}"))
            .await
            .unwrap();
        let evt = stream.next().await.unwrap();
        assert_eq!(evt.topic, "nav");
        assert_eq!(evt.payload.as_ref(), b"{}");
    }

    #[tokio::test]
    async fn publish_log_records_each_call() {
        let bridge = MockDdsBridge::new();
        bridge.publish_sample("a", sample("a", b"1")).await.unwrap();
        bridge.publish_sample("a", sample("a", b"2")).await.unwrap();
        bridge.publish_sample("b", sample("b", b"x")).await.unwrap();
        assert_eq!(bridge.published_count(), 3);
        assert_eq!(bridge.published("a").len(), 2);
        assert_eq!(bridge.published("b").len(), 1);
    }

    #[tokio::test]
    async fn unavailable_kill_switch_surfaces_typed_error() {
        let bridge = MockDdsBridge::new();
        bridge.set_unavailable(true);
        let err = bridge
            .publish_sample("nav", sample("nav", b"{}"))
            .await
            .unwrap_err();
        assert!(
            err.is_participant_unavailable(),
            "expected ParticipantUnavailable, got {err:?}"
        );
    }

    #[tokio::test]
    async fn shutdown_prevents_subsequent_publishes() {
        let bridge = MockDdsBridge::new();
        bridge.shutdown().await.unwrap();
        let err = bridge
            .publish_sample("nav", sample("nav", b"{}"))
            .await
            .unwrap_err();
        assert!(err.is_participant_unavailable());
        assert!(bridge.is_shutdown());
    }

    #[tokio::test]
    async fn publish_overwrites_topic_to_dispatch_arg() {
        // The mock should preserve the invariant that the sample's
        // topic always matches the dispatch arg — this is what the
        // inbound wiring relies on to demux samples per topic.
        let bridge = MockDdsBridge::new();
        let mut s = sample("wrong", b"{}");
        s.topic = "ignored".into();
        bridge.publish_sample("right", s).await.unwrap();
        let logged = bridge.published("right");
        assert_eq!(logged.len(), 1);
        assert_eq!(logged[0].topic, "right");
    }

    #[tokio::test]
    async fn inject_sample_drives_subscribers() {
        let bridge = MockDdsBridge::new();
        let mut stream = bridge
            .subscribe_topic("nav", QosProfile::default())
            .await
            .unwrap();
        bridge.inject_sample(sample("nav", b"hi"));
        let evt = stream.next().await.unwrap();
        assert_eq!(evt.payload.as_ref(), b"hi");
    }

    #[tokio::test]
    async fn shutdown_is_idempotent() {
        let bridge = MockDdsBridge::new();
        bridge.shutdown().await.unwrap();
        bridge.shutdown().await.unwrap();
        bridge.shutdown().await.unwrap();
        assert!(bridge.is_shutdown());
    }
}
