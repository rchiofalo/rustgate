// Copyright © 2026 Roberto Chiofalo.

//! Emergency event repeater.
//!
//! Caches active emergency/alert events and re-broadcasts them at a
//! configurable interval. New clients receive all active emergencies
//! on connect (similar to position cache replay).
//!
//! Emergencies are cancelled when a matching cancel event is received,
//! identified by the same UID with `cancel="true"` in the detail.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use rustgate_core::message::{MessageType, RoutableMessage};
use tokio::sync::RwLock;

/// Default re-broadcast interval for active emergencies.
const DEFAULT_REPEAT_INTERVAL: Duration = Duration::from_secs(3);

/// Default time after which an unrepeated emergency becomes stale.
const DEFAULT_STALE_DELAY: Duration = Duration::from_secs(300);

/// Caches active emergency events for re-broadcast and replay.
#[derive(Debug)]
pub struct EmergencyRepeater {
    events: RwLock<HashMap<String, CachedEmergency>>,
    repeat_interval: Duration,
    stale_delay: Duration,
}

#[derive(Debug, Clone)]
struct CachedEmergency {
    message: RoutableMessage,
    received_at: SystemTime,
}

impl Default for EmergencyRepeater {
    fn default() -> Self {
        Self {
            events: RwLock::new(HashMap::new()),
            repeat_interval: DEFAULT_REPEAT_INTERVAL,
            stale_delay: DEFAULT_STALE_DELAY,
        }
    }
}

impl EmergencyRepeater {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a repeater with custom intervals.
    pub fn with_intervals(repeat_interval: Duration, stale_delay: Duration) -> Self {
        Self {
            events: RwLock::new(HashMap::new()),
            repeat_interval,
            stale_delay,
        }
    }

    /// The configured repeat interval.
    pub fn repeat_interval(&self) -> Duration {
        self.repeat_interval
    }

    /// Process an incoming message — cache if emergency, remove if cancel.
    ///
    /// Returns `true` if this message is an emergency that was cached.
    pub async fn process(&self, msg: &RoutableMessage) -> bool {
        if msg.metadata.message_type != MessageType::Alert {
            return false;
        }

        let uid = extract_uid(&msg.payload);
        let Some(uid) = uid else { return false };

        if is_cancel_event(&msg.payload) {
            let mut events = self.events.write().await;
            let removed = events.remove(uid).is_some();
            if removed {
                tracing::info!(uid = %uid, "emergency cancelled");
            }
            return false;
        }

        let mut events = self.events.write().await;
        let _ = events.insert(
            uid.to_string(),
            CachedEmergency {
                message: msg.clone(),
                received_at: SystemTime::now(),
            },
        );
        tracing::info!(uid = %uid, source = %msg.source.cn, "emergency cached for repeat");
        true
    }

    /// Get all active (non-stale) emergency events for replay.
    pub async fn active_events(&self) -> Vec<RoutableMessage> {
        let events = self.events.read().await;
        let now = SystemTime::now();

        events
            .values()
            .filter(|e| now.duration_since(e.received_at).unwrap_or_default() < self.stale_delay)
            .map(|e| e.message.clone())
            .collect()
    }

    /// Remove stale emergency events older than the stale delay.
    pub async fn sweep(&self) -> usize {
        let mut events = self.events.write().await;
        let before = events.len();
        let now = SystemTime::now();

        events.retain(|_, e| {
            now.duration_since(e.received_at).unwrap_or_default() < self.stale_delay
        });

        before - events.len()
    }

    /// Number of active cached emergencies.
    pub async fn len(&self) -> usize {
        self.events.read().await.len()
    }

    /// Check if no emergencies are cached.
    pub async fn is_empty(&self) -> bool {
        self.events.read().await.is_empty()
    }

    /// Spawn a background re-broadcast task.
    ///
    /// Sends all active emergencies to the provided sender at the
    /// configured repeat interval. The task runs until shutdown.
    pub fn start_repeat_task(
        self: &Arc<Self>,
        sender: tokio::sync::mpsc::Sender<Arc<RoutableMessage>>,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> tokio::task::JoinHandle<()> {
        let repeater = Arc::clone(self);
        let interval = self.repeat_interval;

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            // Skip first immediate tick
            let _ = ticker.tick().await;

            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        let events = repeater.active_events().await;
                        for msg in events {
                            if sender.send(Arc::new(msg)).await.is_err() {
                                break;
                            }
                        }
                        // Sweep stale entries
                        let removed = repeater.sweep().await;
                        if removed > 0 {
                            tracing::debug!(removed, "emergency repeater sweep");
                        }
                    }
                    _ = shutdown.changed() => {
                        break;
                    }
                }
            }
        })
    }
}

/// Extract the `uid` attribute from a CoT `<event>` element.
fn extract_uid(payload: &[u8]) -> Option<&str> {
    let text = std::str::from_utf8(payload).ok()?;
    let event_start = text.find("<event ")?;
    let event_end = text[event_start..].find('>')? + event_start;
    let event_tag = &text[event_start..event_end];

    let uid_start = event_tag.find("uid=\"")? + 5;
    let uid_end = event_tag[uid_start..].find('"')? + uid_start;
    Some(&event_tag[uid_start..uid_end])
}

/// Check if a CoT event is an emergency cancel.
///
/// Looks for `cancel="true"` in the `<emergency>` detail element.
fn is_cancel_event(payload: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(payload) else {
        return false;
    };
    text.contains("cancel=\"true\"") || text.contains("cancel='true'")
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use bytes::Bytes;
    use rustgate_core::identity::Identity;
    use rustgate_core::message::{Destination, Metadata};

    use super::*;

    fn make_alert(_uid: &str, payload: &str) -> RoutableMessage {
        RoutableMessage {
            source: Identity::new("test".to_string(), "fp".to_string(), BTreeSet::new())
                .expect("valid identity"),
            destination: Destination::Broadcast,
            payload: Bytes::from(payload.to_string()),
            metadata: Metadata {
                received_at: SystemTime::now(),
                source_protocol: "cot".to_string(),
                message_type: MessageType::Alert,
                ttl: None,
            },
        }
    }

    fn make_position() -> RoutableMessage {
        RoutableMessage {
            source: Identity::new("test".to_string(), "fp".to_string(), BTreeSet::new())
                .expect("valid identity"),
            destination: Destination::Broadcast,
            payload: Bytes::from_static(b"<event type=\"a-f-G\" uid=\"pos1\" />"),
            metadata: Metadata {
                received_at: SystemTime::now(),
                source_protocol: "cot".to_string(),
                message_type: MessageType::Position,
                ttl: None,
            },
        }
    }

    #[tokio::test]
    async fn cache_emergency_event() {
        let repeater = EmergencyRepeater::new();
        let msg = make_alert(
            "alert-1",
            r#"<event type="b-a-o-tbl" uid="alert-1"><detail><emergency type="911 Alert" /></detail></event>"#,
        );

        assert!(repeater.process(&msg).await);
        assert_eq!(repeater.len().await, 1);

        let active = repeater.active_events().await;
        assert_eq!(active.len(), 1);
    }

    #[tokio::test]
    async fn cancel_removes_emergency() {
        let repeater = EmergencyRepeater::new();
        let msg = make_alert(
            "alert-1",
            r#"<event type="b-a-o-tbl" uid="alert-1"><detail><emergency type="911 Alert" /></detail></event>"#,
        );
        assert!(repeater.process(&msg).await);
        assert_eq!(repeater.len().await, 1);

        let cancel = make_alert(
            "alert-1",
            r#"<event type="b-a-o-tbl" uid="alert-1"><detail><emergency type="911 Alert" cancel="true" /></detail></event>"#,
        );
        assert!(!repeater.process(&cancel).await);
        assert_eq!(repeater.len().await, 0);
    }

    #[tokio::test]
    async fn ignores_non_alert_messages() {
        let repeater = EmergencyRepeater::new();
        let msg = make_position();
        assert!(!repeater.process(&msg).await);
        assert!(repeater.is_empty().await);
    }

    #[tokio::test]
    async fn stale_events_excluded() {
        let repeater = EmergencyRepeater::with_intervals(
            Duration::from_secs(1),
            Duration::from_millis(1), // 1ms stale delay
        );

        let msg = make_alert(
            "alert-1",
            r#"<event type="b-a-o-tbl" uid="alert-1"><detail><emergency type="911 Alert" /></detail></event>"#,
        );
        assert!(repeater.process(&msg).await);

        // Wait for stale delay
        tokio::time::sleep(Duration::from_millis(10)).await;

        let active = repeater.active_events().await;
        assert!(active.is_empty(), "stale events should be excluded");
    }

    #[tokio::test]
    async fn sweep_removes_stale() {
        let repeater =
            EmergencyRepeater::with_intervals(Duration::from_secs(1), Duration::from_millis(1));

        let msg = make_alert(
            "alert-1",
            r#"<event type="b-a-o-tbl" uid="alert-1"><detail><emergency type="911 Alert" /></detail></event>"#,
        );
        assert!(repeater.process(&msg).await);
        tokio::time::sleep(Duration::from_millis(10)).await;

        let removed = repeater.sweep().await;
        assert_eq!(removed, 1);
        assert!(repeater.is_empty().await);
    }

    #[test]
    fn extract_uid_works() {
        let xml = br#"<event type="b-a-o" uid="emergency-123"><detail /></event>"#;
        assert_eq!(extract_uid(xml), Some("emergency-123"));
    }

    #[test]
    fn extract_uid_missing() {
        assert_eq!(extract_uid(b"not xml"), None);
    }

    #[test]
    fn is_cancel_detects_cancel() {
        let xml = br#"<event uid="a1"><detail><emergency cancel="true" /></detail></event>"#;
        assert!(is_cancel_event(xml));
    }

    #[test]
    fn is_cancel_normal_event() {
        let xml = br#"<event uid="a1"><detail><emergency type="911" /></detail></event>"#;
        assert!(!is_cancel_event(xml));
    }
}
