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
            .filter(|e| is_fresh(now, e.received_at, self.stale_delay))
            .map(|e| e.message.clone())
            .collect()
    }

    /// Remove stale emergency events older than the stale delay.
    pub async fn sweep(&self) -> usize {
        let mut events = self.events.write().await;
        let before = events.len();
        let now = SystemTime::now();

        events.retain(|_, e| is_fresh(now, e.received_at, self.stale_delay));

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

/// Decide whether a cached emergency received at `received_at` is still
/// fresh relative to `now`.
///
/// Fail-closed on clock skew: if `now < received_at` (NTP step-back or a
/// future-dated `received_at`), `duration_since` errors and we treat the
/// entry as stale (drop it) rather than the old `unwrap_or_default()`
/// behaviour, which mapped the error to a zero elapsed time and let a
/// future-dated event pass the staleness filter forever (SEC-23).
fn is_fresh(now: SystemTime, received_at: SystemTime, stale_delay: Duration) -> bool {
    now.duration_since(received_at)
        .map(|elapsed| elapsed < stale_delay)
        .unwrap_or(false)
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
    #![allow(clippy::panic, clippy::unwrap_used)]
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
            metadata: Metadata::new(SystemTime::now(), "cot".to_string(), MessageType::Alert),
        }
    }

    fn make_position() -> RoutableMessage {
        RoutableMessage {
            source: Identity::new("test".to_string(), "fp".to_string(), BTreeSet::new())
                .expect("valid identity"),
            destination: Destination::Broadcast,
            payload: Bytes::from_static(b"<event type=\"a-f-G\" uid=\"pos1\" />"),
            metadata: Metadata::new(SystemTime::now(), "cot".to_string(), MessageType::Position),
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
    fn is_fresh_drops_future_received_at() {
        // SEC-23: a future `received_at` (clock step-back / corrupted
        // timestamp) must be treated as STALE, not fresh. The old
        // `unwrap_or_default()` mapped the `now < received_at` error to a
        // zero elapsed time, which compared as fresh and let the event
        // pass the staleness filter indefinitely — fail-open.
        let now = SystemTime::now();
        let future = now + Duration::from_secs(3600);
        assert!(
            !is_fresh(now, future, Duration::from_secs(300)),
            "future received_at must be treated as stale"
        );
    }

    #[test]
    fn is_fresh_accepts_recent_and_drops_old() {
        let now = SystemTime::now();
        let recent = now - Duration::from_secs(10);
        let old = now - Duration::from_secs(600);
        assert!(is_fresh(now, recent, Duration::from_secs(300)));
        assert!(!is_fresh(now, old, Duration::from_secs(300)));
    }

    /// SEC-23 end-to-end: an entry whose `received_at` is in the future
    /// must be excluded from `active_events()` and removed by `sweep()`.
    /// We insert directly into the events map to plant the future
    /// timestamp, since `process()` always stamps `SystemTime::now()`.
    #[tokio::test]
    async fn future_dated_emergency_is_excluded_and_swept() {
        let repeater = EmergencyRepeater::new();
        {
            let mut events = repeater.events.write().await;
            let msg = make_alert(
                "future-1",
                r#"<event type="b-a-o-tbl" uid="future-1"><detail><emergency type="911 Alert" /></detail></event>"#,
            );
            let _ = events.insert(
                "future-1".to_string(),
                CachedEmergency {
                    message: msg,
                    received_at: SystemTime::now() + Duration::from_secs(3600),
                },
            );
        }

        let active = repeater.active_events().await;
        assert!(
            active.is_empty(),
            "future-dated emergency must be excluded from active replay"
        );

        let removed = repeater.sweep().await;
        assert_eq!(removed, 1, "future-dated emergency must be swept out");
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

    /// Pins the `Debug + Send + Sync + 'static` bound surface on
    /// `EmergencyRepeater`. It lives inside `Arc<EmergencyRepeater>`
    /// shared between the router's `process()` call site and the
    /// `start_repeat_task`'s background tokio task; any regression to
    /// the three bounds would break `Arc::new(...)` + `tokio::spawn` at
    /// the consumer elsewhere, so pinning at the declaration gives a
    /// crisp failure message at the source of the break.
    #[test]
    fn repeater_implements_debug_send_sync_static() {
        fn assert_bounds<T>()
        where
            T: std::fmt::Debug + Send + Sync + 'static,
        {
        }
        assert_bounds::<EmergencyRepeater>();
    }

    /// Pins the two module-level defaults — both are documented cadence
    /// values (`3` seconds between repeats, `5` minutes before stale).
    /// A regression that silently tightened either would starve
    /// reconnecting clients of replay (too short) or bloat the active
    /// set with long-expired alerts (too long).
    #[test]
    fn default_repeat_interval_and_stale_delay_have_documented_literal_values() {
        assert_eq!(DEFAULT_REPEAT_INTERVAL, Duration::from_secs(3));
        assert_eq!(DEFAULT_STALE_DELAY, Duration::from_secs(300));
    }

    /// Pins that `new()` and `default()` produce repeaters that are
    /// observably identical at the configuration surface (repeat
    /// interval + initial emptiness). A future refactor that forked
    /// one constructor's behaviour from the other would trip here.
    #[tokio::test]
    async fn new_and_default_produce_observably_identical_repeaters() {
        let via_new = EmergencyRepeater::new();
        let via_default = EmergencyRepeater::default();

        assert_eq!(via_new.repeat_interval(), via_default.repeat_interval());
        assert_eq!(via_new.repeat_interval(), DEFAULT_REPEAT_INTERVAL);
        assert!(via_new.is_empty().await);
        assert!(via_default.is_empty().await);
        assert_eq!(via_new.len().await, 0);
        assert_eq!(via_default.len().await, 0);
    }

    /// Pins the `repeat_interval()` accessor round-trip at both the
    /// smallest sensible (1 ms) and largest representable
    /// (`u64::MAX` seconds) boundaries. A regression that clamped or
    /// narrowed the stored value would trip here. The accessor is
    /// load-bearing because `start_repeat_task` reads it once at spawn
    /// time to construct the ticker interval; a silent clamp would
    /// quietly change the re-broadcast cadence in production.
    #[test]
    fn repeat_interval_accessor_round_trips_across_boundary_values() {
        let short =
            EmergencyRepeater::with_intervals(Duration::from_millis(1), Duration::from_secs(300));
        assert_eq!(short.repeat_interval(), Duration::from_millis(1));

        let long = EmergencyRepeater::with_intervals(
            Duration::from_secs(u64::MAX),
            Duration::from_secs(u64::MAX),
        );
        assert_eq!(long.repeat_interval(), Duration::from_secs(u64::MAX));
    }

    /// Pins that `extract_uid` accepts ONLY double-quoted attributes —
    /// single-quoted `uid='...'` is deliberately rejected. Documents
    /// the module's strict-wire-format contract so any future relaxation
    /// (e.g. accepting single quotes) is a visible change that updates
    /// this test and the downstream dedup cache's UID normalization.
    #[test]
    fn extract_uid_rejects_single_quoted_attribute_value() {
        let xml = b"<event type='b-a-o' uid='single-quoted' />";
        assert_eq!(extract_uid(xml), None);
    }

    /// Pins the "space after `<event`" contract in the attribute
    /// parser: `<event>` with no attributes whatsoever returns `None`
    /// because the parser searches for `<event ` (with trailing space)
    /// and a zero-attribute `<event>` has no space. This is the
    /// expected behaviour — a zero-attribute event has nothing to
    /// cache and should not be mistakenly coerced to an empty UID.
    #[test]
    fn extract_uid_returns_none_for_event_tag_without_attributes() {
        let xml = b"<event><detail /></event>";
        assert_eq!(extract_uid(xml), None);
    }

    /// Pins that `is_cancel_event` returns `false` (not a panic) for
    /// non-UTF-8 payloads. CoT payloads should always be UTF-8, but
    /// corrupted, truncated, or maliciously-crafted bytes must not
    /// crash the router — the graceful `std::str::from_utf8` → `false`
    /// path is the documented fail-safe.
    #[test]
    fn is_cancel_returns_false_gracefully_for_non_utf8_payload() {
        let not_utf8: &[u8] = &[0xff, 0xfe, 0xfd, 0x00, 0x80];
        assert!(!is_cancel_event(not_utf8));
    }

    /// Pins the strict-literal match on `cancel="true"` — any other
    /// value (`"false"`, `"TRUE"`, `"1"`, arbitrary text) must NOT
    /// trigger cancel semantics. A regression that loosened this to
    /// case-insensitive or "any non-empty value" matching would allow
    /// an operator typo to silently cancel every active alert.
    #[test]
    fn is_cancel_requires_exact_true_literal_value() {
        let xml_false = br#"<event uid="a1"><detail><emergency cancel="false" /></detail></event>"#;
        let xml_upper = br#"<event uid="a1"><detail><emergency cancel="TRUE" /></detail></event>"#;
        let xml_numeric = br#"<event uid="a1"><detail><emergency cancel="1" /></detail></event>"#;
        assert!(!is_cancel_event(xml_false));
        assert!(!is_cancel_event(xml_upper));
        assert!(!is_cancel_event(xml_numeric));
    }

    /// Pins that `process()` replaces the cached emergency for a given
    /// UID when a second emergency with the same UID arrives. This is
    /// the "emergency update" code path — a moved 911 alert must
    /// replace the previous cached position, not duplicate it or
    /// leave the stale copy behind. `HashMap::insert` semantics
    /// already give us this, but pinning it guards against any future
    /// switch to `entry().or_insert_with(...)` that would silently
    /// keep the stale copy.
    #[tokio::test]
    async fn process_replaces_existing_cached_emergency_for_same_uid() {
        let repeater = EmergencyRepeater::new();

        let initial = make_alert(
            "alert-1",
            r#"<event type="b-a-o-tbl" uid="alert-1"><detail><point lat="0" /></detail></event>"#,
        );
        let updated = make_alert(
            "alert-1",
            r#"<event type="b-a-o-tbl" uid="alert-1"><detail><point lat="42" /></detail></event>"#,
        );

        assert!(repeater.process(&initial).await);
        assert!(repeater.process(&updated).await);
        assert_eq!(
            repeater.len().await,
            1,
            "same-UID re-process must replace, not duplicate"
        );

        let active = repeater.active_events().await;
        assert_eq!(active.len(), 1);
        let payload = std::str::from_utf8(&active[0].payload).unwrap();
        assert!(
            payload.contains(r#"lat="42""#),
            "active event must reflect the UPDATED payload, not the initial one: {payload}"
        );
    }

    /// Pins that `process()` on an alert with no UID attribute returns
    /// `false` and does not cache anything. A malformed alert should
    /// be silently dropped (CoT XML that lacks a UID cannot be
    /// deduped, cancelled, or routed by ID), never coerced to a
    /// synthetic UID that would collide across sources.
    #[tokio::test]
    async fn process_returns_false_for_alert_with_missing_uid_attribute() {
        let repeater = EmergencyRepeater::new();
        let msg = make_alert(
            "ignored",
            r#"<event type="b-a-o-tbl"><detail><emergency type="911" /></detail></event>"#,
        );
        assert!(!repeater.process(&msg).await);
        assert!(repeater.is_empty().await);
    }

    /// Pins that cancelling an unknown UID is a no-op — `process()`
    /// returns `false`, the cache stays empty, and no panic or log-
    /// corruption occurs. This is the common race: the cancel arrives
    /// at this pod before the original alert (e.g., the alert went to
    /// a different pod first and the cancel arrived via federation).
    #[tokio::test]
    async fn cancel_of_unknown_uid_is_a_silent_no_op() {
        let repeater = EmergencyRepeater::new();
        let cancel = make_alert(
            "ghost-uid",
            r#"<event type="b-a-o-tbl" uid="ghost-uid"><detail><emergency cancel="true" /></detail></event>"#,
        );
        assert!(!repeater.process(&cancel).await);
        assert!(repeater.is_empty().await);
        assert_eq!(repeater.len().await, 0);
    }
}
