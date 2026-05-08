// Copyright © 2026 Roberto Chiofalo.

//! In-memory [`crate::bridge::FoundryBridge`] implementation for tests.
//!
//! `MockFoundryBridge` is the reference implementation against which
//! the partner-gated SDK adapter (`foundry-real`) is written. It
//! exercises every code path in the wiring without any network
//! surface:
//!
//! - `upsert_object` deposits the property bag into an in-memory
//!   keyed-by-`(type_id, uid)` map and broadcasts a corresponding
//!   [`crate::bridge::ObjectChange`] on the change channel for that
//!   type.
//! - `subscribe_changes` returns a `BroadcastStream` of changes
//!   filtered to the requested type.
//! - `invoke_action` echoes the request back as an
//!   [`crate::bridge::ActionResult`] so end-to-end tests can drive
//!   the action path.
//! - The `set_offline(true)` knob causes every method to surface
//!   [`crate::error::FoundryError::Offline`] for the offline-replay
//!   test.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use futures::stream::BoxStream;
use parking_lot::Mutex;
use serde_json::Value;
use tokio::sync::broadcast;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::BroadcastStream;

use crate::bridge::{
    ActionRequest, ActionResult, ChangeType, FoundryBridge, ObjectChange, ObjectId,
};
use crate::error::FoundryError;

/// Capacity of the per-type broadcast channel. 256 is large enough
/// that every realistic test scenario fits comfortably; lagged
/// receivers are skipped (the broadcast channel returns
/// `Lagged(_)`) and the inbound wiring task logs and continues.
const CHANNEL_CAPACITY: usize = 256;

/// In-memory mock bridge.
///
/// Cheap to clone — every shared piece of state is wrapped in
/// `Arc`. Individual test scenarios can hold a clone for assertions
/// (the in-memory store survives wiring teardown so the test can
/// inspect what reached the bridge) while another clone is handed
/// to the wiring tasks.
#[derive(Clone)]
pub struct MockFoundryBridge {
    inner: Arc<Inner>,
}

struct Inner {
    /// Keyed by (`type_id`, `uid`) → property bag. The mock derives
    /// `uid` from the bag's `rustgate.uid` field if present,
    /// otherwise from a monotonic counter.
    store: Mutex<HashMap<(String, String), Value>>,
    /// Per-type broadcast channels. Constructed lazily on first
    /// subscriber or first upsert.
    channels: Mutex<HashMap<String, broadcast::Sender<ObjectChange>>>,
    /// Monotonic counter for synthetic UIDs.
    next_id: Mutex<u64>,
    /// Offline kill-switch — flipping to `true` causes every method
    /// to surface `FoundryError::Offline`.
    offline: Mutex<bool>,
}

impl std::fmt::Debug for MockFoundryBridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockFoundryBridge")
            .field("offline", &*self.inner.offline.lock())
            .field("stored_objects", &self.inner.store.lock().len())
            .field("channel_count", &self.inner.channels.lock().len())
            .finish()
    }
}

impl Default for MockFoundryBridge {
    fn default() -> Self {
        Self::new()
    }
}

impl MockFoundryBridge {
    /// Construct a fresh bridge in the online state.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Inner {
                store: Mutex::new(HashMap::new()),
                channels: Mutex::new(HashMap::new()),
                next_id: Mutex::new(0),
                offline: Mutex::new(false),
            }),
        }
    }

    /// Toggle the offline kill-switch. When `true`, every trait
    /// method surfaces [`FoundryError::Offline`]. Used by tests to
    /// drive the offline-replay path in the outbound wiring.
    pub fn set_offline(&self, offline: bool) {
        *self.inner.offline.lock() = offline;
    }

    /// Returns `true` when the bridge is currently in the offline
    /// state.
    pub fn is_offline(&self) -> bool {
        *self.inner.offline.lock()
    }

    /// Inspect the in-memory store snapshot. Used by tests to
    /// assert that an upsert reached the bridge.
    pub fn stored_objects(&self) -> Vec<((String, String), Value)> {
        self.inner
            .store
            .lock()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    /// Number of objects currently in the in-memory store.
    pub fn stored_count(&self) -> usize {
        self.inner.store.lock().len()
    }

    /// Inject a synthetic change-stream event. Used by tests to
    /// drive the inbound wiring's reverse-projection path.
    /// Subscribers that joined before the call observe the change;
    /// the in-memory store is also updated so subsequent
    /// `stored_objects()` queries reflect the injected state.
    pub fn inject_change(&self, change: ObjectChange) {
        if change.change_type == ChangeType::Deleted {
            let _ = self
                .inner
                .store
                .lock()
                .remove(&(change.type_id.clone(), change.object_id.0.clone()));
        } else {
            let _ = self.inner.store.lock().insert(
                (change.type_id.clone(), change.object_id.0.clone()),
                change.properties.clone(),
            );
        }
        let sender = self
            .inner
            .channels
            .lock()
            .entry(change.type_id.clone())
            .or_insert_with(|| broadcast::channel(CHANNEL_CAPACITY).0)
            .clone();
        // Send is best-effort: a `SendError` here means there are
        // no live subscribers, which is fine — the test can sub
        // before injecting.
        let _ = sender.send(change);
    }

    fn synthesize_id(&self, properties: &Value) -> String {
        if let Some(uid) = properties
            .get("rustgate.uid")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
        {
            return uid.to_string();
        }
        let mut counter = self.inner.next_id.lock();
        *counter = counter.saturating_add(1);
        format!("mock-rid-{}", *counter)
    }

    fn channel_for(&self, type_id: &str) -> broadcast::Sender<ObjectChange> {
        self.inner
            .channels
            .lock()
            .entry(type_id.to_string())
            .or_insert_with(|| broadcast::channel(CHANNEL_CAPACITY).0)
            .clone()
    }
}

#[async_trait]
impl FoundryBridge for MockFoundryBridge {
    async fn upsert_object(
        &self,
        type_id: &str,
        properties: Value,
    ) -> Result<ObjectId, FoundryError> {
        if self.is_offline() {
            return Err(FoundryError::Offline {
                reason: "mock bridge marked offline".to_string(),
            });
        }
        let id = self.synthesize_id(&properties);
        let key = (type_id.to_string(), id.clone());
        let existed = self.inner.store.lock().contains_key(&key);
        let _ = self
            .inner
            .store
            .lock()
            .insert(key.clone(), properties.clone());
        let change_type = if existed {
            ChangeType::Updated
        } else {
            ChangeType::Created
        };
        let object_id = ObjectId(id);
        let sender = self.channel_for(type_id);
        let _ = sender.send(ObjectChange {
            type_id: type_id.to_string(),
            object_id: object_id.clone(),
            change_type,
            properties,
        });
        Ok(object_id)
    }

    async fn subscribe_changes(
        &self,
        type_id: &str,
    ) -> Result<BoxStream<'static, ObjectChange>, FoundryError> {
        if self.is_offline() {
            return Err(FoundryError::Offline {
                reason: "mock bridge marked offline".to_string(),
            });
        }
        let sender = self.channel_for(type_id);
        let receiver = sender.subscribe();
        let stream = BroadcastStream::new(receiver).filter_map(|res| res.ok());
        Ok(Box::pin(stream))
    }

    async fn invoke_action(&self, request: ActionRequest) -> Result<ActionResult, FoundryError> {
        if self.is_offline() {
            return Err(FoundryError::Offline {
                reason: "mock bridge marked offline".to_string(),
            });
        }
        Ok(ActionResult {
            committed: true,
            output: request.arguments,
        })
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use futures::StreamExt;
    use serde_json::json;

    use super::*;

    #[tokio::test]
    async fn upsert_emits_create_then_update() {
        let bridge = MockFoundryBridge::new();
        let mut stream = bridge.subscribe_changes("track").await.unwrap();
        let _ = bridge
            .upsert_object("track", json!({"rustgate.uid": "T1"}))
            .await
            .unwrap();
        let first = stream.next().await.unwrap();
        assert_eq!(first.change_type, ChangeType::Created);
        let _ = bridge
            .upsert_object("track", json!({"rustgate.uid": "T1", "speed": 5.0}))
            .await
            .unwrap();
        let second = stream.next().await.unwrap();
        assert_eq!(second.change_type, ChangeType::Updated);
    }

    #[tokio::test]
    async fn offline_kill_switch_surfaces_offline_error() {
        let bridge = MockFoundryBridge::new();
        bridge.set_offline(true);
        let err = bridge
            .upsert_object("track", json!({"rustgate.uid": "T1"}))
            .await
            .unwrap_err();
        assert!(err.is_offline(), "expected Offline, got {err:?}");
    }

    #[tokio::test]
    async fn invoke_action_echoes_arguments() {
        let bridge = MockFoundryBridge::new();
        let req = ActionRequest {
            action_id: "do-thing".to_string(),
            arguments: json!({"a": 1}),
        };
        let res = bridge.invoke_action(req).await.unwrap();
        assert!(res.committed);
        assert_eq!(res.output, json!({"a": 1}));
    }

    #[tokio::test]
    async fn inject_change_drives_subscribers() {
        let bridge = MockFoundryBridge::new();
        let mut stream = bridge.subscribe_changes("track").await.unwrap();
        bridge.inject_change(ObjectChange {
            type_id: "track".to_string(),
            object_id: ObjectId("inj".to_string()),
            change_type: ChangeType::Created,
            properties: json!({"k": "v"}),
        });
        let evt = stream.next().await.unwrap();
        assert_eq!(evt.object_id.0, "inj");
    }
}
