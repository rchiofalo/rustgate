//! Latest-state cache for position reports.
//!
//! TAK clients expect to receive the current situational awareness (SA)
//! picture on connect. This cache stores the most recent position CoT
//! event per CN and replays them to newly connected sessions.

use std::collections::HashMap;

use tokio::sync::RwLock;

use rustgate_core::message::RoutableMessage;

/// Stores the most recent position report per client CN.
#[derive(Debug, Default)]
pub struct PositionCache {
    entries: RwLock<HashMap<String, RoutableMessage>>,
}

impl PositionCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Store a position report, replacing any previous entry for this CN.
    pub async fn store(&self, msg: RoutableMessage) {
        let cn = msg.source.cn.clone();
        let mut entries = self.entries.write().await;
        let _ = entries.insert(cn, msg);
    }

    /// Get all cached position reports for replay to a new session.
    pub async fn get_all(&self) -> Vec<RoutableMessage> {
        let entries = self.entries.read().await;
        entries.values().cloned().collect()
    }

    /// Remove the cached position for a CN (e.g., on disconnect).
    pub async fn remove(&self, cn: &str) {
        let mut entries = self.entries.write().await;
        let _ = entries.remove(cn);
    }

    /// Number of cached positions.
    pub async fn len(&self) -> usize {
        self.entries.read().await.len()
    }

    /// Check if cache is empty.
    pub async fn is_empty(&self) -> bool {
        self.entries.read().await.is_empty()
    }
}
