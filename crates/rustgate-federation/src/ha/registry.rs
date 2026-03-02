//! Cross-pod connection registry for federation observability.
//!
//! Tracks active federation connections (both inbound and outbound) across
//! all pods in a multi-pod deployment. Uses NATS JetStream KV for
//! distributed state with TTL-based cleanup.

use std::collections::HashMap;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, watch};
use tracing::{debug, info, warn};

const CONN_BUCKET: &str = "federation-connections";
const CONN_TTL_SECS: u64 = 30;
const CONN_REFRESH_SECS: u64 = 10;

/// Direction of a federation connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    /// We initiated the connection to the remote peer.
    Outbound,
    /// The remote peer connected to us.
    Inbound,
}

impl std::fmt::Display for Direction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Outbound => write!(f, "outbound"),
            Self::Inbound => write!(f, "inbound"),
        }
    }
}

/// Information about an active federation connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionInfo {
    /// The federation peer ID.
    pub peer_id: String,
    /// The pod managing this connection.
    pub pod_id: String,
    /// Whether the connection is inbound or outbound.
    pub direction: Direction,
    /// When the connection was established (Unix timestamp in seconds).
    pub connected_at: u64,
}

/// Aggregated information about a pod's federation connections.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PodInfo {
    /// Pod identifier.
    pub id: String,
    /// Number of outbound connections (claimed peers).
    pub claimed_peers: usize,
    /// Total number of connections (inbound + outbound).
    pub connections: usize,
    /// Most recent connection timestamp (Unix seconds).
    pub last_heartbeat: u64,
}

/// Tracks active federation connections across all pods.
///
/// Each connection is stored as a KV entry with a 30-second TTL.
/// A background refresh loop keeps entries alive by re-putting them.
pub struct ConnectionRegistry {
    kv: async_nats::jetstream::kv::Store,
    pod_id: String,
    registered: Mutex<HashMap<String, ConnectionInfo>>,
    shutdown_tx: watch::Sender<bool>,
    shutdown_rx: watch::Receiver<bool>,
    task_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl std::fmt::Debug for ConnectionRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectionRegistry")
            .field("pod_id", &self.pod_id)
            .finish()
    }
}

impl ConnectionRegistry {
    /// Create a new connection registry.
    ///
    /// Initializes the NATS KV bucket with the configured TTL.
    pub async fn new(jetstream: async_nats::jetstream::Context, pod_id: String) -> Result<Self> {
        let kv = jetstream
            .create_key_value(async_nats::jetstream::kv::Config {
                bucket: CONN_BUCKET.into(),
                max_age: Duration::from_secs(CONN_TTL_SECS),
                ..Default::default()
            })
            .await
            .context("failed to create federation-connections KV bucket")?;

        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        Ok(Self {
            kv,
            pod_id,
            registered: Mutex::new(HashMap::new()),
            shutdown_tx,
            shutdown_rx,
            task_handle: Mutex::new(None),
        })
    }

    /// Start the background refresh loop.
    pub async fn start(&self) {
        let kv = self.kv.clone();
        let registered = {
            let reg = self.registered.lock().await;
            Arc::new(Mutex::new(reg.clone()))
        };
        let mut shutdown_rx = self.shutdown_rx.clone();

        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(CONN_REFRESH_SECS));

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        refresh_registrations(&kv, &registered).await;
                    }
                    _ = shutdown_rx.changed() => {
                        debug!("connection registry refresh loop shutting down");
                        return;
                    }
                }
            }
        });

        let mut task_handle = self.task_handle.lock().await;
        *task_handle = Some(handle);

        info!(pod_id = %self.pod_id, "connection registry started");
    }

    /// Register a federation connection.
    pub async fn register(&self, peer_id: &str, direction: Direction) -> Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let info = ConnectionInfo {
            peer_id: peer_id.to_string(),
            pod_id: self.pod_id.clone(),
            direction,
            connected_at: now,
        };

        let data = serde_json::to_vec(&info).context("failed to serialize connection info")?;
        let key = format!("{}:{}", self.pod_id, peer_id);

        let _ = self
            .kv
            .put(&key, data.into())
            .await
            .context("failed to register connection in KV")?;

        let mut registered = self.registered.lock().await;
        let _ = registered.insert(key, info);

        debug!(
            peer_id = %peer_id,
            direction = %direction,
            pod_id = %self.pod_id,
            "registered federation connection"
        );

        Ok(())
    }

    /// Unregister a federation connection.
    pub async fn unregister(&self, peer_id: &str) -> Result<()> {
        let key = format!("{}:{}", self.pod_id, peer_id);

        let mut registered = self.registered.lock().await;
        let _ = registered.remove(&key);
        drop(registered);

        self.kv
            .delete(&key)
            .await
            .context("failed to unregister connection from KV")?;

        debug!(
            peer_id = %peer_id,
            pod_id = %self.pod_id,
            "unregistered federation connection"
        );

        Ok(())
    }

    /// List all active connections across all pods.
    pub async fn list_connections(&self) -> Result<Vec<ConnectionInfo>> {
        let mut connections = Vec::new();

        let mut keys = Vec::new();
        {
            use futures::StreamExt;
            let mut key_stream = self
                .kv
                .keys()
                .await
                .context("failed to list connection keys")?;
            while let Some(result) = key_stream.next().await {
                if let Ok(key) = result {
                    keys.push(key);
                }
            }
        }

        for key in keys {
            if let Ok(Some(entry)) = self.kv.entry(&key).await {
                if let Ok(info) = serde_json::from_slice::<ConnectionInfo>(&entry.value) {
                    connections.push(info);
                }
            }
        }

        Ok(connections)
    }

    /// Aggregate connections by pod.
    pub async fn list_pods(&self) -> Result<Vec<PodInfo>> {
        let connections = self.list_connections().await?;
        let mut pod_map: HashMap<String, PodInfo> = HashMap::new();

        for conn in connections {
            let pod = pod_map
                .entry(conn.pod_id.clone())
                .or_insert_with(|| PodInfo {
                    id: conn.pod_id.clone(),
                    claimed_peers: 0,
                    connections: 0,
                    last_heartbeat: conn.connected_at,
                });

            pod.connections += 1;
            if conn.direction == Direction::Outbound {
                pod.claimed_peers += 1;
            }
            if conn.connected_at > pod.last_heartbeat {
                pod.last_heartbeat = conn.connected_at;
            }
        }

        Ok(pod_map.into_values().collect())
    }

    /// Gracefully stop the connection registry.
    pub async fn stop(&self) {
        let _ = self.shutdown_tx.send(true);

        // Remove all our registrations
        let registered = self.registered.lock().await;
        for key in registered.keys() {
            if let Err(e) = self.kv.delete(key).await {
                warn!(key = %key, error = %e, "failed to unregister connection on shutdown");
            }
        }
        drop(registered);

        // Stop background task
        let mut handle = self.task_handle.lock().await;
        if let Some(h) = handle.take() {
            h.abort();
        }

        info!(pod_id = %self.pod_id, "connection registry stopped");
    }
}

use std::sync::Arc;

/// Refresh all registered connections by re-putting them to reset TTL.
async fn refresh_registrations(
    kv: &async_nats::jetstream::kv::Store,
    registered: &Mutex<HashMap<String, ConnectionInfo>>,
) {
    let snapshot = {
        let reg = registered.lock().await;
        reg.clone()
    };

    for (key, info) in &snapshot {
        if let Ok(data) = serde_json::to_vec(info) {
            if let Err(e) = kv.put(key, data.into()).await {
                warn!(key = %key, error = %e, "failed to refresh connection registration");
            }
        }
    }
}

#[cfg(test)]
#[allow(unused_results)]
mod tests {
    use super::*;

    #[test]
    fn direction_display() {
        assert_eq!(Direction::Outbound.to_string(), "outbound");
        assert_eq!(Direction::Inbound.to_string(), "inbound");
    }

    #[test]
    fn direction_serde_round_trip() {
        let outbound = Direction::Outbound;
        let json = serde_json::to_string(&outbound).expect("serialize");
        assert_eq!(json, "\"outbound\"");
        let parsed: Direction = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, Direction::Outbound);

        let inbound = Direction::Inbound;
        let json = serde_json::to_string(&inbound).expect("serialize");
        assert_eq!(json, "\"inbound\"");
        let parsed: Direction = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, Direction::Inbound);
    }

    #[test]
    fn connection_info_serde_round_trip() {
        let info = ConnectionInfo {
            peer_id: "peer-1".into(),
            pod_id: "pod-abc".into(),
            direction: Direction::Outbound,
            connected_at: 1700000000,
        };

        let json = serde_json::to_string(&info).expect("serialize");
        let parsed: ConnectionInfo = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.peer_id, "peer-1");
        assert_eq!(parsed.pod_id, "pod-abc");
        assert_eq!(parsed.direction, Direction::Outbound);
        assert_eq!(parsed.connected_at, 1700000000);
    }

    #[test]
    fn pod_info_aggregation_fields() {
        let pod = PodInfo {
            id: "pod-1".into(),
            claimed_peers: 3,
            connections: 5,
            last_heartbeat: 1700000000,
        };

        assert_eq!(pod.id, "pod-1");
        assert_eq!(pod.claimed_peers, 3);
        assert_eq!(pod.connections, 5);
    }

    #[test]
    fn conn_bucket_name() {
        assert_eq!(CONN_BUCKET, "federation-connections");
    }

    #[test]
    fn conn_ttl_exceeds_refresh() {
        let ttl = CONN_TTL_SECS;
        let refresh = CONN_REFRESH_SECS;
        assert!(ttl > refresh, "TTL must exceed refresh interval");
    }
}
