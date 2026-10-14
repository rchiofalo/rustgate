// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Cross-pod connection registry for federation observability.
//!
//! Tracks active federation connections (both inbound and outbound) across
//! all pods in a multi-pod deployment. Uses NATS JetStream KV for
//! distributed state with TTL-based cleanup.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use rustgate_core::masking::hash_cn;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, watch};
use tracing::{debug, info, warn};

use crate::error::{FederationError, Result};

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
    pub peer_id: rustgate_core::PeerId,
    /// The pod managing this connection.
    pub pod_id: String,
    /// Whether the connection is inbound or outbound.
    pub direction: Direction,
    /// When the connection was established (Unix timestamp in seconds).
    pub connected_at: u64,
    /// Fencing token (NATS KV claim revision) for split-brain detection.
    ///
    /// A monotonically increasing integer tied to the peer ownership claim.
    /// Pods must hold a current fencing token to operate on a peer. `None`
    /// for pods running older versions without fencing support, or for
    /// inbound connections (which are not claimed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fencing_token: Option<u64>,
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
    // Single source of truth for registration state, shared with the
    // background refresh task via `Arc` clone. Registrations added after
    // `start()` via `register` are refreshed because both sides lock the same
    // `Arc<Mutex<..>>` — see issue #1494.
    registered: Arc<Mutex<HashMap<String, ConnectionInfo>>>,
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
            .map_err(|e| {
                FederationError::storage(format!(
                    "failed to create federation-connections KV bucket: {e}"
                ))
            })?;

        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        Ok(Self {
            kv,
            pod_id,
            registered: Arc::new(Mutex::new(HashMap::new())),
            shutdown_tx,
            shutdown_rx,
            task_handle: Mutex::new(None),
        })
    }

    /// Start the background refresh loop.
    pub async fn start(&self) {
        // Share the SAME `Arc<Mutex<..>>` as `self.registered` so
        // registrations added after `start()` via `register` are refreshed
        // (issue #1494). A cloned snapshot would freeze the refresh set at
        // start time and let later registrations' TTL expire.
        let kv = self.kv.clone();
        let registered = self.registered.clone();
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
    ///
    /// The `fencing_token` is the NATS KV claim revision for outbound
    /// connections. Pass `None` for inbound connections or when HA is
    /// not active.
    ///
    /// F-113: takes a typed [`rustgate_core::PeerId`] reference. The
    /// derived KV key (`{pod_id}.{peer_id}`) and the JSON payload's
    /// `peer_id` field stay byte-identical to the pre-typed version
    /// because the underlying string is unchanged.
    pub async fn register(
        &self,
        peer_id: &rustgate_core::PeerId,
        direction: Direction,
        fencing_token: Option<u64>,
    ) -> Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let info = ConnectionInfo {
            peer_id: peer_id.clone(),
            pod_id: self.pod_id.clone(),
            direction,
            connected_at: now,
            fencing_token,
        };

        let data = serde_json::to_vec(&info)
            .map_err(|e| FederationError::serde("failed to serialize connection info", e))?;
        let key = format!("{}.{}", self.pod_id, peer_id.as_str());

        let _ = self.kv.put(&key, data.into()).await.map_err(|e| {
            FederationError::storage(format!("failed to register connection in KV: {e}"))
        })?;

        let mut registered = self.registered.lock().await;
        let _ = registered.insert(key, info);

        debug!(
            peer_id = %hash_cn(peer_id.as_str()),
            direction = %direction,
            pod_id = %self.pod_id,
            "registered federation connection"
        );

        Ok(())
    }

    /// Unregister a federation connection.
    ///
    /// F-113: takes a typed [`rustgate_core::PeerId`] reference; the KV
    /// key derivation is unchanged.
    pub async fn unregister(&self, peer_id: &rustgate_core::PeerId) -> Result<()> {
        let key = format!("{}.{}", self.pod_id, peer_id.as_str());

        let mut registered = self.registered.lock().await;
        let _ = registered.remove(&key);
        drop(registered);

        self.kv.delete(&key).await.map_err(|e| {
            FederationError::storage(format!("failed to unregister connection from KV: {e}"))
        })?;

        debug!(
            peer_id = %hash_cn(peer_id.as_str()),
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
            let mut key_stream = self.kv.keys().await.map_err(|e| {
                FederationError::storage(format!("failed to list connection keys: {e}"))
            })?;
            while let Some(result) = key_stream.next().await {
                if let Ok(key) = result {
                    keys.push(key);
                }
            }
        }

        for key in keys {
            if let Ok(Some(entry)) = self.kv.entry(&key).await
                && let Ok(info) = serde_json::from_slice::<ConnectionInfo>(&entry.value)
            {
                connections.push(info);
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
        if let Ok(data) = serde_json::to_vec(info)
            && let Err(e) = kv.put(key, data.into()).await
        {
            warn!(key = %key, error = %e, "failed to refresh connection registration");
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
            peer_id: rustgate_core::PeerId::new("peer-1"),
            pod_id: "pod-abc".into(),
            direction: Direction::Outbound,
            connected_at: 1700000000,
            fencing_token: Some(42),
        };

        let json = serde_json::to_string(&info).expect("serialize");
        let parsed: ConnectionInfo = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.peer_id.as_str(), "peer-1");
        assert_eq!(parsed.pod_id, "pod-abc");
        assert_eq!(parsed.direction, Direction::Outbound);
        assert_eq!(parsed.connected_at, 1700000000);
        assert_eq!(parsed.fencing_token, Some(42));
    }

    #[test]
    fn connection_info_serde_without_fencing_token() {
        // Old pods don't include fencing_token — deserialize should default to None
        let json = r#"{"peer_id":"peer-1","pod_id":"pod-abc","direction":"outbound","connected_at":1700000000}"#;
        let parsed: ConnectionInfo = serde_json::from_str(json).expect("deserialize");
        assert_eq!(parsed.fencing_token, None);
    }

    #[test]
    fn connection_info_no_fencing_token_omits_field() {
        // When fencing_token is None, it should not appear in serialized JSON
        let info = ConnectionInfo {
            peer_id: rustgate_core::PeerId::new("peer-1"),
            pod_id: "pod-abc".into(),
            direction: Direction::Outbound,
            connected_at: 1700000000,
            fencing_token: None,
        };

        let json = serde_json::to_string(&info).expect("serialize");
        assert!(
            !json.contains("fencing_token"),
            "None fencing_token should be omitted from JSON"
        );
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

    /// Pins the full trait-bound surface on `Direction`. `Copy` is
    /// load-bearing because every hot-path comparison in `list_pods`
    /// (`if conn.direction == Direction::Outbound`) relies on by-value
    /// copying instead of references. `Send + Sync + 'static` are
    /// load-bearing because `ConnectionInfo` (which owns a `Direction`)
    /// is shipped across the `refresh_registrations` background task.
    #[test]
    fn direction_implements_copy_clone_partial_eq_debug_send_sync_static() {
        fn assert_bounds<T>()
        where
            T: Copy + Clone + PartialEq + Eq + std::fmt::Debug + Send + Sync + 'static,
        {
        }
        assert_bounds::<Direction>();
    }

    /// Pins the wire contract for unknown variant rejection. `Direction`
    /// is serialized `rename_all = "lowercase"` so the canonical wire
    /// tokens are `"outbound"` and `"inbound"`; any other casing or
    /// unknown value MUST fail deserialization (if a future peer running
    /// an older version emitted `"Outbound"`, we want a crisp parse
    /// error, not a silent coerce to a default variant).
    #[test]
    fn direction_serde_rejects_capital_case_and_unknown_variants() {
        for hostile in [
            "\"Outbound\"",
            "\"OUTBOUND\"",
            "\"Inbound\"",
            "\"INBOUND\"",
            "\"outbound \"", // trailing space
            "\" outbound\"", // leading space
            "\"wizard\"",
            "\"\"",
            "\"both\"",
            "\"none\"",
        ] {
            let result: std::result::Result<Direction, _> = serde_json::from_str(hostile);
            assert!(
                result.is_err(),
                "expected serde rejection of hostile Direction wire value {hostile}, got Ok"
            );
        }
    }

    /// Pins the `Clone + Debug + Send + Sync + 'static` bound surface on
    /// `ConnectionInfo`. It lives inside `Arc<Mutex<HashMap<…,
    /// ConnectionInfo>>>` in the refresh task, so a regression that
    /// removed `Send` or `Sync` would break the `tokio::spawn` at
    /// compile time elsewhere — pinning here gives a crisp error.
    #[test]
    fn connection_info_implements_clone_debug_send_sync_static() {
        fn assert_bounds<T>()
        where
            T: Clone + std::fmt::Debug + Send + Sync + 'static,
        {
        }
        assert_bounds::<ConnectionInfo>();
    }

    /// Pins forward-compatibility: `ConnectionInfo` deserialization must
    /// tolerate unknown fields from newer pods (serde's default when
    /// `deny_unknown_fields` is absent). A regression that added
    /// `#[serde(deny_unknown_fields)]` would silently break every
    /// cross-version upgrade in a rolling deployment.
    #[test]
    fn connection_info_deserialize_tolerates_unknown_fields_from_newer_pods() {
        let forward_compat_json = r#"{
            "peer_id": "peer-future",
            "pod_id": "pod-future",
            "direction": "outbound",
            "connected_at": 1700000000,
            "fencing_token": 42,
            "future_field_added_in_v3": "ignored",
            "another_unknown": 99
        }"#;
        let parsed: ConnectionInfo =
            serde_json::from_str(forward_compat_json).expect("unknown fields must be tolerated");
        assert_eq!(parsed.peer_id.as_str(), "peer-future");
        assert_eq!(parsed.pod_id, "pod-future");
        assert_eq!(parsed.fencing_token, Some(42));
    }

    /// Pins that `fencing_token: Some(0)` is NOT omitted from the wire
    /// shape — the `skip_serializing_if = "Option::is_none"` attribute
    /// must only trigger on `None`, not on `Some(0)`. A regression that
    /// swapped the predicate for `Option::is_none_or(|x| *x == 0)` would
    /// silently drop the first revision of a fencing claim (revision 0
    /// is the zero-indexed first NATS KV put) and cause every initial
    /// claim to look unfenced to the split-brain detector.
    #[test]
    fn connection_info_fencing_token_zero_is_serialized_not_omitted() {
        let info = ConnectionInfo {
            peer_id: rustgate_core::PeerId::new("peer-1"),
            pod_id: "pod-abc".into(),
            direction: Direction::Outbound,
            connected_at: 1700000000,
            fencing_token: Some(0),
        };
        let json = serde_json::to_string(&info).expect("serialize");
        assert!(
            json.contains("\"fencing_token\":0"),
            "Some(0) fencing_token must be serialized, got: {json}"
        );
    }

    /// Pins round-trip at the `u64::MAX` boundary. Fencing tokens come
    /// from NATS KV revision numbers which grow monotonically over the
    /// life of a KV bucket; pinning the boundary guards against any
    /// future narrowing refactor (e.g. swapping `u64` for `u32` to save
    /// 4 bytes) that would silently truncate large revisions.
    #[test]
    fn connection_info_fencing_token_roundtrips_at_u64_max_boundary() {
        let info = ConnectionInfo {
            peer_id: rustgate_core::PeerId::new("peer-1"),
            pod_id: "pod-abc".into(),
            direction: Direction::Outbound,
            connected_at: u64::MAX,
            fencing_token: Some(u64::MAX),
        };
        let json = serde_json::to_string(&info).expect("serialize");
        let parsed: ConnectionInfo = serde_json::from_str(&json).expect("deserialize at u64::MAX");
        assert_eq!(parsed.fencing_token, Some(u64::MAX));
        assert_eq!(parsed.connected_at, u64::MAX);
    }

    /// Pins the `PodInfo` JSON wire shape: all four documented fields
    /// (`id`, `claimed_peers`, `connections`, `last_heartbeat`) must
    /// appear in the serialized output. An operator REST dashboard
    /// keyed off these exact field names would break silently if a
    /// refactor renamed any of them.
    #[test]
    fn pod_info_json_shape_contains_all_documented_fields() {
        let pod = PodInfo {
            id: "pod-1".into(),
            claimed_peers: 3,
            connections: 5,
            last_heartbeat: 1700000000,
        };
        let json = serde_json::to_string(&pod).expect("serialize");
        for expected in [
            "\"id\":\"pod-1\"",
            "\"claimed_peers\":3",
            "\"connections\":5",
            "\"last_heartbeat\":1700000000",
        ] {
            assert!(
                json.contains(expected),
                "PodInfo JSON missing documented field token `{expected}`: {json}"
            );
        }
    }

    /// Pins the `Clone + Debug + Send + Sync + 'static` bound set on
    /// `PodInfo` — the pod registry's `list_pods()` returns `Vec<PodInfo>`
    /// across the tokio runtime boundary and the REST API layer clones
    /// pod snapshots for Prometheus export.
    #[test]
    fn pod_info_implements_clone_debug_send_sync_static() {
        fn assert_bounds<T>()
        where
            T: Clone + std::fmt::Debug + Send + Sync + 'static,
        {
        }
        assert_bounds::<PodInfo>();
    }

    /// Pins `Send + Sync` on `ConnectionRegistry` itself. The registry
    /// is held as `Arc<ConnectionRegistry>` inside the federation
    /// manager and shared across the gRPC server's async runtime, the
    /// inbound-connection-register task, and the refresh loop — all
    /// three require both bounds. Removing an internal field that's
    /// `Send + Sync` (e.g., swapping `tokio::sync::Mutex` for a
    /// non-Send primitive) would break the `Arc<Self>` share at
    /// compile time; pinning here catches the regression at the type
    /// level.
    #[test]
    fn connection_registry_type_implements_send_and_sync() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}
        assert_send::<ConnectionRegistry>();
        assert_sync::<ConnectionRegistry>();
    }

    /// Pins the three NATS-KV constants. `CONN_BUCKET` must stay
    /// stable because it is the shared distributed-registry key
    /// across a heterogeneous pod fleet — a rename would silently
    /// split a rolling-upgrade fleet into two isolated registries.
    /// `CONN_TTL_SECS = 30` and `CONN_REFRESH_SECS = 10` are the
    /// documented cadence; pinning both literals here lets the
    /// changelog catch a silent cadence change.
    #[test]
    fn conn_constants_have_documented_literal_values() {
        assert_eq!(CONN_BUCKET, "federation-connections");
        assert_eq!(CONN_TTL_SECS, 30);
        assert_eq!(CONN_REFRESH_SECS, 10);
    }

    /// Strengthens the existing `conn_ttl_exceeds_refresh` test: the
    /// refresh cadence must fire at least THREE times within a single
    /// TTL window so two consecutive refresh failures (e.g. a transient
    /// NATS disconnect) still leaves a successful refresh cycle before
    /// the TTL drops the entry. With `CONN_TTL_SECS=30` and
    /// `CONN_REFRESH_SECS=10`, this means `30 >= 3 * 10 = 30` — any
    /// regression that tightened TTL below the 3× safety margin would
    /// make a single missed refresh cause entries to go missing across
    /// the pod fleet.
    #[test]
    fn conn_refresh_fires_at_least_three_times_within_ttl_window() {
        // Bind to locals to keep clippy::assertions_on_constants quiet —
        // the runtime check stays effective while the lint sees a non-const
        // operand. The existing `conn_ttl_exceeds_refresh` uses this pattern.
        let ttl = CONN_TTL_SECS;
        let refresh = CONN_REFRESH_SECS;
        assert!(
            ttl >= 3 * refresh,
            "TTL ({ttl}s) must allow at least 3 refreshes ({refresh}s each) \
             so two transient failures still leave a safety margin"
        );
    }

    /// Pins the `CONN_REFRESH_SECS > 0` floor. A zero refresh interval
    /// would cause `tokio::time::interval(Duration::from_secs(0))` to
    /// panic (the tokio contract rejects zero-duration intervals), and
    /// a regression that set it to zero would crash the background
    /// refresh task at `start()`.
    #[test]
    fn conn_refresh_secs_is_strictly_positive() {
        let refresh = CONN_REFRESH_SECS;
        let ttl = CONN_TTL_SECS;
        assert!(refresh > 0);
        assert!(ttl > 0);
    }
}
