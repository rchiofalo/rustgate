// Copyright © 2026 Roberto Chiofalo.

//! etcd peer discovery backend.
//!
//! Scans an etcd v3 key prefix (default `rustgate/peers/`) and treats each
//! key-value pair as a federation peer descriptor. Two value formats are
//! accepted per key:
//!
//! 1. **JSON** — the value is a full `PeerConfig` serialized as JSON. Use
//!    this when you need fine-grained control (groups, protocol version,
//!    trust CN, JWT token, etc.).
//! 2. **Plain `host:port`** — a bare address string. The backend synthesizes
//!    a `PeerConfig` with the key suffix as the peer id, `__ANON__` groups,
//!    and V2 gRPC as the protocol.
//!
//! Parsing is lenient: if one key fails to decode, a warning is logged and
//! the remaining keys are still returned. This matches the file-based
//! reloader's behavior where one bad entry does not poison the whole set.

use async_trait::async_trait;
use etcd_client::{Client, GetOptions};
use tokio::sync::Mutex;
use tracing::{debug, warn};

use super::PeerDiscovery;
use crate::config::{PeerConfig, RoutingMode};

/// etcd peer discovery source.
///
/// Holds a lazily-established `Client` (wrapped in an async `Mutex` because
/// etcd-client's `get` takes `&mut self`) and re-resolves the peer set on
/// every tick. A future optimization could replace the polling loop with
/// `Client::watch(prefix).with_prefix()` to react instantly to key changes,
/// but the fixed-interval model is simpler and matches the other backends.
pub struct EtcdDiscovery {
    endpoints: Vec<String>,
    prefix: String,
    /// `None` until the first successful `Client::connect` call; populated
    /// lazily so the constructor cannot fail on startup if etcd is down.
    client: Mutex<Option<Client>>,
}

impl std::fmt::Debug for EtcdDiscovery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EtcdDiscovery")
            .field("endpoints", &self.endpoints)
            .field("prefix", &self.prefix)
            .finish_non_exhaustive()
    }
}

impl EtcdDiscovery {
    /// Construct a new etcd discovery backend.
    ///
    /// `endpoints` are etcd gRPC endpoints (e.g. `["http://127.0.0.1:2379"]`).
    /// `prefix` is scanned with `GetOptions::with_prefix()` on every
    /// reconcile tick. Connection to the etcd cluster is deferred to the
    /// first `discover` call so a transient cluster outage at rustgate
    /// startup does not prevent the process from launching.
    pub fn new(endpoints: Vec<String>, prefix: impl Into<String>) -> Self {
        Self {
            endpoints,
            prefix: prefix.into(),
            client: Mutex::new(None),
        }
    }

    /// Ensure a connected `Client` exists and return a locked mutable ref.
    /// On failure, the mutex is cleared so the next tick retries a fresh
    /// connect.
    async fn get_or_connect<'a>(
        &'a self,
        guard: &'a mut tokio::sync::MutexGuard<'_, Option<Client>>,
    ) -> anyhow::Result<&'a mut Client> {
        if guard.is_none() {
            let client = Client::connect(self.endpoints.clone(), None)
                .await
                .map_err(|e| anyhow::anyhow!("failed to connect to etcd: {e}"))?;
            **guard = Some(client);
        }
        // Safe unwrap: we just inserted `Some` above if the slot was empty.
        guard
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("etcd client slot unexpectedly empty"))
    }

    /// Convert an etcd key-value pair into a [`PeerConfig`]. Supports both
    /// JSON-encoded full configs and plain `host:port` strings. Returns
    /// `None` on malformed input and emits a warning; callers use this so
    /// one bad entry cannot poison the entire discovery response.
    fn decode_entry(prefix: &str, key: &str, value: &str) -> Option<PeerConfig> {
        let trimmed_value = value.trim();
        if trimmed_value.starts_with('{') {
            match serde_json::from_str::<PeerConfig>(trimmed_value) {
                Ok(cfg) => Some(cfg),
                Err(e) => {
                    warn!(key = %key, error = %e, "etcd peer entry is not valid JSON PeerConfig");
                    None
                }
            }
        } else if trimmed_value.is_empty() {
            warn!(key = %key, "etcd peer entry has empty value");
            None
        } else {
            let id = key.strip_prefix(prefix).unwrap_or(key).to_string();
            if id.is_empty() {
                warn!(key = %key, "etcd peer entry has empty id after prefix strip");
                return None;
            }
            Some(PeerConfig {
                id: id.into(),
                address: trimmed_value.to_string(),
                groups: vec!["__ANON__".into()],
                inbound_groups: None,
                outbound_groups: None,
                enabled: true,
                is_outbound: true,
                trust_cert_cn: None,
                routing_mode: RoutingMode::default(),
                protocol_version: 2,
                jwt_token: None,
                region: None,
                zone: None,
                priority: 100,
            })
        }
    }

    /// Parse a shared slice of `(key, value)` pairs into peer configs.
    /// Exposed as an associated function so unit tests can feed synthetic
    /// data without mocking an etcd server.
    fn parse_kvs(prefix: &str, kvs: &[(String, String)]) -> Vec<PeerConfig> {
        kvs.iter()
            .filter_map(|(k, v)| Self::decode_entry(prefix, k, v))
            .collect()
    }
}

#[async_trait]
impl PeerDiscovery for EtcdDiscovery {
    async fn discover(&self) -> anyhow::Result<Vec<PeerConfig>> {
        let mut guard = self.client.lock().await;
        let result = async {
            let client = self.get_or_connect(&mut guard).await?;
            let opts = GetOptions::new().with_prefix();
            let resp = client
                .get(self.prefix.clone(), Some(opts))
                .await
                .map_err(|e| anyhow::anyhow!("etcd GET {} failed: {e}", self.prefix))?;
            let kvs: Vec<(String, String)> = resp
                .kvs()
                .iter()
                .filter_map(|kv| {
                    let key = kv.key_str().ok()?.to_string();
                    let value = kv.value_str().ok()?.to_string();
                    Some((key, value))
                })
                .collect();
            debug!(
                prefix = %self.prefix,
                count = kvs.len(),
                "etcd discovery returned peer entries"
            );
            Ok::<_, anyhow::Error>(Self::parse_kvs(&self.prefix, &kvs))
        }
        .await;

        // On failure, drop the cached client so the next tick reconnects.
        if result.is_err() {
            *guard = None;
        }
        result
    }

    fn backend_name(&self) -> &'static str {
        "etcd"
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn decode_entry_accepts_plain_host_port() {
        let cfg =
            EtcdDiscovery::decode_entry("rustgate/peers/", "rustgate/peers/alpha", "10.0.0.1:9000")
                .expect("decode");
        assert_eq!(cfg.id.as_str(), "alpha");
        assert_eq!(cfg.address, "10.0.0.1:9000");
        assert!(cfg.is_outbound);
        assert_eq!(cfg.protocol_version, 2);
    }

    #[test]
    fn decode_entry_accepts_json_peer_config() {
        let json = r#"{
            "id": "beta",
            "address": "10.0.0.2:9001",
            "groups": ["east"],
            "enabled": true,
            "is_outbound": true,
            "trust_cert_cn": null,
            "protocol_version": 1
        }"#;
        let cfg = EtcdDiscovery::decode_entry("rustgate/peers/", "rustgate/peers/beta", json)
            .expect("decode");
        assert_eq!(cfg.id.as_str(), "beta");
        assert_eq!(cfg.address, "10.0.0.2:9001");
        assert_eq!(cfg.protocol_version, 1);
        assert_eq!(cfg.groups, vec!["east".to_string()]);
    }

    #[test]
    fn decode_entry_rejects_empty_value() {
        let cfg = EtcdDiscovery::decode_entry("rustgate/peers/", "rustgate/peers/gamma", "");
        assert!(cfg.is_none());
    }

    #[test]
    fn decode_entry_rejects_invalid_json() {
        let cfg =
            EtcdDiscovery::decode_entry("rustgate/peers/", "rustgate/peers/delta", "{not json");
        assert!(cfg.is_none());
    }

    #[test]
    fn parse_kvs_skips_bad_entries() {
        let prefix = "rustgate/peers/";
        let kvs = vec![
            (
                "rustgate/peers/ok1".to_string(),
                "10.0.0.1:9000".to_string(),
            ),
            ("rustgate/peers/bad".to_string(), String::new()),
            (
                "rustgate/peers/ok2".to_string(),
                "10.0.0.2:9001".to_string(),
            ),
        ];
        let out = EtcdDiscovery::parse_kvs(prefix, &kvs);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].id.as_str(), "ok1");
        assert_eq!(out[1].id.as_str(), "ok2");
    }
}
