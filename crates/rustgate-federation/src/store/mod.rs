pub mod file;

use std::time::SystemTime;

use crate::config::RoutingMode;

/// Persistent information about a configured federation peer.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FederateInfo {
    /// Unique identifier.
    pub id: String,
    /// Network address (host:port).
    pub address: String,
    /// Groups this federate participates in.
    pub groups: Vec<String>,
    /// Whether this federate is enabled.
    pub enabled: bool,
    /// Whether we initiate the connection (outbound) or they connect to us (inbound).
    pub is_outbound: bool,
    /// Optional CN of the certificate to trust for this peer.
    pub trust_cert_cn: Option<String>,
    /// Routing mode: matrix (per-peer subscription) or broadcast.
    #[serde(default)]
    pub routing_mode: RoutingMode,
    /// When this federate was first registered.
    #[serde(default = "now")]
    pub created_at: SystemTime,
    /// Last time we saw activity from this federate.
    pub last_seen: Option<SystemTime>,
    /// Total messages sent to this federate.
    #[serde(default)]
    pub messages_sent: u64,
    /// Total messages received from this federate.
    #[serde(default)]
    pub messages_recv: u64,
}

fn now() -> SystemTime {
    SystemTime::now()
}

/// Fields that can be updated on an existing federate.
#[derive(Debug, Default)]
pub struct FederateUpdate {
    pub address: Option<String>,
    pub groups: Option<Vec<String>>,
    pub is_outbound: Option<bool>,
    pub trust_cert_cn: Option<Option<String>>,
}

/// Trait for federation peer persistence backends.
pub trait FederateStore: Send + Sync {
    /// Load all federates from persistent storage.
    fn load(&mut self) -> anyhow::Result<()>;

    /// Persist all federates to storage.
    fn save(&self) -> anyhow::Result<()>;

    /// Add or replace a federate.
    fn add(&mut self, info: FederateInfo);

    /// Get a federate by ID.
    fn get(&self, id: &str) -> Option<&FederateInfo>;

    /// List all federates.
    fn list(&self) -> Vec<&FederateInfo>;

    /// List only enabled federates.
    fn list_enabled(&self) -> Vec<&FederateInfo>;

    /// List enabled outbound federates.
    fn list_outbound(&self) -> Vec<&FederateInfo>;

    /// Remove a federate by ID. Returns `true` if it existed.
    fn remove(&mut self, id: &str) -> bool;

    /// Update fields on an existing federate. Returns the old address if changed.
    fn update(&mut self, id: &str, update: FederateUpdate) -> anyhow::Result<Option<String>>;

    /// Toggle the enabled flag.
    fn set_enabled(&mut self, id: &str, enabled: bool) -> anyhow::Result<()>;

    /// Set the routing mode.
    fn set_routing_mode(&mut self, id: &str, mode: RoutingMode) -> anyhow::Result<()>;

    /// Update the last_seen timestamp.
    fn update_last_seen(&mut self, id: &str);

    /// Accumulate message counters.
    fn update_stats(&mut self, id: &str, sent: u64, recv: u64);

    /// Number of configured federates.
    fn count(&self) -> usize;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_info(id: &str) -> FederateInfo {
        FederateInfo {
            id: id.to_string(),
            address: format!("10.0.0.1:{}", 9001),
            groups: vec!["Alpha".into()],
            enabled: true,
            is_outbound: true,
            trust_cert_cn: None,
            routing_mode: RoutingMode::default(),
            created_at: SystemTime::now(),
            last_seen: None,
            messages_sent: 0,
            messages_recv: 0,
        }
    }

    #[test]
    fn federate_info_clone() {
        let original = make_info("peer-1");
        let cloned = original.clone();
        assert_eq!(cloned.id, original.id);
        assert_eq!(cloned.address, original.address);
        assert_eq!(cloned.groups, original.groups);
        assert_eq!(cloned.enabled, original.enabled);
    }

    #[test]
    fn federate_info_debug() {
        let info = make_info("peer-1");
        let debug = format!("{info:?}");
        assert!(debug.contains("peer-1"));
    }

    #[test]
    fn federate_info_serde_round_trip() {
        let info = make_info("peer-1");
        let json = serde_json::to_string(&info).expect("serialize");
        let parsed: FederateInfo = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.id, info.id);
        assert_eq!(parsed.address, info.address);
        assert_eq!(parsed.groups, info.groups);
        assert_eq!(parsed.enabled, info.enabled);
        assert_eq!(parsed.is_outbound, info.is_outbound);
        assert_eq!(parsed.routing_mode, info.routing_mode);
    }

    #[test]
    fn federate_info_serde_with_last_seen() {
        let mut info = make_info("peer-1");
        info.last_seen = Some(SystemTime::now());
        let json = serde_json::to_string(&info).expect("serialize");
        let parsed: FederateInfo = serde_json::from_str(&json).expect("deserialize");
        assert!(parsed.last_seen.is_some());
    }

    #[test]
    fn federate_info_serde_with_all_fields() {
        let mut info = make_info("peer-1");
        info.trust_cert_cn = Some("my-cert-cn".into());
        info.routing_mode = RoutingMode::Broadcast;
        info.messages_sent = 100;
        info.messages_recv = 50;
        info.last_seen = Some(SystemTime::now());
        info.groups = vec!["Alpha".into(), "Bravo".into(), "Charlie".into()];

        let json = serde_json::to_string(&info).expect("serialize");
        let parsed: FederateInfo = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.trust_cert_cn.as_deref(), Some("my-cert-cn"));
        assert_eq!(parsed.routing_mode, RoutingMode::Broadcast);
        assert_eq!(parsed.messages_sent, 100);
        assert_eq!(parsed.messages_recv, 50);
        assert_eq!(parsed.groups.len(), 3);
    }

    #[test]
    fn federate_info_deserialize_missing_optional_fields() {
        let json = r#"{
            "id": "peer-1",
            "address": "10.0.0.1:9001",
            "groups": [],
            "enabled": true,
            "is_outbound": false,
            "trust_cert_cn": null,
            "last_seen": null
        }"#;
        let parsed: FederateInfo = serde_json::from_str(json).expect("deserialize");
        assert_eq!(parsed.routing_mode, RoutingMode::Matrix);
        assert_eq!(parsed.messages_sent, 0);
        assert_eq!(parsed.messages_recv, 0);
        assert!(parsed.created_at > SystemTime::UNIX_EPOCH);
    }

    #[test]
    fn federate_update_default_all_none() {
        let update = FederateUpdate::default();
        assert!(update.address.is_none());
        assert!(update.groups.is_none());
        assert!(update.is_outbound.is_none());
        assert!(update.trust_cert_cn.is_none());
    }

    #[test]
    fn federate_update_debug() {
        let update = FederateUpdate {
            address: Some("new-addr".into()),
            groups: None,
            is_outbound: Some(true),
            trust_cert_cn: None,
        };
        let debug = format!("{update:?}");
        assert!(debug.contains("new-addr"));
    }

    #[test]
    fn federate_info_serialize_array() {
        let infos = vec![
            make_info("peer-1"),
            make_info("peer-2"),
            make_info("peer-3"),
        ];
        let json = serde_json::to_string(&infos).expect("serialize");
        let parsed: Vec<FederateInfo> = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0].id, "peer-1");
        assert_eq!(parsed[1].id, "peer-2");
        assert_eq!(parsed[2].id, "peer-3");
    }

    #[test]
    fn now_helper_returns_recent_time() {
        let t = now();
        let elapsed = t.elapsed().expect("elapsed");
        assert!(elapsed.as_secs() < 1);
    }
}
