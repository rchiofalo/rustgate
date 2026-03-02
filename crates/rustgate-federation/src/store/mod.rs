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
