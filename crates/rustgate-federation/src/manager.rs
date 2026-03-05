//! Federation manager — orchestrates all federation peer connections.
//!
//! The manager owns the V1 and V2 inbound servers and outbound clients,
//! routing messages between federation peers and the local system
//! via callbacks. It does not directly depend on the Router or NATS;
//! integration with those systems happens at the wiring layer
//! (e.g., in `rustgate-server`).

use std::collections::HashMap;
use std::sync::Arc;

use bytes::Bytes;
#[cfg(feature = "v2")]
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::config::FederationConfig;
use crate::connector::PeerConnector;
use crate::peer::{PeerHandle, PeerStatus};
use crate::v1::{V1Client, V1Server};

/// Callback invoked for each non-heartbeat message received from a federation peer.
///
/// Arguments: (peer_id_or_cn, raw_payload_bytes)
///
/// The caller is responsible for provenance checking, format conversion,
/// and routing the message to local clients (e.g., via the Router).
pub type OnInbound = Arc<dyn Fn(String, Bytes) + Send + Sync>;

/// Wraps either a V1 or V2 outbound federation client.
enum FederationClient {
    V1(V1Client),
    #[cfg(feature = "v2")]
    V2(crate::v2::client::V2Client),
}

impl std::fmt::Debug for FederationClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::V1(_) => write!(f, "FederationClient::V1"),
            #[cfg(feature = "v2")]
            Self::V2(_) => write!(f, "FederationClient::V2"),
        }
    }
}

/// Orchestrates all federation peer connections.
///
/// Manages the V1/V2 inbound servers and outbound clients, providing:
/// - Lifecycle management (start/shutdown)
/// - Inbound message routing via callback
/// - Outbound message forwarding with group-aware filtering
/// - Peer status tracking and reporting
#[derive(Debug)]
pub struct FederationManager {
    config: FederationConfig,
    connector: Option<PeerConnector>,
    v1_server: Option<V1Server>,
    #[cfg(feature = "v2")]
    v2_server_handle: Option<JoinHandle<Result<(), tonic::transport::Error>>>,
    clients: HashMap<String, FederationClient>,
    peers: HashMap<String, Arc<PeerHandle>>,
    running: bool,
}

/// Aggregated status snapshot of the federation subsystem.
#[derive(Debug, Clone, serde::Serialize)]
pub struct FederationStatus {
    /// Whether the federation manager is running.
    pub running: bool,
    /// Whether the V1 inbound server is active.
    pub v1_server_active: bool,
    /// Whether the V2 gRPC inbound server is active.
    pub v2_server_active: bool,
    /// Total number of configured peers.
    pub total_peers: usize,
    /// Number of currently connected peers.
    pub connected_peers: usize,
    /// Per-peer status snapshots.
    pub peers: Vec<PeerStatus>,
}

impl FederationManager {
    /// Create a new federation manager from configuration.
    ///
    /// Does not start any connections — call `start()` to begin.
    pub fn new(config: FederationConfig) -> Self {
        Self {
            config,
            connector: None,
            v1_server: None,
            #[cfg(feature = "v2")]
            v2_server_handle: None,
            clients: HashMap::new(),
            peers: HashMap::new(),
            running: false,
        }
    }

    /// Start the federation manager.
    ///
    /// Creates the TLS connector, starts the V1/V2 inbound servers (if enabled),
    /// and initiates outbound connections to all configured peers.
    ///
    /// The `on_inbound` callback is invoked for every non-heartbeat message
    /// received from any federation peer (both inbound and outbound connections).
    pub async fn start(&mut self, on_inbound: OnInbound) -> anyhow::Result<()> {
        if self.running {
            return Err(anyhow::anyhow!("federation manager is already running"));
        }

        // Read TLS certificate material
        let cert_pem = std::fs::read_to_string(&self.config.cert_file)
            .map_err(|e| anyhow::anyhow!("read cert file: {e}"))?;
        let key_pem = std::fs::read_to_string(&self.config.key_file)
            .map_err(|e| anyhow::anyhow!("read key file: {e}"))?;
        let ca_pem = std::fs::read_to_string(&self.config.ca_file)
            .map_err(|e| anyhow::anyhow!("read CA file: {e}"))?;

        // Create outbound connector (used by V1 clients)
        let connector = PeerConnector::from_pem(
            &cert_pem,
            &key_pem,
            &ca_pem,
            self.config.skip_hostname_verify,
        )?;
        self.connector = Some(connector.clone());

        // Start V1 inbound server if enabled
        if self.config.v1_enabled {
            let tls_config = rustgate_transport::TlsConfig::from_pem(&cert_pem, &key_pem, &ca_pem)?;

            let server = V1Server::start(
                self.config.v1_listen_addr,
                &tls_config,
                self.config.federate_id.clone(),
                self.config.heartbeat_interval,
                self.config.heartbeat_timeout,
                Arc::clone(&on_inbound),
            )
            .await?;

            self.v1_server = Some(server);
            info!(
                addr = %self.config.v1_listen_addr,
                "V1 federation server started"
            );
        }

        // Start V2 gRPC inbound server if enabled
        #[cfg(feature = "v2")]
        if self.config.v2_enabled {
            use tonic::transport::ServerTlsConfig;

            let server_cert = tonic::transport::Identity::from_pem(&cert_pem, &key_pem);
            let server_ca = tonic::transport::Certificate::from_pem(&ca_pem);

            let tls_config = ServerTlsConfig::new()
                .identity(server_cert)
                .client_ca_root(server_ca);

            let on_event_inbound = Arc::clone(&on_inbound);
            let federate_id = self.config.federate_id.clone();
            let on_event: crate::v2::server::OnEvent = Arc::new(move |event, peer_id| {
                if event.event.is_some() {
                    match crate::v2::convert::federated_event_to_xml(&event) {
                        Ok(xml) => {
                            on_event_inbound(peer_id, Bytes::from(xml));
                        }
                        Err(e) => {
                            warn!(
                                federate = %federate_id,
                                error = %e,
                                "failed to convert inbound V2 server event to XML"
                            );
                        }
                    }
                } else if let Some(ref contact) = event.contact {
                    if let Some(xml) = crate::v2::convert::contact_list_entry_to_xml(contact) {
                        on_event_inbound(peer_id, Bytes::from(xml));
                    }
                }
            });

            let service = crate::v2::server::FederationService::new(
                self.config.federate_id.clone(),
                self.config
                    .peers
                    .iter()
                    .flat_map(|p| p.groups.clone())
                    .collect::<std::collections::BTreeSet<_>>()
                    .into_iter()
                    .collect(),
                on_event,
            );

            let handle = crate::v2::server::FederationService::start(
                self.config.v2_listen_addr,
                tls_config,
                service,
                self.config.max_message_size,
            );

            self.v2_server_handle = Some(handle);
            info!(
                addr = %self.config.v2_listen_addr,
                "V2 gRPC federation server started"
            );
        }

        // Build V2 TLS config for outbound gRPC clients (if v2 feature is enabled)
        #[cfg(feature = "v2")]
        let v2_tls_config = {
            use tonic::transport::ClientTlsConfig;

            let ca_cert = tonic::transport::Certificate::from_pem(&ca_pem);
            let client_identity = tonic::transport::Identity::from_pem(&cert_pem, &key_pem);

            ClientTlsConfig::new()
                .ca_certificate(ca_cert)
                .identity(client_identity)
        };

        // Connect to all enabled outbound peers
        for peer_config in &self.config.peers {
            if !peer_config.enabled || !peer_config.is_outbound {
                continue;
            }

            let addr: std::net::SocketAddr = match peer_config.address.parse() {
                Ok(a) => a,
                Err(e) => {
                    warn!(
                        peer_id = %peer_config.id,
                        address = %peer_config.address,
                        error = %e,
                        "skipping peer with invalid address"
                    );
                    continue;
                }
            };

            let peer = Arc::new(PeerHandle::new(peer_config.clone()));

            match peer_config.protocol_version {
                1 => {
                    let client = V1Client::start(
                        Arc::clone(&peer),
                        crate::v1::client::V1ClientConfig {
                            connector: connector.clone(),
                            addr,
                            server_name: addr.ip().to_string(),
                            server_uid: self.config.federate_id.clone(),
                            heartbeat_interval: self.config.heartbeat_interval,
                            heartbeat_timeout: self.config.heartbeat_timeout,
                            reconnect_delay: self.config.reconnect_delay,
                            max_reconnects: self.config.max_reconnects,
                            on_message: Arc::clone(&on_inbound),
                        },
                    );

                    info!(
                        peer_id = %peer_config.id,
                        addr = %addr,
                        "started V1 federation client"
                    );

                    let _ = self.peers.insert(peer_config.id.clone(), peer);
                    let _ = self
                        .clients
                        .insert(peer_config.id.clone(), FederationClient::V1(client));
                }
                #[cfg(feature = "v2")]
                2 => {
                    let on_event_inbound = Arc::clone(&on_inbound);
                    let federate_id = self.config.federate_id.clone();
                    let on_event: crate::v2::client::OnEvent = Arc::new(move |event, peer_id| {
                        // Try GeoEvent first, then fall back to ContactListEntry
                        if event.event.is_some() {
                            match crate::v2::convert::federated_event_to_xml(&event) {
                                Ok(xml) => {
                                    on_event_inbound(peer_id, Bytes::from(xml));
                                }
                                Err(e) => {
                                    warn!(
                                        federate = %federate_id,
                                        error = %e,
                                        "failed to convert inbound V2 GeoEvent to XML"
                                    );
                                }
                            }
                        } else if let Some(ref contact) = event.contact {
                            if let Some(xml) =
                                crate::v2::convert::contact_list_entry_to_xml(contact)
                            {
                                on_event_inbound(peer_id, Bytes::from(xml));
                            }
                        }
                    });

                    let client = crate::v2::client::V2Client::start(
                        Arc::clone(&peer),
                        crate::v2::client::V2ClientConfig {
                            address: peer_config.address.clone(),
                            tls_config: v2_tls_config.clone(),
                            federate_id: self.config.federate_id.clone(),
                            groups: peer_config.groups.clone(),
                            health_interval: self.config.health_check_interval,
                            reconnect_delay: self.config.reconnect_delay,
                            max_reconnects: self.config.max_reconnects,
                            on_event,
                        },
                    );

                    info!(
                        peer_id = %peer_config.id,
                        addr = %addr,
                        "started V2 gRPC federation client"
                    );

                    let _ = self.peers.insert(peer_config.id.clone(), peer);
                    let _ = self
                        .clients
                        .insert(peer_config.id.clone(), FederationClient::V2(client));
                }
                other => {
                    warn!(
                        peer_id = %peer_config.id,
                        protocol_version = other,
                        "skipping peer with unsupported protocol version"
                    );
                    continue;
                }
            }
        }

        self.running = true;
        info!(
            federate_id = %self.config.federate_id,
            v1_server = self.config.v1_enabled,
            outbound_peers = self.clients.len(),
            "federation manager started"
        );

        Ok(())
    }

    /// Forward a message payload to all relevant connected federation peers.
    ///
    /// Injects a flow tag into the XML for traceability, then filters peers
    /// by group overlap: a peer receives the message only if at least one of
    /// its configured groups matches one of the `source_groups`. If either
    /// `source_groups` or the peer's groups are empty, the message is
    /// forwarded unconditionally (broadcast behavior).
    ///
    /// For V2 peers, the raw XML payload is converted to a FederatedEvent
    /// before sending over gRPC.
    ///
    /// Returns the number of peers the message was successfully queued to.
    pub async fn forward(&self, payload: Bytes, source_groups: &[String]) -> usize {
        let mut sent = 0;

        // Inject flow tag for traceability (identifies which federation server
        // processed this message and when)
        #[cfg(feature = "v2")]
        let payload = {
            let tagged = crate::v2::convert::add_flow_tag(&payload, &self.config.federate_id);
            Bytes::from(tagged)
        };
        #[cfg(not(feature = "v2"))]
        let payload = payload;

        // Lazily convert to FederatedEvent only if there are V2 peers
        #[cfg(feature = "v2")]
        let mut v2_event: Option<crate::v2::proto::figpb::FederatedEvent> = None;

        for (id, client) in &self.clients {
            let peer = match self.peers.get(id) {
                Some(p) => p,
                None => continue,
            };

            if !peer.is_connected() {
                continue;
            }

            // Group-aware filtering: forward only if source groups overlap
            // with this peer's outbound groups (directional filtering).
            let outbound = peer.config.effective_outbound_groups();
            if !source_groups.is_empty() && !outbound.is_empty() {
                let has_overlap = source_groups.iter().any(|g| outbound.contains(g));
                if !has_overlap {
                    continue;
                }
            }

            let result = match client {
                FederationClient::V1(v1) => v1.send(payload.clone()).await,
                #[cfg(feature = "v2")]
                FederationClient::V2(v2) => {
                    // Convert XML payload to FederatedEvent on first V2 peer
                    let event = match &v2_event {
                        Some(e) => e.clone(),
                        None => {
                            let metadata =
                                crate::provenance::FederationMetadata::new(self.config.max_hops);
                            match crate::v2::convert::xml_to_federated_event(&payload, &metadata) {
                                Ok(e) => {
                                    v2_event = Some(e.clone());
                                    e
                                }
                                Err(e) => {
                                    warn!(
                                        peer_id = %id,
                                        error = %e,
                                        "failed to convert XML to FederatedEvent for V2 peer"
                                    );
                                    continue;
                                }
                            }
                        }
                    };
                    v2.send(event).await
                }
            };

            match result {
                Ok(()) => {
                    sent += 1;
                }
                Err(e) => {
                    warn!(
                        peer_id = %id,
                        error = %e,
                        "failed to forward message to federation peer"
                    );
                }
            }
        }
        sent
    }

    /// Gracefully shut down the federation manager and all connections.
    pub async fn shutdown(&mut self) {
        if !self.running {
            return;
        }

        // Shut down V1 server
        if let Some(mut server) = self.v1_server.take() {
            server.shutdown().await;
            info!("V1 federation server stopped");
        }

        // Shut down V2 gRPC server
        #[cfg(feature = "v2")]
        if let Some(handle) = self.v2_server_handle.take() {
            handle.abort();
            info!("V2 gRPC federation server stopped");
        }

        // Shut down all outbound clients
        for (id, client) in self.clients.drain() {
            match client {
                FederationClient::V1(mut v1) => {
                    v1.shutdown().await;
                    info!(peer_id = %id, "V1 federation client stopped");
                }
                #[cfg(feature = "v2")]
                FederationClient::V2(mut v2) => {
                    v2.shutdown().await;
                    info!(peer_id = %id, "V2 federation client stopped");
                }
            }
        }

        self.peers.clear();
        self.running = false;
        info!("federation manager shut down");
    }

    /// Get the status snapshot for a specific peer.
    pub fn peer_status(&self, id: &str) -> Option<PeerStatus> {
        self.peers.get(id).map(|p| p.status())
    }

    /// Get status snapshots for all peers.
    pub fn all_peer_statuses(&self) -> Vec<PeerStatus> {
        self.peers.values().map(|p| p.status()).collect()
    }

    /// Get the aggregated federation status.
    pub fn status(&self) -> FederationStatus {
        #[cfg(feature = "v2")]
        let v2_active = self.v2_server_handle.is_some();
        #[cfg(not(feature = "v2"))]
        let v2_active = false;

        FederationStatus {
            running: self.running,
            v1_server_active: self.v1_server.is_some(),
            v2_server_active: v2_active,
            total_peers: self.peers.len(),
            connected_peers: self.connected_peer_count(),
            peers: self.all_peer_statuses(),
        }
    }

    /// Get the number of currently connected peers.
    pub fn connected_peer_count(&self) -> usize {
        self.peers.values().filter(|p| p.is_connected()).count()
    }

    /// Get the total number of tracked peers.
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Check whether the manager is running.
    pub fn is_running(&self) -> bool {
        self.running
    }

    /// Get a reference to the federation configuration.
    pub fn config(&self) -> &FederationConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::Duration;

    use super::*;
    use crate::config::{FederationConfig, PeerConfig, RoutingMode};

    fn test_config() -> FederationConfig {
        FederationConfig {
            federate_id: "test-federation".into(),
            v1_enabled: false,
            v1_listen_addr: "127.0.0.1:0".parse().expect("valid addr"),
            v2_enabled: false,
            v2_listen_addr: "127.0.0.1:0".parse().expect("valid addr"),
            peers: vec![],
            heartbeat_interval: Duration::from_secs(30),
            heartbeat_timeout: Duration::from_secs(90),
            health_check_interval: Duration::from_secs(5),
            client_timeout: Duration::from_secs(15),
            max_message_size: 10 * 1024 * 1024,
            reconnect_delay: Duration::from_secs(30),
            max_reconnects: -1,
            max_hops: 10,
            default_group: "__ANON__".into(),
            store_path: None,
            skip_hostname_verify: false,
            cert_file: PathBuf::from("/nonexistent/cert.pem"),
            key_file: PathBuf::from("/nonexistent/key.pem"),
            ca_file: PathBuf::from("/nonexistent/ca.pem"),
        }
    }

    fn test_peer_config(id: &str, groups: Vec<String>) -> PeerConfig {
        PeerConfig {
            id: id.into(),
            address: "127.0.0.1:9001".into(),
            groups,
            inbound_groups: None,
            outbound_groups: None,
            enabled: true,
            is_outbound: true,
            trust_cert_cn: None,
            routing_mode: RoutingMode::default(),
            protocol_version: 1,
        }
    }

    #[test]
    fn new_manager_is_not_running() {
        let manager = FederationManager::new(test_config());
        assert!(!manager.is_running());
        assert_eq!(manager.peer_count(), 0);
        assert_eq!(manager.connected_peer_count(), 0);
    }

    #[test]
    fn new_manager_has_empty_status() {
        let manager = FederationManager::new(test_config());
        let status = manager.status();
        assert!(!status.running);
        assert!(!status.v1_server_active);
        assert_eq!(status.total_peers, 0);
        assert_eq!(status.connected_peers, 0);
        assert!(status.peers.is_empty());
    }

    #[test]
    fn new_manager_returns_config() {
        let config = test_config();
        let manager = FederationManager::new(config.clone());
        assert_eq!(manager.config().federate_id, "test-federation");
    }

    #[test]
    fn peer_status_returns_none_for_unknown() {
        let manager = FederationManager::new(test_config());
        assert!(manager.peer_status("nonexistent").is_none());
    }

    #[test]
    fn all_peer_statuses_empty() {
        let manager = FederationManager::new(test_config());
        assert!(manager.all_peer_statuses().is_empty());
    }

    #[tokio::test]
    async fn shutdown_when_not_running_is_safe() {
        let mut manager = FederationManager::new(test_config());
        manager.shutdown().await;
        assert!(!manager.is_running());
    }

    #[tokio::test]
    async fn double_shutdown_is_safe() {
        let mut manager = FederationManager::new(test_config());
        manager.shutdown().await;
        manager.shutdown().await;
        assert!(!manager.is_running());
    }

    #[tokio::test]
    async fn start_fails_with_missing_certs() {
        let mut manager = FederationManager::new(test_config());
        let on_inbound: OnInbound = Arc::new(|_cn, _data| {});
        let result = manager.start(on_inbound).await;
        assert!(result.is_err());
        assert!(!manager.is_running());
    }

    #[tokio::test]
    async fn start_and_shutdown_with_real_certs() {
        use rustgate_test_utils::certs::TestCa;

        let ca = TestCa::new("Test CA");
        let server_cert = ca.issue_server_cert("localhost", &["localhost"]);

        let tmp = tempfile::tempdir().expect("tempdir");
        let cert_path = tmp.path().join("cert.pem");
        let key_path = tmp.path().join("key.pem");
        let ca_path = tmp.path().join("ca.pem");

        std::fs::write(&cert_path, &server_cert.cert_pem).expect("write cert");
        std::fs::write(&key_path, &server_cert.key_pem).expect("write key");
        std::fs::write(&ca_path, &ca.cert_pem).expect("write ca");

        let config = FederationConfig {
            federate_id: "test-server".into(),
            v1_enabled: true,
            v1_listen_addr: "127.0.0.1:0".parse().expect("valid addr"),
            cert_file: cert_path,
            key_file: key_path,
            ca_file: ca_path,
            ..test_config()
        };

        let mut manager = FederationManager::new(config);
        let on_inbound: OnInbound = Arc::new(|_cn, _data| {});

        manager.start(on_inbound).await.expect("start");
        assert!(manager.is_running());
        assert!(manager.status().v1_server_active);

        manager.shutdown().await;
        assert!(!manager.is_running());
    }

    #[tokio::test]
    async fn start_rejects_double_start() {
        use rustgate_test_utils::certs::TestCa;

        let ca = TestCa::new("Test CA");
        let server_cert = ca.issue_server_cert("localhost", &["localhost"]);

        let tmp = tempfile::tempdir().expect("tempdir");
        let cert_path = tmp.path().join("cert.pem");
        let key_path = tmp.path().join("key.pem");
        let ca_path = tmp.path().join("ca.pem");

        std::fs::write(&cert_path, &server_cert.cert_pem).expect("write cert");
        std::fs::write(&key_path, &server_cert.key_pem).expect("write key");
        std::fs::write(&ca_path, &ca.cert_pem).expect("write ca");

        let config = FederationConfig {
            federate_id: "test-server".into(),
            v1_enabled: false,
            cert_file: cert_path,
            key_file: key_path,
            ca_file: ca_path,
            ..test_config()
        };

        let mut manager = FederationManager::new(config);
        let on_inbound: OnInbound = Arc::new(|_cn, _data| {});

        manager.start(Arc::clone(&on_inbound)).await.expect("start");
        let result = manager.start(on_inbound).await;
        assert!(result.is_err());
        assert!(
            result
                .expect_err("double start should fail")
                .to_string()
                .contains("already running")
        );

        manager.shutdown().await;
    }

    #[tokio::test]
    async fn start_with_outbound_peers() {
        use rustgate_test_utils::certs::TestCa;

        let ca = TestCa::new("Test CA");
        let client_cert = ca.issue_client_cert("federation-client", &["Alpha"]);

        let tmp = tempfile::tempdir().expect("tempdir");
        let cert_path = tmp.path().join("cert.pem");
        let key_path = tmp.path().join("key.pem");
        let ca_path = tmp.path().join("ca.pem");

        std::fs::write(&cert_path, &client_cert.cert_pem).expect("write cert");
        std::fs::write(&key_path, &client_cert.key_pem).expect("write key");
        std::fs::write(&ca_path, &ca.cert_pem).expect("write ca");

        let config = FederationConfig {
            federate_id: "test-server".into(),
            v1_enabled: false,
            peers: vec![
                test_peer_config("peer-1", vec!["Alpha".into()]),
                test_peer_config("peer-2", vec!["Beta".into()]),
            ],
            cert_file: cert_path,
            key_file: key_path,
            ca_file: ca_path,
            reconnect_delay: Duration::from_secs(1),
            max_reconnects: 0,
            ..test_config()
        };

        let mut manager = FederationManager::new(config);
        let on_inbound: OnInbound = Arc::new(|_cn, _data| {});

        manager.start(on_inbound).await.expect("start");
        assert_eq!(manager.peer_count(), 2);

        // Peers exist but won't be connected (no server listening)
        assert!(manager.peer_status("peer-1").is_some());
        assert!(manager.peer_status("peer-2").is_some());

        // Give clients time to try and fail
        tokio::time::sleep(Duration::from_millis(200)).await;

        let statuses = manager.all_peer_statuses();
        assert_eq!(statuses.len(), 2);

        manager.shutdown().await;
        assert_eq!(manager.peer_count(), 0);
    }

    #[tokio::test]
    async fn start_skips_disabled_and_inbound_peers() {
        use rustgate_test_utils::certs::TestCa;

        let ca = TestCa::new("Test CA");
        let client_cert = ca.issue_client_cert("federation-client", &["Alpha"]);

        let tmp = tempfile::tempdir().expect("tempdir");
        let cert_path = tmp.path().join("cert.pem");
        let key_path = tmp.path().join("key.pem");
        let ca_path = tmp.path().join("ca.pem");

        std::fs::write(&cert_path, &client_cert.cert_pem).expect("write cert");
        std::fs::write(&key_path, &client_cert.key_pem).expect("write key");
        std::fs::write(&ca_path, &ca.cert_pem).expect("write ca");

        let mut disabled = test_peer_config("disabled-peer", vec!["Alpha".into()]);
        disabled.enabled = false;

        let mut inbound_only = test_peer_config("inbound-only", vec!["Beta".into()]);
        inbound_only.is_outbound = false;

        let mut bad_version = test_peer_config("bad-version", vec!["Gamma".into()]);
        bad_version.protocol_version = 99;

        let config = FederationConfig {
            federate_id: "test-server".into(),
            v1_enabled: false,
            peers: vec![
                disabled,
                inbound_only,
                bad_version,
                test_peer_config("active-peer", vec!["Delta".into()]),
            ],
            cert_file: cert_path,
            key_file: key_path,
            ca_file: ca_path,
            reconnect_delay: Duration::from_secs(1),
            max_reconnects: 0,
            ..test_config()
        };

        let mut manager = FederationManager::new(config);
        let on_inbound: OnInbound = Arc::new(|_cn, _data| {});

        manager.start(on_inbound).await.expect("start");
        // Only active-peer should be started (disabled, inbound-only, and bad version skipped)
        assert_eq!(manager.peer_count(), 1);
        assert!(manager.peer_status("active-peer").is_some());

        manager.shutdown().await;
    }

    #[tokio::test]
    async fn start_skips_invalid_address() {
        use rustgate_test_utils::certs::TestCa;

        let ca = TestCa::new("Test CA");
        let client_cert = ca.issue_client_cert("federation-client", &["Alpha"]);

        let tmp = tempfile::tempdir().expect("tempdir");
        let cert_path = tmp.path().join("cert.pem");
        let key_path = tmp.path().join("key.pem");
        let ca_path = tmp.path().join("ca.pem");

        std::fs::write(&cert_path, &client_cert.cert_pem).expect("write cert");
        std::fs::write(&key_path, &client_cert.key_pem).expect("write key");
        std::fs::write(&ca_path, &ca.cert_pem).expect("write ca");

        let mut bad_addr = test_peer_config("bad-peer", vec!["Alpha".into()]);
        bad_addr.address = "not-a-valid-address".into();

        let config = FederationConfig {
            federate_id: "test-server".into(),
            v1_enabled: false,
            peers: vec![bad_addr],
            cert_file: cert_path,
            key_file: key_path,
            ca_file: ca_path,
            ..test_config()
        };

        let mut manager = FederationManager::new(config);
        let on_inbound: OnInbound = Arc::new(|_cn, _data| {});

        // Start should succeed even with bad address (skipped with warning)
        manager.start(on_inbound).await.expect("start");
        assert_eq!(manager.peer_count(), 0);

        manager.shutdown().await;
    }

    #[tokio::test]
    async fn forward_with_no_peers_returns_zero() {
        let manager = FederationManager::new(test_config());
        let sent = manager
            .forward(Bytes::from("test"), &["Alpha".into()])
            .await;
        assert_eq!(sent, 0);
    }

    #[test]
    fn federation_status_serializes() {
        let status = FederationStatus {
            running: true,
            v1_server_active: true,
            v2_server_active: false,
            total_peers: 2,
            connected_peers: 1,
            peers: vec![],
        };
        let json = serde_json::to_string(&status).expect("serialize");
        assert!(json.contains("\"running\":true"));
        assert!(json.contains("\"v1_server_active\":true"));
        assert!(json.contains("\"total_peers\":2"));
    }

    #[test]
    fn manager_debug_output() {
        let manager = FederationManager::new(test_config());
        let debug = format!("{manager:?}");
        assert!(debug.contains("FederationManager"));
    }
}
