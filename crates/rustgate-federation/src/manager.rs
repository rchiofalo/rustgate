//! Federation manager — orchestrates all federation peer connections.
//!
//! The manager owns the V1 and V2 inbound servers and outbound clients,
//! routing messages between federation peers and the local system
//! via callbacks. It does not directly depend on the Router or NATS;
//! integration with those systems happens at the wiring layer
//! (e.g., in `rustgate-server`).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use rustgate_core::{PeerId, audit};
use rustls::RootCertStore;
#[cfg(feature = "v2")]
use tokio::task::JoinHandle;
use tracing::{Instrument, debug, error, info, warn};

use crate::config::FederationConfig;
use crate::connector::{OutboundConnector, PeerConnector};
use crate::dedup::MessageDedup;
use crate::peer::{PeerHandle, PeerStatus};
use crate::replay_buffer::ReplayBuffer;
use crate::trust_store::TrustStore;
use crate::v1::{V1Client, V1Server};

/// Callback invoked for each non-heartbeat message received from a federation peer.
///
/// Arguments: (peer_id_or_cn, raw_payload_bytes)
///
/// The caller is responsible for provenance checking, format conversion,
/// and routing the message to local clients (e.g., via the Router).
///
/// NOTE: Uses `Fn` (not `AsyncFn`) because `dyn AsyncFn` is not object-safe
/// as of Rust 1.93. Async work is dispatched via `spawn_background()` inside
/// the closure body. Revisit when `dyn AsyncFn` stabilizes for trait objects.
pub type OnInbound = Arc<dyn Fn(String, Bytes) + Send + Sync>;

/// Capacity for HA peer adoption/loss event channels.
///
/// Bounds memory growth under rapid peer state changes while providing
/// enough headroom for normal churn. Events that exceed capacity are
/// dropped with a warning log.
#[cfg(feature = "ha")]
const HA_CHANNEL_CAPACITY: usize = 256;

/// Type alias for the shared replay buffers map.
type SharedReplayBuffers = Arc<Mutex<HashMap<PeerId, ReplayBuffer>>>;

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
pub struct FederationManager {
    config: FederationConfig,
    connector: Option<OutboundConnector>,
    v1_server: Option<V1Server>,
    #[cfg(feature = "v2")]
    v2_server_handle: Option<JoinHandle<Result<(), tonic::transport::Error>>>,
    clients: HashMap<PeerId, Arc<FederationClient>>,
    peers: HashMap<PeerId, Arc<PeerHandle>>,
    running: bool,

    // Connection materials stored during start() for reuse by adopt_peer()
    on_inbound: Option<OnInbound>,
    v1_dedup: Option<Arc<Mutex<MessageDedup>>>,
    #[cfg(feature = "v2")]
    v2_tls_config: Option<tonic::transport::ClientTlsConfig>,
    /// Merged CA PEM used for TLS (base CA + trust store).
    ca_pem: Option<String>,
    /// Live trust store for dynamic TLS refresh (kept alive for the
    /// `DynamicCertVerifier` closure and the REST API).
    trust_store: Option<Arc<TrustStore>>,
    /// Per-peer replay buffers for reconnection catch-up.
    replay_buffers: SharedReplayBuffers,

    // ── HA subsystem ─────────────────────────────────────────────────
    #[cfg(feature = "ha")]
    claim_manager: Option<crate::ha::claims::ClaimManager>,
    #[cfg(feature = "ha")]
    connection_registry: Option<crate::ha::registry::ConnectionRegistry>,
    #[cfg(feature = "ha")]
    ha_adopt_rx: Option<tokio::sync::mpsc::Receiver<PeerId>>,
    #[cfg(feature = "ha")]
    ha_lost_rx: Option<tokio::sync::mpsc::Receiver<PeerId>>,
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
    /// Whether HA (distributed peer ownership) is enabled.
    pub ha_enabled: bool,
    /// Pod identifier (only set when HA is active).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pod_id: Option<String>,
}

impl std::fmt::Debug for FederationManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FederationManager")
            .field("config", &self.config)
            .field("running", &self.running)
            .field("peers", &self.peers.len())
            .field("clients", &self.clients.len())
            .finish_non_exhaustive()
    }
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
            on_inbound: None,
            v1_dedup: None,
            #[cfg(feature = "v2")]
            v2_tls_config: None,
            ca_pem: None,
            trust_store: None,
            replay_buffers: Arc::new(Mutex::new(HashMap::new())),
            #[cfg(feature = "ha")]
            claim_manager: None,
            #[cfg(feature = "ha")]
            connection_registry: None,
            #[cfg(feature = "ha")]
            ha_adopt_rx: None,
            #[cfg(feature = "ha")]
            ha_lost_rx: None,
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

        // Load trust store if configured. The trust store provides dynamic
        // CA management — certificates can be added/removed at runtime via
        // the REST API, and changes take effect on the next TLS handshake
        // without restarting.
        //
        // The merged PEM (base CA + current trust store certs) is still
        // built for V2/tonic which doesn't support dynamic verification,
        // and for outbound connectors. The inbound V1 server uses a
        // DynamicCertVerifier that queries the live trust store.
        let trust_store: Option<Arc<TrustStore>> =
            if let Some(ref dir) = self.config.trust_store_dir {
                let ts = TrustStore::load_from_directory(dir)?;
                let count = ts.count()?;
                if count == 0 {
                    info!(dir = %dir.display(), "trust store loaded (empty — using base CA only)");
                } else {
                    info!(
                        dir = %dir.display(),
                        base_ca = %self.config.ca_file.display(),
                        trust_store_certs = count,
                        "loaded trust store certificates"
                    );
                }
                Some(Arc::new(ts))
            } else {
                None
            };

        // Build merged CA PEM for components that can't use dynamic verification
        // (V2/tonic, initial outbound connector, adopt_peer).
        let ca_pem = if let Some(ref ts) = trust_store {
            let mut merged = ca_pem;
            for cert_info in &ts.list_certificates()? {
                if let Some(pem_bytes) = ts.get_certificate_pem(&cert_info.common_name)? {
                    let pem_str = std::str::from_utf8(&pem_bytes).map_err(|e| {
                        anyhow::anyhow!(
                            "trust store certificate '{}' contains invalid UTF-8: {e}",
                            cert_info.common_name
                        )
                    })?;
                    merged.push('\n');
                    merged.push_str(pem_str);
                }
            }
            merged
        } else {
            ca_pem
        };

        self.trust_store = trust_store;

        // Create outbound connector (used by V1 clients).
        // When a trust store is configured, use a DynamicPeerConnector
        // that rebuilds its TLS config when CAs change.
        let connector: OutboundConnector = if let Some(ref ts) = self.trust_store {
            let ts_clone = Arc::clone(ts);
            let base_ca = ca_pem.clone().into_bytes();
            let provider = Arc::new(move || {
                let current_gen = ts_clone.generation();
                let store = ts_clone
                    .build_root_cert_store_with_base(&base_ca)
                    .unwrap_or_else(|e| {
                        warn!(
                            error = %e,
                            "failed to build root store with base CA, \
                             falling back to trust store CAs only — \
                             clients signed by the base CA may be rejected"
                        );
                        match ts_clone.build_root_cert_store() {
                            Ok(s) => s,
                            Err(e2) => {
                                error!(
                                    error = %e2,
                                    "trust store lock poisoned — returning empty root store, \
                                     CA verification is disabled"
                                );
                                RootCertStore::empty()
                            }
                        }
                    });
                (current_gen, store)
            });
            let dynamic = crate::connector::DynamicPeerConnector::new(
                &cert_pem,
                &key_pem,
                provider,
                self.config.skip_hostname_verify,
            )?;
            info!(
                "outbound federation using dynamic connector (trust store changes take effect on next connection)"
            );
            OutboundConnector::Dynamic(dynamic)
        } else {
            let static_connector = PeerConnector::from_pem(
                &cert_pem,
                &key_pem,
                &ca_pem,
                self.config.skip_hostname_verify,
            )?;
            OutboundConnector::Static(static_connector)
        };
        self.connector = Some(connector.clone());

        // Store connection materials for reuse by adopt_peer()
        self.on_inbound = Some(Arc::clone(&on_inbound));
        self.ca_pem = Some(ca_pem.clone());

        // Shared dedup cache for V1 loop detection.
        // V1 has no provenance metadata, so we detect loops by
        // remembering recently-seen (uid, time) pairs from CoT XML.
        let v1_dedup: Arc<Mutex<MessageDedup>> = Arc::new(Mutex::new(MessageDedup::new()));
        self.v1_dedup = Some(Arc::clone(&v1_dedup));

        // Start V1 inbound server if enabled
        if self.config.v1_enabled {
            let tls_config = rustgate_transport::TlsConfig::from_pem(&cert_pem, &key_pem, &ca_pem)?;

            let on_v1_server =
                Self::create_v1_dedup_callback(&v1_dedup, &on_inbound, "inbound server");

            // When a trust store is configured, use a DynamicCertVerifier
            // so that CA changes take effect on the next TLS handshake
            // without restarting the server.
            let server = if let Some(ref ts) = self.trust_store {
                let ts_clone = Arc::clone(ts);
                let base_ca = ca_pem.clone().into_bytes();
                let crls = tls_config.crls().to_vec();

                let dynamic_verifier = rustgate_transport::DynamicCertVerifier::new(
                    Box::new(move || {
                        let current_gen = ts_clone.generation();
                        let store = ts_clone
                            .build_root_cert_store_with_base(&base_ca)
                            .unwrap_or_else(|e| {
                                warn!(
                                    error = %e,
                                    "failed to build root store with base CA for inbound verifier, \
                                     falling back to trust store CAs only — \
                                     clients signed by the base CA may be rejected"
                                );
                                match ts_clone.build_root_cert_store() {
                                    Ok(s) => s,
                                    Err(e2) => {
                                        error!(
                                            error = %e2,
                                            "trust store lock poisoned — returning empty root store, \
                                             CA verification is disabled"
                                        );
                                        RootCertStore::empty()
                                    }
                                }
                            });
                        (current_gen, store)
                    }),
                    crls,
                )
                .map_err(|e| anyhow::anyhow!("build dynamic cert verifier: {e}"))?;

                let server_config =
                    tls_config.build_server_config_with_verifier(dynamic_verifier)?;
                let listener = rustgate_transport::TlsListener::bind_with_server_config(
                    self.config.v1_listen_addr,
                    Arc::new(server_config),
                    rustgate_transport::DEFAULT_MAX_HANDSHAKES,
                )
                .await?;

                info!(
                    "V1 inbound using dynamic certificate verifier (trust store changes take effect on next handshake)"
                );
                V1Server::start_with_listener(
                    listener,
                    self.config.federate_id.clone(),
                    self.config.heartbeat_interval,
                    self.config.heartbeat_timeout,
                    on_v1_server,
                    Some(self.config.max_message_size),
                )?
            } else {
                V1Server::start(
                    self.config.v1_listen_addr,
                    &tls_config,
                    self.config.federate_id.clone(),
                    self.config.heartbeat_interval,
                    self.config.heartbeat_timeout,
                    on_v1_server,
                    Some(self.config.max_message_size),
                )
                .await?
            };

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

            let on_event = Self::create_v2_event_handler(&on_inbound, &self.config.federate_id);

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

            let cfg = ClientTlsConfig::new()
                .ca_certificate(ca_cert)
                .identity(client_identity);
            self.v2_tls_config = Some(cfg.clone());
            cfg
        };

        // ── HA initialization ─────────────────────────────────────────
        #[cfg(feature = "ha")]
        if let (Some(nats_url), Some(pod_id)) = (&self.config.ha_nats_url, &self.config.pod_id) {
            let client = async_nats::connect(nats_url)
                .await
                .map_err(|e| anyhow::anyhow!("HA NATS connect to {nats_url}: {e}"))?;
            let jetstream = async_nats::jetstream::new(client);

            let mut cm = crate::ha::claims::ClaimManager::new(jetstream.clone(), pod_id.clone())
                .await
                .map_err(|e| anyhow::anyhow!("create claim manager: {e}"))?;
            let cr = crate::ha::registry::ConnectionRegistry::new(jetstream, pod_id.clone())
                .await
                .map_err(|e| anyhow::anyhow!("create connection registry: {e}"))?;

            let (adopt_tx, adopt_rx) = tokio::sync::mpsc::channel(HA_CHANNEL_CAPACITY);
            let (lost_tx, lost_rx) = tokio::sync::mpsc::channel(HA_CHANNEL_CAPACITY);
            cm.set_callbacks(
                Arc::new(move |peer_id: String| {
                    if let Err(e) = adopt_tx.try_send(PeerId::new(peer_id)) {
                        warn!(error = %e, "HA adopt channel full, dropping event");
                    }
                }),
                Arc::new(move |peer_id: String, stale_fence: u64| {
                    debug!(
                        peer_id = %peer_id,
                        stale_fence = stale_fence,
                        "claim lost, queuing disconnect"
                    );
                    if let Err(e) = lost_tx.try_send(PeerId::new(peer_id)) {
                        warn!(error = %e, "HA claim-lost channel full, dropping event");
                    }
                }),
            );

            cm.start().await;
            cr.start().await;

            info!(
                pod_id = %pod_id,
                nats_url = %nats_url,
                "HA claim manager and connection registry started"
            );

            self.claim_manager = Some(cm);
            self.connection_registry = Some(cr);
            self.ha_adopt_rx = Some(adopt_rx);
            self.ha_lost_rx = Some(lost_rx);
        }

        // Connect to all enabled outbound peers
        for peer_config in &self.config.peers {
            if !peer_config.enabled || !peer_config.is_outbound {
                continue;
            }

            // In HA mode, only connect to peers we can claim
            #[cfg(feature = "ha")]
            let ha_fencing_token = if let Some(ref cm) = self.claim_manager {
                match cm.try_claim(peer_config.id.as_str()).await {
                    Some(token) => Some(token),
                    None => {
                        info!(
                            peer_id = %peer_config.id,
                            "peer claimed by another pod, skipping"
                        );
                        continue;
                    }
                }
            } else {
                None
            };

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

            let peer = Arc::new(PeerHandle::with_circuit_breaker(
                peer_config.clone(),
                self.config.circuit_breaker_threshold,
                self.config.circuit_breaker_timeout.as_secs(),
            ));

            match peer_config.protocol_version {
                1 => {
                    let on_v1_client =
                        Self::create_v1_dedup_callback(&v1_dedup, &on_inbound, "outbound client");
                    let replay_drain = Self::create_v1_replay_drain(&self.replay_buffers);

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
                            on_message: on_v1_client,
                            replay_drain: Some(replay_drain),
                        },
                    );

                    info!(
                        peer_id = %peer_config.id,
                        addr = %addr,
                        "started V1 federation client"
                    );

                    let _ = self.peers.insert(peer_config.id.clone(), peer);
                    let _ = self.clients.insert(
                        peer_config.id.clone(),
                        Arc::new(FederationClient::V1(client)),
                    );
                }
                #[cfg(feature = "v2")]
                2 => {
                    let on_event =
                        Self::create_v2_event_handler(&on_inbound, &self.config.federate_id);
                    let replay_drain = Self::create_v2_replay_drain(&self.replay_buffers);

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
                            replay_drain: Some(replay_drain),
                            max_hops: self.config.max_hops,
                        },
                    );

                    info!(
                        peer_id = %peer_config.id,
                        addr = %addr,
                        "started V2 gRPC federation client"
                    );

                    let _ = self.peers.insert(peer_config.id.clone(), peer);
                    let _ = self.clients.insert(
                        peer_config.id.clone(),
                        Arc::new(FederationClient::V2(client)),
                    );
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

            // Register outbound connection in the HA registry
            #[cfg(feature = "ha")]
            if let Some(ref cr) = self.connection_registry
                && let Err(e) = cr
                    .register(
                        peer_config.id.as_str(),
                        crate::ha::registry::Direction::Outbound,
                        ha_fencing_token,
                    )
                    .await
            {
                warn!(
                    peer_id = %peer_config.id,
                    error = %e,
                    "failed to register connection in HA registry"
                );
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
        let span = tracing::debug_span!(
            "federation_forward",
            peer_count = self.clients.len(),
            source_groups = ?source_groups,
        );

        self.forward_inner(payload, source_groups)
            .instrument(span)
            .await
    }

    /// Inner forwarding logic, separated so the caller can `.instrument()` a
    /// span around this future without holding an `EnteredSpan` across `.await`.
    async fn forward_inner(&self, payload: Bytes, source_groups: &[String]) -> usize {
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

        // Buffer the message for replay on reconnection
        self.buffer_for_replay(&payload, source_groups);

        // Snapshot clients and peer handles so callers can release the outer
        // lock before we block on per-peer channel sends.
        let snapshot: Vec<(PeerId, Arc<FederationClient>, Arc<PeerHandle>)> = self
            .clients
            .iter()
            .filter_map(|(id, client)| {
                self.peers
                    .get(id)
                    .map(|peer| (id.clone(), Arc::clone(client), Arc::clone(peer)))
            })
            .collect();

        for (id, client, peer) in &snapshot {
            if !peer.is_available() {
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

            let result = match client.as_ref() {
                FederationClient::V1(v1) => v1.send(payload.clone()).await,
                #[cfg(feature = "v2")]
                FederationClient::V2(v2) => {
                    // Convert XML payload to FederatedEvent on first V2 peer
                    let event = match &v2_event {
                        Some(e) => e.clone(),
                        None => {
                            let mut metadata =
                                crate::provenance::FederationMetadata::new(self.config.max_hops);
                            metadata.add_hop(&self.config.federate_id, &self.config.federate_id);
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
                    if peer.record_success() {
                        info!(
                            peer_id = %id,
                            "circuit breaker recovered — peer is healthy again"
                        );
                        #[cfg(feature = "api")]
                        crate::metrics::circuit_breaker_recoveries().inc();
                        audit::federation_circuit_recovered(id);
                    }
                    sent += 1;
                }
                Err(e) => {
                    if peer.record_failure() {
                        let trips = peer.circuit_trip_count();
                        warn!(
                            peer_id = %id,
                            trips = trips,
                            "circuit breaker tripped — skipping peer until recovery timeout"
                        );
                        #[cfg(feature = "api")]
                        crate::metrics::circuit_breaker_trips().inc();
                        audit::federation_circuit_tripped(id, trips);
                    }
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

    /// Store a message in the replay buffer for all configured peers.
    ///
    /// Called during forwarding so that messages are available for replay
    /// when a peer reconnects after a disconnection.
    fn buffer_for_replay(&self, payload: &Bytes, groups: &[String]) {
        if self.config.replay_buffer_capacity == 0 {
            return;
        }
        if let Ok(mut buffers) = self.replay_buffers.lock() {
            for peer_id in self.peers.keys() {
                let buffer = buffers
                    .entry(peer_id.clone())
                    .or_insert_with(|| ReplayBuffer::new(self.config.replay_buffer_capacity));
                let _ = buffer.push(payload.clone(), groups.to_vec());
            }
        }
    }

    /// Get buffered messages for a peer since a given sequence number.
    ///
    /// Returns all messages if `since_seq` is 0 (full replay).
    /// Returns an empty vec if the peer has no replay buffer or if
    /// the buffer lock cannot be acquired.
    pub fn replay_messages(
        &self,
        peer_id: &str,
        since_seq: u64,
    ) -> Vec<crate::replay_buffer::BufferedMessage> {
        if let Ok(buffers) = self.replay_buffers.lock() {
            buffers
                .get(peer_id)
                .map(|buf| buf.messages_since(since_seq))
                .unwrap_or_default()
        } else {
            Vec::new()
        }
    }

    /// Get all buffered messages for a peer, deduplicated by payload.
    ///
    /// Used during reconnection replay to avoid resending identical
    /// messages. Returns an empty vec if the peer has no buffer.
    pub fn replay_messages_deduped(
        &self,
        peer_id: &str,
    ) -> Vec<crate::replay_buffer::BufferedMessage> {
        if let Ok(buffers) = self.replay_buffers.lock() {
            buffers
                .get(peer_id)
                .map(|buf| buf.all_messages_deduped())
                .unwrap_or_default()
        } else {
            Vec::new()
        }
    }

    /// Remove the replay buffer for a specific peer.
    ///
    /// Called when a peer is permanently disconnected or removed from
    /// configuration. Frees the memory used by its buffered messages.
    pub fn remove_replay_buffer(&self, peer_id: &str) {
        if let Ok(mut buffers) = self.replay_buffers.lock()
            && buffers.remove(peer_id).is_some()
        {
            info!(peer_id = %peer_id, "removed replay buffer for peer");
        }
    }

    /// Clear the replay buffer for a specific peer after successful replay.
    ///
    /// Called after all buffered messages have been resent on reconnection
    /// so the same messages are not replayed again on the next reconnect.
    pub fn clear_replay_buffer(&self, peer_id: &str) {
        if let Ok(mut buffers) = self.replay_buffers.lock()
            && let Some(buf) = buffers.get_mut(peer_id)
        {
            buf.clear();
        }
    }

    /// Get a shared handle to the replay buffers map.
    ///
    /// Used to create replay drain callbacks for outbound clients.
    pub fn shared_replay_buffers(&self) -> SharedReplayBuffers {
        Arc::clone(&self.replay_buffers)
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
            let Ok(client) = Arc::try_unwrap(client) else {
                warn!(peer_id = %id, "could not unwrap federation client Arc during shutdown");
                continue;
            };
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

        // Clear all replay buffers
        if let Ok(mut buffers) = self.replay_buffers.lock() {
            let count = buffers.len();
            buffers.clear();
            if count > 0 {
                info!(count, "cleared all replay buffers during shutdown");
            }
        }

        // Shut down HA subsystem (releases claims, unregisters connections)
        #[cfg(feature = "ha")]
        {
            if let Some(ref cm) = self.claim_manager {
                cm.stop().await;
                info!("HA claim manager stopped");
            }
            if let Some(ref cr) = self.connection_registry {
                cr.stop().await;
                info!("HA connection registry stopped");
            }
        }

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

    /// Get the live trust store, if one is configured.
    ///
    /// The returned `Arc<TrustStore>` is the same instance used by the
    /// `DynamicCertVerifier` — changes made via `add_certificate_from_pem`
    /// or `remove_certificate` will take effect on the next TLS handshake.
    pub fn trust_store(&self) -> Option<&Arc<TrustStore>> {
        self.trust_store.as_ref()
    }

    /// Get the aggregated federation status.
    pub fn status(&self) -> FederationStatus {
        #[cfg(feature = "v2")]
        let v2_active = self.v2_server_handle.is_some();
        #[cfg(not(feature = "v2"))]
        let v2_active = false;

        #[cfg(feature = "ha")]
        let ha_enabled = self.claim_manager.is_some();
        #[cfg(not(feature = "ha"))]
        let ha_enabled = false;

        FederationStatus {
            running: self.running,
            v1_server_active: self.v1_server.is_some(),
            v2_server_active: v2_active,
            total_peers: self.peers.len(),
            connected_peers: self.connected_peer_count(),
            peers: self.all_peer_statuses(),
            ha_enabled,
            pod_id: self.config.pod_id.clone(),
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

    // ── Helper methods for replay and callback creation ────────────────

    /// Create a replay drain closure for a V1 client.
    ///
    /// The returned closure, when called with a peer ID, returns all
    /// deduped buffered messages for that peer and clears its buffer.
    fn create_v1_replay_drain(buffers: &SharedReplayBuffers) -> crate::v1::client::ReplayDrain {
        let buffers = Arc::clone(buffers);
        Arc::new(move |peer_id: &str| {
            if let Ok(mut guard) = buffers.lock()
                && let Some(buf) = guard.get_mut(peer_id)
            {
                let messages = buf.all_messages_deduped();
                buf.clear();
                return messages;
            }
            Vec::new()
        })
    }

    /// Create a replay drain closure for a V2 client.
    ///
    /// Same as the V1 drain — returns deduped buffered messages and
    /// clears the buffer. The V2 client handles XML-to-FederatedEvent
    /// conversion during replay.
    #[cfg(feature = "v2")]
    fn create_v2_replay_drain(buffers: &SharedReplayBuffers) -> crate::v2::client::V2ReplayDrain {
        let buffers = Arc::clone(buffers);
        Arc::new(move |peer_id: &str| {
            if let Ok(mut guard) = buffers.lock()
                && let Some(buf) = guard.get_mut(peer_id)
            {
                let messages = buf.all_messages_deduped();
                buf.clear();
                return messages;
            }
            Vec::new()
        })
    }

    /// Create a V1 dedup-wrapping message callback.
    ///
    /// Returns a callback that checks incoming messages against the shared
    /// dedup cache before forwarding to the inbound handler. Duplicate
    /// messages (same UID + timestamp) are silently dropped for loop detection.
    fn create_v1_dedup_callback(
        dedup: &Arc<Mutex<MessageDedup>>,
        on_inbound: &OnInbound,
        context: &str,
    ) -> crate::v1::client::OnMessage {
        let dedup = Arc::clone(dedup);
        let on_inbound = Arc::clone(on_inbound);
        let context = context.to_owned();
        Arc::new(move |peer_id, data| {
            if let Ok(mut guard) = dedup.lock()
                && guard.is_duplicate(&data)
            {
                tracing::debug!(
                    peer_id = %peer_id,
                    context = %context,
                    "dropped duplicate V1 message (loop detection)"
                );
                return;
            }
            on_inbound(peer_id, data);
        })
    }

    /// Create a V2 event handler callback.
    ///
    /// Returns a callback that checks provenance metadata (loop detection and
    /// hop limits), then converts `FederatedEvent` payloads to XML before
    /// forwarding to the inbound handler.
    #[cfg(feature = "v2")]
    fn create_v2_event_handler(
        on_inbound: &OnInbound,
        federate_id: &str,
    ) -> crate::v2::client::OnEvent {
        let on_event_inbound = Arc::clone(on_inbound);
        let federate_id = federate_id.to_owned();
        Arc::new(move |event, peer_id| {
            // Check provenance for loops and hop limits
            let metadata = crate::v2::convert::extract_metadata(&event);
            if metadata.should_drop(&federate_id) {
                warn!(
                    federate = %federate_id,
                    peer = %peer_id,
                    hops = metadata.current_hops,
                    max_hops = metadata.max_hops,
                    "dropped inbound V2 event (loop or hop limit)"
                );
                return;
            }

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
            } else if let Some(ref contact) = event.contact
                && let Some(xml) = crate::v2::convert::contact_list_entry_to_xml(contact)
            {
                on_event_inbound(peer_id, Bytes::from(xml));
            }
        })
    }

    // ── HA peer management ───────────────────────────────────────────

    /// Connect a single outbound peer, creating its client and PeerHandle.
    ///
    /// Requires that `start()` has been called (connector, on_inbound, etc. are set).
    /// Used by both `start()` loop (indirectly) and `adopt_peer()`.
    #[cfg(feature = "ha")]
    fn connect_outbound_peer(
        &mut self,
        peer_config: &crate::config::PeerConfig,
    ) -> anyhow::Result<()> {
        let connector = self
            .connector
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("connector not initialized (call start() first)"))?
            .clone();
        let on_inbound = self
            .on_inbound
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("on_inbound not set (call start() first)"))?
            .clone();
        let v1_dedup = self
            .v1_dedup
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("v1_dedup not set (call start() first)"))?
            .clone();

        let addr: std::net::SocketAddr = peer_config
            .address
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid peer address '{}': {e}", peer_config.address))?;

        let peer = Arc::new(PeerHandle::with_circuit_breaker(
            peer_config.clone(),
            self.config.circuit_breaker_threshold,
            self.config.circuit_breaker_timeout.as_secs(),
        ));

        match peer_config.protocol_version {
            1 => {
                let on_v1_client =
                    Self::create_v1_dedup_callback(&v1_dedup, &on_inbound, "outbound client");
                let replay_drain = Self::create_v1_replay_drain(&self.replay_buffers);

                let client = V1Client::start(
                    Arc::clone(&peer),
                    crate::v1::client::V1ClientConfig {
                        connector,
                        addr,
                        server_name: addr.ip().to_string(),
                        server_uid: self.config.federate_id.clone(),
                        heartbeat_interval: self.config.heartbeat_interval,
                        heartbeat_timeout: self.config.heartbeat_timeout,
                        reconnect_delay: self.config.reconnect_delay,
                        max_reconnects: self.config.max_reconnects,
                        on_message: on_v1_client,
                        replay_drain: Some(replay_drain),
                    },
                );

                info!(
                    peer_id = %peer_config.id,
                    addr = %addr,
                    "started V1 federation client (adoption)"
                );

                let _ = self.peers.insert(peer_config.id.clone(), peer);
                let _ = self.clients.insert(
                    peer_config.id.clone(),
                    Arc::new(FederationClient::V1(client)),
                );
            }
            #[cfg(feature = "v2")]
            2 => {
                let v2_tls = self
                    .v2_tls_config
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("v2_tls_config not set"))?
                    .clone();

                let on_event = Self::create_v2_event_handler(&on_inbound, &self.config.federate_id);
                let replay_drain = Self::create_v2_replay_drain(&self.replay_buffers);

                let client = crate::v2::client::V2Client::start(
                    Arc::clone(&peer),
                    crate::v2::client::V2ClientConfig {
                        address: peer_config.address.clone(),
                        tls_config: v2_tls,
                        federate_id: self.config.federate_id.clone(),
                        groups: peer_config.groups.clone(),
                        health_interval: self.config.health_check_interval,
                        reconnect_delay: self.config.reconnect_delay,
                        max_reconnects: self.config.max_reconnects,
                        on_event,
                        replay_drain: Some(replay_drain),
                        max_hops: self.config.max_hops,
                    },
                );

                info!(
                    peer_id = %peer_config.id,
                    addr = %addr,
                    "started V2 gRPC federation client (adoption)"
                );

                let _ = self.peers.insert(peer_config.id.clone(), peer);
                let _ = self.clients.insert(
                    peer_config.id.clone(),
                    Arc::new(FederationClient::V2(client)),
                );
            }
            other => {
                return Err(anyhow::anyhow!(
                    "unsupported protocol version {other} for peer {}",
                    peer_config.id
                ));
            }
        }

        Ok(())
    }

    /// Adopt an orphaned peer whose claim expired (another pod died).
    ///
    /// Claims the peer, waits the adoption delay (gives the remote time to clean up),
    /// then creates a new outbound connection. Registers the connection in the
    /// HA registry.
    #[cfg(feature = "ha")]
    pub async fn adopt_peer(&mut self, peer_id: &PeerId) -> anyhow::Result<()> {
        // Find the peer config
        let peer_config = self
            .config
            .peers
            .iter()
            .find(|p| p.id == *peer_id && p.enabled && p.is_outbound)
            .cloned()
            .ok_or_else(|| {
                anyhow::anyhow!("no enabled outbound peer config found for '{peer_id}'")
            })?;

        // Already connected?
        if self.clients.contains_key(peer_id.as_str()) {
            info!(peer_id = %peer_id, "peer already connected, skipping adoption");
            return Ok(());
        }

        // Try to claim the peer and get the fencing token
        let fencing_token = if let Some(ref cm) = self.claim_manager {
            cm.try_claim(peer_id.as_str()).await
        } else {
            return Err(anyhow::anyhow!("HA claim manager not initialized"));
        };

        let fencing_token = match fencing_token {
            Some(token) => token,
            None => {
                info!(peer_id = %peer_id, "peer claimed by another pod during adoption");
                return Ok(());
            }
        };

        // Wait adoption delay + jitter to let the remote clean up
        let delay = crate::ha::claims::ClaimManager::adopt_delay()
            + crate::ha::claims::ClaimManager::adoption_jitter();
        info!(
            peer_id = %peer_id,
            fence = fencing_token,
            delay_secs = delay.as_secs(),
            "waiting adoption delay before connecting"
        );
        tokio::time::sleep(delay).await;

        // Re-validate fencing token after adoption delay (split-brain guard).
        // During the delay, another pod may have claimed this peer with a
        // newer token. If so, abort adoption to avoid duplicate connections.
        if let Some(ref cm) = self.claim_manager
            && !cm.is_token_valid(peer_id.as_str(), fencing_token).await
        {
            warn!(
                peer_id = %peer_id,
                fence = fencing_token,
                "fencing token became stale during adoption delay, aborting"
            );
            return Ok(());
        }

        // Connect
        self.connect_outbound_peer(&peer_config)?;

        // Register in HA connection registry with fencing token
        if let Some(ref cr) = self.connection_registry
            && let Err(e) = cr
                .register(
                    peer_id.as_str(),
                    crate::ha::registry::Direction::Outbound,
                    Some(fencing_token),
                )
                .await
        {
            warn!(peer_id = %peer_id, error = %e, "failed to register adopted connection");
        }

        info!(peer_id = %peer_id, "peer adopted successfully");
        Ok(())
    }

    /// Disconnect a peer whose claim was lost to another pod.
    ///
    /// Stops the outbound client, removes the peer handle, unregisters from the
    /// HA connection registry, and releases the claim.
    #[cfg(feature = "ha")]
    pub async fn disconnect_peer(&mut self, peer_id: &PeerId) {
        // Remove and shut down the client
        if let Some(client) = self.clients.remove(peer_id.as_str()) {
            match Arc::try_unwrap(client) {
                Ok(FederationClient::V1(mut v1)) => {
                    v1.shutdown().await;
                    info!(peer_id = %peer_id, "V1 client stopped (claim lost)");
                }
                #[cfg(feature = "v2")]
                Ok(FederationClient::V2(mut v2)) => {
                    v2.shutdown().await;
                    info!(peer_id = %peer_id, "V2 client stopped (claim lost)");
                }
                Err(_) => {
                    warn!(peer_id = %peer_id, "could not unwrap federation client Arc during disconnect");
                }
            }
        }

        let _ = self.peers.remove(peer_id.as_str());

        // Clean up the replay buffer for this peer
        self.remove_replay_buffer(peer_id.as_str());

        // Unregister from connection registry
        if let Some(ref cr) = self.connection_registry
            && let Err(e) = cr.unregister(peer_id.as_str()).await
        {
            warn!(peer_id = %peer_id, error = %e, "failed to unregister connection");
        }

        // Release claim
        if let Some(ref cm) = self.claim_manager
            && let Err(e) = cm.release(peer_id.as_str()).await
        {
            warn!(peer_id = %peer_id, error = %e, "failed to release claim");
        }
    }

    /// Take the HA event receivers (adoption and claim-lost channels).
    ///
    /// Returns `(adopt_rx, claim_lost_rx)`. Can only be called once — subsequent
    /// calls return `(None, None)`. The caller (typically main.rs) spawns tasks
    /// that read from these channels and call `adopt_peer()` / `disconnect_peer()`.
    #[cfg(feature = "ha")]
    pub fn take_ha_receivers(
        &mut self,
    ) -> (
        Option<tokio::sync::mpsc::Receiver<PeerId>>,
        Option<tokio::sync::mpsc::Receiver<PeerId>>,
    ) {
        (self.ha_adopt_rx.take(), self.ha_lost_rx.take())
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
            trust_store_dir: None,
            cert_file: PathBuf::from("/nonexistent/cert.pem"),
            key_file: PathBuf::from("/nonexistent/key.pem"),
            ca_file: PathBuf::from("/nonexistent/ca.pem"),
            jwt_secret: None,
            jwt_expiry_secs: 3600,
            circuit_breaker_threshold: 5,
            circuit_breaker_timeout: Duration::from_secs(60),
            replay_buffer_capacity: 1000,
            pod_id: None,
            ha_nats_url: None,
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
            jwt_token: None,
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
    async fn start_with_trust_store_dir() {
        use rustgate_test_utils::certs::TestCa;

        let ca = TestCa::new("Base CA");
        let server_cert = ca.issue_server_cert("localhost", &["localhost"]);

        let tmp = tempfile::tempdir().expect("tempdir");
        let cert_path = tmp.path().join("cert.pem");
        let key_path = tmp.path().join("key.pem");
        let ca_path = tmp.path().join("ca.pem");
        let trust_dir = tmp.path().join("trust-store");
        std::fs::create_dir_all(&trust_dir).expect("create trust dir");

        std::fs::write(&cert_path, &server_cert.cert_pem).expect("write cert");
        std::fs::write(&key_path, &server_cert.key_pem).expect("write key");
        std::fs::write(&ca_path, &ca.cert_pem).expect("write ca");

        // Write an additional CA to the trust store directory
        let extra_ca = TestCa::new("Extra Federation CA");
        std::fs::write(trust_dir.join("extra-ca.pem"), &extra_ca.cert_pem).expect("write extra ca");

        let config = FederationConfig {
            federate_id: "test-trust-store".into(),
            v1_enabled: true,
            v1_listen_addr: "127.0.0.1:0".parse().expect("valid addr"),
            cert_file: cert_path,
            key_file: key_path,
            ca_file: ca_path,
            trust_store_dir: Some(trust_dir),
            ..test_config()
        };

        let mut manager = FederationManager::new(config);
        let on_inbound: OnInbound = Arc::new(|_cn, _data| {});

        // Start should succeed — trust store dir loaded and merged
        manager
            .start(on_inbound)
            .await
            .expect("start with trust store");
        assert!(manager.is_running());
        assert!(manager.status().v1_server_active);

        manager.shutdown().await;
    }

    #[tokio::test]
    async fn start_with_empty_trust_store_dir() {
        use rustgate_test_utils::certs::TestCa;

        let ca = TestCa::new("Base CA");
        let server_cert = ca.issue_server_cert("localhost", &["localhost"]);

        let tmp = tempfile::tempdir().expect("tempdir");
        let cert_path = tmp.path().join("cert.pem");
        let key_path = tmp.path().join("key.pem");
        let ca_path = tmp.path().join("ca.pem");
        let trust_dir = tmp.path().join("empty-trust-store");

        std::fs::write(&cert_path, &server_cert.cert_pem).expect("write cert");
        std::fs::write(&key_path, &server_cert.key_pem).expect("write key");
        std::fs::write(&ca_path, &ca.cert_pem).expect("write ca");

        // Empty trust store dir (will be created by TrustStore::load_from_directory)
        let config = FederationConfig {
            federate_id: "test-empty-trust-store".into(),
            v1_enabled: true,
            v1_listen_addr: "127.0.0.1:0".parse().expect("valid addr"),
            cert_file: cert_path,
            key_file: key_path,
            ca_file: ca_path,
            trust_store_dir: Some(trust_dir),
            ..test_config()
        };

        let mut manager = FederationManager::new(config);
        let on_inbound: OnInbound = Arc::new(|_cn, _data| {});

        // Start should succeed — empty trust store just uses base CA
        manager
            .start(on_inbound)
            .await
            .expect("start with empty trust store");
        assert!(manager.is_running());

        manager.shutdown().await;
    }

    #[tokio::test]
    async fn trust_store_certs_used_in_tls_verification() {
        use rustgate_test_utils::certs::TestCa;
        use rustgate_transport::{TlsConfig, TlsListener};

        // Two separate CAs — base and extra
        let base_ca = TestCa::new("Base CA");
        let extra_ca = TestCa::new("Extra Federation CA");

        // Server cert signed by base CA
        let server_cert = base_ca.issue_server_cert("localhost", &["localhost"]);
        // Client cert signed by extra CA (not base CA!)
        let client_cert = extra_ca.issue_client_cert("trust-store-client", &["Alpha"]);

        // Build merged CA PEM (simulating what FederationManager does with trust store)
        let trust_store = crate::trust_store::TrustStore::new(None);
        let _ = trust_store
            .add_certificate_from_pem(extra_ca.cert_pem.as_bytes())
            .expect("add extra CA to trust store");

        let mut merged_ca = base_ca.cert_pem.clone();
        for info in trust_store.list_certificates().expect("list certificates") {
            if let Some(pem) = trust_store
                .get_certificate_pem(&info.common_name)
                .expect("get certificate pem")
            {
                merged_ca.push('\n');
                merged_ca.push_str(std::str::from_utf8(&pem).expect("PEM is valid UTF-8"));
            }
        }

        // Server uses merged CA — should accept clients from both CAs
        let tls_config =
            TlsConfig::from_pem(&server_cert.cert_pem, &server_cert.key_pem, &merged_ca)
                .expect("tls config with merged CA");
        let listener = TlsListener::bind("127.0.0.1:0", &tls_config)
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");

        let handle = tokio::spawn(async move {
            let _session = listener.accept().await.expect("accept");
            tokio::time::sleep(Duration::from_secs(5)).await;
        });

        // Connect with client cert signed by extra CA — should succeed
        let mut client_ca = base_ca.cert_pem.clone();
        client_ca.push('\n');
        client_ca.push_str(&extra_ca.cert_pem);

        let connector = crate::connector::PeerConnector::from_pem(
            &client_cert.cert_pem,
            &client_cert.key_pem,
            &client_ca,
            false,
        )
        .expect("create connector");

        let result = connector.connect(addr, "localhost").await;
        assert!(
            result.is_ok(),
            "client cert from trust store CA should be accepted: {:?}",
            result.err()
        );

        handle.abort();
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
            ha_enabled: false,
            pod_id: None,
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

    #[test]
    fn ha_fields_none_by_default() {
        let config = test_config();
        assert!(config.pod_id.is_none());
        assert!(config.ha_nats_url.is_none());

        let manager = FederationManager::new(config);
        let status = manager.status();
        assert!(!status.ha_enabled);
        assert!(status.pod_id.is_none());
    }

    #[test]
    fn ha_status_shows_pod_id_from_config() {
        let config = FederationConfig {
            pod_id: Some("pod-abc".into()),
            ..test_config()
        };
        let manager = FederationManager::new(config);
        let status = manager.status();
        // HA is not enabled (no claim manager started) but pod_id is visible
        assert!(!status.ha_enabled);
        assert_eq!(status.pod_id.as_deref(), Some("pod-abc"));
    }

    #[test]
    fn ha_status_serialization_omits_null_pod_id() {
        let status = FederationStatus {
            running: true,
            v1_server_active: false,
            v2_server_active: false,
            total_peers: 0,
            connected_peers: 0,
            peers: vec![],
            ha_enabled: false,
            pod_id: None,
        };
        let json = serde_json::to_string(&status).expect("serialize");
        // pod_id should be omitted when None due to skip_serializing_if
        assert!(!json.contains("pod_id"));
        assert!(json.contains("\"ha_enabled\":false"));
    }

    #[test]
    fn ha_status_serialization_includes_pod_id() {
        let status = FederationStatus {
            running: true,
            v1_server_active: false,
            v2_server_active: false,
            total_peers: 0,
            connected_peers: 0,
            peers: vec![],
            ha_enabled: true,
            pod_id: Some("my-pod".into()),
        };
        let json = serde_json::to_string(&status).expect("serialize");
        assert!(json.contains("\"pod_id\":\"my-pod\""));
        assert!(json.contains("\"ha_enabled\":true"));
    }

    #[cfg(feature = "ha")]
    #[test]
    fn take_ha_receivers_returns_none_without_start() {
        let mut manager = FederationManager::new(test_config());
        let (adopt, lost) = manager.take_ha_receivers();
        assert!(adopt.is_none());
        assert!(lost.is_none());
    }

    /// Verify that concurrent forward() calls via read locks do not deadlock
    /// or panic when interleaved with peer mutations via write locks.
    ///
    /// This exercises the snapshot pattern in forward(): by collecting
    /// Arc clones of clients/peers before iterating, forward() releases
    /// its references to the inner HashMaps so the outer RwLock can be
    /// dropped before the async sends complete.
    #[tokio::test]
    async fn forward_snapshot_handles_concurrent_peer_churn() {
        use rustgate_test_utils::certs::TestCa;
        use tokio::sync::RwLock;

        let ca = TestCa::new("Test CA");
        let client_cert = ca.issue_client_cert("federation-client", &["Alpha"]);

        let tmp = tempfile::tempdir().expect("tempdir");
        let cert_path = tmp.path().join("cert.pem");
        let key_path = tmp.path().join("key.pem");
        let ca_path = tmp.path().join("ca.pem");

        std::fs::write(&cert_path, &client_cert.cert_pem).expect("write cert");
        std::fs::write(&key_path, &client_cert.key_pem).expect("write key");
        std::fs::write(&ca_path, &ca.cert_pem).expect("write ca");

        // Create a manager with several peers to churn through.
        let peers: Vec<PeerConfig> = (0..5)
            .map(|i| test_peer_config(&format!("peer-{i}"), vec!["Alpha".into()]))
            .collect();

        let config = FederationConfig {
            federate_id: "churn-test".into(),
            v1_enabled: false,
            peers,
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
        assert_eq!(manager.peer_count(), 5);

        let manager = Arc::new(RwLock::new(manager));

        // Spawn concurrent forward tasks (read locks).
        let mut forward_handles = Vec::new();
        for i in 0..10 {
            let mgr = Arc::clone(&manager);
            forward_handles.push(tokio::spawn(async move {
                // Small stagger so forwards overlap with mutations.
                tokio::time::sleep(Duration::from_millis(i * 5)).await;
                let guard = mgr.read().await;
                // Sends will fail (no remote server), but should not panic.
                let _sent = guard
                    .forward(Bytes::from("<event/>"), &["Alpha".into()])
                    .await;
            }));
        }

        // Spawn concurrent peer mutation tasks (write locks).
        // Directly remove clients and peers from the maps to simulate churn
        // without requiring the HA feature gate on disconnect_peer().
        let mut mutate_handles = Vec::new();
        for i in 0..3u64 {
            let mgr = Arc::clone(&manager);
            let peer_id = format!("peer-{i}");
            mutate_handles.push(tokio::spawn(async move {
                // Stagger so some mutations overlap with forwards.
                tokio::time::sleep(Duration::from_millis(10 + i * 10)).await;
                let mut guard = mgr.write().await;
                // Simulate peer churn: remove the client and peer handle.
                let _ = guard.clients.remove(peer_id.as_str());
                let _ = guard.peers.remove(peer_id.as_str());
            }));
        }

        // All tasks should complete without deadlock or panic.
        for handle in forward_handles {
            handle.await.expect("forward task should not panic");
        }
        for handle in mutate_handles {
            handle.await.expect("mutation task should not panic");
        }

        // Verify peers were actually removed.
        let guard = manager.read().await;
        assert_eq!(
            guard.peer_count(),
            2,
            "3 of 5 peers should have been disconnected"
        );

        // Forward still works after churn.
        let _sent = guard
            .forward(Bytes::from("<event/>"), &["Alpha".into()])
            .await;

        drop(guard);
        manager.write().await.shutdown().await;
    }

    // ── Replay buffer tests ─────────────────────────────────────────

    #[test]
    fn buffer_for_replay_populates_per_peer() {
        let mut config = test_config();
        config.replay_buffer_capacity = 100;
        let mut manager = FederationManager::new(config);

        // Manually add peers so buffer_for_replay has targets
        let peer1 = Arc::new(PeerHandle::new(test_peer_config(
            "peer-1",
            vec!["Alpha".into()],
        )));
        let peer2 = Arc::new(PeerHandle::new(test_peer_config(
            "peer-2",
            vec!["Beta".into()],
        )));
        let _ = manager.peers.insert("peer-1".into(), peer1);
        let _ = manager.peers.insert("peer-2".into(), peer2);

        manager.buffer_for_replay(&Bytes::from("msg1"), &["Alpha".into()]);
        manager.buffer_for_replay(&Bytes::from("msg2"), &["Beta".into()]);

        let msgs1 = manager.replay_messages("peer-1", 0);
        assert_eq!(msgs1.len(), 2);

        let msgs2 = manager.replay_messages("peer-2", 0);
        assert_eq!(msgs2.len(), 2);
    }

    #[test]
    fn buffer_for_replay_skipped_when_capacity_zero() {
        let mut config = test_config();
        config.replay_buffer_capacity = 0;
        let mut manager = FederationManager::new(config);

        let peer = Arc::new(PeerHandle::new(test_peer_config(
            "peer-1",
            vec!["Alpha".into()],
        )));
        let _ = manager.peers.insert("peer-1".into(), peer);

        manager.buffer_for_replay(&Bytes::from("msg1"), &["Alpha".into()]);

        let msgs = manager.replay_messages("peer-1", 0);
        assert!(msgs.is_empty());
    }

    #[test]
    fn remove_replay_buffer_cleans_up() {
        let mut config = test_config();
        config.replay_buffer_capacity = 100;
        let mut manager = FederationManager::new(config);

        let peer = Arc::new(PeerHandle::new(test_peer_config(
            "peer-1",
            vec!["Alpha".into()],
        )));
        let _ = manager.peers.insert("peer-1".into(), peer);

        manager.buffer_for_replay(&Bytes::from("msg1"), &["Alpha".into()]);
        assert_eq!(manager.replay_messages("peer-1", 0).len(), 1);

        manager.remove_replay_buffer("peer-1");
        assert!(manager.replay_messages("peer-1", 0).is_empty());
    }

    #[test]
    fn clear_replay_buffer_empties_but_keeps_entry() {
        let mut config = test_config();
        config.replay_buffer_capacity = 100;
        let mut manager = FederationManager::new(config);

        let peer = Arc::new(PeerHandle::new(test_peer_config(
            "peer-1",
            vec!["Alpha".into()],
        )));
        let _ = manager.peers.insert("peer-1".into(), peer);

        manager.buffer_for_replay(&Bytes::from("msg1"), &["Alpha".into()]);
        manager.buffer_for_replay(&Bytes::from("msg2"), &["Alpha".into()]);
        assert_eq!(manager.replay_messages("peer-1", 0).len(), 2);

        manager.clear_replay_buffer("peer-1");
        assert!(manager.replay_messages("peer-1", 0).is_empty());

        // Buffer entry still exists — new messages can be buffered
        manager.buffer_for_replay(&Bytes::from("msg3"), &["Alpha".into()]);
        assert_eq!(manager.replay_messages("peer-1", 0).len(), 1);
    }

    #[test]
    fn replay_messages_deduped_removes_duplicates() {
        let mut config = test_config();
        config.replay_buffer_capacity = 100;
        let mut manager = FederationManager::new(config);

        let peer = Arc::new(PeerHandle::new(test_peer_config(
            "peer-1",
            vec!["Alpha".into()],
        )));
        let _ = manager.peers.insert("peer-1".into(), peer);

        manager.buffer_for_replay(&Bytes::from("msg1"), &["Alpha".into()]);
        manager.buffer_for_replay(&Bytes::from("msg1"), &["Alpha".into()]); // duplicate
        manager.buffer_for_replay(&Bytes::from("msg2"), &["Beta".into()]);

        let deduped = manager.replay_messages_deduped("peer-1");
        assert_eq!(deduped.len(), 2);
        assert_eq!(deduped[0].payload, Bytes::from("msg1"));
        assert_eq!(deduped[1].payload, Bytes::from("msg2"));
    }

    #[test]
    fn v1_replay_drain_returns_and_clears() {
        let mut config = test_config();
        config.replay_buffer_capacity = 100;
        let manager = FederationManager::new(config);

        // Manually populate the buffer
        {
            let mut buffers = manager.replay_buffers.lock().expect("lock");
            let buf = buffers
                .entry("peer-1".into())
                .or_insert_with(|| ReplayBuffer::new(100));
            let _ = buf.push(Bytes::from("msg-a"), vec!["Alpha".into()]);
            let _ = buf.push(Bytes::from("msg-b"), vec!["Beta".into()]);
        }

        let drain = FederationManager::create_v1_replay_drain(&manager.replay_buffers);

        // First drain returns all messages
        let messages = drain("peer-1");
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].payload, Bytes::from("msg-a"));
        assert_eq!(messages[1].payload, Bytes::from("msg-b"));

        // Second drain returns empty (buffer was cleared)
        let messages = drain("peer-1");
        assert!(messages.is_empty());
    }

    #[tokio::test]
    async fn shutdown_clears_all_replay_buffers() {
        let mut config = test_config();
        config.replay_buffer_capacity = 100;
        let mut manager = FederationManager::new(config);

        // Manually populate replay buffers
        {
            let mut buffers = manager.replay_buffers.lock().expect("lock");
            let buf1 = buffers
                .entry("peer-1".into())
                .or_insert_with(|| ReplayBuffer::new(100));
            let _ = buf1.push(Bytes::from("msg1"), vec![]);

            let buf2 = buffers
                .entry("peer-2".into())
                .or_insert_with(|| ReplayBuffer::new(100));
            let _ = buf2.push(Bytes::from("msg2"), vec![]);
        }

        manager.running = true; // simulate running state
        manager.shutdown().await;

        let buffers = manager.replay_buffers.lock().expect("lock");
        assert!(buffers.is_empty());
    }
}
