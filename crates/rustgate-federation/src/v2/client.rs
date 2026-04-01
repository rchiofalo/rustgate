//! V2 federation gRPC client with 5-stream handshake.
//!
//! Implements the outbound gRPC federation connection that follows the
//! TAK Server V2 federation protocol. The client establishes multiple
//! concurrent streams (group exchange, event streaming, health checks)
//! and reconnects automatically on failure.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, watch};
use tonic::Request;
use tonic::transport::{Channel, ClientTlsConfig, Endpoint, Uri};
use tracing::{debug, error, info, warn};

use super::proto::figpb;
use super::proto::figpb::federated_channel_client::FederatedChannelClient;
use crate::peer::{PeerHandle, PeerState};
use crate::provenance;
use crate::reconnect::{backoff_delay, should_stop_reconnecting};

/// Callback invoked when a FederatedEvent is received from the remote peer.
pub type OnEvent = Arc<dyn Fn(figpb::FederatedEvent, String) + Send + Sync>;

/// Configuration for a V2 federation gRPC client.
pub struct V2ClientConfig {
    pub address: String,
    pub tls_config: ClientTlsConfig,
    pub federate_id: String,
    pub groups: Vec<String>,
    pub health_interval: Duration,
    pub reconnect_delay: Duration,
    pub max_reconnects: i32,
    pub on_event: OnEvent,
}

impl fmt::Debug for V2ClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("V2ClientConfig")
            .field("address", &self.address)
            .field("federate_id", &self.federate_id)
            .field("groups", &self.groups)
            .field("health_interval", &self.health_interval)
            .field("reconnect_delay", &self.reconnect_delay)
            .field("max_reconnects", &self.max_reconnects)
            .finish_non_exhaustive()
    }
}

/// V2 gRPC outbound federation client.
///
/// Maintains a persistent gRPC connection to a remote federation peer,
/// performs the 5-stream handshake, and automatically reconnects on failure.
#[derive(Debug)]
pub struct V2Client {
    /// Background task handle.
    task_handle: Option<tokio::task::JoinHandle<()>>,
    /// Shutdown signal sender.
    shutdown_tx: Option<watch::Sender<bool>>,
    /// Channel for sending outbound events to the remote peer.
    outbound_tx: mpsc::Sender<figpb::FederatedEvent>,
    /// Peer state tracking.
    peer: Arc<PeerHandle>,
}

impl V2Client {
    /// Start a new V2 gRPC client that connects to the given address.
    ///
    /// The client spawns a background task that:
    /// 1. Establishes a gRPC channel over TLS
    /// 2. Performs the 5-stream handshake (groups, events, health)
    /// 3. Reconnects automatically on failure with exponential backoff
    pub fn start(peer: Arc<PeerHandle>, config: V2ClientConfig) -> Self {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (outbound_tx, outbound_rx) = mpsc::channel::<figpb::FederatedEvent>(256);

        let peer_clone = Arc::clone(&peer);
        let task_handle = tokio::spawn(connection_loop(
            peer_clone,
            config,
            outbound_rx,
            shutdown_rx,
        ));

        Self {
            task_handle: Some(task_handle),
            shutdown_tx: Some(shutdown_tx),
            outbound_tx,
            peer,
        }
    }

    /// Send a FederatedEvent to the remote peer.
    pub async fn send(&self, event: figpb::FederatedEvent) -> anyhow::Result<()> {
        self.outbound_tx
            .send(event)
            .await
            .map_err(|_| anyhow::anyhow!("outbound channel closed"))?;
        self.peer.record_sent();
        Ok(())
    }

    /// Get a reference to the peer handle.
    pub fn peer(&self) -> &PeerHandle {
        &self.peer
    }

    /// Shut down the client and wait for the background task to finish.
    pub async fn shutdown(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(true);
        }
        if let Some(handle) = self.task_handle.take() {
            let _ = handle.await;
        }
        self.peer.set_state(PeerState::Disconnected);
    }
}

/// Build a Subscription message identifying ourselves.
fn our_subscription(federate_id: &str) -> figpb::Subscription {
    let server_uid = provenance::deterministic_uuid(federate_id);
    figpb::Subscription {
        identity: Some(figpb::Identity {
            name: federate_id.to_string(),
            uid: server_uid,
            description: String::new(),
            r#type: figpb::identity::ConnectionType::FederationHubClient as i32,
            server_id: federate_id.to_string(),
        }),
        filter: String::new(),
        version: Some(figpb::TakServerVersion {
            major: 5,
            minor: 0,
            patch: 0,
            branch: "release".into(),
            variant: "rustgate".into(),
        }),
    }
}

/// Calculate post-disconnect cooldown before reconnecting.
///
/// TAK Server's federation cleanup can take 30–60 seconds to purge a stale
/// federate entry. Reconnecting too quickly triggers "duplicate federate
/// connection" rejections. The cooldown is 4× the base reconnect delay,
/// with a minimum of 60 seconds.
pub(crate) fn post_disconnect_cooldown(reconnect_delay: Duration) -> Duration {
    let cooldown = reconnect_delay.saturating_mul(4);
    let min_cooldown = Duration::from_secs(60);
    cooldown.max(min_cooldown)
}

/// Main connection loop with automatic reconnection.
async fn connection_loop(
    peer: Arc<PeerHandle>,
    config: V2ClientConfig,
    mut outbound_rx: mpsc::Receiver<figpb::FederatedEvent>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let mut reconnect_count: u32 = 0;

    loop {
        // Check shutdown
        if *shutdown_rx.borrow() {
            info!(peer = %peer.id, "shutdown requested, exiting connection loop");
            break;
        }

        // Check reconnect limit
        if should_stop_reconnecting(config.max_reconnects, reconnect_count) {
            info!(
                peer = %peer.id,
                max = config.max_reconnects,
                "max reconnect attempts reached"
            );
            peer.set_state(PeerState::Disconnected);
            break;
        }

        if reconnect_count > 0 {
            peer.set_state(PeerState::Reconnecting);
            let _ = peer.increment_reconnect_count();
            let delay = backoff_delay(config.reconnect_delay, reconnect_count);
            info!(
                peer = %peer.id,
                attempt = reconnect_count,
                delay = ?delay,
                "reconnecting after delay"
            );

            tokio::select! {
                _ = tokio::time::sleep(delay) => {}
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
            }
        }

        peer.set_state(PeerState::Connecting);
        info!(peer = %peer.id, address = %config.address, "connecting to remote peer");

        // Build the gRPC channel
        let channel = match build_channel(&config.address, config.tls_config.clone()).await {
            Ok(ch) => ch,
            Err(e) => {
                rustgate_core::audit::federation_connect_failed(&peer.id, &e.to_string());
                warn!(peer = %peer.id, error = %e, "failed to build gRPC channel");
                peer.set_error(&e.to_string());
                reconnect_count += 1;
                continue;
            }
        };

        let client = FederatedChannelClient::new(channel);

        // Run the 5-stream handshake and event loop
        let result = run_streams(&peer, client, &config, &mut outbound_rx, &mut shutdown_rx).await;

        match result {
            Ok(()) => {
                rustgate_core::audit::federation_peer_disconnected(&peer.id, "clean shutdown");
                info!(peer = %peer.id, "streams closed gracefully");
            }
            Err(e) => {
                rustgate_core::audit::federation_peer_disconnected(&peer.id, &e.to_string());
                warn!(peer = %peer.id, error = %e, "streams failed");
                peer.set_error(&e.to_string());
            }
        }

        peer.set_state(PeerState::Disconnected);

        // Post-disconnect cooldown: wait before reconnecting to give the remote
        // TAK Server time to purge the stale federate entry. Without this delay,
        // rapid reconnection triggers "duplicate federate connection" rejections
        // on the remote side. Use 4× the base reconnect delay, minimum 60s.
        let cooldown = post_disconnect_cooldown(config.reconnect_delay);
        info!(
            peer = %peer.id,
            cooldown = ?cooldown,
            "post-disconnect cooldown before reconnect"
        );

        tokio::select! {
            _ = tokio::time::sleep(cooldown) => {}
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    break;
                }
            }
        }

        reconnect_count += 1;
    }
}

/// Build a tonic gRPC channel with TLS.
async fn build_channel(address: &str, tls_config: ClientTlsConfig) -> anyhow::Result<Channel> {
    // Parse the address and ensure it has the https scheme
    let uri: Uri = format!("https://{address}")
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid address: {e}"))?;

    let endpoint = Endpoint::from(uri)
        .tls_config(tls_config)
        .map_err(|e| anyhow::anyhow!("TLS config error: {e}"))?
        .connect_timeout(Duration::from_secs(30))
        .timeout(Duration::from_secs(300))
        // gRPC keepalive: ping every 10s, timeout after 5s, allow while idle.
        // Matches TAK Server federation protocol expectations.
        .http2_keep_alive_interval(Duration::from_secs(10))
        .keep_alive_timeout(Duration::from_secs(5))
        .keep_alive_while_idle(true);

    let channel = endpoint
        .connect()
        .await
        .map_err(|e| anyhow::anyhow!("gRPC connect error: {e}"))?;

    Ok(channel)
}

/// Run the 5-stream handshake and maintain all concurrent streams.
///
/// Stream sequence (TAK Server SDK compatible):
/// 1. ServerFederateGroupsStream — receive remote groups (server-streaming)
/// 2. ClientFederateGroupsStream — send our groups (client-streaming)
/// 3. ServerEventStream — open for sending events (client-streaming)
/// 4. ClientEventStream — open for receiving events (server-streaming)
/// 5. Health check loop — periodic HealthCheck RPCs
async fn run_streams(
    peer: &Arc<PeerHandle>,
    mut client: FederatedChannelClient<Channel>,
    config: &V2ClientConfig,
    outbound_rx: &mut mpsc::Receiver<figpb::FederatedEvent>,
    shutdown_rx: &mut watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let sub = our_subscription(&config.federate_id);

    // --- Step 1: ServerFederateGroupsStream (receive remote groups) ---
    let mut server_groups_stream = client
        .server_federate_groups_stream(Request::new(sub.clone()))
        .await
        .map_err(|e| anyhow::anyhow!("server_federate_groups_stream failed: {e}"))?
        .into_inner();

    // Wait for the first message to confirm recognition
    if let Some(first_msg) = server_groups_stream
        .message()
        .await
        .map_err(|e| anyhow::anyhow!("failed to receive initial groups: {e}"))?
    {
        info!(
            peer = %peer.id,
            groups = ?first_msg.federate_groups,
            "received remote peer groups"
        );
    }

    // --- Step 2: ClientFederateGroupsStream (send our groups) ---
    let (groups_tx, groups_rx) = mpsc::channel::<figpb::FederateGroups>(16);
    let groups_stream = tokio_stream::wrappers::ReceiverStream::new(groups_rx);

    let _groups_resp = client
        .client_federate_groups_stream(Request::new(groups_stream))
        .await
        .map_err(|e| anyhow::anyhow!("client_federate_groups_stream failed: {e}"))?;

    // Send our initial groups
    let our_groups = figpb::FederateGroups {
        stream_update: Some(figpb::ServerHealth {
            status: figpb::server_health::ServingStatus::Serving as i32,
        }),
        federate_groups: config.groups.clone(),
        federate_provenance: Vec::new(),
        federate_hops: None,
        federate_group_hop_limits: None,
        nested_groups: Vec::new(),
    };
    groups_tx
        .send(our_groups)
        .await
        .map_err(|_| anyhow::anyhow!("groups channel closed"))?;

    // --- Step 3: ServerEventStream (open for sending) ---
    let (send_tx, send_rx) = mpsc::channel::<figpb::FederatedEvent>(256);
    let send_stream = tokio_stream::wrappers::ReceiverStream::new(send_rx);

    let _send_resp = client
        .server_event_stream(Request::new(send_stream))
        .await
        .map_err(|e| anyhow::anyhow!("server_event_stream failed: {e}"))?;

    // --- Step 4: ClientEventStream (open for receiving) ---
    let mut recv_stream = client
        .client_event_stream(Request::new(sub.clone()))
        .await
        .map_err(|e| anyhow::anyhow!("client_event_stream failed: {e}"))?
        .into_inner();

    // --- Connection established ---
    peer.set_state(PeerState::Connected);
    peer.mark_connected();
    rustgate_core::audit::federation_peer_connected(&peer.id, &config.federate_id, "outbound");
    info!(peer = %peer.id, "V2 gRPC handshake complete, streams active");

    // --- Step 5: Run all streams concurrently ---
    let mut health_ticker = tokio::time::interval(config.health_interval);
    // Skip the first immediate tick — do an explicit initial health check instead
    let _ = health_ticker.tick().await;

    // Initial health check (immediate, prevents inactivity disconnect)
    let health_result = client
        .health_check(Request::new(figpb::ClientHealth {
            status: figpb::client_health::ServingStatus::Serving as i32,
        }))
        .await;

    if let Err(e) = health_result {
        warn!(peer = %peer.id, error = %e, "initial health check failed");
        return Err(anyhow::anyhow!("initial health check failed: {e}"));
    }
    debug!(peer = %peer.id, "initial health check passed");

    loop {
        tokio::select! {
            // Receive events from remote
            msg = recv_stream.message() => {
                match msg {
                    Ok(Some(event)) => {
                        peer.record_recv();
                        peer.record_heartbeat();
                        let pid = peer.id.to_string();
                        (config.on_event)(event, pid);
                    }
                    Ok(None) => {
                        info!(peer = %peer.id, "receive stream ended");
                        break;
                    }
                    Err(e) => {
                        warn!(peer = %peer.id, error = %e, "receive stream error");
                        return Err(anyhow::anyhow!("receive stream error: {e}"));
                    }
                }
            }

            // Receive remote group updates
            msg = server_groups_stream.message() => {
                match msg {
                    Ok(Some(groups_msg)) => {
                        debug!(
                            peer = %peer.id,
                            groups = ?groups_msg.federate_groups,
                            "remote peer updated groups"
                        );
                    }
                    Ok(None) => {
                        info!(peer = %peer.id, "groups stream ended");
                        break;
                    }
                    Err(e) => {
                        warn!(peer = %peer.id, error = %e, "groups stream error");
                        return Err(anyhow::anyhow!("groups stream error: {e}"));
                    }
                }
            }

            // Forward outbound events to remote
            Some(event) = outbound_rx.recv() => {
                if send_tx.send(event).await.is_err() {
                    warn!(peer = %peer.id, "send stream closed");
                    break;
                }
                peer.record_sent();
            }

            // Periodic health checks
            _ = health_ticker.tick() => {
                let resp = client
                    .health_check(Request::new(figpb::ClientHealth {
                        status: figpb::client_health::ServingStatus::Serving as i32,
                    }))
                    .await;

                match resp {
                    Ok(r) => {
                        let status = r.into_inner().status;
                        if status != figpb::server_health::ServingStatus::Serving as i32 {
                            warn!(peer = %peer.id, status, "remote not serving");
                        }
                        peer.record_heartbeat();
                    }
                    Err(e) => {
                        error!(peer = %peer.id, error = %e, "health check failed");
                        return Err(anyhow::anyhow!("health check failed: {e}"));
                    }
                }
            }

            // Shutdown signal
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    info!(peer = %peer.id, "shutdown signal received");
                    break;
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
#[allow(unused_results)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use crate::config::{PeerConfig, RoutingMode};

    fn test_peer(id: &str) -> Arc<PeerHandle> {
        Arc::new(PeerHandle::new(PeerConfig {
            id: id.into(),
            address: "127.0.0.1:9001".into(),
            groups: vec!["Alpha".into()],
            inbound_groups: None,
            outbound_groups: None,
            enabled: true,
            is_outbound: true,
            trust_cert_cn: None,
            routing_mode: RoutingMode::Broadcast,
            protocol_version: 2,
            jwt_token: None,
        }))
    }

    fn noop_on_event() -> OnEvent {
        Arc::new(|_event, _peer| {})
    }

    fn counting_on_event() -> (OnEvent, Arc<AtomicU64>) {
        let count = Arc::new(AtomicU64::new(0));
        let c = Arc::clone(&count);
        let cb: OnEvent = Arc::new(move |_event, _peer| {
            c.fetch_add(1, Ordering::Relaxed);
        });
        (cb, count)
    }

    #[test]
    fn our_subscription_has_identity() {
        let sub = our_subscription("test-server");
        let identity = sub.identity.expect("identity");
        assert_eq!(identity.name, "test-server");
        assert_eq!(identity.server_id, "test-server");
        assert_eq!(
            identity.r#type,
            figpb::identity::ConnectionType::FederationHubClient as i32
        );
    }

    #[test]
    fn our_subscription_has_version() {
        let sub = our_subscription("s");
        let ver = sub.version.expect("version");
        assert_eq!(ver.major, 5);
        assert_eq!(ver.variant, "rustgate");
    }

    #[test]
    fn our_subscription_uid_is_deterministic() {
        let sub = our_subscription("my-server");
        let identity = sub.identity.expect("identity");
        assert_eq!(identity.uid, provenance::deterministic_uuid("my-server"));
    }

    #[tokio::test]
    async fn client_send_fails_after_shutdown() {
        let peer = test_peer("test-peer");
        let tls_config = ClientTlsConfig::new();

        let mut client = V2Client::start(
            peer,
            V2ClientConfig {
                address: "127.0.0.1:19999".into(),
                tls_config,
                federate_id: "test-server".into(),
                groups: vec!["Alpha".into()],
                health_interval: Duration::from_secs(5),
                reconnect_delay: Duration::from_secs(1),
                max_reconnects: 0, // max_reconnects = 0 means immediate stop
                on_event: noop_on_event(),
            },
        );

        // Give the connection loop time to stop (max_reconnects=0)
        tokio::time::sleep(Duration::from_millis(200)).await;
        client.shutdown().await;

        let event = figpb::FederatedEvent::default();
        let result = client.send(event).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn client_peer_accessor_returns_handle() {
        let peer = test_peer("accessor-test");
        let tls_config = ClientTlsConfig::new();

        let mut client = V2Client::start(
            peer,
            V2ClientConfig {
                address: "127.0.0.1:19998".into(),
                tls_config,
                federate_id: "test-server".into(),
                groups: vec![],
                health_interval: Duration::from_secs(5),
                reconnect_delay: Duration::from_secs(1),
                max_reconnects: 0,
                on_event: noop_on_event(),
            },
        );

        assert_eq!(client.peer().id, "accessor-test");

        tokio::time::sleep(Duration::from_millis(200)).await;
        client.shutdown().await;
    }

    #[tokio::test]
    async fn client_shutdown_is_idempotent() {
        let peer = test_peer("shutdown-test");
        let tls_config = ClientTlsConfig::new();

        let mut client = V2Client::start(
            peer,
            V2ClientConfig {
                address: "127.0.0.1:19997".into(),
                tls_config,
                federate_id: "test-server".into(),
                groups: vec![],
                health_interval: Duration::from_secs(5),
                reconnect_delay: Duration::from_secs(1),
                max_reconnects: 0,
                on_event: noop_on_event(),
            },
        );

        tokio::time::sleep(Duration::from_millis(200)).await;
        client.shutdown().await;
        // Second shutdown should be a no-op
        client.shutdown().await;
        assert_eq!(client.peer().state(), PeerState::Disconnected);
    }

    #[tokio::test]
    async fn client_peer_state_transitions() {
        let peer = test_peer("state-test");
        let tls_config = ClientTlsConfig::new();

        // With max_reconnects=1, it should try once then stop
        let mut client = V2Client::start(
            Arc::clone(&peer),
            V2ClientConfig {
                address: "127.0.0.1:19996".into(),
                tls_config,
                federate_id: "test-server".into(),
                groups: vec![],
                health_interval: Duration::from_secs(5),
                reconnect_delay: Duration::from_millis(50), // fast reconnect for test
                max_reconnects: 1,
                on_event: noop_on_event(),
            },
        );

        // Eventually the client will be disconnected after exhausting retries
        tokio::time::sleep(Duration::from_millis(500)).await;
        client.shutdown().await;
        assert_eq!(peer.state(), PeerState::Disconnected);
    }

    #[test]
    fn counting_callback_increments() {
        let (on_event, count) = counting_on_event();
        on_event(figpb::FederatedEvent::default(), "peer-1".into());
        on_event(figpb::FederatedEvent::default(), "peer-1".into());
        assert_eq!(count.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn post_disconnect_cooldown_default() {
        // Default reconnect_delay of 30s → 120s cooldown, but minimum is 60s
        let cooldown = post_disconnect_cooldown(Duration::from_secs(30));
        assert_eq!(cooldown, Duration::from_secs(120));
    }

    #[test]
    fn post_disconnect_cooldown_minimum_enforced() {
        // 10s * 4 = 40s, but minimum is 60s
        let cooldown = post_disconnect_cooldown(Duration::from_secs(10));
        assert_eq!(cooldown, Duration::from_secs(60));
    }

    #[test]
    fn post_disconnect_cooldown_exact_minimum() {
        // 15s * 4 = 60s, exactly the minimum
        let cooldown = post_disconnect_cooldown(Duration::from_secs(15));
        assert_eq!(cooldown, Duration::from_secs(60));
    }

    #[test]
    fn post_disconnect_cooldown_zero() {
        let cooldown = post_disconnect_cooldown(Duration::ZERO);
        assert_eq!(cooldown, Duration::from_secs(60));
    }
}
