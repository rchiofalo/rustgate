//! V2 federation gRPC client with 5-stream handshake.
//!
//! Implements the outbound gRPC federation connection that follows the
//! TAK Server V2 federation protocol. The client establishes multiple
//! concurrent streams (group exchange, event streaming, health checks)
//! and reconnects automatically on failure.

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

/// Callback invoked when a FederatedEvent is received from the remote peer.
pub type OnEvent = Arc<dyn Fn(figpb::FederatedEvent, String) + Send + Sync>;

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
    #[allow(clippy::too_many_arguments)]
    pub fn start(
        peer: Arc<PeerHandle>,
        address: String,
        tls_config: ClientTlsConfig,
        federate_id: String,
        groups: Vec<String>,
        health_interval: Duration,
        reconnect_delay: Duration,
        max_reconnects: i32,
        on_event: OnEvent,
    ) -> Self {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (outbound_tx, outbound_rx) = mpsc::channel::<figpb::FederatedEvent>(256);

        let peer_clone = Arc::clone(&peer);
        let task_handle = tokio::spawn(connection_loop(
            peer_clone,
            address,
            tls_config,
            federate_id,
            groups,
            health_interval,
            reconnect_delay,
            max_reconnects,
            on_event,
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

/// Calculate reconnection backoff delay.
///
/// Uses exponential backoff: base * 2^min(attempt, 5), capped at 5 minutes.
pub(crate) fn backoff_delay(base: Duration, attempt: u32) -> Duration {
    let exp = attempt.min(5);
    let delay = base.saturating_mul(2u32.pow(exp));
    let max_delay = Duration::from_secs(300);
    delay.min(max_delay)
}

/// Check whether to stop reconnecting based on max_reconnects limit.
fn should_stop(max_reconnects: i32, count: u32) -> bool {
    max_reconnects >= 0 && count >= max_reconnects as u32
}

/// Main connection loop with automatic reconnection.
#[allow(clippy::too_many_arguments)]
async fn connection_loop(
    peer: Arc<PeerHandle>,
    address: String,
    tls_config: ClientTlsConfig,
    federate_id: String,
    groups: Vec<String>,
    health_interval: Duration,
    reconnect_delay: Duration,
    max_reconnects: i32,
    on_event: OnEvent,
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
        if should_stop(max_reconnects, reconnect_count) {
            info!(
                peer = %peer.id,
                max = max_reconnects,
                "max reconnect attempts reached"
            );
            peer.set_state(PeerState::Disconnected);
            break;
        }

        if reconnect_count > 0 {
            peer.set_state(PeerState::Reconnecting);
            let _ = peer.increment_reconnect_count();
            let delay = backoff_delay(reconnect_delay, reconnect_count);
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
        info!(peer = %peer.id, address = %address, "connecting to remote peer");

        // Build the gRPC channel
        let channel = match build_channel(&address, tls_config.clone()).await {
            Ok(ch) => ch,
            Err(e) => {
                warn!(peer = %peer.id, error = %e, "failed to build gRPC channel");
                peer.set_error(&e.to_string());
                reconnect_count += 1;
                continue;
            }
        };

        let client = FederatedChannelClient::new(channel);

        // Run the 5-stream handshake and event loop
        let result = run_streams(
            &peer,
            client,
            &federate_id,
            &groups,
            health_interval,
            &on_event,
            &mut outbound_rx,
            &mut shutdown_rx,
        )
        .await;

        match result {
            Ok(()) => {
                info!(peer = %peer.id, "streams closed gracefully");
            }
            Err(e) => {
                warn!(peer = %peer.id, error = %e, "streams failed");
                peer.set_error(&e.to_string());
            }
        }

        peer.set_state(PeerState::Disconnected);
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
        .timeout(Duration::from_secs(300));

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
#[allow(clippy::too_many_arguments)]
async fn run_streams(
    peer: &Arc<PeerHandle>,
    mut client: FederatedChannelClient<Channel>,
    federate_id: &str,
    groups: &[String],
    health_interval: Duration,
    on_event: &OnEvent,
    outbound_rx: &mut mpsc::Receiver<figpb::FederatedEvent>,
    shutdown_rx: &mut watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let sub = our_subscription(federate_id);

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
        federate_groups: groups.to_vec(),
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
    info!(peer = %peer.id, "V2 gRPC handshake complete, streams active");

    // --- Step 5: Run all streams concurrently ---
    let mut health_ticker = tokio::time::interval(health_interval);
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
                        on_event(event, pid);
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
    use super::*;
    use crate::config::{PeerConfig, RoutingMode};
    use std::sync::atomic::{AtomicU64, Ordering};

    fn test_peer(id: &str) -> Arc<PeerHandle> {
        Arc::new(PeerHandle::new(PeerConfig {
            id: id.into(),
            address: "127.0.0.1:9001".into(),
            groups: vec!["Alpha".into()],
            enabled: true,
            is_outbound: true,
            trust_cert_cn: None,
            routing_mode: RoutingMode::Broadcast,
            protocol_version: 2,
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
    fn backoff_delay_base_case() {
        let delay = backoff_delay(Duration::from_secs(15), 0);
        assert_eq!(delay, Duration::from_secs(15));
    }

    #[test]
    fn backoff_delay_exponential() {
        assert_eq!(
            backoff_delay(Duration::from_secs(15), 1),
            Duration::from_secs(30)
        );
        assert_eq!(
            backoff_delay(Duration::from_secs(15), 2),
            Duration::from_secs(60)
        );
        assert_eq!(
            backoff_delay(Duration::from_secs(15), 3),
            Duration::from_secs(120)
        );
    }

    #[test]
    fn backoff_delay_caps_exponent_at_five() {
        let delay_5 = backoff_delay(Duration::from_secs(1), 5);
        let delay_6 = backoff_delay(Duration::from_secs(1), 6);
        let delay_10 = backoff_delay(Duration::from_secs(1), 10);
        assert_eq!(delay_5, delay_6);
        assert_eq!(delay_5, delay_10);
    }

    #[test]
    fn backoff_delay_caps_at_five_minutes() {
        let delay = backoff_delay(Duration::from_secs(60), 5);
        assert_eq!(delay, Duration::from_secs(300));
    }

    #[test]
    fn backoff_delay_large_base_caps_at_five_minutes() {
        let delay = backoff_delay(Duration::from_secs(120), 5);
        assert_eq!(delay, Duration::from_secs(300));
    }

    #[test]
    fn backoff_delay_zero_base() {
        let delay = backoff_delay(Duration::ZERO, 5);
        assert_eq!(delay, Duration::ZERO);
    }

    #[test]
    fn should_stop_unlimited() {
        assert!(!should_stop(-1, 0));
        assert!(!should_stop(-1, 100));
        assert!(!should_stop(-1, u32::MAX));
    }

    #[test]
    fn should_stop_limited() {
        assert!(!should_stop(3, 0));
        assert!(!should_stop(3, 2));
        assert!(should_stop(3, 3));
        assert!(should_stop(3, 4));
    }

    #[test]
    fn should_stop_zero_reconnects() {
        assert!(should_stop(0, 0));
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
            "127.0.0.1:19999".into(),
            tls_config,
            "test-server".into(),
            vec!["Alpha".into()],
            Duration::from_secs(5),
            Duration::from_secs(1),
            0, // max_reconnects = 0 means immediate stop
            noop_on_event(),
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
            "127.0.0.1:19998".into(),
            tls_config,
            "test-server".into(),
            vec![],
            Duration::from_secs(5),
            Duration::from_secs(1),
            0,
            noop_on_event(),
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
            "127.0.0.1:19997".into(),
            tls_config,
            "test-server".into(),
            vec![],
            Duration::from_secs(5),
            Duration::from_secs(1),
            0,
            noop_on_event(),
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
            "127.0.0.1:19996".into(),
            tls_config,
            "test-server".into(),
            vec![],
            Duration::from_secs(5),
            Duration::from_millis(50), // fast reconnect for test
            1,
            noop_on_event(),
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
}
