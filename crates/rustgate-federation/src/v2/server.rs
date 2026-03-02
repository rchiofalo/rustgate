//! V2 federation gRPC server implementing the FederatedChannel service.
//!
//! Handles inbound federation connections from remote peers over gRPC/mTLS.
//! Implements the TAK Server V2 federation protocol with group exchange,
//! event streaming, health checks, and provenance tracking.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{RwLock, mpsc};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, Streaming};
use tracing::{debug, info};

use super::proto::figpb;
use super::proto::figpb::federated_channel_server::FederatedChannel;
use crate::provenance;

/// Callback invoked when a FederatedEvent is received from a remote peer.
pub type OnEvent = Arc<dyn Fn(figpb::FederatedEvent, String) + Send + Sync>;

/// V2 gRPC FederatedChannel service implementation.
///
/// Manages inbound federation connections, tracks per-peer outbound streams
/// and advertised groups, and forwards events to local consumers via callbacks.
pub struct FederationService {
    /// Our federation server identity.
    federate_id: String,
    /// Deterministic UUID derived from federate_id.
    server_uid: String,
    /// Groups we advertise to peers.
    groups: Vec<String>,
    /// Per-peer outbound event streams (peer_id → sender).
    outbound_streams: Arc<RwLock<HashMap<String, mpsc::Sender<figpb::FederatedEvent>>>>,
    /// Per-peer advertised groups.
    peer_groups: Arc<RwLock<HashMap<String, Vec<String>>>>,
    /// Callback for inbound events.
    on_event: OnEvent,
}

impl std::fmt::Debug for FederationService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FederationService")
            .field("federate_id", &self.federate_id)
            .field("server_uid", &self.server_uid)
            .field("groups", &self.groups)
            .finish_non_exhaustive()
    }
}

impl FederationService {
    /// Create a new FederationService.
    pub fn new(federate_id: String, groups: Vec<String>, on_event: OnEvent) -> Self {
        let server_uid = provenance::deterministic_uuid(&federate_id);
        Self {
            federate_id,
            server_uid,
            groups,
            outbound_streams: Arc::new(RwLock::new(HashMap::new())),
            peer_groups: Arc::new(RwLock::new(HashMap::new())),
            on_event,
        }
    }

    /// Send a FederatedEvent to all connected peers.
    pub async fn broadcast(&self, event: figpb::FederatedEvent) -> usize {
        let streams = self.outbound_streams.read().await;
        let mut sent = 0;
        for (peer_id, tx) in streams.iter() {
            if tx.send(event.clone()).await.is_ok() {
                sent += 1;
                debug!(peer = %peer_id, "broadcast event to peer");
            }
        }
        sent
    }

    /// Send a FederatedEvent only to peers whose groups overlap with the given groups.
    pub async fn broadcast_to_groups(
        &self,
        event: figpb::FederatedEvent,
        groups: &[String],
    ) -> usize {
        let streams = self.outbound_streams.read().await;
        let peer_groups = self.peer_groups.read().await;
        let mut sent = 0;

        for (peer_id, tx) in streams.iter() {
            let shares_group = peer_groups
                .get(peer_id.as_str())
                .is_some_and(|pg| pg.iter().any(|g| groups.contains(g)));

            // If we don't track groups for this peer, send anyway (backward compat).
            // Combined with group overlap check into a single condition.
            if (shares_group || !peer_groups.contains_key(peer_id.as_str()))
                && tx.send(event.clone()).await.is_ok()
            {
                sent += 1;
            }
        }
        sent
    }

    /// Number of connected outbound streams.
    pub async fn connection_count(&self) -> usize {
        self.outbound_streams.read().await.len()
    }

    /// Build the subscription response we send to peers.
    fn our_subscription(&self) -> figpb::Subscription {
        figpb::Subscription {
            identity: Some(figpb::Identity {
                name: self.federate_id.clone(),
                uid: self.server_uid.clone(),
                description: String::new(),
                r#type: figpb::identity::ConnectionType::FederationHubServer as i32,
                server_id: self.federate_id.clone(),
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

    /// Extract peer ID from tonic request metadata (TLS CN or address).
    fn peer_id_from_request<T>(request: &Request<T>) -> String {
        request
            .remote_addr()
            .map(|addr| addr.to_string())
            .unwrap_or_else(|| "unknown".to_string())
    }

    /// Create a pre-configured `tonic::transport::Server` with federation
    /// keepalive and message size settings.
    ///
    /// Configures:
    /// - HTTP/2 keepalive timeout: 20 seconds
    /// - HTTP/2 keepalive interval: None (passive — relies on client pings)
    /// - Max frame size and initial window sizes tuned for large CoT payloads
    ///
    /// The caller is responsible for binding to an address and adding TLS config.
    pub fn configured_server(max_message_size: usize) -> tonic::transport::Server {
        tonic::transport::Server::builder()
            .http2_keepalive_timeout(Some(Duration::from_secs(20)))
            .initial_stream_window_size(Some(1024 * 1024)) // 1 MB
            .initial_connection_window_size(Some(2 * 1024 * 1024)) // 2 MB
            .max_frame_size(Some(max_message_size.min(u32::MAX as usize) as u32))
    }
}

#[tonic::async_trait]
impl FederatedChannel for FederationService {
    // --- Unary RPCs ---

    async fn send_one_event(
        &self,
        request: Request<figpb::FederatedEvent>,
    ) -> Result<Response<figpb::Empty>, Status> {
        let peer_id = Self::peer_id_from_request(&request);
        let event = request.into_inner();
        debug!(peer = %peer_id, "received single event");
        (self.on_event)(event, peer_id);
        Ok(Response::new(figpb::Empty {}))
    }

    async fn get_identity(
        &self,
        _request: Request<figpb::Empty>,
    ) -> Result<Response<figpb::Identity>, Status> {
        Ok(Response::new(figpb::Identity {
            name: self.federate_id.clone(),
            uid: self.server_uid.clone(),
            description: String::new(),
            r#type: figpb::identity::ConnectionType::FederationHubServer as i32,
            server_id: self.federate_id.clone(),
        }))
    }

    async fn health_check(
        &self,
        request: Request<figpb::ClientHealth>,
    ) -> Result<Response<figpb::ServerHealth>, Status> {
        let peer_id = Self::peer_id_from_request(&request);
        debug!(peer = %peer_id, "health check received");
        Ok(Response::new(figpb::ServerHealth {
            status: figpb::server_health::ServingStatus::Serving as i32,
        }))
    }

    async fn send_one_blob(
        &self,
        _request: Request<figpb::BinaryBlob>,
    ) -> Result<Response<figpb::Empty>, Status> {
        // Binary blobs not supported in this implementation
        Ok(Response::new(figpb::Empty {}))
    }

    async fn get_auth_token_by_x509(
        &self,
        _request: Request<figpb::BinaryBlob>,
    ) -> Result<Response<figpb::FederateTokenResponse>, Status> {
        // Token auth not used in mTLS mode
        Ok(Response::new(figpb::FederateTokenResponse {
            token: String::new(),
        }))
    }

    async fn getx509_identity(
        &self,
        _request: Request<figpb::Empty>,
    ) -> Result<Response<figpb::BinaryBlob>, Status> {
        Ok(Response::new(figpb::BinaryBlob::default()))
    }

    // --- Client-streaming RPCs (we receive a stream from the remote) ---

    async fn server_event_stream(
        &self,
        request: Request<Streaming<figpb::FederatedEvent>>,
    ) -> Result<Response<figpb::Subscription>, Status> {
        let peer_id = Self::peer_id_from_request(&request);
        let mut stream = request.into_inner();

        info!(peer = %peer_id, "server_event_stream opened (receiving events)");

        let on_event = Arc::clone(&self.on_event);
        let pid = peer_id.clone();

        drop(tokio::spawn(async move {
            while let Ok(Some(event)) = stream.message().await {
                on_event(event, pid.clone());
            }
            info!(peer = %pid, "server_event_stream closed");
        }));

        Ok(Response::new(self.our_subscription()))
    }

    async fn binary_message_stream(
        &self,
        request: Request<Streaming<figpb::BinaryBlob>>,
    ) -> Result<Response<figpb::Empty>, Status> {
        let peer_id = Self::peer_id_from_request(&request);
        let mut stream = request.into_inner();

        // Drain the stream without processing (binary blobs not supported)
        drop(tokio::spawn(async move {
            while let Ok(Some(_blob)) = stream.message().await {
                debug!(peer = %peer_id, "received binary blob (ignored)");
            }
        }));

        Ok(Response::new(figpb::Empty {}))
    }

    async fn server_rol_stream(
        &self,
        request: Request<Streaming<figpb::Rol>>,
    ) -> Result<Response<figpb::Subscription>, Status> {
        let peer_id = Self::peer_id_from_request(&request);
        let mut stream = request.into_inner();

        // Drain ROL stream without processing (missions not supported)
        drop(tokio::spawn(async move {
            while let Ok(Some(_rol)) = stream.message().await {
                debug!(peer = %peer_id, "received ROL message (ignored)");
            }
        }));

        Ok(Response::new(self.our_subscription()))
    }

    async fn client_federate_groups_stream(
        &self,
        request: Request<Streaming<figpb::FederateGroups>>,
    ) -> Result<Response<figpb::Subscription>, Status> {
        let peer_id = Self::peer_id_from_request(&request);
        let mut stream = request.into_inner();

        info!(peer = %peer_id, "client_federate_groups_stream opened (receiving groups)");

        let peer_groups = Arc::clone(&self.peer_groups);
        let pid = peer_id.clone();

        drop(tokio::spawn(async move {
            while let Ok(Some(groups_msg)) = stream.message().await {
                let groups = groups_msg.federate_groups;
                info!(peer = %pid, groups = ?groups, "peer updated groups");
                let _ = peer_groups.write().await.insert(pid.clone(), groups);
            }
            info!(peer = %pid, "client_federate_groups_stream closed");
            let _ = peer_groups.write().await.remove(&pid);
        }));

        Ok(Response::new(self.our_subscription()))
    }

    // --- Server-streaming RPCs (we send a stream to the remote) ---

    type ClientEventStreamStream = ReceiverStream<Result<figpb::FederatedEvent, Status>>;

    async fn client_event_stream(
        &self,
        request: Request<figpb::Subscription>,
    ) -> Result<Response<Self::ClientEventStreamStream>, Status> {
        let sub = request.into_inner();
        let peer_id = sub
            .identity
            .as_ref()
            .map(|i| {
                if !i.name.is_empty() {
                    i.name.clone()
                } else {
                    i.uid.clone()
                }
            })
            .unwrap_or_else(|| "unknown".to_string());

        info!(peer = %peer_id, "client_event_stream opened (sending events)");

        let (event_tx, mut event_rx) = mpsc::channel::<figpb::FederatedEvent>(256);
        let (stream_tx, stream_rx) = mpsc::channel::<Result<figpb::FederatedEvent, Status>>(256);

        // Store the outbound channel for broadcasting
        let _ = self
            .outbound_streams
            .write()
            .await
            .insert(peer_id.clone(), event_tx);

        // Forward events from the mpsc channel to the gRPC stream
        let outbound_streams = Arc::clone(&self.outbound_streams);
        let pid = peer_id.clone();
        drop(tokio::spawn(async move {
            while let Some(event) = event_rx.recv().await {
                if stream_tx.send(Ok(event)).await.is_err() {
                    break;
                }
            }
            info!(peer = %pid, "client_event_stream closed");
            let _ = outbound_streams.write().await.remove(&pid);
        }));

        Ok(Response::new(ReceiverStream::new(stream_rx)))
    }

    type ClientROLStreamStream = ReceiverStream<Result<figpb::Rol, Status>>;

    async fn client_rol_stream(
        &self,
        _request: Request<figpb::Subscription>,
    ) -> Result<Response<Self::ClientROLStreamStream>, Status> {
        // ROL/missions not supported — return an empty stream that stays open
        let (_tx, rx) = mpsc::channel(1);
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    type ServerFederateGroupsStreamStream = ReceiverStream<Result<figpb::FederateGroups, Status>>;

    async fn server_federate_groups_stream(
        &self,
        request: Request<figpb::Subscription>,
    ) -> Result<Response<Self::ServerFederateGroupsStreamStream>, Status> {
        let sub = request.into_inner();
        let peer_id = sub
            .identity
            .as_ref()
            .map(|i| i.name.clone())
            .unwrap_or_else(|| "unknown".to_string());

        info!(peer = %peer_id, "server_federate_groups_stream opened (sending our groups)");

        let (tx, rx) = mpsc::channel(16);

        // Send our initial groups with SERVING status
        let groups_msg = figpb::FederateGroups {
            stream_update: Some(figpb::ServerHealth {
                status: figpb::server_health::ServingStatus::Serving as i32,
            }),
            federate_groups: self.groups.clone(),
            federate_provenance: Vec::new(),
            federate_hops: None,
            federate_group_hop_limits: None,
            nested_groups: Vec::new(),
        };

        let _ = tx.send(Ok(groups_msg)).await;

        // Hold the sender alive in a background task so the stream stays open.
        // The stream closes when the remote disconnects (rx is dropped by tonic).
        drop(tokio::spawn(async move {
            // Keep tx alive until the connection drops — pending never resolves
            futures::future::pending::<()>().await;
            drop(tx);
        }));

        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

#[cfg(test)]
#[allow(unused_results)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

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
    fn service_debug_output() {
        let svc =
            FederationService::new("test-server".into(), vec!["Alpha".into()], noop_on_event());
        let dbg = format!("{svc:?}");
        assert!(dbg.contains("test-server"));
        assert!(dbg.contains("Alpha"));
    }

    #[test]
    fn service_uid_is_deterministic() {
        let svc = FederationService::new("server-1".into(), vec![], noop_on_event());
        assert_eq!(svc.server_uid, provenance::deterministic_uuid("server-1"));
    }

    #[test]
    fn our_subscription_has_identity() {
        let svc =
            FederationService::new("fed-server".into(), vec!["Group1".into()], noop_on_event());
        let sub = svc.our_subscription();
        let identity = sub.identity.expect("identity");
        assert_eq!(identity.name, "fed-server");
        assert_eq!(
            identity.r#type,
            figpb::identity::ConnectionType::FederationHubServer as i32
        );
    }

    #[test]
    fn our_subscription_has_version() {
        let svc = FederationService::new("s".into(), vec![], noop_on_event());
        let sub = svc.our_subscription();
        let ver = sub.version.expect("version");
        assert_eq!(ver.major, 5);
        assert_eq!(ver.variant, "rustgate");
    }

    #[tokio::test]
    async fn connection_count_starts_at_zero() {
        let svc = FederationService::new("s".into(), vec![], noop_on_event());
        assert_eq!(svc.connection_count().await, 0);
    }

    #[tokio::test]
    async fn broadcast_with_no_peers_returns_zero() {
        let svc = FederationService::new("s".into(), vec![], noop_on_event());
        let event = figpb::FederatedEvent::default();
        assert_eq!(svc.broadcast(event).await, 0);
    }

    #[tokio::test]
    async fn broadcast_to_groups_with_no_peers_returns_zero() {
        let svc = FederationService::new("s".into(), vec![], noop_on_event());
        let event = figpb::FederatedEvent::default();
        assert_eq!(svc.broadcast_to_groups(event, &["Alpha".into()]).await, 0);
    }

    #[tokio::test]
    async fn broadcast_sends_to_registered_peer() {
        let svc = FederationService::new("s".into(), vec![], noop_on_event());
        let (tx, mut rx) = mpsc::channel(16);

        // Manually register a peer stream
        svc.outbound_streams
            .write()
            .await
            .insert("peer-1".into(), tx);

        let event = figpb::FederatedEvent {
            event: Some(figpb::GeoEvent {
                uid: "broadcast-test".into(),
                ..Default::default()
            }),
            ..Default::default()
        };

        let sent = svc.broadcast(event).await;
        assert_eq!(sent, 1);

        let received = rx.recv().await.expect("should receive event");
        assert_eq!(received.event.expect("event").uid, "broadcast-test");
    }

    #[tokio::test]
    async fn broadcast_to_groups_sends_only_to_matching_peers() {
        let svc = FederationService::new("s".into(), vec![], noop_on_event());
        let (tx_alpha, mut rx_alpha) = mpsc::channel(16);
        let (tx_bravo, mut rx_bravo) = mpsc::channel(16);

        // Register two peers with different groups
        {
            let mut streams = svc.outbound_streams.write().await;
            streams.insert("peer-alpha".into(), tx_alpha);
            streams.insert("peer-bravo".into(), tx_bravo);
        }
        {
            let mut groups = svc.peer_groups.write().await;
            groups.insert("peer-alpha".into(), vec!["Alpha".into()]);
            groups.insert("peer-bravo".into(), vec!["Bravo".into()]);
        }

        let event = figpb::FederatedEvent::default();
        let sent = svc.broadcast_to_groups(event, &["Alpha".into()]).await;
        assert_eq!(sent, 1);

        // Alpha should get it
        assert!(rx_alpha.try_recv().is_ok());
        // Bravo should not
        assert!(rx_bravo.try_recv().is_err());
    }

    #[tokio::test]
    async fn broadcast_to_groups_sends_to_peers_without_groups() {
        let svc = FederationService::new("s".into(), vec![], noop_on_event());
        let (tx, mut rx) = mpsc::channel(16);

        // Register peer with NO groups tracked (backward compat: should receive)
        svc.outbound_streams
            .write()
            .await
            .insert("peer-nogroups".into(), tx);
        // Don't add to peer_groups

        let event = figpb::FederatedEvent::default();
        let sent = svc.broadcast_to_groups(event, &["Alpha".into()]).await;
        assert_eq!(sent, 1);
        assert!(rx.try_recv().is_ok());
    }

    #[tokio::test]
    async fn get_identity_returns_server_info() {
        let svc = FederationService::new("my-server".into(), vec!["G1".into()], noop_on_event());
        let resp = svc
            .get_identity(Request::new(figpb::Empty {}))
            .await
            .expect("get_identity");
        let identity = resp.into_inner();
        assert_eq!(identity.name, "my-server");
        assert_eq!(identity.server_id, "my-server");
    }

    #[tokio::test]
    async fn health_check_returns_serving() {
        let svc = FederationService::new("s".into(), vec![], noop_on_event());
        let resp = svc
            .health_check(Request::new(figpb::ClientHealth {
                status: figpb::client_health::ServingStatus::Serving as i32,
            }))
            .await
            .expect("health_check");
        let health = resp.into_inner();
        assert_eq!(
            health.status,
            figpb::server_health::ServingStatus::Serving as i32
        );
    }

    #[tokio::test]
    async fn send_one_event_invokes_callback() {
        let (on_event, count) = counting_on_event();
        let svc = FederationService::new("s".into(), vec![], on_event);
        let event = figpb::FederatedEvent {
            event: Some(figpb::GeoEvent {
                uid: "test".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let _ = svc
            .send_one_event(Request::new(event))
            .await
            .expect("send_one_event");
        assert_eq!(count.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn send_one_blob_returns_empty() {
        let svc = FederationService::new("s".into(), vec![], noop_on_event());
        let resp = svc
            .send_one_blob(Request::new(figpb::BinaryBlob::default()))
            .await
            .expect("send_one_blob");
        let _ = resp.into_inner();
    }

    #[tokio::test]
    async fn get_auth_token_returns_empty() {
        let svc = FederationService::new("s".into(), vec![], noop_on_event());
        let resp = svc
            .get_auth_token_by_x509(Request::new(figpb::BinaryBlob::default()))
            .await
            .expect("get_auth_token");
        assert_eq!(resp.into_inner().token, "");
    }

    #[tokio::test]
    async fn getx509_identity_returns_default() {
        let svc = FederationService::new("s".into(), vec![], noop_on_event());
        let _ = svc
            .getx509_identity(Request::new(figpb::Empty {}))
            .await
            .expect("getx509_identity");
    }

    #[tokio::test]
    async fn connection_count_reflects_registered_peers() {
        let svc = FederationService::new("s".into(), vec![], noop_on_event());
        assert_eq!(svc.connection_count().await, 0);

        let (tx1, _rx1) = mpsc::channel(1);
        let (tx2, _rx2) = mpsc::channel(1);
        {
            let mut streams = svc.outbound_streams.write().await;
            streams.insert("peer-1".into(), tx1);
            streams.insert("peer-2".into(), tx2);
        }
        assert_eq!(svc.connection_count().await, 2);
    }

    #[test]
    fn test_configured_server_default_size() {
        let _server = FederationService::configured_server(10 * 1024 * 1024);
    }

    #[test]
    fn test_configured_server_zero_size() {
        let _server = FederationService::configured_server(0);
    }

    #[test]
    fn test_configured_server_u32_max_clamp() {
        // max_frame_size uses .min(u32::MAX) so very large values are clamped
        let _server = FederationService::configured_server(usize::MAX);
    }
}
