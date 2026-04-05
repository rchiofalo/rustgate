//! UDP CoT input listener for connectionless message delivery.
//!
//! Receives UDP datagrams containing CoT XML and routes them through the
//! standard message router. There is no session state — each datagram is
//! treated independently with a synthetic anonymous identity.
//!
//! This is strictly opt-in and logs a prominent warning when started.

use std::collections::BTreeSet;
use std::sync::Arc;

use bytes::Bytes;
use rustgate_core::constants::PLAINTEXT_GROUP;
use rustgate_core::identity::Identity;
use rustgate_core::message::RoutableMessage;
use rustgate_cot::MessageBuilder;
use rustgate_transport_types::{Router, SessionHandle};
use tokio::net::UdpSocket;
use tokio::sync::{Notify, mpsc};
use tracing::warn;

use crate::replay::ReplayFilter;

/// Maximum UDP datagram size. CoT messages are typically well under 64 KB.
const MAX_DATAGRAM_SIZE: usize = 65_535;

/// Configuration for the UDP input listener.
#[derive(Debug, Clone)]
pub struct UdpInputConfig {
    /// Default CN for UDP-sourced messages.
    pub cn: String,
    /// Default group for UDP-sourced messages.
    pub default_group: String,
}

impl Default for UdpInputConfig {
    fn default() -> Self {
        Self {
            cn: "udp-anonymous".to_string(),
            default_group: PLAINTEXT_GROUP.to_string(),
        }
    }
}

/// Callback for NATS publishing after local routing.
pub type OnNatsPublish = Arc<dyn Fn(RoutableMessage) + Send + Sync>;

/// Callback for federation forwarding.
pub type OnFederationForward = Arc<dyn Fn(Bytes, Vec<String>) + Send + Sync>;

/// UDP input receiver that routes datagrams through the message router.
#[derive(Debug)]
pub struct UdpInput;

impl UdpInput {
    /// Run the UDP input loop until `shutdown` is notified.
    ///
    /// Each received datagram is parsed as CoT XML, assigned a synthetic
    /// identity, and routed through the standard router. Invalid or
    /// oversized datagrams are logged and dropped.
    pub async fn run(
        socket: UdpSocket,
        router: Arc<Router>,
        config: UdpInputConfig,
        nats_publish: Option<OnNatsPublish>,
        fed_forward: Option<OnFederationForward>,
        replay_filter: Option<Arc<ReplayFilter>>,
        shutdown: Arc<Notify>,
    ) {
        warn!(
            local_addr = ?socket.local_addr().ok(),
            "UDP input listener active — datagrams are NOT encrypted"
        );

        let mut buf = vec![0u8; MAX_DATAGRAM_SIZE];
        let mut msg_builder = MessageBuilder::new();

        // Register a single session handle for UDP so routed responses
        // have somewhere to go (they'll be silently dropped since UDP is
        // fire-and-forget, but the router requires registration for group
        // membership to work).
        let mut groups = BTreeSet::new();
        let _ = groups.insert(config.default_group.clone());
        let identity = match Identity::plaintext(config.cn.clone(), groups) {
            Ok(id) => Arc::new(id),
            Err(e) => {
                tracing::error!(error = %e, "invalid UDP identity configuration");
                return;
            }
        };
        let (tx, _rx) = mpsc::channel::<Arc<RoutableMessage>>(1);
        let handle = SessionHandle::new(Arc::clone(&identity), tx);
        let session_id = handle.id;
        router.register(handle).await;

        loop {
            tokio::select! {
                result = socket.recv_from(&mut buf) => {
                    match result {
                        Ok((len, peer_addr)) => {
                            if len == 0 {
                                continue;
                            }

                            let payload = Bytes::copy_from_slice(&buf[..len]);
                            tracing::debug!(
                                peer = %peer_addr,
                                bytes = len,
                                "UDP datagram received"
                            );

                            // Build a per-datagram identity that includes the
                            // source address for traceability.
                            let dgram_cn = format!("{}-{}", config.cn, peer_addr);
                            let mut dgram_groups = BTreeSet::new();
                            let _ = dgram_groups.insert(config.default_group.clone());
                            let dgram_identity = match Identity::plaintext(dgram_cn, dgram_groups) {
                                Ok(id) => id,
                                Err(e) => {
                                    tracing::warn!(error = %e, peer = %peer_addr, "invalid datagram identity");
                                    continue;
                                }
                            };

                            // Anti-replay: drop datagrams with duplicate (uid, time)
                            if let Some(filter) = &replay_filter
                                && filter.is_replay(&payload)
                            {
                                tracing::debug!(
                                    peer = %peer_addr,
                                    "UDP datagram dropped: replay detected"
                                );
                                continue;
                            }

                            let msg = msg_builder.build(&dgram_identity, payload, "udp");
                            router.route(msg.clone()).await;

                            if let Some(nats_cb) = &nats_publish {
                                nats_cb(msg.clone());
                            }

                            if let Some(fwd) = &fed_forward {
                                let groups: Vec<String> =
                                    msg.source.groups.iter().cloned().collect();
                                fwd(msg.payload.clone(), groups);
                            }
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "UDP recv error");
                        }
                    }
                }
                _ = shutdown.notified() => {
                    tracing::info!("UDP input shutting down");
                    break;
                }
            }
        }

        router.unregister(&config.cn, session_id).await;
    }
}

/// Internal module alias — the types are re-exported from the crate root
/// but within this file we reference them via the router module.
mod rustgate_transport_types {
    pub use crate::router::{Router, SessionHandle};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_udp_config() {
        let cfg = UdpInputConfig::default();
        assert_eq!(cfg.cn, "udp-anonymous");
        assert_eq!(cfg.default_group, "__plaintext__");
    }

    #[tokio::test]
    async fn udp_receives_and_routes() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let local_addr = socket.local_addr().expect("local_addr");

        let router = Arc::new(Router::new());
        let config = UdpInputConfig::default();
        let shutdown = Arc::new(Notify::new());
        let shutdown_clone = Arc::clone(&shutdown);

        // Register a listener in the same default group to receive routed messages
        let mut groups = BTreeSet::new();
        let _ = groups.insert("__plaintext__".to_string());
        let listener_identity = Arc::new(
            Identity::plaintext("test-listener".to_string(), groups).expect("valid identity"),
        );
        let (listener_tx, mut listener_rx) = mpsc::channel::<Arc<RoutableMessage>>(16);
        let listener_handle = SessionHandle::new(listener_identity, listener_tx);
        router.register(listener_handle).await;

        let router_clone = Arc::clone(&router);
        let task = tokio::spawn(async move {
            UdpInput::run(
                socket,
                router_clone,
                config,
                None,
                None,
                None,
                shutdown_clone,
            )
            .await;
        });

        // Send a CoT-like datagram
        let client = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");
        let payload = b"<event version=\"2.0\" uid=\"test\" type=\"a-f-G\" />";
        let sent = client.send_to(payload, local_addr).await.expect("send");
        assert_eq!(sent, payload.len());

        // Give it a moment to process
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // The message should have been broadcast-routed
        // (The listener is in the same group, so should receive it via broadcast)
        // Note: The UDP identity CN is per-datagram with address suffix,
        // so broadcast routing will deliver to all except the sender CN.
        // Since test-listener has a different CN, it should receive it.
        let msg = tokio::time::timeout(std::time::Duration::from_secs(1), listener_rx.recv())
            .await
            .expect("timeout")
            .expect("recv");
        assert_eq!(msg.metadata.source_protocol, "udp");

        shutdown.notify_one();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), task).await;
    }

    #[tokio::test]
    async fn udp_shutdown_clean() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let router = Arc::new(Router::new());
        let config = UdpInputConfig::default();
        let shutdown = Arc::new(Notify::new());
        let shutdown_clone = Arc::clone(&shutdown);

        let router_clone = Arc::clone(&router);
        let task = tokio::spawn(async move {
            UdpInput::run(
                socket,
                router_clone,
                config,
                None,
                None,
                None,
                shutdown_clone,
            )
            .await;
        });

        // Immediate shutdown
        shutdown.notify_one();
        let result = tokio::time::timeout(std::time::Duration::from_secs(2), task).await;
        assert!(result.is_ok(), "UDP input should shut down promptly");
    }
}
