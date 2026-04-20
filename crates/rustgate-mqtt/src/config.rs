// Copyright © 2026 Roberto Chiofalo.

//! Configuration for the MQTT server.

use std::sync::Arc;

use rustgate_transport::Router;
use tokio::sync::{Notify, Semaphore};

use crate::listener::MqttListener;
use crate::topic::WildcardPolicy;

/// Configuration for [`MqttServer::run`](crate::MqttServer::run).
#[derive(Debug)]
pub struct MqttServerConfig {
    /// The bound MQTT TLS listener.
    pub listener: MqttListener,

    /// Shared router for message delivery.
    pub router: Arc<Router>,

    /// Connection-limit semaphore shared across all transports.
    pub connection_limit: Arc<Semaphore>,

    /// Shutdown signal.
    pub shutdown: Arc<Notify>,

    /// Optional prefix to strip from MQTT topics before mapping to groups.
    ///
    /// For example, with `topic_prefix = Some("rustgate/".into())`, the MQTT
    /// topic `rustgate/alpha` maps to group `alpha`. Topics that do not start
    /// with the prefix are rejected.
    pub topic_prefix: Option<String>,

    /// Maximum MQTT packet size in bytes (default: 16 MiB).
    pub max_packet_size: usize,

    /// Minimum keep-alive interval in seconds. Clients requesting 0
    /// (disabled) or a value below this floor get this value imposed.
    pub min_keep_alive_secs: u16,

    /// Channel capacity for response packets flowing from read loop to
    /// write loop (per session).
    pub response_channel_capacity: usize,

    /// Wildcard policy applied to SUBSCRIBE topic filters.
    ///
    /// Default is [`WildcardPolicy::SingleLevelOnly`], which accepts `+`
    /// (single-level) filters such as `fleet/+/position` but rejects `#`
    /// (multi-level). Set to [`WildcardPolicy::Full`] on listeners where
    /// authorised clients legitimately need full-subtree subscriptions;
    /// set to [`WildcardPolicy::Reject`] to match pre-wildcard behaviour.
    pub wildcard_policy: WildcardPolicy,
}

impl MqttServerConfig {
    /// Default maximum packet size: 16 MiB (matches websocket frame cap).
    pub const DEFAULT_MAX_PACKET_SIZE: usize = 16 * 1024 * 1024;

    /// Default minimum keep-alive in seconds.
    pub const DEFAULT_MIN_KEEP_ALIVE_SECS: u16 = 30;

    /// Default response channel capacity per session.
    pub const DEFAULT_RESPONSE_CHANNEL_CAPACITY: usize = 64;
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, unused_results)]
mod tests {
    use rustgate_core::constants::MAX_FRAME_SIZE;

    use super::*;

    // ------------------------------------------------------------------
    // Default constants — pin the wire / operator-visible numbers.
    // Changing any of these affects CONNACK negotiation, keep-alive
    // floors, and session memory footprint, so a silent drift in the
    // constant is exactly the sort of thing this test catches.
    // ------------------------------------------------------------------

    #[test]
    fn default_max_packet_size_is_sixteen_mib() {
        // 16 MiB keeps MQTT in lockstep with the websocket frame cap
        // and with `rustgate_core::constants::MAX_FRAME_SIZE`.
        assert_eq!(MqttServerConfig::DEFAULT_MAX_PACKET_SIZE, 16 * 1024 * 1024,);
        assert_eq!(MqttServerConfig::DEFAULT_MAX_PACKET_SIZE, 16_777_216);
    }

    #[test]
    fn default_max_packet_size_matches_shared_frame_cap() {
        // Cross-check that the MQTT default does not drift away from
        // the workspace-wide shared frame cap used by the length-
        // prefixed and protobuf codecs.
        assert_eq!(MqttServerConfig::DEFAULT_MAX_PACKET_SIZE, MAX_FRAME_SIZE,);
    }

    #[test]
    fn default_min_keep_alive_is_thirty_seconds() {
        // Clients requesting 0 (disabled) or a smaller value have this
        // value forced upon them — changing it alters CONNACK behaviour.
        assert_eq!(MqttServerConfig::DEFAULT_MIN_KEEP_ALIVE_SECS, 30);
    }

    #[test]
    fn default_response_channel_capacity_is_sixty_four() {
        // Per-session backpressure boundary between the read loop and
        // the write loop. Changing this affects memory accounting in
        // tests that assert queue depth.
        assert_eq!(MqttServerConfig::DEFAULT_RESPONSE_CHANNEL_CAPACITY, 64);
    }

    // ------------------------------------------------------------------
    // Trait bounds — pin compile-time invariants cheaply, without
    // spinning up a Router / TLS stack just to test `Debug`.
    // ------------------------------------------------------------------

    #[test]
    fn config_type_is_debug() {
        // The `#[derive(Debug)]` must remain — tracing expansions such
        // as `tracing::info!(?config, ...)` would fail to compile if a
        // future refactor accidentally dropped the derive.
        fn assert_debug<T: std::fmt::Debug>() {}
        assert_debug::<MqttServerConfig>();
    }
}
