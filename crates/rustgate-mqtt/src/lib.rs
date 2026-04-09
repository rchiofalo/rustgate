//! MQTT 5.0/3.1.1 transport adapter for rustgate.
//!
//! Provides an MQTT listener that accepts connections over mTLS, translates
//! MQTT PUBLISH/SUBSCRIBE operations into rustgate router actions, and
//! delivers routed messages back to subscribed MQTT sessions.
//!
//! # Protocol support
//!
//! - **MQTT 5.0** — full user properties, reason codes, session expiry
//! - **MQTT 3.1.1** — backward-compatible via protocol-level negotiation
//! - **QoS 0** (at-most-once) and **QoS 1** (at-least-once)
//! - **mTLS** — identity derived exclusively from the client certificate
//!
//! # Architecture
//!
//! The adapter follows rustgate's transport-crate pattern: a [`MqttListener`]
//! accepts TLS connections, a [`MqttServer`] manages the accept loop and
//! session lifecycle, and each session registers with the shared
//! [`Router`](rustgate_transport::Router) for message delivery.
//!
//! MQTT topics map to rustgate groups (1:1 by default, with optional prefix
//! stripping). Authorization is enforced by the router's authz PEP on every
//! PUBLISH and SUBSCRIBE.

mod config;
mod error;
mod listener;
mod packet;
mod server;
mod session;
mod topic;

pub use config::MqttServerConfig;
pub use error::MqttError;
pub use listener::MqttListener;
pub use server::MqttServer;
pub use topic::{topic_to_group, validate_publish_topic, validate_subscribe_filter};
