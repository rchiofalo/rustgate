// Copyright © 2026 Roberto Chiofalo.

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

/// Canonical value of the `transport` structured-log field emitted by every
/// session-lifecycle event in this crate.
///
/// Exposed as a named constant (not a magic string) so downstream consumers
/// grep for the exact token their log aggregator is configured against, and
/// so a future rename surfaces as a single-point diff rather than a silent
/// dashboard regression.
pub const TRANSPORT_LABEL: &str = "mqtt";

pub use config::{MqttServerConfig, OnMqttAccept, OnMqttReject};
pub use error::MqttError;
pub use listener::MqttListener;
pub use server::MqttServer;
pub use topic::{
    WildcardPolicy, filter_has_wildcards, filter_matches, topic_to_group, validate_publish_topic,
    validate_subscribe_filter, validate_topic_prefix,
};
