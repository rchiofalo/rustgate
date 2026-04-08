//! Server-to-server federation for cross-network message routing.
//!
//! This crate implements both the V1 (length-prefixed XML over mTLS) and
//! V2 (gRPC over mTLS) federation protocols. The [`manager::FederationManager`]
//! orchestrates peer connections, heartbeats, circuit breakers, and message
//! forwarding. Peer configuration is persisted via the [`store`] module and
//! dynamic TLS trust is managed by [`trust_store::TrustStore`].

pub mod config;
pub mod connector;
pub mod dedup;
#[cfg(feature = "ha")]
pub mod ha;
pub mod heartbeat;
pub mod jwt;
pub mod manager;
pub mod peer;
pub mod provenance;
mod reconnect;
pub mod replay_buffer;
pub mod replay_persist;
pub mod store;
pub mod trust_store;
pub mod v1;
pub mod v2;

#[cfg(feature = "api")]
pub mod api;
#[cfg(feature = "api")]
pub mod metrics;
