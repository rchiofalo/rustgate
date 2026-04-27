// Copyright © 2026 Roberto Chiofalo.

//! Server-to-server federation for cross-network message routing.
//!
//! This crate implements both the V1 (length-prefixed XML over mTLS) and
//! V2 (gRPC over mTLS) federation protocols. The [`manager::FederationManager`]
//! orchestrates peer connections, heartbeats, circuit breakers, and message
//! forwarding. Peer configuration is persisted via the [`store`] module and
//! dynamic TLS trust is managed by [`trust_store::TrustStore`].
//!
//! # Error handling
//!
//! This crate does not expose a single umbrella `FederationError`; each
//! submodule with a distinct failure surface defines its own typed enum
//! (e.g. [`jwt::JwtError`], [`replay_persist::ReplayStoreError`]). Binary
//! callers in `rustgate-server` propagate these via `?` and surface them
//! through `anyhow::Error` at the orchestration layer;
//! [`rustgate_core::error::RustgateError`] is the boundary aggregator for
//! the `rustgate-core` / `rustgate-transport` slice and is not
//! automatically constructed from this crate's per-submodule errors.

pub mod config;
pub mod connector;
pub mod dedup;
#[cfg(any(
    feature = "peer-discovery-dns-sd",
    feature = "peer-discovery-consul",
    feature = "peer-discovery-etcd"
))]
pub mod discovery;
#[cfg(feature = "ha")]
pub mod ha;
pub mod heartbeat;
pub mod jwt;
pub mod manager;
pub mod peer;
pub mod provenance;
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
