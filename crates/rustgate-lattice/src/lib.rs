// Copyright © 2026 Roberto Chiofalo.

#![forbid(unsafe_code)]

//! Anduril Lattice bidirectional adapter for rustgate.
//!
//! This crate lets rustgate present itself as a native Lattice sensor
//! feed (publishing tactical entities outbound) and as a Lattice
//! command consumer (draining entities inbound and re-injecting them
//! into the router for fan-out across CoT, MAVLink, NATS, and the
//! other registered protocols).
//!
//! # MVP scope
//!
//! The Lattice gRPC SDK ships behind Anduril partnership / NDA.
//! Including the real proto bindings in this PR is not possible
//! without that access. The MVP therefore ships the **integration
//! shape** so a partner-side PR that drops in the actual `tonic`
//! client behind the `lattice-real` feature is a small, contained
//! change that does not have to touch the router, the server binary,
//! or the wiring helpers.
//!
//! Concretely the MVP delivers:
//!
//! - The [`bridge::LatticeBridge`] async trait — `publish_entity`,
//!   `subscribe_entities`, `report_health`. Three methods is enough
//!   for the sensor-feed and command-consumer paths Lattice asks of
//!   a third-party data source.
//! - [`bridge::Entity`], [`bridge::EntityFilter`],
//!   [`bridge::HealthStatus`] — the shared types every backend
//!   round-trips. Designed to map cleanly to Lattice's `Entity` /
//!   `EntityFilter` proto when those bindings land.
//! - `mock::MockLatticeBridge` (feature `lattice-mock`) — an
//!   in-memory, channel-backed implementation that is sufficient for
//!   integration testing the router → bridge → router round trip
//!   without an actual Lattice endpoint.
//! - [`config::LatticeConfig`] — TOML deserialisation for the
//!   `[lattice]` block in `rustgate.toml`. Auth surface declares
//!   mTLS cert / key paths plus a JWT secret path; no actual SDK
//!   call yet, but the schema is wired so the real-SDK PR can
//!   consume it without churn.
//! - [`wiring::spawn_outbound_task`] /
//!   [`wiring::spawn_inbound_task`] — background tasks that the
//!   server binary uses to plug a bridge into a
//!   [`rustgate_router::Router`] message stream. Both are
//!   parameterised over `Arc<dyn LatticeBridge>` so the partner
//!   real-SDK impl plugs in unchanged.
//!
//! # Future work — `lattice-real`
//!
//! The `lattice-real` feature is declared in `Cargo.toml` today
//! with no deps and no module behind it. A follow-up PR (after
//! Lattice SDK access is available) lands the partner-side
//! `tonic` client + the `LatticeBridge` impl that wraps it,
//! gated behind the same flag. Consumers who already wire the
//! mock backend will not have to change anything beyond the
//! feature selection.
//!
//! # Architecture
//!
//! ```text
//!                ┌────────────────────────┐
//!                │    rustgate-router     │
//!                │      (Router<...>)     │
//!                └────────────────────────┘
//!                  on_delivered │  ▲ Router::route
//!                               │  │
//!                               ▼  │
//!     ┌────────────────────────────────────────────────┐
//!     │          rustgate-lattice (this crate)         │
//!     │                                                │
//!     │  spawn_outbound_task ─┐         ┌── spawn_inbound_task
//!     │                       ▼         ▼              │
//!     │           ┌────────────────────────┐           │
//!     │           │  LatticeBridge trait   │           │
//!     │           └────────────────────────┘           │
//!     │                ▲             ▲                 │
//!     │                │             │                 │
//!     │      MockLatticeBridge    real-SDK impl        │
//!     │      (lattice-mock)       (lattice-real, TBD)  │
//!     └────────────────────────────────────────────────┘
//! ```
//!
//! # Integration points
//!
//! The bridge is consumed from `rustgate-server` startup. When the
//! `[lattice]` config block is present and the operator has selected
//! a backend feature flag (`lattice-mock` for testing or
//! `lattice-real` once available), the server constructs the bridge,
//! calls [`wiring::spawn_outbound_task`] to subscribe to position /
//! track messages on the router, and calls
//! [`wiring::spawn_inbound_task`] to drain Lattice's
//! [`bridge::LatticeBridge::subscribe_entities`] stream and feed
//! [`rustgate_router::Router::route`].

pub mod bridge;
pub mod config;
pub mod error;
pub mod wiring;

#[cfg(feature = "lattice-mock")]
pub mod mock;

pub use bridge::{Entity, EntityFilter, EntityKind, GeoBbox, HealthStatus, LatticeBridge};
pub use config::{LatticeAuth, LatticeConfig};
pub use error::{LatticeError, Result};
#[cfg(feature = "lattice-mock")]
pub use mock::MockLatticeBridge;
pub use wiring::{spawn_inbound_task, spawn_outbound_task};
