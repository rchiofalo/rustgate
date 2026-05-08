// Copyright © 2026 Roberto Chiofalo.

//! Bidirectional bridge between rustgate entities and **Palantir
//! Foundry / Gotham** ontology objects.
//!
//! The Foundry ontology models the world as typed objects (Person,
//! Vehicle, Track, Event, …) connected by typed links, mutated through
//! REST upserts and surfaced to clients through WebSocket change
//! streams and Action triggers (operator-fired button presses on a
//! Foundry workspace). This crate maps a [`rustgate_core::entity::Entity`]
//! into and out of that shape so the router can fan tactical traffic
//! into Foundry alongside CoT XML, MAVLink, ASTERIX, STANAG-4586, VMF,
//! Link 16, and the rest of the workspace's wire formats.
//!
//! # Scope of this deliverable
//!
//! Foundry's REST/WebSocket SDK is partner-gated, so the integration
//! is intentionally split:
//!
//! - **Trait + scaffold (this crate, default build)** — the
//!   [`bridge::FoundryBridge`] trait, the [`config::FoundryConfig`]
//!   TOML schema, the [`mapper::PropertyMapper`] dotted-path
//!   property-map machinery, and the inbound/outbound wiring tasks in
//!   [`wiring`]. Everything the partner-gated SDK does NOT need to
//!   know about lives here.
//! - **`foundry-mock` feature** — `mock::MockFoundryBridge`, an
//!   in-memory store + change broadcaster that drives the wiring
//!   end-to-end in tests without any network surface. The mock is
//!   the reference implementation against which the partner-gated
//!   SDK code is written.
//! - **`foundry-real` feature** — currently a placeholder for the
//!   partner-gated REST/WebSocket SDK integration. Bringing the real
//!   integration online is a contained follow-up: implement
//!   `FoundryBridge` against the SDK's REST `upsert` /
//!   WebSocket-stream endpoints and gate the existing wiring on this
//!   feature flag without touching any other crate.
//!
//! # Round-trip discipline
//!
//! `Entity` ↔ Foundry `properties` is **lossy by design** — the
//! property-map declares which entity fields project onto which
//! Foundry properties and the rest of the entity state is
//! intentionally dropped. Callers that need full round-trip fidelity
//! also persist the entity to a wire-format-preserving sink (CoT XML,
//! protobuf) alongside the Foundry projection. This is consistent
//! with the [`rustgate_core::entity::EntityCodec`] cross-codec
//! contract: same-protocol round-trip is preserved; cross-protocol
//! fan-out drops attributes the destination format does not carry.
//!
//! # Offline replay
//!
//! When the bridge returns [`error::FoundryError::Offline`], the
//! outbound wiring queues the failed upsert into an in-memory FIFO
//! capped at [`wiring::OFFLINE_QUEUE_CAPACITY`] entries. On the next
//! successful upsert (the bridge transitions Offline → Online) the
//! queue drains in FIFO order with last-writer-wins semantics — if
//! two queued upserts target the same `(type_id, uid)` the later one
//! supersedes the earlier. The queue is bounded; on overflow the
//! oldest entry is evicted. A persistent on-disk queue lands once the
//! real SDK is wired up — see the `wiring` module docs for the
//! interface boundary that keeps the swap contained.
//!
//! # What is deliberately absent
//!
//! - **Real REST/WebSocket calls.** Behind `foundry-real`, currently
//!   stubbed.
//! - **Action invocation execution.** [`bridge::FoundryBridge::invoke_action`]
//!   is on the trait so the wiring shape is final, but the action
//!   stream that triggers RoutableMessage injection on Foundry
//!   button-presses is wired up alongside the real SDK.
//! - **Authentication.** OAuth2 / Bearer / JWT against the Foundry
//!   tenant is the SDK's responsibility — the trait carries opaque
//!   credentials in the config and the implementation maps them to
//!   the SDK's auth flow.
//!
//! # Public API
//!
//! - [`bridge::FoundryBridge`] — async trait, the integration boundary
//! - [`bridge::ObjectId`] / [`bridge::ObjectChange`] /
//!   [`bridge::ActionRequest`] / [`bridge::ActionResult`] — wire types
//! - [`config::FoundryConfig`] — TOML config root
//! - [`mapper::PropertyMapper`] — dotted-path entity ↔ JSON projection
//! - `mock::MockFoundryBridge` (feature `foundry-mock`)
//! - [`wiring::spawn_outbound`] / [`wiring::spawn_inbound`]
//! - [`error::FoundryError`]

#![forbid(unsafe_code)]
#![doc(html_no_source)]

pub mod bridge;
pub mod config;
pub mod error;
pub mod mapper;
pub mod wiring;

#[cfg(feature = "foundry-mock")]
pub mod mock;

pub use bridge::{ActionRequest, ActionResult, FoundryBridge, ObjectChange, ObjectId};
pub use config::{FoundryConfig, ObjectTypeMapping, PropertyMap};
pub use error::FoundryError;
pub use mapper::PropertyMapper;
#[cfg(feature = "foundry-mock")]
pub use mock::MockFoundryBridge;
pub use wiring::{OFFLINE_QUEUE_CAPACITY, OutboundHandle};
