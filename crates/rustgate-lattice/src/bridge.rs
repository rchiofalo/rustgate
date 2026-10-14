// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Bridge trait and shared types for the Lattice adapter.
//!
//! The trait surface is intentionally minimal — three async methods
//! that cover the publish-out / subscribe-in / report-health paths
//! Lattice asks of a third-party data source. Implementations are
//! always boxed behind `Arc<dyn LatticeBridge>` at every consumer in
//! the workspace so the partner-side real-SDK impl drops in unchanged.

use std::sync::Arc;
use std::time::SystemTime;

use bytes::Bytes;
use futures::stream::BoxStream;
use serde::{Deserialize, Serialize};

use crate::error::Result;

// `Entity::payload` carries a `bytes::Bytes` whose `Deserialize`
// impl ships behind a non-default `serde` feature on the upstream
// crate. The MVP mock backend never round-trips an `Entity` through
// `serde`, and the partner real-SDK PR will own its own
// proto-to-`Entity` mapping (it will not deserialise `Entity` from
// JSON / TOML directly). So `Entity` derives only `Debug` and
// `Clone`; downstream types whose payloads are pure primitives
// continue to derive `Serialize` / `Deserialize` so they can flow
// through `serde` for the `LatticeConfig` parse path and for any
// future `--dry-run` / golden-file assertion harness.

/// The async trait every Lattice backend implements.
///
/// Implementations MUST be `Send + Sync` because `Arc<dyn LatticeBridge>`
/// is held across `tokio::spawn` boundaries in
/// [`crate::wiring::spawn_outbound_task`] /
/// [`crate::wiring::spawn_inbound_task`]. The trait uses
/// [`async_trait`] so it can stay object-safe; an `impl Trait` return
/// type would prevent the `Arc<dyn ..>` indirection that lets the
/// backend be swapped at startup.
#[async_trait::async_trait]
pub trait LatticeBridge: Send + Sync {
    /// Symbolic backend name (`"mock"`, `"real-grpc"`, ...).
    ///
    /// Used in error messages and audit fields so the operator can
    /// distinguish between bridges in a multi-bridge deployment.
    /// Returned as `&'static str` because every implementation knows
    /// its own backend name at compile time.
    fn backend_name(&self) -> &'static str;

    /// Publish a single tactical [`Entity`] outbound to Lattice.
    ///
    /// Implementations MUST be safe to call from many tasks
    /// concurrently — the outbound task drives one publish per
    /// router event and does not serialise. The MVP outbound task
    /// (`spawn_outbound_task`) does its own batching at the channel
    /// edge; backends that prefer to batch on the wire SHOULD do so
    /// internally rather than blocking the per-call return.
    async fn publish_entity(&self, entity: Entity) -> Result<()>;

    /// Subscribe to inbound entities matching `filter`.
    ///
    /// Returns a [`BoxStream`] of [`Entity`] values, terminated when
    /// the underlying Lattice subscription drops or the bridge is
    /// shutdown. The stream is single-consumer by design; the
    /// inbound wiring task in [`crate::wiring::spawn_inbound_task`]
    /// drains it serially and re-injects each entity into the
    /// router.
    async fn subscribe_entities(&self, filter: EntityFilter) -> Result<BoxStream<'static, Entity>>;

    /// Report rustgate's local health to Lattice.
    ///
    /// Lattice expects every connected feed / consumer to publish a
    /// liveness signal periodically; the wiring task drives this on
    /// a fixed cadence (30s by default) so the bridge does not have
    /// to manage its own timer.
    async fn report_health(&self, status: HealthStatus) -> Result<()>;
}

/// A tactical entity in the Lattice shape.
///
/// Designed to map to Lattice's `Entity` proto when those bindings
/// land. Field names follow the protobuf casing the SDK uses so the
/// real-SDK impl can adopt this struct verbatim or, at worst, with a
/// trivial field-by-field translation.
///
/// `payload` carries the wire-format body (CoT XML, MAVLink frame,
/// or any other registered codec output) so the inbound side can
/// re-inject the entity into the router as a `RoutableMessage`
/// without any Lattice-specific knowledge in the router.
#[derive(Debug, Clone)]
pub struct Entity {
    /// Stable identifier — Lattice's `entity_id`. Used for dedup on
    /// the inbound side and for correlation in publish-failure audit
    /// records.
    pub entity_id: String,
    /// The entity kind ([`EntityKind`]) — the inbound wiring uses
    /// this to map back into a [`rustgate_core::message::MessageType`]
    /// without inspecting the payload.
    pub kind: EntityKind,
    /// Geodetic position, optional because not every Lattice entity
    /// is georeferenced (a notional `Order` or `Task` may not be).
    pub position: Option<GeoPosition>,
    /// Wall-clock timestamp the source recorded the entity at.
    /// Used to seed `Metadata::received_at` on the inbound side.
    pub observed_at: SystemTime,
    /// Opaque wire-format body. Treated as `Bytes` so the inbound
    /// path can re-construct a `RoutableMessage::payload` without an
    /// intermediate `Vec<u8>` copy.
    pub payload: Bytes,
    /// Source CN that produced this entity, when known. The mock
    /// backend forwards the originating router CN here so the
    /// inbound integration test can assert round-trip fidelity.
    pub source_cn: Option<String>,
}

/// Filter applied to the inbound subscription.
///
/// Designed to map to Lattice's `EntityFilter` proto. Today the
/// filter set is a geo bounding-box plus a list of allowed
/// [`EntityKind`] values — extension fields can be added as
/// optionals without breaking the trait.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EntityFilter {
    /// Optional geographic bounding box; `None` accepts entities at
    /// any location.
    pub geo_bbox: Option<GeoBbox>,
    /// Allowed entity kinds; an empty vector accepts every kind.
    pub types: Vec<EntityKind>,
}

/// Coarse-grained categorisation of a Lattice entity.
///
/// Intentionally narrow — every additional variant is a wire-format
/// commitment to the partner-side SDK, so this list mirrors the
/// MVP-relevant subset of Lattice's `Entity.Kind` enum and lets the
/// rest fall under [`EntityKind::Other`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EntityKind {
    /// A moving track — the canonical position-report case Lattice
    /// expects from a sensor feed.
    Track,
    /// A stationary or slow-moving platform (vehicle, station).
    Platform,
    /// A geospatial annotation (waypoint, no-fly zone, ROZ).
    Annotation,
    /// A signal-of-interest contact.
    Signal,
    /// Anything else — carrying an opaque label so a follow-up PR
    /// can extend the enum without breaking serialisation.
    Other(String),
}

/// Geographic position in WGS-84 decimal degrees plus optional altitude.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct GeoPosition {
    /// Latitude in decimal degrees (`[-90.0, 90.0]`).
    pub latitude: f64,
    /// Longitude in decimal degrees (`[-180.0, 180.0]`).
    pub longitude: f64,
    /// Altitude in metres above the WGS-84 ellipsoid, optional.
    pub altitude_m: Option<f64>,
}

/// Geographic bounding box for [`EntityFilter`].
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct GeoBbox {
    /// Southern latitude bound.
    pub min_lat: f64,
    /// Northern latitude bound.
    pub max_lat: f64,
    /// Western longitude bound.
    pub min_lon: f64,
    /// Eastern longitude bound.
    pub max_lon: f64,
}

impl GeoBbox {
    /// Returns `true` when `pos` is inside the bounding box (inclusive).
    ///
    /// Antimeridian-crossing boxes (`min_lon > max_lon`) are NOT
    /// supported in the MVP — operators should split such regions
    /// into two filters. The check returns `false` for non-finite
    /// coordinates.
    pub fn contains(&self, pos: &GeoPosition) -> bool {
        let lat_ok = pos.latitude.is_finite()
            && pos.latitude >= self.min_lat
            && pos.latitude <= self.max_lat;
        let lon_ok = pos.longitude.is_finite()
            && pos.longitude >= self.min_lon
            && pos.longitude <= self.max_lon;
        lat_ok && lon_ok
    }
}

/// Liveness / health signal a bridge reports back to Lattice.
///
/// Designed to map to a Lattice-side health proto. The fields are
/// intentionally generic (uptime + pending counts + a free-form
/// detail string) so a real-SDK PR can either consume them
/// verbatim or fan them out into Lattice's richer health surface
/// without churning every consumer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    /// Symbolic source name, usually `"rustgate"` plus the local
    /// hostname suffix.
    pub source: String,
    /// Cumulative count of entities published outbound since
    /// process start.
    pub published_count: u64,
    /// Cumulative count of entities consumed inbound.
    pub consumed_count: u64,
    /// Free-form status detail (e.g. `"healthy"`, `"degraded:
    /// federation-circuit-open"`).
    pub detail: String,
}

/// Convenience alias used by callers that want to share a single
/// bridge across many tasks. Equivalent to
/// `Arc<dyn LatticeBridge + Send + Sync>` but spelled here so the
/// type appears in rustdoc once and consumers do not have to know
/// the full trait-object syntax.
pub type SharedBridge = Arc<dyn LatticeBridge>;
