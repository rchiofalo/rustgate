// Copyright © 2026 Roberto Chiofalo.

//! OGC SensorThings API v1.0 client integration for rustgate.
//!
//! [OGC SensorThings] is the open-standard REST + JSON + MQTT
//! interface for IoT sensor data. NGA, NATO Centre for Maritime
//! Research and Experimentation (CMRE), and allied agencies use it
//! for geospatial sensor sharing — weather stations, hydrometric
//! gauges, seismic networks, CBRN sensors, and similar fixed-station
//! telemetry feeds. The data model is a graph:
//!
//! - `Things` — the physical sensor station (a buoy, a met tower, a
//!   chemical detector).
//! - `Datastreams` — each measurement stream a `Thing` produces, with
//!   its own `ObservedProperty`, `Sensor`, and unit.
//! - `Sensors` — descriptive metadata about the measurement device.
//! - `ObservedProperties` — what is being measured (`Temperature`,
//!   `WindSpeed`, `gamma_dose_rate`, …).
//! - `Observations` — the actual measurements, each with a
//!   `phenomenonTime` and a `result`. This is the firehose.
//! - `Locations` — geospatial position of a `Thing` (typically GeoJSON
//!   `Point` or `Polygon`).
//! - `FeatureOfInterest` — what the observation is *about* (often
//!   the same as the `Thing`'s `Location` for fixed stations).
//!
//! On the wire the server exposes a hypermedia tree under a v1.0 root
//! such as `https://example.org/SensorThings/v1.0/`. Clients reach
//! observations either by polling a REST URL such as
//! `…/Datastreams(42)/Observations?$top=100&$orderby=phenomenonTime+desc`
//! (this crate's MVP) or by subscribing to an MQTT topic such as
//! `v1.0/Datastreams(42)/Observations` (deferred — see below).
//!
//! # Scope of this deliverable (MVP)
//!
//! This crate ships a **client-side adapter** that polls a remote
//! SensorThings server, decodes incoming `Observation` documents, maps
//! each one to a canonical [`rustgate_core::entity::Entity`] under
//! [`rustgate_core::entity::EntityKind::Sensor`], and feeds the
//! resulting [`rustgate_core::message::RoutableMessage`] into a
//! [`rustgate_router::Router`] for normal cross-protocol fan-out.
//!
//! - **MVP transport: HTTP polling.** Each configured datastream is
//!   polled on its own configurable interval (default 30 s). The
//!   poller carries the most recent `phenomenonTime` it has seen so
//!   subsequent polls request only newer observations via
//!   `?$filter=phenomenonTime gt …` — no client-side dedup is needed.
//! - **MQTT push subscription is deferred.** SensorThings v1.0 also
//!   defines an MQTT publish/subscribe transport (`v1.0/Datastreams(N)/Observations`)
//!   for push notification. That half lands in a follow-up issue and
//!   reuses the existing [`rustgate-mqtt`] client capability — the
//!   payload shape is identical to the REST-polled `Observation`
//!   document, so the [`mapper`] module is shared verbatim.
//! - **Location resolution.** When the operator opts into it, the
//!   poller widens the request to
//!   `?$expand=Datastream/Thing/Locations` so the lat/lon for each
//!   observation arrives in a single round trip rather than four
//!   chained GETs (`Observation` → `Datastream` → `Thing` →
//!   `Locations`). This is the standard SensorThings pattern. See
//!   [`client`] for how the expand mode is enabled.
//! - **Authentication.** For the REST polling path, bearer-token
//!   auth via a path-on-disk secret (mode-checked + `Zeroizing`
//!   wrapped at load time) is the only mode supported. For the MQTT
//!   push path, username/password authentication is supported via
//!   the `username` (inline) + `password-path` (file on disk,
//!   mode-checked + `Zeroizing`-wrapped) pair on
//!   [`config::MqttPushConfig`]. mTLS, OAuth2, and API-key auth are
//!   out of scope for this PR — the configuration schema reserves
//!   the bearer-token slot under `auth-token-path` so a follow-up
//!   can layer additional auth modes without churning operators'
//!   `rustgate.toml`.
//!
//! # Round-trip discipline
//!
//! `Observation` → `Entity` is intentionally **lossy** — the strict
//! subset of SensorThings fields the MVP carries onto the entity
//! (`uid`, `position`, `timestamp`, plus a curated set of
//! `attributes.sensorthings.*` keys) is the slice the router and
//! downstream codecs can usefully act on. The `result` value, the
//! `Datastream` id, and the original `phenomenonTime` string ride on
//! the attribute bag verbatim so an audit consumer that wants the
//! full upstream JSON can recover everything that mattered. This is
//! consistent with the cross-codec contract pinned by the
//! [`rustgate_core::entity::EntityCodec`] trait — we are not a codec
//! (the wire form is a JSON document arriving over an HTTP fetch, not
//! a wire-format frame), but the same lossy-but-recoverable shape
//! applies.
//!
//! # What is deliberately absent
//!
//! - **MQTT push subscription** — deferred to a follow-up; the MVP
//!   exposes the polling path only.
//! - **HistoricalLocations / FeaturesOfInterest enumeration** — the
//!   MVP polls `Datastreams(N)/Observations` and resolves Location
//!   via `$expand`. The full hypermedia surface is not exposed.
//! - **Server-side filter authoring** — operators can configure
//!   `$filter` strings in `rustgate.toml`, but the crate does not
//!   compose filters from rustgate-side ACL/authz state.
//! - **Submitting observations back** — this is a one-way client
//!   (server → rustgate). Bidirectional support (rustgate publishing
//!   to SensorThings via `POST Observations`) is out of scope.
//! - **Outbound writeback to Foundry / Lattice** — the crate hands
//!   each observation to the router as a `RoutableMessage`; routing
//!   to other adapters happens through normal router fan-out.
//!
//! # Public API
//!
//! - [`client::SensorThingsClient`] — HTTP polling client
//! - [`config::SensorThingsConfig`] / [`config::Subscription`] —
//!   TOML config root + per-datastream subscription entry
//! - [`mapper::observation_to_entity`] — pure projection
//!   `Observation` → `Entity`
//! - [`types::Observation`] / [`types::Datastream`] /
//!   [`types::Location`] / [`types::Thing`] —
//!   serde-derived wire types (the strict subset the mapper needs)
//! - [`wiring::spawn_polling_task`] — spawns the per-datastream
//!   polling background task and returns a [`SubsystemHandle`]
//!   for graceful shutdown
//! - [`error::SensorThingsError`] — typed failure enum
//!
//! [OGC SensorThings]: https://www.ogc.org/standard/sensorthings/
//! [`rustgate-mqtt`]: https://github.com/rchiofalo/rustgate
//! [`SubsystemHandle`]: rustgate_core::tasks::SubsystemHandle

#![forbid(unsafe_code)]
#![doc(html_no_source)]

pub mod client;
pub mod config;
pub mod error;
pub mod mapper;
#[cfg(feature = "mqtt-push")]
pub mod mqtt_push;
pub mod types;
pub mod wiring;

pub use client::SensorThingsClient;
pub use config::{EntityKindTag, MqttPushConfig, SensorThingsConfig, Subscription};
pub use error::SensorThingsError;
pub use mapper::observation_to_entity;
#[cfg(feature = "mqtt-push")]
pub use mqtt_push::spawn_mqtt_push_task;
pub use types::{Datastream, Location, Observation, ObservationsPage, Thing};
pub use wiring::{SOURCE_OGC_SENSORTHINGS, spawn_polling_task};
