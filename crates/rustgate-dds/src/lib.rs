// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Bidirectional bridge between rustgate entities and a **DDS
//! (Data Distribution Service)** in-vehicle data bus.
//!
//! DDS is mandated for in-vehicle networking by NATO Generic Vehicle
//! Architecture (NGVA, **STANAG 4754**) and the US Army's Vehicular
//! Integration for C4ISR/EW Interoperability (VICTORY) standard.
//! Every modern NATO armored vehicle and a growing fleet of US
//! ground platforms ship a DDS data bus carrying Navigation, Video,
//! Alarms, and Weapons topics under the **NGVA Land Data Model**.
//!
//! This crate gives rustgate a `Subscriber` shape over those topics
//! and a `Publisher` shape for the reverse direction so a tactical
//! deployment can fan in-vehicle telemetry up to TAK / NATS / MQTT
//! consumers and inject mission orders back down to the bus.
//!
//! # Scope of this deliverable
//!
//! Production-grade DDS Rust bindings are still maturing
//! (`cyclonedds-rs` is unmaintained as of 2026; `dust-dds` is
//! pure-Rust but pre-1.0). The integration is intentionally split:
//!
//! - **Trait + scaffold (this crate, default build)** — the
//!   [`bridge::DdsBridge`] trait, the [`config::DdsConfig`] TOML
//!   schema, the [`mapper::PropertyMapper`] dotted-path projection
//!   machinery, and the inbound / outbound wiring tasks in
//!   [`wiring`]. Everything the eventual real-SDK adapter does NOT
//!   need to know about lives here.
//! - **`dds-mock` feature** — `mock::MockDdsBridge`, an in-memory
//!   broadcast-channel-per-topic implementation that drives the
//!   wiring end-to-end in tests without any DDS domain participant.
//!   The mock is the reference implementation against which a future
//!   `dds-real` binding is written.
//! - **`dds-real` feature** — pulls in the pure-Rust `rustdds`
//!   RTPS stack plus `ros2-client` for ROS 2 graph interop. Two
//!   bridges land behind the gate:
//!   - `real::RealDdsBridge` for raw DDS topics (NGVA / VICTORY
//!     vehicle buses, RTI Connext peers, Eclipse Cyclone DDS,
//!     FastDDS, …) — CDR-encoded `DdsPayloadWire` wrapping the
//!     property-bag bytes.
//!   - `ros2::Ros2Bridge` for ROS 2 topics — shares the
//!     `DomainParticipant` with the raw-DDS bridge so a single
//!     rustgate process serves both DDS-native peers and ROS 2
//!     graph tools (`ros2 topic echo`, `ros2 bag record`, etc.)
//!     without running two parallel RTPS stacks.
//!
//!   Intra-doc links to `real::*` and `ros2::*` use plain backticks
//!   rather than `[…]` references because rustdoc's `cargo doc`
//!   pass on the workspace does not enable `dds-real` and would
//!   fail on the broken links under `-D rustdoc::broken-intra-doc-links`.
//!
//! # NGVA Land Data Model topics
//!
//! Operators bind rustgate-side `entity-kind` tags to DDS topics
//! through the [`config::DdsConfig`] schema. The MVP target schema is
//! the NGVA Land Data Model:
//!
//! | NGVA topic                       | rustgate `entity-kind` | Notes                                                        |
//! |----------------------------------|------------------------|--------------------------------------------------------------|
//! | `rustgate.ngva.Navigation`       | `ground`               | GNSS / IMU position + velocity from the vehicle nav stack    |
//! | `rustgate.ngva.Video`            | `sensor`               | EO/IR feed metadata (the bytes ride a separate RTP fan-out)  |
//! | `rustgate.ngva.Alarms`           | `track`                | Threat alerts, warning lamps, BMS notifications              |
//! | `rustgate.ngva.Weapons`          | `munition`             | Engagement state, ready-rounds, lase / fire commands         |
//!
//! The trait is intentionally generic over topic name and entity
//! kind — operators can extend the table with deployment-specific
//! topics through additional `[[dds.subscriptions]]` blocks without
//! touching this crate.
//!
//! # Round-trip discipline
//!
//! `Entity` ↔ DDS sample is **lossy by design** — the property-map
//! declares which entity fields project onto which DDS sample fields
//! (using the same dotted-path machinery as
//! [`rustgate_foundry`](https://docs.rs/rustgate-foundry)) and the
//! rest of the entity state is intentionally dropped. Callers that
//! need full round-trip fidelity also persist the entity to a
//! wire-format-preserving sink (CoT XML, protobuf) alongside the DDS
//! projection. This is consistent with the
//! [`rustgate_core::entity::EntityCodec`] cross-codec contract:
//! same-protocol round-trip is preserved; cross-protocol fan-out
//! drops attributes the destination format does not carry.
//!
//! # What is deliberately absent
//!
//! - **Real DDS domain participant + reader / writer.** Behind
//!   `dds-real`, currently stubbed. The trait is final; the binding
//!   is the contained follow-up.
//! - **Discovery (DDSI-RTPS) tuning.** QoS profiles ride through the
//!   trait as a [`bridge::QosProfile`]; the mapping from the QoS
//!   shape to the underlying DDS implementation's policy bag is the
//!   real-SDK adapter's responsibility.
//! - **Authentication (DDS Security, IDL key material).** DDS
//!   Security plugin configuration is the SDK's responsibility — the
//!   trait carries opaque credentials in the config and the
//!   implementation maps them to the SDK's auth flow.
//!
//! # Public API
//!
//! - [`bridge::DdsBridge`] — async trait, the integration boundary
//! - [`bridge::DdsSample`] — wire payload + topic + source GUID + timestamp
//! - [`bridge::QosProfile`] / [`bridge::Reliability`] /
//!   [`bridge::Durability`] / [`bridge::History`] — DDS QoS shape
//! - [`config::DdsConfig`] — TOML config root
//! - [`mapper::PropertyMapper`] — dotted-path entity ↔ JSON projection
//! - `mock::MockDdsBridge` (feature `dds-mock`)
//! - [`wiring::spawn_outbound`] / [`wiring::spawn_inbound`]
//! - [`error::DdsError`]

#![forbid(unsafe_code)]
#![doc(html_no_source)]

pub mod bridge;
pub mod config;
pub mod error;
pub mod mapper;
pub mod wiring;

#[cfg(feature = "dds-mock")]
pub mod mock;

#[cfg(feature = "dds-real")]
pub mod real;
#[cfg(feature = "dds-real")]
pub mod ros2;

pub use bridge::{DdsBridge, DdsSample, Durability, History, QosProfile, Reliability};
pub use config::{DdsConfig, PropertyMap, Subscription};
pub use error::DdsError;
pub use mapper::PropertyMapper;
#[cfg(feature = "dds-mock")]
pub use mock::MockDdsBridge;
#[cfg(feature = "dds-real")]
pub use real::{RealDdsBridge, TYPE_NAME as REAL_TYPE_NAME};
#[cfg(feature = "dds-real")]
pub use ros2::{Ros2Bridge, Ros2TopicConfig};
pub use wiring::{OutboundHandle, SOURCE_DDS};
