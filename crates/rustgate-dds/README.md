# rustgate-dds

DDS (Data Distribution Service) Pub/Sub bridge for **NATO Generic Vehicle
Architecture (NGVA, STANAG 4754)** and the US Army's **VICTORY** standard.

## Status

This crate ships the DDS bridge end-to-end. The default build is a
trait + config + mock + wiring scaffold; the **`dds-real` feature**
layers on real bindings backed by [`rustdds`] (pure-Rust RTPS) and
[`ros2-client`] (ROS 2 graph compatibility on top of rustdds).

Two production-grade bridge implementations:

| Type | Use case | Wire format |
|---|---|---|
| [`MockDdsBridge`] (`dds-mock`) | In-memory tests | Broadcast channel per topic |
| [`RealDdsBridge`] (`dds-real`) | Raw DDS-RTPS peers (NGVA, VICTORY, Cyclone DDS, RTI Connext, FastDDS) | CDR-encoded `DdsPayloadWire` |
| [`Ros2Bridge`] (`dds-real`) | ROS 2 nodes — `ros2 topic echo`, `ros2 bag record`, `ros2 node list` see published topics | CDR-encoded ROS 2 IDL types |

The `Ros2Bridge` shares its `DomainParticipant` with the `RealDdsBridge`
so a single rustgate process serves both DDS-native peers and ROS 2
graph tools without running two parallel RTPS stacks.

This closes the DDS half of #870 (the GeoJSON output half landed in
#1326). DDS Security plugin configuration remains deferred to a
follow-up — in-vehicle deployments today rely on link-layer security
(IPsec / MACsec / RF crypto) rather than DDS-level auth.

## Why DDS

Every modern NATO armored vehicle and a growing fleet of US Army platforms
ship a DDS data bus carrying Navigation, Video, Alarms, and Weapons topics
under the **NGVA Land Data Model**. DDS is mandated by:

- **STANAG 4754** — NATO Generic Vehicle Architecture (NGVA)
- **VICTORY** — US Army Vehicular Integration for C4ISR/EW Interoperability

Adding DDS gives rustgate access to the in-vehicle telemetry and command
surface of those platforms without bolt-on translation layers.

## Public API

| Item | Purpose |
|------|---------|
| `DdsBridge` | Async trait — `subscribe_topic`, `publish_sample`, `shutdown` |
| `DdsSample` / `QosProfile` / `Reliability` / `Durability` / `History` | Wire types and DDS QoS shape |
| `DdsConfig` | TOML config root with `[[subscriptions]]` array |
| `Subscription` / `PropertyMap` | Per-topic config + property-map rule |
| `PropertyMapper` | Stateless dotted-path entity ↔ JSON projection |
| `MockDdsBridge` (feature `dds-mock`) | In-memory bridge for tests |
| `RealDdsBridge` (feature `dds-real`) | Real DDS-RTPS bridge via rustdds |
| `Ros2Bridge` / `Ros2TopicConfig` (feature `dds-real`) | ROS 2 graph bridge via ros2-client |
| `wiring::spawn_outbound` / `wiring::spawn_inbound` | Background-task constructors |

## NGVA Land Data Model topic mapping

The MVP target schema for in-vehicle deployments:

| NGVA topic                     | rustgate `entity-kind` | Recommended QoS                  |
|--------------------------------|------------------------|----------------------------------|
| `rustgate.ngva.Navigation`     | `ground`               | `QosProfile::TELEMETRY`          |
| `rustgate.ngva.Video`          | `sensor`               | `QosProfile::TELEMETRY`          |
| `rustgate.ngva.Alarms`         | `track`                | `QosProfile::COMMAND`            |
| `rustgate.ngva.Weapons`        | `munition`             | `QosProfile::COMMAND`            |

The trait is generic over topic name and entity kind so a deployment can
extend the table with platform-specific topics without touching this crate.

## Property-map machinery

Operators bind rustgate-side `Entity` fields to DDS sample properties
through a TOML table:

```toml
[dds]
domain-id = 0
participant-name = "rustgate"

[[dds.subscriptions]]
topic = "rustgate.ngva.Navigation"
entity-kind = "ground"
property-map = [
    { dds = "uid", entity = "uid" },
    { dds = "callsign", entity = "callsign" },
    { dds = "position.lat", entity = "position.lat" },
    { dds = "position.lon", entity = "position.lon" },
    { dds = "velocity.speed_m_s", entity = "velocity.speed_m_s" },
]

[[dds.subscriptions]]
topic = "rustgate.ngva.Weapons"
entity-kind = "munition"
qos = { reliability = "reliable", durability = "transient-local", history = { kind = "keep-all" } }
property-map = [
    { dds = "uid", entity = "uid" },
    { dds = "weapon.state", entity = "attributes.weapon_state" },
]
```

Supported entity-side dotted paths: `uid`, `callsign`,
`mil_std_2525_sidc`, `position.lat|lon|hae_meters`,
`velocity.speed_m_s|course_deg`, `attributes.<key>`. A typo surfaces as
`DdsError::PathNotFound`. Optional fields absent on the source entity
are silently skipped.

## Offline replay

When the bridge returns `DdsError::ParticipantUnavailable`, the outbound
task queues the sample in an in-memory FIFO capped at
`OFFLINE_QUEUE_CAPACITY = 4096` entries. On the next successful publish
the queue drains in order with **last-writer-wins** collapse — duplicate
`(topic, uid)` entries are merged so the most recent projection is the
one that lands on the wire. On overflow the oldest entry is evicted.

A persistent on-disk queue lands once the real SDK is wired up — the
existing `rustgate-router::store_forward` redb-backed queue is the
natural sink, and the swap is contained to the wiring module.

## Out of scope (deferred)

- **Real DDS SDK integration** — `dds-real` feature is a placeholder
  today. Pinning a specific impl (Cyclone DDS via `cyclonedds-rs`,
  RTI Connext via FFI, or `dust-dds` once 1.0 ships) is the contained
  follow-up.
- **DDS Security plugin configuration** — the DDS Security spec's
  authentication / access-control / cryptographic plugins are the
  SDK adapter's responsibility.
- **CDR (Common Data Representation) wire format** — the MVP wiring
  carries DDS samples as JSON-encoded property bags so the property-map
  machinery is portable across SDKs. A real SDK adapter MAY widen this
  to CDR by translating CDR ↔ JSON inside the implementation.
- **DDSI-RTPS discovery tuning** — QoS profiles ride through the trait
  as a `QosProfile`; the mapping from the QoS shape to the underlying
  DDS implementation's policy bag is the real-SDK adapter's job.
- **Per-mapping configurable inbound `Destination`** — inbound messages
  are `Broadcast` today; tightening to `Destination::Group(...)` per
  subscription is a contained follow-up.
- **On-disk persistent offline queue** — in-memory MVP only; the
  existing `rustgate-router::store_forward` redb-backed queue is the
  natural sink for a follow-up.

## Quality gates

```
cargo +nightly fmt --all
cargo clippy --locked --workspace --all-targets \
    --features nats,enrollment,est,proto,full-detail,metrics,federation,federation-ha,websocket,mqtt,otel,http,dds,dds-mock
cargo nextest run -p rustgate-dds --features dds-mock
```

[`DdsBridge`]: src/bridge.rs
[`PropertyMapper`]: src/mapper.rs
[`MockDdsBridge`]: src/mock.rs
