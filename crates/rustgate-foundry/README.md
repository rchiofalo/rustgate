# rustgate-foundry

Bidirectional bridge between rustgate entities and **Palantir Foundry /
Gotham** ontology objects.

## Status

This crate ships the **integration scaffold** for the Foundry bridge:
the [`FoundryBridge`] trait, the TOML config schema, the
[`PropertyMapper`] dotted-path projection machinery, the
[`MockFoundryBridge`] reference implementation, and the inbound /
outbound wiring tasks. Foundry's REST/WebSocket SDK is partner-gated;
plugging the real adapter in is a contained change behind a future
`foundry-real` feature flag once the SDK drops.

## Public API

| Item | Purpose |
|------|---------|
| `FoundryBridge` | Async trait — `upsert_object`, `subscribe_changes`, `invoke_action` |
| `ObjectId` / `ObjectChange` / `ActionRequest` / `ActionResult` | Wire types |
| `FoundryConfig` | TOML config root with `[[object-types]]` array |
| `ObjectTypeMapping` / `PropertyMap` | Per-entity-type config + property-map rule |
| `PropertyMapper` | Stateless dotted-path entity ↔ JSON projection |
| `MockFoundryBridge` (feature `foundry-mock`) | In-memory bridge for tests |
| `wiring::spawn_outbound` / `wiring::spawn_inbound` | Background-task constructors |

## Property-map machinery

Operators bind a small slice of an `Entity` to a Foundry property bag
through a TOML table:

```toml
[[foundry.object-types]]
entity-type = "ground"
foundry-type = "mil-track-dismount"
property-map = [
    { entity = "uid", foundry = "rustgate.uid" },
    { entity = "callsign", foundry = "callSign" },
    { entity = "position.lat", foundry = "latitude" },
    { entity = "position.lon", foundry = "longitude" },
    { entity = "velocity.speed_m_s", foundry = "speedMps" },
    { entity = "attributes.battery", foundry = "battery" },
]
```

Supported entity-side dotted paths: `uid`, `callsign`,
`mil_std_2525_sidc`, `position.lat|lon|hae_meters`,
`velocity.speed_m_s|course_deg`, `attributes.<key>`. A typo surfaces as
`FoundryError::PathNotFound`. Optional fields absent on the source
entity are silently skipped.

## Offline replay

When the bridge returns `FoundryError::Offline`, the outbound task
queues the upsert in an in-memory FIFO capped at
`OFFLINE_QUEUE_CAPACITY = 4096` entries. On the next successful
upsert the queue drains in order with **last-writer-wins** collapse —
duplicate `(type_id, uid)` entries are merged so the most recent
projection is the one that lands on Foundry. On overflow the oldest
entry is evicted.

A persistent on-disk queue lands once the real SDK is wired up — the
existing `rustgate-router::store_forward` redb-backed queue is the
natural sink, and the swap is contained to the wiring module.

## Out of scope (deferred)

- **Real REST/WebSocket SDK integration** — `foundry-real` feature is
  a placeholder today.
- **Action invocation execution** — `invoke_action` is on the trait
  so the wiring shape is final, but the action-stream that triggers
  RoutableMessage injection on operator button-presses is wired
  alongside the real SDK.
- **OAuth2 / JWT authentication** — handled by the SDK adapter, not
  by this crate.
- **Per-mapping configurable `Destination`** — inbound messages are
  `Broadcast` today; tightening to `Destination::Group(...)` per
  mapping is a contained follow-up.

## Quality gates

```
cargo +nightly fmt --all
cargo clippy --locked --workspace --all-targets \
    --features nats,enrollment,est,proto,full-detail,metrics,federation,federation-ha,websocket,mqtt,otel,http,foundry,foundry-mock
cargo nextest run -p rustgate-foundry --features foundry-mock
```

[`FoundryBridge`]: src/bridge.rs
[`PropertyMapper`]: src/mapper.rs
[`MockFoundryBridge`]: src/mock.rs
