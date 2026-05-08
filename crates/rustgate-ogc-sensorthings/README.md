# rustgate-ogc-sensorthings

Client integration for the [OGC SensorThings] v1.0 IoT sensor data
standard.

[OGC SensorThings] is the open-standard REST + JSON + MQTT interface
for IoT sensor data. NGA, NATO CMRE, and allied agencies use it for
geospatial sensor sharing — weather stations, hydrometric gauges,
seismic networks, CBRN detectors, and similar fixed-station telemetry.

## Status

This crate ships the **HTTP polling half** of the SensorThings
integration:

- Per-`Datastream` polling with configurable cadence, page size, and
  optional `?$expand=Datastream/Thing/Locations` for single-round-trip
  geospatial resolution.
- `Observation` → canonical `rustgate_core::entity::Entity` mapping
  preserving the strict subset of SensorThings fields the router
  cares about, with the rest carried opaque on the
  `attributes.sensorthings.*` namespace.
- Background polling task wired through
  `rustgate_router::Router::route` — every observation reaches the
  router as a `RoutableMessage` for normal cross-protocol fan-out.
- Bearer-token auth via a path-on-disk secret (`Zeroizing` wrapped
  by the wiring layer at startup).
- Typed failure surface: `Transport` / `HttpStatus` / `Decode` /
  `Timeout` / `Config`, with `is_transient()` driving the polling
  task's backoff decision.

The **MQTT push subscription half** is deferred to a follow-up issue
— the SensorThings `v1.0/Datastreams(N)/Observations` MQTT topic is
declared in the spec alongside the REST polling path and the
`Observation` payload shape is byte-for-byte identical, so the
existing `rustgate-mqtt` client capability + the [`mapper`] module
in this crate cover the upgrade without restructuring either.

## Public API

| Item | Purpose |
|------|---------|
| `SensorThingsClient` | HTTP polling client; per-config one instance |
| `SensorThingsConfig` / `Subscription` | TOML config root + per-`Datastream` subscription entry |
| `EntityKindTag` | Closed-vocabulary tag controlling the mapped `EntityKind` |
| `Observation` / `Datastream` / `Thing` / `Location` / `ObservationsPage` | Strict-subset wire types |
| `observation_to_entity` | Pure projection helper |
| `wiring::spawn_polling_task` | Background task constructor |
| `wiring::SOURCE_OGC_SENSORTHINGS` | Source-protocol tag for emitted `RoutableMessage`s |
| `SensorThingsError` | Typed failure enum |

## Configuration

Operators bind one or more `Datastream` ids to subscriptions through a
single `[sensorthings]` block in `rustgate.toml`:

```toml
[sensorthings]
endpoint = "https://example.org/SensorThings/v1.0"
auth-token-path = "/secrets/sensorthings-token"   # optional bearer
poll-interval-secs = 30
request-timeout-secs = 10
expand-location = true

[[sensorthings.subscriptions]]
datastream-id = 42
entity-kind = "sensor"      # any closed-vocabulary EntityKind tag
group = "weather"           # optional Destination::Group target
poll-interval-secs = 15     # per-subscription override
page-size = 100             # ?$top= for the polling URL
```

The schema uses `kebab-case` field names with `deny_unknown_fields`
so a typo (`poll_interval_secs` instead of `poll-interval-secs`) is
rejected at parse time.

## Polling URL composition

For every subscription `S` with `datastream-id = N` the client
issues a GET against:

```
<endpoint>/Datastreams(<N>)/Observations
    ?$top=<page>
    &$orderby=phenomenonTime+asc
    [&$expand=Datastream/Thing/Locations]
    [&$filter=phenomenonTime gt <iso8601>]
```

`$expand` is included when `expand-location = true` (default) — this
is the standard SensorThings idiom for fetching the sensor station's
lat/lon in a single round trip. `$filter` is added once the polling
task has seen at least one `phenomenonTime`, so subsequent polls
request only newer observations and the on-the-wire footprint stays
small.

## Round-trip discipline

`Observation` → `Entity` is intentionally **lossy** — only the
strict subset of SensorThings fields the router and downstream
codecs can usefully act on are projected onto the typed entity slots:

- `Observation.@iot.id` → `Entity::uid` (as
  `"sensorthings-observation-{id}"`)
- `Observation.Datastream.Thing.Locations[0].location` →
  `Entity::position` (only when the `location` is a GeoJSON `Point`)
- `Observation.Datastream.name` → `Entity::callsign`
- `Observation.phenomenonTime` →
  `attributes.sensorthings.phenomenon_time`
- `Observation.result` →
  `attributes.sensorthings.result` (scalars) or
  `attributes.sensorthings.result_json` (objects, arrays)

The full upstream document is recoverable through
`attributes.sensorthings.self_link` when the SensorThings server
included `@iot.selfLink`.

## Out of scope (deferred)

- **MQTT push subscription** — the SensorThings MQTT half lands in a
  follow-up issue and reuses `rustgate-mqtt` plus the `mapper` module
  here.
- **HistoricalLocations / FeaturesOfInterest enumeration** — the MVP
  polls `Datastreams(N)/Observations` and resolves Location via
  `$expand`. The full hypermedia surface is not exposed.
- **Server-side filter authoring** — operators configure
  `$filter` strings via TOML, but this crate does not compose
  filters from rustgate-side ACL/authz state.
- **Submitting observations back** — this is a one-way client
  (server → rustgate). Bidirectional support
  (`POST /Observations` from rustgate) is out of scope.
- **Token rotation** — the bearer token is loaded once at startup;
  rotation lands alongside the future SIGHUP-driven config-reload
  umbrella.

## Companion protocols

Issue #869 covers SAPIENT (BSI Flex 335) + NFFI (STANAG 5527, NATO
Blue Force Tracking) + OGC SensorThings (this crate). SAPIENT shipped
in #1327; NFFI ships alongside this PR. With this PR plus the NFFI
PR both merged, #869 closes.

[OGC SensorThings]: https://www.ogc.org/standard/sensorthings/
[`mapper`]: src/mapper.rs
