# rustgate-lattice

Bidirectional adapter that lets rustgate present itself as a native
**Anduril Lattice** sensor feed and command consumer.

## What this crate does

- Exposes the [`LatticeBridge`] async trait — the surface every
  Lattice backend (mock, real SDK) implements: `publish_entity`,
  `subscribe_entities`, `report_health`.
- Defines [`Entity`], [`EntityFilter`], [`HealthStatus`], and
  [`LatticeConfig`] — the shared types every backend round-trips.
- Ships [`MockLatticeBridge`] (feature-gated `lattice-mock`) — an
  in-memory, channel-backed implementation suitable for integration
  tests and air-gapped CI.
- Provides outbound + inbound wiring helpers
  ([`spawn_outbound_task`], [`spawn_inbound_task`]) that the server
  binary uses to plug the bridge into [`rustgate_router::Router`]
  message events without leaking any Lattice-specific types into
  the router crate.

## What this crate does NOT do (yet)

The **real** Lattice gRPC SDK ships behind Anduril partnership /
NDA, so this PR cannot include the actual proto bindings or an
on-the-wire client. The integration shape is shipped today so the
partner-side PR that drops in the protobuf descriptors and the
`LatticeBridge` implementation that wraps the generated `tonic`
client is a small, contained change that does not have to touch
the router, the server binary, or the wiring tasks.

The placeholder lives behind the **`lattice-real`** feature flag
(currently empty stub) so a no-feature build of the workspace is
unaffected and the partner PR has a stable landing spot.

## Architecture

```
              ┌─────────────────────────┐
              │     rustgate-router     │
              │       (Router<...>)     │
              └─────────────────────────┘
            on_message_delivered │ ▲ Router::route
                                 │ │
                                 ▼ │
   ┌──────────────────────────────────────────────────┐
   │           rustgate-lattice (this crate)          │
   │                                                  │
   │   spawn_outbound_task ─┐         ┌── spawn_inbound_task
   │                        ▼         ▼               │
   │             ┌────────────────────────┐           │
   │             │   LatticeBridge trait  │           │
   │             └────────────────────────┘           │
   │                  ▲           ▲                   │
   │                  │           │                   │
   │       MockLatticeBridge   (real SDK impl —       │
   │       (lattice-mock)       lattice-real, TBD)    │
   └──────────────────────────────────────────────────┘
```

## Configuration

Toml block under `[lattice]` in `rustgate.toml`:

```toml
[lattice]
endpoint            = "https://lattice.example.mil"
batch-size          = 64
geo-bbox            = { min-lat = 30.0, max-lat = 50.0, min-lon = -125.0, max-lon = -100.0 }
entity-types        = ["track", "platform"]

[lattice.auth]
mtls-cert-path      = "/etc/rustgate/lattice/client.crt"
mtls-key-path       = "/etc/rustgate/lattice/client.key"
jwt-secret-path     = "/etc/rustgate/lattice/jwt.secret"
```

When the `[lattice]` block is absent the wiring helpers are no-ops
and rustgate runs unchanged.

## Out of scope for this PR

- Real Lattice gRPC SDK integration (the actual proto bindings,
  the `tonic` client, JWT-over-mTLS auth) — partner-NDA dependency.
- Lattice `Task` / `Order` consumer side — Lattice's command-and-
  control surface uses a separate proto + RPC; carrying it in this
  PR would force a placeholder shape that the real SDK would have
  to reshape. Tracked as follow-up.
- Backend selection by config (`backend = "mock" | "real"`) — adds
  a config-driven dispatch when both backends actually exist; for
  now the only available impl is the mock and it is selected by
  the `lattice-mock` feature flag.

## Quality gates

```
cargo +nightly fmt --all
cargo clippy --locked --workspace --all-targets \
    --features nats,enrollment,est,proto,full-detail,metrics,federation,federation-ha,websocket,mqtt,otel,http,lattice,lattice-mock
cargo nextest run -p rustgate-lattice --features lattice-mock
```

[`Entity`]: crate::bridge::Entity
[`EntityFilter`]: crate::bridge::EntityFilter
[`HealthStatus`]: crate::bridge::HealthStatus
[`LatticeBridge`]: crate::bridge::LatticeBridge
[`LatticeConfig`]: crate::config::LatticeConfig
[`MockLatticeBridge`]: crate::mock::MockLatticeBridge
[`spawn_inbound_task`]: crate::wiring::spawn_inbound_task
[`spawn_outbound_task`]: crate::wiring::spawn_outbound_task
