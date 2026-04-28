# rustgate-nats

NATS / JetStream bridge for cross-instance message delivery.

## Role in the workspace

`rustgate-nats` bridges local sessions to a NATS event bus, enabling
stateless horizontal scaling. Inbound messages are published to NATS
subjects; outbound messages are consumed via a JetStream pull consumer that
applies real backpressure rather than dropping under load. Depends on
[rustgate-core](../rustgate-core/README.md),
[rustgate-cot](../rustgate-cot/README.md),
[rustgate-transport](../rustgate-transport/README.md), and
[rustgate-resilience](../rustgate-resilience/README.md). Wired into
[rustgate-server](../rustgate-server/README.md) under `--features nats`.

## Public API surface

- `NatsAdapter` — top-level handle that owns the `async-nats` client and
  produces publishers / subscribers / replay handles / request clients
- `NatsPublisher` — publishes routed messages onto subject hierarchies
  derived from message destination and group
- `NatsSubscriber` — JetStream pull-consumer wrapper with
  `LagCallback` / `LatencyCallback` hooks for the `rustgate_nats_consumer_*`
  Prometheus gauges
- `JetStreamReplay` — Situational-Awareness bootstrap replayer that
  optionally checkpoints to disk so restarts resume from the last
  acknowledged sequence
- `NatsRequestClient`, `NatsRequestResponder`, `NatsRequestHandler`,
  `RequestError`, `ERROR_HEADER` — request/reply layer over the same
  connection
- `NatsConfig`, `NatsConfigError`, `NatsTlsConfig`, `NatsTlsConfigError` —
  validated configuration including credentials file, TLS material, and
  subscription capacity
- `WireEvent` — serde-stable wire envelope used on the bus
- `LagSnapshot` — point-in-time snapshot of consumer lag (pending,
  redelivered, ack-floor) emitted by the periodic poller

## Feature flags

| Name | Purpose | Default-on? |
|---|---|---|
| `full-detail` | Enables protobuf-detail extraction via [rustgate-proto](../rustgate-proto/README.md) so wire events carry the full CoT field set | No |

## Topology / deployment notes

Requires an external NATS broker with JetStream enabled. TLS is configurable
end-to-end (server cert verification + optional client mTLS); the connection
emits a structured `slow consumer` warning when the local subscription
buffer fills. NATS subject tokens are NFC-normalized via
`unicode-normalization` before use to defeat Unicode-equivalence spoofing
on user-supplied identifiers (see `publisher::sanitize_nats_token`).

## Where to look first

- `crates/rustgate-nats/src/lib.rs` — `NatsAdapter::connect` and the
  TLS-application path
- `crates/rustgate-nats/src/subscriber.rs` — the JetStream pull-consumer
  loop with backpressure and lag instrumentation
