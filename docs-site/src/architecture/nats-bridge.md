# NATS Bridge

The `rustgate-nats` crate is an optional bridge between rustgate's internal router and a NATS / JetStream cluster. It exists so a fleet of rustgate edge nodes can scale horizontally through a central NATS hub without each node needing direct federation links to every other node.

The crate is enabled via `--features nats` and configured via the `--nats-*` family of flags (see [Reference: Configuration](../reference/configuration.md)).

## Responsibilities

- **Publish** routed messages to a configurable subject pattern derived from destination groups, identities, or message metadata.
- **Subscribe** to subjects via a JetStream pull consumer with at-least-once delivery, ack-floor tracking, and configurable redelivery.
- **Deduplicate** at the subscriber against rustgate's existing message-UID dedup table so a federation loop never replays a message into the local router.
- **Surface lag metrics** — every 5 seconds the subscriber polls `consumer.info()` and forwards `num_pending`, `num_redelivered`, and `ack_floor.stream_seq` to a caller-supplied callback. The binary registers Prometheus gauges under `--features metrics,nats`:
  - `rustgate_nats_consumer_pending`
  - `rustgate_nats_consumer_num_redelivered`
  - `rustgate_nats_consumer_ack_floor_stream_seq`

The crate itself stays metrics-free — gauge registration lives in the binary so the library has no Prometheus dependency.

## Failure modes

- **NATS unreachable on startup** — the bridge fails fast with a clear error message; the rest of the server starts normally if `--nats-required=false`.
- **Transient connection loss mid-flight** — the bridge reconnects with exponential backoff and the lag poller stays alive across transient errors instead of dying silently.
- **JetStream consumer drift** — surfaced via the lag gauges; investigate using the [NATS Bridge Failure runbook](../operations/runbooks/nats-bridge-failure.md).

## Related documentation

- [Federation](./federation.md) for in-band server-to-server replication when NATS isn't available.
- [Observability & Metrics](../operations/observability.md) for the full metric inventory.
