# rustgate-router

Routing engine for rustgate — the core data-plane primitives that move
a `RoutableMessage` from ingress to one or more egress sinks.

## Role in the workspace

`rustgate-router` provides the routing primitives: `Router`,
`SessionHandle`, ACL evaluation, deduplication, store-and-forward
queuing, position-cache replay, message filtering, throttling, tenant
quotas, obligations, and egress envelope rendering. It is consumed by
`rustgate-transport` (TCP/UDP ingress) and the sink crates
(`rustgate-federation`, `rustgate-nats`, `rustgate-http`,
`rustgate-mqtt`, `rustgate-websocket`) that fan messages out.

**TLS, certificate handling, and TCP listeners live in
`rustgate-tls`.** Codec and protocol framing primitives stay in
`rustgate-transport`. This crate is **post-handshake, post-decode**: it
operates on `RoutableMessage` from `rustgate-core` and never sees the
wire format.

## Public API surface

The top-level `lib.rs` re-exports the most-used types from each
submodule; consumers typically import them via `use rustgate_router::*;`
or per-symbol.

### Core routing

- `Router` — the per-server routing engine. Holds session table, ACL,
  authz observer, dedup cache, position cache, store-forward queue,
  obligation engine, and rate limiter.
- `SessionHandle` — per-client mpsc sender + backpressure-aware
  `try_send` API
- `acl::{GroupAcl, GroupAclPolicy}` — RBAC group ACL evaluation
- `interceptor::MessageInterceptor` — pluggable SPI for cross-cutting
  message inspection (audit, debug, compliance)

### Dedup, replay, throttle

- `dedup::{DedupCache, DedupStats, OnDuplicate, OnInsert}` — SHA-256
  keyed LRU dedup cache with time-window TTL
- `cache::{PositionCache, OnCacheSize}` — latest-position-per-CN cache
  with TTL eviction and replay-on-connect
- `replay::*` — store-forward replay primitives
- `throttle::*` — per-CN message-rate + burst limits
- `repeater::*` — periodic position re-broadcast for slow-tactical-radio
  bridges

### Store-and-forward + tenant quotas + obligations + egress

- `store_forward::{StoreForwardError, ...}` — redb-backed per-client
  durable queue with global byte cap, drop-oldest FIFO eviction,
  per-CN sequence numbers, and HMAC-SHA256 integrity tagging
- `quota::*` — per-tenant connection + rate caps keyed by certificate
  Organization
- `obligations::{ObligationError, ...}` — policy-action engine
  (`StripPii`, `DegradePosition`, `InjectMarking` from #1286)
- `egress::{EgressEnvelope, EgressError, RecipientClass}` — egress-side
  rendering: produces the per-recipient envelope a sink crate writes
  to the wire
- `filter::*` — type/group/distance/staleness filters applied before
  delivery

### CJADC2 routing (feature-gated)

- `cjadc2::{DestinationEnvelope, plan_routing_fanout}` — multi-domain
  routing fan-out planner (closes #853). Takes a
  `rustgate_authz::RoutingDecision` and produces per-destination egress
  envelopes for the CJADC2 reference architecture.

## Feature flags

| Feature | Description |
|---|---|
| `cjadc2` | Multi-domain routing fan-out planner. Enables the `crate::cjadc2` module and pulls in `rustgate-authz/cjadc2`. Off by default — non-CJADC2 deployments do not link the planner or pull in the routing-decision types. |

The `[features]` section is intentionally minimal because routing is a
single coherent concern. Per-protocol routing helpers live in the
respective transport crates (`rustgate-mavlink`, `rustgate-mqtt`,
`rustgate-websocket`, …); the router operates on
`RoutableMessage` regardless of source.

## Error handling

Most fallible APIs in this crate return
`rustgate_core::error::Result`, whose error type is
`rustgate_core::error::RustgateError`. Specialised submodules expose
typed enums for matchable failure modes:

- `store_forward::StoreForwardError` — queue full / corrupt / locked
- `obligations::ObligationError` — policy action could not apply
- `egress::EgressError` — recipient unreachable / envelope render failed

This is the workspace's `thiserror` pattern (ADR 0007 — no `anyhow` in
library crates).

## Topology / deployment notes

The router is `Send + Sync` and holds all hot-reloadable state in
`ArcSwap<Option<T>>` (ADR 0003). SIGHUP-triggered config reloads land
new policies without taking the router offline.

Per-session backpressure is two-tiered (ADR-documented in
`docs/concurrency-model.md`):

1. **Global admission** (`BackpressureGate` in `rustgate-transport`)
   sets high/low water marks on total queued bytes
2. **Per-session delivery** (`SessionHandle::try_send`) uses a bounded
   mpsc channel; when full, the message either goes to store-and-forward
   (if enabled) or is dropped with an audit event

The `Router` itself does not own the TCP/TLS sockets — the listener in
`rustgate-transport` calls into `Router::route(message)` after the
codec produces a `RoutableMessage`.
