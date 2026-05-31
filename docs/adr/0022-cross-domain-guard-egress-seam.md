# ADR 0022: Cross-domain guard egress seam

- **Status:** Accepted
- **Date:** 2026-05-30
- **Deciders:** rchiofalo
- **Related:** #1457 (wire `rustgate-guard` into the server binary),
  PR-A #1465 (crate `Deserialize` + `GuardGate`),
  PR-B #1466 (`audit::guard_activated` / `audit::guard_rejected`),
  PR-C1 #1467 (router `OnEgressGuard` hook),
  PR-C2 (server wiring),
  [`docs/design/guard-server-wiring.md`](../design/guard-server-wiring.md)
  (full working design note),
  ADR 0016 (`on_callback!` macro for typed aliases)

## Context

`rustgate-guard` is a fully-implemented, tested cross-domain inspection
boundary (~1,172 LOC) — a synchronous, `&mut self`, **fail-closed** gate
(`CrossDomainGuard::evaluate`) that rate-limits, requires data markings,
and audits every decision to a dedicated hash-chained log. Until #1457 it
had **zero server wiring**: an operator could not deploy a UNCLASS↔SECRET
gateway from config; the crate was reachable only by linking it directly.

Closing that gap is not the mechanical "wire it like `start_lattice`" task
the issue implied. The guard has no background task to spawn — it is an
inline gate that must sit on the **egress path**, and the router did not
expose a single pre-egress gate. So the real decision was *where the gate
sits*, under a maintainer directive to pick the **most secure** option and,
only on a security tie, prefer the option that keeps shared logic in a
shared crate. The full analysis lives in the design note; this ADR records
the decisions and the reasoning that selected them.

## Decision

**D1 — Central gate via a core `OnEgressGuard` callback (option D1b).**
The gate runs **inside `Router::route_for_egress`**, not per-sink. The seam
is a hand-written callback alias `OnEgressGuard = Arc<dyn Fn(&RoutableMessage)
-> EgressGuardVerdict + Send + Sync>` in `rustgate-core::egress` (a
hand-written alias, not the `on_callback!` macro of ADR 0016, because a
guard is a *gate* that returns a verdict — `EgressGuardVerdict::{Allow,
Deny { reason }}` — not a fire-and-forget observer). The router holds an
`ArcSwap<Option<OnEgressGuard>>` slot (`set_on_egress_guard`, same
hot-reload pattern as `on_routed`); the **server** builds the closure from
its `GuardGate` and installs it (`crates/rustgate-server/src/guard.rs`,
`start_guard`). The router therefore takes **no** `rustgate-guard`
dependency.

**Placement — after `route_inner`, before any external sink.**
`route_for_egress` runs `route_inner` *first* (local same-domain session
fan-out: Send-PEP obligations + per-session delivery) and then returns the
`Arc<RoutableMessage>` external sinks forward. The gate is invoked on that
returned `Arc`, before `on_multicast_forward` / `on_routed` and before any
sink consumes it. This gates the **network-to-network cross-domain hop**
(external-sink egress), which is exactly the guard's documented model — not
the local same-domain session fan-out, which is an ACL/authz concern.

**D2 — `Arc<parking_lot::Mutex<CrossDomainGuard>>`, fail-closed.**
`evaluate` is `&mut self` (mutates token buckets + audit writer). It is
wrapped in a `parking_lot::Mutex` (per the shared-infra rule: never
`std::sync::Mutex` on a hot path, no `.unwrap()` on lock). A single mutex
is correct for v1: `evaluate` is cheap (bucket math + one audit append) and
the audit writer is a single-file serialization point regardless.

**D3 — Single global direction for v1.** The `GuardDirection` per call comes
from `GuardConfig.direction`; a `bidirectional` deployment resolves to the
least-restrictive `low-to-high` for the per-call check. Per-sink direction
(tagging each external sink with its domain side) is a follow-up that layers
on without a config break.

**Config single-source-of-truth.** `GuardConfig` derives `Deserialize`
(`deny_unknown_fields`, kebab-case) + `validate()` *in `rustgate-guard`*;
the server parses a `[guard]` wrapper into that type rather than shadowing
it. The deny-reason vocabulary is `GuardError::reason_token()`, also in the
crate. The `[guard]` file is read into `Zeroizing` memory per the shared
secret-file discipline. The whole feature is behind an off-by-default
`guard` cargo feature with `rustgate-guard` as an optional dep.

## Alternatives considered

- **D1a — per-sink gate, router stays guard-free.** Each egress sink (UDP,
  NATS, MQTT, plaintext, federation) calls `gate.evaluate(...)` itself.
  Rejected as **fail-open by omission**: it relies on every sink author —
  and every future refactor that adds a delivery path — remembering to wire
  the gate. For a control whose entire purpose is "nothing crosses
  unchecked," a gate you can forget to wire is the wrong gate. It is also
  *non-uniform*: the federation seam is the `OnFederationForward` callback,
  which carries only post-obligation `Bytes` (no `RoutableMessage`, no
  source `Identity`), so `audit::guard_rejected` could not populate the CN
  there without a signature change. D1b is strictly more secure, so the
  reuse tie-breaker never engaged.

- **D1b with a direct `rustgate-router → rustgate-guard` dependency.**
  Rejected because it is unnecessary: the existing egress-callback pattern
  (`OnNatsPublish` / `OnFederationForward` / `OnHttpForward`, all in
  `rustgate-core::egress`) lets the seam be a core callback alias the server
  fills, keeping the router free of any guard dependency. Same security, less
  coupling.

- **Gate inside the router PEP obligation chain (`MaskPoint`, …) or the
  `on_routed` / `on_multicast_forward` observers.** Rejected on contract
  mismatch: obligations *transform* a payload and observers *cannot reject*;
  the guard must be able to refuse and must audit. Different contract.

- **Per-sink direction from the start (D3).** Deferred, not rejected: it is
  the right long-term shape, but a single global direction satisfies the v1
  UNCLASS↔SECRET gateway use case and the per-sink refinement adds no wire
  break later.

- **Shard the guard mutex per direction (D2).** Deferred: the audit writer
  is a single file, so it serializes regardless; sharding buys nothing until
  egress-throughput profiling shows the critical section dominating.

## Consequences

- **Complete by construction.** Every ingress→egress path in the workspace
  flows through `route_for_egress` (UDP, NATS, MQTT, plaintext, federation,
  and `route()` which delegates to it). One installed guard covers every
  external sink — present and future — with zero per-sink code. A new sink
  that uses the normal routing entrypoint inherits the gate automatically.

- **New invariant to hold.** The completeness guarantee rests on "all
  external egress goes through `route_for_egress`." A future delivery path
  that deliberately bypasses it would escape the guard. This invariant is
  stated in the router docs and must be held by review — far easier than
  "every sink author remembered to call the gate." `Router::send` is *not*
  a bypass: it is the per-session channel push used *inside* the fan-out,
  after `route_for_egress`.

- **Zero cost when off.** With no `--guard-config`, the hook is one
  `ArcSwap::load` + `is_none()` check on the egress path. The `guard`
  feature is off by default and `rustgate-guard` is an optional dep, so a
  default build does not compile or link it.

- **Fail-closed end to end.** A denied message is dropped from external
  egress (the verdict governs only the external copy; any local same-domain
  delivery already happened in `route_inner`). A guard whose audit log
  cannot be written denies rather than passing traffic.

- **Scope boundary recorded.** The guard protects the network-to-network
  hop, not session-to-session delivery within a domain. Gating *local
  session* delivery across a domain split (sessions of differing
  classification on one server) is a distinct, larger feature and a
  separate ADR — explicitly out of scope here.

- **Reversible.** The seam is an optional callback slot; removing the guard
  is deleting the `start_guard` install and the feature. The core
  `OnEgressGuard` alias is generic enough to host a different boundary
  implementation without router changes.
