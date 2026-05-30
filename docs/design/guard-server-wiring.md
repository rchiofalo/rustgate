# Design note: wiring `rustgate-guard` into the server (#1457)

- **Status:** Draft for review (no code yet)
- **Date:** 2026-05-30
- **Issue:** #1457
- **Author:** rchiofalo

> This is a design note, not an ADR. It exists so the integration point
> and its trade-offs are agreed **before** code touches the routing hot
> path. Once the approach is signed off, the implementation lands as one
> or more PRs and a short ADR records the decision.

## Problem

`rustgate-guard` is a fully-implemented, tested cross-domain inspection
boundary (~1,172 LOC) — but it has **zero server wiring**. An operator
cannot deploy a UNCLASS↔SECRET gateway via config; the crate is reachable
only by linking it directly. #1457 closes that gap.

This is *not* the mechanical "wire it like `start_lattice`" task the issue
implied. The guard's evaluation entry point is a **synchronous,
`&mut self`, fail-closed gate** that must sit on the **per-sink egress
path** — there is no background task to spawn, and the router does not
today expose a single pre-egress gate. So the real work is choosing the
integration seam, not loading a TOML file.

## What the guard actually is (from the crate)

- `CrossDomainGuard::new(GuardConfig) -> Result<Self>`
  (`crates/rustgate-guard/src/lib.rs:272`) — opens the dedicated
  hash-chained audit log, resumes the chain.
- `CrossDomainGuard::evaluate(&mut self, msg: &RoutableMessage,
  direction: GuardDirection) -> Result<Bytes>` (`lib.rs:326`) —
  **synchronous**, **`&mut self`** (mutates token buckets + audit
  writer), **fail-closed**: returns `GuardError` (rate-limit, missing
  marking, classification-not-dominant, audit/IO error) or the admitted
  payload. Writes **exactly one** tamper-evident audit record per call.
- `GuardConfig` (`lib.rs:139`): `low_to_high_max_bps`,
  `high_to_low_max_bps`, `mandatory_marking`, `audit_log_path`,
  `direction`. **Does not derive `Deserialize` today.**
- `GuardDirection`: `LowToHigh | HighToLow | Bidirectional`.

The crate **already reuses workspace primitives** — it builds its audit
log on `rustgate_archive::audit_chain::HashChainWriter` + `GENESIS_PREV`
and sanitizes logged CNs with `rustgate_core::sanitize::sanitize_for_log`.
The wiring must preserve that and not reinvent anything.

## Decisions needed (the reason for this note)

### D1 — Where does the gate sit?

The guard inspects a message **leaving a security domain**. Candidate
seams, all *after* `Router::route_for_egress` decides delivery:

| Seam | Fits? |
|---|---|
| Router PEP obligation chain (`MaskPoint`, …) | **No** — obligations *transform* a payload; the guard is a *gate* that can reject and must audit. Different contract. The guard composes *after* obligations (it should see post-mask bytes). |
| `on_routed` / `on_multicast_forward` callbacks | **No** — these *observe*, they cannot reject. |
| **Per-sink pre-egress hook** (federation / NATS / HTTP / multicast, before the bytes leave the process) | **Yes** — this is the boundary. |

**Proposed:** introduce one explicit **pre-egress gate** that each
external sink consults before emitting. A sink with no guard configured
is unaffected (the gate is `Option`). This is a *new* seam — the main
review question is whether we add it as:

- **(D1a)** a single `Option<Arc<GuardGate>>` threaded into the egress
  forwarders (`start_federation`, `start_nats`, `start_http`, multicast),
  each calling `gate.evaluate(...)` before send; or
- **(D1b)** a router-level egress filter the router itself invokes inside
  `route_for_egress` before returning the `Arc<RoutableMessage>` for
  forwarding.

D1a keeps the router unaware of the guard (cleaner layering, mirrors how
NATS/federation are already optional callbacks) but repeats the call at
each sink. D1b centralizes it but puts a cross-domain concept into the
core router. **Recommendation: D1a** — it matches the existing
"server wires optional egress behavior via callbacks" pattern and keeps
`rustgate-router` free of a `rustgate-guard` dependency (avoids a new
edge; guard stays a server-level concern).

### D2 — The `&mut self` hot-path lock

`evaluate` is `&mut self` (token buckets + audit writer are mutable).
Sharing it across sink tasks needs interior mutability.

- The guard's own token-bucket sibling in `rustgate-resilience` is
  fail-open on a poisoned `parking_lot::Mutex`; the guard is **fail-closed**
  by design, so we want the opposite posture on lock contention.
- **Proposed:** wrap as `Arc<parking_lot::Mutex<CrossDomainGuard>>`
  (per the shared-infra rule: `parking_lot::Mutex` for sync hot paths,
  never `std::sync::Mutex`, no `.unwrap()` on lock). `evaluate` is
  CPU-cheap (bucket math + one audit append); the critical section is
  short. **Open question for review:** is a single mutex acceptable
  throughput-wise at the egress fan-out, or do we shard per direction?
  For v1 a single mutex is almost certainly fine (the audit writer is a
  single file anyway — it's the serialization point regardless).

### D3 — Direction per sink

`evaluate` needs a `GuardDirection`. Which egress legs are high→low vs
low→high is a **deployment fact**, not something the message carries.
**Proposed:** the direction is **per-listener/per-sink config**, declared
in the `[guard]` block (e.g. the federation egress to peer X is
`high-to-low`). v1 can start with a single global direction from
`GuardConfig.direction` and refine to per-sink later. **Needs your
call:** global-for-v1 vs per-sink from the start.

## Shared-utility discipline (hard requirements for the impl)

Per [`shared-infrastructure.md`](../../.claude/rules/shared-infrastructure.md)
and the existing crate, the wiring **must reuse**, not reinvent:

- **Secret material** → `zeroize::Zeroizing<T>`. The `[guard]` TOML is
  read via the **shared secret-file path discipline**: load into
  `Zeroizing<String>` (mirrors `mavlink.rs` / enrollment), even though
  the guard config itself is not a key — the audit-log path and any
  future pre-shared marking secret must not linger in plaintext buffers.
- **Constant-time compares** (if any marking/credential equality is
  added) → `subtle::ConstantTimeEq`, never `==`.
- **Audit** → the guard already uses
  `rustgate_archive::audit_chain::HashChainWriter`; the **server-side**
  activation/rejection events go through `rustgate_core::audit::*`
  (add `guard_activated` / `guard_rejected` audit fns there, not ad-hoc
  `tracing::warn!`), consistent with the audit-vs-tracing rule.
- **Logged CNs** → `sanitize_for_log` (already used inside the crate);
  for any *access-log*-style line, `rustgate_core::masking::hash_cn`.
- **Locks** → `parking_lot::Mutex` (D2), not `std`.
- **Lifecycle** → if the guard needs any background task (e.g. audit-log
  rotation), use `rustgate_core::tasks::{spawn_background,
  SubsystemHandle}` and register it in the graceful-shutdown set — same
  as every other subsystem. (v1 likely needs none; `evaluate` is
  inline.)
- **TCP/socket, timeouts, framing** → not applicable (guard is in-process),
  but any new network surface must use `rustgate_core::net` +
  `rustgate_core::constants` per the playbook.
- **Config** → add `GuardConfig` serde mirror with
  `#[serde(deny_unknown_fields, rename_all = "kebab-case")]` and a
  `validate()`, mirroring `MavlinkListenerConfig` / SensorThings; CLI
  flag `--guard-config` + `define_config_file!` field; feature-gate the
  whole thing behind a new server `guard` feature (off by default,
  `rustgate-guard` as an `optional` dep).
- **`GuardConfig` itself** currently lives in the crate without
  `Deserialize` — add the derive **in the crate** (with the kebab-case +
  deny-unknown-fields attrs) so the server doesn't shadow it with a
  duplicate type. Keeps one source of truth.

## Proposed PR breakdown

1. **PR-A (crate):** add `serde::Deserialize` + `validate()` to
   `GuardConfig` in `rustgate-guard`; add a `GuardGate` newtype
   (`Arc<parking_lot::Mutex<CrossDomainGuard>>` + an `evaluate` shim that
   maps `GuardError` → drop+audit). Unit-tested in-crate. No server change.
2. **PR-B (core):** add `audit::guard_activated` / `audit::guard_rejected`
   to `rustgate-core::audit`.
3. **PR-C (server):** `--guard-config` flag + config-file field + new
   `guard` feature; `start_guard()` in `setup.rs` (mirrors
   `start_ogc_sensorthings` for the load half); thread
   `Option<GuardGate>` into the egress sinks (D1a) and call it pre-send;
   `docs/cross-domain-guard.md`; CHANGELOG. The integration test: a
   message that violates the boundary (over-cap / missing marking /
   non-dominant classification) is dropped + audited on the egress leg.
4. **ADR** recording D1/D2/D3 once chosen.

PR-A and PR-B are self-contained and low-risk; PR-C is the one that
touches egress and wants the most review.

## Open questions for sign-off

1. **D1**: confirm D1a (per-sink callback, router stays guard-free) vs
   D1b (router-level filter)?
2. **D3**: global direction for v1, or per-sink from the start?
3. Scope of v1 sinks: all of federation/NATS/HTTP/multicast, or start
   with one (federation is the canonical cross-domain leg) and extend?
4. Is a single `parking_lot::Mutex<Guard>` acceptable for v1, given the
   audit writer is a single-file serialization point regardless?
