# Design note: wiring `rustgate-guard` into the server (#1457)

- **Status:** Draft for review — PR-A (#1465) and PR-B (#1466) landed; the
  hot-path wiring (PR-C/PR-D) awaits sign-off on the seam decision below.
- **Date:** 2026-05-30 (rev. after code review against the egress seams)
- **Issue:** #1457
- **Author:** rchiofalo

> This is a design note, not an ADR. It exists so the integration point
> and its trade-offs are agreed **before** code touches the routing hot
> path. Once the approach is signed off, the implementation lands as one
> or more PRs and a short ADR records the decision.
>
> **Revision note:** the egress-seam analysis in D1 was corrected after a
> review cross-checked it against the actual sink wiring. The original
> draft assumed a uniform per-sink "hand me the `RoutableMessage`" hook;
> the code has two different seam shapes, and the federation seam (the
> originally-proposed "v1 first" target) is the hardest, not the easiest.
> See **D1 → Seam reality**.

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
seams, all evaluated *after* `Router::route_for_egress` has applied
Send-PEP obligations:

| Seam | Fits? |
|---|---|
| Router PEP obligation chain (`MaskPoint`, …) | **No** — obligations *transform* a payload; the guard is a *gate* that can reject and must audit. Different contract. |
| `on_routed` / `on_multicast_forward` callbacks | **No** — these *observe*, they cannot reject. |
| Per-sink seam, before the bytes leave the process | **Yes** — but the seam shape differs sharply per sink. See below. |

#### Seam reality — verified against the code (this is the load-bearing correction)

The sinks do **not** share one uniform "hand me the `RoutableMessage`
before egress" hook. There are two distinct shapes, and the guard needs a
`&RoutableMessage` (for `source.cn`, classification, direction
attribution) — which only one of them has:

1. **Sinks that own the `Arc<RoutableMessage>`.** UDP
   (`rustgate-transport/src/udp.rs:446`) and the NATS subscriber
   (`rustgate-nats/src/subscriber.rs:499`) call `route_for_egress(msg)`
   themselves and act on the returned `Option<Arc<RoutableMessage>>`.
   A guard gate drops in cleanly here: the sink already holds the full
   message, so `gate.evaluate(&arc_msg, dir)` has everything it needs
   (CN, classification, payload). **This is the easy D1a seam.**

2. **The federation-forward callback — `Bytes` only, no identity.**
   Federation egress is *not* a sink that calls `route_for_egress`; it is
   the `OnFederationForward` callback the **router invokes inside**
   `route_for_egress` (wired via `Subscriber::with_federation_forward`,
   `setup.rs:672`). Its signature is
   `OnFederationForward = Arc<dyn Fn(Bytes, Vec<String>, Metadata)>`
   (`rustgate-core/src/egress.rs:53`) — it receives the **already
   post-obligation payload bytes**, the eligible source groups, and
   metadata, but **not** a `RoutableMessage` and **not** the source
   `Identity`. At this seam the guard cannot populate the `cn` field
   that `audit::guard_rejected` (PR-B) expects, and cannot do CN-based
   attribution, without a signature change.

**Implication for "federation first."** Federation is the canonical
cross-domain leg conceptually, but it is the *hardest* D1a seam, not the
easiest — its callback has already discarded the `RoutableMessage`. The
options are therefore:

- **(D1a)** Per-sink gate, router stays guard-free. Clean for UDP/NATS
  (they hold the `Arc`). For **federation**, either (i) accept
  `Bytes`-only guarding at the fed-forward callback — throughput cap +
  marking-from-payload work, but the `guard.rejected` audit has no CN
  (`cn = "unknown"`); or (ii) widen `OnFederationForward` to carry the
  source `Identity`/CN (a small, contained core signature change).
- **(D1b)** Router-level gate invoked *inside* `route_for_egress` before
  the fed-forward callback fires, where the `RoutableMessage` still
  exists. Gives full CN audit on every sink uniformly, but adds a
  `rustgate-router` → guard dependency edge (or a guard *callback* the
  router holds, which keeps the edge out but moves the hook into core).

#### Resolved — security first, then reuse

The maintainer directive is: pick the **most secure** option; if options
are equally secure, prefer the one that lets shared logic live in a
**shared crate**. Applying both, in order:

**Security — D1b wins, decisively.** The two options are *not* equally
secure, so the reuse tie-breaker never engages:

- **`route_for_egress` is the single egress chokepoint today.** Every
  ingress→egress path in the workspace flows through it — UDP, NATS,
  MQTT, plaintext, and federation-sourced messages all call it
  (verified: `mqtt/session.rs`, `nats/subscriber.rs`, `transport/udp.rs`,
  `server/setup.rs`, plus `route()` which delegates to it). `Router::send`
  is *not* a bypass — it is the downstream per-session channel push used
  *inside* the fan-out, after `route_for_egress`. A gate placed **inside**
  `route_for_egress` (D1b) is therefore **complete by construction over
  every path that exists today**, and any *new* sink that uses the normal
  routing entrypoint inherits the gate with zero extra code. (The one
  residual obligation: a future delivery path that deliberately skips
  `route_for_egress` would escape the gate — so the invariant "all egress
  goes through `route_for_egress`" should be stated in the router docs and
  guarded by review, which is far easier to hold than "every sink author
  remembered to call the gate.")
- **D1a (per-sink) is fail-*open* by omission.** It relies on every sink
  author remembering to call `gate.evaluate(...)`. A new egress sink — or
  a refactor that adds a delivery path — silently escapes the boundary
  until someone notices. For a cross-domain guard whose entire purpose is
  "nothing crosses unchecked," a control you can forget to wire is the
  wrong control. This is the deciding factor.
- D1b also gives **uniform, complete CN audit** on every sink (the
  `RoutableMessage` — hence `source.cn`, classification, tenant — is in
  hand at that point), so `audit::guard_rejected` is always fully
  populated. The `Bytes`-only / `unknown`-CN compromise the federation
  seam would have forced under D1a disappears entirely.

**Reuse — D1b also satisfies it, so there is no trade-off.** D1b does
**not** require a `rustgate-router → rustgate-guard` dependency. Instead,
follow the pattern the router already uses for `OnNatsPublish` /
`OnFederationForward` / `OnHttpForward` (all defined via `on_callback!`
in `rustgate-core::egress`): define an **`OnEgressGuard` callback alias in
`rustgate-core::egress`**, hold an `ArcSwap<Option<OnEgressGuard>>` on the
`Router` (same hot-reload pattern as `on_fanout`), and have the **server**
construct the closure from its `GuardGate` and install it. The guard
decision logic stays in `rustgate-guard`; the *seam* is a core callback
alias reused exactly like the existing egress callbacks. Net: router
stays guard-free **and** the gate is unbypassable — the security win and
the layering win coincide.

**Decision:** **D1b via a core `OnEgressGuard` callback.** The gate runs
inside `route_for_egress` after Send-PEP obligations and before any sink
forwarding; on `Err` the message is dropped and `audit::guard_rejected`
fires with the full CN. v1 wires the closure for whichever boundaries the
`[guard]` config names; because the hook is central, no per-sink edits
are needed and future sinks inherit it.

**What this changes in the PR plan:** there is no separate "federation
fast-follow" (PR-D) — the central hook covers federation, UDP, NATS, MQTT,
and any future sink at once. PR-C becomes: add `OnEgressGuard` to
`rustgate-core::egress`, the `ArcSwap` slot + invocation in
`route_for_egress`, and the server `start_guard` + closure install.

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

### Composition with obligations — confirmed, not a choice

A side benefit verified during review: at the federation seam the guard
*automatically* sees **post-obligation** bytes, because
`route_for_egress` applies the Send-PEP obligation chain *before* it
invokes the `OnFederationForward` callback. So the "guard composes after
`MaskPoint`/`StripPii`" property the guard crate documents is
**structurally guaranteed by the existing flow**, not something the
wiring must arrange. On the UDP/NATS seam the same holds: the `Arc` those
sinks receive from `route_for_egress` is already the post-Send-PEP form.

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

1. **PR-A (crate) — DONE (#1465):** `serde::Deserialize` +
   `deny_unknown_fields` + `validate()` on `GuardConfig` (the crate is the
   single source of truth, not a server shadow); `GuardGate` =
   `Arc<parking_lot::Mutex<CrossDomainGuard>>` with an `evaluate` shim.
   Unit-tested in-crate. No server change.
2. **PR-B (core) — DONE (#1466):** `audit::guard_activated` /
   `audit::guard_rejected` in `rustgate-core::audit`. Note `guard_rejected`
   takes a `subject_cn`; see the seam finding — the federation seam cannot
   supply it as-is.
3. **PR-C (core + server) — the central gate (D1b):**
   - **core:** add an `OnEgressGuard` callback alias to
     `rustgate-core::egress` (alongside the existing `OnNatsPublish` /
     `OnFederationForward` / `OnHttpForward`), an
     `ArcSwap<Option<OnEgressGuard>>` slot on `Router` (same hot-reload
     pattern as `on_fanout`), and the invocation inside `route_for_egress`
     — after Send-PEP obligations, before sink forwarding; on `Err` drop
     the message and fire `audit::guard_rejected` with the full CN. **No
     `rustgate-router → rustgate-guard` dependency** (the seam is a core
     callback the server fills).
   - **server:** `--guard-config` flag + `define_config_file!` field +
     off-by-default `guard` feature (`rustgate-guard` optional dep);
     `start_guard()` in `setup.rs` (mirrors `start_ogc_sensorthings` for
     the load half) builds the `GuardGate` and installs the closure on the
     router; `docs/cross-domain-guard.md`; CHANGELOG.
   - **test:** a boundary-violating message (over-cap / missing-marking /
     non-dominant-classification) is dropped + audited with its CN — and a
     test that a sink with no guard configured is unaffected.

   Because the gate is central, this single PR covers federation, UDP,
   NATS, MQTT, and any future sink at once — there is **no separate
   federation fast-follow**.
4. **ADR** recording D1 (D1b via core `OnEgressGuard`), D2, D3 + the
   single-chokepoint seam finding.

PR-A and PR-B are merged-ready. PR-C is the central-hook change and wants
the most review (it touches `route_for_egress`); splitting the core-alias
half from the server-wiring half into two PRs is reasonable if the diff
gets large.

## Open questions for sign-off

D1 and the federation-seam question are **resolved** above (D1b via a core
`OnEgressGuard` callback — most secure *and* keeps the router guard-free).
Remaining:

1. **D3:** global direction for v1 (single `GuardConfig.direction`), or
   per-sink direction from the start? *(Recommendation: global for v1 — a
   central single gate has one direction context unless/until per-sink
   config is added; per-sink can layer on later without a wire break.)*
2. Single `parking_lot::Mutex<Guard>` acceptable for v1 (the audit writer
   is a single-file serialization point regardless)? — *implemented as
   such in PR-A; flag if you want sharding.* With the **central** gate,
   the mutex is now a genuine single chokepoint on the egress hot path, so
   this is worth an explicit nod: `evaluate` is cheap (bucket math + one
   audit append) and the audit file serializes anyway, so it is sound for
   v1; revisit only if egress-throughput profiling shows the gate's
   critical section dominating.
