# ADR 0028: Backend-agnostic durable, replayable message store

- **Status:** Proposed
- **Date:** 2026-07-03
- **Deciders:** rchiofalo
- **Related:** #1458 (durable replay epic), #1455, #731, ADR 0006 (redb for
  store-and-forward), ADR 0012 (`bytes::Bytes` on the hot path),
  ADR 0007 (`thiserror` at library boundaries)

## Context

The workspace has grown **three independent append-and-replay stores**, each
solving the same shape of problem — persist a stream of messages, hand them
back later from a known position, and bound growth — with its own on-disk
layout, error type, and retention logic:

- **`rustgate-router` store-and-forward** (`store_forward.rs`, `ClientQueue`):
  a redb-backed, per-CN durable queue. Keys are big-endian `seq_u64`; each
  stored envelope carries an appended HMAC-SHA256 integrity tag and the owning
  CN so per-CN drains can filter. Retention is a global byte cap with
  drop-oldest FIFO eviction. ACL and authz are re-evaluated on drain.
- **`rustgate-mqtt` session store** (`session_store.rs`): today an in-memory
  session-state store, with a source comment already noting that "a future PR
  can layer a redb-backed implementation behind" the same interface. MQTT
  session persistence is exactly the durable-replay problem restated.
- **`rustgate-federation` replay store** (`replay_persist.rs`, `ReplayStore`):
  a redb-backed, per-peer replay buffer. A single table keyed by
  `(peer_id, seq)`, a global byte cap, and `load_all()` rehydration on
  restart. Multiple historical key layouts are tolerated for backward
  compatibility.

These three carry duplicated concepts — a named stream, a monotonic offset, a
byte/record cap, oldest-first eviction, corruption detection — with no shared
type. That means three places to audit for the same class of bug (torn writes,
unbounded growth, replay-from-wrong-offset), three error enums, and no way for
higher layers (CoT position replay, mission history) to depend on "a durable
replayable log" without picking one concrete store.

Issue #1458 is an epic whose checklist spans four goals: define a shared trait;
make store-and-forward durable-by-default; persist MQTT session state; and
expose replay to the CoT/mission layers. Those goals collectively touch router,
mqtt, federation, and layers that do not yet exist — far more than one branch
or one PR should attempt, and flipping store-and-forward's default or rewiring
MQTT persistence in the same change would be a behavioral risk landing
alongside a new abstraction.

**Constraints (non-negotiable).** `rustgate-core` sits at the bottom of the
dependency graph and must gain **no new dependencies** for this seam
(`bytes::Bytes` and `thiserror` are already core deps; ADR 0012 and ADR 0007).
No `unsafe`, no `unwrap`/`panic` in production. The existing stores' bespoke
method shapes (per-CN HMAC tagging, per-peer keying, historical redb layouts)
are load-bearing and must keep working unchanged until each is migrated
deliberately.

## Decision

Introduce a **backend-agnostic `DurableStore` trait** in
`rustgate-core::durable` as the first, purely additive slice of the epic. The
trait captures the shared contract the three stores already implement in spirit,
so callers can hold `Arc<dyn DurableStore>` and be indifferent to whether the
backend is redb today or a JetStream-style log later.

The trait and its supporting types live in
`crates/rustgate-core/src/durable.rs`:

```rust
pub trait DurableStore: Send + Sync {
    fn append(&self, stream: &str, payload: &[u8]) -> Result<u64, DurableStoreError>;
    fn replay_from(&self, stream: &str, offset: u64)
        -> Result<Vec<StoredRecord>, DurableStoreError>;
    fn retain(&self, stream: &str, policy: RetentionPolicy) -> Result<(), DurableStoreError>;
    fn len(&self, stream: &str) -> Result<u64, DurableStoreError>;
    fn is_empty(&self, stream: &str) -> Result<bool, DurableStoreError>; // default impl
    fn total_bytes(&self, stream: &str) -> Result<u64, DurableStoreError>;
}

pub struct StoredRecord { pub offset: u64, pub payload: Bytes }
pub struct RetentionPolicy { pub max_bytes: Option<u64>, pub max_records: Option<u64> }

#[derive(thiserror::Error)]
pub enum DurableStoreError { Backend(String), NotFound { .. }, Corrupt { .. } }
```

**Object safety is a design requirement.** Every method takes `&self`, none are
generic, and none are `async` — so `Arc<dyn DurableStore>` compiles and the seam
is usable as a trait object. This mirrors the *existing* synchronous redb-backed
stores rather than forcing boxed futures; a future async backend wraps a
blocking implementation with the workspace's task-offload helpers instead of
changing this contract.

**A *stream* is a named, independent append-only log** — a per-CN queue
(router), a per-peer buffer (federation), or a per-client-session log (mqtt).
Offsets are per-stream and strictly increasing. `replay_from` returns every
retained record at or after the offset in ascending order; an empty result
(including retention having already evicted the range) is not an error.
`retain` evicts oldest-first until both caps are satisfied and is idempotent for
an unchanged stream.

**This branch does not rewire any of the three stores.** It lands the trait, its
types, unit tests (an in-memory test-only impl proving object safety and the
offset/replay/retention contract), and this ADR. Reconciling each concrete store
onto the trait — where the bespoke method shapes actually change — is deferred
to the named follow-up issues below, so the abstraction and each behavioral
migration land and get reviewed independently.

### Backend plan: redb now, JetStream-style log later

The concrete stores are redb-backed today (ADR 0006), and redb remains the
default embedded backend `DurableStore` implementations sit on. The trait is
shaped so a networked, JetStream-style append log (NATS JetStream is already a
workspace transport) can implement the same contract for deployments that want
replay to live off-box: `append` maps to a publish returning a sequence,
`replay_from` to a consumer starting at a sequence, `retain` to stream limits.
The trait deliberately exposes only what both backends can honor — a monotonic
offset, ordered replay-from, and oldest-first retention — and hides
backend-specific concerns (HMAC tagging, redb table layout, JetStream acks)
inside each implementation.

### Staged migration path (follow-up issues, to be scheduled by the owner)

1. **Store-and-forward onto the trait** — implement `DurableStore` for the
   router `ClientQueue`, mapping `stream` to CN and preserving HMAC tagging and
   the drop-oldest byte cap behind `retain`. This is where the "durable by
   default" default-flip is evaluated, separately from introducing the trait.
2. **MQTT session state behind the trait** — realize the `session_store.rs`
   TODO by layering a redb-backed `DurableStore` implementation for MQTT
   session persistence, replacing the in-memory store.
3. **Federation replay onto the trait** — implement `DurableStore` for
   `ReplayStore`, mapping `stream` to `peer_id` and folding `load_all`
   rehydration into `replay_from`, while keeping backward-compatible key
   layouts inside the implementation.

A fourth epic goal — exposing replay to the CoT/mission layers — becomes
tractable only after at least one store implements the trait, and is tracked as
a later slice of #1458 rather than committed to here.

## Alternatives considered

- **Do nothing; keep three bespoke stores.** Rejected: the duplication is the
  problem #1458 exists to solve. Every new durable-replay consumer (mission
  history, CoT replay) would either couple to one concrete store or add a
  fourth bespoke one.
- **Migrate all three stores onto a trait in one change.** Rejected: it
  bundles a new abstraction with three behavioral migrations (including a
  default-flip for store-and-forward and replacing MQTT's in-memory store),
  violating one-concrete-task-per-branch and making review of the risky parts
  harder. The additive-trait-first ordering lets each migration be reviewed on
  its own.
- **An `async` trait (native `async fn` or boxed futures).** Rejected for this
  slice: the existing stores are synchronous redb calls, so an async trait
  would force either premature boxing or an executor dependency into
  `rustgate-core`. A synchronous, object-safe trait matches today's code; a
  future async backend can offload blocking work without changing the contract.
- **A generic `DurableStore<T>` over the record type.** Rejected: generics
  break object safety, and every consumer already works in terms of opaque
  payload bytes (`Bytes`). Keeping the payload as bytes preserves
  `Arc<dyn DurableStore>` and matches ADR 0012.

## Consequences

- `rustgate-core` gains a new unconditional module (`durable`) and no new
  dependency. Because the module is unconditional and feature-flag-free, it does
  not expand the `check-features` powerset surface.
- Higher layers can now depend on `Arc<dyn DurableStore>` — a stable seam —
  rather than on a concrete store, unblocking CoT/mission replay work without
  prematurely choosing a backend.
- The three live stores are **untouched** by this branch and keep working
  exactly as before; there is no runtime behavior change to ship, so no config
  or operational impact until a migration issue lands.
- New maintenance obligation: as each store migrates onto the trait, its
  bespoke error type folds into `DurableStoreError` (backend errors → `Backend`,
  HMAC/torn-write failures → `Corrupt`), and its retention logic must honor the
  documented oldest-first, both-caps semantics. Those changes are behavioral and
  gated behind their own issues and CHANGELOG entries.
- The decision is reversible while it is still just a trait: if the seam proves
  wrong before any store migrates, removing `durable.rs` and this ADR has no
  blast radius. Once stores implement it, revisiting means re-touching each
  migrated store, so the trait shape should be validated against the
  store-and-forward migration (follow-up 1) before the federation and MQTT
  migrations commit to it.
