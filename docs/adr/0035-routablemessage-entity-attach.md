# ADR 0035: Attach a parsed `Entity` to `RoutableMessage`

- **Status:** Proposed
- **Date:** 2026-07-03
- **Deciders:** rchiofalo
- **Related:** #1540 (attach parsed entity alongside payload),
  #847 (canonical `Entity` type + `EntityCodec` trait — CLOSED),
  #858 (inference back-annotation via `EntityCodecRegistry` — CLOSED),
  #851 (Foundry bridge + wiring scaffold — CLOSED),
  ADR 0018 (schema-first codec design),
  ADR 0023 (tactical codec ingress seam — the edge that will populate the attach)

## Context

rustgate carries a single normalized shape — `rustgate_core::entity::Entity`
(ADR 0018, #847) — that every protocol codec decodes to and re-encodes from.
Two downstream seams want that entity:

- **Inference back-annotation** (`rustgate-inference`, #858) runs a model
  pipeline over each routed entity. Today it re-decodes `msg.payload` with the
  registered `EntityCodecRegistry` codec inside the `OnRouted` callback.
- **Foundry outbound projection** (`rustgate-foundry`, #851) projects an
  entity onto a Palantir Foundry property bag and upserts it. Today its
  per-message handler is a deliberate scaffold: it receives a
  `RoutableMessage`, has no entity to project (the envelope carries only
  `payload: Bytes`), logs at `debug`, and drops the message. The end-to-end
  machinery is exercised only through a `dispatch_entity` test hook.

The envelope has never carried the parsed entity. Where a codec has *already*
decoded the payload at ingress, both seams re-parse the same bytes — the
Foundry path cannot proceed at all without a second decode it does not have,
and the inference path pays a redundant parse. The #847 module docs always
flagged this: *"future work will optionally attach an `Entity` alongside
`payload` so the workspace can migrate codec by codec without a breaking flag
day."* This ADR records that attach decision and the phased plan around it.

Three premises in the originating issue were imprecise and are corrected here:

1. Inference is **not** blocked on the attach — it already works end-to-end
   via the registry decode (#858). "Finishing inference production wiring"
   means adding a real ONNX backend behind a separate `inference-onnx`
   feature, which is **out of scope** for this ADR.
2. Lattice outbound does **not** need this attach — it already routes via a
   lattice-local entity that carries the raw payload bytes. Only Foundry
   needs it, because Foundry projects `rustgate_core::entity::Entity`, which
   has no payload field.
3. The attach, the Foundry live registration, and the ONNX backend are three
   separable workstreams. Bundling them is the anti-goal (it couples an
   additive core change to a partner-gated SDK and a native ML dependency).

## Decision

**D1 — Add one optional, `Arc`-wrapped field to `RoutableMessage`.**
`pub entity: Option<Arc<rustgate_core::entity::Entity>>`, defaulted to `None`
at every construction site. `RoutableMessage` is cloned once per recipient on
the broadcast fan-out hot path; `Arc` keeps that clone an O(1) refcount bump
rather than a deep copy of the entity's attribute bag. The field is populated
via a `RoutableMessage::with_entity(entity) -> Self` builder mirroring the
existing `Metadata::with_*` pattern.

**D2 — Purely additive, no wire-format churn.** `RoutableMessage` is not
`Serialize`/`Deserialize` (only `Metadata` is), so the new field touches no
on-the-wire or on-disk shape. Every existing `RoutableMessage { … }` literal
gains `entity: None`; no behavior changes because nothing reads the field
until a producer attaches an entity and a consumer opts into the fast path.

**D3 — Wire two proof-of-attach consumer seams, change no observable
behavior.**

- *Inference* (`rustgate-inference::wiring::router_callback`): when
  `msg.entity` is `Some`, use it directly and skip the
  `registry.get(...).to_entity_dyn(&msg.payload)` decode; fall back to the
  codec decode when `None`. The attached entity is exactly what the registry
  codec would produce, so the fast path is observably equivalent — it only
  avoids the second parse.
- *Foundry* (`rustgate-foundry::wiring::handle_outbound`): when `msg.entity`
  is `Some`, project + dispatch it via the existing `dispatch_entity`; keep
  the `None` debug-scaffold branch. Because the function now genuinely awaits
  on the `Some` arm, the prior `#[allow(clippy::unused_async)]` scaffold
  justification is removed — the lint self-clears.

**D4 — No producer yet; the attach is opt-in.** No ingress codec populates
`msg.entity` in this slice. Every message still flows with `entity: None`, so
both seams take their existing (fallback / scaffold) branch. The producer side
— having a codec attach its decoded entity at the ingress seam (ADR 0023) — is
the next phased step.

## Phased plan

1. **This slice — attach + seams (#1540).** The `Option<Arc<Entity>>` field,
   the `with_entity` builder, the inference fast path, and the Foundry
   `handle_outbound` consumer. Additive; no producer.
2. **Codec populate.** An ingress codec (starting with CoT, then the tactical
   codecs behind ADR 0023's shared seam) attaches its decoded `Entity` to the
   `RoutableMessage` it produces, so downstream consumers hit the fast path.
3. **Foundry outbound live registration.** Wire `spawn_outbound`'s `tx` into
   the router's egress observer so routed messages actually reach
   `handle_outbound` in a live server, and swap the in-memory offline queue
   for the `store_forward` redb-backed sink. Gated on the partner SDK
   (`foundry-real`) landing.
4. **Inference ONNX backend.** A real `InferenceModel` backend behind a
   separate `inference-onnx` feature, replacing the mock. Independent of the
   attach — inference already runs via the registry decode today.

Steps 3 and 4 are explicitly **out of scope** for #1540 and are tracked as
follow-ups.

## Alternatives considered

- **Attach a bare `Entity` (not `Arc`-wrapped).** Rejected: `RoutableMessage`
  is cloned once per recipient in the broadcast fan-out. A bare `Entity` field
  deep-copies the attribute `BTreeMap` on every clone, turning O(1) fan-out
  into O(recipients · entity size). `Arc` makes the clone a refcount bump and
  is consistent with `Destination::Group`'s `Arc<str>` (ADR / #784).

- **Make `RoutableMessage` `#[non_exhaustive]` + add a `new()` constructor.**
  Rejected for this slice: `#[non_exhaustive]` only blocks *external* literal
  construction, and every one of the ~238 construction sites is in-workspace
  (crates + tests), so it would not save the mechanical `entity: None` churn.
  It would also force external literal sites through a constructor as a
  breaking change for a purely additive field. The `Metadata` precedent
  (which *is* `#[non_exhaustive]`) was justified by its serde wire contract;
  `RoutableMessage` has none.

- **Finish Foundry live registration + the ONNX backend in the same branch.**
  Rejected as the primary anti-goal: it couples an additive core-type change
  to a partner-gated SDK and a native ML dependency, each with its own risk
  and review surface. Registering `spawn_outbound` live before the producer
  attach and a real SDK exist would ship a path that drops every message.

- **Carry the payload bytes inside the Foundry-local entity (the Lattice
  approach) instead of attaching to the envelope.** Rejected for Foundry:
  Foundry projects the canonical `rustgate_core::entity::Entity`, which has no
  payload field by design (ADR 0018's strict-subset choice). The envelope
  attach is the shape that serves *all* future consumers, not one adapter.

## Consequences

- **Additive and reversible.** The field defaults to `None` everywhere and no
  producer sets it yet, so this slice changes no observable behavior. Removing
  it is deleting the field, the builder, and the two `Some`-arm branches.

- **The fast path is a no-differential optimization.** Because an attached
  entity is exactly what the registry codec would decode, the inference fast
  path cannot diverge from the fallback — a unit test pins that the registry
  codec is *not* consulted when an entity is attached and *is* consulted when
  it is not.

- **One invariant to hold: attach == decode.** When step 2 lands a producer,
  the entity it attaches MUST equal what the registered codec would decode
  from the same payload, or the fast path and the fallback diverge. This is a
  review invariant, mirroring ADR 0023's "edge codec == router codec".

- **Foundry's scaffold now has a live consumer arm.** `handle_outbound` no
  longer unconditionally drops; the `Some` arm dispatches. The `None` arm
  remains until step 2 gives it entities to consume. The `unused_async`
  suppression is gone.
