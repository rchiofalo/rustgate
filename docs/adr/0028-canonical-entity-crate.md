# ADR 0028: Extract the canonical entity model into `rustgate-entity`

- **Status:** Proposed
- **Date:** 2026-07-03
- **Deciders:** rustgate maintainers
- **Related:** #1535 (this decision), #847 (original in-core scaffold),
  #848 (correlation `FusedEntity`), ADR 0018 (schema-first codec design),
  ADR 0023 (tactical codec ingress seam)

## Context

The canonical, protocol-agnostic entity model — `Entity` plus its
supporting enums (`EntityKind`, `Position`, `Velocity`,
`AttributeValue`), the `EntityCodec` trait, its object-safe
`DynEntityCodec` blanket-impl form, and the `EntityCodecRegistry` — lives
today in `crates/rustgate-core/src/entity.rs`. It is the lingua franca
between every protocol the router speaks: 13 codec implementations
(`rustgate-cot`, `rustgate-mavlink`, `rustgate-asterix`,
`rustgate-stanag4586`, `rustgate-link16`, `rustgate-dis`,
`rustgate-sapient`, `rustgate-nffi`, `rustgate-vmf`,
`rustgate-meshtastic`, the declarative `rustgate-codec-schema`, and the
core's own reference impl) decode inbound wire formats into an `Entity`
and re-encode outbound `Entity` values back to their native form.

The model lives in `rustgate-core` for a historical reason, not a
designed one. It began as an in-core scaffold under #847, whose richer
model — a UUIDv7 `id`, an `Affiliation` enum, a provenance /
`SourceAttribution` chain, a `confidence` scalar, and inter-entity
`relationships` — was **descoped** to ship the v1 seam. What landed is a
deliberately narrow strict-subset value type plus the codec trait. That
was the right call for #847, but it left the shared model welded into
`rustgate-core`, the crate every other crate already depends on, so the
entity surface cannot evolve (or add a dependency) without touching the
foundation crate that carries `Identity`, `RoutableMessage`, TLS
socket helpers, the audit chain, and encrypted archives.

The framing in #1535 that the current state is "ad hoc" is only half
right and worth correcting for the record. The `EntityCodec` seam is
**not** ad hoc: it is uniform across all 13 codecs and dispatched
through a single `EntityCodecRegistry`. The real fragmentation is
elsewhere:

- **`rustgate-lattice` defines its own `Entity` and `EntityKind`** in
  `crates/rustgate-lattice/src/bridge.rs`, with no dependency on the
  core model at all — a genuine parallel type, not a re-export.
- **`rustgate-foundry` and `rustgate-dds` each duplicate an
  `EntityOverlay`** mapper type (`crates/rustgate-foundry/src/mapper.rs`
  and `crates/rustgate-dds/src/mapper.rs`) rather than sharing one.

Those divergences are what a standalone entity crate is meant to give a
convergence target for. Wedging them onto a type buried in
`rustgate-core` is both a layering smell (a partner bridge should not
need the whole of core to speak the entity model) and a practical
blocker for the descoped #847 richness, which would bloat core further.

## Decision

Extract the canonical entity model into a new standalone crate,
`rustgate-entity`, and migrate consumers onto it in phases. **This ADR
authorizes the extraction and records the migration plan; the first
slice (this branch) ships only the crate skeleton and moves no code.**

The crate lands at `crates/rustgate-entity/` and is added as the
workspace's 40th member (up from 39), kept in lockstep across
`CLAUDE.md`, the `README.md` architecture table, and
`docs/architecture.md`. Its dependency surface is intentionally minimal
— it re-exports the in-core model rather than declaring the wire-format
dependencies (`serde`, `bytes`) itself, so `cargo machete` sees no
unused deps.

The migration is explicitly phased so that no single PR carries the full
blast radius across ~20 consumers plus the divergent partner types:

1. **Crate skeleton (this branch, #1535).** `rustgate-entity` exists as
   a re-export shim: `pub use rustgate_core::entity::*` at the crate
   root and behind a `pub mod prelude`, plus the migration-target trait
   signatures documented in rustdoc. No type moves out of
   `rustgate-core`; all existing consumers compile unchanged. New code
   may begin importing `rustgate_entity::*`.
2. **Re-export shim in core.** Move the type *definitions* from
   `rustgate-core::entity` into `rustgate-entity`, and have
   `rustgate-core` re-export them for backward compatibility. Consumers
   still importing from `rustgate_core::entity` keep working; the
   physical home flips without a flag day.
3. **Codec migration.** Point the 13 codec crates at
   `rustgate_entity::EntityCodec` directly and drop the core re-export
   dependency where a crate no longer needs anything else from core.
4. **Partner-bridge unification.** Converge the lattice `Entity` /
   `EntityKind` and the foundry/dds `EntityOverlay` onto the canonical
   model, then — separately — reintroduce the descoped #847 richness
   (`id`, `Affiliation`, provenance, confidence, relationships) in the
   now-standalone crate where it does not bloat `rustgate-core`.

This ADR does **not** re-close the #847 epic. It converts the roadmap
stub in #1535 into a concrete, reviewable first PR and leaves the
type-migration and partner unification as tracked follow-ups.

## Alternatives considered

- **Leave the model in `rustgate-core` and grow it there.** Simplest —
  no new crate, no migration. Rejected because it keeps the entity model
  coupled to the foundation crate: every entity-model change forces a
  `rustgate-core` rebuild across the whole workspace, the descoped #847
  richness would bloat core, and the partner bridges would have to
  depend on all of core to converge. The layering cost compounds as the
  model grows.
- **Do the full extraction and consumer migration in one PR.** This is
  the literal ask in #1535 ("build the unified `rustgate-entity` crate …
  migrate the partner bridges and correlation/inference onto it"). The
  direction is correct but the scope is not: one PR touching ~20 crates
  plus the divergent lattice/foundry/dds types is un-compile-verifiable
  in review, has a large blast radius, and violates the one-concrete-task
  budget. Rejected in favour of the phased plan; the end state is
  identical, reached in reviewable slices.
- **Skeleton crate that re-exports nothing (empty placeholder).**
  Rejected because a crate that lists `rustgate-core` as a dependency
  without using it trips `cargo machete`, and an empty crate gives new
  code nothing to import against. The re-export shim both satisfies the
  unused-dep check and makes the migration-target import path real from
  day one.

## Consequences

Once this slice is in force, the workspace has a 40th crate that is a
thin, dependency-light alias for the in-core entity model. New code can
import `rustgate_entity::{Entity, EntityCodec, EntityCodecRegistry, …}`
and will not have to change its imports when the definitions physically
move in phase 2. The 13 existing codec crates and the ~20 total
consumers are untouched and cannot break, because no type has moved.

The decision creates a **lockstep maintenance obligation**: the crate
count (40) must stay consistent across `CLAUDE.md`, `README.md`,
`docs/architecture.md`, and the workspace `members` list, or the
`check-playbook-drift.sh` CI check flags the drift. It also creates a
**deferred-work ledger**: phases 2–4 are the substance of the epic and
remain open. Until phase 4 lands, the lattice `Entity` and the
foundry/dds `EntityOverlay` duplicates still exist — this ADR records
them as known divergences with a convergence target, not as resolved.

The decision is **reversible** at low cost while it is still a shim: if
the extraction proves unwarranted, deleting `crates/rustgate-entity/`
and its workspace entries restores the prior state, since no consumer
depends on it yet and no definition has left `rustgate-core`. That
reversibility ends once phase 2 moves the definitions — from that point
`rustgate-core` re-exports from `rustgate-entity` and the dependency
direction is committed.
