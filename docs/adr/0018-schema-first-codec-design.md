# ADR 0018: Schema-first codec design for tactical wire formats

- **Status:** Accepted
- **Date:** 2026-05-18
- **Deciders:** rchiofalo
- **Related:** #1352 (v1 codec-schema), #1370 (v2 dispatch + value-mapping),
  #1383 / #1385 / #1387 / #1389 (v3 family), #1399 / #1402 (v4 cross-byte),
  #1403 / #1404 (v4.1 signed), #1407 / #1408 (v5 variable-shift),
  #1394 / #1397 (parity-test tautology fix),
  #1411 (v6 schema chaining — deferred),
  [`docs/codec-schema-grammar.md`](../codec-schema-grammar.md)

## Context

rustgate ships codecs for 10+ tactical wire formats: STANAG 4586, IEEE 1278.1
DIS, MAVLink v1/v2, VMF (MIL-STD-6017), ASTERIX, Link 16 (STANAG 5518), CoT,
SAPIENT, NFFI, Meshtastic. Each is well-specified, well-versioned, and used
by exactly the kind of system rustgate exists to route between. The shapes are
deceptively similar: fixed offsets, big-endian by NATO convention, occasional
bit-packing for flags or FPI cascades, sometimes a variable-length tail keyed
off a count byte.

Writing a hand-rolled Rust codec per protocol means maintaining N parallel
implementations of the same patterns. Worse: it means N parallel test
harnesses that never quite agree on what "the wire format" is. When the
STANAG 4586 codec landed in #1390 with a SchemaCodec-driven encode that
silently zeroed `vehicle_id` on a NaN altitude (#1393), the existing
hand-rolled-encode-vs-hand-rolled-decode proptest passed trivially because
both halves used the same broken implementation. The weekly-fuzz harness
caught what the proptest missed.

The forcing function: every new protocol added to the workspace risks the
same class of regression. We needed a discipline that:

1. Captures the wire format declaratively, once, in a form that does not
   depend on the codec author choosing the right Rust idioms.
2. Catches drift between any two implementations of the same wire format
   at proptest time, not weekly-fuzz time.
3. Stays a thin contract over the production codec — does not couple the
   production code to a particular grammar, doesn't force a single
   runtime, doesn't introduce performance overhead in the hot path.

## Decision

**Every tactical-protocol crate ships a YAML schema and a `schema-parity`
proptest alongside the hand-rolled codec.**

The schema lives at `crates/<crate>/schemas/<message>.yaml`. The proptest
lives at `crates/<crate>/tests/schema_parity_<message>.rs`. The proptest
asserts:

```text
inline_reference_encoder(input)  ==  SchemaCodec::from_entity(
                                       SchemaCodec::to_entity(
                                         inline_reference_encoder(input)))
```

byte-for-byte for every arbitrary input proptest generates. The
inline_reference_encoder is **hand-coded inside the test file** and does
not call the production codec — that is the load-bearing #1394 fix; an
earlier iteration used `production::encode` for one half of the round-trip
and missed the #1393 regression class.

The grammar grows by **deliberate addition**: each version adds the smallest
feature that lets a real workspace codec round-trip its wire format. Five
versions have shipped (v1 → v5); the grammar reference at
[`docs/codec-schema-grammar.md`](../codec-schema-grammar.md) lists every
key, every validator constraint, and every backward-compat rule.

The schema is **not** the production codec. The hand-rolled codec stays in
`src/`. Migration of a production codec to a SchemaCodec-driven runtime is a
separate refactor that has only successfully landed once (#1390 / #1393
STANAG 4586 vehicle position decode). Future migrations are gated on the
v6 grammar (`#1411` schema chaining) and on each codec's specific layout
constraints.

## Alternatives considered

- **Stay hand-rolled per crate.** Lowest cost today, highest cost over
  time — every new protocol re-pays the cost of writing both a codec and
  its proptest harness, and the #1393 class of regression has no
  cross-implementation check to catch it.

- **Generate codecs from the schema at build time** (a la `prost` for
  protobuf). Cleaner long-term, but a much bigger commitment: requires
  a custom proc-macro / build script, ties every codec's source to the
  schema's grammar version, and makes the rollout of grammar features
  invasive (every codec recompiles when the grammar changes). Rejected as
  premature — the schema-as-pin pattern delivers the cross-implementation
  check without the proc-macro infrastructure.

- **Adopt an existing schema vocabulary** (XTCE, CCSDS Space Packet, MAVLink
  XML message definitions). XTCE is 200+ pages with dozens of optional
  features (algorithmic calibration, container inheritance, parameter
  aggregation) we don't need. MAVLink message XML is single-protocol.
  Building a thin in-house grammar that covers the 80% of tactical wire
  formats (fixed offsets, bit-packing, FPI cascades, count-driven repeats)
  ships in five small PRs instead of one large adoption effort.

- **Use the schema as a JSON Schema-style validator** (decode bytes, then
  validate the decoded value satisfies a contract). Catches the wrong class
  of bug — semantic invariants are already enforced in the wrapper layer
  via `thiserror`-typed errors. The actual gap is wire-format drift, which
  needs byte-level round-trip not value-level validation.

## Consequences

**What the codebase now looks like.** Every tactical-protocol crate has:

- One `schemas/*.yaml` per message type with a byte-layout docstring.
- One `tests/schema_parity_*.rs` per message type with the inline
  reference-encoder pattern.
- A dev-dep on `rustgate-codec-schema` (production code does not depend on
  it unless the codec has been migrated to SchemaCodec-driven — currently
  only STANAG 4586 vehicle_position decode).

The production codec source files are unchanged in shape from the
hand-rolled approach; the schema is purely additive.

**New constraints on future work.**

- Every new tactical-protocol codec PR includes a schema YAML + parity
  test. The recipe is in
  [`CONTRIBUTING.md`](../../CONTRIBUTING.md#adding-a-new-protocol-schema-parity-test).
- New grammar features require a real-protocol forcing function. The three
  bars (real protocol needs it, existing grammar genuinely cannot express
  it, backward-compatible) are spelled out in
  [`docs/architecture.md`](../architecture.md#when-to-add-a-new-grammar-feature).
- Wire-format docstrings inside the YAML are the canonical reference for
  the layout. The hand-rolled codec's comments must agree; the
  schema-parity proptest catches drift.

**What is now harder.**

- Schemas for XML / JSON / Protobuf wire formats (CoT, SAPIENT, Meshtastic,
  NFFI) are out of scope — the grammar is binary-fixed-offset by design.
  Those codecs stay hand-rolled with no schema-parity test until either
  the grammar grows new vocabularies or those codecs adopt a different
  validation discipline.
- The grammar carries a backward-compat commitment: every v3 schema must
  validate and produce byte-identical wire output under v4 and beyond.
  Breaking changes would require bumping `schema-version` (currently
  always `"1"`).

**What is now easier.**

- Adding a new tactical-protocol codec is a templated effort:
  hand-rolled codec → schema YAML → parity proptest. Six codecs already
  follow this template; the seventh is mostly mechanical.
- Wire-format documentation is co-located with the validator that enforces
  it. A reader who wants to know "what does byte 7 of a DIS Entity State
  body mean" reads the YAML; a reader who wants to know "is this
  documentation actually true" runs the parity test.
- Regressions of the #1393 class — silent field-zeroing during a
  refactor — fail the parity proptest at compile time rather than at
  weekly-fuzz time.

**Migration path.** The decision is reversible at the schema-parity-test
level: a crate can drop its schema and parity test without affecting
production. The grammar features themselves can be removed only if no
schema uses them; the backward-compat commitment means existing schemas
must continue to validate, so v3+ features are sticky once a schema in
the workspace depends on them.
