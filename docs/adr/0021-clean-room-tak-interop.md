# ADR 0021: Clean-room interoperability policy for TAK and third-party protocols

- **Status:** Accepted
- **Date:** 2026-05-30
- **Deciders:** rchiofalo
- **Related:** #1455 (TAK Server application-layer compatibility epic),
  ADR 0018 (schema-first codec design),
  [`CONTRIBUTING.md`](../../CONTRIBUTING.md) (clean-room contributor rules),
  *Google LLC v. Oracle America, Inc.*, 593 U.S. 1 (2021),
  *Lotus Dev. Corp. v. Borland Int'l*, 516 U.S. 233 (1996),
  17 U.S.C. §102(b), 17 U.S.C. §105

> **Update (2026-10, relicensed to AGPL-3.0-only, #1727).** This ADR was
> written while rustgate was proprietary, and its body says so. The
> clean-room rule **still stands unchanged**, but its justification has
> shifted. AGPL-3.0 and GPLv3 may be combined (section 13 of each license
> permits it), so copying GPLv3 code is no longer an outright license
> conflict. The rule now rests on three things: (1) copied code would bring
> in copyright owned by a third party, ending the sole-ownership position
> that allows rustgate to be relicensed or dual-licensed; (2) EPL-licensed
> code is generally not GPL-compatible at all, so the FreeTAKServer / taky
> conflict remains; and (3) the independent-creation record below is
> still what defends the vendored schemas. Where the body says "the
> proprietary license", read "rustgate's license and its sole-ownership
> requirement".

> **This ADR is engineering policy, not legal advice.** It records the
> rules the project follows to keep interoperability work clean and the
> reasoning behind them. Nothing here guarantees any litigation outcome.
> Before any commercial release, the posture described here must be
> confirmed with qualified counsel.

## Context

rustgate interoperates with externally-defined protocols — CoT, the TAK
Protocol (v1 protobuf stream/mesh), TAK Server v2 federation, MAVLink,
MQTT, DIS, Link 16, VMF, ASTERIX, STANAG 4586, and others. The roadmap
(#1455) adds deeper **TAK Server application-layer compatibility**
(Enterprise Sync, Mission API, Marti REST). That work sits closest to a
government-adjacent ecosystem whose reference implementations carry
**copyleft** licenses, so the IP boundary must be explicit *before* code
is written.

The TAK reference implementations are:

- **ATAK-CIV** (`deptofdefense/AndroidTacticalAssaultKit-CIV`) and **TAK
  Server** (`TAK-Product-Center/Server`) — U.S. DoD works published under
  **GPLv3**.
- **FreeTAKServer**, **taky** — third-party OSS reimplementations under
  GPL/EPL-family licenses.

When this ADR was written rustgate shipped under a **proprietary** license
(it is now AGPL-3.0-only; see the update above). GPL/EPL source text cannot
live in it. The whole question is therefore: *what may we legitimately use
to build interoperable code, and what must we never touch?*

### The distinction that controls everything

Two things are routinely conflated and must be kept apart:

1. **A protocol / wire format / schema interface** — the field
   *(name, type, number)* tuples, message layouts, endpoint paths, status
   codes that a conforming implementation **must** match to interoperate.
   These are *interfaces / methods of operation*, not creative expression.
2. **A specific implementation's source code** — the Java/Python/Rust that
   *realizes* the protocol, including its comments, internal structure,
   helper logic, and test fixtures. This is protected expression; copying
   it from a copyleft project imports obligations the proprietary license
   cannot satisfy.

rustgate may freely re-express (1). rustgate must never copy (2).

### Where the existing vendored schemas stand (audited 2026-05-30)

rustgate vendors small protobuf schemas under
`atakmap.commoncommo.protobuf.v1`, `com.atakmap`, and
`gov.tak.cop.proto.v1` (in `rustgate-proto` and `rustgate-federation`). A
provenance audit compared them field-by-field against the upstream GPLv3
files and found they are **independent re-expressions, not copies**:

- **All upstream comments and documentation are absent** — our files
  carry none of the expressive content (timestamp-semantics notes,
  XML-mapping comments, field-optionality prose) that fills the upstream
  `.proto` files.
- **Type and structural divergences exist** — e.g. our `TakControl`
  declares `string` version fields where upstream uses `uint32`; our
  `CotEvent` orders `caveat`/`releaseableTo` differently from upstream.
  A verbatim copy could not contain these differences.
- **What is identical is only the unprotectable interface** — the
  *(name, type, number)* tuples that the wire format *forces*. That is
  precisely the part that must match for interoperability and the part
  least likely to be protectable.

The audit's conclusion: the schemas are best characterized as
independently-authored interface definitions that share the protocol's
required tuples, not derivatives of upstream expression.

## Decision

**rustgate implements third-party-protocol interoperability clean-room,
from public protocol facts only. We never copy a reference
implementation's source expression. We keep a contemporaneous record of
that independence.**

### 1. Permitted sources (the clean room)

Interop code may be derived ONLY from:

- **Published protocol specifications, schema/IDL files, and developer
  documentation** that describe the wire format as a *fact* (RFCs,
  OGC/NATO/MIL-STD specs, `mavlink.io`, the public TAK protocol
  documentation, published `.proto`/XSD interface files).
- **Wire behavior we observe ourselves** from clients/servers we are
  entitled to run (e.g. an ATAK client we operate), captured as our own
  packet traces / fixtures.
- **Our own original expression** written against the above.

### 2. Prohibited sources

- **TAK Server / ATAK-CIV source code as a code source.** GPLv3. Do not
  transcribe it, do not paste from it, do not decompile shipped binaries
  to recover it. The *protocol facts* it documents are usable (item 1);
  its *source expression* is not.
- **Copyleft reference implementations (FreeTAKServer, taky, …) as a code
  source.** They may be **read to understand the public protocol** — the
  protocol is a public fact — but **no code, comments, internal
  structure, naming beyond protocol-required tuples, or test fixtures may
  be copied or transcribed**. When in doubt, work from the spec, not the
  implementation.
- Any source under NDA, EULA, or terms forbidding derivative
  reimplementation.

### 3. Re-express, do not vendor verbatim

When rustgate needs a schema/IDL that exists upstream under a copyleft
license, it **re-expresses** the interface (writes its own `.proto`/YAML
from the protocol facts) rather than copying the upstream file. The
re-expressed file:

- carries **no** upstream comments, headers, or license text;
- carries a **rustgate provenance header** (see §4) stating it is an
  independent implementation of the public wire format;
- is the project's own copyrighted work.

This is the posture the existing TAK schemas already satisfy; it is now
the explicit rule. (Schema-first YAML pins per ADR 0018 are the same idea
applied to the bit-level codecs.)

### 4. Provenance header on every re-expressed interface file

Every vendored/re-expressed third-party schema or IDL file MUST begin
with a header of this shape:

<!-- REUSE-IgnoreStart -->
```proto
// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only
//
// Independent clean-room implementation of the public <PROTOCOL> wire
// format for interoperability. The field names, types, and numbers below
// are dictated by the protocol's wire format (a method of operation /
// uncopyrightable interface, cf. 17 U.S.C. §102(b)); they are NOT copied
// from, and this file is NOT derived from, any third-party source code.
// Authored from public protocol documentation and observed wire behavior.
// See docs/adr/0021-clean-room-tak-interop.md.
```
<!-- REUSE-IgnoreEnd -->

The header is the contemporaneous, per-file record of independent
authorship. It is deliberately **not** a third-party attribution / GPL
NOTICE: asserting GPL provenance would wrongly concede the file is a
derivative of upstream expression, which the audit found it is not.

### 5. Provenance discipline in commits and PRs

- A PR that adds or changes third-party-protocol interop **must state, in
  its description, the public source it was built from** (which spec /
  doc / observed behavior).
- Commits and PRs must **never** state or imply that a prohibited source
  was read to produce the code.
- New schema/IDL files must carry the §4 header in the same PR.

### 6. Naming and trademark

Use generic, descriptive terms ("TAK Protocol v1 framing",
"Marti-compatible sync endpoint") per the existing CLAUDE.md
generic-terminology rule. Nominative use of a protocol name to state
compatibility is fine; do not imply endorsement, certification, or
affiliation with any trademark holder.

## Why this is the defensible posture (reasoning of record)

No document guarantees a court outcome. The goal is to make rustgate's
position rest on **several independent grounds, each of which alone is
likely dispositive**, so an adversary must defeat all of them:

1. **The schema interface is likely uncopyrightable.** Field
   *(name, type, number)* tuples are the "method of operation" by which
   the protocol is used — uncopyrightable under **17 U.S.C. §102(b)** and
   *Lotus v. Borland* (menu command hierarchy held an uncopyrightable
   method of operation). *Google v. Oracle* decided on fair use and
   expressly did not hold APIs copyrightable, leaving the §102(b) argument
   fully available for a far narrower data-interchange schema.
2. **Merger.** Once wire compatibility is required, `uint64 staleTime = 8`
   is essentially the only way to express the field — idea and expression
   merge, defeating protection.
3. **Independent creation.** The audit shows our files are not copies
   (no upstream comments; type/order divergences). Independent creation is
   a complete defense to copying, and the per-file §4 header plus PR
   provenance create the contemporaneous evidence of it.
4. **Industry norm / non-derivative.** FSF and SFLC guidance, and long
   practice (independent protocol reimplementations talking to GPL
   references — WireGuard, the Lotus/Borland line), treat an independent
   implementation of a protocol as **not** a derivative work of the
   reference implementation. No case has held otherwise.
5. **U.S. Government works (a thumb on the scale, not a pillar).** ATAK-CIV
   and TAK Server are DoD works; under **17 U.S.C. §105** they are public
   domain domestically, and it is genuinely doubtful GPLv3 is enforceable
   on a public-domain work at all. This is untested and contractor-authored
   portions may differ, so we do **not** rely on it — but it cuts our way.

We rely on (1)–(4); (5) is a bonus. Crucially, we do **not** rely on the
weakest argument alone, and we keep the record (headers + PR provenance)
that makes (3) concrete.

## Alternatives considered

- **License TAK Server / partner with a TAK vendor.** Valid commercial
  path; couples release cadence to a third-party license and contradicts
  vendor neutrality. Revisit only if a formal partnership is pursued.
- **Vendor FreeTAKServer/taky logic directly.** Fastest to "working",
  imports GPL/EPL obligations incompatible with the proprietary license —
  a non-starter.
- **Ship a GPLv3 NOTICE for the existing protos.** *Rejected* — it would
  assert the files are GPL-derived, conceding derivative status the audit
  found to be false and undercutting the independent-creation defense. The
  §4 provenance header is the correct artifact.
- **Avoid TAK compatibility entirely.** Cleanest, but forfeits the largest
  competitive gap in the 2026 audit. Rejected.

## Consequences

**Enables.** #1455 and its children proceed with a written, multi-ground
defensible posture and a per-file evidentiary trail.

**Constrains contributors.** Interop PRs without a stated public source,
or new schema files without the §4 header, should not merge. Reading
copyleft references for *understanding* is allowed; copying is not, and
the PR must reflect original authorship. See `CONTRIBUTING.md`.

**Easier later.** A due-diligence / acquisition / customer security review
finds a policy, per-file independent-authorship headers, and PR-level
provenance — not a git-archaeology exercise.

## Migration / immediate actions

1. Add the §4 provenance header to every already-vendored third-party
   schema file (`rustgate-proto/proto/*`, `rustgate-federation/proto/*`)
   — this PR.
2. Add the clean-room contributor section to `CONTRIBUTING.md` — this PR.
3. Track the `TakControl` `string`-vs-`uint32` divergence as a **wire-
   correctness** follow-up (it is a compatibility bug for real TAK
   interop, not an IP issue).
4. Future TAK-compat PRs cite this ADR and state their public source.
