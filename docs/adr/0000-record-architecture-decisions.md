# ADR 0000: Record architecture decisions

- **Status:** Accepted
- **Date:** 2026-04-27
- **Related:** issue #816 (F-140)

## Context

The rustgate workspace is sixteen crates, eleven CI jobs, and a
growing set of cross-cutting conventions. Many of those conventions
were chosen for non-obvious reasons — a particular locking primitive
over the obvious alternative, one X.509 stack instead of another,
`std::sync::OnceLock` rather than `once_cell::sync::Lazy`. Until now
the rationale for those choices lived only in the commit messages
that introduced them, scattered across the git log and frequently
buried in PRs that merged unrelated work.

A new contributor opening the workspace had no single discoverable
place to learn *why* the codebase looks the way it does. The result
was either reinvention (someone reaches for the obvious option,
fights clippy or CI, and asks "why is this banned?") or quiet drift
(someone mirrors a pattern they saw without understanding the
rationale, then a future change breaks the unstated invariant).

`docs/` already carries long-form architectural documentation
(`architecture.md`, `concurrency-model.md`, `authorization.md`,
etc.), but those documents describe the system as it stands. They
are not the right place for "we considered X, picked Y, and here is
the trade-off we live with" framing.

## Decision

Architectural decisions are recorded in this `docs/adr/` directory
using the slim Michael Nygard format. Each ADR is a short markdown
file with a four-digit number prefix and a kebab-case slug. Every
ADR captures: status, context (the forces driving the decision),
the decision itself, the alternatives that were weighed, and the
consequences the project now lives with.

The format is intentionally lightweight. A decision worth writing
down is not a decision worth writing five pages about. The goal is
discoverability, not exhaustive documentation.

ADRs are immutable once accepted. If a decision is revisited, the
old ADR is marked **Superseded by ADR XXXX** and a new ADR is
written. This preserves the historical reasoning and lets a future
contributor see the decision lifecycle.

A `template.md` in this directory provides the canonical empty
form. The [`README.md`](README.md) lists every ADR with its status
and is the canonical entry point.

## Alternatives considered

- **Continue using commit messages alone.** Rejected: commit
  messages are not discoverable. A new contributor cannot grep the
  git log for "why parking_lot" — they would have to know the
  decision exists before they could find the rationale. ADRs put
  the rationale where someone looking for it can find it.
- **Put rationales in `docs/architecture.md`.** Rejected: the
  long-form docs describe the system as it currently stands.
  Mixing in rejected alternatives, supersession history, and
  trade-off analysis would dilute the reference value of those
  documents.
- **Use a heavier ADR format (full Nygard, MADR, etc.).** Rejected
  for the seed set: the workspace's decisions are mostly small
  ("which mutex", "which crate"), and a heavyweight template
  invites either bloat or skipping the ADR. The slim form is enough
  for the decisions we have. If a future decision needs more
  structure, the template can be extended.

## Consequences

- New non-obvious architectural decisions are expected to ship with
  an ADR. The `CONTRIBUTING.md` "new feature" checklist references
  this directory and the [`template.md`](template.md).
- The seed set in this PR (ADRs 0001–0010) covers decisions that
  already shipped without a written rationale. Future ADRs are
  added at the time of the decision, not retroactively.
- The index in [`README.md`](README.md) is the canonical list. CI
  does not validate that the index is in sync with the directory
  contents — keeping it current is on the author of each new ADR.
- ADRs do not replace the long-form docs in `docs/`. The two layers
  cooperate: an ADR captures *why* a choice was made; the long-form
  doc explains *how* the resulting system works.
- Markdown links between ADRs use relative paths
  (`[ADR 0001](0001-parking-lot-mutexes-for-sync-paths.md)`).
  Cross-links from outside `docs/adr/` use the full relative path
  from the repository root.
