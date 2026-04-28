# ADR XXXX: <decision title>

- **Status:** Proposed
- **Date:** YYYY-MM-DD
- **Deciders:** <names or roles>
- **Related:** <issue or PR numbers, related ADRs>

## Context

What forces the decision? What is the problem we are solving, and
what is the current state of the codebase that makes this decision
necessary now? Two or three short paragraphs is enough.

If there are constraints from outside the workspace — an upstream
crate decision, a regulatory requirement, an interop contract — say
so explicitly. The reader should understand what is non-negotiable
versus what is being chosen between.

## Decision

State the decision in one or two sentences, then expand. Be concrete
about *what* the codebase will do — file paths, type names,
configuration knobs — not just the abstract principle. A new
contributor reading the ADR should be able to find the load-bearing
code from the decision text.

## Alternatives considered

Each alternative gets a one-line summary, then a short paragraph on
why it was rejected. Honest trade-off analysis here matters more
than length: if the rejected option still has merit, say so, and
say what would have to change for the decision to be revisited.

- **Alternative A** — short summary. Why rejected.
- **Alternative B** — short summary. Why rejected.

## Consequences

What does the codebase look like once the decision is in force? What
new constraints does this place on future work? What is now harder,
and what is now easier? If the decision creates a maintenance burden
(a custom helper to keep in sync with upstream, a lint that has to
be enforced manually), name it.

If the decision is reversible, describe the migration path. If it is
not, say so plainly so future contributors understand the cost of
revisiting.
