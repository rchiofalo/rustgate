# ADR 0024: Fail-closed semantics for the cross-domain guard

- **Status:** Proposed
- **Date:** 2026-06-25
- **Deciders:** rchiofalo
- **Related:** #1495 (guard fail-open paths), ADR 0022 (cross-domain guard
  egress seam), `rustgate-core::classification`, `rustgate-core::audit_chain`

> **Review status — needs revision before implementation.** The problem
> statements below are verified against source, and the fail-closed direction
> is correct, but an adversarial review found that the H-1 fix as first drafted
> is an **availability regression** for real ATAK traffic. See
> [Required revisions](#required-revisions-from-adversarial-review) — items 1–4
> are prerequisites, not follow-ups.

## Context

`rustgate-guard` is the workspace's strictest fail-closed control (ADR 0022
wires it inline on `Router::route_for_egress`), yet two paths silently fail
**open**, both verified in source:

**H-1 — a present-but-unparseable marking is authorized.** The mandatory-marking
gate at `lib.rs:450` tests only `marking.is_none()` (presence, never
parseability). `extract_marking` returns `Some(raw)` for any `<marking
value="…"/>`. The dominance check `check_classification_authorized`
(`lib.rs:810`) parses via `ClassificationMarking::from_str` and on parse failure
executes an early `return None` (`lib.rs:816`) — where `None` means *authorize*.
Net effect: a malformed TopSecret banner passes the presence check, fails to
parse, and is **released across a `HighToLow` boundary** — exactly the case the
existing `guard_unauthorized_classification_rejected_for_high_to_low_direction`
test exists to prevent, bypassed by malforming the string.

**H-2 — the audit chain silently re-genesises.** `CrossDomainGuard::new`
(`lib.rs:385`) calls `read_chain_state(&path).unwrap_or_else(|_| (GENESIS_PREV, 1))`.
Any error — corruption, a torn tail past `REWIND_BUDGET`, a pre-`seq` log format,
an I/O fault — is swallowed and the tamper-evident chain is reset to genesis. An
attacker who can truncate/corrupt the log gets the chain silently restarted on
the next guard restart, destroying non-repudiation. The doc comment at
`lib.rs:380` claims the constructor *returns* `GuardError::Io` when chain state
cannot be read — the `unwrap_or_else` directly contradicts that contract.

**Constraints.** The audit-record JSON shape and `reason_token()` vocabulary are
a SIEM wire contract; `GuardDirection::as_audit` spellings are wire format; no
`unwrap`/`panic`/`unsafe` in prod; `ClassificationMarking` is the sole CAPCO
authority (no re-rolling the parser). `--authz-fail-open` is the house precedent
for "secure default, explicit operator opt-out."

## Decision

Make both paths fail **closed**: H-1 unconditionally, H-2 closed-by-default with
a narrow, audited opt-out mirroring `--authz-fail-open`. **No format-version
bump** — the audit-record schema and chain hashing are unchanged; only
construction-time and decision-time control flow change.

**H-1 — reject an unparseable marking** (no knob). Add
`GuardError::UnparseableMarking { marking, direction }` with a new stable
`reason_token()` `"unparseable_marking"` (distinct from
`"unauthorized_classification"` so SIEM can tell a malformed banner from a
known-too-high one). In `check_classification_authorized`, on parse `Err(_)`
return `Some(UnparseableMarking{…})` instead of `None`. The deny becomes
direction-independent — a marking the guard cannot understand is one it cannot
make a release *or* admission decision about. **Subject to the warm-up gate in
revision 1.**

**H-2 — fail closed on chain-load error, with an explicit opt-out.** Add
`audit_chain_fail_open: bool` to `GuardConfig` (`#[serde(default)]` → `false`,
kebab key `audit-chain-fail-open`). Rewrite `CrossDomainGuard::new` to `match`
on `read_chain_state`: on `Err` with the default (`false`), return a construction
error so `start_guard` fails and the server aborts before any traffic crosses
(matching the documented contract). With the opt-out (`true`), do **not** silently
re-genesis: write an explicit `boundary.chain_break` continuity record first
(carrying the unreadable-tip reason and prior on-disk size), emit a new
`audit::guard_chain_reset(path, reason)` event, then resume — **carrying the seq
forward** (revision 3), not resetting to 1.

**CLI:** add `--guard-audit-chain-fail-open` (env
`RUSTGATE_GUARD_AUDIT_CHAIN_FAIL_OPEN`, default false) for parity with
`--authz-fail-open`, with a startup warning when set; the TOML `[guard]` key is
the primary source of truth per ADR 0022.

## Alternatives considered

- **H-1: keep authorize-on-parse-failure (status quo).** Rejected — this *is*
  the vulnerability; a release path that cannot parse a banner has no basis to
  release.
- **H-1: degrade/sanitize the marking (strip → Unclassified).** Rejected —
  silently downgrading an unknown banner could release TopSecret content
  relabeled benign; the guard's contract is reject-or-pass-unchanged.
- **H-1: gate parseability behind `mandatory_marking` only.** Rejected — ties a
  classification-correctness invariant to a throughput/presence knob; a
  HighToLow release of a malformed banner is unsafe regardless of the flag.
- **H-2: hard-fail only, no opt-out.** Rejected as the *default* is correct but
  a benign cause (pre-`seq` log, torn tail after unclean shutdown) would brick
  every legitimate egress on restart with no escape hatch.
- **H-2: silently open a fresh file with a `.2` suffix.** Rejected — still a
  silent discontinuity; the in-band `boundary.chain_break` record is greppable
  in the one file the SIEM already tails.
- **One combined `--guard-fail-open` for both.** Rejected — conflates unrelated
  risk surfaces; H-1 must never be opt-out-able, H-2 legitimately can be.

## Consequences

Safer: a malformed banner can no longer ride a TopSecret payload across a
HighToLow boundary; a corrupted chain can no longer be silently restarted; the
constructor's doc contract finally matches its code. SIEM gains two
distinguishable signals (`unparseable_marking`, `boundary.chain_break` /
`guard_chain_reset`).

New burden / behavior change: operators whose traffic currently relies
(perhaps unknowingly) on malformed markings passing will see denies — the
intended correction, but a behavior change (see revision 1). A guard pointed at
an unreadable audit log now **fails to start** by default; `audit-chain-fail-open`
is the documented escape hatch. The new reason token and event type are a
**coordinated-release dependency** for any SIEM that validates against a closed
reason/event allowlist (additive for grep-based rules).

Back-compat: no format bump; the new config field defaults fail-closed so
existing `[guard]` TOML parses unchanged and healthy chains resume identically.
Fully reversible (additive variant + flag).

## Required revisions (from adversarial review)

The review verdict was **needs_revision**. These are prerequisites:

1. **H-1 parser-tolerance + log-only warm-up (blast-radius).** The CAPCO parser
   (`classification.rs:462`) *requires* a leading `//` and rejects any token
   outside the four levels. Externally-sourced CoT routinely carries bare
   markings (`value="UNCLASSIFIED"`, vendor caveats) that **today parse-fail →
   authorize**. A straight flip-to-deny drops benign LowToHigh admission traffic
   the instant the guard is enabled, fleet-wide (the guard is a single global
   chokepoint with no per-sink canary). Required: (a) extend
   `rustgate-core::classification` to accept the bare-level forms actually
   received (or a normalization shim) so only *truly* garbage is unparseable;
   (b) ship a **log-only mode** that emits the would-be deny as a WARN audit
   event without dropping, so operators see exactly which production markings
   would start being denied *before* enforcement.
2. **Close the malformed-ENVELOPE bypass, not just malformed-VALUE.**
   `extract_marking` returns `None` on an XML *read error* too — so on a
   permissive (`mandatory_marking=false`) HighToLow deployment, corrupting the
   XML *structure* yields `None` and skips the dominance check entirely. On a
   HighToLow direction with XML-intent payloads that fail to parse, treat as
   deny (cannot-inspect == cannot-release).
3. **H-2 opt-out must CARRY SEQ FORWARD, not reset to 1.** Resuming from
   `GENESIS_PREV` with `next_seq=1` recreates exactly the cross-segment seq
   collision `read_chain_state` was built to refuse. Recover the best-known
   prior max seq (record it in the `boundary.chain_break` marker) and set the
   resumed writer's `next_seq = prior_max + 1`; only the prev-hash link restarts.
   Teach `verify_audit_log` to recognize `boundary.chain_break` as a sanctioned
   hash-seam so it does not flag the genesis-linked record as tampering.
4. **Fix construction control-flow + error-type collisions.** Thread one
   append-mode file handle through both the marker write and `HashChainWriter`
   construction (don't open twice). Resolve the `From<io::Error>` ambiguity:
   either drop the existing `GuardError::Io #[from]` or make the new
   construction-error variant non-`#[from]`.

Also: `validate()` must reject two guard instances configured against the same
audit-log path (would interleave two restarted seq series into one file).

## Test plan

H-1: malformed banner → `UnparseableMarking` for **both** directions, `reason
== "unparseable_marking"`, one `decision="deny"` audit record; a well-formed
TopSecret HighToLow still yields `UnauthorizedClassification` (tokens stay
distinct); a bare `value="UNCLASSIFIED"` exercises the warm-up/tolerance path
(revision 1); empty `value=""` covered. H-2: corrupt the tail → default
construction **refuses** (no fresh genesis written); opt-in → `boundary.chain_break`
is the first new record, **seq continues** (revision 3 assertion — the single
most important test), `verify_audit_log` accepts the seam, `guard_chain_reset`
emitted; healthy chains resume identically (existing test stays green). Config:
`audit_chain_fail_open` defaults false and round-trips. Integration: guard with
an unreadable audit path fails server startup by default; with the flag, starts
+ warns. Run `cargo hack` feature-powerset (reason tokens feed metric labels).

## Open questions

- Confirm no production deployment carries vendor-extension markings the CAPCO
  parser legitimately can't parse (those need a parser extension, not a guard
  opt-out).
- SIEM owner sign-off on the new reason token + event type before release.
- Is the CLI flag wanted, or does the TOML `[guard]` key alone suffice (ADR 0022
  prefers the single block)?
