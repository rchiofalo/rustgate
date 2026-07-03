# §8 semantic-pass verification — classification handling

- **Status:** Verified (Q1/Q3/Q4 closed as sound); Q2 **DEFERRED** open decision
- **Date:** 2026-07-03
- **Issue:** #1563
- **Source:** `audit/RUSTGATE-ANALYSIS.md` §8 "Open architectural questions"

## Purpose

Issue #1563 raised four **lower-confidence** architectural questions from
the June 2026 semantic audit's §8. These were flagged as *questions, not
findings* — the reviewer who raised them also filed a claim that was later
disproved, so each needed a focused verification pass against current code
before any fix. This note records the code-evidence verdict for each, with
exact `file:line` anchors a reviewer can open.

Three of the four (Q1, Q3, Q4) are confirmed **sound by design** — no code
change is warranted. The fourth (Q2) is a **real gap**, but the fix is a
genuine design fork with a live fleet-safety hazard, so it is recorded here
as an explicitly **DEFERRED** open decision pending owner input rather than
acted on. No production code changes accompany this note.

## Q1 — Guard opt-in posture: **SOUND (by design)**

**Question.** Is the cross-domain guard opt-in (`--guard-config`), and what
is classification enforcement when it is off?

**Verdict.** The guard is intentionally opt-in and this is correct layering,
not a gap. `start_guard` (`crates/rustgate-server/src/guard.rs:79-82`)
returns `Ok(())` and installs nothing when `--guard-config` is unset:

```rust
let Some(path) = cli.integrations.guard_config_file.as_ref() else {
    return Ok(());
};
```

The guard is a *cross-domain egress* control layered **on top of** the
always-on authorization PEPs (send/receive) and the `MaskPoint` /
obligation machinery in the router. When the guard is off, classification
enforcement is still performed by:

- the authz Send/Receive PEPs
  (`authz_evaluate_{send,receive}_with_classification`,
  `crates/rustgate-router/src/router.rs:1739-1770`), which forward
  `Metadata.classification` into the Cedar/authz `AuthzContext`; and
- the optional `--require-classification-marking` admission gate
  (`crates/rustgate-router/src/router.rs:3238`), which fails closed on a
  missing marking when the operator enables it.

The guard adds a *further* mandatory-marking / throughput / marking-based
release check for cross-domain deployments; making it mandatory globally
would break single-domain deployments that never cross a boundary. **No
change.**

## Q2 — Ingress classification extraction: **REAL GAP — DEFERRED (owner decision required)**

**Question.** Does tactical UDP/TCP ingress extract protocol-native
classification (STANAG/ASTERIX codewords) into `Metadata.classification`,
or is ingested tactical data routed as *unclassified*?

**Verdict — the gap is real.** Tactical codec ingress builds its
`RoutableMessage` with `Metadata::new(...)`
(`crates/rustgate-transport/src/codec_ingress.rs:326`), and `Metadata::new`
defaults `classification` to `None`
(`crates/rustgate-core/src/message.rs:154`). The ingress path never calls
`with_classification`, so **every message ingested through a tactical codec
carries `classification: None`** regardless of any protocol-native marking
on the wire.

**Downstream consequence.** Because the marking is `None`, the authz PEPs
build an empty classification context —
`authz_evaluate_{send,receive}_with_classification`
(`crates/rustgate-router/src/router.rs:1746-1748` and `1766-1768`) take the
`None => AuthzContext::default()` arm. A classification-gated authz rule
(e.g. a Cedar policy that denies a recipient below the message's clearance)
therefore **cannot fire on tactical-ingested data** — the context it would
key on is empty.

**What is *not* affected.** The cross-domain guard is unaffected by this
gap: it extracts markings from the **payload bytes**, not from
`Metadata.classification`. See `extract_marking(&payload)`
(`crates/rustgate-guard/src/lib.rs:459`, helper at `:749`). So a guarded
cross-domain deployment still enforces payload-embedded markings even
though `Metadata.classification` is empty. The gap is specifically in the
*authz PEP* classification context, not in the guard.

**Why this is not a quick fix — the codeword may not be on the wire.** A
grep of the tactical codec entity/PDU types found **no security-codeword
field** to extract. The nearest field, DIS `marking`
(`crates/rustgate-dis/src/codec.rs:131-134`, `:461-482`), is an
entity **callsign/label**, not a CAPCO-style classification codeword.
STANAG 4586 and ASTERIX likewise do not currently surface a codeword to the
codec. So an extraction PR may be partly non-actionable until the actual
message profiles in scope are confirmed to carry a derivable marking.

**Why a naive fix is actively harmful.** The obvious "reject
marking-less tactical data" fix would drop benign tactical traffic
fleet-wide the moment it is deployed. This is the exact hazard that #1495
records (a naive reject-on-missing-marking rule dropping benign
bare-marking traffic across the fleet). Any Q2 code slice **must not
fail-closed** on marking-less tactical traffic; it needs a log-only warm-up
period first, per the #1495 precedent.

### DEFERRED design fork (owner input required before any code)

This is a genuine design fork with no recorded owner decision. The owner
has **explicitly deferred** it. Before any classification-extraction code
is written on the tactical ingress path, the owner must decide:

1. **Should tactical codec ingress (DIS / ASTERIX / STANAG 4586 / SAPIENT /
   LINK16 / NFFI) extract protocol-native classification into
   `Metadata.classification` at all** — and is the codeword actually
   present in the message profiles that will be ingested? (Grep says the
   current codec types do not surface one.)
2. **On a marking-less tactical message, should ingress fail-OPEN** (route
   as today, `classification: None`) **or fail-CLOSED** (reject)? Given the
   #1495 precedent, the recommendation is fail-open with a **log-only
   warm-up period**, never a hard reject.
3. **Should the classification source-of-truth be unified** between the
   guard (reads payload bytes today) and the authz PEP (reads
   `Metadata.classification`)? They can currently disagree.

**Until the owner answers, no classification-extraction code is added to
the tactical codecs.** The seam a future PR would wire into is the
`RoutableMessage` construction at `codec_ingress.rs:326`; a foundational,
no-behavior-change hook there (an ingress trait returning
`Option<ClassificationMarking>`, default `None`) is a candidate first
slice — but that too is deferred to this decision.

## Q3 — Position-cache replay clearance: **SOUND**

**Question.** Does position-cache replay re-evaluate classification against
the *late-joining* recipient's clearance?

**Verdict.** Yes. `Router::replay_positions`
(`crates/rustgate-router/src/router.rs:3968`) clones the cached message's
marking and forwards it through **both** PEP evaluations against the
late-joining recipient's subject:

```rust
let classification = msg.metadata.classification.clone();
// send PEP …
let recv_outcome = self.authz_evaluate_receive_with_classification(
    engine,
    &recipient_subject,               // the late-joining recipient
    &resource,
    classification.as_ref(),
);
```

(`crates/rustgate-router/src/router.rs:4046-4085`.) A policy tightened
*after* the position was cached takes effect on replay — a recipient no
longer cleared for the cached marking is denied, and stale coordinates are
not leaked. The send PEP is evaluated first, so a sender that lost its
send authorization also stops replaying. **No change.**

## Q4 — Egress envelope uniformity: **SOUND (SEC-18 / #1545 already closed)**

**Question.** Do all egress sinks (NATS / HTTP / MQTT / federation) route
through `prepare_egress_envelope`, or only multicast — i.e. can obligation
sets diverge per sink?

**Verdict.** Every egress sink renders its envelope through the single
`Router::prepare_egress_envelope_for_sink` entry point with its own
`RecipientClass`, so obligation sets cannot diverge per sink. Confirmed
call sites:

- NATS — `crates/rustgate-nats/src/subscriber.rs:603,611,624`
- MQTT — `crates/rustgate-mqtt/src/session.rs:1143,1151,1164`
- WebSocket — `crates/rustgate-websocket/src/server.rs:563,571,584`
- Direct/session sinks — `crates/rustgate-server/src/session.rs:618-646,1119-1144`
- Federation inbound fan-out — `crates/rustgate-server/src/setup.rs:1891-1905`

The related leak, SEC-18 / #1545 (`MaskPoint` silently forwarding intact
coordinates for non-CoT/non-MAVLink position protocols), is **already
closed** — the non-XML branch now fails closed (see `CHANGELOG.md` SEC-18
entry and [ADR 0027](../adr/0027-maskpoint-fail-closed.md)). **No change.**

## Summary

| # | Question | Verdict | Action |
|---|----------|---------|--------|
| Q1 | Guard opt-in posture | SOUND (by design) | none |
| Q2 | Ingress classification extraction | REAL GAP | **DEFERRED** — owner decision required (fork above) |
| Q3 | Position-cache replay clearance | SOUND | none |
| Q4 | Egress envelope uniformity | SOUND (SEC-18 closed) | none |

Overall §8 premise: **PARTIAL** — three questions refuted as concerns, one
(Q2) confirmed as a real gap whose fix is an owner-deferred design fork,
not a code change delivered here.
