# Authorization (RBAC / ABAC)

rustgate ships a per-message authorization engine in the `rustgate-authz`
crate. It is evaluated on every routed message at the router Policy
Enforcement Point (PEP) and is designed for sub-microsecond decisions on
the dataplane hot path. This document covers the concept, the native
JSON policy format, migration from the legacy `--group-acl-file`, and
the optional Cedar backend.

## Concepts

- **Deny-by-default**: when no rule matches, the engine returns `Deny`.
  `default_effect: "allow"` is available but not recommended — operators
  opting into open mode take on the full responsibility of auditing
  their rules.
- **Rule order matters**: within a given `(action, resource kind)`
  bucket the first matching rule wins. Explicit `deny` rules short-circuit
  the scan, so the authoring idiom "explicit deny before broad allow"
  works as written.
- **Per-evaluation allocation-free**: subjects and resources are
  borrowed views into caller-owned data. The decision cache is a
  sharded, fixed-capacity FIFO-eviction table keyed on a 128-bit
  `SubjectHash` (a pair of independently-seeded ahash outputs), a
  per-call resource hash, the action, and the compiled policy epoch.
  Swapping a policy bumps the epoch so stale entries are never looked
  up. Repeated evaluations of the same tuple complete in tens of
  nanoseconds.
- **Fail-closed reload**: hot-reloads run the full parse + compile
  pipeline before swapping the engine. A bad edit never interrupts
  enforcement — the previous policy continues to serve.

## The RuleSet JSON format

A policy is a JSON document:

```json
{
  "version": 1,
  "default_effect": "deny",
  "rules": [
    {
      "id": "allow-alpha-to-bravo-direct",
      "effect": "allow",
      "action": "send",
      "subject": { "cn_eq": "alpha" },
      "resource": { "kind": "direct", "target_cn": "bravo" }
    },
    {
      "id": "deny-test-group-broadcast",
      "effect": "deny",
      "action": "send",
      "subject": { "groups_any_of": ["test"] },
      "resource": { "kind": "broadcast" }
    }
  ]
}
```

> **Note:** Only the `send` and `receive` actions reach the data-plane PEPs
> today. Rules whose `action` is `federate`, `publish`, or `subscribe` —
> and rules whose resource kind is `federation` or `nats_subject` — parse
> and compile, but no production call site evaluates them. They are
> reserved syntax for a future Phase 2 that wires federation/NATS egress
> through its own PEPs. Authoring such a rule today has no runtime
> effect.

### Top-level fields

| Field | Type | Description |
|---|---|---|
| `version` | integer | Currently `1`. Parser rejects any other value. |
| `default_effect` | string | `"deny"` (default) or `"allow"`. |
| `rules` | array | Ordered list of [`Rule`](#rule). |

### Rule

| Field | Type | Description |
|---|---|---|
| `id` | string | Stable identifier. Must be non-empty and unique across the set. Appears in decision outcomes and audit records. |
| `effect` | string | `"allow"` or `"deny"`. |
| `action` | string | One of `send`, `receive`, `federate`, `publish`, `subscribe`. Only `send` and `receive` are wired to data-plane PEPs today — see the note under [Actions](#actions). |
| `subject` | object | See [`SubjectMatcher`](#subjectmatcher). An empty object matches every subject. |
| `resource` | object | See [`ResourceMatcher`](#resourcematcher). |
| `obligations` | array | Optional side-effects to apply on allow outcomes. |

### SubjectMatcher

All populated fields are AND-combined.

| Field | Type | Meaning |
|---|---|---|
| `cn_eq` | string | Subject CN must equal this exactly. |
| `groups_any_of` | array of strings | Subject must be in at least one listed group. |
| `groups_all_of` | array of strings | Subject must be in every listed group. |
| `spiffe_prefix` | string | Subject SPIFFE ID (from a URI SAN) must start with this literal prefix. |
| `attribute_eq` | object | Each key must match the subject's attribute of the same key. Supported JSON value types are string, integer, bool, and array-of-strings (subset check against an attribute set). |

### ResourceMatcher

Tagged by `"kind"`:

| Kind | Extra fields | Meaning |
|---|---|---|
| `direct` | `target_cn` (optional) | Unicast send to the CN. `null`/omitted matches any target. |
| `group` | `group` | Group-scoped send. |
| `broadcast` | — | Broadcast to all connected peers. |
| `federation` | `peer_id` (optional) | **Not yet evaluated at runtime.** Reserved for a future federation PEP — see the note under [Actions](#actions). |
| `nats_subject` | `subject_pattern` | **Not yet evaluated at runtime.** Reserved for a future NATS publish/subscribe PEP — see the note under [Actions](#actions). |
| `any` | — | Matches any resource kind. Useful for broad deny rules. |

### Actions

| Action | Status | When it fires |
|---|---|---|
| `send` | **Active** | Client-originated unicast, group, or broadcast dispatch — evaluated at the router Send PEP before fanout and on every store-forward drain / SA replay. |
| `receive` | **Active** | Router delivery path toward a specific subscriber — evaluated at the router Receive PEP on every per-recipient try_send. |
| `federate` | *Reserved* | Intended for federation peer forwarding. No production call site evaluates this action today. Federation egress currently uses the same post-`send`-PEP payload that local sessions receive (via [`Router::route_for_egress`](../crates/rustgate-transport/src/router.rs)); a first-class federation PEP is Phase 2 work. |
| `publish` | *Reserved* | Intended for NATS publish. No production call site evaluates this action today. NATS egress currently uses the same post-`send`-PEP payload. |
| `subscribe` | *Reserved* | Intended for NATS subscribe. Not evaluated today. |

Rules whose `action` is `federate`, `publish`, or `subscribe` parse and
compile without error, but are never matched by a data-plane decision.
They do not produce `authz_denied` or `authz_allowed` records. Until the
corresponding PEPs land, the only enforcement point for egress to
external sinks is the `send`-action PEP at the router — authors should
express egress-scoped restrictions there.

### Obligations

Obligations are carried on allow outcomes for the dataplane to apply
alongside delivery. The router actuates them at every Policy Enforcement
Point (PEP) — Send-side before fan-out, Receive-side per recipient —
and also re-evaluates on store-forward drain and SA position replay so
a policy change never leaves a stale copy loose in an offline queue or
replay cache.

| Obligation | Effect |
|---|---|
| `mask_point` | CoT `<point>` coordinates (`lat`, `lon`, `hae`) are zeroed via `rustgate_cot::mask::strip_coordinates`. Only the `<point>` element is touched (case-insensitive, namespace-tolerant — `<POINT>`, `<cot:point>` are matched). Recovery rules: non-XML payloads forward unmodified with `recovery = "forwarded_unmasked"` in the audit trail; XML-intent payloads that fail parsing or trip the attribute budget are erased (`recovery = "dropped"`) — a crafted sender cannot leak coordinates by aborting the document after `<point>` was already copied. |
| `mask_payload` | Payload body replaced with empty `Bytes`; classified message type coerced to `other:masked`. Envelope fields (source identity, destination, timestamps) are preserved so downstream UIs can render a placeholder. |
| `tag_classified` | Audit-only. Emits `audit.classified_delivery` at the Receive PEP with subject/recipient CNs, resource kind/id, rule id, and policy id. Wire payload is unchanged. |
| `audit_extended` | Audit-only. Reserved for future expanded audit records; no dataplane side effect today. |

Obligations compose across the routing pipeline in a specific order:

1. **Send PEP (router ingress).** The engine evaluates the `send` action
   once per message against the sender's identity and the destination
   resource. On allow, any data-plane obligations (`MaskPoint`,
   `MaskPayload`) are applied in place to the owned envelope *after* the
   SA position cache has stored the pre-obligation form — so replay to
   late joiners re-evaluates the current policy rather than replaying a
   cached mutation from whatever policy was active at ingest time. The
   mutated envelope is then wrapped in `Arc` for local fan-out.
2. **Egress forwarding (NATS / federation / HTTP).** The `Arc` returned
   by [`Router::route_for_egress`](../crates/rustgate-transport/src/router.rs)
   is the exact post-Send-PEP form that local sessions received, so
   external sinks see the same mutated payload — a `MaskPoint`
   obligation zeroes coordinates for SIEM collectors and federation
   peers as well as in-process recipients.
3. **Receive PEP (per-recipient).** On each per-session `try_send`, the
   Receive PEP runs against the recipient's identity. `TagClassified` /
   `AuditExtended` are audit-shaped and do not mutate the payload;
   `MaskPoint` / `MaskPayload` from the Receive PEP stack on top of any
   Send-side mutation by cloning the shared `Arc` and re-applying (see
   [`RoutedMessage::with_obligations`](../crates/rustgate-transport/src/router.rs)).
4. **Re-evaluation paths.** Store-forward drain, SA position replay, and
   any other offline-redelivery path re-run both PEPs against the
   *current* policy so stored messages never bypass a tightening policy
   change.

`MaskPayload` supersedes `MaskPoint` because it replaces the payload
entirely — either ordering produces the same final (empty) body.

**Multicast caveat.** A `Destination::Multicast` message does not run a
top-level Send PEP — the PEP runs per-group inside
`send_to_group_excluding`. External egress of a multicast message
therefore carries the pre-obligation payload; closing that gap requires
the Phase 2 `federate` / `publish` PEPs referenced in the [Actions](#actions)
table.

#### Audit events emitted by the obligation dispatcher

| Event | When | Fields |
|---|---|---|
| `authz.classified_delivery` | `TagClassified` fires **after** a successful `try_send` on the Receive PEP. Never emitted from the persistence path — a backpressure drop does not produce a phantom delivery record. | `subject_cn`, `recipient_cn`, `action`, `resource_kind`, `resource_id`, `rule_id`, `policy_id`, `result = "tagged"` |
| `authz.obligation_failed` | `MaskPoint` failed to mask the payload. The dispatcher chose a recovery (`"dropped"` for XML-intent parse failure / attribute-budget trip, `"forwarded_unmasked"` for non-XML payloads where no `<point>` could exist). | `subject_cn`, `obligation`, `error`, `recovery`, `source_protocol`, `destination_kind`, `action = "actuate_obligation"`, `result = "failure"` |
| `authz.obligation_unknown` | The authz engine emitted an `Obligation` variant unknown to this transport build. The `Obligation` enum is `#[non_exhaustive]`; this event surfaces transport↔authz version skew on operators' dashboards. | `subject_cn`, `obligation` (Debug-formatted variant), `source_protocol`, `destination_kind`, `action = "actuate_obligation"`, `result = "skipped"` |

All three events use `target = "audit"` and are hash-chained when the
audit log writer is configured for tamper evidence
(`rustgate_core::audit_chain::HashChainWriter`). `destination_kind` is
one of `"direct"`, `"group"`, `"broadcast"`, `"multicast"` — stable
across releases for SIEM rules. `subject_cn` is recorded in plaintext
by design: the classified-delivery audit is the forensic trail that
ties a specific user to a specific artefact. See the doc comment on
`rustgate_core::audit::authz_classified_delivery` for the full PII
policy rationale.

#### Per-recipient delivery audit (`--audit-delivery`)

For deployments that need a **per-recipient chain-of-custody trail**
(every classified message has a record naming exactly which CN
received it and exactly when), set `--audit-delivery` /
`RUSTGATE_AUDIT_DELIVERY=true` (default off). When enabled, the router
emits one of two events for every recipient on every routed message:

| Event | When | Fields |
|---|---|---|
| `message.delivered` | A per-recipient `try_send` succeeded — the message has been enqueued on the recipient's session channel and will be flushed to the wire by the writer task. Fires AFTER the `authz.classified_delivery` audit when both apply, so a SIEM can correlate the obligation with its delivery. | `source` (sender CN), `dest` (recipient CN), `uid` (CoT `uid="…"` attribute or empty), `msg_type` (the `MessageType::Display` form: `position`, `chat`, `alert`, etc.), `group` (the destination group name on group / multicast fan-out, or the small fixed-vocabulary tag `direct` / `broadcast` for non-group destinations), `action = "deliver"`, `result = "success"` |
| `message.dropped` | A per-recipient `try_send` failed (channel full or closed → `reason = "backpressure"`) OR no live session existed for the recipient and store-and-forward was unavailable (`reason = "no_subscribers"`). Other reason tokens — `acl_denied`, `authz_denied`, `obligation_failed` — are emitted by the existing `authz.*` audit family at a higher level and are NOT duplicated by this event. | `source`, `dest`, `uid`, `reason`, `action = "deliver"`, `result = "dropped"` |

**Volume implications.** Per-recipient audit is high-volume by design.
A single broadcast to 100 subscribers produces 100 audit records, and a
multicast across 5 groups of 50 subscribers each produces 250 records.
On a busy tactical link this can dominate the audit-log byte budget —
which is why the flag defaults to off. Operators who turn it on should
also size `--audit-log` storage and rotation cadence to absorb the
expected fan-out (a rough estimate: average broadcast subscribers ×
broadcasts per second × ~250 bytes per JSON line). The hash-chain tip
sequence (`tip_seq`, see #883) advances correspondingly, so a seq-gap
verifier sees one increment per recipient.

**PII discipline.** Per #1207 / #1221, the audit-log uses **raw CNs**
for `source` and `dest` because the audit is a forensic chain of
custody — the operator who later queries the log to answer "which
classified events did `bob.smith` receive on date X" must be able to
filter by raw CN. The lower-cardinality access-log (target=`access`)
continues to use `hash_cn` for operator dashboards. Every `&str` field
is sanitized at the audit boundary by
`rustgate_core::sanitize::sanitize_for_log` so an attacker-controlled
CN with embedded CR/LF cannot log-forge a fake delivery record.

**Performance.** When `--audit-delivery` is unset (the default), the
per-recipient cost on the routing hot path is exactly one
`ArcSwap::load` plus one `is_none()` check — a few nanoseconds per
recipient with no allocation. When the flag is set, each recipient
pays the cost of one bounded scan over the payload prefix to extract
the CoT `uid` and one heap allocation for the `MessageType::Display`
string before the audit emission.

**Where it fires.** All four destination paths emit:

- `Destination::Direct` — fires on `try_send` success or backpressure;
  also fires `message.dropped { reason = "no_subscribers" }` when the
  destination CN has no live session (the router may still persist via
  store-and-forward; the drop is recorded against the live attempt
  regardless).
- `Destination::Group` — fires once per group member per pass through
  `send_to_group`, after per-recipient ACL and Receive-PEP filtering.
- `Destination::Broadcast` — fires once per connected session (excluding
  the sender) after Receive-PEP and obligation actuation.
- `Destination::Multicast` — fires once per group member per group in
  the multicast list, deduplicated against recipients already reached
  by an earlier group in the same fan-out (per the `delivered` set in
  `send_to_multicast`).

**SIEM correlation patterns.**

- *"Did recipient X actually receive this classified message?"* — join
  on `uid` between the `authz.classified_delivery` event and the
  `message.delivered` event. The two events are emitted in that order
  on the success path; a `classified_delivery` without a matching
  `delivered` indicates an unobserved drop (rare — the dispatcher
  emits `classified_delivery` only after a successful `try_send`).
- *"Which recipients lost messages this hour?"* — query
  `event_type = "message.dropped"` filtered to `reason in
  ["backpressure", "no_subscribers"]`. The other reasons
  (`acl_denied`, `authz_denied`, `obligation_failed`) appear only via
  the `authz.*` family and the `rustgate_router_dropped_total{reason}`
  metric.

### Metadata residue: what the maskers do NOT scrub

`MaskPoint` and `MaskPayload` are payload-body mutations. The surrounding
envelope and non-`<point>` XML regions are passed through untouched.
Policy authors should treat the following as leak vectors when modelling
a classification boundary:

- **`msg.source.groups`, `msg.source.attributes`, `msg.source.tenant`** —
  the sender's identity and group memberships ride with every delivered
  copy. A recipient who should not learn that "a member of `team-alpha`
  was broadcasting" cannot be shielded with masking alone.
- **`msg.destination`** — a `Destination::Direct(target)` still discloses
  the intended recipient CN to any Receive-side handler that observes the
  envelope, even if the payload is masked.
- **`msg.metadata.received_at`, `msg.metadata.source_protocol`,
  `msg.metadata.ttl`** — forensic envelope fields are preserved for
  audit. Timing correlation across a classified broadcast remains
  possible.
- **`<detail>` children, event `uid`, event `type`** under `MaskPoint` —
  only the `<point>` element is scrubbed. A free-form geographic
  reference inside `<detail><remarks>` or a callsign embedded in
  `<__group name="...">` is NOT masked. For payloads where any
  byte of the body is sensitive, use `MaskPayload`.
- **`msg.metadata.message_type`** — under `MaskPayload` this is coerced
  to `other:masked`, but under `MaskPoint` the original type (Position,
  Alert, etc.) is preserved and discloses the event category.

When a policy requires stronger redaction than either masker provides,
the correct tool is an explicit `Deny` rule — the dispatcher does not
attempt to sanitize metadata.

## Subject attributes

The PEP derives the [`Subject`](../crates/rustgate-authz/src/model.rs)
directly from the authenticated mTLS identity:

| Field | Source |
|---|---|
| `cn` | Certificate CN. |
| `groups` | OU fields on the subject DN. |
| `spiffe_id` | URI SAN matching `spiffe://...`, if present. |
| `attributes` | Attribute bag populated from additional SAN types and subject fields. |
| `fingerprint` | SHA-256 of the leaf certificate. |

The attribute bag is a typed map (`AttrValue::{Str,Int,Bool,Set}`) so
policies can reason over arbitrary enrollment-time metadata without
forcing everything into group strings.

## Migration from `--group-acl-file`

The legacy `--group-acl-file` flag continues to work unchanged. It uses
a separate, coarser rules model at the router send/receive gate, and it
does **not** see subject attributes or NATS/federation actions. The
recommended migration path is incremental:

1. Start with the existing group ACL still configured.
2. Add an authz policy via `--authz-policy-file` that mirrors the
   group ACL as explicit allow rules on `send` and `receive` actions,
   plus an overall `default_effect: "deny"`.
3. Verify via the `rustgate_authz_decisions_total{decision="deny"}`
   metric and the audit log that no legitimate traffic is being denied.
4. Remove the `--group-acl-file` flag once the authz policy is known to
   be correct.

The two layers can coexist indefinitely: both must allow a message for
it to be delivered.

## Hot-reload

With `--authz-policy-file` set, a background task polls the file every
`--authz-reload-interval` seconds (default 5). A SHA-256 digest skips
unchanged files cheaply. On a change, the new policy is parsed, compiled,
and validated on a worker thread, and only swapped onto the router if
every step succeeds. A failed reload keeps the previous engine serving
and emits an `authz.reload_failed` audit event identifying the failing
stage (`read`, `parse`, or `compile`).

## Reload semantics

The hot-reload path is non-blocking and lock-free on the dataplane hot
path. Achieving that property — sub-microsecond PEP latency under
arbitrary reload pressure — requires accepting an explicit
**eventual-consistency** window between the Send PEP and the Receive
PEP. Operators authoring policy migrations need to understand the
window so they can plan around it.

This section is the load-bearing reference for issue
[#805](https://github.com/rchiofalo/rustgate/issues/805) and the
IMPROVEMENT-ANALYSIS.md F-14 finding.

### The `ArcSwap` architecture

The router holds the policy engine inside an
`arc_swap::ArcSwap<Option<Arc<dyn PolicyEngine>>>` (see
[`Router::authz`](../crates/rustgate-transport/src/router.rs)). Reads
and writes do not contend:

- **Readers** call `self.authz.load()` and observe whichever engine
  was installed at the moment of that call. Each PEP site owns its own
  guard; guards are cheap to acquire and short-lived.
- **Writers** — `Router::swap_authz` (SIGHUP / file-watcher) and
  `Router::clear_authz` — call `self.authz.store(Arc::new(...))` once
  and return immediately. The previous engine `Arc` lives until the
  last outstanding reader guard drops.

There is no read-write lock. Readers do not block writers; writers do
not block readers. Two PEP evaluations on the same message arriving
either side of a `store` will observe two different engines. That is
the entire surface of the eventual-consistency window — everything
below is consequences.

### The window in concrete terms

Consider a single message with one direct recipient. The dispatch path
runs two PEP evaluations: Send PEP in `route_inner`, Receive PEP in
`send_to_session`. They each call `self.authz.load()` independently:

```text
t0   route_inner:        guard0 = self.authz.load()      -> policy vN
t1   Send PEP @ vN:      Allow (obligations from vN)
t2   apply_obligations:  payload mutated per vN
t3   <SIGHUP — store(vN+1) — guard0 still holds vN>
t4   send_to_session:    guard1 = self.authz.load()      -> policy vN+1
t5   Receive PEP @ vN+1: Allow / Deny / Allow-with-different-obligations
t6   try_send / drop
```

For broadcast and group fan-out the same message produces N
independent Receive PEP evaluations, each with its own `.load()` call
in `send_to_all` / `send_to_group`. The router does cache the
broadcast/group authz guard once for the per-recipient loop
(`send_to_all` snapshots `authz` outside the loop), but a multi-group
multicast message acquires a fresh guard per group inside
`send_to_group_excluding`. Across all those guards a SIGHUP can land
between any two and split the dispatch decisions across two policy
versions.

The **window length** is bounded by message dispatch time:

- Common case: tens of microseconds (Send PEP → all Receive PEPs land
  within one async tick).
- Tail: milliseconds when a recipient channel is near-full and the
  router has yielded between fan-out iterations.
- Pathological: bounded only by per-session backpressure timing.
  Once a delivery enters the persistence path
  (`persist_for_offline`), the next PEP evaluation runs at drain
  time, which can be seconds, minutes, or longer after the original
  Send PEP. The drain path is *not* part of the reload window — it
  intentionally re-evaluates against current policy on every drain
  tick (see [Hot-reload and store-and-forward](#hot-reload-and-store-and-forward)
  below).

### Compound effect on obligations

rustgate **does not snapshot the obligation set at Send time and carry
it through to Receive**. Each PEP site re-evaluates the engine
freshly:

- The Send PEP computes its own `outcome.obligations` against the
  guard loaded in `route_inner`. Send-side obligations
  (`MaskPoint`, `MaskPayload`) are applied to the owned envelope
  **before** fan-out, so all recipients in the same dispatch see the
  Send-side mutation regardless of what their per-recipient PEP
  decides.
- The Receive PEP computes its own `outcome.obligations` against the
  guard loaded in `send_to_session` / `send_to_group` /
  `send_to_all`, then stacks Receive-side obligations on top of the
  Send-mutated envelope via
  [`RoutedMessage::with_obligations`](../crates/rustgate-transport/src/router.rs).

So the operator-visible behavior across a Send-vN, Receive-vN+1 split
is:

| Policy change | Send-side effect (vN baked in) | Receive-side effect (vN+1 fresh) |
|---|---|---|
| vN+1 *removes* `MaskPoint` from a rule | Already applied; coordinates remain zeroed in the delivered payload | Receive PEP under vN+1 does not re-add a mask, but the Send mutation has already happened |
| vN+1 *adds* `MaskPoint` to a Receive rule | Send under vN did not mask | Receive under vN+1 stacks `MaskPoint` on top — coordinates are zeroed before `try_send` |
| vN+1 *removes* `TagClassified` | n/a (TagClassified is Receive-only) | Audit record `authz.classified_delivery` is **not** emitted for vN+1 — the new policy wins |
| vN+1 *flips Allow → Deny* on the recipient | Message already in flight from Send-vN | Receive PEP filters the recipient and emits `authz.denied`; other recipients whose PEP ran under vN may still be delivered |

The conservative interpretation: **Send obligations are committed
state**, Receive obligations are policy-current. A `MaskPoint` applied
under vN cannot be undone if the rule is removed in vN+1 — the cleartext
no longer exists in the in-flight envelope. Conversely, a `MaskPoint`
added at the Receive layer in vN+1 *will* take effect on every
recipient evaluated after the swap, even if those recipients are part
of a fan-out that started under vN.

Per-recipient obligations stack on a *clone* of the Send-side
`Arc<RoutableMessage>` (`with_obligations` calls `Arc::make_mut` on a
fresh clone of the envelope), so two recipients of the same broadcast
seeing different Receive-side obligation sets do not interfere with
each other.

### Compound effect on group / ACL membership

The legacy `GroupAclPolicy` is held in a parallel `ArcSwap` and
follows the same reload model — a SIGHUP that swaps both policies
together is two atomic stores, not one transaction. A message can
therefore observe the new ACL with the old authz engine, or the new
authz engine with the old ACL, depending on which `.load()` lands
first.

Group membership itself is **not** re-evaluated mid-dispatch:

- Membership is derived once from the connecting client's certificate
  OUs at session establishment and stored on `Identity.groups`.
- `send_to_group` reads the membership snapshot from the
  `SessionHandle` map at fan-out time, not from a live ACL or authz
  re-check.
- A policy change in vN+1 that *narrows the allowed set of receive
  groups* takes effect at the Receive PEP for any recipient whose
  delivery is still pending — but a recipient whose certificate OU is
  unchanged remains a member of the cached set. Reload does not
  forcibly disconnect clients whose membership is no longer policy-
  authorized; the next per-recipient Receive PEP filters them out.

The practical consequence: a reload that tightens group access denies
*future* deliveries to the affected recipients (correct) without
disconnecting their sessions (deliberate — operators tune that
separately via `--authz-fail-open` and connection-policy reloads).

### Hot-reload and store-and-forward

Messages persisted for offline delivery are an explicit *escape* from
the in-flight reload window. `filter_offline_messages` re-runs both
PEPs against the current policy snapshot every time a queue is
drained, so a tightening reload that lands while a recipient is
offline takes full effect on drain. SA position replay
(`replay_positions`) follows the same rule: the cached envelope is
the pre-Send-obligation form, and the Send PEP runs again at replay
time to actuate whatever obligations the *current* policy requires.

This is the property that lets the cache-store invariants in
`route_inner` keep the pre-mutation form: a tightening reload that
lands between ingest and replay is honored, not bypassed.

### Why this is acceptable for tactical use

The alternative to eventual consistency is a router-wide read lock
held across the whole dispatch path, including the per-recipient
fan-out loops. That would serialize policy reloads against every
in-flight message and would either:

- Hold up reloads behind the slowest recipient (latency penalty —
  unacceptable when policy changes carry security weight), or
- Hold up dispatch behind reloads (availability penalty —
  unacceptable on a tactical router whose whole point is liveness).

The eventual-consistency window:

- Is bounded by message dispatch time. For the common case
  (single-tick fan-out) the window is microseconds.
- Is fail-closed on the *new* policy for any PEP that runs after the
  swap — a tightening change is honored on every recipient whose
  Receive PEP has not yet run.
- Is conservative on the *old* policy for any side-effect already
  committed before the swap — Send-side obligations applied under
  vN remain applied even if vN+1 would not have required them.

For tactical routing this trade is the right one. Liveness wins; the
window is short; tightening changes propagate strictly forward in
time across the per-recipient loops.

### Operator guidance

For routine operational reloads:

- **Trigger reloads during low-traffic windows.** A reload landing
  between active fan-outs has no observable split. `--authz-reload-
  interval` (default 5s) plus a quiet-window mtime touch is the
  cleanest pattern.
- **Correlate reload edges with denial spikes.** The
  `audit::authz_reload_success` event (`rustgate_core::audit`) emits
  the new `policy_id` and rule count on a successful swap;
  `audit::authz_reload_failed` emits the failing stage. Both are
  hash-chained when the audit log writer is configured for tamper
  evidence. Plot reload events against
  `rustgate_authz_decisions_total{decision="deny"}` and any spike
  immediately after a reload is the in-flight window manifesting.
- **Use `--authz-fail-open` for deliberate emergency reloads.** When
  pushing a known-good intermediate policy under time pressure,
  fail-open ensures a transient parse/compile error during the swap
  attempt does not collapse traffic. (The default fail-closed mode is
  still the right choice for steady state.)

For zero-downtime policy migrations:

- **Stage a "compatible-with-both" intermediate policy.** When moving
  from policy A to policy C, deploy an intermediate B that allows
  both the old and new shapes. Reload A → B at any time; later
  reload B → C once all clients have migrated to the new identity
  shape. This collapses the Send-vN / Receive-vN+1 hazard to a
  no-op: B accepts whatever A accepted *and* whatever C accepts, so
  any in-flight split between the reloads is policy-equivalent.
- **For critical tightening changes, drain first.** If the new
  policy must *immediately* deny a set of currently-allowed flows
  with no in-flight overlap, the operator can either (a) disconnect
  the affected clients before SIGHUP — store-and-forward will
  re-evaluate on reconnect against the new policy — or (b) flush
  the position cache and any per-CN store-and-forward queues so the
  new policy applies cleanly to the next message wave. Both options
  trade availability for serializability and should be reserved for
  the cases where strict ordering matters.

The eventual-consistency window is a documented and accepted property
of the rustgate authz dataplane. Strict serializability is available
on the persisted paths (store-and-forward, SA replay) — both
re-evaluate against the current policy on every drain — so a policy
that is tight enough on the persistence boundary will catch any
stragglers from an in-flight split.

## Policy reload effective time

This section is for SREs planning a tightening rollout who need a
defensible answer to "as of what wall-clock time does the new policy
apply to every routed message?". Issue
[#721](https://github.com/rchiofalo/rustgate/issues/721).

The mental model is simple but the timing is fuzzy at sub-microsecond
resolution. `arc_swap::ArcSwap` makes the swap itself instantaneous
(a single atomic pointer store) but in-flight evaluations that
already cloned the previous engine `Arc` continue to run against the
pre-swap policy until they finish. The window is short — typically
sub-microsecond, bounded by the tail latency of one evaluation on
the loaded policy — but it is not zero. There is no barrier; readers
never block writers and writers never block readers (see "The
`ArcSwap` architecture" above for the lock-free contract).

Three properties to anchor on:

1. **The swap is atomic for future `.load()` calls.** Every PEP site
   that calls `self.authz.load()` after the `store` observes the new
   engine. There is no "torn read" hazard; the inner pointer is
   either the old `Arc` or the new one, never both.
2. **In-flight evaluations finish on the old policy.** A PEP that
   has already called `.load()` and cloned the old engine `Arc`
   continues to run against that engine. The drop of the cloned
   `Arc` at the end of evaluation is what releases the previous
   engine's last refcount once the swap has retired the slot.
3. **Effective time is "T plus drain time", not just "T".** The new
   policy is in force for *all* messages from `T + drain_time`
   onward, where `drain_time` is the longest in-flight evaluation
   active at `T`. For compliance audits requiring "policy X effective
   at T", record both: the audit timestamp from
   `audit::authz_reload_success` (T) and the gauge drain observation
   (T + drain_time).

### `rustgate_authz_evaluations_in_flight` — the drain gauge

`rustgate_authz_evaluations_in_flight` (Prometheus `IntGauge`) is the
operator-visible signal for "how many evaluations are still holding
the pre-swap engine `Arc`". It increments by `+1` on entry to every
Send and Receive PEP evaluation and decrements by `-1` on the
corresponding RAII guard drop, regardless of whether the evaluation
returned Allow, Deny, or panicked on the way out. Every PEP path is
covered because the guard is constructed inside
`authz_evaluate_inner`, which is the single shared codepath for the
two `authz_evaluate_send` / `authz_evaluate_receive` entry points.

Operational use:

- **Steady-state baseline.** On a healthy router the gauge oscillates
  around a small value proportional to the live message rate × per-
  evaluation latency (Little's law). Plot it as a per-second average,
  not a max — instantaneous peaks are dominated by sampling
  granularity.
- **Reload drain observation.** Annotate your dashboard with
  `audit::authz_reload_success` events. After every annotation,
  watch the gauge return to its pre-swap baseline. The wall-clock
  delta from the annotation to the gauge returning to baseline is
  the drain time — i.e., the moment the new policy is in force on
  every in-flight request.
- **Stuck-evaluation alerting.** A gauge value that does not return
  to baseline within seconds of a reload is a stuck PEP — an engine
  whose `evaluate()` is wedged. The native engine's measured P99 is
  ~80 ns; anything past tens of milliseconds warrants investigation.
  Alert on `max_over_time(rustgate_authz_evaluations_in_flight[1m])`
  staying above the steady-state baseline for longer than your
  per-evaluation tail SLO.
- **Capacity planning.** A monotonically rising gauge is the symptom
  of a misconfigured policy whose `evaluate()` cost has grown faster
  than the message rate. Combine with `rustgate_authz_eval_nanos` to
  separate "more evaluations" from "slower evaluations".

### Why the metric path was taken over a barrier-stall

The alternative to the metric+docs approach is a router-wide barrier
that stalls `swap_authz` until every in-flight evaluation that
observed the previous engine has finished. That option was
deliberately rejected: it converts the lock-free hot path into a
blocking one, and on a tactical router whose value proposition is
liveness, the latency of the swap is more important than its
serializability. The metric makes the existing window observable
without changing its shape — operators get the drain time as data,
not as a serialization point. The persisted paths
(store-and-forward, SA replay) already provide strict serializability
where it matters; see "Hot-reload and store-and-forward" above.

## Optional Cedar backend

For operators with an existing Cedar policy corpus, rustgate can be
built with `--features cedar` and pointed at a Cedar source file via
`--authz-policy-format cedar`:

```bash
rustgate \
  --authz-policy-file /etc/rustgate/policy.cedar \
  --authz-policy-format cedar \
  ...
```

The Cedar backend maps rustgate types into Cedar entity UIDs as follows:

| rustgate concept | Cedar entity |
|---|---|
| Subject CN | `RustgatePrincipal::"<cn>"` |
| Action | `Action::"send"` (and peers) |
| Direct resource | `Direct::"<cn>"` |
| Group resource | `Group::"<name>"` |
| Broadcast resource | `Broadcast::"all"` |
| Federation resource | `Federation::"<peer>"` — *reserved; not evaluated at runtime.* |
| NATS subject | `NatsSubject::"<subject>"` — *reserved; not evaluated at runtime.* |

As with the native backend, only the `send` and `receive` actions reach
production call sites today. Cedar rules targeting `Federation::` or
`NatsSubject::` entities are accepted by the parser/translator but are
never matched by a live decision request.

Example Cedar rule:

```cedar
permit(
    principal == RustgatePrincipal::"alpha",
    action == Action::"send",
    resource == Direct::"bravo"
);
```

Any error from Cedar — parse failure, request construction, evaluation
— is mapped to `Deny` and logged at `warn!` on the `authz` target. The
backend is deliberately fail-closed. In particular, Cedar treats a
policy that errors at evaluation time as if it had not matched, which
for a `forbid(...)` rule would silently turn a crash into a
policy-overriding-safety footgun (an unrelated `permit` that happened
to match would win). The backend inspects `Response::diagnostics()`
after every evaluation and forces the verdict to `Deny` whenever any
policy reports an error, regardless of what the authorizer returned.

Limitations today:
- No context or entity attributes are forwarded to Cedar. Policies that
  need attribute-based conditions should continue to use the native
  backend, where the `SubjectMatcher::attribute_eq` path is evaluated
  directly.
- Hot-reload of Cedar policies is deferred. Cedar policies load once at
  startup; SIGHUP and the polling watcher currently only apply to the
  native backend.

## Related docs

- Runbook: [docs/runbooks/authz.md](runbooks/authz.md)
- Configuration: [docs/configuration.md](configuration.md)
