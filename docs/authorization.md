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
    },
    {
      "id": "allow-command-nats-publish",
      "effect": "allow",
      "action": "publish",
      "subject": { "groups_all_of": ["command", "operator"] },
      "resource": { "kind": "nats_subject", "subject_pattern": "cot.*" },
      "obligations": ["audit_extended"]
    }
  ]
}
```

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
| `action` | string | One of `send`, `receive`, `federate`, `publish`, `subscribe`. |
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
| `federation` | `peer_id` (optional) | Federation link to a peer server. `null`/omitted matches any peer. |
| `nats_subject` | `subject_pattern` | NATS subject; literal or trailing-`*` wildcard. |
| `any` | — | Matches any resource kind. Useful for broad deny rules. |

### Actions

| Action | When it fires |
|---|---|
| `send` | Client-originated unicast, group, or broadcast dispatch. |
| `receive` | Router delivery path toward a specific subscriber. |
| `federate` | Forwarding across a federation peer link. |
| `publish` | NATS publish. |
| `subscribe` | NATS subscribe. |

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

Obligations compose: Send-side obligations mutate the envelope before
it is wrapped in `Arc` and fanned out; Receive-side obligations stack
on each per-recipient copy. `MaskPayload` supersedes `MaskPoint` because
it replaces the payload entirely — either ordering produces the same
final (empty) body.

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
| Federation resource | `Federation::"<peer>"` |
| NATS subject | `NatsSubject::"<subject>"` |

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
