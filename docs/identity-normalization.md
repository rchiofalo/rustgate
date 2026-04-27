# Identity / CN Normalization

This document audits the per-layer normalization rules applied to the
client Common Name (CN) string as it flows from the X.509 certificate
through `Identity` construction, the group ACL, and the RBAC/ABAC
authorization engine. It exists because divergent normalization across
layers would let an attacker who controls their CN spoof a different
principal — e.g. a CN that ACL treats as `alice` but authz treats as
`Alice` (or worse, with a Unicode lookalike like Turkish dotless i
`alıce` U+0131).

The headline invariant is **defense-in-depth via AND-composition**:
every authorization decision must satisfy *both* the group ACL *and*
the authz engine. The two layers deliberately use different
normalization rules so that any disagreement fails closed (the more
restrictive of the two denies). This document spells out which rule
applies where, what an attacker can and cannot do under each rule, and
the invariants pinned by tests so a future refactor that "unifies"
normalization without preserving the AND-composition will fail
locally before reaching review.

## Layers and their normalization

| Layer | Crate / file | Normalization applied | Why |
|---|---|---|---|
| **Cert extraction** | `rustgate-transport::extract::extract_cn` | None — verbatim casing preserved from the X.509 RDN | The CN is needed in original form for logging and forensic correlation; normalization is pushed to security-relevant lookups so a `tracing::warn!` line still shows the operator the exact bytes the client presented. |
| **Identity construction** | `rustgate-core::identity::{Identity::new, Identity::plaintext}` | Validates non-empty, length cap (256), control-char rejection. Does NOT NFC-normalize, lowercase, or trim. | `Identity` is the structured handle a router-side task carries through dispatch; equality (`PartialEq`/`Hash`) is byte-exact so two cert-rotation-separated sessions with the same CN-but-different-fingerprint stay distinct in the authz cache. Re-encoding the CN here would silently merge those sessions. |
| **Group ACL match** | `rustgate-transport::acl::{GroupAcl, GroupAclPolicy}` | ASCII lowercase at *both* allow-list construction (`new`, `with_deny`) AND lookup (`can_send`, `can_receive`) | RFC 5280 §7.1 specifies CN is case-insensitive. ASCII-only lowercase is the historic, intentionally narrow choice — non-ASCII case folding (Turkish İ/ı, German ß) is not performed because typical X.509 CNs are ASCII in practice and applying full Unicode case folding would expand the attack surface to lookalike-collapsing transforms. |
| **HTTP filter source-CN match** | `rustgate-http::filter` (`MessageFilter::matches`) | ASCII lowercase at both filter-list construction and lookup | Same RFC 5280 §7.1 reasoning. The HTTP egress filter's source-CN allow-list mirrors the ACL discipline. |
| **Server ACL config loaders** | `rustgate-server::acl_api`, `rustgate-server::acl_reloader`, `rustgate-server::setup` | ASCII lowercase on every CN read from operator-supplied YAML/REST input | The loader normalizes once; the `GroupAcl::new` constructor then idempotently lowercases again. Idempotency is load-bearing — a future refactor that drops the loader-side lowercase would still produce a working policy because the constructor catches it. |
| **Authz Cedar / compiled engine** | `rustgate-authz::compile::CompiledSubjectPred::matches`, `rustgate-authz::cedar_backend` | None — byte-identical `==` comparison on the raw `subject.cn` | Cedar policy is authored against a specific entity-id string. Normalizing here would silently change which policies match which subjects across releases. The policy author is the single source of truth for the CN spelling expected at this layer. |
| **NATS subject sanitization** | `rustgate-nats::publisher::sanitize_nats_token` | NFC + character allowlist (`unicode_normalization`) | NATS subjects are dot-separated tokens with their own charset rules; NFC defends against Unicode-equivalence attacks on the token text. CN is not sanitized through this path — the NATS publisher reads `msg.source.cn` as a structured log field, not as a subject component. |
| **Operational logging** | `rustgate-core::masking::hash_cn` and `rustgate-core::sanitize::sanitize_for_log` | SHA-256 truncation (12 hex chars) for PII protection at info/debug; control-char replacement with U+FFFD for log-injection defense | Orthogonal to authorization; no normalization is applied to the value before hashing or sanitizing because the operator needs the hash to be stable across whatever case/encoding the client presents. |

## Per-layer security invariants (pinned by tests)

The crate-local test suites pin each invariant. A regression that breaks
one of these will fail locally before reaching CI review.

1. **Identity preserves caller bytes verbatim** —
   `rustgate_core::identity::tests::identity_preserves_cn_bytes_verbatim`
   constructs `Identity::new("Alice", ...)` and asserts the stored
   field is `"Alice"`, not `"alice"`. This is the load-bearing test
   that traps a "well-meaning" refactor that adds NFC + lowercase to
   the constructor under the false assumption that all downstream
   layers normalize.

2. **ACL is case-insensitive AND order-of-operations idempotent** —
   `rustgate_transport::acl::tests::policy_case_insensitive_match`
   pins that an allow list constructed with `{"Alice"}` matches a
   lookup of `"alice"`, `"ALICE"`, and `"Alice"` alike. The construction
   AND lookup both lowercase — a regression that drops the lookup-side
   lowercase would still pass any single-direction test.

3. **Authz Cedar is case-sensitive by design** —
   `rustgate_authz::compile::tests::compiled_subject_pred_cn_eq_is_case_sensitive`
   pins that a policy with `cn_eq="alice"` does NOT match a subject
   with `cn="Alice"`. This is the load-bearing test that traps a
   regression which adds `to_ascii_lowercase()` to either side of the
   `subject.cn` comparison — the new behavior would silently change
   which policies match across releases.

4. **Unicode lookalikes are NOT folded together** —
   `rustgate_core::identity::tests::unicode_lookalike_does_not_match_legitimate_cn`
   pins that `"alice"` (ASCII) and `"alıce"` (Turkish dotless i,
   U+0131) construct different `Identity` objects with different `cn`
   fields. This is the load-bearing security test: a regression that
   introduced full Unicode case folding (e.g. `unicase` or
   `caseless`) would silently let the dotless-i form match an ASCII
   `alice` allow list — the exact attack class this audit was filed
   against.

5. **NFC composition variation does NOT match across encoding** —
   `rustgate_core::identity::tests::nfd_and_nfc_construct_different_identities`
   pins that `"caf\u{00e9}"` (NFC) and `"cafe\u{0301}"` (NFD) construct
   distinct `Identity` objects. Without an NFC normalization step at
   construction, the two byte sequences are different identities. This
   is the deliberate divergence: pushing NFC into Identity would
   require every callsite that compares CN strings (federation peer
   identity, store-and-forward queue keys, audit-chain correlation) to
   also normalize on read, which would expand the audit surface.
   Operators are expected to enroll certs with consistent encoding;
   the NATS publisher's NFC sanitization defends the *subject*
   pathway separately.

6. **Whitespace is NOT trimmed at construction** —
   `rustgate_core::identity::tests::leading_trailing_whitespace_is_preserved_verbatim`
   pins that `"  alice  "` and `"alice"` construct different `Identity`
   objects. CAs are expected to issue certs without surrounding
   whitespace; if a malformed CSR produces a CN with embedded spaces
   the operator wants to see the exact bytes in audit logs to
   diagnose the issuance pipeline. Silently trimming would mask the
   issuance bug.

## Threat model: what an attacker controlling their CN cannot do

This subsection enumerates the failure modes the AND-composition
defends against and why each one fails closed.

**Scenario 1: case-mismatched policy author and CA.** ACL has
`senders={"alice"}` (lowercased to `alice`). Cedar policy has
`cn_eq="alice"`. Client cert CN is `"Alice"`. ACL lookup lowercases
`"Alice"` → `"alice"` → matches. Cedar comparison: `"alice" == "Alice"`
→ false → denies. AND-composition: deny. The mismatch is operator
visibility (the policy author meant for `Alice` to be allowed), not a
spoof. Audit emits `authz_denied`; operator fixes the policy or the
issuance pipeline.

**Scenario 2: Turkish dotless-i lookalike.** Client presents cert with
CN `"alıce"` (U+0131 instead of ASCII `i`). ACL has `senders={"alice"}`.
Cedar has `cn_eq="alice"`. Both layers compare bytes — neither
`"alıce".to_ascii_lowercase()` nor the raw byte form equals `"alice"`.
Both deny. The attacker-controlled lookalike is rejected at every
layer because ASCII-only normalization does not fold non-ASCII
codepoints and Cedar does not normalize at all.

**Scenario 3: NFD-form cafés.** Client A enrolls with `"café"` in NFC
form (`caf\u{00e9}`). Client B enrolls with `"café"` in NFD form
(`cafe\u{0301}`). Both ACL and Cedar see distinct byte strings. Both
clients are treated as distinct identities; neither can spoof the
other. The deliberate non-normalization at every layer is what makes
this work — adding NFC to Identity but not to Cedar would let A and B
share an ACL allow list while remaining distinct in Cedar policy, and
the operator would have no way to express "allow either form" without
duplicating policy.

**Scenario 4: leading-whitespace `" alice"`.** Client cert presents
CN `" alice"` (leading space). Identity stores the literal bytes. ACL
lookup lowercases to `" alice"` — does not match `"alice"` in the allow
list because the constructor's `to_ascii_lowercase()` does not trim.
Cedar compares `" alice" == "alice"` → false. Both deny. The leading
whitespace is rejected as a spoof attempt; the audit log carries the
exact bytes so the operator can see the attack shape.

## Why we do NOT push normalization into Identity construction

The audit considered the alternative of moving normalization (NFC →
trim → ASCII lowercase) into the `Identity::new` and `Identity::plaintext`
constructors so every downstream layer consumes an already-normalized
CN. We rejected this for four reasons:

1. **Equality contract for the authz cache.** `Identity` is `Hash + Eq`
   and is used as a `HashMap` key in the authz cache. Normalizing at
   construction would silently merge two distinct cert sessions whose
   CNs differ only in case or NFD/NFC form — and the cache would leak
   authorization decisions across them. The status quo's byte-exact
   equality is the boundary that keeps cert-rotation-separated
   sessions distinct.

2. **Forensic visibility.** Audit logs and `tracing::warn!` lines
   currently show the operator the exact bytes the client presented.
   Normalizing at construction collapses this signal. A failed mTLS
   handshake against a CA that issues mixed-case CNs would no longer
   show the operator that the policy was case-sensitive — the entire
   forensic trail would carry the normalized form.

3. **Cedar policy stability.** Cedar entity IDs are byte-exact strings.
   Adding normalization at Identity construction means a policy
   written against `cn_eq="alice"` would silently start matching every
   client that presents `"Alice"`, `"ALICE"`, or `"Café"` (NFD).
   Across releases this is a security-relevant behavior change with no
   visible deprecation surface — every existing deployment's policy
   meaning would shift.

4. **AND-composition is the security boundary.** The current ACL +
   authz divergence means an attacker has to defeat *both* layers to
   reach a target. A unified normalization layer collapses this to a
   single layer: defeat one normalization rule and you've defeated
   every layer. The status quo's redundant-with-different-rules
   discipline is the defense.

For the same reasons, we do NOT add NFC to the ACL or HTTP filter
construction. ASCII-only lowercase is the conscious narrow choice; it
is documented in `acl.rs` rustdoc and pinned by the
`policy_case_insensitive_match` test.

## What an operator should do

- **Issue certificates with consistent CN spelling.** A CA that issues
  `Alice`, `alice`, and `ALICE` to three different operators
  configures three policy entries to allow them all. ASCII-lowercase
  ACL handles this; Cedar policy must list each spelling explicitly.
- **Avoid Unicode in CNs.** Stick to printable ASCII. The codebase
  validates absence of control characters; NFC variation is not
  defended against at any authorization layer because the operator is
  expected to control issuance.
- **When migrating ACL → Cedar policy, mirror the case in both.** The
  ACL is case-insensitive but Cedar is case-sensitive. A policy that
  mirrors `senders={"alice"}` should write `cn_eq="alice"`, not
  `cn_eq="Alice"`.
- **Audit a denied-by-only-one-layer event.** A `authz_denied` audit
  with the subject CN matching an ACL allow list is the canonical
  signal that the Cedar policy and the ACL disagree on case. Fix the
  Cedar policy or the issuance pipeline; do not "fix" by adding
  normalization to the engine.

## Related

- `rustgate-transport/src/acl.rs` — ACL implementation and rustdoc on
  the case-insensitive contract.
- `rustgate-authz/src/compile.rs` — `CompiledSubjectPred::matches`,
  the byte-exact CN comparison.
- `rustgate-core/src/identity.rs` — `Identity::new` /
  `Identity::plaintext` constructor validation rules.
- `rustgate-core/src/masking.rs` — `hash_cn` for operational log
  cardinality capping (orthogonal to authorization).
- `docs/authorization.md` — the RBAC/ABAC engine, policy authoring,
  obligation dispatch.
- `docs/threat-model.md` — broader workspace threat model.
- Issue #723 (this audit), #802 (`hash_cn` made public), #1207
  (audit-boundary log sanitization).
