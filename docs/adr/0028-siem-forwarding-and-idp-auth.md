# ADR 0028: SIEM forwarding and external IdP authentication

- **Status:** Proposed
- **Date:** 2026-07-03
- **Deciders:** rchiofalo
- **Related:** #1460 (SIEM forwarding + IdP/OAuth/OIDC/SAML epic),
  `rustgate-core::audit`, `rustgate-archive::audit_chain`, ADR 0014
  (hash-chained audit log)

## Context

rustgate emits a structured audit trail today: `rustgate-core::audit`
publishes JSON audit records via `tracing` at `INFO` with target
`"audit"`, and `rustgate-archive::audit_chain` writes a tamper-evident
SHA-256 hash chain to disk. Both are **local-only** — an operator who
wants those events in an enterprise SIEM (Splunk, ArcSight, QRadar,
Elastic) has to scrape the JSON log off the box out of band. Two large,
frequently-requested capability areas sit on top of that gap:

1. **SIEM forwarding.** Ship audit events to a SIEM over syslog
   (RFC 5424) with a SIEM-native payload format — ArcSight CEF is the
   lowest-common-denominator that Splunk/QRadar/ArcSight all ingest.
2. **External IdP authentication.** Let the admin/management surfaces
   authenticate operators against an enterprise identity provider
   (OAuth 2.0 / OIDC / SAML) instead of the current static bearer token,
   plus per-username lockout after repeated failures.

Both are epic-sized. Bundling them into one branch would violate the
one-cohesive-slice principle and the workspace PR-volume rules, and the
two tracks share no code. This ADR scopes **both** tracks and records a
phased plan, and ships the smallest safe foundational slice of Track 1
(the CEF payload formatter) so the follow-on transport work has a stable
seam to build against. No Track 2 code ships in this ADR.

Non-negotiable constraints from outside the slice:

- The audit record shape (`event_type` dot-notation, `action`,
  `result`, plus per-event fields) is the existing contract in
  `rustgate-core::audit`; the formatter maps **from** that shape and
  must not require changes to it.
- Log-injection defense is already the house posture
  (`sanitize::sanitize_for_log` at the audit boundary). The CEF
  formatter re-applies escaping at *its* boundary (CEF header pipe /
  backslash escaping, extension `=` / backslash / newline escaping) so a
  value that reaches it unsanitized still cannot forge a CEF line.

## Decision

Deliver the epic in phases. This ADR ships **Phase 1a** only.

### Phase 1a — CEF payload formatter (this ADR, shipped)

A new **off-by-default `siem` feature** on `rustgate-archive` gates a
pure, dependency-free CEF formatter:

- `crates/rustgate-archive/src/siem/mod.rs` — the `AuditEvent` input
  struct (`event_type`, `name`, `action`, `result`, and a bounded
  ordered `extension` key/value map borrowed from the existing audit
  field set) and the `Severity` mapping.
- `crates/rustgate-archive/src/siem/cef.rs` —
  `format_cef(&AuditEvent) -> String`, emitting an RFC-compliant
  CEF v0 line: `CEF:0|vendor|product|version|signature|name|severity|extension`.
  The four header text fields are pipe- and backslash-escaped
  (`\|`, `\\`); extension values are `=` / backslash / newline-escaped
  (`\=`, `\\`, `\n`) and can never emit a raw newline.

Severity is derived from the audit `result` string: `success` and other
benign outcomes map low (3); `rejected` / `denied` / `deny` / `failed` /
`failure` and other adverse outcomes map high (6–8). The formatter is a
**pure string transform** — no socket, no TLS, no `tracing-subscriber`
layer, no network I/O. It has no production callers yet; it is the seam
Phase 1b consumes.

### Phase 1b — syslog-over-TLS transport (deferred, next branch)

A `tracing-subscriber` `Layer` that intercepts `target="audit"` records,
renders them through `format_cef`, and ships them to a syslog collector
over RFC 5424 framing on a TCP+TLS sink. This pulls in connection
lifecycle, backpressure, reconnect/backoff, and a subscriber layer — a
distinct, riskier slice that gets its own branch and integration tests
against a mock syslog listener. Deferred deliberately so Phase 1a can
land as a reviewable, zero-blast-radius unit.

### Phase 2 — external IdP authentication (deferred, ADR-scoped only)

OAuth 2.0 / OIDC (authorization-code + PKCE) and SAML 2.0 assertion
validation for the admin/management surfaces, replacing the static
bearer token as an *opt-in* alternative. Feature-gated; no code in this
ADR.

### Phase 3 — per-username lockout (deferred, ADR-scoped only)

Per-principal failed-attempt tracking with lockout/backoff on the
authentication surfaces, complementing the per-IP rate limiters that
already exist (`rustgate-resilience::conn_rate_limiter`,
`rustgate-enrollment::ratelimit`). No code in this ADR.

## Alternatives considered

- **Ship the whole epic in one branch.** Rejected: two unrelated code
  tracks (payload+transport vs. auth), each epic-sized, would blow the
  PR-volume budget and produce an unreviewable diff. Phasing keeps each
  slice cohesive.
- **Ship syslog transport in the same slice as the formatter (skip
  Phase 1a/1b split).** Rejected: the transport is where the real risk
  lives (connection lifecycle, backpressure, a subscriber layer that
  intercepts every audit record). Landing the pure formatter first gives
  the transport a tested seam and keeps Phase 1a's blast radius at zero.
- **Emit LEEF or raw JSON to syslog instead of CEF.** Rejected for the
  first slice: CEF is the broadest-ingest format across Splunk, QRadar,
  and ArcSight. JSON-over-syslog and LEEF can be added later behind the
  same `format_*` seam without changing the transport.
- **Put the formatter in `rustgate-core::audit`.** Rejected: `audit` is
  a zero-dependency emission boundary depended on by every crate;
  SIEM-format concerns belong with the other forensic-trail machinery in
  `rustgate-archive` (which already owns `audit_chain`), behind an
  off-by-default feature so the default build pays nothing.

## Consequences

Once this ADR is in force:

- `rustgate-archive` gains an off-by-default `siem` feature and a
  `siem` module. The default build and every existing feature
  combination are byte-for-byte unchanged — the module and its tests are
  fully `#[cfg(feature = "siem")]`-gated, so `cargo hack
  --feature-powerset` builds it both on and off with no undeclared or
  unused feature.
- Phase 1b has a stable, unit-tested formatting seam
  (`format_cef`) to build the syslog sink against; it will not need to
  re-litigate escaping or severity mapping.
- The audit-record shape in `rustgate-core::audit` stays the contract;
  the formatter is a consumer of it. A new audit field is picked up by
  Phase 1b simply by adding it to the `extension` map at the call site.
- Tracks 2 and 3 (IdP auth, per-username lockout) are recorded here as
  committed scope but carry no code; they get their own branches and, if
  the design firms up, their own ADR status transitions.

This decision is reversible: the `siem` module is additive and
feature-gated, so removing it is a clean delete with no migration.
