# rustgate-guard

Cross-domain content inspection guard for boundary-crossing traffic.

## Role in the workspace

`rustgate-guard` bundles the four boundary-crossing controls that
travel together in every cross-domain solution (CDS) deployment but
were absent from the obligation-engine scaffold in #1286 (`StripPii`,
`DegradePosition`, `InjectMarking`):

1. **Per-direction throughput cap** — every byte that crosses the
   boundary is metered through a `rustgate-resilience::token_bucket`
   sized to the direction's `*_max_bps` budget. Exceeding the cap
   fail-closes with `GuardError::RateLimitExceeded` and emits a
   `boundary.evaluate` audit record marked `decision = "deny"`,
   `reason = "rate_limit"`. Caps are independent per direction — a
   saturated `LowToHigh` channel does not affect `HighToLow`.
2. **Mandatory CAPCO marking** — when `GuardConfig::mandatory_marking`
   is set, the guard rejects any inbound message that carries no CAPCO
   banner (no `<marking>` child on a CoT detail element, or a banner
   that fails to parse via
   `rustgate_core::classification::ClassificationMarking`). The
   rejection emits an audit record with `reason = "missing_marking"`
   so SIEM rules can correlate misconfigured policies with the
   boundary they were evaluated at.
3. **Dedicated audit envelope** — the guard owns a
   `rustgate-archive::audit_chain::HashChainWriter` pointed at a
   **separate** log file from the general audit chain, so
   cross-domain accountability survives rotation of the operational
   log. Every evaluation — admit or deny — emits exactly one record
   before the `evaluate` call returns.
4. **Pre-egress before-and-after hashes** — each audit record carries
   `input_sha256` and `output_sha256` so an external auditor can prove
   what changed at the guard. Hashes are computed over the payload
   bytes (NOT the rendered XML), so a transform that re-orders
   attributes still produces a different hash.

Closes #857.

## Composition with the obligation engine

The CDI obligation kinds from #1286 (`StripPii`, `DegradePosition`,
`InjectMarking`) **compose** with the guard rather than replacing it.
A policy may apply transforms via obligations AND the guard may still
reject — the `output_sha256` reflects whatever the message looked like
at the moment the guard saw it, so an upstream obligation that injected
a marking is visible in the trail.

Guard rejection is **final**. Even with obligations applied, a
rate-limit or missing-marking trip drops the message; the audit record
is the only artifact that survives.

## Public API surface

- `Guard` — the inspection entry point. Constructed with
  `GuardConfig` (per-direction caps + flag toggles) and a
  `HashChainWriter` for the dedicated audit envelope.
- `Guard::evaluate(direction, payload)` — apply rate limit + marking
  check + pre-egress hash, emit audit record, return
  `Result<(), GuardError>`.
- `GuardConfig` — builder-style configuration (`with_max_bps`,
  `with_mandatory_marking`, …)
- `GuardDirection::{LowToHigh, HighToLow}` — boundary direction.
- `GuardError` — `thiserror`-derived: `RateLimitExceeded`,
  `MissingMarking`, `InvalidMarking`, `AuditWriteFailed`.

## Feature flags

| Feature | Description |
|---|---|
| `metrics` | Prometheus counters for per-direction admit/deny events. Pulls in `rustgate-metrics` + the resilience crate's `metrics` feature. Adds three metrics: `guard_evaluations_total{direction, decision}`, `guard_bytes_inspected_total{direction}`, `guard_audit_write_errors_total`. |

## Topology / deployment notes

The guard runs **post-decode, pre-egress** — between the routing
decision and the sink crate. It operates on `bytes::Bytes` payloads
that have already been classified by their source and have a known
direction (`LowToHigh` means the message originated on the
lower-classification network and is being released upward).

A typical CDS deployment has:

- Two `rustgate-server` instances, one per classification level
- A guard wired between them (in the same process or as a sidecar)
- Separate hash-chained audit logs per direction so an audit at the
  low-side can be reconciled with the high-side independently

The guard does NOT perform classification labeling itself — that lives
in the obligation engine's `InjectMarking` action. The guard CHECKS
that a label is present and parseable; it does not create labels.
