# ADR 0027: MaskPoint fails closed for unmaskable position protocols

- **Status:** Proposed
- **Date:** 2026-06-30
- **Deciders:** rchiofalo
- **Related:** #1545 (SEC-18, the leak this corrects), #742 (the prior
  non-XML pass-through design this reverses), #772 / #775 (the audit
  vocabulary #742 introduced), ADR 0022 (guard egress seam), ADR 0024
  (guard fail-closed — the sibling fail-open finding)

## Context

`Obligation::MaskPoint` is the router's position-stripping control: a
policy attaches it to a downgrade group so a message's coordinates are
erased before egress. `apply_mask_point`
(`rustgate-router/src/obligations.rs`) masks two payload shapes — CoT
XML (`rustgate_cot::mask::strip_coordinates`) and MAVLink
(`rustgate_mavlink::mask_position`). **Every other position-bearing
protocol falls through to the non-XML branch and was forwarded
*unmasked*** — DIS, Link 16, ASTERIX, VMF, SAPIENT, NFFI, STANAG 4586,
Meshtastic, TAK protobuf. The June 2026 semantic audit (#1545) flagged
this as its single most serious finding: a `MaskPoint` obligation meant
to strip location does **nothing** for those protocols and the original
coordinates egress intact to NATS / HTTP / federation peers. The audit
token recorded the leak; it did not prevent it.

The non-XML branch was not an oversight — #742 deliberately built a
three-bucket forensic vocabulary (`forwarded_binary`,
`forwarded_unmasked`, `forwarded_unknown`) around forwarding non-XML
payloads, on the premise that *"MaskPoint is a CoT-specific control; a
payload with no `<point>` element has nothing to mask, so dropping it
would be silently discarding traffic on a mis-configuration."* That
premise is **wrong for binary position protocols**: an ASTERIX track or
a DIS Entity State PDU carries latitude/longitude in binary fields, not
in a `<point>` element. "No `<point>`" is not "no position."

## Decision

**Fail closed.** A non-XML, non-MAVLink payload reaching `MaskPoint` is
treated as a position-bearing protocol the dispatcher cannot mask, and
its body is **erased** (`apply_mask_payload` → empty payload, message
type `Other("masked")`) — the same terminal state the existing
XML-parse-failure path already produces. The audit record carries
`recovery = "dropped"` (reusing `MASK_RECOVERY_DROPPED`); the
`source_protocol` field still names which upstream tripped the drop, and
the operational DEBUG log keeps the `forwarded_*` protocol-class string
as a separate `protocol_class` field for drill-down. Rate-limiting and
the `mask_point_non_xml` reason token are unchanged.

This is **default-deny**: a payload the dispatcher cannot prove is
position-free is treated as if it carries a position. Genuinely
point-less binary traffic routed through a `MaskPoint` group is erased
too — the safe trade-off on a classification boundary, matching the ACL
model's "unconfigured ⇒ denied" posture.

MAVLink is unchanged: it has a registered masker, and a frame
`mask_position` cannot place (e.g. `HEARTBEAT`) is genuinely point-less
and still forwards. Extending `mask_position`'s frame coverage is a
MAVLink-crate concern, out of scope here.

## Alternatives considered

- **Per-codec maskers (DIS ECEF-zero + checksum, Link 16 micro-deg,
  ASTERIX item rewrite, …).** The *proper* long-term fix and the
  non-interim half of #1545's recommendation. Deferred: each codec's
  position encoding is a separate, non-trivial implementation with its
  own checksum/CRC re-derivation, and shipping them is a multi-PR effort.
  Fail-closed closes the leak today; the maskers can replace the drop
  per-protocol as they land (each flips one `source_protocol` from
  `dropped` back to masked-and-forwarded).
- **Keep forwarding, raise the audit severity.** Rejected — an audit
  token does not stop the egress; the coordinates still leave.
- **Registry of "known position-free" protocols, forward those, drop the
  rest.** Rejected as the *default*: it fails **open** for any protocol
  not yet in the registry, so a newly added position protocol leaks until
  someone remembers to list it. Default-deny is the correct posture for a
  release boundary.

## Consequences

Safer: the most serious finding of the semantic audit is closed —
position can no longer egress a `MaskPoint` group unmasked for any
protocol. Behavior change: deployments that attach `MaskPoint` to a
group carrying non-CoT/non-MAVLink traffic will now see those messages
erased rather than forwarded. For position-bearing protocols that is the
intended correction; for genuinely point-less binary traffic it is
conservative collateral — the documented cost of failing closed.

SIEM: the `recovery` token for the non-XML branch moves from
`forwarded_binary` / `forwarded_unmasked` / `forwarded_unknown` to
`dropped`. The protocol-class distinction is preserved in the DEBUG
`protocol_class` field and in `source_protocol`; grep-based rules keyed
on the `forwarded_*` tokens for this branch must move to `dropped`. The
`forwarded_*` constants remain part of the public audit vocabulary (the
MAVLink point-less path still emits `forwarded_binary`).

Reversible: restoring forwarding is a one-line change, and each per-codec
masker that lands narrows the set of protocols this drop applies to.
