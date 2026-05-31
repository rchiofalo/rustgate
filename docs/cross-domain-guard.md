# Cross-Domain Egress Guard

The cross-domain guard is an optional inspection boundary that gates
**every message leaving the server toward an external sink** — UDP, NATS,
MQTT, plaintext, and federation. It exists for deployments that bridge two
network domains of differing trust or classification (the canonical
"low-side / high-side" cross-domain solution shape) and need a single,
auditable chokepoint that can rate-limit, require data markings, and refuse
traffic at the boundary.

It is **off by default**. With no `--guard-config` set, there is no
behavioural change and no hot-path cost beyond one atomic pointer load.

## Threat model & scope

The guard protects the **network-to-network cross-domain hop**: traffic
that egresses the server toward another domain. It is *not* a
session-to-session access control inside a single domain — local
same-domain fan-out (delivery to directly connected sessions) is handled by
the ACL and authz layers and is intentionally *not* gated here. Use the
guard when the question is "should this leave this domain?", and the ACL /
authz engine when the question is "may this client talk to that client?".

Properties:

- **Fail-closed.** A guard that denies a message drops it from external
  egress; a guard whose audit log cannot be written denies rather than
  silently passing traffic.
- **Complete by construction.** The gate is installed on the router's
  single egress chokepoint (`route_for_egress`). Every external sink —
  present and future — flows through that one point, so one configured
  guard covers all of them without per-sink wiring.
- **Audited.** Activation emits `audit.guard.activated`; every denial emits
  `audit.guard.rejected` with the source CN, sink, direction, and a stable
  machine-readable reason token (see below).

## Building with the guard

The guard lives behind the `guard` cargo feature on `rustgate-server`:

```bash
cargo build -p rustgate-server --features guard
```

Without the feature, `--guard-config` is unrecognised and the guard code is
not compiled in.

## Enabling at runtime

Point the server at a guard config file:

```bash
rustgate-server --guard-config /etc/rustgate/guard.toml   # or RUSTGATE_GUARD_CONFIG=…
```

When set, the server reads and validates the `[guard]` block at startup,
installs the boundary on the router, and logs a prominent `warn!` line
making the active posture unmistakable. A malformed or invalid config is a
hard startup error — the server will not run with a guard it cannot honour.

## Configuration

```toml
[guard]
# Per-direction throughput ceilings (bytes/sec, token-bucket enforced).
low-to-high-max-bps  = 1048576     # 1 MiB/s admitting into the high side
high-to-low-max-bps  = 262144      # 256 KiB/s on the release direction (tighter)

# Require every message to carry a data marking (CAPCO-style). When true,
# an unmarked message is denied. Leave true unless you have a specific
# reason — this is the fail-closed default.
mandatory-marking    = true

# Dedicated, hash-chained audit log for boundary decisions. Separate from
# the main server audit log so the cross-domain trail is self-contained.
audit-log-path       = "/var/log/rustgate/boundary-audit.jsonl"

# Deployment direction. v1 applies a single global direction to all egress:
#   "low-to-high"   — admitting toward the higher domain
#   "high-to-low"   — releasing toward the lower domain (usually tighter)
#   "bidirectional" — a two-way bridge; resolves to the least-restrictive
#                     low-to-high for the per-call evaluation in v1
direction            = "bidirectional"
```

All keys are required and unknown keys are rejected (`deny_unknown_fields`)
so a typo fails fast rather than silently disabling a control.

### Direction in v1

v1 applies **one global direction** to every egress message, taken from the
`direction` key. A `bidirectional` deployment resolves to `low-to-high`
(the least-restrictive concrete direction) for the per-call check. Per-sink
direction — tagging each external sink with its own domain side so a single
server can enforce `high-to-low` on one bridge and `low-to-high` on another
— is a planned follow-up that layers on without a config break.

## Denial reasons

Every denial carries a stable reason token (also surfaced in the audit
event). These are the single source of truth from `rustgate-guard`:

| Token | Meaning |
|-------|---------|
| `rate_limit` | The direction's `*-max-bps` token bucket was exhausted. |
| `missing_marking` | `mandatory-marking = true` and the message had no data marking. |
| `unauthorized_classification` | The message's marking is not permitted to cross in this direction. |
| `audit_error` | The boundary audit log could not be written — fail-closed denial. |
| `io_error` | An I/O error occurred while evaluating the message. |

## Observability

- `audit.guard.activated` — emitted once at startup with the configured
  direction and mandatory-marking flag.
- `audit.guard.rejected` — emitted per denial with source CN, sink,
  direction, and reason token.
- The dedicated boundary audit log (`audit-log-path`) is a SHA-256
  hash-chained JSONL trail; verify it with the standard audit-chain
  verifier.

## Interaction with ACL / authz

The guard runs **after** local same-domain session fan-out and **before**
any external sink, so:

- Messages delivered only to local sessions are never seen by the guard.
- A message fanned out locally *and* forwarded externally is delivered
  locally regardless of the guard's verdict; the verdict only governs the
  external copy.
- ACL and authz still apply on top — the guard is an additional boundary
  control, not a replacement for per-client authorization.

## Limitations (v1)

- Single global direction (per-sink direction is a follow-up).
- Config is read at startup; SIGHUP hot-reload of the guard config is a
  planned follow-up (the router slot itself is already hot-swappable).
