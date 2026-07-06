# ADR 0036: Secure-by-default warm-up for three insecure startup defaults

- **Status:** Proposed
- **Date:** 2026-07-03
- **Deciders:** rchiofalo
- **Related:** #1559 (secure-by-default hardening), ADR 0024 (guard
  fail-closed warm-up precedent), #1495 (guard fail-open warm-up),
  `crates/rustgate-server/src/cli.rs`

## Context

rustgate ships three startup defaults that are convenient for a minimal
or development deployment but unsafe in production, all verified in
`crates/rustgate-server/src/cli.rs`:

1. **No routing policy ⇒ app-layer-open.** When neither
   `--group-acl-file` nor `--authz-policy-file` is set, the router
   installs no enforcement point: any authenticated client may send and
   receive on any group. Nothing warns the operator that the message
   plane is wide open.
2. **Bound metrics endpoint ⇒ unauthenticated.** `--metrics-bind` with
   no `--metrics-token-file` exposes `/metrics` (and, once a package
   store is configured, the mutating `/api/packages` surface — already
   guarded separately) with no bearer token. The field doc on
   `metrics_token_file` calls this "backward compatible", which is
   exactly the problem: the safe default is opt-in, not on.
3. **Unbounded per-listener rate limits.** `--ws-max-frames-per-sec`,
   `--ws-max-bytes-per-sec`, and `--udp-rate-limit` all default to `0`
   (unlimited), and a `--udp-bind` listener accepts datagrams from any
   source IP unless `--udp-allowed-cidrs` is set. A single client can
   saturate a listener.

The issue's first-cut fix — refuse to start without a policy unless an
`--insecure-*` flag is set, require a metrics token whenever
`--metrics-bind` is set, and change the rate-limit defaults to finite
values — is correct in *direction* but is an immediate availability
regression for every existing minimal and dev deployment if applied in
one release. This is the same class of regression the ADR 0024
adversarial review caught for the guard fail-closed flip, and the same
lesson recorded for the #1495 guard warm-up: a global posture change
with no per-deployment canary drops benign traffic fleet-wide the
instant it lands.

`--authz-fail-open` is the house precedent for "secure default, explicit
operator opt-out", and ADR 0024 established the *staged* precedent:
surface the would-be change as a log-only warning first, enforce one
release later.

## Decision

Stage each of the three flips as **log-only this release, enforcement
one release later**, following the ADR 0024 warm-up precedent. This ADR
covers the **warm-up slice only**; the enforcement flip is a deliberate
follow-up branch after one release cycle.

This release changes **no** routing, metrics, or rate-limit behaviour.
It adds, in `Cli::validate()`
(`crates/rustgate-server/src/cli.rs`), a startup warning for each flip
that names exactly what will be denied or required in the enforcement
release, plus one explicit opt-out flag per flip so operators can
pre-pin the current (insecure) posture on purpose and silence the
warning:

| Flip (enforcement release) | Warm-up warning condition | Opt-out flag |
|---|---|---|
| No-policy ⇒ default-deny | neither `--group-acl-file` nor `--authz-policy-file` set, and opt-out absent | `--authz-no-policy-allow` |
| Metrics endpoint ⇒ require token | `--metrics-bind` set, `--metrics-token-file` unset, opt-out absent | `--metrics-no-auth` |
| Unbounded ⇒ finite rate-limit defaults | any of `--ws-max-frames-per-sec` / `--ws-max-bytes-per-sec` / `--udp-rate-limit` == 0, or `--udp-bind` set with `--udp-allowed-cidrs` unset, and opt-out absent | `--insecure-unbounded-rate-limits` |

The warnings are emitted at `tracing::warn` on the `audit` target with a
stable `flip` field (`no-policy-deny`, `metrics-require-auth`,
`finite-rate-limit-defaults`) and an `opt_out` field naming the flag, so
a SIEM can enumerate which deployments still need migration. Each opt-out
is a `bool` clap arg wired into the existing arg group (`AuthzArgs`,
`MetricsArgs`, `LimitArgs`) and mirrored into the `define_config_file!`
serde block so it round-trips through a TOML config under
`deny_unknown_fields`.

The **enforcement release** (out of scope here) will: bail at startup
when no routing policy is configured unless `--authz-no-policy-allow` is
set; require `--metrics-token-file` when `--metrics-bind` is set unless
`--metrics-no-auth` is set; and change the three rate-limit defaults to
finite values unless `--insecure-unbounded-rate-limits` is set. The
opt-out flags introduced now let operators pre-pin the old behaviour
*before* that release, so the enforcement flip is a no-op for anyone who
has already opted out.

## Alternatives considered

- **One-shot flip (the issue's own suggestion).** Refuse-to-start /
  require-token / change-defaults in a single release. Rejected: an
  immediate availability regression for every minimal and dev
  deployment, with no warm-up window for operators to notice and
  migrate — the exact failure mode ADR 0024 and the #1495 memory record.
- **Warnings with no opt-out flags.** Ship only the warnings this
  release, add the opt-outs at enforcement time. Rejected: operators who
  read the warning have no way to act on it yet, and the enforcement
  release would then introduce both the flip *and* the escape hatch
  together — no clean pre-pin path.
- **One combined `--insecure-defaults` flag for all three.** Rejected:
  conflates three unrelated risk surfaces; an operator who firewalls
  their metrics port should not thereby also silence the open-routing
  warning. Per-flip flags keep each decision independent, matching the
  `--authz-fail-open` granularity precedent.
- **Hard-bail immediately for the no-policy case only** (leaving metrics
  and rate limits for later). Rejected: still a one-shot flip for the
  highest-traffic surface (the message plane), and inconsistent staging
  across the three related flips is harder to document and reason about.

## Consequences

Safer over two releases: operators get an explicit, greppable startup
signal naming each insecure default and the flag that pins or fixes it,
before any behaviour changes. The opt-out flags give a deliberate,
audited way to keep the old posture where it is genuinely intended (a
metrics port already firewalled to a trusted scraper; a fully-trusted
LAN with no policy plane).

New burden this release is minimal and purely additive: three `bool`
flags and three startup warnings. The warnings are noise on minimal/dev
deployments — mitigated by making each a single concise line, gated on
its opt-out being absent, so an operator who accepts the posture can
silence it once.

Migration path: (1) this release — warnings + opt-outs, no behaviour
change; operators migrate to a policy / token / finite limits, or set
the opt-out; (2) next release — enforcement flip, which is a no-op for
anyone who migrated or opted out. Fully reversible up to the enforcement
release (additive flags + warnings only).

Coordinated-release note for the enforcement branch: the three new
rate-limit *default values* and the metrics-token requirement are a
behaviour change that must be called out in the CHANGELOG `Changed` /
`Security` sections at that time, and the opt-out flag names introduced
here are the stable escape hatches it will reference.

## Open questions

- The exact finite rate-limit default values for the enforcement release
  are not fixed here; they belong to the enforcement branch after
  observing real warm-up telemetry (which deployments the
  `finite-rate-limit-defaults` warning fires on).
- Whether the enforcement release should treat a `--udp-bind` with no
  `--udp-allowed-cidrs` as a hard bail or a defaulted-open-with-warning
  is deferred; the warm-up warning covers both interpretations.
