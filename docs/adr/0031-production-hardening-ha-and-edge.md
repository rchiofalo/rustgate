# ADR 0031: Production hardening — HA direction, capacity, edge install, and SLOs

- **Status:** Proposed
- **Date:** 2026-07-03
- **Deciders:** Roberto Chiofalo
- **Related:** #1459 (production-hardening epic), ADR
  [0006](0006-redb-over-sled-for-store-and-forward.md) (durable store),
  [0003](0003-arcswap-hot-reload.md) (hot-reload), `docs/disaster-recovery.md`,
  `docs/capacity-planning.md`, `deploy/systemd/`, `ops/prometheus/slo.rules.yml`

## Context

The production-hardening epic (#1459) names four gaps in how rustgate is
run at scale, three of which are documentation/artifact shortfalls and one
of which is a genuine architectural fork:

1. **HA coordination requires NATS.** Multi-pod high availability today
   depends entirely on NATS KV: peer-ownership claims, connection registry,
   and peer config all live in NATS buckets with a 30-second TTL
   (`crates/rustgate-federation/src/ha/{claims,registry}.rs`;
   `docs/disaster-recovery.md` "Federation HA Recovery"). If NATS is lost,
   **all HA coordination stops**. There is no NATS-free clustering path.
2. **No capacity guidance.** There is no document an operator can use to
   size a deployment. The admission-control knobs exist
   (`--max-queued-bytes` default 512 MiB, `--max-concurrent-handshakes`
   default 100, `--max-connections` default 1024) but nothing ties them to
   a client count or a pod size.
3. **No bare-metal / edge install artifact.** The only shipped deploy
   assets are the Helm chart (`helm/`) and the root `Dockerfile`. Tactical
   edge nodes that run the binary directly under systemd have no hardened
   unit file to start from.
4. **No shipped SLOs or error budgets.** `ops/prometheus/recording-rules.yml`
   computes the raw ratios an SLO would need (handshake error ratio, client
   queue drop rate) but no SLO target, burn-rate alert, or error-budget
   definition is shipped.

Items 2–4 carry no design risk — they are artifacts built on interfaces
that already exist. Item 1 is a real architectural decision that deserves
its own review and its own implementation issue; smuggling an unreviewed
leaderless-clustering design into a hardening branch would be a mistake.

## Decision

Split the epic. This ADR records the **direction** for HA and ships the
three risk-free artifacts now; it explicitly **defers** the native-HA
implementation to a dedicated follow-up.

**HA direction (decided):**

- **NATS-optional coordination is the target.** A single rustgate instance
  must be fully functional with no NATS dependency — it already is. HA
  coordination (multi-pod peer ownership) remains **NATS-backed for now**
  and is documented as such in `docs/disaster-recovery.md`.
- **A durable, restart-safe store is the prerequisite for NATS-free HA.**
  Leaderless clustering needs a shared source of truth for peer ownership
  that survives a coordinator restart. The redb-backed store chosen in
  ADR 0006 for store-and-forward is the natural substrate; extending it (or
  an equivalent embedded durable store) to hold ownership leases is the
  first concrete step, and it is named here as a **prerequisite epic**, not
  designed here.
- **Native leaderless clustering is an explicit non-goal of this branch.**
  The design fork — gossip vs. raft vs. lease-on-durable-store, failure
  detector, split-brain fencing — is deferred to a **follow-up issue**. This
  ADR does not choose among those options; it only records that the choice
  is pending and that the NATS path stays supported until a replacement
  ships and is validated.

**Artifacts shipped in this branch:**

- `docs/capacity-planning.md` — sizing guidance keyed to the existing
  admission-control knobs, with a worked 5,000-client example and a
  client-count → resource table, labelled as an **unbenchmarked estimate**.
- `deploy/systemd/rustgate.service` + `deploy/systemd/README.md` — a
  hardened unit for bare-metal/edge installs. **`Type=simple`**, because the
  server emits no `sd_notify` readiness signal today (verified: no
  `NOTIFY_SOCKET`/`sd_notify` in the tree). Readiness is instead gated by an
  `ExecStartPre=` pre-flight (`rustgate test-connection`) and the HTTP
  `/health/ready` probe.
- `ops/prometheus/slo.rules.yml` — reference SLO recording rules and
  multi-window burn-rate alerts built on the **exact** metric names already
  emitted (`rustgate_handshake_failures_total`, `rustgate_negotiations_total`,
  `rustgate_client_queue_drops_total`, `rustgate_messages_routed_total`).

## Alternatives considered

- **Design native leaderless HA in this ADR.** Rejected. The choice
  between gossip, raft, and a lease-on-durable-store has real trade-offs
  (operational complexity, split-brain semantics, dependency footprint) and
  deserves a focused review, not a paragraph inside a hardening branch. The
  April 2026 loop lesson applies: over-scoping one branch is how work goes
  sideways.
- **Drop NATS as an HA dependency now.** Rejected. NATS HA works today and
  removing it before a validated replacement exists would regress the one
  multi-pod story we have. NATS stays supported until the durable-store
  path lands and is benchmarked.
- **Ship capacity numbers as benchmarked figures.** Rejected. There is no
  load-test rig in CI. Presenting estimates as measurements would create
  false authority; the doc is labelled an estimate-until-benchmarked
  throughout, with the benchmark named as the thing that retires the label.
- **Use `Type=notify` in the systemd unit.** Rejected — the server does not
  call `sd_notify`, so `Type=notify` would leave systemd waiting for a
  readiness signal that never arrives and the unit would be marked failed
  after the timeout. `Type=simple` is correct until sd_notify is wired.

## Consequences

- Operators gain a sizing reference, a hardened edge install path, and
  ready-to-load SLO/burn-rate rules — all built on interfaces that already
  ship, so nothing here can break the build (no Rust changes).
- The HA gap is now **recorded and bounded** rather than implicit. The
  follow-up issue owns the native-clustering design; this ADR is the anchor
  it links back to. Until that lands, `docs/disaster-recovery.md` remains
  the source of truth that HA needs NATS.
- The capacity doc carries a **maintenance obligation**: when a load-test
  rig produces real numbers, the estimate labels must be replaced with
  measured figures and this ADR's "unbenchmarked" framing updated.
- The systemd unit's `Type=simple` is a **forward reference**: if/when the
  server learns `sd_notify`, the unit should move to `Type=notify` and the
  `deploy/systemd/README.md` note updated. That is a reversible, one-line
  change gated on the server-side feature.
- This decision is reversible. If native HA is descoped permanently, the
  prerequisite-epic framing here is retired and NATS becomes the documented
  permanent answer.
