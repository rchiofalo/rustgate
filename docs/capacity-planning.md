# Capacity Planning

This page helps you size a rustgate deployment: how much memory and CPU a
given client count needs, and how the admission-control knobs bound
worst-case resource use.

> **Estimate, not a benchmark.** The numbers below are **engineering
> estimates derived from the configured limits**, not measurements from a
> load-test rig. They are safe to use for initial sizing and for setting the
> admission-control ceilings, but treat them as upper/lower bounds to
> validate against your own traffic, not as guaranteed throughput. When a
> load-test harness lands (tracked as the benchmark follow-up to
> [ADR 0031](adr/0031-production-hardening-ha-and-edge.md)), this page will
> be updated with measured figures and the estimate label removed.

## The knobs that bound resource use

rustgate's memory ceiling is set by admission control, not by client count
directly. Three flags matter most:

| Flag | Default | What it bounds |
|------|---------|----------------|
| `--max-queued-bytes` | 512 MiB | Total in-flight queued bytes across **all** sessions. When crossed, the accept loop is deferred (new connections wait) until the counter drops below the low-water mark. This is the hard memory ceiling for the message-queue tier. |
| `--max-connections` | 1024 | Maximum simultaneous client connections (backs a semaphore). Excess connections wait for a slot. |
| `--max-concurrent-handshakes` | 100 | Maximum TLS handshakes in flight at once. Bounds CPU during connection floods; excess handshakes queue. |

Two related defaults live in the transport layer rather than the CLI:

- Per-session queue: bounded `mpsc`; when full, messages go to
  store-and-forward (if enabled) or are dropped (counted by
  `rustgate_client_queue_drops_total`).
- `DEFAULT_MAX_QUEUED_BYTES = 512 MiB` is the source of the CLI default
  above; the low-water mark defaults to 90% of the high-water mark.

**Key consequence:** total queue memory is capped at `--max-queued-bytes`
**regardless of client count**. Adding clients past the point where the
queue is full does not grow queue memory — it triggers admission deferral
(`rustgate_admission_deferred_total`) and, for slow readers, client-queue
drops. Size `--max-queued-bytes` to the memory you are willing to dedicate
to buffering, then size the pod so that ceiling plus per-connection overhead
fits.

## Per-client overhead (estimate)

| Component | Estimate per connected client | Notes |
|-----------|-------------------------------|-------|
| TLS session + buffers | ~64–128 KiB | rustls session state, read/write buffers |
| Per-session queue headroom | up to the mpsc bound | Shared against the global `--max-queued-bytes` ceiling |
| Task / bookkeeping | ~8–16 KiB | Per-session tokio task, identity, metadata |

Steady-state per-client RAM (excluding queued message backlog) is on the
order of **~100–200 KiB**. The queued-message backlog is **not** per-client
additive — it is globally capped by `--max-queued-bytes`.

## Worked example: 5,000 clients

Target: 5,000 connected tactical clients, position-update-heavy traffic.

1. **Connections.** Raise `--max-connections` above the client count with
   headroom for reconnect churn: `--max-connections 6000`.
2. **Queue ceiling.** Position updates are small (hundreds of bytes to a few
   KiB). Keep the default `--max-queued-bytes 512 MiB` unless you see
   sustained `rustgate_admission_deferred_total` — that is the signal to
   raise it (and the pod memory) or to enable store-and-forward.
3. **Handshake concurrency.** 5,000 clients reconnecting after a network
   blip is a handshake flood. The default `--max-concurrent-handshakes 100`
   bounds CPU; raise to `256` on multi-core nodes if reconnect storms take
   too long to drain, watching CPU.
4. **Memory.** Per-client overhead 5,000 × ~150 KiB ≈ **~0.75 GiB**, plus
   the 512 MiB queue ceiling, plus runtime/heap overhead. Budget **~2 GiB**
   RAM for headroom.
5. **CPU.** Steady-state routing is cheap; the cost centres are TLS
   handshakes (reconnect storms) and codec work. Budget **2–4 vCPU** for
   5,000 position-heavy clients and scale on observed CPU during reconnect
   events, not steady state.

## Client-count → resource table (estimate)

Figures are per-instance estimates for position-update-heavy traffic,
single pod, no store-and-forward backlog. Validate against your traffic.

| Clients | `--max-connections` | `--max-queued-bytes` | RAM (budget) | CPU (budget) | Pod size |
|---------|---------------------|----------------------|--------------|--------------|----------|
| 500 | 1024 (default) | 512 MiB (default) | ~1 GiB | 1 vCPU | small |
| 2,000 | 2500 | 512 MiB | ~1.5 GiB | 1–2 vCPU | small–medium |
| 5,000 | 6000 | 512 MiB | ~2 GiB | 2–4 vCPU | medium |
| 10,000 | 12000 | 1 GiB | ~4 GiB | 4–8 vCPU | large |
| 20,000+ | shard across pods | 1 GiB per pod | ~4 GiB per pod | 4–8 vCPU per pod | horizontal scale |

Beyond ~10,000 clients per instance, prefer **horizontal scaling** (more
pods behind the load balancer, federation between them) over a single large
pod: it bounds blast radius on a pod restart and keeps handshake floods
per-pod. See [`docs/deployment.md`](deployment.md) for the Helm HPA config
and [`docs/federation.md`](federation.md) for cross-pod message flow.

## What to watch

These series (already emitted; see
[`docs/metrics-reference.md`](metrics-reference.md)) tell you when a pod is
under-provisioned:

- `rustgate_admission_deferred_total` rising → queue ceiling reached; raise
  `--max-queued-bytes` and RAM, or enable store-and-forward.
- `rustgate_client_queue_drops_total` rising → slow readers dropping
  messages; investigate client links, not server size.
- `rustgate_handshake_failures_total` / `rustgate_negotiations_total` ratio
  high → CA/CRL/cert problem, not capacity.
- CPU saturation during reconnect storms → raise
  `--max-concurrent-handshakes` and vCPU.

The reference SLO and burn-rate rules in
[`ops/prometheus/slo.rules.yml`](../ops/prometheus/slo.rules.yml) alert on
the availability and drop budgets these series feed.
