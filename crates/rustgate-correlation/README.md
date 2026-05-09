# rustgate-correlation

Multi-sensor track correlation engine for rustgate. Closes #848.

## Role in the workspace

When the same physical object is reported by multiple sensors — an
ATAK position via CoT, a radar track over Link 16, a drone-camera
track over MAVLink, a DIS PDU from a simulator, a SAPIENT detection
from an autonomous sensor — the operator should see *one* fused
entity on the map, not N duplicates. This crate implements the
correlation engine the technical analysis Vol. II, Feature 7
specifies: spatial / temporal / kinematic / type gating, weighted
scoring, inverse-variance position fusion, and a bounded LRU cap.

The crate depends on `rustgate-core` (for the canonical `Entity`
shape) and `rustgate-router` (for the `OnRouted` callback type
alias). It pulls in `rstar` for the spatial index, `dashmap` for
sharded fused-entity storage, and `lru` for the eviction tracker.

## MVP scope

- `CorrelationEngine` — DashMap-backed fused-entity store, RTree
  spatial index, LRU recency tracker.
- `CorrelationConfig` — distance / time / kinematic / weights /
  cap knobs with per-kind spatial thresholds.
- `FusedEntity`, `SourceTrack`, `CorrelationOutcome` — value
  types representing a fused entity and the verdict per submit.
- `submit(entity)` — main entry point. Returns
  `Created` / `Merged` / `Updated` / `Rejected` based on the gate
  ladder.
- `query_at(lat, lon, radius_m)` — range query over fused
  entities, sorted by distance.
- `expire_stale(now)` — drop fused entities older than the
  configured time window.
- `router_callback(engine, registry)` — convenience constructor
  for the `OnRouted` callback shape used by the server binary's
  setup wiring.

## Public API surface

- `CorrelationEngine::new` / `with_config` — constructors.
- `CorrelationEngine::submit` / `submit_at` — submit a report,
  receive a `CorrelationOutcome` verdict.
- `CorrelationEngine::query_at` — spatial range query.
- `CorrelationEngine::snapshot` — return all currently-tracked
  fused entities (for the admin HTTP endpoint).
- `CorrelationEngine::expire_stale` — drop entries older than
  `time_window`.
- Scoring primitives: `spatial_score`, `temporal_score`,
  `kinematic_score`, `type_score`, `types_compatible`,
  `SCORE_MATCH_THRESHOLD`.
- Fusion primitives: `fuse_position`, `fuse_classification`,
  `haversine_distance_m`.

## Algorithm overview

1. **Spatial gating** — distance from the incoming report to the
   candidate fused entity, against a per-kind threshold (defaults:
   100 m ground, 500 m air, 250 m marine).
2. **Temporal gating** — wall-clock delta against the configured
   `time_window` (default 30 s).
3. **Kinematic consistency** — Δspeed against the configured
   tolerance (default 25 m/s); course is not gated.
4. **Type compatibility** — aircraft × ground = incompatible;
   permissive variants (`Track`, `Sensor`, `Unknown`) fuse with
   any specific kind.
5. **Weighted scoring** — total = `Σ w_i * s_i` where the four
   `s_i` are the gates above; matches require
   `total >= SCORE_MATCH_THRESHOLD` (`0.5`).
6. **Position fusion** — inverse-variance weighted mean using
   `correlation.ce90` / `correlation.position_uncertainty_m` /
   `cot.ce` attributes when published, fallback newest-wins.
7. **Classification fusion** — most-specific kind across sources;
   permissive variants do not override positive IDs.
8. **LRU eviction** — when the engine reaches `max_entities`
   (default 100 000), the least-recently-updated fused entity is
   dropped to make room for the new one.

## Feature flags

This crate is always built when included as a workspace member.
The optional `correlation` feature on `rustgate-server` toggles the
integration layer (router callback registration, admin HTTP
endpoint) — that wiring lives in the server binary, not here.

## What is deliberately deferred

- **Track-history retention.** The MVP keeps only the latest
  report per source. Time-series persistence (the foundation of
  multi-hypothesis tracking and after-action review) lands in a
  follow-up.
- **Multi-hypothesis tracking (MHT).** When two candidates both
  score above threshold, the engine picks the highest scorer
  rather than maintaining parallel hypotheses.
- **Full Kalman filter.** Position fusion is inverse-variance
  weighted but does not maintain a per-track covariance matrix
  with a Kalman gain update.
- **Cross-tenant isolation.** All reports flow into one engine.
  Multi-tenant deployments needing isolation should construct one
  engine per tenant and key on `Identity::tenant`.
