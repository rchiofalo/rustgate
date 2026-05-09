// Copyright © 2026 Roberto Chiofalo.

//! Multi-sensor track correlation engine — closes #848.
//!
//! When the same physical object is reported by multiple sensors (an
//! ATAK position via CoT, a radar track over Link 16, a drone-camera
//! track over MAVLink, a DIS PDU from a simulator, a SAPIENT detection
//! from an autonomous sensor), an operator should see a *single* fused
//! entity on the map — not three or four duplicates. Without
//! correlation, AR/IVAS users in particular suffer: every duplicate is
//! a separate icon clipped into their field of view, which dilutes
//! situational awareness rather than improving it.
//!
//! This crate implements the algorithm from the technical analysis
//! tracked under #848:
//!
//! 1. **Spatial gating.** Two reports must lie within a configurable
//!    distance threshold of each other (defaults: 100 m for ground,
//!    500 m for air). Distance is computed on a flat-Earth small-angle
//!    approximation against [`fusion::haversine_distance_m`] at the
//!    fused entity's last known position — sufficient for the
//!    sub-kilometre gating distances this MVP cares about.
//! 2. **Temporal gating.** A new report must arrive inside the
//!    configured `time_window` (default 30 s) of the candidate fused
//!    entity's `last_update`. Stale fused entities are aged out by
//!    [`engine::CorrelationEngine::expire_stale`].
//! 3. **Kinematic consistency.** When both reports carry a velocity
//!    vector, their speeds must agree to within a tolerance
//!    (`kinematic_tolerance_mps`, default 25 m/s). The reports do *not*
//!    need a matching course — two sensors at different bearings on
//!    the same fast-mover will report symmetrically different courses
//!    while reporting the same speed.
//! 4. **Type compatibility.** Aircraft tracks cannot correlate with
//!    ground vehicle tracks, marine tracks, or munitions; ground tracks
//!    cannot correlate with aircraft or marine tracks; etc. A
//!    [`rustgate_core::entity::EntityKind::Unknown`] / `Track` /
//!    `Sensor` report is permissive — those variants represent
//!    operator uncertainty about the platform type and must not block
//!    fusion against a more-specific incoming report. See
//!    [`score::types_compatible`] for the full table.
//! 5. **Weighted scoring.** The four gates above feed into a single
//!    `[0.0, 1.0]` score via a weighted sum. The match threshold is
//!    fixed at `0.5` so a passing-but-marginal score correlates rather
//!    than spawning a duplicate fused entity.
//! 6. **Position fusion.** When a new report merges into an existing
//!    fused entity, the fused position is the *inverse-variance
//!    weighted* mean of the source positions. Reports that carry a
//!    `ce90` (circular error 90 %) attribute are weighted by
//!    `1 / ce90²`; reports that carry only `position_uncertainty_m`
//!    are weighted by `1 / σ²`; reports that carry neither fall back
//!    to newest-wins. Velocity is newest-wins (kinematics drift fast;
//!    averaging a stale report into a new one is harmful). Type is
//!    the highest-confidence (most specific) classification across
//!    sources.
//!
//! # Public API
//!
//! - [`CorrelationEngine`] — the core stateful object (a `DashMap`
//!   from [`FusedEntityId`] to [`FusedEntity`] plus an `RTree` spatial
//!   index keyed on `(lat, lon)`).
//! - [`CorrelationConfig`] — knobs for distance / time / kinematic
//!   thresholds, fusion weights, and the LRU cap.
//! - [`FusedEntity`] / [`SourceTrack`] / [`CorrelationOutcome`] —
//!   value types for the fused entity, its provenance list, and the
//!   verdict that [`CorrelationEngine::submit`] returns to the caller.
//! - [`router_callback`] — convenience constructor for an
//!   [`rustgate_router::OnRouted`] callback that funnels every routed
//!   `RoutableMessage` (with the entity decoded by the router's
//!   `EntityCodecRegistry`) into [`CorrelationEngine::submit`]. The
//!   server binary wires this in the same shape as the existing video-
//!   stream catalog.
//!
//! # What is deliberately deferred
//!
//! - **Track-history retention.** This MVP keeps only the latest
//!   report per source (the `SourceTrack.original_entity` field).
//!   Time-series persistence — the foundation of multi-hypothesis
//!   tracking and after-action review — lands in a follow-up issue
//!   alongside the durable archive integration.
//! - **Multi-hypothesis tracking (MHT).** When two candidate fused
//!   entities both score above the threshold for an incoming report,
//!   this engine picks the highest scorer rather than maintaining
//!   parallel hypotheses. MHT is the standard upgrade path; the
//!   single-best-match shape here is sufficient for the MVP's primary
//!   goal of de-duplicating same-object reports.
//! - **Full Kalman filter.** The position fusion is inverse-variance
//!   weighted but does not maintain a per-track covariance matrix
//!   updated by a Kalman gain. A tactical-grade tracker would; this
//!   MVP does not. Adding a covariance update is straightforward at
//!   the [`fusion::fuse_position`] boundary if a future PR needs it.
//! - **Cross-tenant isolation.** All reports flow into one
//!   correlation namespace. Multi-tenant deployments where Tenant A
//!   must not see Tenant B's tracks need a per-tenant
//!   [`CorrelationEngine`] keyed on
//!   [`rustgate_core::identity::Identity::tenant`] — the
//!   single-engine surface here is sufficient for the single-tenant
//!   default but not load-bearing.

#![forbid(unsafe_code)]
#![doc(html_no_source)]

pub mod config;
pub mod engine;
pub mod error;
pub mod fusion;
pub mod score;
pub mod types;

pub use config::{CorrelationConfig, FusionWeights, KindThresholds};
pub use engine::{CorrelationEngine, router_callback};
pub use error::CorrelationError;
pub use fusion::{fuse_classification, fuse_position, haversine_distance_m};
pub use score::{
    SCORE_MATCH_THRESHOLD, kinematic_score, spatial_score, temporal_score, type_score,
    types_compatible,
};
pub use types::{CorrelationOutcome, FusedEntity, FusedEntityId, RejectionReason, SourceTrack};
