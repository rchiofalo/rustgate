// Copyright © 2026 Roberto Chiofalo.

//! Value types shared across the correlation engine.
//!
//! `FusedEntity` is the deduplicated, fused representation of a
//! physical object reported by one or more sensors. Each per-sensor
//! contribution rides on a [`SourceTrack`]; the
//! [`FusedEntity::sources`] vector is the provenance trail. Operators
//! can audit "which sensors saw this aircraft?" by walking the sources
//! list — the [`SourceTrack::source_protocol`] field carries the
//! `metadata.source_protocol` string from the originating
//! [`rustgate_core::message::RoutableMessage`] (e.g. `"cot"`,
//! `"mavlink"`, `"link16"`).

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

use rustgate_core::entity::{Entity, EntityKind, Position, Velocity};
use serde::{Deserialize, Serialize};

/// Stable identifier for a [`FusedEntity`] within a
/// [`crate::engine::CorrelationEngine`].
///
/// IDs are monotonically increasing within an engine instance —
/// allocated by an internal atomic counter — and are not reused even
/// after eviction. They are *not* portable across engine instances or
/// process restarts; downstream consumers that need a stable wire ID
/// should re-key on the underlying `SourceTrack.original_entity.uid`
/// for the most-trusted source.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FusedEntityId(pub u64);

impl FusedEntityId {
    /// Allocate the next sequential ID against an atomic counter.
    /// Constructed by [`crate::engine::CorrelationEngine`] only —
    /// callers should not synthesise IDs by hand because the engine
    /// trusts the internal counter for uniqueness.
    pub(crate) fn next(counter: &AtomicU64) -> Self {
        Self(counter.fetch_add(1, Ordering::Relaxed))
    }
}

impl std::fmt::Display for FusedEntityId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "fused-{}", self.0)
    }
}

/// One sensor's contribution to a [`FusedEntity`].
///
/// The original [`Entity`] is preserved verbatim so a future
/// "explain why this fused" diagnostic can replay the inputs that
/// produced the merge. The `weight` field is the inverse-variance
/// fusion weight — see [`crate::fusion::position_weight`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceTrack {
    /// Stable identifier within the source protocol (e.g. CoT
    /// `<event uid>`, MAVLink `system_id/component_id` tuple).
    /// Lifted from [`rustgate_core::entity::Entity::uid`].
    pub source_id: String,
    /// `metadata.source_protocol` string for the originating message.
    /// Used to render "fused from CoT + Link 16" provenance traces.
    pub source_protocol: String,
    /// The decoded entity verbatim — preserves attributes (CE90,
    /// classification, callsign) so a re-fusion or replay can
    /// reconstruct the merge inputs.
    pub original_entity: Entity,
    /// Inverse-variance fusion weight. Larger means "trust this
    /// source's position more in the weighted average". Sources that
    /// publish neither `ce90` nor `position_uncertainty_m` get a
    /// fallback unit weight (`1.0`).
    pub weight: f64,
    /// Wall-clock instant the engine ingested this source's report.
    pub last_seen: SystemTime,
}

/// Deduplicated, fused representation of a physical object reported
/// by one or more sensors. Closes #848.
///
/// The `sources` vector is the provenance trail; `fused_position`,
/// `fused_kinematics`, and `fused_classification` are the merged
/// view that downstream consumers (the AR/IVAS overlay, the
/// commander's COP, federation egress) render. The `confidence` field
/// is the most recent score from [`crate::score`] — operators can
/// surface it to colour-code icons by fusion certainty.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FusedEntity {
    /// Engine-local stable ID. Re-allocated on creation; never
    /// reused on eviction.
    pub primary_id: FusedEntityId,
    /// One entry per sensor that has contributed to this fused
    /// entity. Iteration order is ingestion order.
    pub sources: Vec<SourceTrack>,
    /// Inverse-variance weighted mean of source positions, or
    /// newest-wins when no source carries a CE90 / uncertainty
    /// attribute. `None` only when no contributing source has a
    /// position (e.g. a chat-only message that nevertheless rode an
    /// `Entity` envelope).
    pub fused_position: Option<Position>,
    /// Newest-wins kinematics from the most recent contributing
    /// source. Stale-mean averaging would smear a fast-mover's
    /// trajectory across stale samples; Kalman smoothing is the
    /// upgrade path tracked under the deferred work in
    /// [`crate`].
    pub fused_kinematics: Option<Velocity>,
    /// Most-specific classification across contributing sources. A
    /// single `Aircraft` source overrides any number of `Track` /
    /// `Unknown` sources because the latter represent operator
    /// uncertainty rather than a positive identification.
    pub fused_classification: EntityKind,
    /// Wall-clock instant this fused entity was last touched (created
    /// or merged). The engine evicts entries older than `time_window`
    /// from the spatial index so subsequent reports cannot fuse
    /// against a stale fused entity.
    pub last_update: SystemTime,
    /// Most recent fusion score in `[0.0, 1.0]`. The score that
    /// produced the most recent merge (or `1.0` for a freshly created
    /// fused entity, since the original report is its only source).
    pub confidence: f64,
}

/// Verdict returned by [`crate::engine::CorrelationEngine::submit`]
/// for a single submitted [`Entity`].
///
/// Callers use the verdict to drive metrics and forensic logs. The
/// [`CorrelationOutcome::Rejected`] variant covers cases where the
/// engine refused to fuse for a non-error reason — e.g. a position
/// outside the WGS-84 envelope or a missing position field.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", content = "data", rename_all = "snake_case")]
pub enum CorrelationOutcome {
    /// No existing fused entity passed the gates; a new one was
    /// created. Carries its assigned [`FusedEntityId`].
    Created(FusedEntityId),
    /// An existing fused entity passed the gates; the new report was
    /// merged into it. Carries the existing fused entity's ID so the
    /// caller can correlate the merge against the previous outcome.
    Merged(FusedEntityId),
    /// Same physical sensor (same `source_id` and `source_protocol`)
    /// re-reported into an existing fused entity. Updates that source's
    /// most-recent observation but does not invoke the gating /
    /// scoring path again — the cheap fast path for a flood of
    /// position updates from one sensor.
    Updated(FusedEntityId),
    /// The engine refused to ingest the report. The
    /// [`RejectionReason`] explains why — used by audit / metrics
    /// callers to surface "we dropped a malformed report" without an
    /// `Err` propagation.
    Rejected(RejectionReason),
}

/// Reasons the engine may refuse to ingest a submitted report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum RejectionReason {
    /// The submitted entity carried no [`Position`] field. Without a
    /// position the engine cannot insert into the spatial index, so
    /// it cannot participate in correlation.
    MissingPosition,
    /// The position was outside the WGS-84 envelope. The codec is
    /// normally responsible for validation; the engine repeats the
    /// check at its boundary.
    InvalidPosition,
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn fused_entity_id_increments_monotonically() {
        let counter = AtomicU64::new(0);
        let a = FusedEntityId::next(&counter);
        let b = FusedEntityId::next(&counter);
        let c = FusedEntityId::next(&counter);
        assert_eq!(a.0, 0);
        assert_eq!(b.0, 1);
        assert_eq!(c.0, 2);
    }

    #[test]
    fn fused_entity_id_renders_with_human_readable_prefix() {
        let id = FusedEntityId(42);
        assert_eq!(format!("{id}"), "fused-42");
    }

    #[test]
    fn correlation_outcome_round_trips_through_serde_json() {
        let outcomes = [
            CorrelationOutcome::Created(FusedEntityId(1)),
            CorrelationOutcome::Merged(FusedEntityId(2)),
            CorrelationOutcome::Updated(FusedEntityId(3)),
            CorrelationOutcome::Rejected(RejectionReason::MissingPosition),
            CorrelationOutcome::Rejected(RejectionReason::InvalidPosition),
        ];
        for o in outcomes {
            let json = serde_json::to_string(&o).expect("serialise");
            let decoded: CorrelationOutcome = serde_json::from_str(&json).expect("deserialise");
            assert_eq!(decoded, o);
        }
    }
}
