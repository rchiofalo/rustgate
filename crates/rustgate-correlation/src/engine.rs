// Copyright © 2026 Roberto Chiofalo.

//! Stateful correlation engine — the [`CorrelationEngine`] entry point.
//!
//! The engine owns three pieces of state:
//!
//! 1. A [`DashMap`] from [`FusedEntityId`] to [`FusedEntity`] — the
//!    set of fused entities the engine is currently tracking. Sharded
//!    inside `dashmap` so concurrent submits / queries do not
//!    serialise on a single mutex.
//! 2. An `RTree<EntityRef>` spatial index over the fused entities'
//!    last-known positions. The R-tree is rebuilt incrementally on
//!    submit / merge / expire, kept under a `parking_lot::RwLock` so
//!    the spatial query can run with shared access while submit
//!    holds exclusive access only across the index mutation.
//! 3. An `lru::LruCache` recency tracker keyed on
//!    [`FusedEntityId`]. Used to pick an eviction victim when the
//!    map reaches `max_entities`. Held behind a `parking_lot::Mutex`
//!    because LRU operations mutate the underlying linked list on
//!    every read.
//!
//! Submission flow ([`CorrelationEngine::submit`]):
//!
//! 1. Validate the incoming [`Entity`] has a position inside the WGS-84
//!    envelope.
//! 2. Look up an existing fused entity to merge into:
//!    * Same-source fast path: if any fused entity already has a
//!      [`SourceTrack`] with the same `(source_id, source_protocol)`
//!      pair, treat the incoming report as an
//!      [`CorrelationOutcome::Updated`] — refresh the source's
//!      `last_seen` and the fused entity's last-known position
//!      without running the gate ladder again.
//!    * Spatial query: find every fused entity whose last-known
//!      position is within the (kind-derived) gating distance of the
//!      incoming report. Score each candidate against the spatial /
//!      temporal / kinematic / type weights; pick the highest-scoring
//!      candidate that passes the type gate and clears
//!      [`SCORE_MATCH_THRESHOLD`].
//! 3. If a match is found, merge: append a new [`SourceTrack`],
//!    recompute the fused position, classification, kinematics,
//!    update `last_update` and `confidence`, and bump the LRU.
//! 4. If no match is found, create a new [`FusedEntity`]. If the new
//!    entity would push the map past `max_entities`, evict the LRU
//!    victim before inserting.
//!
//! All paths return a [`CorrelationOutcome`] verdict — see the
//! variant docs for what each means.

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::SystemTime;

use dashmap::DashMap;
use lru::LruCache;
use parking_lot::{Mutex, RwLock};
use rstar::{AABB, PointDistance, RTree, RTreeObject};
use rustgate_core::entity::{Entity, EntityKind, Position};
use rustgate_core::message::RoutableMessage;

use crate::config::{CorrelationConfig, FusionWeights, KindThresholds};
use crate::fusion::{fuse_classification, fuse_position, position_weight};
use crate::score::{
    SCORE_MATCH_THRESHOLD, kinematic_score, spatial_score, temporal_score, type_score,
    types_compatible,
};
use crate::types::{CorrelationOutcome, FusedEntity, FusedEntityId, RejectionReason, SourceTrack};

/// Cap on the number of candidate fused entities the spatial query
/// returns from one r-tree lookup. R-tree range queries can pull
/// large neighbourhoods on cluttered scenes (an air-corridor with
/// tens of nearby tracks); bounding the candidate set keeps the
/// scoring loop O(1) per submit on the worst case while still
/// producing a high-quality match for the realistic case (a handful
/// of nearby fused entities).
const MAX_SPATIAL_CANDIDATES: usize = 16;

/// `RTreeObject` shim wrapping a fused entity ID with the position
/// the index is currently keyed on. The `RTree` stores these by
/// value (Copy); the actual `FusedEntity` lives in the
/// [`CorrelationEngine::entities`] `DashMap` for a single source of
/// truth.
#[derive(Debug, Clone, Copy, PartialEq)]
struct EntityRef {
    id: FusedEntityId,
    /// Position keyed on `[longitude, latitude]` so the r-tree's
    /// AABB-based queries operate in degrees-x-degrees space. The
    /// engine converts the metre-distance gating threshold into a
    /// degrees-bounding-box at query time.
    point: [f64; 2],
}

impl RTreeObject for EntityRef {
    type Envelope = AABB<[f64; 2]>;

    fn envelope(&self) -> Self::Envelope {
        AABB::from_point(self.point)
    }
}

impl PointDistance for EntityRef {
    fn distance_2(&self, point: &[f64; 2]) -> f64 {
        let dx = self.point[0] - point[0];
        let dy = self.point[1] - point[1];
        dx * dx + dy * dy
    }
}

/// Multi-sensor correlation engine. Closes #848.
///
/// Construct with [`CorrelationEngine::new`] (uses
/// [`CorrelationConfig::default`]) or [`CorrelationEngine::with_config`]
/// to override individual thresholds. The engine is `Send + Sync`
/// and cloneable behind `Arc` — all internal state is sharded /
/// guarded so the same engine can be wired into the router callback
/// path *and* exposed to an HTTP query handler at the same time.
pub struct CorrelationEngine {
    /// Source of truth for all currently-tracked fused entities.
    entities: DashMap<FusedEntityId, FusedEntity>,
    /// Spatial index for "find candidate fused entities near this
    /// new report" queries. Rebuilt on every mutation; for the MVP
    /// this is acceptable because the index is small (bounded by
    /// `max_entities`) and the rebuild is bulk-load O(N).
    spatial: RwLock<RTree<EntityRef>>,
    /// LRU recency tracker. Bumped on every submit / merge so
    /// eviction picks the *least recently updated* fused entity
    /// rather than the oldest by `last_update` (the two diverge when
    /// an old entity gets a fresh report).
    lru: Mutex<LruCache<FusedEntityId, ()>>,
    /// Monotonic counter for [`FusedEntityId`] allocation.
    counter: AtomicU64,
    /// Operator-tunable thresholds and fusion weights.
    config: CorrelationConfig,
}

impl std::fmt::Debug for CorrelationEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CorrelationEngine")
            .field("entities", &self.entities.len())
            .field("max_entities", &self.config.max_entities)
            .finish()
    }
}

impl CorrelationEngine {
    /// Construct an engine with [`CorrelationConfig::default`].
    pub fn new() -> Self {
        Self::with_config(CorrelationConfig::default())
    }

    /// Construct an engine with operator-supplied configuration.
    pub fn with_config(config: CorrelationConfig) -> Self {
        let cap = NonZeroUsize::new(config.max_entities.max(1))
            .expect("max(1) is non-zero by construction");
        Self {
            entities: DashMap::new(),
            spatial: RwLock::new(RTree::new()),
            lru: Mutex::new(LruCache::new(cap)),
            counter: AtomicU64::new(0),
            config,
        }
    }

    /// Number of fused entities currently tracked. Surfaced for
    /// metrics and health checks.
    pub fn len(&self) -> usize {
        self.entities.len()
    }

    /// `true` when the engine has no fused entities. Mirrors the
    /// `Vec::is_empty` shape so the type can stand in for a
    /// collection in operator-facing diagnostics.
    pub fn is_empty(&self) -> bool {
        self.entities.is_empty()
    }

    /// Snapshot every currently-tracked fused entity. Cloned —
    /// callers that need a streaming surface should reach for the
    /// future async-iterator API rather than this snapshot. For the
    /// MVP an HTTP handler at `/api/correlation/fused-entities`
    /// drives this once per request, which is acceptable for the
    /// `max_entities` cap of 100 000.
    pub fn snapshot(&self) -> Vec<FusedEntity> {
        self.entities.iter().map(|e| e.value().clone()).collect()
    }

    /// Range query — return every currently-tracked fused entity
    /// whose last-known position lies within `radius_m` of
    /// `(lat, lon)`. Sorted by ascending distance.
    pub fn query_at(&self, lat: f64, lon: f64, radius_m: f64) -> Vec<FusedEntity> {
        let degrees = metres_to_degrees(radius_m, lat);
        let envelope = AABB::from_corners(
            [lon - degrees.lon_deg, lat - degrees.lat_deg],
            [lon + degrees.lon_deg, lat + degrees.lat_deg],
        );
        let candidates: Vec<EntityRef> = {
            let guard = self.spatial.read();
            guard.locate_in_envelope(&envelope).copied().collect()
        };
        let mut results: Vec<(f64, FusedEntity)> = candidates
            .into_iter()
            .filter_map(|r| {
                let entity = self.entities.get(&r.id)?.value().clone();
                let pos = entity.fused_position?;
                let d = crate::fusion::haversine_distance_m(lat, lon, pos.lat, pos.lon);
                if d <= radius_m {
                    Some((d, entity))
                } else {
                    None
                }
            })
            .collect();
        results.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));
        results.into_iter().map(|(_, e)| e).collect()
    }

    /// Submit an [`Entity`] for correlation. Returns the verdict —
    /// see [`CorrelationOutcome`] for variant semantics.
    ///
    /// Soft-rejection paths (missing position, invalid lat/lon)
    /// return [`CorrelationOutcome::Rejected`] instead of an
    /// `Err`; the router callback path treats these as a
    /// `tracing::debug!` non-event so a single bad codec output
    /// cannot poison the routing critical path.
    pub fn submit(&self, entity: Entity) -> CorrelationOutcome {
        self.submit_at(entity, SystemTime::now())
    }

    /// Variant of [`Self::submit`] with an explicit ingestion
    /// timestamp. Used by tests to drive deterministic temporal
    /// gating without sleeping; production callers stick with
    /// [`Self::submit`].
    pub fn submit_at(&self, entity: Entity, now: SystemTime) -> CorrelationOutcome {
        let Some(pos) = entity.position else {
            return CorrelationOutcome::Rejected(RejectionReason::MissingPosition);
        };
        if !position_in_wgs84(&pos) {
            return CorrelationOutcome::Rejected(RejectionReason::InvalidPosition);
        }

        // Same-source fast path. A flood of position updates from
        // one sensor must not trigger a gate-ladder evaluation per
        // message — refresh the source's last_seen + recompute the
        // fused position and bump LRU.
        if let Some(id) = self.find_same_source(&entity) {
            self.update_source(id, entity, now);
            return CorrelationOutcome::Updated(id);
        }

        // Score every spatial candidate; pick the highest scorer
        // that passes the type gate and clears the threshold.
        let kind = entity.kind.clone();
        let candidates = self.spatial_candidates(pos, threshold_for_kind(&kind, &self.config));
        let weights = renormalised_weights(&self.config.fusion_weights);
        let mut best: Option<(FusedEntityId, f64)> = None;
        for cand_id in candidates {
            let Some(cand) = self.entities.get(&cand_id) else {
                continue;
            };
            // Type-compatibility hard gate. The score equivalent is
            // also computed below, but skipping here saves the rest
            // of the score arithmetic on a guaranteed-zero match.
            if !types_compatible(&kind, &cand.fused_classification) {
                continue;
            }
            // Temporal hard gate. A fused entity older than the
            // configured `time_window` is no longer eligible to fuse
            // — the matching report should spawn a fresh fused entity
            // instead, mirroring the [`Self::expire_stale`] policy.
            // Without this gate, a spatial+type+kinematic-perfect new
            // report would push an arbitrarily stale candidate's
            // total above the threshold even when its temporal score
            // is exactly zero. Closes the same-coords-but-very-old
            // false-positive case.
            let elapsed = now
                .duration_since(cand.last_update)
                .or_else(|_| cand.last_update.duration_since(now))
                .unwrap_or_default();
            if elapsed > self.config.time_window {
                continue;
            }
            let Some(cand_pos) = cand.fused_position else {
                continue;
            };
            let s_spatial = spatial_score(&pos, &cand_pos, threshold_for_kind(&kind, &self.config));
            let s_temporal = temporal_score(now, cand.last_update, self.config.time_window);
            let s_kinematic = kinematic_score(
                entity.velocity.as_ref(),
                cand.fused_kinematics.as_ref(),
                self.config.kinematic_tolerance_mps,
            );
            let s_type = type_score(&kind, &cand.fused_classification);
            let total = weights.spatial * s_spatial
                + weights.temporal * s_temporal
                + weights.kinematic * s_kinematic
                + weights.r#type * s_type;
            // Drop the read guard before any potential writeback.
            drop(cand);
            if total >= SCORE_MATCH_THRESHOLD
                && best.as_ref().is_none_or(|(_, score)| total > *score)
            {
                best = Some((cand_id, total));
            }
        }

        if let Some((id, score)) = best {
            self.merge_into(id, entity, now, score);
            return CorrelationOutcome::Merged(id);
        }

        let id = self.create_new(entity, now);
        CorrelationOutcome::Created(id)
    }

    /// Drop fused entities whose `last_update` is older than the
    /// configured `time_window`. Returns the number of entries
    /// evicted. Operators can wire this in a tokio interval task
    /// for a regular sweep; this MVP does not spawn one internally
    /// because doing so would couple the engine to a tokio runtime
    /// for a job that is cheap to run from any caller.
    pub fn expire_stale(&self, now: SystemTime) -> usize {
        let cutoff = self.config.time_window;
        let to_evict: Vec<FusedEntityId> = self
            .entities
            .iter()
            .filter_map(|e| {
                let elapsed = now
                    .duration_since(e.value().last_update)
                    .unwrap_or_default();
                if elapsed > cutoff {
                    Some(*e.key())
                } else {
                    None
                }
            })
            .collect();
        let count = to_evict.len();
        for id in to_evict {
            let _ = self.entities.remove(&id);
            let _ = self.lru.lock().pop(&id);
        }
        if count > 0 {
            self.rebuild_spatial();
        }
        count
    }

    fn spatial_candidates(&self, report: Position, threshold_m: f64) -> Vec<FusedEntityId> {
        let degrees = metres_to_degrees(threshold_m, report.lat);
        let envelope = AABB::from_corners(
            [report.lon - degrees.lon_deg, report.lat - degrees.lat_deg],
            [report.lon + degrees.lon_deg, report.lat + degrees.lat_deg],
        );
        let guard = self.spatial.read();
        guard
            .locate_in_envelope(&envelope)
            .take(MAX_SPATIAL_CANDIDATES)
            .map(|r| r.id)
            .collect()
    }

    fn find_same_source(&self, entity: &Entity) -> Option<FusedEntityId> {
        // A source is identified by the tuple (source_id, source_protocol):
        // the same wire UID arriving over two different protocols is two
        // distinct sensors, not one. Matching on source_id alone (#1501) would
        // wrongly treat a DIS entity 1234 and a VMF entity 1234 as updates of
        // each other instead of independent tracks to correlate/fuse.
        let proto = source_protocol_attr(entity).unwrap_or_else(|| "unknown".to_string());
        for cand in self.entities.iter() {
            for src in &cand.value().sources {
                if src.source_id == entity.uid && src.source_protocol == proto {
                    return Some(*cand.key());
                }
            }
        }
        None
    }

    fn update_source(&self, id: FusedEntityId, entity: Entity, now: SystemTime) {
        if let Some(mut fused) = self.entities.get_mut(&id) {
            let proto = source_protocol_attr(&entity).unwrap_or_else(|| "unknown".to_string());
            let weight = position_weight(&entity);
            let mut replaced = false;
            for src in fused.sources.iter_mut() {
                // Same (source_id, source_protocol) — replace this source's
                // track in place (see `find_same_source`).
                if src.source_id == entity.uid && src.source_protocol == proto {
                    src.original_entity = entity.clone();
                    src.weight = weight;
                    src.last_seen = now;
                    replaced = true;
                    break;
                }
            }
            if !replaced {
                // Defensive: if the source vanished between
                // find_same_source and the write, append it (with its real
                // protocol so a later update matches it correctly).
                fused.sources.push(SourceTrack {
                    source_id: entity.uid.clone(),
                    source_protocol: proto,
                    original_entity: entity.clone(),
                    weight,
                    last_seen: now,
                });
            }
            if let Some(pos) = fuse_position(&fused.sources) {
                fused.fused_position = Some(pos);
            }
            if let Some(vel) = entity.velocity {
                fused.fused_kinematics = Some(vel);
            }
            fused.fused_classification = fuse_classification(&fused.sources);
            fused.last_update = now;
        }
        self.bump_lru(id);
        self.rebuild_spatial();
    }

    fn merge_into(&self, id: FusedEntityId, entity: Entity, now: SystemTime, score: f64) {
        let weight = position_weight(&entity);
        if let Some(mut fused) = self.entities.get_mut(&id) {
            fused.sources.push(SourceTrack {
                source_id: entity.uid.clone(),
                source_protocol: source_protocol_attr(&entity)
                    .unwrap_or_else(|| "unknown".to_string()),
                original_entity: entity.clone(),
                weight,
                last_seen: now,
            });
            if let Some(pos) = fuse_position(&fused.sources) {
                fused.fused_position = Some(pos);
            }
            if let Some(vel) = entity.velocity {
                fused.fused_kinematics = Some(vel);
            }
            fused.fused_classification = fuse_classification(&fused.sources);
            fused.last_update = now;
            fused.confidence = score;
        }
        self.bump_lru(id);
        self.rebuild_spatial();
    }

    fn create_new(&self, entity: Entity, now: SystemTime) -> FusedEntityId {
        // Eviction first so the new entry never pushes us above the
        // configured cap.
        if self.entities.len() >= self.config.max_entities
            && let Some(victim) = self.lru.lock().pop_lru().map(|(id, _)| id)
        {
            let _ = self.entities.remove(&victim);
        }
        let weight = position_weight(&entity);
        let pos = entity.position;
        let velocity = entity.velocity;
        let kind = entity.kind.clone();
        let id = FusedEntityId::next(&self.counter);
        let source = SourceTrack {
            source_id: entity.uid.clone(),
            source_protocol: source_protocol_attr(&entity).unwrap_or_else(|| "unknown".to_string()),
            original_entity: entity,
            weight,
            last_seen: now,
        };
        let fused = FusedEntity {
            primary_id: id,
            sources: vec![source],
            fused_position: pos,
            fused_kinematics: velocity,
            fused_classification: kind,
            last_update: now,
            // First report — by definition no scoring happened, so
            // the engine reports full confidence.
            confidence: 1.0,
        };
        let _ = self.entities.insert(id, fused);
        let _ = self.lru.lock().put(id, ());
        self.rebuild_spatial();
        id
    }

    fn bump_lru(&self, id: FusedEntityId) {
        let _ = self.lru.lock().get(&id);
    }

    fn rebuild_spatial(&self) {
        let refs: Vec<EntityRef> = self
            .entities
            .iter()
            .filter_map(|e| {
                let pos = e.value().fused_position?;
                Some(EntityRef {
                    id: *e.key(),
                    point: [pos.lon, pos.lat],
                })
            })
            .collect();
        let mut guard = self.spatial.write();
        *guard = RTree::bulk_load(refs);
    }
}

impl Default for CorrelationEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of converting a metre distance into the latitude /
/// longitude bounding-box increments that contain it. Used by the
/// spatial-query path to translate a metre-scale gating threshold
/// into the degrees-x-degrees envelope an `RTree` query expects.
#[derive(Debug, Clone, Copy)]
struct DegreeEnvelope {
    lat_deg: f64,
    lon_deg: f64,
}

fn metres_to_degrees(metres: f64, lat: f64) -> DegreeEnvelope {
    // 1° latitude ≈ 111_320 m everywhere; 1° longitude is
    // ~111_320 * cos(lat) m. Cap the longitude expansion at the
    // pole-degenerate case so a query at very high latitude does
    // not blow up the envelope.
    let lat_deg = metres / 111_320.0;
    let cos_lat = lat.to_radians().cos().abs().max(1e-6);
    let lon_deg = metres / (111_320.0 * cos_lat);
    DegreeEnvelope { lat_deg, lon_deg }
}

fn position_in_wgs84(p: &Position) -> bool {
    p.lat.is_finite()
        && p.lon.is_finite()
        && (-90.0..=90.0).contains(&p.lat)
        && (-180.0..=180.0).contains(&p.lon)
}

fn threshold_for_kind(kind: &EntityKind, config: &CorrelationConfig) -> f64 {
    match kind {
        EntityKind::Aircraft | EntityKind::Munition => config.distance_threshold_m.air,
        EntityKind::Ground => config.distance_threshold_m.ground,
        EntityKind::Marine => config.distance_threshold_m.marine,
        _ => config.distance_threshold_m.default,
    }
}

fn renormalised_weights(weights: &FusionWeights) -> FusionWeights {
    let sum = weights.sum();
    if sum <= 0.0 {
        return FusionWeights::default();
    }
    FusionWeights {
        spatial: weights.spatial / sum,
        temporal: weights.temporal / sum,
        kinematic: weights.kinematic / sum,
        r#type: weights.r#type / sum,
    }
}

fn source_protocol_attr(entity: &Entity) -> Option<String> {
    use rustgate_core::entity::AttributeValue;
    match entity.attributes.get("correlation.source_protocol")? {
        AttributeValue::Str(s) => Some(s.clone()),
        _ => None,
    }
}

/// Convenience constructor for an [`rustgate_router::OnRouted`]
/// callback that funnels every routed [`RoutableMessage`] through
/// the supplied engine. Mirrors the shape used by the video stream
/// catalog wiring (`rustgate_admin::video::router_callback`).
///
/// The callback decodes the `RoutableMessage`'s payload via the
/// router-installed [`rustgate_core::entity::EntityCodecRegistry`]
/// (passed in here so the engine does not pull a transport-layer
/// dep). When no codec is registered for the message's
/// `metadata.source_protocol`, the message is silently ignored —
/// the engine has nothing to fuse without a decoded entity.
pub fn router_callback(
    engine: Arc<CorrelationEngine>,
    registry: Arc<rustgate_core::entity::EntityCodecRegistry>,
) -> rustgate_router::OnRouted {
    Arc::new(move |msg: Arc<RoutableMessage>| {
        let Some(codec) = registry.get(&msg.metadata.source_protocol) else {
            return;
        };
        let entity = match codec.to_entity_dyn(&msg.payload) {
            Ok(entity) => entity,
            Err(err) => {
                tracing::debug!(
                    error = %err,
                    proto = %msg.metadata.source_protocol,
                    "correlation: codec rejected payload",
                );
                return;
            }
        };
        let outcome = engine.submit(entity);
        tracing::debug!(?outcome, "correlation submit");
    })
}

/// Compatibility helper used by [`KindThresholds::default`] tests
/// upstream of this module — pin the public surface so callers can
/// rely on the shape.
pub fn _kind_thresholds_compile_check() -> KindThresholds {
    KindThresholds::default()
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use std::collections::BTreeMap;
    use std::time::Duration;

    use rustgate_core::entity::{AttributeValue, Entity, EntityKind, Position, Velocity};

    use super::*;

    fn entity(uid: &str, kind: EntityKind, lat: f64, lon: f64) -> Entity {
        Entity {
            uid: uid.into(),
            kind,
            position: Some(Position {
                lat,
                lon,
                hae_meters: None,
            }),
            velocity: None,
            timestamp: SystemTime::UNIX_EPOCH,
            callsign: None,
            mil_std_2525_sidc: None,
            attributes: BTreeMap::new(),
            taskings: Default::default(),
            files: Default::default(),
        }
    }

    #[test]
    fn submit_creates_new_fused_entity_for_first_report() {
        let engine = CorrelationEngine::new();
        let outcome = engine.submit(entity("a", EntityKind::Ground, 38.0, -77.0));
        assert!(matches!(outcome, CorrelationOutcome::Created(_)));
        assert_eq!(engine.len(), 1);
    }

    #[test]
    fn submit_rejects_entity_without_position() {
        let engine = CorrelationEngine::new();
        let mut e = entity("a", EntityKind::Ground, 0.0, 0.0);
        e.position = None;
        let outcome = engine.submit(e);
        assert_eq!(
            outcome,
            CorrelationOutcome::Rejected(RejectionReason::MissingPosition)
        );
    }

    #[test]
    fn submit_rejects_invalid_position() {
        let engine = CorrelationEngine::new();
        let outcome = engine.submit(entity("a", EntityKind::Ground, 91.0, 0.0));
        assert_eq!(
            outcome,
            CorrelationOutcome::Rejected(RejectionReason::InvalidPosition)
        );
    }

    #[test]
    fn submit_merges_two_close_reports_of_same_kind() {
        let engine = CorrelationEngine::new();
        // Two CoT-shaped reports within ~10 m of each other.
        let now = SystemTime::UNIX_EPOCH;
        let _ = engine.submit_at(entity("a", EntityKind::Ground, 38.0, -77.0), now);
        let outcome = engine.submit_at(entity("b", EntityKind::Ground, 38.000050, -77.000050), now);
        assert!(
            matches!(outcome, CorrelationOutcome::Merged(_)),
            "expected merge, got {outcome:?}",
        );
        assert_eq!(engine.len(), 1, "no new fused entity should have spawned");
    }

    #[test]
    fn submit_does_not_merge_incompatible_kinds() {
        let engine = CorrelationEngine::new();
        let now = SystemTime::UNIX_EPOCH;
        let _ = engine.submit_at(entity("a", EntityKind::Aircraft, 38.0, -77.0), now);
        let outcome = engine.submit_at(entity("b", EntityKind::Ground, 38.0, -77.0), now);
        // Aircraft × Ground = type-incompatible -> separate fused entity.
        assert!(matches!(outcome, CorrelationOutcome::Created(_)));
        assert_eq!(engine.len(), 2);
    }

    #[test]
    fn submit_same_source_id_is_an_update_not_a_merge() {
        let engine = CorrelationEngine::new();
        let now = SystemTime::UNIX_EPOCH;
        let outcome1 = engine.submit_at(entity("a", EntityKind::Ground, 38.0, -77.0), now);
        let id_created = match outcome1 {
            CorrelationOutcome::Created(id) => id,
            other => panic!("expected Created, got {other:?}"),
        };
        let outcome2 = engine.submit_at(
            entity("a", EntityKind::Ground, 38.000010, -77.000010),
            now + Duration::from_secs(1),
        );
        assert_eq!(outcome2, CorrelationOutcome::Updated(id_created));
        assert_eq!(engine.len(), 1);
    }

    #[test]
    fn submit_same_uid_different_protocol_is_a_distinct_source_not_an_update() {
        use rustgate_core::entity::AttributeValue;
        let engine = CorrelationEngine::new();
        let now = SystemTime::UNIX_EPOCH;

        let mut dis = entity("a", EntityKind::Ground, 38.0, -77.0);
        let _ = dis.attributes.insert(
            "correlation.source_protocol".to_string(),
            AttributeValue::Str("dis".into()),
        );
        let id = match engine.submit_at(dis, now) {
            CorrelationOutcome::Created(id) => id,
            other => panic!("expected Created, got {other:?}"),
        };

        // Same wire UID "a" but a DIFFERENT protocol (vmf) at the same spot is
        // a SEPARATE sensor: it must fuse as a distinct source, not silently
        // update the dis track in place as if it were the same source (#1501).
        let mut vmf = entity("a", EntityKind::Ground, 38.000010, -77.000010);
        let _ = vmf.attributes.insert(
            "correlation.source_protocol".to_string(),
            AttributeValue::Str("vmf".into()),
        );
        let outcome = engine.submit_at(vmf, now + Duration::from_secs(1));
        assert!(
            !matches!(outcome, CorrelationOutcome::Updated(_)),
            "same uid + different protocol must not be an in-place update, got {outcome:?}",
        );
        assert_eq!(outcome, CorrelationOutcome::Merged(id));

        // One fused entity carrying TWO distinct sources (dis + vmf).
        let snap = engine.snapshot();
        assert_eq!(snap.len(), 1);
        let protos: std::collections::BTreeSet<&str> = snap[0]
            .sources
            .iter()
            .map(|s| s.source_protocol.as_str())
            .collect();
        assert_eq!(
            protos,
            ["dis", "vmf"]
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>()
        );
    }

    #[test]
    fn query_at_returns_only_entities_within_radius() {
        let engine = CorrelationEngine::new();
        let now = SystemTime::UNIX_EPOCH;
        let _ = engine.submit_at(entity("a", EntityKind::Ground, 38.0, -77.0), now);
        let _ = engine.submit_at(entity("b", EntityKind::Ground, 39.0, -77.0), now);
        // Radius 10 km — only the southern entity matches.
        let near = engine.query_at(38.0, -77.0, 10_000.0);
        assert_eq!(near.len(), 1);
    }

    #[test]
    fn expire_stale_drops_old_entries() {
        let engine = CorrelationEngine::new();
        let t0 = SystemTime::UNIX_EPOCH;
        let _ = engine.submit_at(entity("a", EntityKind::Ground, 38.0, -77.0), t0);
        assert_eq!(engine.len(), 1);
        let evicted = engine.expire_stale(t0 + Duration::from_secs(31));
        assert_eq!(evicted, 1);
        assert_eq!(engine.len(), 0);
    }

    #[test]
    fn expire_stale_keeps_recent_entries() {
        let engine = CorrelationEngine::new();
        let t0 = SystemTime::UNIX_EPOCH;
        let _ = engine.submit_at(entity("a", EntityKind::Ground, 38.0, -77.0), t0);
        let evicted = engine.expire_stale(t0 + Duration::from_secs(5));
        assert_eq!(evicted, 0);
        assert_eq!(engine.len(), 1);
    }

    #[test]
    fn lru_eviction_kicks_in_at_max_entities() {
        let config = CorrelationConfig {
            max_entities: 2,
            ..CorrelationConfig::default()
        };
        let engine = CorrelationEngine::with_config(config);
        let now = SystemTime::UNIX_EPOCH;
        let _ = engine.submit_at(entity("a", EntityKind::Ground, 0.0, 0.0), now);
        let _ = engine.submit_at(entity("b", EntityKind::Ground, 1.0, 1.0), now);
        let _ = engine.submit_at(entity("c", EntityKind::Ground, 2.0, 2.0), now);
        assert_eq!(engine.len(), 2);
    }

    #[test]
    fn submit_with_velocity_passes_kinematic_gate_when_speeds_match() {
        let engine = CorrelationEngine::new();
        let now = SystemTime::UNIX_EPOCH;
        let mut e1 = entity("a", EntityKind::Ground, 38.0, -77.0);
        e1.velocity = Some(Velocity {
            speed_m_s: 12.0,
            course_deg: 90.0,
        });
        let mut e2 = entity("b", EntityKind::Ground, 38.000050, -77.000050);
        e2.velocity = Some(Velocity {
            speed_m_s: 13.0,
            course_deg: 90.0,
        });
        let _ = engine.submit_at(e1, now);
        let outcome = engine.submit_at(e2, now);
        assert!(matches!(outcome, CorrelationOutcome::Merged(_)));
    }

    #[test]
    fn submit_with_ce90_attribute_biases_fused_position() {
        let engine = CorrelationEngine::new();
        let now = SystemTime::UNIX_EPOCH;
        let mut e1 = entity("a", EntityKind::Ground, 38.000000, -77.0);
        let _ = e1
            .attributes
            .insert("correlation.ce90".into(), AttributeValue::Float(50.0));
        let mut e2 = entity("b", EntityKind::Ground, 38.000050, -77.0);
        let _ = e2
            .attributes
            .insert("correlation.ce90".into(), AttributeValue::Float(5.0));
        let _ = engine.submit_at(e1, now);
        let _ = engine.submit_at(e2, now);
        let snap = engine.snapshot();
        assert_eq!(snap.len(), 1);
        let pos = snap[0].fused_position.expect("fused");
        // The 5 m CE90 source has 100x the weight of the 50 m source,
        // so the fused lat must lean strongly toward the second
        // source's 38.000050.
        assert!(pos.lat > 38.000040, "fused lat {} too low", pos.lat);
    }

    #[test]
    fn snapshot_round_trips_through_serde_json() {
        let engine = CorrelationEngine::new();
        let now = SystemTime::UNIX_EPOCH;
        let _ = engine.submit_at(entity("a", EntityKind::Ground, 38.0, -77.0), now);
        let snap = engine.snapshot();
        let json = serde_json::to_string(&snap).expect("serialise");
        let _: Vec<FusedEntity> = serde_json::from_str(&json).expect("deserialise");
    }
}
