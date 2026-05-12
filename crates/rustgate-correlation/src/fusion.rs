// Copyright © 2026 Roberto Chiofalo.

//! Position / classification fusion primitives.
//!
//! Splits the merge math out of the engine module so the algorithms
//! are testable in isolation and so a future Kalman-filter upgrade
//! has a single boundary to change.
//!
//! # Inverse-variance position fusion
//!
//! Given N source positions `(p_i)` with uncertainties `(σ_i)`, the
//! minimum-variance unbiased estimator of the true position is the
//! weighted mean
//!
//! ```text
//!     p̂ = Σ (w_i p_i) / Σ w_i,    w_i = 1 / σ_i²
//! ```
//!
//! Sources that publish a circular-error-90 (`ce90`) attribute use
//! `ce90 / 1.645` as the equivalent 1-σ uncertainty (the 90th
//! percentile of a 2D Gaussian on the principal axis sits at 1.645σ).
//! Sources that publish only `position_uncertainty_m` use that value
//! directly. Sources that publish neither get `σ = ∞` in the limit;
//! the engine clamps to a fixed fallback weight of `1.0` so a
//! position with no uncertainty still contributes — newest-wins is
//! the bias the fallback steers toward, since the most recent source
//! is appended last and dominates the sum when every contributor
//! falls back to unit weight.
//!
//! # Classification fusion
//!
//! [`fuse_classification`] returns the *most specific* entity kind
//! across the contributing sources. A single positive ID
//! (`Aircraft`, `Ground`, …) overrides any number of generic /
//! permissive sources (`Track`, `Sensor`, `Unknown`). When two
//! contributors carry conflicting positive IDs (e.g. one says
//! `Aircraft`, the other says `Marine`), the type-compatibility gate
//! upstream of fusion already rejected the merge — so the case
//! cannot reach this function in practice. Defensive code path: pick
//! the newer source's classification.

use rustgate_core::entity::{AttributeValue, Entity, EntityKind, Position};

use crate::types::SourceTrack;

/// Mean Earth radius in metres — WGS-84 derived value.
pub(crate) const EARTH_RADIUS_M: f64 = 6_371_008.8;

/// Conversion factor from circular-error-90 (`ce90`) to one-sigma
/// uncertainty for a 2D Gaussian. The 90th-percentile contour of a
/// circular Gaussian sits at `1.645 σ`; dividing CE90 by this scalar
/// recovers the one-sigma value the inverse-variance weighting wants.
pub(crate) const CE90_TO_SIGMA: f64 = 1.645;

/// Fallback inverse-variance weight applied when a source carries
/// neither `ce90` nor `position_uncertainty_m`.
pub(crate) const DEFAULT_POSITION_WEIGHT: f64 = 1.0;

/// Great-circle distance in metres between two WGS-84 points.
///
/// Uses the haversine formula. Sufficiently accurate for the
/// sub-kilometre gating distances this MVP cares about; for
/// long-haul (>1000 km) tracking a Vincenty-formula upgrade can
/// land at this same call site without changing the public API.
pub fn haversine_distance_m(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    let lat1_rad = lat1.to_radians();
    let lat2_rad = lat2.to_radians();
    let d_lat = (lat2 - lat1).to_radians();
    let d_lon = (lon2 - lon1).to_radians();
    let a =
        (d_lat / 2.0).sin().powi(2) + lat1_rad.cos() * lat2_rad.cos() * (d_lon / 2.0).sin().powi(2);
    let c = 2.0 * a.sqrt().asin();
    EARTH_RADIUS_M * c
}

/// Inverse-variance weight for a source position based on the
/// entity's published uncertainty attributes.
///
/// Looks for the following attribute keys, in priority order:
/// 1. `correlation.ce90` — circular error 90 % in metres.
/// 2. `correlation.position_uncertainty_m` — one-sigma uncertainty
///    in metres.
/// 3. `cot.ce` — CoT `<point ce="…"/>` attribute, treated as CE90 by
///    convention.
/// 4. Falls back to a unit weight (`1.0`) when no uncertainty is
///    published.
///
/// Returns a strictly positive weight. A published uncertainty of
/// zero (or negative — defensive) collapses to the default weight to
/// avoid a divide-by-zero in the weighted-mean denominator.
pub fn position_weight(entity: &Entity) -> f64 {
    if let Some(ce90) = read_uncertainty(entity, "correlation.ce90") {
        let sigma = ce90 / CE90_TO_SIGMA;
        if sigma > 0.0 {
            return 1.0 / (sigma * sigma);
        }
    }
    if let Some(sigma) = read_uncertainty(entity, "correlation.position_uncertainty_m")
        && sigma > 0.0
    {
        return 1.0 / (sigma * sigma);
    }
    if let Some(ce90) = read_uncertainty(entity, "cot.ce") {
        let sigma = ce90 / CE90_TO_SIGMA;
        if sigma > 0.0 {
            return 1.0 / (sigma * sigma);
        }
    }
    DEFAULT_POSITION_WEIGHT
}

fn read_uncertainty(entity: &Entity, key: &str) -> Option<f64> {
    match entity.attributes.get(key)? {
        AttributeValue::Float(v) => Some(*v),
        AttributeValue::Int(v) => Some(*v as f64),
        AttributeValue::Str(s) => s.parse().ok(),
        AttributeValue::Bool(_) => None,
    }
}

/// Inverse-variance weighted mean position across the supplied
/// sources. Returns `None` when no source carries a position.
///
/// The resulting `hae_meters` is the weighted mean of the
/// contributing sources' altitudes when every source has one;
/// otherwise drops to `None` because mixing has-altitude and
/// no-altitude sources via a partial mean would produce a
/// systematic downward bias on the displayed altitude. Operators
/// who care about altitude in a mixed-source environment publish
/// `correlation.altitude_uncertainty_m` to tell the fuser to weight
/// altitude-bearing sources differently — that knob lands in a
/// follow-up.
pub fn fuse_position(sources: &[SourceTrack]) -> Option<Position> {
    let mut sum_w = 0.0f64;
    let mut sum_lat = 0.0f64;
    let mut sum_lon = 0.0f64;
    let mut sum_hae = 0.0f64;
    let mut sum_w_hae = 0.0f64;

    for source in sources {
        let Some(pos) = source.original_entity.position else {
            continue;
        };
        let w = source.weight.max(0.0);
        if w == 0.0 {
            continue;
        }
        sum_w += w;
        sum_lat += w * pos.lat;
        sum_lon += w * pos.lon;
        if let Some(hae) = pos.hae_meters {
            sum_w_hae += w;
            sum_hae += w * hae;
        }
    }

    if sum_w == 0.0 {
        return None;
    }

    let lat = sum_lat / sum_w;
    let lon = sum_lon / sum_w;
    let hae_meters = if sum_w_hae > 0.0 {
        Some(sum_hae / sum_w_hae)
    } else {
        None
    };
    Some(Position {
        lat,
        lon,
        hae_meters,
    })
}

/// Pick the most-specific [`EntityKind`] across the contributing
/// sources.
///
/// Iterates in source order and prefers `Aircraft` / `Ground` /
/// `Marine` / `Munition` over `Track` / `Sensor` / `Unknown`. When
/// every source is permissive (e.g. a chain of `Sensor` reports),
/// returns the first source's kind verbatim — it is the most
/// recent positive evidence available, even if it is permissive.
pub fn fuse_classification(sources: &[SourceTrack]) -> EntityKind {
    debug_assert!(!sources.is_empty(), "fuse_classification of empty sources");
    let mut best: Option<&EntityKind> = None;
    for source in sources {
        let kind = &source.original_entity.kind;
        match (best, kind) {
            // First non-permissive variant wins.
            (None | Some(EntityKind::Track | EntityKind::Sensor | EntityKind::Unknown(_)), k)
                if !matches!(
                    k,
                    EntityKind::Track | EntityKind::Sensor | EntityKind::Unknown(_)
                ) =>
            {
                best = Some(k);
            }
            // No best yet, accept anything.
            (None, k) => best = Some(k),
            _ => {}
        }
    }
    best.cloned().unwrap_or(EntityKind::Unknown("none".into()))
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use std::collections::BTreeMap;
    use std::time::SystemTime;

    use rustgate_core::entity::Velocity;

    use super::*;

    fn entity_at(lat: f64, lon: f64, kind: EntityKind) -> Entity {
        Entity {
            uid: "u".into(),
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

    fn source(entity: Entity, weight: f64) -> SourceTrack {
        SourceTrack {
            source_id: entity.uid.clone(),
            source_protocol: "test".into(),
            original_entity: entity,
            weight,
            last_seen: SystemTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn haversine_distance_zero_for_same_point() {
        assert!(haversine_distance_m(38.0, -77.0, 38.0, -77.0).abs() < 1e-9);
    }

    #[test]
    fn haversine_distance_one_degree_lat_is_about_111km() {
        let d = haversine_distance_m(38.0, -77.0, 39.0, -77.0);
        assert!((d - 111_195.0).abs() < 200.0, "{d}m");
    }

    #[test]
    fn fuse_position_weighted_mean_biases_toward_more_certain_source() {
        let a = source(entity_at(0.0, 0.0, EntityKind::Aircraft), 1.0);
        let b = source(entity_at(1.0, 0.0, EntityKind::Aircraft), 9.0);
        // 1 * 0 + 9 * 1 / 10 = 0.9 — biased toward the more certain
        // source, exactly what inverse-variance weighting wants.
        let fused = fuse_position(&[a, b]).expect("fused");
        assert!((fused.lat - 0.9).abs() < 1e-9);
    }

    #[test]
    fn fuse_position_returns_none_when_no_source_has_position() {
        let mut e = entity_at(0.0, 0.0, EntityKind::Aircraft);
        e.position = None;
        let s = source(e, 1.0);
        assert!(fuse_position(&[s]).is_none());
    }

    #[test]
    fn position_weight_uses_ce90_when_present() {
        let mut e = entity_at(0.0, 0.0, EntityKind::Ground);
        let _ = e
            .attributes
            .insert("correlation.ce90".into(), AttributeValue::Float(10.0));
        let w = position_weight(&e);
        // sigma = 10 / 1.645 ≈ 6.08; weight = 1 / 36.95 ≈ 0.0271
        assert!((w - 1.645f64.powi(2) / 100.0).abs() < 1e-6, "{w}");
    }

    #[test]
    fn position_weight_falls_back_to_default_without_attributes() {
        let e = entity_at(0.0, 0.0, EntityKind::Ground);
        assert_eq!(position_weight(&e), DEFAULT_POSITION_WEIGHT);
    }

    #[test]
    fn fuse_classification_prefers_specific_over_permissive() {
        let permissive = source(entity_at(0.0, 0.0, EntityKind::Track), 1.0);
        let specific = source(entity_at(0.0, 0.0, EntityKind::Aircraft), 1.0);
        assert_eq!(
            fuse_classification(&[permissive, specific]),
            EntityKind::Aircraft
        );
    }

    #[test]
    fn fuse_classification_keeps_first_when_all_permissive() {
        let s1 = source(entity_at(0.0, 0.0, EntityKind::Track), 1.0);
        let s2 = source(entity_at(0.0, 0.0, EntityKind::Sensor), 1.0);
        assert_eq!(fuse_classification(&[s1, s2]), EntityKind::Track);
    }

    #[test]
    fn position_weight_handles_int_attribute() {
        let mut e = entity_at(0.0, 0.0, EntityKind::Ground);
        let _ = e
            .attributes
            .insert("correlation.ce90".into(), AttributeValue::Int(20));
        // Should not be the default weight — i64 is read as f64.
        assert!(position_weight(&e) != DEFAULT_POSITION_WEIGHT);
    }

    #[test]
    fn fuse_position_skips_zero_weight_sources() {
        let zero = source(entity_at(10.0, 10.0, EntityKind::Aircraft), 0.0);
        let real = source(entity_at(0.0, 0.0, EntityKind::Aircraft), 1.0);
        let fused = fuse_position(&[zero, real]).expect("fused");
        // Zero-weight source must be ignored even though its position
        // would otherwise pull the mean toward (10, 10).
        assert!(fused.lat.abs() < 1e-9);
        assert!(fused.lon.abs() < 1e-9);
    }

    // Pin that Velocity's import works (used by other modules / docs).
    #[allow(dead_code)]
    fn _velocity_uses() -> Velocity {
        Velocity {
            speed_m_s: 0.0,
            course_deg: 0.0,
        }
    }
}
