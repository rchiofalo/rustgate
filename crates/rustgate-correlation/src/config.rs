// Copyright © 2026 Roberto Chiofalo.

//! Configuration knobs for the correlation engine.
//!
//! Every threshold has a published default chosen for a tactical-edge
//! sensor mix (CoT positions, MAVLink GPS reports, Link 16 J-series
//! tracks, DIS PDUs, SAPIENT detections). Operators tune these on a
//! per-deployment basis once they have ground truth on their sensor
//! collection — the defaults are starting points, not invariants.
//!
//! The struct derives `serde::Deserialize` so a future hot-reload path
//! can lift the config from `rustgate.toml`. For the MVP the engine is
//! constructed from a [`CorrelationConfig`] in code — no TOML schema
//! is wired in yet.

use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Correlation thresholds and fusion weights.
///
/// All numeric fields are in SI / WGS-84 units (metres for distance,
/// metres-per-second for kinematic tolerance, seconds for the time
/// window).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub struct CorrelationConfig {
    /// Per-kind spatial gating distances in metres.
    pub distance_threshold_m: KindThresholds,
    /// Maximum age of a fused entity past which a new report cannot
    /// merge into it. Older entities are still queryable until
    /// [`crate::engine::CorrelationEngine::expire_stale`] runs and
    /// drops them.
    pub time_window: Duration,
    /// Maximum allowable difference in metres-per-second between the
    /// incoming report's speed and the fused entity's speed for the
    /// kinematic gate to pass. Course is not gated — two sensors
    /// observing the same fast-mover at different bearings will
    /// disagree on course while agreeing on speed.
    pub kinematic_tolerance_mps: f64,
    /// Relative weights for the four scoring components. Renormalised
    /// internally — operators may set them to any non-negative ratio.
    pub fusion_weights: FusionWeights,
    /// LRU cap on the number of fused entities. Beyond this, the
    /// least-recently-updated fused entity is evicted to make room for
    /// a new one. Sized for a corps-level operating picture by default.
    pub max_entities: usize,
}

impl Default for CorrelationConfig {
    fn default() -> Self {
        Self {
            distance_threshold_m: KindThresholds::default(),
            time_window: Duration::from_secs(30),
            kinematic_tolerance_mps: 25.0,
            fusion_weights: FusionWeights::default(),
            max_entities: 100_000,
        }
    }
}

/// Spatial gating distances that vary by entity kind.
///
/// Aircraft tracks are gated more loosely than ground tracks because
/// their position uncertainty grows quadratically with the radar /
/// link-16 update period (a fast-mover covers ~250 m per second). The
/// `marine` and `default` thresholds split the difference.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub struct KindThresholds {
    /// Threshold for ground / dismount / fixed-installation tracks.
    pub ground: f64,
    /// Threshold for aircraft, munition, and other airborne tracks.
    pub air: f64,
    /// Threshold for marine surface and sub-surface tracks.
    pub marine: f64,
    /// Threshold for any track whose [`rustgate_core::entity::EntityKind`]
    /// is `Track`, `Sensor`, or `Unknown(_)` and so cannot be matched
    /// to one of the more specific buckets above.
    pub default: f64,
}

impl Default for KindThresholds {
    fn default() -> Self {
        Self {
            ground: 100.0,
            air: 500.0,
            marine: 250.0,
            default: 200.0,
        }
    }
}

/// Relative weights for the four scoring components.
///
/// All four weights default to `0.25` so each component contributes
/// equally to the `[0.0, 1.0]` total score, with the match threshold
/// at `0.5` meaning at least two of the four components have to be
/// strongly positive for fusion to fire. Operators that trust their
/// sensors' position more than their classification (or vice versa)
/// retune the ratios — the engine renormalises so a non-unit sum is
/// fine.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub struct FusionWeights {
    /// Weight on the spatial-gate score (1 – distance / threshold).
    pub spatial: f64,
    /// Weight on the temporal-gate score (1 – age / window).
    pub temporal: f64,
    /// Weight on the kinematic score (1 – Δspeed / tolerance).
    pub kinematic: f64,
    /// Weight on the type-compatibility score (1.0 if compatible,
    /// 0.0 if not — the type gate is the only hard cut, not a
    /// gradient).
    pub r#type: f64,
}

impl Default for FusionWeights {
    fn default() -> Self {
        Self {
            spatial: 0.4,
            temporal: 0.2,
            kinematic: 0.2,
            r#type: 0.2,
        }
    }
}

impl FusionWeights {
    /// Sum of the four components. Used by the engine to renormalise
    /// when an operator sets non-unit weights.
    pub fn sum(&self) -> f64 {
        self.spatial + self.temporal + self.kinematic + self.r#type
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn default_thresholds_match_published_defaults() {
        let cfg = CorrelationConfig::default();
        assert_eq!(cfg.distance_threshold_m.ground, 100.0);
        assert_eq!(cfg.distance_threshold_m.air, 500.0);
        assert_eq!(cfg.time_window, Duration::from_secs(30));
        assert_eq!(cfg.kinematic_tolerance_mps, 25.0);
        assert_eq!(cfg.max_entities, 100_000);
    }

    #[test]
    fn fusion_weights_sum_renormalises_to_expected_total() {
        let w = FusionWeights::default();
        // Default ratios (0.4 + 0.2 + 0.2 + 0.2) = 1.0 — operator
        // overrides may change the sum but the engine renormalises.
        assert!((w.sum() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn config_round_trips_through_serde_json() {
        let cfg = CorrelationConfig::default();
        let json = serde_json::to_string(&cfg).expect("serialise");
        let decoded: CorrelationConfig = serde_json::from_str(&json).expect("deserialise");
        assert_eq!(
            decoded.distance_threshold_m.ground,
            cfg.distance_threshold_m.ground
        );
        assert_eq!(decoded.max_entities, cfg.max_entities);
    }
}
