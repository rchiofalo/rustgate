// Copyright © 2026 Roberto Chiofalo.

//! Weighted scoring for spatial / temporal / kinematic / type gates.
//!
//! Each component returns a `f64` in `[0.0, 1.0]` where `1.0` means
//! "the gate passed strongly" and `0.0` means "the gate failed". The
//! engine collapses the four components into a single score via the
//! weights in [`crate::config::FusionWeights`]; if the result clears
//! [`SCORE_MATCH_THRESHOLD`] the report fuses into the candidate
//! fused entity.
//!
//! The component shapes are *triangular*: `1.0` at zero distance /
//! age / Δspeed, decaying linearly to `0.0` at the configured
//! threshold, then clamped at zero past it. Triangular shapes are the
//! cheapest possible decay and make the test surface trivial to
//! reason about — operators who want a Gaussian or sigmoid decay can
//! plug in a different scoring crate at the engine boundary without
//! breaking the public API.

use std::time::{Duration, SystemTime};

use rustgate_core::entity::{EntityKind, Position, Velocity};

use crate::fusion::haversine_distance_m;

/// Match threshold for the weighted total score. Scores at or above
/// this value cause the engine to merge the incoming report into the
/// candidate fused entity; scores below cause it to spawn a new one.
///
/// Pinned at `0.5` so a single weak component (e.g. spatial gate
/// barely passing at the threshold edge) cannot drive a merge by
/// itself — at least two of the four components must contribute
/// strongly. Operators that want stricter or looser matching tune the
/// component weights in [`crate::config::FusionWeights`] rather than
/// nudging the threshold; the threshold is a fixed reference point
/// that keeps the behaviour predictable across deployments.
pub const SCORE_MATCH_THRESHOLD: f64 = 0.5;

/// Triangular spatial score given the great-circle distance between
/// the incoming report and the candidate fused entity, in metres,
/// against the configured per-kind threshold.
///
/// Returns `1.0` at zero distance, decays linearly to `0.0` at
/// `threshold_m`, and clamps to `0.0` past it.
pub fn spatial_score(report: &Position, fused: &Position, threshold_m: f64) -> f64 {
    if threshold_m <= 0.0 {
        return 0.0;
    }
    let distance_m = haversine_distance_m(report.lat, report.lon, fused.lat, fused.lon);
    let normalised = (distance_m / threshold_m).clamp(0.0, 1.0);
    1.0 - normalised
}

/// Triangular temporal score given the wall-clock delta between the
/// incoming report and the fused entity's `last_update`.
///
/// Returns `1.0` for simultaneous reports, decays linearly to `0.0`
/// at `time_window`, and clamps to `0.0` past it. Clock-backwards
/// edge cases (NTP corrections etc.) are treated as zero delta so a
/// time skip cannot accidentally fail the temporal gate.
pub fn temporal_score(report_at: SystemTime, fused_at: SystemTime, time_window: Duration) -> f64 {
    if time_window.is_zero() {
        return 0.0;
    }
    let elapsed = report_at
        .duration_since(fused_at)
        .or_else(|_| fused_at.duration_since(report_at))
        .unwrap_or(Duration::ZERO);
    let elapsed_secs = elapsed.as_secs_f64();
    let window_secs = time_window.as_secs_f64();
    if window_secs <= 0.0 {
        return 0.0;
    }
    let normalised = (elapsed_secs / window_secs).clamp(0.0, 1.0);
    1.0 - normalised
}

/// Triangular kinematic score given the difference in metres-per-
/// second between the incoming report's speed and the fused entity's
/// speed.
///
/// Returns `1.0` when speeds match exactly, decays linearly to `0.0`
/// at `tolerance_mps`, and clamps to `0.0` past it. When *neither*
/// side has a velocity, this returns `1.0` — a missing velocity is
/// not evidence against fusion (some sensors simply do not report
/// kinematics). When *one* side has a velocity and the other does
/// not, returns a permissive `0.5` so the kinematic component
/// neither helps nor harms; the engine relies on spatial / temporal
/// / type to make the call.
pub fn kinematic_score(
    report: Option<&Velocity>,
    fused: Option<&Velocity>,
    tolerance_mps: f64,
) -> f64 {
    match (report, fused) {
        (None, None) => 1.0,
        (None, Some(_)) | (Some(_), None) => 0.5,
        (Some(r), Some(f)) => {
            if tolerance_mps <= 0.0 {
                return 0.0;
            }
            let delta = (r.speed_m_s - f.speed_m_s).abs();
            let normalised = (delta / tolerance_mps).clamp(0.0, 1.0);
            1.0 - normalised
        }
    }
}

/// Type-compatibility score. Hard-edged: `1.0` if the two
/// classifications are compatible, `0.0` if not. Compatibility is
/// asymmetric in spirit but symmetric in implementation — see
/// [`types_compatible`] for the table.
pub fn type_score(report: &EntityKind, fused: &EntityKind) -> f64 {
    if types_compatible(report, fused) {
        1.0
    } else {
        0.0
    }
}

/// Boolean "can these two entity kinds correlate at all?" check.
///
/// Aircraft tracks cannot correlate with ground vehicle tracks — a
/// helicopter and an APC at the same lat/lon are physically distinct
/// objects. The same applies pairwise across the specific platform
/// kinds (Aircraft / Ground / Marine / Munition).
///
/// The permissive variants (`Track` — generic, `Sensor` — radar
/// detection, `Unknown(_)` — codec hit no known classifier) are
/// compatible with *every* specific kind because they represent
/// operator uncertainty, not a positive identification. A SAPIENT
/// "blob detected at coords" report MUST be allowed to fuse with a
/// CoT "friendly aircraft at coords" report — collapsing them is
/// exactly what the operator wants.
pub fn types_compatible(a: &EntityKind, b: &EntityKind) -> bool {
    match (a, b) {
        // Same kind — always compatible. Catches Aircraft ↔ Aircraft
        // and friends without enumerating each pair.
        (x, y) if std::mem::discriminant(x) == std::mem::discriminant(y) => true,
        // Permissive variants on either side fuse against any kind.
        (EntityKind::Track | EntityKind::Sensor | EntityKind::Unknown(_), _)
        | (_, EntityKind::Track | EntityKind::Sensor | EntityKind::Unknown(_)) => true,
        // The remaining specific-vs-different-specific pairs are
        // incompatible: Aircraft × Ground, Aircraft × Marine,
        // Aircraft × Munition, Ground × Marine, Ground × Munition,
        // Marine × Munition.
        _ => false,
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn pos(lat: f64, lon: f64) -> Position {
        Position {
            lat,
            lon,
            hae_meters: None,
        }
    }

    #[test]
    fn spatial_score_decays_to_zero_at_threshold() {
        let a = pos(38.0, -77.0);
        let b = pos(38.0, -77.0);
        assert!((spatial_score(&a, &b, 100.0) - 1.0).abs() < 1e-9);

        // ~111 km north — well past 100 m threshold, must clamp to 0.
        let c = pos(39.0, -77.0);
        assert_eq!(spatial_score(&a, &c, 100.0), 0.0);
    }

    #[test]
    fn temporal_score_uses_absolute_delta() {
        let now = SystemTime::UNIX_EPOCH;
        let later = now + Duration::from_secs(15);
        let s_forward = temporal_score(later, now, Duration::from_secs(30));
        let s_backward = temporal_score(now, later, Duration::from_secs(30));
        assert!((s_forward - 0.5).abs() < 1e-6);
        assert!((s_backward - 0.5).abs() < 1e-6);
    }

    #[test]
    fn temporal_score_clamps_zero_past_window() {
        let now = SystemTime::UNIX_EPOCH;
        let way_later = now + Duration::from_secs(600);
        assert_eq!(temporal_score(way_later, now, Duration::from_secs(30)), 0.0);
    }

    #[test]
    fn kinematic_score_matches_pair_of_velocities() {
        let v1 = Velocity {
            speed_m_s: 50.0,
            course_deg: 90.0,
        };
        let v2 = Velocity {
            speed_m_s: 60.0,
            course_deg: 270.0,
        };
        // 10 m/s delta against a 25 m/s tolerance -> 0.6 score.
        let s = kinematic_score(Some(&v1), Some(&v2), 25.0);
        assert!((s - 0.6).abs() < 1e-9, "score {s}");
    }

    #[test]
    fn kinematic_score_handles_missing_velocity() {
        let v = Velocity {
            speed_m_s: 12.0,
            course_deg: 90.0,
        };
        // Both missing — permissive 1.0.
        assert_eq!(kinematic_score(None, None, 25.0), 1.0);
        // One missing — neutral 0.5.
        assert_eq!(kinematic_score(Some(&v), None, 25.0), 0.5);
        assert_eq!(kinematic_score(None, Some(&v), 25.0), 0.5);
    }

    #[test]
    fn type_score_is_one_for_compatible_pairs() {
        assert_eq!(
            type_score(&EntityKind::Aircraft, &EntityKind::Aircraft),
            1.0
        );
        assert_eq!(type_score(&EntityKind::Track, &EntityKind::Aircraft), 1.0);
        assert_eq!(
            type_score(&EntityKind::Unknown("blob".into()), &EntityKind::Ground),
            1.0
        );
    }

    #[test]
    fn type_score_is_zero_for_incompatible_pairs() {
        assert_eq!(type_score(&EntityKind::Aircraft, &EntityKind::Ground), 0.0);
        assert_eq!(type_score(&EntityKind::Marine, &EntityKind::Munition), 0.0);
        assert_eq!(type_score(&EntityKind::Aircraft, &EntityKind::Marine), 0.0);
    }

    #[test]
    fn types_compatible_table_is_symmetric() {
        // Whatever the table says, it must give the same answer
        // regardless of argument order. This pins the implementation
        // against a future asymmetric revision.
        let kinds = [
            EntityKind::Aircraft,
            EntityKind::Ground,
            EntityKind::Marine,
            EntityKind::Munition,
            EntityKind::Track,
            EntityKind::Sensor,
            EntityKind::Unknown("foo".into()),
        ];
        for a in &kinds {
            for b in &kinds {
                assert_eq!(
                    types_compatible(a, b),
                    types_compatible(b, a),
                    "asymmetric: {a:?} vs {b:?}",
                );
            }
        }
    }
}
