// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Closed-form conversion between WGS-84 geodetic (lat / lon / alt)
//! and ECEF (Earth-Centred-Earth-Fixed Cartesian) coordinates.
//!
//! DIS Entity State PDUs carry positions in **ECEF metres** (geocentric
//! Cartesian), while every consumer rustgate routes — CoT, MAVLink,
//! ASTERIX, the position cache, dashboards — works in **WGS-84
//! geodetic decimal degrees**. This module is the conversion layer.
//!
//! # Algorithm
//!
//! - Geodetic → ECEF (`wgs84_to_ecef`): closed-form using the WGS-84
//!   prime-vertical radius of curvature `N(φ) = a / sqrt(1 − e² sin²φ)`.
//!   No iteration; one call to `sqrt`.
//! - ECEF → Geodetic (`ecef_to_wgs84`): closed-form Bowring 1985
//!   approximation. Single-pass (no iteration loop) yields better than
//!   1 mm precision for altitudes up to ~10 000 km — well above any
//!   Earth-orbital regime DIS deals with. The classic iterative
//!   algorithm converges in ~3 iterations for the same precision but
//!   costs an extra two trigonometric pairs per call; the single-pass
//!   form is well-documented in Heikkinen 1982 and Bowring 1985.
//!
//! # Precision
//!
//! The closed-form inverse is exact at the equator and accurate to
//! better than 0.1 mm at the poles for altitudes within the Earth-
//! atmosphere envelope (< 200 km). Round-trip
//! `wgs84_to_ecef ∘ ecef_to_wgs84` recovers the input to within
//! ~1 mm — the integration test in `tests/roundtrip.rs` pins this.

/// WGS-84 semi-major axis in metres (equatorial radius). NIMA TR8350.2,
/// 4th edition, the same value pinned by every IEEE 1278.1 deployment.
pub const WGS84_A: f64 = 6_378_137.0;

/// WGS-84 flattening (1 / 298.257223563). Exact value per NIMA
/// TR8350.2; deviations as small as the 11th significant digit will
/// shift the inverse-conversion altitude by hundreds of metres at high
/// altitudes, so this constant is intentionally pinned to the spec.
pub const WGS84_F: f64 = 1.0 / 298.257_223_563;

/// WGS-84 first eccentricity squared, derived from `WGS84_F`.
/// `e² = 2f − f²`. Pre-computed as a constant so callers do not
/// recompute it per PDU.
pub const WGS84_E2: f64 = 2.0 * WGS84_F - WGS84_F * WGS84_F;

/// WGS-84 semi-minor axis (polar radius), derived: `b = a (1 − f)`.
pub const WGS84_B: f64 = WGS84_A * (1.0 - WGS84_F);

/// WGS-84 second eccentricity squared, derived: `eb² = (a² − b²) / b²`.
/// Used by Bowring 1985 ECEF→geodetic.
pub const WGS84_EB2: f64 = (WGS84_A * WGS84_A - WGS84_B * WGS84_B) / (WGS84_B * WGS84_B);

/// Convert WGS-84 geodetic coordinates to ECEF Cartesian metres.
///
/// `lat_deg` is in `[-90, 90]`; `lon_deg` is in `[-180, 180]`;
/// `alt_m` is height above the WGS-84 ellipsoid in metres. Returns
/// `(x, y, z)` in metres with the standard ECEF convention: X axis
/// through the prime meridian on the equator, Y axis 90° east, Z axis
/// through the geographic north pole.
///
/// Closed-form using the prime-vertical radius of curvature
/// `N(φ) = a / sqrt(1 − e² sin²φ)`. No iteration.
#[must_use]
pub fn wgs84_to_ecef(lat_deg: f64, lon_deg: f64, alt_m: f64) -> (f64, f64, f64) {
    let lat = lat_deg.to_radians();
    let lon = lon_deg.to_radians();
    let sin_lat = lat.sin();
    let cos_lat = lat.cos();
    let sin_lon = lon.sin();
    let cos_lon = lon.cos();

    let n = WGS84_A / (1.0 - WGS84_E2 * sin_lat * sin_lat).sqrt();

    let x = (n + alt_m) * cos_lat * cos_lon;
    let y = (n + alt_m) * cos_lat * sin_lon;
    let z = (n * (1.0 - WGS84_E2) + alt_m) * sin_lat;
    (x, y, z)
}

/// Convert ECEF Cartesian metres to WGS-84 geodetic coordinates.
///
/// Inputs are `(x, y, z)` in metres with the standard ECEF convention.
/// Returns `(lat_deg, lon_deg, alt_m)` where `lat_deg` is in
/// `[-90, 90]`, `lon_deg` is in `[-180, 180]`, and `alt_m` is height
/// above the WGS-84 ellipsoid.
///
/// Single-pass Bowring 1985 closed-form inverse. The auxiliary angle
/// `θ = atan2(z·a, p·b)` is computed once; the latitude is then
/// `atan2(z + eb²·b·sin³θ, p − e²·a·cos³θ)`. No iteration loop —
/// precision is better than 1 mm for altitudes within the Earth-
/// atmosphere envelope and degrades gracefully (still well within
/// 1 cm) up to the ~36 000 km geostationary regime.
///
/// Special-case behaviour:
/// - On the polar axis (`p ≈ 0`), latitude collapses to ±90° with
///   `lon_deg = 0` and `alt_m = |z| − b`.
/// - At the geocentre (`x = y = z = 0`), returns `(0, 0, −a)` —
///   geometrically the point is below the ellipsoid by `a`. Operators
///   should treat this as a malformed wire input rather than rely on
///   the exact return value.
#[must_use]
pub fn ecef_to_wgs84(x: f64, y: f64, z: f64) -> (f64, f64, f64) {
    // Equatorial distance from the polar axis.
    let p = (x * x + y * y).sqrt();

    // Polar-axis singularity: latitude is ±90°, longitude undefined
    // (we report 0). Altitude above the ellipsoid is |z| − b.
    if p < f64::EPSILON {
        let lat_deg = if z >= 0.0 { 90.0 } else { -90.0 };
        let alt_m = z.abs() - WGS84_B;
        return (lat_deg, 0.0, alt_m);
    }

    // Bowring 1985 auxiliary angle. The intermediate `theta` does not
    // have geometric meaning on its own — it is a function tuned so a
    // single `atan2` evaluation (below) yields a closed-form latitude
    // accurate to better than 1 mm.
    let theta = (z * WGS84_A).atan2(p * WGS84_B);
    let sin_theta = theta.sin();
    let cos_theta = theta.cos();

    let lat = (z + WGS84_EB2 * WGS84_B * sin_theta * sin_theta * sin_theta)
        .atan2(p - WGS84_E2 * WGS84_A * cos_theta * cos_theta * cos_theta);
    let sin_lat = lat.sin();
    let cos_lat = lat.cos();

    let n = WGS84_A / (1.0 - WGS84_E2 * sin_lat * sin_lat).sqrt();
    // Guard against `cos_lat ≈ 0` (near the pole) where the
    // p / cos_lat form becomes ill-conditioned. The polar branch
    // above already handles `p ≈ 0`; here we fall back to the z-axis
    // form for the rare `|lat| ≈ 90°` case from a non-polar `p`.
    let alt_m = if cos_lat.abs() > 1e-12 {
        p / cos_lat - n
    } else {
        z / sin_lat - n * (1.0 - WGS84_E2)
    };

    let lon = y.atan2(x);
    (lat.to_degrees(), lon.to_degrees(), alt_m)
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    /// Round-trip an arbitrary geodetic point through ECEF and assert
    /// the latitude / longitude recover to better than 1e-9 degrees
    /// (~0.1 mm at the equator) and altitude recovers to better than
    /// 1 mm. The closed-form Bowring 1985 form is exact in the limit
    /// for points near the surface.
    fn assert_round_trip(lat_deg: f64, lon_deg: f64, alt_m: f64) {
        let (x, y, z) = wgs84_to_ecef(lat_deg, lon_deg, alt_m);
        let (lat2, lon2, alt2) = ecef_to_wgs84(x, y, z);
        assert!(
            (lat_deg - lat2).abs() < 1e-9,
            "lat drift {} → {} (∆ {})",
            lat_deg,
            lat2,
            lat_deg - lat2
        );
        assert!(
            (lon_deg - lon2).abs() < 1e-9,
            "lon drift {} → {} (∆ {})",
            lon_deg,
            lon2,
            lon_deg - lon2
        );
        assert!(
            (alt_m - alt2).abs() < 1e-3,
            "alt drift {} → {} (∆ {})",
            alt_m,
            alt2,
            alt_m - alt2
        );
    }

    #[test]
    fn statue_of_liberty_matches_published_ecef() {
        // Reference: Statue of Liberty, 40.6892° N, 74.0445° W,
        // 93 m HAE. Closed-form WGS-84 prime-vertical conversion
        // yields ECEF ≈ (1 331 360, −4 656 651, 4 136 374) metres.
        // Pin the values to four significant figures so the test is
        // robust against floating-point rounding but still catches
        // any sign / axis flip in the conversion.
        let (x, y, z) = wgs84_to_ecef(40.6892, -74.0445, 93.0);
        assert!((x - 1_331_360.0).abs() < 1.0, "x = {x}");
        assert!((y - -4_656_651.0).abs() < 1.0, "y = {y}");
        assert!((z - 4_136_374.0).abs() < 1.0, "z = {z}");
    }

    #[test]
    fn round_trip_at_equator_prime_meridian() {
        // Origin of the WGS-84 graticule. At lat=0, lon=0, alt=0 the
        // ECEF form should be exactly (a, 0, 0).
        let (x, y, z) = wgs84_to_ecef(0.0, 0.0, 0.0);
        assert!((x - WGS84_A).abs() < 1e-6, "x = {x}");
        assert!(y.abs() < 1e-6, "y = {y}");
        assert!(z.abs() < 1e-6, "z = {z}");

        assert_round_trip(0.0, 0.0, 0.0);
    }

    #[test]
    fn round_trip_at_north_pole() {
        // Polar branch is special-cased; pin that the round-trip still
        // recovers the input.
        let (x, y, z) = wgs84_to_ecef(90.0, 0.0, 0.0);
        assert!(x.abs() < 1e-6, "x = {x}");
        assert!(y.abs() < 1e-6, "y = {y}");
        assert!((z - WGS84_B).abs() < 1e-6, "z = {z}");

        let (lat, _lon, alt) = ecef_to_wgs84(x, y, z);
        assert!((lat - 90.0).abs() < 1e-9);
        assert!(alt.abs() < 1e-3);
    }

    #[test]
    fn round_trip_high_altitude() {
        // Geostationary altitude (~35 786 km). Bowring 1985 single-pass
        // should still be accurate to within ~1 mm.
        assert_round_trip(0.0, 0.0, 35_786_000.0);
    }

    #[test]
    fn round_trip_southern_hemisphere() {
        // Sydney Opera House: −33.8568° N, 151.2153° E, 4 m HAE.
        assert_round_trip(-33.8568, 151.2153, 4.0);
    }

    #[test]
    fn round_trip_negative_altitude_below_ellipsoid() {
        // Bottom of Marianas Trench: ~11.35° N, 142.2° E, −10 935 m
        // HAE. Pin the conversion handles below-ellipsoid altitudes
        // (sub-marine / sub-surface entities) without losing precision.
        assert_round_trip(11.35, 142.2, -10_935.0);
    }

    #[test]
    fn round_trip_at_typical_simulation_locations() {
        // A spread of latitudes / longitudes / altitudes covering the
        // common exercise-scenario envelope (continental US, Europe,
        // Pacific). Pins the conversion is uniformly accurate.
        for &(lat, lon, alt) in &[
            (38.8895, -77.0353, 18.0),   // Washington Monument
            (51.5007, -0.1246, 11.0),    // Big Ben
            (35.6586, 139.7454, 60.0),   // Tokyo Tower
            (-22.9519, -43.2105, 710.0), // Christ the Redeemer
            (78.2232, 15.6267, 5.0),     // Svalbard
            (-89.99, 0.0, 0.0),          // Near south pole (non-polar branch)
        ] {
            assert_round_trip(lat, lon, alt);
        }
    }
}
