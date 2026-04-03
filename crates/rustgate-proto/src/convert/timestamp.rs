//! ISO 8601 <-> epoch milliseconds conversion.
//!
//! Minimal hand-rolled parser matching the format TAK clients produce:
//! `2021-02-27T20:32:24.771Z` or `2021-02-27T20:32:24Z`.

use crate::error::ProtoError;

/// Convert an ISO 8601 UTC timestamp string to milliseconds since Unix epoch.
///
/// Accepts: `YYYY-MM-DDThh:mm:ss[.SSS]Z`
pub fn iso8601_to_millis(s: &str) -> Result<u64, ProtoError> {
    let s = s.trim_end_matches('Z');
    let (date, time_with_frac) = s
        .split_once('T')
        .ok_or_else(|| ProtoError::InvalidTimestamp(format!("no T separator: {s}")))?;

    let mut date_parts = date.split('-');
    let year: i64 = parse_part(&mut date_parts, "year", s)?;
    let month: u32 = parse_part(&mut date_parts, "month", s)?;
    let day: u32 = parse_part(&mut date_parts, "day", s)?;

    // Validate ranges to prevent overflow in epoch calculation.
    if !(0..=9999).contains(&year) {
        return Err(ProtoError::InvalidTimestamp(format!(
            "year out of range: {s}"
        )));
    }
    if !(1..=12).contains(&month) {
        return Err(ProtoError::InvalidTimestamp(format!(
            "month out of range: {s}"
        )));
    }
    if !(1..=31).contains(&day) {
        return Err(ProtoError::InvalidTimestamp(format!(
            "day out of range: {s}"
        )));
    }

    // Split fractional seconds
    let (time_str, frac_millis) = match time_with_frac.split_once('.') {
        Some((t, frac)) => {
            // Take only ASCII digits to avoid slicing into multi-byte characters.
            let digits: String = frac
                .chars()
                .filter(|c| c.is_ascii_digit())
                .take(3)
                .collect();
            let padded = format!("{digits:0<3}");
            let ms: u64 = padded
                .parse()
                .map_err(|_| ProtoError::InvalidTimestamp(format!("bad fractional: {s}")))?;
            (t, ms)
        }
        None => (time_with_frac, 0),
    };

    let mut time_parts = time_str.split(':');
    let hour: u32 = parse_part(&mut time_parts, "hour", s)?;
    let min: u32 = parse_part(&mut time_parts, "minute", s)?;
    let sec: u32 = parse_part(&mut time_parts, "second", s)?;

    if hour > 23 || min > 59 || sec > 59 {
        return Err(ProtoError::InvalidTimestamp(format!(
            "time out of range: {s}"
        )));
    }

    let epoch_days = days_since_epoch(year, month, day);
    if epoch_days < 0 {
        return Err(ProtoError::InvalidTimestamp(format!(
            "date before epoch: {s}"
        )));
    }
    let total_secs =
        epoch_days as u64 * 86400 + u64::from(hour) * 3600 + u64::from(min) * 60 + u64::from(sec);

    Ok(total_secs * 1000 + frac_millis)
}

/// Convert milliseconds since Unix epoch to ISO 8601 UTC string.
///
/// Produces: `YYYY-MM-DDThh:mm:ss.SSSZ`
pub fn millis_to_iso8601(millis: u64) -> String {
    let total_secs = millis / 1000;
    let ms = millis % 1000;

    let days = (total_secs / 86400) as i64;
    let day_secs = total_secs % 86400;
    let hour = day_secs / 3600;
    let min = (day_secs % 3600) / 60;
    let sec = day_secs % 60;

    let (year, month, day) = date_from_epoch_days(days);

    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}.{ms:03}Z")
}

fn parse_part<'a, T: std::str::FromStr>(
    iter: &mut impl Iterator<Item = &'a str>,
    name: &str,
    original: &str,
) -> Result<T, ProtoError> {
    iter.next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| ProtoError::InvalidTimestamp(format!("missing {name}: {original}")))
}

/// Days since Unix epoch (1970-01-01) for a given date.
///
/// Uses the algorithm from Howard Hinnant's `civil_from_days` / `days_from_civil`.
fn days_since_epoch(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let m = if month <= 2 {
        month as i64 + 9
    } else {
        month as i64 - 3
    };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let doy = (153 * m as u64 + 2) / 5 + day as u64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe as i64 - 719468
}

/// Convert epoch days back to (year, month, day).
fn date_from_epoch_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_epoch() {
        let iso = "2021-02-27T20:32:24.771Z";
        let millis = iso8601_to_millis(iso).expect("parse");
        let back = millis_to_iso8601(millis);
        assert_eq!(back, iso);
    }

    #[test]
    fn round_trip_no_fraction() {
        let iso = "2021-02-27T20:32:24Z";
        let millis = iso8601_to_millis(iso).expect("parse");
        let back = millis_to_iso8601(millis);
        assert_eq!(back, "2021-02-27T20:32:24.000Z");
    }

    #[test]
    fn epoch_zero() {
        let millis = iso8601_to_millis("1970-01-01T00:00:00Z").expect("parse");
        assert_eq!(millis, 0);
    }

    #[test]
    fn known_timestamp() {
        // 2020-02-08T18:10:44.000Z = 1581185444000 ms
        let millis = iso8601_to_millis("2020-02-08T18:10:44.000Z").expect("parse");
        assert_eq!(millis, 1581185444000);
    }

    #[test]
    fn millis_to_iso_known() {
        let iso = millis_to_iso8601(1581185444000);
        assert_eq!(iso, "2020-02-08T18:10:44.000Z");
    }

    #[test]
    fn round_trip_2026() {
        let iso = "2026-02-26T12:00:00.000Z";
        let millis = iso8601_to_millis(iso).expect("parse");
        let back = millis_to_iso8601(millis);
        assert_eq!(back, iso);
    }

    #[test]
    fn invalid_no_separator() {
        assert!(iso8601_to_millis("20210227").is_err());
    }

    #[test]
    fn invalid_bad_date() {
        assert!(iso8601_to_millis("abc-02-27T20:32:24Z").is_err());
    }

    // ── regression tests for issue #370 (fuzz crashes) ───────────

    #[test]
    fn extreme_year_returns_err() {
        // Previously caused integer overflow panic in debug builds.
        assert!(iso8601_to_millis("25252525252525252-01-01T00:00:00Z").is_err());
        assert!(iso8601_to_millis("99999999999999999-01-01T00:00:00Z").is_err());
    }

    #[test]
    fn month_out_of_range() {
        assert!(iso8601_to_millis("2021-13-01T00:00:00Z").is_err());
        assert!(iso8601_to_millis("2021-00-01T00:00:00Z").is_err());
    }

    #[test]
    fn day_out_of_range() {
        assert!(iso8601_to_millis("2021-01-32T00:00:00Z").is_err());
        assert!(iso8601_to_millis("2021-01-00T00:00:00Z").is_err());
    }

    #[test]
    fn time_out_of_range() {
        assert!(iso8601_to_millis("2021-01-01T24:00:00Z").is_err());
        assert!(iso8601_to_millis("2021-01-01T00:60:00Z").is_err());
        assert!(iso8601_to_millis("2021-01-01T00:00:60Z").is_err());
    }

    #[test]
    fn non_ascii_fractional_seconds() {
        // Non-ASCII bytes in fractional seconds should not panic on string slicing.
        // The non-digit characters are filtered out, producing 0 millis.
        let millis = iso8601_to_millis("2021-01-01T00:00:00.\u{ff}\u{fe}\u{fd}Z").expect("parse");
        assert_eq!(millis % 1000, 0);
    }

    #[test]
    fn empty_fractional_seconds() {
        // Empty fraction after dot should produce 0 millis, not panic.
        let millis = iso8601_to_millis("2021-01-01T00:00:00.Z").expect("parse");
        assert_eq!(millis % 1000, 0);
    }
}
