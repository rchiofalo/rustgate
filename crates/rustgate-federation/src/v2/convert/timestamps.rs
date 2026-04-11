// Copyright © 2026 Roberto Chiofalo.

//! Timestamp parsing and formatting utilities for federation conversions.
//!
//! Wraps the low-level `rustgate-proto` timestamp helpers with
//! `ConvertError`-returning variants so that callers in this module
//! don't need to manually convert `ProtoError`.

use rustgate_proto::convert::timestamp::{iso8601_to_millis, millis_to_iso8601};

use super::ConvertError;

/// Parse an ISO 8601 timestamp string into milliseconds since the Unix epoch.
///
/// Returns `0` when the input is empty rather than raising an error, since
/// federation protocol messages frequently omit optional timestamps.
pub(crate) fn parse_timestamp_millis(iso: &str) -> Result<i64, ConvertError> {
    if iso.is_empty() {
        return Ok(0);
    }
    Ok(iso8601_to_millis(iso)? as i64)
}

/// Format milliseconds since the Unix epoch as an ISO 8601 string.
///
/// Returns an empty string when the input is `0`.
pub(crate) fn format_timestamp_millis(millis: i64) -> String {
    if millis <= 0 {
        return String::new();
    }
    millis_to_iso8601(millis as u64)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn empty_string_returns_zero() {
        assert_eq!(parse_timestamp_millis("").unwrap(), 0);
    }

    #[test]
    fn valid_timestamp_parses() {
        let millis = parse_timestamp_millis("2021-02-27T20:32:24.000Z").unwrap();
        assert!(millis > 0);
    }

    #[test]
    fn invalid_timestamp_returns_error() {
        assert!(parse_timestamp_millis("not-a-timestamp").is_err());
    }

    #[test]
    fn zero_millis_formats_to_empty() {
        assert_eq!(format_timestamp_millis(0), "");
    }

    #[test]
    fn positive_millis_formats_to_iso8601() {
        let s = format_timestamp_millis(1614460344000);
        assert!(s.contains("2021"));
    }
}
