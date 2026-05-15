// Copyright © 2026 Roberto Chiofalo.

//! Errors produced by the STANAG 4586 codec.
//!
//! The codec deliberately keeps the error surface narrow: every
//! failure mode that can be reached from a single
//! [`crate::vehicle_position::decode`] call has its own variant so
//! tests can pin behaviour and the session layer can route by
//! variant rather than re-parsing display strings.

use std::io;

/// Errors returned by [`crate::vehicle_position::decode`].
#[derive(Debug, thiserror::Error)]
pub enum Stanag4586Error {
    /// The input slice was shorter than the expected fixed-size frame.
    ///
    /// Surfaces the actual byte count so log readers can correlate
    /// against the documented frame length without having to guess
    /// from a generic "short read" message.
    #[error("STANAG 4586 frame too short: got {actual} bytes, need at least {expected}")]
    FrameTooShort {
        /// Bytes actually supplied to the decoder.
        actual: usize,
        /// Minimum byte count documented for the frame type.
        expected: usize,
    },

    /// A field whose value range is constrained by the spec carried a
    /// value outside that range.
    ///
    /// Currently emitted for the latitude/longitude bounds check
    /// during decode. The constraint is the plain WGS-84 range:
    /// `lat ∈ [-90, 90]`, `lon ∈ [-180, 180]`. Out-of-range values
    /// are typically a sign of a wire-format mismatch (wrong message
    /// type, byte-swapped header, …) so failing fast is more useful
    /// than silently clamping.
    #[error("STANAG 4586 field `{field}` out of spec range: {value}")]
    FieldOutOfRange {
        /// Name of the offending field.
        field: &'static str,
        /// Stringified value (`f64::to_string` for floats) so the
        /// caller does not have to keep the original numeric type
        /// alive in the error chain.
        value: String,
    },

    /// Catch-all for errors surfaced by the schema-driven codec runtime
    /// that the wire-format error vocabulary above does not have a
    /// dedicated variant for.
    ///
    /// The wrapped string carries the underlying
    /// [`rustgate_codec_schema::SchemaCodecError`] display form so
    /// operator logs name the root cause (typically a missing /
    /// wrong-typed attribute on the round-trip path, which only
    /// happens if a future schema revision drops a field).
    /// `FrameTooShort` and `FieldOutOfRange` (the operationally
    /// common rejects) are mapped to their dedicated variants first;
    /// `Schema` captures the long tail without growing the public
    /// API surface for one-off schema-internal errors.
    #[error("STANAG 4586 schema codec error: {0}")]
    Schema(String),
}

impl From<Stanag4586Error> for io::Error {
    fn from(err: Stanag4586Error) -> Self {
        io::Error::new(io::ErrorKind::InvalidData, err)
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, unused_results)]
mod tests {
    use std::error::Error as _;

    use super::*;

    #[test]
    fn frame_too_short_display_contains_both_sizes() {
        let err = Stanag4586Error::FrameTooShort {
            actual: 12,
            expected: 40,
        };
        assert_eq!(
            err.to_string(),
            "STANAG 4586 frame too short: got 12 bytes, need at least 40"
        );
    }

    #[test]
    fn field_out_of_range_display_includes_field_and_value() {
        let err = Stanag4586Error::FieldOutOfRange {
            field: "latitude_deg",
            value: "95.5".into(),
        };
        assert_eq!(
            err.to_string(),
            "STANAG 4586 field `latitude_deg` out of spec range: 95.5"
        );
    }

    #[test]
    fn from_into_io_error_sets_invalid_data() {
        let err: io::Error = Stanag4586Error::FrameTooShort {
            actual: 0,
            expected: 40,
        }
        .into();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn no_variant_carries_a_source() {
        // Pin that source() bottoms out at None for every variant —
        // a future refactor that wraps an inner error must update
        // its tests rather than break consumers iterating the chain.
        assert!(
            Stanag4586Error::FrameTooShort {
                actual: 0,
                expected: 0,
            }
            .source()
            .is_none()
        );
        assert!(
            Stanag4586Error::FieldOutOfRange {
                field: "x",
                value: "0".into(),
            }
            .source()
            .is_none()
        );
        assert!(Stanag4586Error::Schema("test".into()).source().is_none());
    }

    #[test]
    fn schema_variant_display_quotes_inner_message() {
        // Pin the wrapped-error display so any future refactor that
        // changes the prefix string regenerates this assertion at
        // the same time. Operator log readers grep on the prefix.
        let err = Stanag4586Error::Schema("payload too short".into());
        assert_eq!(
            err.to_string(),
            "STANAG 4586 schema codec error: payload too short"
        );
    }
}
