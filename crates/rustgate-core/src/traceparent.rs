// Copyright © 2026 Roberto Chiofalo.

//! W3C Trace Context propagation primitives.
//!
//! Implements the wire-stable [`TraceContext`] value type along with a
//! strict parser and `Display` for the W3C `traceparent` header
//! defined in <https://www.w3.org/TR/trace-context/>. The companion
//! `tracestate` header value is carried alongside as an opaque,
//! length-bounded string per RFC.
//!
//! This module is the type backbone for cross-server distributed-trace
//! propagation across federation, NATS, HTTP, and other egress paths.
//! Persisting [`TraceContext`] on `RoutableMessage::metadata` is a
//! deferred change tracked under issue #852 (PR-C of the split plan);
//! this module ships the type and parser only so transports can inject
//! and extract `traceparent` at protocol boundaries (PR-A + PR-B
//! deliverables).

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Maximum permitted size of the `tracestate` header value, per the
/// W3C Trace Context specification (section 3.3.1.2). Implementations
/// MUST limit the size to 512 bytes; values exceeding this are rejected.
pub const MAX_TRACESTATE_BYTES: usize = 512;

/// Parsed W3C `traceparent` header plus its companion `tracestate`.
///
/// The wire-stable serialization form is the W3C `traceparent` banner
/// `00-{trace_id_hex}-{parent_span_id_hex}-{flags_hex}`, so the type
/// uses serde delegation through `Display` / `FromStr` (`#[serde(into,
/// try_from)]`). JSON, TOML, bincode, and MsgPack all therefore carry
/// the same banner string a peer sees on the wire instead of a struct
/// dump that would break on a future field addition.
///
/// # Wire format
///
/// `00-` indicates version 00 — the only currently-defined version the
/// parser accepts. A different version byte is rejected with
/// [`ParseTraceparentError::UnsupportedVersion`].
///
/// # All-zero invariants
///
/// Per W3C section 3.2.2.3, an all-zero `trace_id` or all-zero
/// `parent_span_id` is invalid and MUST be rejected. The parser
/// enforces both invariants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(into = "String", try_from = "String")]
pub struct TraceContext {
    /// 128-bit trace identifier (16 bytes).
    pub trace_id: [u8; 16],
    /// 64-bit parent span identifier (8 bytes).
    pub parent_span_id: [u8; 8],
    /// W3C trace flags. Bit 0 is the `sampled` flag.
    pub trace_flags: u8,
    /// Companion `tracestate` header value, capped at
    /// [`MAX_TRACESTATE_BYTES`] (512 bytes per RFC).
    pub tracestate: Option<String>,
}

impl TraceContext {
    /// Construct a new [`TraceContext`] without a `tracestate` companion.
    ///
    /// Validates the all-zero invariants on `trace_id` and `parent_span_id`.
    pub fn new(
        trace_id: [u8; 16],
        parent_span_id: [u8; 8],
        trace_flags: u8,
    ) -> Result<Self, ParseTraceparentError> {
        if trace_id.iter().all(|b| *b == 0) {
            return Err(ParseTraceparentError::AllZeroTraceId);
        }
        if parent_span_id.iter().all(|b| *b == 0) {
            return Err(ParseTraceparentError::AllZeroSpanId);
        }
        Ok(Self {
            trace_id,
            parent_span_id,
            trace_flags,
            tracestate: None,
        })
    }

    /// Attach a `tracestate` companion. Returns
    /// [`ParseTraceparentError::TracestateTooLarge`] when the input
    /// exceeds [`MAX_TRACESTATE_BYTES`].
    pub fn with_tracestate(mut self, ts: impl Into<String>) -> Result<Self, ParseTraceparentError> {
        let ts = ts.into();
        if ts.len() > MAX_TRACESTATE_BYTES {
            return Err(ParseTraceparentError::TracestateTooLarge {
                size: ts.len(),
                limit: MAX_TRACESTATE_BYTES,
            });
        }
        self.tracestate = Some(ts);
        Ok(self)
    }

    /// Returns `true` when the W3C `sampled` flag (bit 0 of
    /// `trace_flags`) is set.
    pub fn is_sampled(&self) -> bool {
        self.trace_flags & 0x01 != 0
    }
}

/// Typed error for [`TraceContext::from_str`] / [`TraceContext::new`]
/// failures. Each variant maps to a distinct W3C parser rejection
/// reason so the audit trail can record exactly why a remote peer's
/// header was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseTraceparentError {
    /// The header did not consist of exactly four `-`-separated parts.
    #[error("expected 4 '-'-separated fields, got {got}")]
    WrongFieldCount {
        /// Observed field count.
        got: usize,
    },
    /// The version byte was not `00`. Future W3C versions will be
    /// added explicitly when this implementation is updated.
    #[error("unsupported traceparent version {version:?} (only `00` is accepted)")]
    UnsupportedVersion {
        /// The two-character version field as observed in the header.
        version: String,
    },
    /// One of the hex fields had the wrong length.
    #[error("field `{field}` expected {expected} hex chars, got {got}")]
    WrongLength {
        /// Field name (`trace_id`, `parent_span_id`, or `flags`).
        field: &'static str,
        /// Expected character count.
        expected: usize,
        /// Observed character count.
        got: usize,
    },
    /// One of the hex fields contained a non-hex character.
    #[error("field `{field}` contains non-hex character")]
    NonHex {
        /// Field name (`trace_id`, `parent_span_id`, or `flags`).
        field: &'static str,
    },
    /// The `trace_id` was all zeros, which W3C section 3.2.2.3 forbids.
    #[error("trace_id must not be all zero")]
    AllZeroTraceId,
    /// The `parent_span_id` was all zeros, which W3C section 3.2.2.3
    /// forbids.
    #[error("parent_span_id must not be all zero")]
    AllZeroSpanId,
    /// The `tracestate` companion exceeded the W3C 512-byte cap.
    #[error("tracestate exceeds 512-byte cap: got {size} bytes (limit {limit})")]
    TracestateTooLarge {
        /// Observed length.
        size: usize,
        /// Configured cap (always [`MAX_TRACESTATE_BYTES`]).
        limit: usize,
    },
}

impl fmt::Display for TraceContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Lowercase hex, fixed-width, version `00` per W3C section 3.2.
        // Iterate so we avoid an intermediate allocation and keep the
        // hot-path `Display` trivial.
        f.write_str("00-")?;
        for byte in &self.trace_id {
            write!(f, "{byte:02x}")?;
        }
        f.write_str("-")?;
        for byte in &self.parent_span_id {
            write!(f, "{byte:02x}")?;
        }
        write!(f, "-{:02x}", self.trace_flags)
    }
}

/// Decode a single hex byte from two ASCII hex characters. Returns
/// `None` when either character is not a hex digit. Inlined into the
/// parser hot path so the per-character branch is one cmov on the happy
/// path.
fn decode_hex_byte(hi: u8, lo: u8) -> Option<u8> {
    let h = hex_nibble(hi)?;
    let l = hex_nibble(lo)?;
    Some((h << 4) | l)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn decode_hex_field<const N: usize>(
    s: &str,
    field: &'static str,
) -> Result<[u8; N], ParseTraceparentError> {
    let expected = N * 2;
    if s.len() != expected {
        return Err(ParseTraceparentError::WrongLength {
            field,
            expected,
            got: s.len(),
        });
    }
    let bytes = s.as_bytes();
    let mut out = [0u8; N];
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = bytes[i * 2];
        let lo = bytes[i * 2 + 1];
        *slot = decode_hex_byte(hi, lo).ok_or(ParseTraceparentError::NonHex { field })?;
    }
    Ok(out)
}

impl FromStr for TraceContext {
    type Err = ParseTraceparentError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // W3C section 3.2.1: the header is four `-`-separated fields.
        // We split into 5 parts and explicitly reject overflow rather
        // than tolerating trailing junk.
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() != 4 {
            return Err(ParseTraceparentError::WrongFieldCount { got: parts.len() });
        }

        let version = parts[0];
        if version != "00" {
            return Err(ParseTraceparentError::UnsupportedVersion {
                version: version.to_string(),
            });
        }

        let trace_id = decode_hex_field::<16>(parts[1], "trace_id")?;
        let parent_span_id = decode_hex_field::<8>(parts[2], "parent_span_id")?;
        let flags_field = parts[3];
        let flags_arr = decode_hex_field::<1>(flags_field, "flags")?;
        let trace_flags = flags_arr[0];

        // Constructor enforces the W3C all-zero invariants.
        Self::new(trace_id, parent_span_id, trace_flags)
    }
}

// Serde delegation. `#[serde(into = "String", try_from = "String")]`
// runs through these conversions, giving us banner-string round-trip
// across every serializer the workspace uses.

impl From<TraceContext> for String {
    fn from(ctx: TraceContext) -> Self {
        ctx.to_string()
    }
}

impl TryFrom<String> for TraceContext {
    type Error = ParseTraceparentError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use super::*;

    fn sample_trace_id() -> [u8; 16] {
        [
            0x4b, 0xf9, 0x2f, 0x35, 0x77, 0xb3, 0x4d, 0xa6, 0xa3, 0xce, 0x92, 0x9d, 0x0e, 0x0e,
            0x47, 0x36,
        ]
    }

    fn sample_span_id() -> [u8; 8] {
        [0x00, 0xf0, 0x67, 0xaa, 0x0b, 0xa9, 0x02, 0xb7]
    }

    #[test]
    fn traceparent_round_trips_through_display_and_fromstr() {
        let banner = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        let ctx: TraceContext = banner.parse().expect("parse");
        assert_eq!(ctx.trace_id, sample_trace_id());
        assert_eq!(ctx.parent_span_id, sample_span_id());
        assert_eq!(ctx.trace_flags, 0x01);
        assert!(ctx.is_sampled());
        assert_eq!(ctx.to_string(), banner);
    }

    #[test]
    fn traceparent_rejects_non_version_00() {
        // W3C reserves all non-`00` version bytes; a parser must reject
        // them rather than guess at field layout.
        let banner = "01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        let err = banner
            .parse::<TraceContext>()
            .expect_err("non-00 must reject");
        assert!(matches!(
            err,
            ParseTraceparentError::UnsupportedVersion { ref version } if version == "01"
        ));
    }

    #[test]
    fn traceparent_rejects_wrong_length() {
        // Trace-id with one fewer hex char.
        let banner = "00-4bf92f3577b34da6a3ce929d0e0e473-00f067aa0ba902b7-01";
        let err = banner
            .parse::<TraceContext>()
            .expect_err("short trace_id must reject");
        assert!(matches!(
            err,
            ParseTraceparentError::WrongLength {
                field: "trace_id",
                expected: 32,
                got: 31,
            }
        ));
    }

    #[test]
    fn traceparent_rejects_non_hex_characters() {
        // 'g' is outside [0-9a-f] and must trip the NonHex variant.
        let banner = "00-4bf92f3577b34da6a3ce929d0e0e4g36-00f067aa0ba902b7-01";
        let err = banner
            .parse::<TraceContext>()
            .expect_err("non-hex must reject");
        assert!(matches!(
            err,
            ParseTraceparentError::NonHex { field: "trace_id" }
        ));
    }

    #[test]
    fn traceparent_rejects_all_zero_trace_id() {
        // W3C section 3.2.2.3: an all-zero trace_id is invalid.
        let banner = "00-00000000000000000000000000000000-00f067aa0ba902b7-01";
        let err = banner
            .parse::<TraceContext>()
            .expect_err("all-zero trace_id must reject");
        assert_eq!(err, ParseTraceparentError::AllZeroTraceId);
    }

    #[test]
    fn traceparent_rejects_all_zero_span_id() {
        // W3C section 3.2.2.3: an all-zero parent_span_id is invalid.
        let banner = "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01";
        let err = banner
            .parse::<TraceContext>()
            .expect_err("all-zero span_id must reject");
        assert_eq!(err, ParseTraceparentError::AllZeroSpanId);
    }

    #[test]
    fn tracestate_within_512_byte_cap_round_trips() {
        // Pin that `with_tracestate` accepts a 512-byte payload exactly
        // (boundary is inclusive). 512 ASCII bytes round-trip through
        // `tracestate` without truncation.
        let payload: String = "a".repeat(MAX_TRACESTATE_BYTES);
        let ctx = TraceContext::new(sample_trace_id(), sample_span_id(), 0x01)
            .expect("new")
            .with_tracestate(&payload)
            .expect("at-cap tracestate must succeed");
        assert_eq!(ctx.tracestate.as_deref(), Some(payload.as_str()));
    }

    #[test]
    fn tracestate_over_512_bytes_rejected() {
        // Byte 513 is the first that exceeds the cap — the error
        // surfaces the observed and configured sizes so audit records
        // can include the precise overflow.
        let oversize = "x".repeat(MAX_TRACESTATE_BYTES + 1);
        let ctx = TraceContext::new(sample_trace_id(), sample_span_id(), 0x00).expect("new");
        let err = ctx
            .with_tracestate(&oversize)
            .expect_err("over-cap must reject");
        assert!(matches!(
            err,
            ParseTraceparentError::TracestateTooLarge {
                size: 513,
                limit: 512,
            }
        ));
    }

    #[test]
    fn serde_json_round_trip_uses_display_form() {
        // JSON, TOML, bincode, and MsgPack all delegate to the
        // `String` adapter — pin the banner-string serialization here
        // so a future struct-dump regression fails fast.
        let ctx = TraceContext::new(sample_trace_id(), sample_span_id(), 0x01).expect("new");
        let json = serde_json::to_string(&ctx).expect("serialize");
        assert_eq!(
            json,
            "\"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01\""
        );
        let back: TraceContext = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, ctx);
    }

    #[test]
    fn traceparent_rejects_field_count_mismatch() {
        // Three `-` separators give 4 fields — anything else is a
        // malformed banner.
        let banner = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7";
        let err = banner
            .parse::<TraceContext>()
            .expect_err("3 fields must reject");
        assert!(matches!(
            err,
            ParseTraceparentError::WrongFieldCount { got: 3 }
        ));
    }

    #[test]
    fn traceparent_uppercase_hex_is_normalized_to_lowercase_on_display() {
        // The parser tolerates uppercase hex (per `hex_nibble`) but the
        // canonical wire form is lowercase (W3C section 3.2.1).
        // Round-trip an uppercase input through Display and assert it
        // emerges lowercase.
        let upper = "00-4BF92F3577B34DA6A3CE929D0E0E4736-00F067AA0BA902B7-01";
        let ctx: TraceContext = upper.parse().expect("parse uppercase");
        let lower = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        assert_eq!(ctx.to_string(), lower);
    }

    #[test]
    fn is_sampled_reads_bit_zero() {
        let ctx = TraceContext::new(sample_trace_id(), sample_span_id(), 0x00).expect("new");
        assert!(!ctx.is_sampled());
        let ctx = TraceContext::new(sample_trace_id(), sample_span_id(), 0x01).expect("new");
        assert!(ctx.is_sampled());
        // Bit 0 only — bit 1 must not flip the sampled determination.
        let ctx = TraceContext::new(sample_trace_id(), sample_span_id(), 0x02).expect("new");
        assert!(!ctx.is_sampled());
    }
}
