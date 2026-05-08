// Copyright © 2026 Roberto Chiofalo.

//! Typed error variants surfaced by the NFFI codec.
//!
//! Every failure path in this crate maps to one of these variants —
//! the parser never panics and the encoder never silently drops
//! data. The enum is non-exhaustive so future variants can land
//! without a breaking change at the consumer boundary.

/// Failure modes for [`crate::codec::NffiCodec`] and the underlying
/// [`crate::codec::decode_document`] / [`crate::codec::encode_document`]
/// primitives.
///
/// Distinct from the canonical workspace `RustgateError` because
/// the boundary aggregator (used in the `rustgate-core` /
/// `rustgate-router` slice) is not automatically constructed from
/// per-codec errors — binary callers propagate `?` and map at the
/// orchestration layer.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NffiError {
    /// Wraps an underlying `quick-xml` reader / writer error. Most
    /// commonly a malformed XML document (mismatched tags,
    /// truncated input, invalid attribute quoting) — surface the
    /// upstream message verbatim so an operator can correlate
    /// against the source frame.
    #[error("XML parse error: {0}")]
    Xml(#[from] quick_xml::Error),

    /// The encoded NFFI payload exceeds the
    /// [`crate::MAX_PAYLOAD_BYTES`] defense-in-depth cap. Surfaces
    /// on encode (the encoder declines to emit) and on decode (a
    /// frame whose payload length exceeds the cap is rejected
    /// before allocation). Real coalition feeds never approach
    /// this cap; tripping it is almost always a sign of hostile or
    /// corrupted input.
    #[error(
        "NFFI payload {bytes} bytes exceeds {} byte cap",
        crate::MAX_PAYLOAD_BYTES
    )]
    PayloadTooLarge {
        /// Size of the offending payload in bytes.
        bytes: usize,
    },

    /// A required attribute (e.g. `lat` on `<wgs84Position>`) was
    /// missing from a parsed element. The element name and missing
    /// attribute are both reported so an operator can pinpoint the
    /// offending input.
    #[error("element `{element}` missing required attribute `{attribute}`")]
    MissingAttribute {
        /// Element local name (e.g. `"wgs84Position"`).
        element: &'static str,
        /// Missing attribute name (e.g. `"lat"`).
        attribute: &'static str,
    },

    /// An attribute value did not parse as the expected float.
    /// Typical cause: an upstream sensor bug or a frame routed
    /// through a transport that munged the bytes.
    #[error("invalid float for attribute `{attribute}` on element `{element}`")]
    InvalidFloat {
        /// Element local name where the offending attribute was
        /// found.
        element: &'static str,
        /// Attribute name that failed to parse.
        attribute: &'static str,
    },

    /// A numeric field was out of its spec-defined range. STANAG
    /// 5527 borrows the WGS-84 lat/lon envelope from MIL-STD-2525:
    /// latitude is `[-90, 90]`, longitude is `[-180, 180]`. Course
    /// is degrees clockwise from true north `[0, 360)`. Values
    /// outside these ranges are rejected rather than propagated to
    /// downstream geofilter / multicast logic.
    #[error("field `{field}` out of range: {value}")]
    OutOfRange {
        /// Name of the offending field (e.g. `"lat"`, `"course"`).
        field: &'static str,
        /// The offending value.
        value: f64,
    },

    /// The 15-character APP-6A SIDC string failed to parse. NFFI
    /// `<sidc>` bodies are spec'd as exactly 15 characters; a
    /// shorter or longer body is rejected. The `actual` length is
    /// reported so an operator can correlate against the source.
    #[error("APP-6A SIDC must be exactly 15 characters, got {actual}")]
    InvalidSidcLength {
        /// Actual length of the offending SIDC string.
        actual: usize,
    },

    /// The decoded NFFI document carried no `<track>` elements.
    /// A document without any track payload is structurally valid
    /// XML but operationally meaningless — surface this as a typed
    /// error rather than returning an empty `Vec` so the caller
    /// must decide between "skip silently" and "log and continue".
    #[error("NFFI document carries no <track> elements")]
    NoTracks,

    /// Encode path: the supplied [`rustgate_core::entity::Entity`]
    /// has no shape that fits the NFFI wire form (typically an
    /// event with no position the codec can lift into a
    /// `<wgs84Position>`). Cross-protocol fan-out callers see this
    /// for entities the NFFI spec does not model.
    #[error("entity cannot be mapped to NFFI track: {0}")]
    UnsupportedEntity(String),
}
