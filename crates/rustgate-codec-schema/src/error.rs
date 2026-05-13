// Copyright © 2026 Roberto Chiofalo.

//! Typed errors for schema parsing and schema-driven codec
//! operations.

/// Errors surfaced while parsing or validating a [`Schema`].
///
/// [`Schema`]: crate::Schema
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SchemaError {
    /// The schema YAML / JSON failed to parse against the typed
    /// [`Schema`] shape. The wrapped string is the serde error
    /// message verbatim — callers should surface it to operators
    /// as-is.
    ///
    /// [`Schema`]: crate::Schema
    #[error("schema parse failed: {0}")]
    Parse(String),

    /// The schema parsed but failed structural validation. Common
    /// causes:
    /// - Two fields overlap (the byte ranges intersect).
    /// - A field extends past the declared `message_size_bytes`.
    /// - The `discriminator_offset` points outside the message
    ///   payload.
    /// - An [`Entity`](rustgate_core::entity::Entity) projection
    ///   target uses an unknown dotted path.
    /// - Calibration coefficients are non-finite (NaN / Inf).
    #[error("schema validation failed: {message}")]
    Validation {
        /// Operator-readable diagnostic.
        message: String,
    },
}

/// Errors surfaced while encoding / decoding payloads against a
/// [`Schema`].
///
/// [`Schema`]: crate::Schema
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SchemaCodecError {
    /// The payload is shorter than the schema's declared
    /// `message_size_bytes`.
    #[error("payload too short: got {actual} bytes, schema requires at least {required}")]
    PayloadTooShort {
        /// Byte length the caller supplied.
        actual: usize,
        /// Byte length the schema requires.
        required: usize,
    },

    /// Decoded bytes are not valid UTF-8 for a string field.
    #[error("field `{field}` UTF-8 decode failed: {source}")]
    Utf8 {
        /// Field name the schema labelled this string.
        field: String,
        /// The std-library decode error.
        #[source]
        source: std::str::Utf8Error,
    },

    /// An [`Entity`](rustgate_core::entity::Entity) value mapped via
    /// `value_mapping` did not match any of the declared raw values,
    /// and no `default_raw` was configured. The schema is incomplete
    /// for the actual data the producer is emitting.
    #[error(
        "field `{field}`: no value-mapping entry matches `{value}` and no default_raw configured"
    )]
    UnmappedValue {
        /// Field name.
        field: String,
        /// Value that wasn't found in the mapping.
        value: String,
    },

    /// The Entity field a schema field projects to is missing on the
    /// supplied [`Entity`](rustgate_core::entity::Entity) and the
    /// schema field is marked required (no default). Common when an
    /// encoder is asked to emit an Entity that lacks the field a
    /// schema expects.
    #[error("Entity field `{path}` is required by schema field `{field}` but is missing")]
    MissingRequiredEntityField {
        /// Schema field name.
        field: String,
        /// Dotted path the schema field projects from.
        path: String,
    },

    /// A field value exceeds the wire-format's representable range
    /// (e.g. trying to encode `300` into a `u8`). Includes the field
    /// name + the value that failed.
    #[error("field `{field}` value `{value}` is out of range for type `{type_name}`")]
    OutOfRange {
        /// Schema field name.
        field: String,
        /// Value the encoder tried to write.
        value: String,
        /// Schema field type name (`u8`, `i16`, `f32`, …).
        type_name: String,
    },

    /// Multi-message dispatch failed to find a [`MessageType`] whose
    /// `id` matches the byte read at the schema's
    /// `discriminator_offset`. The schema's vocabulary doesn't
    /// cover the wire variant the producer is emitting.
    ///
    /// [`MessageType`]: crate::MessageType
    #[error(
        "no message type matches discriminator byte 0x{value:02x} at offset {offset}; add the missing message-type id to the schema"
    )]
    UnknownDiscriminator {
        /// Offset where the runtime read the discriminator byte.
        offset: usize,
        /// Byte value that did not match any declared `id`.
        value: u8,
    },
}
