// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

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

    /// Encoding would produce a payload larger than the maximum frame size.
    /// A `repeat` field's count is taken from the source
    /// [`Entity`](rustgate_core::entity::Entity) — ultimately an
    /// attacker-influenced wire field in cross-protocol transcoding — so an
    /// unbounded count would grow the output buffer past
    /// [`rustgate_core::constants::MAX_FRAME_SIZE`]. Rejecting here bounds a
    /// transcode-side allocation DoS that would otherwise drive
    /// `Vec::resize` to a multi-gigabyte allocation.
    #[error("encoded payload would be {needed} bytes, exceeding the {limit}-byte maximum")]
    PayloadTooLarge {
        /// Byte length the encode would have required.
        needed: usize,
        /// The maximum permitted (`MAX_FRAME_SIZE`).
        limit: usize,
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

    /// A byte-aligned field follows a v5 [`ShiftMode::CollapseWhenAbsent`]
    /// bit-packed field whose absence left the bit cursor on a
    /// non-byte-aligned position. The schema is inherently broken for
    /// the actual data: a byte field cannot start mid-byte.
    ///
    /// The schema author should either:
    /// - Ensure every collapse-when-absent bit-packed field's
    ///   `bit_width` is a multiple of 8 (so the shift stays
    ///   byte-aligned), or
    /// - Move byte fields ahead of the collapse-when-absent section.
    ///
    /// [`ShiftMode::CollapseWhenAbsent`]: crate::ShiftMode::CollapseWhenAbsent
    #[error(
        "byte-aligned field `{field}` cannot follow a bit-packed collapse-when-absent field that left a non-byte-aligned bit-cursor offset ({bit_shift} bits)"
    )]
    BitCursorMisalignment {
        /// The byte-aligned field whose offset cannot be resolved.
        field: String,
        /// Bits of shift accumulated from earlier collapse-when-absent
        /// fields; not a multiple of 8.
        bit_shift: usize,
    },
}
