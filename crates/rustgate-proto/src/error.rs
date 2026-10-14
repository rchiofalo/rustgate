// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Protocol translation error types.

/// Errors during TAK protocol buffer translation.
#[derive(Debug, thiserror::Error)]
pub enum ProtoError {
    #[error("protobuf decode: {0}")]
    Decode(#[from] prost::DecodeError),

    #[error("protobuf encode: {0}")]
    Encode(#[from] prost::EncodeError),

    #[error("xml parse: {0}")]
    Xml(#[from] quick_xml::Error),

    #[error("missing field: {0}")]
    MissingField(&'static str),

    /// A required protocol-negotiation version field was absent on the
    /// wire (the proto3 `uint32` zero default) or sent explicitly as `0`.
    ///
    /// `min_proto_version` / `max_proto_version` are `uint32`; proto3
    /// decodes an unset scalar to `0`, which is indistinguishable from a
    /// literal `0`. Pre-F-64, `parse_tak_request` silently mapped that
    /// unset default to the server's supported range, which let a
    /// malicious client force negotiation to `MAX_PROTO_VERSION` without
    /// populating the fields. The server now rejects `0` (never a valid
    /// version — the lowest real version is `1`); it surfaces as this
    /// typed error.
    #[error("missing or zero protocol-negotiation field: {0}")]
    BlankVersion(&'static str),

    #[error("invalid timestamp: {0}")]
    InvalidTimestamp(String),

    #[error("frame too large: {size} bytes (max {max})")]
    FrameTooLarge { size: usize, max: usize },

    /// A numeric field was outside its spec-defined range.
    ///
    /// MITRE CoT Message Router User's Guide (MP090284) Table 2-1 defines
    /// `lat` and `lon` in WGS-84 decimal degrees: latitude -90..=90,
    /// longitude -180..=180.
    #[error("field `{field}` out of range: {value}")]
    OutOfRange { field: &'static str, value: f64 },
}

impl From<ProtoError> for std::io::Error {
    fn from(e: ProtoError) -> Self {
        std::io::Error::new(std::io::ErrorKind::InvalidData, e)
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn missing_field_display_contains_field_name() {
        let err = ProtoError::MissingField("uid");
        assert_eq!(err.to_string(), "missing field: uid");
    }

    #[test]
    fn invalid_timestamp_display_carries_value() {
        let err = ProtoError::InvalidTimestamp("not-a-date".to_string());
        assert_eq!(err.to_string(), "invalid timestamp: not-a-date");
    }

    #[test]
    fn frame_too_large_display_names_both_bounds() {
        // Diagnostic contract: both `size` and `max` must appear in the
        // message so operators can see by how much the incoming frame
        // exceeded the cap without re-parsing the structured error.
        let err = ProtoError::FrameTooLarge {
            size: 16_777_216,
            max: 1_048_576,
        };
        let msg = err.to_string();
        assert!(msg.contains("16777216"), "missing actual size: {msg}");
        assert!(msg.contains("1048576"), "missing max bound: {msg}");
    }

    #[test]
    fn out_of_range_display_names_field_and_value() {
        // Lat/lon validation surfaces OutOfRange. The field name must
        // be recognizable ("lat" / "lon") and the offending value must
        // appear verbatim for debugging.
        let err = ProtoError::OutOfRange {
            field: "lat",
            value: 91.5,
        };
        let msg = err.to_string();
        assert!(msg.contains("lat"), "missing field name: {msg}");
        assert!(msg.contains("91.5"), "missing value: {msg}");
    }

    #[test]
    fn from_prost_decode_error_maps_to_decode_variant() {
        // prost only constructs DecodeError internally, so we trigger
        // it by handing prost garbage bytes and decoding a known type.
        let err: prost::DecodeError = prost::Message::decode(&b"\xFF\xFF"[..])
            .map(|_: crate::tak_proto::TakControl| ())
            .unwrap_err();
        let wrapped: ProtoError = err.into();
        assert!(matches!(wrapped, ProtoError::Decode(_)));
        assert!(wrapped.to_string().starts_with("protobuf decode:"));
    }

    #[test]
    fn from_quick_xml_error_maps_to_xml_variant() {
        // Generate a genuine quick_xml::Error from an unterminated tag.
        let mut reader = quick_xml::Reader::from_str("<unclosed");
        let mut buf = Vec::new();
        let err: quick_xml::Error = loop {
            match reader.read_event_into(&mut buf) {
                Ok(quick_xml::events::Event::Eof) => {
                    panic!("expected a parse error, got EOF");
                }
                Ok(_) => continue,
                Err(e) => break e,
            }
        };
        let wrapped: ProtoError = err.into();
        assert!(matches!(wrapped, ProtoError::Xml(_)));
        assert!(wrapped.to_string().starts_with("xml parse:"));
    }

    #[test]
    fn into_io_error_uses_invalid_data_kind() {
        // The io::Error conversion is used by the codec wrapper to
        // bubble protocol errors up to framed-codec consumers. Pinning
        // ErrorKind::InvalidData keeps session cleanup paths predictable.
        let proto_err = ProtoError::MissingField("contact.callsign");
        let io_err: std::io::Error = proto_err.into();
        assert_eq!(io_err.kind(), std::io::ErrorKind::InvalidData);
        assert!(io_err.to_string().contains("contact.callsign"));
    }

    #[test]
    fn into_io_error_preserves_source_chain() {
        // `Display` on the io::Error should reflect the wrapped ProtoError's
        // message — source preservation lets `.downcast` work upstream.
        let proto_err = ProtoError::InvalidTimestamp("2026-13-40".to_string());
        let io_err: std::io::Error = proto_err.into();
        let inner = io_err.into_inner().expect("io::Error should wrap source");
        assert!(inner.downcast_ref::<ProtoError>().is_some());
    }
}
