// Copyright © 2026 Roberto Chiofalo.

//! Conversion between CoT XML, RoutableMessage, and V2 FederatedEvent types.
//!
//! Provides bidirectional conversions for the V2 gRPC federation protocol:
//! - CoT XML ↔ `FederatedEvent` (proto)
//! - `RoutableMessage` ↔ `FederatedEvent` (for routing through the manager)
//!
//! All XML parsing delegates to `rustgate-proto` for security-validated parsing.

mod cot_to_event;
mod routable_message;
mod timestamps;

// Re-export all public items for API compatibility.
pub use cot_to_event::{
    add_flow_tag, contact_list_entry_to_xml, federated_event_to_xml, xml_to_federated_event,
};
pub use routable_message::{
    extract_metadata, federated_event_to_routable, routable_to_federated_event,
};

use super::proto;

/// Errors that can occur during format conversion.
#[derive(Debug)]
pub enum ConvertError {
    /// XML parsing failed.
    Xml(String),
    /// A required field was missing in the source data.
    MissingField(&'static str),
    /// A field value is invalid.
    InvalidField(String),
    /// Timestamp conversion failed.
    InvalidTimestamp(String),
}

impl std::fmt::Display for ConvertError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Xml(msg) => write!(f, "xml parse error: {msg}"),
            Self::MissingField(field) => write!(f, "missing required field: {field}"),
            Self::InvalidField(msg) => write!(f, "invalid field: {msg}"),
            Self::InvalidTimestamp(msg) => write!(f, "invalid timestamp: {msg}"),
        }
    }
}

impl std::error::Error for ConvertError {}

impl From<rustgate_proto::ProtoError> for ConvertError {
    fn from(e: rustgate_proto::ProtoError) -> Self {
        match e {
            rustgate_proto::ProtoError::MissingField(f) => Self::MissingField(f),
            rustgate_proto::ProtoError::InvalidTimestamp(s) => Self::InvalidTimestamp(s),
            other => Self::Xml(other.to_string()),
        }
    }
}

// ---------------------------------------------------------------------------
// XML helpers
// ---------------------------------------------------------------------------

/// Write an XML attribute (`name="value"`) with proper escaping.
fn write_attr(xml: &mut Vec<u8>, name: &str, value: &str) {
    xml.push(b' ');
    xml.extend_from_slice(name.as_bytes());
    xml.extend_from_slice(b"=\"");
    xml_escape_into(xml, value);
    xml.push(b'"');
}

/// Escape special XML characters in attribute values.
fn xml_escape_into(buf: &mut Vec<u8>, s: &str) {
    for b in s.bytes() {
        match b {
            b'&' => buf.extend_from_slice(b"&amp;"),
            b'<' => buf.extend_from_slice(b"&lt;"),
            b'>' => buf.extend_from_slice(b"&gt;"),
            b'"' => buf.extend_from_slice(b"&quot;"),
            b'\'' => buf.extend_from_slice(b"&apos;"),
            _ => buf.push(b),
        }
    }
}

/// Return a string with XML-escaped attribute characters.
///
/// Pushes directly into a `String` (not a `Vec<u8>`) to keep the UTF-8
/// invariant type-enforced — no runtime conversion, no `.expect()`, no
/// panic path. Mirrors `rustgate_enrollment::response::xml_escape`.
fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use super::*;

    // --- XML escaping tests ---

    #[test]
    fn xml_escape_special_characters() {
        let mut buf = Vec::new();
        xml_escape_into(&mut buf, "A&B<C>D\"E'F");
        assert_eq!(
            String::from_utf8(buf).expect("utf8"),
            "A&amp;B&lt;C&gt;D&quot;E&apos;F"
        );
    }

    #[test]
    fn xml_escape_no_special_characters() {
        let mut buf = Vec::new();
        xml_escape_into(&mut buf, "plain text 123");
        assert_eq!(String::from_utf8(buf).expect("utf8"), "plain text 123");
    }

    #[test]
    fn xml_escape_string_helper() {
        assert_eq!(xml_escape("A&B"), "A&amp;B");
        assert_eq!(xml_escape("plain"), "plain");
    }

    #[test]
    fn xml_escape_into_empty_is_no_op() {
        let mut buf = Vec::new();
        xml_escape_into(&mut buf, "");
        assert!(buf.is_empty(), "empty input should not write bytes");
    }

    #[test]
    fn xml_escape_into_preserves_non_ascii_bytes_unchanged() {
        // Non-ASCII bytes should pass through without transformation —
        // the escape set is strictly {&, <, >, ", '}. A regression that
        // started filtering or lossily transforming UTF-8 continuation
        // bytes would show up here.
        let mut buf = Vec::new();
        xml_escape_into(&mut buf, "caf\u{00e9}");
        assert_eq!(
            String::from_utf8(buf).expect("utf8"),
            "caf\u{00e9}",
            "non-ASCII input should pass through unchanged"
        );
    }

    #[test]
    fn xml_escape_string_helper_escapes_all_five_entities() {
        // Mirror of xml_escape_special_characters but through the String
        // helper so a future refactor that accidentally dropped one of the
        // five entities from only one code path fails here.
        assert_eq!(
            xml_escape("A&B<C>D\"E'F"),
            "A&amp;B&lt;C&gt;D&quot;E&apos;F"
        );
    }

    #[test]
    fn write_attr_emits_name_equals_quoted_value_with_leading_space() {
        let mut buf = Vec::new();
        write_attr(&mut buf, "uid", "hello");
        assert_eq!(String::from_utf8(buf).expect("utf8"), r#" uid="hello""#);
    }

    #[test]
    fn write_attr_escapes_value_but_not_name() {
        // The name is written raw (it is always an internal static); only
        // the value is escaped. Pin that contract so a regression that
        // started escaping the name would fail here rather than producing
        // subtly-malformed XML that downstream parsers accept.
        let mut buf = Vec::new();
        write_attr(&mut buf, "callsign", r#"Alpha "Bravo" & <Charlie>"#);
        assert_eq!(
            String::from_utf8(buf).expect("utf8"),
            r#" callsign="Alpha &quot;Bravo&quot; &amp; &lt;Charlie&gt;""#
        );
    }

    // --- ConvertError Display / Error-trait tests ---

    #[test]
    fn convert_error_xml_display_renders_parse_context() {
        let err = ConvertError::Xml("bad tag at line 3".to_string());
        assert_eq!(err.to_string(), "xml parse error: bad tag at line 3");
    }

    #[test]
    fn convert_error_missing_field_display_renders_field_name() {
        let err = ConvertError::MissingField("uid");
        assert_eq!(err.to_string(), "missing required field: uid");
    }

    #[test]
    fn convert_error_invalid_field_display_renders_reason() {
        let err = ConvertError::InvalidField("hae out of range".to_string());
        assert_eq!(err.to_string(), "invalid field: hae out of range");
    }

    #[test]
    fn convert_error_invalid_timestamp_display_renders_reason() {
        let err = ConvertError::InvalidTimestamp("missing T separator".to_string());
        assert_eq!(err.to_string(), "invalid timestamp: missing T separator");
    }

    #[test]
    fn convert_error_implements_std_error_trait() {
        // Pin the `std::error::Error` impl: a caller that wants to wrap a
        // `ConvertError` in `anyhow::Error` or `Box<dyn Error>` needs this
        // bound to compile. A regression that accidentally removed the
        // impl would fail here at test-compile time rather than at a
        // distant call site.
        use std::error::Error;
        fn assert_error<T: Error>(_: &T) {}
        let err = ConvertError::MissingField("probe");
        assert_error(&err);
        // Leaf errors return None from source() — the `impl Error` is
        // default-derived, so there is no explicit source chain to pin.
        assert!(err.source().is_none());
    }

    // --- From<ProtoError> conversion tests ---

    #[test]
    fn proto_error_missing_field_converts_to_convert_missing_field() {
        let proto_err = rustgate_proto::ProtoError::MissingField("event");
        let convert_err: ConvertError = proto_err.into();
        assert!(
            matches!(convert_err, ConvertError::MissingField("event")),
            "MissingField should preserve the &'static str, got {convert_err:?}"
        );
    }

    #[test]
    fn proto_error_invalid_timestamp_converts_to_convert_invalid_timestamp() {
        let proto_err =
            rustgate_proto::ProtoError::InvalidTimestamp("missing T separator".to_string());
        let convert_err: ConvertError = proto_err.into();
        match convert_err {
            ConvertError::InvalidTimestamp(ref msg) => {
                assert_eq!(msg, "missing T separator");
            }
            other => panic!("expected InvalidTimestamp, got {other:?}"),
        }
    }

    #[test]
    fn proto_error_frame_too_large_converts_to_convert_xml_via_display() {
        // The `other => Self::Xml(other.to_string())` catch-all routes any
        // non-MissingField, non-InvalidTimestamp ProtoError through the
        // Xml variant, preserving the Display rendering. Pin that
        // behaviour for a representative variant — a regression that
        // dropped the arm would fall through to the wrong variant or fail
        // to compile.
        let proto_err = rustgate_proto::ProtoError::FrameTooLarge {
            size: 1 << 24,
            max: 1 << 20,
        };
        let expected = proto_err.to_string();
        let convert_err: ConvertError = proto_err.into();
        match convert_err {
            ConvertError::Xml(ref msg) => assert_eq!(msg, &expected),
            other => panic!("expected Xml fallback, got {other:?}"),
        }
    }
}
