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
}
