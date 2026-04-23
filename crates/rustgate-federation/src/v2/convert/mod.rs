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

    // --- ConvertError::Display tests ---

    /// Pin the operator-facing prefix for the `Xml` variant. The `xml parse
    /// error:` prefix is what on-call engineers grep for in log
    /// aggregations; a silent drift to `xml error:` or `parse xml:` would
    /// silently break every alerting rule keyed on the message.
    #[test]
    fn convert_error_xml_display_prefixes_with_xml_parse_error() {
        let err = ConvertError::Xml("unterminated tag at line 3".to_string());
        let msg = err.to_string();
        assert!(
            msg.starts_with("xml parse error: "),
            "Xml Display must keep the `xml parse error: ` prefix for log-grep stability: {msg}"
        );
        assert!(
            msg.contains("unterminated tag at line 3"),
            "Xml Display must include the wrapped parser message verbatim: {msg}"
        );
    }

    /// Pin the `missing required field:` prefix AND the verbatim echo of
    /// the `&'static str` argument. The static-str branch exists so every
    /// occurrence shares an interned literal (no per-event String
    /// allocation on the hot path); a regression that silently converted
    /// to `String` would still render the same message here but would
    /// regress allocation behaviour — pinning the format at least ensures
    /// the static message content itself never drifts.
    #[test]
    fn convert_error_missing_field_display_names_static_field_verbatim() {
        let err = ConvertError::MissingField("contact.callsign");
        let msg = err.to_string();
        assert_eq!(
            msg, "missing required field: contact.callsign",
            "MissingField Display must be the literal `missing required field: <name>` shape"
        );
    }

    /// Pin the `invalid field:` prefix. `InvalidField` is the catch-all
    /// for semantic-but-not-missing failures (e.g. lat/lon out of range,
    /// empty UID strings) so its message is what users see when their CoT
    /// payload fails validation — stability matters for CS escalations.
    #[test]
    fn convert_error_invalid_field_display_prefixes_with_invalid_field() {
        let err = ConvertError::InvalidField("lat 95.0 exceeds WGS-84 range".to_string());
        let msg = err.to_string();
        assert!(
            msg.starts_with("invalid field: "),
            "InvalidField Display must keep the `invalid field: ` prefix: {msg}"
        );
        assert!(
            msg.contains("lat 95.0 exceeds WGS-84 range"),
            "InvalidField Display must include the payload verbatim: {msg}"
        );
    }

    /// Pin the `invalid timestamp:` prefix. `InvalidTimestamp` is distinct
    /// from `InvalidField` because TAK/CoT has a well-defined ISO-8601
    /// profile and operators filter on the token specifically to
    /// distinguish clock-drift incidents from schema violations.
    #[test]
    fn convert_error_invalid_timestamp_display_prefixes_with_invalid_timestamp() {
        let err = ConvertError::InvalidTimestamp("2026-13-40T25:00:00Z".to_string());
        let msg = err.to_string();
        assert!(
            msg.starts_with("invalid timestamp: "),
            "InvalidTimestamp Display must keep the `invalid timestamp: ` prefix: {msg}"
        );
        assert!(
            msg.contains("2026-13-40T25:00:00Z"),
            "InvalidTimestamp Display must echo the offending value so operators can correlate: {msg}"
        );
    }

    // --- From<ProtoError> mapping tests ---

    /// `ProtoError::MissingField` carries `&'static str`; the mapping
    /// into `ConvertError::MissingField` must forward that same static
    /// reference (rather than allocating a `String`) so both hot-path
    /// allocation behaviour AND the identity of the field name are
    /// preserved. A regression that reassigned the match arm (e.g.
    /// `Self::Xml(f.to_string())`) would still compile but would lose the
    /// variant distinction operators use to filter missing-data events
    /// separately from malformed-XML events.
    #[test]
    fn from_proto_missing_field_preserves_static_field_name() {
        let proto = rustgate_proto::ProtoError::MissingField("uid");
        let convert: ConvertError = proto.into();
        match convert {
            ConvertError::MissingField(name) => assert_eq!(
                name, "uid",
                "From<ProtoError::MissingField> must forward the field name verbatim"
            ),
            other => panic!(
                "expected MissingField variant after mapping; got {:?}",
                other
            ),
        }
    }

    /// `ProtoError::InvalidTimestamp` carries `String`; the mapping must
    /// forward the same value so the operator-facing diagnostic does not
    /// lose the offending timestamp between the proto layer and the
    /// federation layer.
    #[test]
    fn from_proto_invalid_timestamp_preserves_value_string() {
        let proto = rustgate_proto::ProtoError::InvalidTimestamp("not-a-date".to_string());
        let convert: ConvertError = proto.into();
        match convert {
            ConvertError::InvalidTimestamp(v) => assert_eq!(
                v, "not-a-date",
                "From<ProtoError::InvalidTimestamp> must forward the value verbatim"
            ),
            other => panic!(
                "expected InvalidTimestamp variant after mapping; got {:?}",
                other
            ),
        }
    }

    /// Every other `ProtoError` variant (Decode, Encode, Xml,
    /// FrameTooLarge, OutOfRange) must fall through to the
    /// `ConvertError::Xml` catch-all via `to_string()`. The contract is
    /// load-bearing: the federation layer intentionally collapses the
    /// proto-side detail into a single variant because downstream gRPC
    /// status code mapping does not care which exact parser branch fired.
    /// A regression that added a panic arm or routed OutOfRange to
    /// MissingField would silently break federation error semantics —
    /// pin that the fall-through preserves the payload string inside
    /// `ConvertError::Xml`.
    #[test]
    fn from_proto_other_variants_fall_through_to_xml_with_stringified_payload() {
        let proto = rustgate_proto::ProtoError::OutOfRange {
            field: "lat",
            value: 91.5,
        };
        let proto_msg = proto.to_string();
        let convert: ConvertError = proto.into();
        match convert {
            ConvertError::Xml(payload) => {
                assert_eq!(
                    payload, proto_msg,
                    "fall-through must preserve the ProtoError's Display string inside ConvertError::Xml"
                );
                assert!(
                    payload.contains("lat"),
                    "stringified payload must still include the original field name: {payload}"
                );
            }
            other => panic!("expected Xml fall-through variant; got {:?}", other),
        }
    }

    // --- XML escape edge-case tests ---

    /// An empty input must yield an untouched buffer — the loop body must
    /// be skipped entirely. A regression that prepended a fixed byte
    /// (e.g. a BOM) or called `.push(0)` once before the loop would fail
    /// here and catch the off-by-one bug before it corrupts CoT frames.
    #[test]
    fn xml_escape_into_empty_input_leaves_buffer_empty() {
        let mut buf = Vec::new();
        xml_escape_into(&mut buf, "");
        assert!(
            buf.is_empty(),
            "empty input must produce an empty buffer; got {} bytes",
            buf.len()
        );
    }

    /// Multi-byte UTF-8 code points must pass through verbatim because
    /// the XML spec only reserves the five ASCII characters `& < > " '`
    /// for escaping in attribute values — everything else (accented
    /// Latin, CJK, emoji) is a valid XML character and must be echoed as
    /// its raw UTF-8 bytes. A regression that narrowed the default arm
    /// (e.g. stripped anything above 0x7F thinking it was "non-XML") would
    /// silently mangle every non-English callsign. Pin the byte-exact
    /// pass-through so the failure mode is visible at unit-test time.
    #[test]
    fn xml_escape_into_multi_byte_utf8_passes_through_bytewise() {
        let mut buf = Vec::new();
        let input = "Café \u{1F680}"; // French "Café" + 🚀 emoji
        xml_escape_into(&mut buf, input);
        assert_eq!(
            buf.as_slice(),
            input.as_bytes(),
            "non-ASCII UTF-8 must pass through as-is, byte-for-byte"
        );
    }

    /// Pin the full shape of `write_attr`: a leading space separator, the
    /// literal name, `="`, the XML-escaped value, and a closing `"`. The
    /// leading space is load-bearing because `write_attr` is called
    /// repeatedly inside an element's open-tag to emit
    /// `<cot uid="x" time="…">`; a regression that dropped the leading
    /// space would produce `<cotuid="x"time="…">` and break every XML
    /// parser silently at deserialization time rather than loudly at
    /// serialization time. Also verify the escape delegation by including
    /// an `&` in the value — a refactor that inlined the escape skip path
    /// for `write_attr` specifically would pass the shape test but fail
    /// the escape test.
    #[test]
    fn write_attr_produces_leading_space_and_escaped_quoted_value() {
        let mut buf = Vec::new();
        write_attr(&mut buf, "uid", "A&B");
        assert_eq!(
            String::from_utf8(buf).expect("utf8"),
            " uid=\"A&amp;B\"",
            "write_attr must emit ` name=\"<escaped-value>\"` — leading space, name, =, quoted escaped value"
        );
    }
}
