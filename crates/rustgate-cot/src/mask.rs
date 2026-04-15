// Copyright © 2026 Roberto Chiofalo.

//! Authorization obligation helpers for CoT XML payloads.
//!
//! Implements the data-plane side of the `MaskPoint` authz obligation
//! defined in `rustgate_authz::Obligation`. The router calls
//! [`strip_coordinates`] on a per-recipient basis when the policy engine
//! returns an allow decision carrying `MaskPoint`, so analysts who are
//! cleared to see the event metadata but not its geography receive a copy
//! with the `<point>` element's `lat`, `lon`, and `hae` attributes zeroed.
//!
//! The obligation is named `MaskPoint` (not `MaskGeo`) to reflect its
//! actual scope: only the `<point>` element is touched. Free-form
//! geographic references inside `<detail>` children, the event `uid`,
//! or envelope metadata are NOT scrubbed by this obligation. Policy
//! authors who need stronger leak prevention should use `MaskPayload`
//! (which empties the body entirely) or deny delivery outright.
//!
//! # Design
//!
//! Coordinates are **overwritten in place** rather than stripped:
//!
//! - Most CoT consumers (ATAK, WinTAK, custom clients) require `<point>`
//!   with the three coordinate attributes or will refuse to render the
//!   event at all. Removing the element or attributes breaks downstream
//!   parsers.
//! - Overwriting to `0.0` preserves schema validity and gives a clear
//!   "this was masked" signal (no real tactical event sits at 0°/0°/0m on
//!   the equator at sea level).
//! - All other XML (event metadata, detail children, source group) is
//!   passed through byte-for-byte.
//!
//! Malformed XML returns [`MaskError::Xml`]; the caller is expected to
//! decide the recovery. Valid XML that simply lacks a `<point>` element
//! is passed through byte-for-byte without error. `MaskPoint` is a
//! best-effort leak-prevention obligation, not a hard security boundary
//! — the caller distinguishes "not XML at all" (pass-through) from
//! "XML-shaped but malformed" (fail-closed) so a sender cannot bypass
//! the mask by terminating their payload mid-element.
//!
//! # Element matching
//!
//! The masker matches `<point>` case-insensitively and after stripping
//! any namespace prefix (e.g. `<cot:Point>` still matches). Spec-conform
//! CoT uses lowercase `<point>` without a namespace, but accepting the
//! common variants closes the obvious bypass where a sender wraps the
//! element in a prefix to dodge a byte-exact match. See
//! [`strip_coordinates`] for the behaviour.

use std::{fmt, io};

use bytes::Bytes;
use quick_xml::Writer;
use quick_xml::events::{BytesStart, Event};
use quick_xml::reader::Reader;

/// Attribute value written in place of real coordinates.
const MASKED_VALUE: &[u8] = b"0.0";

/// Upper bound on `<point>` attribute count.
///
/// Spec-conforming CoT `<point>` uses 5 attributes (`lat`, `lon`, `hae`,
/// `ce`, `le`). This cap is deliberately loose so legitimate extensions
/// pass but crafted XML cannot amplify per-recipient masking cost on a
/// broadcast. [`strip_coordinates`] returns
/// [`MaskError::AttrBudgetExceeded`] when the cap is hit.
pub const MAX_POINT_ATTRIBUTES: usize = 64;

/// Error returned by [`strip_coordinates`] when masking fails.
///
/// Split from [`crate::ParseError`] so callers can distinguish
/// "payload is not CoT XML" from downstream I/O failures on the writer.
///
/// Marked `#[non_exhaustive]` so adding variants (e.g. `AttrBudgetExceeded`)
/// stays source-compatible. Callers must include a wildcard arm.
#[derive(Debug)]
#[non_exhaustive]
pub enum MaskError {
    /// The payload is not well-formed XML.
    Xml(quick_xml::Error),
    /// The in-memory writer returned an I/O error. This should be
    /// unreachable under normal operation (writes go into a `Vec<u8>`)
    /// but is surfaced rather than panicked for forward-compat.
    Io(io::Error),
    /// A `<point>` element exceeded [`MAX_POINT_ATTRIBUTES`]. Rejected as
    /// a protection against crafted XML that would amplify per-recipient
    /// masking cost on a broadcast.
    AttrBudgetExceeded {
        /// Maximum allowed attribute count.
        limit: usize,
    },
}

impl fmt::Display for MaskError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Xml(e) => write!(f, "payload is not a valid CoT document: {e}"),
            Self::Io(e) => write!(f, "writer failed during CoT masking: {e}"),
            Self::AttrBudgetExceeded { limit } => write!(
                f,
                "<point> attribute count exceeded masking budget of {limit}"
            ),
        }
    }
}

impl std::error::Error for MaskError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Xml(e) => Some(e),
            Self::Io(e) => Some(e),
            Self::AttrBudgetExceeded { .. } => None,
        }
    }
}

impl From<quick_xml::Error> for MaskError {
    fn from(e: quick_xml::Error) -> Self {
        Self::Xml(e)
    }
}

impl From<quick_xml::events::attributes::AttrError> for MaskError {
    fn from(e: quick_xml::events::attributes::AttrError) -> Self {
        Self::Xml(quick_xml::Error::from(e))
    }
}

impl From<io::Error> for MaskError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// Return `true` when `name` is a `<point>` element, tolerating case
/// and a namespace prefix.
///
/// quick_xml exposes the qualified tag bytes via `Event::name()` — for
/// `<cot:point>` the bytes are `cot:point`, for `<Point>` they are
/// `Point`, for `<POINT>` they are `POINT`. CoT on the wire uses bare
/// lowercase `point` without a namespace, but accepting the common
/// variants closes the obvious bypass where a sender wraps the element
/// in a prefix to dodge a byte-exact match.
///
/// The function is hot — called once per opening tag in the payload —
/// but avoids allocation by operating on the raw byte slice. The local
/// name is derived by locating the last `:` (qualified-name separator
/// per the XML namespaces spec) and comparing the suffix ASCII-case-
/// insensitively against `"point"`. ASCII fold is sufficient because
/// the target literal `"point"` is pure ASCII and XML element names
/// cannot begin with a character whose case fold escapes ASCII in a
/// way that would collide with "point".
fn is_point_tag(name: &[u8]) -> bool {
    let local = match name.iter().rposition(|b| *b == b':') {
        Some(idx) => &name[idx + 1..],
        None => name,
    };
    local.eq_ignore_ascii_case(b"point")
}

/// Return a copy of `xml` with every `<point>` element's `lat`, `lon`,
/// and `hae` attributes overwritten with `"0.0"`.
///
/// Attributes other than the three coordinate fields are preserved on the
/// same element. Elements other than `<point>` are passed through
/// unchanged. Comments, processing instructions, CDATA sections, and
/// whitespace are all preserved. Matching is case-insensitive and
/// tolerant of a namespace prefix (e.g. `<cot:Point>` also matches).
///
/// Payloads whose first non-whitespace byte is not `<` are treated as
/// non-XML and returned verbatim without invoking the parser. This is a
/// defensive fast-path: `MaskPoint` obligations that land on binary
/// payloads (MAVLink, protobuf) would otherwise spin quick_xml through
/// a full read_event loop and return an immediate parse error.
///
/// # Errors
///
/// Returns [`MaskError::Xml`] when the payload fails to parse as XML
/// partway through (XML-intent detected but malformed mid-document).
/// The caller is expected to fail-closed in that case — a crafted
/// payload that aborts parsing immediately after its `<point>` element
/// has been emitted must not leak coordinates via pass-through
/// recovery.
pub fn strip_coordinates(xml: &[u8]) -> Result<Bytes, MaskError> {
    // Fast-path: no XML intent → verbatim. A single-pass scan for the
    // first non-whitespace byte avoids allocating a Reader for non-XML
    // payloads (binary protocols, plain text). Valid XML must start
    // with `<` after optional leading whitespace; anything else cannot
    // contain a `<point>` element we need to mask.
    if xml
        .iter()
        .find(|b| !b.is_ascii_whitespace())
        .is_none_or(|b| *b != b'<')
    {
        return Ok(Bytes::copy_from_slice(xml));
    }

    let mut reader = Reader::from_reader(xml);
    // quick_xml defaults: no external entity resolution, no DTD processing.
    // Retain defaults — XXE defence comes for free and matches the parser
    // used by `parse_cot_event` in this crate.
    reader.config_mut().trim_text(false);

    // Pre-size to the input length — masking never grows the document by
    // more than a handful of bytes, so this avoids reallocation on
    // typical inputs.
    let mut out = Vec::with_capacity(xml.len());
    let mut writer = Writer::new(&mut out);
    let mut buf = Vec::new();

    // `<point>` matching is delegated to `is_point_tag` so case and
    // namespace variants do not bypass the masker. The authz engine
    // presents `MaskPoint` as a data-plane leak-prevention control;
    // accepting only one exact casing would let a sender dodge the
    // mask by emitting `<Point>` or `<cot:point>`.
    loop {
        let event = reader.read_event_into(&mut buf)?;
        match event {
            Event::Eof => break,
            Event::Start(ref e) if is_point_tag(e.name().as_ref()) => {
                let masked = mask_point_attrs(e)?;
                writer.write_event(Event::Start(masked))?;
            }
            Event::Empty(ref e) if is_point_tag(e.name().as_ref()) => {
                let masked = mask_point_attrs(e)?;
                writer.write_event(Event::Empty(masked))?;
            }
            other => writer.write_event(other)?,
        }
        buf.clear();
    }

    Ok(Bytes::from(out))
}

/// Build a new start tag with the coordinate attributes replaced. The
/// original qualified tag name is preserved byte-for-byte: if the input
/// was `<cot:Point …/>`, the output is `<cot:Point lat="0.0" …/>`. All
/// non-coordinate attributes are preserved in their original order.
///
/// Returns [`MaskError::AttrBudgetExceeded`] if more than
/// [`MAX_POINT_ATTRIBUTES`] attributes are present — this bounds the CPU
/// and allocation cost of per-recipient masking under hostile input,
/// AND fails-closed so a sender cannot bypass the mask by padding the
/// tag with attributes until the parser gives up (the caller's response
/// to this error is to drop the payload, not forward it unmasked).
///
/// The original name is copied into an owned [`String`] so the returned
/// [`BytesStart`] has `'static` lifetime. Element names in well-formed
/// XML are valid UTF-8 by construction — quick_xml has already
/// validated the document before this helper runs — so the `from_utf8`
/// conversion is an invariant check, not a hot-path cost. On the
/// unreachable path where it fails, we surface a [`MaskError::Xml`]
/// rather than panic.
fn mask_point_attrs(src: &BytesStart<'_>) -> Result<BytesStart<'static>, MaskError> {
    // Preserve the original qualified name (including any namespace
    // prefix and casing) so receivers that round-trip the event see
    // the same element shape they would have seen pre-mask.
    let name_bytes = src.name();
    let name_str = std::str::from_utf8(name_bytes.as_ref())
        .map_err(|e| MaskError::Xml(quick_xml::Error::Encoding(e.into())))?;
    let mut masked = BytesStart::new(name_str.to_owned());
    let mut count = 0usize;
    for attr in src.attributes() {
        let attr = attr?;
        count += 1;
        if count > MAX_POINT_ATTRIBUTES {
            return Err(MaskError::AttrBudgetExceeded {
                limit: MAX_POINT_ATTRIBUTES,
            });
        }
        let key_bytes = attr.key.as_ref();
        match key_bytes {
            b"lat" | b"lon" | b"hae" => {
                masked.push_attribute((key_bytes, MASKED_VALUE));
            }
            _ => {
                masked.push_attribute((key_bytes, attr.value.as_ref()));
            }
        }
    }
    Ok(masked)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use super::*;

    const SAMPLE_COT: &str = r#"<?xml version="1.0"?><event uid="u1" type="a-f-G-U-C" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z"><point lat="38.8977" lon="-77.0365" hae="125.4"/><detail><__group name="Cyan"/></detail></event>"#;

    #[test]
    fn strips_lat_lon_hae_from_self_closing_point() {
        let out = strip_coordinates(SAMPLE_COT.as_bytes()).unwrap();
        let s = std::str::from_utf8(&out).unwrap();
        assert!(s.contains(r#"lat="0.0""#), "lat not zeroed: {s}");
        assert!(s.contains(r#"lon="0.0""#), "lon not zeroed: {s}");
        assert!(s.contains(r#"hae="0.0""#), "hae not zeroed: {s}");
        assert!(!s.contains("38.8977"), "raw lat leaked: {s}");
        assert!(!s.contains("-77.0365"), "raw lon leaked: {s}");
        assert!(!s.contains("125.4"), "raw hae leaked: {s}");
    }

    #[test]
    fn preserves_non_coordinate_attributes_on_point() {
        let xml = r#"<event uid="u1" type="a-f-G-U-C" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z"><point lat="1.0" lon="2.0" hae="3.0" ce="9.9" le="9.9"/></event>"#;
        let out = strip_coordinates(xml.as_bytes()).unwrap();
        let s = std::str::from_utf8(&out).unwrap();
        assert!(s.contains(r#"ce="9.9""#), "ce attribute dropped: {s}");
        assert!(s.contains(r#"le="9.9""#), "le attribute dropped: {s}");
    }

    #[test]
    fn preserves_event_and_detail_unchanged() {
        let out = strip_coordinates(SAMPLE_COT.as_bytes()).unwrap();
        let s = std::str::from_utf8(&out).unwrap();
        assert!(s.contains(r#"uid="u1""#), "event uid dropped: {s}");
        assert!(s.contains(r#"type="a-f-G-U-C""#), "event type dropped: {s}");
        assert!(s.contains(r#"<__group name="Cyan""#), "detail dropped: {s}");
    }

    #[test]
    fn handles_open_form_point_element() {
        let xml = r#"<event uid="u1" type="a-f-G-U-C" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z"><point lat="38.0" lon="-77.0" hae="0.0"></point></event>"#;
        let out = strip_coordinates(xml.as_bytes()).unwrap();
        let s = std::str::from_utf8(&out).unwrap();
        assert!(s.contains(r#"lat="0.0""#));
        assert!(
            s.contains("</point>"),
            "open-form point closing tag lost: {s}"
        );
    }

    #[test]
    fn passes_through_documents_with_no_point_element() {
        let xml = r#"<event uid="u1" type="b-t-f" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z"><detail><chat>hello</chat></detail></event>"#;
        let out = strip_coordinates(xml.as_bytes()).unwrap();
        let s = std::str::from_utf8(&out).unwrap();
        assert!(s.contains("<chat>hello</chat>"));
    }

    #[test]
    fn masks_multiple_point_elements() {
        let xml = r#"<event uid="u1" type="a-f-G-U-C" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z"><point lat="1.0" lon="2.0" hae="3.0"/><detail><other-point lat="99.9" lon="88.8" hae="77.7"/></detail></event>"#;
        let out = strip_coordinates(xml.as_bytes()).unwrap();
        let s = std::str::from_utf8(&out).unwrap();
        // <point> is masked
        assert!(!s.contains("1.0"), "first point not masked: {s}");
        assert!(!s.contains("2.0"), "first point not masked: {s}");
        assert!(!s.contains("3.0"), "first point not masked: {s}");
        // other-point (different tag name) is left alone — only `<point>` is in scope
        assert!(s.contains("99.9"), "other-point wrongly masked: {s}");
        assert!(s.contains("88.8"), "other-point wrongly masked: {s}");
        assert!(s.contains("77.7"), "other-point wrongly masked: {s}");
    }

    #[test]
    fn rejects_invalid_xml() {
        let xml = b"<event><point lat='1.0' lon='2.0' hae='3.0'";
        assert!(strip_coordinates(xml).is_err());
    }

    #[test]
    fn rejects_point_over_attribute_budget() {
        // Build a <point> with MAX_POINT_ATTRIBUTES + 1 attributes. This
        // guards the per-recipient masking path from crafted XML that
        // would amplify cost under a broadcast with many recipients.
        let mut xml = String::from(
            r#"<event uid="u1" type="a-f-G-U-C" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z"><point lat="1.0" lon="2.0" hae="3.0""#,
        );
        for i in 0..=MAX_POINT_ATTRIBUTES {
            xml.push_str(&format!(r#" x{i}="v""#));
        }
        xml.push_str("/></event>");
        let err = strip_coordinates(xml.as_bytes()).unwrap_err();
        assert!(
            matches!(
                err,
                MaskError::AttrBudgetExceeded {
                    limit: MAX_POINT_ATTRIBUTES,
                }
            ),
            "expected AttrBudgetExceeded, got: {err:?}"
        );
    }

    #[test]
    fn accepts_point_at_attribute_budget() {
        // Exactly MAX_POINT_ATTRIBUTES must succeed — the cap is
        // exclusive at the upper bound.
        let mut xml = String::from(
            r#"<event uid="u1" type="a-f-G-U-C" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z"><point lat="1.0" lon="2.0" hae="3.0""#,
        );
        // 3 existing attrs (lat/lon/hae), add up to the cap.
        for i in 0..MAX_POINT_ATTRIBUTES - 3 {
            xml.push_str(&format!(r#" x{i}="v""#));
        }
        xml.push_str("/></event>");
        assert!(strip_coordinates(xml.as_bytes()).is_ok());
    }

    #[test]
    fn masked_output_still_parses_as_cot() {
        let out = strip_coordinates(SAMPLE_COT.as_bytes()).unwrap();
        // crate's own parser must accept the masked bytes — policy
        // downstream depends on the masked payload remaining CoT-shaped
        // so receivers can still render the event.
        let parsed = crate::parse(&out).expect("masked payload must re-parse");
        let pos = parsed
            .position
            .expect("masked payload must still have a position");
        assert_eq!(pos.lat, 0.0);
        assert_eq!(pos.lon, 0.0);
        assert_eq!(pos.hae, 0.0);
    }

    #[test]
    fn masks_uppercase_point_element() {
        // Case-variant bypass: earlier implementations matched byte-exact
        // `b"point"` and would silently leak coordinates through `<Point>`.
        let xml = r#"<event uid="u1" type="a-f-G-U-C" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z"><Point lat="38.8977" lon="-77.0365" hae="125.4"/></event>"#;
        let out = strip_coordinates(xml.as_bytes()).unwrap();
        let s = std::str::from_utf8(&out).unwrap();
        assert!(
            s.contains(r#"lat="0.0""#),
            "uppercase Point not masked: {s}"
        );
        assert!(
            !s.contains("38.8977"),
            "raw lat leaked via case bypass: {s}"
        );
        // Original casing must be preserved on the wire so receivers that
        // depend on exact element shape are unaffected.
        assert!(s.contains("<Point"), "original casing lost after mask: {s}");
    }

    #[test]
    fn masks_all_caps_point_element() {
        let xml = r#"<event uid="u1" type="a-f-G-U-C" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z"><POINT lat="1.23" lon="4.56" hae="7.89"/></event>"#;
        let out = strip_coordinates(xml.as_bytes()).unwrap();
        let s = std::str::from_utf8(&out).unwrap();
        assert!(s.contains(r#"lat="0.0""#), "ALL-CAPS POINT not masked: {s}");
        assert!(!s.contains("1.23"), "raw lat leaked: {s}");
    }

    #[test]
    fn masks_namespaced_point_element() {
        // Namespace bypass: `<cot:point>` has tag bytes `cot:point`, so a
        // byte-exact check misses it. `is_point_tag` strips the prefix.
        let xml = r#"<event xmlns:cot="urn:cot" uid="u1" type="a-f-G-U-C" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z"><cot:point lat="38.8977" lon="-77.0365" hae="125.4"/></event>"#;
        let out = strip_coordinates(xml.as_bytes()).unwrap();
        let s = std::str::from_utf8(&out).unwrap();
        assert!(
            s.contains(r#"lat="0.0""#),
            "namespaced point not masked: {s}"
        );
        assert!(
            !s.contains("38.8977"),
            "raw lat leaked via namespace prefix: {s}"
        );
        // Namespace prefix must survive the rewrite so namespace-aware
        // receivers can still resolve the element.
        assert!(
            s.contains("<cot:point"),
            "namespace prefix dropped after mask: {s}"
        );
    }

    #[test]
    fn masks_mixed_case_namespaced_point() {
        let xml = r#"<event xmlns:cot="urn:cot" uid="u1" type="a-f-G-U-C" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z"><cot:Point lat="38.8977" lon="-77.0365" hae="125.4"/></event>"#;
        let out = strip_coordinates(xml.as_bytes()).unwrap();
        let s = std::str::from_utf8(&out).unwrap();
        assert!(s.contains(r#"lat="0.0""#), "cot:Point not masked: {s}");
        assert!(!s.contains("38.8977"), "raw lat leaked: {s}");
        assert!(
            s.contains("<cot:Point"),
            "mixed-case namespaced tag lost: {s}"
        );
    }

    #[test]
    fn fast_path_passes_non_xml_through_unchanged() {
        // Non-XML payloads must bypass the parser entirely (fast path).
        // `<point>` search is irrelevant — the payload cannot be CoT.
        let payloads: &[&[u8]] = &[
            b"not xml at all",
            b"",
            b"   \t\n  ",
            b"MAVLINK\x00\x01\x02\x03",
            b"{\"json\":\"also not xml\"}",
        ];
        for payload in payloads {
            let out = strip_coordinates(payload).unwrap();
            assert_eq!(out.as_ref(), *payload, "fast-path mutated non-XML payload");
        }
    }

    #[test]
    fn fast_path_skips_parser_for_leading_whitespace_non_xml() {
        // The fast-path looks at the first *non-whitespace* byte, so a
        // payload that starts with whitespace and then non-`<` must still
        // bypass the parser.
        let payload = b"   \n\tnot xml either";
        let out = strip_coordinates(payload).unwrap();
        assert_eq!(out.as_ref(), payload);
    }

    #[test]
    fn xml_intent_with_malformed_tail_returns_error() {
        // Key fail-closed behaviour: a payload that announces itself as
        // XML (leading `<`) but is malformed mid-parse must NOT fall back
        // to pass-through. A sender could otherwise leak coordinates by
        // emitting `<event><point lat="…"…/>` and then cutting the
        // document so quick_xml errors after `<point>` was already
        // copied to the output buffer.
        let xml = br#"<event><point lat="38.8977" lon="-77.0365" hae="125.4"/><unterminated"#;
        let err = strip_coordinates(xml).unwrap_err();
        assert!(
            matches!(err, MaskError::Xml(_)),
            "expected Xml, got {err:?}"
        );
    }
}
