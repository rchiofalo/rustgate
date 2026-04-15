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
//! log once and pass the original payload through. Valid XML that simply
//! lacks a `<point>` element is passed through byte-for-byte without
//! error. `MaskPoint` is a best-effort leak-prevention obligation, not a
//! hard security boundary — denying delivery entirely because the payload
//! happens not to be CoT would surprise operators whose policies predate
//! a payload-type change.

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

/// Return a copy of `xml` with every `<point>` element's `lat`, `lon`,
/// and `hae` attributes overwritten with `"0.0"`.
///
/// Attributes other than the three coordinate fields are preserved on the
/// same element. Elements other than `<point>` are passed through
/// unchanged. Comments, processing instructions, CDATA sections, and
/// whitespace are all preserved.
///
/// # Errors
///
/// Returns [`MaskError::Xml`] when the payload fails to parse as XML.
/// Callers should typically pass the original payload through unchanged
/// on error — coordinate masking is best-effort.
pub fn strip_coordinates(xml: &[u8]) -> Result<Bytes, MaskError> {
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

    // IMPORTANT: `<point>` is matched as a bare, lowercase, un-namespaced
    // element — the same contract as the parser in `crate::parse_cot_event`
    // (see `lib.rs` loop over `e.name().as_ref()`). If the parser is ever
    // broadened to accept `<cot:point>` or mixed-case variants, this
    // masker MUST be broadened in lockstep or classified coordinates
    // will leak via the un-recognised form.
    loop {
        let event = reader.read_event_into(&mut buf)?;
        match event {
            Event::Eof => break,
            Event::Start(ref e) if e.name().as_ref() == b"point" => {
                let masked = mask_point_attrs(e)?;
                writer.write_event(Event::Start(masked))?;
            }
            Event::Empty(ref e) if e.name().as_ref() == b"point" => {
                let masked = mask_point_attrs(e)?;
                writer.write_event(Event::Empty(masked))?;
            }
            other => writer.write_event(other)?,
        }
        buf.clear();
    }

    Ok(Bytes::from(out))
}

/// Build a new `<point>` start tag with the coordinate attributes
/// replaced. All other attributes are preserved in their original order.
///
/// Returns [`MaskError::AttrBudgetExceeded`] if more than
/// [`MAX_POINT_ATTRIBUTES`] attributes are present — this bounds the CPU
/// and allocation cost of per-recipient masking under hostile input.
fn mask_point_attrs<'a>(src: &BytesStart<'a>) -> Result<BytesStart<'a>, MaskError> {
    let name = String::from_utf8_lossy(src.name().as_ref()).into_owned();
    let mut masked = BytesStart::new(name);
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
}
