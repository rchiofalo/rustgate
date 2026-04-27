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

use std::io;

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
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MaskError {
    /// The payload is not well-formed XML.
    #[error("payload is not a valid CoT document: {0}")]
    Xml(#[source] quick_xml::Error),
    /// The in-memory writer returned an I/O error. This should be
    /// unreachable under normal operation (writes go into a `Vec<u8>`)
    /// but is surfaced rather than panicked for forward-compat.
    #[error("writer failed during CoT masking: {0}")]
    Io(#[source] io::Error),
    /// A `<point>` element exceeded [`MAX_POINT_ATTRIBUTES`]. Rejected as
    /// a protection against crafted XML that would amplify per-recipient
    /// masking cost on a broadcast.
    #[error("<point> attribute count exceeded masking budget of {limit}")]
    AttrBudgetExceeded {
        /// Maximum allowed attribute count.
        limit: usize,
    },
}

impl MaskError {
    /// Return a short discriminant label suitable for structured logs and
    /// audit `reason` fields.
    ///
    /// Unlike the [`std::fmt::Display`] impl, this method never embeds content
    /// derived from the input payload. [`quick_xml::Error`]'s own
    /// `Display` can echo payload-derived tag names (e.g.
    /// `EndEventMismatch { expected, found }`); a DEBUG log that prints
    /// the full error chain therefore risks leaking fragments of a
    /// classified payload that failed to parse. Emitting `e.kind()`
    /// instead of `e` keeps the operational log free of payload bytes
    /// while still naming the failure class for triage.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Xml(_) => "xml_parse_error",
            Self::Io(_) => "io_error",
            Self::AttrBudgetExceeded { .. } => "attr_budget_exceeded",
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

    // Defensive round-trip check: re-parse our own output. quick_xml's
    // reader is lenient about attribute values containing the byte that
    // is NOT the wrapping quote (e.g. `'value with " inside'` is
    // accepted because the value uses `'`-quotes), but the writer always
    // emits attribute values wrapped in `"` without escaping inner `"`
    // characters. The result is that a single permissive read followed
    // by a single write can produce bytes that fail to re-parse — which
    // breaks the masker's documented self-stability contract and was
    // caught by the `cot_mask_strip_coordinates` weekly extended fuzz
    // (the original crash artifact lives under
    // `fuzz/corpus/cot_mask_strip_coordinates/` and is regression-pinned
    // by a test below).
    //
    // Failing closed here is the right answer per the function's
    // documented contract: "a sender that emits `<event><point …/>`
    // and then truncates … must NOT leak coordinates via pass-through
    // recovery". A document whose masked form we cannot ourselves
    // re-read is exactly such a partial-parse case — we surface it as
    // `MaskError::Xml` so the caller drops the payload rather than
    // forwarding output that might leak coordinates back to a receiver
    // whose parser disagrees with ours.
    //
    // Cost: one extra single-pass quick_xml walk over `out`. For a
    // typical CoT event (≤2 KiB) this is microseconds; the value is
    // a strong "if `Ok`, the bytes round-trip" invariant that future
    // quick_xml read/write asymmetries cannot break.
    let mut verify = Reader::from_reader(out.as_slice());
    verify.config_mut().trim_text(false);
    let mut verify_buf = Vec::new();
    loop {
        match verify.read_event_into(&mut verify_buf)? {
            Event::Eof => break,
            // quick_xml's reader is lazy on attribute parsing — the
            // top-level `read_event_into` accepts a Start/Empty whose
            // attribute *syntax* is malformed, and only surfaces the
            // error when the caller actually iterates `attributes()`.
            // The masker's hot path (`mask_point_attrs`) does iterate,
            // so an output whose Start tag we cannot iterate would
            // crash the next pass even though our own loop walked it
            // cleanly. Force attribute parsing on every Start/Empty
            // here so the failure surfaces in pass 1, not pass 2.
            Event::Start(e) | Event::Empty(e) => {
                for attr in e.attributes() {
                    let _ = attr?;
                }
            }
            _ => {}
        }
        verify_buf.clear();
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

    // -- defensive-invariant coverage -----------------------------------

    #[test]
    fn kind_returns_stable_discriminant_strings_across_variants() {
        // Operators grep on `MaskError::kind()` discriminants in
        // structured-log audit trails. A refactor that renamed any of the
        // three tokens (e.g. "xml_parse_error" → "xml") would silently
        // break SIEM rules filtering on them. Pin the exact text on every
        // variant.
        let xml_err = strip_coordinates(b"<event><point").unwrap_err();
        assert_eq!(xml_err.kind(), "xml_parse_error");
        let io_err = MaskError::from(io::Error::other("writer failed"));
        assert_eq!(io_err.kind(), "io_error");
        let budget_err = MaskError::AttrBudgetExceeded {
            limit: MAX_POINT_ATTRIBUTES,
        };
        assert_eq!(budget_err.kind(), "attr_budget_exceeded");
    }

    #[test]
    fn kind_returns_static_str_independent_of_payload_bytes() {
        // `kind()` is the payload-safe alternative to `Display`: a DEBUG
        // log that prints the full error chain via `Display` can echo
        // quick_xml's `EndEventMismatch { expected, found }` with
        // payload-derived tag names and leak fragments of a classified
        // event. `kind()` returns a `&'static str` owned by the binary's
        // data segment — regardless of which malformed payload triggered
        // the error, the same static token comes out. Pin that invariant
        // by feeding three distinct malformed payloads and asserting the
        // same static string on all three.
        let err1 = strip_coordinates(b"<event><point").unwrap_err();
        let err2 = strip_coordinates(b"<foo>text</bar>").unwrap_err();
        let err3 = strip_coordinates(b"<a><b").unwrap_err();
        let k1: &'static str = err1.kind();
        let k2: &'static str = err2.kind();
        let k3: &'static str = err3.kind();
        assert_eq!(k1, "xml_parse_error");
        assert_eq!(k2, "xml_parse_error");
        assert_eq!(k3, "xml_parse_error");
        // Same pointer for &'static str from the same const-returning match
        // arm — a regression that made `kind()` allocate would fail this.
        assert_eq!(k1.as_ptr(), k2.as_ptr());
        assert_eq!(k2.as_ptr(), k3.as_ptr());
    }

    #[test]
    fn source_chain_behaves_as_documented_for_every_variant() {
        use std::error::Error as _;
        // Xml → chains to inner quick_xml::Error so
        // `anyhow::Context::context()` at call sites renders the parser
        // detail.
        let xml_err = strip_coordinates(b"<event><point").unwrap_err();
        assert!(
            xml_err.source().is_some(),
            "Xml variant must chain to inner quick_xml::Error"
        );
        // Io → chains to inner io::Error.
        let io_err = MaskError::from(io::Error::other("writer failed"));
        assert!(
            io_err.source().is_some(),
            "Io variant must chain to inner io::Error"
        );
        // AttrBudgetExceeded carries only the limit value — no inner source.
        // A regression that added a `#[source]`-annotated field would
        // silently extend the operator-facing error chain.
        let budget_err = MaskError::AttrBudgetExceeded {
            limit: MAX_POINT_ATTRIBUTES,
        };
        assert!(
            budget_err.source().is_none(),
            "AttrBudgetExceeded must have no inner source"
        );
    }

    #[test]
    fn attr_budget_exceeded_display_embeds_limit_value_exactly() {
        // Pin the exact Display text — operator dashboards and SIEM rules
        // filter on the numeric limit to correlate amplification attempts.
        // A refactor to `{limit:03}`, `{limit:#x}`, or "<point> had too
        // many attributes" would break those filters without failing any
        // existing test.
        let err = MaskError::AttrBudgetExceeded { limit: 64 };
        assert_eq!(
            err.to_string(),
            "<point> attribute count exceeded masking budget of 64"
        );
        // Non-default cap must also render with the embedded value.
        let err = MaskError::AttrBudgetExceeded { limit: 128 };
        assert_eq!(
            err.to_string(),
            "<point> attribute count exceeded masking budget of 128"
        );
    }

    #[test]
    fn xml_variant_display_prefixes_message_and_appends_source() {
        // The Display output for Xml composes a fixed prefix with the
        // inner quick_xml::Error rendering. The prefix is the contract
        // operator log filters key on; the suffix is the parser's own
        // diagnostic. Pin both shape elements: the literal prefix and
        // the colon-space delimiter that introduces the inner error.
        let err = strip_coordinates(b"<event><point").unwrap_err();
        let display = err.to_string();
        assert!(
            display.starts_with("payload is not a valid CoT document: "),
            "expected literal prefix, got {display:?}"
        );
    }

    #[test]
    fn io_variant_display_prefixes_message_and_appends_source() {
        // Same Display-shape contract as the Xml variant — pin the
        // literal prefix and the colon-space delimiter so a refactor
        // that switched the message to "writer io error: …" or dropped
        // the inner error from Display would fail here loudly.
        let err = MaskError::from(io::Error::other("simulated"));
        let display = err.to_string();
        assert_eq!(display, "writer failed during CoT masking: simulated");
    }

    #[test]
    fn mask_error_is_send_sync_static() {
        // MaskError crosses async boundaries in the router. Downstream
        // audit sinks wrap it in `Box<dyn Error + Send + Sync + 'static>`
        // for chained-error reporting. A regression that added a borrowed
        // field (e.g. `&str` name) would fail this bound here, instead of
        // at the far-away boxing site.
        fn assert_bounds<T: Send + Sync + 'static>() {}
        assert_bounds::<MaskError>();
    }

    #[test]
    fn point_tag_match_rejects_suffix_and_prefix_element_variants() {
        // `is_point_tag` uses `eq_ignore_ascii_case` on the local name —
        // anything that isn't an exact match to "point" (after namespace
        // stripping) must pass through unmodified. Guards against a
        // refactor to a substring / starts-with / ends-with match that
        // would over-mask legitimate elements sharing the substring.
        let cases: &[&str] = &[
            r#"<pointer lat="1.0" lon="2.0" hae="3.0"/>"#,
            r#"<pointful lat="1.0" lon="2.0" hae="3.0"/>"#,
            r#"<mypoint lat="1.0" lon="2.0" hae="3.0"/>"#,
            r#"<xpoint lat="1.0" lon="2.0" hae="3.0"/>"#,
            r#"<points lat="1.0" lon="2.0" hae="3.0"/>"#,
        ];
        for element in cases {
            let xml = format!(
                r#"<event uid="u1" type="a-f-G-U-C" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z">{element}</event>"#
            );
            let out = strip_coordinates(xml.as_bytes()).unwrap();
            let s = std::str::from_utf8(&out).unwrap();
            assert!(
                s.contains("1.0") && s.contains("2.0") && s.contains("3.0"),
                "element {element} wrongly masked: {s}"
            );
        }
    }

    #[test]
    fn coordinate_attribute_matching_is_byte_exact_and_case_sensitive() {
        // Asymmetric with the ELEMENT-name match (case-insensitive):
        // coordinate ATTRIBUTE matching is byte-exact against b"lat" /
        // b"lon" / b"hae". A crafted payload using uppercase attribute
        // names keeps the coordinates intact — this is the documented
        // contract (CoT spec mandates lowercase; changing the matcher to
        // case-insensitive would over-mask legitimate events re-using
        // "LAT" as a custom attribute). Pin the asymmetry explicitly so a
        // refactor to case-insensitive attribute matching stays conscious.
        let xml = r#"<event uid="u1" type="a-f-G-U-C" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z"><point LAT="38.8977" LON="-77.0365" HAE="125.4"/></event>"#;
        let out = strip_coordinates(xml.as_bytes()).unwrap();
        let s = std::str::from_utf8(&out).unwrap();
        assert!(s.contains(r#"LAT="38.8977""#), "LAT wrongly masked: {s}");
        assert!(s.contains(r#"LON="-77.0365""#), "LON wrongly masked: {s}");
        assert!(s.contains(r#"HAE="125.4""#), "HAE wrongly masked: {s}");
    }

    #[test]
    fn deeply_nested_point_inside_detail_subtree_is_masked() {
        // `strip_coordinates` walks a flat event stream — depth is
        // irrelevant to the matcher. Pin that explicitly so a refactor to
        // stateful tracking (e.g. "only mask top-level <point>") cannot
        // create a leak by wrapping coords in deeper elements.
        let xml = r#"<event uid="u1" type="a-f-G-U-C" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z"><detail><__group name="Cyan"/><wrap><inner><point lat="38.8977" lon="-77.0365" hae="125.4"/></inner></wrap></detail></event>"#;
        let out = strip_coordinates(xml.as_bytes()).unwrap();
        let s = std::str::from_utf8(&out).unwrap();
        assert!(
            s.contains(r#"lat="0.0""#),
            "deeply nested point not masked: {s}"
        );
        assert!(!s.contains("38.8977"), "raw lat leaked via depth: {s}");
        assert!(!s.contains("-77.0365"), "raw lon leaked via depth: {s}");
        assert!(!s.contains("125.4"), "raw hae leaked via depth: {s}");
    }

    #[test]
    fn attribute_budget_is_per_element_not_document_cumulative() {
        // The MAX_POINT_ATTRIBUTES cap fires per-<point>, NOT as a running
        // total across the document. Two <point> elements each with 50
        // attributes (total 100 — well over the 64-cap if summed) must
        // both pass, proving the counter resets between elements. A
        // regression that hoisted the counter to document scope would
        // reject legitimate multi-point CoT payloads.
        let attrs_each = 50;
        assert!(
            attrs_each <= MAX_POINT_ATTRIBUTES,
            "test precondition: each point must stay at or below the cap"
        );
        assert!(
            attrs_each * 2 > MAX_POINT_ATTRIBUTES,
            "test precondition: two points must sum above the cap to matter"
        );
        let mut first = String::from(r#"<point lat="1.0" lon="2.0" hae="3.0""#);
        for i in 0..attrs_each - 3 {
            first.push_str(&format!(r#" a{i}="v""#));
        }
        first.push_str("/>");
        let mut second = String::from(r#"<point lat="4.0" lon="5.0" hae="6.0""#);
        for i in 0..attrs_each - 3 {
            second.push_str(&format!(r#" b{i}="v""#));
        }
        second.push_str("/>");
        let xml = format!(
            r#"<event uid="u1" type="a-f-G-U-C" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z">{first}{second}</event>"#
        );
        assert!(
            strip_coordinates(xml.as_bytes()).is_ok(),
            "per-element budget must not accumulate across <point> elements"
        );
    }

    #[test]
    fn max_point_attributes_public_constant_value_is_pinned_at_64() {
        // Compile-time pin. `MAX_POINT_ATTRIBUTES` is public and governs
        // the per-recipient masking cost ceiling; a regression that
        // loosened it (e.g. to 1024) would let a hostile sender amplify
        // CPU cost on a broadcast. Changing the value is a deliberate
        // decision that must break this test.
        const _: () = assert!(MAX_POINT_ATTRIBUTES == 64);
        assert_eq!(MAX_POINT_ATTRIBUTES, 64);
    }

    /// Regression test for the weekly-fuzz crash on
    /// `cot_mask_strip_coordinates` (artifact
    /// `crash-27a80e9c299caaa10dd933aa124b20d6f01ff229`). The fuzz
    /// target's invariant is that `strip_coordinates(strip_coordinates(x))`
    /// must succeed if the first call did — equivalently, masked output
    /// must itself be valid input. quick_xml's reader is permissive about
    /// attribute values containing the OPPOSITE quote byte (e.g. a value
    /// wrapped in `'`-quotes can contain `"`), but its writer always
    /// emits values wrapped in `"` without escaping inner `"` — so a
    /// permissive read followed by a write produces bytes whose next
    /// read fails. The fix is a defensive output-validation pass at the
    /// end of `strip_coordinates` that re-parses the writer's output;
    /// this test pins the fail-closed contract by feeding the exact
    /// crash artifact and asserting that the masker returns
    /// `MaskError::Xml` rather than producing a regression-prone byte
    /// sequence the caller might forward verbatim.
    #[test]
    fn weekly_fuzz_crash_27a80e9c_fails_closed_on_unwriteable_attribute_value() {
        // Captured from the fuzz CI artifact — base64 in the issue body
        // and the original crash file under
        // `fuzz/corpus/cot_mask_strip_coordinates/`. Pinned as a literal
        // byte vector so the test is self-contained and runs in
        // environments without the fuzz corpus on disk.
        let crash_input: &[u8] = &[
            60, 60, 101, 47, 118, 60, 101, 118, 126, 116, 62, 116, 62, 60, 112, 111, 105, 110, 116,
            13, 13, 13, 13, 13, 79, 79, 79, 79, 79, 79, 79, 79, 79, 79, 79, 79, 79, 79, 79, 79, 79,
            79, 79, 79, 79, 79, 79, 79, 79, 79, 79, 79, 79, 79, 79, 79, 79, 79, 79, 79, 79, 79, 79,
            79, 79, 79, 79, 79, 79, 79, 79, 79, 79, 79, 79, 79, 79, 79, 79, 79, 79, 79, 79, 79, 79,
            79, 79, 79, 60, 33, 100, 60, 91, 173, 60, 33, 69, 78, 84, 73, 84, 89, 37, 97, 116, 61,
            39, 255, 60, 91, 101, 33, 101, 118, 34, 108, 255, 255, 56, 34, 39, 13, 13, 13, 13, 13,
            13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
            13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
            13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
            13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
            13, 13, 62, 104, 101, 44, 0,
        ];
        // The pre-fix behaviour was: pass 1 returned `Ok(bytes)` whose
        // next parse attempt failed with `position 98: attribute key
        // must be directly followed by `=` or space`. The post-fix
        // behaviour is that `strip_coordinates` itself catches this
        // and returns `Err(MaskError::Xml(_))`. Either an `Ok(_)` whose
        // bytes DO re-parse OR an `Err(MaskError::Xml(_))` is acceptable
        // (the test allows either outcome so a hypothetical future
        // quick_xml fix that emits round-trippable bytes would not
        // regress this test); what is NOT acceptable is producing bytes
        // that we ourselves cannot read back.
        match strip_coordinates(crash_input) {
            Ok(masked) => {
                let mut verify = Reader::from_reader(masked.as_ref());
                verify.config_mut().trim_text(false);
                let mut buf = Vec::new();
                loop {
                    match verify.read_event_into(&mut buf) {
                        Ok(Event::Eof) => break,
                        Ok(_) => buf.clear(),
                        Err(e) => panic!(
                            "regression: strip_coordinates returned Ok(_) but its own \
                             output fails to re-parse: {e}"
                        ),
                    }
                }
            }
            Err(MaskError::Xml(_)) => {
                // Expected post-fix path: defensive validation rejected
                // the unwriteable attribute value before the bytes ever
                // reached the caller.
            }
            Err(other) => panic!("expected `Ok(_)` or `MaskError::Xml(_)`, got {other:?}"),
        }
    }

    /// Tighter contract test: any input that `strip_coordinates`
    /// accepts MUST produce output the same function will accept on a
    /// second pass. Documents the self-stability invariant the fuzz
    /// target asserts, in unit-test form, so a regression on this
    /// invariant fails locally without the fuzzer in the loop.
    #[test]
    fn output_is_always_re_acceptable() {
        let inputs: &[&[u8]] = &[
            // Normal CoT
            SAMPLE_COT.as_bytes(),
            // CoT with single-quoted attribute values containing literal `"`
            // — the same shape as the fuzz crash but minimal.
            br#"<event uid='u "1"' type="a-f-G-U-C" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z"><point lat="1.0" lon="2.0" hae="3.0"/></event>"#,
            // CoT with attribute values containing literal `&`
            br#"<event uid="u&amp;1" type="a-f-G-U-C" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z"><point lat="1.0" lon="2.0" hae="3.0"/></event>"#,
        ];
        for (idx, input) in inputs.iter().enumerate() {
            // Either pass 1 rejects (caller fail-closes — fine), or
            // pass 1 succeeds AND pass 2 succeeds (self-stability).
            // Pass 1 Ok + pass 2 Err is the regression we are guarding.
            if let Ok(first) = strip_coordinates(input)
                && let Err(e) = strip_coordinates(&first)
            {
                panic!(
                    "input {idx} self-stability broken: pass 1 Ok, pass 2 Err({e}); \
                     pass 1 output bytes: {:?}",
                    first.as_ref()
                );
            }
        }
    }
}
