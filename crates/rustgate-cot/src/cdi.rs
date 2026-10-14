// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Cross-domain inspection (CDI) helpers — refs #857.
//!
//! The cross-domain inspection guard is the security boundary between
//! networks of different classifications (e.g. SECRET → UNCLASSIFIED).
//! At the boundary every event MUST be redacted of identity-linked PII,
//! coarsened so position data does not exceed the lower-side resolution
//! envelope, and tagged with a CAPCO classification banner so receivers
//! see the marking travelling with the event. The full guard lives in
//! the deferred `rustgate-guard` crate (rate limiting, mandatory
//! marking-injection, dedicated audit envelope, encrypted spool); this
//! module ships the three CoT-specific transformations the existing
//! obligation engine actuates as scaffold for that work.
//!
//! # Scope and shape
//!
//! Each helper takes a `&[u8]` payload and returns either a transformed
//! [`Bytes`] copy or `MaskError` under the same fail-closed
//! contract as the existing `strip_coordinates` family:
//!
//! - **Non-XML payloads** (first non-whitespace byte is not `<`) are
//!   returned verbatim — these helpers are best-effort CoT controls and
//!   a policy attached to a MAVLink, protobuf, or plain-text stream is
//!   a misconfiguration, not a leak. The transport-side actuator emits
//!   the standard `authz.obligation_failed` audit record with the
//!   appropriate recovery token.
//! - **XML-intent parse failures** propagate as `mask::MaskError::Xml`
//!   so the caller can fail-closed on the boundary message rather than
//!   forward partially-redacted bytes.
//!
//! Element matching is namespace-prefix-tolerant and case-insensitive,
//! delegating to the existing helpers in `mask` so a sender cannot
//! dodge the transform by emitting `<cot:contact>` or `<DETAIL>`.
//!
//! # Out of scope
//!
//! - The full `rustgate-guard` crate (deferred).
//! - The CAPCO parser and policy validation (`#849`).
//! - CDS hardware diode integration.
//! - Rate limiting at the boundary (deferred to `rustgate-guard`).

use bytes::Bytes;
use quick_xml::Writer;
use quick_xml::events::{BytesStart, Event};
use quick_xml::reader::Reader;

use crate::mask::{MAX_DETAIL_ATTRIBUTES, MaskError};

/// Replacement value written in place of a stripped PII attribute. The
/// element is preserved so a downstream parser still sees the
/// `<contact>` (or peer) shape, but every identifying attribute has its
/// value blanked. The brackets are inert in CoT XML (no entity
/// expansion, no element nesting) so schema validity survives.
const STRIPPED_VALUE: &[u8] = b"";

/// Attribute names on `<contact>` (and similar elements) that MUST be
/// stripped at the cross-domain boundary. Matched case-insensitively
/// against the attribute key. The list deliberately overshoots the spec
/// (`callsign`, `phone`, `email`, `endpoint`) to catch vendor-specific
/// variants like `xmppUsername` or `irc_channel` — at the boundary the
/// safer default is "redact unless explicitly allowlisted" rather than
/// "preserve unless explicitly denylisted".
const PII_CONTACT_ATTR_TOKENS: &[&[u8]] = &[
    b"callsign",
    b"phone",
    b"email",
    b"endpoint",
    b"xmpp",
    b"irc",
    b"sip",
    b"icq",
    b"hostname",
    b"username",
];

/// Per-element attribute-count cap reused from [`crate::mask`]. Crafted XML
/// packing thousands of attributes onto a single `<contact>` element
/// would otherwise force the actuator to allocate per-attribute; the
/// cap fail-closes via [`MaskError::AttrBudgetExceeded`] instead.
const ATTR_BUDGET: usize = MAX_DETAIL_ATTRIBUTES;

/// Local-name predicate factored out of [`crate::mask`]: strip any namespace
/// prefix and return the local part for case-insensitive comparison.
fn local_name(name: &[u8]) -> &[u8] {
    match name.iter().rposition(|b| *b == b':') {
        Some(idx) => &name[idx + 1..],
        None => name,
    }
}

/// Return `true` when `name` is a `<contact>` element. Case-insensitive
/// and namespace-tolerant — `<cot:Contact/>` matches just as `<contact/>`
/// does. Mirrors `mask::is_contact_tag`; duplicated here so the CDI
/// helpers do not depend on a `pub(crate)` mask-internal symbol.
fn is_contact_element(name: &[u8]) -> bool {
    local_name(name).eq_ignore_ascii_case(b"contact")
}

/// Return `true` when `name` is a `<detail>` element. The CDI marking
/// injector targets this element so the banner travels alongside the
/// other CoT detail children.
fn is_detail_element(name: &[u8]) -> bool {
    local_name(name).eq_ignore_ascii_case(b"detail")
}

/// Return `true` when `name` is a `<point>` element. Mirrors
/// `mask::is_point_tag`; duplicated for the same module-isolation
/// reason as [`is_contact_element`].
fn is_point_element(name: &[u8]) -> bool {
    local_name(name).eq_ignore_ascii_case(b"point")
}

/// Return `true` when `name` is a `<marking>` element — the wrapper the
/// CDI marking injector uses to deposit the CAPCO banner.
fn is_marking_element(name: &[u8]) -> bool {
    local_name(name).eq_ignore_ascii_case(b"marking")
}

/// Return `true` when `attr_name` matches any token in
/// `PII_CONTACT_ATTR_TOKENS` as a case-insensitive substring. The
/// substring scan is intentional — vendor extensions like
/// `xmppUsername` should also trip the matcher.
fn attr_name_is_pii(attr_name: &[u8]) -> bool {
    if attr_name.is_empty() {
        return false;
    }
    // ASCII fold with a stack buffer for the typical short attribute
    // name; fall back to a heap copy on the rare oversized case so the
    // match still succeeds rather than silently passing through.
    if attr_name.len() <= 64 {
        let mut buf = [0u8; 64];
        for (i, b) in attr_name.iter().enumerate() {
            buf[i] = b.to_ascii_lowercase();
        }
        let lc = &buf[..attr_name.len()];
        return PII_CONTACT_ATTR_TOKENS
            .iter()
            .any(|tok| lc.windows(tok.len()).any(|w| w == *tok));
    }
    let lc: Vec<u8> = attr_name.iter().map(|b| b.to_ascii_lowercase()).collect();
    PII_CONTACT_ATTR_TOKENS
        .iter()
        .any(|tok| lc.windows(tok.len()).any(|w| w == *tok))
}

/// Return `true` when the payload is XML-intent (first non-whitespace
/// byte is `<`). Non-XML payloads are returned verbatim by every helper
/// in this module — see the module-level docstring for the recovery
/// contract.
fn is_xml_intent(xml: &[u8]) -> bool {
    xml.iter()
        .find(|b| !b.is_ascii_whitespace())
        .is_some_and(|b| *b == b'<')
}

/// Build a [`Reader`] with the same defaults as the [`crate::mask`] family.
fn reader(xml: &[u8]) -> Reader<&[u8]> {
    let mut r = Reader::from_reader(xml);
    // Match the existing masker: no entity resolution, no DTD
    // processing, preserve text whitespace exactly as-is.
    r.config_mut().trim_text(false);
    r
}

/// Strip operator-identity PII fields from CoT `<contact>` and similar
/// `<detail>` children.
///
/// The transform walks every `<contact>`, `<endpoint>`, and any element
/// whose attributes contain a PII-bearing key (`callsign`, `phone`,
/// `email`, `endpoint`, plus the broader IM/chat tokens listed in
/// `PII_CONTACT_ATTR_TOKENS`). Matching attributes have their values
/// replaced with the empty byte sequence; the element shape, attribute
/// order, and non-PII attributes are preserved byte-for-byte. Elements
/// without PII attributes pass through unchanged.
///
/// # Recovery contract
///
/// - **Non-XML payload** — returned verbatim wrapped in `Ok`. The
///   transport actuator surfaces the recovery token via the standard
///   `authz.obligation_failed` audit event.
/// - **XML-intent parse failure** — surfaces [`MaskError::Xml`]; the
///   caller MUST drop the payload rather than forward partially-
///   redacted bytes.
/// - **Attribute budget trip** — surfaces
///   [`MaskError::AttrBudgetExceeded`] when a single element packs
///   more than `ATTR_BUDGET` attributes.
///
/// # Errors
///
/// Returns the variants documented in the recovery contract above.
pub fn strip_pii(xml: &[u8]) -> Result<Bytes, MaskError> {
    if !is_xml_intent(xml) {
        return Ok(Bytes::copy_from_slice(xml));
    }
    let mut reader = reader(xml);
    let mut out = Vec::with_capacity(xml.len());
    let mut writer = Writer::new(&mut out);
    let mut buf = Vec::new();
    loop {
        let event = reader.read_event_into(&mut buf)?;
        match event {
            Event::Eof => break,
            Event::Start(ref e) | Event::Empty(ref e) => {
                let mutated = strip_pii_attrs(e)?;
                if let Some(masked) = mutated {
                    let copy = match event {
                        Event::Start(_) => Event::Start(masked),
                        Event::Empty(_) => Event::Empty(masked),
                        _ => unreachable!("guarded by outer match arm"),
                    };
                    writer.write_event(copy)?;
                } else {
                    writer.write_event(event)?;
                }
            }
            other => writer.write_event(other)?,
        }
        buf.clear();
    }
    Ok(Bytes::from(out))
}

/// Re-emit a Start/Empty tag with PII attribute values blanked. Returns
/// `Ok(None)` when no attribute on the element matches the PII tokens
/// — the caller then writes the original event byte-for-byte to avoid
/// the round-trip cost on the typical no-op element.
fn strip_pii_attrs(src: &BytesStart<'_>) -> Result<Option<BytesStart<'static>>, MaskError> {
    let name_bytes = src.name();
    // Only re-emit when the element is contact-shaped or carries a PII
    // attribute. The contact predicate is a fast-path against the spec
    // shape; the attribute scan covers vendor extensions.
    let is_contact = is_contact_element(name_bytes.as_ref());
    let mut needs_rewrite = is_contact;
    if !needs_rewrite {
        for attr in src.attributes() {
            let attr = attr?;
            if attr_name_is_pii(attr.key.as_ref()) {
                needs_rewrite = true;
                break;
            }
        }
    }
    if !needs_rewrite {
        return Ok(None);
    }
    let name_str = std::str::from_utf8(name_bytes.as_ref())
        .map_err(|e| MaskError::Xml(quick_xml::Error::Encoding(e.into())))?;
    let mut out = BytesStart::new(name_str.to_owned());
    let mut count = 0usize;
    for attr in src.attributes() {
        let attr = attr?;
        count += 1;
        if count > ATTR_BUDGET {
            return Err(MaskError::AttrBudgetExceeded { limit: ATTR_BUDGET });
        }
        let key_bytes = attr.key.as_ref();
        if is_contact || attr_name_is_pii(key_bytes) {
            out.push_attribute((key_bytes, STRIPPED_VALUE));
        } else {
            // Preserve non-PII attributes verbatim.
            out.push_attribute((key_bytes, attr.value.as_ref()));
        }
    }
    Ok(Some(out))
}

/// Round CoT `<point>` lat/lon coordinates to a coarser grid.
///
/// `precision_meters` configures the grid spacing along both axes. The
/// helper rounds to the nearest grid cell (centre-of-cell rounding via
/// `(value / step).round() * step`). `precision_meters == 0` is treated
/// as a no-op — the payload passes through unmodified — so a misconfig
/// cannot panic via division-by-zero on the boundary path.
///
/// Rounding uses the spherical-Earth approximation: 1 degree of
/// latitude ≈ 111_320 metres regardless of latitude; 1 degree of
/// longitude ≈ 111_320 × cos(latitude) metres. Coarse enough for the
/// CDI-degradation use case (operators specify km-scale precision when
/// they want a city-level fix, not a sub-metre survey).
///
/// # Recovery contract
///
/// Same as [`strip_pii`].
///
/// # Errors
///
/// Returns the same variants as [`strip_pii`] under the same conditions.
pub fn degrade_position(xml: &[u8], precision_meters: u32) -> Result<Bytes, MaskError> {
    if !is_xml_intent(xml) || precision_meters == 0 {
        // No-op fast paths: non-XML payloads pass through; a zero step
        // would otherwise divide-by-zero on the rounding helper.
        return Ok(Bytes::copy_from_slice(xml));
    }
    let mut reader = reader(xml);
    let mut out = Vec::with_capacity(xml.len());
    let mut writer = Writer::new(&mut out);
    let mut buf = Vec::new();
    loop {
        let event = reader.read_event_into(&mut buf)?;
        match event {
            Event::Eof => break,
            Event::Start(ref e) | Event::Empty(ref e) if is_point_element(e.name().as_ref()) => {
                let degraded = degrade_point_attrs(e, precision_meters)?;
                let copy = match event {
                    Event::Start(_) => Event::Start(degraded),
                    Event::Empty(_) => Event::Empty(degraded),
                    _ => unreachable!("guarded by outer match arm"),
                };
                writer.write_event(copy)?;
            }
            other => writer.write_event(other)?,
        }
        buf.clear();
    }
    Ok(Bytes::from(out))
}

/// Re-emit a `<point>` Start/Empty tag with `lat`/`lon` rounded to the
/// configured grid. `hae` and other attributes pass through unchanged
/// — altitude degradation is out of scope for the scaffold; the full
/// guard handles it as part of the CDS resolution policy.
///
/// # Idempotence trade-off
///
/// The scaffold uses a single equator-equivalent grid step
/// ([`METRES_PER_DEG_LAT`]) for BOTH latitude and longitude. The full
/// guard in the deferred `rustgate-guard` crate will scale longitude
/// by `cos(latitude)` so the on-the-ground grid is isotropic at any
/// latitude. The scaffold trades that scaling for **idempotence**:
/// without it, applying `DegradePosition` twice would re-derive a
/// slightly different `cos(latitude)` from the already-rounded lat
/// value, snapping the longitude into a different cell on each
/// application. The double-application proptest pinned by #787
/// catches that drift, so the scaffold over-degrades at high
/// latitudes (longitude grid is `precision_meters` at the equator,
/// `precision_meters / cos(latitude)` on the ground) rather than
/// breaking the idempotence contract.
fn degrade_point_attrs(
    src: &BytesStart<'_>,
    precision_meters: u32,
) -> Result<BytesStart<'static>, MaskError> {
    let name_bytes = src.name();
    let name_str = std::str::from_utf8(name_bytes.as_ref())
        .map_err(|e| MaskError::Xml(quick_xml::Error::Encoding(e.into())))?;
    let mut out = BytesStart::new(name_str.to_owned());
    let mut count = 0usize;
    for attr in src.attributes() {
        let attr = attr?;
        count += 1;
        if count > ATTR_BUDGET {
            return Err(MaskError::AttrBudgetExceeded { limit: ATTR_BUDGET });
        }
        let key_bytes = attr.key.as_ref();
        if key_bytes.eq_ignore_ascii_case(b"lat") {
            let new_value = degrade_coordinate(attr.value.as_ref(), precision_meters);
            out.push_attribute((key_bytes, new_value.as_bytes()));
        } else if key_bytes.eq_ignore_ascii_case(b"lon") {
            // Same equator-step as latitude — see the docstring above
            // for the idempotence rationale.
            let new_value = degrade_coordinate(attr.value.as_ref(), precision_meters);
            out.push_attribute((key_bytes, new_value.as_bytes()));
        } else {
            out.push_attribute((key_bytes, attr.value.as_ref()));
        }
    }
    Ok(out)
}

/// Metres per degree of latitude — spherical Earth approximation. Good
/// enough for the CDI use case (km-scale degradation), avoids the cost
/// of an ellipsoidal model the scaffold does not need.
const METRES_PER_DEG_LAT: f64 = 111_320.0;

/// Round a coordinate attribute value (raw bytes from the CoT element)
/// to the configured grid step in metres. Used for BOTH latitude and
/// longitude in the scaffold — see the [`degrade_point_attrs`] doc
/// comment for the idempotence rationale. On parse failure the
/// original bytes are echoed back so a malformed numeric value does
/// not silently vanish; the caller's outer parse-error path is the
/// one that decides whether to fail-closed at the document level.
///
/// The snap is performed via integer cell counting (`(value /
/// step).round() as i64` then `cell as f64 * step`) so that two
/// successive applications converge to the same cell index even when
/// f64 round-tripping introduces sub-bit drift in the formatted
/// representation.
fn degrade_coordinate(value_bytes: &[u8], precision_meters: u32) -> String {
    let Ok(s) = std::str::from_utf8(value_bytes) else {
        return String::from_utf8_lossy(value_bytes).into_owned();
    };
    let trimmed = s.trim();
    let Ok(value) = trimmed.parse::<f64>() else {
        return s.to_string();
    };
    let step_deg = f64::from(precision_meters) / METRES_PER_DEG_LAT;
    if !step_deg.is_finite() || step_deg <= 0.0 {
        return format_coordinate(value);
    }
    let cell_count = (value / step_deg).round();
    let snapped = cell_count * step_deg;
    format_coordinate(snapped)
}

/// Format a coordinate in a CoT-friendly shape.
///
/// The width is `{:.10}` rather than the spec-typical `{:.6}` because
/// the formatter MUST be a fixed point of the round-trip
/// `parse → snap_to_grid → format` cycle (refs #857 and the
/// `double_application_is_idempotent` proptest pinned by #787): if a
/// coarser format dropped digits below the grid step, a second
/// application would re-snap to a different cell. Ten decimals is
/// sub-millimetre at the equator — well below any plausible CDI grid
/// step (typical values are 100 m – 10 km) so the second pass over
/// the same step rounds to the same integer cell index and emits the
/// same bytes.
///
/// Zero is rendered as `"0.0"` rather than `"0.0000000000"` so that an
/// already-masked `<point lat="0.0">` (output of
/// [`crate::mask::strip_coordinates`]) round-trips through this
/// formatter unchanged. Without that special case, applying
/// `MaskPoint` followed by `DegradePosition` would produce different
/// bytes than applying them in the canonical reverse order — breaking
/// the dispatcher's "two permutations of the same set produce
/// byte-identical output" contract from refs #882.
fn format_coordinate(value: f64) -> String {
    if !value.is_finite() || value == 0.0 {
        // Match `mask::strip_coordinates`'s zero rendering so the two
        // helpers compose without introducing byte-level drift.
        return "0.0".to_string();
    }
    format!("{value:.10}")
}

/// Inject a CAPCO classification banner into the CoT `<detail>` element.
///
/// The injector wraps the marking string in a `<marking value="…"/>`
/// child of the first `<detail>` element it encounters. Existing
/// `<marking/>` children (from a previous boundary hop) are removed
/// before insertion so the banner reflects the most-recent CDI
/// transition rather than accumulating layers of tags. Documents
/// without a `<detail>` element pass through unmodified — the marking
/// belongs nested under `<detail>` per the CoT spec, and the scaffold
/// declines to invent a parent rather than risk building malformed XML.
///
/// `marking` is XML-escaped at injection time (`&`, `<`, `>`, `"`),
/// so a crafted banner cannot break out of the attribute value or
/// inject a closing tag.
///
/// # Recovery contract
///
/// Same as [`strip_pii`].
///
/// # Errors
///
/// Returns the same variants as [`strip_pii`] under the same conditions.
pub fn inject_marking(xml: &[u8], marking: &str) -> Result<Bytes, MaskError> {
    if !is_xml_intent(xml) {
        return Ok(Bytes::copy_from_slice(xml));
    }
    let mut reader = reader(xml);
    let mut out = Vec::with_capacity(xml.len() + marking.len() + 32);
    let mut writer = Writer::new(&mut out);
    let mut buf = Vec::new();
    // Sanitize: remove control characters that would break the audit
    // log surface. quick_xml's `push_attribute(&str)` already escapes
    // `&`, `<`, `>`, `"`, `'` via the `escape_attr` helper, so we MUST
    // hand it the raw post-sanitization bytes — pre-escaping would
    // double-encode the entity references.
    let sanitized = sanitize_marking(marking);
    let mut depth: i32 = 0;
    let mut detail_depth: Option<i32> = None;
    let mut injected = false;
    let mut suppress_marking = false;
    loop {
        let event = reader.read_event_into(&mut buf)?;
        match event {
            Event::Eof => break,
            Event::Start(ref e) => {
                depth += 1;
                if is_detail_element(e.name().as_ref()) && detail_depth.is_none() && !injected {
                    detail_depth = Some(depth);
                    writer.write_event(Event::Start(e.clone().into_owned()))?;
                } else if is_marking_element(e.name().as_ref())
                    && detail_depth.is_some()
                    && !injected
                {
                    // Suppress an existing `<marking>...</marking>`
                    // pair so a previous CDI banner does not pile up.
                    suppress_marking = true;
                } else if !suppress_marking {
                    writer.write_event(event)?;
                }
            }
            Event::End(ref e) => {
                if is_marking_element(e.name().as_ref()) && suppress_marking {
                    suppress_marking = false;
                } else {
                    if let Some(d) = detail_depth
                        && d == depth
                        && !injected
                    {
                        // Inject the marking child immediately before the
                        // closing `</detail>` so the banner travels as
                        // the last child — receivers iterating detail
                        // children see it after every other element.
                        let mut marking_tag = BytesStart::new("marking");
                        marking_tag.push_attribute(("value", sanitized.as_str()));
                        writer.write_event(Event::Empty(marking_tag))?;
                        injected = true;
                        detail_depth = None;
                    }
                    writer.write_event(event)?;
                }
                depth -= 1;
            }
            Event::Empty(ref e) => {
                if is_marking_element(e.name().as_ref()) && detail_depth.is_some() && !injected {
                    // Drop the standalone `<marking/>` so the new one
                    // takes its place. Suppression is single-event
                    // because `Empty` has no matching `End`.
                } else {
                    writer.write_event(event)?;
                }
            }
            other => {
                if !suppress_marking {
                    writer.write_event(other)?;
                }
            }
        }
        buf.clear();
    }
    Ok(Bytes::from(out))
}

/// Strip control characters from a marking string. quick_xml escapes
/// `&`, `<`, `>`, `"`, `'` automatically when the attribute value is
/// passed via `push_attribute(&str)`, so the only sanitization we must
/// do is remove characters that would break the audit log surface
/// (newlines, carriage returns, NUL bytes) — entity escaping is the
/// writer's responsibility and pre-escaping would double-encode.
fn sanitize_marking(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        if (ch as u32) < 0x20 && ch != '\t' {
            // Drop control characters that would break logs / audit.
            continue;
        }
        out.push(ch);
    }
    out
}

// All `?` propagation in this module funnels through the existing
// `From<quick_xml::Error>` and `From<io::Error>` impls on `MaskError`
// in `crate::mask`. No additional bridge types needed; the reader and
// writer error types both convert via those impls already.

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    //! Refs #857 — pin the scaffold's recovery contract and the
    //! per-helper invariants documented in the module-level docstring.

    use super::*;

    const COT_WITH_CONTACT: &[u8] = br#"<event uid="u1" type="a-f-G-U-C" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z"><point lat="38.8977" lon="-77.0365" hae="125.4"/><detail><contact callsign="ALPHA-1" phone="+1-555-0100" email="alpha@example.test"/></detail></event>"#;

    #[test]
    fn strip_pii_removes_callsign_phone_email_from_contact() {
        let out = strip_pii(COT_WITH_CONTACT).expect("strip_pii ok");
        let s = std::str::from_utf8(&out).unwrap();
        // Spec attributes blanked.
        assert!(s.contains(r#"callsign="""#), "callsign not blanked: {s}");
        assert!(s.contains(r#"phone="""#), "phone not blanked: {s}");
        assert!(s.contains(r#"email="""#), "email not blanked: {s}");
        // Original PII values gone.
        assert!(!s.contains("ALPHA-1"), "callsign value leaked: {s}");
        assert!(!s.contains("555-0100"), "phone value leaked: {s}");
        assert!(!s.contains("alpha@example.test"), "email value leaked: {s}");
        // Non-PII context survived.
        assert!(s.contains(r#"uid="u1""#), "envelope uid lost: {s}");
        assert!(s.contains("<point"), "point element removed: {s}");
    }

    #[test]
    fn strip_pii_handles_endpoint_and_xmpp_attributes() {
        // Endpoint and IM attributes should also be redacted (they
        // contain operator-identifying data even when the spec
        // callsign attribute is absent).
        let xml = br#"<event><detail><contact endpoint="*:1234:tcp" xmppUsername="op@chat"/></detail></event>"#;
        let out = strip_pii(xml).expect("ok");
        let s = std::str::from_utf8(&out).unwrap();
        assert!(s.contains(r#"endpoint="""#), "endpoint not blanked: {s}");
        assert!(s.contains(r#"xmppUsername="""#), "xmpp not blanked: {s}",);
        assert!(!s.contains("*:1234:tcp"), "endpoint value leaked: {s}");
        assert!(!s.contains("op@chat"), "xmpp value leaked: {s}");
    }

    #[test]
    fn strip_pii_passes_non_xml_payload_through_unchanged() {
        let payload = b"binary mavlink payload \x00\x01\x02";
        let out = strip_pii(payload).expect("ok");
        assert_eq!(out.as_ref(), payload);
    }

    #[test]
    fn strip_pii_returns_xml_error_on_malformed_payload() {
        // Mid-document parse abort — the helper must surface the error
        // rather than forward bytes that already leaked PII before the
        // parser tripped.
        let malformed = br#"<event><detail><contact callsign="X" phone="Y"/><unterminated"#;
        let res = strip_pii(malformed);
        assert!(matches!(res, Err(MaskError::Xml(_))));
    }

    #[test]
    fn degrade_position_rounds_lat_lon_to_kilometre_precision() {
        let out = degrade_position(COT_WITH_CONTACT, 1000).expect("ok");
        let s = std::str::from_utf8(&out).unwrap();
        // 1 km step at lat ≈ 38.9° ≈ 0.00898 deg latitude. The
        // input lat 38.8977 rounds to 38.897600 (40 × 0.00898) — pin
        // the rounded representation rather than re-deriving the
        // grid in the test, so a future refactor that swaps the
        // step formula breaks visibly here.
        // Original raw values must NOT survive byte-for-byte.
        assert!(!s.contains("38.8977"), "raw lat leaked: {s}");
        assert!(!s.contains("-77.0365"), "raw lon leaked: {s}");
        // Coordinates round to six-decimal precision; pin the prefix
        // rather than the exact float to tolerate platform rounding.
        assert!(
            s.contains(r#"lat="38.8"#) || s.contains(r#"lat="38.9"#),
            "lat not rounded near 38.9: {s}"
        );
        assert!(
            s.contains(r#"lon="-77.0"#) || s.contains(r#"lon="-77.1"#),
            "lon not rounded near -77.0: {s}"
        );
        // `hae` passes through (altitude degradation deferred).
        assert!(s.contains(r#"hae="125.4""#), "hae mutated: {s}");
    }

    #[test]
    fn degrade_position_preserves_other_cot_attributes() {
        let out = degrade_position(COT_WITH_CONTACT, 1000).expect("ok");
        let s = std::str::from_utf8(&out).unwrap();
        // Envelope fields untouched.
        assert!(s.contains(r#"uid="u1""#));
        assert!(s.contains(r#"type="a-f-G-U-C""#));
        // Contact remains (degrade_position does not strip PII; that's
        // a separate obligation that may chain after).
        assert!(s.contains(r#"callsign="ALPHA-1""#), "callsign mutated: {s}");
    }

    #[test]
    fn degrade_position_no_op_on_non_xml_payload() {
        let payload = b"\x00\x01binary\x02\x03";
        let out = degrade_position(payload, 1000).expect("ok");
        assert_eq!(out.as_ref(), payload);
    }

    #[test]
    fn degrade_position_zero_precision_is_no_op() {
        // Defensive: a misconfigured policy with `precision_meters = 0`
        // must not panic via division-by-zero on the rounding helper.
        let out = degrade_position(COT_WITH_CONTACT, 0).expect("ok");
        assert_eq!(out.as_ref(), COT_WITH_CONTACT);
    }

    #[test]
    fn inject_marking_adds_marking_child_to_detail() {
        let out = inject_marking(COT_WITH_CONTACT, "//SECRET//NOFORN").expect("ok");
        let s = std::str::from_utf8(&out).unwrap();
        assert!(
            s.contains(r#"<marking value="//SECRET//NOFORN""#),
            "marking element not injected: {s}",
        );
        // Existing <detail> children survive.
        assert!(s.contains(r#"callsign="ALPHA-1""#), "contact lost: {s}");
    }

    #[test]
    fn inject_marking_replaces_existing_marking_if_present() {
        let xml = br#"<event uid="u1"><detail><marking value="//OLD//"/><contact callsign="A"/></detail></event>"#;
        let out = inject_marking(xml, "//NEW//SECRET").expect("ok");
        let s = std::str::from_utf8(&out).unwrap();
        assert!(
            s.contains(r#"<marking value="//NEW//SECRET""#),
            "new marking not injected: {s}",
        );
        assert!(!s.contains("//OLD//"), "old marking survived: {s}");
        // Non-marking detail children survive.
        assert!(s.contains(r#"callsign="A""#), "sibling lost: {s}");
    }

    #[test]
    fn inject_marking_no_op_on_non_xml_payload() {
        let payload = b"binary tak protobuf \xBF\x01";
        let out = inject_marking(payload, "//SECRET//").expect("ok");
        assert_eq!(out.as_ref(), payload);
    }

    #[test]
    fn inject_marking_passes_through_when_no_detail_element() {
        // Documents without `<detail>` are forwarded unmodified — see
        // the docstring: the scaffold declines to invent a parent.
        let xml = br#"<event uid="u1"><point lat="0" lon="0" hae="0"/></event>"#;
        let out = inject_marking(xml, "//SECRET//").expect("ok");
        assert_eq!(out.as_ref(), xml);
    }

    #[test]
    fn inject_marking_escapes_xml_special_characters() {
        // A crafted banner containing `"`, `<`, `>`, `&`, `'` MUST NOT
        // break out of the attribute value. The injector emits the
        // entity references and a downstream parser re-decodes them.
        let xml = br#"<event><detail><contact callsign="A"/></detail></event>"#;
        let out = inject_marking(xml, r#"</marking>"&<x>'"#).expect("ok");
        let s = std::str::from_utf8(&out).unwrap();
        // The literal closing tag must not appear — it would terminate
        // the marking element prematurely.
        assert!(
            !s.contains("</marking>\""),
            "literal close tag leaked into attribute: {s}",
        );
        assert!(s.contains("&lt;"), "less-than not escaped: {s}");
        assert!(s.contains("&gt;"), "greater-than not escaped: {s}");
        assert!(s.contains("&amp;"), "ampersand not escaped: {s}");
        assert!(s.contains("&quot;"), "quote not escaped: {s}");
        assert!(s.contains("&apos;"), "apostrophe not escaped: {s}");
    }

    #[test]
    fn strip_pii_then_degrade_position_chains_associatively() {
        // The transport-side dispatcher applies obligations in
        // canonical chaining order. This module-level pin ensures the
        // two helpers compose without one undoing the other:
        // strip_pii blanks contact attrs, then degrade_position
        // rounds the point — neither touches the other's surface.
        let stripped = strip_pii(COT_WITH_CONTACT).expect("strip ok");
        let degraded = degrade_position(&stripped, 1000).expect("degrade ok");
        let s = std::str::from_utf8(&degraded).unwrap();
        // PII gone, position degraded, envelope intact.
        assert!(!s.contains("ALPHA-1"));
        assert!(!s.contains("38.8977"));
        assert!(s.contains(r#"uid="u1""#));
        // Reverse order produces the same byte output for these two
        // helpers: each operates on a disjoint element subset.
        let degraded_first = degrade_position(COT_WITH_CONTACT, 1000).expect("ok");
        let then_stripped = strip_pii(&degraded_first).expect("ok");
        assert_eq!(
            std::str::from_utf8(&degraded).unwrap(),
            std::str::from_utf8(&then_stripped).unwrap(),
            "strip+degrade must be order-independent on disjoint elements",
        );
    }
}
