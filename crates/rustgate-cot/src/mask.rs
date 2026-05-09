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
//! actual scope at the [`MaskDetailLevel::Coarse`] (default) tier: only
//! the `<point>` element is touched. Free-form geographic references
//! inside `<detail>` children, the event `uid`, or envelope metadata
//! are NOT scrubbed by this tier. Policy authors who need stronger leak
//! prevention should either select a stricter
//! [`MaskDetailLevel`] via [`strip_coordinates_with_level`], use
//! `MaskPayload` (which empties the body entirely), or deny delivery
//! outright.
//!
//! # Detail levels (refs #882)
//!
//! [`MaskDetailLevel`] selects how aggressively secondary
//! position-bearing fields are scrubbed:
//!
//! - **[`MaskDetailLevel::Coarse`]** (default, [`strip_coordinates`])
//!   masks only `<point lat lon hae />`. This is the legacy behaviour
//!   and the most permissive level — secondary fields like
//!   `<contact callsign>`, `<__group>`, `<takv platform>`, and any
//!   custom `lat`/`lon`-named attributes are passed through untouched.
//! - **[`MaskDetailLevel::Medium`]** also redacts `<contact callsign>`
//!   (callsigns are identity-linked to position) and `<__group>`
//!   attributes (unit affiliation reveals tactical sector membership).
//! - **[`MaskDetailLevel::Strict`]** further redacts `<takv platform>`
//!   (TAK device platform identifies the operator's hardware family),
//!   `<status battery>` (battery level can be operationally signalling),
//!   and any attribute on any element whose name (case-insensitively)
//!   contains `lat`, `lon`, `alt`, `pos`, or `loc` — closing the
//!   "callsign-like custom field" hole that motivated the issue.
//!
//! A single redacted attribute value is replaced with the static byte
//! string `[REDACTED]` rather than the empty string so a downstream
//! consumer can distinguish "operator masked this" from "sender omitted
//! this", and so a CoT parser that strips empty attributes does not
//! silently drop the redaction signal.
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

/// Attribute value written in place of secondary position-bearing
/// fields (callsign, group affiliation, takv platform, custom lat/lon
/// attributes) when the configured [`MaskDetailLevel`] redacts them.
///
/// The literal `[REDACTED]` is preferred over the empty string so a
/// downstream consumer can distinguish "operator masked this" from
/// "sender omitted this", and so a permissive parser that drops empty
/// attribute values does not silently lose the masking signal. The
/// brackets are inert in CoT XML (no entity expansion, no element
/// nesting) — schema validity is preserved.
const REDACTED_VALUE: &[u8] = b"[REDACTED]";

/// Upper bound on `<point>` attribute count.
///
/// Spec-conforming CoT `<point>` uses 5 attributes (`lat`, `lon`, `hae`,
/// `ce`, `le`). This cap is deliberately loose so legitimate extensions
/// pass but crafted XML cannot amplify per-recipient masking cost on a
/// broadcast. [`strip_coordinates`] returns
/// [`MaskError::AttrBudgetExceeded`] when the cap is hit.
pub const MAX_POINT_ATTRIBUTES: usize = 64;

/// Per-element attribute-count cap applied to every element the masker
/// inspects under [`MaskDetailLevel::Medium`] / [`MaskDetailLevel::Strict`].
///
/// Same cost-amplification protection as [`MAX_POINT_ATTRIBUTES`] but
/// applied to the broader set of elements the stricter levels touch
/// (`<contact>`, `<__group>`, `<takv>`, `<status>`, plus any custom
/// element under Strict). Crafted XML packing 10 000 attributes onto a
/// single `<contact>` element would otherwise force the masker to
/// allocate and re-emit each one — the cap fail-closes via
/// [`MaskError::AttrBudgetExceeded`] instead.
pub const MAX_DETAIL_ATTRIBUTES: usize = 64;

/// Operator-selected aggressiveness for [`strip_coordinates_with_level`].
///
/// Refs #882 (point masking detail leakage). The CoT spec leaves
/// secondary position-bearing fields untouched by the legacy
/// [`Coarse`](Self::Coarse) masker — a receiver who sees a masked
/// `<point />` but a clear `<contact callsign>` or `<__group>` may
/// still extract operationally sensitive metadata. The level lets an
/// operator select how aggressively those secondary fields are
/// scrubbed without committing to the all-or-nothing
/// `Obligation::MaskPayload`.
///
/// **The default is [`Coarse`](Self::Coarse).** [`strip_coordinates`]
/// dispatches to this level for backward compatibility with every
/// caller that does not opt into a stricter tier.
///
/// **Ordering is informational, not numeric.** Adding variants must
/// preserve the meaning that each successive variant is a *superset*
/// of redactions applied by all earlier variants — a Strict deployment
/// MUST scrub every field a Medium deployment scrubs, plus its own
/// additions. The ordering is encoded by `Medium`,
/// `Strict`, etc. — match exhaustively at call sites
/// rather than comparing variants by integer rank, since the enum is
/// `#[non_exhaustive]` and a future tier may sit between two existing
/// ones.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MaskDetailLevel {
    /// Default level. Masks only `<point lat lon hae />`. Secondary
    /// position-bearing fields (`<contact callsign>`, `<__group>`,
    /// `<takv>`, `<status battery>`, custom lat/lon-named attributes)
    /// are passed through untouched.
    ///
    /// This is the legacy pre-#882 behaviour. Choose this level when
    /// the receiver is trusted to handle callsign / group / device
    /// metadata, and operational policy explicitly tolerates that
    /// metadata reaching them.
    #[default]
    Coarse,
    /// Coarse plus `<contact callsign>` and `<__group>` attributes.
    ///
    /// Callsigns are identity-linked to position — a receiver who
    /// knows "ALPHA-1 is at the masked position" can derive sector
    /// membership over time even without raw coordinates. `<__group>`
    /// carries unit affiliation (e.g. colour-coded teams) which
    /// likewise reveals tactical structure. Choose this level when
    /// the receiver should see the event shape but neither the
    /// operator's identity nor unit affiliation.
    Medium,
    /// Medium plus `<takv platform>`, `<status battery>`, and any
    /// attribute on any element whose name contains (case-insensitively)
    /// `lat`, `lon`, `alt`, `pos`, or `loc`.
    ///
    /// `<takv platform>` reveals the operator's TAK device family
    /// (ATAK-CIV, WinTAK, iTAK), which can be operationally signalling
    /// in a fleet that uses platform-specific roles. `<status battery>`
    /// can correlate with patrol duration. The custom-attribute pass
    /// closes the "callsign-like operator-defined field" hole — a
    /// vendor-specific `<x my_lat="…">` would otherwise leak a position
    /// the masker did not know to look for.
    ///
    /// Choose this level when the receiver should see only the
    /// envelope and event type — no identity, no unit affiliation,
    /// no device-derived signal.
    Strict,
}

impl MaskDetailLevel {
    /// Return `true` when this level redacts `<contact callsign>` and
    /// `<__group>` attributes. True for [`Medium`](Self::Medium) and
    /// [`Strict`](Self::Strict), false for [`Coarse`](Self::Coarse).
    pub fn redacts_callsign_and_group(self) -> bool {
        matches!(self, Self::Medium | Self::Strict)
    }

    /// Return `true` when this level redacts `<takv>`, `<status>`, and
    /// custom lat/lon-named attributes. True for
    /// [`Strict`](Self::Strict) only.
    pub fn redacts_takv_and_custom(self) -> bool {
        matches!(self, Self::Strict)
    }
}

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
    /// An attribute value contains characters that the masker's writer
    /// cannot faithfully round-trip. Specifically: a raw `"` byte
    /// inside an attribute value (legal when the input uses single-
    /// quote delimiters) cannot survive the writer because the writer
    /// always wraps values in `"` and does not escape inner `"`. The
    /// resulting bytes parse on the next pass as additional attributes,
    /// breaking the masker's documented idempotence invariant. Treated
    /// as fail-closed in line with the masker's contract.
    #[error("attribute value cannot be round-tripped through the masker")]
    UnsafeAttrValue,
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
            Self::UnsafeAttrValue => "unsafe_attr_value",
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
    local_name(name).eq_ignore_ascii_case(b"point")
}

/// Strip the namespace prefix from a qualified XML name and return the
/// local part. Used by every `is_*_tag` predicate so a namespaced
/// variant cannot bypass the matcher.
fn local_name(name: &[u8]) -> &[u8] {
    match name.iter().rposition(|b| *b == b':') {
        Some(idx) => &name[idx + 1..],
        None => name,
    }
}

/// Return `true` when `name` is a `<contact>` element (case-insensitive,
/// namespace-tolerant). Used by [`MaskDetailLevel::Medium`] and stricter
/// to redact `<contact callsign="…">` attributes.
fn is_contact_tag(name: &[u8]) -> bool {
    local_name(name).eq_ignore_ascii_case(b"contact")
}

/// Return `true` when `name` is a `<__group>` element (case-insensitive,
/// namespace-tolerant). The double underscore prefix is part of the
/// element name in spec CoT — it does NOT denote a namespace.
fn is_group_affiliation_tag(name: &[u8]) -> bool {
    local_name(name).eq_ignore_ascii_case(b"__group")
}

/// Return `true` when `name` is a `<takv>` element (case-insensitive,
/// namespace-tolerant). Used by [`MaskDetailLevel::Strict`] to redact
/// platform / version metadata that identifies the operator's TAK
/// device family.
fn is_takv_tag(name: &[u8]) -> bool {
    local_name(name).eq_ignore_ascii_case(b"takv")
}

/// Return `true` when `name` is a `<status>` element (case-insensitive,
/// namespace-tolerant). Used by [`MaskDetailLevel::Strict`] to redact
/// the `battery` attribute, which can correlate with patrol duration.
fn is_status_tag(name: &[u8]) -> bool {
    local_name(name).eq_ignore_ascii_case(b"status")
}

/// Substrings that identify a position-bearing attribute *name* (not
/// value). Matched case-insensitively as a substring on the attribute
/// key — `my_lat`, `LATITUDE`, `geoLOC`, and `pos_x` all match. Pure
/// ASCII; an attribute whose name escapes ASCII through a non-Latin
/// script falls outside CoT spec and would not be mistaken for one of
/// these tokens by a well-behaved sender.
const POSITION_ATTR_TOKENS: &[&[u8]] = &[b"lat", b"lon", b"alt", b"pos", b"loc"];

/// Return `true` when `attr_name` contains (case-insensitively) any of
/// the [`POSITION_ATTR_TOKENS`]. Used by
/// [`MaskDetailLevel::Strict`] to redact the value of any custom
/// attribute whose name suggests a position field.
///
/// The match is a substring scan rather than equality so a vendor
/// extension like `my_lat` or `pos_estimated_x` is also caught — the
/// motivating concern for #882's Strict tier is that operator-defined
/// custom fields might re-introduce position data the masker did not
/// know to look for.
fn attr_name_is_position_like(attr_name: &[u8]) -> bool {
    if attr_name.is_empty() {
        return false;
    }
    // ASCII-fold once, then scan for each token. A 64-byte stack
    // buffer covers every plausible attribute name (XML allows much
    // longer, but real-world CoT attribute keys are short); attribute
    // keys exceeding the buffer are still checked, just via a heap
    // copy — preserving correctness for crafted inputs.
    if attr_name.len() <= 64 {
        let mut buf = [0u8; 64];
        for (i, b) in attr_name.iter().enumerate() {
            buf[i] = b.to_ascii_lowercase();
        }
        let lc = &buf[..attr_name.len()];
        return POSITION_ATTR_TOKENS
            .iter()
            .any(|tok| lc.windows(tok.len()).any(|w| w == *tok));
    }
    let lc: Vec<u8> = attr_name.iter().map(|b| b.to_ascii_lowercase()).collect();
    POSITION_ATTR_TOKENS
        .iter()
        .any(|tok| lc.windows(tok.len()).any(|w| w == *tok))
}

/// Return a copy of `xml` with every `<point>` element's `lat`, `lon`,
/// and `hae` attributes overwritten with `"0.0"` at
/// [`MaskDetailLevel::Coarse`].
///
/// This is the legacy entrypoint preserved for backward compatibility
/// with every caller pre-#882. Equivalent to
/// `strip_coordinates_with_level(xml, MaskDetailLevel::Coarse)`.
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
    strip_coordinates_with_level(xml, MaskDetailLevel::Coarse)
}

/// Like [`strip_coordinates`] but applies the operator-selected
/// [`MaskDetailLevel`].
///
/// Refs #882 (point masking detail leakage). The Coarse-level legacy
/// behaviour zeroed `<point lat lon hae />` only, leaving secondary
/// position-bearing fields (`<contact callsign>`, `<__group>`,
/// `<takv platform>`, `<status battery>`, custom lat/lon-named
/// attributes) intact for receivers to extract operationally
/// sensitive metadata from. This entrypoint lets the caller select a
/// stricter level without committing to the all-or-nothing
/// `MaskPayload`.
///
/// At [`MaskDetailLevel::Medium`]:
/// - Every `<contact>` element's `callsign` attribute (case-insensitive)
///   is replaced with `[REDACTED]`.
/// - Every `<__group>` element's `name` and `role` attributes are
///   replaced with `[REDACTED]`.
///
/// At [`MaskDetailLevel::Strict`] (in addition to the Medium scrubs):
/// - Every `<takv>` element's `platform` and `version` attributes are
///   replaced with `[REDACTED]`.
/// - Every `<status>` element's `battery` attribute is replaced with
///   `[REDACTED]`.
/// - On every element, any attribute whose **name** contains (case-
///   insensitively) any of `lat`, `lon`, `alt`, `pos`, `loc` has its
///   value replaced with `[REDACTED]`. The match is a substring scan
///   so vendor extensions like `my_lat` and `pos_estimated_x` are
///   covered. The three canonical `<point>` coordinate attributes
///   (`lat`, `lon`, `hae`) are still zeroed to `0.0` rather than
///   `[REDACTED]` because downstream parsers expect numeric values
///   there — the Coarse-level shape is preserved on the spec elements.
///
/// All non-redacted attributes survive in their original byte form
/// and order; non-target elements pass through byte-for-byte; XML
/// declarations, comments, processing instructions, and CDATA are
/// preserved. The matching for every target element is case-
/// insensitive and namespace-prefix-tolerant.
///
/// # Errors
///
/// Same fail-closed contract as [`strip_coordinates`]:
/// [`MaskError::Xml`] for XML-intent payloads that trip the parser,
/// [`MaskError::AttrBudgetExceeded`] for crafted XML packing more than
/// [`MAX_POINT_ATTRIBUTES`] (on `<point>`) or [`MAX_DETAIL_ATTRIBUTES`]
/// (on every other element the level inspects) attributes onto a
/// single tag.
pub fn strip_coordinates_with_level(
    xml: &[u8],
    level: MaskDetailLevel,
) -> Result<Bytes, MaskError> {
    // Fast-path: no XML intent → verbatim. A single-pass scan for the
    // first non-whitespace byte avoids allocating a Reader for non-XML
    // payloads (binary protocols, plain text). Valid XML must start
    // with `<` after optional leading whitespace; anything else cannot
    // contain a `<point>` element we need to mask. The fast-path is
    // identical across every level — non-XML cannot host any of the
    // secondary fields either.
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
    // more than a handful of bytes (Coarse) or by ~16 bytes per redacted
    // attribute (Medium/Strict, where `[REDACTED]` is 10 bytes plus the
    // value-length delta). Reallocation on extreme stricter-tier inputs
    // is acceptable; the +0% Coarse path remains the typical case.
    let mut out = Vec::with_capacity(xml.len());
    let mut writer = Writer::new(&mut out);
    let mut buf = Vec::new();

    // Element matching is delegated to the `is_*_tag` predicates so
    // case and namespace variants do not bypass the masker. The authz
    // engine presents `MaskPoint` as a data-plane leak-prevention
    // control; accepting only one exact casing would let a sender
    // dodge the mask by emitting `<Point>` or `<cot:point>`.
    //
    // Order matters: `<point>` is its own coordinate-zeroing path (still
    // Coarse-shape on its three numeric attributes). Strict adds a
    // pass-by-attribute-name check for custom position-like fields so
    // a vendor extension is covered even on a non-target element.
    loop {
        let event = reader.read_event_into(&mut buf)?;
        // Fail-closed pre-check on attribute values that would lose
        // round-trip identity through the writer. quick_xml's reader
        // accepts attribute values with the *opposite* quote inside
        // (e.g. `t='"e="'` — a single-quoted value containing raw
        // `"` bytes). The writer always emits attribute values
        // wrapped in `"` and does NOT escape inner `"` characters,
        // so a single-pass through the masker turns `t='"e="'` into
        // `t=""e=""` — bytes that the parser then reads as **two**
        // attributes (`t=""` and `e=""`) on the next pass. The
        // resulting attribute-cardinality drift broke the masker's
        // documented idempotence invariant. Discovered by the
        // `cot_mask_strip_coordinates` weekly extended fuzzer; the
        // 16-byte regression input is pinned by a test below.
        //
        // The right answer per the masker's fail-closed contract is
        // to refuse the document — a sender whose attributes need
        // escapes the writer cannot faithfully emit must drop, not
        // forward output that disagrees with the input.
        if let Event::Start(ref e) | Event::Empty(ref e) = event {
            check_attrs_round_trip_safe(e)?;
        }
        match event {
            Event::Eof => break,
            Event::Start(ref e) | Event::Empty(ref e) if is_point_tag(e.name().as_ref()) => {
                let masked = mask_point_attrs(e, level)?;
                let copy = match event {
                    Event::Start(_) => Event::Start(masked),
                    Event::Empty(_) => Event::Empty(masked),
                    // Unreachable — the outer arm guards on Start|Empty.
                    _ => unreachable!("guarded by outer match arm"),
                };
                writer.write_event(copy)?;
            }
            Event::Start(ref e) | Event::Empty(ref e)
                if level.redacts_callsign_and_group()
                    && (is_contact_tag(e.name().as_ref())
                        || is_group_affiliation_tag(e.name().as_ref())) =>
            {
                let masked = mask_detail_attrs(e, level)?;
                let copy = match event {
                    Event::Start(_) => Event::Start(masked),
                    Event::Empty(_) => Event::Empty(masked),
                    _ => unreachable!("guarded by outer match arm"),
                };
                writer.write_event(copy)?;
            }
            Event::Start(ref e) | Event::Empty(ref e)
                if level.redacts_takv_and_custom()
                    && (is_takv_tag(e.name().as_ref()) || is_status_tag(e.name().as_ref())) =>
            {
                let masked = mask_detail_attrs(e, level)?;
                let copy = match event {
                    Event::Start(_) => Event::Start(masked),
                    Event::Empty(_) => Event::Empty(masked),
                    _ => unreachable!("guarded by outer match arm"),
                };
                writer.write_event(copy)?;
            }
            Event::Start(ref e) | Event::Empty(ref e) if level.redacts_takv_and_custom() => {
                // Strict-only: scan every other element for an attribute
                // whose NAME is position-like (lat/lon/alt/pos/loc as a
                // substring). If at least one such attribute is found,
                // re-emit the element with those values redacted; if not,
                // fall through to byte-for-byte pass-through.
                if any_attr_name_is_position_like(e)? {
                    let masked = mask_detail_attrs(e, level)?;
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

/// Build a new `<point>` start tag with the coordinate attributes
/// replaced. The original qualified tag name is preserved byte-for-byte:
/// if the input was `<cot:Point …/>`, the output is
/// `<cot:Point lat="0.0" …/>`. Non-coordinate attributes are preserved
/// in their original order.
///
/// At [`MaskDetailLevel::Strict`], any non-coordinate attribute on
/// `<point>` whose name is position-like (substring scan against
/// [`POSITION_ATTR_TOKENS`]) ALSO has its value redacted to
/// `[REDACTED]`. This closes the case where a vendor extension stamps
/// a custom `<point my_lat="…">` on the spec element itself. The three
/// canonical numeric attributes still receive `0.0` rather than
/// `[REDACTED]` so a numeric parser does not error on the spec shape.
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
fn mask_point_attrs(
    src: &BytesStart<'_>,
    level: MaskDetailLevel,
) -> Result<BytesStart<'static>, MaskError> {
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
            _ if level.redacts_takv_and_custom() && attr_name_is_position_like(key_bytes) => {
                // Strict-only: a custom position-like attribute on
                // `<point>` itself (e.g. `<point my_lat="…">`) gets
                // the bracket-style redaction, distinguishing it from
                // the spec coordinate-zeroing path.
                masked.push_attribute((key_bytes, REDACTED_VALUE));
            }
            _ => {
                masked.push_attribute((key_bytes, attr.value.as_ref()));
            }
        }
    }
    Ok(masked)
}

/// Build a new start tag for a non-`<point>` element the configured
/// [`MaskDetailLevel`] redacts. The element's qualified name is
/// preserved; per-attribute redaction is applied as documented on
/// [`strip_coordinates_with_level`].
///
/// Per-element attribute count is capped at [`MAX_DETAIL_ATTRIBUTES`]
/// — same cost-amplification protection [`MAX_POINT_ATTRIBUTES`]
/// gives `<point>`, applied to the broader element set the stricter
/// levels touch. Trips fail-closed via [`MaskError::AttrBudgetExceeded`].
fn mask_detail_attrs(
    src: &BytesStart<'_>,
    level: MaskDetailLevel,
) -> Result<BytesStart<'static>, MaskError> {
    let name_bytes = src.name();
    let name_str = std::str::from_utf8(name_bytes.as_ref())
        .map_err(|e| MaskError::Xml(quick_xml::Error::Encoding(e.into())))?;
    let element_name = name_bytes.as_ref().to_vec();
    let mut masked = BytesStart::new(name_str.to_owned());
    let mut count = 0usize;
    for attr in src.attributes() {
        let attr = attr?;
        count += 1;
        if count > MAX_DETAIL_ATTRIBUTES {
            return Err(MaskError::AttrBudgetExceeded {
                limit: MAX_DETAIL_ATTRIBUTES,
            });
        }
        let key_bytes = attr.key.as_ref();
        if attr_should_be_redacted_on_element(&element_name, key_bytes, level) {
            masked.push_attribute((key_bytes, REDACTED_VALUE));
        } else {
            masked.push_attribute((key_bytes, attr.value.as_ref()));
        }
    }
    Ok(masked)
}

/// Decide whether `attr_name` on an element named `element_name` should
/// be redacted under the configured `level`. Centralised so the
/// per-element / per-attribute decision table is documented in one
/// place rather than scattered across the dispatcher arms.
fn attr_should_be_redacted_on_element(
    element_name: &[u8],
    attr_name: &[u8],
    level: MaskDetailLevel,
) -> bool {
    // Strict's custom-attribute scan applies on every element.
    if level.redacts_takv_and_custom() && attr_name_is_position_like(attr_name) {
        return true;
    }
    // Medium / Strict: spec-element attributes get specific names redacted.
    if level.redacts_callsign_and_group() {
        if is_contact_tag(element_name) && attr_name.eq_ignore_ascii_case(b"callsign") {
            return true;
        }
        if is_group_affiliation_tag(element_name)
            && (attr_name.eq_ignore_ascii_case(b"name") || attr_name.eq_ignore_ascii_case(b"role"))
        {
            return true;
        }
    }
    // Strict-only: takv platform/version, status battery.
    if level.redacts_takv_and_custom() {
        if is_takv_tag(element_name)
            && (attr_name.eq_ignore_ascii_case(b"platform")
                || attr_name.eq_ignore_ascii_case(b"version"))
        {
            return true;
        }
        if is_status_tag(element_name) && attr_name.eq_ignore_ascii_case(b"battery") {
            return true;
        }
    }
    false
}

/// Return `true` if `e` has at least one attribute whose name matches
/// [`attr_name_is_position_like`]. Used by the Strict pass to decide
/// whether to allocate a re-emitted element or pass the original
/// through byte-for-byte.
///
/// The cap [`MAX_DETAIL_ATTRIBUTES`] is intentionally NOT applied here
/// — the scan only inspects names and stops at the first hit, so the
/// hot path stays cheap. The cap is enforced at re-emission time in
/// [`mask_detail_attrs`] when the element is rewritten, which is the
/// only place where the per-attribute allocation cost matters.
fn any_attr_name_is_position_like(e: &BytesStart<'_>) -> Result<bool, MaskError> {
    for attr in e.attributes() {
        let attr = attr?;
        if attr_name_is_position_like(attr.key.as_ref()) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Fail-closed if any attribute value on `e` contains a raw `"` byte.
///
/// quick_xml's `BytesStart::push_attribute` (and the
/// `writer.write_event` pass-through path used for non-target
/// elements) always wrap attribute values in `"` quotes and do NOT
/// escape inner `"` characters. An input attribute whose value
/// genuinely contains a `"` character — possible whenever the input
/// uses single-quote attribute delimiters — therefore round-trips
/// through the masker as bytes the next-pass parser splits into
/// extra attributes. That breaks the masker's documented idempotence
/// invariant *and* is exactly the fail-closed case the function's
/// outer doc-comment commits to: when in doubt, drop the payload
/// rather than forward bytes that downstream consumers may parse
/// inconsistently with our own.
///
/// Returns [`MaskError::UnsafeAttrValue`] so callers and audit logs
/// can distinguish this fail-closed case from "the input was not
/// well-formed XML" ([`MaskError::Xml`]) — the input WAS well-formed
/// XML; we just can't safely re-emit it.
fn check_attrs_round_trip_safe(e: &BytesStart<'_>) -> Result<(), MaskError> {
    for attr in e.attributes() {
        let attr = attr?;
        if attr.value.as_ref().contains(&b'"') {
            return Err(MaskError::UnsafeAttrValue);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use super::*;

    const SAMPLE_COT: &str = r#"<?xml version="1.0"?><event uid="u1" type="a-f-G-U-C" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z"><point lat="38.8977" lon="-77.0365" hae="125.4"/><detail><__group name="Cyan"/></detail></event>"#;

    /// Regression for the `cot_mask_strip_coordinates` weekly extended
    /// fuzz finding: an attribute value containing a raw `"` byte —
    /// permissible in well-formed XML when the attribute uses single-
    /// quote delimiters — round-tripped through the masker as bytes the
    /// next-pass parser split into extra attributes, breaking the
    /// documented idempotence invariant.
    ///
    /// The input below is the libfuzzer-minimised 16-byte reproducer:
    /// `<point\rt='"e="'>` — a `<point>` start tag with `\r` whitespace
    /// before the `t='"e="'` attribute. Pre-fix, the masker emitted
    /// `<point t=""e=""/>` on pass 1 and `<point t="" e=""/>` on pass 2
    /// (parser saw the unescaped `"` as an attribute boundary). Post-
    /// fix, the masker fails closed on pass 1 with
    /// [`MaskError::UnsafeAttrValue`].
    #[test]
    fn fuzz_regression_strip_coordinates_unsafe_attr_value_quotes() {
        // Bytes from the cargo-fuzz minimised artifact.
        let input: &[u8] = &[
            0x3c, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x0d, 0x74, 0x3d, 0x27, 0x22, 0x65, 0x3d, 0x22,
            0x27, 0x3e,
        ];
        match strip_coordinates(input) {
            Err(MaskError::UnsafeAttrValue) => {}
            Ok(out) => panic!(
                "expected fail-closed UnsafeAttrValue, got Ok({} bytes): {:?}",
                out.len(),
                std::str::from_utf8(&out)
            ),
            Err(other) => panic!("expected UnsafeAttrValue, got {other:?}"),
        }
    }

    /// Companion to the regression above: the legitimate single-quote
    /// attribute case (no `"` inside the value) must continue to
    /// round-trip cleanly. Pre-fix this also worked; the test exists to
    /// pin the boundary so a future "drop the round-trip check"
    /// regression does not silently widen the fail-closed surface.
    #[test]
    fn single_quoted_attr_without_inner_double_quote_is_accepted() {
        let input = br#"<event uid='u1'><point lat='1.0' lon='2.0' hae='3.0'/></event>"#;
        let masked = strip_coordinates(input).expect("legitimate single-quoted XML must mask");
        // The masker only re-emits target elements (`<point>` here);
        // non-target elements (`<event>`) pass through byte-for-byte
        // and keep their original quote style. The post-fix invariant
        // we care about is: the canonical `<point>` coordinates were
        // zeroed AND the masked output is idempotent.
        assert!(
            masked
                .windows(b"lat=\"0.0\"".len())
                .any(|w| w == b"lat=\"0.0\""),
            "lat zeroed: {:?}",
            std::str::from_utf8(&masked)
        );
        let twice = strip_coordinates(&masked).expect("second pass must succeed");
        assert_eq!(masked, twice, "idempotence");
    }

    /// Properly-escaped `"` inside an attribute value (`&quot;`) must
    /// continue to be accepted — quick_xml exposes the escaped form
    /// verbatim from `attr.value`, so the raw-byte check sees `&quot;`
    /// (no literal `"`) and lets the value through.
    #[test]
    fn escaped_double_quote_in_attr_value_is_accepted() {
        let input =
            br#"<event uid="say &quot;hi&quot;"><point lat="1.0" lon="2.0" hae="3.0"/></event>"#;
        let masked =
            strip_coordinates(input).expect("escaped quote in attr value must mask cleanly");
        // Idempotence still holds.
        let twice = strip_coordinates(&masked).expect("second pass must succeed");
        assert_eq!(masked, twice);
    }

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
            Err(MaskError::Xml(_)) | Err(MaskError::UnsafeAttrValue) => {
                // Expected post-fix path: either the defensive output
                // validation rejected the unwriteable bytes
                // (`MaskError::Xml`) OR the input pre-check fired on a
                // raw `"` byte inside an attribute value
                // (`MaskError::UnsafeAttrValue`, added when the
                // weekly fuzz turned up `<point\rt='"e="'/>` —
                // a separate but related round-trip violation).
            }
            Err(other) => panic!(
                "expected `Ok(_)` or `MaskError::Xml(_)` or `MaskError::UnsafeAttrValue`, got {other:?}"
            ),
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

    // ── MaskDetailLevel coverage (refs #882) ─────────────────────────

    /// Sample CoT carrying a callsign, group affiliation, takv platform,
    /// status battery, and a custom `<x my_lat="…">` attribute. Used
    /// by the level-aware tests below so each tier is exercised
    /// against the same input.
    const RICH_COT: &str = r#"<event uid="u1" type="a-f-G-U-C" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z"><point lat="38.8977" lon="-77.0365" hae="125.4"/><detail><contact callsign="ALPHA-1"/><__group name="Cyan" role="Team Lead"/><takv version="4.10.1" platform="ATAK-CIV"/><status battery="73"/><x my_lat="37.7" my_lon="-122.4"/></detail></event>"#;

    #[test]
    fn coarse_masks_point_only() {
        // Happy-path regression of the legacy behaviour: at the
        // default MaskDetailLevel::Coarse only `<point>` is touched.
        // Every secondary field listed in #882 must remain intact.
        let out =
            strip_coordinates_with_level(RICH_COT.as_bytes(), MaskDetailLevel::Coarse).unwrap();
        let s = std::str::from_utf8(&out).unwrap();
        // Point coordinates zeroed.
        assert!(s.contains(r#"lat="0.0""#), "lat not zeroed: {s}");
        assert!(s.contains(r#"lon="0.0""#), "lon not zeroed: {s}");
        assert!(s.contains(r#"hae="0.0""#), "hae not zeroed: {s}");
        assert!(!s.contains("38.8977"), "raw lat leaked: {s}");
        // Secondary fields untouched at Coarse — the legacy behaviour.
        assert!(
            s.contains(r#"callsign="ALPHA-1""#),
            "Coarse must not redact callsign: {s}"
        );
        assert!(
            s.contains(r#"name="Cyan""#),
            "Coarse must not redact group name: {s}"
        );
        assert!(
            s.contains(r#"role="Team Lead""#),
            "Coarse must not redact group role: {s}"
        );
        assert!(
            s.contains(r#"platform="ATAK-CIV""#),
            "Coarse must not redact takv platform: {s}"
        );
        assert!(
            s.contains(r#"battery="73""#),
            "Coarse must not redact status battery: {s}"
        );
        assert!(
            s.contains(r#"my_lat="37.7""#),
            "Coarse must not redact custom lat-named attribute: {s}"
        );
    }

    #[test]
    fn coarse_does_not_mask_callsign() {
        // Regression-pin the negative half of the contract: a payload
        // carrying only a callsign (no point, no other detail) must
        // pass through under Coarse byte-for-byte. A future tier-leak
        // bug where Coarse silently picked up Medium's callsign scrub
        // would fail this test.
        let xml = r#"<event uid="u1" type="a-f-G-U-C" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z"><detail><contact callsign="ALPHA-1"/></detail></event>"#;
        let out = strip_coordinates_with_level(xml.as_bytes(), MaskDetailLevel::Coarse).unwrap();
        let s = std::str::from_utf8(&out).unwrap();
        assert!(
            s.contains(r#"callsign="ALPHA-1""#),
            "Coarse must leave callsign alone: {s}"
        );
    }

    #[test]
    fn medium_also_masks_callsign() {
        // Refs #882 sub-item: callsign reveals identity which is
        // identity-linked to position. Medium must redact the
        // callsign attribute on every <contact> element.
        let xml = r#"<event uid="u1" type="a-f-G-U-C" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z"><point lat="38.8977" lon="-77.0365" hae="125.4"/><detail><contact callsign="ALPHA-1"/></detail></event>"#;
        let out = strip_coordinates_with_level(xml.as_bytes(), MaskDetailLevel::Medium).unwrap();
        let s = std::str::from_utf8(&out).unwrap();
        assert!(s.contains(r#"lat="0.0""#), "point still masked: {s}");
        assert!(
            !s.contains("ALPHA-1"),
            "Medium must redact callsign value: {s}"
        );
        assert!(
            s.contains(r#"callsign="[REDACTED]""#),
            "expected callsign=[REDACTED] under Medium: {s}"
        );
    }

    #[test]
    fn medium_also_masks_group_affiliation() {
        // Refs #882 sub-item: <__group> carries unit affiliation
        // (colour-coded teams in TAK), which reveals tactical
        // structure even without raw coordinates.
        let xml = r#"<event uid="u1" type="a-f-G-U-C" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z"><point lat="38.8977" lon="-77.0365" hae="125.4"/><detail><__group name="Cyan" role="Team Lead"/></detail></event>"#;
        let out = strip_coordinates_with_level(xml.as_bytes(), MaskDetailLevel::Medium).unwrap();
        let s = std::str::from_utf8(&out).unwrap();
        assert!(!s.contains("Cyan"), "Medium must redact group name: {s}");
        assert!(
            !s.contains("Team Lead"),
            "Medium must redact group role: {s}"
        );
        assert!(
            s.contains(r#"name="[REDACTED]""#),
            "expected name=[REDACTED] under Medium: {s}"
        );
        assert!(
            s.contains(r#"role="[REDACTED]""#),
            "expected role=[REDACTED] under Medium: {s}"
        );
    }

    #[test]
    fn medium_does_not_mask_takv_or_battery() {
        // Medium is a strict subset of Strict — it must NOT scrub
        // the Strict-only fields, so a deployment that picked
        // Medium gets exactly what the docstring promised.
        let xml = r#"<event uid="u1" type="a-f-G-U-C" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z"><detail><takv version="4.10.1" platform="ATAK-CIV"/><status battery="73"/></detail></event>"#;
        let out = strip_coordinates_with_level(xml.as_bytes(), MaskDetailLevel::Medium).unwrap();
        let s = std::str::from_utf8(&out).unwrap();
        assert!(
            s.contains(r#"platform="ATAK-CIV""#),
            "Medium must not redact takv platform: {s}"
        );
        assert!(
            s.contains(r#"battery="73""#),
            "Medium must not redact battery: {s}"
        );
    }

    #[test]
    fn strict_masks_takv_platform() {
        // Refs #882 sub-item: <takv platform> identifies the operator's
        // TAK device family (ATAK-CIV, WinTAK, iTAK), which can be
        // operationally signalling in a fleet using platform-specific
        // roles.
        let xml = r#"<event uid="u1" type="a-f-G-U-C" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z"><detail><takv version="4.10.1" platform="ATAK-CIV"/></detail></event>"#;
        let out = strip_coordinates_with_level(xml.as_bytes(), MaskDetailLevel::Strict).unwrap();
        let s = std::str::from_utf8(&out).unwrap();
        assert!(
            !s.contains("ATAK-CIV"),
            "Strict must redact takv platform: {s}"
        );
        assert!(
            !s.contains("4.10.1"),
            "Strict must redact takv version: {s}"
        );
        assert!(
            s.contains(r#"platform="[REDACTED]""#),
            "expected platform=[REDACTED] under Strict: {s}"
        );
    }

    #[test]
    fn strict_masks_status_battery() {
        // Battery level can correlate with patrol duration —
        // operationally signalling under a sufficiently aggressive
        // threat model.
        let xml = r#"<event uid="u1" type="a-f-G-U-C" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z"><detail><status battery="73"/></detail></event>"#;
        let out = strip_coordinates_with_level(xml.as_bytes(), MaskDetailLevel::Strict).unwrap();
        let s = std::str::from_utf8(&out).unwrap();
        assert!(!s.contains("73"), "Strict must redact battery: {s}");
        assert!(
            s.contains(r#"battery="[REDACTED]""#),
            "expected battery=[REDACTED] under Strict: {s}"
        );
    }

    #[test]
    fn strict_masks_custom_lat_attr() {
        // Refs #882: a vendor extension stamping a custom `<x my_lat>`
        // / `<x my_lon>` attribute would otherwise leak position the
        // masker did not know to look for. Strict's substring scan on
        // `lat`/`lon`/`alt`/`pos`/`loc` covers vendor-defined names.
        let xml = r#"<event uid="u1" type="a-f-G-U-C" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z"><detail><x my_lat="37.7" my_lon="-122.4" my_alt="42" pos_x="100" geo_loc="san_fran"/></detail></event>"#;
        let out = strip_coordinates_with_level(xml.as_bytes(), MaskDetailLevel::Strict).unwrap();
        let s = std::str::from_utf8(&out).unwrap();
        assert!(!s.contains("37.7"), "Strict must redact my_lat: {s}");
        assert!(!s.contains("-122.4"), "Strict must redact my_lon: {s}");
        assert!(
            !s.contains(r#"my_alt="42""#),
            "Strict must redact my_alt: {s}"
        );
        assert!(
            !s.contains(r#"pos_x="100""#),
            "Strict must redact pos_x: {s}"
        );
        assert!(
            !s.contains("san_fran"),
            "Strict must redact geo_loc value: {s}"
        );
        // Each redacted attribute keeps its NAME so a downstream
        // consumer can see the field existed.
        assert!(
            s.contains(r#"my_lat="[REDACTED]""#),
            "my_lat name preserved: {s}"
        );
        assert!(
            s.contains(r#"my_lon="[REDACTED]""#),
            "my_lon name preserved: {s}"
        );
    }

    #[test]
    fn strict_masks_uppercase_custom_lat_attr() {
        // Substring match must be ASCII-case-insensitive — uppercased
        // and mixed-case vendor attributes must also be redacted.
        let xml = r#"<event uid="u1" type="a-f-G-U-C" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z"><detail><x LATITUDE="38.0" Longitude="-77.0"/></detail></event>"#;
        let out = strip_coordinates_with_level(xml.as_bytes(), MaskDetailLevel::Strict).unwrap();
        let s = std::str::from_utf8(&out).unwrap();
        assert!(!s.contains("38.0"), "Strict must redact LATITUDE: {s}");
        assert!(!s.contains("-77.0"), "Strict must redact Longitude: {s}");
    }

    #[test]
    fn strict_does_not_redact_unrelated_attributes() {
        // The substring scan must match position tokens only — `loc`
        // (and `pos`, `alt`, etc.) is permissive enough that a
        // legitimate non-position field could collide. Pin the cases
        // that DO match (so the contract is documented) and the cases
        // that do NOT.
        let xml = r#"<event uid="u1" type="a-f-G-U-C" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z"><detail><x team="Alpha" status_ok="true" foo="bar"/></detail></event>"#;
        let out = strip_coordinates_with_level(xml.as_bytes(), MaskDetailLevel::Strict).unwrap();
        let s = std::str::from_utf8(&out).unwrap();
        assert!(
            s.contains(r#"team="Alpha""#),
            "Strict must not redact unrelated `team`: {s}"
        );
        assert!(
            s.contains(r#"foo="bar""#),
            "Strict must not redact unrelated `foo`: {s}"
        );
    }

    #[test]
    fn strict_includes_every_medium_redaction() {
        // Strict is a documented superset of Medium. A payload that
        // exercises every Medium field at Strict-level must produce
        // the same redactions as Medium for those fields, plus the
        // Strict-only ones.
        let xml = r#"<event uid="u1" type="a-f-G-U-C" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z"><detail><contact callsign="ALPHA-1"/><__group name="Cyan"/></detail></event>"#;
        let out = strip_coordinates_with_level(xml.as_bytes(), MaskDetailLevel::Strict).unwrap();
        let s = std::str::from_utf8(&out).unwrap();
        assert!(
            !s.contains("ALPHA-1"),
            "Strict must redact callsign (inherited from Medium): {s}"
        );
        assert!(
            !s.contains("Cyan"),
            "Strict must redact group name (inherited from Medium): {s}"
        );
    }

    #[test]
    fn byte_stable_for_inputs_with_no_secondary_fields() {
        // A payload with only a `<point>` and no secondary fields
        // should produce IDENTICAL bytes under Coarse/Medium/Strict
        // — no level-specific scrub fires, so the new Medium/Strict
        // code paths must not regress the byte-stable invariant.
        let xml = r#"<event uid="u1" type="a-f-G-U-C" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z"><point lat="38.8977" lon="-77.0365" hae="125.4"/></event>"#;
        let coarse = strip_coordinates_with_level(xml.as_bytes(), MaskDetailLevel::Coarse).unwrap();
        let medium = strip_coordinates_with_level(xml.as_bytes(), MaskDetailLevel::Medium).unwrap();
        let strict = strip_coordinates_with_level(xml.as_bytes(), MaskDetailLevel::Strict).unwrap();
        assert_eq!(
            coarse, medium,
            "Medium must byte-match Coarse on no-detail input"
        );
        assert_eq!(
            coarse, strict,
            "Strict must byte-match Coarse on no-detail input"
        );
    }

    #[test]
    fn strip_coordinates_default_is_coarse() {
        // The legacy entrypoint must dispatch to Coarse for backward
        // compatibility. A regression that flipped the default to
        // Medium would silently change the wire shape on every
        // existing caller.
        let coarse =
            strip_coordinates_with_level(RICH_COT.as_bytes(), MaskDetailLevel::Coarse).unwrap();
        let legacy = strip_coordinates(RICH_COT.as_bytes()).unwrap();
        assert_eq!(
            legacy, coarse,
            "strip_coordinates() must equal strip_coordinates_with_level(_, Coarse)"
        );
    }

    #[test]
    fn mask_detail_level_default_is_coarse() {
        // Pin the documented default — the `Default` derive uses
        // `Coarse`, so a deployment that calls `MaskDetailLevel::default()`
        // gets the legacy behaviour out of the box.
        assert_eq!(MaskDetailLevel::default(), MaskDetailLevel::Coarse);
    }

    #[test]
    fn mask_detail_level_redacts_predicates_match_documented_tier_table() {
        // Pin the per-tier predicate table so a refactor that
        // accidentally swapped two arms (e.g. Medium suddenly
        // returned true for `redacts_takv_and_custom`) is caught
        // here rather than at a much-later integration test that
        // would just see "wrong fields redacted".
        assert!(!MaskDetailLevel::Coarse.redacts_callsign_and_group());
        assert!(!MaskDetailLevel::Coarse.redacts_takv_and_custom());
        assert!(MaskDetailLevel::Medium.redacts_callsign_and_group());
        assert!(!MaskDetailLevel::Medium.redacts_takv_and_custom());
        assert!(MaskDetailLevel::Strict.redacts_callsign_and_group());
        assert!(MaskDetailLevel::Strict.redacts_takv_and_custom());
    }

    #[test]
    fn medium_handles_namespaced_contact_element() {
        // `<contact>` matching is namespace-prefix-tolerant for the
        // same reason `<point>` is — a sender that wraps the element
        // in a namespace prefix must NOT bypass the masker.
        let xml = r#"<event xmlns:cot="urn:cot" uid="u1" type="a-f-G-U-C" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z"><detail><cot:contact callsign="ALPHA-1"/></detail></event>"#;
        let out = strip_coordinates_with_level(xml.as_bytes(), MaskDetailLevel::Medium).unwrap();
        let s = std::str::from_utf8(&out).unwrap();
        assert!(
            !s.contains("ALPHA-1"),
            "namespaced contact must still redact callsign: {s}"
        );
    }

    #[test]
    fn medium_handles_uppercase_contact_element() {
        // Element-name matching is ASCII-case-insensitive — same
        // contract as `<point>`. Pin the case-variant bypass.
        let xml = r#"<event uid="u1" type="a-f-G-U-C" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z"><detail><Contact callsign="ALPHA-1"/></detail></event>"#;
        let out = strip_coordinates_with_level(xml.as_bytes(), MaskDetailLevel::Medium).unwrap();
        let s = std::str::from_utf8(&out).unwrap();
        assert!(
            !s.contains("ALPHA-1"),
            "uppercase Contact must still redact callsign: {s}"
        );
    }

    #[test]
    fn detail_attr_budget_caps_per_element() {
        // A crafted <contact> element packed with > MAX_DETAIL_ATTRIBUTES
        // attributes must trip the same fail-closed cap as <point>.
        // Pre-this-PR a `<contact>` with thousands of attributes would
        // amplify per-recipient masking cost; the cap closes that.
        let mut xml = String::from(
            r#"<event uid="u1" type="a-f-G-U-C" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z"><detail><contact callsign="ALPHA-1""#,
        );
        for i in 0..=MAX_DETAIL_ATTRIBUTES {
            xml.push_str(&format!(r#" x{i}="v""#));
        }
        xml.push_str("/></detail></event>");
        let err =
            strip_coordinates_with_level(xml.as_bytes(), MaskDetailLevel::Medium).unwrap_err();
        assert!(
            matches!(
                err,
                MaskError::AttrBudgetExceeded {
                    limit: MAX_DETAIL_ATTRIBUTES,
                }
            ),
            "expected AttrBudgetExceeded, got: {err:?}"
        );
    }

    #[test]
    fn medium_xml_intent_malformed_payload_is_rejected() {
        // Same fail-closed contract as Coarse: an XML-intent payload
        // that trips the parser must NOT fall back to pass-through,
        // even at a stricter level. A regression that handled the
        // Medium/Strict scrub with a different recovery path could
        // re-introduce a coordinate-leak via partial parse.
        let malformed = br#"<event><point lat="38.8977" lon="-77.0365" hae="125.4"/><contact callsign="ALPHA-1"/><unterminated"#;
        let err = strip_coordinates_with_level(malformed, MaskDetailLevel::Medium).unwrap_err();
        assert!(
            matches!(err, MaskError::Xml(_)),
            "expected Xml, got {err:?}"
        );
    }

    #[test]
    fn strict_self_stable_on_redacted_output() {
        // The defensive output round-trip in strip_coordinates_with_level
        // must also pass under Strict — a buggy `[REDACTED]` re-emit that
        // produced bytes the next pass cannot read would break the
        // documented self-stability contract.
        let first =
            strip_coordinates_with_level(RICH_COT.as_bytes(), MaskDetailLevel::Strict).unwrap();
        // Pass 2 must not error.
        let second = strip_coordinates_with_level(&first, MaskDetailLevel::Strict).unwrap();
        // And idempotence on the strict pass: re-applying Strict to
        // already-Strict-masked output must not drift.
        assert_eq!(first, second, "Strict must be idempotent on its own output");
    }

    #[test]
    fn medium_at_attribute_budget_is_accepted() {
        // Inverse of the over-budget test: exactly MAX_DETAIL_ATTRIBUTES
        // attributes on `<contact>` must succeed. Cap is exclusive at
        // the upper bound.
        let mut xml = String::from(
            r#"<event uid="u1" type="a-f-G-U-C" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z"><detail><contact callsign="ALPHA-1""#,
        );
        // 1 existing attr (callsign), pad up to the cap.
        for i in 0..MAX_DETAIL_ATTRIBUTES - 1 {
            xml.push_str(&format!(r#" x{i}="v""#));
        }
        xml.push_str("/></detail></event>");
        assert!(
            strip_coordinates_with_level(xml.as_bytes(), MaskDetailLevel::Medium).is_ok(),
            "exactly MAX_DETAIL_ATTRIBUTES must succeed under Medium"
        );
    }

    #[test]
    fn point_inside_strict_with_custom_lat_attr_redacts_custom_attr_only() {
        // Strict on `<point my_lat="…">`: the spec coordinates still
        // get the `0.0` numeric mask, but the custom position-named
        // attribute gets bracketed redaction. This is the documented
        // shape — pin it so a refactor that unified the two paths
        // does not silently change the wire format.
        let xml = r#"<event uid="u1" type="a-f-G-U-C" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z"><point lat="38.8977" lon="-77.0365" hae="125.4" my_lat="37.7"/></event>"#;
        let out = strip_coordinates_with_level(xml.as_bytes(), MaskDetailLevel::Strict).unwrap();
        let s = std::str::from_utf8(&out).unwrap();
        assert!(s.contains(r#"lat="0.0""#), "spec lat zeroed: {s}");
        assert!(
            s.contains(r#"my_lat="[REDACTED]""#),
            "custom my_lat redacted: {s}"
        );
        assert!(!s.contains("37.7"), "raw custom lat leaked: {s}");
    }
}
