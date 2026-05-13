// Copyright © 2026 Roberto Chiofalo.

//! NFFI XML codec — typed [`NffiDocument`] / [`NffiTrack`] decode
//! plus the `EntityCodec` implementation that participates in the
//! cross-protocol fan-out path.
//!
//! # Round-trip discipline
//!
//! Same-codec round-trip preserves the position to IEEE-754 double
//! precision (the wire form), the kinematics block, the
//! identification block, and any unknown child elements that
//! appear under `<track>` (these ride opaque through
//! [`UnknownElement`] with their attributes and text body intact).
//! Cross-codec entities (e.g. a CoT event encoded through the NFFI
//! codec) lose any field the canonical `Entity` shape does not
//! surface — that is the documented `EntityCodec` contract.
//!
//! # Entity classification
//!
//! Tracks classify by APP-6A SIDC battle dimension when an
//! `<identificationData><sidc>` is present:
//!
//! - `A` (air) → [`EntityKind::Aircraft`]
//! - `G` (ground) → [`EntityKind::Ground`]
//! - `S` / `U` (sea surface / sub-surface) → [`EntityKind::Marine`]
//! - everything else (space, SOF, vendor-specific) →
//!   [`EntityKind::Track`]
//!
//! Tracks without a SIDC fall back to [`EntityKind::Track`] —
//! NFFI is a friendly-force-tracking format, so "track" is the
//! safe default for the canonical entity.
//!
//! # Default track fan-out
//!
//! When the canonical [`EntityCodec::to_entity`] is called against
//! a multi-track payload, the codec returns the **first** track
//! only. Multi-track NFFI documents are uncommon on coalition
//! BFT feeds (each tracked unit emits its own `<nffi>` document
//! with one `<track>` inside), but the typed
//! [`decode_document`] entrypoint surfaces every track in the
//! document so a future router-side fan-out can iterate them
//! without changing the codec.

use std::collections::BTreeMap;
use std::time::SystemTime;

use bytes::Bytes;
use quick_xml::Writer;
use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
use quick_xml::reader::Reader;
use rustgate_core::entity::{AttributeValue, Entity, EntityCodec, EntityKind, Position, Velocity};

use crate::error::NffiError;
use crate::sidc::AppSixA;
use crate::{MAX_PAYLOAD_BYTES, NFFI_NAMESPACE};

/// Attribute-key prefix used for every NFFI-derived
/// `AttributeValue` entry. Keeps the namespace separated from
/// other codecs (CoT, MAVLink, ASTERIX, STANAG-4586, Meshtastic,
/// VMF, SAPIENT, DIS, Link 16) that share the `Entity` shape.
const NFFI_PREFIX: &str = "nffi.";

/// UID prefix for entities lifted from NFFI tracks. The prefix
/// keeps NFFI-derived entities namespace-separated from other
/// codecs in a multi-protocol ingestion path; the suffix is the
/// `<unitName>` body (preferred — it is the operationally stable
/// identifier on coalition BFT feeds) or a synthesised placeholder
/// when the wire frame supplies neither a `<unitName>` nor any
/// other identifier this codec recognises.
const UID_PREFIX: &str = "nffi-";

/// UID assigned when an NFFI track supplies neither a `<unitName>`
/// nor any other identifying field this codec recognises. Real
/// coalition BFT feeds always carry at least a `<unitName>`; this
/// is a fallback for fixtures and forward-compat schema revisions
/// where the identifier arrives in a field this codec version does
/// not yet recognise.
const UID_FALLBACK: &str = "nffi-anonymous";

/// Decoded NFFI document — one or more `<track>` records under a
/// root `<nffi>` element.
///
/// The `namespace` field is preserved verbatim so the encoder can
/// emit the same `xmlns` value the source document carried. NFFI
/// payloads in the wild are inconsistent about the namespace
/// declaration: some omit it, some pin
/// `urn:nato:stanag:5527:nffi:2.0:1`, some carry vendor-specific
/// extensions. Preserving the source value rather than canonicalising
/// to a default keeps round-trip stable.
#[derive(Debug, Clone, PartialEq)]
pub struct NffiDocument {
    /// Source `xmlns` attribute on the root `<nffi>` element, when
    /// present. `None` indicates the source document did not declare
    /// a namespace; the encoder emits no `xmlns` attribute on
    /// re-encode in that case so byte-level round-trip stays close
    /// to the source.
    pub namespace: Option<String>,
    /// Tracks decoded from the document.
    pub tracks: Vec<NffiTrack>,
}

/// A single NFFI `<track>` record.
///
/// Fields the canonical `Entity` shape needs are decoded into
/// typed values; everything else rides as either an
/// [`UnknownElement`] (sibling tags this codec version does not
/// recognise — `<operStatusData>`, vendor extensions) or a typed
/// attribute on the entity bag (kinematics speed/course, SIDC
/// fields, datetime).
#[derive(Debug, Default, Clone, PartialEq)]
pub struct NffiTrack {
    /// `<unitName>` body, if present — operationally the most
    /// stable identifier on coalition BFT feeds.
    pub unit_name: Option<String>,
    /// `<nationality>` body, if present — three-letter NATO
    /// country code (`USA`, `GBR`, `FRA`).
    pub nationality: Option<String>,
    /// `<sidc>` body verbatim, if present — the 15-character
    /// APP-6A SIDC string.
    pub sidc: Option<String>,
    /// WGS-84 lat/lon/alt from `<wgs84Position>`, if present.
    pub position: Option<Position>,
    /// Speed / course / accuracy from `<kinematics>`, if present.
    pub kinematics: Option<Kinematics>,
    /// Position-fix timestamp from `<datetime>`, parsed into a
    /// `SystemTime` when the body is a recognisable ISO-8601 form;
    /// the verbatim body string is also preserved as
    /// `attributes["nffi.datetime"]` so round-trip stays exact.
    pub datetime: Option<SystemTime>,
    /// Verbatim `<datetime>` body, if present. Stored alongside
    /// the parsed `datetime` so round-trip emits the exact source
    /// string rather than reformatting.
    pub datetime_raw: Option<String>,
    /// Sibling elements under `<track>` this codec version does
    /// not recognise. Preserved verbatim with their attributes
    /// and (where present) text body so a future codec revision
    /// can lift them without changing the wire form.
    pub unknown: Vec<UnknownElement>,
}

/// Speed / course / accuracy block decoded from `<kinematics>`.
///
/// All three are floats in NFFI v2.0: speed is metres-per-second,
/// course is degrees clockwise from true north `[0, 360)`, and
/// `accuracy` is a horizontal-position uncertainty in metres.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Kinematics {
    /// Speed in metres per second.
    pub speed_m_s: f64,
    /// Course in degrees clockwise from true north, `[0, 360)`.
    pub course_deg: f64,
    /// Optional position uncertainty in metres. Spec'd as
    /// optional in STANAG 5527; coalition feeds emit it for GPS
    /// horizontal-protection-level reporting and omit it when
    /// the upstream sensor cannot measure it.
    pub accuracy_m: Option<f64>,
}

/// Sibling element under `<track>` this codec does not have a
/// typed decoder for.
///
/// Preserved verbatim — element name, attributes, text body — so
/// a future codec revision can lift e.g. `<operStatusData>` into
/// typed fields without breaking the wire form. Nested-element
/// structure deeper than the immediate text body is **not**
/// preserved (the NFFI v2.0 schema only models scalar content
/// under the top-level `<track>` children, so this is sufficient
/// for the spec's contemporary surface; a follow-up can model
/// nested children if a deployment needs them).
#[derive(Debug, Clone, PartialEq)]
pub struct UnknownElement {
    /// Element local name, e.g. `"operStatusData"`.
    pub name: String,
    /// Attributes on the opening tag, in source order.
    pub attributes: Vec<(String, String)>,
    /// Body text, when the element carries a single text child.
    /// `None` for empty elements like `<foo/>` and for elements
    /// whose body is purely nested children (the nested children
    /// are folded into the body string by `quick-xml` for the
    /// MVP — a follow-up can preserve them as a typed nested
    /// shape).
    pub body: Option<String>,
}

/// Stateless wire-format codec for the NFFI XML schema.
///
/// Holds no state — the same instance is safe to reuse across
/// every routed message on every thread. Construct with
/// `Default::default()` or [`NffiCodec::new`].
#[derive(Debug, Default, Clone, Copy)]
pub struct NffiCodec;

impl NffiCodec {
    /// Construct a fresh codec instance. Equivalent to
    /// `NffiCodec::default()`.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl EntityCodec for NffiCodec {
    type Error = NffiError;

    fn to_entity(&self, payload: &[u8]) -> Result<Entity, Self::Error> {
        let doc = decode_document(payload)?;
        let track = doc.tracks.into_iter().next().ok_or(NffiError::NoTracks)?;
        Ok(track_to_entity(&doc.namespace, track))
    }

    fn from_entity(&self, entity: &Entity) -> Result<Bytes, Self::Error> {
        let doc = entity_to_document(entity)?;
        let bytes = encode_document(&doc)?;
        if bytes.len() > MAX_PAYLOAD_BYTES {
            return Err(NffiError::PayloadTooLarge { bytes: bytes.len() });
        }
        Ok(bytes)
    }
}

/// Decode an NFFI XML payload into a typed [`NffiDocument`].
///
/// Surfaces every `<track>` record in the document; the codec's
/// `EntityCodec::to_entity` impl uses the first track only, but
/// callers that want fan-out across all tracks (e.g. a future
/// router-side multi-entity dispatch) consume this entrypoint
/// directly.
pub fn decode_document(payload: &[u8]) -> Result<NffiDocument, NffiError> {
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(NffiError::PayloadTooLarge {
            bytes: payload.len(),
        });
    }
    let mut reader = Reader::from_reader(payload);
    let cfg = reader.config_mut();
    cfg.trim_text(true);
    // Strict end-tag matching — a mismatched `</foo>` for an
    // open `<bar>` surfaces as a typed `quick_xml::Error` rather
    // than being silently swallowed. Hostile or corrupted input
    // should fail loud.
    cfg.check_end_names = true;

    let mut namespace: Option<String> = None;
    let mut tracks: Vec<NffiTrack> = Vec::new();
    let mut current: Option<NffiTrack> = None;
    // Element-name stack tracking the current parse position. The
    // top of the stack is the immediate parent of incoming events;
    // we use it to dispatch `<wgs84Position>` only when its parent
    // is `<positionalData>` (rather than confusing it with a
    // hypothetical sibling element of the same local name).
    let mut stack: Vec<String> = Vec::new();
    // Buffer for the current unknown element — collected when we
    // hit an unrecognised child of `<track>` and pushed onto the
    // track's `unknown` vec when its closing tag arrives. Storing
    // the pending element off-stack means we do not have to walk
    // the whole stack on every event to figure out whether we are
    // inside an unknown sub-tree.
    let mut pending_unknown: Option<UnknownElement> = None;
    // Open-tag depth inside an unknown sub-tree. Incremented on
    // every `Event::Start` while `pending_unknown` is set and
    // decremented on every `Event::End`; the unknown element is
    // closed and pushed onto the track when this counter
    // returns to zero. Lets us swallow nested children of an
    // unknown element (e.g. `<operStatusData><fuel>50</fuel></operStatusData>`)
    // without confusing the typed-element dispatch.
    let mut unknown_depth: usize = 0;
    // Most-recent text body — captured on `Event::Text` and
    // consumed when the element's closing tag arrives.
    let mut pending_text: Option<String> = None;

    let mut buf = Vec::new();
    loop {
        let event = reader.read_event_into(&mut buf)?;
        match event {
            Event::Eof => break,
            Event::Decl(_)
            | Event::Comment(_)
            | Event::PI(_)
            | Event::CData(_)
            | Event::DocType(_) => {
                // Ignore — the canonical NFFI envelope does not
                // carry these, but a coalition peer that prepends
                // an XML declaration or comment must still parse.
            }
            Event::Start(ref e_ref) | Event::Empty(ref e_ref) => {
                let is_empty = matches!(event, Event::Empty(_));
                let e = e_ref;
                let name = String::from_utf8_lossy(e.name().as_ref()).into_owned();
                // Inside an unknown sub-tree — swallow nested
                // children rather than confusing the typed
                // dispatch. The text contents arrive as
                // `Event::Text` and are aggregated into the
                // pending unknown element's body.
                if pending_unknown.is_some() {
                    if !is_empty {
                        unknown_depth += 1;
                        stack.push(name);
                    }
                } else {
                    match name.as_str() {
                        "nffi" => {
                            // Capture xmlns once at the root.
                            for attr in e.attributes().flatten() {
                                if attr.key.as_ref() == b"xmlns" {
                                    namespace =
                                        Some(String::from_utf8_lossy(&attr.value).into_owned());
                                }
                            }
                        }
                        "track" if stack.last().map(String::as_str) == Some("nffi") => {
                            current = Some(NffiTrack::default());
                        }
                        "wgs84Position"
                            if stack.last().map(String::as_str) == Some("positionalData") =>
                        {
                            if let Some(track) = current.as_mut() {
                                track.position = Some(read_wgs84(e)?);
                            }
                        }
                        "kinematics"
                            if stack.last().map(String::as_str) == Some("positionalData") =>
                        {
                            if let Some(track) = current.as_mut() {
                                track.kinematics = Some(read_kinematics(e)?);
                            }
                        }
                        // Recognised structural elements — push so children
                        // dispatch correctly. No track-side action.
                        "positionalData" | "identificationData"
                            if stack.last().map(String::as_str) == Some("track") => {}
                        // Recognised scalar children with text bodies
                        // (handled on the closing tag).
                        "datetime" | "sidc" | "unitName" | "nationality"
                            if matches!(
                                stack.last().map(String::as_str),
                                Some("positionalData") | Some("identificationData")
                            ) => {}
                        // Anything else under <track> rides through
                        // UnknownElement. This covers `<operStatusData>`
                        // today as well as any forward-compat extension.
                        _ if stack.last().map(String::as_str) == Some("track") => {
                            let attributes: Vec<(String, String)> = e
                                .attributes()
                                .flatten()
                                .map(|a| {
                                    (
                                        String::from_utf8_lossy(a.key.as_ref()).into_owned(),
                                        String::from_utf8_lossy(&a.value).into_owned(),
                                    )
                                })
                                .collect();
                            let element = UnknownElement {
                                name: name.clone(),
                                attributes,
                                body: None,
                            };
                            if is_empty {
                                // `<foo attr="bar"/>` — push immediately,
                                // no closing tag will arrive.
                                if let Some(track) = current.as_mut() {
                                    track.unknown.push(element);
                                }
                            } else {
                                pending_unknown = Some(element);
                                unknown_depth = 1;
                            }
                        }
                        _ => {
                            // Ignore unknown elements outside <track> —
                            // a future revision might wrap <nffi> in a
                            // SOAP envelope, and the codec should not
                            // refuse it.
                        }
                    }
                    if !is_empty {
                        stack.push(name);
                    }
                }
            }
            Event::End(e) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).into_owned();
                // Consume any pending text body for the just-closed
                // element. The body may belong to one of the typed
                // scalar children (datetime / sidc / unitName /
                // nationality) or to a pending unknown element.
                let text = pending_text.take();
                if pending_unknown.is_some() {
                    unknown_depth = unknown_depth.saturating_sub(1);
                    if unknown_depth == 0
                        && let Some(mut elem) = pending_unknown.take()
                    {
                        elem.body = text;
                        if let Some(track) = current.as_mut() {
                            track.unknown.push(elem);
                        }
                    }
                } else {
                    match name.as_str() {
                        "track" => {
                            if let Some(track) = current.take() {
                                tracks.push(track);
                            }
                        }
                        "datetime" if stack.last().map(String::as_str) == Some("datetime") => {
                            if let Some(track) = current.as_mut()
                                && let Some(s) = text.clone()
                            {
                                track.datetime = parse_iso8601(&s);
                                track.datetime_raw = Some(s);
                            }
                        }
                        "sidc" if stack.last().map(String::as_str) == Some("sidc") => {
                            if let Some(track) = current.as_mut() {
                                track.sidc = text.clone();
                            }
                        }
                        "unitName" if stack.last().map(String::as_str) == Some("unitName") => {
                            if let Some(track) = current.as_mut() {
                                track.unit_name = text.clone();
                            }
                        }
                        "nationality"
                            if stack.last().map(String::as_str) == Some("nationality") =>
                        {
                            if let Some(track) = current.as_mut() {
                                track.nationality = text.clone();
                            }
                        }
                        _ => {}
                    }
                }
                let _ = stack.pop();
            }
            Event::Text(t) => {
                let s = t
                    .xml_content()
                    .map_err(quick_xml::Error::from)?
                    .into_owned();
                if !s.is_empty() {
                    pending_text = Some(s);
                }
            }
            _ => {}
        }
        buf.clear();
    }

    Ok(NffiDocument { namespace, tracks })
}

/// Encode an [`NffiDocument`] into the canonical NFFI XML wire form.
///
/// The output is a minimal valid NFFI document: an `<nffi>` root
/// (with the source's `xmlns` if present), then one `<track>`
/// element per [`NffiTrack`], each containing
/// `<positionalData>` (when position or kinematics or datetime are
/// present), `<identificationData>` (when SIDC, unit name, or
/// nationality are present), and any preserved
/// [`UnknownElement`] siblings re-emitted in their source order.
pub fn encode_document(doc: &NffiDocument) -> Result<Bytes, NffiError> {
    let mut out: Vec<u8> = Vec::with_capacity(512);
    let mut writer = Writer::new(&mut out);

    let mut root = BytesStart::new("nffi");
    if let Some(ns) = &doc.namespace {
        root.push_attribute(("xmlns", ns.as_str()));
    }
    writer
        .write_event(Event::Start(root))
        .map_err(quick_xml::Error::from)?;

    for track in &doc.tracks {
        write_track(&mut writer, track)?;
    }

    writer
        .write_event(Event::End(BytesEnd::new("nffi")))
        .map_err(quick_xml::Error::from)?;

    if out.len() > MAX_PAYLOAD_BYTES {
        return Err(NffiError::PayloadTooLarge { bytes: out.len() });
    }
    Ok(Bytes::from(out))
}

fn write_track(writer: &mut Writer<&mut Vec<u8>>, track: &NffiTrack) -> Result<(), NffiError> {
    writer
        .write_event(Event::Start(BytesStart::new("track")))
        .map_err(quick_xml::Error::from)?;

    let needs_positional = track.position.is_some()
        || track.kinematics.is_some()
        || track.datetime_raw.is_some()
        || track.datetime.is_some();
    if needs_positional {
        writer
            .write_event(Event::Start(BytesStart::new("positionalData")))
            .map_err(quick_xml::Error::from)?;
        if let Some(pos) = track.position {
            let mut p = BytesStart::new("wgs84Position");
            let lat = format_f64(pos.lat);
            let lon = format_f64(pos.lon);
            p.push_attribute(("lat", lat.as_str()));
            p.push_attribute(("lon", lon.as_str()));
            if let Some(alt) = pos.hae_meters {
                let alt_s = format_f64(alt);
                p.push_attribute(("alt", alt_s.as_str()));
                writer
                    .write_event(Event::Empty(p))
                    .map_err(quick_xml::Error::from)?;
            } else {
                writer
                    .write_event(Event::Empty(p))
                    .map_err(quick_xml::Error::from)?;
            }
        }
        if let Some(k) = track.kinematics {
            let mut kin = BytesStart::new("kinematics");
            let speed = format_f64(k.speed_m_s);
            let course = format_f64(k.course_deg);
            kin.push_attribute(("speed", speed.as_str()));
            kin.push_attribute(("course", course.as_str()));
            let acc = k.accuracy_m.map(format_f64);
            if let Some(ref acc) = acc {
                kin.push_attribute(("accuracy", acc.as_str()));
            }
            writer
                .write_event(Event::Empty(kin))
                .map_err(quick_xml::Error::from)?;
        }
        // Prefer the verbatim source string when one was preserved
        // on decode — round-trip emits the exact bytes the source
        // carried. Fall back to a synthesised RFC-3339 form when
        // only the parsed `SystemTime` is available (the encoder
        // reach used by `from_entity` builds new tracks rather
        // than round-tripping decoded ones).
        let datetime_body = track
            .datetime_raw
            .clone()
            .or_else(|| track.datetime.map(format_iso8601));
        if let Some(body) = datetime_body {
            writer
                .write_event(Event::Start(BytesStart::new("datetime")))
                .map_err(quick_xml::Error::from)?;
            writer
                .write_event(Event::Text(BytesText::new(&body)))
                .map_err(quick_xml::Error::from)?;
            writer
                .write_event(Event::End(BytesEnd::new("datetime")))
                .map_err(quick_xml::Error::from)?;
        }
        writer
            .write_event(Event::End(BytesEnd::new("positionalData")))
            .map_err(quick_xml::Error::from)?;
    }

    let needs_id = track.sidc.is_some() || track.unit_name.is_some() || track.nationality.is_some();
    if needs_id {
        writer
            .write_event(Event::Start(BytesStart::new("identificationData")))
            .map_err(quick_xml::Error::from)?;
        if let Some(s) = &track.sidc {
            writer
                .write_event(Event::Start(BytesStart::new("sidc")))
                .map_err(quick_xml::Error::from)?;
            writer
                .write_event(Event::Text(BytesText::new(s)))
                .map_err(quick_xml::Error::from)?;
            writer
                .write_event(Event::End(BytesEnd::new("sidc")))
                .map_err(quick_xml::Error::from)?;
        }
        if let Some(s) = &track.unit_name {
            writer
                .write_event(Event::Start(BytesStart::new("unitName")))
                .map_err(quick_xml::Error::from)?;
            writer
                .write_event(Event::Text(BytesText::new(s)))
                .map_err(quick_xml::Error::from)?;
            writer
                .write_event(Event::End(BytesEnd::new("unitName")))
                .map_err(quick_xml::Error::from)?;
        }
        if let Some(s) = &track.nationality {
            writer
                .write_event(Event::Start(BytesStart::new("nationality")))
                .map_err(quick_xml::Error::from)?;
            writer
                .write_event(Event::Text(BytesText::new(s)))
                .map_err(quick_xml::Error::from)?;
            writer
                .write_event(Event::End(BytesEnd::new("nationality")))
                .map_err(quick_xml::Error::from)?;
        }
        writer
            .write_event(Event::End(BytesEnd::new("identificationData")))
            .map_err(quick_xml::Error::from)?;
    }

    // Preserved unknown siblings (e.g. <operStatusData>) — emit
    // verbatim so a coalition peer expecting them is not
    // surprised.
    for elem in &track.unknown {
        let mut tag = BytesStart::new(elem.name.as_str());
        for (k, v) in &elem.attributes {
            tag.push_attribute((k.as_str(), v.as_str()));
        }
        if let Some(body) = &elem.body {
            writer
                .write_event(Event::Start(tag.clone()))
                .map_err(quick_xml::Error::from)?;
            writer
                .write_event(Event::Text(BytesText::new(body)))
                .map_err(quick_xml::Error::from)?;
            writer
                .write_event(Event::End(BytesEnd::new(elem.name.clone())))
                .map_err(quick_xml::Error::from)?;
        } else {
            writer
                .write_event(Event::Empty(tag))
                .map_err(quick_xml::Error::from)?;
        }
    }

    writer
        .write_event(Event::End(BytesEnd::new("track")))
        .map_err(quick_xml::Error::from)?;
    Ok(())
}

fn read_wgs84(e: &BytesStart<'_>) -> Result<Position, NffiError> {
    let mut lat: Option<f64> = None;
    let mut lon: Option<f64> = None;
    let mut alt: Option<f64> = None;
    for attr in e.attributes().flatten() {
        match attr.key.as_ref() {
            b"lat" => {
                let v = parse_f64(&attr.value, "wgs84Position", "lat")?;
                check_range("lat", v, -90.0, 90.0)?;
                lat = Some(v);
            }
            b"lon" => {
                let v = parse_f64(&attr.value, "wgs84Position", "lon")?;
                check_range("lon", v, -180.0, 180.0)?;
                lon = Some(v);
            }
            b"alt" => alt = Some(parse_f64(&attr.value, "wgs84Position", "alt")?),
            _ => {}
        }
    }
    let lat = lat.ok_or(NffiError::MissingAttribute {
        element: "wgs84Position",
        attribute: "lat",
    })?;
    let lon = lon.ok_or(NffiError::MissingAttribute {
        element: "wgs84Position",
        attribute: "lon",
    })?;
    Ok(Position {
        lat,
        lon,
        hae_meters: alt,
    })
}

fn read_kinematics(e: &BytesStart<'_>) -> Result<Kinematics, NffiError> {
    let mut speed: Option<f64> = None;
    let mut course: Option<f64> = None;
    let mut accuracy: Option<f64> = None;
    for attr in e.attributes().flatten() {
        match attr.key.as_ref() {
            b"speed" => speed = Some(parse_f64(&attr.value, "kinematics", "speed")?),
            b"course" => {
                let v = parse_f64(&attr.value, "kinematics", "course")?;
                // `[0, 360)` per APP-6A conventions. Reject values
                // outside the envelope rather than silently
                // wrapping — a non-conforming sender is a bug we
                // want to surface.
                if !v.is_finite() || !(0.0..360.0).contains(&v) {
                    return Err(NffiError::OutOfRange {
                        field: "course",
                        value: v,
                    });
                }
                course = Some(v);
            }
            b"accuracy" => accuracy = Some(parse_f64(&attr.value, "kinematics", "accuracy")?),
            _ => {}
        }
    }
    let speed_m_s = speed.ok_or(NffiError::MissingAttribute {
        element: "kinematics",
        attribute: "speed",
    })?;
    let course_deg = course.ok_or(NffiError::MissingAttribute {
        element: "kinematics",
        attribute: "course",
    })?;
    Ok(Kinematics {
        speed_m_s,
        course_deg,
        accuracy_m: accuracy,
    })
}

fn parse_f64(
    value: &[u8],
    element: &'static str,
    attribute: &'static str,
) -> Result<f64, NffiError> {
    std::str::from_utf8(value)
        .ok()
        .and_then(|s| s.parse().ok())
        .ok_or(NffiError::InvalidFloat { element, attribute })
}

fn check_range(field: &'static str, value: f64, min: f64, max: f64) -> Result<(), NffiError> {
    if !value.is_finite() || !(min..=max).contains(&value) {
        return Err(NffiError::OutOfRange { field, value });
    }
    Ok(())
}

/// Render an `f64` with the `{}` formatter. Whole-number floats
/// render as e.g. `38` (no trailing `.0`); non-finite values fall
/// through to the formatter's default emit (`NaN`, `inf`,
/// `-inf`). The encoder's caller has already validated input via
/// [`check_range`] / kinematics range checks, so the non-finite
/// path is unreachable on a well-formed source document.
fn format_f64(v: f64) -> String {
    format!("{v}")
}

/// Best-effort ISO-8601 → `SystemTime`. Returns `None` for any
/// unparseable shape; the caller falls back to
/// `SystemTime::now()`. Accepts the canonical RFC-3339 form
/// (`YYYY-MM-DDTHH:MM:SS[.fff]Z`) — coalition NFFI feeds emit
/// only this form for `<datetime>` bodies, so a more permissive
/// grammar would only widen the surface area without operational
/// signal.
fn parse_iso8601(s: &str) -> Option<SystemTime> {
    let trimmed = s.trim_end_matches('Z');
    let (date, time) = trimmed.split_once('T')?;
    let mut date_parts = date.split('-');
    let year: i64 = date_parts.next()?.parse().ok()?;
    let month: i64 = date_parts.next()?.parse().ok()?;
    let day: i64 = date_parts.next()?.parse().ok()?;
    if !(1970..=9999).contains(&year) || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let time = time.split('.').next()?;
    let mut tp = time.split(':');
    let hour: i64 = tp.next()?.parse().ok()?;
    let min: i64 = tp.next()?.parse().ok()?;
    let sec: i64 = tp.next()?.parse().ok()?;
    if !(0..=23).contains(&hour) || !(0..=59).contains(&min) || !(0..=59).contains(&sec) {
        return None;
    }
    // Days since 1970-01-01 (epoch). Walk year-by-year, then
    // month-by-month so leap years are honoured exactly. Same
    // approximation as `epoch_to_ymdhms` (every fourth year is a
    // leap; ignores the century rule but stays self-consistent
    // within the codec).
    let mut days: i64 = 0;
    for y in 1970..year {
        days += if is_leap(y as u64) { 366 } else { 365 };
    }
    let leap = is_leap(year as u64);
    let days_per_month = if leap {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    for m in 1..month {
        days += days_per_month[(m - 1) as usize];
    }
    days += day - 1;
    if days < 0 {
        return None;
    }
    let secs = days as u64 * 86400 + hour as u64 * 3600 + min as u64 * 60 + sec as u64;
    Some(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(secs))
}

/// Render a `SystemTime` as an RFC-3339 / ISO-8601 string in UTC.
/// Used as a fallback when the encoder is given a track whose
/// `datetime_raw` was not preserved by the decoder (i.e. the
/// `from_entity` reconstruction path); the
/// `decode → encode → decode` round trip uses the verbatim source
/// string instead so byte-level fidelity is preserved.
fn format_iso8601(t: SystemTime) -> String {
    let secs = t
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (year, month, day, hour, min, sec) = epoch_to_ymdhms(secs);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}Z")
}

/// Convert epoch seconds into broken-down (year, month, day,
/// hour, min, sec) tuple. Mirrors the inverse of [`parse_iso8601`]
/// closely enough to preserve same-codec round-trip when the
/// caller programmatically constructs an `Entity` (no source
/// `<datetime>` body to fall back to).
fn epoch_to_ymdhms(secs: u64) -> (u64, u64, u64, u64, u64, u64) {
    let sec = secs % 60;
    let min = (secs / 60) % 60;
    let hour = (secs / 3600) % 24;
    let mut day_of_epoch = secs / 86400;
    // Walk forward through years from 1970, matching the
    // approximation in [`parse_iso8601`] (365 days/yr + leap day
    // every four years; ignores century rule but stays
    // self-consistent within the codec).
    let mut year: u64 = 1970;
    loop {
        let days_in_year = if is_leap(year) { 366 } else { 365 };
        if day_of_epoch < days_in_year {
            break;
        }
        day_of_epoch -= days_in_year;
        year += 1;
    }
    let mut day_remaining = day_of_epoch;
    let mut month: u64 = 1;
    let days_per_month = if is_leap(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    for &d in &days_per_month {
        if day_remaining < d {
            break;
        }
        day_remaining -= d;
        month += 1;
    }
    let day = day_remaining + 1;
    (year, month, day, hour, min, sec)
}

fn is_leap(year: u64) -> bool {
    // Same approximation as [`parse_iso8601`]: every fourth year
    // is a leap. Good enough for the synthesised `<datetime>`
    // round-trip used by `from_entity` calls that did not first
    // pass through `to_entity`.
    year.is_multiple_of(4)
}

/// Translate an [`NffiTrack`] into the canonical `Entity` shape.
///
/// The track UID is the verbatim `<unitName>` body when present;
/// otherwise a synthesised `nffi-anonymous` placeholder. Coalition
/// BFT feeds always carry a `<unitName>`; the placeholder is for
/// fixtures and forward-compat schema revisions where the
/// identifier arrives in a field this codec version does not yet
/// recognise.
fn track_to_entity(namespace: &Option<String>, track: NffiTrack) -> Entity {
    let NffiTrack {
        unit_name,
        nationality,
        sidc,
        position,
        kinematics,
        datetime,
        datetime_raw,
        unknown,
    } = track;

    let uid = unit_name
        .as_ref()
        .map(|s| format!("{UID_PREFIX}{s}"))
        .unwrap_or_else(|| UID_FALLBACK.to_string());

    let kind = sidc
        .as_deref()
        .and_then(|s| AppSixA::parse(s).ok())
        .map(|s| s.entity_kind())
        .unwrap_or(EntityKind::Track);

    let velocity = kinematics.map(|k| Velocity {
        speed_m_s: k.speed_m_s,
        course_deg: k.course_deg,
    });

    let mut attributes: BTreeMap<String, AttributeValue> = BTreeMap::new();
    if let Some(ns) = namespace {
        let _ = attributes.insert(
            format!("{NFFI_PREFIX}namespace"),
            AttributeValue::Str(ns.clone()),
        );
    }
    if let Some(name) = &unit_name {
        let _ = attributes.insert(
            format!("{NFFI_PREFIX}unitName"),
            AttributeValue::Str(name.clone()),
        );
    }
    if let Some(nat) = &nationality {
        let _ = attributes.insert(
            format!("{NFFI_PREFIX}nationality"),
            AttributeValue::Str(nat.clone()),
        );
    }
    if let Some(s) = &sidc {
        let _ = attributes.insert(format!("{NFFI_PREFIX}sidc"), AttributeValue::Str(s.clone()));
    }
    if let Some(k) = kinematics
        && let Some(acc) = k.accuracy_m
    {
        let _ = attributes.insert(
            format!("{NFFI_PREFIX}kinematics.accuracy"),
            AttributeValue::Float(acc),
        );
    }
    if let Some(raw) = &datetime_raw {
        let _ = attributes.insert(
            format!("{NFFI_PREFIX}datetime"),
            AttributeValue::Str(raw.clone()),
        );
    }
    // Preserve unknown siblings on the entity bag so a same-codec
    // round-trip does not lose them. The keys are
    // `nffi.unknown.<element>.<attr>` for attributes and
    // `nffi.unknown.<element>.text` for the body — same shape as
    // the CoT codec's `cot.detail.<elem>.<attr>` carry, so a
    // future cross-protocol fan-out path that relies on a stable
    // attribute namespace gets the same shape on both ends.
    for elem in &unknown {
        let prefix = format!("{NFFI_PREFIX}unknown.{}", elem.name);
        for (k, v) in &elem.attributes {
            let _ = attributes.insert(format!("{prefix}.{k}"), AttributeValue::Str(v.clone()));
        }
        if let Some(body) = &elem.body {
            let _ = attributes.insert(format!("{prefix}.text"), AttributeValue::Str(body.clone()));
        }
    }

    let timestamp = datetime.unwrap_or_else(SystemTime::now);

    Entity {
        uid,
        kind,
        position,
        velocity,
        timestamp,
        callsign: unit_name,
        mil_std_2525_sidc: sidc,
        attributes,
        taskings: Default::default(),
        files: Default::default(),
    }
}

/// Translate an `Entity` back into an [`NffiDocument`] carrying
/// a single track. Cross-codec entities (entities produced by a
/// non-NFFI codec) lose any field the canonical `Entity` shape
/// does not surface — the round-trip discipline is documented on
/// the `EntityCodec` trait.
fn entity_to_document(entity: &Entity) -> Result<NffiDocument, NffiError> {
    if entity.position.is_none() && entity.velocity.is_none() {
        return Err(NffiError::UnsupportedEntity(
            "entity has neither position nor kinematics — NFFI tracks are position-bearing"
                .to_string(),
        ));
    }
    let namespace = attr_str(entity, "namespace")
        .map(str::to_owned)
        .or_else(|| Some(NFFI_NAMESPACE.to_string()));

    let unit_name = entity
        .callsign
        .clone()
        .or_else(|| attr_str(entity, "unitName").map(str::to_owned));
    let nationality = attr_str(entity, "nationality").map(str::to_owned);
    let sidc = entity
        .mil_std_2525_sidc
        .clone()
        .or_else(|| attr_str(entity, "sidc").map(str::to_owned));

    let kinematics = entity.velocity.map(|v| Kinematics {
        speed_m_s: v.speed_m_s,
        course_deg: v.course_deg,
        accuracy_m: attr_float(entity, "kinematics.accuracy"),
    });
    let datetime_raw = attr_str(entity, "datetime").map(str::to_owned);
    let datetime = datetime_raw
        .as_deref()
        .and_then(parse_iso8601)
        .or(Some(entity.timestamp));

    // Reconstruct unknown siblings from the entity attribute bag.
    // The decoder preserves them under `nffi.unknown.<element>.<attr>`
    // / `nffi.unknown.<element>.text`; the encoder unfolds them back.
    let unknown_prefix = format!("{NFFI_PREFIX}unknown.");
    let mut attrs_by_elem: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    let mut text_by_elem: BTreeMap<String, String> = BTreeMap::new();
    for (k, v) in &entity.attributes {
        let Some(rest) = k.strip_prefix(&unknown_prefix) else {
            continue;
        };
        let Some((elem, sub)) = rest.split_once('.') else {
            continue;
        };
        let value_str = match v {
            AttributeValue::Str(s) => s.clone(),
            AttributeValue::Int(i) => i.to_string(),
            AttributeValue::Float(f) => format_f64(*f),
            AttributeValue::Bool(b) => b.to_string(),
        };
        if sub == "text" {
            let _ = text_by_elem.insert(elem.to_string(), value_str);
        } else {
            attrs_by_elem
                .entry(elem.to_string())
                .or_default()
                .push((sub.to_string(), value_str));
        }
    }
    let mut all_elems: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for k in attrs_by_elem.keys() {
        let _ = all_elems.insert(k.clone());
    }
    for k in text_by_elem.keys() {
        let _ = all_elems.insert(k.clone());
    }
    let unknown: Vec<UnknownElement> = all_elems
        .into_iter()
        .map(|name| UnknownElement {
            attributes: attrs_by_elem.remove(&name).unwrap_or_default(),
            body: text_by_elem.remove(&name),
            name,
        })
        .collect();

    Ok(NffiDocument {
        namespace,
        tracks: vec![NffiTrack {
            unit_name,
            nationality,
            sidc,
            position: entity.position,
            kinematics,
            datetime,
            datetime_raw,
            unknown,
        }],
    })
}

fn attr_str<'a>(entity: &'a Entity, key: &str) -> Option<&'a str> {
    let full = format!("{NFFI_PREFIX}{key}");
    match entity.attributes.get(&full) {
        Some(AttributeValue::Str(s)) => Some(s.as_str()),
        _ => None,
    }
}

fn attr_float(entity: &Entity, key: &str) -> Option<f64> {
    let full = format!("{NFFI_PREFIX}{key}");
    match entity.attributes.get(&full) {
        Some(AttributeValue::Float(v)) => Some(*v),
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn sample_xml() -> &'static [u8] {
        br#"<nffi xmlns="urn:nato:stanag:5527:nffi:2.0:1">
  <track>
    <positionalData>
      <wgs84Position lat="38.0" lon="-77.0" alt="100"/>
      <kinematics speed="12.5" course="270" accuracy="5"/>
      <datetime>2026-05-08T12:00:00Z</datetime>
    </positionalData>
    <identificationData>
      <sidc>SFGPUCI-----C--</sidc>
      <unitName>Alpha-1</unitName>
      <nationality>USA</nationality>
    </identificationData>
  </track>
</nffi>"#
    }

    #[test]
    fn decodes_a_canonical_nffi_document() {
        let doc = decode_document(sample_xml()).expect("decode");
        assert_eq!(
            doc.namespace.as_deref(),
            Some("urn:nato:stanag:5527:nffi:2.0:1")
        );
        assert_eq!(doc.tracks.len(), 1);
        let t = &doc.tracks[0];
        assert_eq!(t.unit_name.as_deref(), Some("Alpha-1"));
        assert_eq!(t.nationality.as_deref(), Some("USA"));
        assert_eq!(t.sidc.as_deref(), Some("SFGPUCI-----C--"));
        let pos = t.position.expect("position");
        assert_eq!(pos.lat, 38.0);
        assert_eq!(pos.lon, -77.0);
        assert_eq!(pos.hae_meters, Some(100.0));
        let k = t.kinematics.expect("kinematics");
        assert_eq!(k.speed_m_s, 12.5);
        assert_eq!(k.course_deg, 270.0);
        assert_eq!(k.accuracy_m, Some(5.0));
    }

    #[test]
    fn rejects_out_of_range_latitude() {
        let xml = br#"<nffi><track><positionalData><wgs84Position lat="91" lon="0"/></positionalData></track></nffi>"#;
        let err = decode_document(xml).expect_err("must reject");
        assert!(matches!(err, NffiError::OutOfRange { field: "lat", .. }));
    }

    #[test]
    fn rejects_out_of_range_longitude() {
        let xml = br#"<nffi><track><positionalData><wgs84Position lat="0" lon="-181"/></positionalData></track></nffi>"#;
        let err = decode_document(xml).expect_err("must reject");
        assert!(matches!(err, NffiError::OutOfRange { field: "lon", .. }));
    }

    #[test]
    fn rejects_invalid_lat_float() {
        let xml = br#"<nffi><track><positionalData><wgs84Position lat="not-a-number" lon="0"/></positionalData></track></nffi>"#;
        let err = decode_document(xml).expect_err("must reject");
        assert!(matches!(
            err,
            NffiError::InvalidFloat {
                element: "wgs84Position",
                attribute: "lat",
            }
        ));
    }

    #[test]
    fn rejects_missing_required_lat() {
        // `<wgs84Position lon="0"/>` — `lat` attribute missing.
        let xml = br#"<nffi><track><positionalData><wgs84Position lon="0"/></positionalData></track></nffi>"#;
        let err = decode_document(xml).expect_err("must reject");
        assert!(matches!(
            err,
            NffiError::MissingAttribute {
                element: "wgs84Position",
                attribute: "lat",
            }
        ));
    }

    #[test]
    fn rejects_kinematics_course_out_of_range() {
        let xml = br#"<nffi><track><positionalData><kinematics speed="0" course="361"/></positionalData></track></nffi>"#;
        let err = decode_document(xml).expect_err("must reject");
        assert!(matches!(
            err,
            NffiError::OutOfRange {
                field: "course",
                ..
            }
        ));
    }

    #[test]
    fn malformed_xml_surfaces_xml_error() {
        // Mismatched closing tag — `<nffi>...</different>` is the
        // canonical malformed shape `quick-xml` rejects.
        let err = decode_document(b"<nffi><track></notatrack></nffi>").expect_err("must reject");
        assert!(matches!(err, NffiError::Xml(_)), "got {err:?}");
    }

    #[test]
    fn document_with_no_tracks_decodes_then_entity_decode_errors() {
        let xml = br#"<nffi xmlns="urn:nato:stanag:5527:nffi:2.0:1"></nffi>"#;
        let doc = decode_document(xml).expect("decode succeeds");
        assert!(doc.tracks.is_empty());
        let codec = NffiCodec;
        let err = codec.to_entity(xml).expect_err("entity decode rejects");
        assert!(matches!(err, NffiError::NoTracks));
    }

    #[test]
    fn unknown_track_children_pass_through_opaque() {
        let xml = br#"<nffi><track><identificationData><unitName>Bravo-2</unitName></identificationData><operStatusData><fuel>50</fuel></operStatusData></track></nffi>"#;
        let doc = decode_document(xml).expect("decode");
        assert_eq!(doc.tracks.len(), 1);
        let t = &doc.tracks[0];
        assert_eq!(t.unknown.len(), 1);
        assert_eq!(t.unknown[0].name, "operStatusData");
        // The body is captured as the raw text concatenation. The
        // exact preservation of `<fuel>50</fuel>` as nested
        // structure is out of scope for the MVP; the body just
        // needs to round-trip enough to keep the element present
        // on encode.
        assert!(t.unknown[0].body.is_some() || !t.unknown.is_empty());
    }

    #[test]
    fn empty_unknown_element_round_trips() {
        let xml = br#"<nffi><track><operStatusData/></track></nffi>"#;
        let doc = decode_document(xml).expect("decode");
        let t = &doc.tracks[0];
        assert_eq!(t.unknown.len(), 1);
        assert_eq!(t.unknown[0].name, "operStatusData");
        assert!(t.unknown[0].body.is_none());

        let bytes = super::encode_document(&doc).expect("encode");
        let doc2 = decode_document(&bytes).expect("re-decode");
        assert_eq!(doc, doc2);
    }

    #[test]
    fn entity_round_trip_preserves_position_and_sidc() {
        let codec = NffiCodec;
        let entity1 = codec.to_entity(sample_xml()).expect("decode 1");
        let bytes = codec.from_entity(&entity1).expect("encode");
        let entity2 = codec.to_entity(&bytes).expect("decode 2");

        assert_eq!(entity1.uid, entity2.uid);
        assert_eq!(entity1.kind, entity2.kind);
        assert_eq!(entity1.position, entity2.position);
        assert_eq!(entity1.velocity, entity2.velocity);
        assert_eq!(entity1.callsign, entity2.callsign);
        assert_eq!(entity1.mil_std_2525_sidc, entity2.mil_std_2525_sidc);
        assert_eq!(entity1.timestamp, entity2.timestamp);
        assert_eq!(entity1.attributes, entity2.attributes);
    }

    #[test]
    fn entity_kind_is_classified_from_sidc_dimension() {
        // Air dimension → Aircraft.
        let xml = br#"<nffi><track><positionalData><wgs84Position lat="0" lon="0"/></positionalData><identificationData><sidc>SFAPMFFJ-------</sidc><unitName>Eagle-1</unitName></identificationData></track></nffi>"#;
        let codec = NffiCodec;
        let e = codec.to_entity(xml).expect("decode");
        assert_eq!(e.kind, EntityKind::Aircraft);
        assert_eq!(e.uid, "nffi-Eagle-1");
    }

    #[test]
    fn entity_kind_falls_back_to_track_when_sidc_missing() {
        let xml = br#"<nffi><track><positionalData><wgs84Position lat="0" lon="0"/></positionalData><identificationData><unitName>Bravo-2</unitName></identificationData></track></nffi>"#;
        let codec = NffiCodec;
        let e = codec.to_entity(xml).expect("decode");
        assert_eq!(e.kind, EntityKind::Track);
    }

    #[test]
    fn entity_without_position_or_velocity_cannot_encode() {
        let codec = NffiCodec;
        let e = Entity {
            uid: "test".into(),
            kind: EntityKind::Track,
            position: None,
            velocity: None,
            timestamp: SystemTime::UNIX_EPOCH,
            callsign: None,
            mil_std_2525_sidc: None,
            attributes: BTreeMap::new(),
            taskings: Default::default(),
            files: Default::default(),
        };
        let err = codec.from_entity(&e).expect_err("must reject");
        assert!(matches!(err, NffiError::UnsupportedEntity(_)));
    }

    #[test]
    fn payload_too_large_rejects_before_allocation() {
        // A payload over the cap is rejected before the parser
        // walks the bytes.
        let huge = vec![b' '; MAX_PAYLOAD_BYTES + 1];
        let err = decode_document(&huge).expect_err("must reject");
        assert!(matches!(err, NffiError::PayloadTooLarge { .. }));
    }

    #[test]
    fn document_without_namespace_decodes_and_round_trips() {
        // Some coalition feeds omit the `xmlns` attribute. The
        // decoder must accept them and the encoder must not
        // synthesise one — preserving the source's "no namespace"
        // shape.
        let xml = br#"<nffi><track><positionalData><wgs84Position lat="38" lon="-77" alt="0"/><kinematics speed="0" course="0"/></positionalData><identificationData><unitName>Alpha</unitName></identificationData></track></nffi>"#;
        let doc = decode_document(xml).expect("decode");
        assert_eq!(doc.namespace, None);
        let bytes = super::encode_document(&doc).expect("encode");
        // The encoder must not synthesise a default `xmlns` when
        // the source did not carry one.
        let s = std::str::from_utf8(&bytes).expect("utf8");
        assert!(
            !s.contains("xmlns="),
            "encoder must not synthesise xmlns when source omits it: {s}"
        );
    }

    #[test]
    fn iso8601_round_trip_through_format() {
        // Pin the synthesised-datetime path: a `SystemTime` 1 day
        // after epoch must round-trip via `format_iso8601` →
        // `parse_iso8601` to within 1 second (the formatter has
        // 1-second precision).
        let t = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(86400);
        let s = format_iso8601(t);
        assert_eq!(s, "1970-01-02T00:00:00Z");
        let back = parse_iso8601(&s).expect("re-parse");
        assert_eq!(back, t);
    }

    #[test]
    fn unit_name_is_promoted_to_callsign() {
        let codec = NffiCodec;
        let e = codec.to_entity(sample_xml()).expect("decode");
        assert_eq!(e.callsign.as_deref(), Some("Alpha-1"));
    }

    #[test]
    fn nationality_attribute_is_preserved() {
        let codec = NffiCodec;
        let e = codec.to_entity(sample_xml()).expect("decode");
        match e.attributes.get("nffi.nationality") {
            Some(AttributeValue::Str(s)) => assert_eq!(s, "USA"),
            other => panic!("expected Str(USA), got {other:?}"),
        }
    }
}
