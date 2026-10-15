// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! CoT XML implementation of the canonical [`rustgate_core::entity::EntityCodec`]
//! trait — refs #847.
//!
//! [`CotEntityCodec`] decodes CoT XML payloads into the protocol-agnostic
//! `Entity` shape defined by `rustgate-core` and re-encodes them back to
//! a minimal CoT XML form. This is the first concrete codec wired against
//! the abstraction layer; MAVLink, ASTERIX, STANAG-4586, and Link 16
//! codecs ship in subsequent PRs against the same trait.
//!
//! # Mapping summary
//!
//! | CoT element                                         | `Entity` field                          |
//! |-----------------------------------------------------|-----------------------------------------|
//! | `<event uid="…">`                                   | `Entity.uid`                            |
//! | `<event type="…">`                                  | `Entity.kind` (via 2525 dispatch) +     |
//! |                                                     | `attributes["cot.event_type"]`          |
//! | `<event time>` / `<event start>` / `<event stale>`  | `attributes["cot.time"]` / `cot.start` /|
//! |                                                     | `cot.stale`; `Entity.timestamp` from    |
//! |                                                     | `<event time>` when present             |
//! | `<event how>`                                       | `attributes["cot.how"]`                 |
//! | `<point lat lon hae>`                               | `Entity.position`                       |
//! | `<point ce> / <point le>`                           | `attributes["cot.point.ce"]` /          |
//! |                                                     | `attributes["cot.point.le"]`            |
//! | `<detail><track speed= course=>`                    | `Entity.velocity`                       |
//! | `<detail><contact callsign=…>`                      | `Entity.callsign` +                     |
//! |                                                     | `attributes["cot.contact.<attr>"]`      |
//! | any other `<detail>` child element + attributes     | `attributes["cot.detail.<elem>.<attr>"]`|
//! | `<detail>` text child (e.g. `<remarks>foo</remarks>`)| `attributes["cot.detail.<elem>.text"]` |
//!
//! `Entity::kind` is dispatched from the second segment of the CoT
//! affiliation string when the `type` is an SA atom (`a-X-…`):
//! `a-*-A-*` → [`EntityKind::Aircraft`], `a-*-G-*` → [`EntityKind::Ground`],
//! `a-*-S-*` / `a-*-U-*` → [`EntityKind::Marine`], otherwise
//! [`EntityKind::Track`] for SA atoms and [`EntityKind::Unknown`]
//! carrying the raw `type` for non-atom shapes (`b-*`, `t-*`, …).
//!
//! # Round-trip discipline
//!
//! Same-codec round-trip is preserved: `from_entity(to_entity(xml))`
//! produces a CoT payload that re-decodes to an `Entity` equal to the
//! original. Cross-codec attributes (keys not prefixed with `cot.`) are
//! silently dropped on encode — see the [`rustgate_core::entity`] docs
//! for the rationale.
//!
//! # Out of scope
//!
//! - Full CoT detail-subtree fidelity (nested elements deeper than one
//!   level are folded with a path-prefix scheme, not preserved as a
//!   tree).
//! - The MIL-STD-2525 SIDC carry — `Entity::mil_std_2525_sidc` is
//!   populated when the CoT payload carries `<usericon iconsetpath>` or
//!   `<__milsymbol>` extensions, but synthesising a SIDC from the bare
//!   CoT type string is deferred to the standalone SIDC mapper that
//!   ships alongside the symbol-rendering work.

use std::collections::BTreeMap;
use std::time::SystemTime;

use bytes::Bytes;
use quick_xml::Writer;
use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
use quick_xml::reader::Reader;
use rustgate_core::entity::{AttributeValue, Entity, EntityCodec, EntityKind, Position, Velocity};

use crate::ParseError;

/// Attribute-key prefix used for every CoT-derived
/// [`AttributeValue`] entry. Keeps the namespace separated from
/// other codecs (MAVLink, ASTERIX, …) that will land alongside.
const COT_PREFIX: &str = "cot.";

/// Maximum `<detail>` nesting depth accepted by [`decode_cot`].
///
/// Matches the `MAX_XML_DEPTH = 256` cap enforced by the streaming XML
/// codec in `rustgate-transport` and the certificate XML surfaces in
/// `rustgate-tls`. CoT detail trees are 2-3 levels deep in practice; 256
/// is generous while still rejecting a pathologically nested payload
/// that would otherwise inflate the flattened attribute-key strings.
const MAX_DETAIL_DEPTH: usize = 256;

/// Maximum total size (keys + values) of the flattened `<detail>`
/// attribute bag accepted by [`decode_cot`].
///
/// Matches the `MAX_ATTR_BAG_BYTES = 4 KiB` cap the certificate
/// SAN/attribute extractor enforces. Bounds the per-entity attribute map
/// against a payload built from thousands of tiny detail elements, each
/// individually well under the frame limit.
const MAX_ATTR_BAG_BYTES: usize = 4 * 1024;

/// CoT XML codec for the canonical [`Entity`] shape.
///
/// Stateless — the same instance is safe to reuse across every routed
/// message on every thread. The router holds an `Arc<CotEntityCodec>`
/// per protocol slot.
#[derive(Debug, Default, Clone, Copy)]
pub struct CotEntityCodec;

impl EntityCodec for CotEntityCodec {
    type Error = ParseError;

    fn to_entity(&self, payload: &[u8]) -> Result<Entity, Self::Error> {
        decode_cot(payload)
    }

    fn from_entity(&self, entity: &Entity) -> Result<Bytes, Self::Error> {
        encode_cot(entity)
    }
}

/// Dispatch the [`EntityKind`] from the CoT `type` string.
///
/// Pure function so the test surface can pin every branch without
/// constructing a full payload.
fn classify_kind(event_type: &str) -> EntityKind {
    let bytes = event_type.as_bytes();
    // SA atom: `a-X-Y-…` where Y selects the platform family.
    if bytes.len() >= 5 && bytes[0] == b'a' && bytes[1] == b'-' && bytes[3] == b'-' {
        let family = bytes[4];
        return match family {
            b'A' => EntityKind::Aircraft,
            b'G' => EntityKind::Ground,
            b'S' | b'U' => EntityKind::Marine,
            b'P' | b'M' => EntityKind::Munition,
            _ => EntityKind::Track,
        };
    }
    // Bits/atoms outside the SA family — sensors are `t-*`,
    // alerts/comms are `b-*`. Keep the raw type string on the
    // attributes bag so dashboards can still group on it.
    if bytes.starts_with(b"t-") {
        return EntityKind::Sensor;
    }
    EntityKind::Unknown(event_type.to_string())
}

/// Decode a CoT XML payload into the canonical [`Entity`] shape.
///
/// The implementation walks the XML once with `quick_xml::Reader`,
/// extracting the strict-subset fields directly and folding everything
/// else under `<detail>` into the [`Entity::attributes`] bag using
/// dotted keys (`cot.detail.<elem>.<attr>` for attributes,
/// `cot.detail.<elem>.text` for the text body of a single-text-child
/// element like `<remarks>`). Nested elements deeper than one level
/// inside `<detail>` are flattened with the same dotted path so a
/// future codec version can adopt them as first-class without
/// breaking the wire form.
fn decode_cot(payload: &[u8]) -> Result<Entity, ParseError> {
    let mut reader = Reader::from_reader(payload);
    reader.config_mut().trim_text(true);

    let mut uid: Option<String> = None;
    let mut event_type: Option<String> = None;
    let mut event_time_attr: Option<String> = None;
    let mut callsign: Option<String> = None;
    let mut sidc: Option<String> = None;
    let mut position: Option<Position> = None;
    let mut velocity: Option<Velocity> = None;
    let mut attributes: BTreeMap<String, AttributeValue> = BTreeMap::new();
    // Running size (keys + values) of the flattened `<detail>` bag, capped
    // at `MAX_ATTR_BAG_BYTES`. Only detail-derived inserts feed this — the
    // fixed strict-subset `event`/`point` attributes are a bounded set.
    let mut bag_bytes: usize = 0;

    // Path stack of detail-tree element local names. The root
    // `<detail>` itself is not pushed; only its children. A
    // single entry => direct child of `<detail>`; deeper entries =>
    // nested children flattened via a dotted path.
    let mut detail_path: Vec<String> = Vec::new();
    let mut in_detail = false;
    // Track the most recent text-child push site so a `<remarks>`-like
    // element gets its body hoisted onto attributes after the closing tag.
    let mut pending_text_key: Option<String> = None;
    let mut pending_text_value: Option<String> = None;

    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Eof => break,
            Event::Start(e) => match e.name().as_ref() {
                b"event" => {
                    for attr in e.attributes().flatten() {
                        let key = attr.key.as_ref();
                        let val = String::from_utf8_lossy(&attr.value).into_owned();
                        match key {
                            b"uid" => uid = Some(val),
                            b"type" => {
                                event_type = Some(val.clone());
                                let _ = attributes.insert(
                                    format!("{COT_PREFIX}event_type"),
                                    AttributeValue::Str(val),
                                );
                            }
                            b"time" => {
                                event_time_attr = Some(val.clone());
                                let _ = attributes
                                    .insert(format!("{COT_PREFIX}time"), AttributeValue::Str(val));
                            }
                            b"start" => {
                                let _ = attributes
                                    .insert(format!("{COT_PREFIX}start"), AttributeValue::Str(val));
                            }
                            b"stale" => {
                                let _ = attributes
                                    .insert(format!("{COT_PREFIX}stale"), AttributeValue::Str(val));
                            }
                            b"how" => {
                                let _ = attributes
                                    .insert(format!("{COT_PREFIX}how"), AttributeValue::Str(val));
                            }
                            b"version" => {
                                let _ = attributes.insert(
                                    format!("{COT_PREFIX}version"),
                                    AttributeValue::Str(val),
                                );
                            }
                            _ => {}
                        }
                    }
                }
                b"detail" => in_detail = true,
                name if in_detail => {
                    // Push the local name onto the detail path; consume
                    // attributes; capture velocity/callsign/sidc from
                    // recognized children.
                    let local = String::from_utf8_lossy(name).into_owned();
                    detail_path.push(local.clone());
                    if detail_path.len() > MAX_DETAIL_DEPTH {
                        return Err(ParseError::DetailTooDeep {
                            max: MAX_DETAIL_DEPTH,
                        });
                    }
                    let prefix = detail_attr_prefix(&detail_path);
                    if local == "track" {
                        let (v, attr_kvs) = read_track_attrs(&e)?;
                        if velocity.is_none() {
                            velocity = v;
                        }
                        for (k, val) in attr_kvs {
                            insert_detail_attr(
                                &mut attributes,
                                &mut bag_bytes,
                                format!("{prefix}.{k}"),
                                val,
                            )?;
                        }
                    } else if local == "contact" {
                        for attr in e.attributes().flatten() {
                            let k = String::from_utf8_lossy(attr.key.as_ref()).into_owned();
                            let v = String::from_utf8_lossy(&attr.value).into_owned();
                            if k == "callsign" && callsign.is_none() {
                                callsign = Some(v.clone());
                            }
                            insert_detail_attr(
                                &mut attributes,
                                &mut bag_bytes,
                                format!("{prefix}.{k}"),
                                AttributeValue::Str(v),
                            )?;
                        }
                    } else {
                        for attr in e.attributes().flatten() {
                            let k = String::from_utf8_lossy(attr.key.as_ref()).into_owned();
                            let v = String::from_utf8_lossy(&attr.value).into_owned();
                            if local == "usericon" && k == "iconsetpath" && sidc.is_none() {
                                sidc = Some(v.clone());
                            }
                            insert_detail_attr(
                                &mut attributes,
                                &mut bag_bytes,
                                format!("{prefix}.{k}"),
                                AttributeValue::Str(v),
                            )?;
                        }
                    }
                    pending_text_key = Some(format!("{prefix}.text"));
                    pending_text_value = None;
                }
                _ => {}
            },
            Event::Empty(e) => match e.name().as_ref() {
                b"point" => {
                    let p = read_point_attrs(&e, &mut attributes)?;
                    if position.is_none() {
                        position = p;
                    }
                }
                name if in_detail => {
                    let local = String::from_utf8_lossy(name).into_owned();
                    detail_path.push(local.clone());
                    if detail_path.len() > MAX_DETAIL_DEPTH {
                        return Err(ParseError::DetailTooDeep {
                            max: MAX_DETAIL_DEPTH,
                        });
                    }
                    let prefix = detail_attr_prefix(&detail_path);
                    if local == "track" {
                        let (v, attr_kvs) = read_track_attrs(&e)?;
                        if velocity.is_none() {
                            velocity = v;
                        }
                        for (k, val) in attr_kvs {
                            insert_detail_attr(
                                &mut attributes,
                                &mut bag_bytes,
                                format!("{prefix}.{k}"),
                                val,
                            )?;
                        }
                    } else if local == "contact" {
                        for attr in e.attributes().flatten() {
                            let k = String::from_utf8_lossy(attr.key.as_ref()).into_owned();
                            let v = String::from_utf8_lossy(&attr.value).into_owned();
                            if k == "callsign" && callsign.is_none() {
                                callsign = Some(v.clone());
                            }
                            insert_detail_attr(
                                &mut attributes,
                                &mut bag_bytes,
                                format!("{prefix}.{k}"),
                                AttributeValue::Str(v),
                            )?;
                        }
                    } else {
                        for attr in e.attributes().flatten() {
                            let k = String::from_utf8_lossy(attr.key.as_ref()).into_owned();
                            let v = String::from_utf8_lossy(&attr.value).into_owned();
                            if local == "usericon" && k == "iconsetpath" && sidc.is_none() {
                                sidc = Some(v.clone());
                            }
                            insert_detail_attr(
                                &mut attributes,
                                &mut bag_bytes,
                                format!("{prefix}.{k}"),
                                AttributeValue::Str(v),
                            )?;
                        }
                    }
                    let _ = detail_path.pop();
                }
                _ => {}
            },
            Event::End(e) => match e.name().as_ref() {
                b"detail" => in_detail = false,
                _ if in_detail => {
                    if let (Some(key), Some(val)) =
                        (pending_text_key.take(), pending_text_value.take())
                    {
                        insert_detail_attr(
                            &mut attributes,
                            &mut bag_bytes,
                            key,
                            AttributeValue::Str(val),
                        )?;
                    }
                    let _ = detail_path.pop();
                }
                _ => {}
            },
            Event::Text(t) if in_detail && pending_text_key.is_some() => {
                let s = t
                    .xml10_content()
                    .map_err(quick_xml::Error::from)?
                    .into_owned();
                if !s.is_empty() {
                    pending_text_value = Some(s);
                }
            }
            _ => {}
        }
        buf.clear();
    }

    let uid = uid.ok_or(ParseError::MissingAttribute("uid"))?;
    let event_type = event_type.ok_or(ParseError::MissingAttribute("type"))?;

    let kind = classify_kind(&event_type);
    let timestamp = event_time_attr
        .as_deref()
        .and_then(parse_iso8601_to_systemtime)
        .unwrap_or_else(SystemTime::now);

    Ok(Entity {
        uid,
        kind,
        position,
        velocity,
        timestamp,
        callsign,
        mil_std_2525_sidc: sidc,
        attributes,
        taskings: Default::default(),
        files: Default::default(),
    })
}

/// Approximate byte footprint of an [`AttributeValue`] for the
/// attribute-bag size cap. String values count their UTF-8 length;
/// scalar values count a fixed 8-byte estimate (they are stored as
/// primitives, not strings).
fn attr_value_bytes(value: &AttributeValue) -> usize {
    match value {
        AttributeValue::Str(s) => s.len(),
        _ => 8,
    }
}

/// Insert one flattened `<detail>` attribute, enforcing the
/// [`MAX_ATTR_BAG_BYTES`] running-size cap.
///
/// `bag_bytes` accumulates the key + value footprint of every
/// detail-derived entry so a payload built from many tiny elements is
/// rejected once the flattened bag would exceed the cap, mirroring the
/// certificate attribute-bag limit enforced elsewhere in the workspace.
fn insert_detail_attr(
    attributes: &mut BTreeMap<String, AttributeValue>,
    bag_bytes: &mut usize,
    key: String,
    value: AttributeValue,
) -> Result<(), ParseError> {
    *bag_bytes = bag_bytes.saturating_add(key.len() + attr_value_bytes(&value));
    if *bag_bytes > MAX_ATTR_BAG_BYTES {
        return Err(ParseError::AttrBagTooLarge {
            max: MAX_ATTR_BAG_BYTES,
        });
    }
    let _ = attributes.insert(key, value);
    Ok(())
}

/// Dotted-path prefix for the current depth in the detail tree. The
/// path always starts with `cot.detail.` so flat attributes round-trip
/// with stable names.
fn detail_attr_prefix(path: &[String]) -> String {
    let mut s = String::from("cot.detail");
    for segment in path {
        s.push('.');
        s.push_str(segment);
    }
    s
}

/// Read `lat`, `lon`, `hae`, `ce`, `le` attributes off a `<point>` tag.
///
/// `lat` / `lon` are validated to the WGS-84 envelope using the same
/// helper the existing [`crate::parse`] uses; `hae` / `ce` / `le` are
/// stored on the attributes bag as floats so the round-trip preserves
/// them.
fn read_point_attrs(
    e: &BytesStart<'_>,
    attributes: &mut BTreeMap<String, AttributeValue>,
) -> Result<Option<Position>, ParseError> {
    let mut lat = None;
    let mut lon = None;
    let mut hae = None;
    for attr in e.attributes().flatten() {
        match attr.key.as_ref() {
            b"lat" => {
                let v = parse_f64(&attr.value, "lat")?;
                check_range("lat", v, -90.0, 90.0)?;
                lat = Some(v);
            }
            b"lon" => {
                let v = parse_f64(&attr.value, "lon")?;
                check_range("lon", v, -180.0, 180.0)?;
                lon = Some(v);
            }
            b"hae" => {
                let v = parse_f64(&attr.value, "hae")?;
                hae = Some(v);
                let _ =
                    attributes.insert(format!("{COT_PREFIX}point.hae"), AttributeValue::Float(v));
            }
            b"ce" => {
                let v = parse_f64(&attr.value, "ce")?;
                let _ =
                    attributes.insert(format!("{COT_PREFIX}point.ce"), AttributeValue::Float(v));
            }
            b"le" => {
                let v = parse_f64(&attr.value, "le")?;
                let _ =
                    attributes.insert(format!("{COT_PREFIX}point.le"), AttributeValue::Float(v));
            }
            _ => {}
        }
    }
    match (lat, lon) {
        (Some(lat), Some(lon)) => Ok(Some(Position {
            lat,
            lon,
            hae_meters: hae,
        })),
        _ => Ok(None),
    }
}

/// Per-attribute key/value pair captured off a `<track>` tag — the
/// `String` key is the raw XML attribute name and the [`AttributeValue`]
/// is its decoded value (typed [`AttributeValue::Float`] for the
/// strict-subset `speed` / `course` attributes, [`AttributeValue::Str`]
/// for everything else). Defined as a named alias to keep the
/// [`read_track_attrs`] return type readable.
type TrackAttrPairs = Vec<(String, AttributeValue)>;

/// Read `speed` and `course` attributes off a `<track>` tag and
/// return both the `Velocity` and the per-attribute key/value pairs
/// for the attribute bag. Unknown attributes are passed through as
/// strings.
fn read_track_attrs(e: &BytesStart<'_>) -> Result<(Option<Velocity>, TrackAttrPairs), ParseError> {
    let mut speed: Option<f64> = None;
    let mut course: Option<f64> = None;
    let mut other: Vec<(String, AttributeValue)> = Vec::new();
    for attr in e.attributes().flatten() {
        let key = String::from_utf8_lossy(attr.key.as_ref()).into_owned();
        let raw = String::from_utf8_lossy(&attr.value).into_owned();
        match attr.key.as_ref() {
            b"speed" => {
                let v = parse_f64(&attr.value, "speed")?;
                speed = Some(v);
                other.push((key, AttributeValue::Float(v)));
            }
            b"course" => {
                let v = parse_f64(&attr.value, "course")?;
                course = Some(v);
                other.push((key, AttributeValue::Float(v)));
            }
            _ => other.push((key, AttributeValue::Str(raw))),
        }
    }
    let velocity = match (speed, course) {
        (Some(speed_m_s), Some(course_deg)) => Some(Velocity {
            speed_m_s,
            course_deg,
        }),
        _ => None,
    };
    Ok((velocity, other))
}

fn parse_f64(value: &[u8], field: &'static str) -> Result<f64, ParseError> {
    std::str::from_utf8(value)
        .ok()
        .and_then(|s| s.parse().ok())
        .ok_or(ParseError::InvalidFloat(field))
}

fn check_range(field: &'static str, value: f64, min: f64, max: f64) -> Result<(), ParseError> {
    if !value.is_finite() || !(min..=max).contains(&value) {
        return Err(ParseError::OutOfRange { field, value });
    }
    Ok(())
}

/// Best-effort ISO-8601 → `SystemTime`. Returns `None` for any
/// unparseable shape; the caller falls back to `SystemTime::now`.
/// Mirrors the parser used by the legacy `parse` path so an
/// `<event time>` attribute round-trips with the same accepted
/// grammar.
fn parse_iso8601_to_systemtime(s: &str) -> Option<SystemTime> {
    let trimmed = s.trim_end_matches('Z');
    let (date, time) = trimmed.split_once('T')?;
    let mut date_parts = date.split('-');
    let year: i64 = date_parts.next()?.parse().ok()?;
    let month: i64 = date_parts.next()?.parse().ok()?;
    let day: i64 = date_parts.next()?.parse().ok()?;
    if !(0..=9999).contains(&year) || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
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
    let days = (year - 1970) * 365 + (year - 1969) / 4 + day_of_year(month, day);
    if days < 0 {
        return None;
    }
    let secs = days as u64 * 86400 + hour as u64 * 3600 + min as u64 * 60 + sec as u64;
    Some(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(secs))
}

fn day_of_year(month: i64, day: i64) -> i64 {
    const DAYS: [i64; 12] = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    DAYS.get(month.saturating_sub(1) as usize)
        .copied()
        .unwrap_or(0)
        + day
}

/// Encode an [`Entity`] back into a minimal CoT XML payload.
///
/// The output schema:
///
/// ```xml
/// <event version="2.0" uid="…" type="…" time="…" start="…" stale="…" how="…">
///   <point lat="…" lon="…" hae="…" ce="…" le="…"/>
///   <detail>
///     <track speed="…" course="…"/>
///     <contact callsign="…"/>
///     <!-- additional detail children rebuilt from `cot.detail.<elem>.…` keys -->
///   </detail>
/// </event>
/// ```
///
/// `from_entity` only emits elements it has data for: a CoT payload
/// without a position skips the `<point>` tag entirely; one without
/// any detail-side attributes skips `<detail>`. Same-codec round-trip
/// fidelity is preserved for the common `<contact>` / `<track>` /
/// `<remarks>` shapes; arbitrary nested detail subtrees deeper than
/// one level fold via the dotted-path scheme on decode and unfold
/// flat on encode.
fn encode_cot(entity: &Entity) -> Result<Bytes, ParseError> {
    let mut out: Vec<u8> = Vec::with_capacity(256);
    let mut writer = Writer::new(&mut out);

    let mut event = BytesStart::new("event");
    event.push_attribute(("version", attr_str(entity, "version").unwrap_or("2.0")));
    event.push_attribute(("uid", entity.uid.as_str()));
    let event_type = attr_str(entity, "event_type")
        .map(str::to_owned)
        .unwrap_or_else(|| kind_to_event_type(&entity.kind));
    event.push_attribute(("type", event_type.as_str()));
    if let Some(time) = attr_str(entity, "time") {
        event.push_attribute(("time", time));
    }
    if let Some(start) = attr_str(entity, "start") {
        event.push_attribute(("start", start));
    }
    if let Some(stale) = attr_str(entity, "stale") {
        event.push_attribute(("stale", stale));
    }
    if let Some(how) = attr_str(entity, "how") {
        event.push_attribute(("how", how));
    }
    writer
        .write_event(Event::Start(event))
        .map_err(quick_xml::Error::from)?;

    if let Some(pos) = entity.position {
        let mut point = BytesStart::new("point");
        let lat = format_f64(pos.lat);
        let lon = format_f64(pos.lon);
        point.push_attribute(("lat", lat.as_str()));
        point.push_attribute(("lon", lon.as_str()));
        let hae = pos
            .hae_meters
            .or_else(|| attr_float(entity, "point.hae"))
            .unwrap_or(0.0);
        let hae_s = format_f64(hae);
        point.push_attribute(("hae", hae_s.as_str()));
        let ce_s = attr_float(entity, "point.ce").map(format_f64);
        if let Some(ref ce) = ce_s {
            point.push_attribute(("ce", ce.as_str()));
        }
        let le_s = attr_float(entity, "point.le").map(format_f64);
        if let Some(ref le) = le_s {
            point.push_attribute(("le", le.as_str()));
        }
        writer
            .write_event(Event::Empty(point))
            .map_err(quick_xml::Error::from)?;
    }

    let mut detail_emitted = false;
    let detail_children = collect_detail_children(entity);
    let needs_detail =
        entity.velocity.is_some() || entity.callsign.is_some() || !detail_children.is_empty();
    if needs_detail {
        writer
            .write_event(Event::Start(BytesStart::new("detail")))
            .map_err(quick_xml::Error::from)?;
        detail_emitted = true;

        if let Some(v) = entity.velocity {
            let mut track = BytesStart::new("track");
            let speed = format_f64(v.speed_m_s);
            let course = format_f64(v.course_deg);
            track.push_attribute(("speed", speed.as_str()));
            track.push_attribute(("course", course.as_str()));
            writer
                .write_event(Event::Empty(track))
                .map_err(quick_xml::Error::from)?;
        }

        if let Some(cs) = &entity.callsign {
            let mut contact = BytesStart::new("contact");
            contact.push_attribute(("callsign", cs.as_str()));
            // Any other contact-attribute keys (e.g. endpoint, phone)
            // come back through `detail_children` for the `contact`
            // element; the explicit `callsign` push above already
            // covers the strict-subset field.
            for (key, val) in detail_children
                .iter()
                .filter(|(elem, _, _)| elem == "contact")
                .filter(|(_, k, _)| k != "callsign")
                .map(|(_, k, v)| (k.as_str(), v.as_str()))
            {
                contact.push_attribute((key, val));
            }
            writer
                .write_event(Event::Empty(contact))
                .map_err(quick_xml::Error::from)?;
        }

        // Emit remaining detail children. `contact` is already
        // consumed; `track` is rebuilt from `Entity.velocity` and the
        // raw attribute carry would duplicate it, so skip the
        // `track` element here. Everything else gets a faithful
        // empty- or text-bodied tag.
        let mut emitted_elems: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
        if entity.callsign.is_some() {
            let _ = emitted_elems.insert("contact");
        }
        if entity.velocity.is_some() {
            let _ = emitted_elems.insert("track");
        }
        let mut by_elem: BTreeMap<&str, Vec<(&str, &str)>> = BTreeMap::new();
        let mut text_by_elem: BTreeMap<&str, &str> = BTreeMap::new();
        for (elem, key, val) in &detail_children {
            if emitted_elems.contains(elem.as_str()) {
                continue;
            }
            if key == "text" {
                let _ = text_by_elem.insert(elem.as_str(), val.as_str());
            } else {
                by_elem
                    .entry(elem.as_str())
                    .or_default()
                    .push((key.as_str(), val.as_str()));
            }
        }
        // Stable iteration order via the BTreeMap keys.
        let mut all_elems: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
        for k in by_elem.keys() {
            let _ = all_elems.insert(k);
        }
        for k in text_by_elem.keys() {
            let _ = all_elems.insert(k);
        }
        for elem in all_elems {
            let attrs = by_elem.get(elem).cloned().unwrap_or_default();
            let text = text_by_elem.get(elem).copied();
            let mut tag = BytesStart::new(elem);
            for (k, v) in &attrs {
                tag.push_attribute((*k, *v));
            }
            if let Some(body) = text {
                writer
                    .write_event(Event::Start(tag.clone()))
                    .map_err(quick_xml::Error::from)?;
                writer
                    .write_event(Event::Text(BytesText::new(body)))
                    .map_err(quick_xml::Error::from)?;
                writer
                    .write_event(Event::End(BytesEnd::new(elem.to_owned())))
                    .map_err(quick_xml::Error::from)?;
            } else {
                writer
                    .write_event(Event::Empty(tag))
                    .map_err(quick_xml::Error::from)?;
            }
        }
    }

    if detail_emitted {
        writer
            .write_event(Event::End(BytesEnd::new("detail")))
            .map_err(quick_xml::Error::from)?;
    }
    writer
        .write_event(Event::End(BytesEnd::new("event")))
        .map_err(quick_xml::Error::from)?;

    Ok(Bytes::from(out))
}

/// Render the [`EntityKind`] back to a CoT type string when the
/// entity carries no `cot.event_type` carry-over (i.e. it was built
/// programmatically rather than parsed from CoT). The fallback is
/// deliberately coarse — same-codec round-trip uses the carried-over
/// string instead.
fn kind_to_event_type(kind: &EntityKind) -> String {
    match kind {
        EntityKind::Aircraft => "a-u-A".to_string(),
        EntityKind::Ground => "a-u-G".to_string(),
        EntityKind::Marine => "a-u-S".to_string(),
        EntityKind::Munition => "a-u-P".to_string(),
        EntityKind::Sensor => "t-x-d".to_string(),
        EntityKind::Track => "a-u-G".to_string(),
        EntityKind::Unknown(s) => s.clone(),
    }
}

/// Look up a string attribute under the `cot.<key>` namespace.
fn attr_str<'a>(entity: &'a Entity, key: &str) -> Option<&'a str> {
    let full = format!("{COT_PREFIX}{key}");
    match entity.attributes.get(&full) {
        Some(AttributeValue::Str(s)) => Some(s.as_str()),
        _ => None,
    }
}

/// Look up a float attribute under the `cot.<key>` namespace.
fn attr_float(entity: &Entity, key: &str) -> Option<f64> {
    let full = format!("{COT_PREFIX}{key}");
    match entity.attributes.get(&full) {
        Some(AttributeValue::Float(v)) => Some(*v),
        _ => None,
    }
}

/// Triples of `(detail_element, attribute_or_text_key, value_string)`
/// extracted from the entity's attributes bag for `cot.detail.<elem>.<k>`
/// keys. Single-level only — nested elements are folded into the
/// element name with dot-separation on decode and unfold flat here.
fn collect_detail_children(entity: &Entity) -> Vec<(String, String, String)> {
    let prefix = format!("{COT_PREFIX}detail.");
    let mut out = Vec::new();
    for (k, v) in &entity.attributes {
        let Some(rest) = k.strip_prefix(&prefix) else {
            continue;
        };
        // Split on the FIRST dot — `<elem>` is everything up to it,
        // `<key>` is everything after. Nested-element decoding uses
        // additional dots in `<elem>` (e.g. `takv.os` becomes a
        // sibling of `takv` flat on encode, which is acceptable for
        // v1).
        let Some((elem, k_rest)) = rest.split_once('.') else {
            continue;
        };
        let value_str = match v {
            AttributeValue::Str(s) => s.clone(),
            AttributeValue::Int(i) => i.to_string(),
            AttributeValue::Float(f) => format_f64(*f),
            AttributeValue::Bool(b) => b.to_string(),
        };
        out.push((elem.to_owned(), k_rest.to_owned(), value_str));
    }
    out
}

/// Render an `f64` with the `{}` formatter. Whole-number floats render
/// as e.g. `38` (no trailing `.0`) which matches the CoT samples in
/// circulation; non-finite values fall through to whatever the
/// formatter emits (`NaN`, `inf`, `-inf`) — the encoder's caller has
/// already validated the input via [`check_range`] so this branch is
/// unreachable on a well-formed [`Entity`].
fn format_f64(v: f64) -> String {
    format!("{v}")
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn known_cot_xml() -> &'static [u8] {
        br#"<event version="2.0" uid="GOLF-1" type="a-f-G-U-C" time="2024-01-01T00:00:00Z" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z" how="m-g">
  <point lat="38.0" lon="-77.0" hae="100.0" ce="9.9" le="9.9"/>
  <detail>
    <track speed="12.5" course="270.0"/>
    <contact callsign="alpha"/>
    <remarks>foo</remarks>
  </detail>
</event>"#
    }

    #[test]
    fn cot_event_round_trips_through_entity_codec() {
        let codec = CotEntityCodec;
        let entity1 = codec.to_entity(known_cot_xml()).expect("decode 1");
        let xml2 = codec.from_entity(&entity1).expect("encode");
        let entity2 = codec.to_entity(&xml2).expect("decode 2");

        // The `timestamp` field is set from <event time> on both
        // decodes, so the two entities must compare equal.
        assert_eq!(entity1.uid, entity2.uid);
        assert_eq!(entity1.kind, entity2.kind);
        assert_eq!(entity1.position, entity2.position);
        assert_eq!(entity1.velocity, entity2.velocity);
        assert_eq!(entity1.callsign, entity2.callsign);
        assert_eq!(entity1.attributes, entity2.attributes);
        assert_eq!(entity1.timestamp, entity2.timestamp);
    }

    #[test]
    fn cot_event_uid_extraction() {
        let codec = CotEntityCodec;
        let entity = codec.to_entity(known_cot_xml()).expect("decode");
        assert_eq!(entity.uid, "GOLF-1");
    }

    #[test]
    fn cot_track_kind_classified_from_event_type() {
        let codec = CotEntityCodec;
        let cases = [
            ("a-f-G-U-C", EntityKind::Ground),
            ("a-f-A-M-F-J", EntityKind::Aircraft),
            ("a-h-S-X", EntityKind::Marine),
            ("a-h-U-X", EntityKind::Marine),
            ("a-f-P-X", EntityKind::Munition),
            ("a-f-X-X", EntityKind::Track),
            ("t-x-d", EntityKind::Sensor),
        ];
        for (event_type, expected) in cases {
            let xml = format!(
                r#"<event uid="x" type="{event_type}"><point lat="0" lon="0" hae="0"/></event>"#
            );
            let entity = codec.to_entity(xml.as_bytes()).expect("decode");
            assert_eq!(
                entity.kind, expected,
                "type={event_type} expected {expected:?}, got {:?}",
                entity.kind
            );
        }
        // Non-SA/non-sensor falls through to Unknown carrying the type.
        let xml = br#"<event uid="x" type="b-t-f"><point lat="0" lon="0" hae="0"/></event>"#;
        let entity = codec.to_entity(xml).expect("decode");
        assert_eq!(entity.kind, EntityKind::Unknown("b-t-f".into()));
    }

    #[test]
    fn cot_position_extracted_from_point() {
        let codec = CotEntityCodec;
        let xml = br#"<event uid="x" type="a-f-G-U-C"><point lat="42.0" lon="-71.0" hae="100.0"/></event>"#;
        let entity = codec.to_entity(xml).expect("decode");
        let pos = entity.position.expect("position present");
        assert_eq!(pos.lat, 42.0);
        assert_eq!(pos.lon, -71.0);
        assert_eq!(pos.hae_meters, Some(100.0));
    }

    #[test]
    fn cot_position_handles_missing_hae() {
        let codec = CotEntityCodec;
        let xml = br#"<event uid="x" type="a-f-G-U-C"><point lat="42.0" lon="-71.0"/></event>"#;
        let entity = codec.to_entity(xml).expect("decode");
        let pos = entity.position.expect("position present");
        assert_eq!(pos.lat, 42.0);
        assert_eq!(pos.lon, -71.0);
        assert_eq!(pos.hae_meters, None);
    }

    #[test]
    fn cot_velocity_extracted_from_track_detail() {
        let codec = CotEntityCodec;
        let xml = br#"<event uid="x" type="a-f-G-U-C"><point lat="0" lon="0" hae="0"/><detail><track speed="100" course="270"/></detail></event>"#;
        let entity = codec.to_entity(xml).expect("decode");
        let v = entity.velocity.expect("velocity present");
        assert_eq!(v.speed_m_s, 100.0);
        assert_eq!(v.course_deg, 270.0);
    }

    #[test]
    fn cot_callsign_extracted_from_contact_detail() {
        let codec = CotEntityCodec;
        let xml = br#"<event uid="x" type="a-f-G-U-C"><point lat="0" lon="0" hae="0"/><detail><contact callsign="alpha"/></detail></event>"#;
        let entity = codec.to_entity(xml).expect("decode");
        assert_eq!(entity.callsign.as_deref(), Some("alpha"));
    }

    #[test]
    fn cot_attributes_capture_unmapped_detail_children() {
        let codec = CotEntityCodec;
        let xml = br#"<event uid="x" type="a-f-G-U-C"><point lat="0" lon="0" hae="0"/><detail><remarks>foo</remarks></detail></event>"#;
        let entity = codec.to_entity(xml).expect("decode");
        let key = format!("{COT_PREFIX}detail.remarks.text");
        match entity.attributes.get(&key) {
            Some(AttributeValue::Str(v)) => assert_eq!(v, "foo"),
            other => panic!("expected Str(\"foo\"), got {other:?}"),
        }
    }

    #[test]
    fn cot_invalid_xml_returns_parse_error() {
        let codec = CotEntityCodec;
        let bad = b"<event uid=\"x\" type=\"a-f-G-U-C\"><point lat=\"not-a-number\" lon=\"0\" hae=\"0\"/></event>";
        let err = codec.to_entity(bad).expect_err("must fail");
        assert!(matches!(err, ParseError::InvalidFloat("lat")));
    }

    #[test]
    fn cot_round_trip_preserves_extension_attributes() {
        let codec = CotEntityCodec;
        let xml = br#"<event version="2.0" uid="x" type="a-f-G-U-C" how="m-g" time="2024-01-01T00:00:00Z" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z"><point lat="0" lon="0" hae="0"/><detail><remarks>roger</remarks><__group name="Cyan"/></detail></event>"#;
        let e1 = codec.to_entity(xml).expect("decode 1");
        let xml2 = codec.from_entity(&e1).expect("encode");
        let e2 = codec.to_entity(&xml2).expect("decode 2");

        // Each carry-over key from the unmapped detail children must
        // round-trip into the second entity.
        let remarks_key = format!("{COT_PREFIX}detail.remarks.text");
        let group_key = format!("{COT_PREFIX}detail.__group.name");
        assert_eq!(
            e1.attributes.get(&remarks_key),
            e2.attributes.get(&remarks_key),
            "remarks text carry must round-trip"
        );
        assert_eq!(
            e1.attributes.get(&group_key),
            e2.attributes.get(&group_key),
            "__group/name carry must round-trip"
        );
        // Event-level carries.
        assert_eq!(
            e1.attributes.get(&format!("{COT_PREFIX}how")),
            e2.attributes.get(&format!("{COT_PREFIX}how")),
        );
        assert_eq!(
            e1.attributes.get(&format!("{COT_PREFIX}version")),
            e2.attributes.get(&format!("{COT_PREFIX}version")),
        );
    }

    #[test]
    fn cot_detail_nesting_beyond_cap_is_rejected() {
        // A `<detail>` subtree nested deeper than MAX_DETAIL_DEPTH must
        // be rejected rather than flattened into unbounded attribute
        // keys — mirroring the transport/TLS MAX_XML_DEPTH cap.
        let mut xml = String::from(
            r#"<event uid="x" type="a-f-G-U-C"><point lat="0" lon="0" hae="0"/><detail>"#,
        );
        let depth = MAX_DETAIL_DEPTH + 5;
        for _ in 0..depth {
            xml.push_str("<n>");
        }
        for _ in 0..depth {
            xml.push_str("</n>");
        }
        xml.push_str("</detail></event>");
        let codec = CotEntityCodec;
        let err = codec
            .to_entity(xml.as_bytes())
            .expect_err("over-deep detail must be rejected");
        assert!(
            matches!(err, ParseError::DetailTooDeep { max } if max == MAX_DETAIL_DEPTH),
            "expected DetailTooDeep, got {err:?}"
        );
    }

    #[test]
    fn cot_detail_at_cap_depth_is_accepted() {
        // Exactly MAX_DETAIL_DEPTH levels must still parse — the cap is
        // an upper bound, not an off-by-one rejection of legal payloads.
        let mut xml = String::from(
            r#"<event uid="x" type="a-f-G-U-C"><point lat="0" lon="0" hae="0"/><detail>"#,
        );
        for _ in 0..MAX_DETAIL_DEPTH {
            xml.push_str("<n>");
        }
        for _ in 0..MAX_DETAIL_DEPTH {
            xml.push_str("</n>");
        }
        xml.push_str("</detail></event>");
        let codec = CotEntityCodec;
        assert!(
            codec.to_entity(xml.as_bytes()).is_ok(),
            "detail nested to exactly the cap must be accepted"
        );
    }

    #[test]
    fn cot_detail_attr_bag_beyond_cap_is_rejected() {
        // Many sibling detail elements whose flattened keys+values exceed
        // MAX_ATTR_BAG_BYTES must be rejected — mirroring the certificate
        // MAX_ATTR_BAG_BYTES cap. Each `<e_i k="…"/>` contributes well
        // under the frame limit individually but sums past the bag cap.
        let mut xml = String::from(
            r#"<event uid="x" type="a-f-G-U-C"><point lat="0" lon="0" hae="0"/><detail>"#,
        );
        // Each element adds ~30+ bytes of key + value; 512 of them blow
        // past the 4 KiB bag cap comfortably.
        for i in 0..512 {
            xml.push_str(&format!(r#"<elem{i} attr="valuevaluevalue"/>"#));
        }
        xml.push_str("</detail></event>");
        let codec = CotEntityCodec;
        let err = codec
            .to_entity(xml.as_bytes())
            .expect_err("oversized attribute bag must be rejected");
        assert!(
            matches!(err, ParseError::AttrBagTooLarge { max } if max == MAX_ATTR_BAG_BYTES),
            "expected AttrBagTooLarge, got {err:?}"
        );
    }

    #[test]
    fn cot_small_detail_bag_is_accepted() {
        // A handful of small detail elements stays well under the bag cap
        // and must parse cleanly — the cap only fires on pathological
        // payloads, not ordinary CoT traffic.
        let xml = br#"<event uid="x" type="a-f-G-U-C"><point lat="0" lon="0" hae="0"/><detail><contact callsign="alpha"/><__group name="Cyan"/></detail></event>"#;
        let codec = CotEntityCodec;
        assert!(codec.to_entity(xml).is_ok());
    }
}
