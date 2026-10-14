// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Full CoT XML parser extracting all protobuf-mappable fields.
//!
//! # Security
//!
//! Uses `quick-xml` streaming parser which does not resolve external entities
//! or process DTD declarations, preventing XXE injection.

use quick_xml::Reader;
use quick_xml::events::Event;

use crate::convert::timestamp::iso8601_to_millis;
use crate::error::ProtoError;

/// Complete CoT event with all fields needed for protobuf conversion.
#[derive(Debug, Clone, Default)]
pub struct FullCotEvent {
    // <event> attributes
    /// CoT XML schema version (the `version` attribute on `<event>`).
    ///
    /// Per MITRE CoT Message Router User's Guide (MP090284) Table 2-1 this
    /// attribute is required. We capture it verbatim rather than normalizing
    /// to a numeric type so downstream consumers see the same value the
    /// source emitter produced (e.g. `"2.0"`). Empty when the source XML
    /// omits the attribute; callers that require a value should substitute
    /// their own default.
    pub version: String,
    pub uid: String,
    pub event_type: String,
    pub how: String,
    pub time: String,
    pub start: String,
    pub stale: String,
    pub access: String,
    pub qos: String,
    pub opex: String,

    // <point> attributes
    pub lat: f64,
    pub lon: f64,
    pub hae: f64,
    pub ce: f64,
    pub le: f64,

    // Known <detail> sub-elements
    pub contact: Option<ContactDetail>,
    pub group: Option<GroupDetail>,
    pub precision_location: Option<PrecisionLocationDetail>,
    pub status: Option<StatusDetail>,
    pub takv: Option<TakvDetail>,
    pub track: Option<TrackDetail>,
    pub link: Vec<LinkDetail>,
    pub remarks: Option<RemarksDetail>,
    pub color: Option<ColorDetail>,
    pub labels: Option<LabelsDetail>,
    pub usericon: Option<UserIconDetail>,
    pub marti: Option<MartiDetail>,

    /// Residual XML: children of `<detail>` that are NOT known typed elements.
    /// Does not include the outer `<detail>` tags per TAK protobuf spec.
    pub xml_detail: String,
}

/// Parsed `<contact>` detail element from a CoT event.
#[derive(Debug, Clone, Default)]
pub struct ContactDetail {
    pub endpoint: String,
    pub callsign: String,
}

/// Parsed `<__group>` detail element carrying team color and role.
#[derive(Debug, Clone, Default)]
pub struct GroupDetail {
    pub name: String,
    pub role: String,
}

/// Parsed `<precisionlocation>` detail element with GPS metadata.
#[derive(Debug, Clone, Default)]
pub struct PrecisionLocationDetail {
    pub geopointsrc: String,
    pub altsrc: String,
}

/// Parsed `<status>` detail element with battery and device readiness.
#[derive(Debug, Clone, Default)]
pub struct StatusDetail {
    pub battery: u32,
}

/// Parsed `<takv>` detail element identifying the client software version.
#[derive(Debug, Clone, Default)]
pub struct TakvDetail {
    pub device: String,
    pub platform: String,
    pub os: String,
    pub version: String,
}

/// Parsed `<track>` detail element with speed and course.
#[derive(Debug, Clone, Default)]
pub struct TrackDetail {
    pub speed: f64,
    pub course: f64,
}

/// A `<link>` element representing a relationship to another entity.
#[derive(Debug, Clone, PartialEq)]
pub struct LinkDetail {
    pub relation: String,
    pub link_type: String,
    pub uid: String,
    pub parent_callsign: Option<String>,
    pub production_time: Option<String>,
}

/// A `<remarks>` element containing free-text annotations.
#[derive(Debug, Clone, PartialEq)]
pub struct RemarksDetail {
    pub source: Option<String>,
    pub timestamp: Option<String>,
    pub text: String,
}

/// A `<color>` element carrying an ARGB integer color value.
#[derive(Debug, Clone, PartialEq)]
pub struct ColorDetail {
    pub argb: Option<i64>,
}

/// A `<labels>` element controlling label visibility or text.
#[derive(Debug, Clone, PartialEq)]
pub struct LabelsDetail {
    pub value: String,
}

/// A `<usericon>` element specifying a custom icon path.
#[derive(Debug, Clone, PartialEq)]
pub struct UserIconDetail {
    pub iconsetpath: String,
}

/// A `<marti>` element listing destination callsigns for directed messaging.
#[derive(Debug, Clone, PartialEq)]
pub struct MartiDetail {
    pub dest_callsigns: Vec<String>,
}

/// Maximum bytes for residual xmlDetail to prevent unbounded memory growth
/// from crafted input. 64 KiB is generous for legitimate CoT detail sections.
const MAX_XML_DETAIL_BYTES: usize = 64 * 1024;

/// Maximum number of `<dest>` entries in a `<marti>` element to prevent
/// unbounded memory growth from crafted input.
const MAX_MARTI_DESTINATIONS: usize = 1000;

/// Parse CoT XML into a [`FullCotEvent`] with all protobuf-mappable fields.
pub fn parse_full(xml: &[u8]) -> Result<FullCotEvent, ProtoError> {
    let mut reader = Reader::from_reader(xml);
    reader.config_mut().trim_text(true);

    let mut event = FullCotEvent::default();
    let mut buf = Vec::new();
    let mut in_detail = false;
    let mut xml_detail_buf = Vec::<u8>::new();
    let mut xml_detail_truncated = false;

    loop {
        buf.clear();
        match reader.read_event_into(&mut buf)? {
            Event::Eof => break,

            Event::Start(ref e) => match e.name().as_ref() {
                b"event" => parse_event_attrs(e, &mut event)?,
                b"point" => parse_point_attrs(e, &mut event)?,
                b"detail" => in_detail = true,
                tag if in_detail => {
                    if is_known_detail(tag) {
                        parse_known_start(tag, e, &mut reader, &mut event)?;
                    } else if !xml_detail_truncated {
                        capture_unknown_start(e, &mut reader, &mut xml_detail_buf)?;
                        if xml_detail_buf.len() > MAX_XML_DETAIL_BYTES {
                            xml_detail_buf.truncate(MAX_XML_DETAIL_BYTES);
                            xml_detail_truncated = true;
                        }
                    } else {
                        // Over budget — skip the element entirely
                        let mut skip_buf = Vec::new();
                        let _ = reader.read_to_end_into(e.to_end().name(), &mut skip_buf)?;
                    }
                }
                _ => {}
            },

            Event::Empty(ref e) => match e.name().as_ref() {
                b"event" => parse_event_attrs(e, &mut event)?,
                b"point" => parse_point_attrs(e, &mut event)?,
                tag if in_detail => {
                    if is_known_detail(tag) {
                        parse_known_empty(tag, e, &mut event);
                    } else if !xml_detail_truncated {
                        capture_unknown_empty(e, &mut xml_detail_buf);
                        if xml_detail_buf.len() > MAX_XML_DETAIL_BYTES {
                            xml_detail_buf.truncate(MAX_XML_DETAIL_BYTES);
                            xml_detail_truncated = true;
                        }
                    }
                }
                _ => {}
            },

            Event::End(ref e) => {
                if e.name().as_ref() == b"detail" {
                    in_detail = false;
                }
            }

            _ => {}
        }
    }

    if !xml_detail_buf.is_empty() {
        event.xml_detail = String::from_utf8_lossy(&xml_detail_buf).into_owned();
    }

    if event.uid.is_empty() {
        return Err(ProtoError::MissingField("uid"));
    }
    if event.event_type.is_empty() {
        return Err(ProtoError::MissingField("type"));
    }

    Ok(event)
}

fn is_known_detail(tag: &[u8]) -> bool {
    matches!(
        tag,
        b"contact"
            | b"__group"
            | b"precisionlocation"
            | b"status"
            | b"takv"
            | b"track"
            | b"link"
            | b"remarks"
            | b"color"
            | b"labels"
            | b"usericon"
            | b"marti"
    )
}

fn parse_event_attrs(
    e: &quick_xml::events::BytesStart<'_>,
    event: &mut FullCotEvent,
) -> Result<(), ProtoError> {
    for attr in e.attributes().flatten() {
        let value = String::from_utf8_lossy(&attr.value).into_owned();
        match attr.key.as_ref() {
            b"version" => event.version = value,
            b"uid" => event.uid = value,
            b"type" => event.event_type = value,
            b"how" => event.how = value,
            b"time" => {
                validate_timestamp("time", &value)?;
                event.time = value;
            }
            b"start" => {
                validate_timestamp("start", &value)?;
                event.start = value;
            }
            b"stale" => {
                validate_timestamp("stale", &value)?;
                event.stale = value;
            }
            b"access" => event.access = value,
            b"qos" => event.qos = value,
            b"opex" => event.opex = value,
            _ => {}
        }
    }
    Ok(())
}

/// Validate that a CoT timestamp attribute parses as ISO 8601.
///
/// MITRE CoT Message Router User's Guide (MP090284) Table 2-1 specifies
/// `time`, `start`, and `stale` as ISO 8601 / RFC 3339 UTC timestamps
/// (`YYYY-MM-DDThh:mm:ss[.SSS]Z`). We reject malformed values at parse
/// time so downstream consumers (NATS JSON wire, federation relay,
/// protobuf conversion) never have to re-validate — the proto conversion
/// path already fails closed via `iso8601_to_millis`, so this matches
/// that behavior at the XML entry point.
///
/// Empty strings are allowed (upstream may omit an optional attribute);
/// the "is this attribute present" check is separate.
fn validate_timestamp(field: &'static str, value: &str) -> Result<(), ProtoError> {
    if value.is_empty() {
        return Ok(());
    }
    iso8601_to_millis(value).map(|_| ()).map_err(|e| match e {
        ProtoError::InvalidTimestamp(msg) => {
            ProtoError::InvalidTimestamp(format!("{field}: {msg}"))
        }
        other => other,
    })
}

fn parse_point_attrs(
    e: &quick_xml::events::BytesStart<'_>,
    event: &mut FullCotEvent,
) -> Result<(), ProtoError> {
    for attr in e.attributes().flatten() {
        let value_str = String::from_utf8_lossy(&attr.value);
        match attr.key.as_ref() {
            b"lat" => {
                let v = parse_f64(&value_str)?;
                check_range("lat", v, -90.0, 90.0)?;
                event.lat = v;
            }
            b"lon" => {
                let v = parse_f64(&value_str)?;
                check_range("lon", v, -180.0, 180.0)?;
                event.lon = v;
            }
            b"hae" => event.hae = parse_f64(&value_str)?,
            b"ce" => event.ce = parse_f64(&value_str)?,
            b"le" => event.le = parse_f64(&value_str)?,
            _ => {}
        }
    }
    Ok(())
}

fn parse_f64(s: &str) -> Result<f64, ProtoError> {
    s.parse()
        .map_err(|_| ProtoError::InvalidTimestamp(format!("bad float: {s}")))
}

/// Reject values outside `[min, max]` (inclusive) or non-finite.
///
/// Used for WGS-84 lat/lon range enforcement per MP090284 Table 2-1.
fn check_range(field: &'static str, value: f64, min: f64, max: f64) -> Result<(), ProtoError> {
    if !value.is_finite() || !(min..=max).contains(&value) {
        return Err(ProtoError::OutOfRange { field, value });
    }
    Ok(())
}

/// Parse a known detail child element that was a Start event (has children).
fn parse_known_start(
    tag: &[u8],
    e: &quick_xml::events::BytesStart<'_>,
    reader: &mut Reader<&[u8]>,
    event: &mut FullCotEvent,
) -> Result<(), ProtoError> {
    match tag {
        b"contact" => {
            event.contact = Some(parse_contact(e));
            let mut skip_buf = Vec::new();
            let _ = reader.read_to_end_into(e.to_end().name(), &mut skip_buf)?;
        }
        b"__group" => {
            event.group = Some(parse_group(e));
            let mut skip_buf = Vec::new();
            let _ = reader.read_to_end_into(e.to_end().name(), &mut skip_buf)?;
        }
        b"precisionlocation" => {
            event.precision_location = Some(parse_precision_location(e));
            let mut skip_buf = Vec::new();
            let _ = reader.read_to_end_into(e.to_end().name(), &mut skip_buf)?;
        }
        b"status" => {
            event.status = Some(parse_status(e));
            let mut skip_buf = Vec::new();
            let _ = reader.read_to_end_into(e.to_end().name(), &mut skip_buf)?;
        }
        b"takv" => {
            event.takv = Some(parse_takv(e));
            let mut skip_buf = Vec::new();
            let _ = reader.read_to_end_into(e.to_end().name(), &mut skip_buf)?;
        }
        b"track" => {
            event.track = Some(parse_track(e));
            let mut skip_buf = Vec::new();
            let _ = reader.read_to_end_into(e.to_end().name(), &mut skip_buf)?;
        }
        b"link" => {
            event.link.push(parse_link(e));
            let mut skip_buf = Vec::new();
            let _ = reader.read_to_end_into(e.to_end().name(), &mut skip_buf)?;
        }
        b"remarks" => {
            event.remarks = Some(parse_remarks_start(e, reader)?);
        }
        b"color" => {
            event.color = Some(parse_color(e));
            let mut skip_buf = Vec::new();
            let _ = reader.read_to_end_into(e.to_end().name(), &mut skip_buf)?;
        }
        b"labels" => {
            event.labels = Some(parse_labels(e));
            let mut skip_buf = Vec::new();
            let _ = reader.read_to_end_into(e.to_end().name(), &mut skip_buf)?;
        }
        b"usericon" => {
            event.usericon = Some(parse_usericon(e));
            let mut skip_buf = Vec::new();
            let _ = reader.read_to_end_into(e.to_end().name(), &mut skip_buf)?;
        }
        b"marti" => {
            event.marti = Some(parse_marti_start(e, reader)?);
        }
        _ => {
            let mut skip_buf = Vec::new();
            let _ = reader.read_to_end_into(e.to_end().name(), &mut skip_buf)?;
        }
    }
    Ok(())
}

/// Parse a known detail child element that was an Empty event (self-closing).
fn parse_known_empty(tag: &[u8], e: &quick_xml::events::BytesStart<'_>, event: &mut FullCotEvent) {
    match tag {
        b"contact" => event.contact = Some(parse_contact(e)),
        b"__group" => event.group = Some(parse_group(e)),
        b"precisionlocation" => event.precision_location = Some(parse_precision_location(e)),
        b"status" => event.status = Some(parse_status(e)),
        b"takv" => event.takv = Some(parse_takv(e)),
        b"track" => event.track = Some(parse_track(e)),
        b"link" => event.link.push(parse_link(e)),
        b"remarks" => {
            event.remarks = Some(parse_remarks_empty(e));
        }
        b"color" => event.color = Some(parse_color(e)),
        b"labels" => event.labels = Some(parse_labels(e)),
        b"usericon" => event.usericon = Some(parse_usericon(e)),
        b"marti" => {
            event.marti = Some(MartiDetail {
                dest_callsigns: Vec::new(),
            });
        }
        _ => {}
    }
}

fn parse_contact(e: &quick_xml::events::BytesStart<'_>) -> ContactDetail {
    let mut detail = ContactDetail::default();
    for attr in e.attributes().flatten() {
        let value = String::from_utf8_lossy(&attr.value).into_owned();
        match attr.key.as_ref() {
            b"endpoint" => detail.endpoint = value,
            b"callsign" => detail.callsign = value,
            _ => {}
        }
    }
    detail
}

fn parse_group(e: &quick_xml::events::BytesStart<'_>) -> GroupDetail {
    let mut detail = GroupDetail::default();
    for attr in e.attributes().flatten() {
        let value = String::from_utf8_lossy(&attr.value).into_owned();
        match attr.key.as_ref() {
            b"name" => detail.name = value,
            b"role" => detail.role = value,
            _ => {}
        }
    }
    detail
}

fn parse_precision_location(e: &quick_xml::events::BytesStart<'_>) -> PrecisionLocationDetail {
    let mut detail = PrecisionLocationDetail::default();
    for attr in e.attributes().flatten() {
        let value = String::from_utf8_lossy(&attr.value).into_owned();
        match attr.key.as_ref() {
            b"geopointsrc" => detail.geopointsrc = value,
            b"altsrc" => detail.altsrc = value,
            _ => {}
        }
    }
    detail
}

fn parse_status(e: &quick_xml::events::BytesStart<'_>) -> StatusDetail {
    let mut detail = StatusDetail::default();
    for attr in e.attributes().flatten() {
        let value_str = String::from_utf8_lossy(&attr.value);
        if attr.key.as_ref() == b"battery" {
            detail.battery = value_str.parse().unwrap_or(0);
        }
    }
    detail
}

fn parse_takv(e: &quick_xml::events::BytesStart<'_>) -> TakvDetail {
    let mut detail = TakvDetail::default();
    for attr in e.attributes().flatten() {
        let value = String::from_utf8_lossy(&attr.value).into_owned();
        match attr.key.as_ref() {
            b"device" => detail.device = value,
            b"platform" => detail.platform = value,
            b"os" => detail.os = value,
            b"version" => detail.version = value,
            _ => {}
        }
    }
    detail
}

fn parse_track(e: &quick_xml::events::BytesStart<'_>) -> TrackDetail {
    let mut detail = TrackDetail::default();
    for attr in e.attributes().flatten() {
        let value_str = String::from_utf8_lossy(&attr.value);
        match attr.key.as_ref() {
            b"speed" => detail.speed = value_str.parse().unwrap_or(0.0),
            b"course" => detail.course = value_str.parse().unwrap_or(0.0),
            _ => {}
        }
    }
    detail
}

fn parse_link(e: &quick_xml::events::BytesStart<'_>) -> LinkDetail {
    let mut relation = String::new();
    let mut link_type = String::new();
    let mut uid = String::new();
    let mut parent_callsign = None;
    let mut production_time = None;
    for attr in e.attributes().flatten() {
        let value = String::from_utf8_lossy(&attr.value).into_owned();
        match attr.key.as_ref() {
            b"relation" => relation = value,
            b"type" => link_type = value,
            b"uid" => uid = value,
            b"parent_callsign" => parent_callsign = Some(value),
            b"production_time" => production_time = Some(value),
            _ => {}
        }
    }
    LinkDetail {
        relation,
        link_type,
        uid,
        parent_callsign,
        production_time,
    }
}

/// Parse a `<remarks>` Start element, reading text content until the closing tag.
fn parse_remarks_start(
    e: &quick_xml::events::BytesStart<'_>,
    reader: &mut Reader<&[u8]>,
) -> Result<RemarksDetail, ProtoError> {
    let mut source = None;
    let mut timestamp = None;
    for attr in e.attributes().flatten() {
        let value = String::from_utf8_lossy(&attr.value).into_owned();
        match attr.key.as_ref() {
            b"source" => source = Some(value),
            b"time" => timestamp = Some(value),
            _ => {}
        }
    }

    // Read text content until the closing </remarks> tag
    let mut text_buf = Vec::new();
    let mut inner_buf = Vec::new();
    loop {
        inner_buf.clear();
        match reader.read_event_into(&mut inner_buf)? {
            Event::Text(ref t) => {
                if text_buf.len() + t.len() > MAX_XML_DETAIL_BYTES {
                    return Err(ProtoError::FrameTooLarge {
                        size: text_buf.len() + t.len(),
                        max: MAX_XML_DETAIL_BYTES,
                    });
                }
                text_buf.extend_from_slice(t.as_ref());
            }
            Event::End(ref end) if end.name().as_ref() == b"remarks" => break,
            Event::Eof => break,
            _ => {}
        }
    }

    let text = String::from_utf8_lossy(&text_buf).into_owned();
    Ok(RemarksDetail {
        source,
        timestamp,
        text,
    })
}

/// Parse attributes from a self-closing `<remarks/>` element.
fn parse_remarks_empty(e: &quick_xml::events::BytesStart<'_>) -> RemarksDetail {
    let mut source = None;
    let mut timestamp = None;
    for attr in e.attributes().flatten() {
        let value = String::from_utf8_lossy(&attr.value).into_owned();
        match attr.key.as_ref() {
            b"source" => source = Some(value),
            b"time" => timestamp = Some(value),
            _ => {}
        }
    }
    RemarksDetail {
        source,
        timestamp,
        text: String::new(),
    }
}

fn parse_color(e: &quick_xml::events::BytesStart<'_>) -> ColorDetail {
    let mut argb = None;
    for attr in e.attributes().flatten() {
        if attr.key.as_ref() == b"argb" {
            let value_str = String::from_utf8_lossy(&attr.value);
            argb = value_str.parse().ok();
        }
    }
    ColorDetail { argb }
}

fn parse_labels(e: &quick_xml::events::BytesStart<'_>) -> LabelsDetail {
    let mut value = String::new();
    for attr in e.attributes().flatten() {
        if attr.key.as_ref() == b"value" {
            value = String::from_utf8_lossy(&attr.value).into_owned();
        }
    }
    LabelsDetail { value }
}

fn parse_usericon(e: &quick_xml::events::BytesStart<'_>) -> UserIconDetail {
    let mut iconsetpath = String::new();
    for attr in e.attributes().flatten() {
        if attr.key.as_ref() == b"iconsetpath" {
            iconsetpath = String::from_utf8_lossy(&attr.value).into_owned();
        }
    }
    UserIconDetail { iconsetpath }
}

/// Parse a `<marti>` Start element, collecting `<dest callsign="..."/>` children.
fn parse_marti_start(
    e: &quick_xml::events::BytesStart<'_>,
    reader: &mut Reader<&[u8]>,
) -> Result<MartiDetail, ProtoError> {
    let _ = e; // marti element itself has no attributes we need
    let mut dest_callsigns = Vec::new();
    let mut inner_buf = Vec::new();
    loop {
        inner_buf.clear();
        match reader.read_event_into(&mut inner_buf)? {
            Event::Empty(ref child) if child.name().as_ref() == b"dest" => {
                if dest_callsigns.len() >= MAX_MARTI_DESTINATIONS {
                    continue;
                }
                for attr in child.attributes().flatten() {
                    if attr.key.as_ref() == b"callsign" {
                        dest_callsigns.push(String::from_utf8_lossy(&attr.value).into_owned());
                    }
                }
            }
            Event::End(ref end) if end.name().as_ref() == b"marti" => break,
            Event::Eof => break,
            _ => {}
        }
    }
    Ok(MartiDetail { dest_callsigns })
}

/// Capture an unknown XML element (Start event) as raw bytes for xmlDetail.
fn capture_unknown_start(
    e: &quick_xml::events::BytesStart<'_>,
    reader: &mut Reader<&[u8]>,
    xml_detail_buf: &mut Vec<u8>,
) -> Result<(), ProtoError> {
    // Reconstruct opening tag
    write_opening_tag(e, xml_detail_buf);
    xml_detail_buf.push(b'>');

    // Read inner content until matching end tag
    let end_name = e.to_end().name().into_inner().to_vec();
    let mut inner_buf = Vec::new();
    loop {
        inner_buf.clear();
        let ev = reader.read_event_into(&mut inner_buf)?;
        match &ev {
            Event::End(end) if end.name().as_ref() == end_name.as_slice() => {
                xml_detail_buf.extend_from_slice(b"</");
                xml_detail_buf.extend_from_slice(&end_name);
                xml_detail_buf.push(b'>');
                break;
            }
            Event::Eof => break,
            _ => write_event_to_buf(&ev, xml_detail_buf),
        }
    }
    Ok(())
}

/// Capture an unknown XML element (Empty/self-closing) as raw bytes.
fn capture_unknown_empty(e: &quick_xml::events::BytesStart<'_>, xml_detail_buf: &mut Vec<u8>) {
    write_opening_tag(e, xml_detail_buf);
    xml_detail_buf.extend_from_slice(b"/>");
}

/// Write the opening tag name and attributes (without > or />).
fn write_opening_tag(e: &quick_xml::events::BytesStart<'_>, buf: &mut Vec<u8>) {
    buf.push(b'<');
    buf.extend_from_slice(e.name().as_ref());
    for attr in e.attributes().flatten() {
        buf.push(b' ');
        buf.extend_from_slice(attr.key.as_ref());
        buf.extend_from_slice(b"=\"");
        buf.extend_from_slice(&attr.value);
        buf.push(b'"');
    }
}

/// Write a quick_xml event back to a byte buffer as raw XML.
fn write_event_to_buf(ev: &Event<'_>, buf: &mut Vec<u8>) {
    match ev {
        Event::Start(e) => {
            write_opening_tag(e, buf);
            buf.push(b'>');
        }
        Event::End(e) => {
            buf.extend_from_slice(b"</");
            buf.extend_from_slice(e.name().as_ref());
            buf.push(b'>');
        }
        Event::Empty(e) => {
            write_opening_tag(e, buf);
            buf.extend_from_slice(b"/>");
        }
        Event::Text(e) => {
            buf.extend_from_slice(e.as_ref());
        }
        Event::CData(e) => {
            buf.extend_from_slice(b"<![CDATA[");
            buf.extend_from_slice(e.as_ref());
            buf.extend_from_slice(b"]]>");
        }
        Event::Comment(e) => {
            buf.extend_from_slice(b"<!--");
            buf.extend_from_slice(e.as_ref());
            buf.extend_from_slice(b"-->");
        }
        _ => {}
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn parse_full_position_event() {
        let xml = br#"<event version="2.0" uid="ALPHA-1" type="a-f-G-U-C" how="m-g" time="2021-02-27T20:32:24Z" start="2021-02-27T20:32:24Z" stale="2021-02-27T20:37:24Z">
            <point lat="37.7749" lon="-122.4194" hae="10.5" ce="50.0" le="30.0"/>
            <detail>
                <contact callsign="ALPHA" endpoint="*:-1:stcp"/>
                <__group name="Cyan" role="Team Lead"/>
                <track speed="10.5" course="90.0"/>
            </detail>
        </event>"#;

        let evt = parse_full(xml).expect("parse");
        assert_eq!(evt.uid, "ALPHA-1");
        assert_eq!(evt.event_type, "a-f-G-U-C");
        assert_eq!(evt.how, "m-g");
        assert!((evt.lat - 37.7749).abs() < f64::EPSILON);
        assert!((evt.lon - (-122.4194)).abs() < f64::EPSILON);
        assert!((evt.hae - 10.5).abs() < f64::EPSILON);
        assert!((evt.ce - 50.0).abs() < f64::EPSILON);
        assert!((evt.le - 30.0).abs() < f64::EPSILON);

        let contact = evt.contact.expect("contact");
        assert_eq!(contact.callsign, "ALPHA");
        assert_eq!(contact.endpoint, "*:-1:stcp");

        let group = evt.group.expect("group");
        assert_eq!(group.name, "Cyan");
        assert_eq!(group.role, "Team Lead");

        let track = evt.track.expect("track");
        assert!((track.speed - 10.5).abs() < f64::EPSILON);
        assert!((track.course - 90.0).abs() < f64::EPSILON);

        assert!(evt.xml_detail.is_empty());
    }

    #[test]
    fn parse_full_with_typed_marti_and_remarks() {
        let xml = br#"<event version="2.0" uid="ALPHA-1" type="a-f-G-U-C" how="m-g" time="2021-02-27T20:32:24Z" start="2021-02-27T20:32:24Z" stale="2021-02-27T20:37:24Z">
            <point lat="37.0" lon="-122.0" hae="0.0" ce="50.0" le="30.0"/>
            <detail>
                <contact callsign="ALPHA"/>
                <marti><dest callsign="BRAVO"/></marti>
                <remarks>test note</remarks>
            </detail>
        </event>"#;

        let evt = parse_full(xml).expect("parse");
        assert!(evt.contact.is_some());

        let marti = evt.marti.as_ref().expect("marti");
        assert_eq!(marti.dest_callsigns, vec!["BRAVO"]);

        let remarks = evt.remarks.as_ref().expect("remarks");
        assert_eq!(remarks.text, "test note");

        // Known types should NOT appear in residual
        assert!(evt.xml_detail.is_empty());
    }

    /// Verify that known detail children from real iTAK/ATAK clients are
    /// extracted into typed fields and truly unknown tags remain in xml_detail.
    #[test]
    fn parse_full_extracts_itak_typed_details() {
        let xml = br#"<event uid="ITAK-1" type="a-f-G-U-C" how="m-g" time="2021-01-01T00:00:00Z" start="2021-01-01T00:00:00Z" stale="2021-01-01T00:05:00Z">
            <point lat="37.0" lon="-122.0" hae="0.0" ce="50.0" le="30.0"/>
            <detail>
                <contact callsign="ALPHA" endpoint="*:-1:stcp"/>
                <__group name="Cyan" role="Team Member"/>
                <uid Droid="ALPHA"/>
                <color argb="-16711936"/>
                <link uid="SENDER-1" type="a-f-G" relation="p-p"/>
                <usericon iconsetpath="COT_MAPPING_2525B/a-f/a-f-G"/>
                <_flow-tags_ TAK-Server-e5dbc="2021-01-01T00:00:00Z"/>
            </detail>
        </event>"#;

        let evt = parse_full(xml).expect("parse");

        // Known elements parsed into typed fields
        assert_eq!(evt.contact.as_ref().unwrap().callsign, "ALPHA");
        assert_eq!(evt.group.as_ref().unwrap().name, "Cyan");

        // Newly typed detail elements
        let color = evt.color.as_ref().expect("color");
        assert_eq!(color.argb, Some(-16_711_936));

        let link = evt.link.first().expect("link");
        assert_eq!(link.uid, "SENDER-1");
        assert_eq!(link.link_type, "a-f-G");
        assert_eq!(link.relation, "p-p");

        let usericon = evt.usericon.as_ref().expect("usericon");
        assert_eq!(usericon.iconsetpath, "COT_MAPPING_2525B/a-f/a-f-G");

        // Truly unknown elements remain in xml_detail
        assert!(evt.xml_detail.contains("uid"));
        assert!(evt.xml_detail.contains("Droid"));
        assert!(evt.xml_detail.contains("_flow-tags_"));

        // Typed elements should NOT be in xml_detail
        assert!(!evt.xml_detail.contains("<color"));
        assert!(!evt.xml_detail.contains("<link"));
        assert!(!evt.xml_detail.contains("<usericon"));
    }

    /// Verify shape drawing elements round-trip through xml_detail.
    #[test]
    fn parse_full_preserves_shape_details() {
        let xml = br#"<event uid="SHAPE-1" type="u-d-r" how="h-e" time="2021-01-01T00:00:00Z" start="2021-01-01T00:00:00Z" stale="2021-01-01T00:05:00Z">
            <point lat="37.0" lon="-122.0" hae="0.0" ce="50.0" le="30.0"/>
            <detail>
                <shape>
                    <polyline closed="true">
                        <vertex lat="37.0" lon="-122.0" hae="0.0"/>
                        <vertex lat="37.1" lon="-122.0" hae="0.0"/>
                        <vertex lat="37.1" lon="-122.1" hae="0.0"/>
                        <vertex lat="37.0" lon="-122.1" hae="0.0"/>
                    </polyline>
                </shape>
                <strokeColor value="-65536"/>
                <fillColor value="536870912"/>
                <strokeWeight value="3.0"/>
                <labels_on value="false"/>
            </detail>
        </event>"#;

        let evt = parse_full(xml).expect("parse");

        // All shape-related elements should be in xml_detail
        assert!(evt.xml_detail.contains("shape"));
        assert!(evt.xml_detail.contains("polyline"));
        assert!(evt.xml_detail.contains("vertex"));
        assert!(evt.xml_detail.contains("strokeColor"));
        assert!(evt.xml_detail.contains("fillColor"));
        assert!(evt.xml_detail.contains("strokeWeight"));
        assert!(evt.xml_detail.contains("labels_on"));
    }

    /// Verify GeoChat detail elements: __chat stays in xml_detail residual,
    /// link and remarks are extracted into typed fields.
    #[test]
    fn parse_full_extracts_chat_typed_details() {
        let xml = br#"<event uid="GeoChat.SENDER.RECV.MSG1" type="b-t-f" how="h-g-i-g-o" time="2021-01-01T00:00:00Z" start="2021-01-01T00:00:00Z" stale="2021-01-01T00:05:00Z">
            <point lat="37.0" lon="-122.0" hae="0.0" ce="50.0" le="30.0"/>
            <detail>
                <__chat parent="RootContactGroup" groupOwner="false" chatroom="RECV" id="RECV" senderCallsign="SENDER">
                    <chatgrp uid0="SENDER" uid1="RECV" id="RECV"/>
                </__chat>
                <link uid="SENDER" type="a-f-G-U-C" relation="p-p"/>
                <remarks source="BAO.F.ATAK.SENDER" to="RECV" time="2021-01-01T00:00:00Z">hello world</remarks>
            </detail>
        </event>"#;

        let evt = parse_full(xml).expect("parse");

        // __chat is not a known typed element, stays in xml_detail
        assert!(evt.xml_detail.contains("__chat"));
        assert!(evt.xml_detail.contains("chatgrp"));
        assert!(evt.xml_detail.contains("senderCallsign"));

        // link and remarks are now typed
        let link = evt.link.first().expect("link");
        assert_eq!(link.uid, "SENDER");
        assert_eq!(link.link_type, "a-f-G-U-C");
        assert_eq!(link.relation, "p-p");

        let remarks = evt.remarks.as_ref().expect("remarks");
        assert_eq!(remarks.source.as_deref(), Some("BAO.F.ATAK.SENDER"));
        assert_eq!(remarks.timestamp.as_deref(), Some("2021-01-01T00:00:00Z"));
        assert_eq!(remarks.text, "hello world");

        // Typed elements should NOT be in xml_detail
        assert!(!evt.xml_detail.contains("<link"));
        assert!(!evt.xml_detail.contains("<remarks"));
    }

    #[test]
    fn parse_full_minimal_event() {
        let xml = br#"<event uid="TEST-1" type="a-f-G"/>"#;
        let evt = parse_full(xml).expect("parse");
        assert_eq!(evt.uid, "TEST-1");
        assert_eq!(evt.event_type, "a-f-G");
        assert!(evt.contact.is_none());
        assert!(evt.xml_detail.is_empty());
    }

    #[test]
    fn parse_full_missing_uid() {
        let xml = br#"<event type="a-f-G"/>"#;
        assert!(parse_full(xml).is_err());
    }

    #[test]
    fn parse_full_missing_type() {
        let xml = br#"<event uid="TEST-1"/>"#;
        assert!(parse_full(xml).is_err());
    }

    #[test]
    fn parse_full_all_detail_types() {
        let xml = br#"<event uid="TEST-1" type="a-f-G">
            <detail>
                <contact callsign="ALPHA" endpoint="*:-1:stcp"/>
                <__group name="Cyan" role="Team Lead"/>
                <precisionlocation geopointsrc="GPS" altsrc="GPS"/>
                <status battery="85"/>
                <takv device="Pixel" platform="ATAK-CIV" os="Android" version="4.10.0"/>
                <track speed="5.5" course="180.0"/>
            </detail>
        </event>"#;

        let evt = parse_full(xml).expect("parse");
        assert!(evt.contact.is_some());
        assert!(evt.group.is_some());
        assert!(evt.precision_location.is_some());
        assert!(evt.status.is_some());
        assert!(evt.takv.is_some());
        assert!(evt.track.is_some());

        let pl = evt.precision_location.as_ref().expect("pl");
        assert_eq!(pl.geopointsrc, "GPS");
        assert_eq!(pl.altsrc, "GPS");

        let status = evt.status.as_ref().expect("status");
        assert_eq!(status.battery, 85);

        let takv = evt.takv.as_ref().expect("takv");
        assert_eq!(takv.device, "Pixel");
        assert_eq!(takv.platform, "ATAK-CIV");
        assert_eq!(takv.os, "Android");
        assert_eq!(takv.version, "4.10.0");

        assert!(evt.xml_detail.is_empty());
    }

    #[test]
    fn parse_link_detail() {
        let xml = br#"<event uid="LINK-1" type="a-f-G">
            <detail>
                <link uid="SENDER-1" type="a-f-G-U-C" relation="p-p" parent_callsign="HQ" production_time="2021-01-01T00:00:00Z"/>
            </detail>
        </event>"#;

        let evt = parse_full(xml).expect("parse");
        let link = evt.link.into_iter().next().expect("link");
        assert_eq!(link.uid, "SENDER-1");
        assert_eq!(link.link_type, "a-f-G-U-C");
        assert_eq!(link.relation, "p-p");
        assert_eq!(link.parent_callsign.as_deref(), Some("HQ"));
        assert_eq!(
            link.production_time.as_deref(),
            Some("2021-01-01T00:00:00Z")
        );
        assert!(evt.xml_detail.is_empty());
    }

    #[test]
    fn parse_remarks_detail_with_attributes() {
        let xml = br#"<event uid="REM-1" type="b-t-f">
            <detail>
                <remarks source="BAO.F.ATAK.SENDER" time="2021-01-01T00:00:00Z">hello world</remarks>
            </detail>
        </event>"#;

        let evt = parse_full(xml).expect("parse");
        let remarks = evt.remarks.expect("remarks");
        assert_eq!(remarks.source.as_deref(), Some("BAO.F.ATAK.SENDER"));
        assert_eq!(remarks.timestamp.as_deref(), Some("2021-01-01T00:00:00Z"));
        assert_eq!(remarks.text, "hello world");
        assert!(evt.xml_detail.is_empty());
    }

    #[test]
    fn parse_remarks_detail_text_only() {
        let xml = br#"<event uid="REM-2" type="b-t-f">
            <detail>
                <remarks>just a note</remarks>
            </detail>
        </event>"#;

        let evt = parse_full(xml).expect("parse");
        let remarks = evt.remarks.expect("remarks");
        assert!(remarks.source.is_none());
        assert!(remarks.timestamp.is_none());
        assert_eq!(remarks.text, "just a note");
    }

    #[test]
    fn parse_color_detail() {
        let xml = br#"<event uid="COLOR-1" type="a-f-G">
            <detail>
                <color argb="-16711936"/>
            </detail>
        </event>"#;

        let evt = parse_full(xml).expect("parse");
        let color = evt.color.expect("color");
        assert_eq!(color.argb, Some(-16_711_936));
        assert!(evt.xml_detail.is_empty());
    }

    #[test]
    fn parse_color_detail_no_argb() {
        let xml = br#"<event uid="COLOR-2" type="a-f-G">
            <detail>
                <color/>
            </detail>
        </event>"#;

        let evt = parse_full(xml).expect("parse");
        let color = evt.color.expect("color");
        assert_eq!(color.argb, None);
    }

    #[test]
    fn parse_labels_detail() {
        let xml = br#"<event uid="LABELS-1" type="a-f-G">
            <detail>
                <labels value="Team Alpha"/>
            </detail>
        </event>"#;

        let evt = parse_full(xml).expect("parse");
        let labels = evt.labels.expect("labels");
        assert_eq!(labels.value, "Team Alpha");
        assert!(evt.xml_detail.is_empty());
    }

    #[test]
    fn parse_usericon_detail() {
        let xml = br#"<event uid="ICON-1" type="a-f-G">
            <detail>
                <usericon iconsetpath="COT_MAPPING_2525B/a-f/a-f-G"/>
            </detail>
        </event>"#;

        let evt = parse_full(xml).expect("parse");
        let usericon = evt.usericon.expect("usericon");
        assert_eq!(usericon.iconsetpath, "COT_MAPPING_2525B/a-f/a-f-G");
        assert!(evt.xml_detail.is_empty());
    }

    #[test]
    fn parse_marti_detail_single_dest() {
        let xml = br#"<event uid="MARTI-1" type="a-f-G">
            <detail>
                <marti><dest callsign="BRAVO"/></marti>
            </detail>
        </event>"#;

        let evt = parse_full(xml).expect("parse");
        let marti = evt.marti.expect("marti");
        assert_eq!(marti.dest_callsigns, vec!["BRAVO"]);
        assert!(evt.xml_detail.is_empty());
    }

    #[test]
    fn parse_marti_detail_multiple_dests() {
        let xml = br#"<event uid="MARTI-2" type="a-f-G">
            <detail>
                <marti>
                    <dest callsign="BRAVO"/>
                    <dest callsign="CHARLIE"/>
                    <dest callsign="DELTA"/>
                </marti>
            </detail>
        </event>"#;

        let evt = parse_full(xml).expect("parse");
        let marti = evt.marti.expect("marti");
        assert_eq!(marti.dest_callsigns, vec!["BRAVO", "CHARLIE", "DELTA"]);
        assert!(evt.xml_detail.is_empty());
    }

    #[test]
    fn parse_unknown_tags_to_xml_detail_residual() {
        let xml = br#"<event uid="UNKNOWN-1" type="a-f-G">
            <detail>
                <contact callsign="ALPHA"/>
                <customTag foo="bar"/>
                <_flow-tags_ server="2021-01-01T00:00:00Z"/>
            </detail>
        </event>"#;

        let evt = parse_full(xml).expect("parse");
        assert!(evt.contact.is_some());
        assert!(evt.xml_detail.contains("customTag"));
        assert!(evt.xml_detail.contains("foo"));
        assert!(evt.xml_detail.contains("_flow-tags_"));
        // Known types should not be in residual
        assert!(!evt.xml_detail.contains("<contact"));
    }

    /// All new typed detail elements present in a single event.
    #[test]
    fn parse_all_new_detail_types_combined() {
        let xml = br#"<event uid="COMBINED-1" type="a-f-G" how="m-g" time="2021-01-01T00:00:00Z" start="2021-01-01T00:00:00Z" stale="2021-01-01T00:05:00Z">
            <point lat="37.0" lon="-122.0" hae="0.0" ce="50.0" le="30.0"/>
            <detail>
                <contact callsign="ALPHA" endpoint="*:-1:stcp"/>
                <link uid="SENDER-1" type="a-f-G" relation="p-p"/>
                <remarks source="BAO.F.ATAK.SENDER" time="2021-01-01T00:00:00Z">test message</remarks>
                <color argb="-65536"/>
                <labels value="Squad Leader"/>
                <usericon iconsetpath="COT_MAPPING_2525B/a-f/a-f-G-U"/>
                <marti>
                    <dest callsign="BRAVO"/>
                    <dest callsign="CHARLIE"/>
                </marti>
                <unknownElement data="preserved"/>
            </detail>
        </event>"#;

        let evt = parse_full(xml).expect("parse");

        // Original typed field
        assert_eq!(evt.contact.as_ref().unwrap().callsign, "ALPHA");

        // New typed fields
        let link = evt.link.first().expect("link");
        assert_eq!(link.uid, "SENDER-1");
        assert_eq!(link.relation, "p-p");

        let remarks = evt.remarks.as_ref().expect("remarks");
        assert_eq!(remarks.text, "test message");
        assert_eq!(remarks.source.as_deref(), Some("BAO.F.ATAK.SENDER"));

        let color = evt.color.as_ref().expect("color");
        assert_eq!(color.argb, Some(-65536));

        let labels = evt.labels.as_ref().expect("labels");
        assert_eq!(labels.value, "Squad Leader");

        let usericon = evt.usericon.as_ref().expect("usericon");
        assert_eq!(usericon.iconsetpath, "COT_MAPPING_2525B/a-f/a-f-G-U");

        let marti = evt.marti.as_ref().expect("marti");
        assert_eq!(marti.dest_callsigns, vec!["BRAVO", "CHARLIE"]);

        // Unknown element in residual
        assert!(evt.xml_detail.contains("unknownElement"));
        assert!(evt.xml_detail.contains("preserved"));

        // Typed elements should NOT be in residual
        assert!(!evt.xml_detail.contains("<link"));
        assert!(!evt.xml_detail.contains("<remarks"));
        assert!(!evt.xml_detail.contains("<color"));
        assert!(!evt.xml_detail.contains("<labels"));
        assert!(!evt.xml_detail.contains("<usericon"));
        assert!(!evt.xml_detail.contains("<marti"));
    }

    #[test]
    fn parse_self_closing_remarks_and_marti() {
        let xml = br#"<event uid="EMPTY-1" type="a-f-G">
            <detail>
                <remarks/>
                <marti/>
            </detail>
        </event>"#;

        let evt = parse_full(xml).expect("parse");
        let remarks = evt.remarks.expect("remarks");
        assert!(remarks.text.is_empty());
        assert!(remarks.source.is_none());

        let marti = evt.marti.expect("marti");
        assert!(marti.dest_callsigns.is_empty());
    }

    #[test]
    fn parse_self_closing_remarks_preserves_attributes() {
        let xml = br#"<event uid="REM-EMPTY-1" type="a-f-G">
            <detail>
                <remarks source="BAO.F.ATAK.SENDER" time="2021-01-01T00:00:00Z"/>
            </detail>
        </event>"#;

        let evt = parse_full(xml).expect("parse");
        let remarks = evt.remarks.expect("remarks");
        assert!(remarks.text.is_empty());
        assert_eq!(remarks.source.as_deref(), Some("BAO.F.ATAK.SENDER"));
        assert_eq!(remarks.timestamp.as_deref(), Some("2021-01-01T00:00:00Z"));
    }

    #[test]
    fn parse_full_accepts_wgs84_boundary_lat_lon() {
        // MP090284 Table 2-1: lat -90..=90, lon -180..=180. Exact extremes must parse.
        for (lat, lon) in [("-90", "-180"), ("90", "180"), ("0", "0")] {
            let xml = format!(
                r#"<event uid="U" type="a-f-G"><point lat="{lat}" lon="{lon}" hae="0" ce="1" le="1"/></event>"#
            );
            assert!(
                parse_full(xml.as_bytes()).is_ok(),
                "boundary ({lat}, {lon})"
            );
        }
    }

    #[test]
    fn parse_full_rejects_lat_out_of_range() {
        let xml = br#"<event uid="U" type="a-f-G"><point lat="90.5" lon="0" hae="0" ce="1" le="1"/></event>"#;
        let err = parse_full(xml).expect_err("lat > 90");
        assert!(matches!(err, ProtoError::OutOfRange { field: "lat", .. }));

        let xml = br#"<event uid="U" type="a-f-G"><point lat="-273.15" lon="0" hae="0" ce="1" le="1"/></event>"#;
        let err = parse_full(xml).expect_err("lat < -90");
        assert!(matches!(err, ProtoError::OutOfRange { field: "lat", .. }));
    }

    #[test]
    fn parse_full_rejects_lon_out_of_range() {
        let xml = br#"<event uid="U" type="a-f-G"><point lat="0" lon="180.1" hae="0" ce="1" le="1"/></event>"#;
        let err = parse_full(xml).expect_err("lon > 180");
        assert!(matches!(err, ProtoError::OutOfRange { field: "lon", .. }));

        let xml = br#"<event uid="U" type="a-f-G"><point lat="0" lon="-200" hae="0" ce="1" le="1"/></event>"#;
        let err = parse_full(xml).expect_err("lon < -180");
        assert!(matches!(err, ProtoError::OutOfRange { field: "lon", .. }));
    }

    #[test]
    fn parse_multiple_link_elements() {
        let xml = br#"<event uid="MULTI-LINK" type="a-f-G">
            <detail>
                <link uid="A" type="a-f-G" relation="p-p"/>
                <link uid="B" type="a-f-G" relation="p-s"/>
            </detail>
        </event>"#;

        let evt = parse_full(xml).expect("parse");
        assert_eq!(evt.link.len(), 2);
        assert_eq!(evt.link[0].uid, "A");
        assert_eq!(evt.link[0].relation, "p-p");
        assert_eq!(evt.link[1].uid, "B");
        assert_eq!(evt.link[1].relation, "p-s");
    }

    #[test]
    fn parse_full_captures_version_attribute() {
        // MITRE MP090284 Table 2-1 requires the `version` attribute on
        // `<event>`. The parser stores it verbatim so downstream wire
        // formats can round-trip the source schema version.
        let xml = br#"<event version="2.1" uid="VER-1" type="a-f-G" how="m-g" time="2021-02-27T20:32:24Z" start="2021-02-27T20:32:24Z" stale="2021-02-27T20:37:24Z">
            <point lat="0.0" lon="0.0" hae="0.0" ce="0.0" le="0.0"/>
        </event>"#;

        let evt = parse_full(xml).expect("parse");
        assert_eq!(evt.version, "2.1");
    }

    #[test]
    fn parse_full_version_empty_when_attribute_missing() {
        // Some non-conforming emitters omit the `version` attribute. The
        // parser tolerates this — the `FullCotEvent::version` field stays
        // empty, and downstream wire-format builders apply their own
        // default (e.g., "2.0") if a value is mandatory on their side.
        let xml = br#"<event uid="NO-VER" type="a-f-G">
            <point lat="0.0" lon="0.0" hae="0.0" ce="0.0" le="0.0"/>
        </event>"#;

        let evt = parse_full(xml).expect("parse");
        assert!(evt.version.is_empty());
    }

    // ── MITRE MP090284 Table 2-1 RFC 3339 timestamp validation ──────

    #[test]
    fn parse_full_accepts_rfc3339_timestamp_with_fractional_seconds() {
        let xml = br#"<event uid="TS-1" type="a-f-G" time="2026-02-26T12:00:00.500Z" start="2026-02-26T12:00:00.000Z" stale="2026-02-26T12:05:00.000Z"/>"#;
        let evt = parse_full(xml).expect("parse");
        assert_eq!(evt.time, "2026-02-26T12:00:00.500Z");
    }

    #[test]
    fn parse_full_accepts_rfc3339_timestamp_without_fractional_seconds() {
        let xml = br#"<event uid="TS-2" type="a-f-G" time="2026-02-26T12:00:00Z" start="2026-02-26T12:00:00Z" stale="2026-02-26T12:05:00Z"/>"#;
        let evt = parse_full(xml).expect("parse");
        assert_eq!(evt.stale, "2026-02-26T12:05:00Z");
    }

    #[test]
    fn parse_full_rejects_malformed_time_attribute() {
        // Missing `T` separator — not an RFC 3339 timestamp.
        let xml =
            br#"<event uid="TS-BAD-TIME" type="a-f-G" time="not-a-timestamp" stale="2026-02-26T12:05:00Z"/>"#;
        match parse_full(xml) {
            Err(ProtoError::InvalidTimestamp(msg)) => assert!(msg.starts_with("time:")),
            other => panic!("expected InvalidTimestamp for time, got {other:?}"),
        }
    }

    #[test]
    fn parse_full_rejects_malformed_start_attribute() {
        let xml = br#"<event uid="TS-BAD-START" type="a-f-G" start="2026-13-99T99:99:99Z" stale="2026-02-26T12:05:00Z"/>"#;
        match parse_full(xml) {
            Err(ProtoError::InvalidTimestamp(msg)) => assert!(msg.starts_with("start:")),
            other => panic!("expected InvalidTimestamp for start, got {other:?}"),
        }
    }

    #[test]
    fn parse_full_rejects_malformed_stale_attribute() {
        let xml = br#"<event uid="TS-BAD-STALE" type="a-f-G" stale="garbage"/>"#;
        match parse_full(xml) {
            Err(ProtoError::InvalidTimestamp(msg)) => assert!(msg.starts_with("stale:")),
            other => panic!("expected InvalidTimestamp for stale, got {other:?}"),
        }
    }

    #[test]
    fn parse_full_allows_omitted_timestamp_attributes() {
        // Omitting the attribute should not trip the validator (the
        // attribute simply never enters `parse_event_attrs`).
        let xml = br#"<event uid="TS-MISSING" type="a-f-G"/>"#;
        let evt = parse_full(xml).expect("parse");
        assert!(evt.time.is_empty());
        assert!(evt.start.is_empty());
        assert!(evt.stale.is_empty());
    }
}
