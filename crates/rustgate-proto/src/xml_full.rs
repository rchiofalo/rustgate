//! Full CoT XML parser extracting all protobuf-mappable fields.
//!
//! # Security
//!
//! Uses `quick-xml` streaming parser which does not resolve external entities
//! or process DTD declarations, preventing XXE injection.

use quick_xml::events::Event;
use quick_xml::Reader;

use crate::error::ProtoError;

/// Complete CoT event with all fields needed for protobuf conversion.
#[derive(Debug, Clone, Default)]
pub struct FullCotEvent {
    // <event> attributes
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

    /// Residual XML: children of `<detail>` that are NOT known typed elements.
    /// Does not include the outer `<detail>` tags per TAK protobuf spec.
    pub xml_detail: String,
}

#[derive(Debug, Clone, Default)]
pub struct ContactDetail {
    pub endpoint: String,
    pub callsign: String,
}

#[derive(Debug, Clone, Default)]
pub struct GroupDetail {
    pub name: String,
    pub role: String,
}

#[derive(Debug, Clone, Default)]
pub struct PrecisionLocationDetail {
    pub geopointsrc: String,
    pub altsrc: String,
}

#[derive(Debug, Clone, Default)]
pub struct StatusDetail {
    pub battery: u32,
}

#[derive(Debug, Clone, Default)]
pub struct TakvDetail {
    pub device: String,
    pub platform: String,
    pub os: String,
    pub version: String,
}

#[derive(Debug, Clone, Default)]
pub struct TrackDetail {
    pub speed: f64,
    pub course: f64,
}

/// Parse CoT XML into a [`FullCotEvent`] with all protobuf-mappable fields.
pub fn parse_full(xml: &[u8]) -> Result<FullCotEvent, ProtoError> {
    let mut reader = Reader::from_reader(xml);
    reader.config_mut().trim_text(true);

    let mut event = FullCotEvent::default();
    let mut buf = Vec::new();
    let mut in_detail = false;
    let mut xml_detail_buf = Vec::<u8>::new();

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
                    } else {
                        capture_unknown_start(e, &mut reader, &mut xml_detail_buf)?;
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
                    } else {
                        capture_unknown_empty(e, &mut xml_detail_buf);
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
        b"contact" | b"__group" | b"precisionlocation" | b"status" | b"takv" | b"track"
    )
}

fn parse_event_attrs(
    e: &quick_xml::events::BytesStart<'_>,
    event: &mut FullCotEvent,
) -> Result<(), ProtoError> {
    for attr in e.attributes().flatten() {
        let value = String::from_utf8_lossy(&attr.value).into_owned();
        match attr.key.as_ref() {
            b"uid" => event.uid = value,
            b"type" => event.event_type = value,
            b"how" => event.how = value,
            b"time" => event.time = value,
            b"start" => event.start = value,
            b"stale" => event.stale = value,
            b"access" => event.access = value,
            b"qos" => event.qos = value,
            b"opex" => event.opex = value,
            _ => {}
        }
    }
    Ok(())
}

fn parse_point_attrs(
    e: &quick_xml::events::BytesStart<'_>,
    event: &mut FullCotEvent,
) -> Result<(), ProtoError> {
    for attr in e.attributes().flatten() {
        let value_str = String::from_utf8_lossy(&attr.value);
        match attr.key.as_ref() {
            b"lat" => event.lat = parse_f64(&value_str)?,
            b"lon" => event.lon = parse_f64(&value_str)?,
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

/// Parse a known detail child element that was a Start event (has children).
fn parse_known_start(
    tag: &[u8],
    e: &quick_xml::events::BytesStart<'_>,
    reader: &mut Reader<&[u8]>,
    event: &mut FullCotEvent,
) -> Result<(), ProtoError> {
    match tag {
        b"contact" => event.contact = Some(parse_contact(e)),
        b"__group" => event.group = Some(parse_group(e)),
        b"precisionlocation" => event.precision_location = Some(parse_precision_location(e)),
        b"status" => event.status = Some(parse_status(e)),
        b"takv" => event.takv = Some(parse_takv(e)),
        b"track" => event.track = Some(parse_track(e)),
        _ => {}
    }
    // Consume the closing tag (and any nested content we don't care about)
    let mut skip_buf = Vec::new();
    let _ = reader.read_to_end_into(e.to_end().name(), &mut skip_buf)?;
    Ok(())
}

/// Parse a known detail child element that was an Empty event (self-closing).
fn parse_known_empty(
    tag: &[u8],
    e: &quick_xml::events::BytesStart<'_>,
    event: &mut FullCotEvent,
) {
    match tag {
        b"contact" => event.contact = Some(parse_contact(e)),
        b"__group" => event.group = Some(parse_group(e)),
        b"precisionlocation" => event.precision_location = Some(parse_precision_location(e)),
        b"status" => event.status = Some(parse_status(e)),
        b"takv" => event.takv = Some(parse_takv(e)),
        b"track" => event.track = Some(parse_track(e)),
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
fn capture_unknown_empty(
    e: &quick_xml::events::BytesStart<'_>,
    xml_detail_buf: &mut Vec<u8>,
) {
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
    fn parse_full_with_xml_detail_residual() {
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
        assert!(evt.xml_detail.contains("marti"));
        assert!(evt.xml_detail.contains("BRAVO"));
        assert!(evt.xml_detail.contains("remarks"));
        assert!(evt.xml_detail.contains("test note"));
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
}
