// Copyright © 2026 Roberto Chiofalo.

//! TAK protobuf -> XML CoT conversion.

use prost::Message;

use super::timestamp::millis_to_iso8601;
use crate::error::ProtoError;
use crate::tak_proto;

/// Convert serialized TakMessage protobuf bytes to CoT XML bytes.
///
/// Reconstructs the full XML document including typed detail elements
/// and any residual `xmlDetail` content.
pub fn proto_to_xml(proto_bytes: &[u8]) -> Result<Vec<u8>, ProtoError> {
    let tak_message = tak_proto::TakMessage::decode(proto_bytes)?;
    let cot = tak_message
        .cot_event
        .ok_or(ProtoError::MissingField("cotEvent"))?;
    build_xml(&cot)
}

fn build_xml(cot: &tak_proto::CotEvent) -> Result<Vec<u8>, ProtoError> {
    let mut xml = Vec::with_capacity(512);

    // <event> opening tag with attributes
    xml.extend_from_slice(b"<event version=\"2.0\"");
    write_attr(&mut xml, "uid", &cot.uid);
    write_attr(&mut xml, "type", &cot.r#type);

    if !cot.how.is_empty() {
        write_attr(&mut xml, "how", &cot.how);
    }

    if cot.send_time > 0 {
        write_attr(&mut xml, "time", &millis_to_iso8601(cot.send_time));
    }
    if cot.start_time > 0 {
        write_attr(&mut xml, "start", &millis_to_iso8601(cot.start_time));
    }
    if cot.stale_time > 0 {
        write_attr(&mut xml, "stale", &millis_to_iso8601(cot.stale_time));
    }

    if !cot.access.is_empty() {
        write_attr(&mut xml, "access", &cot.access);
    }
    if !cot.qos.is_empty() {
        write_attr(&mut xml, "qos", &cot.qos);
    }
    if !cot.opex.is_empty() {
        write_attr(&mut xml, "opex", &cot.opex);
    }

    xml.push(b'>');

    // <point> element
    let point = format!(
        "<point lat=\"{}\" lon=\"{}\" hae=\"{}\" ce=\"{}\" le=\"{}\"/>",
        cot.lat, cot.lon, cot.hae, cot.ce, cot.le
    );
    xml.extend_from_slice(point.as_bytes());

    // <detail> element
    let detail = cot.detail.as_ref();
    let has_detail = detail.is_some_and(|d| {
        !d.xml_detail.is_empty()
            || d.contact.is_some()
            || d.group.is_some()
            || d.precision_location.is_some()
            || d.status.is_some()
            || d.takv.is_some()
            || d.track.is_some()
    });

    if has_detail {
        xml.extend_from_slice(b"<detail>");

        if let Some(d) = detail {
            // Typed sub-elements
            if let Some(ref c) = d.contact {
                write_contact(&mut xml, c);
            }
            if let Some(ref g) = d.group {
                write_group(&mut xml, g);
            }
            if let Some(ref p) = d.precision_location {
                write_precision_location(&mut xml, p);
            }
            if let Some(ref s) = d.status {
                write_status(&mut xml, s);
            }
            if let Some(ref t) = d.takv {
                write_takv(&mut xml, t);
            }
            if let Some(ref t) = d.track {
                write_track(&mut xml, t);
            }

            // Residual xmlDetail (raw XML fragment per the TAK protobuf spec).
            // Validate it's well-formed before embedding — a crafted protobuf
            // message could contain closing tags (</detail>, </event>) that
            // would break the enclosing document structure.
            if !d.xml_detail.is_empty() && is_safe_xml_fragment(&d.xml_detail) {
                xml.extend_from_slice(d.xml_detail.as_bytes());
            }
        }

        xml.extend_from_slice(b"</detail>");
    }

    xml.extend_from_slice(b"</event>");
    Ok(xml)
}

fn write_attr(xml: &mut Vec<u8>, name: &str, value: &str) {
    xml.push(b' ');
    xml.extend_from_slice(name.as_bytes());
    xml.extend_from_slice(b"=\"");
    xml_escape_into(xml, value);
    xml.push(b'"');
}

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

fn write_contact(xml: &mut Vec<u8>, c: &tak_proto::Contact) {
    xml.extend_from_slice(b"<contact");
    if !c.callsign.is_empty() {
        write_attr(xml, "callsign", &c.callsign);
    }
    if !c.endpoint.is_empty() {
        write_attr(xml, "endpoint", &c.endpoint);
    }
    xml.extend_from_slice(b"/>");
}

fn write_group(xml: &mut Vec<u8>, g: &tak_proto::Group) {
    xml.extend_from_slice(b"<__group");
    if !g.name.is_empty() {
        write_attr(xml, "name", &g.name);
    }
    if !g.role.is_empty() {
        write_attr(xml, "role", &g.role);
    }
    xml.extend_from_slice(b"/>");
}

fn write_precision_location(xml: &mut Vec<u8>, p: &tak_proto::PrecisionLocation) {
    xml.extend_from_slice(b"<precisionlocation");
    if !p.geopointsrc.is_empty() {
        write_attr(xml, "geopointsrc", &p.geopointsrc);
    }
    if !p.altsrc.is_empty() {
        write_attr(xml, "altsrc", &p.altsrc);
    }
    xml.extend_from_slice(b"/>");
}

fn write_status(xml: &mut Vec<u8>, s: &tak_proto::Status) {
    xml.extend_from_slice(b"<status");
    write_attr(xml, "battery", &s.battery.to_string());
    xml.extend_from_slice(b"/>");
}

fn write_takv(xml: &mut Vec<u8>, t: &tak_proto::Takv) {
    xml.extend_from_slice(b"<takv");
    if !t.device.is_empty() {
        write_attr(xml, "device", &t.device);
    }
    if !t.platform.is_empty() {
        write_attr(xml, "platform", &t.platform);
    }
    if !t.os.is_empty() {
        write_attr(xml, "os", &t.os);
    }
    if !t.version.is_empty() {
        write_attr(xml, "version", &t.version);
    }
    xml.extend_from_slice(b"/>");
}

fn write_track(xml: &mut Vec<u8>, t: &tak_proto::Track) {
    xml.extend_from_slice(b"<track");
    write_attr(xml, "speed", &t.speed.to_string());
    write_attr(xml, "course", &t.course.to_string());
    xml.extend_from_slice(b"/>");
}

/// Validate that an xmlDetail string is a well-formed XML fragment
/// that won't break the enclosing `<detail>` element.
///
/// Wraps the fragment in a temporary root element and attempts to parse it
/// with quick_xml. Rejects malformed XML and structural injection attempts
/// (e.g., `</detail></event><evil/>`).
fn is_safe_xml_fragment(fragment: &str) -> bool {
    use quick_xml::Reader;
    use quick_xml::events::Event;

    let wrapped = format!("<_r>{fragment}</_r>");
    let mut reader = Reader::from_reader(wrapped.as_bytes());
    reader.config_mut().trim_text(false);
    let mut buf = Vec::new();
    loop {
        buf.clear();
        match reader.read_event_into(&mut buf) {
            Ok(Event::Eof) => return true,
            Err(_) => return false,
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_xml_fragment_valid() {
        assert!(is_safe_xml_fragment(
            "<marti><dest callsign=\"BRAVO\"/></marti>"
        ));
        assert!(is_safe_xml_fragment("<remarks>test note</remarks>"));
        assert!(is_safe_xml_fragment("<custom attr=\"val\"/>"));
        assert!(is_safe_xml_fragment(""));
    }

    #[test]
    fn safe_xml_fragment_rejects_structural_injection() {
        // Closing ancestor tags would corrupt the document
        assert!(!is_safe_xml_fragment("</detail></event><evil/>"));
        assert!(!is_safe_xml_fragment("</detail>"));
        assert!(!is_safe_xml_fragment("<ok/></detail>"));
    }

    #[test]
    fn safe_xml_fragment_rejects_malformed() {
        assert!(!is_safe_xml_fragment("<unclosed>"));
        assert!(!is_safe_xml_fragment("<a><b></a></b>"));
    }

    #[test]
    fn xml_detail_injection_dropped_in_output() {
        // Build a protobuf message with malicious xmlDetail
        let cot = tak_proto::CotEvent {
            uid: "ATTACKER".into(),
            r#type: "a-f-G".into(),
            detail: Some(tak_proto::Detail {
                xml_detail: "</detail></event><injected/>".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let xml = build_xml(&cot).expect("build_xml");
        let xml_str = std::str::from_utf8(&xml).expect("utf8");

        // The injected content should NOT appear in the output
        assert!(
            !xml_str.contains("<injected"),
            "injection should be dropped: {xml_str}"
        );
        // But the document should still be well-formed
        assert!(xml_str.contains("</detail>"));
        assert!(xml_str.contains("</event>"));
    }
}
