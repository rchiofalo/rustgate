//! XML CoT to TAK protobuf conversion.
//!
//! ## Field Mapping
//!
//! The following XML `<event>` attributes are explicitly mapped to protobuf
//! fields in `CotEvent`:
//!
//! | XML attribute | Proto field | Notes |
//! |---------------|-------------|-------|
//! | `uid` | `uid` | |
//! | `type` | `type` | |
//! | `how` | `how` | |
//! | `time` | `send_time` | ISO 8601 to milliseconds |
//! | `start` | `start_time` | ISO 8601 to milliseconds |
//! | `stale` | `stale_time` | ISO 8601 to milliseconds |
//! | `access` | `access` | |
//! | `qos` | `qos` | |
//! | `opex` | `opex` | |
//! | `<point>` lat/lon/hae/ce/le | corresponding proto fields | |
//!
//! ## Detail Mapping
//!
//! Known `<detail>` children are mapped to typed proto fields:
//!
//! - `<contact>` — `endpoint`, `callsign`
//! - `<__group>` — `name`, `role`
//! - `<precisionlocation>` — mapped to `PrecisionLocation`
//! - `<status>` — `battery`
//! - `<takv>` — `device`, `platform`, `os`, `version`
//! - `<track>` — `speed`, `course`
//!
//! ## Field Loss Behavior
//!
//! - **Unknown `<event>` attributes** (not listed above) are **silently
//!   discarded** during conversion. They do not appear in the protobuf
//!   output.
//! - **Unknown `<detail>` children** (elements not in the list above) are
//!   serialized back to XML and preserved in `Detail.xmlDetail`. This is a
//!   lossy process: attribute ordering and whitespace may change.
//! - **Nested attributes** within known detail elements that are not part
//!   of the proto schema are also discarded.
//! - The proto schema includes `caveat` and `releaseableTo` fields on
//!   `CotEvent`. These are **reserved but currently unmapped** — they are
//!   initialized to empty strings during conversion. If the source XML
//!   contains corresponding attributes, they will be discarded.
//!
//! This behavior is by design — the protobuf schema defines a fixed set of
//! fields, and XML attributes outside that set have no corresponding
//! representation.

use prost::Message;

use super::timestamp::iso8601_to_millis;
use crate::error::ProtoError;
use crate::{tak_proto, xml_full};

/// Convert raw CoT XML bytes to serialized TakMessage protobuf bytes.
///
/// Parses the XML fully, maps all fields to protobuf types, and packages
/// unknown detail children into `Detail.xmlDetail`. See the [module-level
/// documentation](self) for the complete field mapping and loss behavior.
pub fn xml_to_proto(xml: &[u8]) -> Result<Vec<u8>, ProtoError> {
    let full = xml_full::parse_full(xml)?;
    let cot_event = full_to_cot_event(&full)?;
    let tak_message = tak_proto::TakMessage {
        tak_control: None,
        cot_event: Some(cot_event),
    };

    let mut buf = Vec::with_capacity(tak_message.encoded_len());
    tak_message.encode(&mut buf)?;
    Ok(buf)
}

fn full_to_cot_event(full: &xml_full::FullCotEvent) -> Result<tak_proto::CotEvent, ProtoError> {
    let send_time = if full.time.is_empty() {
        0
    } else {
        iso8601_to_millis(&full.time)?
    };
    let start_time = if full.start.is_empty() {
        0
    } else {
        iso8601_to_millis(&full.start)?
    };
    let stale_time = if full.stale.is_empty() {
        0
    } else {
        iso8601_to_millis(&full.stale)?
    };

    let detail = build_detail(full);

    Ok(tak_proto::CotEvent {
        r#type: full.event_type.clone(),
        access: full.access.clone(),
        qos: full.qos.clone(),
        opex: full.opex.clone(),
        uid: full.uid.clone(),
        send_time,
        start_time,
        stale_time,
        how: full.how.clone(),
        lat: full.lat,
        lon: full.lon,
        hae: full.hae,
        ce: full.ce,
        le: full.le,
        detail: Some(detail),
        caveat: String::new(),
        releaseable_to: String::new(),
    })
}

fn build_detail(full: &xml_full::FullCotEvent) -> tak_proto::Detail {
    let contact = full.contact.as_ref().map(|c| tak_proto::Contact {
        endpoint: c.endpoint.clone(),
        callsign: c.callsign.clone(),
    });

    let group = full.group.as_ref().map(|g| tak_proto::Group {
        name: g.name.clone(),
        role: g.role.clone(),
    });

    let precision_location =
        full.precision_location
            .as_ref()
            .map(|p| tak_proto::PrecisionLocation {
                geopointsrc: p.geopointsrc.clone(),
                altsrc: p.altsrc.clone(),
            });

    let status = full
        .status
        .as_ref()
        .map(|s| tak_proto::Status { battery: s.battery });

    let takv = full.takv.as_ref().map(|t| tak_proto::Takv {
        device: t.device.clone(),
        platform: t.platform.clone(),
        os: t.os.clone(),
        version: t.version.clone(),
    });

    let track = full.track.as_ref().map(|t| tak_proto::Track {
        speed: t.speed,
        course: t.course,
    });

    // Typed detail elements without protobuf counterparts are serialized
    // back into xml_detail so they survive the XML -> proto -> XML round-trip.
    let mut xml_detail = full.xml_detail.clone();
    serialize_typed_details_to_xml(full, &mut xml_detail);

    tak_proto::Detail {
        xml_detail,
        contact,
        group,
        precision_location,
        status,
        takv,
        track,
    }
}

/// Serialize typed detail fields that have no protobuf counterpart back into
/// the xml_detail string so they survive proto round-trips.
fn serialize_typed_details_to_xml(full: &xml_full::FullCotEvent, buf: &mut String) {
    for link in &full.link {
        buf.push_str("<link");
        push_xml_attr(buf, "relation", &link.relation);
        push_xml_attr(buf, "type", &link.link_type);
        push_xml_attr(buf, "uid", &link.uid);
        if let Some(ref pc) = link.parent_callsign {
            push_xml_attr(buf, "parent_callsign", pc);
        }
        if let Some(ref pt) = link.production_time {
            push_xml_attr(buf, "production_time", pt);
        }
        buf.push_str("/>");
    }

    if let Some(ref remarks) = full.remarks {
        buf.push_str("<remarks");
        if let Some(ref src) = remarks.source {
            push_xml_attr(buf, "source", src);
        }
        if let Some(ref ts) = remarks.timestamp {
            push_xml_attr(buf, "time", ts);
        }
        if remarks.text.is_empty() {
            buf.push_str("/>");
        } else {
            buf.push('>');
            xml_escape_attr_into(buf, &remarks.text);
            buf.push_str("</remarks>");
        }
    }

    if let Some(ref color) = full.color {
        buf.push_str("<color");
        if let Some(argb) = color.argb {
            push_xml_attr(buf, "argb", &argb.to_string());
        }
        buf.push_str("/>");
    }

    if let Some(ref labels) = full.labels {
        buf.push_str("<labels");
        push_xml_attr(buf, "value", &labels.value);
        buf.push_str("/>");
    }

    if let Some(ref usericon) = full.usericon {
        buf.push_str("<usericon");
        push_xml_attr(buf, "iconsetpath", &usericon.iconsetpath);
        buf.push_str("/>");
    }

    if let Some(ref marti) = full.marti {
        if marti.dest_callsigns.is_empty() {
            buf.push_str("<marti/>");
        } else {
            buf.push_str("<marti>");
            for cs in &marti.dest_callsigns {
                buf.push_str("<dest");
                push_xml_attr(buf, "callsign", cs);
                buf.push_str("/>");
            }
            buf.push_str("</marti>");
        }
    }
}

/// Append ` key="value"` to an XML buffer with proper escaping.
fn push_xml_attr(buf: &mut String, key: &str, value: &str) {
    buf.push(' ');
    buf.push_str(key);
    buf.push_str("=\"");
    xml_escape_attr_into(buf, value);
    buf.push('"');
}

/// Escape special XML characters in attribute values to prevent injection.
fn xml_escape_attr_into(buf: &mut String, s: &str) {
    for c in s.chars() {
        match c {
            '&' => buf.push_str("&amp;"),
            '<' => buf.push_str("&lt;"),
            '>' => buf.push_str("&gt;"),
            '"' => buf.push_str("&quot;"),
            _ => buf.push(c),
        }
    }
}
