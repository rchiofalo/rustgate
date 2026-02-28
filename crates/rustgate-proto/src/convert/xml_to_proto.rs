//! XML CoT -> TAK protobuf conversion.

use prost::Message;

use crate::error::ProtoError;
use crate::tak_proto;
use crate::xml_full;

use super::timestamp::iso8601_to_millis;

/// Convert raw CoT XML bytes to serialized TakMessage protobuf bytes.
///
/// Parses the XML fully, maps all fields to protobuf types, and packages
/// unknown detail children into `Detail.xmlDetail`.
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

    tak_proto::Detail {
        xml_detail: full.xml_detail.clone(),
        contact,
        group,
        precision_location,
        status,
        takv,
        track,
    }
}
