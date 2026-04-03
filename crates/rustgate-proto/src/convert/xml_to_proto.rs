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
