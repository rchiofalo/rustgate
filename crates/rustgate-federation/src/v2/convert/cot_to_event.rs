// Copyright © 2026 Roberto Chiofalo.

//! CoT XML ↔ `FederatedEvent` (proto) conversions.
//!
//! Converts between raw CoT XML bytes and the V2 gRPC `FederatedEvent`
//! protobuf type, including flow-tag injection and contact-list entry
//! generation.

use bytes::Bytes;
use rustgate_proto::{FullCotEvent, parse_full};

use super::proto::figpb;
use super::timestamps::{format_timestamp_millis, parse_timestamp_millis};
use super::{ConvertError, write_attr, xml_escape};
use crate::provenance::FederationMetadata;

// ---------------------------------------------------------------------------
// CoT XML → FederatedEvent
// ---------------------------------------------------------------------------

/// Convert raw CoT XML bytes into a `FederatedEvent`.
///
/// Parses the XML with the full parser, extracts all mappable fields into
/// a `GeoEvent`, and wraps the result in a `FederatedEvent` with the
/// provided federation metadata (provenance, hops).
pub fn xml_to_federated_event(
    xml: &[u8],
    metadata: &FederationMetadata,
) -> Result<figpb::FederatedEvent, ConvertError> {
    let full = parse_full(xml)?;
    let geo = full_cot_to_geo_event(&full)?;

    // Extract group from the CoT detail's __group element
    let groups = match &full.group {
        Some(g) if !g.name.is_empty() => vec![g.name.clone()],
        _ => Vec::new(),
    };

    Ok(figpb::FederatedEvent {
        event: Some(geo),
        contact: None, // ContactListEntry is for contact list ops, not position reports
        federate_groups: groups,
        federate_provenance: metadata
            .provenance
            .iter()
            .map(|p| figpb::FederateProvenance {
                federation_server_id: p.server_id.as_str().to_owned(),
                federation_server_name: p.server_name.as_str().to_owned(),
            })
            .collect(),
        federate_hops: Some(figpb::FederateHops {
            max_hops: i64::from(metadata.max_hops),
            current_hops: i64::from(metadata.current_hops),
        }),
        federate_group_hop_limits: None,
    })
}

/// Build a `GeoEvent` from a fully parsed CoT XML event.
fn full_cot_to_geo_event(full: &FullCotEvent) -> Result<figpb::GeoEvent, ConvertError> {
    let send_time = parse_timestamp_millis(&full.time)?;
    let start_time = parse_timestamp_millis(&full.start)?;
    let stale_time = parse_timestamp_millis(&full.stale)?;

    Ok(figpb::GeoEvent {
        send_time,
        start_time,
        stale_time,
        lat: full.lat,
        lon: full.lon,
        hae: full.hae,
        ce: full.ce,
        le: full.le,
        uid: full.uid.clone(),
        r#type: full.event_type.clone(),
        coord_source: full
            .precision_location
            .as_ref()
            .map_or_else(String::new, |p| p.geopointsrc.clone()),
        other: full.xml_detail.clone(),
        battery: full.status.as_ref().map_or(0, |s| s.battery as i32),
        ploc: full
            .precision_location
            .as_ref()
            .map_or_else(String::new, |p| p.geopointsrc.clone()),
        palt: full
            .precision_location
            .as_ref()
            .map_or_else(String::new, |p| p.altsrc.clone()),
        screen_name: full
            .contact
            .as_ref()
            .map_or_else(String::new, |c| c.callsign.clone()),
        group_name: full
            .group
            .as_ref()
            .map_or_else(String::new, |g| g.name.clone()),
        group_role: full
            .group
            .as_ref()
            .map_or_else(String::new, |g| g.role.clone()),
        phone: String::new(),
        speed: full.track.as_ref().map_or(0.0, |t| t.speed),
        course: full.track.as_ref().map_or(0.0, |t| t.course),
        binary: None,
        ptp_uids: Vec::new(),
        ptp_callsigns: Vec::new(),
        feed_uid: String::new(),
        mission_names: Vec::new(),
        access: full.access.clone(),
        caveat: String::new(),
        releaseable_to: String::new(),
        bloads: Vec::new(),
    })
}

// ---------------------------------------------------------------------------
// FederatedEvent → CoT XML
// ---------------------------------------------------------------------------

/// Convert a `FederatedEvent` back into CoT XML bytes.
///
/// Reconstructs the full `<event>` XML document from the `GeoEvent` fields,
/// including typed detail elements (contact, group, track, etc.) and any
/// residual XML stored in the `other` field.
pub fn federated_event_to_xml(event: &figpb::FederatedEvent) -> Result<Vec<u8>, ConvertError> {
    let geo = event
        .event
        .as_ref()
        .ok_or(ConvertError::MissingField("event"))?;

    let mut xml = Vec::with_capacity(512);

    // <event> opening
    xml.extend_from_slice(b"<event version=\"2.0\"");
    write_attr(&mut xml, "uid", &geo.uid);
    write_attr(&mut xml, "type", &geo.r#type);

    // Timestamps
    let time_str = format_timestamp_millis(geo.send_time);
    if !time_str.is_empty() {
        write_attr(&mut xml, "time", &time_str);
    }
    let start_str = format_timestamp_millis(geo.start_time);
    if !start_str.is_empty() {
        write_attr(&mut xml, "start", &start_str);
    }
    let stale_str = format_timestamp_millis(geo.stale_time);
    if !stale_str.is_empty() {
        write_attr(&mut xml, "stale", &stale_str);
    }

    if !geo.access.is_empty() {
        write_attr(&mut xml, "access", &geo.access);
    }

    // Default how to "m-g" if not recoverable from the other field
    write_attr(&mut xml, "how", "m-g");
    xml.push(b'>');

    // <point>
    let point = format!(
        "<point lat=\"{}\" lon=\"{}\" hae=\"{}\" ce=\"{}\" le=\"{}\"/>",
        geo.lat, geo.lon, geo.hae, geo.ce, geo.le
    );
    xml.extend_from_slice(point.as_bytes());

    // <detail>
    let has_detail = !geo.screen_name.is_empty()
        || !geo.group_name.is_empty()
        || geo.speed != 0.0
        || geo.course != 0.0
        || !geo.coord_source.is_empty()
        || geo.battery != 0
        || !geo.other.is_empty();

    if has_detail {
        xml.extend_from_slice(b"<detail>");

        if !geo.screen_name.is_empty() {
            xml.extend_from_slice(b"<contact");
            write_attr(&mut xml, "callsign", &geo.screen_name);
            xml.extend_from_slice(b"/>");
        }

        if !geo.group_name.is_empty() {
            xml.extend_from_slice(b"<__group");
            write_attr(&mut xml, "name", &geo.group_name);
            if !geo.group_role.is_empty() {
                write_attr(&mut xml, "role", &geo.group_role);
            }
            xml.extend_from_slice(b"/>");
        }

        if geo.speed != 0.0 || geo.course != 0.0 {
            xml.extend_from_slice(b"<track");
            write_attr(&mut xml, "speed", &geo.speed.to_string());
            write_attr(&mut xml, "course", &geo.course.to_string());
            xml.extend_from_slice(b"/>");
        }

        if !geo.coord_source.is_empty() {
            xml.extend_from_slice(b"<precisionlocation");
            write_attr(&mut xml, "geopointsrc", &geo.coord_source);
            if !geo.palt.is_empty() {
                write_attr(&mut xml, "altsrc", &geo.palt);
            }
            xml.extend_from_slice(b"/>");
        }

        if geo.battery != 0 {
            xml.extend_from_slice(b"<status");
            write_attr(&mut xml, "battery", &geo.battery.to_string());
            xml.extend_from_slice(b"/>");
        }

        // Residual XML detail (validated by the parser on the way in)
        if !geo.other.is_empty() {
            xml.extend_from_slice(geo.other.as_bytes());
        }

        xml.extend_from_slice(b"</detail>");
    }

    xml.extend_from_slice(b"</event>");
    Ok(xml)
}

// ---------------------------------------------------------------------------
// Flow tag injection
// ---------------------------------------------------------------------------

/// Inject a `<_flow-tags_>` element into a CoT XML payload for traceability.
///
/// The flow tag records which federation server processed the message and when.
/// If the XML has a `</detail>` section, the tag is inserted before it.
/// If there is no `<detail>` section but `</event>` exists, a new `<detail>`
/// section is created containing the flow tag.
///
/// Returns the original `Bytes` (refcount-cloned) when no marker is found
/// or when the payload is not valid UTF-8 — both fast paths skip the
/// per-message `Vec<u8>` allocation that the previous `Vec<u8>`-returning
/// signature forced. When a marker is present, builds a fresh allocation
/// containing the spliced output and converts to `Bytes` once.
pub fn add_flow_tag(data: &Bytes, source: &str) -> Bytes {
    let s = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return data.clone(),
    };

    let now = time::OffsetDateTime::now_utc();
    let ts = now
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string());

    let flow_tag = format!(
        r#"<_flow-tags_><source name="{}" ts="{}"/></_flow-tags_>"#,
        xml_escape(source),
        ts,
    );

    if let Some(pos) = s.find("</detail>") {
        // Insert flow tag before </detail>
        let mut result = String::with_capacity(s.len() + flow_tag.len());
        result.push_str(&s[..pos]);
        result.push_str(&flow_tag);
        result.push_str(&s[pos..]);
        Bytes::from(result.into_bytes())
    } else if let Some(pos) = s.find("</event>") {
        // No detail section — wrap flow tag in a new detail element
        let mut result = String::with_capacity(s.len() + flow_tag.len() + 17);
        result.push_str(&s[..pos]);
        result.push_str("<detail>");
        result.push_str(&flow_tag);
        result.push_str("</detail>");
        result.push_str(&s[pos..]);
        Bytes::from(result.into_bytes())
    } else {
        data.clone()
    }
}

// ---------------------------------------------------------------------------
// ContactListEntry → CoT XML
// ---------------------------------------------------------------------------

/// Convert a `ContactListEntry` into a synthetic CoT XML message.
///
/// Contact deletions produce a `t-x-d-d` event type; creates and updates
/// produce `a-f-G-U-C`. Returns `None` if the contact has no UID.
///
/// The generated XML uses zero coordinates with maximum CE/LE to indicate
/// unknown position, and a 5-minute stale window.
pub fn contact_list_entry_to_xml(contact: &figpb::ContactListEntry) -> Option<Vec<u8>> {
    if contact.uid.is_empty() {
        return None;
    }

    let now = time::OffsetDateTime::now_utc();
    let stale = now + time::Duration::minutes(5);

    let fmt = &time::format_description::well_known::Rfc3339;
    let now_str = now.format(fmt).unwrap_or_default();
    let stale_str = stale.format(fmt).unwrap_or_default();

    // DELETE operation → t-x-d-d; everything else → a-f-G-U-C
    let cot_type = if contact.operation == figpb::Crud::Delete as i32 {
        "t-x-d-d"
    } else {
        "a-f-G-U-C"
    };

    let mut xml = Vec::with_capacity(512);
    xml.extend_from_slice(b"<event version=\"2.0\"");
    write_attr(&mut xml, "uid", &contact.uid);
    write_attr(&mut xml, "type", cot_type);
    write_attr(&mut xml, "time", &now_str);
    write_attr(&mut xml, "start", &now_str);
    write_attr(&mut xml, "stale", &stale_str);
    write_attr(&mut xml, "how", "h-e");
    xml.extend_from_slice(b">");

    // Unknown location
    xml.extend_from_slice(
        b"<point lat=\"0.0\" lon=\"0.0\" hae=\"0.0\" ce=\"9999999\" le=\"9999999\"/>",
    );

    xml.extend_from_slice(b"<detail>");

    // <contact callsign="..." [phone="..."] [sipAddress="..."] [endpoint="..."]/>
    xml.extend_from_slice(b"<contact");
    write_attr(&mut xml, "callsign", &contact.callsign);
    if !contact.phone.is_empty() {
        write_attr(&mut xml, "phone", &contact.phone);
    }
    if !contact.sip.is_empty() {
        write_attr(&mut xml, "sipAddress", &contact.sip);
    }
    if !contact.direct_connect.is_empty() {
        write_attr(&mut xml, "endpoint", &contact.direct_connect);
    }
    xml.extend_from_slice(b"/>");

    xml.extend_from_slice(b"</detail></event>");
    Some(xml)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use super::*;
    use crate::provenance::FederationMetadata;

    fn sample_xml() -> &'static [u8] {
        b"<event version=\"2.0\" uid=\"ALPHA-1\" type=\"a-f-G-U-C\" how=\"m-g\" \
          time=\"2021-02-27T20:32:24.000Z\" start=\"2021-02-27T20:32:24.000Z\" \
          stale=\"2021-02-27T20:37:24.000Z\">\
          <point lat=\"38.8977\" lon=\"-77.0365\" hae=\"10.5\" ce=\"50.0\" le=\"30.0\"/>\
          <detail>\
            <contact callsign=\"ALPHA\" endpoint=\"*:-1:stcp\"/>\
            <__group name=\"Cyan\" role=\"Team Lead\"/>\
            <track speed=\"10.5\" course=\"90.0\"/>\
            <precisionlocation geopointsrc=\"GPS\" altsrc=\"GPS\"/>\
            <status battery=\"85\"/>\
          </detail>\
          </event>"
    }

    fn empty_metadata() -> FederationMetadata {
        FederationMetadata {
            provenance: Vec::new(),
            max_hops: 10,
            current_hops: 0,
        }
    }

    fn sample_metadata() -> FederationMetadata {
        FederationMetadata {
            provenance: vec![crate::provenance::FederateProvenance {
                server_id: rustgate_core::PeerId::new("server-1"),
                server_name: rustgate_core::ServerName::new("Server One"),
            }],
            max_hops: 10,
            current_hops: 1,
        }
    }

    // --- xml_to_federated_event tests ---

    #[test]
    fn xml_to_event_uid_preserved() {
        let event = xml_to_federated_event(sample_xml(), &empty_metadata()).expect("conversion");
        let geo = event.event.as_ref().expect("geo event");
        assert_eq!(geo.uid, "ALPHA-1");
    }

    #[test]
    fn xml_to_event_type_preserved() {
        let event = xml_to_federated_event(sample_xml(), &empty_metadata()).expect("conversion");
        let geo = event.event.as_ref().expect("geo event");
        assert_eq!(geo.r#type, "a-f-G-U-C");
    }

    #[test]
    fn xml_to_event_coordinates() {
        let event = xml_to_federated_event(sample_xml(), &empty_metadata()).expect("conversion");
        let geo = event.event.as_ref().expect("geo event");
        assert!((geo.lat - 38.8977).abs() < 0.0001);
        assert!((geo.lon - (-77.0365)).abs() < 0.0001);
        assert!((geo.hae - 10.5).abs() < 0.001);
        assert!((geo.ce - 50.0).abs() < 0.001);
        assert!((geo.le - 30.0).abs() < 0.001);
    }

    #[test]
    fn xml_to_event_timestamps() {
        let event = xml_to_federated_event(sample_xml(), &empty_metadata()).expect("conversion");
        let geo = event.event.as_ref().expect("geo event");
        assert!(geo.send_time > 0);
        assert!(geo.start_time > 0);
        assert!(geo.stale_time > 0);
        assert!(geo.stale_time > geo.start_time);
    }

    #[test]
    fn xml_to_event_contact_fields() {
        let event = xml_to_federated_event(sample_xml(), &empty_metadata()).expect("conversion");
        let geo = event.event.as_ref().expect("geo event");
        assert_eq!(geo.screen_name, "ALPHA");
    }

    #[test]
    fn xml_to_event_group_fields() {
        let event = xml_to_federated_event(sample_xml(), &empty_metadata()).expect("conversion");
        let geo = event.event.as_ref().expect("geo event");
        assert_eq!(geo.group_name, "Cyan");
        assert_eq!(geo.group_role, "Team Lead");
        assert_eq!(event.federate_groups, vec!["Cyan"]);
    }

    #[test]
    fn xml_to_event_track_fields() {
        let event = xml_to_federated_event(sample_xml(), &empty_metadata()).expect("conversion");
        let geo = event.event.as_ref().expect("geo event");
        assert!((geo.speed - 10.5).abs() < 0.001);
        assert!((geo.course - 90.0).abs() < 0.001);
    }

    #[test]
    fn xml_to_event_precision_location() {
        let event = xml_to_federated_event(sample_xml(), &empty_metadata()).expect("conversion");
        let geo = event.event.as_ref().expect("geo event");
        assert_eq!(geo.coord_source, "GPS");
        assert_eq!(geo.ploc, "GPS");
        assert_eq!(geo.palt, "GPS");
    }

    #[test]
    fn xml_to_event_battery() {
        let event = xml_to_federated_event(sample_xml(), &empty_metadata()).expect("conversion");
        let geo = event.event.as_ref().expect("geo event");
        assert_eq!(geo.battery, 85);
    }

    #[test]
    fn xml_to_event_with_provenance() {
        let event = xml_to_federated_event(sample_xml(), &sample_metadata()).expect("conversion");
        assert_eq!(event.federate_provenance.len(), 1);
        assert_eq!(
            event.federate_provenance[0].federation_server_id,
            "server-1"
        );
        assert_eq!(
            event.federate_provenance[0].federation_server_name,
            "Server One"
        );
        let hops = event.federate_hops.as_ref().expect("hops");
        assert_eq!(hops.max_hops, 10);
        assert_eq!(hops.current_hops, 1);
    }

    #[test]
    fn xml_to_event_no_groups_when_no_group_element() {
        let xml = b"<event version=\"2.0\" uid=\"X\" type=\"a-f\" \
                     time=\"2021-01-01T00:00:00Z\" start=\"2021-01-01T00:00:00Z\" \
                     stale=\"2021-01-01T00:05:00Z\">\
                     <point lat=\"0\" lon=\"0\" hae=\"0\" ce=\"0\" le=\"0\"/>\
                     </event>";
        let event = xml_to_federated_event(xml, &empty_metadata()).expect("conversion");
        assert!(event.federate_groups.is_empty());
    }

    #[test]
    fn xml_to_event_invalid_xml_returns_error() {
        let result = xml_to_federated_event(b"not xml at all", &empty_metadata());
        assert!(result.is_err());
    }

    // --- federated_event_to_xml tests ---

    #[test]
    fn event_to_xml_round_trip_uid() {
        let event = xml_to_federated_event(sample_xml(), &empty_metadata()).expect("conversion");
        let xml = federated_event_to_xml(&event).expect("to xml");
        let xml_str = String::from_utf8(xml).expect("utf8");
        assert!(xml_str.contains("uid=\"ALPHA-1\""));
    }

    #[test]
    fn event_to_xml_round_trip_type() {
        let event = xml_to_federated_event(sample_xml(), &empty_metadata()).expect("conversion");
        let xml = federated_event_to_xml(&event).expect("to xml");
        let xml_str = String::from_utf8(xml).expect("utf8");
        assert!(xml_str.contains("type=\"a-f-G-U-C\""));
    }

    #[test]
    fn event_to_xml_round_trip_coordinates() {
        let event = xml_to_federated_event(sample_xml(), &empty_metadata()).expect("conversion");
        let xml = federated_event_to_xml(&event).expect("to xml");
        let xml_str = String::from_utf8(xml).expect("utf8");
        assert!(xml_str.contains("lat=\"38.8977\""));
        assert!(xml_str.contains("lon=\"-77.0365\""));
    }

    #[test]
    fn event_to_xml_includes_contact() {
        let event = xml_to_federated_event(sample_xml(), &empty_metadata()).expect("conversion");
        let xml = federated_event_to_xml(&event).expect("to xml");
        let xml_str = String::from_utf8(xml).expect("utf8");
        assert!(xml_str.contains("callsign=\"ALPHA\""));
    }

    #[test]
    fn event_to_xml_includes_group() {
        let event = xml_to_federated_event(sample_xml(), &empty_metadata()).expect("conversion");
        let xml = federated_event_to_xml(&event).expect("to xml");
        let xml_str = String::from_utf8(xml).expect("utf8");
        assert!(xml_str.contains("__group"));
        assert!(xml_str.contains("name=\"Cyan\""));
    }

    #[test]
    fn event_to_xml_includes_track() {
        let event = xml_to_federated_event(sample_xml(), &empty_metadata()).expect("conversion");
        let xml = federated_event_to_xml(&event).expect("to xml");
        let xml_str = String::from_utf8(xml).expect("utf8");
        assert!(xml_str.contains("<track"));
        assert!(xml_str.contains("speed=\"10.5\""));
        assert!(xml_str.contains("course=\"90\""));
    }

    #[test]
    fn event_to_xml_missing_event_returns_error() {
        let event = figpb::FederatedEvent::default();
        let result = federated_event_to_xml(&event);
        assert!(result.is_err());
    }

    #[test]
    fn event_to_xml_minimal_event() {
        let event = figpb::FederatedEvent {
            event: Some(figpb::GeoEvent {
                uid: "test-uid".into(),
                r#type: "a-f-G".into(),
                lat: 0.0,
                lon: 0.0,
                ..Default::default()
            }),
            ..Default::default()
        };
        let xml = federated_event_to_xml(&event).expect("to xml");
        let xml_str = String::from_utf8(xml).expect("utf8");
        assert!(xml_str.starts_with("<event"));
        assert!(xml_str.ends_with("</event>"));
        assert!(xml_str.contains("uid=\"test-uid\""));
    }

    // --- Round-trip conversion tests ---

    #[test]
    fn full_round_trip_xml_to_event_to_xml() {
        let event = xml_to_federated_event(sample_xml(), &sample_metadata()).expect("to event");
        let xml_out = federated_event_to_xml(&event).expect("to xml");
        let xml_str = String::from_utf8(xml_out).expect("utf8");

        // Verify key fields survive round-trip
        assert!(xml_str.contains("uid=\"ALPHA-1\""));
        assert!(xml_str.contains("type=\"a-f-G-U-C\""));
        assert!(xml_str.contains("lat=\"38.8977\""));
        assert!(xml_str.contains("callsign=\"ALPHA\""));
        assert!(xml_str.contains("__group"));
        assert!(xml_str.contains("name=\"Cyan\""));
    }

    #[test]
    fn full_round_trip_event_to_xml_to_event() {
        let original = figpb::FederatedEvent {
            event: Some(figpb::GeoEvent {
                uid: "round-trip-test".into(),
                r#type: "a-f-G-U-C".into(),
                lat: 51.5074,
                lon: -0.1278,
                hae: 11.0,
                ce: 100.0,
                le: 50.0,
                screen_name: "BRAVO".into(),
                group_name: "Red".into(),
                group_role: "Sniper".into(),
                speed: 5.0,
                course: 180.0,
                battery: 42,
                coord_source: "GPS".into(),
                palt: "GPS".into(),
                send_time: 1614460344000,
                start_time: 1614460344000,
                stale_time: 1614460644000,
                ..Default::default()
            }),
            federate_groups: vec!["Red".into()],
            ..Default::default()
        };

        let xml = federated_event_to_xml(&original).expect("to xml");
        let recovered = xml_to_federated_event(&xml, &empty_metadata()).expect("to event");

        let orig_geo = original.event.as_ref().expect("geo");
        let recv_geo = recovered.event.as_ref().expect("geo");

        assert_eq!(recv_geo.uid, orig_geo.uid);
        assert_eq!(recv_geo.r#type, orig_geo.r#type);
        assert!((recv_geo.lat - orig_geo.lat).abs() < 0.0001);
        assert!((recv_geo.lon - orig_geo.lon).abs() < 0.0001);
        assert_eq!(recv_geo.screen_name, orig_geo.screen_name);
        assert_eq!(recv_geo.group_name, orig_geo.group_name);
        assert_eq!(recv_geo.battery, orig_geo.battery);
    }

    // --- add_flow_tag tests ---

    #[test]
    fn flow_tag_inserted_before_detail_close() {
        let xml = Bytes::from_static(b"<event><detail><contact callsign=\"A\"/></detail></event>");
        let result = add_flow_tag(&xml, "fed-server-1");
        let s = std::str::from_utf8(&result).expect("utf8");
        assert!(s.contains("<_flow-tags_>"));
        assert!(s.contains("<source name=\"fed-server-1\""));
        assert!(s.contains("</_flow-tags_></detail>"));
    }

    #[test]
    fn flow_tag_creates_detail_section_when_missing() {
        let xml = Bytes::from_static(b"<event><point lat=\"0\" lon=\"0\"/></event>");
        let result = add_flow_tag(&xml, "my-server");
        let s = std::str::from_utf8(&result).expect("utf8");
        assert!(s.contains("<detail><_flow-tags_>"));
        assert!(s.contains("</_flow-tags_></detail></event>"));
    }

    #[test]
    fn flow_tag_escapes_source_name() {
        let xml = Bytes::from_static(b"<event><detail></detail></event>");
        let result = add_flow_tag(&xml, "server&<>\"name");
        let s = std::str::from_utf8(&result).expect("utf8");
        assert!(s.contains("server&amp;&lt;&gt;&quot;name"));
    }

    #[test]
    fn flow_tag_includes_timestamp() {
        let xml = Bytes::from_static(b"<event><detail></detail></event>");
        let result = add_flow_tag(&xml, "s");
        let s = std::str::from_utf8(&result).expect("utf8");
        // Timestamp should be in RFC3339 format (contains 'T' and 'Z' or offset)
        assert!(s.contains("ts=\"20"));
    }

    #[test]
    fn flow_tag_no_change_for_invalid_xml() {
        let data = Bytes::from_static(b"not xml at all");
        let result = add_flow_tag(&data, "s");
        assert_eq!(result, data);
    }

    // --- contact_list_entry_to_xml tests ---

    #[test]
    fn contact_entry_create_produces_position_type() {
        let contact = figpb::ContactListEntry {
            operation: figpb::Crud::Create as i32,
            uid: "user-123".into(),
            callsign: "ALPHA".into(),
            phone: String::new(),
            sip: String::new(),
            direct_connect: String::new(),
        };
        let xml = contact_list_entry_to_xml(&contact).expect("should produce XML");
        let s = String::from_utf8(xml).expect("utf8");
        assert!(s.contains("type=\"a-f-G-U-C\""));
        assert!(s.contains("uid=\"user-123\""));
        assert!(s.contains("callsign=\"ALPHA\""));
    }

    #[test]
    fn contact_entry_delete_produces_delete_type() {
        let contact = figpb::ContactListEntry {
            operation: figpb::Crud::Delete as i32,
            uid: "user-456".into(),
            callsign: "BRAVO".into(),
            ..Default::default()
        };
        let xml = contact_list_entry_to_xml(&contact).expect("should produce XML");
        let s = String::from_utf8(xml).expect("utf8");
        assert!(s.contains("type=\"t-x-d-d\""));
    }

    #[test]
    fn contact_entry_includes_optional_fields() {
        let contact = figpb::ContactListEntry {
            operation: figpb::Crud::Create as i32,
            uid: "user-789".into(),
            callsign: "CHARLIE".into(),
            phone: "+1-555-0100".into(),
            sip: "sip:charlie@example.com".into(),
            direct_connect: "*:-1:stcp".into(),
        };
        let xml = contact_list_entry_to_xml(&contact).expect("should produce XML");
        let s = String::from_utf8(xml).expect("utf8");
        assert!(s.contains("phone=\"+1-555-0100\""));
        assert!(s.contains("sipAddress=\"sip:charlie@example.com\""));
        assert!(s.contains("endpoint=\"*:-1:stcp\""));
    }

    #[test]
    fn contact_entry_empty_uid_returns_none() {
        let contact = figpb::ContactListEntry {
            uid: String::new(),
            callsign: "DELTA".into(),
            ..Default::default()
        };
        assert!(contact_list_entry_to_xml(&contact).is_none());
    }

    #[test]
    fn contact_entry_has_zero_coordinates() {
        let contact = figpb::ContactListEntry {
            operation: figpb::Crud::Create as i32,
            uid: "user-000".into(),
            callsign: "ECHO".into(),
            ..Default::default()
        };
        let xml = contact_list_entry_to_xml(&contact).expect("should produce XML");
        let s = String::from_utf8(xml).expect("utf8");
        assert!(s.contains("lat=\"0.0\""));
        assert!(s.contains("lon=\"0.0\""));
        assert!(s.contains("ce=\"9999999\""));
        assert!(s.contains("le=\"9999999\""));
    }

    #[test]
    fn contact_entry_how_is_h_e() {
        let contact = figpb::ContactListEntry {
            operation: figpb::Crud::Create as i32,
            uid: "user-he".into(),
            callsign: "FOXTROT".into(),
            ..Default::default()
        };
        let xml = contact_list_entry_to_xml(&contact).expect("should produce XML");
        let s = String::from_utf8(xml).expect("utf8");
        assert!(s.contains("how=\"h-e\""));
    }

    #[test]
    fn contact_entry_escapes_xml_special_chars() {
        let contact = figpb::ContactListEntry {
            operation: figpb::Crud::Create as i32,
            uid: "user&amp".into(),
            callsign: "A<B>C".into(),
            ..Default::default()
        };
        let xml = contact_list_entry_to_xml(&contact).expect("should produce XML");
        let s = String::from_utf8(xml).expect("utf8");
        assert!(s.contains("uid=\"user&amp;amp\""));
        assert!(s.contains("callsign=\"A&lt;B&gt;C\""));
    }
}
