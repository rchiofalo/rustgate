//! Conversion between CoT XML, RoutableMessage, and V2 FederatedEvent types.
//!
//! Provides bidirectional conversions for the V2 gRPC federation protocol:
//! - CoT XML ↔ `FederatedEvent` (proto)
//! - `RoutableMessage` ↔ `FederatedEvent` (for routing through the manager)
//!
//! All XML parsing delegates to `rustgate-proto` for security-validated parsing.

use std::collections::BTreeSet;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use rustgate_core::identity::{GroupId, Identity};
use rustgate_core::message::{
    Destination, MessageType, Metadata, RoutableMessage, SOURCE_FEDERATION,
};
use rustgate_proto::convert::timestamp::{iso8601_to_millis, millis_to_iso8601};
use rustgate_proto::{FullCotEvent, parse_full};

use super::proto::figpb;
use crate::provenance::FederationMetadata;

/// Errors that can occur during format conversion.
#[derive(Debug)]
pub enum ConvertError {
    /// XML parsing failed.
    Xml(String),
    /// A required field was missing in the source data.
    MissingField(&'static str),
    /// Timestamp conversion failed.
    InvalidTimestamp(String),
}

impl std::fmt::Display for ConvertError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Xml(msg) => write!(f, "xml parse error: {msg}"),
            Self::MissingField(field) => write!(f, "missing required field: {field}"),
            Self::InvalidTimestamp(msg) => write!(f, "invalid timestamp: {msg}"),
        }
    }
}

impl std::error::Error for ConvertError {}

impl From<rustgate_proto::ProtoError> for ConvertError {
    fn from(e: rustgate_proto::ProtoError) -> Self {
        match e {
            rustgate_proto::ProtoError::MissingField(f) => Self::MissingField(f),
            rustgate_proto::ProtoError::InvalidTimestamp(s) => Self::InvalidTimestamp(s),
            other => Self::Xml(other.to_string()),
        }
    }
}

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
                federation_server_id: p.server_id.clone(),
                federation_server_name: p.server_name.clone(),
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
    let send_time = if full.time.is_empty() {
        0
    } else {
        iso8601_to_millis(&full.time)? as i64
    };
    let start_time = if full.start.is_empty() {
        0
    } else {
        iso8601_to_millis(&full.start)? as i64
    };
    let stale_time = if full.stale.is_empty() {
        0
    } else {
        iso8601_to_millis(&full.stale)? as i64
    };

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
    if geo.send_time > 0 {
        write_attr(&mut xml, "time", &millis_to_iso8601(geo.send_time as u64));
    }
    if geo.start_time > 0 {
        write_attr(&mut xml, "start", &millis_to_iso8601(geo.start_time as u64));
    }
    if geo.stale_time > 0 {
        write_attr(&mut xml, "stale", &millis_to_iso8601(geo.stale_time as u64));
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
// RoutableMessage → FederatedEvent
// ---------------------------------------------------------------------------

/// Convert a `RoutableMessage` (with XML payload) into a `FederatedEvent`.
///
/// The source identity's groups are merged with any groups found in the
/// CoT XML detail section to form the `federate_groups` list.
pub fn routable_to_federated_event(
    msg: &RoutableMessage,
    metadata: &FederationMetadata,
) -> Result<figpb::FederatedEvent, ConvertError> {
    let mut event = xml_to_federated_event(&msg.payload, metadata)?;

    // Merge source identity groups into federate_groups
    for group in &msg.source.groups {
        if !event.federate_groups.contains(group) {
            event.federate_groups.push(group.clone());
        }
    }

    // If destination is a specific group, ensure it's in federate_groups
    if let Destination::Group(ref group_id) = msg.destination
        && !event.federate_groups.contains(group_id)
    {
        event.federate_groups.push(group_id.clone());
    }

    Ok(event)
}

// ---------------------------------------------------------------------------
// FederatedEvent → RoutableMessage
// ---------------------------------------------------------------------------

/// Convert a `FederatedEvent` into a `RoutableMessage` with an XML payload.
///
/// Creates an identity from the peer's certificate information and determines
/// the destination from the event's `federate_groups`.
pub fn federated_event_to_routable(
    event: &figpb::FederatedEvent,
    peer_cn: &str,
    peer_fingerprint: &str,
) -> Result<RoutableMessage, ConvertError> {
    let xml = federated_event_to_xml(event)?;

    // Build source identity from peer cert info + event groups
    let groups: BTreeSet<GroupId> = event.federate_groups.iter().cloned().collect();

    let source = Identity {
        cn: peer_cn.to_string(),
        fingerprint: peer_fingerprint.to_string(),
        groups,
    };

    // Determine destination: if exactly one group, route to that group;
    // otherwise broadcast to all
    let destination = if event.federate_groups.len() == 1 {
        Destination::Group(event.federate_groups[0].clone())
    } else {
        Destination::Broadcast
    };

    // Infer message type from CoT type attribute
    let message_type = event
        .event
        .as_ref()
        .map(|geo| infer_message_type(&geo.r#type))
        .unwrap_or(MessageType::Other("unknown".to_string()));

    // Compute TTL from start/stale times if available
    let ttl = event.event.as_ref().and_then(|geo| {
        if geo.stale_time > 0 && geo.start_time > 0 && geo.stale_time > geo.start_time {
            let diff_ms = (geo.stale_time - geo.start_time) as u64;
            Some(Duration::from_millis(diff_ms))
        } else {
            None
        }
    });

    Ok(RoutableMessage {
        source,
        destination,
        payload: Bytes::from(xml),
        metadata: Metadata {
            received_at: SystemTime::now(),
            source_protocol: SOURCE_FEDERATION.to_string(),
            message_type,
            ttl,
        },
    })
}

// ---------------------------------------------------------------------------
// FederationMetadata ↔ FederatedEvent provenance
// ---------------------------------------------------------------------------

/// Extract `FederationMetadata` from a `FederatedEvent`'s provenance fields.
pub fn extract_metadata(event: &figpb::FederatedEvent) -> FederationMetadata {
    let provenance = event
        .federate_provenance
        .iter()
        .map(|p| crate::provenance::FederateProvenance {
            server_id: p.federation_server_id.clone(),
            server_name: p.federation_server_name.clone(),
        })
        .collect();

    let (max_hops, current_hops) = event
        .federate_hops
        .as_ref()
        .map(|h| (h.max_hops as u32, h.current_hops as u32))
        .unwrap_or((10, 0));

    FederationMetadata {
        provenance,
        max_hops,
        current_hops,
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Infer the message type from a CoT type string.
fn infer_message_type(cot_type: &str) -> MessageType {
    if cot_type.starts_with("a-") {
        MessageType::Position
    } else if cot_type.starts_with("b-t-f") {
        MessageType::Chat
    } else if cot_type.starts_with("b-a") {
        MessageType::Alert
    } else {
        MessageType::Other(cot_type.to_string())
    }
}

/// Write an XML attribute (`name="value"`) with proper escaping.
fn write_attr(xml: &mut Vec<u8>, name: &str, value: &str) {
    xml.push(b' ');
    xml.extend_from_slice(name.as_bytes());
    xml.extend_from_slice(b"=\"");
    xml_escape_into(xml, value);
    xml.push(b'"');
}

/// Escape special XML characters in attribute values.
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

/// Return a string with XML-escaped attribute characters.
fn xml_escape(s: &str) -> String {
    let mut buf = Vec::with_capacity(s.len());
    xml_escape_into(&mut buf, s);
    // xml_escape_into only emits valid UTF-8 (ASCII replacements for ASCII bytes)
    String::from_utf8(buf).expect("xml_escape_into produces valid UTF-8")
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
/// Returns the original bytes unchanged if neither marker is found.
pub fn add_flow_tag(data: &[u8], source: &str) -> Vec<u8> {
    let s = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return data.to_vec(),
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
        result.into_bytes()
    } else if let Some(pos) = s.find("</event>") {
        // No detail section — wrap flow tag in a new detail element
        let mut result = String::with_capacity(s.len() + flow_tag.len() + 17);
        result.push_str(&s[..pos]);
        result.push_str("<detail>");
        result.push_str(&flow_tag);
        result.push_str("</detail>");
        result.push_str(&s[pos..]);
        result.into_bytes()
    } else {
        data.to_vec()
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
    use super::*;

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
                server_id: "server-1".into(),
                server_name: "Server One".into(),
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

    // --- routable_to_federated_event tests ---

    #[test]
    fn routable_to_event_merges_source_groups() {
        let mut groups = BTreeSet::new();
        let _ = groups.insert("Alpha".to_string());
        let _ = groups.insert("Bravo".to_string());

        let msg = RoutableMessage {
            source: Identity {
                cn: "test-peer".into(),
                fingerprint: "abc123".into(),
                groups,
            },
            destination: Destination::Broadcast,
            payload: Bytes::from_static(sample_xml()),
            metadata: Metadata {
                received_at: SystemTime::now(),
                source_protocol: SOURCE_FEDERATION.to_string(),
                message_type: MessageType::Position,
                ttl: None,
            },
        };

        let event = routable_to_federated_event(&msg, &empty_metadata()).expect("conversion");

        // Should contain "Cyan" from XML + "Alpha" and "Bravo" from source
        assert!(event.federate_groups.contains(&"Cyan".to_string()));
        assert!(event.federate_groups.contains(&"Alpha".to_string()));
        assert!(event.federate_groups.contains(&"Bravo".to_string()));
    }

    #[test]
    fn routable_to_event_includes_destination_group() {
        let msg = RoutableMessage {
            source: Identity {
                cn: "test-peer".into(),
                fingerprint: "abc123".into(),
                groups: BTreeSet::new(),
            },
            destination: Destination::Group("Delta".to_string()),
            payload: Bytes::from_static(sample_xml()),
            metadata: Metadata {
                received_at: SystemTime::now(),
                source_protocol: SOURCE_FEDERATION.to_string(),
                message_type: MessageType::Position,
                ttl: None,
            },
        };

        let event = routable_to_federated_event(&msg, &empty_metadata()).expect("conversion");
        assert!(event.federate_groups.contains(&"Delta".to_string()));
    }

    // --- federated_event_to_routable tests ---

    #[test]
    fn event_to_routable_source_identity() {
        let event = xml_to_federated_event(sample_xml(), &empty_metadata()).expect("conversion");
        let msg =
            federated_event_to_routable(&event, "peer-1", "fingerprint-abc").expect("conversion");
        assert_eq!(msg.source.cn, "peer-1");
        assert_eq!(msg.source.fingerprint, "fingerprint-abc");
    }

    #[test]
    fn event_to_routable_source_protocol() {
        let event = xml_to_federated_event(sample_xml(), &empty_metadata()).expect("conversion");
        let msg = federated_event_to_routable(&event, "peer-1", "fp").expect("conversion");
        assert_eq!(msg.metadata.source_protocol, SOURCE_FEDERATION);
    }

    #[test]
    fn event_to_routable_message_type_position() {
        let event = xml_to_federated_event(sample_xml(), &empty_metadata()).expect("conversion");
        let msg = federated_event_to_routable(&event, "peer-1", "fp").expect("conversion");
        assert_eq!(msg.metadata.message_type, MessageType::Position);
    }

    #[test]
    fn event_to_routable_single_group_routes_to_group() {
        let event = figpb::FederatedEvent {
            event: Some(figpb::GeoEvent {
                uid: "test".into(),
                r#type: "a-f-G".into(),
                ..Default::default()
            }),
            federate_groups: vec!["OnlyGroup".into()],
            ..Default::default()
        };
        let msg = federated_event_to_routable(&event, "peer", "fp").expect("conversion");
        assert!(
            matches!(&msg.destination, Destination::Group(g) if g == "OnlyGroup"),
            "expected Group(OnlyGroup) destination"
        );
    }

    #[test]
    fn event_to_routable_multiple_groups_broadcasts() {
        let event = figpb::FederatedEvent {
            event: Some(figpb::GeoEvent {
                uid: "test".into(),
                r#type: "a-f-G".into(),
                ..Default::default()
            }),
            federate_groups: vec!["A".into(), "B".into()],
            ..Default::default()
        };
        let msg = federated_event_to_routable(&event, "peer", "fp").expect("conversion");
        assert!(matches!(msg.destination, Destination::Broadcast));
    }

    #[test]
    fn event_to_routable_ttl_computed_from_timestamps() {
        let event = figpb::FederatedEvent {
            event: Some(figpb::GeoEvent {
                uid: "test".into(),
                r#type: "a-f-G".into(),
                start_time: 1000000,
                stale_time: 1300000, // 300 seconds later
                ..Default::default()
            }),
            ..Default::default()
        };
        let msg = federated_event_to_routable(&event, "peer", "fp").expect("conversion");
        let ttl = msg.metadata.ttl.expect("should have ttl");
        assert_eq!(ttl, Duration::from_millis(300000));
    }

    #[test]
    fn event_to_routable_no_ttl_when_no_timestamps() {
        let event = figpb::FederatedEvent {
            event: Some(figpb::GeoEvent {
                uid: "test".into(),
                r#type: "a-f-G".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let msg = federated_event_to_routable(&event, "peer", "fp").expect("conversion");
        assert!(msg.metadata.ttl.is_none());
    }

    #[test]
    fn event_to_routable_groups_in_identity() {
        let event = figpb::FederatedEvent {
            event: Some(figpb::GeoEvent {
                uid: "test".into(),
                r#type: "a-f-G".into(),
                ..Default::default()
            }),
            federate_groups: vec!["X".into(), "Y".into()],
            ..Default::default()
        };
        let msg = federated_event_to_routable(&event, "peer", "fp").expect("conversion");
        assert!(msg.source.groups.contains("X"));
        assert!(msg.source.groups.contains("Y"));
    }

    // --- extract_metadata tests ---

    #[test]
    fn extract_metadata_empty_event() {
        let event = figpb::FederatedEvent::default();
        let meta = extract_metadata(&event);
        assert!(meta.provenance.is_empty());
        assert_eq!(meta.max_hops, 10);
        assert_eq!(meta.current_hops, 0);
    }

    #[test]
    fn extract_metadata_with_provenance() {
        let event = figpb::FederatedEvent {
            federate_provenance: vec![
                figpb::FederateProvenance {
                    federation_server_id: "s1".into(),
                    federation_server_name: "S One".into(),
                },
                figpb::FederateProvenance {
                    federation_server_id: "s2".into(),
                    federation_server_name: "S Two".into(),
                },
            ],
            federate_hops: Some(figpb::FederateHops {
                max_hops: 5,
                current_hops: 2,
            }),
            ..Default::default()
        };
        let meta = extract_metadata(&event);
        assert_eq!(meta.provenance.len(), 2);
        assert_eq!(meta.provenance[0].server_id, "s1");
        assert_eq!(meta.provenance[1].server_id, "s2");
        assert_eq!(meta.max_hops, 5);
        assert_eq!(meta.current_hops, 2);
    }

    // --- infer_message_type tests ---

    #[test]
    fn infer_message_type_position() {
        assert_eq!(infer_message_type("a-f-G-U-C"), MessageType::Position);
        assert_eq!(infer_message_type("a-h-G"), MessageType::Position);
    }

    #[test]
    fn infer_message_type_chat() {
        assert_eq!(infer_message_type("b-t-f"), MessageType::Chat);
    }

    #[test]
    fn infer_message_type_alert() {
        assert_eq!(infer_message_type("b-a-g"), MessageType::Alert);
    }

    #[test]
    fn infer_message_type_other() {
        assert_eq!(
            infer_message_type("t-x-c-t"),
            MessageType::Other("t-x-c-t".to_string())
        );
    }

    // --- XML escaping tests ---

    #[test]
    fn xml_escape_special_characters() {
        let mut buf = Vec::new();
        xml_escape_into(&mut buf, "A&B<C>D\"E'F");
        assert_eq!(
            String::from_utf8(buf).expect("utf8"),
            "A&amp;B&lt;C&gt;D&quot;E&apos;F"
        );
    }

    #[test]
    fn xml_escape_no_special_characters() {
        let mut buf = Vec::new();
        xml_escape_into(&mut buf, "plain text 123");
        assert_eq!(String::from_utf8(buf).expect("utf8"), "plain text 123");
    }

    #[test]
    fn xml_escape_string_helper() {
        assert_eq!(xml_escape("A&B"), "A&amp;B");
        assert_eq!(xml_escape("plain"), "plain");
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

    #[test]
    fn full_round_trip_routable_to_event_to_routable() {
        let source_groups: BTreeSet<GroupId> = ["Alpha".to_string()].into_iter().collect();

        let msg = RoutableMessage {
            source: Identity {
                cn: "test-server".into(),
                fingerprint: "fp-abc".into(),
                groups: source_groups,
            },
            destination: Destination::Group("Alpha".to_string()),
            payload: Bytes::from_static(sample_xml()),
            metadata: Metadata {
                received_at: SystemTime::now(),
                source_protocol: SOURCE_FEDERATION.to_string(),
                message_type: MessageType::Position,
                ttl: None,
            },
        };

        let event = routable_to_federated_event(&msg, &sample_metadata()).expect("to event");

        // Verify groups merged
        assert!(event.federate_groups.contains(&"Cyan".to_string()));
        assert!(event.federate_groups.contains(&"Alpha".to_string()));

        // Convert back
        let msg_back =
            federated_event_to_routable(&event, "peer-x", "fp-xyz").expect("to routable");

        assert_eq!(msg_back.source.cn, "peer-x");
        assert_eq!(msg_back.metadata.source_protocol, SOURCE_FEDERATION);
        assert_eq!(msg_back.metadata.message_type, MessageType::Position);
    }

    // --- add_flow_tag tests ---

    #[test]
    fn flow_tag_inserted_before_detail_close() {
        let xml = b"<event><detail><contact callsign=\"A\"/></detail></event>";
        let result = add_flow_tag(xml, "fed-server-1");
        let s = String::from_utf8(result).expect("utf8");
        assert!(s.contains("<_flow-tags_>"));
        assert!(s.contains("<source name=\"fed-server-1\""));
        assert!(s.contains("</_flow-tags_></detail>"));
    }

    #[test]
    fn flow_tag_creates_detail_section_when_missing() {
        let xml = b"<event><point lat=\"0\" lon=\"0\"/></event>";
        let result = add_flow_tag(xml, "my-server");
        let s = String::from_utf8(result).expect("utf8");
        assert!(s.contains("<detail><_flow-tags_>"));
        assert!(s.contains("</_flow-tags_></detail></event>"));
    }

    #[test]
    fn flow_tag_escapes_source_name() {
        let xml = b"<event><detail></detail></event>";
        let result = add_flow_tag(xml, "server&<>\"name");
        let s = String::from_utf8(result).expect("utf8");
        assert!(s.contains("server&amp;&lt;&gt;&quot;name"));
    }

    #[test]
    fn flow_tag_includes_timestamp() {
        let xml = b"<event><detail></detail></event>";
        let result = add_flow_tag(xml, "s");
        let s = String::from_utf8(result).expect("utf8");
        // Timestamp should be in RFC3339 format (contains 'T' and 'Z' or offset)
        assert!(s.contains("ts=\"20"));
    }

    #[test]
    fn flow_tag_no_change_for_invalid_xml() {
        let data = b"not xml at all";
        let result = add_flow_tag(data, "s");
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
