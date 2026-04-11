// Copyright © 2026 Roberto Chiofalo.

//! Bidirectional XML CoT <-> TAK protobuf conversion.

pub mod proto_to_xml;
pub mod timestamp;
pub mod xml_to_proto;

pub use proto_to_xml::proto_to_xml;
pub use xml_to_proto::xml_to_proto;

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: parse XML, convert to proto, convert back to XML, re-parse.
    /// Verifies semantic equivalence.
    fn round_trip_xml(xml: &[u8]) {
        let proto_bytes = xml_to_proto(xml).expect("xml_to_proto");
        let xml_back = proto_to_xml(&proto_bytes).expect("proto_to_xml");

        // Re-parse both to compare semantically
        let original = crate::xml_full::parse_full(xml).expect("parse original");
        let restored = crate::xml_full::parse_full(&xml_back).expect("parse restored");

        assert_eq!(original.uid, restored.uid);
        assert_eq!(original.event_type, restored.event_type);
        assert_eq!(original.how, restored.how);
        assert!((original.lat - restored.lat).abs() < 0.0001);
        assert!((original.lon - restored.lon).abs() < 0.0001);
        assert!((original.hae - restored.hae).abs() < 0.0001);
        assert!((original.ce - restored.ce).abs() < 0.0001);
        assert!((original.le - restored.le).abs() < 0.0001);

        // Timestamp round-trips within 1 second (millis truncation)
        // Note: ISO 8601 -> millis -> ISO 8601 preserves ms precision,
        // but the original XML may have different precision
    }

    #[test]
    fn round_trip_position_event() {
        let xml = br#"<event version="2.0" uid="ALPHA-1" type="a-f-G-U-C" how="m-g" time="2021-02-27T20:32:24.000Z" start="2021-02-27T20:32:24.000Z" stale="2021-02-27T20:37:24.000Z">
            <point lat="37.7749" lon="-122.4194" hae="10.5" ce="50.0" le="30.0"/>
            <detail>
                <contact callsign="ALPHA" endpoint="*:-1:stcp"/>
                <__group name="Cyan" role="Team Lead"/>
                <track speed="10.5" course="90.0"/>
            </detail>
        </event>"#;
        round_trip_xml(xml);
    }

    #[test]
    fn round_trip_preserves_contact() {
        let xml = br#"<event version="2.0" uid="TEST-1" type="a-f-G" how="m-g" time="2021-01-01T00:00:00.000Z" start="2021-01-01T00:00:00.000Z" stale="2021-01-01T00:05:00.000Z">
            <point lat="0.0" lon="0.0" hae="0.0" ce="0.0" le="0.0"/>
            <detail>
                <contact callsign="BRAVO" endpoint="192.168.1.1:4242:tcp"/>
            </detail>
        </event>"#;
        let proto_bytes = xml_to_proto(xml).expect("encode");
        let xml_back = proto_to_xml(&proto_bytes).expect("decode");
        let restored = crate::xml_full::parse_full(&xml_back).expect("parse");

        let contact = restored.contact.expect("contact");
        assert_eq!(contact.callsign, "BRAVO");
        assert_eq!(contact.endpoint, "192.168.1.1:4242:tcp");
    }

    #[test]
    fn round_trip_preserves_group() {
        let xml = br#"<event uid="TEST-1" type="a-f-G">
            <detail>
                <__group name="Cyan" role="Team Lead"/>
            </detail>
        </event>"#;
        let proto_bytes = xml_to_proto(xml).expect("encode");
        let xml_back = proto_to_xml(&proto_bytes).expect("decode");
        let restored = crate::xml_full::parse_full(&xml_back).expect("parse");

        let group = restored.group.expect("group");
        assert_eq!(group.name, "Cyan");
        assert_eq!(group.role, "Team Lead");
    }

    #[test]
    fn round_trip_preserves_all_detail_types() {
        let xml = br#"<event uid="TEST-1" type="a-f-G" how="m-g" time="2021-01-01T00:00:00.000Z" start="2021-01-01T00:00:00.000Z" stale="2021-01-01T00:05:00.000Z">
            <point lat="37.0" lon="-122.0" hae="100.0" ce="10.0" le="5.0"/>
            <detail>
                <contact callsign="ALPHA" endpoint="*:-1:stcp"/>
                <__group name="Cyan" role="Team Lead"/>
                <precisionlocation geopointsrc="GPS" altsrc="GPS"/>
                <status battery="85"/>
                <takv device="Pixel" platform="ATAK-CIV" os="Android" version="4.10.0"/>
                <track speed="5.5" course="180.0"/>
            </detail>
        </event>"#;
        let proto_bytes = xml_to_proto(xml).expect("encode");
        let xml_back = proto_to_xml(&proto_bytes).expect("decode");
        let restored = crate::xml_full::parse_full(&xml_back).expect("parse");

        assert!(restored.contact.is_some());
        assert!(restored.group.is_some());
        assert!(restored.precision_location.is_some());
        assert!(restored.status.is_some());
        assert!(restored.takv.is_some());
        assert!(restored.track.is_some());

        let pl = restored.precision_location.expect("pl");
        assert_eq!(pl.geopointsrc, "GPS");
        assert_eq!(pl.altsrc, "GPS");

        let status = restored.status.expect("status");
        assert_eq!(status.battery, 85);

        let takv = restored.takv.expect("takv");
        assert_eq!(takv.platform, "ATAK-CIV");
    }

    #[test]
    fn round_trip_preserves_xml_detail() {
        let xml = br#"<event uid="TEST-1" type="a-f-G" how="m-g" time="2021-01-01T00:00:00.000Z" start="2021-01-01T00:00:00.000Z" stale="2021-01-01T00:05:00.000Z">
            <point lat="0.0" lon="0.0" hae="0.0" ce="0.0" le="0.0"/>
            <detail>
                <contact callsign="ALPHA"/>
                <marti><dest callsign="BRAVO"/></marti>
            </detail>
        </event>"#;
        let proto_bytes = xml_to_proto(xml).expect("encode");
        let xml_back = proto_to_xml(&proto_bytes).expect("decode");
        let restored = crate::xml_full::parse_full(&xml_back).expect("parse");

        // marti is now a typed detail field, preserved through round-trip
        let marti = restored.marti.expect("marti");
        assert_eq!(marti.dest_callsigns, vec!["BRAVO"]);
    }

    /// Shape detail elements survive XML → protobuf → XML round-trip via xmlDetail.
    #[test]
    fn round_trip_preserves_shape_xml_detail() {
        let xml = br#"<event uid="SHAPE-1" type="u-d-r" how="h-e" time="2021-01-01T00:00:00.000Z" start="2021-01-01T00:00:00.000Z" stale="2021-01-01T00:05:00.000Z">
            <point lat="37.0" lon="-122.0" hae="0.0" ce="50.0" le="30.0"/>
            <detail>
                <shape><polyline closed="true"><vertex lat="37.0" lon="-122.0" hae="0.0"/><vertex lat="37.1" lon="-122.1" hae="0.0"/></polyline></shape>
                <strokeColor value="-65536"/>
                <fillColor value="536870912"/>
            </detail>
        </event>"#;
        let proto_bytes = xml_to_proto(xml).expect("encode");
        let xml_back = proto_to_xml(&proto_bytes).expect("decode");
        let restored = crate::xml_full::parse_full(&xml_back).expect("parse");

        assert!(restored.xml_detail.contains("shape"));
        assert!(restored.xml_detail.contains("polyline"));
        assert!(restored.xml_detail.contains("vertex"));
        assert!(restored.xml_detail.contains("strokeColor"));
        assert!(restored.xml_detail.contains("fillColor"));
    }

    /// GeoChat detail elements survive XML -> protobuf -> XML round-trip.
    /// __chat stays in xml_detail residual, remarks is now a typed field.
    #[test]
    fn round_trip_preserves_chat_xml_detail() {
        let xml = br#"<event uid="GeoChat.A.B.1" type="b-t-f" how="h-g-i-g-o" time="2021-01-01T00:00:00.000Z" start="2021-01-01T00:00:00.000Z" stale="2021-01-01T00:05:00.000Z">
            <point lat="37.0" lon="-122.0" hae="0.0" ce="50.0" le="30.0"/>
            <detail>
                <__chat chatroom="B" senderCallsign="A"><chatgrp uid0="A" uid1="B"/></__chat>
                <remarks source="BAO.F.ATAK.A" to="B">hello world</remarks>
            </detail>
        </event>"#;
        let proto_bytes = xml_to_proto(xml).expect("encode");
        let xml_back = proto_to_xml(&proto_bytes).expect("decode");
        let restored = crate::xml_full::parse_full(&xml_back).expect("parse");

        // __chat is not a typed element, stays in xml_detail
        assert!(restored.xml_detail.contains("__chat"));
        assert!(restored.xml_detail.contains("chatgrp"));
        assert!(restored.xml_detail.contains("senderCallsign"));

        // remarks is now a typed field, preserved through round-trip
        let remarks = restored.remarks.expect("remarks");
        assert_eq!(remarks.source.as_deref(), Some("BAO.F.ATAK.A"));
        assert_eq!(remarks.text, "hello world");
    }

    #[test]
    fn round_trip_minimal_event() {
        let xml = br#"<event uid="MINIMAL" type="a-f-G"/>"#;
        let proto_bytes = xml_to_proto(xml).expect("encode");
        let xml_back = proto_to_xml(&proto_bytes).expect("decode");
        let restored = crate::xml_full::parse_full(&xml_back).expect("parse");
        assert_eq!(restored.uid, "MINIMAL");
        assert_eq!(restored.event_type, "a-f-G");
    }

    #[test]
    fn round_trip_timestamps() {
        let xml = br#"<event uid="TS-1" type="a-f-G" time="2026-02-26T12:00:00.500Z" start="2026-02-26T12:00:00.000Z" stale="2026-02-26T12:05:00.000Z"/>"#;
        let proto_bytes = xml_to_proto(xml).expect("encode");
        let xml_back = proto_to_xml(&proto_bytes).expect("decode");
        let restored = crate::xml_full::parse_full(&xml_back).expect("parse");

        assert_eq!(restored.time, "2026-02-26T12:00:00.500Z");
        assert_eq!(restored.start, "2026-02-26T12:00:00.000Z");
        assert_eq!(restored.stale, "2026-02-26T12:05:00.000Z");
    }

    #[test]
    fn proto_to_xml_missing_cot_event() {
        // TakMessage with no CotEvent
        use prost::Message;
        let msg = crate::tak_proto::TakMessage {
            tak_control: None,
            cot_event: None,
        };
        let mut buf = Vec::new();
        msg.encode(&mut buf).expect("encode");
        let result = proto_to_xml(&buf);
        assert!(result.is_err());
    }

    #[test]
    fn xml_to_proto_invalid_xml() {
        let result = xml_to_proto(b"not xml at all");
        assert!(result.is_err());
    }
}
