// Copyright © 2026 Roberto Chiofalo.

#![allow(clippy::unwrap_used)]

use std::time::Duration;

use rustgate_core::message::MessageType;
use rustgate_cot::{CotDestination, ParseError, parse};

#[test]
fn parse_position_event() {
    let xml = br#"<event version="2.0" uid="ANDROID-123" type="a-f-G-U-C"
        start="2021-02-27T20:32:24Z" stale="2021-02-27T20:38:24Z">
        <point lat="38.5" lon="-77.3" hae="100.0"/>
    </event>"#;

    let cot = parse(xml).unwrap();
    assert_eq!(cot.uid, "ANDROID-123");
    assert_eq!(cot.event_type, "a-f-G-U-C");
    assert_eq!(cot.message_type, MessageType::Position);
    assert_eq!(cot.destination, CotDestination::Broadcast);

    let pos = cot.position.unwrap();
    assert!((pos.lat - 38.5).abs() < 0.001);
    assert!((pos.lon - (-77.3)).abs() < 0.001);
    assert!((pos.hae - 100.0).abs() < 0.001);

    assert_eq!(cot.ttl, Some(Duration::from_secs(360)));
}

#[test]
fn parse_chat_event() {
    let xml = br#"<event uid="msg-1" type="b-t-f">
        <point lat="0" lon="0" hae="0"/>
    </event>"#;

    let cot = parse(xml).unwrap();
    assert_eq!(cot.message_type, MessageType::Chat);
}

#[test]
fn parse_alert_event() {
    let xml = br#"<event uid="alert-1" type="b-a-o-tbl">
        <point lat="0" lon="0" hae="0"/>
    </event>"#;

    let cot = parse(xml).unwrap();
    assert_eq!(cot.message_type, MessageType::Alert);
}

#[test]
fn parse_dest_callsign() {
    let xml = br#"<event uid="msg-1" type="a-f">
        <detail><marti><dest callsign="ALPHA-1"/></marti></detail>
    </event>"#;

    let cot = parse(xml).unwrap();
    assert_eq!(cot.destination, CotDestination::Callsign("ALPHA-1".into()));
}

#[test]
fn parse_dest_group() {
    let xml = br#"<event uid="msg-1" type="a-f">
        <detail><marti><dest group="Team-Red"/></marti></detail>
    </event>"#;

    let cot = parse(xml).unwrap();
    assert_eq!(cot.destination, CotDestination::Group("Team-Red".into()));
}

#[test]
fn callsign_takes_precedence_over_group() {
    let xml = br#"<event uid="msg-1" type="a-f">
        <detail><marti><dest callsign="BRAVO" group="Team-Red"/></marti></detail>
    </event>"#;

    let cot = parse(xml).unwrap();
    assert_eq!(cot.destination, CotDestination::Callsign("BRAVO".into()));
}

#[test]
fn missing_uid_errors() {
    let xml = br#"<event type="a-f"/>"#;
    assert!(matches!(
        parse(xml),
        Err(ParseError::MissingAttribute("uid"))
    ));
}

#[test]
fn missing_type_errors() {
    let xml = br#"<event uid="test-1"/>"#;
    assert!(matches!(
        parse(xml),
        Err(ParseError::MissingAttribute("type"))
    ));
}

#[test]
fn no_point_element_ok() {
    let xml = br#"<event uid="test-1" type="a-f"/>"#;
    let cot = parse(xml).unwrap();
    assert!(cot.position.is_none());
}

#[test]
fn no_ttl_without_stale() {
    let xml = br#"<event uid="test-1" type="a-f" start="2021-02-27T20:32:24Z"/>"#;
    let cot = parse(xml).unwrap();
    assert!(cot.ttl.is_none());
}
