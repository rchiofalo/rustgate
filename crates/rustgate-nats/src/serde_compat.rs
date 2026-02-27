//! JSON wire format for CoT events on NATS.
//!
//! Defines types that serialize/deserialize to the JSON schema used for
//! CoT event transport over NATS. This enables bidirectional interop
//! between rustgate and other services consuming the same event bus.

use std::collections::BTreeSet;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use rustgate_core::identity::Identity;
use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};

/// JSON wire format for a CoT event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireEvent {
    pub version: String,
    pub uid: String,
    #[serde(rename = "type")]
    pub event_type: String,
    pub time: String,
    pub start: String,
    pub stale: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub how: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub access: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub qos: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub opex: String,
    pub point: WirePoint,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<WireDetail>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WirePoint {
    pub lat: f64,
    pub lon: f64,
    pub hae: f64,
    pub ce: f64,
    pub le: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireDetail {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub track: Option<WireTrack>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<WireUidDetail>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contact: Option<WireContact>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remarks: Option<WireRemarks>,
    #[serde(default, rename = "_flow-tags_", skip_serializing_if = "Option::is_none")]
    pub flow_tags: Option<WireFlowTags>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<WireStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sensor: Option<WireSensor>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireTrack {
    #[serde(default, skip_serializing_if = "is_zero_f64")]
    pub course: f64,
    #[serde(default, skip_serializing_if = "is_zero_f64")]
    pub speed: f64,
    #[serde(default, rename = "trackValid", skip_serializing_if = "std::ops::Not::not")]
    pub track_valid: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireUidDetail {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub callsign: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub droid: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireContact {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub callsign: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireRemarks {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub note: Vec<WireNote>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireNote {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub text: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub source: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ts: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireFlowTags {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source: Vec<WireFlowSource>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireFlowSource {
    pub name: String,
    pub ts: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub host: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub uid: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireStatus {
    #[serde(default, skip_serializing_if = "is_zero_i32")]
    pub battery: i32,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub readiness: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireSensor {
    #[serde(default, skip_serializing_if = "is_zero_f64")]
    pub fov: f64,
    #[serde(default, skip_serializing_if = "is_zero_f64")]
    pub range: f64,
}

fn is_zero_f64(v: &f64) -> bool {
    *v == 0.0
}

fn is_zero_i32(v: &i32) -> bool {
    *v == 0
}

impl WireEvent {
    /// Build a wire event from parsed CoT fields.
    pub fn from_cot(cot: &rustgate_cot::CotEvent) -> Self {
        let now = SystemTime::now();
        let now_str = format_rfc3339(now);
        let stale = match cot.ttl {
            Some(ttl) => format_rfc3339(now + ttl),
            None => format_rfc3339(now + Duration::from_secs(300)),
        };

        let (lat, lon, hae) = match &cot.position {
            Some(pos) => (pos.lat, pos.lon, pos.hae),
            None => (0.0, 0.0, 0.0),
        };

        Self {
            version: "2.0".to_string(),
            uid: cot.uid.clone(),
            event_type: cot.event_type.clone(),
            time: now_str.clone(),
            start: now_str,
            stale,
            how: "m-g".to_string(),
            access: String::new(),
            qos: String::new(),
            opex: String::new(),
            point: WirePoint {
                lat,
                lon,
                hae,
                ce: 50.0,
                le: 30.0,
            },
            detail: None,
        }
    }

    /// Convert a wire event into a RoutableMessage for local delivery.
    ///
    /// Accepts the original NATS payload bytes directly to avoid a redundant
    /// serialize round-trip and to preserve any unknown fields for forward
    /// compatibility. The source identity uses the UID as the CN (no mTLS
    /// identity for NATS-originated messages).
    pub fn into_routable(self, group: &str, payload: Bytes) -> RoutableMessage {
        let message_type = map_event_type(&self.event_type);

        let mut groups = BTreeSet::new();
        if !group.is_empty() {
            let _ = groups.insert(group.to_string());
        }

        let source = Identity {
            cn: self.uid.clone(),
            fingerprint: String::new(),
            groups,
        };

        RoutableMessage {
            source,
            destination: Destination::Broadcast,
            payload,
            metadata: Metadata {
                received_at: SystemTime::now(),
                source_protocol: "nats".to_string(),
                message_type,
                ttl: None,
            },
        }
    }

    /// Check if position is unknown (0,0 per CoT spec).
    pub fn is_position_unknown(&self) -> bool {
        self.point.lat == 0.0 && self.point.lon == 0.0
    }
}

fn map_event_type(cot_type: &str) -> MessageType {
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

/// Format a SystemTime as an RFC 3339 timestamp (whole seconds, UTC).
fn format_rfc3339(t: SystemTime) -> String {
    let dt = OffsetDateTime::from(t);
    let dt = dt.replace_nanosecond(0).unwrap_or(dt);
    dt.format(&Rfc3339).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_json() {
        let event = WireEvent {
            version: "2.0".to_string(),
            uid: "test-uid-123".to_string(),
            event_type: "a-f-G-U-C".to_string(),
            time: "2026-02-26T12:00:00Z".to_string(),
            start: "2026-02-26T12:00:00Z".to_string(),
            stale: "2026-02-26T12:05:00Z".to_string(),
            how: "m-g".to_string(),
            access: String::new(),
            qos: String::new(),
            opex: String::new(),
            point: WirePoint {
                lat: 37.7749,
                lon: -122.4194,
                hae: 0.0,
                ce: 50.0,
                le: 30.0,
            },
            detail: Some(WireDetail {
                track: Some(WireTrack {
                    course: 45.0,
                    speed: 10.0,
                    track_valid: true,
                }),
                uid: Some(WireUidDetail {
                    callsign: Some("SENSOR-abc".to_string()),
                    droid: None,
                }),
                contact: None,
                remarks: None,
                flow_tags: None,
                status: None,
                sensor: None,
            }),
        };

        let json = serde_json::to_string(&event).expect("serialize");
        let parsed: WireEvent = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(parsed.uid, "test-uid-123");
        assert_eq!(parsed.event_type, "a-f-G-U-C");
        assert!((parsed.point.lat - 37.7749).abs() < f64::EPSILON);
        assert!((parsed.point.lon - (-122.4194)).abs() < f64::EPSILON);

        let detail = parsed.detail.expect("detail present");
        let track = detail.track.expect("track present");
        assert!((track.course - 45.0).abs() < f64::EPSILON);
        assert!(track.track_valid);
    }

    #[test]
    fn deserialize_sensor_simulator_json() {
        let json = r#"{
            "version": "2.0",
            "uid": "sensor-abc-123",
            "type": "a-u-G-U-C",
            "time": "2026-02-26T12:00:00Z",
            "start": "2026-02-26T12:00:00Z",
            "stale": "2026-02-26T12:00:10Z",
            "how": "m-g",
            "point": {"lat": 37.7749, "lon": -122.4194, "hae": 0, "ce": 50, "le": 30},
            "detail": {
                "track": {"course": 180.5, "speed": 12.3, "trackValid": true},
                "uid": {"callsign": "SENSOR-abc"}
            }
        }"#;

        let event: WireEvent = serde_json::from_str(json).expect("parse JSON");
        assert_eq!(event.uid, "sensor-abc-123");
        assert_eq!(event.event_type, "a-u-G-U-C");
        assert!((event.point.lat - 37.7749).abs() < f64::EPSILON);

        let track = event.detail.as_ref().and_then(|d| d.track.as_ref()).expect("track");
        assert!((track.speed - 12.3).abs() < f64::EPSILON);
        assert!(track.track_valid);
    }

    #[test]
    fn into_routable_sets_nats_protocol() {
        let event = WireEvent {
            version: "2.0".to_string(),
            uid: "test-uid".to_string(),
            event_type: "a-f-G-U-C".to_string(),
            time: "2026-02-26T12:00:00Z".to_string(),
            start: "2026-02-26T12:00:00Z".to_string(),
            stale: "2026-02-26T12:05:00Z".to_string(),
            how: String::new(),
            access: String::new(),
            qos: String::new(),
            opex: String::new(),
            point: WirePoint { lat: 37.0, lon: -122.0, hae: 0.0, ce: 50.0, le: 30.0 },
            detail: None,
        };

        let msg = event.into_routable("Cyan", Bytes::from_static(b"{}"));
        assert_eq!(msg.metadata.source_protocol, "nats");
        assert_eq!(msg.source.cn, "test-uid");
        assert!(msg.source.groups.contains("Cyan"));
        assert!(matches!(msg.metadata.message_type, MessageType::Position));
    }

    #[test]
    fn position_unknown_check() {
        let event = WireEvent {
            version: "2.0".to_string(),
            uid: "test".to_string(),
            event_type: "a-f-G".to_string(),
            time: String::new(),
            start: String::new(),
            stale: String::new(),
            how: String::new(),
            access: String::new(),
            qos: String::new(),
            opex: String::new(),
            point: WirePoint { lat: 0.0, lon: 0.0, hae: 0.0, ce: 0.0, le: 0.0 },
            detail: None,
        };
        assert!(event.is_position_unknown());
    }

    #[test]
    fn format_rfc3339_produces_valid_timestamp() {
        let ts = format_rfc3339(SystemTime::now());
        assert!(ts.ends_with('Z'), "timestamp should be UTC: {ts}");
        assert!(ts.contains('T'), "should have date/time separator: {ts}");
    }
}
