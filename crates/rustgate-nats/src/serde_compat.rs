// Copyright © 2026 Roberto Chiofalo.

//! JSON wire format for CoT events on NATS.
//!
//! Defines types that serialize/deserialize to the JSON schema used for
//! CoT event transport over NATS. This enables bidirectional interop
//! between rustgate and other services consuming the same event bus.

use std::collections::BTreeSet;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use rustgate_core::identity::Identity;
use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

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

/// GPS position in the NATS JSON wire format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WirePoint {
    pub lat: f64,
    pub lon: f64,
    pub hae: f64,
    pub ce: f64,
    pub le: f64,
}

/// Aggregated detail fields in the NATS JSON wire format.
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
    #[serde(
        default,
        rename = "_flow-tags_",
        skip_serializing_if = "Option::is_none"
    )]
    pub flow_tags: Option<WireFlowTags>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<WireStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sensor: Option<WireSensor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<WireGroup>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub takv: Option<WireTakv>,
    #[serde(
        default,
        rename = "precisionlocation",
        skip_serializing_if = "Option::is_none"
    )]
    pub precision_location: Option<WirePrecisionLocation>,
    #[serde(default, rename = "xmlDetail", skip_serializing_if = "Option::is_none")]
    pub xml_detail: Option<String>,
}

/// Speed and course in the NATS JSON wire format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireTrack {
    #[serde(default, skip_serializing_if = "is_zero_f64")]
    pub course: f64,
    #[serde(default, skip_serializing_if = "is_zero_f64")]
    pub speed: f64,
    #[serde(
        default,
        rename = "trackValid",
        skip_serializing_if = "std::ops::Not::not"
    )]
    pub track_valid: bool,
}

/// Per-UID metadata in the NATS JSON wire format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireUidDetail {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub callsign: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub droid: Option<String>,
}

/// Contact callsign and endpoint in the NATS JSON wire format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireContact {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub callsign: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
}

/// Free-text remarks/notes in the NATS JSON wire format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireRemarks {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub note: Vec<WireNote>,
}

/// Single remark entry with text, source, and timestamp.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireNote {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub text: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub source: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ts: String,
}

/// Flow control tags in the NATS JSON wire format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireFlowTags {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source: Vec<WireFlowSource>,
}

/// Source metadata for flow control.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireFlowSource {
    pub name: String,
    pub ts: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub host: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub uid: String,
}

/// Device status (battery, readiness) in the NATS JSON wire format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireStatus {
    #[serde(default, skip_serializing_if = "is_zero_i32")]
    pub battery: i32,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub readiness: String,
}

/// Sensor metadata in the NATS JSON wire format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireSensor {
    #[serde(default, skip_serializing_if = "is_zero_f64")]
    pub fov: f64,
    #[serde(default, skip_serializing_if = "is_zero_f64")]
    pub range: f64,
}

/// Team affiliation (name, role) in the NATS JSON wire format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireGroup {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub role: String,
}

/// Client software version in the NATS JSON wire format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireTakv {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub device: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub platform: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub os: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub version: String,
}

/// GPS precision metadata in the NATS JSON wire format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WirePrecisionLocation {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub geopointsrc: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub altsrc: String,
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

    /// Build a wire event from the full CoT parser output.
    ///
    /// Unlike `from_cot()`, this populates the detail section with track,
    /// contact, status, group, takv, precision location, and residual XML.
    #[cfg(feature = "full-detail")]
    pub fn from_full_cot(cot: &rustgate_proto::xml_full::FullCotEvent) -> Self {
        let detail = WireDetail {
            track: cot.track.as_ref().map(|t| WireTrack {
                course: t.course,
                speed: t.speed,
                track_valid: t.speed > 0.0 || t.course > 0.0,
            }),
            uid: None,
            contact: cot.contact.as_ref().map(|c| WireContact {
                callsign: if c.callsign.is_empty() {
                    None
                } else {
                    Some(c.callsign.clone())
                },
                endpoint: if c.endpoint.is_empty() {
                    None
                } else {
                    Some(c.endpoint.clone())
                },
            }),
            remarks: cot.remarks.as_ref().map(|r| WireRemarks {
                note: vec![WireNote {
                    text: r.text.clone(),
                    source: r.source.clone().unwrap_or_default(),
                    ts: r.timestamp.clone().unwrap_or_default(),
                }],
            }),
            flow_tags: None,
            status: cot.status.as_ref().map(|s| WireStatus {
                battery: i32::try_from(s.battery).unwrap_or(i32::MAX),
                readiness: String::new(),
            }),
            sensor: None,
            group: cot.group.as_ref().map(|g| WireGroup {
                name: g.name.clone(),
                role: g.role.clone(),
            }),
            takv: cot.takv.as_ref().map(|t| WireTakv {
                device: t.device.clone(),
                platform: t.platform.clone(),
                os: t.os.clone(),
                version: t.version.clone(),
            }),
            precision_location: cot
                .precision_location
                .as_ref()
                .map(|p| WirePrecisionLocation {
                    geopointsrc: p.geopointsrc.clone(),
                    altsrc: p.altsrc.clone(),
                }),
            xml_detail: if cot.xml_detail.is_empty() {
                None
            } else {
                Some(cot.xml_detail.clone())
            },
        };

        let has_any = detail.track.is_some()
            || detail.contact.is_some()
            || detail.remarks.is_some()
            || detail.status.is_some()
            || detail.group.is_some()
            || detail.takv.is_some()
            || detail.precision_location.is_some()
            || detail.xml_detail.is_some();

        Self {
            version: "2.0".to_string(),
            uid: cot.uid.clone(),
            event_type: cot.event_type.clone(),
            time: cot.time.clone(),
            start: cot.start.clone(),
            stale: cot.stale.clone(),
            how: cot.how.clone(),
            access: cot.access.clone(),
            qos: cot.qos.clone(),
            opex: cot.opex.clone(),
            point: WirePoint {
                lat: cot.lat,
                lon: cot.lon,
                hae: cot.hae,
                ce: cot.ce,
                le: cot.le,
            },
            detail: if has_any { Some(detail) } else { None },
        }
    }

    /// Convert a wire event into a RoutableMessage for local delivery.
    ///
    /// Accepts the original NATS payload bytes directly to avoid a redundant
    /// serialize round-trip and to preserve any unknown fields for forward
    /// compatibility. The source identity uses the UID as the CN (no mTLS
    /// identity for NATS-originated messages).
    pub fn into_routable(
        self,
        group: &str,
        payload: Bytes,
    ) -> Result<RoutableMessage, rustgate_core::identity::IdentityError> {
        let message_type = map_event_type(&self.event_type);

        let mut groups = BTreeSet::new();
        if !group.is_empty() {
            let _ = groups.insert(group.to_string());
        }

        let source = Identity::plaintext(self.uid.clone(), groups)?;

        Ok(RoutableMessage {
            source,
            destination: Destination::Broadcast,
            payload,
            metadata: Metadata {
                received_at: SystemTime::now(),
                source_protocol: "nats".to_string(),
                message_type,
                ttl: None,
            },
        })
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
                group: None,
                takv: None,
                precision_location: None,
                xml_detail: None,
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

        let track = event
            .detail
            .as_ref()
            .and_then(|d| d.track.as_ref())
            .expect("track");
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
            point: WirePoint {
                lat: 37.0,
                lon: -122.0,
                hae: 0.0,
                ce: 50.0,
                le: 30.0,
            },
            detail: None,
        };

        let msg = event
            .into_routable("Cyan", Bytes::from_static(b"{}"))
            .expect("valid identity");
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
            point: WirePoint {
                lat: 0.0,
                lon: 0.0,
                hae: 0.0,
                ce: 0.0,
                le: 0.0,
            },
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

    #[cfg(feature = "full-detail")]
    mod full_detail_tests {
        use rustgate_proto::xml_full::{
            ContactDetail, FullCotEvent, GroupDetail, PrecisionLocationDetail, StatusDetail,
            TakvDetail, TrackDetail,
        };

        use super::*;

        #[test]
        fn from_full_cot_populates_all_detail_fields() {
            let full = FullCotEvent {
                uid: "ALPHA-1".to_string(),
                event_type: "a-f-G-U-C".to_string(),
                how: "m-g".to_string(),
                time: "2026-02-27T12:00:00Z".to_string(),
                start: "2026-02-27T12:00:00Z".to_string(),
                stale: "2026-02-27T12:05:00Z".to_string(),
                lat: 37.7749,
                lon: -122.4194,
                hae: 10.5,
                ce: 50.0,
                le: 30.0,
                contact: Some(ContactDetail {
                    callsign: "ALPHA".to_string(),
                    endpoint: "*:-1:stcp".to_string(),
                }),
                group: Some(GroupDetail {
                    name: "Cyan".to_string(),
                    role: "Team Lead".to_string(),
                }),
                status: Some(StatusDetail { battery: 85 }),
                takv: Some(TakvDetail {
                    device: "iPhone".to_string(),
                    platform: "iTAK".to_string(),
                    os: "iOS 18".to_string(),
                    version: "2.12".to_string(),
                }),
                track: Some(TrackDetail {
                    speed: 10.5,
                    course: 90.0,
                }),
                precision_location: Some(PrecisionLocationDetail {
                    geopointsrc: "GPS".to_string(),
                    altsrc: "GPS".to_string(),
                }),
                ..Default::default()
            };

            let wire = WireEvent::from_full_cot(&full);

            assert_eq!(wire.uid, "ALPHA-1");
            assert_eq!(wire.event_type, "a-f-G-U-C");
            assert!((wire.point.lat - 37.7749).abs() < f64::EPSILON);

            let detail = wire.detail.expect("detail populated");

            let track = detail.track.expect("track");
            assert!((track.speed - 10.5).abs() < f64::EPSILON);
            assert!((track.course - 90.0).abs() < f64::EPSILON);
            assert!(track.track_valid);

            let contact = detail.contact.expect("contact");
            assert_eq!(contact.callsign.as_deref(), Some("ALPHA"));
            assert_eq!(contact.endpoint.as_deref(), Some("*:-1:stcp"));

            let group = detail.group.expect("group");
            assert_eq!(group.name, "Cyan");
            assert_eq!(group.role, "Team Lead");

            let status = detail.status.expect("status");
            assert_eq!(status.battery, 85);

            let takv = detail.takv.expect("takv");
            assert_eq!(takv.device, "iPhone");
            assert_eq!(takv.platform, "iTAK");

            let pl = detail.precision_location.expect("precision_location");
            assert_eq!(pl.geopointsrc, "GPS");
        }

        #[test]
        fn from_full_cot_round_trips_through_json() {
            let full = FullCotEvent {
                uid: "TEST-RT".to_string(),
                event_type: "a-f-G-U-C".to_string(),
                time: "2026-02-27T12:00:00Z".to_string(),
                start: "2026-02-27T12:00:00Z".to_string(),
                stale: "2026-02-27T12:05:00Z".to_string(),
                lat: 37.0,
                lon: -122.0,
                hae: 0.0,
                ce: 50.0,
                le: 30.0,
                contact: Some(ContactDetail {
                    callsign: "BRAVO".to_string(),
                    endpoint: String::new(),
                }),
                group: Some(GroupDetail {
                    name: "Red".to_string(),
                    role: "Team Member".to_string(),
                }),
                xml_detail: "<marti><dest callsign=\"CHARLIE\"/></marti>".to_string(),
                ..Default::default()
            };

            let wire = WireEvent::from_full_cot(&full);
            let json = serde_json::to_string(&wire).expect("serialize");
            let parsed: WireEvent = serde_json::from_str(&json).expect("deserialize");

            assert_eq!(parsed.uid, "TEST-RT");
            let detail = parsed.detail.expect("detail");
            assert_eq!(detail.group.as_ref().expect("group").name, "Red");
            assert_eq!(
                detail.xml_detail.as_deref(),
                Some("<marti><dest callsign=\"CHARLIE\"/></marti>")
            );
        }

        #[test]
        fn from_full_cot_no_detail_when_empty() {
            let full = FullCotEvent {
                uid: "MINIMAL".to_string(),
                event_type: "a-f-G".to_string(),
                lat: 37.0,
                lon: -122.0,
                ..Default::default()
            };

            let wire = WireEvent::from_full_cot(&full);
            assert!(wire.detail.is_none());
        }
    }
}
