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

        // Preserve the source `<event version="…">` attribute per MITRE CoT
        // Message Router User's Guide (MP090284) Table 2-1; fall back to
        // "2.0" only when the source XML omitted the attribute so JSON
        // consumers always see a valid schema version.
        let version = if cot.version.is_empty() {
            "2.0".to_string()
        } else {
            cot.version.clone()
        };

        Self {
            version,
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

    /// Check if the reported position should be treated as unknown.
    ///
    /// The base CoT specification (MITRE MP090284, Table 2-1) defines
    /// `ce` and `le` as 1-sigma error bounds in meters and does not
    /// reserve a formal "position unknown" sentinel. In practice,
    /// reporters signal an unknown fix by stuffing the error fields
    /// with a large magic value:
    ///
    /// * TAK ecosystem clients commonly emit `9999999` (seven 9s).
    /// * The MITRE reference routing GUI (Figure 6-5) uses `999999999`
    ///   (nine 9s) as an "effectively infinite error" convention.
    ///
    /// Rather than hard-code either sentinel, we treat any ce/le at or
    /// above `UNKNOWN_POSITION_ERROR` (1,000 km) as "unknown". Earth's
    /// equatorial radius is ~6,371 km; no realistic GPS/INS report has
    /// a 1-sigma error approaching 1,000 km, so the threshold catches
    /// every known sentinel convention without false positives.
    ///
    /// Both `ce` and `le` must exceed the threshold. A reporter with a
    /// valid 2-D fix but unknown altitude error is still usable.
    ///
    /// The earlier implementation treated `lat == 0.0 && lon == 0.0` as
    /// unknown, which silently dropped legitimate reports from the
    /// Gulf of Guinea and other equatorial waters.
    pub fn is_position_unknown(&self) -> bool {
        self.point.ce >= UNKNOWN_POSITION_ERROR && self.point.le >= UNKNOWN_POSITION_ERROR
    }
}

/// Threshold (meters) above which `ce`/`le` are treated as "position unknown".
///
/// The CoT base spec does not define a sentinel, but all known reporter
/// implementations use a large magic value (`9999999` for TAK,
/// `999999999` for the MITRE reference GUI). 1,000 km is below every
/// observed sentinel and well above any legitimate GPS/INS 1-sigma
/// error, so matching "ce ≥ threshold AND le ≥ threshold" is a robust
/// cross-implementation test.
pub const UNKNOWN_POSITION_ERROR: f64 = 1_000_000.0;

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
        assert_eq!(&*msg.source.cn, "test-uid");
        assert!(msg.source.groups.contains("Cyan"));
        assert!(matches!(msg.metadata.message_type, MessageType::Position));
    }

    #[test]
    fn position_unknown_requires_ce_le_sentinel() {
        // Helper to build a WireEvent with a given point — the non-point
        // fields are irrelevant to the position-unknown predicate.
        fn event_with_point(point: WirePoint) -> WireEvent {
            WireEvent {
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
                point,
                detail: None,
            }
        }

        // TAK convention: both ce and le at 9_999_999 (seven 9s) → unknown.
        assert!(
            event_with_point(WirePoint {
                lat: 37.0,
                lon: -122.0,
                hae: 0.0,
                ce: 9_999_999.0,
                le: 9_999_999.0,
            })
            .is_position_unknown(),
            "TAK sentinel ce=le=9999999 must be treated as position unknown"
        );

        // MITRE reference-GUI convention: both at 999_999_999 (nine 9s) → unknown.
        assert!(
            event_with_point(WirePoint {
                lat: 37.0,
                lon: -122.0,
                hae: 0.0,
                ce: 999_999_999.0,
                le: 999_999_999.0,
            })
            .is_position_unknown(),
            "MITRE reference sentinel ce=le=999999999 must be treated as position unknown"
        );

        // 0,0 with a valid fix is NOT unknown (equatorial ocean).
        assert!(
            !event_with_point(WirePoint {
                lat: 0.0,
                lon: 0.0,
                hae: 0.0,
                ce: 50.0,
                le: 30.0,
            })
            .is_position_unknown(),
            "0,0 with valid ce/le is a legitimate equatorial fix"
        );

        // Realistic large-but-not-sentinel error (500 m) → known.
        assert!(
            !event_with_point(WirePoint {
                lat: 37.0,
                lon: -122.0,
                hae: 0.0,
                ce: 500.0,
                le: 500.0,
            })
            .is_position_unknown(),
            "realistic GPS-degraded error must not trip the unknown threshold"
        );

        // Only one of ce/le at the sentinel is NOT unknown — a valid
        // 2-D fix with unknown altitude error is still a fix.
        assert!(
            !event_with_point(WirePoint {
                lat: 37.0,
                lon: -122.0,
                hae: 0.0,
                ce: 50.0,
                le: UNKNOWN_POSITION_ERROR,
            })
            .is_position_unknown(),
            "ce-valid, le-unknown should be treated as known"
        );
    }

    #[test]
    fn format_rfc3339_produces_valid_timestamp() {
        let ts = format_rfc3339(SystemTime::now());
        assert!(ts.ends_with('Z'), "timestamp should be UTC: {ts}");
        assert!(ts.contains('T'), "should have date/time separator: {ts}");
    }

    // -----------------------------------------------------------------------
    // Constant pins
    //
    // `UNKNOWN_POSITION_ERROR` is a doc-comment contract: "1,000 km, below
    // every observed sentinel and above any legitimate GPS/INS 1-sigma
    // error". A silent bump would either invite false positives (too low)
    // or silently accept TAK-sentinel `9_999_999` / MITRE-sentinel
    // `999_999_999` reports as valid fixes (too high). Pin the literal.
    // -----------------------------------------------------------------------

    #[test]
    fn unknown_position_error_threshold_is_one_million_meters() {
        // 1,000,000 meters = 1,000 km. Both TAK (7×9 → 9_999_999) and
        // MITRE (9×9 → 999_999_999) sentinels exceed this, and no real-
        // world GPS/INS 1-sigma error approaches it. Change at your peril.
        assert_eq!(UNKNOWN_POSITION_ERROR, 1_000_000.0);
    }

    // -----------------------------------------------------------------------
    // `is_position_unknown` boundary contract
    //
    // The predicate is `ce >= threshold && le >= threshold`. Pin both sides
    // of the inclusive boundary so a regression to `>` (which would leak
    // the exact-threshold case through as "known") fails here rather than
    // at a live sensor report.
    // -----------------------------------------------------------------------

    fn event_with_point(point: WirePoint) -> WireEvent {
        WireEvent {
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
            point,
            detail: None,
        }
    }

    #[test]
    fn is_position_unknown_true_exactly_at_threshold_inclusive() {
        // `ce == le == UNKNOWN_POSITION_ERROR` must trip the predicate.
        // A regression to strict-greater comparison would classify this
        // as known and silently forward zero-confidence fixes.
        let event = event_with_point(WirePoint {
            lat: 37.0,
            lon: -122.0,
            hae: 0.0,
            ce: UNKNOWN_POSITION_ERROR,
            le: UNKNOWN_POSITION_ERROR,
        });
        assert!(
            event.is_position_unknown(),
            "inclusive boundary: ce==le==threshold must be unknown"
        );
    }

    #[test]
    fn is_position_unknown_false_just_below_threshold() {
        // One-epsilon-below each side must stay known, pinning the
        // negation arm of the boundary.
        let event = event_with_point(WirePoint {
            lat: 37.0,
            lon: -122.0,
            hae: 0.0,
            ce: UNKNOWN_POSITION_ERROR - 1.0,
            le: UNKNOWN_POSITION_ERROR - 1.0,
        });
        assert!(
            !event.is_position_unknown(),
            "one meter under the threshold on both axes must be known"
        );
    }

    // -----------------------------------------------------------------------
    // Helper predicates
    //
    // `is_zero_f64` and `is_zero_i32` gate `skip_serializing_if`. Missing
    // IEEE 754 edge cases (NaN, ±∞, signed zero) would either silently
    // strip legitimate zero-is-valid readings (NaN coerced to "is zero")
    // or emit redundant field values that confuse downstream consumers.
    // -----------------------------------------------------------------------

    #[test]
    fn is_zero_f64_treats_negative_zero_as_zero() {
        // IEEE 754 -0.0 compares equal to +0.0, and this helper relies
        // on `==` semantics. Pin the contract so a refactor to bitwise
        // comparison (which would classify -0.0 as non-zero) trips here.
        assert!(is_zero_f64(&0.0));
        assert!(is_zero_f64(&-0.0));
    }

    #[test]
    fn is_zero_f64_rejects_nan_and_infinities() {
        // NaN ≠ NaN by spec, so `NaN == 0.0` is false. ±∞ likewise not
        // zero. A regression that used `!= 0.0` truth-tables incorrectly
        // (or rolled to `f64::total_cmp`) would silently drift here.
        assert!(!is_zero_f64(&f64::NAN));
        assert!(!is_zero_f64(&f64::INFINITY));
        assert!(!is_zero_f64(&f64::NEG_INFINITY));
    }

    #[test]
    fn is_zero_f64_rejects_subnormal_and_tiny_nonzero() {
        // Smallest positive subnormal is non-zero — skip_serializing_if
        // must leave it in the JSON stream.
        assert!(!is_zero_f64(&f64::MIN_POSITIVE));
        assert!(!is_zero_f64(&1e-300));
    }

    #[test]
    fn is_zero_i32_handles_boundary_values() {
        // Only literal zero counts. Negative one, INT_MAX, INT_MIN are
        // all non-zero battery readings and must be serialized.
        assert!(is_zero_i32(&0));
        assert!(!is_zero_i32(&-1));
        assert!(!is_zero_i32(&1));
        assert!(!is_zero_i32(&i32::MAX));
        assert!(!is_zero_i32(&i32::MIN));
    }

    // -----------------------------------------------------------------------
    // `map_event_type` dispatch table
    //
    // The four-branch classifier drives `MessageType` on every inbound
    // NATS message; a silent rearrangement (e.g. swapping the `a-` and
    // `b-a` checks) would reclassify every position as an alert. Pin
    // each branch to a specific input string.
    // -----------------------------------------------------------------------

    #[test]
    fn map_event_type_a_prefix_routes_to_position() {
        // Any `a-*` event type → Position (affiliated contact).
        assert!(matches!(map_event_type("a-f-G-U-C"), MessageType::Position));
        assert!(matches!(map_event_type("a-u-G"), MessageType::Position));
        assert!(matches!(map_event_type("a-"), MessageType::Position));
    }

    #[test]
    fn map_event_type_b_t_f_prefix_routes_to_chat() {
        // `b-t-f*` → Chat (free-text). The prefix is longer than the
        // catch-all `b-a`, so its branch must match first.
        assert!(matches!(map_event_type("b-t-f"), MessageType::Chat));
        assert!(matches!(map_event_type("b-t-f-r"), MessageType::Chat));
    }

    #[test]
    fn map_event_type_b_a_prefix_routes_to_alert() {
        // `b-a*` but NOT `b-t-f*` → Alert (a 9-line CASEVAC is `b-a-o`).
        assert!(matches!(map_event_type("b-a"), MessageType::Alert));
        assert!(matches!(map_event_type("b-a-o"), MessageType::Alert));
    }

    #[test]
    fn map_event_type_unknown_prefix_falls_through_to_other() {
        // Anything not in the three tagged prefixes is preserved
        // verbatim in `MessageType::Other`, so operators can see the
        // raw event-type string in logs.
        let takp = map_event_type("t-x-takp-q");
        assert!(
            matches!(&takp, MessageType::Other(s) if s == "t-x-takp-q"),
            "expected Other(\"t-x-takp-q\"), got {takp:?}"
        );
        let empty = map_event_type("");
        assert!(
            matches!(&empty, MessageType::Other(s) if s.is_empty()),
            "expected Other(\"\"), got {empty:?}"
        );
    }

    #[test]
    fn map_event_type_b_prefix_without_a_or_t_f_falls_through() {
        // `b-i` and `b-r` exist in the spec but are neither chat nor
        // alert. They must pass through as `Other`, NOT misclassify.
        let bi = map_event_type("b-i");
        assert!(
            matches!(&bi, MessageType::Other(s) if s == "b-i"),
            "b-i must not alias to a tagged MessageType; got {bi:?}"
        );
    }

    // -----------------------------------------------------------------------
    // `format_rfc3339` pins
    //
    // The RFC 3339 emitter is the sole way NATS wire events encode time.
    // Downstream consumers parse with `Z`-suffix-aware libraries, so a
    // regression that shipped a `+00:00` suffix would break every strict
    // parser (including Java/Kotlin ecosystems that require trailing Z).
    // -----------------------------------------------------------------------

    #[test]
    fn format_rfc3339_of_unix_epoch_is_1970_01_01() {
        // The epoch is the deterministic anchor. A regression to a
        // local-time formatter would render a non-UTC offset here.
        assert_eq!(
            format_rfc3339(SystemTime::UNIX_EPOCH),
            "1970-01-01T00:00:00Z"
        );
    }

    #[test]
    fn format_rfc3339_truncates_subsecond_precision() {
        // `replace_nanosecond(0)` drops all sub-second precision so
        // emitted timestamps are whole seconds regardless of source
        // granularity. Pin that a non-zero nanosecond input still
        // serializes without a fractional part.
        let t = SystemTime::UNIX_EPOCH + Duration::from_nanos(123_456_789);
        let out = format_rfc3339(t);
        assert!(
            !out.contains('.'),
            "sub-second digits must be truncated: {out}"
        );
        assert!(out.ends_with('Z'));
    }

    // -----------------------------------------------------------------------
    // `from_cot` defaults
    //
    // `from_cot` is the fallback path for parsed events that didn't go
    // through the full-detail pipeline; its default field values are
    // hard-coded and operator-visible over the wire. Pin the literals.
    // -----------------------------------------------------------------------

    #[test]
    fn from_cot_emits_mg_how_and_default_ce_le_and_version_two() {
        let cot = rustgate_cot::CotEvent {
            uid: "FROM-COT-1".to_string(),
            event_type: "a-f-G".to_string(),
            destination: rustgate_cot::CotDestination::Broadcast,
            message_type: MessageType::Position,
            position: Some(rustgate_cot::Position {
                lat: 1.0,
                lon: 2.0,
                hae: 3.0,
            }),
            ttl: None,
            source_group: None,
        };
        let wire = WireEvent::from_cot(&cot);
        assert_eq!(wire.version, "2.0");
        assert_eq!(wire.how, "m-g");
        assert!((wire.point.ce - 50.0).abs() < f64::EPSILON);
        assert!((wire.point.le - 30.0).abs() < f64::EPSILON);
        assert_eq!(wire.uid, "FROM-COT-1");
        assert!((wire.point.lat - 1.0).abs() < f64::EPSILON);
        assert!((wire.point.lon - 2.0).abs() < f64::EPSILON);
        assert!((wire.point.hae - 3.0).abs() < f64::EPSILON);
        assert!(wire.detail.is_none(), "from_cot must not invent details");
    }

    #[test]
    fn from_cot_without_position_emits_zero_zero_zero() {
        // Missing position is valid (e.g. a chat-only event). The
        // serializer must not panic, and the point must default to
        // (0, 0, 0) rather than producing a malformed JSON structure.
        let cot = rustgate_cot::CotEvent {
            uid: "NO-POS".to_string(),
            event_type: "b-t-f".to_string(),
            destination: rustgate_cot::CotDestination::Broadcast,
            message_type: MessageType::Chat,
            position: None,
            ttl: None,
            source_group: None,
        };
        let wire = WireEvent::from_cot(&cot);
        assert!((wire.point.lat - 0.0).abs() < f64::EPSILON);
        assert!((wire.point.lon - 0.0).abs() < f64::EPSILON);
        assert!((wire.point.hae - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn from_cot_stale_defaults_to_five_minutes_after_time_when_ttl_is_none() {
        // When CotEvent carries no TTL, the wire contract stales the
        // event at now+300s. Pin both: stale differs from time, and
        // the difference is exactly 300 seconds parseable via RFC 3339.
        let cot = rustgate_cot::CotEvent {
            uid: "STALE-DEFAULT".to_string(),
            event_type: "a-f-G".to_string(),
            destination: rustgate_cot::CotDestination::Broadcast,
            message_type: MessageType::Position,
            position: None,
            ttl: None,
            source_group: None,
        };
        let wire = WireEvent::from_cot(&cot);
        assert_ne!(wire.time, wire.stale, "stale must advance past time");
        let time = OffsetDateTime::parse(&wire.time, &Rfc3339).expect("parse time");
        let stale = OffsetDateTime::parse(&wire.stale, &Rfc3339).expect("parse stale");
        let delta = (stale - time).whole_seconds();
        assert_eq!(
            delta, 300,
            "default stale window must be exactly 300s, got {delta}"
        );
    }

    #[test]
    fn from_cot_stale_honours_supplied_ttl() {
        // A non-default TTL must flow through into the emitted stale
        // field verbatim (to the second). Pin a 42-second TTL.
        let cot = rustgate_cot::CotEvent {
            uid: "TTL-42".to_string(),
            event_type: "a-f-G".to_string(),
            destination: rustgate_cot::CotDestination::Broadcast,
            message_type: MessageType::Position,
            position: None,
            ttl: Some(Duration::from_secs(42)),
            source_group: None,
        };
        let wire = WireEvent::from_cot(&cot);
        let time = OffsetDateTime::parse(&wire.time, &Rfc3339).expect("parse time");
        let stale = OffsetDateTime::parse(&wire.stale, &Rfc3339).expect("parse stale");
        assert_eq!((stale - time).whole_seconds(), 42);
    }

    #[test]
    fn from_cot_time_and_start_agree() {
        // `time` and `start` are both assigned from the same `now_str`
        // so they must be bit-for-bit identical. A refactor that
        // re-invoked `format_rfc3339` twice around a second boundary
        // could diverge by one second and silently break dedup logic
        // keyed on the pair.
        let cot = rustgate_cot::CotEvent {
            uid: "TIME-START".to_string(),
            event_type: "a-f-G".to_string(),
            destination: rustgate_cot::CotDestination::Broadcast,
            message_type: MessageType::Position,
            position: None,
            ttl: None,
            source_group: None,
        };
        let wire = WireEvent::from_cot(&cot);
        assert_eq!(wire.time, wire.start, "time and start must be identical");
    }

    // -----------------------------------------------------------------------
    // `into_routable` contract
    //
    // The conversion drops NATS-origin messages into the router with a
    // broadcast destination, the UID as the source CN, and the
    // `"nats"` source-protocol tag. Operators grep that literal in
    // logs and metrics, so pin every observable field of the result.
    // -----------------------------------------------------------------------

    fn plain_event(uid: &str, etype: &str) -> WireEvent {
        WireEvent {
            version: "2.0".to_string(),
            uid: uid.to_string(),
            event_type: etype.to_string(),
            time: "2026-01-01T00:00:00Z".to_string(),
            start: "2026-01-01T00:00:00Z".to_string(),
            stale: "2026-01-01T00:05:00Z".to_string(),
            how: String::new(),
            access: String::new(),
            qos: String::new(),
            opex: String::new(),
            point: WirePoint {
                lat: 0.0,
                lon: 0.0,
                hae: 0.0,
                ce: 50.0,
                le: 30.0,
            },
            detail: None,
        }
    }

    #[test]
    fn into_routable_destination_is_broadcast_regardless_of_group() {
        // NATS-origin messages go onto the local bus as broadcasts;
        // the subscribing router's ACL gates group-level delivery.
        let msg = plain_event("B1", "a-f-G")
            .into_routable("any-group", Bytes::from_static(b"{}"))
            .expect("identity");
        assert!(matches!(msg.destination, Destination::Broadcast));
    }

    #[test]
    fn into_routable_metadata_ttl_is_none() {
        // The wire event has a `stale` string but no machine-readable
        // TTL, so router metadata.ttl must be None (let the router use
        // its own stale-detection path). A regression that derived a
        // TTL from the stale field would introduce clock-skew drift.
        let msg = plain_event("T1", "a-f-G")
            .into_routable("", Bytes::from_static(b"{}"))
            .expect("identity");
        assert!(msg.metadata.ttl.is_none());
    }

    #[test]
    fn into_routable_source_protocol_is_nats_literal() {
        // Metrics and dashboards key on the literal string `"nats"`.
        // Silent renames (e.g. to `"nats-jetstream"`) would invalidate
        // every operator's Grafana query in a zero-downtime reload.
        let msg = plain_event("P1", "a-f-G")
            .into_routable("", Bytes::from_static(b"{}"))
            .expect("identity");
        assert_eq!(msg.metadata.source_protocol, "nats");
    }

    #[test]
    fn into_routable_empty_group_does_not_insert_empty_string() {
        // Empty-group input must produce an empty `groups` set — never
        // insert the literal empty string, which would match every
        // group-scoped ACL rule keyed on "".
        let msg = plain_event("EMPTY", "a-f-G")
            .into_routable("", Bytes::from_static(b"{}"))
            .expect("identity");
        assert!(msg.source.groups.is_empty(), "empty group must stay empty");
    }

    #[test]
    fn into_routable_cn_is_event_uid() {
        // The source CN is the event UID for NATS-origin messages
        // (no mTLS identity). Pin the invariant: whatever UID the
        // wire event carries must match the emitted Identity.cn.
        let msg = plain_event("UNIQUE-UID", "a-f-G")
            .into_routable("", Bytes::from_static(b"{}"))
            .expect("identity");
        assert_eq!(&*msg.source.cn, "UNIQUE-UID");
    }

    #[test]
    fn into_routable_message_type_follows_event_type_classifier() {
        // The metadata.message_type is classified by `map_event_type`,
        // so the routing decision must agree with the raw dispatch.
        let pos = plain_event("CLASS-POS", "a-f-G")
            .into_routable("", Bytes::from_static(b"{}"))
            .expect("identity");
        assert!(matches!(pos.metadata.message_type, MessageType::Position));

        let chat = plain_event("CLASS-CHAT", "b-t-f")
            .into_routable("", Bytes::from_static(b"{}"))
            .expect("identity");
        assert!(matches!(chat.metadata.message_type, MessageType::Chat));

        let alert = plain_event("CLASS-ALERT", "b-a-o")
            .into_routable("", Bytes::from_static(b"{}"))
            .expect("identity");
        assert!(matches!(alert.metadata.message_type, MessageType::Alert));

        let other = plain_event("CLASS-OTHER", "t-x-takp")
            .into_routable("", Bytes::from_static(b"{}"))
            .expect("identity");
        assert!(
            matches!(&other.metadata.message_type, MessageType::Other(s) if s == "t-x-takp"),
            "got {:?}",
            other.metadata.message_type,
        );
    }

    #[test]
    fn into_routable_payload_bytes_pass_through_byte_for_byte() {
        // The payload must be the exact bytes supplied (zero-copy
        // via `Bytes`). Pin by feeding non-JSON raw bytes and checking
        // equality on the router side.
        let payload = Bytes::from_static(b"\x00\x01\x02raw-bytes");
        let msg = plain_event("RAW", "a-f-G")
            .into_routable("", payload.clone())
            .expect("identity");
        assert_eq!(msg.payload, payload);
    }

    // -----------------------------------------------------------------------
    // Serde rename / skip-serializing contract
    //
    // The JSON field names are an external API contract with every
    // non-rustgate consumer of the NATS bus. A typo in `rename = "…"`
    // silently breaks interop on every deployed client. Pin each one.
    // -----------------------------------------------------------------------

    #[test]
    fn wire_event_serializes_event_type_as_type_key() {
        // `event_type` → JSON `"type"` is documented in the struct's
        // serde attribute and relied on by every non-rustgate consumer.
        let event = plain_event("RN", "a-f-G");
        let json = serde_json::to_string(&event).expect("serialize");
        assert!(
            json.contains("\"type\":\"a-f-G\""),
            "event_type must serialize as JSON key `type`: {json}"
        );
        assert!(
            !json.contains("\"event_type\""),
            "serialized form must not leak the Rust field name: {json}"
        );
    }

    #[test]
    fn wire_event_omits_empty_optional_strings_via_skip_serializing_if() {
        // `how`, `access`, `qos`, `opex` default to empty and are
        // `skip_serializing_if = "String::is_empty"`. A regression that
        // dropped the attribute would bloat the wire with four empty
        // string fields per event — doubling bandwidth for chat bursts.
        let event = plain_event("OMIT", "a-f-G");
        let json = serde_json::to_string(&event).expect("serialize");
        assert!(
            !json.contains("\"how\""),
            "empty how must be elided: {json}"
        );
        assert!(
            !json.contains("\"access\""),
            "empty access must be elided: {json}"
        );
        assert!(
            !json.contains("\"qos\""),
            "empty qos must be elided: {json}"
        );
        assert!(
            !json.contains("\"opex\""),
            "empty opex must be elided: {json}"
        );
    }

    #[test]
    fn wire_event_omits_absent_detail_section() {
        // `detail: None` must elide the whole `"detail": null` field.
        let event = plain_event("DETAIL-NONE", "a-f-G");
        let json = serde_json::to_string(&event).expect("serialize");
        assert!(
            !json.contains("\"detail\""),
            "absent detail section must be elided, not nulled: {json}"
        );
    }

    #[test]
    fn wire_track_renames_track_valid_to_camel_case() {
        // `trackValid` is the wire convention (MITRE MP090284 section
        // 6.3.4); Rust-convention `track_valid` would break interop.
        let track = WireTrack {
            course: 0.0,
            speed: 0.0,
            track_valid: true,
        };
        let json = serde_json::to_string(&track).expect("serialize");
        assert!(
            json.contains("\"trackValid\":true"),
            "must emit camelCase `trackValid`, got {json}"
        );
        assert!(
            !json.contains("\"track_valid\""),
            "must not leak snake_case Rust name: {json}"
        );
    }

    #[test]
    fn wire_track_skips_zero_course_speed_and_false_track_valid() {
        // Full-default track must serialize to `{}` — all three fields
        // are `skip_serializing_if` gated.
        let track = WireTrack {
            course: 0.0,
            speed: 0.0,
            track_valid: false,
        };
        let json = serde_json::to_string(&track).expect("serialize");
        assert_eq!(json, "{}", "zero/false track must elide every field");
    }

    #[test]
    fn wire_detail_renames_flow_tags_to_underscored_form() {
        // The `_flow-tags_` key uses leading/trailing underscore per
        // MITRE convention; Rust-convention `flow_tags` would break
        // interop with every TAK server that consumes this detail.
        let detail = WireDetail {
            track: None,
            uid: None,
            contact: None,
            remarks: None,
            flow_tags: Some(WireFlowTags { source: vec![] }),
            status: None,
            sensor: None,
            group: None,
            takv: None,
            precision_location: None,
            xml_detail: None,
        };
        let json = serde_json::to_string(&detail).expect("serialize");
        assert!(
            json.contains("\"_flow-tags_\""),
            "must emit `_flow-tags_` literal, got {json}"
        );
        assert!(
            !json.contains("\"flow_tags\""),
            "Rust name must not leak to wire: {json}"
        );
    }

    #[test]
    fn wire_detail_renames_precision_location_to_single_word() {
        // `precisionlocation` (no camel case, no underscore) is the
        // spec-mandated key. Pin against the two wrong variants.
        let detail = WireDetail {
            track: None,
            uid: None,
            contact: None,
            remarks: None,
            flow_tags: None,
            status: None,
            sensor: None,
            group: None,
            takv: None,
            precision_location: Some(WirePrecisionLocation {
                geopointsrc: "GPS".to_string(),
                altsrc: "GPS".to_string(),
            }),
            xml_detail: None,
        };
        let json = serde_json::to_string(&detail).expect("serialize");
        assert!(
            json.contains("\"precisionlocation\""),
            "must emit single-word `precisionlocation`, got {json}"
        );
        assert!(
            !json.contains("\"precision_location\""),
            "underscored form must not leak: {json}"
        );
        assert!(
            !json.contains("\"precisionLocation\""),
            "camelCase form must not leak: {json}"
        );
    }

    #[test]
    fn wire_detail_renames_xml_detail_to_camel_case() {
        // `xmlDetail` is the FreeTAKServer-compatible key. Snake-case
        // would break round-trip translation via FTS.
        let detail = WireDetail {
            track: None,
            uid: None,
            contact: None,
            remarks: None,
            flow_tags: None,
            status: None,
            sensor: None,
            group: None,
            takv: None,
            precision_location: None,
            xml_detail: Some("<inner/>".to_string()),
        };
        let json = serde_json::to_string(&detail).expect("serialize");
        assert!(
            json.contains("\"xmlDetail\""),
            "must emit camelCase `xmlDetail`, got {json}"
        );
        assert!(
            !json.contains("\"xml_detail\""),
            "snake_case must not leak: {json}"
        );
    }

    // -----------------------------------------------------------------------
    // `#[serde(default)]` tolerance
    //
    // Forward compatibility: every optional field must tolerate missing
    // JSON keys so a consumer of an older schema can parse a newer event
    // without an explicit migration step.
    // -----------------------------------------------------------------------

    #[test]
    fn wire_event_deserializes_minimal_json_with_every_optional_missing() {
        // No detail, no how, no access, no qos, no opex — but parse OK.
        let minimal = r#"{
            "version": "2.0",
            "uid": "MIN",
            "type": "a-f-G",
            "time": "2026-01-01T00:00:00Z",
            "start": "2026-01-01T00:00:00Z",
            "stale": "2026-01-01T00:05:00Z",
            "point": {"lat": 0, "lon": 0, "hae": 0, "ce": 50, "le": 30}
        }"#;
        let event: WireEvent = serde_json::from_str(minimal).expect("minimal parse");
        assert_eq!(event.uid, "MIN");
        assert!(event.how.is_empty());
        assert!(event.access.is_empty());
        assert!(event.qos.is_empty());
        assert!(event.opex.is_empty());
        assert!(event.detail.is_none());
    }

    #[test]
    fn wire_detail_deserializes_empty_object_as_all_none() {
        // Empty detail object must yield a WireDetail with every
        // Option::None — no panic, no default-construction surprise.
        let detail: WireDetail = serde_json::from_str("{}").expect("empty detail");
        assert!(detail.track.is_none());
        assert!(detail.uid.is_none());
        assert!(detail.contact.is_none());
        assert!(detail.remarks.is_none());
        assert!(detail.flow_tags.is_none());
        assert!(detail.status.is_none());
        assert!(detail.sensor.is_none());
        assert!(detail.group.is_none());
        assert!(detail.takv.is_none());
        assert!(detail.precision_location.is_none());
        assert!(detail.xml_detail.is_none());
    }

    // -----------------------------------------------------------------------
    // Type-surface pins
    //
    // The wire types flow across async task boundaries (NATS subscriber
    // task → router) and through the decoder pipeline. Compile-time
    // bounds stay pinned via a generic helper so a refactor that broke
    // any of them fails at test-compile, not at the first send site.
    // -----------------------------------------------------------------------

    #[test]
    fn wire_types_implement_send_sync_clone_debug() {
        fn assert_bounds<T: Send + Sync + Clone + std::fmt::Debug>() {}
        assert_bounds::<WireEvent>();
        assert_bounds::<WirePoint>();
        assert_bounds::<WireDetail>();
        assert_bounds::<WireTrack>();
        assert_bounds::<WireContact>();
        assert_bounds::<WireRemarks>();
        assert_bounds::<WireNote>();
        assert_bounds::<WireFlowTags>();
        assert_bounds::<WireFlowSource>();
        assert_bounds::<WireStatus>();
        assert_bounds::<WireSensor>();
        assert_bounds::<WireGroup>();
        assert_bounds::<WireTakv>();
        assert_bounds::<WirePrecisionLocation>();
        assert_bounds::<WireUidDetail>();
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

        #[test]
        fn from_full_cot_preserves_version_attribute() {
            // Source XML advertises a non-"2.0" schema version — a compliant
            // translator must echo it back on the JSON wire per MITRE
            // MP090284 Table 2-1, not silently rewrite it to "2.0".
            let full = FullCotEvent {
                version: "2.1".to_string(),
                uid: "VER-1".to_string(),
                event_type: "a-f-G".to_string(),
                ..Default::default()
            };

            let wire = WireEvent::from_full_cot(&full);
            assert_eq!(wire.version, "2.1");
        }

        #[test]
        fn from_full_cot_defaults_version_when_source_omits_it() {
            // Backward-compat fallback: if upstream parser produced an empty
            // version (e.g. the source XML omitted the attribute), we emit
            // "2.0" rather than a blank string so JSON consumers always see a
            // conforming version token.
            let full = FullCotEvent {
                uid: "VER-MISSING".to_string(),
                event_type: "a-f-G".to_string(),
                ..Default::default()
            };

            let wire = WireEvent::from_full_cot(&full);
            assert_eq!(wire.version, "2.0");
        }
    }
}
