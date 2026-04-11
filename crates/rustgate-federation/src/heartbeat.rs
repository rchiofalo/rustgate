// Copyright © 2026 Roberto Chiofalo.

//! Federation heartbeat generation and detection.
//!
//! Federation peers exchange periodic heartbeat messages (CoT type `t-x-c-t`)
//! to maintain connection liveness. [`create_heartbeat`] builds the XML payload
//! and [`is_heartbeat`] performs a fast byte-level check without full XML parsing.

use bytes::Bytes;

/// CoT event type for federation heartbeat messages.
pub const HEARTBEAT_TYPE: &str = "t-x-c-t";

/// Default TAK server UID used in heartbeat messages.
const DEFAULT_SERVER_UID: &str = "tak-server";

/// Create a CoT heartbeat message for federation keepalive.
///
/// Generates a CoT XML event with type `t-x-c-t` and the given server UID.
/// Timestamps are set to the current UTC time with a 60-second stale window.
pub fn create_heartbeat(server_uid: &str) -> Bytes {
    let uid = if server_uid.is_empty() {
        DEFAULT_SERVER_UID
    } else {
        server_uid
    };

    let now = time::OffsetDateTime::now_utc();
    let stale = now + time::Duration::seconds(60);

    let format = time::format_description::well_known::Iso8601::DEFAULT;
    let now_str = now
        .format(&format)
        .unwrap_or_else(|_| String::from("1970-01-01T00:00:00Z"));
    let stale_str = stale
        .format(&format)
        .unwrap_or_else(|_| String::from("1970-01-01T00:00:00Z"));

    let xml = format!(
        "<event version=\"2.0\" uid=\"{uid}\" type=\"{HEARTBEAT_TYPE}\" \
         time=\"{now_str}\" start=\"{now_str}\" stale=\"{stale_str}\" \
         how=\"h-g-i-g-o\">\
         <point lat=\"0.0\" lon=\"0.0\" hae=\"0.0\" ce=\"999999\" le=\"999999\"/>\
         <detail/>\
         </event>"
    );

    Bytes::from(xml)
}

/// Check whether a payload is a heartbeat message.
///
/// Performs a quick byte-level check for the `t-x-c-t` type attribute
/// without full XML parsing for performance.
pub fn is_heartbeat(payload: &[u8]) -> bool {
    // Look for type="t-x-c-t" or type='t-x-c-t' in the first portion of the payload.
    // Limit search to first 512 bytes to avoid scanning large messages.
    let search_limit = payload.len().min(512);
    let haystack = &payload[..search_limit];

    // Check for double-quoted and single-quoted variants
    // type="t-x-c-t" is 14 bytes, type='t-x-c-t' is also 14 bytes
    haystack
        .windows(14)
        .any(|w| w == b"type=\"t-x-c-t\"" || w == b"type='t-x-c-t'")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_heartbeat_produces_valid_xml() {
        let hb = create_heartbeat("test-server");
        let xml = std::str::from_utf8(&hb).expect("valid utf8");

        assert!(xml.starts_with("<event"));
        assert!(xml.contains("type=\"t-x-c-t\""));
        assert!(xml.contains("uid=\"test-server\""));
        assert!(xml.contains("<point"));
        assert!(xml.contains("<detail/>"));
    }

    #[test]
    fn create_heartbeat_empty_uid_uses_default() {
        let hb = create_heartbeat("");
        let xml = std::str::from_utf8(&hb).expect("valid utf8");
        assert!(xml.contains("uid=\"tak-server\""));
    }

    #[test]
    fn is_heartbeat_detects_double_quotes() {
        let xml = b"<event version=\"2.0\" uid=\"s\" type=\"t-x-c-t\" time=\"t\">";
        assert!(is_heartbeat(xml));
    }

    #[test]
    fn is_heartbeat_detects_single_quotes() {
        let xml = b"<event version='2.0' uid='s' type='t-x-c-t' time='t'>";
        assert!(is_heartbeat(xml));
    }

    #[test]
    fn is_heartbeat_rejects_non_heartbeat() {
        let xml = b"<event version=\"2.0\" uid=\"s\" type=\"a-f-G-U-C\" time=\"t\">";
        assert!(!is_heartbeat(xml));
    }

    #[test]
    fn is_heartbeat_rejects_empty() {
        assert!(!is_heartbeat(b""));
    }

    #[test]
    fn is_heartbeat_rejects_short_payload() {
        assert!(!is_heartbeat(b"<event>"));
    }

    #[test]
    fn create_heartbeat_round_trip_detection() {
        let hb = create_heartbeat("my-server");
        assert!(is_heartbeat(&hb));
    }

    #[test]
    fn create_heartbeat_contains_timestamps() {
        let hb = create_heartbeat("test-server");
        let xml = std::str::from_utf8(&hb).expect("valid utf8");
        assert!(xml.contains("time="));
        assert!(xml.contains("start="));
        assert!(xml.contains("stale="));
    }

    #[test]
    fn create_heartbeat_contains_how_attribute() {
        let hb = create_heartbeat("test-server");
        let xml = std::str::from_utf8(&hb).expect("valid utf8");
        assert!(xml.contains("how=\"h-g-i-g-o\""));
    }

    #[test]
    fn create_heartbeat_contains_version() {
        let hb = create_heartbeat("test-server");
        let xml = std::str::from_utf8(&hb).expect("valid utf8");
        assert!(xml.contains("version=\"2.0\""));
    }

    #[test]
    fn create_heartbeat_point_coordinates() {
        let hb = create_heartbeat("test-server");
        let xml = std::str::from_utf8(&hb).expect("valid utf8");
        assert!(xml.contains("lat=\"0.0\""));
        assert!(xml.contains("lon=\"0.0\""));
        assert!(xml.contains("hae=\"0.0\""));
        assert!(xml.contains("ce=\"999999\""));
        assert!(xml.contains("le=\"999999\""));
    }

    #[test]
    fn create_heartbeat_custom_uid_preserved() {
        let hb = create_heartbeat("my-custom-uid-12345");
        let xml = std::str::from_utf8(&hb).expect("valid utf8");
        assert!(xml.contains("uid=\"my-custom-uid-12345\""));
    }

    #[test]
    fn create_heartbeat_uid_with_special_chars() {
        // UIDs can contain various characters
        let hb = create_heartbeat("server-v2.prod-01");
        let xml = std::str::from_utf8(&hb).expect("valid utf8");
        assert!(xml.contains("uid=\"server-v2.prod-01\""));
    }

    #[test]
    fn is_heartbeat_with_extra_attributes_before_type() {
        let xml = b"<event version=\"2.0\" uid=\"srv\" foo=\"bar\" type=\"t-x-c-t\" time=\"t\">";
        assert!(is_heartbeat(xml));
    }

    #[test]
    fn is_heartbeat_with_different_cot_type() {
        let xml = b"<event version=\"2.0\" uid=\"s\" type=\"a-f-G-U-C-I\" time=\"t\">";
        assert!(!is_heartbeat(xml));
    }

    #[test]
    fn is_heartbeat_partial_match_not_detected() {
        // "t-x-c-t" but not as a type attribute
        let xml = b"<event version=\"2.0\" uid=\"t-x-c-t\" type=\"a-f-G\" time=\"t\">";
        assert!(!is_heartbeat(xml));
    }

    #[test]
    fn is_heartbeat_respects_512_byte_limit() {
        // Put the heartbeat type attribute beyond the 512-byte search limit
        let mut payload = vec![b' '; 510];
        payload.extend_from_slice(b"type=\"t-x-c-t\"");
        assert!(!is_heartbeat(&payload));
    }

    #[test]
    fn is_heartbeat_at_512_byte_boundary() {
        // Put the heartbeat type attribute just within the 512-byte limit
        let prefix = vec![b'<'; 498]; // 498 bytes of padding
        let mut payload = prefix;
        payload.extend_from_slice(b"type=\"t-x-c-t\""); // 14 bytes, total = 512
        assert!(is_heartbeat(&payload));
    }

    #[test]
    fn is_heartbeat_binary_payload() {
        let binary_data: Vec<u8> = (0..256).map(|i| i as u8).collect();
        assert!(!is_heartbeat(&binary_data));
    }

    #[test]
    fn is_heartbeat_very_large_payload() {
        // Ensure large payloads don't cause issues (only first 512 bytes searched)
        let mut payload = b"<event type=\"t-x-c-t\">".to_vec();
        payload.extend(vec![b'x'; 100_000]);
        assert!(is_heartbeat(&payload));
    }

    #[test]
    fn heartbeat_type_constant() {
        assert_eq!(HEARTBEAT_TYPE, "t-x-c-t");
    }

    #[test]
    fn create_heartbeat_returns_bytes_type() {
        let hb = create_heartbeat("test");
        // Verify it's valid UTF-8 (XML should always be)
        assert!(std::str::from_utf8(&hb).is_ok());
    }

    #[test]
    fn create_heartbeat_ends_with_closing_tag() {
        let hb = create_heartbeat("test");
        let xml = std::str::from_utf8(&hb).expect("valid utf8");
        assert!(xml.ends_with("</event>"));
    }
}
