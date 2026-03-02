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
}
