// Copyright © 2026 Roberto Chiofalo.

//! TAK protobuf -> XML CoT conversion.

use prost::Message;

use super::timestamp::millis_to_iso8601;
use crate::error::ProtoError;
use crate::tak_proto;

/// Convert serialized TakMessage protobuf bytes to CoT XML bytes.
///
/// Reconstructs the full XML document including typed detail elements
/// and any residual `xmlDetail` content.
pub fn proto_to_xml(proto_bytes: &[u8]) -> Result<Vec<u8>, ProtoError> {
    let tak_message = tak_proto::TakMessage::decode(proto_bytes)?;
    let cot = tak_message
        .cot_event
        .ok_or(ProtoError::MissingField("cotEvent"))?;
    build_xml(&cot)
}

fn build_xml(cot: &tak_proto::CotEvent) -> Result<Vec<u8>, ProtoError> {
    let mut xml = Vec::with_capacity(512);

    // <event> opening tag with attributes
    xml.extend_from_slice(b"<event version=\"2.0\"");
    write_attr(&mut xml, "uid", &cot.uid);
    write_attr(&mut xml, "type", &cot.r#type);

    if !cot.how.is_empty() {
        write_attr(&mut xml, "how", &cot.how);
    }

    if cot.send_time > 0 {
        write_attr(&mut xml, "time", &millis_to_iso8601(cot.send_time));
    }
    if cot.start_time > 0 {
        write_attr(&mut xml, "start", &millis_to_iso8601(cot.start_time));
    }
    if cot.stale_time > 0 {
        write_attr(&mut xml, "stale", &millis_to_iso8601(cot.stale_time));
    }

    if !cot.access.is_empty() {
        write_attr(&mut xml, "access", &cot.access);
    }
    if !cot.qos.is_empty() {
        write_attr(&mut xml, "qos", &cot.qos);
    }
    if !cot.opex.is_empty() {
        write_attr(&mut xml, "opex", &cot.opex);
    }

    xml.push(b'>');

    // <point> element
    let point = format!(
        "<point lat=\"{}\" lon=\"{}\" hae=\"{}\" ce=\"{}\" le=\"{}\"/>",
        cot.lat, cot.lon, cot.hae, cot.ce, cot.le
    );
    xml.extend_from_slice(point.as_bytes());

    // <detail> element
    let detail = cot.detail.as_ref();
    let has_detail = detail.is_some_and(|d| {
        !d.xml_detail.is_empty()
            || d.contact.is_some()
            || d.group.is_some()
            || d.precision_location.is_some()
            || d.status.is_some()
            || d.takv.is_some()
            || d.track.is_some()
    });

    if has_detail {
        xml.extend_from_slice(b"<detail>");

        if let Some(d) = detail {
            // Typed sub-elements
            if let Some(ref c) = d.contact {
                write_contact(&mut xml, c);
            }
            if let Some(ref g) = d.group {
                write_group(&mut xml, g);
            }
            if let Some(ref p) = d.precision_location {
                write_precision_location(&mut xml, p);
            }
            if let Some(ref s) = d.status {
                write_status(&mut xml, s);
            }
            if let Some(ref t) = d.takv {
                write_takv(&mut xml, t);
            }
            if let Some(ref t) = d.track {
                write_track(&mut xml, t);
            }

            // Residual xmlDetail (raw XML fragment per the TAK protobuf spec).
            // Validate it's well-formed before embedding — a crafted protobuf
            // message could contain closing tags (</detail>, </event>) that
            // would break the enclosing document structure.
            if !d.xml_detail.is_empty() && is_safe_xml_fragment(&d.xml_detail) {
                xml.extend_from_slice(d.xml_detail.as_bytes());
            }
        }

        xml.extend_from_slice(b"</detail>");
    }

    xml.extend_from_slice(b"</event>");
    Ok(xml)
}

fn write_attr(xml: &mut Vec<u8>, name: &str, value: &str) {
    xml.push(b' ');
    xml.extend_from_slice(name.as_bytes());
    xml.extend_from_slice(b"=\"");
    xml_escape_into(xml, value);
    xml.push(b'"');
}

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

fn write_contact(xml: &mut Vec<u8>, c: &tak_proto::Contact) {
    xml.extend_from_slice(b"<contact");
    if !c.callsign.is_empty() {
        write_attr(xml, "callsign", &c.callsign);
    }
    if !c.endpoint.is_empty() {
        write_attr(xml, "endpoint", &c.endpoint);
    }
    xml.extend_from_slice(b"/>");
}

fn write_group(xml: &mut Vec<u8>, g: &tak_proto::Group) {
    xml.extend_from_slice(b"<__group");
    if !g.name.is_empty() {
        write_attr(xml, "name", &g.name);
    }
    if !g.role.is_empty() {
        write_attr(xml, "role", &g.role);
    }
    xml.extend_from_slice(b"/>");
}

fn write_precision_location(xml: &mut Vec<u8>, p: &tak_proto::PrecisionLocation) {
    xml.extend_from_slice(b"<precisionlocation");
    if !p.geopointsrc.is_empty() {
        write_attr(xml, "geopointsrc", &p.geopointsrc);
    }
    if !p.altsrc.is_empty() {
        write_attr(xml, "altsrc", &p.altsrc);
    }
    xml.extend_from_slice(b"/>");
}

fn write_status(xml: &mut Vec<u8>, s: &tak_proto::Status) {
    xml.extend_from_slice(b"<status");
    write_attr(xml, "battery", &s.battery.to_string());
    xml.extend_from_slice(b"/>");
}

fn write_takv(xml: &mut Vec<u8>, t: &tak_proto::Takv) {
    xml.extend_from_slice(b"<takv");
    if !t.device.is_empty() {
        write_attr(xml, "device", &t.device);
    }
    if !t.platform.is_empty() {
        write_attr(xml, "platform", &t.platform);
    }
    if !t.os.is_empty() {
        write_attr(xml, "os", &t.os);
    }
    if !t.version.is_empty() {
        write_attr(xml, "version", &t.version);
    }
    xml.extend_from_slice(b"/>");
}

fn write_track(xml: &mut Vec<u8>, t: &tak_proto::Track) {
    xml.extend_from_slice(b"<track");
    write_attr(xml, "speed", &t.speed.to_string());
    write_attr(xml, "course", &t.course.to_string());
    xml.extend_from_slice(b"/>");
}

/// Validate that an xmlDetail string is a well-formed XML fragment
/// that won't break the enclosing `<detail>` element.
///
/// Wraps the fragment in a temporary root element and attempts to parse it
/// with quick_xml. Rejects malformed XML and structural injection attempts
/// (e.g., `</detail></event><evil/>`).
fn is_safe_xml_fragment(fragment: &str) -> bool {
    use quick_xml::Reader;
    use quick_xml::events::Event;

    let wrapped = format!("<_r>{fragment}</_r>");
    let mut reader = Reader::from_reader(wrapped.as_bytes());
    reader.config_mut().trim_text(false);
    let mut buf = Vec::new();
    loop {
        buf.clear();
        match reader.read_event_into(&mut buf) {
            Ok(Event::Eof) => return true,
            Err(_) => return false,
            _ => {}
        }
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn safe_xml_fragment_valid() {
        assert!(is_safe_xml_fragment(
            "<marti><dest callsign=\"BRAVO\"/></marti>"
        ));
        assert!(is_safe_xml_fragment("<remarks>test note</remarks>"));
        assert!(is_safe_xml_fragment("<custom attr=\"val\"/>"));
        assert!(is_safe_xml_fragment(""));
    }

    #[test]
    fn safe_xml_fragment_rejects_structural_injection() {
        // Closing ancestor tags would corrupt the document
        assert!(!is_safe_xml_fragment("</detail></event><evil/>"));
        assert!(!is_safe_xml_fragment("</detail>"));
        assert!(!is_safe_xml_fragment("<ok/></detail>"));
    }

    #[test]
    fn safe_xml_fragment_rejects_malformed() {
        assert!(!is_safe_xml_fragment("<unclosed>"));
        assert!(!is_safe_xml_fragment("<a><b></a></b>"));
    }

    #[test]
    fn xml_detail_injection_dropped_in_output() {
        // Build a protobuf message with malicious xmlDetail
        let cot = tak_proto::CotEvent {
            uid: "ATTACKER".into(),
            r#type: "a-f-G".into(),
            detail: Some(tak_proto::Detail {
                xml_detail: "</detail></event><injected/>".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let xml = build_xml(&cot).expect("build_xml");
        let xml_str = std::str::from_utf8(&xml).expect("utf8");

        // The injected content should NOT appear in the output
        assert!(
            !xml_str.contains("<injected"),
            "injection should be dropped: {xml_str}"
        );
        // But the document should still be well-formed
        assert!(xml_str.contains("</detail>"));
        assert!(xml_str.contains("</event>"));
    }

    // ── New defensive-invariant tests (see issue #909) ──────────

    /// `xml_escape_into` is the single chokepoint protecting every
    /// attribute value emitted by `write_attr` from XML injection. All
    /// five XML special characters (`& < > " '`) MUST be replaced with
    /// their named entities, in exactly one pass, with no other bytes
    /// altered. A regression that dropped any one of these mappings
    /// would immediately open an XML-injection hole in the wire format
    /// (e.g. an attacker-supplied callsign containing `"` would escape
    /// the attribute quote and let arbitrary attributes or tags be
    /// grafted onto the outer `<event>`). This test pins all five
    /// mappings in a single defensive assertion.
    #[test]
    fn xml_escape_into_escapes_all_five_xml_special_chars_into_entities() {
        let mut buf = Vec::new();
        xml_escape_into(&mut buf, "a&b<c>d\"e'f");
        assert_eq!(
            std::str::from_utf8(&buf).expect("utf8"),
            "a&amp;b&lt;c&gt;d&quot;e&apos;f",
            "all five XML special chars must round-trip through their named entities"
        );
    }

    /// Plain-ASCII alphanumerics and common punctuation MUST pass
    /// through `xml_escape_into` byte-for-byte. A regression that
    /// over-escaped (e.g. encoding `/`, `:`, or `.`) would silently
    /// corrupt every TAK endpoint URL and callsign on the wire.
    #[test]
    fn xml_escape_into_passes_through_ascii_alphanumeric_and_punctuation_unchanged() {
        let input = "ALPHA-42:192.168.1.1/tcp_endpoint=v1";
        let mut buf = Vec::new();
        xml_escape_into(&mut buf, input);
        assert_eq!(
            std::str::from_utf8(&buf).expect("utf8"),
            input,
            "characters outside the five-char escape set must survive verbatim"
        );
    }

    /// Multi-byte UTF-8 sequences MUST pass through unescaped — the
    /// escape function operates on bytes and must NOT mistakenly
    /// treat any high-bit byte (0x80-0xFF) as a special char. A
    /// byte-level `if b >= 0x80` regression would produce mojibake
    /// in every non-ASCII callsign or group-name.
    #[test]
    fn xml_escape_into_preserves_multibyte_utf8_bytes_verbatim() {
        let input = "αβγ-名前-🚀";
        let mut buf = Vec::new();
        xml_escape_into(&mut buf, input);
        assert_eq!(
            std::str::from_utf8(&buf).expect("utf8"),
            input,
            "multi-byte UTF-8 input must survive unescaped"
        );
    }

    /// `write_attr` is the load-bearing private helper that every
    /// attribute in every emitted `<event>` / `<point>` / typed
    /// sub-element flows through. It MUST emit exactly
    /// ` name="escaped-value"` — leading space, then name, then
    /// `="`, then escaped value, then `"`. This test pins the byte
    /// sequence so a silent refactor (e.g. dropping the leading
    /// space, switching to single-quote, or forgetting to escape)
    /// fails here rather than at a downstream CoT parser.
    #[test]
    fn write_attr_emits_space_name_equals_escaped_quoted_value() {
        let mut buf = Vec::new();
        write_attr(&mut buf, "callsign", "ALPHA");
        assert_eq!(
            std::str::from_utf8(&buf).expect("utf8"),
            r#" callsign="ALPHA""#,
            "write_attr output format must be exactly ` name=\"value\"`"
        );
    }

    /// A value containing `"` MUST be escaped to `&quot;` by
    /// `write_attr`, otherwise the attribute-quote terminator would
    /// close early and any following bytes would be interpreted as
    /// additional attributes or a tag break. This is the attribute
    /// injection attack class the double-quote entity was designed
    /// to defeat, so pinning it here is worth a dedicated test.
    #[test]
    fn write_attr_escapes_double_quote_in_value_to_prevent_attribute_breakout() {
        let mut buf = Vec::new();
        write_attr(&mut buf, "uid", r#"A" onerror="x"#);
        let rendered = std::str::from_utf8(&buf).expect("utf8");
        assert!(
            !rendered.contains(r#"" onerror"#),
            "a literal double-quote must never appear inside the attribute value: {rendered}"
        );
        assert!(
            rendered.contains("&quot;"),
            "the escape entity must appear in place of the literal `\"`: {rendered}"
        );
        assert_eq!(
            rendered, r#" uid="A&quot; onerror=&quot;x""#,
            "exact wire format pin for the escape substitution"
        );
    }

    /// An empty attribute value MUST still produce `name=""` — not
    /// a missing attribute or a short-formed bare name. This pins
    /// the "empty string is still a value" semantic that downstream
    /// Marti parsers rely on for optional fields (e.g. `how=""`).
    #[test]
    fn write_attr_on_empty_value_emits_empty_quoted_string() {
        let mut buf = Vec::new();
        write_attr(&mut buf, "how", "");
        assert_eq!(
            std::str::from_utf8(&buf).expect("utf8"),
            r#" how="""#,
            "empty-string value must still emit an empty quoted attribute"
        );
    }

    /// `proto_to_xml` on bytes that are not a valid TakMessage
    /// protobuf MUST surface `ProtoError::Decode(_)` specifically,
    /// not a generic error or a misrouted `MissingField`. The io-
    /// layer conversion in `error.rs` maps `Decode` onto
    /// `std::io::ErrorKind::InvalidData`, so the correct error
    /// variant propagation here is load-bearing for session-cleanup
    /// behaviour in the codec layer.
    #[test]
    fn proto_to_xml_on_malformed_protobuf_bytes_returns_decode_variant() {
        // 0xFF bytes are guaranteed not to decode as a valid TakMessage
        // because they are an invalid protobuf wire-format tag.
        let result = proto_to_xml(&[0xFF, 0xFF, 0xFF, 0xFF]);
        match result {
            Err(ProtoError::Decode(_)) => {}
            Err(other) => panic!("expected Decode, got {other:?}"),
            Ok(bytes) => panic!(
                "expected a Decode error, got Ok({})",
                String::from_utf8_lossy(&bytes)
            ),
        }
    }

    /// When the outer TakMessage decodes cleanly but carries no
    /// `cot_event`, `proto_to_xml` MUST return the specific
    /// `ProtoError::MissingField("cotEvent")` variant. The existing
    /// convert/mod.rs sibling test only asserts `is_err()`; this
    /// test strengthens that by pinning both the variant AND the
    /// field-name string, so a refactor that dropped to generic
    /// "missing" error messaging (losing operator diagnostics)
    /// fails here.
    #[test]
    fn proto_to_xml_on_missing_cot_event_returns_specific_missing_field_variant() {
        use prost::Message;
        let msg = tak_proto::TakMessage {
            tak_control: None,
            cot_event: None,
        };
        let mut buf = Vec::new();
        msg.encode(&mut buf).expect("encode TakMessage");

        match proto_to_xml(&buf) {
            Err(ProtoError::MissingField("cotEvent")) => {}
            Err(other) => panic!("expected MissingField(\"cotEvent\"), got {other:?}"),
            Ok(b) => panic!("expected Err, got Ok({})", String::from_utf8_lossy(&b)),
        }
    }

    /// A hostile UID containing XML-special characters MUST be
    /// fully escaped in the emitted `<event ...>` opening tag.
    /// This is the end-to-end defence that `write_attr` delegates
    /// to `xml_escape_into` — if either the delegation or the
    /// escape set regressed, an attacker-controlled UID could
    /// break out of the attribute, inject a new tag, or confuse
    /// downstream CoT parsers. The test drives `build_xml` end-to-
    /// end so the `write_attr` → `xml_escape_into` chain is pinned
    /// together, not just the primitives in isolation.
    #[test]
    fn build_xml_escapes_hostile_uid_to_prevent_xml_injection() {
        let cot = tak_proto::CotEvent {
            uid: r#"A" type="evil" x=""#.into(),
            r#type: "a-f-G".into(),
            ..Default::default()
        };
        let xml = build_xml(&cot).expect("build_xml");
        let rendered = std::str::from_utf8(&xml).expect("utf8");

        assert!(
            rendered.contains("&quot;"),
            "hostile `\"` in UID must be escaped to &quot; in output: {rendered}"
        );
        // Count unescaped double-quotes: the only legitimate `"` chars
        // are the attribute delimiters around escaped values, not bare
        // `"` bytes inside an attribute payload. Every `"` that isn't
        // part of an `="..."` pair would be an injection.
        let escaped_quotes = rendered.matches("&quot;").count();
        assert!(
            escaped_quotes >= 3,
            "expected at least three &quot; escapes (one per literal `\"` in the hostile UID), got {escaped_quotes}: {rendered}"
        );
        // Defence-in-depth: the injected literal `type="evil"` must not
        // reappear as a real attribute.
        assert!(
            !rendered.contains(r#"type="evil""#),
            "injected attribute must not survive to the wire: {rendered}"
        );
    }

    /// When a `CotEvent` has no timestamps set (all three default to
    /// zero), `build_xml` MUST skip the `time`/`start`/`stale`
    /// attributes entirely rather than emitting `time="1970-…"`
    /// placeholder timestamps. The opening-tag branch explicitly
    /// guards on `> 0`; this test pins that contract so a future
    /// `>= 0` typo (which would emit epoch-zero timestamps for
    /// every bare event) fails loudly.
    #[test]
    fn build_xml_skips_time_attrs_when_all_timestamps_are_zero() {
        let cot = tak_proto::CotEvent {
            uid: "TS-ZERO".into(),
            r#type: "a-f-G".into(),
            // send_time, start_time, stale_time default to 0
            ..Default::default()
        };
        let xml = build_xml(&cot).expect("build_xml");
        let rendered = std::str::from_utf8(&xml).expect("utf8");

        assert!(
            !rendered.contains("time=\""),
            "zero send_time must NOT emit a time attribute: {rendered}"
        );
        assert!(
            !rendered.contains("start=\""),
            "zero start_time must NOT emit a start attribute: {rendered}"
        );
        assert!(
            !rendered.contains("stale=\""),
            "zero stale_time must NOT emit a stale attribute: {rendered}"
        );
    }

    /// When a `CotEvent` has no `detail` set and no typed sub-
    /// elements, `build_xml` MUST omit the `<detail>…</detail>`
    /// wrapper entirely. Emitting an empty `<detail/>` or
    /// `<detail></detail>` would bloat every heartbeat/status
    /// message and would confuse older TAK clients that treat an
    /// empty detail as a signal. The `has_detail` guard at lines
    /// 66-74 is the load-bearing branch; this pins the negative
    /// path so a refactor to `always emit` fails here.
    #[test]
    fn build_xml_omits_detail_wrapper_when_fully_empty() {
        let cot = tak_proto::CotEvent {
            uid: "NO-DETAIL".into(),
            r#type: "a-f-G".into(),
            detail: None,
            ..Default::default()
        };
        let xml = build_xml(&cot).expect("build_xml");
        let rendered = std::str::from_utf8(&xml).expect("utf8");

        assert!(
            !rendered.contains("<detail"),
            "no typed sub-elements and no xml_detail must produce no <detail> wrapper: {rendered}"
        );
        assert!(
            rendered.contains("</event>"),
            "outer <event> must still close cleanly: {rendered}"
        );
    }

    /// A `Status` sub-element MUST emit `battery="0"` when the
    /// protobuf value is 0 (not omit the attribute). The battery
    /// is a u32 field rendered via `to_string()`, so `0` is a
    /// legitimate reading (e.g. a dead device reporting one last
    /// heartbeat), not a "field unset" sentinel. This test pins
    /// the always-emit semantic so a future optimization that
    /// skipped zero values wouldn't silently swallow dead-device
    /// telemetry.
    #[test]
    fn write_status_emits_battery_attribute_even_when_zero() {
        let mut buf = Vec::new();
        let status = tak_proto::Status { battery: 0 };
        write_status(&mut buf, &status);
        let rendered = std::str::from_utf8(&buf).expect("utf8");
        assert_eq!(
            rendered, r#"<status battery="0"/>"#,
            "Status with battery=0 must still emit the battery attribute"
        );
    }

    /// `write_contact` MUST omit optional fields when they are
    /// empty. A regression that emitted `callsign=""` or
    /// `endpoint=""` would either (a) bloat every contact element
    /// or (b) leak the empty-string distinction to downstream
    /// parsers that treat empty-string as a real callsign. The
    /// source uses `if !c.callsign.is_empty()` for both fields;
    /// this test pins that negative branch.
    #[test]
    fn write_contact_omits_empty_callsign_and_endpoint() {
        let mut buf = Vec::new();
        let c = tak_proto::Contact {
            callsign: String::new(),
            endpoint: String::new(),
        };
        write_contact(&mut buf, &c);
        assert_eq!(
            std::str::from_utf8(&buf).expect("utf8"),
            "<contact/>",
            "empty callsign and empty endpoint must produce a bare <contact/>"
        );
    }

    /// `write_takv` MUST emit all four non-empty fields in a
    /// stable, left-to-right declaration order: device → platform
    /// → os → version. TAK clients parse takv attributes
    /// positionally in some paths, and downstream test fixtures
    /// assert substring matches; reordering would silently break
    /// both. Pin the order here so the emit sequence is a first-
    /// class contract, not an emergent property of code layout.
    #[test]
    fn write_takv_emits_device_platform_os_version_in_declared_order() {
        let mut buf = Vec::new();
        let t = tak_proto::Takv {
            device: "Pixel".into(),
            platform: "ATAK-CIV".into(),
            os: "Android".into(),
            version: "4.10.0".into(),
        };
        write_takv(&mut buf, &t);
        let rendered = std::str::from_utf8(&buf).expect("utf8");

        let device_pos = rendered.find("device=").expect("device must appear");
        let platform_pos = rendered.find("platform=").expect("platform must appear");
        let os_pos = rendered.find("os=").expect("os must appear");
        let version_pos = rendered.find("version=").expect("version must appear");
        assert!(
            device_pos < platform_pos && platform_pos < os_pos && os_pos < version_pos,
            "emit order must be device → platform → os → version: {rendered}"
        );
        assert_eq!(
            rendered, r#"<takv device="Pixel" platform="ATAK-CIV" os="Android" version="4.10.0"/>"#,
            "exact wire format pin for the four-field path"
        );
    }
}
