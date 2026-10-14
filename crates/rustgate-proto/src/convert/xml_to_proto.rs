// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! XML CoT to TAK protobuf conversion.
//!
//! ## Field Mapping
//!
//! The following XML `<event>` attributes are explicitly mapped to protobuf
//! fields in `CotEvent`:
//!
//! | XML attribute | Proto field | Notes |
//! |---------------|-------------|-------|
//! | `uid` | `uid` | |
//! | `type` | `type` | |
//! | `how` | `how` | |
//! | `time` | `send_time` | ISO 8601 to milliseconds |
//! | `start` | `start_time` | ISO 8601 to milliseconds |
//! | `stale` | `stale_time` | ISO 8601 to milliseconds |
//! | `access` | `access` | |
//! | `qos` | `qos` | |
//! | `opex` | `opex` | |
//! | `<point>` lat/lon/hae/ce/le | corresponding proto fields | |
//!
//! ## Detail Mapping
//!
//! Known `<detail>` children are mapped to typed proto fields:
//!
//! - `<contact>` — `endpoint`, `callsign`
//! - `<__group>` — `name`, `role`
//! - `<precisionlocation>` — mapped to `PrecisionLocation`
//! - `<status>` — `battery`
//! - `<takv>` — `device`, `platform`, `os`, `version`
//! - `<track>` — `speed`, `course`
//!
//! ## Field Loss Behavior
//!
//! - **Unknown `<event>` attributes** (not listed above) are **silently
//!   discarded** during conversion. They do not appear in the protobuf
//!   output.
//! - **Unknown `<detail>` children** (elements not in the list above) are
//!   serialized back to XML and preserved in `Detail.xmlDetail`. This is a
//!   lossy process: attribute ordering and whitespace may change.
//! - **Nested attributes** within known detail elements that are not part
//!   of the proto schema are also discarded.
//! - The proto schema includes `caveat` and `releaseableTo` fields on
//!   `CotEvent`. These are **reserved but currently unmapped** — they are
//!   initialized to empty strings during conversion. If the source XML
//!   contains corresponding attributes, they will be discarded.
//!
//! This behavior is by design — the protobuf schema defines a fixed set of
//! fields, and XML attributes outside that set have no corresponding
//! representation.

use prost::Message;

use super::timestamp::iso8601_to_millis;
use crate::error::ProtoError;
use crate::{tak_proto, xml_full};

/// Convert raw CoT XML bytes to serialized TakMessage protobuf bytes.
///
/// Parses the XML fully, maps all fields to protobuf types, and packages
/// unknown detail children into `Detail.xmlDetail`. See the [module-level
/// documentation](self) for the complete field mapping and loss behavior.
pub fn xml_to_proto(xml: &[u8]) -> Result<Vec<u8>, ProtoError> {
    let full = xml_full::parse_full(xml)?;
    let cot_event = full_to_cot_event(&full)?;
    let tak_message = tak_proto::TakMessage {
        tak_control: None,
        cot_event: Some(cot_event),
    };

    let mut buf = Vec::with_capacity(tak_message.encoded_len());
    tak_message.encode(&mut buf)?;
    Ok(buf)
}

fn full_to_cot_event(full: &xml_full::FullCotEvent) -> Result<tak_proto::CotEvent, ProtoError> {
    let send_time = if full.time.is_empty() {
        0
    } else {
        iso8601_to_millis(&full.time)?
    };
    let start_time = if full.start.is_empty() {
        0
    } else {
        iso8601_to_millis(&full.start)?
    };
    let stale_time = if full.stale.is_empty() {
        0
    } else {
        iso8601_to_millis(&full.stale)?
    };

    let detail = build_detail(full);

    Ok(tak_proto::CotEvent {
        r#type: full.event_type.clone(),
        access: full.access.clone(),
        qos: full.qos.clone(),
        opex: full.opex.clone(),
        uid: full.uid.clone(),
        send_time,
        start_time,
        stale_time,
        how: full.how.clone(),
        lat: full.lat,
        lon: full.lon,
        hae: full.hae,
        ce: full.ce,
        le: full.le,
        detail: Some(detail),
        caveat: String::new(),
        releaseable_to: String::new(),
    })
}

fn build_detail(full: &xml_full::FullCotEvent) -> tak_proto::Detail {
    let contact = full.contact.as_ref().map(|c| tak_proto::Contact {
        endpoint: c.endpoint.clone(),
        callsign: c.callsign.clone(),
    });

    let group = full.group.as_ref().map(|g| tak_proto::Group {
        name: g.name.clone(),
        role: g.role.clone(),
    });

    let precision_location =
        full.precision_location
            .as_ref()
            .map(|p| tak_proto::PrecisionLocation {
                geopointsrc: p.geopointsrc.clone(),
                altsrc: p.altsrc.clone(),
            });

    let status = full
        .status
        .as_ref()
        .map(|s| tak_proto::Status { battery: s.battery });

    let takv = full.takv.as_ref().map(|t| tak_proto::Takv {
        device: t.device.clone(),
        platform: t.platform.clone(),
        os: t.os.clone(),
        version: t.version.clone(),
    });

    let track = full.track.as_ref().map(|t| tak_proto::Track {
        speed: t.speed,
        course: t.course,
    });

    // Typed detail elements without protobuf counterparts are serialized
    // back into xml_detail so they survive the XML -> proto -> XML round-trip.
    let mut xml_detail = full.xml_detail.clone();
    serialize_typed_details_to_xml(full, &mut xml_detail);

    tak_proto::Detail {
        xml_detail,
        contact,
        group,
        precision_location,
        status,
        takv,
        track,
    }
}

/// Serialize typed detail fields that have no protobuf counterpart back into
/// the xml_detail string so they survive proto round-trips.
fn serialize_typed_details_to_xml(full: &xml_full::FullCotEvent, buf: &mut String) {
    for link in &full.link {
        buf.push_str("<link");
        push_xml_attr(buf, "relation", &link.relation);
        push_xml_attr(buf, "type", &link.link_type);
        push_xml_attr(buf, "uid", &link.uid);
        if let Some(ref pc) = link.parent_callsign {
            push_xml_attr(buf, "parent_callsign", pc);
        }
        if let Some(ref pt) = link.production_time {
            push_xml_attr(buf, "production_time", pt);
        }
        buf.push_str("/>");
    }

    if let Some(ref remarks) = full.remarks {
        buf.push_str("<remarks");
        if let Some(ref src) = remarks.source {
            push_xml_attr(buf, "source", src);
        }
        if let Some(ref ts) = remarks.timestamp {
            push_xml_attr(buf, "time", ts);
        }
        if remarks.text.is_empty() {
            buf.push_str("/>");
        } else {
            buf.push('>');
            xml_escape_attr_into(buf, &remarks.text);
            buf.push_str("</remarks>");
        }
    }

    if let Some(ref color) = full.color {
        buf.push_str("<color");
        if let Some(argb) = color.argb {
            push_xml_attr(buf, "argb", &argb.to_string());
        }
        buf.push_str("/>");
    }

    if let Some(ref labels) = full.labels {
        buf.push_str("<labels");
        push_xml_attr(buf, "value", &labels.value);
        buf.push_str("/>");
    }

    if let Some(ref usericon) = full.usericon {
        buf.push_str("<usericon");
        push_xml_attr(buf, "iconsetpath", &usericon.iconsetpath);
        buf.push_str("/>");
    }

    if let Some(ref marti) = full.marti {
        if marti.dest_callsigns.is_empty() {
            buf.push_str("<marti/>");
        } else {
            buf.push_str("<marti>");
            for cs in &marti.dest_callsigns {
                buf.push_str("<dest");
                push_xml_attr(buf, "callsign", cs);
                buf.push_str("/>");
            }
            buf.push_str("</marti>");
        }
    }
}

/// Append ` key="value"` to an XML buffer with proper escaping.
fn push_xml_attr(buf: &mut String, key: &str, value: &str) {
    buf.push(' ');
    buf.push_str(key);
    buf.push_str("=\"");
    xml_escape_attr_into(buf, value);
    buf.push('"');
}

/// Escape special XML characters in attribute values to prevent injection.
fn xml_escape_attr_into(buf: &mut String, s: &str) {
    for c in s.chars() {
        match c {
            '&' => buf.push_str("&amp;"),
            '<' => buf.push_str("&lt;"),
            '>' => buf.push_str("&gt;"),
            '"' => buf.push_str("&quot;"),
            _ => buf.push(c),
        }
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, unused_results)]
mod tests {
    use super::*;
    use crate::xml_full::{
        ColorDetail, ContactDetail, FullCotEvent, GroupDetail, LabelsDetail, LinkDetail,
        MartiDetail, PrecisionLocationDetail, RemarksDetail, StatusDetail, TakvDetail, TrackDetail,
        UserIconDetail,
    };

    // -------- xml_escape_attr_into --------

    #[test]
    fn xml_escape_attr_into_noop_on_empty_input() {
        let mut buf = String::new();
        xml_escape_attr_into(&mut buf, "");
        assert_eq!(buf, "");
    }

    #[test]
    fn xml_escape_attr_into_preserves_ordinary_ascii() {
        // Control: ordinary letters and digits must pass through untouched.
        // A silent corruption here would turn every attribute into a double-
        // encoded string on every subsequent round trip.
        let mut buf = String::new();
        xml_escape_attr_into(&mut buf, "ALPHA-1 team=lead");
        assert_eq!(buf, "ALPHA-1 team=lead");
    }

    #[test]
    fn xml_escape_attr_into_escapes_ampersand() {
        let mut buf = String::new();
        xml_escape_attr_into(&mut buf, "a&b");
        assert_eq!(buf, "a&amp;b");
    }

    #[test]
    fn xml_escape_attr_into_escapes_less_than() {
        let mut buf = String::new();
        xml_escape_attr_into(&mut buf, "a<b");
        assert_eq!(buf, "a&lt;b");
    }

    #[test]
    fn xml_escape_attr_into_escapes_greater_than() {
        let mut buf = String::new();
        xml_escape_attr_into(&mut buf, "a>b");
        assert_eq!(buf, "a&gt;b");
    }

    #[test]
    fn xml_escape_attr_into_escapes_double_quote() {
        let mut buf = String::new();
        xml_escape_attr_into(&mut buf, "a\"b");
        assert_eq!(buf, "a&quot;b");
    }

    #[test]
    fn xml_escape_attr_into_escapes_all_four_in_one_pass() {
        // Pins the contract that every one of the four dangerous chars is
        // escaped on the same pass. A regression that forgot any single
        // variant would let attribute-value XML injection through on that
        // char.
        let mut buf = String::new();
        xml_escape_attr_into(&mut buf, "& < > \"");
        assert_eq!(buf, "&amp; &lt; &gt; &quot;");
    }

    #[test]
    fn xml_escape_attr_into_preserves_non_ascii_unicode() {
        // Unicode code points outside ASCII have no XML-attribute meaning
        // and must pass through unchanged. Important for CoT events from
        // non-English locales.
        let mut buf = String::new();
        xml_escape_attr_into(&mut buf, "αβ日本語");
        assert_eq!(buf, "αβ日本語");
    }

    #[test]
    fn xml_escape_attr_into_preserves_single_quote_and_tab_and_newline() {
        // Single quote, tab, and newline are NOT escaped by this function.
        // Attribute values in the output use double-quoted form, so single
        // quotes need no escaping; whitespace is preserved byte-for-byte.
        let mut buf = String::new();
        xml_escape_attr_into(&mut buf, "'a\tb\nc");
        assert_eq!(buf, "'a\tb\nc");
    }

    #[test]
    fn xml_escape_attr_into_appends_to_existing_buffer() {
        // Critical: the function must APPEND, not overwrite. The outer
        // serializer relies on this to build up a single output buffer
        // across many attribute writes.
        let mut buf = String::from("prefix ");
        xml_escape_attr_into(&mut buf, "a<b");
        assert_eq!(buf, "prefix a&lt;b");
    }

    // -------- push_xml_attr --------

    #[test]
    fn push_xml_attr_emits_leading_space_and_double_quoted_value() {
        let mut buf = String::new();
        push_xml_attr(&mut buf, "relation", "p-p");
        assert_eq!(buf, r#" relation="p-p""#);
    }

    #[test]
    fn push_xml_attr_handles_empty_value() {
        let mut buf = String::new();
        push_xml_attr(&mut buf, "callsign", "");
        assert_eq!(buf, r#" callsign="""#);
    }

    #[test]
    fn push_xml_attr_escapes_value_through_xml_escape_attr_into() {
        // Injection defense: an attacker-controlled attribute value
        // containing `"` would close the attribute early and allow
        // arbitrary attribute injection into the surrounding element.
        // The escape must be applied BY push_xml_attr, not left to the
        // caller.
        let mut buf = String::new();
        push_xml_attr(&mut buf, "callsign", r#"EVIL" onload="alert(1)"#);
        assert_eq!(buf, r#" callsign="EVIL&quot; onload=&quot;alert(1)""#);
    }

    #[test]
    fn push_xml_attr_does_not_escape_key() {
        // Keys come from static string literals in the source, never from
        // user input, so the key is pushed verbatim. Pinning the contract
        // so a future refactor that accidentally escapes keys (changing
        // `time` into `ti&#109;e`) fails CI.
        let mut buf = String::new();
        push_xml_attr(&mut buf, "<k>", "v");
        assert_eq!(buf, r#" <k>="v""#);
    }

    #[test]
    fn push_xml_attr_appends_to_existing_buffer() {
        let mut buf = String::from("<link");
        push_xml_attr(&mut buf, "uid", "X");
        assert_eq!(buf, r#"<link uid="X""#);
    }

    // -------- serialize_typed_details_to_xml --------

    #[test]
    fn serialize_typed_details_to_xml_noop_when_no_typed_details_present() {
        // A FullCotEvent with no link/remarks/color/labels/usericon/marti
        // must leave the buffer exactly as it was; any spurious write here
        // would corrupt every CoT event that only had contact/group/etc.
        let full = FullCotEvent::default();
        let mut buf = String::from("EXISTING");
        serialize_typed_details_to_xml(&full, &mut buf);
        assert_eq!(buf, "EXISTING");
    }

    #[test]
    fn serialize_typed_details_to_xml_emits_minimal_link() {
        let full = FullCotEvent {
            link: vec![LinkDetail {
                relation: "p-p".into(),
                link_type: "a-f-G".into(),
                uid: "ALPHA".into(),
                parent_callsign: None,
                production_time: None,
            }],
            ..Default::default()
        };
        let mut buf = String::new();
        serialize_typed_details_to_xml(&full, &mut buf);
        assert_eq!(buf, r#"<link relation="p-p" type="a-f-G" uid="ALPHA"/>"#);
    }

    #[test]
    fn serialize_typed_details_to_xml_includes_optional_link_fields_when_present() {
        let full = FullCotEvent {
            link: vec![LinkDetail {
                relation: "p-p".into(),
                link_type: "a-f-G".into(),
                uid: "ALPHA".into(),
                parent_callsign: Some("BRAVO".into()),
                production_time: Some("2026-04-19T00:00:00Z".into()),
            }],
            ..Default::default()
        };
        let mut buf = String::new();
        serialize_typed_details_to_xml(&full, &mut buf);
        assert_eq!(
            buf,
            r#"<link relation="p-p" type="a-f-G" uid="ALPHA" parent_callsign="BRAVO" production_time="2026-04-19T00:00:00Z"/>"#
        );
    }

    #[test]
    fn serialize_typed_details_to_xml_emits_multiple_links_in_order() {
        // Order preservation matters: some CoT consumers rely on the
        // order of <link> elements to reconstruct a chain of relationships.
        let full = FullCotEvent {
            link: vec![
                LinkDetail {
                    relation: "p-p".into(),
                    link_type: "a-f-G".into(),
                    uid: "FIRST".into(),
                    parent_callsign: None,
                    production_time: None,
                },
                LinkDetail {
                    relation: "c".into(),
                    link_type: "a-f".into(),
                    uid: "SECOND".into(),
                    parent_callsign: None,
                    production_time: None,
                },
            ],
            ..Default::default()
        };
        let mut buf = String::new();
        serialize_typed_details_to_xml(&full, &mut buf);
        assert_eq!(
            buf,
            concat!(
                r#"<link relation="p-p" type="a-f-G" uid="FIRST"/>"#,
                r#"<link relation="c" type="a-f" uid="SECOND"/>"#
            )
        );
    }

    #[test]
    fn serialize_typed_details_to_xml_escapes_hostile_link_uid() {
        // Direct injection-defense test: an attacker who can control a
        // <link> uid (e.g. by crafting the CoT event upstream) must not
        // be able to break out of the attribute value and inject new
        // XML elements.
        let full = FullCotEvent {
            link: vec![LinkDetail {
                relation: "p-p".into(),
                link_type: "a-f-G".into(),
                uid: r#"X"><evil/>"#.into(),
                parent_callsign: None,
                production_time: None,
            }],
            ..Default::default()
        };
        let mut buf = String::new();
        serialize_typed_details_to_xml(&full, &mut buf);
        assert_eq!(
            buf,
            r#"<link relation="p-p" type="a-f-G" uid="X&quot;&gt;&lt;evil/&gt;"/>"#
        );
    }

    #[test]
    fn serialize_typed_details_to_xml_remarks_empty_text_is_self_closed() {
        // An empty <remarks/> is emitted self-closing rather than as an
        // open/close pair, because the downstream round-trip parser
        // treats the two as semantically identical but a pairing regression
        // would widen the wire footprint for every event with a missing
        // remarks body.
        let full = FullCotEvent {
            remarks: Some(RemarksDetail {
                source: Some("BAO".into()),
                timestamp: Some("2026-04-19T00:00:00Z".into()),
                text: String::new(),
            }),
            ..Default::default()
        };
        let mut buf = String::new();
        serialize_typed_details_to_xml(&full, &mut buf);
        assert_eq!(
            buf,
            r#"<remarks source="BAO" time="2026-04-19T00:00:00Z"/>"#
        );
    }

    #[test]
    fn serialize_typed_details_to_xml_remarks_with_text_emits_open_close_pair() {
        let full = FullCotEvent {
            remarks: Some(RemarksDetail {
                source: None,
                timestamp: None,
                text: "hello world".into(),
            }),
            ..Default::default()
        };
        let mut buf = String::new();
        serialize_typed_details_to_xml(&full, &mut buf);
        assert_eq!(buf, "<remarks>hello world</remarks>");
    }

    #[test]
    fn serialize_typed_details_to_xml_escapes_remarks_text() {
        // Remarks text commonly contains free-form user input and is the
        // most exposed injection surface in the detail section.
        let full = FullCotEvent {
            remarks: Some(RemarksDetail {
                source: None,
                timestamp: None,
                text: r#"a & b < c > d " e"#.into(),
            }),
            ..Default::default()
        };
        let mut buf = String::new();
        serialize_typed_details_to_xml(&full, &mut buf);
        assert_eq!(buf, "<remarks>a &amp; b &lt; c &gt; d &quot; e</remarks>");
    }

    #[test]
    fn serialize_typed_details_to_xml_color_with_argb() {
        let full = FullCotEvent {
            color: Some(ColorDetail { argb: Some(-65536) }),
            ..Default::default()
        };
        let mut buf = String::new();
        serialize_typed_details_to_xml(&full, &mut buf);
        assert_eq!(buf, r#"<color argb="-65536"/>"#);
    }

    #[test]
    fn serialize_typed_details_to_xml_color_without_argb_emits_bare_tag() {
        // Color element present but argb absent means an <color/> element
        // with no attributes round-trips cleanly. Pinning this variant
        // because it's easy to mistakenly emit no tag at all when the
        // only carried field is None.
        let full = FullCotEvent {
            color: Some(ColorDetail { argb: None }),
            ..Default::default()
        };
        let mut buf = String::new();
        serialize_typed_details_to_xml(&full, &mut buf);
        assert_eq!(buf, "<color/>");
    }

    #[test]
    fn serialize_typed_details_to_xml_labels_emits_value_attribute() {
        let full = FullCotEvent {
            labels: Some(LabelsDetail {
                value: "Target Alpha".into(),
            }),
            ..Default::default()
        };
        let mut buf = String::new();
        serialize_typed_details_to_xml(&full, &mut buf);
        assert_eq!(buf, r#"<labels value="Target Alpha"/>"#);
    }

    #[test]
    fn serialize_typed_details_to_xml_usericon_emits_iconsetpath() {
        let full = FullCotEvent {
            usericon: Some(UserIconDetail {
                iconsetpath: "COT_MAPPING_2525C/a-f/a-f-G".into(),
            }),
            ..Default::default()
        };
        let mut buf = String::new();
        serialize_typed_details_to_xml(&full, &mut buf);
        assert_eq!(
            buf,
            r#"<usericon iconsetpath="COT_MAPPING_2525C/a-f/a-f-G"/>"#
        );
    }

    #[test]
    fn serialize_typed_details_to_xml_marti_empty_is_self_closed() {
        let full = FullCotEvent {
            marti: Some(MartiDetail {
                dest_callsigns: Vec::new(),
            }),
            ..Default::default()
        };
        let mut buf = String::new();
        serialize_typed_details_to_xml(&full, &mut buf);
        assert_eq!(buf, "<marti/>");
    }

    #[test]
    fn serialize_typed_details_to_xml_marti_nests_dest_callsigns() {
        // Pins the exact shape the directed-messaging path produces:
        // a non-empty marti is open/close wrapped and each destination
        // callsign is its own self-closing <dest callsign="..."/> tag.
        let full = FullCotEvent {
            marti: Some(MartiDetail {
                dest_callsigns: vec!["ALPHA".into(), "BRAVO".into()],
            }),
            ..Default::default()
        };
        let mut buf = String::new();
        serialize_typed_details_to_xml(&full, &mut buf);
        assert_eq!(
            buf,
            concat!(
                "<marti>",
                r#"<dest callsign="ALPHA"/>"#,
                r#"<dest callsign="BRAVO"/>"#,
                "</marti>"
            )
        );
    }

    #[test]
    fn serialize_typed_details_to_xml_escapes_marti_callsign() {
        let full = FullCotEvent {
            marti: Some(MartiDetail {
                dest_callsigns: vec![r#"A"B<C"#.into()],
            }),
            ..Default::default()
        };
        let mut buf = String::new();
        serialize_typed_details_to_xml(&full, &mut buf);
        assert_eq!(buf, r#"<marti><dest callsign="A&quot;B&lt;C"/></marti>"#);
    }

    // -------- build_detail --------

    #[test]
    fn build_detail_preserves_original_xml_detail_prefix() {
        // xml_detail for residual children must come FIRST, before any
        // typed-detail serialization, so legacy residual content is not
        // shuffled around the typed elements we serialize afterwards.
        let full = FullCotEvent {
            xml_detail: "<preserved/>".into(),
            labels: Some(LabelsDetail { value: "X".into() }),
            ..Default::default()
        };
        let detail = build_detail(&full);
        assert!(detail.xml_detail.starts_with("<preserved/>"));
        assert!(detail.xml_detail.contains(r#"<labels value="X"/>"#));
    }

    #[test]
    fn build_detail_maps_all_typed_fields_when_present() {
        let full = FullCotEvent {
            contact: Some(ContactDetail {
                endpoint: "*:-1:stcp".into(),
                callsign: "ALPHA".into(),
            }),
            group: Some(GroupDetail {
                name: "Cyan".into(),
                role: "Team Lead".into(),
            }),
            precision_location: Some(PrecisionLocationDetail {
                geopointsrc: "GPS".into(),
                altsrc: "GPS".into(),
            }),
            status: Some(StatusDetail { battery: 85 }),
            takv: Some(TakvDetail {
                device: "Pixel".into(),
                platform: "ATAK-CIV".into(),
                os: "Android".into(),
                version: "4.10.0".into(),
            }),
            track: Some(TrackDetail {
                speed: 5.5,
                course: 180.0,
            }),
            ..Default::default()
        };
        let detail = build_detail(&full);
        assert_eq!(detail.contact.as_ref().unwrap().callsign, "ALPHA");
        assert_eq!(detail.group.as_ref().unwrap().name, "Cyan");
        assert_eq!(
            detail.precision_location.as_ref().unwrap().geopointsrc,
            "GPS"
        );
        assert_eq!(detail.status.as_ref().unwrap().battery, 85);
        assert_eq!(detail.takv.as_ref().unwrap().platform, "ATAK-CIV");
        assert!((detail.track.as_ref().unwrap().speed - 5.5).abs() < 1e-9);
    }

    #[test]
    fn build_detail_yields_none_for_absent_typed_fields() {
        let full = FullCotEvent::default();
        let detail = build_detail(&full);
        assert!(detail.contact.is_none());
        assert!(detail.group.is_none());
        assert!(detail.precision_location.is_none());
        assert!(detail.status.is_none());
        assert!(detail.takv.is_none());
        assert!(detail.track.is_none());
        assert_eq!(detail.xml_detail, "");
    }

    // -------- full_to_cot_event --------

    #[test]
    fn full_to_cot_event_returns_zero_timestamps_for_empty_strings() {
        // The three timestamp fields (time/start/stale) are optional on
        // the XML side: an empty string must become a 0 millisecond
        // value rather than triggering the iso8601 parser (which would
        // reject "" and fail the whole conversion).
        let full = FullCotEvent {
            uid: "MIN".into(),
            event_type: "a-f-G".into(),
            ..Default::default()
        };
        let cot = full_to_cot_event(&full).expect("empty timestamps ok");
        assert_eq!(cot.send_time, 0);
        assert_eq!(cot.start_time, 0);
        assert_eq!(cot.stale_time, 0);
    }

    #[test]
    fn full_to_cot_event_parses_valid_iso8601_timestamps() {
        let full = FullCotEvent {
            uid: "TS".into(),
            event_type: "a-f-G".into(),
            time: "2021-02-27T20:32:24.000Z".into(),
            start: "2021-02-27T20:32:24.500Z".into(),
            stale: "2021-02-27T20:37:24.000Z".into(),
            ..Default::default()
        };
        let cot = full_to_cot_event(&full).expect("valid timestamps ok");
        // 2021-02-27T20:32:24.000Z in millis since unix epoch.
        assert_eq!(cot.send_time, 1614457944000);
        assert_eq!(cot.start_time, 1614457944500);
        assert_eq!(cot.stale_time, 1614458244000);
    }

    #[test]
    fn full_to_cot_event_rejects_invalid_time_timestamp() {
        // A garbage timestamp must surface as an error, not silently
        // default to 0 — the latter would hide wire-format corruption
        // from operators.
        let full = FullCotEvent {
            uid: "BAD".into(),
            event_type: "a-f-G".into(),
            time: "not-a-date".into(),
            ..Default::default()
        };
        assert!(full_to_cot_event(&full).is_err());
    }

    #[test]
    fn full_to_cot_event_preserves_string_fields_verbatim() {
        let full = FullCotEvent {
            uid: "ALPHA".into(),
            event_type: "a-f-G-U-C".into(),
            how: "m-g".into(),
            access: "Undefined".into(),
            qos: "6-r-g".into(),
            opex: "x".into(),
            ..Default::default()
        };
        let cot = full_to_cot_event(&full).expect("ok");
        assert_eq!(cot.uid, "ALPHA");
        assert_eq!(cot.r#type, "a-f-G-U-C");
        assert_eq!(cot.how, "m-g");
        assert_eq!(cot.access, "Undefined");
        assert_eq!(cot.qos, "6-r-g");
        assert_eq!(cot.opex, "x");
    }

    #[test]
    fn full_to_cot_event_preserves_point_fields_verbatim() {
        let full = FullCotEvent {
            uid: "P".into(),
            event_type: "a-f-G".into(),
            lat: 37.7749,
            lon: -122.4194,
            hae: 10.5,
            ce: 50.0,
            le: 30.0,
            ..Default::default()
        };
        let cot = full_to_cot_event(&full).expect("ok");
        assert!((cot.lat - 37.7749).abs() < 1e-9);
        assert!((cot.lon + 122.4194).abs() < 1e-9);
        assert!((cot.hae - 10.5).abs() < 1e-9);
        assert!((cot.ce - 50.0).abs() < 1e-9);
        assert!((cot.le - 30.0).abs() < 1e-9);
    }

    #[test]
    fn full_to_cot_event_leaves_reserved_fields_empty() {
        // caveat and releaseable_to are reserved in the proto schema but
        // currently unmapped. The conversion MUST initialize them to the
        // empty string — returning uninitialized or source-dependent
        // values would leak stack contents or past-event state into
        // downstream consumers.
        let full = FullCotEvent {
            uid: "X".into(),
            event_type: "a-f-G".into(),
            ..Default::default()
        };
        let cot = full_to_cot_event(&full).expect("ok");
        assert_eq!(cot.caveat, "");
        assert_eq!(cot.releaseable_to, "");
    }

    #[test]
    fn full_to_cot_event_always_sets_detail_even_when_empty() {
        // The TAK protobuf convention is that every CotEvent has a
        // Detail, even if every field in that Detail is None/empty.
        // A regression that returned `detail: None` would break every
        // downstream consumer that calls `detail.unwrap()` or
        // `detail.as_ref().and_then(...)` on the assumption.
        let full = FullCotEvent::default();
        let cot = full_to_cot_event(&full).expect("ok");
        assert!(cot.detail.is_some());
    }

    // -------- xml_to_proto (public entry point) --------

    #[test]
    fn xml_to_proto_minimum_event_roundtrips_uid_and_type() {
        // Decode the proto back with prost to confirm the bytes match
        // the documented CotEvent shape — we intentionally do NOT go
        // through proto_to_xml here so we're testing the xml_to_proto
        // half in isolation, not the round-trip.
        use prost::Message;
        let bytes = xml_to_proto(br#"<event uid="U1" type="a-f-G"/>"#).expect("ok");
        let msg = crate::tak_proto::TakMessage::decode(bytes.as_slice()).expect("decode");
        let cot = msg.cot_event.expect("cot_event");
        assert_eq!(cot.uid, "U1");
        assert_eq!(cot.r#type, "a-f-G");
        assert_eq!(cot.send_time, 0);
        assert!(cot.detail.is_some());
    }

    #[test]
    fn xml_to_proto_rejects_invalid_time_attribute() {
        // Top-level entry point must propagate the iso8601 parse error
        // rather than swallow it; pins the fail-closed posture for
        // malformed timestamps.
        let result = xml_to_proto(br#"<event uid="U" type="a" time="garbage"/>"#);
        assert!(result.is_err());
    }

    #[test]
    fn xml_to_proto_rejects_invalid_xml_payload() {
        // Non-XML bytes surface as a parse error from the underlying
        // streaming parser; the conversion must never return Ok.
        assert!(xml_to_proto(b"bare bytes, no <event> at all").is_err());
    }

    #[test]
    fn xml_to_proto_wraps_cot_event_in_tak_message_with_no_tak_control() {
        // The top-level TakMessage should have tak_control: None for
        // XML-originated events — tak_control is reserved for the
        // separate streaming-control protobuf path.
        use prost::Message;
        let bytes = xml_to_proto(br#"<event uid="U" type="a-f-G"/>"#).expect("ok");
        let msg = crate::tak_proto::TakMessage::decode(bytes.as_slice()).expect("decode");
        assert!(msg.tak_control.is_none());
    }
}
