// Copyright © 2026 Roberto Chiofalo.

//! Payload serialization for HTTP-forwarded messages.
//!
//! Supports two formats: a JSON envelope containing source identity,
//! metadata, and base64-encoded payload; and raw XML passthrough for
//! consumers that expect CoT XML directly.

use rustgate_core::b64;
use rustgate_core::message::{Destination, RoutableMessage};
use serde::Serialize;

use crate::config::PayloadFormat;
use crate::error::HttpError;

/// JSON wire format for an HTTP-forwarded message.
///
/// The raw payload bytes are base64-encoded because CoT XML may contain
/// binary content or non-UTF8 sequences in certain edge cases.
#[derive(Debug, Serialize)]
struct HttpWireMessage<'a> {
    source_cn: &'a str,
    source_groups: Vec<&'a str>,
    destination: String,
    message_type: String,
    source_protocol: &'a str,
    received_at: String,
    payload: String,
    payload_size: usize,
    instance_id: &'a str,
}

/// Serialize a routable message into the target's configured format.
///
/// Returns `(body_bytes, content_type)` ready for the HTTP request.
pub(crate) fn serialize(
    msg: &RoutableMessage,
    format: PayloadFormat,
    instance_id: &str,
) -> Result<(Vec<u8>, &'static str), HttpError> {
    match format {
        PayloadFormat::Json => serialize_json(msg, instance_id),
        PayloadFormat::RawXml => Ok((msg.payload.to_vec(), "application/xml")),
        PayloadFormat::Protobuf => serialize_protobuf(msg),
    }
}

/// Serialize a routable message as protobuf-encoded CoT event.
///
/// Uses `rustgate_proto::xml_to_proto` to convert the CoT XML payload
/// into a protobuf-encoded binary representation suitable for tactical
/// system interop (Palantir, Anduril, TAK Server peers).
///
/// When the `proto` feature is disabled, returns a config error — the
/// format should have been rejected at validation time.
#[allow(unused_variables)] // `msg` unused when proto feature is off
fn serialize_protobuf(msg: &RoutableMessage) -> Result<(Vec<u8>, &'static str), HttpError> {
    #[cfg(feature = "proto")]
    {
        let proto_bytes =
            rustgate_proto::xml_to_proto(&msg.payload).map_err(|e| HttpError::ProtoConvert {
                message: e.to_string(),
            })?;
        Ok((proto_bytes, "application/x-protobuf"))
    }
    #[cfg(not(feature = "proto"))]
    {
        Err(HttpError::Config(
            "protobuf format requires the `proto` feature to be enabled".to_string(),
        ))
    }
}

fn serialize_json(
    msg: &RoutableMessage,
    instance_id: &str,
) -> Result<(Vec<u8>, &'static str), HttpError> {
    let destination = format_destination(&msg.destination);
    let message_type = msg.metadata.message_type.to_string();
    let received_at = format_timestamp(msg.metadata.received_at);
    let payload_b64 = b64::encode(&msg.payload);

    let wire = HttpWireMessage {
        source_cn: &msg.source.cn,
        source_groups: msg.source.groups.iter().map(String::as_str).collect(),
        destination,
        message_type,
        source_protocol: &msg.metadata.source_protocol,
        received_at,
        payload: payload_b64,
        payload_size: msg.payload.len(),
        instance_id,
    };

    let body = serde_json::to_vec(&wire).map_err(|e| HttpError::Serialize { source: e })?;
    Ok((body, "application/json"))
}

pub(crate) fn format_destination(dest: &Destination) -> String {
    match dest {
        Destination::Group(g) => format!("group:{g}"),
        Destination::Direct(id) => format!("direct:{}", id.cn),
        Destination::Broadcast => "broadcast".to_string(),
        Destination::Multicast(groups) => {
            let joined: Vec<&str> = groups.iter().map(String::as_str).collect();
            format!("multicast:{}", joined.join(","))
        }
    }
}

/// Format a SystemTime as RFC 3339 / ISO 8601 UTC timestamp.
fn format_timestamp(t: std::time::SystemTime) -> String {
    let format = time::format_description::well_known::Iso8601::DEFAULT;
    match time::OffsetDateTime::from(t).format(&format) {
        Ok(s) => s,
        // Fallback: unix epoch seconds if formatting fails
        Err(_) => match t.duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => d.as_secs().to_string(),
            Err(_) => "0".to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use std::collections::BTreeSet;
    use std::sync::Arc;
    use std::time::SystemTime;

    use bytes::Bytes;
    use rustgate_core::identity::Identity;
    use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};

    use super::*;

    fn make_msg(payload: &[u8]) -> RoutableMessage {
        RoutableMessage {
            source: Identity {
                cn: "test-cn".to_string(),
                fingerprint: Default::default(),
                groups: {
                    let mut s = BTreeSet::new();
                    let _ = s.insert("alpha".to_string());
                    s
                },
                tenant: None,
                spiffe_id: None,
                attributes: Arc::new(Default::default()),
            },
            destination: Destination::Broadcast,
            payload: Bytes::from(payload.to_vec()),
            metadata: Metadata {
                received_at: SystemTime::now(),
                source_protocol: "tcp".to_string(),
                message_type: MessageType::Position,
                ttl: None,
            },
        }
    }

    #[test]
    fn json_serialization_roundtrip() {
        let msg = make_msg(b"<event/>");
        let (body, content_type) = serialize(&msg, PayloadFormat::Json, "inst-01").unwrap();
        assert_eq!(content_type, "application/json");

        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["source_cn"], "test-cn");
        assert_eq!(parsed["source_protocol"], "tcp");
        assert_eq!(parsed["message_type"], "position");
        assert_eq!(parsed["destination"], "broadcast");
        assert_eq!(parsed["instance_id"], "inst-01");
        assert_eq!(parsed["payload_size"], 8);
        // Payload is base64
        let decoded = b64::decode(parsed["payload"].as_str().unwrap()).unwrap();
        assert_eq!(decoded, b"<event/>");
    }

    #[test]
    fn json_contains_groups() {
        let msg = make_msg(b"<event/>");
        let (body, _) = serialize(&msg, PayloadFormat::Json, "inst").unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let groups = parsed["source_groups"].as_array().unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0], "alpha");
    }

    #[test]
    fn json_received_at_is_iso8601() {
        let msg = make_msg(b"test");
        let (body, _) = serialize(&msg, PayloadFormat::Json, "inst").unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let ts = parsed["received_at"].as_str().unwrap();
        // ISO 8601 timestamps contain 'T' and numeric digits
        assert!(ts.contains('T'), "expected ISO 8601 timestamp, got: {ts}");
    }

    #[test]
    fn raw_xml_passthrough() {
        let xml = b"<event uid='123'><point lat='1.0' lon='2.0'/></event>";
        let msg = make_msg(xml);
        let (body, content_type) = serialize(&msg, PayloadFormat::RawXml, "inst").unwrap();
        assert_eq!(content_type, "application/xml");
        assert_eq!(body, xml);
    }

    #[test]
    fn json_destination_group() {
        let mut msg = make_msg(b"test");
        msg.destination = Destination::Group("team-alpha".to_string());
        let (body, _) = serialize(&msg, PayloadFormat::Json, "inst").unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["destination"], "group:team-alpha");
    }

    #[test]
    fn json_destination_direct() {
        let mut msg = make_msg(b"test");
        msg.destination = Destination::Direct(Identity {
            cn: "target-user".to_string(),
            fingerprint: Default::default(),
            groups: BTreeSet::new(),
            tenant: None,
            spiffe_id: None,
            attributes: Arc::new(Default::default()),
        });
        let (body, _) = serialize(&msg, PayloadFormat::Json, "inst").unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["destination"], "direct:target-user");
    }

    #[test]
    fn json_destination_multicast() {
        let mut msg = make_msg(b"test");
        msg.destination = Destination::Multicast(vec!["alpha".to_string(), "bravo".to_string()]);
        let (body, _) = serialize(&msg, PayloadFormat::Json, "inst").unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["destination"], "multicast:alpha,bravo");
    }

    #[test]
    fn protobuf_without_feature_returns_error() {
        #[cfg(not(feature = "proto"))]
        {
            let msg = make_msg(b"<event/>");
            let err = serialize(&msg, PayloadFormat::Protobuf, "inst").unwrap_err();
            assert!(err.to_string().contains("proto"), "got: {err}");
        }
    }

    #[cfg(feature = "proto")]
    #[test]
    fn protobuf_serialization_content_type() {
        // Minimal valid CoT event XML for proto conversion
        let xml = b"<event version='2.0' uid='test-1' type='a-f-G' \
            time='2026-01-01T00:00:00Z' start='2026-01-01T00:00:00Z' \
            stale='2026-01-01T01:00:00Z' how='m-g'>\
            <point lat='38.0' lon='-77.0' hae='0' ce='10' le='10'/>\
            <detail/></event>";
        let msg = make_msg(xml);
        let (body, content_type) = serialize(&msg, PayloadFormat::Protobuf, "inst").unwrap();
        assert_eq!(content_type, "application/x-protobuf");
        assert!(!body.is_empty(), "protobuf body should not be empty");
    }

    #[test]
    fn binary_payload_base64_encoded() {
        let binary_data = vec![0x00, 0x01, 0xFF, 0xFE, 0x80];
        let msg = make_msg(&binary_data);
        let (body, _) = serialize(&msg, PayloadFormat::Json, "inst").unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let decoded = b64::decode(parsed["payload"].as_str().unwrap()).unwrap();
        assert_eq!(decoded, binary_data);
    }
}
