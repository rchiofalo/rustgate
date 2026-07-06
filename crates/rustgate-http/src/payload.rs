// Copyright © 2026 Roberto Chiofalo.

//! Payload serialization for HTTP-forwarded messages.
//!
//! Supports two formats: a JSON envelope containing source identity,
//! metadata, and base64-encoded payload; and raw XML passthrough for
//! consumers that expect CoT XML directly.

use bytes::Bytes;
use rustgate_core::b64;
use rustgate_core::message::{Destination, RoutableMessage};
use serde::Serialize;

use crate::config::{BatchFormat, PayloadFormat};
use crate::error::HttpError;
use crate::geojson;

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
///
/// `RawXml` returns the original `Bytes` payload by ref-count clone (no
/// copy). `Json` and `Protobuf` allocate fresh buffers and wrap them in
/// `Bytes` once — staying on `Bytes` end-to-end means the caller can
/// share the body across retry attempts and (where enabled) auth signing
/// without an extra `Vec<u8> -> Bytes` round-trip allocation.
pub(crate) fn serialize(
    msg: &RoutableMessage,
    format: PayloadFormat,
    instance_id: &str,
) -> Result<(Bytes, &'static str), HttpError> {
    match format {
        PayloadFormat::Json => serialize_json(msg, instance_id),
        PayloadFormat::RawXml => Ok((msg.payload.clone(), "application/xml")),
        PayloadFormat::Protobuf => serialize_protobuf(msg),
        PayloadFormat::GeoJson => geojson::serialize_feature(msg, instance_id),
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
// justification: `msg` is only consumed inside `#[cfg(feature = "proto")]`.
// When the feature is off we still return a `Config` error (the format
// should have been rejected at validation time — this is a belt-and-braces
// guard); duplicating the signature under `#[cfg]` would double the surface
// area for no benefit.
#[allow(unused_variables)]
fn serialize_protobuf(msg: &RoutableMessage) -> Result<(Bytes, &'static str), HttpError> {
    #[cfg(feature = "proto")]
    {
        let proto_bytes =
            rustgate_proto::xml_to_proto(&msg.payload).map_err(|e| HttpError::ProtoConvert {
                message: e.to_string(),
            })?;
        Ok((Bytes::from(proto_bytes), "application/x-protobuf"))
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
) -> Result<(Bytes, &'static str), HttpError> {
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
    Ok((Bytes::from(body), "application/json"))
}

pub(crate) fn format_destination(dest: &Destination) -> String {
    match dest {
        Destination::Group(g) => format!("group:{g}"),
        Destination::Direct(id) => format!("direct:{}", id.cn),
        Destination::Broadcast => "broadcast".to_string(),
        Destination::Multicast(groups) => {
            // `Arc<str>` is the canonical lean form for group fanout
            // (closes #784); deref the inner `Arc<str>` to `&str` for
            // the comma-joined wire shape.
            let joined: Vec<&str> = groups.iter().map(|g| &**g).collect();
            format!("multicast:{}", joined.join(","))
        }
    }
}

/// Concatenate already-serialized single-message bodies into a combined
/// batch request body.
///
/// Returns `(combined_body, content_type)`. The caller is responsible
/// for deciding *when* to flush — this helper is pure and does no I/O,
/// no locking, and no size checking.
///
/// # Framing
///
/// `payload_format` is consulted first: when it is
/// [`PayloadFormat::GeoJson`] the bodies (which are already serialized
/// `Feature` objects) are wrapped in a `FeatureCollection` envelope —
/// the only batch shape every GIS tool accepts (Leaflet, Mapbox,
/// Kepler.gl, QGIS, ArcGIS). Content-Type:
/// `application/geo+json`. The `batch_format` argument is ignored in
/// this branch — JSON-array vs NDJSON is not meaningful for GeoJSON.
///
/// For every other [`PayloadFormat`] the `batch_format` argument
/// drives the framing:
///
/// - [`BatchFormat::JsonArray`] — wraps bodies in `[…, …, …]` with a
///   single `,` separator between entries. Each `body` element MUST
///   already be a valid JSON document (typically from
///   [`serialize`] with [`PayloadFormat::Json`]); the helper does not
///   re-parse or re-validate, so feeding it non-JSON bytes produces
///   structurally-invalid output by design. Content-Type:
///   `application/json`.
/// - [`BatchFormat::Ndjson`] — joins bodies with `\n` separators and
///   appends a trailing `\n` (standard NDJSON convention: every line
///   including the last ends with LF). Content-Type:
///   `application/x-ndjson`.
///
/// # Empty input
///
/// An empty body slice produces `[]` for `JsonArray`, `""` for
/// `Ndjson`, and a well-formed empty `FeatureCollection` for GeoJSON.
/// Callers should avoid flushing an empty batch in practice — the
/// [`Batcher`](crate::batch::Batcher) only yields flush payloads when
/// at least one message is buffered — but the helper itself is total.
pub(crate) fn render_batch(
    bodies: &[Bytes],
    payload_format: PayloadFormat,
    batch_format: BatchFormat,
) -> (Bytes, &'static str) {
    if matches!(payload_format, PayloadFormat::GeoJson) {
        return geojson::render_feature_collection(bodies);
    }
    match batch_format {
        BatchFormat::JsonArray => render_json_array(bodies),
        BatchFormat::Ndjson => render_ndjson(bodies),
    }
}

fn render_json_array(bodies: &[Bytes]) -> (Bytes, &'static str) {
    if bodies.is_empty() {
        return (Bytes::from_static(b"[]"), "application/json");
    }
    // Exact-size preallocation: 2 brackets + sum-of-lengths + (n-1) commas.
    let total: usize = bodies.iter().map(|b| b.len()).sum();
    let cap = total + 2 + bodies.len().saturating_sub(1);
    let mut buf = Vec::with_capacity(cap);
    buf.push(b'[');
    for (i, body) in bodies.iter().enumerate() {
        if i > 0 {
            buf.push(b',');
        }
        buf.extend_from_slice(body);
    }
    buf.push(b']');
    (Bytes::from(buf), "application/json")
}

fn render_ndjson(bodies: &[Bytes]) -> (Bytes, &'static str) {
    if bodies.is_empty() {
        return (Bytes::new(), "application/x-ndjson");
    }
    let total: usize = bodies.iter().map(|b| b.len()).sum();
    let mut buf = Vec::with_capacity(total + bodies.len());
    for body in bodies {
        buf.extend_from_slice(body);
        buf.push(b'\n');
    }
    (Bytes::from(buf), "application/x-ndjson")
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
                cn: "test-cn".into(),
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
            metadata: Metadata::new(SystemTime::now(), "tcp".to_string(), MessageType::Position),
            entity: None,
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
        assert_eq!(body.as_ref(), xml);
    }

    #[test]
    fn json_destination_group() {
        let mut msg = make_msg(b"test");
        msg.destination = Destination::Group("team-alpha".into());
        let (body, _) = serialize(&msg, PayloadFormat::Json, "inst").unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["destination"], "group:team-alpha");
    }

    #[test]
    fn json_destination_direct() {
        let mut msg = make_msg(b"test");
        msg.destination = Destination::Direct(Identity {
            cn: "target-user".into(),
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
        msg.destination = Destination::Multicast(vec!["alpha".into(), "bravo".into()]);
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

    #[test]
    fn json_content_type_is_application_json_exact_string() {
        // The content-type strings are part of the on-the-wire
        // contract every downstream consumer (load balancers,
        // reverse proxies, SIEM ingest pipelines) inspects to
        // decide how to route, parse, and rate-limit. Pin the
        // exact `&'static str` value so a "normalise" refactor
        // that swapped to `application/json; charset=utf-8` or
        // `text/json` (both technically valid) would fail here
        // rather than at the first downstream consumer whose
        // content-type allowlist did not include the new form.
        let msg = make_msg(b"test");
        let (_, content_type) = serialize(&msg, PayloadFormat::Json, "inst").unwrap();
        assert_eq!(
            content_type, "application/json",
            "content-type must be the exact literal `application/json`"
        );
    }

    #[test]
    fn raw_xml_content_type_is_application_xml_exact_string() {
        // Symmetric to the JSON content-type pin — `application/xml`
        // is the advertised type for RawXml passthrough. A refactor
        // to `text/xml` (the legacy form) would silently change
        // every deployed consumer's content-negotiation outcome.
        let msg = make_msg(b"<event/>");
        let (_, content_type) = serialize(&msg, PayloadFormat::RawXml, "inst").unwrap();
        assert_eq!(
            content_type, "application/xml",
            "content-type must be the exact literal `application/xml`"
        );
    }

    #[test]
    fn json_wire_message_field_names_are_snake_case_contract() {
        // `HttpWireMessage` has no `#[serde(rename_all = …)]`
        // attribute, so the JSON output uses the Rust field names
        // verbatim (`source_cn`, `source_groups`, `destination`,
        // `message_type`, `source_protocol`, `received_at`,
        // `payload`, `payload_size`, `instance_id`). Every deployed
        // downstream consumer decodes against these exact keys. A
        // regression that added `rename_all = "camelCase"` would
        // silently produce `sourceCn`, `messageType`, etc., and
        // break every consumer without any compile error. Pin all
        // nine field names so the serde rename contract trips here
        // rather than at the consumer's JSON decoder.
        let msg = make_msg(b"test");
        let (body, _) = serialize(&msg, PayloadFormat::Json, "inst").unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let obj = parsed.as_object().expect("top-level must be a JSON object");
        for expected in [
            "source_cn",
            "source_groups",
            "destination",
            "message_type",
            "source_protocol",
            "received_at",
            "payload",
            "payload_size",
            "instance_id",
        ] {
            assert!(
                obj.contains_key(expected),
                "wire JSON must carry the `{expected}` field name verbatim (snake_case); got keys: {:?}",
                obj.keys().collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn payload_size_is_raw_byte_length_not_base64_expanded_length() {
        // `payload_size: msg.payload.len()` — a raw-bytes count,
        // NOT the base64-encoded string length. The documented
        // contract is "bytes of the original payload". A refactor
        // that used `payload_b64.len()` would silently inflate the
        // field by ~33% (base64 expansion ratio) and break every
        // downstream consumer that used the field for billing,
        // quota, or protocol-frame-size decisions. Choose a payload
        // length (10 bytes) where raw length and base64 length
        // differ visibly (10 bytes → base64 "dGVzdC0wMTIzNDU=" =
        // 16 chars) so the distinction is unambiguous.
        let payload = b"test-01234"; // exactly 10 bytes
        let msg = make_msg(payload);
        let (body, _) = serialize(&msg, PayloadFormat::Json, "inst").unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let size = parsed["payload_size"]
            .as_u64()
            .expect("numeric payload_size");
        assert_eq!(
            size, 10,
            "payload_size must be raw byte count (10), not base64 length (~16)"
        );
        let b64_len = parsed["payload"].as_str().expect("string payload").len();
        assert!(
            b64_len > 10,
            "sanity check — the base64 encoding of 10 bytes is longer than 10 chars \
             (got {b64_len}) so `size == b64_len` cannot be a coincidence"
        );
    }

    #[test]
    fn empty_payload_roundtrips_with_zero_size_and_empty_base64_field() {
        // Zero-length payload is a documented edge case — an empty
        // CoT `<detail/>` section or a control-plane keepalive
        // forwarded as HTTP. The wire JSON must carry
        // `payload_size: 0` and `payload: ""` (empty base64 string)
        // without any panic or None-field collapse. A regression
        // that short-circuited empty payloads to `payload: null`
        // would silently break every downstream consumer whose
        // JSON schema specified `payload: string`.
        let msg = make_msg(b"");
        let (body, _) = serialize(&msg, PayloadFormat::Json, "inst").unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["payload_size"], 0);
        assert_eq!(
            parsed["payload"], "",
            "empty payload must serialise as the empty string"
        );
        // And round-trip: decoding the empty base64 string gives zero bytes.
        let decoded = b64::decode("").unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn instance_id_passthrough_preserves_hyphen_and_alphanumeric_characters() {
        // `instance_id` is injected by the caller as a static
        // `&str` and emitted verbatim. Operators pick this id in
        // various shapes (hex uuids, k8s pod names with hyphens,
        // numeric ordinals). Pin that a representative shape
        // (`pod-07-a1b2c3`) survives byte-for-byte — a regression
        // that ran `instance_id` through a sanitiser or
        // url-encoder would silently change the field and break
        // operator dashboards keyed on exact pod identifiers.
        let msg = make_msg(b"x");
        let (body, _) = serialize(&msg, PayloadFormat::Json, "pod-07-a1b2c3").unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            parsed["instance_id"], "pod-07-a1b2c3",
            "instance_id must survive verbatim (no sanitisation, no url-encoding)"
        );
    }

    #[test]
    fn format_destination_multicast_three_groups_uses_comma_separator() {
        // `format_destination` joins the multicast groups with a
        // literal comma. Pin the separator exactly — a regression
        // to `";"`, `" "`, or URL-encoded `"%2C"` would silently
        // break every downstream parser that split on `","` to
        // recover the group list.
        let dest = Destination::Multicast(vec!["alpha".into(), "bravo".into(), "charlie".into()]);
        let rendered = format_destination(&dest);
        assert_eq!(
            rendered, "multicast:alpha,bravo,charlie",
            "multicast join must use a bare `,` separator with no whitespace"
        );
    }

    #[test]
    fn format_destination_multicast_empty_group_vector_yields_bare_prefix() {
        // Edge case — `Destination::Multicast(vec![])` is possible
        // at the type level even if rare at the router layer. The
        // function must still render the `"multicast:"` prefix
        // with an empty suffix (not panic, not drop the prefix).
        // A naive `groups[0]`-style implementation would panic on
        // an empty vector; the current iter-based implementation
        // does not, and this test pins the contract.
        let dest = Destination::Multicast(vec![]);
        let rendered = format_destination(&dest);
        assert_eq!(
            rendered, "multicast:",
            "empty multicast vector must render the bare prefix with no suffix"
        );
    }

    #[test]
    fn format_destination_group_with_empty_name_yields_bare_prefix() {
        // Symmetric edge case — `Destination::Group("".to_string())`
        // is a valid value at the type level. The format must emit
        // `"group:"` without panicking or synthesising any default
        // group name. The test pins that an empty group name
        // survives as an empty suffix rather than being silently
        // replaced (a regression that filled in a default would
        // silently route orphaned messages into a real group).
        let dest = Destination::Group(String::new().into());
        let rendered = format_destination(&dest);
        assert_eq!(
            rendered, "group:",
            "empty group name must render as the bare prefix, not be replaced by a default"
        );
    }

    #[test]
    fn raw_xml_passthrough_preserves_binary_bytes_byte_for_byte() {
        // The RawXml branch returns `msg.payload.clone()` (refcount
        // bump) verbatim — no re-encoding, no UTF-8 validation. This
        // matters because the docstring explicitly notes that CoT
        // XML may contain binary content or non-UTF-8 sequences in
        // some edge cases (embedded attachment bytes, raw
        // protobuf interop blobs). A regression to a UTF-8-validating
        // pass-through (e.g., via `str::from_utf8(...)?`) would
        // silently fail on those payloads. Pin byte-for-byte
        // equality against a deliberately-non-UTF-8 input.
        let binary: Vec<u8> = vec![0xFF, 0xFE, 0x00, 0x80, 0x81, 0xC0];
        let msg = make_msg(&binary);
        let (body, _) = serialize(&msg, PayloadFormat::RawXml, "inst").unwrap();
        assert_eq!(
            body.as_ref(),
            binary.as_slice(),
            "raw XML passthrough must return the payload bytes verbatim including non-UTF-8"
        );
    }

    #[test]
    fn json_preserves_source_protocol_verbatim_for_federation_hop() {
        // `source_protocol` is the grep-key the router + audit
        // trail use to distinguish "originated locally" from
        // "forwarded from a federated peer" (`"federation"`). Pin
        // that the literal string survives into the JSON wire —
        // a silent case-normalisation (`"Federation"`, `"FEDERATION"`)
        // or case-folding refactor would break downstream
        // echo-prevention + provenance tracking without tripping
        // the default-happy-path "tcp" test.
        let mut msg = make_msg(b"x");
        msg.metadata.source_protocol = "federation".to_string();
        let (body, _) = serialize(&msg, PayloadFormat::Json, "inst").unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            parsed["source_protocol"], "federation",
            "source_protocol must survive verbatim (no case-normalisation) so \
             the `federation` audit/echo-prevention grep token remains intact"
        );
    }

    // ── render_batch (issue #906 batch framing) ────────────────────────

    #[test]
    fn render_batch_json_array_single_message_wraps_in_brackets() {
        let bodies = vec![Bytes::from_static(br#"{"a":1}"#)];
        let (body, ct) = render_batch(&bodies, PayloadFormat::Json, BatchFormat::JsonArray);
        assert_eq!(ct, "application/json");
        assert_eq!(&body[..], br#"[{"a":1}]"#);
    }

    #[test]
    fn render_batch_json_array_multi_message_comma_separated() {
        let bodies = vec![
            Bytes::from_static(br#"{"a":1}"#),
            Bytes::from_static(br#"{"b":2}"#),
            Bytes::from_static(br#"{"c":3}"#),
        ];
        let (body, ct) = render_batch(&bodies, PayloadFormat::Json, BatchFormat::JsonArray);
        assert_eq!(ct, "application/json");
        assert_eq!(&body[..], br#"[{"a":1},{"b":2},{"c":3}]"#);
        // Roundtrip: the result parses as a JSON array of three objects.
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v.as_array().map(Vec::len), Some(3));
    }

    #[test]
    fn render_batch_json_array_empty_input_emits_bare_brackets() {
        let (body, ct) = render_batch(&[], PayloadFormat::Json, BatchFormat::JsonArray);
        assert_eq!(ct, "application/json");
        assert_eq!(&body[..], b"[]");
    }

    #[test]
    fn render_batch_ndjson_single_message_appends_newline() {
        let bodies = vec![Bytes::from_static(br#"{"a":1}"#)];
        let (body, ct) = render_batch(&bodies, PayloadFormat::Json, BatchFormat::Ndjson);
        assert_eq!(ct, "application/x-ndjson");
        assert_eq!(&body[..], b"{\"a\":1}\n");
    }

    #[test]
    fn render_batch_ndjson_multi_message_every_line_including_last_ends_with_lf() {
        let bodies = vec![
            Bytes::from_static(br#"{"a":1}"#),
            Bytes::from_static(br#"{"b":2}"#),
            Bytes::from_static(br#"{"c":3}"#),
        ];
        let (body, ct) = render_batch(&bodies, PayloadFormat::Json, BatchFormat::Ndjson);
        assert_eq!(ct, "application/x-ndjson");
        assert_eq!(&body[..], b"{\"a\":1}\n{\"b\":2}\n{\"c\":3}\n");
        // Every NDJSON line is independently parseable.
        let lines: Vec<&[u8]> = body
            .split(|&b| b == b'\n')
            .filter(|l| !l.is_empty())
            .collect();
        assert_eq!(lines.len(), 3);
        for line in lines {
            let _: serde_json::Value = serde_json::from_slice(line).unwrap();
        }
    }

    #[test]
    fn render_batch_ndjson_empty_input_emits_empty_body() {
        let (body, ct) = render_batch(&[], PayloadFormat::Json, BatchFormat::Ndjson);
        assert_eq!(ct, "application/x-ndjson");
        assert!(body.is_empty());
    }

    #[test]
    fn render_batch_preserves_raw_bytes_verbatim() {
        // The helper is format-agnostic about the *content* of each body;
        // it only frames them. Non-JSON bytes round-trip byte-for-byte
        // (behaviour is "structurally invalid output by design", but the
        // render step itself must not mutate input bytes).
        let a = Bytes::from_static(b"hello");
        let b = Bytes::from_static(b"world");
        let (ndjson, _) = render_batch(
            &[a.clone(), b.clone()],
            PayloadFormat::Json,
            BatchFormat::Ndjson,
        );
        assert_eq!(&ndjson[..], b"hello\nworld\n");
        let (arr, _) = render_batch(&[a, b], PayloadFormat::Json, BatchFormat::JsonArray);
        assert_eq!(&arr[..], b"[hello,world]");
    }

    #[test]
    fn render_batch_geojson_dispatches_to_feature_collection_regardless_of_batch_format() {
        // When `payload_format = GeoJson` the `batch_format` argument is
        // ignored — JSON-array vs NDJSON is not meaningful for GeoJSON.
        // Pin that both BatchFormat values produce the same envelope so
        // an operator who left `batch-format = json-array` (the default)
        // and switched to `format = geo_json` does not get a malformed
        // body or a content-type mismatch.
        let f = Bytes::from_static(br#"{"type":"Feature","geometry":null,"properties":{}}"#);
        for batch_format in [BatchFormat::JsonArray, BatchFormat::Ndjson] {
            let (body, ct) = render_batch(
                std::slice::from_ref(&f),
                PayloadFormat::GeoJson,
                batch_format,
            );
            assert_eq!(ct, "application/geo+json");
            let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(parsed["type"], "FeatureCollection");
        }
    }
}
