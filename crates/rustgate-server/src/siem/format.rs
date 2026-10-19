// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Renders an [`AuditRecord`] as a SIEM payload (CEF or JSON) inside an
//! RFC 5424 syslog message, framed for RFC 5425 (syslog over TLS).

use std::fmt::Write as _;
use std::net::SocketAddr;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use super::layer::AuditRecord;

/// Payload format inside each syslog message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "lowercase")]
pub(crate) enum Format {
    /// ArcSight Common Event Format v0.
    #[default]
    Cef,
    /// One JSON object per event.
    Json,
}

/// RFC 5424 facility 13, "log audit".
const SYSLOG_FACILITY: u8 = 13;
const APP_NAME: &str = "rustgate";
const MSG_ID: &str = "audit";
const CEF_VERSION: &str = env!("CARGO_PKG_VERSION");

/// CEF severity (0-10) for every audit event the workspace emits.
///
/// Severity is set per event rather than derived from the `result` field,
/// because results do not track risk: `audit.chain_discontinuity` reports
/// `detected` and `federation.group_claim_rejected` reports `success`, yet
/// both are security signals. `tests::every_audit_event_has_a_severity`
/// fails when an audit event anywhere in the workspace is missing here:
/// both `rustgate_core::audit` functions and direct
/// `tracing::*!(target: "audit", event_type = ...)` calls.
///
/// Bands: 9-10 audit-trail integrity or boundary breach, 7-8 attack
/// indicators and security-control failures, 5-6 policy denials and
/// degraded security posture, 3-4 operational warnings, 1-2 routine.
const SEVERITY: &[(&str, u8)] = &[
    // Audit-trail integrity and boundary breaches.
    ("audit.chain_discontinuity", 10),
    ("guard.chain_reset", 9),
    ("air_gap.violation", 9),
    ("audit.chain_anchor_persist_failed", 8),
    // Attack indicators and failed security controls.
    ("crl.fail_closed_engaged", 8),
    ("federation.group_claim_rejected", 8),
    ("mavlink.replay_rejected", 8),
    ("mavlink.signature_rejected", 8),
    ("store_forward.drain_panic", 8),
    ("classification.denied", 7),
    ("enrollment.auth_failed", 7),
    ("federation.event_rejected", 7),
    ("hw_identity.sign_failed", 7),
    ("hw_identity.unavailable", 7),
    ("session.evicted", 7),
    ("verifier.rebuild_failed", 7),
    ("authz.reload_failed", 7),
    ("cert.rotation_failed", 7),
    ("crl.reload_failed", 7),
    // Policy denials and degraded security posture.
    ("authz.denied", 6),
    ("authz.obligation_failed", 6),
    ("authz.reload_rollback", 6),
    ("classification.missing", 6),
    ("enrollment.certificate_revoked", 6),
    ("enrollment.sign_failed", 6),
    ("federation.discovered_peer_unpinned", 6),
    ("federation.peer_rejected", 6),
    ("guard.rejected", 6),
    ("jwks.refresh_failed", 6),
    ("mavlink.unsigned_rejected", 6),
    ("mavlink.v1_admitted", 6),
    ("mavlink.v1_rejected", 5),
    ("authz.classified_delivery", 5),
    ("authz.obligation_unknown", 5),
    ("admin.drain_triggered", 5),
    ("client.force_disconnected", 5),
    ("client.rejected", 5),
    ("client.tls_error", 5),
    ("federation.circuit_tripped", 5),
    ("federation.config_changed", 5),
    ("federation.traceparent_invalid", 5),
    ("http.circuit_tripped", 5),
    ("http.dlq_failed", 5),
    ("mesh.loop_detected", 5),
    ("revocation.sweep_clock_skew", 5),
    ("security.rate_limited", 5),
    ("siem.disconnected", 5),
    ("tenant.isolation_label_overflow", 5),
    ("tls.handshake_failed", 5),
    // Operational warnings.
    ("archive.key_rotation_due", 4),
    ("crl.fail_closed_cleared", 4),
    ("federation.connect_failed", 4),
    ("http.publish_failed", 4),
    ("jwt.using_retiring_kid", 4),
    ("mgmt.api_accessed", 4),
    ("nats.poison_dlq", 4),
    ("quota.tenant_queued_bytes_exceeded", 4),
    ("quota.tenant_throughput_exceeded", 4),
    ("store_forward.dropped", 4),
    ("cert.rotated", 3),
    ("client.negotiation", 3),
    ("enrollment.certificate_issued", 3),
    ("enrollment.signed", 3),
    ("federation.disconnected", 3),
    ("guard.activated", 3),
    ("http.circuit_probing", 3),
    ("http.circuit_recovered", 3),
    ("http.rate_limited", 3),
    ("hw_identity.loaded", 3),
    ("jwks.key_added", 3),
    ("jwks.key_removed", 3),
    ("mesh.no_route_to_destination", 3),
    ("mesh.ttl_expired", 3),
    ("message.dropped", 3),
    ("mqtt.will_published", 3),
    ("position_replay.rate_limited", 3),
    ("server.started", 3),
    ("siem.connected", 3),
    ("spiffe.svid_refresh", 3),
    ("authz.reload_success", 3),
    ("crl.reloaded", 3),
    ("egress.obligation.applied", 3),
    ("federation.circuit_recovered", 3),
    ("store_forward.key_rotated", 4),
    // Emitted with `target: "audit"` outside `rustgate_core::audit`.
    ("acl.reload_failed", 7),
    ("acl.api_delete", 5),
    ("acl.api_upsert", 5),
    ("audit.untyped", 5),
    ("config.reload", 3),
    ("acl.reload_success", 3),
    ("marti.sync_upload", 3),
    ("missions.package_deleted", 4),
    // Routine.
    ("audit.chain_anchor_persisted", 2),
    ("archive.rotation_completed", 2),
    ("client.connected", 2),
    ("client.disconnected", 2),
    ("federation.connected", 2),
    ("federation.event_received", 1),
    ("http.dlq_drain_completed", 2),
    ("http.dlq_drain_started", 2),
    ("jwks.refresh_success", 1),
    ("mavlink.heartbeat_received", 1),
    ("mesh.forwarded", 1),
    ("mesh.route_added", 2),
    ("mesh.route_removed", 2),
    ("mesh.route_updated", 2),
    ("message.delivered", 1),
    ("store_forward.drained", 2),
    ("udp_multicast.joined", 2),
    ("udp_multicast.publish", 1),
];

/// Severity for an event type not in [`SEVERITY`] (a new event in a
/// deployment built before the table was updated).
const UNKNOWN_EVENT_SEVERITY: u8 = 5;

/// CEF severity (0-10) for `record`.
///
/// Two adjustments on top of the table: events whose outcome varies
/// (e.g. `spiffe.svid_refresh`, `config.reload`) are raised to at least 6
/// when the record reports a failure, and a guard rejection for an
/// unauthorized classification (a blocked spill at the cross-domain
/// boundary) is raised to 8.
pub(crate) fn severity(record: &AuditRecord) -> u8 {
    let base = SEVERITY
        .iter()
        .find(|(event, _)| *event == record.event_type)
        .map_or(UNKNOWN_EVENT_SEVERITY, |(_, sev)| *sev);
    if record.event_type == "guard.rejected"
        && record.field("reason") == Some("unauthorized_classification")
    {
        return base.max(8);
    }
    match record.field("result") {
        Some("failure" | "failed" | "panic") => base.max(6),
        _ => base,
    }
}

/// Syslog severity (RFC 5424 §6.2.1) for a CEF severity.
fn syslog_severity(cef: u8) -> u8 {
    match cef {
        9.. => 2,   // critical
        7..=8 => 3, // error
        5..=6 => 4, // warning
        3..=4 => 5, // notice
        _ => 6,     // informational
    }
}

/// One RFC 5425 frame (`MSG-LEN SP SYSLOG-MSG`) for `record`.
pub(crate) fn syslog_frame(
    record: &AuditRecord,
    format: Format,
    hostname: &str,
    pid: u32,
) -> Vec<u8> {
    let sev = severity(record);
    let payload = match format {
        Format::Cef => cef(record, sev),
        Format::Json => json(record, sev),
    };
    let pri = u16::from(SYSLOG_FACILITY) * 8 + u16::from(syslog_severity(sev));
    let message = format!(
        "<{pri}>1 {ts} {hostname} {APP_NAME} {pid} {MSG_ID} - {payload}",
        ts = rfc5424_timestamp(record.at),
    );
    let mut frame = format!("{} ", message.len()).into_bytes();
    frame.extend_from_slice(message.as_bytes());
    frame
}

/// RFC 5424 `TIMESTAMP` in UTC with millisecond precision (the grammar
/// allows at most six fractional digits).
fn rfc5424_timestamp(at: OffsetDateTime) -> String {
    let at = at.to_offset(time::UtcOffset::UTC);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        at.year(),
        u8::from(at.month()),
        at.day(),
        at.hour(),
        at.minute(),
        at.second(),
        at.millisecond()
    )
}

/// Normalize a hostname for the RFC 5424 `HOSTNAME` field: printable
/// US-ASCII without spaces, at most 255 characters, `-` when empty.
pub(crate) fn syslog_hostname(raw: &str) -> String {
    let host: String = raw
        .chars()
        .filter(|c| c.is_ascii_graphic())
        .take(255)
        .collect();
    if host.is_empty() {
        "-".to_owned()
    } else {
        host
    }
}

/// Render `record` as a CEF v0 line:
/// `CEF:0|rustgate|rustgate|<version>|<event_type>|<event_type>|<severity>|<extension>`.
pub(crate) fn cef(record: &AuditRecord, severity: u8) -> String {
    let event = escape_cef_header(&record.event_type);
    let mut line = format!(
        "CEF:0|{APP_NAME}|{APP_NAME}|{}|{event}|{event}|{severity}|",
        escape_cef_header(CEF_VERSION)
    );
    let mut pairs: Vec<(String, String)> = vec![(
        "rt".to_owned(),
        (record.at.unix_timestamp_nanos() / 1_000_000).to_string(),
    )];
    for (key, value) in &record.fields {
        match key.as_str() {
            "action" => pairs.push(("act".to_owned(), value.clone())),
            "result" => pairs.push(("outcome".to_owned(), value.clone())),
            "reason" => pairs.push(("reason".to_owned(), value.clone())),
            "message" => pairs.push(("msg".to_owned(), value.clone())),
            "cn" => pairs.push(("suser".to_owned(), value.clone())),
            "peer" | "peer_addr" | "remote_addr" => match value.parse::<SocketAddr>() {
                Ok(addr) => {
                    pairs.push(("src".to_owned(), addr.ip().to_string()));
                    pairs.push(("spt".to_owned(), addr.port().to_string()));
                }
                Err(_) => pairs.push((cef_key(key), value.clone())),
            },
            _ => pairs.push((cef_key(key), value.clone())),
        }
    }
    for (i, (key, value)) in pairs.iter().enumerate() {
        if i > 0 {
            line.push(' ');
        }
        let _ = write!(line, "{key}={}", escape_cef_value(value));
    }
    line
}

/// CEF header fields escape `\` and `|`. The format has no escape for
/// line breaks in the header, so control characters become spaces.
fn escape_cef_header(field: &str) -> String {
    let mut out = String::with_capacity(field.len());
    for ch in field.chars() {
        match ch {
            '\\' | '|' => {
                out.push('\\');
                out.push(ch);
            }
            c if c.is_control() => out.push(' '),
            c => out.push(c),
        }
    }
    out
}

/// CEF extension values escape `\` and `=`, and encode CR / LF as `\r` /
/// `\n`; other control characters become spaces, so a value can never
/// end the line or forge a key.
fn escape_cef_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '=' => out.push_str("\\="),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c if c.is_control() => out.push(' '),
            c => out.push(c),
        }
    }
    out
}

/// A CEF extension key for an audit field without a dictionary key: CEF
/// keys are alphanumeric, so `peer_id` becomes `peerId`.
fn cef_key(field: &str) -> String {
    let mut out = String::with_capacity(field.len());
    let mut upper = false;
    for ch in field.chars() {
        if ch.is_ascii_alphanumeric() {
            if upper {
                out.push(ch.to_ascii_uppercase());
                upper = false;
            } else {
                out.push(ch);
            }
        } else {
            upper = !out.is_empty();
        }
    }
    if out.is_empty() {
        "field".to_owned()
    } else {
        out
    }
}

/// Render `record` as one JSON object (no trailing newline). Field names
/// are kept as emitted; `timestamp`, `event_type` and `severity` are
/// added and take precedence over a field of the same name.
pub(crate) fn json(record: &AuditRecord, severity: u8) -> String {
    let mut object = serde_json::Map::new();
    for (key, value) in &record.fields {
        let _ = object.insert(key.clone(), serde_json::Value::String(value.clone()));
    }
    let _ = object.insert(
        "timestamp".to_owned(),
        serde_json::Value::String(rfc5424_timestamp(record.at)),
    );
    let _ = object.insert(
        "event_type".to_owned(),
        serde_json::Value::String(record.event_type.clone()),
    );
    let _ = object.insert("severity".to_owned(), serde_json::Value::from(severity));
    serde_json::Value::Object(object).to_string()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use super::*;

    fn record(event_type: &str, fields: &[(&str, &str)]) -> AuditRecord {
        AuditRecord {
            // 2026-10-18T12:34:56.789Z
            at: OffsetDateTime::from_unix_timestamp_nanos(1_792_326_896_789_000_000).unwrap(),
            event_type: event_type.to_owned(),
            fields: fields
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
        }
    }

    #[test]
    fn every_audit_event_has_a_severity() {
        let events = workspace_audit_events();
        // The scan must find both kinds, including names with digits.
        for expected in ["mavlink.v1_admitted", "config.reload", "acl.reload_failed"] {
            assert!(
                events.iter().any(|e| e == expected),
                "scan missed {expected}"
            );
        }
        let missing: Vec<&String> = events
            .iter()
            .filter(|e| !SEVERITY.iter().any(|(name, _)| name == e))
            .collect();
        assert!(
            missing.is_empty(),
            "audit events without a SIEM severity: {missing:?}"
        );
    }

    /// Every audit event type emitted in the workspace: `audit!("...")` in
    /// `rustgate_core::audit`, and `event_type = "..."` in direct
    /// `target: "audit"` calls in any crate's `src/`.
    fn workspace_audit_events() -> Vec<String> {
        fn rust_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            for entry in std::fs::read_dir(dir).unwrap().flatten() {
                let path = entry.path();
                if path.is_dir() {
                    rust_files(&path, out);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    out.push(path);
                }
            }
        }
        /// The quoted string after each occurrence of `marker`.
        fn quoted_after<'a>(s: &'a str, marker: &str) -> Vec<&'a str> {
            let mut found = Vec::new();
            let mut rest = s;
            while let Some(i) = rest.find(marker) {
                rest = &rest[i + marker.len()..];
                let Some(start) = rest.find('"') else { break };
                let after = &rest[start + 1..];
                let Some(end) = after.find('"') else { break };
                found.push(&after[..end]);
            }
            found
        }
        let crates = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let mut files = Vec::new();
        for krate in std::fs::read_dir(&crates).unwrap().flatten() {
            let src = krate.path().join("src");
            if src.is_dir() {
                rust_files(&src, &mut files);
            }
        }
        let mut events = Vec::new();
        for file in files {
            // Whitespace is removed so formatting cannot hide a call
            // (`target:"audit"`, `event_type="x"`); event names have none.
            let text: String = std::fs::read_to_string(&file)
                .unwrap()
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect();
            // Production code only: the test module emits fixture events.
            let text = text.split("#[cfg(test)]mod").next().unwrap();
            if file.ends_with("rustgate-core/src/audit.rs") {
                events.extend(quoted_after(text, "audit!(").into_iter().map(str::to_owned));
            }
            let mut rest = text;
            while let Some(i) = rest.find("target:\"audit\"") {
                rest = &rest[i + 1..];
                let end = rest
                    .char_indices()
                    .nth(400)
                    .map_or(rest.len(), |(at, _)| at);
                // Only an `event_type` before the call ends belongs to it.
                let window = rest[..end].split(");").next().unwrap_or(&rest[..end]);
                if let Some(event) = quoted_after(window, "event_type=").first() {
                    events.push((*event).to_owned());
                }
            }
        }
        events.sort();
        events.dedup();
        events
    }

    #[test]
    fn severity_table_has_no_duplicates() {
        let mut names: Vec<&str> = SEVERITY.iter().map(|(e, _)| *e).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(before, names.len());
    }

    #[test]
    fn severity_follows_the_event_not_the_result() {
        // `detected` and `success` would read as benign results.
        assert_eq!(
            severity(&record(
                "audit.chain_discontinuity",
                &[("result", "detected")]
            )),
            10
        );
        assert_eq!(
            severity(&record(
                "federation.group_claim_rejected",
                &[("result", "success")]
            )),
            8
        );
        // A failure raises an otherwise routine event.
        assert_eq!(
            severity(&record("spiffe.svid_refresh", &[("result", "success")])),
            3
        );
        assert_eq!(
            severity(&record("spiffe.svid_refresh", &[("result", "failure")])),
            6
        );
        assert_eq!(
            severity(&record("no.such_event", &[])),
            UNKNOWN_EVENT_SEVERITY
        );
        // A blocked classification spill at the guard outranks other rejects.
        assert_eq!(
            severity(&record("guard.rejected", &[("reason", "rate_limit")])),
            6
        );
        assert_eq!(
            severity(&record(
                "guard.rejected",
                &[("reason", "unauthorized_classification")]
            )),
            8
        );
    }

    #[test]
    fn cef_line_maps_known_fields_to_the_dictionary() {
        let rec = record(
            "client.rejected",
            &[
                ("peer", "203.0.113.7:44100"),
                ("reason", "connection limit reached"),
                ("action", "connect"),
                ("result", "rejected"),
                ("peer_id", "east-1"),
            ],
        );
        assert_eq!(
            cef(&rec, 5),
            format!(
                "CEF:0|rustgate|rustgate|{CEF_VERSION}|client.rejected|client.rejected|5|\
                 rt=1792326896789 src=203.0.113.7 spt=44100 reason=connection limit reached \
                 act=connect outcome=rejected peerId=east-1"
            )
        );
    }

    #[test]
    fn cef_never_emits_a_raw_line_break() {
        let rec = record(
            "evil|type\r\nCEF:0|forged",
            &[("note", "a=b\\c\nd\re\u{0}f"), ("bad key=x y", "v")],
        );
        let line = cef(&rec, 3);
        assert!(!line.contains('\n') && !line.contains('\r') && !line.contains('\0'));
        assert!(line.contains("|evil\\|type  CEF:0\\|forged|"), "{line}");
        assert!(line.contains("note=a\\=b\\\\c\\nd\\re f"), "{line}");
        assert!(line.contains(" badKeyXY=v"), "{line}");
    }

    #[test]
    fn json_payload_is_one_object() {
        let rec = record("session.evicted", &[("cn", "alice"), ("reason", "revoked")]);
        let value: serde_json::Value = serde_json::from_str(&json(&rec, 7)).unwrap();
        assert_eq!(value["event_type"], "session.evicted");
        assert_eq!(value["severity"], 7);
        assert_eq!(value["cn"], "alice");
        assert_eq!(value["timestamp"], "2026-10-18T12:34:56.789Z");
        // A field named like an added key cannot override it.
        let spoof = record(
            "client.connected",
            &[("event_type", "audit.chain_discontinuity")],
        );
        let value: serde_json::Value = serde_json::from_str(&json(&spoof, 2)).unwrap();
        assert_eq!(value["event_type"], "client.connected");
    }

    #[test]
    fn syslog_frame_is_octet_counted_rfc5424() {
        let rec = record("audit.chain_discontinuity", &[("result", "detected")]);
        let frame = String::from_utf8(syslog_frame(&rec, Format::Cef, "gw-1", 42)).unwrap();
        let (len, message) = frame.split_once(' ').unwrap();
        assert_eq!(len.parse::<usize>().unwrap(), message.len());
        // facility 13 * 8 + critical (2) = 106
        assert!(
            message.starts_with("<106>1 2026-10-18T12:34:56.789Z gw-1 rustgate 42 audit - CEF:0|"),
            "{message}"
        );
    }

    #[test]
    fn hostname_is_normalized_for_rfc5424() {
        assert_eq!(syslog_hostname("gw 1\n"), "gw1");
        assert_eq!(syslog_hostname(""), "-");
        assert_eq!(syslog_hostname(&"a".repeat(300)).len(), 255);
    }
}
