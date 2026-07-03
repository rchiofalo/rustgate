// Copyright © 2026 Roberto Chiofalo.

//! ArcSight Common Event Format (CEF) v0 line formatter (ADR 0028,
//! Phase 1a).
//!
//! Renders a [`super::AuditEvent`] into a single RFC-compliant CEF line:
//!
//! ```text
//! CEF:0|vendor|product|version|signature|name|severity|extension
//! ```
//!
//! The seven header fields are pipe-delimited. Per the CEF spec, a
//! literal pipe or backslash inside one of the four text header fields
//! (vendor, product, signature, name) is escaped as `\|` / `\\`. In the
//! extension, a literal equals, backslash, or newline inside a *value*
//! is escaped as `\=` / `\\` / `\n`, so a value can never terminate a
//! field early or inject a raw newline into the log stream.
//!
//! This is a pure string transform with no I/O; the syslog sink that
//! consumes it is deferred to ADR 0028 Phase 1b.

use super::AuditEvent;

/// CEF header: the product vendor. Fixed for this workspace.
const CEF_VENDOR: &str = "rustgate";
/// CEF header: the product name. Fixed for this workspace.
const CEF_PRODUCT: &str = "rustgate";
/// CEF header: the product version reported to the SIEM.
const CEF_VERSION: &str = env!("CARGO_PKG_VERSION");
/// CEF format version prefix. `0` is the only version defined by the
/// CEF specification.
const CEF_FORMAT_VERSION: &str = "0";

/// CEF severity, a 0–10 integer where higher is more severe.
///
/// Derived from the audit `result` string. Benign outcomes (a
/// successful connect, a normal disconnect) map low; adverse outcomes
/// (a rejection, a denial, a failure) map high. Values are chosen to
/// land in the CEF-recommended bands: 0–3 low, 4–6 medium, 7–10 high.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Severity(u8);

impl Severity {
    /// Benign / successful outcome.
    pub const LOW: Severity = Severity(3);
    /// Rejected or denied by policy (an authorization decision).
    pub const REJECTED: Severity = Severity(6);
    /// An operation failed (an error outcome).
    pub const FAILED: Severity = Severity(8);

    /// Map an audit `result` string to a CEF severity.
    ///
    /// The comparison is ASCII-case-insensitive. Known adverse outcomes
    /// (`rejected`, `denied`, `deny`, `dropped`, `shed`) map to
    /// [`Severity::REJECTED`]; error outcomes (`failed`, `failure`,
    /// `panic`, `error`) map to [`Severity::FAILED`]. Everything else —
    /// including `success` and unrecognized values — maps to
    /// [`Severity::LOW`], so an unknown outcome is never over-reported
    /// as an alert-worthy event.
    #[must_use]
    pub fn from_result(result: &str) -> Severity {
        // Match on a lowercased copy so the caller's casing does not
        // matter; the audit trail uses lowercase today but a SIEM
        // operator should not depend on that.
        let normalized = result.to_ascii_lowercase();
        match normalized.as_str() {
            "rejected" | "denied" | "deny" | "dropped" | "shed" => Severity::REJECTED,
            "failed" | "failure" | "panic" | "error" => Severity::FAILED,
            _ => Severity::LOW,
        }
    }

    /// The raw 0–10 severity value.
    #[must_use]
    pub fn value(self) -> u8 {
        self.0
    }
}

/// Escape a CEF **header** text field: a literal backslash or pipe is
/// prefixed with a backslash. Applied to vendor, product, signature,
/// and name so an embedded `|` cannot introduce a spurious field
/// boundary.
fn escape_header(field: &str) -> String {
    let mut out = String::with_capacity(field.len());
    for ch in field.chars() {
        if ch == '\\' || ch == '|' {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

/// Escape a CEF **extension value**: a literal backslash or equals is
/// prefixed with a backslash, and a newline / carriage return is
/// rendered as the two-character sequence `\n` / `\r` so no raw control
/// byte reaches the log stream (log-injection guard).
fn escape_extension_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '=' => out.push_str("\\="),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            other => out.push(other),
        }
    }
    out
}

/// Escape a CEF extension **key**. CEF keys are supposed to be simple
/// identifiers; we still strip the structural characters (`=`, space,
/// backslash, and control bytes) so a hostile field name cannot forge a
/// key boundary. Disallowed characters are replaced with `_`.
fn sanitize_extension_key(key: &str) -> String {
    key.chars()
        .map(|ch| {
            if ch == '=' || ch == ' ' || ch == '\\' || ch.is_control() {
                '_'
            } else {
                ch
            }
        })
        .collect()
}

/// Render an [`AuditEvent`] into a single RFC-compliant CEF v0 line.
///
/// The returned string contains no trailing newline — the transport
/// layer (ADR 0028 Phase 1b) owns syslog framing. The header is always
/// seven pipe-delimited fields; the extension is a space-separated run
/// of `key=value` pairs (empty when the event carries no fields).
///
/// The `name` header falls back to `event_type` when
/// [`AuditEvent::name`] is empty, so the field is never blank. The
/// `action` and `result` fields, when non-empty, are also surfaced as
/// the `act` and `outcome` extension fields for SIEM-side correlation.
#[must_use]
pub fn format_cef(event: &AuditEvent) -> String {
    let severity = Severity::from_result(&event.result);

    let name = if event.name.is_empty() {
        event.event_type.as_str()
    } else {
        event.name.as_str()
    };

    let mut line = format!(
        "CEF:{ver}|{vendor}|{product}|{version}|{signature}|{name}|{severity}|",
        ver = CEF_FORMAT_VERSION,
        vendor = escape_header(CEF_VENDOR),
        product = escape_header(CEF_PRODUCT),
        version = escape_header(CEF_VERSION),
        signature = escape_header(&event.event_type),
        name = escape_header(name),
        severity = severity.value(),
    );

    // Extension: `act` and `outcome` first (stable, well-known keys),
    // then the caller's fields in insertion order.
    let mut first = true;
    let mut push_pair = |line: &mut String, key: &str, value: &str| {
        if !first {
            line.push(' ');
        }
        first = false;
        line.push_str(&sanitize_extension_key(key));
        line.push('=');
        line.push_str(&escape_extension_value(value));
    };

    if !event.action.is_empty() {
        push_pair(&mut line, "act", &event.action);
    }
    if !event.result.is_empty() {
        push_pair(&mut line, "outcome", &event.result);
    }
    for (key, value) in &event.extension {
        push_pair(&mut line, key, value);
    }

    line
}

#[cfg(all(test, feature = "siem"))]
mod tests {
    use super::*;

    // Header prefix shared by every golden assertion below. Kept in one
    // place so a version bump only touches the constant, not each test.
    fn header_prefix(signature: &str, name: &str, severity: u8) -> String {
        format!(
            "CEF:0|rustgate|rustgate|{}|{}|{}|{}|",
            env!("CARGO_PKG_VERSION"),
            signature,
            name,
            severity
        )
    }

    #[test]
    fn golden_client_rejected_line() {
        let event = AuditEvent::new("client.rejected", "connect", "rejected")
            .with_name("Client rejected")
            .with_field("peer", "203.0.113.7:44100")
            .with_field("reason", "connection limit reached");

        let line = format_cef(&event);
        let expected = format!(
            "{}act=connect outcome=rejected peer=203.0.113.7:44100 reason=connection limit reached",
            header_prefix("client.rejected", "Client rejected", 6)
        );
        assert_eq!(line, expected);
    }

    #[test]
    fn header_escapes_pipe_and_backslash() {
        // A hostile event_type / name carrying pipe and backslash must
        // be escaped so it cannot forge a header field boundary.
        let event = AuditEvent::new("evt|type", "act", "success").with_name("na\\me|x");
        let line = format_cef(&event);
        assert!(
            line.contains("|evt\\|type|na\\\\me\\|x|"),
            "header not escaped: {line}"
        );
    }

    #[test]
    fn extension_escapes_equals_backslash_and_newline() {
        let event = AuditEvent::new("test.event", "act", "success").with_field("k", "a=b\\c\nd\re");
        let line = format_cef(&event);
        // The raw value's '=', '\\', '\n', '\r' are each escaped.
        assert!(
            line.ends_with("k=a\\=b\\\\c\\nd\\re"),
            "value not escaped: {line}"
        );
        // And no raw newline or carriage return survives anywhere.
        assert!(!line.contains('\n'), "raw newline leaked: {line:?}");
        assert!(!line.contains('\r'), "raw carriage return leaked: {line:?}");
    }

    #[test]
    fn hostile_extension_key_cannot_forge_a_boundary() {
        // A key carrying '=' or a space would otherwise split the pair;
        // it is neutralized to '_'.
        let event = AuditEvent::new("test.event", "", "").with_field("k=y bad", "v");
        let line = format_cef(&event);
        assert!(line.ends_with("k_y_bad=v"), "key not sanitized: {line}");
    }

    #[test]
    fn severity_mapping_low_medium_high() {
        assert_eq!(Severity::from_result("success"), Severity::LOW);
        assert_eq!(Severity::from_result("delivered"), Severity::LOW);
        assert_eq!(Severity::from_result("REJECTED"), Severity::REJECTED);
        assert_eq!(Severity::from_result("denied"), Severity::REJECTED);
        assert_eq!(Severity::from_result("failure"), Severity::FAILED);
        assert_eq!(Severity::from_result("failed"), Severity::FAILED);
        // Unknown outcomes must not be over-reported as alert-worthy.
        assert_eq!(Severity::from_result("wat"), Severity::LOW);
        assert!(Severity::LOW < Severity::REJECTED);
        assert!(Severity::REJECTED < Severity::FAILED);
    }

    #[test]
    fn empty_extension_still_produces_a_valid_seven_field_header() {
        let event = AuditEvent::new("client.disconnected", "", "");
        let line = format_cef(&event);
        // Seven pipe-delimited header fields => the line ends at the
        // trailing pipe with an empty extension (name falls back to
        // event_type, severity is LOW for the empty result).
        assert_eq!(
            line,
            header_prefix("client.disconnected", "client.disconnected", 3)
        );
        // Exactly seven pipes: after "CEF:0" the header has 7 field
        // separators (the leading one after the version prefix counts).
        assert_eq!(line.matches('|').count(), 7);
    }

    #[test]
    fn name_falls_back_to_event_type_when_unset() {
        let event = AuditEvent::new("federation.peer.connected", "connect", "success");
        let line = format_cef(&event);
        assert!(
            line.contains("|federation.peer.connected|federation.peer.connected|3|"),
            "name fallback missing: {line}"
        );
    }
}
