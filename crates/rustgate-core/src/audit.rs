// Copyright © 2026 Roberto Chiofalo.

//! Structured audit logging for security and compliance monitoring.
//!
//! Emits JSON-structured audit events via tracing at the `INFO` level
//! with a `target` of `"audit"`. This allows filtering audit events
//! from operational logs using tracing-subscriber layer filters.
//!
//! # Sanitization at the boundary
//!
//! Every audit-emission helper in this module sanitizes its
//! user-controlled `&str` parameters with [`crate::sanitize::sanitize_for_log`]
//! before the underlying `audit!` macro emits the structured tracing
//! record. This is a defense-in-depth posture: callers MAY still
//! sanitize on their side (the operation is idempotent — replaying it
//! over an already-sanitized string is a no-op), but they no longer
//! NEED to. A new caller that forgets cannot produce a forgeable audit
//! line, because the trust boundary lives inside this module.
//!
//! Sanitization replaces newlines, carriage returns, ANSI CSI escape
//! sequences, and other control characters with the Unicode replacement
//! character (`U+FFFD`). The output is a single Unicode codepoint per
//! replaced byte and round-trips cleanly through serde-json
//! serialization, so the audit-record wire format is unchanged for any
//! input that was already free of control characters — and for inputs
//! that contain control characters, the wire-format change is exactly
//! the intended log-forging mitigation.
//!
//! Numeric, boolean, and typed fields (e.g. [`crate::PeerId`],
//! [`std::net::SocketAddr`]) bypass sanitization because their `Display`
//! and `Debug` impls cannot produce attacker-controlled control bytes.

use std::net::SocketAddr;
use std::time::SystemTime;

use crate::PeerId;
use crate::sanitize::sanitize_for_log;

/// Emit an audit event via structured tracing.
///
/// All audit events share a common shape: timestamp, event type, actor,
/// action, result, and optional metadata. They are emitted at INFO level
/// with target `"audit"` so they can be routed to a separate log sink.
macro_rules! audit {
    ($event_type:expr, $($field:tt)*) => {
        tracing::info!(
            target: "audit",
            event_type = $event_type,
            $($field)*
        );
    };
}

/// Internal helper: sanitize a user-controlled string for safe inclusion
/// in an audit record. Thin wrapper over [`sanitize_for_log`] kept
/// inlined to make per-call-site intent explicit at the audit-emission
/// boundary — every `s(x)` site in this module is a "user-controlled
/// string crossing the audit trust boundary" annotation.
#[inline]
fn s(value: &str) -> String {
    sanitize_for_log(value)
}

/// Sanitize each entry of a borrowed string slice for inclusion in a
/// `?val`-formatted audit field. The returned `Vec<String>` is owned so
/// the caller can pass `?sanitized` to the audit macro without lifetime
/// gymnastics.
#[inline]
fn s_slice(values: &[String]) -> Vec<String> {
    values.iter().map(|v| sanitize_for_log(v)).collect()
}

/// Record a client connection event.
///
/// Sanitization: `cn` and `fingerprint` are sanitized at the audit
/// boundary; callers do not need to wrap them.
pub fn client_connected(cn: &str, peer: SocketAddr, fingerprint: &str, session_id: u64) {
    let cn = s(cn);
    let fingerprint = s(fingerprint);
    audit!(
        "client.connected",
        cn = %cn,
        peer = %peer,
        fingerprint = %fingerprint,
        session_id = session_id,
        action = "connect",
        result = "success"
    );
}

/// Record a client disconnection event.
///
/// Sanitization: `cn` is sanitized at the audit boundary.
pub fn client_disconnected(cn: &str, session_id: u64) {
    let cn = s(cn);
    audit!(
        "client.disconnected",
        cn = %cn,
        session_id = session_id,
        action = "disconnect",
        result = "success"
    );
}

/// Record a connection rejection (limit reached).
///
/// Sanitization: `reason` is sanitized at the audit boundary.
pub fn connection_rejected(peer: SocketAddr, reason: &str) {
    let reason = s(reason);
    audit!(
        "client.rejected",
        peer = %peer,
        action = "connect",
        result = "rejected",
        reason = %reason
    );
}

/// Record a TLS accept error.
///
/// Sanitization: `error` is sanitized at the audit boundary; the error
/// message may include attacker-supplied bytes from the certificate
/// subject or extension parsing.
pub fn tls_accept_error(peer: SocketAddr, error: &str) {
    let error = s(error);
    audit!(
        "client.tls_error",
        peer = %peer,
        action = "tls_handshake",
        result = "failure",
        error = %error
    );
}

/// Record a protocol negotiation outcome.
///
/// Sanitization: `cn` and `protocol` are sanitized at the audit boundary.
pub fn negotiation_result(cn: &str, protocol: &str, success: bool) {
    let cn = s(cn);
    let protocol = s(protocol);
    audit!(
        "client.negotiation",
        cn = %cn,
        protocol = %protocol,
        action = "negotiate",
        result = if success { "success" } else { "failure" }
    );
}

/// Record a federation peer connection event.
///
/// Sanitization: `peer_cn` and `direction` are sanitized at the audit
/// boundary. `peer_id` is a typed [`PeerId`] and bypasses sanitization.
pub fn federation_peer_connected(peer_id: &PeerId, peer_cn: &str, direction: &str) {
    let peer_cn = s(peer_cn);
    let direction = s(direction);
    audit!(
        "federation.connected",
        peer_id = %peer_id,
        peer_cn = %peer_cn,
        direction = %direction,
        action = "connect",
        result = "success"
    );
}

/// Record a federation peer disconnection event.
///
/// Sanitization: `reason` is sanitized at the audit boundary.
pub fn federation_peer_disconnected(peer_id: &PeerId, reason: &str) {
    let reason = s(reason);
    audit!(
        "federation.disconnected",
        peer_id = %peer_id,
        action = "disconnect",
        reason = %reason
    );
}

/// Record a federation circuit breaker trip.
///
/// `total_trips` is the cumulative lifetime trip count for this peer,
/// not the number of trips since the last recovery.
pub fn federation_circuit_tripped(peer_id: &PeerId, total_trips: u64) {
    audit!(
        "federation.circuit_tripped",
        peer_id = %peer_id,
        total_trips = total_trips,
        action = "circuit_breaker",
        result = "open"
    );
}

/// Record a federation circuit breaker recovery.
pub fn federation_circuit_recovered(peer_id: &PeerId) {
    audit!(
        "federation.circuit_recovered",
        peer_id = %peer_id,
        action = "circuit_breaker",
        result = "closed"
    );
}

/// Record a federation connection failure.
///
/// Sanitization: `error` is sanitized at the audit boundary; failure
/// strings often include peer-supplied data (TLS error chains, parsed
/// certificate subjects, etc.).
pub fn federation_connect_failed(peer_id: &PeerId, error: &str) {
    let error = s(error);
    audit!(
        "federation.connect_failed",
        peer_id = %peer_id,
        action = "connect",
        result = "failure",
        error = %error
    );
}

/// Record a federation peer rejection at the mTLS boundary when the
/// client certificate CN cannot be extracted.
///
/// Emitted when a federation RPC arrives without a parseable client
/// certificate CN — historically the server fell back to identifying
/// the peer by remote IP, which silently matched IP-keyed
/// `peer_groups` entries regardless of whether the TLS identity was
/// valid. Callers must reject the RPC after emitting this event; the
/// forensic trail links the refused remote address to the rejection
/// reason (missing cert, malformed DER, empty CN after sanitization).
///
/// Sanitization: both `remote_addr` and `reason` are sanitized at the
/// audit boundary.
pub fn federation_peer_rejected(remote_addr: &str, reason: &str) {
    let remote_addr = s(remote_addr);
    let reason = s(reason);
    audit!(
        "federation.peer_rejected",
        remote_addr = %remote_addr,
        reason = %reason,
        action = "reject",
        result = "failure"
    );
}

/// Record a rejection of wire-claimed federation group memberships.
///
/// Emitted when a federation peer forwards an event whose
/// `federate_groups` field claims origin-CN group memberships that the
/// receiving server does not independently verify. The receiving server
/// drops the wire-claimed groups and either (a) substitutes its own
/// locally-known groups for the origin CN or (b) assigns the empty set
/// (deny-by-default). See `FederationConfig::trust_peer_groups` for the
/// opt-in escape hatch.
///
/// A Byzantine peer with a valid mTLS client certificate can otherwise
/// forge arbitrary group memberships for any origin CN, effectively
/// elevating that origin's privileges across the federation boundary.
/// The audit event captures the peer CN (authenticated via mTLS),
/// the origin CN the peer claimed to speak for, and the claimed
/// group set — giving operators a forensic trail of peers attempting
/// to assert cross-origin group claims.
///
/// Sanitization: `peer_cn`, `origin_cn`, and every entry of
/// `claimed_groups` are sanitized at the audit boundary; an attacker
/// cannot inject newlines or CSI escapes into the audit record by
/// crafting a hostile group name on the wire.
pub fn federation_group_claim_rejected(peer_cn: &str, origin_cn: &str, claimed_groups: &[String]) {
    let peer_cn = s(peer_cn);
    let origin_cn = s(origin_cn);
    let claimed_groups_sanitized = s_slice(claimed_groups);
    audit!(
        "federation.group_claim_rejected",
        peer_cn = %peer_cn,
        origin_cn = %origin_cn,
        claimed_count = claimed_groups.len(),
        claimed_groups = ?claimed_groups_sanitized,
        action = "drop_claims",
        result = "success"
    );
}

/// Record receipt of a federated event delivered via a unary RPC.
///
/// Emitted by V2 federation RPC handlers (e.g. `SendOneEvent`) after an
/// inbound event has cleared mTLS peer-id extraction, hop-count
/// validation, and group-allowlist enforcement, and the event has been
/// dispatched to the local routing pipeline. The forensic trail lets
/// operators correlate ingress per peer with egress dispatch decisions
/// downstream.
///
/// `rpc` is the canonical RPC name (e.g. `"send_one_event"`); `peer_cn`
/// is the mTLS-authenticated peer CN. Field cardinality matches the
/// `rpc` label on the `rustgate_federation_messages_in_by_rpc_total`
/// counter so log/metric joins line up cleanly.
///
/// Sanitization: both `rpc` and `peer_cn` are sanitized at the audit
/// boundary.
pub fn federation_event_received(rpc: &str, peer_cn: &str) {
    let rpc = s(rpc);
    let peer_cn = s(peer_cn);
    audit!(
        "federation.event_received",
        rpc = %rpc,
        peer_cn = %peer_cn,
        action = "receive",
        result = "success"
    );
}

/// Record rejection of a federated event during unary RPC handling.
///
/// Emitted when a V2 federation RPC handler rejects an inbound event for
/// reasons that originate from the event payload itself rather than the
/// mTLS handshake — hop-count exceeded, hop-count negative, or the
/// peer's claimed groups not appearing in the configured allowlist.
/// Mismatches at the mTLS layer are captured by
/// [`federation_peer_rejected`]; this event covers the post-auth
/// pre-dispatch policy gate.
///
/// `rpc` is the canonical RPC name; `peer_cn` is the mTLS-authenticated
/// peer CN; `reason` is a short stable token (`"hop_limit"`,
/// `"unauthorized_group"`, `"peer_not_in_allowlist"`).
///
/// Sanitization: `rpc`, `peer_cn`, and `reason` are sanitized at the
/// audit boundary.
pub fn federation_event_rejected(rpc: &str, peer_cn: &str, reason: &str) {
    let rpc = s(rpc);
    let peer_cn = s(peer_cn);
    let reason = s(reason);
    audit!(
        "federation.event_rejected",
        rpc = %rpc,
        peer_cn = %peer_cn,
        reason = %reason,
        action = "receive",
        result = "rejected"
    );
}

/// Record an enrollment CSR signing event.
///
/// Sanitization: `username` and `client_uid` are sanitized at the audit
/// boundary.
pub fn enrollment_signed(username: &str, client_uid: &str) {
    let username = s(username);
    let client_uid = s(client_uid);
    audit!(
        "enrollment.signed",
        username = %username,
        client_uid = %client_uid,
        action = "sign_csr",
        result = "success"
    );
}

/// Record an enrollment CSR signing failure.
///
/// Sanitization: `username`, `client_uid`, and `error` are sanitized at
/// the audit boundary.
pub fn enrollment_sign_failed(username: &str, client_uid: &str, error: &str) {
    let username = s(username);
    let client_uid = s(client_uid);
    let error = s(error);
    audit!(
        "enrollment.sign_failed",
        username = %username,
        client_uid = %client_uid,
        action = "sign_csr",
        result = "failure",
        error = %error
    );
}

/// Record an enrollment authentication failure.
///
/// Sanitization: `peer` is sanitized at the audit boundary.
pub fn enrollment_auth_failed(peer: &str) {
    let peer = s(peer);
    audit!(
        "enrollment.auth_failed",
        peer = %peer,
        action = "authenticate",
        result = "failure"
    );
}

/// Record a federation API configuration change.
///
/// Sanitization: `actor` and `action` are sanitized at the audit
/// boundary.
// justification: staged for the federation config API (issue #778 follow-up)
// which lands in a separate PR; exporting it now lets callers wire the audit
// emission without a second round-trip through this crate when the feature
// flips on.
#[allow(dead_code)]
pub fn federation_config_changed(actor: &str, action: &str, peer_id: &PeerId) {
    let actor = s(actor);
    let action = s(action);
    audit!(
        "federation.config_changed",
        actor = %actor,
        peer_id = %peer_id,
        action = %action,
        result = "success"
    );
}

/// Record a CRL reload success.
///
/// Sanitization: `source` is sanitized at the audit boundary.
pub fn crl_reload_success(count: usize, source: &str) {
    let source = s(source);
    audit!(
        "crl.reloaded",
        count = count,
        source = %source,
        action = "reload",
        result = "success"
    );
}

/// Record a CRL reload failure.
///
/// Sanitization: `source` and `error` are sanitized at the audit
/// boundary.
pub fn crl_reload_failed(source: &str, error: &str) {
    let source = s(source);
    let error = s(error);
    audit!(
        "crl.reload_failed",
        source = %source,
        action = "reload",
        result = "failure",
        error = %error
    );
}

/// Record an enrollment certificate issued event.
///
/// Sanitization: `username`, `client_uid`, and `serial` are sanitized at
/// the audit boundary.
pub fn enrollment_certificate_issued(username: &str, client_uid: &str, serial: &str) {
    let username = s(username);
    let client_uid = s(client_uid);
    let serial = s(serial);
    audit!(
        "enrollment.certificate_issued",
        username = %username,
        client_uid = %client_uid,
        serial = %serial,
        action = "issue_certificate",
        result = "success"
    );
}

/// Record a certificate revocation event.
///
/// Sanitization: `serial`, `reason`, and `revoked_by` are sanitized at
/// the audit boundary.
pub fn enrollment_certificate_revoked(serial: &str, reason: &str, revoked_by: &str) {
    let serial = s(serial);
    let reason = s(reason);
    let revoked_by = s(revoked_by);
    audit!(
        "enrollment.certificate_revoked",
        serial = %serial,
        reason = %reason,
        revoked_by = %revoked_by,
        action = "revoke_certificate",
        result = "success"
    );
}

/// Record a rate limit triggered event.
///
/// Sanitization: `peer` and `endpoint` are sanitized at the audit
/// boundary.
pub fn rate_limit_triggered(peer: &str, endpoint: &str, limit: usize) {
    let peer = s(peer);
    let endpoint = s(endpoint);
    audit!(
        "security.rate_limited",
        peer = %peer,
        endpoint = %endpoint,
        limit = limit,
        action = "rate_limit",
        result = "rejected"
    );
}

/// Record a TLS handshake failure with detailed reason.
///
/// Sanitization: `peer`, `reason`, and `stage` are sanitized at the
/// audit boundary.
pub fn tls_handshake_failed(peer: &str, reason: &str, stage: &str) {
    let peer = s(peer);
    let reason = s(reason);
    let stage = s(stage);
    audit!(
        "tls.handshake_failed",
        peer = %peer,
        reason = %reason,
        stage = %stage,
        action = "tls_handshake",
        result = "failure"
    );
}

/// Record a successful server certificate rotation.
///
/// Sanitization: `cert_path` and `new_serial` are sanitized at the
/// audit boundary.
pub fn cert_rotation_success(cert_path: &str, new_serial: &str) {
    let cert_path = s(cert_path);
    let new_serial = s(new_serial);
    audit!(
        "cert.rotated",
        cert_path = %cert_path,
        new_serial = %new_serial,
        action = "rotate",
        result = "success"
    );
}

/// Record a failed server certificate rotation attempt.
///
/// Sanitization: `cert_path` and `error` are sanitized at the audit
/// boundary.
pub fn cert_rotation_failed(cert_path: &str, error: &str) {
    let cert_path = s(cert_path);
    let error = s(error);
    audit!(
        "cert.rotation_failed",
        cert_path = %cert_path,
        error = %error,
        action = "rotate",
        result = "failure"
    );
}

/// Record a successful SPIFFE X.509-SVID refresh from the Workload API.
///
/// Sanitization: `spiffe_id` and `trust_domain` are sanitized at the
/// audit boundary.
pub fn spiffe_svid_refresh_success(spiffe_id: &str, trust_domain: &str, expiry_unix: i64) {
    let spiffe_id = s(spiffe_id);
    let trust_domain = s(trust_domain);
    audit!(
        "spiffe.svid_refresh",
        spiffe_id = %spiffe_id,
        trust_domain = %trust_domain,
        expiry_unix = expiry_unix,
        action = "refresh",
        result = "success"
    );
}

/// Record a failed SPIFFE X.509-SVID refresh attempt.
///
/// Sanitization: `error` is sanitized at the audit boundary.
pub fn spiffe_svid_refresh_failure(error: &str) {
    let error = s(error);
    audit!(
        "spiffe.svid_refresh",
        error = %error,
        action = "refresh",
        result = "failure"
    );
}

/// Record an authz deny decision.
///
/// Emitted by the router's policy enforcement point whenever an installed
/// [`PolicyEngine`](https://docs.rs/rustgate-authz) returns a Deny verdict,
/// including when the default effect denies an unmatched request.
///
/// Sanitization: `subject_cn`, `subject_fingerprint`, `action`,
/// `resource_kind`, `resource_id`, `rule_id` (if present), and
/// `policy_id` are sanitized at the audit boundary.
// justification: seven args mirror the deny-record schema required by the
// compliance tooling downstream (subject CN + fingerprint, action, resource
// kind + id, optional rule id, policy id). A struct literal here would add
// construction noise to every call site in the router's hot PEP path without
// changing what ends up on the wire.
#[allow(clippy::too_many_arguments)]
pub fn authz_denied(
    subject_cn: &str,
    subject_fingerprint: &str,
    action: &str,
    resource_kind: &str,
    resource_id: &str,
    rule_id: Option<&str>,
    policy_id: &str,
) {
    let subject_cn = s(subject_cn);
    let subject_fingerprint = s(subject_fingerprint);
    let action = s(action);
    let resource_kind = s(resource_kind);
    let resource_id = s(resource_id);
    let rule_id = rule_id.map(s).unwrap_or_default();
    let policy_id = s(policy_id);
    audit!(
        "authz.denied",
        subject_cn = %subject_cn,
        subject_fingerprint = %subject_fingerprint,
        action = %action,
        resource_kind = %resource_kind,
        resource_id = %resource_id,
        rule_id = %rule_id,
        policy_id = %policy_id,
        result = "deny"
    );
}

/// Record delivery of a message carrying a `TagClassified` obligation.
///
/// Emitted once per recipient by the router's policy enforcement point
/// when the authz engine returns an allow decision whose obligation list
/// contains the `TagClassified` obligation
/// (see `rustgate_authz::Obligation`).
///
/// The event captures enough provenance to reconstruct which subject
/// sent which classified artefact to which recipient under which policy
/// rule — the downstream hash-chained audit log turns those records into
/// a tamper-evident delivery trail. This is the mechanism by which
/// `TagClassified` graduates from a policy hint to an operator-visible
/// compliance artefact without modifying the wire payload.
///
/// # Identity fields
///
/// Unlike `access`-targeted logs (which hash CNs for PII safety on
/// routine traffic), this audit event records the plaintext `subject_cn`
/// and `recipient_cn` **by design**. Classified-delivery audit is the
/// forensic trail that ties a specific user to a specific classified
/// artefact at a specific time —
/// the record is useless without clear-text identity attribution. This
/// asymmetry is intentional: the audit sink is expected to carry the same
/// or stricter access controls as the classified traffic itself, so a
/// reviewer who can already read the audit trail is already cleared for
/// the CNs it names.
///
/// # Operator requirements
///
/// Because this record contains plaintext CNs of recipients of
/// classified artefacts, operators MUST route the `"audit"` tracing
/// target to a sink whose access controls are at least as strict as the
/// classification of the traffic being tagged. The record also MUST NOT
/// be forwarded to general-purpose log aggregation (Loki, Elasticsearch,
/// CloudWatch, etc.) unless those systems are already cleared for the
/// same material. Concretely:
///
/// - Prefer a dedicated hash-chained audit file
///   ([`crate::audit_chain::HashChainWriter`]) on an encrypted
///   volume over a shared syslog/journald stream.
/// - If using a SIEM, confirm its ingest channel and retention store
///   both satisfy the handling caveat that applies to the classified
///   artefact. A `TagClassified` obligation on a SECRET broadcast
///   routed to an UNCLASSIFIED SIEM is a cross-domain leak of the
///   subject-recipient relationship even though the payload body itself
///   was `MaskPayload`-emptied.
/// - Never stream this record to stdout in an environment where the
///   container log driver forwards to an unaccredited collector.
///
/// The fingerprint field deliberately is NOT included: fingerprints are
/// low-cardinality identifiers that reappear across many benign audit
/// records; exposing them here would provide no additional forensic
/// value but would broaden the correlation surface in the event the
/// audit sink is compromised.
///
/// Sanitization: every `&str` parameter is sanitized at the audit
/// boundary. The plaintext-CN policy above governs disclosure
/// (audit-sink access controls) and is distinct from log-injection
/// hardening — both apply.
pub fn authz_classified_delivery(
    subject_cn: &str,
    recipient_cn: &str,
    action: &str,
    resource_kind: &str,
    resource_id: &str,
    rule_id: Option<&str>,
    policy_id: &str,
) {
    let subject_cn = s(subject_cn);
    let recipient_cn = s(recipient_cn);
    let action = s(action);
    let resource_kind = s(resource_kind);
    let resource_id = s(resource_id);
    let rule_id = rule_id.map(s).unwrap_or_default();
    let policy_id = s(policy_id);
    audit!(
        "authz.classified_delivery",
        subject_cn = %subject_cn,
        recipient_cn = %recipient_cn,
        action = %action,
        resource_kind = %resource_kind,
        resource_id = %resource_id,
        rule_id = %rule_id,
        policy_id = %policy_id,
        result = "tagged"
    );
}

// ── Obligation `reason` vocabulary (issue #775) ─────────────────────
//
// SIEM dashboards group authz-obligation failures on a stable `reason`
// token rather than on the underlying error's `Display` form. Building
// dashboards on `Display` is a footgun: `quick_xml::Error` (the
// `MaskError::Xml` source) renders payload-derived tag names, the
// prose drifts across releases, and a SIEM rule keyed on a sentence
// fragment quietly stops firing on the next dependency upgrade. The
// constants below pin the exact string each call-site emits so a
// rename is a deliberate breaking change rather than an accidental
// re-bucketing of every alerted-on event.
//
// Same shape as the `recovery` token vocabulary established by
// issue #742 (see [`MASK_RECOVERY_DROPPED`] et al). Keep new variants
// in sync with the table at the head of this section AND with the
// CHANGELOG entry for the issue that introduced them.

/// Stable `reason` token emitted by [`authz_obligation_failed`] when
/// `MaskPoint` is attached to a payload whose first non-whitespace byte
/// is not `<`. The CoT masker cannot apply to non-XML bytes; the
/// dispatcher passes the payload through unmodified and emits this
/// token alongside the [`MASK_RECOVERY_FORWARDED_BINARY`] /
/// [`MASK_RECOVERY_FORWARDED_UNMASKED`] / [`MASK_RECOVERY_FORWARDED_UNKNOWN`] /
/// [`MASK_RECOVERY_FORWARDED_PARTIAL`]
/// `recovery` token that further refines the bucket by `source_protocol`.
pub const OBLIGATION_REASON_MASK_POINT_NON_XML: &str = "mask_point_non_xml";

/// Stable `reason` token emitted by [`authz_obligation_failed`] when
/// `MaskPoint` is attached to an XML-intent payload that fails to parse
/// as XML (corresponds to `MaskError::Xml`, derived from
/// [`rustgate_cot::mask::MaskError::kind`] returning `"xml_parse_error"`).
/// The dispatcher fail-closes the payload — it is erased rather than
/// forwarded unmasked — so a crafted sender that aborts the document
/// after the `<point>` element was already copied to the writer cannot
/// leak coordinates via pass-through recovery.
///
/// [`rustgate_cot::mask::MaskError::kind`]: https://docs.rs/rustgate-cot
pub const OBLIGATION_REASON_MASK_POINT_XML_ERROR: &str = "mask_point_xml_error";

/// Stable `reason` token emitted by [`authz_obligation_failed`] when
/// the in-memory writer that hosts the masked output returns an I/O
/// error (corresponds to `MaskError::Io`, derived from
/// [`rustgate_cot::mask::MaskError::kind`] returning `"io_error"`). The
/// underlying writer is a `Vec<u8>`, so this path is unreachable under
/// normal operation; the token exists for forward-compat with future
/// streaming writers and for the parity between the `MaskError`
/// discriminants and the audit vocabulary.
///
/// [`rustgate_cot::mask::MaskError::kind`]: https://docs.rs/rustgate-cot
pub const OBLIGATION_REASON_MASK_POINT_IO_ERROR: &str = "mask_point_io_error";

/// Stable `reason` token emitted by [`authz_obligation_failed`] when a
/// `<point>` element exceeds [`rustgate_cot::mask::MAX_POINT_ATTRIBUTES`]
/// (corresponds to `MaskError::AttrBudgetExceeded`, derived from
/// [`rustgate_cot::mask::MaskError::kind`] returning
/// `"attr_budget_exceeded"`). The masker rejects the payload rather
/// than amplifying per-recipient masking cost on a broadcast; the
/// dispatcher fail-closes (payload erased, message type coerced).
///
/// [`rustgate_cot::mask::MaskError::kind`]: https://docs.rs/rustgate-cot
/// [`rustgate_cot::mask::MAX_POINT_ATTRIBUTES`]: https://docs.rs/rustgate-cot
pub const OBLIGATION_REASON_MASK_POINT_ATTR_BUDGET_EXCEEDED: &str =
    "mask_point_attr_budget_exceeded";

/// Stable `reason` token emitted by [`authz_obligation_unknown`] for
/// every encountered unknown obligation variant. The audit field is
/// constant rather than per-variant because the `obligation` field
/// already carries the `{:?}` rendering; the `reason` field exists so
/// SIEM rules can group all unknown-variant events under a single
/// alerting key independent of which specific variant fired.
pub const OBLIGATION_REASON_UNKNOWN_VARIANT: &str = "unknown_variant";

/// Stable `reason` token emitted by [`authz_obligation_failed`] when a
/// cross-domain inspection obligation (`StripPii`, `DegradePosition`,
/// `InjectMarking` — refs #857) lands on a payload whose first
/// non-whitespace byte is not `<`. The CDI helpers are best-effort CoT
/// controls; non-XML payloads pass through unmodified and SIEM
/// dashboards group the resulting forensic event under a single token
/// rather than on a per-obligation suffix.
pub const OBLIGATION_REASON_CDI_NON_XML: &str = "cdi_non_xml";

/// Stable `reason` token emitted by [`authz_obligation_failed`] when a
/// CDI obligation (refs #857) lands on an XML-intent payload that the
/// masker cannot parse. The dispatcher fail-closes the payload — same
/// security posture as `OBLIGATION_REASON_MASK_POINT_XML_ERROR` — so a
/// crafted sender that aborts a document mid-parse cannot leak
/// pre-redaction bytes via pass-through recovery.
pub const OBLIGATION_REASON_CDI_XML_ERROR: &str = "cdi_xml_error";

/// Map a [`rustgate_cot::mask::MaskError::kind`] discriminant to the
/// corresponding `reason` token used by [`authz_obligation_failed`].
///
/// `MaskError::kind()` returns one of three `&'static str` discriminants
/// (`"xml_parse_error"`, `"io_error"`, `"attr_budget_exceeded"`); this
/// helper performs the static `kind ⇒ reason` mapping at the
/// audit-emission boundary so callers do not need to hard-code the
/// translation. An unrecognised discriminant — possible only if a
/// future `MaskError` variant lands without a companion update here —
/// falls back to [`OBLIGATION_REASON_MASK_POINT_XML_ERROR`] (the
/// highest-severity bucket) so a stale build cannot accidentally drop
/// to a non-XML token and under-report the failure class.
///
/// [`rustgate_cot::mask::MaskError::kind`]: https://docs.rs/rustgate-cot
pub fn obligation_reason_for_mask_error_kind(kind: &str) -> &'static str {
    match kind {
        "xml_parse_error" => OBLIGATION_REASON_MASK_POINT_XML_ERROR,
        "io_error" => OBLIGATION_REASON_MASK_POINT_IO_ERROR,
        "attr_budget_exceeded" => OBLIGATION_REASON_MASK_POINT_ATTR_BUDGET_EXCEEDED,
        // Future MaskError variant — fail to the highest-severity
        // bucket rather than introducing a silent third token.
        _ => OBLIGATION_REASON_MASK_POINT_XML_ERROR,
    }
}

/// Stable `recovery` token emitted by [`authz_obligation_failed`] for
/// `MaskPoint` on a payload whose `source_protocol` is in the known-binary
/// list (e.g. MAVLink, TAK protobuf, ASTERIX). The masker is a CoT-XML
/// control; binary framings cannot host a `<point>` element, so
/// pass-through is correct by design and an analyst grepping the audit
/// trail for "MaskPoint was bypassed" should be able to distinguish this
/// from a parser-level bypass.
pub const MASK_RECOVERY_FORWARDED_BINARY: &str = "forwarded_binary";

/// Stable `recovery` token emitted by [`authz_obligation_failed`] for
/// `MaskPoint` on a payload whose `source_protocol` claims XML/CoT but
/// the parser failed (or the first non-whitespace byte is not `<`).
/// "We tried but couldn't parse XML" — position MAY be in the bytes and
/// the masker bypassed inspection. This is the higher-severity bucket
/// for SIEM alerting.
pub const MASK_RECOVERY_FORWARDED_UNMASKED: &str = "forwarded_unmasked";

/// Stable `recovery` token emitted by [`authz_obligation_failed`] for
/// `MaskPoint` on a payload whose `source_protocol` is not in the
/// recognised set. Operator visibility for misconfigured upstreams that
/// stamp arbitrary identifiers on `Metadata::source_protocol` — the
/// router cannot tell whether the bytes might host a position field
/// without reparsing, so it falls into a separate forensic bucket from
/// the known-binary and known-XML cases.
pub const MASK_RECOVERY_FORWARDED_UNKNOWN: &str = "forwarded_unknown";

/// Stable `recovery` token emitted by [`authz_obligation_failed`] when
/// the dispatcher fail-closed an XML-intent payload that tripped the
/// masker (parse error or attribute-budget exceeded) — the payload was
/// erased rather than forwarded unmasked.
pub const MASK_RECOVERY_DROPPED: &str = "dropped";

/// Stable `recovery` token emitted alongside a successful masking
/// emission whose configured `MaskDetailLevel` is more permissive than
/// the strictest available level — i.e. the masker stripped the
/// `<point>` (and possibly `<contact callsign>` / `<__group>` /
/// `<takv>` / custom lat/lon-named attributes) at the operator-selected
/// detail level, but lower-tier secondary position-bearing fields were
/// deliberately retained.
///
/// Refs #882 (point masking detail leakage). The token exists so SIEM
/// dashboards can see that a `MaskPoint`-equivalent obligation was
/// applied AND distinguish "Coarse" emissions from "Strict" emissions
/// without re-deriving the level from per-payload introspection. An
/// operator running a Medium- or Strict-level deployment that observes
/// a `forwarded_partial` token confirms the masker is firing at the
/// configured tier; the absence of the token under a Medium/Strict
/// configuration is the load-bearing signal that the level is not
/// being honoured on the data plane.
///
/// Coarse (default) emissions do NOT carry this token because the
/// pre-#882 vocabulary did not surface a "mask succeeded" audit event
/// at all — Coarse-level masking is the legacy behaviour and stays
/// silent on the audit channel to avoid flipping the dashboard
/// cardinality on an upgrade where the operator did not opt into a
/// stricter level.
pub const MASK_RECOVERY_FORWARDED_PARTIAL: &str = "forwarded_partial";

/// Bucket the `source_protocol` field of an inbound `RoutableMessage`
/// into the recovery-token vocabulary used by [`authz_obligation_failed`]
/// for the `MaskPoint` non-XML-intent path.
///
/// Returns one of:
///
/// - [`MASK_RECOVERY_FORWARDED_BINARY`] when `source_protocol` is a
///   known binary framing (`mavlink`, `tak-protobuf`, `tak_protobuf`,
///   `asterix`). The hyphenated and underscored TAK protobuf spellings
///   are both accepted because [`crate::codec::Codec::protocol_id`]
///   returns `"tak-protobuf"` while older call-sites and config keys
///   spelled it `"tak_protobuf"`.
/// - [`MASK_RECOVERY_FORWARDED_UNMASKED`] when `source_protocol` claims
///   XML or CoT (`cot`, `xml`) but the payload could not be parsed
///   (matching the pre-issue-#742 behaviour).
/// - [`MASK_RECOVERY_FORWARDED_UNKNOWN`] for anything else — a
///   misconfigured upstream, a transport whose identifier this build
///   does not recognise, or the empty string.
///
/// Match is ASCII case-insensitive: an upstream that uppercases or
/// title-cases the protocol identifier still bucketed correctly.
pub fn classify_mask_recovery_for(source_protocol: &str) -> &'static str {
    let known_binary = ["mavlink", "tak-protobuf", "tak_protobuf", "asterix"];
    if known_binary
        .iter()
        .any(|k| source_protocol.eq_ignore_ascii_case(k))
    {
        return MASK_RECOVERY_FORWARDED_BINARY;
    }
    let known_xml = ["cot", "xml"];
    if known_xml
        .iter()
        .any(|k| source_protocol.eq_ignore_ascii_case(k))
    {
        return MASK_RECOVERY_FORWARDED_UNMASKED;
    }
    MASK_RECOVERY_FORWARDED_UNKNOWN
}

/// Record a failure to actuate an authz obligation.
///
/// Emitted by the router's obligation dispatcher when an obligation with
/// data-plane side effects cannot be applied (for example, `MaskPoint` on
/// a payload that parses as XML but trips the masker's attribute budget,
/// or returns a parse error partway through). The dispatcher chooses the
/// caller-appropriate recovery (fail-closed for XML-intent payloads,
/// pass-through for non-XML) but always emits this record so operators
/// can see the policy hint was not honoured.
///
/// `obligation` is the unqualified variant name (e.g. `"MaskPoint"`).
///
/// `reason` is the SIEM-grouping token drawn from the documented
/// vocabulary at the head of the obligation-reason section:
///
/// - [`OBLIGATION_REASON_MASK_POINT_NON_XML`] (`"mask_point_non_xml"`)
///   — payload's first non-whitespace byte is not `<` so the masker
///   cannot apply.
/// - [`OBLIGATION_REASON_MASK_POINT_XML_ERROR`] (`"mask_point_xml_error"`)
///   — XML-intent payload trips `quick_xml`'s parser; fail-closed.
/// - [`OBLIGATION_REASON_MASK_POINT_IO_ERROR`] (`"mask_point_io_error"`)
///   — writer I/O error during masking; reserved for forward-compat.
/// - [`OBLIGATION_REASON_MASK_POINT_ATTR_BUDGET_EXCEEDED`]
///   (`"mask_point_attr_budget_exceeded"`) — `<point>` exceeded the
///   attribute count budget; fail-closed.
///
/// Issue #775 introduced this static-label discipline so SIEM
/// dashboards group on a stable token rather than the underlying
/// error's `Display` form (which can echo payload-derived tag names
/// from `quick_xml::Error` and drift across releases). Use
/// [`obligation_reason_for_mask_error_kind`] at the call site to
/// translate a [`rustgate_cot::mask::MaskError::kind`] discriminant
/// into the matching `reason` token.
///
/// `recovery` is one of the four stable tokens that further refine the
/// failure bucket — orthogonal to `reason`, since two emissions can
/// share a `reason` while differing on `recovery`:
///
/// - [`MASK_RECOVERY_DROPPED`] (`"dropped"`) — XML-intent payload was
///   erased after a parse failure; fail-closed.
/// - [`MASK_RECOVERY_FORWARDED_BINARY`] (`"forwarded_binary"`) —
///   `source_protocol` is a known binary framing (MAVLink, TAK
///   protobuf, ASTERIX); position masking is N/A by design.
/// - [`MASK_RECOVERY_FORWARDED_UNMASKED`] (`"forwarded_unmasked"`) —
///   `source_protocol` claims XML/CoT but parsing failed; the payload
///   MAY have contained a position the masker missed.
/// - [`MASK_RECOVERY_FORWARDED_UNKNOWN`] (`"forwarded_unknown"`) —
///   `source_protocol` is not in the recognised set; operator
///   visibility for misconfigured upstreams.
/// - [`MASK_RECOVERY_FORWARDED_PARTIAL`] (`"forwarded_partial"`) —
///   masking applied at an operator-configured `MaskDetailLevel` more
///   permissive than the strictest available level (refs #882). The
///   `<point>` was zeroed and any secondary position-bearing fields
///   covered by the configured level were redacted, but lower-tier
///   fields (e.g. `<takv>` under `Medium`) were deliberately retained
///   per operator threat model.
///
/// SIEM rules grep for these literal tokens — changing the strings
/// without coordinating with the deployed dashboard set is a breaking
/// change. Use [`classify_mask_recovery_for`] to bucket a given
/// `source_protocol` into the binary / unmasked / unknown trio for the
/// non-XML pass-through path.
///
/// `destination_kind` is a stable tag produced by
/// [`crate::message::Destination::kind_str`] so SIEM rules can
/// distinguish a failure on a unicast direct send from one on a
/// fan-out broadcast without inspecting the payload.
///
/// `policy_id` is the stable identifier of the authz engine that produced
/// the obligation (closes #772). SIEM correlation across rolling policy
/// reloads needs this for forensic clarity: a `MaskPoint` failure under
/// policy `vN` looks identical on the wire to one under `vN+1`, but the
/// remediation may differ when the policy file itself was the regression.
/// Empty-string call sites (callers without engine context) render the
/// field as the empty string — same convention as
/// [`authz_reload_rollback`]'s absent-`previous_policy_id` path.
///
/// Sanitization: every `&str` parameter is sanitized at the audit
/// boundary. In production the `reason` and `recovery` fields are
/// always drawn from the documented constant vocabularies, so the
/// sanitization step is a no-op for those — but it keeps the audit
/// boundary uniform and protects against a future caller that forgets
/// the constraint.
///
/// [`rustgate_cot::mask::MaskError::kind`]: https://docs.rs/rustgate-cot
// justification: seven args mirror the obligation-failed schema required
// by SIEM correlation tooling (subject CN, obligation, reason, recovery,
// source_protocol, destination_kind, policy_id). Bundling into a struct
// would add construction noise to every call site in the obligation hot
// path without changing what ends up on the wire.
#[allow(clippy::too_many_arguments)]
pub fn authz_obligation_failed(
    subject_cn: &str,
    obligation: &str,
    reason: &str,
    recovery: &str,
    source_protocol: &str,
    destination_kind: &str,
    policy_id: &str,
) {
    let subject_cn = s(subject_cn);
    let obligation = s(obligation);
    let reason = s(reason);
    let recovery = s(recovery);
    let source_protocol = s(source_protocol);
    let destination_kind = s(destination_kind);
    let policy_id = s(policy_id);
    audit!(
        "authz.obligation_failed",
        subject_cn = %subject_cn,
        obligation = %obligation,
        reason = %reason,
        recovery = %recovery,
        source_protocol = %source_protocol,
        destination_kind = %destination_kind,
        policy_id = %policy_id,
        action = "actuate_obligation",
        result = "failure"
    );
}

/// Record encountering an unknown [`Obligation`] variant at the PEP.
///
/// `rustgate_authz::Obligation` is `#[non_exhaustive]` — a future authz
/// upgrade may add variants before the transport crate catches up. The
/// dispatcher forwards messages unmodified in that case (no silent drop)
/// but emits this audit event so operators running a stale build against
/// a newer authz engine can detect the skew. The event fires at most
/// once per (obligation, subject) tuple per router instance in practice
/// because unknown variants can only appear if the policy mentions them.
///
/// The structured audit record carries a stable `reason` field set to
/// [`OBLIGATION_REASON_UNKNOWN_VARIANT`]. The token is constant rather
/// than per-variant because the `obligation` field already carries the
/// `{:?}` rendering of the variant; the `reason` field exists so SIEM
/// rules can group every unknown-variant event under a single alerting
/// key independent of which specific variant fired (issue #775).
///
/// `destination_kind` mirrors the field on
/// [`authz_obligation_failed`] so a SIEM can pivot between the two
/// events without custom mapping.
///
/// `policy_id` is the stable identifier of the authz engine that returned
/// the unknown variant (closes #772). SIEM correlation across rolling
/// policy reloads pins which engine version introduced the unrecognised
/// obligation — the audit-flood guard added in #769 already keys its
/// per-`(policy_id, variant)` rate limiter on this same identifier, so
/// surfacing it on the audit emission lets operators correlate the
/// suppressed-emission rate (via the `rustgate_authz_obligation_unknown_total`
/// counter) with the specific policy version that introduced the skew.
/// Empty-string call sites (callers without engine context) render the
/// field as the empty string — same convention as
/// [`authz_obligation_failed`].
///
/// Sanitization: every `&str` parameter is sanitized at the audit
/// boundary.
///
/// [`Obligation`]: https://docs.rs/rustgate-authz
pub fn authz_obligation_unknown(
    subject_cn: &str,
    obligation: &str,
    source_protocol: &str,
    destination_kind: &str,
    policy_id: &str,
) {
    let subject_cn = s(subject_cn);
    let obligation = s(obligation);
    let source_protocol = s(source_protocol);
    let destination_kind = s(destination_kind);
    let policy_id = s(policy_id);
    // `reason` is fixed: every `authz.obligation_unknown` emission
    // surfaces the same unknown-variant case — the `obligation` field
    // already differentiates which specific variant fired. Pinning the
    // token here keeps the SIEM grouping key out of the call site, so
    // a regression that forgot to pass it cannot silently change the
    // dashboard bucket.
    audit!(
        "authz.obligation_unknown",
        subject_cn = %subject_cn,
        obligation = %obligation,
        reason = OBLIGATION_REASON_UNKNOWN_VARIANT,
        source_protocol = %source_protocol,
        destination_kind = %destination_kind,
        policy_id = %policy_id,
        action = "actuate_obligation",
        result = "skipped"
    );
}

/// Record a successful authz policy reload.
///
/// Sanitization: `path` and `policy_id` are sanitized at the audit
/// boundary.
pub fn authz_reload_success(path: &str, policy_id: &str, rule_count: usize) {
    let path = s(path);
    let policy_id = s(policy_id);
    audit!(
        "authz.reload_success",
        path = %path,
        policy_id = %policy_id,
        rule_count = rule_count,
        action = "reload",
        result = "success"
    );
}

/// Record a failed authz policy reload. `stage` identifies which phase
/// failed: `"read"`, `"parse"`, `"compile"`, or `"startup"`.
///
/// Sanitization: `path`, `stage`, and `error` are sanitized at the
/// audit boundary.
pub fn authz_reload_failed(path: &str, stage: &str, error: &str) {
    let path = s(path);
    let stage = s(stage);
    let error = s(error);
    audit!(
        "authz.reload_failed",
        path = %path,
        stage = %stage,
        error = %error,
        action = "reload",
        result = "failure"
    );
}

/// Record that a failed config hot-reload rolled back to the previously
/// installed policy.
///
/// Emitted alongside [`authz_reload_failed`] (and the equivalent reload-
/// failure helpers for other subsystems) at every call site where the
/// new on-disk policy was rejected during validate/parse/compile and the
/// in-memory engine therefore stays at its previous version. Pre-this-
/// event, operators only learned about the rollback by correlating
/// tracing logs; the explicit rollback record now gives SIEMs a single
/// structured event to alert on.
///
/// `reason` is a short operator-facing description ("parse error",
/// "rule cap exceeded", "task panicked", etc.) and is paired with the
/// failure reason already carried by the preceding `*_reload_failed`
/// emission. `previous_policy_id` is the id of the policy that remains
/// in effect — operators page on a rollback they did not initiate, and
/// the stable policy id lets them confirm which policy version is still
/// serving traffic without scraping the next reload-success event.
///
/// Sanitization: `reason` and the optional `previous_policy_id` are
/// sanitized at the audit boundary; callers do not need to wrap them.
///
/// The `previous_policy_id` field is rendered as the empty string when
/// no previous policy was installed (e.g. the very first reload after
/// startup failed), matching the convention adopted by
/// [`authz_classified_delivery`] and [`authz_denied`] for absent rule
/// identifiers.
pub fn authz_reload_rollback(reason: &str, previous_policy_id: Option<&str>) {
    let reason = s(reason);
    let previous_policy_id = previous_policy_id.map(s).unwrap_or_default();
    audit!(
        "authz.reload_rollback",
        reason = %reason,
        previous_policy_id = %previous_policy_id,
        action = "rollback",
        result = "success"
    );
}

/// Record a hash-chained audit-log discontinuity detected at startup.
///
/// Emitted when the persisted anchor tip in `<audit_path>.anchor` does not
/// match the live tip recovered from the audit log itself. `action` values:
///
/// - `"refuse_start"` — the server refused to start because
///   `--audit-allow-chain-break` was not set.
/// - `"continue"` — the operator explicitly opted in via
///   `--audit-allow-chain-break`; the new chain extends from `live_tip`
///   but the break is recorded for forensics.
///
/// The first record written after a `"continue"` decision is the only audit
/// entry where the anchor tip is *known* to disagree with the audit log's
/// chain state, so SIEM rules that alert on this event should also check
/// for the anchor-update record that follows on the next clean shutdown.
///
/// Sanitization: every `&str` parameter is sanitized at the audit
/// boundary.
pub fn chain_discontinuity(
    audit_path: &str,
    anchor_tip: &str,
    live_tip: &str,
    action: &str,
    reason: &str,
) {
    let audit_path = s(audit_path);
    let anchor_tip = s(anchor_tip);
    let live_tip = s(live_tip);
    let action = s(action);
    let reason = s(reason);
    audit!(
        "audit.chain_discontinuity",
        audit_path = %audit_path,
        anchor_tip = %anchor_tip,
        live_tip = %live_tip,
        reason = %reason,
        action = %action,
        result = "detected"
    );
}

/// Record that the audit-chain anchor was persisted at graceful shutdown.
///
/// Surfaces every clean shutdown through the audit trail so a missing record
/// between restarts is itself a signal worth investigating — a crash or kill
/// produces no anchor_persisted entry, whereas a clean shutdown produces
/// exactly one.
///
/// Sanitization: `audit_path` and `tip` are sanitized at the audit
/// boundary.
pub fn chain_anchor_persisted(audit_path: &str, tip: &str) {
    let audit_path = s(audit_path);
    let tip = s(tip);
    audit!(
        "audit.chain_anchor_persisted",
        audit_path = %audit_path,
        tip = %tip,
        action = "persist_anchor",
        result = "success"
    );
}

/// Record that persisting the audit-chain anchor at shutdown failed.
///
/// The error text is emitted verbatim so operators can distinguish disk-full,
/// permission-denied, and read-only-filesystem failures without chasing the
/// correlated ERROR-level tracing record. On the next startup a missing
/// anchor presents as [`ChainContinuity::NoAnchor`] which is benign, so the
/// audit chain itself is not broken by this failure — but the operator
/// loses the tamper-detection signal for the window it took to retry.
///
/// Sanitization: `audit_path` and `error` are sanitized at the audit
/// boundary. Control characters and CSI escapes in OS error messages
/// (e.g. a path with embedded newlines) are neutralised; the body of the
/// rendered error otherwise passes through verbatim.
///
/// [`ChainContinuity::NoAnchor`]: crate::audit_chain::ChainContinuity::NoAnchor
pub fn chain_anchor_persist_failed(audit_path: &str, error: &str) {
    let audit_path = s(audit_path);
    let error = s(error);
    audit!(
        "audit.chain_anchor_persist_failed",
        audit_path = %audit_path,
        error = %error,
        action = "persist_anchor",
        result = "failure"
    );
}

/// Record server startup.
///
/// Sanitization: `bind` and `version` are sanitized at the audit
/// boundary.
pub fn server_started(bind: &str, version: &str) {
    let bind = s(bind);
    let version = s(version);
    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    audit!(
        "server.started",
        bind = %bind,
        version = %version,
        timestamp = timestamp,
        action = "start",
        result = "success"
    );
}

// ── Egress envelope obligation events ──────────────────────────────

/// Record one data-plane obligation actuation that was applied while
/// rendering the post-Send-PEP envelope used for an egress fan-out
/// (NATS, federation, HTTP, MQTT, multicast egress copy).
///
/// Fires once per `(envelope, obligation)` pair — i.e. an envelope
/// rendered from a multicast whose union carries `MaskPoint` and
/// `TagClassified` produces two events for that single envelope, not
/// one per recipient. Closes the per-recipient obligation duplication
/// gap that #746 calls out: today's local-fanout path runs the masking
/// path N times for an N-recipient multicast; the egress path renders
/// it exactly once and the audit cadence reflects that.
///
/// `sink` is the sink class label (`"multicast"`, `"nats"`,
/// `"federation"`, `"http"`, `"mqtt"`, `"local"`); `obligation_type`
/// is the small fixed-vocabulary obligation label
/// (`"mask_point"`, `"mask_payload"`, `"tag_classified"`,
/// `"audit_extended"`, plus the cross-domain inspection labels from
/// refs #857 — `"strip_pii"`, `"degrade_position"`, `"inject_marking"`
/// — and the catch-all `"unknown"`); `recipient_class` is a
/// human-readable rendering of the `RecipientClass` variant
/// (e.g. `"multicast:[alpha,bravo]"`, `"nats:my.subject"`).
///
/// Sanitization: every `&str` parameter is sanitized at the audit
/// boundary so a maliciously-crafted group name or NATS subject cannot
/// forge surrounding fields.
pub fn egress_obligation_applied(sink: &str, obligation_type: &str, recipient_class: &str) {
    let sink = s(sink);
    let obligation_type = s(obligation_type);
    let recipient_class = s(recipient_class);
    audit!(
        "egress.obligation.applied",
        sink = %sink,
        obligation_type = %obligation_type,
        recipient_class = %recipient_class,
        action = "apply_obligation",
        result = "success"
    );
}

// ── HTTP egress audit events ───────────────────────────────────────

/// Record an HTTP publish failure for a target.
///
/// Sanitization: `target` and `error` are sanitized at the audit
/// boundary; `error` may include remote-server response bytes.
pub fn http_publish_failed(target: &str, status: u16, error: &str) {
    let target = s(target);
    let error = s(error);
    audit!(
        "http.publish_failed",
        target = %target,
        status = status,
        error = %error,
        action = "publish",
        result = "failure"
    );
}

/// Record a circuit breaker tripping for an HTTP target.
///
/// Sanitization: `target` is sanitized at the audit boundary.
pub fn http_circuit_tripped(target: &str) {
    let target = s(target);
    audit!(
        "http.circuit_tripped",
        target = %target,
        action = "circuit_breaker",
        result = "tripped"
    );
}

/// Record a circuit breaker recovering for an HTTP target.
///
/// Sanitization: `target` is sanitized at the audit boundary.
pub fn http_circuit_recovered(target: &str) {
    let target = s(target);
    audit!(
        "http.circuit_recovered",
        target = %target,
        action = "circuit_breaker",
        result = "recovered"
    );
}

/// Record a circuit breaker entering the Half-Open probe window.
///
/// Fires at the moment the breaker transitions from Open to Half-Open
/// — cooldown has elapsed and the next request will be released as a
/// probe. This is the trigger point for DLQ auto-drain: any messages
/// dead-lettered while the circuit was open are now eligible for
/// replay once the probe succeeds.
///
/// Sanitization: `target` is sanitized at the audit boundary.
pub fn http_circuit_probing(target: &str) {
    let target = s(target);
    audit!(
        "http.circuit_probing",
        target = %target,
        action = "circuit_breaker",
        result = "probing"
    );
}

/// Record a failed TLS verifier rebuild after trust store change.
///
/// Sanitization: `error` is sanitized at the audit boundary.
pub fn verifier_rebuild_failed(error: &str) {
    let error = s(error);
    audit!(
        "verifier.rebuild_failed",
        error = %error,
        action = "rebuild_verifier",
        result = "failed"
    );
}

/// Record a store-forward message drop due to writer channel overflow.
///
/// Sanitization: `cn` and `reason` are sanitized at the audit boundary.
pub fn store_forward_dropped(cn: &str, reason: &str) {
    let cn = s(cn);
    let reason = s(reason);
    audit!(
        "store_forward.dropped",
        cn = %cn,
        reason = %reason,
        action = "enqueue",
        result = "dropped"
    );
}

/// Record an explicit operator-initiated wipe of the store-forward queue
/// on startup. `depth` is the count of queue entries discarded by the
/// wipe. Emitted once per `ClientQueue::open_with_wipe` invocation — the
/// counterpart to the fail-closed behavior that refuses to start when
/// stored entries exist without a persistent HMAC key. This event
/// provides the audit trail the store-forward contract requires when
/// previously-queued messages are deliberately dropped rather than
/// delivered.
///
/// Sanitization: `path` and `reason` are sanitized at the audit
/// boundary.
pub fn store_forward_key_rotated(path: &str, depth: u64, reason: &str) {
    let path = s(path);
    let reason = s(reason);
    audit!(
        "store_forward.key_rotated",
        path = %path,
        depth = depth,
        reason = %reason,
        action = "wipe_queue",
        result = "rotated"
    );
}

/// Record a panic or cancellation of the `spawn_blocking` task that drains
/// a client's offline store-forward queue on reconnect. `session_hash` is
/// the PII-safe `hash_cn` of the client identity. The join error is
/// logged as free-form text because `JoinError` does not carry structured
/// fields beyond panic/cancel classification.
///
/// Emitted in addition to an operator-facing `warn!` so SIEMs receive a
/// durable signal that a specific client's queued messages were silently
/// dropped — a panicking redb backend would otherwise surface only in
/// ephemeral logs.
///
/// Sanitization: `session_hash` and `error` are sanitized at the audit
/// boundary.
pub fn store_forward_drain_panic(session_hash: &str, error: &str) {
    let session_hash = s(session_hash);
    let error = s(error);
    audit!(
        "store_forward.drain_panic",
        session = %session_hash,
        error = %error,
        action = "drain_queue",
        result = "panic"
    );
}

/// Record a successful store-forward drain of one or more messages on
/// client reconnect. Issue #729 — the dwell-time observability event.
///
/// `cn` is the destination (reconnecting) client's CN. `count` is the
/// number of messages successfully decoded and returned to the router
/// for re-delivery. `dwell_seconds_*` summarize how long those messages
/// sat in the offline queue, computed as `drain_time - queued_at_ms`
/// where `queued_at_ms` is the timestamp captured at admission (NOT
/// `received_at_ms`, which would conflate live-routing time with
/// queue-resident time on messages that rode multiple transports
/// before falling back to store-forward). `expired_count` and
/// `tampered_count` cover entries discarded during the same drain so
/// the audit record reflects the full work the drain performed.
///
/// Emitted in addition to the per-message dwell observation fed into
/// the `rustgate_store_forward_dwell_seconds` Prometheus histogram —
/// the histogram supports operator dashboards (P50/P95/P99 trends),
/// while the audit event supports SIEM correlation against a specific
/// reconnect.
///
/// Sanitization: `cn` is sanitized at the audit boundary.
pub fn store_forward_drained(
    cn: &str,
    count: u64,
    dwell_seconds_mean: f64,
    dwell_seconds_min: f64,
    dwell_seconds_max: f64,
    expired_count: u64,
    tampered_count: u64,
) {
    let cn = s(cn);
    audit!(
        "store_forward.drained",
        cn = %cn,
        count = count,
        dwell_seconds_mean = dwell_seconds_mean,
        dwell_seconds_min = dwell_seconds_min,
        dwell_seconds_max = dwell_seconds_max,
        expired_count = expired_count,
        tampered_count = tampered_count,
        action = "drain_queue",
        result = "delivered"
    );
}

/// Record a position-replay request that was shed by the per-CN replay
/// rate limiter (issue #724). `session_hash` is the PII-safe
/// [`crate::masking::hash_cn`] rendering of the reconnecting client's
/// CN. `attempted` is the number of cached positions that would have
/// been considered for replay had the request been admitted; `allowed`
/// is the number actually replayed (zero when the bucket was empty,
/// non-zero when a partial replay was permitted before exhaustion).
///
/// Emitted on the deny path of `Router::replay_positions` so a SIEM can
/// see clients that are flap-looping and driving the authz engine via
/// uncapped reconnect-driven re-evaluation. The bucket key is the CN —
/// per-CN isolation means one noisy client cannot starve replay for
/// others.
pub fn position_replay_rate_limited(session_hash: &str, attempted: u32, allowed: u32) {
    audit!(
        "position_replay.rate_limited",
        session = %session_hash,
        attempted = attempted,
        allowed = allowed,
        action = "rate_limit",
        result = "shed"
    );
}

/// Record a message being shed by per-target rate limiting.
///
/// Sanitization: `target` and `source_cn` are sanitized at the audit
/// boundary.
pub fn http_rate_limited(target: &str, source_cn: &str) {
    let target = s(target);
    let source_cn = s(source_cn);
    audit!(
        "http.rate_limited",
        target = %target,
        source_cn = %source_cn,
        action = "rate_limit",
        result = "shed"
    );
}

/// Record a dead-letter queue write failure.
///
/// Sanitization: `target` and `error` are sanitized at the audit
/// boundary.
pub fn http_dlq_failed(target: &str, error: &str) {
    let target = s(target);
    let error = s(error);
    audit!(
        "http.dlq_failed",
        target = %target,
        error = %error,
        action = "dead_letter",
        result = "failure"
    );
}

/// Record the start of an auto-drain pass after a target's circuit
/// recovered. `segment_count` is the number of sealed DLQ segments the
/// worker is about to replay — zero is a legal value (no backlog).
/// Paired with [`http_dlq_drain_completed`] once the worker finishes
/// walking every segment; the two events bracket the drain window so
/// operators can see elapsed time and per-segment success rate in the
/// SIEM trail. `#881`.
///
/// Sanitization: `target` is sanitized at the audit boundary.
pub fn http_dlq_drain_started(target: &str, segment_count: usize) {
    let target = s(target);
    audit!(
        "http.dlq_drain_started",
        target = %target,
        segments = segment_count,
        action = "dlq_drain",
        result = "started"
    );
}

/// Record completion of an auto-drain pass. `replayed` is the number
/// of entries that reached the target with a 2xx status; `failed` is
/// the number that either re-entered the DLQ (re-persisted under a
/// fresh segment) or were silently dropped as malformed. `#881`.
///
/// `replayed + failed` is the total entry count read from the drained
/// segments, so operators can reconcile this against the per-entry
/// `rustgate_http_dlq_replayed_total{result}` counter rate without
/// depending on a subtraction.
///
/// Sanitization: `target` is sanitized at the audit boundary.
pub fn http_dlq_drain_completed(target: &str, replayed: u64, failed: u64) {
    let target = s(target);
    audit!(
        "http.dlq_drain_completed",
        target = %target,
        replayed = replayed,
        failed = failed,
        action = "dlq_drain",
        result = "completed"
    );
}

// ── MAVLink framing audit events ────────────────────────────────────

/// Record a MAVLink v2 frame rejected because its `INCOMPAT & SIGNED`
/// bit was clear on a codec configured to require signatures.
///
/// Emitted by the session layer that drives the MAVLink frame codec in
/// `rustgate-mavlink` (arriving in a follow-up PR with the listener).
/// Operators route this event to their SIEM to detect firmware
/// downgrade attempts and misconfigured fleet members that skipped the
/// signing rollout.
///
/// Kept as a plain-text reference rather than a rustdoc intra-doc link
/// because `rustgate-core` deliberately does not depend on
/// `rustgate-mavlink` (the dependency direction is the other way).
///
/// `peer` is the socket address of the link that produced the frame;
/// omit or pass `"unknown"` when the transport cannot supply one
/// (e.g. a UDP datagram whose source we deliberately ignore).
///
/// Sanitization: `peer` is sanitized at the audit boundary.
pub fn mavlink_unsigned_rejected(peer: &str) {
    let peer = s(peer);
    audit!(
        "mavlink.unsigned_rejected",
        peer = %peer,
        action = "frame_decode",
        result = "rejected",
        reason = "unsigned_v2"
    );
}

/// Record a MAVLink v1 frame rejected because the codec was configured
/// to disallow the pre-signing wire format.
///
/// Paired with [`mavlink_unsigned_rejected`] so a SIEM can distinguish
/// "sender failed to sign v2" from "sender is speaking the unsigned
/// legacy protocol" — the operational responses differ (firmware fix
/// vs. dataplane opt-in). Both events fire at most once per frame, not
/// once per packet, so a hostile link cannot amplify them into a log
/// DoS: rejection discards the magic byte and the session layer will
/// close the link after a small number of errors.
///
/// Sanitization: `peer` is sanitized at the audit boundary.
pub fn mavlink_v1_rejected(peer: &str) {
    let peer = s(peer);
    audit!(
        "mavlink.v1_rejected",
        peer = %peer,
        action = "frame_decode",
        result = "rejected",
        reason = "v1_not_allowed"
    );
}

/// Record a MAVLink HEARTBEAT (`MSG_ID = 0`) frame received and decoded
/// at the framing layer.
///
/// Emitted by the MAVLink frame decoder in `rustgate-mavlink` whenever a
/// v1 or v2 frame is recognised as a HEARTBEAT and its payload is large
/// enough to surface the autopilot/vehicle-type fields. A typical drone
/// fleet emits HEARTBEATs at 1 Hz, so this event is the wire-level
/// presence ping a SIEM can correlate against "aircraft fell off the
/// network" higher-level signals — distinguishing a real network
/// partition from a payload outage where the aircraft is silent at the
/// MAVLink layer despite a healthy TCP/UDP link.
///
/// `system_id` and `component_id` come from the v1/v2 header (offset 3
/// and 4 in v1, offset 5 and 6 in v2). `autopilot` and `vehicle_type`
/// come from the HEARTBEAT payload (offsets 5 and 4 respectively, after
/// MAVLink's field-size-descending wire reordering — `custom_mode` is
/// the leading u32). The autopilot enum surfaces ArduPilot vs PX4 vs
/// Vector vs other vendors at SIEM correlation time without having to
/// keep a dialect parser online.
///
/// Kept as a plain-text reference rather than a rustdoc intra-doc link
/// because `rustgate-core` deliberately does not depend on
/// `rustgate-mavlink` (the dependency direction is the other way).
pub fn mavlink_heartbeat_received(
    system_id: u8,
    component_id: u8,
    autopilot: u8,
    vehicle_type: u8,
) {
    audit!(
        "mavlink.heartbeat_received",
        system_id = system_id,
        component_id = component_id,
        autopilot = autopilot,
        vehicle_type = vehicle_type,
        action = "frame_decode",
        result = "received"
    );
}

/// Record an MQTT will message published on behalf of a disconnecting
/// client whose connection ended ungracefully (TLS error, keep-alive
/// timeout, write-loop early exit, abrupt TCP close — anything that is
/// NOT a clean DISCONNECT). Fires AFTER the `Will { topic, group }`
/// payload has been routed via `Router::route_for_egress`, regardless
/// of whether the router accepted or dropped the message — the audit
/// records the broker's decision to fire the will, not the eventual
/// delivery outcome.
///
/// Wired by `publish_will_message` in `rustgate_mqtt` so a SIEM can
/// correlate ungraceful disconnects with the will-publish that
/// followed them. The pairing matters operationally because a will
/// publish can carry presence-loss semantics (a tactical client
/// dropping off the network) that downstream subscribers act on; the
/// SIEM trail records exactly when the broker took that action and on
/// which group, regardless of who eventually saw the message.
///
/// `cn` is the disconnecting client's CN (hashed via `hash_cn` at the
/// call site for PII safety).
///
/// Sanitization: `cn`, `topic`, and `group` are sanitized at the audit
/// boundary; the call site MAY pre-sanitize but is no longer required
/// to. The pre-existing call-site `sanitize_for_log` invocations remain
/// safe because [`sanitize_for_log`] is idempotent — running it twice
/// produces the same string as running it once.
pub fn mqtt_will_published(cn: &str, topic: &str, group: &str, retain: bool) {
    let cn = s(cn);
    let topic = s(topic);
    let group = s(group);
    audit!(
        "mqtt.will_published",
        cn = %cn,
        topic = %topic,
        group = %group,
        retain = retain,
        action = "will_publish",
        result = "fired"
    );
}

/// Record that a NATS-bridged message was dispatched to the poison-message
/// dead-letter queue (DLQ).
///
/// Emitted by `rustgate_nats::NatsSubscriber` whenever a JetStream message
/// fires one of the four local-drop paths (`oversized`, `unparseable`,
/// `unknown-position`, `invalid-identity`) that would otherwise let the
/// pull consumer redeliver the same poison payload indefinitely. The
/// audit fires regardless of whether the optional DLQ subject is wired
/// — the security record is the audit trail; the DLQ subject is the
/// forensic-payload sink.
///
/// `subject` is the original live-stream subject the poison message
/// arrived on (e.g. `"points.ALPHA"`). `msg_id` is the JetStream stream
/// sequence rendered as a decimal string when available, or the literal
/// `"unknown"` when `msg.info()` failed (the audit must still fire so
/// SIEM alerting on `nats.poison_dlq` is not gated by JetStream
/// availability). `reason` is the short slug from the four drop paths.
/// `attempts` is the JetStream delivery attempt count for this stream
/// sequence — the value of `info.delivered` at the moment the
/// subscriber gave up. A persistently-failing message reaches this
/// emission once per attempt, so SIEM rules can rate-limit on the
/// `(subject, msg_id)` pair if the alerting source is the audit log
/// rather than the DLQ subject itself.
///
/// **Sub-item 3 of #883.** Closes the poison-message redelivery gap
/// called out in the issue: pre-this-event the subscriber silently
/// ACKed the four drop paths with no audit record, so a SIEM operator
/// had no way to distinguish "consumer is healthy" from "consumer is
/// burning a poison message every redelivery interval". The new event
/// gives operators a structured signal that survives even when the
/// optional DLQ subject is unset.
///
/// Sanitization: every `&str` field crosses the audit boundary via
/// [`sanitize_for_log`] so an attacker who can publish to the live
/// stream cannot forge a log line through the original subject or a
/// downstream-controlled reason slug. `attempts` is a numeric field
/// and bypasses sanitization.
pub fn nats_poison_message_dlq(subject: &str, msg_id: &str, reason: &str, attempts: u32) {
    let subject = s(subject);
    let msg_id = s(msg_id);
    let reason = s(reason);
    audit!(
        "nats.poison_dlq",
        subject = %subject,
        msg_id = %msg_id,
        reason = %reason,
        attempts = attempts,
        action = "dead_letter",
        result = "moved"
    );
}

/// Record that an encrypted-archive [`crate::encrypted::KeyRing`] was loaded
/// with an active key whose configured `not_after` is within the rotation
/// window — the operator must rotate before the key expires or new-write
/// admission will fail closed.
///
/// Emitted once per `KeyRing::from_bytes` call when the active key has a
/// `key_expirations` entry whose remaining time is `<= 14 days`. Because
/// every server start (and SIGHUP-driven hot reload, where applicable)
/// re-emits the event, dashboards and SIEM rules see a steady reminder
/// until the operator rotates — analogous to the `cert_rotation_*` family
/// for mTLS certificates.
///
/// Rationale for emitting at load rather than on first use: encrypted
/// archives are typically opened lazily (the audit log archive is opened
/// on the first chain-write, the store-and-forward queue on the first
/// drained message). A load-time emission gives operators a deterministic
/// signal at startup that they will need to rotate, even before any
/// archive write happens.
///
/// `kid` is the active key id; `days_remaining` is `(not_after - now) /
/// 86_400`, rounded down. A key whose `not_after` is already in the past
/// is reported with `days_remaining = 0` — but in that case the actual
/// admission gate ([`crate::encrypted::KeyRing::active_key_expired_at`])
/// will refuse new writes with [`crate::encrypted::EncryptError::ActiveKeyExpired`]
/// regardless of whether anyone listens for this audit event.
///
/// Sanitization: `kid` is sanitized at the audit boundary.
pub fn archive_key_rotation_due(kid: &str, days_remaining: i64) {
    let kid = s(kid);
    audit!(
        "archive.key_rotation_due",
        kid = %kid,
        days_remaining = days_remaining,
        action = "rotate_key",
        result = "due"
    );
}

// ── Admin / lifecycle audit events ──────────────────────────────────

/// Record an operator-initiated graceful drain.
///
/// Emitted by the management API when `POST /api/drain` fires the
/// shared shutdown `Notify`, and reserved for any future surface
/// (e.g. a SIGUSR2 handler) that triggers the same drain path. The
/// `source` field discriminates the origin so SIEM and dashboards can
/// attribute API-initiated drains separately from SIGTERM-initiated
/// ones — pre-this-event the only signal was the SubsystemHandle log
/// line, which collapsed both surfaces into one indistinguishable
/// stream during a Kubernetes rolling upgrade.
///
/// `source` is a short token like `"api"` for the management endpoint
/// or `"signal"` for a SIGTERM-equivalent path; SIEM rules key on this
/// to gate alerting (an unexpected `"api"` drain at 03:00 is suspicious
/// in a way a `"signal"` drain during a planned canary rollout is not).
///
/// Sanitization: `source` is sanitized at the audit boundary. Closes
/// `#791`.
pub fn admin_drain_triggered(source: &str) {
    let source = s(source);
    audit!(
        "admin.drain_triggered",
        source = %source,
        action = "drain",
        result = "initiated"
    );
}

/// Record a successful management REST API access.
///
/// Emitted by the `/api/v1/*` read endpoints (refs #902) once
/// authentication succeeds and the response payload is computed.
/// `endpoint` is the operator-facing path (`"/api/v1/crl"`,
/// `"/api/v1/dedup/stats"`); `identity` is the caller's authenticated
/// principal — currently the literal `"bearer"` because the metrics
/// HTTP server fronting the management API uses bearer-token auth, not
/// mTLS, so there is no client CN to record. The field is retained as a
/// parameter so a future mTLS-fronted variant can populate it without a
/// breaking change to the audit shape.
///
/// Fires only on the success path; bearer-token failures are accounted
/// in the standard 401 response and do NOT emit this event (callers
/// can distinguish "operator hit the endpoint" from "someone tried to
/// brute-force it" by absence-vs-presence in the audit trail).
///
/// Sanitization: both `endpoint` and `identity` are sanitized at the
/// audit boundary via [`sanitize_for_log`]. Refs #902.
pub fn mgmt_api_accessed(endpoint: &str, identity: &str) {
    let endpoint = s(endpoint);
    let identity = s(identity);
    audit!(
        "mgmt.api_accessed",
        endpoint = %endpoint,
        identity = %identity,
        action = "access",
        result = "success"
    );
}

/// Record an operator-driven force-disconnect of an active client.
///
/// Emitted when `POST /api/v1/clients/{cn}/disconnect` (refs #902) closes
/// one or more session writer channels for the targeted CN. `cn` is the
/// disconnect target (echoed from the URL path), `by_operator` identifies
/// the principal who issued the API call (currently the literal
/// `"bearer"` because the metrics HTTP server fronting the management
/// API uses bearer-token auth, not mTLS, so there is no caller CN to
/// record), and `sessions_closed` is the number of session handles whose
/// outbound channels were signalled to drain. The event fires regardless
/// of `sessions_closed` value — a `0` count is a normal, not-exceptional
/// state for this endpoint and is part of the forensic trail (operator
/// scripted a batch disconnect with stale CN list).
///
/// Pairs with [`client_disconnected`] for full lifecycle coverage: the
/// session task itself emits `client.disconnected` on its exit path
/// (driven by the writer-channel drop forced here), so a SIEM can join
/// the operator action with the eventual session teardown via the `cn`
/// field.
///
/// Sanitization: `cn` and `by_operator` are sanitized at the audit
/// boundary via [`sanitize_for_log`]. Refs #902.
pub fn client_force_disconnected(cn: &str, by_operator: &str, sessions_closed: u64) {
    let cn = s(cn);
    let by_operator = s(by_operator);
    audit!(
        "client.force_disconnected",
        cn = %cn,
        by_operator = %by_operator,
        sessions_closed = sessions_closed,
        action = "force_disconnect",
        result = "success"
    );
}

// ── JWKS refresh lifecycle (refs #952) ──────────────────────────────

/// Record a successful JWKS refresh from a remote endpoint.
///
/// Emitted by the federation JWKS client after every successful HTTP
/// fetch of `<url>/.well-known/jwks.json` (or the operator-configured
/// path) where the response parses cleanly into a key set. `key_count`
/// is the number of asymmetric public keys advertised in the response
/// after filtering — HS256 entries that the client refused to load
/// because `allow_hs256: false` are NOT counted, by design.
///
/// Pairs with [`jwks_refresh_failed`] for full lifecycle coverage of
/// the refresh loop. SIEM rules can alert on a sustained absence of
/// `jwks.refresh_success` events for a given URL even when the failure
/// stream is silent (network partition).
///
/// Sanitization: `url` is sanitized at the audit boundary.
pub fn jwks_refresh_success(url: &str, key_count: usize) {
    let url = s(url);
    audit!(
        "jwks.refresh_success",
        url = %url,
        key_count = key_count,
        action = "refresh",
        result = "success"
    );
}

/// Record a failed JWKS refresh from a remote endpoint.
///
/// Emitted by the federation JWKS client when an HTTP fetch fails
/// (network error, DNS failure, TLS handshake error), the server returns
/// a non-2xx status, or the response body cannot be parsed as a JWKS
/// document. The cached keyset is preserved on failure (fail-closed
/// posture per #952), so `jwks.refresh_failed` is a degradation signal
/// rather than an availability one — verifiers continue to validate
/// tokens against the last good snapshot.
///
/// Sanitization: `url` and `reason` are sanitized at the audit
/// boundary.
pub fn jwks_refresh_failed(url: &str, reason: &str) {
    let url = s(url);
    let reason = s(reason);
    audit!(
        "jwks.refresh_failed",
        url = %url,
        reason = %reason,
        action = "refresh",
        result = "failure"
    );
}

/// Record a key being added to the active JWKS verifier registry.
///
/// Emitted once per `kid` newly observed in a JWKS response and
/// successfully registered with the `JwtAuthority` verifier set.
/// The companion [`jwks_key_removed`] event fires when a previously
/// registered `kid` disappears from the JWKS response and is dropped
/// from the verifier set.
///
/// `alg` is the JOSE algorithm string (`"ES256"`, `"EdDSA"`, or
/// `"HS256"` when `allow_hs256: true`).
///
/// Sanitization: `url`, `kid`, and `alg` are sanitized at the audit
/// boundary.
pub fn jwks_key_added(url: &str, kid: &str, alg: &str) {
    let url = s(url);
    let kid = s(kid);
    let alg = s(alg);
    audit!(
        "jwks.key_added",
        url = %url,
        kid = %kid,
        alg = %alg,
        action = "add_key",
        result = "success"
    );
}

/// Record a key being removed from the active JWKS verifier registry.
///
/// Emitted when a previously registered `kid` is no longer advertised
/// in the JWKS response and the federation JWKS client removes it from
/// the verifier set. After removal, JWTs carrying this `kid` will
/// fail verification with `JwtError::UnknownKid`.
///
/// Removal is gated on the JWKS response itself being valid — a 5xx
/// or network failure does NOT trigger key removal (fail-closed
/// posture per #952), so this event always corresponds to an
/// authoritative absence in the upstream key server.
///
/// Sanitization: `url` and `kid` are sanitized at the audit boundary.
pub fn jwks_key_removed(url: &str, kid: &str) {
    let url = s(url);
    let kid = s(kid);
    audit!(
        "jwks.key_removed",
        url = %url,
        kid = %kid,
        action = "remove_key",
        result = "success"
    );
}

/// Record a per-recipient delivery confirmation for chain-of-custody
/// audit trails (closes #854).
///
/// Emitted by the router after every successful per-recipient
/// `try_send` when the operator has explicitly opted in via the
/// `--audit-delivery` CLI flag. The event is high-volume in busy
/// deployments — a single broadcast to N subscribers produces N
/// records — so the wiring is gated and disabled by default.
///
/// `source_cn` is the sending client's CN; `dest_cn` is the recipient's
/// CN (raw, not hashed: per #1207 / #1221, audit fields use raw CNs for
/// forensic chain-of-custody, while access logs use `hash_cn` for
/// cardinality-bounded operational logs). `msg_uid` is the CoT
/// `uid="..."` attribute scraped from the payload; pass an empty string
/// when the payload is not CoT-shaped or no uid is present. `msg_type`
/// is the `Display` form of [`crate::message::MessageType`] (e.g.
/// `"position"`, `"chat"`, `"alert"`). `group` is the destination group
/// name on group / multicast fan-out, or a small fixed-vocabulary tag
/// (`"direct"`, `"broadcast"`) for non-group destinations so SIEM
/// correlation queries do not have to special-case the absent-group
/// shape.
///
/// Sanitization: every `&str` field is sanitized at the audit boundary
/// per the workspace audit-boundary discipline (#1197 / #1220). Callers
/// MAY still wrap on their side — `sanitize_for_log` is idempotent —
/// but they no longer NEED to.
pub fn message_delivered(
    source_cn: &str,
    dest_cn: &str,
    msg_uid: &str,
    msg_type: &str,
    group: &str,
) {
    let source_cn = s(source_cn);
    let dest_cn = s(dest_cn);
    let msg_uid = s(msg_uid);
    let msg_type = s(msg_type);
    let group = s(group);
    audit!(
        "message.delivered",
        source = %source_cn,
        dest = %dest_cn,
        uid = %msg_uid,
        msg_type = %msg_type,
        group = %group,
        action = "deliver",
        result = "success"
    );
}

/// Record a per-recipient delivery drop for chain-of-custody audit
/// trails (closes #854).
///
/// Emitted by the router after a per-recipient `try_send` fails (channel
/// full, channel closed, or no live session and no store-and-forward
/// queue) when the operator has explicitly opted in via the
/// `--audit-delivery` CLI flag. The companion to [`message_delivered`]:
/// SIEM correlation across the two events answers "did every classified
/// message intended for recipient X land on the wire, and if not, why?"
///
/// `reason` is one of the small fixed-vocabulary labels the router's
/// `OnDropped` callback already uses — `"backpressure"` (channel full
/// or closed), `"no_subscribers"` (recipient is offline and no
/// store-forward queue is configured), `"acl_denied"`, `"authz_denied"`,
/// `"obligation_failed"` — so dashboards and audit queries share a
/// vocabulary.
///
/// Sanitization: every `&str` field is sanitized at the audit boundary
/// per the workspace audit-boundary discipline (#1197 / #1220).
pub fn message_dropped(source_cn: &str, dest_cn: &str, msg_uid: &str, reason: &str) {
    let source_cn = s(source_cn);
    let dest_cn = s(dest_cn);
    let msg_uid = s(msg_uid);
    let reason = s(reason);
    audit!(
        "message.dropped",
        source = %source_cn,
        dest = %dest_cn,
        uid = %msg_uid,
        reason = %reason,
        action = "deliver",
        result = "dropped"
    );
}

/// Record that the UDP-multicast input listener joined a group.
///
/// Emitted by `rustgate_transport::udp_multicast` once per configured
/// `(group, port)` after `tokio::net::UdpSocket::join_multicast_v4`
/// succeeds. Operators can grep for this event to confirm the server is
/// participating in tactical-mesh SA traffic, and a SIEM rule can flag
/// an absence of the event at startup as a misconfiguration (the join
/// can fail silently if the kernel refuses the request — e.g. when the
/// configured interface lacks an IPv4 address). Closes #861.
///
/// `group` is the dotted-quad multicast address with port (e.g.
/// `"239.2.3.1:6969"`); `interface` is the bind interface as configured
/// by `--udp-multicast-interface` or the literal `"0.0.0.0"` for
/// "all interfaces". Both `&str` arguments are sanitized at the audit
/// boundary so an operator-supplied interface name cannot forge a log
/// line via embedded control characters.
pub fn udp_multicast_joined(group: &str, interface: &str) {
    let group = s(group);
    let interface = s(interface);
    audit!(
        "udp_multicast.joined",
        group = %group,
        interface = %interface,
        action = "join",
        result = "success"
    );
}

/// Record that a routed CoT message was re-published to the configured
/// UDP multicast group.
///
/// Emitted by `rustgate_transport::udp_multicast` once per outbound
/// datagram on the optional rebroadcast path
/// (`--udp-multicast-rebroadcast`). The audit gives operators a
/// per-message trail of egress decisions distinct from the inbound-
/// listener's `udp_multicast.joined` and from the per-message access
/// log: SIEM rules monitoring exfil over multicast can correlate the
/// `msg_uid` against the upstream `client.connected` event. Closes
/// #861.
///
/// `group` is the dotted-quad multicast address with port; `msg_uid`
/// is the CoT `uid="…"` attribute extracted from the payload (or empty
/// for non-CoT shaped payloads, which the rebroadcast path does not
/// emit but the field is sanitized anyway for defense in depth). Both
/// fields cross the audit boundary via [`sanitize_for_log`].
pub fn udp_multicast_publish(group: &str, msg_uid: &str) {
    let group = s(group);
    let msg_uid = s(msg_uid);
    audit!(
        "udp_multicast.publish",
        group = %group,
        uid = %msg_uid,
        action = "publish",
        result = "success"
    );
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::*;

    fn v4_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 12345)
    }

    fn v6_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 9443)
    }

    #[test]
    fn test_client_connected() {
        client_connected("alpha-cn", v4_addr(), "sha256:abc123def456", 1);
        client_connected("", v6_addr(), "", 42);
        client_connected("cn/with-special.chars", v4_addr(), &"f".repeat(128), 0);
    }

    #[test]
    fn test_client_disconnected() {
        client_disconnected("alpha-cn", 1);
        client_disconnected("", 42);
    }

    #[test]
    fn test_connection_rejected() {
        connection_rejected(v4_addr(), "connection limit reached");
        connection_rejected(v6_addr(), "");
    }

    #[test]
    fn test_tls_accept_error() {
        tls_accept_error(v4_addr(), "handshake timeout");
        tls_accept_error(v6_addr(), "certificate expired");
    }

    #[test]
    fn test_negotiation_success() {
        negotiation_result("bravo-cn", "protobuf", true);
    }

    #[test]
    fn test_negotiation_failure() {
        negotiation_result("bravo-cn", "xml", false);
        negotiation_result("", "unknown", false);
    }

    mod federation {
        use super::*;

        #[test]
        fn test_peer_connected() {
            federation_peer_connected(&PeerId::new("peer-1"), "peer-cn", "inbound");
            federation_peer_connected(&PeerId::new("peer-2"), "remote-server", "outbound");
        }

        #[test]
        fn test_peer_disconnected() {
            federation_peer_disconnected(&PeerId::new("peer-1"), "clean shutdown");
            federation_peer_disconnected(&PeerId::new("peer-1"), "");
        }

        #[test]
        fn test_connect_failed() {
            federation_connect_failed(&PeerId::new("peer-1"), "connection refused");
            federation_connect_failed(&PeerId::new("peer-2"), "tls: certificate verify failed");
        }

        #[test]
        fn test_circuit_tripped() {
            federation_circuit_tripped(&PeerId::new("peer-1"), 1);
            federation_circuit_tripped(&PeerId::new("peer-2"), 5);
        }

        #[test]
        fn test_circuit_recovered() {
            federation_circuit_recovered(&PeerId::new("peer-1"));
            federation_circuit_recovered(&PeerId::new("peer-2"));
        }

        #[test]
        fn test_config_changed() {
            federation_config_changed("api", "create", &PeerId::new("peer-1"));
            federation_config_changed("admin", "delete", &PeerId::new("peer-2"));
            federation_config_changed("api", "update", &PeerId::new("peer-3"));
        }
    }

    mod enrollment {
        use super::*;

        #[test]
        fn test_signed() {
            enrollment_signed("admin", "client-uid-123");
            enrollment_signed("user@example.com", "");
        }

        #[test]
        fn test_sign_failed() {
            enrollment_sign_failed("admin", "client-uid-123", "invalid CSR");
            enrollment_sign_failed("", "", "CA not initialized");
        }

        #[test]
        fn test_auth_failed() {
            enrollment_auth_failed("10.0.0.1:12345");
            enrollment_auth_failed("[::1]:443");
        }
    }

    #[test]
    fn test_server_started() {
        server_started("0.0.0.0:4433", "0.1.0");
        server_started("[::]:4433", "0.0.0");
    }

    mod crl {
        use super::*;

        #[test]
        fn test_reload_success() {
            crl_reload_success(3, "/etc/rustgate/crls/revoked.pem");
            crl_reload_success(0, "");
        }

        #[test]
        fn test_reload_failed() {
            crl_reload_failed("/etc/rustgate/crls/revoked.pem", "file not found");
            crl_reload_failed("", "permission denied");
        }
    }

    mod authz_reload_rollback_helper {
        use super::*;

        #[test]
        fn test_authz_reload_rollback() {
            // Smoke: every supported call shape (with and without a
            // previous_policy_id) must render through the audit macro
            // without panicking, mirroring the discipline applied to the
            // sibling `authz_reload_failed` and `authz_reload_success`
            // helpers.
            authz_reload_rollback("parse error", Some("policy-2026-04-25-1"));
            authz_reload_rollback("rule cap exceeded", Some("policy-prev"));
            authz_reload_rollback("read error: file not found", None);
            authz_reload_rollback("", None);
        }
    }

    mod certificate_issued {
        use super::*;

        #[test]
        fn test_enrollment_certificate_issued() {
            enrollment_certificate_issued("admin", "client-uid-123", "A1B2...Y3Z4");
            enrollment_certificate_issued("user@example.com", "", "");
        }
    }

    mod rate_limit {
        use super::*;

        #[test]
        fn test_rate_limit_triggered() {
            rate_limit_triggered("10.0.0.***", "/Marti/api/tls/signClient", 10);
            rate_limit_triggered("[::1]:443", "/api/endpoint", 100);
        }

        #[test]
        fn test_position_replay_rate_limited() {
            // Smoke: a fully-shed replay (zero allowed) and a partial replay
            // (some tokens were available before exhaustion) must both render
            // through the audit macro without panicking. Issue #724.
            position_replay_rate_limited("deadbeefcafe1234", 256, 0);
            position_replay_rate_limited("aabbccddeeff0011", 1024, 17);
        }
    }

    mod tls_handshake {
        use super::*;

        #[test]
        fn test_tls_handshake_failed() {
            tls_handshake_failed("10.0.0.***:4433", "certificate expired", "verification");
            tls_handshake_failed("192.168.1.***:9443", "timeout", "negotiation");
            tls_handshake_failed("[::1]:443", "unknown CA", "chain_validation");
        }
    }

    mod authz {
        use super::*;

        #[test]
        fn test_authz_classified_delivery() {
            authz_classified_delivery(
                "alice",
                "bob",
                "send",
                "group",
                "team-alpha",
                Some("rule-classified-1"),
                "policy-v1",
            );
            // No rule_id path: the audit helper must tolerate an absent
            // rule identifier (e.g. default-effect allow).
            authz_classified_delivery(
                "alice",
                "bob",
                "receive",
                "direct",
                "bob",
                None,
                "policy-v1",
            );
        }

        #[test]
        fn test_authz_obligation_failed() {
            authz_obligation_failed(
                "alice",
                "MaskPoint",
                OBLIGATION_REASON_MASK_POINT_ATTR_BUDGET_EXCEEDED,
                "dropped",
                "tcp",
                "broadcast",
                "policy-v1",
            );
            authz_obligation_failed(
                "alice",
                "MaskPoint",
                OBLIGATION_REASON_MASK_POINT_NON_XML,
                "forwarded_unmasked",
                "mqtt",
                "direct",
                "policy-v1",
            );
            // Empty `policy_id` is allowed for callers without engine
            // context — closes #772 path-of-least-resistance regression
            // pin so a refactor that introduces a new emission site
            // without engine context cannot silently break the audit
            // boundary's sanitization invariant.
            authz_obligation_failed(
                "alice",
                "MaskPoint",
                OBLIGATION_REASON_MASK_POINT_NON_XML,
                "forwarded_unmasked",
                "mqtt",
                "direct",
                "",
            );
        }

        #[test]
        fn test_authz_obligation_unknown() {
            authz_obligation_unknown("alice", "Quarantine", "tcp", "group", "policy-v1");
            // Empty-everything emission must not panic — this is the
            // pre-#769-rate-limiter "no engine context" callpath that
            // shipped before issue #769; keep covering it.
            authz_obligation_unknown("", "", "", "", "");
        }

        // Issue #775: SIEM dashboards group on the literal `reason`
        // tokens. Pin the strings AND the `MaskError::kind` ⇒ reason
        // mapping so a future refactor cannot silently re-bucket an
        // alerted-on event. Same shape as the
        // [`mask_recovery_tokens_are_stable_strings`] regression guard
        // for the `recovery` vocabulary.
        #[test]
        fn obligation_reason_tokens_are_stable_strings() {
            assert_eq!(OBLIGATION_REASON_MASK_POINT_NON_XML, "mask_point_non_xml");
            assert_eq!(
                OBLIGATION_REASON_MASK_POINT_XML_ERROR,
                "mask_point_xml_error"
            );
            assert_eq!(OBLIGATION_REASON_MASK_POINT_IO_ERROR, "mask_point_io_error");
            assert_eq!(
                OBLIGATION_REASON_MASK_POINT_ATTR_BUDGET_EXCEEDED,
                "mask_point_attr_budget_exceeded"
            );
            assert_eq!(OBLIGATION_REASON_UNKNOWN_VARIANT, "unknown_variant");
        }

        #[test]
        fn obligation_reason_for_mask_error_kind_maps_known_discriminants() {
            // `MaskError::kind()` returns one of three `&'static str`
            // discriminants. Each must round-trip through the helper
            // to the matching `reason` token; a regression that
            // forgot a variant would either fall through to the
            // fallback bucket (asserted in the next test) or — worse
            // — return the wrong token.
            assert_eq!(
                obligation_reason_for_mask_error_kind("xml_parse_error"),
                OBLIGATION_REASON_MASK_POINT_XML_ERROR
            );
            assert_eq!(
                obligation_reason_for_mask_error_kind("io_error"),
                OBLIGATION_REASON_MASK_POINT_IO_ERROR
            );
            assert_eq!(
                obligation_reason_for_mask_error_kind("attr_budget_exceeded"),
                OBLIGATION_REASON_MASK_POINT_ATTR_BUDGET_EXCEEDED
            );
        }

        #[test]
        fn obligation_reason_for_mask_error_kind_falls_back_to_xml_error() {
            // A future `MaskError` variant whose `kind()` discriminant
            // lands here without a companion update to the helper must
            // bucket into the highest-severity token, not silently
            // produce a third unknown reason. Operators are then alerted
            // on the unfamiliar emission via existing `mask_point_xml_error`
            // dashboards rather than missing the event entirely.
            assert_eq!(
                obligation_reason_for_mask_error_kind("future_variant"),
                OBLIGATION_REASON_MASK_POINT_XML_ERROR
            );
            assert_eq!(
                obligation_reason_for_mask_error_kind(""),
                OBLIGATION_REASON_MASK_POINT_XML_ERROR
            );
        }

        // The `recovery` token vocabulary emitted by
        // [`authz_obligation_failed`] for the `MaskPoint` non-XML-intent
        // path is contractual — SIEM dashboards filter on the literal
        // strings, so any rename is a breaking change. Pin the strings
        // and the bucket-decision rules here so a future refactor
        // cannot silently regress one of the three forensic cases.
        #[test]
        fn mask_recovery_tokens_are_stable_strings() {
            assert_eq!(MASK_RECOVERY_FORWARDED_BINARY, "forwarded_binary");
            assert_eq!(MASK_RECOVERY_FORWARDED_UNMASKED, "forwarded_unmasked");
            assert_eq!(MASK_RECOVERY_FORWARDED_UNKNOWN, "forwarded_unknown");
            assert_eq!(MASK_RECOVERY_DROPPED, "dropped");
            // refs #882: forwarded_partial is the 5th variant of the
            // recovery vocabulary. Pin the literal so a refactor that
            // renamed it (e.g. to "partial" or "forwarded_at_level")
            // would silently break SIEM dashboards keyed on the token.
            assert_eq!(MASK_RECOVERY_FORWARDED_PARTIAL, "forwarded_partial");
        }

        #[test]
        fn classify_mask_recovery_buckets_known_binary_protocols_as_forwarded_binary() {
            // MAVLink, TAK protobuf (both spellings — `tak-protobuf` is
            // what `Codec::protocol_id()` returns, `tak_protobuf` is
            // what older config keys used), and ASTERIX are all binary
            // framings that cannot host a CoT `<point>` element. The
            // classifier must route them all to the same bucket.
            assert_eq!(
                classify_mask_recovery_for("mavlink"),
                MASK_RECOVERY_FORWARDED_BINARY
            );
            assert_eq!(
                classify_mask_recovery_for("tak-protobuf"),
                MASK_RECOVERY_FORWARDED_BINARY
            );
            assert_eq!(
                classify_mask_recovery_for("tak_protobuf"),
                MASK_RECOVERY_FORWARDED_BINARY
            );
            assert_eq!(
                classify_mask_recovery_for("asterix"),
                MASK_RECOVERY_FORWARDED_BINARY
            );
        }

        #[test]
        fn classify_mask_recovery_buckets_xml_text_protocols_as_forwarded_unmasked() {
            // `cot` and `xml` are the two source_protocol identifiers
            // a payload-XML producer would stamp. A non-XML payload
            // arriving with one of these labels means the masker was
            // expected to apply but the bytes did not parse — the
            // pre-issue-#742 audit token is preserved here so existing
            // SIEM rules keyed on `forwarded_unmasked` keep firing on
            // exactly this case.
            assert_eq!(
                classify_mask_recovery_for("cot"),
                MASK_RECOVERY_FORWARDED_UNMASKED
            );
            assert_eq!(
                classify_mask_recovery_for("xml"),
                MASK_RECOVERY_FORWARDED_UNMASKED
            );
        }

        #[test]
        fn classify_mask_recovery_buckets_unrecognized_as_forwarded_unknown() {
            // Anything not in the recognised binary or XML lists — a
            // misconfigured upstream, a transport whose identifier this
            // build does not yet recognise, or the empty string —
            // surfaces in the operator-visibility "unknown" bucket so
            // the higher-severity unparseable-XML case stays
            // distinguishable.
            assert_eq!(
                classify_mask_recovery_for("unknown_proto_xyz"),
                MASK_RECOVERY_FORWARDED_UNKNOWN
            );
            assert_eq!(
                classify_mask_recovery_for(""),
                MASK_RECOVERY_FORWARDED_UNKNOWN
            );
            // `tcp` is a transport label, not a wire-format label, so
            // the classifier cannot tell whether the bytes were XML or
            // binary — the unknown bucket is the correct answer.
            assert_eq!(
                classify_mask_recovery_for("tcp"),
                MASK_RECOVERY_FORWARDED_UNKNOWN
            );
        }

        #[test]
        fn forwarded_partial_token_is_distinct_from_other_recovery_tokens() {
            // Refs #882: forwarded_partial is the 5th member of the
            // recovery vocabulary. SIEM dashboards filter on these
            // tokens directly, so two members colliding on a literal
            // would silently re-bucket every event keyed on the
            // collided pair. Pin uniqueness explicitly.
            let tokens = [
                MASK_RECOVERY_FORWARDED_BINARY,
                MASK_RECOVERY_FORWARDED_UNMASKED,
                MASK_RECOVERY_FORWARDED_UNKNOWN,
                MASK_RECOVERY_DROPPED,
                MASK_RECOVERY_FORWARDED_PARTIAL,
            ];
            for (i, a) in tokens.iter().enumerate() {
                for (j, b) in tokens.iter().enumerate() {
                    if i != j {
                        assert_ne!(
                            a, b,
                            "recovery tokens {a} and {b} collide — SIEM dashboards depend on uniqueness"
                        );
                    }
                }
            }
        }

        #[test]
        fn forwarded_partial_is_emitted_as_recovery_field_value_at_medium_or_strict() {
            // Refs #882, audit-level pin: the dispatcher emits
            // `recovery=forwarded_partial` when masking succeeded at a
            // configured MaskDetailLevel of Medium or Strict. The
            // audit emission helper accepts an arbitrary &str for the
            // `recovery` field, so the test exercises the literal
            // round-trip through the audit subscriber to pin the
            // wire-format shape future SIEM dashboards depend on.
            use std::io::Write;
            use std::sync::Mutex;

            use tracing_subscriber::Layer;
            use tracing_subscriber::filter::Targets;
            use tracing_subscriber::fmt::MakeWriter;
            use tracing_subscriber::layer::SubscriberExt;

            #[derive(Clone, Default)]
            struct SharedBuf(std::sync::Arc<Mutex<Vec<u8>>>);
            impl Write for SharedBuf {
                fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                    if let Ok(mut guard) = self.0.lock() {
                        guard.extend_from_slice(buf);
                    }
                    Ok(buf.len())
                }
                fn flush(&mut self) -> std::io::Result<()> {
                    Ok(())
                }
            }
            impl<'a> MakeWriter<'a> for SharedBuf {
                type Writer = SharedBuf;
                fn make_writer(&'a self) -> Self::Writer {
                    self.clone()
                }
            }
            let buf = SharedBuf::default();
            let layer = tracing_subscriber::fmt::layer()
                .json()
                .with_writer(buf.clone())
                .with_filter(Targets::new().with_target("audit", tracing::Level::INFO));
            let subscriber = tracing_subscriber::registry().with(layer);
            let _guard = tracing::subscriber::set_default(subscriber);

            authz_obligation_failed(
                "alice",
                "MaskPoint",
                OBLIGATION_REASON_MASK_POINT_NON_XML,
                MASK_RECOVERY_FORWARDED_PARTIAL,
                "cot",
                "broadcast",
                "policy-v1",
            );
            drop(_guard);

            let snapshot: Vec<u8> = match buf.0.lock() {
                Ok(guard) => guard.clone(),
                Err(poisoned) => poisoned.into_inner().clone(),
            };
            let log = String::from_utf8_lossy(&snapshot).to_string();
            assert!(
                log.contains(r#""recovery":"forwarded_partial""#),
                "expected recovery=forwarded_partial in audit, got: {log}"
            );
        }

        #[test]
        fn classify_mask_recovery_is_ascii_case_insensitive() {
            // Upstream peers may title-case or uppercase the protocol
            // identifier (e.g. a federation hop that re-stamps
            // `MAVLink`). The classifier must bucket those identically
            // to their lowercase form so a SIEM does not see the same
            // event split across `forwarded_binary` and
            // `forwarded_unknown` based purely on the upstream's
            // casing convention.
            assert_eq!(
                classify_mask_recovery_for("MAVLINK"),
                MASK_RECOVERY_FORWARDED_BINARY
            );
            assert_eq!(
                classify_mask_recovery_for("MavLink"),
                MASK_RECOVERY_FORWARDED_BINARY
            );
            assert_eq!(
                classify_mask_recovery_for("TAK-Protobuf"),
                MASK_RECOVERY_FORWARDED_BINARY
            );
            assert_eq!(
                classify_mask_recovery_for("CoT"),
                MASK_RECOVERY_FORWARDED_UNMASKED
            );
        }
    }

    mod store_forward {
        use super::*;

        #[test]
        fn test_store_forward_dropped() {
            store_forward_dropped("client-cn", "writer_channel_full");
            store_forward_dropped("client-cn", "writer_task_gone");
            store_forward_dropped("", "");
        }

        #[test]
        fn test_store_forward_drain_panic() {
            store_forward_drain_panic("deadbeef1234", "task panicked: internal redb error");
            store_forward_drain_panic("", "");
        }

        #[test]
        fn test_store_forward_drained() {
            // Smoke-test the dwell-time event added in #729: it must
            // not panic on degenerate inputs (zero count, NaN-adjacent
            // dwell numbers) and must accept the operator-typical
            // shape.
            store_forward_drained("client-cn", 12, 1.5, 0.05, 4.2, 1, 0);
            store_forward_drained("", 0, 0.0, 0.0, 0.0, 0, 0);
            store_forward_drained("solo", 1, 0.001, 0.001, 0.001, 0, 0);
        }
    }

    mod verifier {
        use super::*;

        #[test]
        fn test_verifier_rebuild_failed() {
            verifier_rebuild_failed("root store build error: invalid cert");
            verifier_rebuild_failed("");
        }
    }

    mod egress_envelope {
        use super::*;

        #[test]
        fn test_egress_obligation_applied() {
            // Smoke-test the documented call shapes: every sink class
            // label that today's `RecipientClass` enum surfaces and the
            // documented obligation labels exposed by the transport
            // crate's `obligation_kind_label`. The audit emitter
            // sanitizes `&str` arguments at the boundary, so a
            // newline-injected sink label must NOT split the captured
            // line.
            egress_obligation_applied("multicast", "mask_point", "multicast:[alpha,bravo]");
            egress_obligation_applied("nats", "tag_classified", "nats:siem.events");
            egress_obligation_applied("federation", "mask_payload", "federation:peer-1");
            egress_obligation_applied("http", "audit_extended", "http:dashboard");
            egress_obligation_applied("mqtt", "unknown", "mqtt:tactical/events");
            // Boundary-attack shape: every parameter is sanitized
            // independently, so the smoke test exercises the
            // log-forging input on each.
            egress_obligation_applied(
                "multicast\nFAKE_LINE",
                "mask_point\r\nfoo",
                "multicast:[a]\nb=1",
            );
        }
    }

    mod http_egress {
        use super::*;

        #[test]
        fn test_http_publish_failed() {
            http_publish_failed("siem-collector", 503, "service unavailable");
            http_publish_failed("dashboard", 0, "connection refused");
        }

        #[test]
        fn test_http_circuit_tripped() {
            http_circuit_tripped("siem-collector");
            http_circuit_tripped("analytics-api");
        }

        #[test]
        fn test_http_circuit_recovered() {
            http_circuit_recovered("siem-collector");
            http_circuit_recovered("analytics-api");
        }

        #[test]
        fn test_http_dlq_drain_started() {
            http_dlq_drain_started("siem-collector", 0);
            http_dlq_drain_started("siem-collector", 7);
            http_dlq_drain_started("", 1);
        }

        #[test]
        fn test_http_dlq_drain_completed() {
            http_dlq_drain_completed("siem-collector", 0, 0);
            http_dlq_drain_completed("siem-collector", 42, 3);
            http_dlq_drain_completed("", 0, u64::MAX);
        }
    }

    mod mavlink {
        use super::*;

        #[test]
        fn test_mavlink_unsigned_rejected() {
            // Exercise common and edge shapes of the peer field so the
            // macro doesn't choke on zero-length or IPv6-bracketed
            // addresses. The helper is intentionally fmt-agnostic.
            mavlink_unsigned_rejected("10.0.0.1:14550");
            mavlink_unsigned_rejected("[::1]:14550");
            mavlink_unsigned_rejected("unknown");
            mavlink_unsigned_rejected("");
        }

        #[test]
        fn test_mavlink_v1_rejected() {
            mavlink_v1_rejected("192.168.1.42:14550");
            mavlink_v1_rejected("unknown");
            mavlink_v1_rejected("");
        }

        #[test]
        fn test_mqtt_will_published() {
            // Smoke-test every combination operators see in production:
            // hashed CN (the typical caller wraps via `hash_cn`), a
            // bare lowercase topic, an unprefixed group name, and both
            // retain bit positions. Empty strings are sanitised at the
            // call site but the audit macro itself must not panic on
            // them either.
            mqtt_will_published("hashed-cn-12345", "fleet/red/status", "fleet/red", true);
            mqtt_will_published("hashed-cn-12345", "presence", "presence", false);
            mqtt_will_published("", "", "", false);
        }

        #[test]
        fn test_mavlink_heartbeat_received() {
            // Smoke-test the typical fleet-observability call shape: an
            // ArduPilot Mega (autopilot=12) on a Quadrotor (vehicle_type=2)
            // with system_id=42 and the autopilot's standard MAV_COMP_ID_AUTOPILOT1
            // (component_id=1). The macro must not panic on the boundary
            // values either — 0 across the board (an unconfigured
            // bench-test airframe) and u8::MAX (a synthetic frame from a
            // fuzzer or a misconfigured sender).
            mavlink_heartbeat_received(42, 1, 12, 2);
            mavlink_heartbeat_received(0, 0, 0, 0);
            mavlink_heartbeat_received(u8::MAX, u8::MAX, u8::MAX, u8::MAX);
        }

        #[test]
        fn test_nats_poison_message_dlq() {
            // Smoke-test the four documented `reason` slugs the
            // subscriber emits on a poison drop, plus the boundary
            // shapes the macro must not panic on (zero attempts, max
            // attempts, empty fields, "unknown" msg_id when JetStream
            // info() failed).
            nats_poison_message_dlq("points.ALPHA", "12345", "oversized", 1);
            nats_poison_message_dlq("points.BRAVO", "67890", "unparseable", 5);
            nats_poison_message_dlq("points.CHARLIE", "1", "unknown-position", 0);
            nats_poison_message_dlq("points.DELTA", "unknown", "invalid-identity", u32::MAX);
            nats_poison_message_dlq("", "", "", 0);
        }
    }

    mod admin {
        use super::*;

        #[test]
        fn test_admin_drain_triggered() {
            // Smoke-test the documented sources plus the boundary
            // shapes (empty, oversize) the macro must not panic on.
            admin_drain_triggered("api");
            admin_drain_triggered("signal");
            admin_drain_triggered("");
            admin_drain_triggered(&"x".repeat(1024));
        }

        #[test]
        fn test_client_force_disconnected() {
            // Pin every documented call shape so a future refactor that
            // drops a field or swaps numeric/string positions fails the
            // build. Includes the `0` count edge-case (operator
            // disconnects a CN with no live session) and the boundary
            // shapes (empty, oversize) the macro must not panic on.
            client_force_disconnected("alice", "bearer", 1);
            client_force_disconnected("ghost", "bearer", 0);
            client_force_disconnected("", "", 0);
            client_force_disconnected(&"x".repeat(1024), "bearer", u64::MAX);
        }
    }

    mod delivery {
        use super::*;

        #[test]
        fn test_message_delivered_smoke() {
            // Pin every documented call shape so a future refactor
            // that drops a field or reorders arguments fails the
            // build instead of silently reshaping the audit record.
            message_delivered("alice", "bob", "UID-1", "position", "team");
            message_delivered("alice", "bob", "", "chat", "direct");
            message_delivered("alice", "bob", "UID-2", "alert", "broadcast");
            message_delivered("", "", "", "", "");
        }

        #[test]
        fn test_message_dropped_smoke() {
            // Cover every documented `reason` token in the small
            // fixed vocabulary. A typo here would silently break SIEM
            // rules that filter on the reason field.
            message_dropped("alice", "bob", "UID-1", "backpressure");
            message_dropped("alice", "bob", "UID-1", "no_subscribers");
            message_dropped("alice", "bob", "UID-1", "acl_denied");
            message_dropped("alice", "bob", "UID-1", "authz_denied");
            message_dropped("alice", "bob", "UID-1", "obligation_failed");
            message_dropped("", "", "", "");
        }
    }

    /// Tests pinning the boundary-sanitization contract: every audit
    /// helper that takes a user-controlled `&str` MUST sanitize it
    /// internally so that a forgotten call-site wrap cannot produce a
    /// forgeable log line. These tests capture the audit-target
    /// tracing output, parse the JSON, and assert the dangerous bytes
    /// were replaced with U+FFFD before serialization.
    mod sanitization {
        use std::io::Write;
        use std::sync::{Arc, Mutex};

        use tracing_subscriber::Layer;
        use tracing_subscriber::filter::Targets;
        use tracing_subscriber::fmt::MakeWriter;
        use tracing_subscriber::layer::SubscriberExt;

        use super::*;

        /// Shared in-memory writer used by every sanitization test to
        /// capture the JSON-formatted audit output for inspection.
        #[derive(Clone, Default)]
        struct SharedBuf(Arc<Mutex<Vec<u8>>>);

        impl SharedBuf {
            fn snapshot(&self) -> String {
                let guard = self.0.lock().expect("buf lock poisoned");
                String::from_utf8_lossy(&guard).into_owned()
            }
        }

        impl Write for SharedBuf {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0
                    .lock()
                    .expect("buf lock poisoned")
                    .extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        impl<'a> MakeWriter<'a> for SharedBuf {
            type Writer = SharedBuf;
            fn make_writer(&'a self) -> Self::Writer {
                self.clone()
            }
        }

        /// Run `f` with a temporary tracing subscriber that captures
        /// the `audit` target into a `SharedBuf`. Returns the captured
        /// JSON snapshot for assertion.
        fn capture_audit(f: impl FnOnce()) -> String {
            let buf = SharedBuf::default();
            let layer = tracing_subscriber::fmt::layer()
                .json()
                .with_writer(buf.clone())
                .with_filter(Targets::new().with_target("audit", tracing::Level::INFO));
            let subscriber = tracing_subscriber::registry().with(layer);
            tracing::subscriber::with_default(subscriber, f);
            buf.snapshot()
        }

        /// Locate the JSON line whose `event_type` matches `expected`
        /// and parse it into a `serde_json::Value` for field-level
        /// assertions.
        fn parse_event(snapshot: &str, expected_event_type: &str) -> serde_json::Value {
            let line = snapshot
                .lines()
                .find(|l| l.contains(expected_event_type))
                .expect("expected event type missing from captured audit output");
            serde_json::from_str(line).expect("audit line must be valid JSON")
        }

        #[test]
        fn audit_sanitizes_cn_with_newline_injection() {
            // A CN with an embedded newline is the canonical
            // log-forging payload: an attacker who controls their
            // certificate CN at enrollment time can otherwise split
            // the audit record into two log lines and inject a forged
            // entry visible to a SIEM operator.
            let malicious_cn = "alice\nattacker_log_line";
            let snapshot = capture_audit(|| client_disconnected(malicious_cn, 1));
            let event = parse_event(&snapshot, "client.disconnected");
            let cn = event["fields"]["cn"]
                .as_str()
                .expect("cn field must be a JSON string");
            assert!(
                !cn.contains('\n'),
                "raw newline must not survive sanitization: {cn:?}"
            );
            assert!(
                cn.contains('\u{FFFD}'),
                "sanitized output must contain the replacement codepoint U+FFFD: {cn:?}"
            );
            // The captured snapshot itself must not contain the
            // injected fake entry as a separate logical line — the
            // entire payload is on one JSON line.
            let lines_with_event: Vec<_> = snapshot
                .lines()
                .filter(|l| l.contains("client.disconnected"))
                .collect();
            assert_eq!(
                lines_with_event.len(),
                1,
                "log forging must not split the record into multiple lines"
            );
        }

        #[test]
        fn audit_sanitizes_cn_with_control_char_injection() {
            // C0 control characters (0x01, 0x02, …) survive a naive
            // `%cn` fmt and would otherwise corrupt downstream log
            // parsers that segment on control bytes.
            let malicious_cn = "alice\x01\x02\x03injected";
            let snapshot = capture_audit(|| client_disconnected(malicious_cn, 7));
            let event = parse_event(&snapshot, "client.disconnected");
            let cn = event["fields"]["cn"]
                .as_str()
                .expect("cn field must be a JSON string");
            for forbidden in &['\x01', '\x02', '\x03'] {
                assert!(
                    !cn.contains(*forbidden),
                    "control byte {forbidden:?} must be replaced: {cn:?}"
                );
            }
            assert!(
                cn.contains('\u{FFFD}'),
                "sanitized output must contain U+FFFD: {cn:?}"
            );
        }

        #[test]
        fn audit_sanitizes_group_with_log_forging_payload() {
            // A group name containing CR/LF and an ANSI CSI introducer
            // is the worst-case forge payload: the linebreak splits the
            // log record and the CSI sequence styles a fake entry.
            // Sanitization must neutralise both.
            let malicious_group = "fake_event\r\n\x1b[31m[ALERT]\x1b[0m";
            let snapshot = capture_audit(|| {
                mqtt_will_published("hashed-cn", "topic/safe", malicious_group, false)
            });
            let event = parse_event(&snapshot, "mqtt.will_published");
            let group = event["fields"]["group"]
                .as_str()
                .expect("group field must be a JSON string");
            for forbidden in &['\n', '\r', '\x1b'] {
                assert!(
                    !group.contains(*forbidden),
                    "forge byte {forbidden:?} must be replaced: {group:?}"
                );
            }
            assert!(
                group.contains('\u{FFFD}'),
                "sanitized output must contain U+FFFD: {group:?}"
            );
        }

        #[test]
        fn audit_nats_poison_message_dlq_emits_documented_shape() {
            // Pin the wire-format contract for sub-item 3 of #883:
            // SIEM rules will alert on `event_type ==
            // "nats.poison_dlq"` and `action == "dead_letter"`. A
            // future refactor that renames either field would
            // silently break those rules, so capture the JSON output
            // and pin the shape end-to-end.
            let snapshot = capture_audit(|| {
                nats_poison_message_dlq("points.ALPHA", "12345", "unparseable", 5)
            });
            let event = parse_event(&snapshot, "nats.poison_dlq");
            assert_eq!(
                event["fields"]["event_type"]
                    .as_str()
                    .expect("event_type must be a JSON string"),
                "nats.poison_dlq",
            );
            assert_eq!(
                event["fields"]["action"]
                    .as_str()
                    .expect("action must be a JSON string"),
                "dead_letter",
            );
            assert_eq!(
                event["fields"]["result"]
                    .as_str()
                    .expect("result must be a JSON string"),
                "moved",
            );
            assert_eq!(
                event["fields"]["subject"]
                    .as_str()
                    .expect("subject must be a JSON string"),
                "points.ALPHA",
            );
            assert_eq!(
                event["fields"]["msg_id"]
                    .as_str()
                    .expect("msg_id must be a JSON string"),
                "12345",
            );
            assert_eq!(
                event["fields"]["reason"]
                    .as_str()
                    .expect("reason must be a JSON string"),
                "unparseable",
            );
            // `attempts` is numeric (u32) — must serialise as a number,
            // not a string, so PromQL/PromQ-style alert rules can do
            // numeric comparisons without parsing. tracing-subscriber's
            // JSON format renders u32 as an unsigned integer.
            assert_eq!(
                event["fields"]["attempts"]
                    .as_u64()
                    .expect("attempts must be a numeric JSON value"),
                5,
            );
        }

        #[test]
        fn audit_nats_poison_message_dlq_sanitizes_subject_msg_id_and_reason() {
            // The subscriber receives `subject` from the live JetStream
            // stream, where any client that can publish to
            // `{subject_prefix}.>` can inject control bytes into the
            // subject string. `msg_id` is server-derived (stream
            // sequence rendered as a decimal string), so in practice
            // it cannot contain control bytes — but the audit boundary
            // sanitizes anyway for defense-in-depth, since the
            // server's wire format is not under our control. `reason`
            // is a literal in our code today, but a future caller
            // that threads operator-controlled context through would
            // get the same protection.
            let malicious_subject = "points.ALPHA\r\n\x1b[31m[FAKE ALERT]\x1b[0m";
            let malicious_msg_id = "12345\nfake_event=injected";
            let malicious_reason = "unparseable\r\nspoofed";
            let snapshot = capture_audit(|| {
                nats_poison_message_dlq(malicious_subject, malicious_msg_id, malicious_reason, 7)
            });
            let event = parse_event(&snapshot, "nats.poison_dlq");
            let subject = event["fields"]["subject"]
                .as_str()
                .expect("subject must be a JSON string");
            let msg_id = event["fields"]["msg_id"]
                .as_str()
                .expect("msg_id must be a JSON string");
            let reason = event["fields"]["reason"]
                .as_str()
                .expect("reason must be a JSON string");
            for forbidden in &['\n', '\r', '\x1b'] {
                assert!(
                    !subject.contains(*forbidden),
                    "subject: forge byte {forbidden:?} must be replaced: {subject:?}"
                );
                assert!(
                    !msg_id.contains(*forbidden),
                    "msg_id: forge byte {forbidden:?} must be replaced: {msg_id:?}"
                );
                assert!(
                    !reason.contains(*forbidden),
                    "reason: forge byte {forbidden:?} must be replaced: {reason:?}"
                );
            }
            assert!(
                subject.contains('\u{FFFD}')
                    && msg_id.contains('\u{FFFD}')
                    && reason.contains('\u{FFFD}'),
                "sanitized fields must contain U+FFFD",
            );
            // The captured snapshot itself must not contain the
            // injected fake entry as a separate logical line.
            let lines_with_event: Vec<_> = snapshot
                .lines()
                .filter(|l| l.contains("nats.poison_dlq"))
                .collect();
            assert_eq!(
                lines_with_event.len(),
                1,
                "log forging must not split the record into multiple lines",
            );
        }

        #[test]
        fn audit_admin_drain_triggered_sanitizes_source() {
            // The `source` field is in principle operator-controlled —
            // a future SIGUSR2 handler or a misconfigured wrapper script
            // could thread an unvetted token through. Pin that the
            // audit boundary scrubs CR/LF and ANSI CSI even though
            // every in-tree call site uses a safe literal today.
            let malicious_source = "api\r\n\x1b[31m[FAKE ALERT]\x1b[0m";
            let snapshot = capture_audit(|| admin_drain_triggered(malicious_source));
            let event = parse_event(&snapshot, "admin.drain_triggered");
            let source = event["fields"]["source"]
                .as_str()
                .expect("source must be a JSON string");
            for forbidden in &['\n', '\r', '\x1b'] {
                assert!(
                    !source.contains(*forbidden),
                    "forge byte {forbidden:?} must be replaced: {source:?}"
                );
            }
            assert!(
                source.contains('\u{FFFD}'),
                "sanitized output must contain U+FFFD: {source:?}"
            );
            // Pin the action / result tokens so a SIEM rule that keys
            // on them keeps firing across refactors.
            assert_eq!(
                event["fields"]["action"]
                    .as_str()
                    .expect("action must be a JSON string"),
                "drain"
            );
            assert_eq!(
                event["fields"]["result"]
                    .as_str()
                    .expect("result must be a JSON string"),
                "initiated"
            );
        }

        #[test]
        fn client_force_disconnected_emits_documented_shape() {
            // Pins the wire-format contract for issue #902: SIEM rules
            // alert on `event_type == "client.force_disconnected"` and
            // `action == "force_disconnect"`. A future refactor that
            // renames either field, swaps numeric/string positions, or
            // drops `sessions_closed` would silently break those rules,
            // so capture the JSON output and pin the shape end-to-end.
            let snapshot = capture_audit(|| client_force_disconnected("alice", "bearer", 2));
            let event = parse_event(&snapshot, "client.force_disconnected");
            assert_eq!(
                event["fields"]["event_type"]
                    .as_str()
                    .expect("event_type must be a JSON string"),
                "client.force_disconnected",
            );
            assert_eq!(
                event["fields"]["cn"]
                    .as_str()
                    .expect("cn must be a JSON string"),
                "alice",
            );
            assert_eq!(
                event["fields"]["by_operator"]
                    .as_str()
                    .expect("by_operator must be a JSON string"),
                "bearer",
            );
            assert_eq!(
                event["fields"]["sessions_closed"]
                    .as_u64()
                    .expect("sessions_closed must be a JSON number"),
                2,
            );
            assert_eq!(
                event["fields"]["action"]
                    .as_str()
                    .expect("action must be a JSON string"),
                "force_disconnect",
            );
            assert_eq!(
                event["fields"]["result"]
                    .as_str()
                    .expect("result must be a JSON string"),
                "success",
            );
        }

        #[test]
        fn client_force_disconnected_sanitizes_cn_and_by_operator() {
            // An attacker-controlled CN (or a future mTLS-fronted variant
            // where `by_operator` carries a peer CN) cannot log-forge a
            // fake force-disconnect record by injecting CR/LF or ANSI
            // CSI into the audit boundary. Pin the contract.
            let malicious_cn = "alice\r\nFAKE EVENT";
            let malicious_op = "operator\x1b[31mFAKE\x1b[0m";
            let snapshot = capture_audit(|| {
                client_force_disconnected(malicious_cn, malicious_op, 1);
            });
            let event = parse_event(&snapshot, "client.force_disconnected");
            let cn = event["fields"]["cn"]
                .as_str()
                .expect("cn must be a JSON string");
            let by_operator = event["fields"]["by_operator"]
                .as_str()
                .expect("by_operator must be a JSON string");
            for forbidden in &['\n', '\r', '\x1b'] {
                assert!(
                    !cn.contains(*forbidden),
                    "forge byte {forbidden:?} must be replaced in cn: {cn:?}"
                );
                assert!(
                    !by_operator.contains(*forbidden),
                    "forge byte {forbidden:?} must be replaced in by_operator: {by_operator:?}"
                );
            }
            assert!(
                cn.contains('\u{FFFD}') && by_operator.contains('\u{FFFD}'),
                "sanitized output must contain U+FFFD",
            );
            // The captured snapshot itself must not contain the
            // injected fake entry as a separate logical line.
            let lines: Vec<_> = snapshot
                .lines()
                .filter(|l| l.contains("client.force_disconnected"))
                .collect();
            assert_eq!(
                lines.len(),
                1,
                "log forging must not split the record into multiple lines",
            );
        }

        #[test]
        fn audit_does_not_double_sanitize_already_safe_input() {
            // Idempotency check: a CN that is already free of control
            // characters must round-trip through the audit layer
            // unchanged. This pins that callers who pre-sanitize (e.g.
            // by wrapping in `sanitize_for_log` themselves) do not
            // produce a doubly-altered field — the wire format is
            // identical to the no-op path.
            let safe_cn = "alice";
            let snapshot = capture_audit(|| client_disconnected(safe_cn, 1));
            let event = parse_event(&snapshot, "client.disconnected");
            let cn = event["fields"]["cn"]
                .as_str()
                .expect("cn field must be a JSON string");
            assert_eq!(
                cn, "alice",
                "safe input must not be altered by sanitization"
            );
            assert!(
                !cn.contains('\u{FFFD}'),
                "no replacement codepoint should appear for already-safe input: {cn:?}"
            );
        }

        #[test]
        fn authz_reload_rollback_emits_documented_shape() {
            // Pins the wire-format contract for issue #818: SIEM rules
            // alert on `event_type == "authz.reload_rollback"` and
            // `action == "rollback"`. A future refactor that renames
            // either field would silently break those rules, so capture
            // the JSON output and pin the shape end-to-end.
            let snapshot =
                capture_audit(|| authz_reload_rollback("parse error", Some("policy-2026-04-25-1")));
            let event = parse_event(&snapshot, "authz.reload_rollback");
            assert_eq!(
                event["fields"]["event_type"]
                    .as_str()
                    .expect("event_type must be a JSON string"),
                "authz.reload_rollback",
            );
            assert_eq!(
                event["fields"]["action"]
                    .as_str()
                    .expect("action must be a JSON string"),
                "rollback",
            );
            assert_eq!(
                event["fields"]["result"]
                    .as_str()
                    .expect("result must be a JSON string"),
                "success",
            );
            assert_eq!(
                event["fields"]["reason"]
                    .as_str()
                    .expect("reason must be a JSON string"),
                "parse error",
            );
            assert_eq!(
                event["fields"]["previous_policy_id"]
                    .as_str()
                    .expect("previous_policy_id must be a JSON string when Some"),
                "policy-2026-04-25-1",
            );
        }

        #[test]
        fn authz_reload_rollback_sanitizes_reason_and_policy_id() {
            // The rollback emission point sees attacker-controlled data
            // through the upstream policy file (a malicious reviewer
            // could ship a policy file with control characters in its
            // id, then trigger a rollback to surface the field through
            // the rollback record). Both `reason` and
            // `previous_policy_id` MUST sanitize at the boundary.
            let malicious_reason = "compile failed\n\x1b[31m[FAKE ALERT]\x1b[0m";
            let malicious_policy_id = "policy-x\r\nfake_event=injected";
            let snapshot = capture_audit(|| {
                authz_reload_rollback(malicious_reason, Some(malicious_policy_id))
            });
            let event = parse_event(&snapshot, "authz.reload_rollback");
            let reason = event["fields"]["reason"]
                .as_str()
                .expect("reason must be a JSON string");
            let policy_id = event["fields"]["previous_policy_id"]
                .as_str()
                .expect("previous_policy_id must be a JSON string when Some");
            for forbidden in &['\n', '\r', '\x1b'] {
                assert!(
                    !reason.contains(*forbidden),
                    "reason: forge byte {forbidden:?} must be replaced: {reason:?}"
                );
                assert!(
                    !policy_id.contains(*forbidden),
                    "policy_id: forge byte {forbidden:?} must be replaced: {policy_id:?}"
                );
            }
            assert!(
                reason.contains('\u{FFFD}') && policy_id.contains('\u{FFFD}'),
                "sanitized fields must contain U+FFFD"
            );
        }

        /// Issue #772: receive-time PEP audit events MUST carry a
        /// `policy_id` field so SIEM correlation can pin which engine
        /// version returned the deny verdict — across rolling policy
        /// reloads, a deny under `vN` looks identical on the wire to
        /// one under `vN+1`, but the remediation may differ.
        ///
        /// Pin the field name AND the literal value so a future refactor
        /// that renames either silently breaks the SIEM contract.
        #[test]
        fn authz_denied_audit_includes_policy_id_field() {
            let snapshot = capture_audit(|| {
                authz_denied(
                    "alice",
                    "abc:def",
                    "send",
                    "group",
                    "team-alpha",
                    Some("rule-1"),
                    "policy-2026-04-25-1",
                );
            });
            let event = parse_event(&snapshot, "authz.denied");
            // policy_id must be present, must be a string, and must
            // carry the value passed at the call site (not a stand-in,
            // not the empty string, not redacted).
            let policy_id = event["fields"]["policy_id"]
                .as_str()
                .expect("policy_id must be a JSON string on receive-time PEP audits");
            assert_eq!(
                policy_id, "policy-2026-04-25-1",
                "audit emission must carry the engine's policy_id verbatim",
            );
            // event_type, action, result, and rule_id must not have
            // shifted in this refactor — pin the surrounding shape so
            // any unrelated field rename surfaces here too.
            assert_eq!(
                event["fields"]["event_type"]
                    .as_str()
                    .expect("event_type must be a JSON string"),
                "authz.denied",
            );
            assert_eq!(
                event["fields"]["action"]
                    .as_str()
                    .expect("action must be a JSON string"),
                "send",
            );
            assert_eq!(
                event["fields"]["result"]
                    .as_str()
                    .expect("result must be a JSON string"),
                "deny",
            );
        }

        /// Closes #772: the new `policy_id` field on `authz.denied`
        /// MUST flow through the audit boundary's sanitizer (per #1197 +
        /// #1220). A malicious authz operator who shipped a policy file
        /// with CR/LF bytes in its `policy_id` could otherwise split the
        /// audit record into two log lines and inject a forged entry —
        /// exactly the log-forging vector the boundary sanitizer
        /// closes for every other operator-supplied field.
        #[test]
        fn authz_denied_sanitizes_policy_id_at_audit_boundary() {
            let malicious_policy_id = "policy-x\r\n\x1b[31m[FAKE ALERT]\x1b[0m";
            let snapshot = capture_audit(|| {
                authz_denied(
                    "alice",
                    "abc:def",
                    "send",
                    "group",
                    "team-alpha",
                    Some("rule-1"),
                    malicious_policy_id,
                );
            });
            let event = parse_event(&snapshot, "authz.denied");
            let policy_id = event["fields"]["policy_id"]
                .as_str()
                .expect("policy_id must be a JSON string");
            for forbidden in &['\n', '\r', '\x1b'] {
                assert!(
                    !policy_id.contains(*forbidden),
                    "policy_id: forge byte {forbidden:?} must be replaced: {policy_id:?}"
                );
            }
            assert!(
                policy_id.contains('\u{FFFD}'),
                "sanitized policy_id must contain U+FFFD: {policy_id:?}"
            );
            // Defense in depth: the captured snapshot must remain a
            // single JSON line. A regression that bypassed the
            // sanitizer would split into two lines on the embedded
            // CR/LF, and the SIEM would see a forged "FAKE ALERT"
            // entry the sanitizer is supposed to neutralize.
            let lines_with_event: Vec<_> = snapshot
                .lines()
                .filter(|l| l.contains("authz.denied"))
                .collect();
            assert_eq!(
                lines_with_event.len(),
                1,
                "log forging must not split the record into multiple lines"
            );
        }

        /// Issue #772: the `policy_id` field MUST also surface on the
        /// obligation-failed sibling of `authz_denied`. The two events
        /// are co-emitted on the same receive-time PEP path (a deny
        /// blocks delivery; an obligation_failed signals that the
        /// policy hint was un-actuatable) and SIEM correlation needs
        /// the same engine-version pivot on both.
        #[test]
        fn authz_obligation_failed_audit_includes_policy_id_field() {
            let snapshot = capture_audit(|| {
                authz_obligation_failed(
                    "alice",
                    "MaskPoint",
                    OBLIGATION_REASON_MASK_POINT_NON_XML,
                    "forwarded_unmasked",
                    "tcp",
                    "broadcast",
                    "policy-2026-04-25-1",
                );
            });
            let event = parse_event(&snapshot, "authz.obligation_failed");
            let policy_id = event["fields"]["policy_id"]
                .as_str()
                .expect("policy_id must be a JSON string on obligation_failed audit");
            assert_eq!(
                policy_id, "policy-2026-04-25-1",
                "obligation_failed audit must carry policy_id verbatim",
            );
        }

        /// Closes #772: same sanitization invariant as
        /// `authz_denied_sanitizes_policy_id_at_audit_boundary`, applied
        /// to the obligation-failed sibling. Pinning both pre-empts a
        /// future contributor "fixing" only one site.
        #[test]
        fn authz_obligation_failed_sanitizes_policy_id_at_audit_boundary() {
            let malicious_policy_id = "policy-x\r\nfake_event=injected";
            let snapshot = capture_audit(|| {
                authz_obligation_failed(
                    "alice",
                    "MaskPoint",
                    OBLIGATION_REASON_MASK_POINT_NON_XML,
                    "forwarded_unmasked",
                    "tcp",
                    "broadcast",
                    malicious_policy_id,
                );
            });
            let event = parse_event(&snapshot, "authz.obligation_failed");
            let policy_id = event["fields"]["policy_id"]
                .as_str()
                .expect("policy_id must be a JSON string");
            for forbidden in &['\n', '\r'] {
                assert!(
                    !policy_id.contains(*forbidden),
                    "policy_id: forge byte {forbidden:?} must be replaced: {policy_id:?}"
                );
            }
            assert!(
                policy_id.contains('\u{FFFD}'),
                "sanitized policy_id must contain U+FFFD: {policy_id:?}"
            );
        }

        /// Issue #772: the unknown-variant sibling of
        /// `authz_obligation_failed` MUST also carry `policy_id`.
        /// This is the audit-flood-guarded site (#769): the rate
        /// limiter's bucket key is `(policy_id, variant)`, so a SIEM
        /// rule that correlates the suppressed-emission rate (via
        /// `rustgate_authz_obligation_unknown_total`) with the
        /// engine version that introduced the skew needs `policy_id`
        /// on the audit emission to pivot between the two surfaces.
        #[test]
        fn authz_obligation_unknown_audit_includes_policy_id_field() {
            let snapshot = capture_audit(|| {
                authz_obligation_unknown(
                    "alice",
                    "FutureVariant",
                    "tcp",
                    "broadcast",
                    "policy-2026-04-25-1",
                );
            });
            let event = parse_event(&snapshot, "authz.obligation_unknown");
            let policy_id = event["fields"]["policy_id"]
                .as_str()
                .expect("policy_id must be a JSON string on obligation_unknown audit");
            assert_eq!(
                policy_id, "policy-2026-04-25-1",
                "obligation_unknown audit must carry policy_id verbatim",
            );
            // The static `reason` token must remain alongside —
            // policy_id is additive, not a replacement (issue #775).
            assert_eq!(
                event["fields"]["reason"]
                    .as_str()
                    .expect("reason must be a JSON string"),
                OBLIGATION_REASON_UNKNOWN_VARIANT,
            );
        }

        #[test]
        fn message_delivered_emits_documented_shape() {
            // Closes #854. SIEM correlation queries key on the field
            // names below; pin the wire shape end-to-end so a future
            // refactor that renames a field fails this test instead of
            // silently breaking downstream rules.
            let snapshot = capture_audit(|| {
                message_delivered("alice", "bob", "ANDROID-1", "position", "team-blue")
            });
            let event = parse_event(&snapshot, "message.delivered");
            assert_eq!(
                event["fields"]["source"]
                    .as_str()
                    .expect("source must be a JSON string"),
                "alice"
            );
            assert_eq!(
                event["fields"]["dest"]
                    .as_str()
                    .expect("dest must be a JSON string"),
                "bob"
            );
            assert_eq!(
                event["fields"]["uid"]
                    .as_str()
                    .expect("uid must be a JSON string"),
                "ANDROID-1"
            );
            assert_eq!(
                event["fields"]["msg_type"]
                    .as_str()
                    .expect("msg_type must be a JSON string"),
                "position"
            );
            assert_eq!(
                event["fields"]["group"]
                    .as_str()
                    .expect("group must be a JSON string"),
                "team-blue"
            );
            assert_eq!(
                event["fields"]["action"]
                    .as_str()
                    .expect("action must be a JSON string"),
                "deliver"
            );
            assert_eq!(
                event["fields"]["result"]
                    .as_str()
                    .expect("result must be a JSON string"),
                "success"
            );
        }

        #[test]
        fn message_delivered_sanitizes_cn_with_log_forging() {
            // Closes #854. Recipient CN crosses the audit-boundary at
            // the audit emission site, so sanitization is the helper's
            // responsibility regardless of whether the caller wrapped.
            let malicious_cn = "bob\r\n\x1b[31m[FAKE]\x1b[0m";
            let snapshot = capture_audit(|| {
                message_delivered("alice", malicious_cn, "UID-1", "chat", "direct")
            });
            let event = parse_event(&snapshot, "message.delivered");
            let dest = event["fields"]["dest"]
                .as_str()
                .expect("dest must be a JSON string");
            for forbidden in &['\n', '\r', '\x1b'] {
                assert!(
                    !dest.contains(*forbidden),
                    "forge byte {forbidden:?} must be replaced: {dest:?}"
                );
            }
            assert!(
                dest.contains('\u{FFFD}'),
                "sanitized output must contain U+FFFD: {dest:?}"
            );
        }

        #[test]
        fn message_dropped_emits_documented_shape() {
            // Closes #854. The companion to message_delivered — pin
            // the field set and the static action/result tokens.
            let snapshot =
                capture_audit(|| message_dropped("alice", "bob", "ANDROID-2", "backpressure"));
            let event = parse_event(&snapshot, "message.dropped");
            assert_eq!(
                event["fields"]["source"]
                    .as_str()
                    .expect("source must be a JSON string"),
                "alice"
            );
            assert_eq!(
                event["fields"]["dest"]
                    .as_str()
                    .expect("dest must be a JSON string"),
                "bob"
            );
            assert_eq!(
                event["fields"]["uid"]
                    .as_str()
                    .expect("uid must be a JSON string"),
                "ANDROID-2"
            );
            assert_eq!(
                event["fields"]["reason"]
                    .as_str()
                    .expect("reason must be a JSON string"),
                "backpressure"
            );
            assert_eq!(
                event["fields"]["action"]
                    .as_str()
                    .expect("action must be a JSON string"),
                "deliver"
            );
            assert_eq!(
                event["fields"]["result"]
                    .as_str()
                    .expect("result must be a JSON string"),
                "dropped"
            );
        }

        #[test]
        fn message_dropped_sanitizes_reason_field() {
            // Closes #854. While the in-tree call sites pass static
            // tokens, an attacker-controlled `reason` would be a
            // log-forge vector if the audit boundary missed it.
            let malicious_reason = "backpressure\nattacker_line";
            let snapshot =
                capture_audit(|| message_dropped("alice", "bob", "UID-1", malicious_reason));
            let event = parse_event(&snapshot, "message.dropped");
            let reason = event["fields"]["reason"]
                .as_str()
                .expect("reason must be a JSON string");
            assert!(
                !reason.contains('\n'),
                "raw newline must not survive sanitization: {reason:?}"
            );
            assert!(
                reason.contains('\u{FFFD}'),
                "sanitized output must contain U+FFFD: {reason:?}"
            );
        }

        #[test]
        fn udp_multicast_joined_emits_documented_shape() {
            // Closes #861. Pin the field set and the static
            // action/result tokens so SIEM rules looking for
            // `udp_multicast.joined` keep firing across refactors.
            let snapshot = capture_audit(|| udp_multicast_joined("239.2.3.1:6969", "0.0.0.0"));
            let event = parse_event(&snapshot, "udp_multicast.joined");
            assert_eq!(event["fields"]["group"], "239.2.3.1:6969");
            assert_eq!(event["fields"]["interface"], "0.0.0.0");
            assert_eq!(event["fields"]["action"], "join");
            assert_eq!(event["fields"]["result"], "success");
        }

        #[test]
        fn udp_multicast_joined_sanitizes_interface_field() {
            // Closes #861. An operator-supplied interface name is
            // attacker-influenced via configuration; the audit boundary
            // must replace control bytes with U+FFFD so a forged log
            // line cannot be smuggled through `--udp-multicast-interface`.
            let malicious_interface = "eth0\r\n[FORGED]";
            let snapshot =
                capture_audit(|| udp_multicast_joined("239.2.3.1:6969", malicious_interface));
            let event = parse_event(&snapshot, "udp_multicast.joined");
            let interface = event["fields"]["interface"]
                .as_str()
                .expect("interface must be a JSON string");
            assert!(
                !interface.contains('\n') && !interface.contains('\r'),
                "control bytes must not survive sanitization: {interface:?}"
            );
            assert!(
                interface.contains('\u{FFFD}'),
                "sanitized output must contain U+FFFD: {interface:?}"
            );
        }

        #[test]
        fn udp_multicast_publish_emits_documented_shape() {
            // Closes #861. Pin field shape for the rebroadcast egress
            // audit trail.
            let snapshot = capture_audit(|| udp_multicast_publish("239.2.3.1:6969", "ANDROID-1"));
            let event = parse_event(&snapshot, "udp_multicast.publish");
            assert_eq!(event["fields"]["group"], "239.2.3.1:6969");
            assert_eq!(event["fields"]["uid"], "ANDROID-1");
            assert_eq!(event["fields"]["action"], "publish");
            assert_eq!(event["fields"]["result"], "success");
        }

        #[test]
        fn udp_multicast_publish_sanitizes_uid_field() {
            // Closes #861. CoT `uid="…"` is attacker-controlled — a
            // hostile peer can craft a uid containing newlines or ANSI
            // CSI sequences. The audit boundary must replace those.
            let malicious_uid = "uid\x1b[31m[FORGED]";
            let snapshot = capture_audit(|| udp_multicast_publish("239.2.3.1:6969", malicious_uid));
            let event = parse_event(&snapshot, "udp_multicast.publish");
            let uid = event["fields"]["uid"]
                .as_str()
                .expect("uid must be a JSON string");
            assert!(
                !uid.contains('\x1b'),
                "ANSI CSI must not survive sanitization: {uid:?}"
            );
            assert!(
                uid.contains('\u{FFFD}'),
                "sanitized output must contain U+FFFD: {uid:?}"
            );
        }
    }
}
