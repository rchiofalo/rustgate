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
/// `obligation` is the unqualified variant name (e.g. `"MaskPoint"`) and
/// `recovery` is one of `"dropped"` or `"forwarded_unmasked"` describing
/// what the dispatcher did in response. `destination_kind` is a stable
/// tag produced by [`crate::message::Destination::kind_str`] so SIEM
/// rules can distinguish a failure on a unicast direct send from one on
/// a fan-out broadcast without inspecting the payload.
///
/// Sanitization: every `&str` parameter is sanitized at the audit
/// boundary.
pub fn authz_obligation_failed(
    subject_cn: &str,
    obligation: &str,
    error: &str,
    recovery: &str,
    source_protocol: &str,
    destination_kind: &str,
) {
    let subject_cn = s(subject_cn);
    let obligation = s(obligation);
    let error = s(error);
    let recovery = s(recovery);
    let source_protocol = s(source_protocol);
    let destination_kind = s(destination_kind);
    audit!(
        "authz.obligation_failed",
        subject_cn = %subject_cn,
        obligation = %obligation,
        error = %error,
        recovery = %recovery,
        source_protocol = %source_protocol,
        destination_kind = %destination_kind,
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
/// `destination_kind` mirrors the field on
/// [`authz_obligation_failed`] so a SIEM can pivot between the two
/// events without custom mapping.
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
) {
    let subject_cn = s(subject_cn);
    let obligation = s(obligation);
    let source_protocol = s(source_protocol);
    let destination_kind = s(destination_kind);
    audit!(
        "authz.obligation_unknown",
        subject_cn = %subject_cn,
        obligation = %obligation,
        source_protocol = %source_protocol,
        destination_kind = %destination_kind,
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
                "<point> attribute count exceeded masking budget of 64",
                "dropped",
                "tcp",
                "broadcast",
            );
            authz_obligation_failed(
                "alice",
                "MaskPoint",
                "payload is not XML",
                "forwarded_unmasked",
                "mqtt",
                "direct",
            );
        }

        #[test]
        fn test_authz_obligation_unknown() {
            authz_obligation_unknown("alice", "Quarantine", "tcp", "group");
            authz_obligation_unknown("", "", "", "");
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
    }

    mod verifier {
        use super::*;

        #[test]
        fn test_verifier_rebuild_failed() {
            verifier_rebuild_failed("root store build error: invalid cert");
            verifier_rebuild_failed("");
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
    }
}
