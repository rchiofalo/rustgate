// Copyright © 2026 Roberto Chiofalo.

//! Structured audit logging for security and compliance monitoring.
//!
//! Emits JSON-structured audit events via tracing at the `INFO` level
//! with a `target` of `"audit"`. This allows filtering audit events
//! from operational logs using tracing-subscriber layer filters.

use std::net::SocketAddr;
use std::time::SystemTime;

use crate::PeerId;

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

/// Record a client connection event.
pub fn client_connected(cn: &str, peer: SocketAddr, fingerprint: &str, session_id: u64) {
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
pub fn client_disconnected(cn: &str, session_id: u64) {
    audit!(
        "client.disconnected",
        cn = %cn,
        session_id = session_id,
        action = "disconnect",
        result = "success"
    );
}

/// Record a connection rejection (limit reached).
pub fn connection_rejected(peer: SocketAddr, reason: &str) {
    audit!(
        "client.rejected",
        peer = %peer,
        action = "connect",
        result = "rejected",
        reason = %reason
    );
}

/// Record a TLS accept error.
pub fn tls_accept_error(peer: SocketAddr, error: &str) {
    audit!(
        "client.tls_error",
        peer = %peer,
        action = "tls_handshake",
        result = "failure",
        error = %error
    );
}

/// Record a protocol negotiation outcome.
pub fn negotiation_result(cn: &str, protocol: &str, success: bool) {
    audit!(
        "client.negotiation",
        cn = %cn,
        protocol = %protocol,
        action = "negotiate",
        result = if success { "success" } else { "failure" }
    );
}

/// Record a federation peer connection event.
pub fn federation_peer_connected(peer_id: &PeerId, peer_cn: &str, direction: &str) {
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
pub fn federation_peer_disconnected(peer_id: &PeerId, reason: &str) {
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
pub fn federation_connect_failed(peer_id: &PeerId, error: &str) {
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
pub fn federation_peer_rejected(remote_addr: &str, reason: &str) {
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
pub fn federation_group_claim_rejected(peer_cn: &str, origin_cn: &str, claimed_groups: &[String]) {
    audit!(
        "federation.group_claim_rejected",
        peer_cn = %peer_cn,
        origin_cn = %origin_cn,
        claimed_count = claimed_groups.len(),
        claimed_groups = ?claimed_groups,
        action = "drop_claims",
        result = "success"
    );
}

/// Record an enrollment CSR signing event.
pub fn enrollment_signed(username: &str, client_uid: &str) {
    audit!(
        "enrollment.signed",
        username = %username,
        client_uid = %client_uid,
        action = "sign_csr",
        result = "success"
    );
}

/// Record an enrollment CSR signing failure.
pub fn enrollment_sign_failed(username: &str, client_uid: &str, error: &str) {
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
pub fn enrollment_auth_failed(peer: &str) {
    audit!(
        "enrollment.auth_failed",
        peer = %peer,
        action = "authenticate",
        result = "failure"
    );
}

/// Record a federation API configuration change.
// justification: staged for the federation config API (issue #778 follow-up)
// which lands in a separate PR; exporting it now lets callers wire the audit
// emission without a second round-trip through this crate when the feature
// flips on.
#[allow(dead_code)]
pub fn federation_config_changed(actor: &str, action: &str, peer_id: &PeerId) {
    audit!(
        "federation.config_changed",
        actor = %actor,
        peer_id = %peer_id,
        action = %action,
        result = "success"
    );
}

/// Record a CRL reload success.
pub fn crl_reload_success(count: usize, source: &str) {
    audit!(
        "crl.reloaded",
        count = count,
        source = %source,
        action = "reload",
        result = "success"
    );
}

/// Record a CRL reload failure.
pub fn crl_reload_failed(source: &str, error: &str) {
    audit!(
        "crl.reload_failed",
        source = %source,
        action = "reload",
        result = "failure",
        error = %error
    );
}

/// Record an enrollment certificate issued event.
pub fn enrollment_certificate_issued(username: &str, client_uid: &str, serial: &str) {
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
pub fn enrollment_certificate_revoked(serial: &str, reason: &str, revoked_by: &str) {
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
pub fn rate_limit_triggered(peer: &str, endpoint: &str, limit: usize) {
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
pub fn tls_handshake_failed(peer: &str, reason: &str, stage: &str) {
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
pub fn cert_rotation_success(cert_path: &str, new_serial: &str) {
    audit!(
        "cert.rotated",
        cert_path = %cert_path,
        new_serial = %new_serial,
        action = "rotate",
        result = "success"
    );
}

/// Record a failed server certificate rotation attempt.
pub fn cert_rotation_failed(cert_path: &str, error: &str) {
    audit!(
        "cert.rotation_failed",
        cert_path = %cert_path,
        error = %error,
        action = "rotate",
        result = "failure"
    );
}

/// Record a successful SPIFFE X.509-SVID refresh from the Workload API.
pub fn spiffe_svid_refresh_success(spiffe_id: &str, trust_domain: &str, expiry_unix: i64) {
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
pub fn spiffe_svid_refresh_failure(error: &str) {
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
    audit!(
        "authz.denied",
        subject_cn = %subject_cn,
        subject_fingerprint = %subject_fingerprint,
        action = %action,
        resource_kind = %resource_kind,
        resource_id = %resource_id,
        rule_id = rule_id.unwrap_or(""),
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
pub fn authz_classified_delivery(
    subject_cn: &str,
    recipient_cn: &str,
    action: &str,
    resource_kind: &str,
    resource_id: &str,
    rule_id: Option<&str>,
    policy_id: &str,
) {
    audit!(
        "authz.classified_delivery",
        subject_cn = %subject_cn,
        recipient_cn = %recipient_cn,
        action = %action,
        resource_kind = %resource_kind,
        resource_id = %resource_id,
        rule_id = rule_id.unwrap_or(""),
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
pub fn authz_obligation_failed(
    subject_cn: &str,
    obligation: &str,
    error: &str,
    recovery: &str,
    source_protocol: &str,
    destination_kind: &str,
) {
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
/// [`Obligation`]: https://docs.rs/rustgate-authz
pub fn authz_obligation_unknown(
    subject_cn: &str,
    obligation: &str,
    source_protocol: &str,
    destination_kind: &str,
) {
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
pub fn authz_reload_success(path: &str, policy_id: &str, rule_count: usize) {
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
pub fn authz_reload_failed(path: &str, stage: &str, error: &str) {
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
pub fn chain_discontinuity(
    audit_path: &str,
    anchor_tip: &str,
    live_tip: &str,
    action: &str,
    reason: &str,
) {
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
pub fn chain_anchor_persisted(audit_path: &str, tip: &str) {
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
/// [`ChainContinuity::NoAnchor`]: crate::audit_chain::ChainContinuity::NoAnchor
pub fn chain_anchor_persist_failed(audit_path: &str, error: &str) {
    audit!(
        "audit.chain_anchor_persist_failed",
        audit_path = %audit_path,
        error = %error,
        action = "persist_anchor",
        result = "failure"
    );
}

/// Record server startup.
pub fn server_started(bind: &str, version: &str) {
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
pub fn http_publish_failed(target: &str, status: u16, error: &str) {
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
pub fn http_circuit_tripped(target: &str) {
    audit!(
        "http.circuit_tripped",
        target = %target,
        action = "circuit_breaker",
        result = "tripped"
    );
}

/// Record a circuit breaker recovering for an HTTP target.
pub fn http_circuit_recovered(target: &str) {
    audit!(
        "http.circuit_recovered",
        target = %target,
        action = "circuit_breaker",
        result = "recovered"
    );
}

/// Record a failed TLS verifier rebuild after trust store change.
pub fn verifier_rebuild_failed(error: &str) {
    audit!(
        "verifier.rebuild_failed",
        error = %error,
        action = "rebuild_verifier",
        result = "failed"
    );
}

/// Record a store-forward message drop due to writer channel overflow.
pub fn store_forward_dropped(cn: &str, reason: &str) {
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
pub fn store_forward_key_rotated(path: &str, depth: u64, reason: &str) {
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
pub fn store_forward_drain_panic(session_hash: &str, error: &str) {
    audit!(
        "store_forward.drain_panic",
        session = %session_hash,
        error = %error,
        action = "drain_queue",
        result = "panic"
    );
}

/// Record a message being shed by per-target rate limiting.
pub fn http_rate_limited(target: &str, source_cn: &str) {
    audit!(
        "http.rate_limited",
        target = %target,
        source_cn = %source_cn,
        action = "rate_limit",
        result = "shed"
    );
}

/// Record a dead-letter queue write failure.
pub fn http_dlq_failed(target: &str, error: &str) {
    audit!(
        "http.dlq_failed",
        target = %target,
        error = %error,
        action = "dead_letter",
        result = "failure"
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
pub fn mavlink_unsigned_rejected(peer: &str) {
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
pub fn mavlink_v1_rejected(peer: &str) {
    audit!(
        "mavlink.v1_rejected",
        peer = %peer,
        action = "frame_decode",
        result = "rejected",
        reason = "v1_not_allowed"
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
    }
}
