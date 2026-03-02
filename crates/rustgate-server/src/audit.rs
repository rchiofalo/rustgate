//! Structured audit logging for security and compliance monitoring.
//!
//! Emits JSON-structured audit events via tracing at the `INFO` level
//! with a `target` of `"audit"`. This allows filtering audit events
//! from operational logs using tracing-subscriber layer filters.

use std::net::SocketAddr;
use std::time::SystemTime;

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
pub fn client_connected(cn: &str, peer: SocketAddr, fingerprint: &str) {
    audit!(
        "client.connected",
        cn = %cn,
        peer = %peer,
        fingerprint = %fingerprint,
        action = "connect",
        result = "success"
    );
}

/// Record a client disconnection event.
pub fn client_disconnected(cn: &str) {
    audit!(
        "client.disconnected",
        cn = %cn,
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
pub fn federation_peer_connected(peer_id: &str, peer_cn: &str, direction: &str) {
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
pub fn federation_peer_disconnected(peer_id: &str, reason: &str) {
    audit!(
        "federation.disconnected",
        peer_id = %peer_id,
        action = "disconnect",
        reason = %reason
    );
}

/// Record a federation connection failure.
pub fn federation_connect_failed(peer_id: &str, error: &str) {
    audit!(
        "federation.connect_failed",
        peer_id = %peer_id,
        action = "connect",
        result = "failure",
        error = %error
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
pub fn federation_config_changed(actor: &str, action: &str, peer_id: &str) {
    audit!(
        "federation.config_changed",
        actor = %actor,
        peer_id = %peer_id,
        action = %action,
        result = "success"
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 12345)
    }

    #[test]
    fn client_connected_does_not_panic() {
        // Verify audit functions don't panic when tracing isn't initialized
        client_connected("test-cn", test_addr(), "abc123");
    }

    #[test]
    fn client_disconnected_does_not_panic() {
        client_disconnected("test-cn");
    }

    #[test]
    fn connection_rejected_does_not_panic() {
        connection_rejected(test_addr(), "limit reached");
    }

    #[test]
    fn tls_accept_error_does_not_panic() {
        tls_accept_error(test_addr(), "handshake failed");
    }

    #[test]
    fn negotiation_result_does_not_panic() {
        negotiation_result("test-cn", "protobuf", true);
        negotiation_result("test-cn", "xml", false);
    }

    #[test]
    fn federation_peer_connected_does_not_panic() {
        federation_peer_connected("peer-1", "peer-cn", "inbound");
    }

    #[test]
    fn federation_peer_disconnected_does_not_panic() {
        federation_peer_disconnected("peer-1", "clean");
    }

    #[test]
    fn federation_connect_failed_does_not_panic() {
        federation_connect_failed("peer-1", "connection refused");
    }

    #[test]
    fn enrollment_signed_does_not_panic() {
        enrollment_signed("admin", "client-uid-123");
    }

    #[test]
    fn enrollment_sign_failed_does_not_panic() {
        enrollment_sign_failed("admin", "client-uid-123", "invalid CSR");
    }

    #[test]
    fn enrollment_auth_failed_does_not_panic() {
        enrollment_auth_failed("10.0.0.1:12345");
    }

    #[test]
    fn federation_config_changed_does_not_panic() {
        federation_config_changed("api", "create", "peer-1");
    }

    #[test]
    fn server_started_does_not_panic() {
        server_started("0.0.0.0:4433", "0.1.0");
    }
}
