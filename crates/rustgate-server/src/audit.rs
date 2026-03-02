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
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn v4_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 12345)
    }

    fn v6_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 9443)
    }

    #[test]
    fn test_client_connected() {
        client_connected("alpha-cn", v4_addr(), "sha256:abc123def456");
        client_connected("", v6_addr(), "");
        client_connected("cn/with-special.chars", v4_addr(), &"f".repeat(128));
    }

    #[test]
    fn test_client_disconnected() {
        client_disconnected("alpha-cn");
        client_disconnected("");
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
            federation_peer_connected("peer-1", "peer-cn", "inbound");
            federation_peer_connected("peer-2", "remote-server", "outbound");
        }

        #[test]
        fn test_peer_disconnected() {
            federation_peer_disconnected("peer-1", "clean shutdown");
            federation_peer_disconnected("peer-1", "");
        }

        #[test]
        fn test_connect_failed() {
            federation_connect_failed("peer-1", "connection refused");
            federation_connect_failed("peer-2", "tls: certificate verify failed");
        }

        #[test]
        fn test_config_changed() {
            federation_config_changed("api", "create", "peer-1");
            federation_config_changed("admin", "delete", "peer-2");
            federation_config_changed("api", "update", "peer-3");
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
}
