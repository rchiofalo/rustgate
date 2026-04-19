// Copyright © 2026 Roberto Chiofalo.

//! Network utilities shared across rustgate crates.

use std::os::fd::AsFd;
use std::time::Duration;

/// TCP keepalive idle time before the first probe.
const TCP_KEEPALIVE_IDLE: Duration = Duration::from_secs(30);

/// Interval between TCP keepalive probes after the idle period.
const TCP_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);

/// Configure TCP keepalive on a socket to detect dead connections.
///
/// Sets idle time to 30 seconds and probe interval to 10 seconds.
/// Logs a warning if the options cannot be applied.
pub fn configure_tcp_keepalive(stream: &impl AsFd) {
    let sock_ref = socket2::SockRef::from(stream);
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(TCP_KEEPALIVE_IDLE)
        .with_interval(TCP_KEEPALIVE_INTERVAL);
    if let Err(e) = sock_ref.set_tcp_keepalive(&keepalive) {
        tracing::warn!(error = %e, "failed to set TCP keepalive");
    }
}

/// Disable Nagle's algorithm on a socket (`TCP_NODELAY = 1`).
///
/// rustgate's primary traffic pattern is small interactive messages
/// (tactical CoT position updates: 200–800 bytes, mTLS handshakes,
/// federation control RPCs, WebSocket frames). With Nagle enabled, a
/// small write followed by a flush interacts with the peer's delayed-ACK
/// timer (`TCP_DELACK_MIN = 40 ms` on Linux) and adds a full RTT-scale
/// penalty per message. Disabling Nagle trades away the bundling
/// optimization — appropriate for an interactive message bus, not for
/// bulk transfers.
///
/// Logs a warning if the option cannot be applied; callers treat the
/// failure as non-fatal because the socket remains usable (merely with a
/// latency penalty the caller has already accepted by using TCP).
pub fn configure_tcp_nodelay(stream: &impl AsFd) {
    let sock_ref = socket2::SockRef::from(stream);
    if let Err(e) = sock_ref.set_tcp_nodelay(true) {
        tracing::warn!(error = %e, "failed to set TCP_NODELAY");
    }
}

/// Apply the rustgate tactical-socket defaults: keepalive + `TCP_NODELAY`.
///
/// Call this on every accepted or dialed TCP stream before handing it off
/// to TLS, a codec, or a protocol adapter. Combining both helpers behind
/// a single call prevents drift where a new transport adds keepalive but
/// forgets Nagle-disable (which was the F-151 / #745 regression across
/// every listener and client dial).
pub fn configure_tactical_socket(stream: &impl AsFd) {
    configure_tcp_keepalive(stream);
    configure_tcp_nodelay(stream);
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn keepalive_does_not_fail_on_tcp_listener() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        configure_tcp_keepalive(&listener);
    }

    #[test]
    fn nodelay_sets_flag_on_accepted_socket() {
        use socket2::SockRef;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = std::net::TcpStream::connect(addr).unwrap();
        let (server, _) = listener.accept().unwrap();

        configure_tcp_nodelay(&server);
        configure_tcp_nodelay(&client);

        assert!(SockRef::from(&server).tcp_nodelay().unwrap());
        assert!(SockRef::from(&client).tcp_nodelay().unwrap());
    }

    #[test]
    fn tactical_socket_applies_both_options() {
        use socket2::SockRef;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let _client = std::net::TcpStream::connect(addr).unwrap();
        let (server, _) = listener.accept().unwrap();

        configure_tactical_socket(&server);

        // TCP_NODELAY is observable via socket2; keepalive is set but not
        // readable via a single portable API — verifying it does not
        // error is the extent of what we can assert cross-platform.
        assert!(SockRef::from(&server).tcp_nodelay().unwrap());
    }
}
