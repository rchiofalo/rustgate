// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

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

    #[test]
    fn keepalive_idle_and_interval_constants_pin_rustgate_defaults() {
        // Pin the keepalive timing contract so an accidental edit of the
        // durations at the top of the file fails here rather than silently
        // shifting every production TCP listener onto a different dead-
        // connection detection curve. 30s idle + 10s interval means a
        // genuinely dead peer is detected in ≈40s-plus, which is the shape
        // rustgate's tactical deployments (NAT middleboxes with short UDP
        // timeouts, flaky satcom) depend on; doubling the idle time would
        // halve the liveness signal and push dead-peer cleanup past the
        // federation-heartbeat budget (see FEDERATION_HEARTBEAT_TIMEOUT).
        assert_eq!(super::TCP_KEEPALIVE_IDLE, Duration::from_secs(30));
        assert_eq!(super::TCP_KEEPALIVE_INTERVAL, Duration::from_secs(10));
    }

    #[test]
    fn tcp_nodelay_starts_disabled_so_configure_is_not_a_no_op() {
        use socket2::SockRef;

        // Defensive: if a future OS ever ships sockets with Nagle already
        // disabled by default, every nodelay assertion in this file would
        // become vacuously true (passes whether or not the helper runs).
        // This test fails loudly in that case so we know to redesign the
        // positive-path tests rather than trust them silently.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = std::net::TcpStream::connect(addr).unwrap();
        let (server, _) = listener.accept().unwrap();

        assert!(
            !SockRef::from(&server).tcp_nodelay().unwrap(),
            "fresh accepted TCP sockets should have Nagle enabled (TCP_NODELAY=false)"
        );
        assert!(
            !SockRef::from(&client).tcp_nodelay().unwrap(),
            "fresh connected TCP sockets should have Nagle enabled (TCP_NODELAY=false)"
        );
    }

    #[test]
    fn configure_tcp_keepalive_enables_so_keepalive_flag() {
        use socket2::SockRef;

        // The keepalive helper is the load-bearing half of the dead-peer
        // signal — `configure_tactical_socket` explicitly composes it
        // with nodelay, and every accepted TCP stream in the workspace
        // routes through one of those two entry points. Pin that the
        // SO_KEEPALIVE flag is actually set (cross-platform accessor),
        // not just that the call did not error.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = std::net::TcpStream::connect(addr).unwrap();
        let (server, _) = listener.accept().unwrap();

        // Sanity: fresh sockets do not have SO_KEEPALIVE enabled, so a
        // helper that silently no-ops would be caught here.
        assert!(
            !SockRef::from(&server).keepalive().unwrap(),
            "fresh accepted TCP sockets should have SO_KEEPALIVE disabled by default"
        );

        configure_tcp_keepalive(&server);
        configure_tcp_keepalive(&client);

        assert!(
            SockRef::from(&server).keepalive().unwrap(),
            "configure_tcp_keepalive must enable SO_KEEPALIVE on the server socket"
        );
        assert!(
            SockRef::from(&client).keepalive().unwrap(),
            "configure_tcp_keepalive must enable SO_KEEPALIVE on the client socket"
        );
    }

    #[test]
    fn tactical_socket_enables_both_so_keepalive_and_tcp_nodelay_observably() {
        use socket2::SockRef;

        // End-to-end pin on the combined helper: the F-151 / #745
        // regression was that listeners set keepalive but forgot
        // `TCP_NODELAY`, paying a ~40ms Nagle+DELACK penalty per
        // tactical message. `configure_tactical_socket` exists precisely
        // to make the "keepalive + nodelay" pair atomic at every call
        // site, so we must assert both observables after a single call.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let _client = std::net::TcpStream::connect(addr).unwrap();
        let (server, _) = listener.accept().unwrap();

        configure_tactical_socket(&server);

        let sock = SockRef::from(&server);
        assert!(
            sock.keepalive().unwrap(),
            "configure_tactical_socket must enable SO_KEEPALIVE"
        );
        assert!(
            sock.tcp_nodelay().unwrap(),
            "configure_tactical_socket must enable TCP_NODELAY"
        );
    }

    #[test]
    fn tactical_socket_is_idempotent_on_repeated_calls() {
        use socket2::SockRef;

        // The helpers are called by shared code paths (session spawns,
        // cert reloads, reconnection loops) that can plausibly run more
        // than once against the same live socket; there is no "has it
        // been configured" gate, so the contract is that calling the
        // helper twice is a safe no-op rather than toggling any flag.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let _client = std::net::TcpStream::connect(addr).unwrap();
        let (server, _) = listener.accept().unwrap();

        configure_tactical_socket(&server);
        configure_tactical_socket(&server);
        configure_tactical_socket(&server);

        let sock = SockRef::from(&server);
        assert!(
            sock.keepalive().unwrap(),
            "SO_KEEPALIVE should remain enabled after repeated configure calls"
        );
        assert!(
            sock.tcp_nodelay().unwrap(),
            "TCP_NODELAY should remain enabled after repeated configure calls"
        );
    }

    #[test]
    fn tactical_socket_accepts_both_tcp_listener_and_tcp_stream_via_as_fd_bound() {
        // Compile-time + runtime assertion that the `impl AsFd` bound
        // accepts every type the workspace passes in. If a future
        // refactor narrowed the bound to `&TcpStream`, the callers that
        // pass a `TcpListener` (e.g. server/metrics.rs, enrollment/server.rs)
        // would fail to compile, but not via this module's own suite —
        // this test is the load-bearing self-check that the generic
        // bound stays wide enough for every call site in the workspace.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        configure_tactical_socket(&listener);

        let addr = listener.local_addr().unwrap();
        let client = std::net::TcpStream::connect(addr).unwrap();
        let (server, _) = listener.accept().unwrap();
        configure_tactical_socket(&client);
        configure_tactical_socket(&server);
    }
}
