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

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn keepalive_does_not_fail_on_tcp_listener() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        configure_tcp_keepalive(&listener);
    }
}
