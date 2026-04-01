//! Centralized constants for timeouts, buffer sizes, and capacity limits.
//!
//! These constants provide consistent defaults across all rustgate crates.
//! Crate-specific constants that are only used locally should remain in their
//! respective crates.

use std::time::Duration;

// ── TCP / Network ──────────────────────────────────────────────────

/// TCP keepalive idle timeout before first probe.
pub const TCP_KEEPALIVE_IDLE: Duration = Duration::from_secs(30);

/// Interval between TCP keepalive probes.
pub const TCP_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);

/// Read timeout for client connections (5 minutes).
pub const READ_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// Write timeout for client connections (30 seconds).
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

// ── TLS / Handshake ────────────────────────────────────────────────

/// Maximum time allowed for a TLS or WebSocket handshake.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum time for an HTTP connection (metrics, enrollment).
pub const HTTP_CONNECTION_TIMEOUT: Duration = Duration::from_secs(15);

// ── Protocol / Framing ─────────────────────────────────────────────

/// Maximum frame size for length-prefixed and protobuf codecs (16 MiB).
pub const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024;

// ── Federation ─────────────────────────────────────────────────────

/// Default heartbeat send interval for federation connections.
pub const FEDERATION_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);

/// Default heartbeat timeout — peer is considered dead after this.
pub const FEDERATION_HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(90);

/// Default health check interval for federation peers.
pub const FEDERATION_HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(5);

/// Maximum reconnection backoff for federation clients.
pub const FEDERATION_MAX_RECONNECT_DELAY: Duration = Duration::from_secs(300);
