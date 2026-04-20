// Copyright © 2026 Roberto Chiofalo.

//! Centralized constants for timeouts, buffer sizes, and capacity limits.
//!
//! These constants provide consistent defaults across all rustgate crates.
//! Crate-specific constants that are only used locally should remain in their
//! respective crates.

use std::time::Duration;

// ── TCP / Network ──────────────────────────────────────────────────

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

// ── Client ─────────────────────────────────────────────────────────

/// Maximum reconnection backoff for long-lived client connections.
///
/// Caps the exponential-backoff schedule in
/// `rustgate_client::ReconnectPolicy::default()`. 30 seconds keeps
/// recovery snappy after a brief server restart while still shedding
/// load from an overloaded backend — noticeably tighter than the 5-min
/// federation ceiling because interactive clients are more sensitive
/// to reconnect latency than server-to-server links.
pub const CLIENT_MAX_RECONNECT_DELAY: Duration = Duration::from_secs(30);

// ── Identity / Plaintext ──────────────────────────────────────────

/// Default group assigned to plaintext (TCP/UDP) connections.
pub const PLAINTEXT_GROUP: &str = "__plaintext__";

/// Default common name for anonymous plaintext clients.
pub const ANONYMOUS_IDENTITY: &str = "anonymous";

/// Returns `true` when `name` matches the reserved-sentinel identifier
/// shape `__*__` — starts with `__`, ends with `__`, and is at least
/// four bytes long (so the prefix and suffix cannot overlap).
///
/// rustgate reserves this byte-shape for transport-layer synthetic
/// group names that are never populated from a user cert:
///
/// * [`PLAINTEXT_GROUP`] (`"__plaintext__"`) — the group plaintext
///   TCP/UDP sessions join, since they present no mTLS identity.
/// * `__ANON__` — the federation/NATS default group for anonymous
///   ingress on bridges.
/// * `__default__` — the tenant-quota fallback key in
///   [`rustgate_transport::quota`](../rustgate_transport/quota/).
///
/// Operator-facing policy surfaces (the group ACL JSON file, its hot
/// reload path, and the REST ACL API in `rustgate_server::acl_api`)
/// reject any group-identifier key that matches this shape. A policy
/// keyed by `__plaintext__` (or any other sentinel) is almost never
/// what the operator intended — it either shadows the synthetic
/// group's meaning or is indistinguishable from a user-defined group
/// to the PEP, so it has to be rejected at configuration time rather
/// than silently accepted into the ACL map.
///
/// The check is byte-shape-based rather than an explicit allow list
/// so a future transport-internal sentinel does not create a silent
/// ACL-namespace collision the moment it's added.
///
/// # Examples
///
/// ```
/// use rustgate_core::constants::is_reserved_group_id;
///
/// assert!(is_reserved_group_id("__plaintext__"));
/// assert!(is_reserved_group_id("__ANON__"));
/// assert!(is_reserved_group_id("____")); // minimum 4-byte sentinel
///
/// assert!(!is_reserved_group_id("plaintext"));
/// assert!(!is_reserved_group_id("__half"));
/// assert!(!is_reserved_group_id("half__"));
/// assert!(!is_reserved_group_id("___")); // 3 bytes: prefix/suffix overlap
/// assert!(!is_reserved_group_id(""));
/// ```
pub fn is_reserved_group_id(name: &str) -> bool {
    name.len() >= 4 && name.starts_with("__") && name.ends_with("__")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserved_group_id_matches_known_sentinels() {
        assert!(is_reserved_group_id(PLAINTEXT_GROUP));
        assert!(is_reserved_group_id("__ANON__"));
        assert!(is_reserved_group_id("__default__"));
    }

    #[test]
    fn reserved_group_id_requires_four_bytes_minimum() {
        // "____" is the shortest genuinely-bounded sentinel — 2 bytes
        // of prefix and 2 of suffix with nothing between them still
        // makes the intent unambiguous.
        assert!(is_reserved_group_id("____"));
        // "___" cannot possibly be sentinel-shaped because the prefix
        // and suffix would have to overlap.
        assert!(!is_reserved_group_id("___"));
        assert!(!is_reserved_group_id("__"));
        assert!(!is_reserved_group_id("_"));
        assert!(!is_reserved_group_id(""));
    }

    #[test]
    fn reserved_group_id_rejects_half_matches() {
        // Only one side of the sentinel bookend — an ordinary name
        // that happens to start or end with underscores.
        assert!(!is_reserved_group_id("__prefix_only"));
        assert!(!is_reserved_group_id("suffix_only__"));
        assert!(!is_reserved_group_id("_single_underscore_"));
    }

    #[test]
    fn reserved_group_id_accepts_ordinary_names() {
        for name in ["alpha", "ops", "team.red", "tenant:42", "a-b", "a_b"] {
            assert!(
                !is_reserved_group_id(name),
                "ordinary name {name:?} must not be treated as a sentinel"
            );
        }
    }

    #[test]
    fn reserved_group_id_is_case_sensitive_on_the_interior() {
        // The prefix/suffix are literal `__` bytes; interior bytes
        // are opaque. Mixed case inside a sentinel is still a sentinel.
        assert!(is_reserved_group_id("__MixedCase__"));
        assert!(is_reserved_group_id("__42__"));
    }
}
