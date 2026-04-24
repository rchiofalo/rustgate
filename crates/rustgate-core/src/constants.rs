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

    // ── Constant-value pins ────────────────────────────────────────
    //
    // These constants are advertised as the workspace's single source of
    // truth in `CLAUDE.md` ("Shared Constants" table in
    // shared-infrastructure.md) and referenced by name across all 16
    // crates. Pinning the exact values defends against silent drift
    // during refactors: an accidental edit to one of these values would
    // propagate to every call site without any test failure in the
    // touched crate.

    #[test]
    fn read_timeout_pins_to_five_minutes() {
        // Advertised value: 5 min. Used as the per-connection read
        // deadline across TLS, plaintext, WebSocket, MQTT, enrollment,
        // and federation listeners.
        assert_eq!(READ_TIMEOUT, Duration::from_secs(5 * 60));
        assert_eq!(READ_TIMEOUT.as_secs(), 300);
    }

    #[test]
    fn write_timeout_pins_to_thirty_seconds() {
        // Advertised value: 30s. Write side is much shorter than read
        // because a slow consumer should be evicted rather than allowed
        // to block the writer indefinitely.
        assert_eq!(WRITE_TIMEOUT, Duration::from_secs(30));
    }

    #[test]
    fn handshake_timeout_pins_to_ten_seconds() {
        // Advertised value: 10s. Bounds both the TLS handshake and the
        // WebSocket HTTP/1.1 upgrade — a client that can't complete
        // either in 10 s is either misconfigured or adversarial.
        assert_eq!(HANDSHAKE_TIMEOUT, Duration::from_secs(10));
    }

    #[test]
    fn http_connection_timeout_pins_to_fifteen_seconds() {
        // Advertised value: 15s. Covers the metrics scraper and the
        // enrollment HTTP endpoints — slightly looser than the TLS
        // handshake timeout because it includes both the handshake
        // and the HTTP request/response round-trip.
        assert_eq!(HTTP_CONNECTION_TIMEOUT, Duration::from_secs(15));
    }

    #[test]
    fn max_frame_size_pins_to_sixteen_mib() {
        // Advertised value: 16 MiB. Caps inbound frame size for
        // length-prefixed and protobuf codecs — prevents an adversarial
        // peer from exhausting memory with an oversized length header.
        assert_eq!(MAX_FRAME_SIZE, 16 * 1024 * 1024);
        assert_eq!(MAX_FRAME_SIZE, 16_777_216);
    }

    #[test]
    fn federation_heartbeat_interval_pins_to_thirty_seconds() {
        assert_eq!(FEDERATION_HEARTBEAT_INTERVAL, Duration::from_secs(30));
    }

    #[test]
    fn federation_heartbeat_timeout_pins_to_ninety_seconds() {
        // 90s = 3× the interval, so two consecutive heartbeat drops are
        // tolerated before a peer is marked dead. See the cross-constant
        // invariant below (`federation_heartbeat_timeout_tolerates_three_intervals`).
        assert_eq!(FEDERATION_HEARTBEAT_TIMEOUT, Duration::from_secs(90));
    }

    #[test]
    fn federation_health_check_interval_pins_to_five_seconds() {
        assert_eq!(FEDERATION_HEALTH_CHECK_INTERVAL, Duration::from_secs(5));
    }

    #[test]
    fn federation_max_reconnect_delay_pins_to_five_minutes() {
        // Advertised value: 5 min. Caps the exponential-backoff schedule
        // for federation reconnect — higher than the client ceiling
        // because server-to-server links are less latency-sensitive.
        assert_eq!(FEDERATION_MAX_RECONNECT_DELAY, Duration::from_secs(300));
    }

    #[test]
    fn client_max_reconnect_delay_pins_to_thirty_seconds() {
        // Advertised value: 30s. Keeps interactive client reconnect
        // snappy after a brief server restart.
        assert_eq!(CLIENT_MAX_RECONNECT_DELAY, Duration::from_secs(30));
    }

    #[test]
    fn plaintext_group_sentinel_pins_to_double_underscore_literal() {
        // This exact byte string is the key used by `plaintext.rs` and
        // matched by `is_reserved_group_id`. Any edit that breaks the
        // double-underscore wrap would silently break ACL admission for
        // plaintext sessions.
        assert_eq!(PLAINTEXT_GROUP, "__plaintext__");
    }

    #[test]
    fn anonymous_identity_pins_to_lowercase_literal() {
        // Advertised value: `"anonymous"`. Used as the CN for
        // unauthenticated plaintext sessions. Lowercase is deliberate —
        // CN normalization in the transport lowercases the cert CN, so
        // the synthetic value must match that convention.
        assert_eq!(ANONYMOUS_IDENTITY, "anonymous");
    }

    // ── Cross-constant invariants ──────────────────────────────────
    //
    // Pinning individual values is not enough: these constants have
    // to make sense together. An edit that flips any of these
    // orderings (for example, HEARTBEAT_TIMEOUT < HEARTBEAT_INTERVAL)
    // would build and pass the per-constant pins above, but break
    // the runtime semantics they describe.

    #[test]
    fn read_timeout_exceeds_write_timeout() {
        // Reads are long-lived (waiting for next message on an idle
        // connection). Writes are bounded (never block the writer on
        // a slow consumer). Flipping this ordering would cause either
        // premature idle disconnects or stuck writers.
        assert!(
            READ_TIMEOUT > WRITE_TIMEOUT,
            "READ_TIMEOUT must exceed WRITE_TIMEOUT: read={READ_TIMEOUT:?}, write={WRITE_TIMEOUT:?}",
        );
    }

    #[test]
    fn handshake_timeout_bounded_below_read_timeout() {
        // Handshake must fail fast so a stalled TLS negotiation cannot
        // consume a read slot for 5 min.
        assert!(
            HANDSHAKE_TIMEOUT < READ_TIMEOUT,
            "HANDSHAKE_TIMEOUT must be < READ_TIMEOUT",
        );
    }

    #[test]
    fn handshake_timeout_bounded_below_http_connection_timeout() {
        // HTTP connection timeout covers the TLS handshake plus the
        // request/response exchange — so handshake must be strictly
        // shorter.
        assert!(
            HANDSHAKE_TIMEOUT < HTTP_CONNECTION_TIMEOUT,
            "HANDSHAKE_TIMEOUT ({HANDSHAKE_TIMEOUT:?}) must be < HTTP_CONNECTION_TIMEOUT ({HTTP_CONNECTION_TIMEOUT:?})",
        );
    }

    #[test]
    fn federation_heartbeat_timeout_tolerates_three_intervals() {
        // The heartbeat scheme needs to tolerate at least two consecutive
        // lost heartbeats before declaring a peer dead. With
        // interval=30 s and timeout=90 s, a peer has to miss three
        // consecutive sends (or have its clock skew by >60 s) to be
        // declared dead. Dropping this ratio below 3× would cause
        // federation flap on ordinary packet loss.
        assert!(
            FEDERATION_HEARTBEAT_TIMEOUT >= FEDERATION_HEARTBEAT_INTERVAL * 3,
            "heartbeat timeout ({FEDERATION_HEARTBEAT_TIMEOUT:?}) must tolerate ≥3 intervals ({FEDERATION_HEARTBEAT_INTERVAL:?})",
        );
    }

    #[test]
    fn federation_health_check_fires_multiple_times_per_heartbeat() {
        // Health check must run faster than the heartbeat interval so
        // the supervisor sees fresh state between heartbeats. The
        // advertised 5s/30s ratio gives 6 samples per heartbeat window.
        assert!(
            FEDERATION_HEALTH_CHECK_INTERVAL < FEDERATION_HEARTBEAT_INTERVAL,
            "health check ({FEDERATION_HEALTH_CHECK_INTERVAL:?}) must be < heartbeat interval ({FEDERATION_HEARTBEAT_INTERVAL:?})",
        );
    }

    #[test]
    fn federation_health_check_bounded_below_heartbeat_timeout() {
        // The supervisor must sample the peer's state before the dead-
        // peer detector fires — otherwise a missed heartbeat cannot be
        // acted on.
        assert!(
            FEDERATION_HEALTH_CHECK_INTERVAL < FEDERATION_HEARTBEAT_TIMEOUT,
            "health check must fire faster than peer-dead detection",
        );
    }

    #[test]
    fn federation_reconnect_delay_exceeds_client_reconnect_delay() {
        // Per the module docstring on CLIENT_MAX_RECONNECT_DELAY:
        // interactive clients are more latency-sensitive than
        // server-to-server federation links, so the federation ceiling
        // is deliberately higher.
        assert!(
            FEDERATION_MAX_RECONNECT_DELAY > CLIENT_MAX_RECONNECT_DELAY,
            "federation reconnect ceiling ({FEDERATION_MAX_RECONNECT_DELAY:?}) must exceed client ceiling ({CLIENT_MAX_RECONNECT_DELAY:?})",
        );
    }

    #[test]
    fn every_duration_constant_is_non_zero() {
        // Defends against an accidental `Duration::ZERO` or `from_secs(0)`
        // edit that would disable a timeout rather than set it.
        for (name, d) in [
            ("READ_TIMEOUT", READ_TIMEOUT),
            ("WRITE_TIMEOUT", WRITE_TIMEOUT),
            ("HANDSHAKE_TIMEOUT", HANDSHAKE_TIMEOUT),
            ("HTTP_CONNECTION_TIMEOUT", HTTP_CONNECTION_TIMEOUT),
            (
                "FEDERATION_HEARTBEAT_INTERVAL",
                FEDERATION_HEARTBEAT_INTERVAL,
            ),
            ("FEDERATION_HEARTBEAT_TIMEOUT", FEDERATION_HEARTBEAT_TIMEOUT),
            (
                "FEDERATION_HEALTH_CHECK_INTERVAL",
                FEDERATION_HEALTH_CHECK_INTERVAL,
            ),
            (
                "FEDERATION_MAX_RECONNECT_DELAY",
                FEDERATION_MAX_RECONNECT_DELAY,
            ),
            ("CLIENT_MAX_RECONNECT_DELAY", CLIENT_MAX_RECONNECT_DELAY),
        ] {
            assert!(!d.is_zero(), "{name} must be non-zero; got {d:?}");
        }
    }

    #[test]
    fn max_frame_size_exceeds_one_mib_floor() {
        // Sanity floor: a 16-bit length prefix (~65 KiB) would be too
        // small for any realistic federation message. If this drops
        // below 1 MiB, something has gone badly wrong in the edit.
        //
        // A const-block assertion runs at compile time, so a regression
        // that drops MAX_FRAME_SIZE below 1 MiB fails the build rather
        // than waiting for test execution.
        const { assert!(MAX_FRAME_SIZE >= 1024 * 1024) };
    }

    // ── Sentinel interaction with `is_reserved_group_id` ───────────

    #[test]
    fn plaintext_group_constant_matches_reserved_shape() {
        // Belt-and-braces check: the sentinel constant that the ACL
        // rejecter is supposed to catch actually matches the rejecter.
        // A future rename of either value would break this pairing.
        assert!(
            is_reserved_group_id(PLAINTEXT_GROUP),
            "PLAINTEXT_GROUP ({PLAINTEXT_GROUP:?}) must match is_reserved_group_id",
        );
    }

    #[test]
    fn anonymous_identity_is_not_reserved_group_shape() {
        // `ANONYMOUS_IDENTITY` is a CN (subject identifier), not a
        // group ID. Its byte shape must NOT collide with the reserved
        // group namespace — otherwise an operator who typed `anonymous`
        // as a group would be rejected unexpectedly.
        assert!(
            !is_reserved_group_id(ANONYMOUS_IDENTITY),
            "ANONYMOUS_IDENTITY ({ANONYMOUS_IDENTITY:?}) must NOT match is_reserved_group_id",
        );
    }

    #[test]
    fn plaintext_and_anonymous_sentinels_are_disjoint() {
        // The two advertised synthetic values live in different
        // namespaces (group vs CN) and must not be equal — a merge
        // would make the group-vs-identity distinction ambiguous in
        // log lines and audit records.
        assert_ne!(PLAINTEXT_GROUP, ANONYMOUS_IDENTITY);
    }
}
