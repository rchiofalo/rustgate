//! High-availability (HA) support for federation in multi-pod deployments.
//!
//! Provides distributed peer ownership via NATS KV claims and cross-pod
//! connection tracking. Ensures exactly one pod manages each outbound
//! peer connection.
//!
//! Requires the `ha` feature flag.

pub mod claims;
pub mod registry;

/// Default TTL for KV claims (seconds).
pub const CLAIM_TTL_SECS: u64 = 30;

/// Default refresh interval for claims (seconds).
pub const REFRESH_INTERVAL_SECS: u64 = 10;

/// Maximum jitter for adoption attempts (milliseconds).
pub const MAX_ADOPT_JITTER_MS: u64 = 5000;

/// Delay before connecting to an adopted peer (seconds).
///
/// Gives the remote TAK Server time to clean up the old connection.
pub const ADOPT_DELAY_SECS: u64 = 30;
