//! NATS connection configuration.

use std::hash::{BuildHasher, Hasher};
use std::process;

/// Configuration for the NATS adapter.
#[derive(Debug, Clone)]
pub struct NatsConfig {
    /// NATS server URL (e.g., "nats://localhost:4222").
    pub url: String,

    /// Optional NATS credentials file path for JWT/NKey auth.
    pub credentials_file: Option<String>,

    /// Subject prefix for point updates (default: "points").
    pub subject_prefix: String,

    /// JetStream stream name for history replay (default: "TRACKS_HISTORY").
    pub jetstream_stream: String,

    /// JetStream subject prefix for history (default: "TRACKS.HISTORY").
    pub jetstream_subject_prefix: String,

    /// Default group name when identity has no groups (default: "__ANON__").
    pub default_group: String,

    /// Maximum NATS message payload size to deserialize (default: 256 KB).
    /// Messages larger than this are dropped as a defense-in-depth measure
    /// against resource exhaustion. NATS servers enforce their own max_payload
    /// (default 1 MB), but this provides an additional application-level guard.
    pub max_payload_bytes: usize,

    /// Maximum number of messages to replay from JetStream on startup.
    /// Limits memory consumption during SA bootstrap. 0 = unlimited.
    pub max_replay_count: usize,

    /// Instance ID for echo prevention. Auto-generated if not set.
    pub instance_id: String,
}

impl Default for NatsConfig {
    fn default() -> Self {
        Self {
            url: "nats://localhost:4222".to_string(),
            credentials_file: None,
            subject_prefix: "points".to_string(),
            jetstream_stream: "TRACKS_HISTORY".to_string(),
            jetstream_subject_prefix: "TRACKS.HISTORY".to_string(),
            default_group: "__ANON__".to_string(),
            max_payload_bytes: 256 * 1024,
            max_replay_count: 0,
            instance_id: generate_instance_id(),
        }
    }
}

/// Generate a unique instance ID using OS-seeded randomness.
///
/// Uses `RandomState` (backed by OS entropy) combined with PID and
/// nanosecond timestamp to produce a collision-resistant identifier.
fn generate_instance_id() -> String {
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u64(process::id() as u64);
    hasher.write_u64(
        std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64,
    );
    format!("rustgate-{:016x}", hasher.finish())
}
