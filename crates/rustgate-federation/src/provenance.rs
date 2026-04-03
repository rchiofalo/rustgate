//! Message provenance tracking for federation loop detection.
//!
//! Each federated message carries [`FederationMetadata`] recording the
//! ordered list of servers it has traversed. Before forwarding, a server
//! checks [`FederationMetadata::should_drop`] to detect loops (same server
//! seen twice) and enforce the configurable maximum hop count.

use rustgate_core::{PeerId, ServerName};
use sha2::{Digest, Sha256};

/// Tracks which federation server a message has passed through.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FederateProvenance {
    /// Unique identifier for the federation server (deterministic UUID).
    pub server_id: PeerId,
    /// Human-readable name of the federation server.
    pub server_name: ServerName,
}

/// Metadata attached to federated messages for loop detection and hop limiting.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FederationMetadata {
    /// Ordered list of servers this message has passed through.
    pub provenance: Vec<FederateProvenance>,
    /// Current number of hops this message has taken.
    pub current_hops: u32,
    /// Maximum number of hops before this message is dropped.
    pub max_hops: u32,
}

impl FederationMetadata {
    /// Create new metadata with the given max hop limit.
    pub fn new(max_hops: u32) -> Self {
        Self {
            provenance: Vec::new(),
            current_hops: 0,
            max_hops,
        }
    }

    /// Check whether this message should be dropped.
    ///
    /// Returns `true` if:
    /// - The message has already passed through the server with `my_server_id` (loop)
    /// - The message has exceeded the maximum hop count
    pub fn should_drop(&self, my_server_id: &str) -> bool {
        if self.current_hops >= self.max_hops {
            return true;
        }
        self.provenance
            .iter()
            .any(|p| p.server_id.as_str() == my_server_id)
    }

    /// Record a new hop through the given server.
    pub fn add_hop(&mut self, server_id: &str, server_name: &str) {
        self.provenance.push(FederateProvenance {
            server_id: PeerId::new(server_id),
            server_name: ServerName::new(server_name),
        });
        self.current_hops += 1;
    }
}

impl Default for FederationMetadata {
    fn default() -> Self {
        Self::new(10)
    }
}

/// Generate a deterministic UUID v4-formatted string from an input string.
///
/// Uses SHA-256 of the input and formats the first 16 bytes as a UUID,
/// setting version=4 and variant bits per RFC 4122.
pub fn deterministic_uuid(input: &str) -> String {
    let hash = Sha256::digest(input.as_bytes());
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&hash[..16]);

    // Set version 4 (bits 12-15 of time_hi_and_version)
    bytes[6] = (bytes[6] & 0x0F) | 0x40;
    // Set variant (bits 6-7 of clock_seq_hi_and_reserved)
    bytes[8] = (bytes[8] & 0x3F) | 0x80;

    format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        u16::from_be_bytes([bytes[4], bytes[5]]),
        u16::from_be_bytes([bytes[6], bytes[7]]),
        u16::from_be_bytes([bytes[8], bytes[9]]),
        // Last 6 bytes as a single hex number
        u64::from_be_bytes([
            0, 0, bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
        ]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_metadata_has_zero_hops() {
        let m = FederationMetadata::new(10);
        assert_eq!(m.current_hops, 0);
        assert_eq!(m.max_hops, 10);
        assert!(m.provenance.is_empty());
    }

    #[test]
    fn should_drop_on_loop() {
        let mut m = FederationMetadata::new(10);
        m.add_hop("server-abc", "Server ABC");
        m.add_hop("server-def", "Server DEF");

        assert!(m.should_drop("server-abc"));
        assert!(m.should_drop("server-def"));
        assert!(!m.should_drop("server-ghi"));
    }

    #[test]
    fn should_drop_on_hop_limit() {
        let mut m = FederationMetadata::new(3);
        m.add_hop("s1", "S1");
        assert!(!m.should_drop("unknown"));
        m.add_hop("s2", "S2");
        assert!(!m.should_drop("unknown"));
        m.add_hop("s3", "S3");
        // current_hops == 3, max_hops == 3 → drop
        assert!(m.should_drop("unknown"));
    }

    #[test]
    fn should_not_drop_fresh_message() {
        let m = FederationMetadata::new(10);
        assert!(!m.should_drop("any-server"));
    }

    #[test]
    fn add_hop_increments() {
        let mut m = FederationMetadata::new(10);
        m.add_hop("s1", "Server One");
        assert_eq!(m.current_hops, 1);
        assert_eq!(m.provenance.len(), 1);
        assert_eq!(m.provenance[0].server_id.as_str(), "s1");
        assert_eq!(m.provenance[0].server_name.as_str(), "Server One");

        m.add_hop("s2", "Server Two");
        assert_eq!(m.current_hops, 2);
        assert_eq!(m.provenance.len(), 2);
    }

    #[test]
    fn deterministic_uuid_is_stable() {
        let a = deterministic_uuid("test-server");
        let b = deterministic_uuid("test-server");
        assert_eq!(a, b);
    }

    #[test]
    fn deterministic_uuid_differs_for_different_input() {
        let a = deterministic_uuid("server-a");
        let b = deterministic_uuid("server-b");
        assert_ne!(a, b);
    }

    #[test]
    fn deterministic_uuid_format() {
        let uuid = deterministic_uuid("anything");
        // UUID format: 8-4-4-4-12 hex characters
        let parts: Vec<&str> = uuid.split('-').collect();
        assert_eq!(parts.len(), 5);
        assert_eq!(parts[0].len(), 8);
        assert_eq!(parts[1].len(), 4);
        assert_eq!(parts[2].len(), 4);
        assert_eq!(parts[3].len(), 4);
        assert_eq!(parts[4].len(), 12);

        // Version nibble should be '4'
        assert!(parts[2].starts_with('4'));
    }

    #[test]
    fn metadata_serde_round_trip() {
        let mut m = FederationMetadata::new(5);
        m.add_hop("s1", "Server One");
        m.add_hop("s2", "Server Two");

        let json = serde_json::to_string(&m).expect("serialize");
        let parsed: FederationMetadata = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(parsed.current_hops, 2);
        assert_eq!(parsed.max_hops, 5);
        assert_eq!(parsed.provenance.len(), 2);
        assert_eq!(parsed.provenance[0].server_id.as_str(), "s1");
    }

    #[test]
    fn default_metadata() {
        let m = FederationMetadata::default();
        assert_eq!(m.max_hops, 10);
        assert_eq!(m.current_hops, 0);
    }

    #[test]
    fn should_drop_at_exact_limit() {
        let mut m = FederationMetadata::new(1);
        m.add_hop("s1", "S1");
        // current_hops == 1, max_hops == 1 → should drop
        assert!(m.should_drop("unknown"));
    }

    #[test]
    fn should_drop_zero_max_hops() {
        let m = FederationMetadata::new(0);
        // max_hops == 0, current_hops == 0 → should drop immediately
        assert!(m.should_drop("any-server"));
    }

    #[test]
    fn should_not_drop_at_one_below_limit() {
        let mut m = FederationMetadata::new(3);
        m.add_hop("s1", "S1");
        m.add_hop("s2", "S2");
        // current_hops == 2, max_hops == 3 → should NOT drop
        assert!(!m.should_drop("unknown"));
    }

    #[test]
    fn provenance_chain_preserves_order() {
        let mut m = FederationMetadata::new(10);
        m.add_hop("first", "First Server");
        m.add_hop("second", "Second Server");
        m.add_hop("third", "Third Server");

        assert_eq!(m.provenance[0].server_id.as_str(), "first");
        assert_eq!(m.provenance[1].server_id.as_str(), "second");
        assert_eq!(m.provenance[2].server_id.as_str(), "third");

        assert_eq!(m.provenance[0].server_name.as_str(), "First Server");
        assert_eq!(m.provenance[1].server_name.as_str(), "Second Server");
        assert_eq!(m.provenance[2].server_name.as_str(), "Third Server");
    }

    #[test]
    fn should_drop_detects_loop_in_middle_of_chain() {
        let mut m = FederationMetadata::new(10);
        m.add_hop("s1", "S1");
        m.add_hop("s2", "S2");
        m.add_hop("s3", "S3");

        // s2 is in the middle of the chain
        assert!(m.should_drop("s2"));
    }

    #[test]
    fn should_drop_first_server_in_chain() {
        let mut m = FederationMetadata::new(10);
        m.add_hop("origin", "Origin");
        m.add_hop("relay", "Relay");

        assert!(m.should_drop("origin"));
    }

    #[test]
    fn should_drop_last_server_in_chain() {
        let mut m = FederationMetadata::new(10);
        m.add_hop("origin", "Origin");
        m.add_hop("relay", "Relay");

        assert!(m.should_drop("relay"));
    }

    #[test]
    fn add_hop_with_empty_strings() {
        let mut m = FederationMetadata::new(10);
        m.add_hop("", "");
        assert_eq!(m.current_hops, 1);
        assert_eq!(m.provenance[0].server_id.as_str(), "");
        assert_eq!(m.provenance[0].server_name.as_str(), "");
    }

    #[test]
    fn add_hop_with_special_characters() {
        let mut m = FederationMetadata::new(10);
        m.add_hop(
            "server/with-special_chars.v2",
            "Server: Special & Chars <v2>",
        );
        assert_eq!(
            m.provenance[0].server_id.as_str(),
            "server/with-special_chars.v2"
        );
        assert_eq!(
            m.provenance[0].server_name.as_str(),
            "Server: Special & Chars <v2>"
        );
    }

    #[test]
    fn add_hop_with_unicode() {
        let mut m = FederationMetadata::new(10);
        m.add_hop("server-日本", "サーバー");
        assert_eq!(m.provenance[0].server_id.as_str(), "server-日本");
        assert_eq!(m.provenance[0].server_name.as_str(), "サーバー");
    }

    #[test]
    fn deterministic_uuid_empty_input() {
        let uuid = deterministic_uuid("");
        // Should still produce a valid UUID format
        let parts: Vec<&str> = uuid.split('-').collect();
        assert_eq!(parts.len(), 5);
        assert_eq!(parts[0].len(), 8);
        assert_eq!(parts[4].len(), 12);
    }

    #[test]
    fn deterministic_uuid_long_input() {
        let long_input = "a".repeat(10_000);
        let uuid = deterministic_uuid(&long_input);
        let parts: Vec<&str> = uuid.split('-').collect();
        assert_eq!(parts.len(), 5);
        assert!(parts[2].starts_with('4'));
    }

    #[test]
    fn deterministic_uuid_special_characters() {
        let uuid = deterministic_uuid("hello world! @#$%^&*()");
        let parts: Vec<&str> = uuid.split('-').collect();
        assert_eq!(parts.len(), 5);
        assert!(parts[2].starts_with('4'));
    }

    #[test]
    fn deterministic_uuid_version_and_variant_bits() {
        let uuid = deterministic_uuid("test-input");
        let parts: Vec<&str> = uuid.split('-').collect();

        // Version nibble (bits 12-15 of time_hi_and_version) should be 4
        assert!(parts[2].starts_with('4'));

        // Variant (bits 6-7 of clock_seq_hi_and_reserved) should be 10xx binary
        // First char of parts[3] should be 8, 9, a, or b
        let variant_char = parts[3].chars().next().expect("non-empty variant part");
        assert!(
            variant_char == '8'
                || variant_char == '9'
                || variant_char == 'a'
                || variant_char == 'b'
        );
    }

    #[test]
    fn deterministic_uuid_all_lowercase_hex() {
        let uuid = deterministic_uuid("lowercase-check");
        // UUID should only contain lowercase hex chars and dashes
        for ch in uuid.chars() {
            assert!(ch.is_ascii_hexdigit() || ch == '-', "unexpected char: {ch}");
            if ch.is_ascii_alphabetic() {
                assert!(ch.is_ascii_lowercase(), "expected lowercase: {ch}");
            }
        }
    }

    #[test]
    fn metadata_serde_preserves_all_fields() {
        let mut m = FederationMetadata::new(7);
        m.add_hop("s1", "Server One");
        m.add_hop("s2", "Server Two");
        m.add_hop("s3", "Server Three");

        let json = serde_json::to_string(&m).expect("serialize");
        let parsed: FederationMetadata = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(parsed.current_hops, 3);
        assert_eq!(parsed.max_hops, 7);
        assert_eq!(parsed.provenance.len(), 3);
        assert_eq!(parsed.provenance[0].server_id.as_str(), "s1");
        assert_eq!(parsed.provenance[0].server_name.as_str(), "Server One");
        assert_eq!(parsed.provenance[2].server_id.as_str(), "s3");
        assert_eq!(parsed.provenance[2].server_name.as_str(), "Server Three");
    }

    #[test]
    fn metadata_serde_empty_provenance() {
        let m = FederationMetadata::new(5);
        let json = serde_json::to_string(&m).expect("serialize");
        let parsed: FederationMetadata = serde_json::from_str(&json).expect("deserialize");
        assert!(parsed.provenance.is_empty());
        assert_eq!(parsed.current_hops, 0);
        assert_eq!(parsed.max_hops, 5);
    }

    #[test]
    fn provenance_struct_equality() {
        let a = FederateProvenance {
            server_id: PeerId::new("s1"),
            server_name: ServerName::new("Server One"),
        };
        let b = FederateProvenance {
            server_id: PeerId::new("s1"),
            server_name: ServerName::new("Server One"),
        };
        assert_eq!(a, b);
    }

    #[test]
    fn provenance_struct_inequality() {
        let a = FederateProvenance {
            server_id: PeerId::new("s1"),
            server_name: ServerName::new("Server One"),
        };
        let b = FederateProvenance {
            server_id: PeerId::new("s2"),
            server_name: ServerName::new("Server Two"),
        };
        assert_ne!(a, b);
    }

    #[test]
    fn provenance_clone() {
        let original = FederateProvenance {
            server_id: PeerId::new("s1"),
            server_name: ServerName::new("Server One"),
        };
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    #[test]
    fn metadata_large_hop_chain() {
        let mut m = FederationMetadata::new(100);
        for i in 0..50 {
            m.add_hop(&format!("server-{i}"), &format!("Server {i}"));
        }
        assert_eq!(m.current_hops, 50);
        assert_eq!(m.provenance.len(), 50);
        assert!(!m.should_drop("server-99"));
        assert!(m.should_drop("server-25"));
    }

    #[test]
    fn should_drop_checks_both_loop_and_hops() {
        let mut m = FederationMetadata::new(2);
        m.add_hop("s1", "S1");
        m.add_hop("s2", "S2");

        // Should drop for loop (s1 is in chain)
        assert!(m.should_drop("s1"));
        // Should drop for hop limit (current_hops == 2 >= max_hops == 2)
        assert!(m.should_drop("unknown"));
    }
}
