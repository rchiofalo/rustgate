// Copyright © 2026 Roberto Chiofalo.

//! Per-target message filtering.
//!
//! Compiles [`FilterConfig`] into a [`CompiledFilter`] that can efficiently
//! test whether a [`RoutableMessage`] should be forwarded to a given target.
//! Filters are AND-combined across dimensions: a message must match all
//! configured dimensions to pass. Within a dimension, values are OR-combined.

use std::collections::HashSet;

use rustgate_core::message::RoutableMessage;

use crate::config::FilterConfig;

/// Compiled message filter for a single target.
///
/// Pre-computes hashsets from the raw config vectors for O(1) lookups
/// on the hot path. The `"http"` protocol is always excluded to prevent
/// echo loops, even if not explicitly configured.
#[derive(Debug)]
pub(crate) struct CompiledFilter {
    groups: Option<HashSet<String>>,
    message_types: Option<HashSet<String>>,
    source_cns: Option<HashSet<String>>,
    exclude_protocols: HashSet<String>,
}

impl CompiledFilter {
    /// Build a compiled filter from config.
    ///
    /// Ensures `"http"` is always in `exclude_protocols` for echo prevention.
    /// Source CNs are lowercased for case-insensitive matching (following the
    /// ACL module convention).
    pub(crate) fn from_config(config: &FilterConfig) -> Self {
        let groups = config.groups.as_ref().map(|g| g.iter().cloned().collect());

        let message_types = config
            .message_types
            .as_ref()
            .map(|t| t.iter().cloned().collect());

        // Lowercase for case-insensitive CN matching
        let source_cns = config
            .source_cns
            .as_ref()
            .map(|c| c.iter().map(|s| s.to_ascii_lowercase()).collect());

        // Always include "http" in excluded protocols
        let mut exclude = config
            .exclude_protocols
            .as_ref()
            .map(|p| p.iter().cloned().collect::<HashSet<_>>())
            .unwrap_or_default();
        let _ = exclude.insert("http".to_string());

        Self {
            groups,
            message_types,
            source_cns,
            exclude_protocols: exclude,
        }
    }

    /// Build a default filter that only excludes `"http"` protocol.
    pub(crate) fn default_filter() -> Self {
        let mut exclude = HashSet::new();
        let _ = exclude.insert("http".to_string());
        Self {
            groups: None,
            message_types: None,
            source_cns: None,
            exclude_protocols: exclude,
        }
    }

    /// Returns `true` if the message should be forwarded to this target.
    pub(crate) fn matches(&self, msg: &RoutableMessage) -> bool {
        // Echo prevention: skip messages from excluded protocols
        if self
            .exclude_protocols
            .contains(&msg.metadata.source_protocol)
        {
            return false;
        }

        // Groups: sender must be in at least one of the configured groups
        if let Some(filter_groups) = &self.groups {
            let has_match = msg.source.groups.iter().any(|g| filter_groups.contains(g));
            if !has_match {
                return false;
            }
        }

        // Message type: must match at least one configured type
        if let Some(filter_types) = &self.message_types
            && !filter_types.contains(&msg.metadata.message_type.to_string())
        {
            return false;
        }

        // Source CN: must match (case-insensitive)
        if let Some(filter_cns) = &self.source_cns
            && !filter_cns.contains(&msg.source.cn.to_ascii_lowercase())
        {
            return false;
        }

        true
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use std::collections::BTreeSet;
    use std::sync::Arc;
    use std::time::SystemTime;

    use bytes::Bytes;
    use rustgate_core::identity::Identity;
    use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};

    use super::*;

    fn make_msg(
        cn: &str,
        groups: &[&str],
        protocol: &str,
        msg_type: MessageType,
    ) -> RoutableMessage {
        RoutableMessage {
            source: Identity {
                cn: cn.to_string(),
                fingerprint: Default::default(),
                groups: groups
                    .iter()
                    .map(|g| (*g).to_string())
                    .collect::<BTreeSet<_>>(),
                tenant: None,
                spiffe_id: None,
                attributes: Arc::new(Default::default()),
            },
            destination: Destination::Broadcast,
            payload: Bytes::from_static(b"<event/>"),
            metadata: Metadata {
                received_at: SystemTime::now(),
                source_protocol: protocol.to_string(),
                message_type: msg_type,
                ttl: None,
            },
        }
    }

    #[test]
    fn default_filter_allows_tcp() {
        let filter = CompiledFilter::default_filter();
        let msg = make_msg("alice", &["alpha"], "tcp", MessageType::Position);
        assert!(filter.matches(&msg));
    }

    #[test]
    fn default_filter_blocks_http() {
        let filter = CompiledFilter::default_filter();
        let msg = make_msg("alice", &["alpha"], "http", MessageType::Position);
        assert!(!filter.matches(&msg));
    }

    #[test]
    fn echo_prevention_always_includes_http() {
        let config = FilterConfig {
            groups: None,
            message_types: None,
            source_cns: None,
            exclude_protocols: Some(vec!["nats".to_string()]),
        };
        let filter = CompiledFilter::from_config(&config);
        // Both http and nats should be blocked
        let http_msg = make_msg("alice", &["alpha"], "http", MessageType::Position);
        let nats_msg = make_msg("alice", &["alpha"], "nats", MessageType::Position);
        assert!(!filter.matches(&http_msg));
        assert!(!filter.matches(&nats_msg));
    }

    #[test]
    fn group_filter_accepts_matching() {
        let config = FilterConfig {
            groups: Some(vec!["alpha".to_string(), "bravo".to_string()]),
            message_types: None,
            source_cns: None,
            exclude_protocols: None,
        };
        let filter = CompiledFilter::from_config(&config);
        let msg = make_msg("alice", &["alpha"], "tcp", MessageType::Position);
        assert!(filter.matches(&msg));
    }

    #[test]
    fn group_filter_rejects_non_matching() {
        let config = FilterConfig {
            groups: Some(vec!["alpha".to_string()]),
            message_types: None,
            source_cns: None,
            exclude_protocols: None,
        };
        let filter = CompiledFilter::from_config(&config);
        let msg = make_msg("alice", &["charlie"], "tcp", MessageType::Position);
        assert!(!filter.matches(&msg));
    }

    #[test]
    fn message_type_filter_accepts_matching() {
        let config = FilterConfig {
            groups: None,
            message_types: Some(vec!["position".to_string(), "alert".to_string()]),
            source_cns: None,
            exclude_protocols: None,
        };
        let filter = CompiledFilter::from_config(&config);
        let msg = make_msg("alice", &["alpha"], "tcp", MessageType::Alert);
        assert!(filter.matches(&msg));
    }

    #[test]
    fn message_type_filter_rejects_non_matching() {
        let config = FilterConfig {
            groups: None,
            message_types: Some(vec!["position".to_string()]),
            source_cns: None,
            exclude_protocols: None,
        };
        let filter = CompiledFilter::from_config(&config);
        let msg = make_msg("alice", &["alpha"], "tcp", MessageType::Chat);
        assert!(!filter.matches(&msg));
    }

    #[test]
    fn source_cn_filter_case_insensitive() {
        let config = FilterConfig {
            groups: None,
            message_types: None,
            source_cns: Some(vec!["Command-Post-1".to_string()]),
            exclude_protocols: None,
        };
        let filter = CompiledFilter::from_config(&config);
        let msg = make_msg("command-post-1", &["alpha"], "tcp", MessageType::Position);
        assert!(filter.matches(&msg));
    }

    #[test]
    fn source_cn_filter_rejects_non_matching() {
        let config = FilterConfig {
            groups: None,
            message_types: None,
            source_cns: Some(vec!["allowed-cn".to_string()]),
            exclude_protocols: None,
        };
        let filter = CompiledFilter::from_config(&config);
        let msg = make_msg("other-cn", &["alpha"], "tcp", MessageType::Position);
        assert!(!filter.matches(&msg));
    }

    #[test]
    fn combined_filters_and_logic() {
        let config = FilterConfig {
            groups: Some(vec!["alpha".to_string()]),
            message_types: Some(vec!["position".to_string()]),
            source_cns: Some(vec!["alice".to_string()]),
            exclude_protocols: None,
        };
        let filter = CompiledFilter::from_config(&config);

        // All match
        let msg = make_msg("alice", &["alpha"], "tcp", MessageType::Position);
        assert!(filter.matches(&msg));

        // Wrong group
        let msg = make_msg("alice", &["bravo"], "tcp", MessageType::Position);
        assert!(!filter.matches(&msg));

        // Wrong type
        let msg = make_msg("alice", &["alpha"], "tcp", MessageType::Chat);
        assert!(!filter.matches(&msg));

        // Wrong CN
        let msg = make_msg("bob", &["alpha"], "tcp", MessageType::Position);
        assert!(!filter.matches(&msg));
    }

    #[test]
    fn none_dimensions_accept_all() {
        let config = FilterConfig {
            groups: None,
            message_types: None,
            source_cns: None,
            exclude_protocols: None,
        };
        let filter = CompiledFilter::from_config(&config);
        let msg = make_msg("anyone", &["any-group"], "tcp", MessageType::Chat);
        assert!(filter.matches(&msg));
    }

    #[test]
    fn sender_in_multiple_groups_matches_any() {
        let config = FilterConfig {
            groups: Some(vec!["bravo".to_string()]),
            message_types: None,
            source_cns: None,
            exclude_protocols: None,
        };
        let filter = CompiledFilter::from_config(&config);
        // Sender is in both alpha and bravo — bravo matches
        let msg = make_msg("alice", &["alpha", "bravo"], "tcp", MessageType::Position);
        assert!(filter.matches(&msg));
    }
}
