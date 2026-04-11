// Copyright © 2026 Roberto Chiofalo.

//! JSON deserialization for group ACL configuration files.
//!
//! Converts the human-friendly JSON format into the runtime
//! [`GroupAclPolicy`](rustgate_transport::GroupAclPolicy) used by the router.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

/// Root structure of the group ACL JSON configuration file.
///
/// Uses `deny_unknown_fields` to reject configuration files containing
/// unexpected top-level properties — a typo is surfaced as a
/// deserialization error rather than silently ignored.
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GroupAclFile {
    /// Per-group access control rules.
    pub(crate) groups: HashMap<String, GroupAclEntry>,
}

/// ACL entry for a single group in the configuration file.
///
/// Backward-compatible: legacy files using only `send` and `receive`
/// continue to deserialize unchanged (the new `deny_*` fields default
/// to empty sets via `#[serde(default)]`).
///
/// Uses `deny_unknown_fields` to reject entries containing unexpected
/// properties — a typo like `"recieve"` produces a clear error.
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GroupAclEntry {
    /// Certificate CNs permitted to send messages to this group.
    #[serde(default)]
    pub(crate) send: HashSet<String>,
    /// Certificate CNs permitted to receive messages from this group.
    #[serde(default)]
    pub(crate) receive: HashSet<String>,
    /// Certificate CNs explicitly denied from sending; overrides `send`.
    #[serde(default)]
    pub(crate) deny_send: HashSet<String>,
    /// Certificate CNs explicitly denied from receiving; overrides `receive`.
    #[serde(default)]
    pub(crate) deny_receive: HashSet<String>,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn parse_valid_config() {
        let json = r#"{
            "groups": {
                "alpha": {
                    "send": ["alice", "bob"],
                    "receive": ["alice", "bob", "charlie"]
                }
            }
        }"#;
        let config: GroupAclFile = serde_json::from_str(json).unwrap();
        assert_eq!(config.groups.len(), 1);
        let alpha = &config.groups["alpha"];
        assert!(alpha.send.contains("alice"));
        assert!(alpha.send.contains("bob"));
        assert!(alpha.receive.contains("charlie"));
    }

    #[test]
    fn parse_empty_groups() {
        let json = r#"{"groups": {}}"#;
        let config: GroupAclFile = serde_json::from_str(json).unwrap();
        assert!(config.groups.is_empty());
    }

    #[test]
    fn parse_send_only() {
        let json = r#"{
            "groups": {
                "ops": {
                    "send": ["admin"]
                }
            }
        }"#;
        let config: GroupAclFile = serde_json::from_str(json).unwrap();
        let ops = &config.groups["ops"];
        assert!(ops.send.contains("admin"));
        assert!(ops.receive.is_empty());
    }

    #[test]
    fn parse_receive_only() {
        let json = r#"{
            "groups": {
                "ops": {
                    "receive": ["monitor"]
                }
            }
        }"#;
        let config: GroupAclFile = serde_json::from_str(json).unwrap();
        let ops = &config.groups["ops"];
        assert!(ops.send.is_empty());
        assert!(ops.receive.contains("monitor"));
    }

    #[test]
    fn parse_legacy_file_without_deny_fields() {
        // Backward compat: files written before the deny extension
        // must continue to parse, leaving deny lists empty.
        let json = r#"{
            "groups": {
                "alpha": {
                    "send": ["alice"],
                    "receive": ["alice", "bob"]
                }
            }
        }"#;
        let config: GroupAclFile = serde_json::from_str(json).unwrap();
        let alpha = &config.groups["alpha"];
        assert!(alpha.deny_send.is_empty());
        assert!(alpha.deny_receive.is_empty());
    }

    #[test]
    fn parse_with_deny_fields() {
        let json = r#"{
            "groups": {
                "alpha": {
                    "send": ["alice", "bob"],
                    "receive": ["alice", "bob"],
                    "deny_send": ["bob"],
                    "deny_receive": ["bob"]
                }
            }
        }"#;
        let config: GroupAclFile = serde_json::from_str(json).unwrap();
        let alpha = &config.groups["alpha"];
        assert!(alpha.deny_send.contains("bob"));
        assert!(alpha.deny_receive.contains("bob"));
    }

    #[test]
    fn parse_invalid_json_fails() {
        let json = r#"not valid json"#;
        let result = serde_json::from_str::<GroupAclFile>(json);
        assert!(result.is_err());
    }

    #[test]
    fn rejects_unknown_top_level_field() {
        let json = r#"{"groups": {}, "unknown_key": true}"#;
        let result = serde_json::from_str::<GroupAclFile>(json);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unknown field"),
            "error should mention unknown field: {err}"
        );
    }

    #[test]
    fn rejects_unknown_entry_field() {
        let json = r#"{
            "groups": {
                "alpha": {
                    "send": ["alice"],
                    "recieve": ["bob"]
                }
            }
        }"#;
        let result = serde_json::from_str::<GroupAclFile>(json);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unknown field"),
            "error should mention unknown field: {err}"
        );
    }
}
