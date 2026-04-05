//! JSON deserialization for group ACL configuration files.
//!
//! Converts the human-friendly JSON format into the runtime
//! [`GroupAclPolicy`] used by the router.

use std::collections::{HashMap, HashSet};

use serde::Deserialize;

/// Root structure of the group ACL JSON configuration file.
#[derive(Debug, Deserialize)]
pub(crate) struct GroupAclFile {
    /// Per-group access control rules.
    pub(crate) groups: HashMap<String, GroupAclEntry>,
}

/// ACL entry for a single group in the configuration file.
#[derive(Debug, Deserialize)]
pub(crate) struct GroupAclEntry {
    /// Certificate CNs permitted to send messages to this group.
    #[serde(default)]
    pub(crate) send: HashSet<String>,
    /// Certificate CNs permitted to receive messages from this group.
    #[serde(default)]
    pub(crate) receive: HashSet<String>,
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
    fn parse_invalid_json_fails() {
        let json = r#"not valid json"#;
        let result = serde_json::from_str::<GroupAclFile>(json);
        assert!(result.is_err());
    }
}
