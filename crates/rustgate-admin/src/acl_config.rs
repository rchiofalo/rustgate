// Copyright © 2026 Roberto Chiofalo.

//! JSON deserialization for group ACL configuration files.
//!
//! Converts the human-friendly JSON format into the runtime
//! [`GroupAclPolicy`](rustgate_router::GroupAclPolicy) used by the router.

use std::collections::{HashMap, HashSet};

use rustgate_core::constants::is_reserved_group_id;
use serde::{Deserialize, Serialize};

/// Root structure of the group ACL JSON configuration file.
///
/// Uses `deny_unknown_fields` to reject configuration files containing
/// unexpected top-level properties — a typo is surfaced as a
/// deserialization error rather than silently ignored.
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GroupAclFile {
    /// Per-group access control rules.
    pub groups: HashMap<String, GroupAclEntry>,
}

impl GroupAclFile {
    /// Reject policy files that key a group on a reserved-sentinel
    /// identifier (anything matching `__*__`).
    ///
    /// Those identifiers are reserved for transport-layer synthetic
    /// groups — plaintext sessions join
    /// [`rustgate_core::constants::PLAINTEXT_GROUP`] (`"__plaintext__"`),
    /// anonymous federation ingress uses `__ANON__`, etc. An operator
    /// policy keyed by one of those names is almost always a
    /// misconfiguration: it either shadows the synthetic group's
    /// meaning at the PEP, or — in the `__plaintext__` case —
    /// silently applies the entry to every anonymous plaintext
    /// session the server accepted, broadcasting to a population the
    /// operator did not enumerate.
    ///
    /// Called from the startup loader
    /// (`rustgate_server::setup::load_group_acl`) and the hot-reload
    /// path (`rustgate_server::acl_reloader::AclReloader::reload`)
    /// before the policy is handed to the router, so a bad policy
    /// fails closed at config time rather than swapping into the
    /// dispatch path. The matching rule is also enforced at the REST
    /// ACL API (`rustgate_server::acl_api::valid_group_id`) so a live
    /// PUT cannot sneak a reserved name past the same guardrail.
    pub fn validate_operator_policy(&self) -> Result<(), String> {
        if let Some(name) = self
            .groups
            .keys()
            .find(|name| is_reserved_group_id(name.as_str()))
        {
            return Err(format!(
                "ACL policy references reserved group id `{name}`; names matching \
                 `__*__` (e.g. `__plaintext__`, `__ANON__`) are reserved for \
                 transport-layer synthetic groups and cannot appear in an \
                 operator-authored policy"
            ));
        }
        Ok(())
    }
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
pub struct GroupAclEntry {
    /// Certificate CNs permitted to send messages to this group.
    #[serde(default)]
    pub send: HashSet<String>,
    /// Certificate CNs permitted to receive messages from this group.
    #[serde(default)]
    pub receive: HashSet<String>,
    /// Certificate CNs explicitly denied from sending; overrides `send`.
    #[serde(default)]
    pub deny_send: HashSet<String>,
    /// Certificate CNs explicitly denied from receiving; overrides `receive`.
    #[serde(default)]
    pub deny_receive: HashSet<String>,
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

    #[test]
    fn validate_operator_policy_allows_ordinary_group_names() {
        let json = r#"{
            "groups": {
                "alpha": {"send": ["alice"]},
                "team.red": {"receive": ["bob"]},
                "tenant:42": {"send": ["carol"]}
            }
        }"#;
        let config: GroupAclFile = serde_json::from_str(json).unwrap();
        config
            .validate_operator_policy()
            .expect("ordinary group names must pass validation");
    }

    #[test]
    fn validate_operator_policy_rejects_plaintext_sentinel() {
        // The canonical example from issue #749 — an operator policy
        // must never key off the transport's synthetic plaintext group.
        let json = r#"{
            "groups": {
                "__plaintext__": {"send": ["anyone"]}
            }
        }"#;
        let config: GroupAclFile = serde_json::from_str(json).unwrap();
        let err = config
            .validate_operator_policy()
            .expect_err("__plaintext__ must be rejected as a reserved sentinel");
        assert!(
            err.contains("__plaintext__"),
            "error message must name the offending key: {err}"
        );
        assert!(
            err.contains("reserved"),
            "error message must explain why: {err}"
        );
    }

    #[test]
    fn validate_operator_policy_rejects_arbitrary_sentinel_shape() {
        // The check is byte-shape based (`__*__`), not an explicit
        // hard-coded list, so any future internal sentinel
        // automatically collides-safely.
        let json = r#"{
            "groups": {
                "__future_sentinel__": {"send": ["x"]}
            }
        }"#;
        let config: GroupAclFile = serde_json::from_str(json).unwrap();
        let err = config
            .validate_operator_policy()
            .expect_err("any __*__ shape must be rejected");
        assert!(err.contains("__future_sentinel__"));
    }

    #[test]
    fn validate_operator_policy_rejects_even_when_other_groups_are_valid() {
        // Mixed file with one valid group and one sentinel — the
        // whole policy must be rejected, not just the bad entry
        // quietly dropped. A partial-load would be the exact failure
        // mode we are closing.
        let json = r#"{
            "groups": {
                "alpha": {"send": ["alice"]},
                "__plaintext__": {"receive": ["bob"]}
            }
        }"#;
        let config: GroupAclFile = serde_json::from_str(json).unwrap();
        let err = config
            .validate_operator_policy()
            .expect_err("a policy with any sentinel key must fail whole-file");
        assert!(err.contains("__plaintext__"));
    }

    #[test]
    fn validate_operator_policy_passes_on_empty_policy() {
        let config = GroupAclFile::default();
        config
            .validate_operator_policy()
            .expect("empty policy has no reserved keys to hit");
    }
}
