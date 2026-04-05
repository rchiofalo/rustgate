//! Group access control policy.
//!
//! Defines optional per-group send/receive permissions enforced by the
//! router at dispatch time. When no policy is loaded, all groups operate
//! in open mode (backward compatible).

use std::collections::{HashMap, HashSet};

/// Access control entry for a single group.
///
/// When a group has an ACL entry, only listed principals have the
/// specified permissions. Unlisted principals are denied.
#[derive(Debug, Clone, Default)]
pub struct GroupAcl {
    /// CNs allowed to send to this group.
    senders: HashSet<String>,
    /// CNs allowed to receive from this group.
    receivers: HashSet<String>,
}

impl GroupAcl {
    /// Create a new ACL with explicit sender and receiver sets.
    pub fn new(senders: HashSet<String>, receivers: HashSet<String>) -> Self {
        Self { senders, receivers }
    }

    /// Returns `true` if `cn` is permitted to send to this group.
    pub fn can_send(&self, cn: &str) -> bool {
        self.senders.contains(cn)
    }

    /// Returns `true` if `cn` is permitted to receive from this group.
    pub fn can_receive(&self, cn: &str) -> bool {
        self.receivers.contains(cn)
    }
}

/// Group access control policy applied by the router.
///
/// When no policy is loaded (the default), the router operates in open
/// mode — any group member can send to and receive from their groups.
/// When a policy is present, only explicitly authorized principals may
/// send or receive in groups that have ACL entries. Groups not listed
/// in the policy remain open.
#[derive(Debug, Clone, Default)]
pub struct GroupAclPolicy {
    /// Per-group ACL rules. Groups not present in this map operate in
    /// open mode (any member can send/receive).
    groups: HashMap<String, GroupAcl>,
}

impl GroupAclPolicy {
    /// Create a policy from a map of group ACLs.
    pub fn new(groups: HashMap<String, GroupAcl>) -> Self {
        Self { groups }
    }

    /// Returns `true` if `cn` is authorized to send to `group`.
    ///
    /// If the group has no ACL entry, returns `true` (open mode).
    pub fn is_send_authorized(&self, group: &str, cn: &str) -> bool {
        match self.groups.get(group) {
            Some(acl) => acl.can_send(cn),
            None => true,
        }
    }

    /// Returns `true` if `cn` is authorized to receive from `group`.
    ///
    /// If the group has no ACL entry, returns `true` (open mode).
    pub fn is_receive_authorized(&self, group: &str, cn: &str) -> bool {
        match self.groups.get(group) {
            Some(acl) => acl.can_receive(cn),
            None => true,
        }
    }

    /// Returns `true` if no group ACLs are defined (fully open mode).
    pub fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }

    /// Number of groups with ACL entries.
    pub fn len(&self) -> usize {
        self.groups.len()
    }
}

#[cfg(test)]
mod tests {
    #![allow(unused_results)]

    use super::*;

    #[test]
    fn policy_open_when_empty() {
        let policy = GroupAclPolicy::default();
        assert!(policy.is_send_authorized("any-group", "any-cn"));
        assert!(policy.is_receive_authorized("any-group", "any-cn"));
        assert!(policy.is_empty());
    }

    #[test]
    fn policy_allows_listed_sender() {
        let mut groups = HashMap::new();
        groups.insert(
            "ops".to_string(),
            GroupAcl::new(
                HashSet::from(["alice".to_string()]),
                HashSet::from(["alice".to_string(), "bob".to_string()]),
            ),
        );
        let policy = GroupAclPolicy::new(groups);
        assert!(policy.is_send_authorized("ops", "alice"));
    }

    #[test]
    fn policy_denies_unlisted_sender() {
        let mut groups = HashMap::new();
        groups.insert(
            "ops".to_string(),
            GroupAcl::new(
                HashSet::from(["alice".to_string()]),
                HashSet::from(["alice".to_string(), "bob".to_string()]),
            ),
        );
        let policy = GroupAclPolicy::new(groups);
        assert!(!policy.is_send_authorized("ops", "bob"));
    }

    #[test]
    fn policy_allows_listed_receiver() {
        let mut groups = HashMap::new();
        groups.insert(
            "ops".to_string(),
            GroupAcl::new(
                HashSet::from(["alice".to_string()]),
                HashSet::from(["alice".to_string(), "bob".to_string()]),
            ),
        );
        let policy = GroupAclPolicy::new(groups);
        assert!(policy.is_receive_authorized("ops", "bob"));
    }

    #[test]
    fn policy_denies_unlisted_receiver() {
        let mut groups = HashMap::new();
        groups.insert(
            "ops".to_string(),
            GroupAcl::new(
                HashSet::from(["alice".to_string()]),
                HashSet::from(["alice".to_string()]),
            ),
        );
        let policy = GroupAclPolicy::new(groups);
        assert!(!policy.is_receive_authorized("ops", "charlie"));
    }

    #[test]
    fn policy_open_for_unconfigured_group() {
        let mut groups = HashMap::new();
        groups.insert(
            "ops".to_string(),
            GroupAcl::new(
                HashSet::from(["alice".to_string()]),
                HashSet::from(["alice".to_string()]),
            ),
        );
        let policy = GroupAclPolicy::new(groups);
        // "bravo" is not in the policy — should be open
        assert!(policy.is_send_authorized("bravo", "anyone"));
        assert!(policy.is_receive_authorized("bravo", "anyone"));
    }

    #[test]
    fn is_empty_and_len() {
        let empty = GroupAclPolicy::default();
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);

        let mut groups = HashMap::new();
        groups.insert("ops".to_string(), GroupAcl::default());
        let policy = GroupAclPolicy::new(groups);
        assert!(!policy.is_empty());
        assert_eq!(policy.len(), 1);
    }
}
