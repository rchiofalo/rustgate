// Copyright © 2026 Roberto Chiofalo.

//! Group access control policy.
//!
//! Defines optional per-group send/receive permissions enforced by the
//! router at dispatch time. When no policy is loaded, all groups operate
//! in open mode (backward compatible). When at least one group has an
//! ACL entry, groups *not* listed in the policy default to **deny** so
//! that an incomplete configuration cannot silently leave groups open.
//!
//! All CN comparisons are **case-insensitive** (RFC 5280 §7.1). CNs
//! are normalized to ASCII lowercase at construction time and lookup
//! inputs are lowercased before comparison.
//!
//! Each [`GroupAcl`] supports both *allow lists* and *deny lists* for
//! senders and receivers independently. Deny is always evaluated first
//! and overrides any allow entry — if a CN appears in `deny_senders`, it
//! cannot send to the group even if it is also listed in `senders`.

use std::collections::{HashMap, HashSet};

/// Access control entry for a single group.
///
/// Evaluation rules:
/// - **Deny first**: a CN in `deny_senders` is rejected for sending even
///   if it also appears in `senders` (same for receivers).
/// - **Allow list**: when `senders` is non-empty, only listed CNs (minus
///   any in `deny_senders`) may send. Same logic for `receivers`.
/// - **Deny-only block list**: when `senders` is empty but
///   `deny_senders` is non-empty, the group is open *except* for the
///   denied CNs. Same for receivers.
/// - **Both empty (deny-all)**: when both `senders` and `deny_senders`
///   are empty the group denies all sends. This matches the pre-deny
///   semantics where an empty allow list denied everything, and keeps
///   `GroupAcl::default()` a safe no-permissions value.
#[derive(Debug, Clone, Default)]
pub struct GroupAcl {
    /// CNs allowed to send to this group.
    senders: HashSet<String>,
    /// CNs allowed to receive from this group.
    receivers: HashSet<String>,
    /// CNs explicitly denied from sending; overrides `senders`.
    deny_senders: HashSet<String>,
    /// CNs explicitly denied from receiving; overrides `receivers`.
    deny_receivers: HashSet<String>,
}

impl GroupAcl {
    /// Create a new ACL with explicit allow lists for senders and receivers.
    /// Deny lists default to empty.
    ///
    /// All CN strings are normalized to ASCII lowercase so that lookups
    /// are case-insensitive per RFC 5280 §7.1.
    pub fn new(senders: HashSet<String>, receivers: HashSet<String>) -> Self {
        Self {
            senders: senders
                .into_iter()
                .map(|s| s.to_ascii_lowercase())
                .collect(),
            receivers: receivers
                .into_iter()
                .map(|s| s.to_ascii_lowercase())
                .collect(),
            deny_senders: HashSet::new(),
            deny_receivers: HashSet::new(),
        }
    }

    /// Create a new ACL with both allow and deny lists.
    ///
    /// All CN strings are normalized to ASCII lowercase so that lookups
    /// are case-insensitive per RFC 5280 §7.1.
    pub fn with_deny(
        senders: HashSet<String>,
        receivers: HashSet<String>,
        deny_senders: HashSet<String>,
        deny_receivers: HashSet<String>,
    ) -> Self {
        Self {
            senders: senders
                .into_iter()
                .map(|s| s.to_ascii_lowercase())
                .collect(),
            receivers: receivers
                .into_iter()
                .map(|s| s.to_ascii_lowercase())
                .collect(),
            deny_senders: deny_senders
                .into_iter()
                .map(|s| s.to_ascii_lowercase())
                .collect(),
            deny_receivers: deny_receivers
                .into_iter()
                .map(|s| s.to_ascii_lowercase())
                .collect(),
        }
    }

    /// Returns `true` if `cn` is permitted to send to this group.
    ///
    /// The input `cn` is normalized to ASCII lowercase before comparison
    /// so matching is case-insensitive per RFC 5280 §7.1.
    ///
    /// Case normalization uses `to_ascii_lowercase()`, which handles ASCII
    /// characters only. Non-ASCII Unicode case folding (e.g., Turkish İ/ı,
    /// German ß) is not performed. This is sufficient for typical X.509 CN
    /// values which are ASCII-only in practice.
    ///
    /// Deny is checked first — a CN in `deny_senders` is always rejected,
    /// regardless of whether it appears in `senders`.
    pub fn can_send(&self, cn: &str) -> bool {
        let cn = cn.to_ascii_lowercase();
        if self.deny_senders.contains(&cn) {
            return false;
        }
        if !self.senders.is_empty() {
            return self.senders.contains(&cn);
        }
        // Empty allow list: deny-only block list when deny list is
        // populated, otherwise deny-all (pre-existing semantics).
        !self.deny_senders.is_empty()
    }

    /// Returns `true` if `cn` is permitted to receive from this group.
    ///
    /// The input `cn` is normalized to ASCII lowercase before comparison
    /// so matching is case-insensitive per RFC 5280 §7.1.
    ///
    /// Case normalization uses `to_ascii_lowercase()`, which handles ASCII
    /// characters only. Non-ASCII Unicode case folding (e.g., Turkish İ/ı,
    /// German ß) is not performed. This is sufficient for typical X.509 CN
    /// values which are ASCII-only in practice.
    ///
    /// Deny is checked first — a CN in `deny_receivers` is always rejected,
    /// regardless of whether it appears in `receivers`.
    pub fn can_receive(&self, cn: &str) -> bool {
        let cn = cn.to_ascii_lowercase();
        if self.deny_receivers.contains(&cn) {
            return false;
        }
        if !self.receivers.is_empty() {
            return self.receivers.contains(&cn);
        }
        !self.deny_receivers.is_empty()
    }

    /// CNs in the sender allow list.
    pub fn senders(&self) -> &HashSet<String> {
        &self.senders
    }

    /// CNs in the receiver allow list.
    pub fn receivers(&self) -> &HashSet<String> {
        &self.receivers
    }

    /// CNs in the sender deny list.
    pub fn deny_senders(&self) -> &HashSet<String> {
        &self.deny_senders
    }

    /// CNs in the receiver deny list.
    pub fn deny_receivers(&self) -> &HashSet<String> {
        &self.deny_receivers
    }
}

/// Group access control policy applied by the router.
///
/// When no policy is loaded (the default — empty map), the router
/// operates in open mode: any group member can send to and receive
/// from their groups. Once at least one group has an ACL entry,
/// **default-deny** kicks in: groups *not* listed in the policy are
/// denied for both send and receive. This ensures an incomplete
/// configuration cannot silently leave groups unprotected.
///
/// CN comparisons are case-insensitive (see [`GroupAcl`]).
#[derive(Debug, Clone, Default)]
pub struct GroupAclPolicy {
    /// Per-group ACL rules. When this map is non-empty, groups not
    /// present default to deny.
    groups: HashMap<String, GroupAcl>,
}

impl GroupAclPolicy {
    /// Create a policy from a map of group ACLs.
    pub fn new(groups: HashMap<String, GroupAcl>) -> Self {
        Self { groups }
    }

    /// Returns `true` if `cn` is authorized to send to `group`.
    ///
    /// When the policy map is empty (no ACL loaded), returns `true` for
    /// backward compatibility. When at least one group is configured,
    /// groups without an explicit entry default to **deny**.
    ///
    /// The `cn` is normalized to lowercase internally by [`GroupAcl`].
    pub fn is_send_authorized(&self, group: &str, cn: &str) -> bool {
        match self.groups.get(group) {
            Some(acl) => acl.can_send(cn),
            None => self.groups.is_empty(),
        }
    }

    /// Returns `true` if `cn` is authorized to receive from `group`.
    ///
    /// When the policy map is empty (no ACL loaded), returns `true` for
    /// backward compatibility. When at least one group is configured,
    /// groups without an explicit entry default to **deny**.
    ///
    /// The `cn` is normalized to lowercase internally by [`GroupAcl`].
    pub fn is_receive_authorized(&self, group: &str, cn: &str) -> bool {
        match self.groups.get(group) {
            Some(acl) => acl.can_receive(cn),
            None => self.groups.is_empty(),
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

    /// Read-only access to the underlying group map.
    ///
    /// Used by management surfaces (REST API, diagnostics) to enumerate
    /// or render the current policy.
    pub fn groups(&self) -> &HashMap<String, GroupAcl> {
        &self.groups
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
    fn policy_denies_unconfigured_group_when_policy_loaded() {
        let mut groups = HashMap::new();
        groups.insert(
            "ops".to_string(),
            GroupAcl::new(
                HashSet::from(["alice".to_string()]),
                HashSet::from(["alice".to_string()]),
            ),
        );
        let policy = GroupAclPolicy::new(groups);
        // "bravo" is not in the policy — default-deny when policy loaded.
        assert!(!policy.is_send_authorized("bravo", "anyone"));
        assert!(!policy.is_receive_authorized("bravo", "anyone"));
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

    // ── Deny-rule tests ─────────────────────────────────────────────

    #[test]
    fn deny_sender_overrides_allow() {
        let acl = GroupAcl::with_deny(
            HashSet::from(["alice".to_string(), "bob".to_string()]),
            HashSet::new(),
            HashSet::from(["alice".to_string()]),
            HashSet::new(),
        );
        // alice is allowed AND denied -- deny wins
        assert!(!acl.can_send("alice"));
        // bob is only allowed
        assert!(acl.can_send("bob"));
        // charlie is not in the allow list at all
        assert!(!acl.can_send("charlie"));
    }

    #[test]
    fn deny_receiver_overrides_allow() {
        let acl = GroupAcl::with_deny(
            HashSet::new(),
            HashSet::from(["alice".to_string(), "bob".to_string()]),
            HashSet::new(),
            HashSet::from(["bob".to_string()]),
        );
        assert!(acl.can_receive("alice"));
        assert!(!acl.can_receive("bob"));
        assert!(!acl.can_receive("charlie"));
    }

    #[test]
    fn deny_only_acts_as_block_list() {
        // Empty allow + non-empty deny → open except for denied CNs.
        let acl = GroupAcl::with_deny(
            HashSet::new(),
            HashSet::new(),
            HashSet::from(["mallory".to_string()]),
            HashSet::from(["mallory".to_string()]),
        );
        assert!(acl.can_send("alice"));
        assert!(acl.can_send("bob"));
        assert!(!acl.can_send("mallory"));
        assert!(acl.can_receive("alice"));
        assert!(!acl.can_receive("mallory"));
    }

    #[test]
    fn asymmetric_deny_send_only() {
        // Denied from sending. Receive side uses a non-empty deny list
        // with an empty allow list so it stays in block-list mode
        // (non-denied CNs may still receive).
        let acl = GroupAcl::with_deny(
            HashSet::new(),
            HashSet::new(),
            HashSet::from(["mallory".to_string()]),
            HashSet::from(["eve".to_string()]),
        );
        assert!(!acl.can_send("mallory"));
        assert!(acl.can_receive("mallory"));
        assert!(!acl.can_receive("eve"));
    }

    #[test]
    fn asymmetric_deny_receive_only() {
        // Allow sending (non-empty allow list including mallory),
        // deny receiving (allow list populated so receive evaluates to
        // allow-list-minus-deny).
        let acl = GroupAcl::with_deny(
            HashSet::from(["mallory".to_string()]),
            HashSet::from(["mallory".to_string()]),
            HashSet::new(),
            HashSet::from(["mallory".to_string()]),
        );
        assert!(acl.can_send("mallory"));
        assert!(!acl.can_receive("mallory"));
    }

    #[test]
    fn empty_allow_and_deny_is_deny_all() {
        // Default-constructed ACL must deny everything — matches the
        // pre-deny semantics where an empty allow list denied all CNs.
        let acl = GroupAcl::default();
        assert!(!acl.can_send("alice"));
        assert!(!acl.can_receive("alice"));
    }

    #[test]
    fn legacy_constructor_has_empty_deny_lists() {
        // Backward compatibility: GroupAcl::new must continue to work
        // exactly like before — empty deny sets, allow-list semantics.
        let acl = GroupAcl::new(
            HashSet::from(["alice".to_string()]),
            HashSet::from(["alice".to_string()]),
        );
        assert!(acl.deny_senders().is_empty());
        assert!(acl.deny_receivers().is_empty());
        assert!(acl.can_send("alice"));
        assert!(!acl.can_send("bob"));
    }

    #[test]
    fn deny_in_policy_routing() {
        let mut groups = HashMap::new();
        groups.insert(
            "ops".to_string(),
            GroupAcl::with_deny(
                HashSet::new(),
                HashSet::new(),
                HashSet::from(["mallory".to_string()]),
                HashSet::from(["mallory".to_string()]),
            ),
        );
        let policy = GroupAclPolicy::new(groups);
        assert!(policy.is_send_authorized("ops", "alice"));
        assert!(!policy.is_send_authorized("ops", "mallory"));
        assert!(policy.is_receive_authorized("ops", "alice"));
        assert!(!policy.is_receive_authorized("ops", "mallory"));
    }

    // ── Case-insensitive CN matching tests ─────────────────────────

    #[test]
    fn case_insensitive_cn_matching() {
        let acl = GroupAcl::new(
            HashSet::from(["alice".to_string()]),
            HashSet::from(["bob".to_string()]),
        );
        // Mixed-case input must match lowercase allow list.
        assert!(acl.can_send("Alice"));
        assert!(acl.can_send("ALICE"));
        assert!(acl.can_send("alice"));
        assert!(acl.can_receive("Bob"));
        assert!(acl.can_receive("BOB"));
        assert!(acl.can_receive("bob"));
    }

    #[test]
    fn case_insensitive_deny() {
        let acl = GroupAcl::with_deny(
            HashSet::new(),
            HashSet::new(),
            HashSet::from(["mallory".to_string()]),
            HashSet::from(["mallory".to_string()]),
        );
        // Mixed-case input must match lowercase deny list.
        assert!(!acl.can_send("MALLORY"));
        assert!(!acl.can_send("Mallory"));
        assert!(!acl.can_receive("MALLORY"));
        assert!(!acl.can_receive("Mallory"));
    }

    #[test]
    fn case_insensitive_construction() {
        // Uppercase CNs in construction are normalized to lowercase.
        let acl = GroupAcl::new(
            HashSet::from(["ALICE".to_string()]),
            HashSet::from(["BOB".to_string()]),
        );
        assert!(acl.can_send("alice"));
        assert!(acl.can_send("Alice"));
        assert!(acl.can_receive("bob"));
        assert!(acl.can_receive("Bob"));
    }

    // ── Default-deny policy tests ──────────────────────────────────

    #[test]
    fn policy_open_when_no_groups_loaded() {
        // Backward compat: no groups = fully open.
        let policy = GroupAclPolicy::default();
        assert!(policy.is_send_authorized("any-group", "any-cn"));
        assert!(policy.is_receive_authorized("any-group", "any-cn"));
    }

    #[test]
    fn default_deny_for_unconfigured_group_when_policy_loaded() {
        let mut groups = HashMap::new();
        groups.insert(
            "ops".to_string(),
            GroupAcl::new(
                HashSet::from(["alice".to_string()]),
                HashSet::from(["alice".to_string()]),
            ),
        );
        let policy = GroupAclPolicy::new(groups);
        // "bravo" has no entry — denied because policy is non-empty.
        assert!(!policy.is_send_authorized("bravo", "alice"));
        assert!(!policy.is_receive_authorized("bravo", "alice"));
    }

    #[test]
    fn case_insensitive_policy_lookup() {
        let mut groups = HashMap::new();
        groups.insert(
            "ops".to_string(),
            GroupAcl::new(
                HashSet::from(["alice".to_string()]),
                HashSet::from(["alice".to_string()]),
            ),
        );
        let policy = GroupAclPolicy::new(groups);
        assert!(policy.is_send_authorized("ops", "Alice"));
        assert!(policy.is_send_authorized("ops", "ALICE"));
        assert!(policy.is_receive_authorized("ops", "Alice"));
        assert!(policy.is_receive_authorized("ops", "ALICE"));
    }

    #[test]
    fn case_insensitive_deny_construction() {
        let acl = GroupAcl::with_deny(
            HashSet::new(),
            HashSet::new(),
            HashSet::from(["MALLORY".to_string()]),
            HashSet::new(),
        );
        // "mallory" should be denied (normalized at construction).
        assert!(!acl.can_send("mallory"));
    }

    #[test]
    fn policy_allows_configured_group_denies_unconfigured() {
        let mut groups = HashMap::new();
        groups.insert(
            "alpha".to_string(),
            GroupAcl::new(
                HashSet::from(["alice".to_string()]),
                HashSet::from(["bob".to_string()]),
            ),
        );
        let policy = GroupAclPolicy::new(groups);
        // alpha is configured — authorized.
        assert!(policy.is_send_authorized("alpha", "alice"));
        assert!(policy.is_receive_authorized("alpha", "bob"));
        // beta is NOT configured — denied when policy is non-empty.
        assert!(!policy.is_send_authorized("beta", "alice"));
        assert!(!policy.is_receive_authorized("beta", "bob"));
    }
}
