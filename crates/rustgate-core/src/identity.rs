use std::collections::BTreeSet;

/// Unique group identifier.
pub type GroupId = String;

/// Certificate fingerprint (SHA-256 hex).
pub type CertFingerprint = String;

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct Identity {
    pub cn: String,
    pub fingerprint: CertFingerprint,
    pub groups: BTreeSet<GroupId>,
}

impl Identity {
    pub fn is_member_of(&self, group: &str) -> bool {
        self.groups.contains(group)
    }
}

impl std::fmt::Display for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.cn)
    }
}
