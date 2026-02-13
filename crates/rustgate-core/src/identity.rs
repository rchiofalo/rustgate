use std::collections::BTreeSet;

/// Unique group identifier.
pub type GroupId = String;

/// Certificate fingerprint (SHA-256 hex).
pub type CertFingerprint = String;

/// Identity extracted from an X.509 client certificate.
///
/// CN becomes the unique identifier.
/// OU entries become group memberships.
#[derive(Debug, Clone, Hash, Eq, PartialEq, serde::Serialize)]
pub struct Identity {
    /// Common Name from certificate subject
    pub cn: String,
    /// SHA-256 fingerprint of the client certificate
    pub fingerprint: CertFingerprint,
    /// Groups derived from OU fields in certificate subject
    pub groups: BTreeSet<GroupId>,
}

impl Identity {
    /// Check if this identity is a member of the given group.
    pub fn is_member_of(&self, group: &str) -> bool {
        self.groups.contains(group)
    }
}

impl std::fmt::Display for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.cn)
    }
}
