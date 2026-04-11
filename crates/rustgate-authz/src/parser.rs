// Copyright © 2026 Roberto Chiofalo.

//! JSON parser for [`RuleSet`] policies.

use std::collections::HashSet;

use crate::error::AuthzError;
use crate::policy::RuleSet;

/// Supported policy schema version.
pub const POLICY_SCHEMA_VERSION: u32 = 1;

/// Parse a JSON policy document into a validated [`RuleSet`].
///
/// Validation checks:
/// - `version` must equal `1`
/// - every rule id must be non-empty and unique across the set
pub fn parse_json(bytes: &[u8]) -> Result<RuleSet, AuthzError> {
    let rules: RuleSet = serde_json::from_slice(bytes)?;
    validate(&rules)?;
    Ok(rules)
}

/// Validate a [`RuleSet`] without parsing. Exposed for callers that
/// construct a `RuleSet` programmatically (e.g. tests, benches).
pub fn validate(set: &RuleSet) -> Result<(), AuthzError> {
    if set.version != POLICY_SCHEMA_VERSION {
        return Err(AuthzError::validation(
            "version",
            format!(
                "unsupported policy schema version {}, expected {POLICY_SCHEMA_VERSION}",
                set.version
            ),
        ));
    }

    let mut seen: HashSet<&str> = HashSet::with_capacity(set.rules.len());
    for rule in &set.rules {
        if rule.id.is_empty() {
            return Err(AuthzError::validation("rules", "rule id must not be empty"));
        }
        if !seen.insert(rule.id.as_str()) {
            return Err(AuthzError::validation(
                "rules",
                format!("duplicate rule id `{}`", rule.id),
            ));
        }
    }

    Ok(())
}
