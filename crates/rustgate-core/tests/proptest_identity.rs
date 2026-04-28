// Copyright © 2026 Roberto Chiofalo.

#![allow(clippy::panic, clippy::unwrap_used)]
//! Property-based tests for Identity construction and invariants.
//!
//! Validates that Identity construction rules are consistent and that
//! Display output always matches the CN.

use std::collections::BTreeSet;

use proptest::prelude::*;
use rustgate_core::identity::Identity;

/// Strategy to generate valid CNs: non-empty, printable ASCII, max 256 chars.
fn valid_cn_strategy() -> impl Strategy<Value = String> {
    prop::collection::vec(0x20u8..=0x7Eu8, 1..=64)
        .prop_map(|bytes| bytes.into_iter().map(|b| b as char).collect::<String>())
}

/// Strategy to generate valid fingerprints (hex-like strings).
fn valid_fingerprint_strategy() -> impl Strategy<Value = String> {
    prop::collection::vec("[0-9a-f]{2}", 1..=32).prop_map(|parts| parts.join(":"))
}

/// Strategy to generate valid group names.
fn valid_groups_strategy() -> impl Strategy<Value = BTreeSet<String>> {
    prop::collection::btree_set("[a-zA-Z][a-zA-Z0-9_-]{0,15}", 0..=5)
}

proptest! {
    /// Identity::new succeeds for all valid inputs and the CN is preserved.
    #[test]
    fn identity_new_preserves_cn(
        cn in valid_cn_strategy(),
        fp in valid_fingerprint_strategy(),
        groups in valid_groups_strategy(),
    ) {
        let identity = Identity::new(cn.clone(), fp.clone(), groups.clone()).unwrap();
        prop_assert_eq!(&*identity.cn, cn.as_str());
        prop_assert_eq!(&identity.fingerprint, &fp);
        prop_assert_eq!(&identity.groups, &groups);
    }

    /// Display always shows the CN.
    #[test]
    fn identity_display_equals_cn(
        cn in valid_cn_strategy(),
        fp in valid_fingerprint_strategy(),
    ) {
        let identity = Identity::new(cn.clone(), fp, BTreeSet::new()).unwrap();
        prop_assert_eq!(format!("{identity}"), cn);
    }

    /// Identity::plaintext succeeds for valid CNs and has empty fingerprint.
    #[test]
    fn identity_plaintext_empty_fingerprint(
        cn in valid_cn_strategy(),
        groups in valid_groups_strategy(),
    ) {
        let identity = Identity::plaintext(cn.clone(), groups).unwrap();
        prop_assert_eq!(&*identity.cn, cn.as_str());
        prop_assert!(identity.fingerprint.is_empty());
    }

    /// Group membership check is consistent with the groups passed in.
    #[test]
    fn identity_group_membership_consistent(
        cn in valid_cn_strategy(),
        fp in valid_fingerprint_strategy(),
        groups in valid_groups_strategy(),
        query in "[a-zA-Z][a-zA-Z0-9_-]{0,15}",
    ) {
        let identity = Identity::new(cn, fp, groups.clone()).unwrap();
        let expected = groups.contains(&query);
        prop_assert_eq!(identity.is_member_of(&query), expected);
    }

    /// Empty CN always fails construction.
    #[test]
    fn identity_empty_cn_always_fails(
        fp in valid_fingerprint_strategy(),
        groups in valid_groups_strategy(),
    ) {
        let result = Identity::new(String::new(), fp, groups);
        prop_assert!(result.is_err());
    }

    /// CN with control characters always fails construction.
    #[test]
    fn identity_control_char_cn_always_fails(
        prefix in valid_cn_strategy(),
        control in 0u8..0x20u8,
        fp in valid_fingerprint_strategy(),
    ) {
        let cn = format!("{prefix}{}", control as char);
        let result = Identity::new(cn, fp, BTreeSet::new());
        prop_assert!(result.is_err());
    }

    /// Cloned Identity is equal to the original.
    #[test]
    fn identity_clone_equals_original(
        cn in valid_cn_strategy(),
        fp in valid_fingerprint_strategy(),
        groups in valid_groups_strategy(),
    ) {
        let identity = Identity::new(cn, fp, groups).unwrap();
        let cloned = identity.clone();
        prop_assert_eq!(identity.cn, cloned.cn);
        prop_assert_eq!(identity.fingerprint, cloned.fingerprint);
        prop_assert_eq!(identity.groups, cloned.groups);
    }
}
