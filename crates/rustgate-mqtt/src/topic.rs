// Copyright © 2026 Roberto Chiofalo.

//! MQTT topic ↔ rustgate group mapping, filter validation, and
//! wildcard matching.
//!
//! The validators in this module ([`validate_publish_topic`],
//! [`validate_subscribe_filter`], [`validate_topic_prefix`]) are the
//! MQTT-side member of the workspace's sanitization helper family. Unlike
//! the other helpers — which transform input to make it safe — these
//! reject malformed input with `MqttError::InvalidTopic` because MQTT
//! topic syntax is part of the wire protocol. See the matrix in
//! [`rustgate_core::sanitize`] for how this fits alongside
//! `sanitize_for_log`, `sanitize_nats_token`, and `sanitize_filename`.
//!
//! MQTT topics are UTF-8 strings with `/` as a level separator. rustgate
//! group names are reused as-is (preserving `/`) so that a multi-level
//! topic like `fleet/A/position` maps 1:1 to the group the certificate
//! issuer provisioned in the client's `OU` field.
//!
//! # Wildcards
//!
//! MQTT subscribe filters may contain two wildcards per [MQTT 5.0
//! §4.7.1]:
//!
//! - `+` — single-level wildcard. Matches exactly one topic level at the
//!   position it occupies. `fleet/+/position` matches `fleet/A/position`
//!   but not `fleet/A/B/position`.
//! - `#` — multi-level wildcard. Matches zero or more trailing levels.
//!   Must appear as the **last** character of the filter and must be
//!   preceded by `/` (or be the entire filter). `fleet/#` matches
//!   `fleet`, `fleet/A`, and `fleet/A/B/position`.
//!
//! Wildcards are **never** accepted in PUBLISH topics. They are gated
//! in SUBSCRIBE filters by [`WildcardPolicy`] so operators can shut off
//! the `#` broadcast firehose for untrusted fleets.
//!
//! Wildcard subscriptions are expanded at SUBSCRIBE time against the
//! client's own `Identity.groups` set — the router never synthesises
//! new groups from a wildcard. This keeps the existing group-membership
//! authorisation model intact: if a cert does not carry
//! `fleet/A/position` in its OU, a client cannot receive messages
//! addressed to that group no matter how permissive the filter.
//!
//! [MQTT 5.0 §4.7.1]: https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html#_Topic_Names_and

use std::borrow::Cow;

use crate::error::MqttError;

/// Maximum group name length after topic mapping.
const MAX_GROUP_LEN: usize = 255;

/// MQTT single-level wildcard character.
const WILDCARD_SINGLE: char = '+';

/// MQTT multi-level wildcard character.
const WILDCARD_MULTI: char = '#';

/// Topic level separator per MQTT 5.0 §1.5.4.
const LEVEL_SEP: char = '/';

/// Policy controlling which wildcards are accepted in SUBSCRIBE filters.
///
/// PUBLISH topics always reject wildcards regardless of this policy —
/// the MQTT spec forbids them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WildcardPolicy {
    /// Reject both `+` and `#`. Exact-topic subscriptions only. Matches
    /// the rustgate v1 behaviour before wildcards were supported.
    Reject,
    /// Accept `+` (single-level). Reject `#` (multi-level).
    ///
    /// This is the default: most fleets want `fleet/+/position`-style
    /// fan-out without exposing the `fleet/#` broadcast firehose.
    #[default]
    SingleLevelOnly,
    /// Accept both `+` and `#`. Operators should only enable this on
    /// listeners where authorised clients legitimately need full-subtree
    /// subscriptions — for example, a SIEM tap.
    Full,
}

impl WildcardPolicy {
    fn accepts_multi_level(self) -> bool {
        matches!(self, Self::Full)
    }

    fn accepts_single_level(self) -> bool {
        matches!(self, Self::SingleLevelOnly | Self::Full)
    }
}

/// Map an MQTT topic to a rustgate group name.
///
/// If `prefix` is `Some`, the topic must start with the prefix; the prefix
/// is stripped and the remainder becomes the group name. If `prefix` is
/// `None`, the topic is used as-is.
///
/// Returns `Cow::Borrowed` when no prefix is configured (zero allocation).
///
/// This helper is only for **exact** (wildcard-free) topics — the PUBLISH
/// path and the non-wildcard branch of SUBSCRIBE. Wildcard filters are
/// handled by [`filter_matches`] against the client's identity groups.
pub fn topic_to_group<'a>(topic: &'a str, prefix: Option<&str>) -> Result<Cow<'a, str>, MqttError> {
    let group = if let Some(pfx) = prefix {
        topic.strip_prefix(pfx).ok_or_else(|| {
            MqttError::InvalidTopic(format!("topic must start with prefix '{pfx}'"))
        })?
    } else {
        topic
    };

    validate_group_name(group)?;

    if prefix.is_some() {
        Ok(Cow::Owned(group.to_owned()))
    } else {
        Ok(Cow::Borrowed(group))
    }
}

/// Validate that a topic prefix is well-formed.
///
/// MQTT topic prefixes must end with `/` to ensure clean level-boundary
/// stripping. An empty prefix is treated as no prefix.
pub fn validate_topic_prefix(prefix: &str) -> Result<(), MqttError> {
    if !prefix.is_empty() && !prefix.ends_with('/') {
        return Err(MqttError::InvalidTopic(format!(
            "topic prefix must end with '/': got '{prefix}'"
        )));
    }
    Ok(())
}

/// Validate that an MQTT publish topic contains no wildcards.
///
/// MQTT spec forbids `+` and `#` in PUBLISH topics; they are only valid
/// in SUBSCRIBE topic filters.
pub fn validate_publish_topic(topic: &str) -> Result<(), MqttError> {
    if topic.is_empty() {
        return Err(MqttError::InvalidTopic("empty topic".into()));
    }
    if topic.contains(WILDCARD_SINGLE) || topic.contains(WILDCARD_MULTI) {
        return Err(MqttError::InvalidTopic(
            "wildcards (+, #) are not allowed in publish topics".into(),
        ));
    }
    Ok(())
}

/// Validate a subscribe topic filter against an MQTT wildcard policy.
///
/// Enforces the MQTT 5.0 §4.7.1 level-boundary rules:
///
/// - `+` is only valid as an entire level (not `fleet+`, not `+x`).
/// - `#` is only valid as the last level and must be preceded by `/`
///   (or be the entire filter).
///
/// A filter whose wildcard usage is syntactically correct but forbidden
/// by `policy` is rejected with a policy-specific error.
pub fn validate_subscribe_filter(filter: &str, policy: WildcardPolicy) -> Result<(), MqttError> {
    if filter.is_empty() {
        return Err(MqttError::InvalidTopic("empty topic filter".into()));
    }

    let levels: Vec<&str> = filter.split(LEVEL_SEP).collect();
    let last_idx = levels.len() - 1;

    for (idx, level) in levels.iter().enumerate() {
        let contains_single = level.contains(WILDCARD_SINGLE);
        let contains_multi = level.contains(WILDCARD_MULTI);

        if contains_single {
            if *level != "+" {
                return Err(MqttError::InvalidTopic(format!(
                    "'+' must occupy an entire topic level: got '{level}'"
                )));
            }
            if !policy.accepts_single_level() {
                return Err(MqttError::InvalidTopic(
                    "single-level wildcard '+' is disabled by listener policy".into(),
                ));
            }
        }

        if contains_multi {
            if *level != "#" {
                return Err(MqttError::InvalidTopic(format!(
                    "'#' must occupy an entire topic level: got '{level}'"
                )));
            }
            if idx != last_idx {
                return Err(MqttError::InvalidTopic(
                    "'#' must be the last topic level".into(),
                ));
            }
            if !policy.accepts_multi_level() {
                return Err(MqttError::InvalidTopic(
                    "multi-level wildcard '#' is disabled by listener policy".into(),
                ));
            }
        }

        // Levels without wildcards must satisfy the group-name character rules.
        // Wildcard-only levels (`+` / `#`) bypass the per-character check.
        if !contains_single && !contains_multi {
            validate_level_chars(level)?;
        }
    }
    Ok(())
}

/// Return whether a filter contains any wildcard characters.
pub fn filter_has_wildcards(filter: &str) -> bool {
    filter.contains(WILDCARD_SINGLE) || filter.contains(WILDCARD_MULTI)
}

/// Match an MQTT topic filter against a concrete topic.
///
/// Implements MQTT 5.0 §4.7.1 matching semantics:
///
/// - Level counts must match, unless the filter's final level is `#`.
/// - `+` matches exactly one level (any non-empty level contents).
/// - `#` matches zero or more trailing levels (may match the empty tail).
///
/// Callers must have already passed `filter` through
/// [`validate_subscribe_filter`]; this function assumes syntactic
/// correctness and does not re-validate.
pub fn filter_matches(filter: &str, topic: &str) -> bool {
    let filter_levels: Vec<&str> = filter.split(LEVEL_SEP).collect();
    let topic_levels: Vec<&str> = topic.split(LEVEL_SEP).collect();

    for (idx, fl) in filter_levels.iter().enumerate() {
        if *fl == "#" {
            // '#' absorbs zero or more trailing topic levels (including empty).
            return true;
        }
        let Some(tl) = topic_levels.get(idx) else {
            // Filter has more literal levels than the topic provides.
            return false;
        };
        if *fl == "+" {
            // '+' matches exactly one level.
            continue;
        }
        if fl != tl {
            return false;
        }
    }
    // All filter levels consumed — topic must have no trailing levels.
    filter_levels.len() == topic_levels.len()
}

/// Validate a group name against rustgate's naming rules.
///
/// Group names must be:
/// - 1–255 bytes long
/// - ASCII printable characters only
/// - No whitespace
/// - No MQTT wildcard characters (`+`, `#`)
///
/// `/` is permitted as a hierarchy separator so that multi-level MQTT
/// topics can round-trip through the router without an explicit
/// remapping step.
fn validate_group_name(name: &str) -> Result<(), MqttError> {
    if name.is_empty() {
        return Err(MqttError::InvalidTopic(
            "topic maps to empty group name".into(),
        ));
    }
    if name.len() > MAX_GROUP_LEN {
        return Err(MqttError::InvalidTopic(format!(
            "group name exceeds {MAX_GROUP_LEN} byte limit"
        )));
    }
    for ch in name.chars() {
        if ch == WILDCARD_SINGLE || ch == WILDCARD_MULTI {
            return Err(MqttError::InvalidTopic(format!(
                "wildcard character in group name: {ch:?}"
            )));
        }
        // '/' is an allowed separator even though it is non-graphic in the
        // ASCII-control sense; all other non-graphic / whitespace chars reject.
        if ch == LEVEL_SEP {
            continue;
        }
        if ch.is_ascii_whitespace() || !ch.is_ascii_graphic() {
            return Err(MqttError::InvalidTopic(format!(
                "invalid character in group name: {ch:?}"
            )));
        }
    }
    Ok(())
}

/// Validate the character set of a non-wildcard filter level. Mirrors the
/// per-character rules of [`validate_group_name`] but operates on a single
/// level so empty-level diagnostics point at the right place.
fn validate_level_chars(level: &str) -> Result<(), MqttError> {
    // Empty levels ("foo//bar") are permitted by MQTT spec and round-trip
    // cleanly through `filter_matches` / `topic_to_group`; no rejection here.
    for ch in level.chars() {
        if ch.is_ascii_whitespace() || !ch.is_ascii_graphic() {
            return Err(MqttError::InvalidTopic(format!(
                "invalid character in topic level: {ch:?}"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn direct_topic_maps_to_group() {
        assert_eq!(topic_to_group("alpha", None).unwrap().as_ref(), "alpha");
    }

    #[test]
    fn prefix_strip_maps_correctly() {
        assert_eq!(
            topic_to_group("rustgate/alpha", Some("rustgate/"))
                .unwrap()
                .as_ref(),
            "alpha"
        );
    }

    #[test]
    fn no_prefix_returns_borrowed() {
        let result = topic_to_group("alpha", None).unwrap();
        assert!(matches!(result, Cow::Borrowed(_)));
    }

    #[test]
    fn prefix_returns_owned() {
        let result = topic_to_group("rustgate/alpha", Some("rustgate/")).unwrap();
        assert!(matches!(result, Cow::Owned(_)));
    }

    #[test]
    fn prefix_mismatch_rejected() {
        assert!(topic_to_group("other/alpha", Some("rustgate/")).is_err());
    }

    #[test]
    fn hierarchical_group_name_accepted() {
        // '/' is now allowed so MQTT multi-level topics map through cleanly.
        assert_eq!(
            topic_to_group("fleet/A/position", None).unwrap().as_ref(),
            "fleet/A/position"
        );
    }

    #[test]
    fn wildcard_chars_in_group_rejected() {
        // Wildcards still cannot appear in a *publish* topic / group mapping.
        assert!(topic_to_group("fleet/+/position", None).is_err());
        assert!(topic_to_group("fleet/#", None).is_err());
    }

    #[test]
    fn empty_topic_rejected() {
        assert!(validate_publish_topic("").is_err());
    }

    #[test]
    fn wildcard_in_publish_rejected() {
        assert!(validate_publish_topic("sensors/+/temp").is_err());
        assert!(validate_publish_topic("sensors/#").is_err());
    }

    // ----- validate_subscribe_filter (policy matrix) -----

    #[test]
    fn reject_policy_refuses_all_wildcards() {
        let p = WildcardPolicy::Reject;
        assert!(validate_subscribe_filter("alpha", p).is_ok());
        assert!(validate_subscribe_filter("fleet/+/position", p).is_err());
        assert!(validate_subscribe_filter("fleet/#", p).is_err());
    }

    #[test]
    fn single_level_policy_accepts_plus_rejects_hash() {
        let p = WildcardPolicy::SingleLevelOnly;
        assert!(validate_subscribe_filter("alpha", p).is_ok());
        assert!(validate_subscribe_filter("fleet/+/position", p).is_ok());
        assert!(validate_subscribe_filter("+", p).is_ok());
        assert!(validate_subscribe_filter("fleet/#", p).is_err());
        assert!(validate_subscribe_filter("#", p).is_err());
    }

    #[test]
    fn full_policy_accepts_both_wildcards() {
        let p = WildcardPolicy::Full;
        assert!(validate_subscribe_filter("alpha", p).is_ok());
        assert!(validate_subscribe_filter("fleet/+/position", p).is_ok());
        assert!(validate_subscribe_filter("fleet/#", p).is_ok());
        assert!(validate_subscribe_filter("#", p).is_ok());
    }

    #[test]
    fn plus_must_be_entire_level() {
        let p = WildcardPolicy::Full;
        assert!(validate_subscribe_filter("fleet/A+B/position", p).is_err());
        assert!(validate_subscribe_filter("fleet/+x/position", p).is_err());
        assert!(validate_subscribe_filter("fleet/x+/position", p).is_err());
    }

    #[test]
    fn hash_must_be_last_level_and_entire_level() {
        let p = WildcardPolicy::Full;
        assert!(validate_subscribe_filter("fleet/#/position", p).is_err());
        assert!(validate_subscribe_filter("fleet/x#", p).is_err());
        assert!(validate_subscribe_filter("fleet/#x", p).is_err());
    }

    #[test]
    fn empty_filter_rejected() {
        assert!(validate_subscribe_filter("", WildcardPolicy::Full).is_err());
    }

    // ----- filter_has_wildcards / filter_matches -----

    #[test]
    fn filter_has_wildcards_detects_plus_and_hash() {
        assert!(!filter_has_wildcards("fleet/A/position"));
        assert!(filter_has_wildcards("fleet/+/position"));
        assert!(filter_has_wildcards("fleet/#"));
    }

    #[test]
    fn filter_matches_exact() {
        assert!(filter_matches("fleet/A/position", "fleet/A/position"));
        assert!(!filter_matches("fleet/A/position", "fleet/B/position"));
    }

    #[test]
    fn filter_matches_plus_single_level() {
        assert!(filter_matches("fleet/+/position", "fleet/A/position"));
        assert!(filter_matches("fleet/+/position", "fleet/B/position"));
        // '+' does not span levels.
        assert!(!filter_matches("fleet/+/position", "fleet/A/B/position"));
        // Level count must match without '#'.
        assert!(!filter_matches("fleet/+/position", "fleet/A"));
    }

    #[test]
    fn filter_matches_hash_multi_level() {
        assert!(filter_matches("fleet/#", "fleet"));
        assert!(filter_matches("fleet/#", "fleet/A"));
        assert!(filter_matches("fleet/#", "fleet/A/B/position"));
        assert!(!filter_matches("fleet/#", "other/A"));
    }

    #[test]
    fn filter_matches_bare_plus_matches_single_level_only() {
        assert!(filter_matches("+", "alpha"));
        assert!(!filter_matches("+", "alpha/bravo"));
    }

    #[test]
    fn filter_matches_bare_hash_matches_everything() {
        assert!(filter_matches("#", "alpha"));
        assert!(filter_matches("#", "alpha/bravo/charlie"));
    }

    // ----- group-name validator -----

    #[test]
    fn whitespace_in_group_rejected() {
        assert!(topic_to_group("alpha beta", None).is_err());
    }

    #[test]
    fn long_group_name_rejected() {
        let long = "a".repeat(256);
        assert!(topic_to_group(&long, None).is_err());
    }

    #[test]
    fn max_length_group_accepted() {
        let max = "a".repeat(255);
        assert!(topic_to_group(&max, None).is_ok());
    }

    #[test]
    fn prefix_must_end_with_slash() {
        assert!(validate_topic_prefix("rustgate/").is_ok());
        assert!(validate_topic_prefix("").is_ok());
        assert!(validate_topic_prefix("rustgate").is_err());
        assert!(validate_topic_prefix("r").is_err());
    }

    #[test]
    fn default_policy_is_single_level_only() {
        assert_eq!(WildcardPolicy::default(), WildcardPolicy::SingleLevelOnly);
    }

    #[test]
    fn mqtt_topic_filter_byte_stable_for_known_inputs() {
        // Pin the validator's accept/reject matrix for a corpus of
        // inputs. The matrix in `rustgate_core::sanitize` documents
        // these as *validators* (return `Result<(), MqttError>`) rather
        // than transformers; this test pins which inputs produce `Ok`
        // and which produce `Err` so a regression that loosened or
        // tightened a rule fails CI immediately.
        // Format: (input, validator, policy, expect_ok)
        let publish_cases: &[(&str, bool)] = &[
            ("fleet/A/position", true),
            ("alpha", true),
            ("a/b/c", true),
            ("", false),
            ("fleet/+/position", false),
            ("fleet/#", false),
            ("fleet/+", false),
        ];
        for (input, expect_ok) in publish_cases {
            assert_eq!(
                validate_publish_topic(input).is_ok(),
                *expect_ok,
                "validate_publish_topic({input:?}) expected ok={expect_ok}"
            );
        }
        let subscribe_cases: &[(&str, WildcardPolicy, bool)] = &[
            ("alpha", WildcardPolicy::Reject, true),
            ("alpha", WildcardPolicy::SingleLevelOnly, true),
            ("alpha", WildcardPolicy::Full, true),
            ("fleet/+/position", WildcardPolicy::Reject, false),
            ("fleet/+/position", WildcardPolicy::SingleLevelOnly, true),
            ("fleet/+/position", WildcardPolicy::Full, true),
            ("fleet/#", WildcardPolicy::Reject, false),
            ("fleet/#", WildcardPolicy::SingleLevelOnly, false),
            ("fleet/#", WildcardPolicy::Full, true),
            ("fleet/A+B", WildcardPolicy::Full, false),
            ("fleet/x#", WildcardPolicy::Full, false),
            ("fleet/#/position", WildcardPolicy::Full, false),
            ("", WildcardPolicy::Full, false),
            ("alpha beta", WildcardPolicy::Full, false),
        ];
        for (input, policy, expect_ok) in subscribe_cases {
            assert_eq!(
                validate_subscribe_filter(input, *policy).is_ok(),
                *expect_ok,
                "validate_subscribe_filter({input:?}, {policy:?}) expected ok={expect_ok}"
            );
        }
        let prefix_cases: &[(&str, bool)] = &[
            ("rustgate/", true),
            ("", true),
            ("rustgate", false),
            ("r", false),
        ];
        for (input, expect_ok) in prefix_cases {
            assert_eq!(
                validate_topic_prefix(input).is_ok(),
                *expect_ok,
                "validate_topic_prefix({input:?}) expected ok={expect_ok}"
            );
        }
    }

    #[test]
    fn matrix_invariant_mqtt_validators_reject_rather_than_transform() {
        // Pinned axis from the module-doc matrix in `rustgate_core::sanitize`:
        // MQTT topic validators REJECT malformed input rather than
        // silently transforming it (in contrast to `sanitize_filename`
        // which would map a `/` to `_`, or `sanitize_nats_token` which
        // would strip a control char). A regression that switched any
        // of these validators to a transformer would silently mutate the
        // wire-visible topic bytes seen by a subscriber.
        assert!(validate_publish_topic("fleet/+/x").is_err());
        assert!(validate_subscribe_filter("alpha beta", WildcardPolicy::Full).is_err());
        assert!(validate_topic_prefix("missing-trailing-slash").is_err());
    }
}
