// Copyright © 2026 Roberto Chiofalo.

//! MQTT topic ↔ rustgate group mapping and validation.
//!
//! MQTT topics are UTF-8 strings with `/` as a level separator.
//! rustgate group names are restricted to printable ASCII without `/`.
//! This module handles the translation and validates both sides.

use std::borrow::Cow;

use crate::error::MqttError;

/// Maximum group name length after topic mapping.
const MAX_GROUP_LEN: usize = 255;

/// Map an MQTT topic to a rustgate group name.
///
/// If `prefix` is `Some`, the topic must start with the prefix; the prefix
/// is stripped and the remainder becomes the group name. If `prefix` is
/// `None`, the topic is used as-is.
///
/// Returns `Cow::Borrowed` when no prefix is configured (zero allocation).
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
    if topic.contains('+') || topic.contains('#') {
        return Err(MqttError::InvalidTopic(
            "wildcards (+, #) are not allowed in publish topics".into(),
        ));
    }
    Ok(())
}

/// Validate that a subscribe topic filter is acceptable for v1.
///
/// In v1, wildcards (`+`, `#`) are rejected. Only exact topic matches
/// are supported. Future versions will add wildcard support.
pub fn validate_subscribe_filter(filter: &str) -> Result<(), MqttError> {
    if filter.is_empty() {
        return Err(MqttError::InvalidTopic("empty topic filter".into()));
    }
    if filter.contains('+') || filter.contains('#') {
        return Err(MqttError::InvalidTopic(
            "wildcard topic filters are not supported in v1".into(),
        ));
    }
    Ok(())
}

/// Validate a group name against rustgate's naming rules.
///
/// Group names must be:
/// - 1–255 bytes long
/// - ASCII printable characters only
/// - No `/` (reserved as MQTT level separator; stripped during mapping)
/// - No whitespace
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
    if name.contains('/') {
        return Err(MqttError::InvalidTopic(
            "mapped group name must not contain '/'".into(),
        ));
    }
    for ch in name.chars() {
        if ch.is_ascii_whitespace() || !ch.is_ascii_graphic() {
            return Err(MqttError::InvalidTopic(format!(
                "invalid character in group name: {ch:?}"
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
    fn slash_in_group_rejected() {
        assert!(topic_to_group("a/b", None).is_err());
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

    #[test]
    fn wildcard_in_subscribe_rejected_v1() {
        assert!(validate_subscribe_filter("sensors/+/temp").is_err());
        assert!(validate_subscribe_filter("sensors/#").is_err());
    }

    #[test]
    fn valid_subscribe_filter_accepted() {
        assert!(validate_subscribe_filter("alpha").is_ok());
    }

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
}
