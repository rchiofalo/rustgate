// Copyright © 2026 Roberto Chiofalo.

//! Per-target message filtering.
//!
//! Compiles [`FilterConfig`] into a [`CompiledFilter`] that can efficiently
//! test whether a [`RoutableMessage`] should be forwarded to a given target.
//! Filters are AND-combined across dimensions: a message must match all
//! configured dimensions to pass. Within a dimension, values are OR-combined.

use std::collections::HashSet;

use rustgate_core::message::RoutableMessage;

use crate::config::FilterConfig;

/// Compiled message filter for a single target.
///
/// Pre-computes hashsets from the raw config vectors for O(1) lookups
/// on the hot path. The `"http"` protocol is always excluded to prevent
/// echo loops, even if not explicitly configured.
#[derive(Debug)]
pub(crate) struct CompiledFilter {
    groups: Option<HashSet<String>>,
    message_types: Option<HashSet<String>>,
    source_cns: Option<HashSet<String>>,
    exclude_protocols: HashSet<String>,
}

impl CompiledFilter {
    /// Build a compiled filter from config.
    ///
    /// Ensures `"http"` is always in `exclude_protocols` for echo prevention.
    /// Source CNs are lowercased for case-insensitive matching (following the
    /// ACL module convention).
    pub(crate) fn from_config(config: &FilterConfig) -> Self {
        let groups = config.groups.as_ref().map(|g| g.iter().cloned().collect());

        let message_types = config
            .message_types
            .as_ref()
            .map(|t| t.iter().cloned().collect());

        // Lowercase for case-insensitive CN matching
        let source_cns = config
            .source_cns
            .as_ref()
            .map(|c| c.iter().map(|s| s.to_ascii_lowercase()).collect());

        // Always include "http" in excluded protocols.
        // Lowercase all entries for case-insensitive matching.
        let mut exclude = config
            .exclude_protocols
            .as_ref()
            .map(|p| {
                p.iter()
                    .map(|s| s.to_ascii_lowercase())
                    .collect::<HashSet<_>>()
            })
            .unwrap_or_default();
        let _ = exclude.insert("http".to_string());

        Self {
            groups,
            message_types,
            source_cns,
            exclude_protocols: exclude,
        }
    }

    /// Build a default filter that only excludes `"http"` protocol.
    pub(crate) fn default_filter() -> Self {
        let mut exclude = HashSet::new();
        let _ = exclude.insert("http".to_string());
        Self {
            groups: None,
            message_types: None,
            source_cns: None,
            exclude_protocols: exclude,
        }
    }

    /// Returns `true` if the message should be forwarded to this target.
    pub(crate) fn matches(&self, msg: &RoutableMessage) -> bool {
        // Echo prevention: skip messages from excluded protocols.
        // Uses eq_ignore_ascii_case to avoid allocating a lowercased copy
        // on every hot-path evaluation.
        if self
            .exclude_protocols
            .iter()
            .any(|p| p.eq_ignore_ascii_case(&msg.metadata.source_protocol))
        {
            return false;
        }

        // Groups: sender must be in at least one of the configured groups
        if let Some(filter_groups) = &self.groups {
            let has_match = msg.source.groups.iter().any(|g| filter_groups.contains(g));
            if !has_match {
                return false;
            }
        }

        // Message type: must match at least one configured type
        if let Some(filter_types) = &self.message_types
            && !filter_types.contains(&msg.metadata.message_type.to_string())
        {
            return false;
        }

        // Source CN: must match (case-insensitive)
        if let Some(filter_cns) = &self.source_cns
            && !filter_cns.contains(&msg.source.cn.to_ascii_lowercase())
        {
            return false;
        }

        true
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use std::collections::BTreeSet;
    use std::sync::Arc;
    use std::time::SystemTime;

    use bytes::Bytes;
    use rustgate_core::identity::Identity;
    use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};

    use super::*;

    fn make_msg(
        cn: &str,
        groups: &[&str],
        protocol: &str,
        msg_type: MessageType,
    ) -> RoutableMessage {
        RoutableMessage {
            source: Identity {
                cn: cn.to_string(),
                fingerprint: Default::default(),
                groups: groups
                    .iter()
                    .map(|g| (*g).to_string())
                    .collect::<BTreeSet<_>>(),
                tenant: None,
                spiffe_id: None,
                attributes: Arc::new(Default::default()),
            },
            destination: Destination::Broadcast,
            payload: Bytes::from_static(b"<event/>"),
            metadata: Metadata {
                received_at: SystemTime::now(),
                source_protocol: protocol.to_string(),
                message_type: msg_type,
                ttl: None,
            },
        }
    }

    #[test]
    fn default_filter_allows_tcp() {
        let filter = CompiledFilter::default_filter();
        let msg = make_msg("alice", &["alpha"], "tcp", MessageType::Position);
        assert!(filter.matches(&msg));
    }

    #[test]
    fn default_filter_blocks_http() {
        let filter = CompiledFilter::default_filter();
        let msg = make_msg("alice", &["alpha"], "http", MessageType::Position);
        assert!(!filter.matches(&msg));
    }

    #[test]
    fn echo_prevention_always_includes_http() {
        let config = FilterConfig {
            groups: None,
            message_types: None,
            source_cns: None,
            exclude_protocols: Some(vec!["nats".to_string()]),
        };
        let filter = CompiledFilter::from_config(&config);
        // Both http and nats should be blocked
        let http_msg = make_msg("alice", &["alpha"], "http", MessageType::Position);
        let nats_msg = make_msg("alice", &["alpha"], "nats", MessageType::Position);
        assert!(!filter.matches(&http_msg));
        assert!(!filter.matches(&nats_msg));
    }

    #[test]
    fn group_filter_accepts_matching() {
        let config = FilterConfig {
            groups: Some(vec!["alpha".to_string(), "bravo".to_string()]),
            message_types: None,
            source_cns: None,
            exclude_protocols: None,
        };
        let filter = CompiledFilter::from_config(&config);
        let msg = make_msg("alice", &["alpha"], "tcp", MessageType::Position);
        assert!(filter.matches(&msg));
    }

    #[test]
    fn group_filter_rejects_non_matching() {
        let config = FilterConfig {
            groups: Some(vec!["alpha".to_string()]),
            message_types: None,
            source_cns: None,
            exclude_protocols: None,
        };
        let filter = CompiledFilter::from_config(&config);
        let msg = make_msg("alice", &["charlie"], "tcp", MessageType::Position);
        assert!(!filter.matches(&msg));
    }

    #[test]
    fn message_type_filter_accepts_matching() {
        let config = FilterConfig {
            groups: None,
            message_types: Some(vec!["position".to_string(), "alert".to_string()]),
            source_cns: None,
            exclude_protocols: None,
        };
        let filter = CompiledFilter::from_config(&config);
        let msg = make_msg("alice", &["alpha"], "tcp", MessageType::Alert);
        assert!(filter.matches(&msg));
    }

    #[test]
    fn message_type_filter_rejects_non_matching() {
        let config = FilterConfig {
            groups: None,
            message_types: Some(vec!["position".to_string()]),
            source_cns: None,
            exclude_protocols: None,
        };
        let filter = CompiledFilter::from_config(&config);
        let msg = make_msg("alice", &["alpha"], "tcp", MessageType::Chat);
        assert!(!filter.matches(&msg));
    }

    #[test]
    fn source_cn_filter_case_insensitive() {
        let config = FilterConfig {
            groups: None,
            message_types: None,
            source_cns: Some(vec!["Command-Post-1".to_string()]),
            exclude_protocols: None,
        };
        let filter = CompiledFilter::from_config(&config);
        let msg = make_msg("command-post-1", &["alpha"], "tcp", MessageType::Position);
        assert!(filter.matches(&msg));
    }

    #[test]
    fn source_cn_filter_rejects_non_matching() {
        let config = FilterConfig {
            groups: None,
            message_types: None,
            source_cns: Some(vec!["allowed-cn".to_string()]),
            exclude_protocols: None,
        };
        let filter = CompiledFilter::from_config(&config);
        let msg = make_msg("other-cn", &["alpha"], "tcp", MessageType::Position);
        assert!(!filter.matches(&msg));
    }

    #[test]
    fn combined_filters_and_logic() {
        let config = FilterConfig {
            groups: Some(vec!["alpha".to_string()]),
            message_types: Some(vec!["position".to_string()]),
            source_cns: Some(vec!["alice".to_string()]),
            exclude_protocols: None,
        };
        let filter = CompiledFilter::from_config(&config);

        // All match
        let msg = make_msg("alice", &["alpha"], "tcp", MessageType::Position);
        assert!(filter.matches(&msg));

        // Wrong group
        let msg = make_msg("alice", &["bravo"], "tcp", MessageType::Position);
        assert!(!filter.matches(&msg));

        // Wrong type
        let msg = make_msg("alice", &["alpha"], "tcp", MessageType::Chat);
        assert!(!filter.matches(&msg));

        // Wrong CN
        let msg = make_msg("bob", &["alpha"], "tcp", MessageType::Position);
        assert!(!filter.matches(&msg));
    }

    #[test]
    fn none_dimensions_accept_all() {
        let config = FilterConfig {
            groups: None,
            message_types: None,
            source_cns: None,
            exclude_protocols: None,
        };
        let filter = CompiledFilter::from_config(&config);
        let msg = make_msg("anyone", &["any-group"], "tcp", MessageType::Chat);
        assert!(filter.matches(&msg));
    }

    #[test]
    fn sender_in_multiple_groups_matches_any() {
        let config = FilterConfig {
            groups: Some(vec!["bravo".to_string()]),
            message_types: None,
            source_cns: None,
            exclude_protocols: None,
        };
        let filter = CompiledFilter::from_config(&config);
        // Sender is in both alpha and bravo — bravo matches
        let msg = make_msg("alice", &["alpha", "bravo"], "tcp", MessageType::Position);
        assert!(filter.matches(&msg));
    }

    #[test]
    fn exclude_protocols_case_insensitive_on_sender_side() {
        // The filter lowercases on insert into the HashSet but then
        // compares via `eq_ignore_ascii_case` — the comparator is the
        // load-bearing half, because the sender-side `source_protocol`
        // string is attacker-influenced (a buggy upstream peer could
        // emit `"HTTP"`, `"Http"`, `"hTTp"`, etc.) and the echo-
        // prevention contract must hold irrespective of its case.
        // A regression that dropped `eq_ignore_ascii_case` and relied
        // only on pre-lowercased storage would still pass every
        // happy-path lowercase test but silently let `"HTTP"` from a
        // federated peer re-enter the HTTP egress path and create a
        // routing loop.
        let filter = CompiledFilter::default_filter();
        for variant in ["HTTP", "Http", "hTTp", "http"] {
            let msg = make_msg("alice", &["alpha"], variant, MessageType::Position);
            assert!(
                !filter.matches(&msg),
                "sender protocol {variant:?} must be blocked by echo prevention"
            );
        }
    }

    #[test]
    fn exclude_protocols_config_side_also_lowercased_on_insert() {
        // Symmetric invariant: the storage side lowercases every
        // configured entry so that a mixed-case config (`"NATS"`,
        // `"Mqtt"`) still matches a lowercased sender protocol. If
        // the storage ever stopped lowercasing, `eq_ignore_ascii_case`
        // would still save us — but pinning both halves guards the
        // operational contract "operators can write exclude-protocols
        // in whatever case they like and the filter just works"
        // against a refactor that touched one side without the other.
        let config = FilterConfig {
            groups: None,
            message_types: None,
            source_cns: None,
            exclude_protocols: Some(vec!["NATS".to_string(), "Mqtt".to_string()]),
        };
        let filter = CompiledFilter::from_config(&config);
        let nats_msg = make_msg("alice", &["alpha"], "nats", MessageType::Position);
        let mqtt_msg = make_msg("alice", &["alpha"], "mqtt", MessageType::Position);
        assert!(!filter.matches(&nats_msg));
        assert!(!filter.matches(&mqtt_msg));
    }

    #[test]
    fn groups_filter_is_case_sensitive_unlike_source_cns() {
        // Deliberate asymmetry with `source_cns`: group names are
        // compared case-sensitively because a GroupId in rustgate is
        // a case-preserving identifier (the ACL module treats
        // `"SpecialOps"` and `"specialops"` as distinct groups — see
        // `rustgate_core::identity::GroupId`). The filter must respect
        // that same invariant; a regression that added
        // `.to_ascii_lowercase()` to the group-dimension compile step
        // would silently collapse distinct groups and route messages
        // to the wrong egress target. This test pins the contract by
        // requiring the *exact-case* match to succeed AND the
        // opposite-case config to *not* match, in a single
        // assertion pair.
        let exact = FilterConfig {
            groups: Some(vec!["SpecialOps".to_string()]),
            message_types: None,
            source_cns: None,
            exclude_protocols: None,
        };
        let lower = FilterConfig {
            groups: Some(vec!["specialops".to_string()]),
            message_types: None,
            source_cns: None,
            exclude_protocols: None,
        };
        let exact_filter = CompiledFilter::from_config(&exact);
        let lower_filter = CompiledFilter::from_config(&lower);
        let msg = make_msg("alice", &["SpecialOps"], "tcp", MessageType::Position);
        assert!(
            exact_filter.matches(&msg),
            "exact-case group must match sender's case-preserved group"
        );
        assert!(
            !lower_filter.matches(&msg),
            "lowercase filter must NOT match mixed-case sender group — asymmetric to source_cns"
        );
    }

    #[test]
    fn message_type_filter_matches_display_lowercase_rendering() {
        // The filter compares against
        // `msg.metadata.message_type.to_string()` — which is the
        // MessageType Display impl from
        // `rustgate_core::message::MessageType`. That Display impl
        // emits lowercase tokens (`"position"`, `"chat"`, `"alert"`,
        // `"status"`, `"file"`, `"mavlink"`). The config side is
        // stored verbatim in a HashSet, so every configured value
        // MUST match the lowercase Display output. A regression that
        // changed Display to TitleCase (a plausible "operator-facing
        // improvement" diff) would silently break every deployed
        // message-type filter without a compile error — this test
        // pins the lowercase-tokens contract across all six built-in
        // variants in a single assertion sweep.
        for (variant, token) in [
            (MessageType::Position, "position"),
            (MessageType::Chat, "chat"),
            (MessageType::Alert, "alert"),
            (MessageType::Status, "status"),
            (MessageType::File, "file"),
            (MessageType::Mavlink, "mavlink"),
        ] {
            let config = FilterConfig {
                groups: None,
                message_types: Some(vec![token.to_string()]),
                source_cns: None,
                exclude_protocols: None,
            };
            let filter = CompiledFilter::from_config(&config);
            let msg = make_msg("alice", &["alpha"], "tcp", variant.clone());
            assert!(
                filter.matches(&msg),
                "MessageType::{variant:?} must render as lowercase token {token:?}"
            );
        }
    }

    #[test]
    fn message_type_other_variant_renders_other_colon_prefix() {
        // `MessageType::Other(s)` is the catch-all variant used for
        // protocol-specific or vendor-specific types; its Display
        // prefix `"other:"` is the wire contract every filter config
        // references. A regression that dropped the prefix would
        // silently break filters configured with the documented
        // `"other:foo"` tokens — the filter would no longer match
        // the emitted string.
        let config = FilterConfig {
            groups: None,
            message_types: Some(vec!["other:foo".to_string()]),
            source_cns: None,
            exclude_protocols: None,
        };
        let filter = CompiledFilter::from_config(&config);
        let msg = make_msg(
            "alice",
            &["alpha"],
            "tcp",
            MessageType::Other("foo".to_string()),
        );
        assert!(filter.matches(&msg));
    }

    #[test]
    fn empty_filter_vector_rejects_everything_in_that_dimension() {
        // `Some(vec![])` on any dimension means "allow only the
        // values in this list" where the list is empty — i.e. reject
        // everything. This is the critical fail-closed contract for
        // operators who ship a misconfigured policy: an empty list
        // means "nothing", not "everything". A regression that
        // conflated `Some(empty)` with `None` (as a "helpful" short-
        // circuit) would silently open the filter wide and route
        // every message to the target, which inverts the
        // least-privilege expectation every downstream operator
        // assumes. Pin the fail-closed contract on all three
        // positive-match dimensions.
        for (label, cfg) in [
            (
                "groups",
                FilterConfig {
                    groups: Some(vec![]),
                    message_types: None,
                    source_cns: None,
                    exclude_protocols: None,
                },
            ),
            (
                "message_types",
                FilterConfig {
                    groups: None,
                    message_types: Some(vec![]),
                    source_cns: None,
                    exclude_protocols: None,
                },
            ),
            (
                "source_cns",
                FilterConfig {
                    groups: None,
                    message_types: None,
                    source_cns: Some(vec![]),
                    exclude_protocols: None,
                },
            ),
        ] {
            let filter = CompiledFilter::from_config(&cfg);
            let msg = make_msg("alice", &["alpha"], "tcp", MessageType::Position);
            assert!(
                !filter.matches(&msg),
                "empty {label} vector must fail-closed, not fail-open"
            );
        }
    }

    #[test]
    fn sender_with_no_groups_fails_group_filter() {
        // A sender with an empty `groups` set cannot match any
        // configured group — the iter-over-source-groups short-
        // circuits to false, which is the correct fail-closed
        // behaviour for unauthenticated / misconfigured clients
        // whose mTLS cert has no group SAN. Pinning this keeps a
        // refactor that replaced `any(|g| filter.contains(g))` with
        // a set-intersection primitive from silently flipping the
        // empty-set case.
        let config = FilterConfig {
            groups: Some(vec!["alpha".to_string()]),
            message_types: None,
            source_cns: None,
            exclude_protocols: None,
        };
        let filter = CompiledFilter::from_config(&config);
        let groupless_msg = make_msg("alice", &[], "tcp", MessageType::Position);
        assert!(!filter.matches(&groupless_msg));
    }

    #[test]
    fn exclude_protocols_is_exact_match_not_prefix_or_substring() {
        // The comparator is `eq_ignore_ascii_case`, not `starts_with`
        // or `contains`. A sender protocol `"http2"` must NOT be
        // blocked by an `"http"` exclusion (they are distinct
        // protocols — QUIC, HTTP/2 over TCP, etc.). A regression
        // that switched to substring matching "for convenience" would
        // silently block every HTTP/2, HTTPS, or HTTP-adjacent
        // federated protocol and break legitimate traffic.
        let filter = CompiledFilter::default_filter();
        let http2_msg = make_msg("alice", &["alpha"], "http2", MessageType::Position);
        let https_msg = make_msg("alice", &["alpha"], "https", MessageType::Position);
        assert!(
            filter.matches(&http2_msg),
            "exclude_protocols must be exact-match — \"http2\" is distinct from \"http\""
        );
        assert!(
            filter.matches(&https_msg),
            "exclude_protocols must be exact-match — \"https\" is distinct from \"http\""
        );
    }

    #[test]
    fn duplicate_config_entries_do_not_affect_match_outcome() {
        // The compile step folds config `Vec<String>` into `HashSet`
        // dedup, so `["alpha", "alpha", "ALPHA"]` on the `source_cns`
        // dimension collapses to a single lowercased entry `"alpha"`.
        // This is not purely a performance concern: an operator
        // accidentally duplicating entries should not change any
        // matching outcome, and a regression that used
        // `Vec::contains` instead of `HashSet::contains` would not
        // observably change behaviour on dups either — but pinning
        // the outcome keeps the *logical* contract stable regardless
        // of which storage type the compile step chooses.
        let config = FilterConfig {
            groups: None,
            message_types: None,
            source_cns: Some(vec![
                "alice".to_string(),
                "alice".to_string(),
                "ALICE".to_string(),
            ]),
            exclude_protocols: None,
        };
        let filter = CompiledFilter::from_config(&config);
        let match_msg = make_msg("alice", &["alpha"], "tcp", MessageType::Position);
        let miss_msg = make_msg("bob", &["alpha"], "tcp", MessageType::Position);
        assert!(filter.matches(&match_msg));
        assert!(!filter.matches(&miss_msg));
    }

    #[test]
    fn destination_field_is_not_inspected_by_filter() {
        // The filter reads only `source.groups`, `source.cn`,
        // `metadata.source_protocol`, and `metadata.message_type` —
        // it deliberately ignores `destination`, because HTTP egress
        // is a per-target broadcast-style endpoint and the target
        // itself is the routing decision. A regression that started
        // consulting `destination` would silently start dropping
        // unicast / multicast messages whose destination did not
        // match an operator-invisible heuristic. Pin the contract by
        // constructing three different Destinations and asserting
        // every one passes an otherwise-matching filter.
        let config = FilterConfig {
            groups: Some(vec!["alpha".to_string()]),
            message_types: None,
            source_cns: None,
            exclude_protocols: None,
        };
        let filter = CompiledFilter::from_config(&config);
        let mut base = make_msg("alice", &["alpha"], "tcp", MessageType::Position);
        base.destination = Destination::Broadcast;
        assert!(filter.matches(&base));
        base.destination = Destination::Group("bravo".to_string());
        assert!(filter.matches(&base));
        base.destination = Destination::Multicast(vec!["alpha".to_string(), "bravo".to_string()]);
        assert!(filter.matches(&base));
    }

    #[test]
    fn default_filter_and_empty_exclude_protocols_config_are_equivalent_for_http() {
        // Two plausible constructions of "filter that only blocks
        // http" must produce the same matcher: `default_filter()`
        // directly, and `from_config(FilterConfig { all None })`.
        // A regression that made `from_config` diverge (for example,
        // by failing to unconditionally seed the "http" entry when
        // `exclude_protocols` was `None`) would silently start
        // leaking echo loops for targets with no filter block at
        // all — pin the equivalence.
        let direct = CompiledFilter::default_filter();
        let from_all_none = CompiledFilter::from_config(&FilterConfig {
            groups: None,
            message_types: None,
            source_cns: None,
            exclude_protocols: None,
        });
        let http_msg = make_msg("alice", &["alpha"], "http", MessageType::Position);
        let tcp_msg = make_msg("alice", &["alpha"], "tcp", MessageType::Position);
        assert!(!direct.matches(&http_msg));
        assert!(!from_all_none.matches(&http_msg));
        assert!(direct.matches(&tcp_msg));
        assert!(from_all_none.matches(&tcp_msg));
    }

    #[test]
    fn compiled_filter_implements_debug() {
        // The struct is `#[derive(Debug)]` so it can appear inside
        // the `HttpPublisher`'s own `Debug` output without a custom
        // `finish_non_exhaustive()` escape hatch — `CompiledFilter`
        // holds no secrets, only operator-supplied group / CN /
        // protocol names, so full Debug is safe. A regression that
        // dropped the derive (e.g. because someone decided to
        // implement a custom `finish_non_exhaustive()` for
        // consistency with `HttpPublisher`) would break the
        // auto-derived Debug chain on every enclosing type and
        // silently degrade operator diagnostics.
        let filter = CompiledFilter::default_filter();
        let rendered = format!("{filter:?}");
        assert!(
            rendered.contains("CompiledFilter"),
            "Debug must name the type: {rendered}"
        );
    }
}
