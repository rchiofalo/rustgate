// Copyright © 2026 Roberto Chiofalo.

//! TOML configuration for the OGC SensorThings v1.0 client.
//!
//! Operators configure the client through a single `[sensorthings]`
//! section in `rustgate.toml`. The endpoint and global poll
//! configuration live at the top level; per-datastream subscription
//! tables live in repeated `[[sensorthings.subscriptions]]` blocks.
//!
//! Every config struct uses `kebab-case` field names with
//! `deny_unknown_fields` so a typo (`poll_interval_secs` instead of
//! `poll-interval-secs`) is rejected at parse time rather than
//! silently ignored.
//!
//! # Schema example
//!
//! ```toml
//! [sensorthings]
//! endpoint = "https://example.org/SensorThings/v1.0"
//! auth-token-path = "/secrets/sensorthings-token"   # optional
//! poll-interval-secs = 30
//! request-timeout-secs = 10
//! expand-location = true
//!
//! [[sensorthings.subscriptions]]
//! datastream-id = 42
//! entity-kind = "sensor"
//! group = "weather"           # optional Destination::Group target
//! poll-interval-secs = 15     # optional override of top-level interval
//! page-size = 100             # ?$top= for the polling URL
//! ```

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::SensorThingsError;

/// Default per-datastream polling interval when neither the global
/// nor the subscription-level field is set. Chosen to be slow
/// enough that an unconfigured operator does not hammer a public
/// SensorThings endpoint and fast enough that fixed-station
/// telemetry stays usefully fresh.
pub const DEFAULT_POLL_INTERVAL_SECS: u64 = 30;

/// Default per-request timeout. SensorThings servers vary widely in
/// response latency (a small static dataset returns in tens of ms,
/// a heavy `?$expand=` query against a busy regional weather
/// network can take seconds). 10 s is a comfortable upper bound for
/// the common case.
pub const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 10;

/// Default page size — the value the polling client passes as
/// `?$top=`. SensorThings caps this server-side; servers commonly
/// return at most 100 documents per page even when a larger
/// `?$top=` is supplied.
pub const DEFAULT_PAGE_SIZE: u32 = 100;

/// Root of the SensorThings client configuration.
///
/// `endpoint` is the SensorThings v1.0 root — the URL up to and
/// including `/v1.0` (or `/v1.1`, when servers support both). The
/// polling client appends `/Datastreams(<id>)/Observations…` for
/// each subscription.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct SensorThingsConfig {
    /// Base URL of the SensorThings server, up to and including the
    /// version segment (e.g.
    /// `"https://example.org/SensorThings/v1.0"`). The trailing
    /// slash is optional — the polling client normalises it.
    pub endpoint: String,

    /// Path to a file holding a bearer token used to authenticate
    /// requests. When set, every poll carries
    /// `Authorization: Bearer <token>`. The wiring task is
    /// responsible for the `Zeroizing` wrap and the perm check —
    /// the schema only carries the path.
    #[serde(default)]
    pub auth_token_path: Option<String>,

    /// Default per-datastream polling interval in seconds. Each
    /// subscription may override it.
    #[serde(default = "default_poll_interval_secs")]
    pub poll_interval_secs: u64,

    /// Per-request HTTP timeout in seconds. Wired into the reqwest
    /// client at startup; not overridable per subscription.
    #[serde(default = "default_request_timeout_secs")]
    pub request_timeout_secs: u64,

    /// When `true`, every poll carries
    /// `?$expand=Datastream/Thing/Locations` so the mapper can
    /// resolve the sensor station's lat/lon in a single round
    /// trip. Disable to save bandwidth when the operator does not
    /// need geospatial position on the entity (positionless entries
    /// still ride through, the mapper just emits
    /// `Entity::position = None`).
    #[serde(default = "default_expand_location")]
    pub expand_location: bool,

    /// Per-datastream subscription list. Empty by default — a
    /// configuration with zero subscriptions is valid (the
    /// polling task starts no per-stream loops and exits cleanly
    /// on shutdown).
    #[serde(default)]
    pub subscriptions: Vec<Subscription>,
}

/// One entry in the subscription list. Each entry binds a
/// SensorThings `Datastream` id to a rustgate-side
/// [`rustgate_core::entity::EntityKind`] tag and an optional
/// destination group.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Subscription {
    /// SensorThings-side numeric `Datastream` id. The polling URL
    /// is composed as
    /// `<endpoint>/Datastreams(<datastream_id>)/Observations`.
    pub datastream_id: u64,

    /// Tag controlling the [`rustgate_core::entity::EntityKind`]
    /// the mapper assigns. Defaults to `Sensor`, which is the
    /// right answer for almost every SensorThings deployment —
    /// other tags exist for the rare case where the operator wants
    /// to surface a SensorThings stream as e.g. a `Track` or
    /// `Ground` entity for compatibility with existing dashboards.
    #[serde(default)]
    pub entity_kind: EntityKindTag,

    /// Optional group identifier — when present, the
    /// `RoutableMessage` the wiring emits targets
    /// `Destination::Group(<group>)`. When absent, the message is
    /// `Destination::Broadcast`.
    #[serde(default)]
    pub group: Option<String>,

    /// Optional override of the top-level
    /// [`SensorThingsConfig::poll_interval_secs`] for this
    /// subscription only. Useful when one datastream is a slow
    /// station report and another is a fast tactical sensor on
    /// the same SensorThings tenant.
    #[serde(default)]
    pub poll_interval_secs: Option<u64>,

    /// Optional override of the per-request `?$top=` page size.
    /// Defaults to [`DEFAULT_PAGE_SIZE`].
    #[serde(default = "default_page_size_opt")]
    pub page_size: Option<u32>,
}

/// Tag for the [`rustgate_core::entity::EntityKind`] the mapper
/// assigns to every observation in a subscription. The tag string
/// matches the closed [`rustgate_core::entity::EntityKind::as_str`]
/// vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EntityKindTag {
    /// Default — sensor reading. The right answer for the vast
    /// majority of SensorThings deployments.
    #[default]
    Sensor,
    /// Generic track classification.
    Track,
    /// Air platform.
    Aircraft,
    /// Ground platform.
    Ground,
    /// Marine platform.
    Marine,
    /// Munition.
    Munition,
}

impl EntityKindTag {
    /// Project the configuration tag onto the canonical
    /// [`rustgate_core::entity::EntityKind`].
    pub fn to_entity_kind(self) -> rustgate_core::entity::EntityKind {
        use rustgate_core::entity::EntityKind;
        match self {
            Self::Sensor => EntityKind::Sensor,
            Self::Track => EntityKind::Track,
            Self::Aircraft => EntityKind::Aircraft,
            Self::Ground => EntityKind::Ground,
            Self::Marine => EntityKind::Marine,
            Self::Munition => EntityKind::Munition,
        }
    }
}

impl SensorThingsConfig {
    /// Validate the configuration's runtime invariants. Returns the
    /// first failure; subsequent fields are not checked.
    ///
    /// `serde::Deserialize` already enforces the structural
    /// invariants (kebab-case names, `deny_unknown_fields`,
    /// required vs optional fields). This validator catches the
    /// shape-level bugs: empty endpoint, zero `datastream-id`,
    /// duplicate datastream subscriptions, sub-second poll
    /// intervals.
    pub fn validate(&self) -> Result<(), SensorThingsError> {
        if self.endpoint.trim().is_empty() {
            return Err(SensorThingsError::Config {
                message: "[sensorthings] endpoint must be a non-empty URL".into(),
            });
        }
        if !self.endpoint.starts_with("http://") && !self.endpoint.starts_with("https://") {
            return Err(SensorThingsError::Config {
                message: format!(
                    "[sensorthings] endpoint must start with `http://` or `https://`, got `{}`",
                    self.endpoint,
                ),
            });
        }
        if self.poll_interval_secs == 0 {
            return Err(SensorThingsError::Config {
                message: "[sensorthings] poll-interval-secs must be > 0".into(),
            });
        }
        if self.request_timeout_secs == 0 {
            return Err(SensorThingsError::Config {
                message: "[sensorthings] request-timeout-secs must be > 0".into(),
            });
        }
        let mut seen_ids = std::collections::HashSet::new();
        for sub in &self.subscriptions {
            if sub.datastream_id == 0 {
                return Err(SensorThingsError::Config {
                    message: "subscription `datastream-id` must be > 0".into(),
                });
            }
            if !seen_ids.insert(sub.datastream_id) {
                return Err(SensorThingsError::Config {
                    message: format!(
                        "duplicate subscription for datastream-id {}",
                        sub.datastream_id,
                    ),
                });
            }
            if matches!(sub.poll_interval_secs, Some(0)) {
                return Err(SensorThingsError::Config {
                    message: format!(
                        "subscription for datastream-id {} has poll-interval-secs = 0",
                        sub.datastream_id,
                    ),
                });
            }
            if matches!(sub.page_size, Some(0)) {
                return Err(SensorThingsError::Config {
                    message: format!(
                        "subscription for datastream-id {} has page-size = 0",
                        sub.datastream_id,
                    ),
                });
            }
        }
        Ok(())
    }

    /// Resolve the polling interval for a particular subscription —
    /// the per-subscription override when present, otherwise the
    /// top-level value.
    pub fn effective_poll_interval(&self, sub: &Subscription) -> Duration {
        let secs = sub.poll_interval_secs.unwrap_or(self.poll_interval_secs);
        Duration::from_secs(secs.max(1))
    }

    /// Resolve the per-request timeout — currently only the
    /// top-level value, but exposed as a method so a future
    /// per-subscription override is a non-breaking change.
    pub fn effective_request_timeout(&self) -> Duration {
        Duration::from_secs(self.request_timeout_secs.max(1))
    }

    /// Resolve the page size for a particular subscription.
    pub fn effective_page_size(&self, sub: &Subscription) -> u32 {
        sub.page_size.unwrap_or(DEFAULT_PAGE_SIZE).max(1)
    }

    /// Normalise the endpoint by stripping a trailing slash, so the
    /// polling client can append `/Datastreams(N)/Observations`
    /// uniformly.
    pub fn normalised_endpoint(&self) -> &str {
        self.endpoint.trim_end_matches('/')
    }
}

fn default_poll_interval_secs() -> u64 {
    DEFAULT_POLL_INTERVAL_SECS
}

fn default_request_timeout_secs() -> u64 {
    DEFAULT_REQUEST_TIMEOUT_SECS
}

fn default_expand_location() -> bool {
    true
}

fn default_page_size_opt() -> Option<u32> {
    Some(DEFAULT_PAGE_SIZE)
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_config() {
        let toml_str = r#"
            endpoint = "https://example.org/SensorThings/v1.0"
            auth-token-path = "/secrets/sensorthings-token"
            poll-interval-secs = 30
            request-timeout-secs = 10
            expand-location = true

            [[subscriptions]]
            datastream-id = 42
            entity-kind = "sensor"
            group = "weather"
            poll-interval-secs = 15
            page-size = 100
        "#;
        let cfg: SensorThingsConfig = toml::from_str(toml_str).expect("parse");
        assert_eq!(cfg.endpoint, "https://example.org/SensorThings/v1.0");
        assert_eq!(
            cfg.auth_token_path.as_deref(),
            Some("/secrets/sensorthings-token")
        );
        assert_eq!(cfg.poll_interval_secs, 30);
        assert_eq!(cfg.request_timeout_secs, 10);
        assert!(cfg.expand_location);
        assert_eq!(cfg.subscriptions.len(), 1);
        let sub = &cfg.subscriptions[0];
        assert_eq!(sub.datastream_id, 42);
        assert_eq!(sub.entity_kind, EntityKindTag::Sensor);
        assert_eq!(sub.group.as_deref(), Some("weather"));
        assert_eq!(sub.poll_interval_secs, Some(15));
        assert_eq!(sub.page_size, Some(100));
        cfg.validate().expect("valid");
    }

    #[test]
    fn defaults_apply_when_optional_fields_omitted() {
        let toml_str = r#"
            endpoint = "https://example.org/SensorThings/v1.0"
        "#;
        let cfg: SensorThingsConfig = toml::from_str(toml_str).expect("parse");
        assert!(cfg.auth_token_path.is_none());
        assert_eq!(cfg.poll_interval_secs, DEFAULT_POLL_INTERVAL_SECS);
        assert_eq!(cfg.request_timeout_secs, DEFAULT_REQUEST_TIMEOUT_SECS);
        assert!(cfg.expand_location, "expand-location defaults to true");
        assert!(cfg.subscriptions.is_empty());
        cfg.validate().expect("valid");
    }

    #[test]
    fn rejects_unknown_field() {
        let toml_str = r#"
            endpoint = "https://example.org/SensorThings/v1.0"
            unknown-key = 42
        "#;
        let err = toml::from_str::<SensorThingsConfig>(toml_str).unwrap_err();
        assert!(err.to_string().contains("unknown"));
    }

    #[test]
    fn rejects_underscore_field() {
        // Schema is kebab-case; underscore form is treated as unknown.
        let toml_str = r#"
            endpoint = "https://example.org/SensorThings/v1.0"
            auth_token_path = "/secrets/foo"
        "#;
        let err = toml::from_str::<SensorThingsConfig>(toml_str).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("unknown field") || msg.contains("missing field"),
            "expected unknown/missing field error, got: {msg}"
        );
    }

    #[test]
    fn rejects_subscription_with_zero_datastream_id() {
        let toml_str = r#"
            endpoint = "https://example.org/SensorThings/v1.0"

            [[subscriptions]]
            datastream-id = 0
        "#;
        let cfg: SensorThingsConfig = toml::from_str(toml_str).expect("parse");
        let err = cfg.validate().expect_err("invalid");
        assert!(err.to_string().contains("datastream-id"));
    }

    #[test]
    fn rejects_duplicate_subscription_ids() {
        let toml_str = r#"
            endpoint = "https://example.org/SensorThings/v1.0"

            [[subscriptions]]
            datastream-id = 42

            [[subscriptions]]
            datastream-id = 42
        "#;
        let cfg: SensorThingsConfig = toml::from_str(toml_str).expect("parse");
        let err = cfg.validate().expect_err("duplicate");
        assert!(err.to_string().contains("duplicate"));
    }

    #[test]
    fn rejects_non_http_endpoint() {
        let toml_str = r#"
            endpoint = "ftp://example.org/SensorThings/v1.0"
        "#;
        let cfg: SensorThingsConfig = toml::from_str(toml_str).expect("parse");
        let err = cfg.validate().expect_err("invalid scheme");
        assert!(
            err.to_string().contains("http"),
            "validator must explain why the scheme is rejected, got: {err}"
        );
    }

    #[test]
    fn rejects_zero_poll_interval() {
        let toml_str = r#"
            endpoint = "https://example.org/SensorThings/v1.0"
            poll-interval-secs = 0
        "#;
        let cfg: SensorThingsConfig = toml::from_str(toml_str).expect("parse");
        let err = cfg.validate().expect_err("invalid");
        assert!(err.to_string().contains("poll-interval-secs"));
    }

    #[test]
    fn entity_kind_tag_round_trips_through_canonical_kind() {
        // Pin the closed-vocabulary projection — adding a new tag
        // must update both this test and the EntityKind enum, so the
        // mapping stays consistent across the workspace.
        use rustgate_core::entity::EntityKind;
        assert_eq!(EntityKindTag::Sensor.to_entity_kind(), EntityKind::Sensor);
        assert_eq!(EntityKindTag::Track.to_entity_kind(), EntityKind::Track);
        assert_eq!(
            EntityKindTag::Aircraft.to_entity_kind(),
            EntityKind::Aircraft
        );
        assert_eq!(EntityKindTag::Ground.to_entity_kind(), EntityKind::Ground);
        assert_eq!(EntityKindTag::Marine.to_entity_kind(), EntityKind::Marine);
        assert_eq!(
            EntityKindTag::Munition.to_entity_kind(),
            EntityKind::Munition
        );
    }

    #[test]
    fn effective_poll_interval_prefers_subscription_override() {
        let cfg = SensorThingsConfig {
            endpoint: "https://example.org/SensorThings/v1.0".into(),
            auth_token_path: None,
            poll_interval_secs: 30,
            request_timeout_secs: 10,
            expand_location: true,
            subscriptions: vec![],
        };
        let with_override = Subscription {
            datastream_id: 42,
            entity_kind: EntityKindTag::Sensor,
            group: None,
            poll_interval_secs: Some(15),
            page_size: None,
        };
        assert_eq!(
            cfg.effective_poll_interval(&with_override),
            Duration::from_secs(15)
        );
        let no_override = Subscription {
            datastream_id: 42,
            entity_kind: EntityKindTag::Sensor,
            group: None,
            poll_interval_secs: None,
            page_size: None,
        };
        assert_eq!(
            cfg.effective_poll_interval(&no_override),
            Duration::from_secs(30)
        );
    }

    #[test]
    fn normalised_endpoint_strips_trailing_slash() {
        let cfg = SensorThingsConfig {
            endpoint: "https://example.org/SensorThings/v1.0/".into(),
            auth_token_path: None,
            poll_interval_secs: 30,
            request_timeout_secs: 10,
            expand_location: true,
            subscriptions: vec![],
        };
        assert_eq!(
            cfg.normalised_endpoint(),
            "https://example.org/SensorThings/v1.0"
        );
    }

    #[test]
    fn parses_with_wrapper_table_for_rustgate_toml() {
        // Pins the call-site shape the binary uses: an outer
        // `[sensorthings]` table wrapping the config root. Mirrors
        // how `start_lattice` parses the `[lattice]` block.
        let toml_str = r#"
            [sensorthings]
            endpoint = "https://example.org/SensorThings/v1.0"

            [[sensorthings.subscriptions]]
            datastream-id = 1
            entity-kind = "sensor"
        "#;
        #[derive(Deserialize)]
        struct Wrapper {
            sensorthings: SensorThingsConfig,
        }
        let w: Wrapper = toml::from_str(toml_str).expect("parse");
        assert_eq!(
            w.sensorthings.endpoint,
            "https://example.org/SensorThings/v1.0"
        );
        assert_eq!(w.sensorthings.subscriptions.len(), 1);
    }
}
