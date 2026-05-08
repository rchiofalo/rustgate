// Copyright © 2026 Roberto Chiofalo.

//! TOML configuration for the DDS bridge.
//!
//! Operators configure the bridge through a single `[dds]` section
//! in `rustgate.toml`. The domain-id and participant identity live
//! at the top level; per-topic subscriptions live in repeated
//! `[[dds.subscriptions]]` tables, each carrying its own
//! property-map.
//!
//! Every config struct uses `kebab-case` field names with
//! `deny_unknown_fields` so a typo (`property_map` instead of
//! `property-map`) is rejected at parse time rather than silently
//! ignored.
//!
//! # Schema example
//!
//! ```toml
//! [dds]
//! domain-id = 0
//! participant-name = "rustgate"
//!
//! [[dds.subscriptions]]
//! topic = "rustgate.ngva.Navigation"
//! entity-kind = "ground"
//! property-map = [
//!     { dds = "uid", entity = "uid" },
//!     { dds = "callsign", entity = "callsign" },
//!     { dds = "position.lat", entity = "position.lat" },
//!     { dds = "position.lon", entity = "position.lon" },
//! ]
//!
//! [[dds.subscriptions]]
//! topic = "rustgate.ngva.Weapons"
//! entity-kind = "munition"
//! qos = { reliability = "reliable", durability = "transient-local", history = { kind = "keep-all" } }
//! property-map = [
//!     { dds = "uid", entity = "uid" },
//!     { dds = "weapon.state", entity = "attributes.weapon_state" },
//! ]
//! ```
//!
//! `entity-kind` is matched against
//! [`rustgate_core::entity::EntityKind::as_str`] verbatim. The
//! seven-variant closed vocabulary (`aircraft`, `ground`, `marine`,
//! `sensor`, `track`, `munition`, `unknown`) is the universe of
//! valid `entity-kind` values today.

use serde::{Deserialize, Serialize};

use crate::bridge::QosProfile;

/// Default DDS domain ID. Domain 0 is the canonical default the DDS
/// spec recommends for development / demo deployments; production
/// NGVA platforms typically use a deployment-specific domain ID
/// per-vehicle.
pub const DEFAULT_DOMAIN_ID: u32 = 0;

/// Default DDS participant name reported in `Participant_t` discovery
/// announcements. Operators override per deployment.
pub const DEFAULT_PARTICIPANT_NAME: &str = "rustgate";

/// Root of the DDS bridge configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct DdsConfig {
    /// DDS domain ID the participant joins. Defaults to
    /// [`DEFAULT_DOMAIN_ID`].
    #[serde(default = "default_domain_id")]
    pub domain_id: u32,
    /// Participant name reported in DDS discovery. Defaults to
    /// [`DEFAULT_PARTICIPANT_NAME`].
    #[serde(default = "default_participant_name")]
    pub participant_name: String,
    /// Per-topic subscriptions. The wiring opens one DataReader per
    /// entry at startup; topics not listed here are surfaced as
    /// [`crate::error::DdsError::UnmappedTopic`] when their samples
    /// reach the inbound task.
    #[serde(default)]
    pub subscriptions: Vec<Subscription>,
}

impl Default for DdsConfig {
    fn default() -> Self {
        Self {
            domain_id: DEFAULT_DOMAIN_ID,
            participant_name: DEFAULT_PARTICIPANT_NAME.to_string(),
            subscriptions: Vec::new(),
        }
    }
}

fn default_domain_id() -> u32 {
    DEFAULT_DOMAIN_ID
}

fn default_participant_name() -> String {
    DEFAULT_PARTICIPANT_NAME.to_string()
}

/// One entry in the per-topic subscription table.
///
/// Each entry binds a DDS topic name to a rustgate `entity-kind`
/// (matched against [`rustgate_core::entity::EntityKind::as_str`]),
/// the QoS profile used to create the underlying reader, and the
/// property-projection rules.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Subscription {
    /// DDS topic name (e.g. `rustgate.ngva.Navigation`).
    pub topic: String,
    /// rustgate-side entity classification, matched verbatim
    /// against [`rustgate_core::entity::EntityKind::as_str`].
    pub entity_kind: String,
    /// QoS profile applied to the DataReader. Defaults to
    /// [`QosProfile::default`] (best-effort, volatile, keep-last 1)
    /// — the right shape for high-rate telemetry topics.
    #[serde(default)]
    pub qos: QosProfile,
    /// Property-projection rules. The order matters only for
    /// determinism in the resulting JSON object — every rule is
    /// applied independently.
    #[serde(default)]
    pub property_map: Vec<PropertyMap>,
}

/// One property-projection rule.
///
/// Maps a DDS-side dotted path on the sample property bag to a
/// rustgate-side dotted path resolved against an `Entity` (see
/// [`crate::mapper::PropertyMapper`]). Supported entity-side dotted
/// paths today:
///
/// - `uid`
/// - `callsign`
/// - `mil_std_2525_sidc`
/// - `position.lat` / `position.lon` / `position.hae_meters`
/// - `velocity.speed_m_s` / `velocity.course_deg`
/// - `attributes.<key>` (matches an entry in
///   [`rustgate_core::entity::Entity::attributes`] verbatim;
///   nested keys are NOT split — the entire suffix after
///   `attributes.` is the attribute key).
///
/// The DDS-side property name is treated as opaque — the mapper
/// reads / writes it as a top-level JSON key on the property bag.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct PropertyMap {
    /// DDS sample property name.
    pub dds: String,
    /// Dotted path resolved against the rustgate entity.
    pub entity: String,
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::bridge::{Durability, History, Reliability};

    #[test]
    fn parses_full_config() {
        let toml = r#"
            domain-id = 42
            participant-name = "vehicle-a"

            [[subscriptions]]
            topic = "rustgate.ngva.Navigation"
            entity-kind = "ground"
            property-map = [
                { dds = "callsign", entity = "callsign" },
                { dds = "lat", entity = "position.lat" },
            ]

            [[subscriptions]]
            topic = "rustgate.ngva.Weapons"
            entity-kind = "munition"
            qos = { reliability = "reliable", durability = "transient-local", history = { kind = "keep-all" } }
            property-map = []
        "#;
        let cfg: DdsConfig = toml::from_str(toml).expect("parse");
        assert_eq!(cfg.domain_id, 42);
        assert_eq!(cfg.participant_name, "vehicle-a");
        assert_eq!(cfg.subscriptions.len(), 2);
        assert_eq!(cfg.subscriptions[0].topic, "rustgate.ngva.Navigation");
        assert_eq!(cfg.subscriptions[0].entity_kind, "ground");
        assert_eq!(cfg.subscriptions[0].property_map.len(), 2);
        assert_eq!(cfg.subscriptions[1].qos.reliability, Reliability::Reliable);
        assert_eq!(
            cfg.subscriptions[1].qos.durability,
            Durability::TransientLocal
        );
        assert_eq!(cfg.subscriptions[1].qos.history, History::KeepAll);
    }

    #[test]
    fn defaults_to_domain_zero_and_rustgate_participant() {
        let toml = "";
        let cfg: DdsConfig = toml::from_str(toml).expect("parse");
        assert_eq!(cfg.domain_id, DEFAULT_DOMAIN_ID);
        assert_eq!(cfg.participant_name, DEFAULT_PARTICIPANT_NAME);
        assert!(cfg.subscriptions.is_empty());
    }

    #[test]
    fn rejects_unknown_field_at_root() {
        let toml = r#"
            domain-id = 0
            unknown-key = 1
        "#;
        let err = toml::from_str::<DdsConfig>(toml).unwrap_err();
        assert!(err.to_string().contains("unknown"));
    }

    #[test]
    fn rejects_underscore_field() {
        // The schema uses kebab-case; `domain_id` (underscore) is
        // rejected by `deny_unknown_fields` so a future loosening of
        // the schema shows up immediately.
        let toml = r#"
            domain_id = 1
        "#;
        let err = toml::from_str::<DdsConfig>(toml).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("unknown field") || msg.contains("missing field"),
            "expected unknown/missing field error, got: {msg}"
        );
    }

    #[test]
    fn subscription_qos_defaults_to_telemetry_shape() {
        let toml = r#"
            [[subscriptions]]
            topic = "t"
            entity-kind = "ground"
        "#;
        let cfg: DdsConfig = toml::from_str(toml).expect("parse");
        let qos = cfg.subscriptions[0].qos;
        assert_eq!(qos.reliability, Reliability::BestEffort);
        assert_eq!(qos.durability, Durability::Volatile);
        assert_eq!(qos.history, History::KeepLast { depth: 1 });
    }
}
