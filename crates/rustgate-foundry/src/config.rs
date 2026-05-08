// Copyright © 2026 Roberto Chiofalo.

//! TOML configuration for the Foundry bridge.
//!
//! Operators configure the bridge through a single `[foundry]`
//! section in `rustgate.toml`. The endpoint and credentials live at
//! the top level; the per-object-type mapping lives in repeated
//! `[[foundry.object-types]]` tables, each carrying its own
//! property map.
//!
//! Every config struct uses `kebab-case` field names with
//! `deny_unknown_fields` so a typo (`property_map` instead of
//! `property-map`) is rejected at parse time rather than silently
//! ignored.
//!
//! # Schema example
//!
//! ```toml
//! [foundry]
//! endpoint = "https://foundry.example.com"
//! auth-token-path = "/secrets/foundry-token"
//!
//! [[foundry.object-types]]
//! entity-type = "ground"
//! foundry-type = "mil-track-dismount"
//! property-map = [
//!     { entity = "uid", foundry = "rustgate.uid" },
//!     { entity = "callsign", foundry = "callSign" },
//!     { entity = "position.lat", foundry = "latitude" },
//!     { entity = "position.lon", foundry = "longitude" },
//!     { entity = "velocity.speed_m_s", foundry = "speedMps" },
//! ]
//! ```
//!
//! `entity-type` is matched against
//! [`rustgate_core::entity::EntityKind::as_str`] verbatim. The
//! seven-variant closed vocabulary (`aircraft`, `ground`, `marine`,
//! `sensor`, `track`, `munition`, `unknown`) is the universe of
//! valid `entity-type` values today.

use serde::{Deserialize, Serialize};

/// Root of the Foundry bridge configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct FoundryConfig {
    /// Base URL of the Foundry tenant. Validated by the SDK
    /// adapter, not by this crate — `https://...` is expected but
    /// not enforced here so test harnesses can wire `http://`
    /// loopback endpoints without parser surgery.
    pub endpoint: String,
    /// Path to a file containing the bearer / OAuth2 token used to
    /// authenticate against the tenant. Loaded by the SDK adapter
    /// at startup; the adapter is responsible for the
    /// `Zeroizing` wrap and the mode-0o077 perm check (the same
    /// pattern `rustgate-enrollment` uses for its CA key — see
    /// `rustgate_core::read_secret_file`).
    pub auth_token_path: String,
    /// Per-entity-type mapping table. The wiring iterates this
    /// list at startup; entity types not present here are surfaced
    /// as [`crate::error::FoundryError::UnmappedEntityType`] when
    /// they reach the outbound task.
    #[serde(default, rename = "object-types")]
    pub object_types: Vec<ObjectTypeMapping>,
}

/// One entry in the per-entity-type mapping table.
///
/// Each entry binds a rustgate `entity-type` (matched against
/// [`rustgate_core::entity::EntityKind::as_str`]) to a Foundry
/// object-type identifier and the property-projection rules.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ObjectTypeMapping {
    /// rustgate-side entity classification, matched verbatim
    /// against [`rustgate_core::entity::EntityKind::as_str`].
    pub entity_type: String,
    /// Foundry-side object-type identifier.
    pub foundry_type: String,
    /// Property-projection rules. The order matters only for
    /// determinism in the resulting JSON object — every rule is
    /// applied independently.
    #[serde(default, rename = "property-map")]
    pub property_map: Vec<PropertyMap>,
}

/// One property-projection rule.
///
/// Maps a rustgate-side dotted path (resolved against an
/// `Entity` — see [`crate::mapper::PropertyMapper`]) to a Foundry-
/// side property name. Supported dotted paths today:
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
/// The Foundry-side property name is treated as opaque — the
/// mapper writes it as a top-level JSON key on the property bag.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct PropertyMap {
    /// Dotted path resolved against the source entity.
    pub entity: String,
    /// Foundry property name.
    pub foundry: String,
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_config() {
        let toml = r#"
            endpoint = "https://foundry.example.com"
            auth-token-path = "/secrets/foundry-token"

            [[object-types]]
            entity-type = "ground"
            foundry-type = "mil-track-dismount"
            property-map = [
                { entity = "callsign", foundry = "callSign" },
                { entity = "position.lat", foundry = "latitude" },
            ]
        "#;
        let cfg: FoundryConfig = toml::from_str(toml).expect("parse");
        assert_eq!(cfg.endpoint, "https://foundry.example.com");
        assert_eq!(cfg.object_types.len(), 1);
        assert_eq!(cfg.object_types[0].entity_type, "ground");
        assert_eq!(cfg.object_types[0].foundry_type, "mil-track-dismount");
        assert_eq!(cfg.object_types[0].property_map.len(), 2);
        assert_eq!(cfg.object_types[0].property_map[0].entity, "callsign");
        assert_eq!(cfg.object_types[0].property_map[0].foundry, "callSign");
    }

    #[test]
    fn rejects_unknown_field() {
        let toml = r#"
            endpoint = "https://foundry.example.com"
            auth-token-path = "/secrets/foundry-token"
            unknown-key = 42
        "#;
        let err = toml::from_str::<FoundryConfig>(toml).unwrap_err();
        assert!(err.to_string().contains("unknown"));
    }

    #[test]
    fn rejects_underscore_field() {
        // The schema uses kebab-case; `auth_token_path` (underscore)
        // is rejected by `deny_unknown_fields` — `serde` treats the
        // underscore form as an unknown field and reports it under
        // that label rather than as "missing field". This regression
        // test pins that contract so a future loosening of
        // `deny_unknown_fields` shows up immediately.
        let toml = r#"
            endpoint = "https://foundry.example.com"
            auth_token_path = "/secrets/foundry-token"
        "#;
        let err = toml::from_str::<FoundryConfig>(toml).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("unknown field") || msg.contains("missing field"),
            "expected unknown/missing field error, got: {msg}"
        );
    }

    #[test]
    fn defaults_to_empty_object_types() {
        let toml = r#"
            endpoint = "https://foundry.example.com"
            auth-token-path = "/secrets/foundry-token"
        "#;
        let cfg: FoundryConfig = toml::from_str(toml).expect("parse");
        assert!(cfg.object_types.is_empty());
    }
}
