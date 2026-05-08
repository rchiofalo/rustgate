// Copyright © 2026 Roberto Chiofalo.

//! TOML configuration for the Lattice bridge.
//!
//! Mirrors the conventions used by every other rustgate config block:
//! `kebab-case` field names, `deny_unknown_fields` so operator typos
//! fail fast, defaults applied via `serde(default)` so the minimal
//! `[lattice]` block stays a one-liner.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::bridge::{EntityKind, GeoBbox};

/// Default outbound-publish batch size.
///
/// 64 strikes a balance between Lattice's preferred per-call payload
/// size (small batches keep latency under a second on a saturated
/// link) and the per-message overhead of the gRPC framing layer the
/// real-SDK PR will sit on top of.
pub const DEFAULT_BATCH_SIZE: usize = 64;

/// Default health-report cadence in seconds.
///
/// 30s matches the federation heartbeat cadence (see
/// `rustgate_core::constants::FEDERATION_HEARTBEAT_INTERVAL`) so
/// operator dashboards can correlate liveness across both subsystems.
pub const DEFAULT_HEALTH_INTERVAL_SECS: u64 = 30;

/// Top-level `[lattice]` config block.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct LatticeConfig {
    /// Lattice gRPC endpoint URL (e.g. `https://lattice.example.mil`).
    pub endpoint: String,

    /// Authentication material — mTLS client identity and JWT secret
    /// path. Required for every real Lattice deployment; optional in
    /// tests so the mock backend can be exercised without writing
    /// dummy keys to disk.
    #[serde(default)]
    pub auth: Option<LatticeAuth>,

    /// Outbound publish batch size. Defaults to
    /// [`DEFAULT_BATCH_SIZE`]. The outbound wiring task buffers up
    /// to this many entities before flushing to the bridge so the
    /// real-SDK impl can tune its own per-call payload without
    /// changing the channel topology.
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,

    /// Health-report cadence, seconds. Defaults to
    /// [`DEFAULT_HEALTH_INTERVAL_SECS`].
    #[serde(default = "default_health_interval_secs")]
    pub health_interval_secs: u64,

    /// Optional geographic bounding box for the inbound subscription
    /// — only entities inside this box are pulled from Lattice.
    /// `None` accepts entities at any location.
    #[serde(default)]
    pub geo_bbox: Option<GeoBbox>,

    /// Optional list of allowed inbound entity kinds; an empty list
    /// (or `None`) accepts every kind.
    #[serde(default)]
    pub entity_types: Option<Vec<EntityKind>>,
}

/// `[lattice.auth]` sub-block — mTLS + JWT credential paths.
///
/// Holds *paths* to credential files rather than the credentials
/// themselves so this struct can be `Deserialize` without a custom
/// `Zeroizing` shim and so operators can rotate the on-disk material
/// without restarting rustgate. The real-SDK PR will load these
/// paths into `Zeroizing<...>` buffers at the bridge construction
/// site.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct LatticeAuth {
    /// PEM-encoded mTLS client certificate path.
    pub mtls_cert_path: PathBuf,
    /// PEM-encoded mTLS private key path.
    pub mtls_key_path: PathBuf,
    /// JWT-bearing-token secret path. The file's contents are
    /// expected to be the raw secret bytes (HMAC) or a PEM-encoded
    /// signing key, depending on the partner-side JWT spec.
    pub jwt_secret_path: PathBuf,
}

fn default_batch_size() -> usize {
    DEFAULT_BATCH_SIZE
}

fn default_health_interval_secs() -> u64 {
    DEFAULT_HEALTH_INTERVAL_SECS
}

impl LatticeConfig {
    /// Validate operator-supplied values that `serde` cannot enforce.
    ///
    /// Today this is just `endpoint != ""` and `batch_size > 0`;
    /// future PRs that add wire-format-sensitive fields will extend
    /// the check here without churning the public surface.
    pub fn validate(&self) -> crate::Result<()> {
        if self.endpoint.trim().is_empty() {
            return Err(crate::LatticeError::InvalidConfig {
                reason: "endpoint must not be empty".to_string(),
            });
        }
        if self.batch_size == 0 {
            return Err(crate::LatticeError::InvalidConfig {
                reason: "batch-size must be greater than zero".to_string(),
            });
        }
        if self.health_interval_secs == 0 {
            return Err(crate::LatticeError::InvalidConfig {
                reason: "health-interval-secs must be greater than zero".to_string(),
            });
        }
        if let Some(bbox) = &self.geo_bbox
            && (bbox.min_lat > bbox.max_lat || bbox.min_lon > bbox.max_lon)
        {
            return Err(crate::LatticeError::InvalidConfig {
                reason: "geo-bbox bounds are inverted (min must be <= max)".to_string(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn default_batch_size_used_when_field_omitted() {
        let toml_text = r#"
            endpoint = "https://lattice.example.mil"
        "#;
        let cfg: LatticeConfig = toml::from_str(toml_text).unwrap();
        assert_eq!(cfg.batch_size, DEFAULT_BATCH_SIZE);
        assert_eq!(cfg.health_interval_secs, DEFAULT_HEALTH_INTERVAL_SECS);
        assert!(cfg.auth.is_none());
        assert!(cfg.geo_bbox.is_none());
        assert!(cfg.entity_types.is_none());
        cfg.validate().unwrap();
    }

    #[test]
    fn full_block_round_trips_via_toml() {
        let toml_text = r#"
            endpoint = "https://lattice.example.mil"
            batch-size = 16
            health-interval-secs = 45
            entity-types = ["track", "platform"]

            [auth]
            mtls-cert-path = "/etc/rustgate/lattice/client.crt"
            mtls-key-path = "/etc/rustgate/lattice/client.key"
            jwt-secret-path = "/etc/rustgate/lattice/jwt.secret"

            [geo-bbox]
            min-lat = 30.0
            max-lat = 50.0
            min-lon = -125.0
            max-lon = -100.0
        "#;
        let cfg: LatticeConfig = toml::from_str(toml_text).unwrap();
        assert_eq!(cfg.batch_size, 16);
        assert_eq!(cfg.health_interval_secs, 45);
        let bbox = cfg.geo_bbox.expect("geo-bbox parsed");
        assert_eq!(bbox.min_lat, 30.0);
        assert_eq!(bbox.max_lat, 50.0);
        let auth = cfg.auth.as_ref().expect("auth parsed");
        assert_eq!(
            auth.mtls_cert_path.to_str().unwrap(),
            "/etc/rustgate/lattice/client.crt"
        );
    }

    #[test]
    fn validate_rejects_empty_endpoint() {
        let cfg = LatticeConfig {
            endpoint: String::new(),
            auth: None,
            batch_size: DEFAULT_BATCH_SIZE,
            health_interval_secs: DEFAULT_HEALTH_INTERVAL_SECS,
            geo_bbox: None,
            entity_types: None,
        };
        let err = cfg.validate().unwrap_err();
        assert!(
            matches!(err, crate::LatticeError::InvalidConfig { .. }),
            "expected InvalidConfig, got {err:?}"
        );
    }

    #[test]
    fn validate_rejects_zero_batch_size() {
        let cfg = LatticeConfig {
            endpoint: "https://lattice.example.mil".to_string(),
            auth: None,
            batch_size: 0,
            health_interval_secs: DEFAULT_HEALTH_INTERVAL_SECS,
            geo_bbox: None,
            entity_types: None,
        };
        let err = cfg.validate().unwrap_err();
        assert!(matches!(err, crate::LatticeError::InvalidConfig { .. }));
    }

    #[test]
    fn validate_rejects_inverted_bbox() {
        let cfg = LatticeConfig {
            endpoint: "https://lattice.example.mil".to_string(),
            auth: None,
            batch_size: DEFAULT_BATCH_SIZE,
            health_interval_secs: DEFAULT_HEALTH_INTERVAL_SECS,
            geo_bbox: Some(GeoBbox {
                min_lat: 50.0,
                max_lat: 30.0,
                min_lon: -100.0,
                max_lon: -125.0,
            }),
            entity_types: None,
        };
        let err = cfg.validate().unwrap_err();
        assert!(matches!(err, crate::LatticeError::InvalidConfig { .. }));
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let toml_text = r#"
            endpoint = "https://lattice.example.mil"
            unknown-field = "boom"
        "#;
        let result: std::result::Result<LatticeConfig, _> = toml::from_str(toml_text);
        assert!(result.is_err(), "deny_unknown_fields must reject typos");
    }
}
