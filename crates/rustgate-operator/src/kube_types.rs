// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! `kube`-derived view of `RustgateCluster`.
//!
//! The renderer's source-of-truth CRD types live in [`crate::crd`] and
//! intentionally don't depend on `kube` or `k8s-openapi` so the
//! pure-render binary stays lean. For the live controller we need a
//! type that implements [`kube::Resource`] so `kube_runtime::Controller`
//! can watch and patch it. Rather than implementing the trait by hand
//! (which would force us to swap our hand-rolled `ObjectMeta` for the
//! `k8s_openapi` one), we mirror the spec into a `#[derive(CustomResource)]`
//! type and round-trip via JSON.
//!
//! The two views share the same wire format (their serde shape is
//! identical), so conversions are total and lossless. Tests below pin
//! that property so a future divergence between the renderer's spec and
//! the controller's spec fails at build-time.

#![cfg(feature = "controller")]

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::crd::{
    CertManagerConfig, FederationConfig, RustgateCluster as RenderCluster, RustgateClusterSpec,
    RustgateClusterStatus, StorageConfig,
};
use crate::error::OperatorError;

/// Controller-side spec — mirrors [`RustgateClusterSpec`] field-for-field.
///
/// We can't put `#[derive(CustomResource)]` directly on [`RustgateClusterSpec`]
/// in [`crate::crd`] because that pulls `kube` + `schemars` into the
/// pure-render dep graph, defeating the whole feature-gate. Defining the
/// schema here keeps the controller deps quarantined behind
/// `#[cfg(feature = "controller")]`.
#[derive(
    CustomResource, Debug, Clone, Serialize, Deserialize, PartialEq, Eq, JsonSchema, Default,
)]
#[kube(
    group = "rustgate.io",
    version = "v1alpha1",
    kind = "RustgateCluster",
    plural = "rustgateclusters",
    shortname = "rgc",
    namespaced,
    status = "RustgateClusterStatusKube",
    derive = "Default",
    derive = "PartialEq"
)]
#[serde(rename_all = "camelCase")]
pub struct RustgateClusterSpecKube {
    #[serde(default = "default_replicas")]
    pub replicas: i32,
    #[serde(default = "default_image")]
    pub image: String,
    #[serde(default = "default_image_pull_policy")]
    pub image_pull_policy: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert_manager: Option<CertManagerConfigKube>,
    #[serde(default)]
    pub federation: FederationConfigKube,
    #[serde(default)]
    pub storage: StorageConfigKube,
    #[serde(default = "default_service_port")]
    pub service_port: i32,
    #[serde(default = "default_termination_grace")]
    pub termination_grace_period_seconds: i64,
}

fn default_replicas() -> i32 {
    1
}

fn default_image() -> String {
    "ghcr.io/rchiofalo/rustgate:latest".to_string()
}

fn default_image_pull_policy() -> String {
    "IfNotPresent".to_string()
}

fn default_service_port() -> i32 {
    4433
}

fn default_termination_grace() -> i64 {
    30
}

fn default_federation_port() -> i32 {
    9001
}

fn default_issuer_kind() -> String {
    "ClusterIssuer".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, JsonSchema, Default)]
#[serde(rename_all = "camelCase")]
pub struct CertManagerConfigKube {
    pub issuer: String,
    #[serde(default = "default_issuer_kind")]
    pub issuer_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub common_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct FederationConfigKube {
    #[serde(default)]
    pub auto_discover: bool,
    #[serde(default = "default_federation_port")]
    pub port: i32,
}

impl Default for FederationConfigKube {
    fn default() -> Self {
        Self {
            auto_discover: false,
            port: default_federation_port(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, JsonSchema, Default)]
#[serde(rename_all = "camelCase")]
pub struct StorageConfigKube {
    #[serde(default)]
    pub store_forward: VolumeClaimKube,
    #[serde(default)]
    pub audit_log: VolumeClaimKube,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, JsonSchema, Default)]
#[serde(rename_all = "camelCase")]
pub struct VolumeClaimKube {
    #[serde(default)]
    pub size: String,
    #[serde(default)]
    pub storage_class: String,
}

/// Controller-side status — round-trip equivalent of [`RustgateClusterStatus`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, JsonSchema, Default)]
#[serde(rename_all = "camelCase")]
pub struct RustgateClusterStatusKube {
    #[serde(default)]
    pub ready_replicas: i32,
    #[serde(default)]
    pub available_replicas: i32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_reconciled: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<ConditionKube>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConditionKube {
    #[serde(rename = "type")]
    pub kind: String,
    pub status: String,
    pub reason: String,
    pub message: String,
    pub last_transition_time: String,
}

/// Convert the controller-side resource into the renderer's view by
/// round-tripping through JSON. The two serde shapes are identical, so
/// this is total and panic-free for any well-formed CRD instance.
pub fn to_render_cluster(kube: &RustgateCluster) -> Result<RenderCluster, OperatorError> {
    let value = serde_json::to_value(kube)
        .map_err(|e| OperatorError::invalid_spec(format!("encode: {e}")))?;
    serde_json::from_value::<RenderCluster>(value)
        .map_err(|e| OperatorError::invalid_spec(format!("decode: {e}")))
}

/// Convert the renderer's status back into the controller-side wire
/// shape, ready for a `patch_status` call.
pub fn to_kube_status(
    s: &RustgateClusterStatus,
) -> Result<RustgateClusterStatusKube, OperatorError> {
    let value =
        serde_json::to_value(s).map_err(|e| OperatorError::invalid_spec(format!("encode: {e}")))?;
    serde_json::from_value::<RustgateClusterStatusKube>(value)
        .map_err(|e| OperatorError::invalid_spec(format!("decode: {e}")))
}

// Field-set reference list — held for the compiler to scream if the
// renderer-side types add a new field that the controller-side mirror
// doesn't carry. Tests below pin the same property at the JSON layer.

// justification: a no-op conversion that fails to compile when the
// controller-side spec drifts from the renderer-side spec. The
// destructure-bind covers every field on `RustgateClusterSpec`, so
// adding a field there without mirroring it here fails the build with
// a missing-field error rather than silently round-tripping a
// half-empty value at runtime.
#[allow(dead_code)]
fn _shape_sync_check(spec: &RustgateClusterSpec) -> RustgateClusterSpecKube {
    let RustgateClusterSpec {
        replicas,
        image,
        image_pull_policy,
        cert_manager,
        federation,
        storage,
        service_port,
        termination_grace_period_seconds,
    } = spec.clone();
    RustgateClusterSpecKube {
        replicas,
        image,
        image_pull_policy,
        cert_manager: cert_manager.map(|c| CertManagerConfigKube {
            issuer: c.issuer,
            issuer_kind: c.issuer_kind,
            common_name: c.common_name,
        }),
        federation: FederationConfigKube {
            auto_discover: federation.auto_discover,
            port: federation.port,
        },
        storage: StorageConfigKube {
            store_forward: VolumeClaimKube {
                size: storage.store_forward.size,
                storage_class: storage.store_forward.storage_class,
            },
            audit_log: VolumeClaimKube {
                size: storage.audit_log.size,
                storage_class: storage.audit_log.storage_class,
            },
        },
        service_port,
        termination_grace_period_seconds,
    }
}

// Same reverse-direction sync check for `FederationConfig`,
// `StorageConfig`, `CertManagerConfig` — kept narrow so the compiler
// error points at the exact offending struct.

// justification: destructure-bind catches missing fields at build time
// (same rationale as `_shape_sync_check` above).
#[allow(dead_code)]
fn _federation_sync(cfg: &FederationConfig) -> FederationConfigKube {
    let FederationConfig {
        auto_discover,
        port,
    } = *cfg;
    FederationConfigKube {
        auto_discover,
        port,
    }
}

// justification: destructure-bind catches missing fields at build time
// (same rationale as `_shape_sync_check` above).
#[allow(dead_code)]
fn _storage_sync(cfg: &StorageConfig) -> StorageConfigKube {
    let StorageConfig {
        store_forward,
        audit_log,
    } = cfg.clone();
    StorageConfigKube {
        store_forward: VolumeClaimKube {
            size: store_forward.size,
            storage_class: store_forward.storage_class,
        },
        audit_log: VolumeClaimKube {
            size: audit_log.size,
            storage_class: audit_log.storage_class,
        },
    }
}

// justification: destructure-bind catches missing fields at build time
// (same rationale as `_shape_sync_check` above).
#[allow(dead_code)]
fn _certmgr_sync(cfg: &CertManagerConfig) -> CertManagerConfigKube {
    let CertManagerConfig {
        issuer,
        issuer_kind,
        common_name,
    } = cfg.clone();
    CertManagerConfigKube {
        issuer,
        issuer_kind,
        common_name,
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::crd::{ObjectMeta, RustgateCluster as RenderCluster};

    #[test]
    fn json_round_trip_preserves_spec() {
        let mut render = RenderCluster::new("test", "default");
        render.spec.replicas = 5;
        render.spec.federation.auto_discover = true;
        render.spec.federation.port = 9001;
        render.spec.storage.store_forward.size = "10Gi".to_string();
        render.spec.cert_manager = Some(crate::crd::CertManagerConfig {
            issuer: "letsencrypt".to_string(),
            issuer_kind: "ClusterIssuer".to_string(),
            common_name: Some("rg.example.com".to_string()),
        });
        // Encode the renderer view as the kube view, then decode back —
        // exercises both directions of the JSON bridge.
        let kube_value = serde_json::to_value(&render).unwrap();
        let kube: RustgateCluster = serde_json::from_value(kube_value).unwrap();
        let round_tripped = to_render_cluster(&kube).unwrap();
        assert_eq!(round_tripped.spec, render.spec);
    }

    #[test]
    fn status_round_trip_preserves_fields() {
        let status = RustgateClusterStatus {
            ready_replicas: 3,
            available_replicas: 3,
            last_reconciled: Some("2026-05-10T12:00:00Z".to_string()),
            conditions: vec![crate::crd::Condition {
                kind: "Ready".to_string(),
                status: "True".to_string(),
                reason: "AllReplicasReady".to_string(),
                message: "ready".to_string(),
                last_transition_time: "2026-05-10T12:00:00Z".to_string(),
            }],
        };
        let kube = to_kube_status(&status).unwrap();
        assert_eq!(kube.ready_replicas, 3);
        assert_eq!(kube.conditions.len(), 1);
        assert_eq!(kube.conditions[0].kind, "Ready");
    }

    #[test]
    fn metadata_round_trips() {
        let mut render = RenderCluster::new("mc", "rustgate");
        render.metadata = ObjectMeta {
            name: "mc".into(),
            namespace: "rustgate".into(),
            uid: Some("uid-1".into()),
            labels: Some(
                [("k".to_string(), "v".to_string())]
                    .into_iter()
                    .collect::<std::collections::BTreeMap<_, _>>(),
            ),
            annotations: None,
        };
        let kube_value = serde_json::to_value(&render).unwrap();
        let kube: RustgateCluster = serde_json::from_value(kube_value).unwrap();
        let round_tripped = to_render_cluster(&kube).unwrap();
        assert_eq!(round_tripped.metadata.name, render.metadata.name);
        assert_eq!(round_tripped.metadata.uid, render.metadata.uid);
        assert_eq!(round_tripped.metadata.labels, render.metadata.labels);
    }
}
