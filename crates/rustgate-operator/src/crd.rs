// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! CRD types for the `RustgateCluster` resource.
//!
//! These mirror the `rustgate.io/v1alpha1` `RustgateCluster` shape declared in
//! `helm/crds/rustgatecluster.yaml`. The types are hand-rolled `serde` shapes
//! rather than `kube::CustomResource`-derived ones so the crate compiles
//! without pulling in the full `kube` + `k8s-openapi` toolchain. The schema
//! source-of-truth is the YAML manifest; these Rust types are the projection
//! the operator consumes when reconciling and the golden-render tests verify
//! every field round-trips.

use serde::{Deserialize, Serialize};

use crate::error::{OperatorError, Result};

/// API group for the CRD.
pub const API_GROUP: &str = "rustgate.io";
/// API version for the CRD.
pub const API_VERSION: &str = "v1alpha1";
/// `apiVersion` field value (`rustgate.io/v1alpha1`).
pub const API_VERSION_FQN: &str = "rustgate.io/v1alpha1";
/// `kind` field value.
pub const KIND: &str = "RustgateCluster";
/// Plural name (used in CRD metadata and resource paths).
pub const PLURAL: &str = "rustgateclusters";
/// Default container image when `spec.image` is omitted.
pub const DEFAULT_IMAGE: &str = "ghcr.io/rchiofalo/rustgate:latest";
/// Hard cap on `spec.replicas` to prevent operator misconfiguration from
/// exhausting the cluster. Operators who need more can ship an HPA in a
/// follow-up.
pub const MAX_REPLICAS: i32 = 100;

/// Top-level CRD type. Mirrors `rustgate.io/v1alpha1/RustgateCluster`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RustgateCluster {
    /// `apiVersion` — pinned to [`API_VERSION_FQN`].
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    /// `kind` — pinned to [`KIND`].
    pub kind: String,
    /// `metadata` — name + namespace + uid + labels + annotations.
    pub metadata: ObjectMeta,
    /// User-supplied desired state.
    pub spec: RustgateClusterSpec,
    /// Operator-reported status. Optional on inputs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<RustgateClusterStatus>,
}

/// Object metadata for a [`RustgateCluster`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ObjectMeta {
    /// `metadata.name`.
    pub name: String,
    /// `metadata.namespace`. Empty string defaults to `"default"` at apply
    /// time but the CRD is namespace-scoped so always pass it through.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub namespace: String,
    /// `metadata.uid` — populated by the API server. Used by the operator
    /// to attach owner-references to child objects.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
    /// `metadata.labels`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub labels: Option<std::collections::BTreeMap<String, String>>,
    /// `metadata.annotations`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<std::collections::BTreeMap<String, String>>,
}

/// User-supplied desired state. Field defaults match `helm/values.yaml` so
/// the operator-led path and the bare chart path produce identical pods for
/// equivalent inputs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RustgateClusterSpec {
    /// Replica count (StatefulSet `spec.replicas`). Defaults to `1` when
    /// omitted; the operator caps the value at [`MAX_REPLICAS`] during
    /// validation to fail fast on operator misconfiguration.
    #[serde(default = "default_replicas")]
    pub replicas: i32,
    /// Container image. Defaults to [`DEFAULT_IMAGE`].
    #[serde(default = "default_image")]
    pub image: String,
    /// `imagePullPolicy`. Defaults to `IfNotPresent`.
    #[serde(default = "default_image_pull_policy", rename = "imagePullPolicy")]
    pub image_pull_policy: String,
    /// Optional cert-manager integration. When present the operator emits
    /// a `cert-manager.io/v1/Certificate` per replica so each pod gets a
    /// distinct serving cert with a SAN matching its stable DNS name.
    #[serde(
        default,
        rename = "certManager",
        skip_serializing_if = "Option::is_none"
    )]
    pub cert_manager: Option<CertManagerConfig>,
    /// Federation auto-discovery. When `auto_discover = true` the operator
    /// generates the federation peer list from the StatefulSet's stable pod
    /// DNS records and writes it into the rendered ConfigMap.
    #[serde(default)]
    pub federation: FederationConfig,
    /// Persistent storage configuration. Defaults are conservative.
    #[serde(default)]
    pub storage: StorageConfig,
    /// Tactical service port on which mTLS clients connect. Defaults to
    /// `4433` to match the upstream chart.
    #[serde(default = "default_service_port", rename = "servicePort")]
    pub service_port: i32,
    /// Termination grace period seconds. Must be greater than the rustgate
    /// `SubsystemHandle` 5s drain budget plus the preStop sleep, so we
    /// default to 30s.
    #[serde(
        default = "default_termination_grace",
        rename = "terminationGracePeriodSeconds"
    )]
    pub termination_grace_period_seconds: i64,
}

impl Default for RustgateClusterSpec {
    fn default() -> Self {
        Self {
            replicas: default_replicas(),
            image: default_image(),
            image_pull_policy: default_image_pull_policy(),
            cert_manager: None,
            federation: FederationConfig::default(),
            storage: StorageConfig::default(),
            service_port: default_service_port(),
            termination_grace_period_seconds: default_termination_grace(),
        }
    }
}

fn default_replicas() -> i32 {
    1
}

fn default_image() -> String {
    DEFAULT_IMAGE.to_string()
}

fn default_image_pull_policy() -> String {
    "IfNotPresent".to_string()
}

fn default_service_port() -> i32 {
    4433
}

fn default_termination_grace() -> i64 {
    // 5s drain (`SubsystemHandle`) + 5s preStop + 20s safety margin.
    30
}

/// cert-manager integration. When present the operator renders a
/// `cert-manager.io/v1/Certificate` for the cluster.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CertManagerConfig {
    /// Name of the cert-manager `Issuer` or `ClusterIssuer` to use.
    pub issuer: String,
    /// `kind` — `Issuer` or `ClusterIssuer`. Defaults to `ClusterIssuer`.
    #[serde(default = "default_issuer_kind", rename = "issuerKind")]
    pub issuer_kind: String,
    /// Common name on the issued cert. Defaults to the cluster name when
    /// unset.
    #[serde(
        default,
        rename = "commonName",
        skip_serializing_if = "Option::is_none"
    )]
    pub common_name: Option<String>,
}

fn default_issuer_kind() -> String {
    "ClusterIssuer".to_string()
}

/// Federation discovery configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FederationConfig {
    /// When `true`, the operator generates the federation peer list from
    /// the StatefulSet's stable pod DNS records (`<sts>-N.<svc>.<ns>.svc
    /// .cluster.local`) and writes it into the rendered ConfigMap.
    #[serde(default, rename = "autoDiscover")]
    pub auto_discover: bool,
    /// Federation listen port (`v2Bind`-equivalent). Defaults to `9001`.
    #[serde(default = "default_federation_port", rename = "port")]
    pub port: i32,
}

impl Default for FederationConfig {
    fn default() -> Self {
        Self {
            auto_discover: false,
            port: default_federation_port(),
        }
    }
}

fn default_federation_port() -> i32 {
    9001
}

/// Storage configuration. Two PVCs are managed: store-and-forward (redb)
/// and the audit log archive.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct StorageConfig {
    /// Store-and-forward queue PVC.
    #[serde(default, rename = "storeForward")]
    pub store_forward: VolumeClaim,
    /// Audit log archive PVC.
    #[serde(default, rename = "auditLog")]
    pub audit_log: VolumeClaim,
}

/// PVC template shape. Empty `size` means "do not provision a PVC".
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct VolumeClaim {
    /// PVC `requests.storage` value (e.g. `"10Gi"`). Empty string disables
    /// provisioning entirely so a deployment can opt out of either volume.
    #[serde(default)]
    pub size: String,
    /// `storageClassName`. Empty string uses the cluster default.
    #[serde(default, rename = "storageClass")]
    pub storage_class: String,
}

/// Operator-reported status. The operator updates this on every reconcile.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct RustgateClusterStatus {
    /// Number of pods that match the StatefulSet's selector and are Ready.
    #[serde(default, rename = "readyReplicas")]
    pub ready_replicas: i32,
    /// Number of pods that match the selector regardless of Ready status.
    #[serde(default, rename = "availableReplicas")]
    pub available_replicas: i32,
    /// RFC 3339 timestamp of the last successful reconcile.
    #[serde(
        default,
        rename = "lastReconciled",
        skip_serializing_if = "Option::is_none"
    )]
    pub last_reconciled: Option<String>,
    /// Operator-emitted conditions, mirroring the standard Kubernetes
    /// condition vocabulary.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,
}

/// Standard Kubernetes condition shape.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Condition {
    /// Condition type (`Ready`, `Progressing`, `Degraded`).
    #[serde(rename = "type")]
    pub kind: String,
    /// `True`, `False`, or `Unknown`.
    pub status: String,
    /// Machine-readable reason code.
    pub reason: String,
    /// Human-readable detail.
    pub message: String,
    /// Last transition time as RFC 3339.
    #[serde(rename = "lastTransitionTime")]
    pub last_transition_time: String,
}

impl RustgateCluster {
    /// Construct a freshly-defaulted `RustgateCluster` with the given name
    /// and namespace. Useful in tests.
    #[must_use]
    pub fn new(name: impl Into<String>, namespace: impl Into<String>) -> Self {
        Self {
            api_version: API_VERSION_FQN.to_string(),
            kind: KIND.to_string(),
            metadata: ObjectMeta {
                name: name.into(),
                namespace: namespace.into(),
                ..ObjectMeta::default()
            },
            spec: RustgateClusterSpec::default(),
            status: None,
        }
    }

    /// Validate the spec. Returns an [`OperatorError::InvalidSpec`] on the
    /// first failure. Callers should treat the rejection as a terminal
    /// condition for the reconcile attempt — propagate as a `Ready=False`
    /// status condition rather than retrying.
    pub fn validate(&self) -> Result<()> {
        if self.metadata.name.is_empty() {
            return Err(OperatorError::invalid_spec("metadata.name is required"));
        }
        if self.spec.replicas < 1 {
            return Err(OperatorError::invalid_spec(format!(
                "spec.replicas must be >= 1 (got {})",
                self.spec.replicas
            )));
        }
        if self.spec.replicas > MAX_REPLICAS {
            return Err(OperatorError::invalid_spec(format!(
                "spec.replicas must be <= {MAX_REPLICAS} (got {})",
                self.spec.replicas
            )));
        }
        if self.spec.image.is_empty() {
            return Err(OperatorError::invalid_spec("spec.image must not be empty"));
        }
        if self.spec.service_port < 1 || self.spec.service_port > 65535 {
            return Err(OperatorError::invalid_spec(format!(
                "spec.servicePort must be 1..=65535 (got {})",
                self.spec.service_port
            )));
        }
        if self.spec.federation.port < 1 || self.spec.federation.port > 65535 {
            return Err(OperatorError::invalid_spec(format!(
                "spec.federation.port must be 1..=65535 (got {})",
                self.spec.federation.port
            )));
        }
        if let Some(cm) = &self.spec.cert_manager
            && cm.issuer.is_empty()
        {
            return Err(OperatorError::invalid_spec(
                "spec.certManager.issuer must not be empty when certManager is present",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_minimal_spec() {
        let yaml = r#"
apiVersion: rustgate.io/v1alpha1
kind: RustgateCluster
metadata:
  name: my-cluster
  namespace: default
spec:
  replicas: 3
  image: ghcr.io/rchiofalo/rustgate:latest
"#;
        let cluster: RustgateCluster = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cluster.metadata.name, "my-cluster");
        assert_eq!(cluster.spec.replicas, 3);
        assert!(!cluster.spec.federation.auto_discover);
        assert_eq!(cluster.spec.federation.port, 9001);
        assert_eq!(cluster.spec.service_port, 4433);
        cluster.validate().unwrap();
    }

    #[test]
    fn round_trip_full_spec() {
        let yaml = r#"
apiVersion: rustgate.io/v1alpha1
kind: RustgateCluster
metadata:
  name: my-cluster
  namespace: rustgate
spec:
  replicas: 3
  image: ghcr.io/rchiofalo/rustgate:0.8.0
  certManager:
    issuer: letsencrypt-prod
    issuerKind: ClusterIssuer
  federation:
    autoDiscover: true
    port: 9001
  storage:
    storeForward:
      size: 10Gi
      storageClass: standard
    auditLog:
      size: 5Gi
      storageClass: standard
"#;
        let cluster: RustgateCluster = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cluster.spec.replicas, 3);
        assert!(cluster.spec.federation.auto_discover);
        assert_eq!(
            cluster.spec.cert_manager.as_ref().unwrap().issuer,
            "letsencrypt-prod"
        );
        assert_eq!(cluster.spec.storage.store_forward.size, "10Gi");
        cluster.validate().unwrap();
    }

    #[test]
    fn validation_rejects_empty_name() {
        let mut cluster = RustgateCluster::new("ok", "default");
        cluster.metadata.name.clear();
        assert!(cluster.validate().is_err());
    }

    #[test]
    fn validation_rejects_zero_replicas() {
        let mut cluster = RustgateCluster::new("ok", "default");
        cluster.spec.replicas = 0;
        assert!(cluster.validate().is_err());
    }

    #[test]
    fn validation_rejects_excess_replicas() {
        let mut cluster = RustgateCluster::new("ok", "default");
        cluster.spec.replicas = MAX_REPLICAS + 1;
        assert!(cluster.validate().is_err());
    }

    #[test]
    fn validation_rejects_empty_image() {
        let mut cluster = RustgateCluster::new("ok", "default");
        cluster.spec.image.clear();
        assert!(cluster.validate().is_err());
    }

    #[test]
    fn validation_rejects_invalid_service_port() {
        let mut cluster = RustgateCluster::new("ok", "default");
        cluster.spec.service_port = 0;
        assert!(cluster.validate().is_err());

        cluster.spec.service_port = 65_536;
        assert!(cluster.validate().is_err());
    }

    #[test]
    fn validation_rejects_invalid_federation_port() {
        let mut cluster = RustgateCluster::new("ok", "default");
        cluster.spec.federation.port = 0;
        assert!(cluster.validate().is_err());
    }

    #[test]
    fn validation_rejects_empty_issuer() {
        let mut cluster = RustgateCluster::new("ok", "default");
        cluster.spec.cert_manager = Some(CertManagerConfig {
            issuer: String::new(),
            issuer_kind: "ClusterIssuer".to_string(),
            common_name: None,
        });
        assert!(cluster.validate().is_err());
    }

    #[test]
    fn defaults_match_chart_values() {
        let spec = RustgateClusterSpec::default();
        assert_eq!(spec.replicas, 1);
        assert_eq!(spec.image, DEFAULT_IMAGE);
        assert_eq!(spec.service_port, 4433);
        assert_eq!(spec.termination_grace_period_seconds, 30);
        assert_eq!(spec.federation.port, 9001);
        assert!(!spec.federation.auto_discover);
    }

    #[test]
    fn round_trip_status() {
        let status = RustgateClusterStatus {
            ready_replicas: 3,
            available_replicas: 3,
            last_reconciled: Some("2026-05-08T12:00:00Z".to_string()),
            conditions: vec![Condition {
                kind: "Ready".to_string(),
                status: "True".to_string(),
                reason: "ReconcileSucceeded".to_string(),
                message: "All replicas are ready".to_string(),
                last_transition_time: "2026-05-08T12:00:00Z".to_string(),
            }],
        };
        let yaml = serde_yaml::to_string(&status).unwrap();
        let parsed: RustgateClusterStatus = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(parsed, status);
    }
}
