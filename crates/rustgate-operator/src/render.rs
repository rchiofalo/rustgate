// Copyright © 2026 Roberto Chiofalo.

//! Manifest rendering for the rustgate operator.
//!
//! Given a validated [`RustgateCluster`], the [`render_all`] entry point
//! produces the set of Kubernetes manifests the operator needs to apply:
//!
//! * `apps/v1/StatefulSet` — the rustgate replica set,
//! * `v1/Service` — the headless service for stable DNS,
//! * `v1/Service` — the client-facing ClusterIP service,
//! * `v1/ConfigMap` — the rendered `rustgate.toml` (including the
//!   federation peer list when `spec.federation.autoDiscover` is `true`),
//! * `cert-manager.io/v1/Certificate` — emitted only when
//!   `spec.certManager` is present, one per cluster (the chart's existing
//!   per-pod cert reloader rotates pods through the same SVID).
//!
//! Manifests are returned as [`RenderedManifest`] tuples carrying the
//! resource kind for ordering at apply time. The renderer is pure — it does
//! not call out to the Kubernetes API — which is what the golden-render
//! tests rely on.

use std::collections::BTreeMap;

use serde_json::{Value, json};

use crate::crd::{RustgateCluster, RustgateClusterSpec};
use crate::error::Result;

/// One rendered Kubernetes manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedManifest {
    /// `kind` (e.g. `StatefulSet`, `Service`, `ConfigMap`, `Certificate`).
    pub kind: String,
    /// The canonical name `metadata.name`.
    pub name: String,
    /// JSON value carrying the full manifest.
    pub manifest: Value,
}

impl RenderedManifest {
    /// Serialize the manifest as YAML (suitable for `kubectl apply -f -`).
    pub fn to_yaml(&self) -> Result<String> {
        Ok(serde_yaml::to_string(&self.manifest)?)
    }
}

/// Render every manifest the operator owns for the given cluster.
///
/// The returned vector is ordered: `Service` (headless), `Service` (client),
/// `ConfigMap`, `Certificate` (if any), `StatefulSet`. Apply order matches
/// the dependency graph — the StatefulSet references the headless service
/// by name, the ConfigMap, and the Certificate's TLS secret.
pub fn render_all(cluster: &RustgateCluster) -> Result<Vec<RenderedManifest>> {
    cluster.validate()?;
    let mut out = Vec::with_capacity(5);
    out.push(render_headless_service(cluster)?);
    out.push(render_client_service(cluster)?);
    out.push(render_configmap(cluster)?);
    if let Some(cert) = render_certificate(cluster)? {
        out.push(cert);
    }
    out.push(render_statefulset(cluster)?);
    Ok(out)
}

/// `metadata.name` for the headless StatefulSet service.
fn headless_service_name(cluster: &RustgateCluster) -> String {
    format!("{}-headless", cluster.metadata.name)
}

/// `metadata.name` for the client-facing service.
fn client_service_name(cluster: &RustgateCluster) -> String {
    cluster.metadata.name.clone()
}

/// `metadata.name` for the rendered ConfigMap.
fn configmap_name(cluster: &RustgateCluster) -> String {
    format!("{}-config", cluster.metadata.name)
}

/// `metadata.name` for the cert-manager Certificate.
fn certificate_name(cluster: &RustgateCluster) -> String {
    format!("{}-tls", cluster.metadata.name)
}

/// `Secret` name that the Certificate writes to (and the StatefulSet mounts).
fn tls_secret_name(cluster: &RustgateCluster) -> String {
    format!("{}-tls", cluster.metadata.name)
}

/// Standard labels applied to every owned object.
fn labels(cluster: &RustgateCluster) -> BTreeMap<String, String> {
    let mut labels = BTreeMap::new();
    let _ = labels.insert("app.kubernetes.io/name".to_string(), "rustgate".to_string());
    let _ = labels.insert(
        "app.kubernetes.io/instance".to_string(),
        cluster.metadata.name.clone(),
    );
    let _ = labels.insert(
        "app.kubernetes.io/managed-by".to_string(),
        "rustgate-operator".to_string(),
    );
    let _ = labels.insert(
        "rustgate.io/cluster".to_string(),
        cluster.metadata.name.clone(),
    );
    labels
}

/// Build the owner-references slice that ties a child object to its parent
/// `RustgateCluster`. When the `metadata.uid` is unset (e.g. a freshly-built
/// cluster being rendered for golden tests) the slice is empty so the
/// rendered manifests stay deterministic.
fn owner_references(cluster: &RustgateCluster) -> Vec<Value> {
    let Some(uid) = &cluster.metadata.uid else {
        return Vec::new();
    };
    vec![json!({
        "apiVersion": crate::crd::API_VERSION_FQN,
        "kind": crate::crd::KIND,
        "name": cluster.metadata.name,
        "uid": uid,
        "controller": true,
        "blockOwnerDeletion": true,
    })]
}

fn render_headless_service(cluster: &RustgateCluster) -> Result<RenderedManifest> {
    let manifest = json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": headless_service_name(cluster),
            "namespace": cluster.metadata.namespace,
            "labels": labels(cluster),
            "ownerReferences": owner_references(cluster),
        },
        "spec": {
            "clusterIP": "None",
            "selector": {
                "app.kubernetes.io/name": "rustgate",
                "app.kubernetes.io/instance": cluster.metadata.name,
            },
            "ports": [
                {
                    "name": "tactical",
                    "port": cluster.spec.service_port,
                    "targetPort": cluster.spec.service_port,
                    "protocol": "TCP",
                },
                {
                    "name": "federation",
                    "port": cluster.spec.federation.port,
                    "targetPort": cluster.spec.federation.port,
                    "protocol": "TCP",
                },
            ],
            "publishNotReadyAddresses": true,
        }
    });
    Ok(RenderedManifest {
        kind: "Service".to_string(),
        name: headless_service_name(cluster),
        manifest,
    })
}

fn render_client_service(cluster: &RustgateCluster) -> Result<RenderedManifest> {
    let manifest = json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": client_service_name(cluster),
            "namespace": cluster.metadata.namespace,
            "labels": labels(cluster),
            "ownerReferences": owner_references(cluster),
        },
        "spec": {
            "type": "ClusterIP",
            "selector": {
                "app.kubernetes.io/name": "rustgate",
                "app.kubernetes.io/instance": cluster.metadata.name,
            },
            "ports": [
                {
                    "name": "tactical",
                    "port": cluster.spec.service_port,
                    "targetPort": cluster.spec.service_port,
                    "protocol": "TCP",
                }
            ],
        }
    });
    Ok(RenderedManifest {
        kind: "Service".to_string(),
        name: client_service_name(cluster),
        manifest,
    })
}

/// Render the rustgate.toml content the operator embeds in the ConfigMap.
///
/// When `spec.federation.autoDiscover` is `true`, the operator emits a peer
/// list keyed off the StatefulSet's stable pod DNS names. Each replica
/// `<name>-N.<headless-svc>.<ns>.svc.cluster.local` becomes a peer entry.
/// Pods skip themselves at runtime via the federation manager's existing
/// self-id filter, so listing every replica unconditionally is safe.
pub fn render_rustgate_toml(cluster: &RustgateCluster) -> String {
    let mut out = String::new();
    out.push_str("# rustgate.toml — managed by rustgate-operator\n");
    out.push_str("# Source: RustgateCluster ");
    out.push_str(&cluster.metadata.name);
    out.push('\n');
    out.push('\n');
    out.push_str("[server]\n");
    out.push_str(&format!(
        "tactical-bind = \"0.0.0.0:{}\"\n",
        cluster.spec.service_port
    ));
    out.push('\n');
    if cluster.spec.federation.auto_discover {
        out.push_str("[federation]\n");
        out.push_str("enabled = true\n");
        out.push_str(&format!(
            "v2-bind = \"0.0.0.0:{}\"\n",
            cluster.spec.federation.port
        ));
        out.push_str(&format!(
            "id = \"{}-${{HOSTNAME}}\"\n",
            cluster.metadata.name
        ));
        out.push_str("# Peers below are generated from StatefulSet pod DNS records.\n");
        out.push_str("# The federation manager filters self by id at runtime.\n");
        for i in 0..cluster.spec.replicas {
            let dns = pod_dns(cluster, i);
            out.push('\n');
            out.push_str("[[federation.peers]]\n");
            out.push_str(&format!("id = \"{}-{}\"\n", cluster.metadata.name, i));
            out.push_str(&format!(
                "address = \"{}:{}\"\n",
                dns, cluster.spec.federation.port
            ));
        }
    }
    out
}

/// Stable pod DNS name for replica `i`. Mirrors the layout the StatefulSet
/// controller writes into Endpoints when `publishNotReadyAddresses: true`.
pub fn pod_dns(cluster: &RustgateCluster, i: i32) -> String {
    let ns = if cluster.metadata.namespace.is_empty() {
        "default"
    } else {
        cluster.metadata.namespace.as_str()
    };
    format!(
        "{}-{}.{}.{}.svc.cluster.local",
        cluster.metadata.name,
        i,
        headless_service_name(cluster),
        ns
    )
}

fn render_configmap(cluster: &RustgateCluster) -> Result<RenderedManifest> {
    let mut data = BTreeMap::new();
    let _ = data.insert("rustgate.toml".to_string(), render_rustgate_toml(cluster));
    let manifest = json!({
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {
            "name": configmap_name(cluster),
            "namespace": cluster.metadata.namespace,
            "labels": labels(cluster),
            "ownerReferences": owner_references(cluster),
        },
        "data": data,
    });
    Ok(RenderedManifest {
        kind: "ConfigMap".to_string(),
        name: configmap_name(cluster),
        manifest,
    })
}

fn render_certificate(cluster: &RustgateCluster) -> Result<Option<RenderedManifest>> {
    let Some(cm) = cluster.spec.cert_manager.as_ref() else {
        return Ok(None);
    };
    let common_name = cm
        .common_name
        .clone()
        .unwrap_or_else(|| cluster.metadata.name.clone());
    let mut sans = vec![client_service_name(cluster), headless_service_name(cluster)];
    for i in 0..cluster.spec.replicas {
        sans.push(pod_dns(cluster, i));
    }
    let manifest = json!({
        "apiVersion": "cert-manager.io/v1",
        "kind": "Certificate",
        "metadata": {
            "name": certificate_name(cluster),
            "namespace": cluster.metadata.namespace,
            "labels": labels(cluster),
            "ownerReferences": owner_references(cluster),
        },
        "spec": {
            "secretName": tls_secret_name(cluster),
            "commonName": common_name,
            "dnsNames": sans,
            "issuerRef": {
                "name": cm.issuer,
                "kind": cm.issuer_kind,
            },
            "duration": "2160h",   // 90 days
            "renewBefore": "360h", // 15 days
        }
    });
    Ok(Some(RenderedManifest {
        kind: "Certificate".to_string(),
        name: certificate_name(cluster),
        manifest,
    }))
}

fn render_statefulset(cluster: &RustgateCluster) -> Result<RenderedManifest> {
    let spec: &RustgateClusterSpec = &cluster.spec;
    let mut volume_mounts = vec![
        json!({ "name": "config", "mountPath": "/etc/rustgate", "readOnly": true }),
        json!({ "name": "tls", "mountPath": "/certs", "readOnly": true }),
    ];
    let volumes = vec![
        json!({
            "name": "config",
            "configMap": { "name": configmap_name(cluster) }
        }),
        json!({
            "name": "tls",
            "secret": { "secretName": tls_secret_name(cluster) }
        }),
    ];
    let mut volume_claim_templates = Vec::new();

    if !spec.storage.store_forward.size.is_empty() {
        volume_mounts.push(json!({
            "name": "store-forward",
            "mountPath": "/data/client-queue",
        }));
        volume_claim_templates.push(volume_claim_template(
            "store-forward",
            &spec.storage.store_forward.size,
            &spec.storage.store_forward.storage_class,
        ));
    }
    if !spec.storage.audit_log.size.is_empty() {
        volume_mounts.push(json!({
            "name": "audit-log",
            "mountPath": "/data/audit",
        }));
        volume_claim_templates.push(volume_claim_template(
            "audit-log",
            &spec.storage.audit_log.size,
            &spec.storage.audit_log.storage_class,
        ));
    }

    let env = vec![
        json!({
            "name": "POD_NAME",
            "valueFrom": { "fieldRef": { "fieldPath": "metadata.name" } }
        }),
        json!({
            "name": "POD_NAMESPACE",
            "valueFrom": { "fieldRef": { "fieldPath": "metadata.namespace" } }
        }),
        json!({
            "name": "RUSTGATE_CONFIG",
            "value": "/etc/rustgate/rustgate.toml"
        }),
    ];

    let manifest = json!({
        "apiVersion": "apps/v1",
        "kind": "StatefulSet",
        "metadata": {
            "name": cluster.metadata.name,
            "namespace": cluster.metadata.namespace,
            "labels": labels(cluster),
            "ownerReferences": owner_references(cluster),
        },
        "spec": {
            "serviceName": headless_service_name(cluster),
            "replicas": spec.replicas,
            "podManagementPolicy": "Parallel",
            "selector": {
                "matchLabels": {
                    "app.kubernetes.io/name": "rustgate",
                    "app.kubernetes.io/instance": cluster.metadata.name,
                }
            },
            "template": {
                "metadata": {
                    "labels": labels(cluster),
                },
                "spec": {
                    "terminationGracePeriodSeconds": spec.termination_grace_period_seconds,
                    "securityContext": {
                        "runAsNonRoot": true,
                        "runAsUser": 10001,
                        "runAsGroup": 10001,
                        "fsGroup": 10001,
                        "seccompProfile": { "type": "RuntimeDefault" },
                    },
                    "containers": [{
                        "name": "rustgate",
                        "image": spec.image,
                        "imagePullPolicy": spec.image_pull_policy,
                        "args": ["--config", "/etc/rustgate/rustgate.toml"],
                        "env": env,
                        "ports": [
                            { "name": "tactical", "containerPort": spec.service_port, "protocol": "TCP" },
                            { "name": "federation", "containerPort": spec.federation.port, "protocol": "TCP" },
                        ],
                        "volumeMounts": volume_mounts,
                        "securityContext": {
                            "allowPrivilegeEscalation": false,
                            "readOnlyRootFilesystem": true,
                            "capabilities": { "drop": ["ALL"] },
                        },
                        "readinessProbe": {
                            "tcpSocket": { "port": spec.service_port },
                            "initialDelaySeconds": 5,
                            "periodSeconds": 10,
                        },
                        "livenessProbe": {
                            "tcpSocket": { "port": spec.service_port },
                            "initialDelaySeconds": 30,
                            "periodSeconds": 30,
                        },
                    }],
                    "volumes": volumes,
                }
            },
            "volumeClaimTemplates": volume_claim_templates,
        }
    });
    Ok(RenderedManifest {
        kind: "StatefulSet".to_string(),
        name: cluster.metadata.name.clone(),
        manifest,
    })
}

/// Build a `volumeClaimTemplate` entry. An empty `storage_class` means
/// "use the cluster default".
fn volume_claim_template(name: &str, size: &str, storage_class: &str) -> Value {
    let mut spec = json!({
        "accessModes": ["ReadWriteOnce"],
        "resources": { "requests": { "storage": size } },
    });
    if !storage_class.is_empty()
        && let Value::Object(obj) = &mut spec
    {
        let _ = obj.insert(
            "storageClassName".to_string(),
            Value::String(storage_class.to_string()),
        );
    }
    json!({
        "metadata": { "name": name },
        "spec": spec,
    })
}

/// Convenience: render every owned manifest as a single multi-document YAML
/// stream. Useful for `kubectl apply -f -` from a one-shot operator
/// invocation, and for the `render` CLI subcommand.
pub fn render_all_yaml(cluster: &RustgateCluster) -> Result<String> {
    let mut out = String::new();
    for m in render_all(cluster)? {
        out.push_str("---\n");
        out.push_str(&m.to_yaml()?);
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::crd::{CertManagerConfig, FederationConfig, StorageConfig, VolumeClaim};

    fn full_cluster() -> RustgateCluster {
        let mut c = RustgateCluster::new("my-cluster", "rustgate");
        c.spec = RustgateClusterSpec {
            replicas: 3,
            image: "ghcr.io/rchiofalo/rustgate:0.8.0".to_string(),
            image_pull_policy: "IfNotPresent".to_string(),
            cert_manager: Some(CertManagerConfig {
                issuer: "letsencrypt-prod".to_string(),
                issuer_kind: "ClusterIssuer".to_string(),
                common_name: None,
            }),
            federation: FederationConfig {
                auto_discover: true,
                port: 9001,
            },
            storage: StorageConfig {
                store_forward: VolumeClaim {
                    size: "10Gi".to_string(),
                    storage_class: "standard".to_string(),
                },
                audit_log: VolumeClaim {
                    size: "5Gi".to_string(),
                    storage_class: "standard".to_string(),
                },
            },
            service_port: 4433,
            termination_grace_period_seconds: 30,
        };
        c
    }

    #[test]
    fn render_all_returns_expected_resource_set() {
        let cluster = full_cluster();
        let manifests = render_all(&cluster).unwrap();
        // Service x2, ConfigMap, Certificate, StatefulSet.
        assert_eq!(manifests.len(), 5);
        assert_eq!(manifests[0].kind, "Service");
        assert_eq!(manifests[0].name, "my-cluster-headless");
        assert_eq!(manifests[1].kind, "Service");
        assert_eq!(manifests[1].name, "my-cluster");
        assert_eq!(manifests[2].kind, "ConfigMap");
        assert_eq!(manifests[3].kind, "Certificate");
        assert_eq!(manifests[4].kind, "StatefulSet");
    }

    #[test]
    fn render_skips_certificate_when_absent() {
        let mut cluster = full_cluster();
        cluster.spec.cert_manager = None;
        let manifests = render_all(&cluster).unwrap();
        assert_eq!(manifests.len(), 4);
        assert!(!manifests.iter().any(|m| m.kind == "Certificate"));
    }

    #[test]
    fn render_skips_volume_claim_when_size_empty() {
        let mut cluster = full_cluster();
        cluster.spec.storage.audit_log.size.clear();
        let manifests = render_all(&cluster).unwrap();
        let sts = manifests.iter().find(|m| m.kind == "StatefulSet").unwrap();
        let templates = sts.manifest["spec"]["volumeClaimTemplates"]
            .as_array()
            .unwrap();
        assert_eq!(templates.len(), 1);
        assert_eq!(
            templates[0]["metadata"]["name"].as_str().unwrap(),
            "store-forward"
        );
    }

    #[test]
    fn rustgate_toml_includes_peers_when_auto_discover_on() {
        let cluster = full_cluster();
        let toml = render_rustgate_toml(&cluster);
        assert!(toml.contains("[federation]"));
        // Sanity: we should not be echoing the CRD field name into
        // rustgate.toml (which uses `enabled` rather than `autoDiscover`).
        assert!(!toml.contains("auto_discover"));
        for i in 0..3 {
            assert!(toml.contains(&format!("my-cluster-{i}")));
            assert!(toml.contains(&format!(
                "my-cluster-{i}.my-cluster-headless.rustgate.svc.cluster.local:9001"
            )));
        }
    }

    #[test]
    fn rustgate_toml_skips_peers_when_auto_discover_off() {
        let mut cluster = full_cluster();
        cluster.spec.federation.auto_discover = false;
        let toml = render_rustgate_toml(&cluster);
        assert!(!toml.contains("[federation]"));
        assert!(!toml.contains("[[federation.peers]]"));
    }

    #[test]
    fn render_includes_owner_references_when_uid_set() {
        let mut cluster = full_cluster();
        cluster.metadata.uid = Some("abcd-1234".to_string());
        let manifests = render_all(&cluster).unwrap();
        for m in manifests {
            let refs = &m.manifest["metadata"]["ownerReferences"];
            assert!(refs.is_array());
            let arr = refs.as_array().unwrap();
            assert_eq!(arr.len(), 1, "{} should have 1 ownerRef", m.kind);
            assert_eq!(arr[0]["uid"].as_str().unwrap(), "abcd-1234");
            assert!(arr[0]["controller"].as_bool().unwrap());
        }
    }

    #[test]
    fn render_omits_owner_references_when_uid_unset() {
        let cluster = full_cluster();
        let manifests = render_all(&cluster).unwrap();
        for m in manifests {
            let refs = m.manifest["metadata"]["ownerReferences"]
                .as_array()
                .unwrap();
            assert!(refs.is_empty(), "{} should have empty ownerRefs", m.kind);
        }
    }

    #[test]
    fn render_propagates_validation_errors() {
        let mut cluster = full_cluster();
        cluster.spec.replicas = 0;
        let result = render_all(&cluster);
        assert!(matches!(
            result,
            Err(crate::error::OperatorError::InvalidSpec { .. })
        ));
    }

    #[test]
    fn render_yaml_concatenates_documents() {
        let cluster = full_cluster();
        let yaml = render_all_yaml(&cluster).unwrap();
        // 5 documents, each separated by ---
        assert_eq!(yaml.matches("\n---\n").count() + 1, 5);
        assert!(yaml.contains("kind: StatefulSet"));
        assert!(yaml.contains("kind: Certificate"));
        assert!(yaml.contains("kind: ConfigMap"));
        assert!(yaml.contains("kind: Service"));
    }

    #[test]
    fn statefulset_has_termination_grace_period() {
        let cluster = full_cluster();
        let manifests = render_all(&cluster).unwrap();
        let sts = manifests.iter().find(|m| m.kind == "StatefulSet").unwrap();
        let grace = sts.manifest["spec"]["template"]["spec"]["terminationGracePeriodSeconds"]
            .as_i64()
            .unwrap();
        assert_eq!(grace, 30);
    }

    #[test]
    fn certificate_has_per_pod_sans() {
        let cluster = full_cluster();
        let manifests = render_all(&cluster).unwrap();
        let cert = manifests.iter().find(|m| m.kind == "Certificate").unwrap();
        let dns = cert.manifest["spec"]["dnsNames"].as_array().unwrap();
        // client svc + headless svc + 3 pods = 5
        assert_eq!(dns.len(), 5);
        assert!(dns.iter().any(|v| v.as_str() == Some("my-cluster")));
        assert!(
            dns.iter()
                .any(|v| v.as_str() == Some("my-cluster-headless"))
        );
        for i in 0..3 {
            let expected = format!("my-cluster-{i}.my-cluster-headless.rustgate.svc.cluster.local");
            assert!(dns.iter().any(|v| v.as_str() == Some(expected.as_str())));
        }
    }
}
