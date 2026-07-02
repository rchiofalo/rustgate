// Copyright © 2026 Roberto Chiofalo.

//! Manifest rendering for the rustgate operator.
//!
//! Given a validated [`RustgateCluster`], the [`render_all`] entry point
//! produces the set of Kubernetes manifests the operator needs to apply:
//!
//! * `apps/v1/StatefulSet` — the rustgate replica set,
//! * `v1/Service` — the headless service for stable DNS,
//! * `v1/Service` — the client-facing ClusterIP service,
//! * `v1/ConfigMap` — the rendered `rustgate.toml` plus, when
//!   `spec.federation.autoDiscover` is `true`, a `federation-peers.json`
//!   peer list that the TOML references via `federation-peers-file`,
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

/// In-pod path the ConfigMap's `rustgate.toml` key is mounted at.
const CONFIG_MOUNT_PATH: &str = "/etc/rustgate/rustgate.toml";

/// In-pod path the ConfigMap's `federation-peers.json` key is mounted at.
/// The rendered `rustgate.toml` references this via `federation-peers-file`.
const FEDERATION_PEERS_MOUNT_PATH: &str = "/etc/rustgate/federation-peers.json";

/// ConfigMap data key holding the peer list. Kept separate from the TOML
/// because the server reads peers from a JSON file (`--federation-peers-file`),
/// not from an inline TOML table — see [`render_federation_peers_json`].
const FEDERATION_PEERS_KEY: &str = "federation-peers.json";

/// Render the `rustgate.toml` the operator embeds in the ConfigMap.
///
/// The output uses the **flat, kebab-cased** keys the server's config loader
/// (`rustgate-server`'s `ConfigFile`, a `deny_unknown_fields` mirror of the
/// CLI flags) actually accepts — `bind`, `federation-v2-bind`,
/// `federation-peers-file`. There is deliberately no `[server]` or
/// `[federation]` table and no `enabled` key: the server rejects unknown
/// keys, and federation is enabled implicitly by the presence of
/// `federation-v2-bind` / `federation-peers-file`.
///
/// When `spec.federation.autoDiscover` is `true`, the peer list is emitted to
/// a **separate JSON file** (see [`render_federation_peers_json`]) referenced
/// by `federation-peers-file`; peers are never inlined into the TOML. The
/// per-pod `federation-id` is supplied at runtime via the
/// `RUSTGATE_FEDERATION_ID` environment variable (wired from `POD_NAME` in the
/// StatefulSet) so each replica gets a distinct server identity — a shared
/// config file cannot express a per-pod value.
pub fn render_rustgate_toml(cluster: &RustgateCluster) -> String {
    let mut out = String::new();
    out.push_str("# rustgate.toml — managed by rustgate-operator\n");
    out.push_str("# Source: RustgateCluster ");
    out.push_str(&cluster.metadata.name);
    out.push('\n');
    out.push('\n');
    out.push_str(&format!(
        "bind = \"0.0.0.0:{}\"\n",
        cluster.spec.service_port
    ));
    if cluster.spec.federation.auto_discover {
        out.push('\n');
        out.push_str("# Federation is enabled by the presence of these keys; the\n");
        out.push_str("# per-pod federation-id is injected via the RUSTGATE_FEDERATION_ID\n");
        out.push_str("# environment variable (POD_NAME) in the StatefulSet.\n");
        out.push_str(&format!(
            "federation-v2-bind = \"0.0.0.0:{}\"\n",
            cluster.spec.federation.port
        ));
        out.push_str(&format!(
            "federation-peers-file = \"{FEDERATION_PEERS_MOUNT_PATH}\"\n"
        ));
    }
    out
}

/// Render the `federation-peers.json` the server ingests via
/// `--federation-peers-file`. The server deserializes this file as a JSON
/// array of `rustgate_federation::config::PeerConfig`, so the shape here must
/// match that struct's required fields exactly (`id`, `address`, `groups`,
/// `enabled`, `is_outbound`, `trust_cert_cn`); all other peer fields fall back
/// to their `serde` defaults.
///
/// One entry is emitted per replica, keyed off the StatefulSet's stable pod
/// DNS names (`<name>-N.<headless-svc>.<ns>.svc.cluster.local`). Each replica
/// runs with a distinct per-pod `federation-id` (injected via
/// `RUSTGATE_FEDERATION_ID`), since a shared ConfigMap cannot carry a per-pod
/// value. Returns `None` when auto-discovery is off (no peers file is
/// referenced in that case).
pub fn render_federation_peers_json(cluster: &RustgateCluster) -> Option<String> {
    if !cluster.spec.federation.auto_discover {
        return None;
    }
    let peers: Vec<Value> = (0..cluster.spec.replicas)
        .map(|i| {
            json!({
                "id": format!("{}-{}", cluster.metadata.name, i),
                "address": format!("{}:{}", pod_dns(cluster, i), cluster.spec.federation.port),
                "groups": [],
                "enabled": true,
                "is_outbound": true,
                "trust_cert_cn": Value::Null,
            })
        })
        .collect();
    // Pretty-print for a readable ConfigMap; the server parses either form.
    serde_json::to_string_pretty(&Value::Array(peers)).ok()
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
    if let Some(peers) = render_federation_peers_json(cluster) {
        let _ = data.insert(FEDERATION_PEERS_KEY.to_string(), peers);
    }
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

    let mut env = vec![
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
            "value": CONFIG_MOUNT_PATH
        }),
    ];
    // A shared ConfigMap cannot carry a per-pod federation-id, so inject it
    // from the pod name — this gives each replica the distinct federation
    // identity the server needs.
    if spec.federation.auto_discover {
        env.push(json!({
            "name": "RUSTGATE_FEDERATION_ID",
            "valueFrom": { "fieldRef": { "fieldPath": "metadata.name" } }
        }));
    }

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
                        "args": ["--config", CONFIG_MOUNT_PATH],
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
    fn rustgate_toml_uses_flat_keys_the_server_accepts() {
        let cluster = full_cluster();
        let toml = render_rustgate_toml(&cluster);
        // Flat top-level bind (not a [server] table, not `tactical-bind`).
        assert!(toml.contains("bind = \"0.0.0.0:4433\""));
        assert!(toml.contains("federation-v2-bind = \"0.0.0.0:9001\""));
        assert!(toml.contains("federation-peers-file = \"/etc/rustgate/federation-peers.json\""));
        // The server rejects these — they must never appear in the TOML.
        assert!(!toml.contains("[server]"));
        assert!(!toml.contains("[federation]"));
        assert!(!toml.contains("[[federation.peers]]"));
        assert!(!toml.contains("enabled = true"));
        assert!(!toml.contains("tactical-bind"));
        // Peers are not inlined into the TOML.
        assert!(!toml.contains("svc.cluster.local"));
        // Never echo the CRD field name into config.
        assert!(!toml.contains("auto_discover"));
    }

    #[test]
    fn federation_peers_json_lists_every_replica() {
        let cluster = full_cluster();
        let peers = render_federation_peers_json(&cluster).expect("peers json");
        let parsed: Value = serde_json::from_str(&peers).unwrap();
        let arr = parsed.as_array().unwrap();
        assert_eq!(arr.len(), 3);
        for (i, peer) in arr.iter().enumerate() {
            assert_eq!(
                peer["id"].as_str().unwrap(),
                format!("my-cluster-{i}").as_str()
            );
            assert_eq!(
                peer["address"].as_str().unwrap(),
                format!("my-cluster-{i}.my-cluster-headless.rustgate.svc.cluster.local:9001")
                    .as_str()
            );
            assert!(peer["enabled"].as_bool().unwrap());
            assert!(peer["is_outbound"].as_bool().unwrap());
            assert!(peer["groups"].is_array());
            assert!(peer["trust_cert_cn"].is_null());
        }
    }

    #[test]
    fn rustgate_toml_skips_federation_when_auto_discover_off() {
        let mut cluster = full_cluster();
        cluster.spec.federation.auto_discover = false;
        let toml = render_rustgate_toml(&cluster);
        assert!(!toml.contains("federation-v2-bind"));
        assert!(!toml.contains("federation-peers-file"));
        assert!(toml.contains("bind = \"0.0.0.0:4433\""));
        assert!(render_federation_peers_json(&cluster).is_none());
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
