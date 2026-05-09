// Copyright © 2026 Roberto Chiofalo.

//! Golden-render snapshot tests for the operator's reconcile path.

#![allow(clippy::panic, clippy::unwrap_used)]

use rustgate_operator::crd::{
    CertManagerConfig, FederationConfig, RustgateCluster, RustgateClusterSpec, StorageConfig,
    VolumeClaim,
};
use rustgate_operator::render::{render_all, render_all_yaml};

/// Build a representative cluster with every optional knob set so the
/// snapshot covers the full surface area of the renderer.
fn full_cluster() -> RustgateCluster {
    let mut c = RustgateCluster::new("my-cluster", "rustgate");
    c.metadata.uid = Some("00000000-0000-0000-0000-000000000001".to_string());
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

fn minimal_cluster() -> RustgateCluster {
    let mut c = RustgateCluster::new("rustgate-min", "default");
    c.spec.replicas = 1;
    c
}

#[test]
fn snapshot_full_cluster_yaml() {
    let cluster = full_cluster();
    let yaml = render_all_yaml(&cluster).expect("render");
    insta::assert_snapshot!("full_cluster", yaml);
}

#[test]
fn snapshot_minimal_cluster_yaml() {
    let cluster = minimal_cluster();
    let yaml = render_all_yaml(&cluster).expect("render");
    insta::assert_snapshot!("minimal_cluster", yaml);
}

#[test]
fn snapshot_no_cert_manager_yaml() {
    let mut cluster = full_cluster();
    cluster.spec.cert_manager = None;
    let yaml = render_all_yaml(&cluster).expect("render");
    insta::assert_snapshot!("no_cert_manager", yaml);
}

#[test]
fn snapshot_no_auto_discover_yaml() {
    let mut cluster = full_cluster();
    cluster.spec.federation.auto_discover = false;
    let yaml = render_all_yaml(&cluster).expect("render");
    insta::assert_snapshot!("no_auto_discover", yaml);
}

#[test]
fn snapshot_no_audit_log_pvc_yaml() {
    let mut cluster = full_cluster();
    cluster.spec.storage.audit_log = VolumeClaim::default();
    let yaml = render_all_yaml(&cluster).expect("render");
    insta::assert_snapshot!("no_audit_log_pvc", yaml);
}

#[test]
fn full_cluster_renders_five_manifests() {
    let cluster = full_cluster();
    let manifests = render_all(&cluster).expect("render");
    let kinds: Vec<&str> = manifests.iter().map(|m| m.kind.as_str()).collect();
    assert_eq!(
        kinds,
        vec![
            "Service",
            "Service",
            "ConfigMap",
            "Certificate",
            "StatefulSet"
        ]
    );
}

#[test]
fn statefulset_uses_per_pod_dns_in_federation_peers() {
    let cluster = full_cluster();
    let manifests = render_all(&cluster).expect("render");
    let cm = manifests
        .iter()
        .find(|m| m.kind == "ConfigMap")
        .expect("configmap");
    let toml = cm.manifest["data"]["rustgate.toml"]
        .as_str()
        .expect("rustgate.toml string");
    for i in 0..3 {
        let expected =
            format!("my-cluster-{i}.my-cluster-headless.rustgate.svc.cluster.local:9001");
        assert!(
            toml.contains(&expected),
            "expected federation peer {expected} in rendered config:\n{toml}"
        );
    }
}

#[test]
fn certificate_dns_names_cover_every_pod() {
    let cluster = full_cluster();
    let manifests = render_all(&cluster).expect("render");
    let cert = manifests
        .iter()
        .find(|m| m.kind == "Certificate")
        .expect("certificate");
    let dns = cert.manifest["spec"]["dnsNames"]
        .as_array()
        .expect("dnsNames array");
    assert_eq!(dns.len(), 5); // svc + headless + 3 pods
    let expected_dns = "my-cluster-0.my-cluster-headless.rustgate.svc.cluster.local";
    assert!(dns.iter().any(|v| v.as_str() == Some(expected_dns)));
}

#[test]
fn reconcile_outcome_contains_progressing_condition() {
    let cluster = full_cluster();
    let outcome =
        rustgate_operator::reconcile(&cluster, "2026-05-08T00:00:00Z").expect("reconcile");
    assert_eq!(outcome.manifests.len(), 5);
    assert_eq!(outcome.status.conditions.len(), 1);
    assert_eq!(outcome.status.conditions[0].kind, "Progressing");
    assert_eq!(outcome.status.conditions[0].status, "True");
    assert_eq!(
        outcome.status.last_reconciled.as_deref(),
        Some("2026-05-08T00:00:00Z")
    );
}

#[test]
fn reconcile_rejects_invalid_replicas() {
    let mut cluster = full_cluster();
    cluster.spec.replicas = 0;
    let result = rustgate_operator::reconcile(&cluster, "2026-05-08T00:00:00Z");
    assert!(result.is_err());
}

#[test]
fn yaml_includes_separator_per_document() {
    let cluster = full_cluster();
    let yaml = render_all_yaml(&cluster).expect("render");
    // 5 documents → 5 separators (the renderer always prefixes with `---`)
    assert_eq!(yaml.matches("\n---\n").count() + 1, 5);
}

#[test]
fn round_trip_yaml_to_struct_and_back() {
    let cluster = full_cluster();
    let cluster_yaml = serde_yaml::to_string(&cluster).expect("cluster to_yaml");
    let parsed: RustgateCluster = serde_yaml::from_str(&cluster_yaml).expect("from yaml");
    assert_eq!(parsed.metadata.name, "my-cluster");
    assert_eq!(parsed.spec.replicas, 3);
    assert!(parsed.spec.federation.auto_discover);
    assert_eq!(
        parsed.spec.cert_manager.as_ref().unwrap().issuer,
        "letsencrypt-prod"
    );
}
