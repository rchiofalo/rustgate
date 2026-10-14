// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Cross-module integration test for the controller-feature build.
//!
//! Exercises the kube-side bridge: a [`RustgateCluster`] flows through
//! [`kube_types::to_render_cluster`] to the renderer, and the resulting
//! manifests must match what the renderer would produce against the
//! same source cluster bypassing the bridge. This pins the property
//! that the JSON round-trip is lossless for every field the renderer
//! depends on — a future renderer feature that reads a new spec field
//! would surface here as a diff in the rendered output.

#![cfg(feature = "controller")]
#![allow(clippy::panic, clippy::unwrap_used)]

use rustgate_operator::crd::{
    CertManagerConfig, FederationConfig, RustgateCluster, RustgateClusterSpec, StorageConfig,
    VolumeClaim,
};
use rustgate_operator::kube_types::{
    RustgateCluster as KubeCluster, to_kube_status, to_render_cluster,
};
use rustgate_operator::reconcile::reconcile;
use rustgate_operator::render::render_all;

fn full_cluster() -> RustgateCluster {
    let mut c = RustgateCluster::new("my-cluster", "rustgate");
    c.metadata.uid = Some("00000000-0000-0000-0000-000000000001".to_string());
    c.spec = RustgateClusterSpec {
        replicas: 3,
        image: "ghcr.io/rchiofalo/rustgate:0.9.0".to_string(),
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
fn render_through_bridge_matches_direct_render() {
    let direct = full_cluster();
    // Bridge: encode as the kube view, then decode back. This is what
    // the controller does on every reconcile, so the property under
    // test is the actual contract end-to-end.
    let kube_value = serde_json::to_value(&direct).unwrap();
    let kube: KubeCluster = serde_json::from_value(kube_value).unwrap();
    let via_bridge = to_render_cluster(&kube).unwrap();

    let expected = render_all(&direct).unwrap();
    let actual = render_all(&via_bridge).unwrap();

    assert_eq!(actual.len(), expected.len());
    for (a, e) in actual.iter().zip(expected.iter()) {
        assert_eq!(a.kind, e.kind);
        assert_eq!(a.name, e.name);
        assert_eq!(
            a.manifest, e.manifest,
            "manifest mismatch on {}/{}",
            a.kind, a.name
        );
    }
}

#[test]
fn status_round_trip_through_kube_view_is_lossless() {
    let cluster = full_cluster();
    let outcome = reconcile(&cluster, "2026-05-10T12:00:00Z").unwrap();
    let kube_status = to_kube_status(&outcome.status).unwrap();
    assert_eq!(
        kube_status.last_reconciled.as_deref(),
        Some("2026-05-10T12:00:00Z")
    );
    assert_eq!(
        kube_status.conditions.len(),
        outcome.status.conditions.len()
    );
    for (a, e) in kube_status
        .conditions
        .iter()
        .zip(outcome.status.conditions.iter())
    {
        assert_eq!(a.kind, e.kind);
        assert_eq!(a.status, e.status);
        assert_eq!(a.reason, e.reason);
        assert_eq!(a.message, e.message);
        assert_eq!(a.last_transition_time, e.last_transition_time);
    }
}

#[test]
fn bridge_preserves_minimal_cluster() {
    let mut minimal = RustgateCluster::new("rg-min", "default");
    minimal.spec.replicas = 1;
    let kube_value = serde_json::to_value(&minimal).unwrap();
    let kube: KubeCluster = serde_json::from_value(kube_value).unwrap();
    let via_bridge = to_render_cluster(&kube).unwrap();

    assert_eq!(via_bridge.spec.replicas, 1);
    assert_eq!(via_bridge.metadata.name, "rg-min");
    assert_eq!(via_bridge.metadata.namespace, "default");
    assert!(via_bridge.spec.cert_manager.is_none());
    assert!(!via_bridge.spec.federation.auto_discover);
}

#[test]
fn bridge_preserves_cert_manager_config() {
    let mut c = RustgateCluster::new("rg-cm", "rustgate");
    c.spec.cert_manager = Some(CertManagerConfig {
        issuer: "selfsigned-issuer".to_string(),
        issuer_kind: "Issuer".to_string(),
        common_name: Some("rg.svc.cluster.local".to_string()),
    });
    let kube_value = serde_json::to_value(&c).unwrap();
    let kube: KubeCluster = serde_json::from_value(kube_value).unwrap();
    let via_bridge = to_render_cluster(&kube).unwrap();

    let cm = via_bridge.spec.cert_manager.unwrap();
    assert_eq!(cm.issuer, "selfsigned-issuer");
    assert_eq!(cm.issuer_kind, "Issuer");
    assert_eq!(cm.common_name.as_deref(), Some("rg.svc.cluster.local"));
}

#[test]
fn bridge_preserves_storage_config() {
    let mut c = RustgateCluster::new("rg-stor", "rustgate");
    c.spec.storage = StorageConfig {
        store_forward: VolumeClaim {
            size: "20Gi".to_string(),
            storage_class: "fast-ssd".to_string(),
        },
        audit_log: VolumeClaim {
            size: "100Gi".to_string(),
            storage_class: "archive".to_string(),
        },
    };
    let kube_value = serde_json::to_value(&c).unwrap();
    let kube: KubeCluster = serde_json::from_value(kube_value).unwrap();
    let via_bridge = to_render_cluster(&kube).unwrap();

    assert_eq!(via_bridge.spec.storage.store_forward.size, "20Gi");
    assert_eq!(
        via_bridge.spec.storage.store_forward.storage_class,
        "fast-ssd"
    );
    assert_eq!(via_bridge.spec.storage.audit_log.size, "100Gi");
    assert_eq!(via_bridge.spec.storage.audit_log.storage_class, "archive");
}
