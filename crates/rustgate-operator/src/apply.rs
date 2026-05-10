// Copyright © 2026 Roberto Chiofalo.

//! Server-side apply (SSA) of the renderer's output.
//!
//! The reconcile loop produces a `Vec<RenderedManifest>` from
//! [`crate::render::render_all`]. This module turns those YAML strings
//! into idempotent Kubernetes API calls. The implementation is
//! deliberately kind-agnostic — every manifest goes through
//! [`kube::api::DynamicObject`] and [`kube::api::Api::patch`] with the
//! same `PatchParams::apply("rustgate-operator")`, so a future renderer
//! that emits new kinds (e.g. `NetworkPolicy`, `PodDisruptionBudget`)
//! works without touching this file.
//!
//! ## Field manager
//!
//! Every apply call uses the stable field manager string
//! [`FIELD_MANAGER`]. Mixing field managers within a single cluster
//! causes server-side apply to surface
//! `metav1.Status.reason = "FieldManagerConflict"` errors and lose
//! ownership of fields, so any future helper that also patches owned
//! objects MUST reuse this constant.
//!
//! ## Force flag
//!
//! [`PatchParams::force`] is set to `true`. That tells the API server
//! to take ownership of any conflicting fields from another manager
//! (e.g. an operator that previously ran with a different field
//! manager, or a `kubectl edit` that hand-patched a field). Without
//! `force`, drift from human edits would block the operator on every
//! apply attempt; with `force`, the operator wins. This is intentional —
//! the `RustgateCluster` CR is the source of truth, and the apply step
//! is the operator's enforcement.

#![cfg(feature = "controller")]

use std::collections::BTreeMap;

use kube::api::{Api, DynamicObject, GroupVersionKind, Patch, PatchParams};
use kube::core::TypeMeta;
use kube::discovery::ApiResource;
use kube::{Client, ResourceExt};
use serde_json::Value as JsonValue;

use crate::error::OperatorError;
use crate::metrics;
use crate::render::RenderedManifest;

/// Stable field manager string used for every server-side apply. Do not
/// change without a migration plan — Kubernetes binds field ownership
/// to this string and renaming it would force the API server to treat
/// the operator's next apply as "from a different manager."
pub const FIELD_MANAGER: &str = "rustgate-operator";

/// Reference to a successfully applied object. The controller carries
/// this list through to status reporting and event emission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedRef {
    pub api_version: String,
    pub kind: String,
    pub name: String,
    pub namespace: Option<String>,
}

/// Apply every rendered manifest server-side. Returns a list of refs to
/// the applied objects in order. On the first failure returns the
/// partial list-so-far plus the error so the controller can surface a
/// `Warning/ApplyFailed` event with the right object kind.
///
/// `default_namespace` is used when a rendered manifest has no
/// `metadata.namespace` set — the renderer sets the parent's namespace
/// on every owned object today, but we keep this defensive in case a
/// future kind is cluster-scoped or relies on the implicit default.
pub async fn apply_all(
    client: &Client,
    default_namespace: &str,
    manifests: &[RenderedManifest],
) -> Result<Vec<AppliedRef>, OperatorError> {
    let mut applied = Vec::with_capacity(manifests.len());
    for manifest in manifests {
        match apply_one(client, default_namespace, manifest).await {
            Ok(reference) => {
                metrics::apply(&reference.kind, "ok");
                applied.push(reference);
            }
            Err(err) => {
                let kind = manifest.kind.as_str();
                metrics::apply(kind, "err");
                return Err(err);
            }
        }
    }
    Ok(applied)
}

async fn apply_one(
    client: &Client,
    default_namespace: &str,
    manifest: &RenderedManifest,
) -> Result<AppliedRef, OperatorError> {
    // The renderer produces a `serde_json::Value` per manifest. We
    // pass it directly to server-side apply (no YAML round-trip
    // needed) — the API server accepts either YAML or JSON on the
    // apply path, and JSON keeps the value tree exactly as the
    // renderer produced it.
    let value: JsonValue = manifest.manifest.clone();

    let api_version = value
        .get("apiVersion")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| OperatorError::Apply {
            kind: manifest.kind.clone(),
            name: manifest.name.clone(),
            reason: "manifest missing `apiVersion`".into(),
        })?
        .to_string();
    let kind = value
        .get("kind")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| OperatorError::Apply {
            kind: manifest.kind.clone(),
            name: manifest.name.clone(),
            reason: "manifest missing `kind`".into(),
        })?
        .to_string();
    let name = value
        .pointer("/metadata/name")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| OperatorError::Apply {
            kind: manifest.kind.clone(),
            name: manifest.name.clone(),
            reason: "manifest missing `metadata.name`".into(),
        })?
        .to_string();
    let namespace = value
        .pointer("/metadata/namespace")
        .and_then(JsonValue::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| default_namespace.to_string());

    let gvk = parse_gvk(&api_version, &kind)?;
    let plural = pluralize(&kind);
    let ar = ApiResource {
        group: gvk.group.clone(),
        version: gvk.version.clone(),
        api_version: api_version.clone(),
        kind: gvk.kind.clone(),
        plural,
    };
    let api: Api<DynamicObject> = if is_cluster_scoped(&kind) {
        Api::all_with(client.clone(), &ar)
    } else {
        Api::namespaced_with(client.clone(), &namespace, &ar)
    };

    let patch = Patch::Apply(value);
    let pp = PatchParams::apply(FIELD_MANAGER).force();

    let applied = api
        .patch(&name, &pp, &patch)
        .await
        .map_err(|e| OperatorError::Apply {
            kind: kind.clone(),
            name: name.clone(),
            reason: format!("server-side apply: {e}"),
        })?;

    // Sanity-check the response. server-side apply echoes the object
    // back; we only need the name + namespace from `applied` to know
    // which row to record in the event log.
    let recorded_name = applied.name_any();
    let recorded_ns = applied.namespace();

    // Prefer the server's echoed name (it's the canonical form),
    // but fall back to the manifest's name if the response was empty
    // — defensive against a stripped-down API response in older
    // Kubernetes versions.
    let final_name = if recorded_name.is_empty() {
        name
    } else {
        recorded_name
    };
    Ok(AppliedRef {
        api_version,
        kind,
        name: final_name,
        namespace: recorded_ns.or(Some(namespace)),
    })
}

fn parse_gvk(api_version: &str, kind: &str) -> Result<GroupVersionKind, OperatorError> {
    let (group, version) = match api_version.split_once('/') {
        Some((g, v)) => (g.to_string(), v.to_string()),
        None => (String::new(), api_version.to_string()),
    };
    Ok(GroupVersionKind {
        group,
        version,
        kind: kind.to_string(),
    })
}

/// Heuristic pluralisation. The renderer only emits a small, known set
/// of kinds; if a new kind shows up we fall back to lowercasing + `s`
/// which is correct for everything we've ever emitted. A
/// `kube::discovery::Discovery` round-trip would be more robust but
/// costs an extra API call per reconcile — not worth it for the static
/// set the renderer produces today.
fn pluralize(kind: &str) -> String {
    static OVERRIDES: &[(&str, &str)] = &[
        ("Service", "services"),
        ("ConfigMap", "configmaps"),
        ("StatefulSet", "statefulsets"),
        ("Secret", "secrets"),
        ("ServiceAccount", "serviceaccounts"),
        ("PersistentVolumeClaim", "persistentvolumeclaims"),
        ("Certificate", "certificates"),
        ("Ingress", "ingresses"),
        ("NetworkPolicy", "networkpolicies"),
        ("PodDisruptionBudget", "poddisruptionbudgets"),
        ("HorizontalPodAutoscaler", "horizontalpodautoscalers"),
    ];
    OVERRIDES
        .iter()
        .find(|(k, _)| *k == kind)
        .map(|(_, p)| (*p).to_string())
        .unwrap_or_else(|| format!("{}s", kind.to_ascii_lowercase()))
}

/// Returns true for kinds the operator might apply that live at the
/// cluster scope. The renderer doesn't emit any of these today (every
/// owned object is namespace-scoped), but the check is forward-looking
/// so a `ClusterRole`-like addition fails fast at apply time rather
/// than 404ing.
fn is_cluster_scoped(kind: &str) -> bool {
    matches!(
        kind,
        "ClusterRole"
            | "ClusterRoleBinding"
            | "Namespace"
            | "Node"
            | "StorageClass"
            | "PersistentVolume"
            | "CustomResourceDefinition"
    )
}

/// Build an owner reference back-pointer for any child object. The
/// renderer already attaches owner references, but the controller
/// re-asserts the same shape on every apply so a manually-edited child
/// object doesn't drift out of the cascade-delete chain.
pub fn owner_reference(
    api_version: &str,
    kind: &str,
    name: &str,
    uid: &str,
) -> BTreeMap<String, JsonValue> {
    let mut m = BTreeMap::new();
    let _ = m.insert(
        "apiVersion".to_string(),
        JsonValue::String(api_version.to_string()),
    );
    let _ = m.insert("kind".to_string(), JsonValue::String(kind.to_string()));
    let _ = m.insert("name".to_string(), JsonValue::String(name.to_string()));
    let _ = m.insert("uid".to_string(), JsonValue::String(uid.to_string()));
    let _ = m.insert("controller".to_string(), JsonValue::Bool(true));
    let _ = m.insert("blockOwnerDeletion".to_string(), JsonValue::Bool(true));
    m
}

/// Synthesize a `TypeMeta` for the kube DynamicObject API surface.
/// Public so tests can assert the apply path uses the right TypeMeta.
#[must_use]
pub fn type_meta(api_version: &str, kind: &str) -> TypeMeta {
    TypeMeta {
        api_version: api_version.to_string(),
        kind: kind.to_string(),
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_gvk_with_group_and_version() {
        let g = parse_gvk("apps/v1", "StatefulSet").unwrap();
        assert_eq!(g.group, "apps");
        assert_eq!(g.version, "v1");
        assert_eq!(g.kind, "StatefulSet");
    }

    #[test]
    fn parse_gvk_core_v1_has_empty_group() {
        let g = parse_gvk("v1", "Service").unwrap();
        assert_eq!(g.group, "");
        assert_eq!(g.version, "v1");
    }

    #[test]
    fn pluralize_known_kinds() {
        assert_eq!(pluralize("StatefulSet"), "statefulsets");
        assert_eq!(pluralize("Service"), "services");
        assert_eq!(pluralize("Ingress"), "ingresses");
        assert_eq!(pluralize("NetworkPolicy"), "networkpolicies");
    }

    #[test]
    fn pluralize_fallback_for_unknown_kind() {
        assert_eq!(pluralize("Widget"), "widgets");
    }

    #[test]
    fn cluster_scoped_returns_true_for_clusterrole() {
        assert!(is_cluster_scoped("ClusterRole"));
        assert!(is_cluster_scoped("Namespace"));
        assert!(!is_cluster_scoped("Service"));
        assert!(!is_cluster_scoped("StatefulSet"));
    }

    #[test]
    fn owner_reference_carries_controller_flag() {
        let r = owner_reference("rustgate.io/v1alpha1", "RustgateCluster", "mc", "uid-123");
        assert_eq!(r["controller"], JsonValue::Bool(true));
        assert_eq!(r["blockOwnerDeletion"], JsonValue::Bool(true));
        assert_eq!(r["name"], JsonValue::String("mc".into()));
    }
}
