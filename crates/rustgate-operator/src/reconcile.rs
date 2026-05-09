// Copyright © 2026 Roberto Chiofalo.

//! Reconcile loop.
//!
//! The MVP reconcile path is a pure rendering step: take a
//! [`RustgateCluster`], validate it, produce the manifests it owns
//! ([`crate::render::render_all`]), and return a [`ReconcileOutcome`]
//! describing the next-step actions.
//!
//! The live cluster controller (which would call the Kubernetes API to
//! apply, observe, and update status) is documented as a deferred
//! follow-up: the renderer is the source of truth for *what* gets created,
//! and the apply-loop is mechanical glue that can be implemented with
//! `kube-rs` (or `kubectl apply` in a sidecar) without changing the
//! contract here.
//!
//! ## Lifecycle outline (target controller behaviour)
//!
//! On `Added`/`Modified`:
//!   1. Validate the spec via [`RustgateCluster::validate`].
//!   2. Compute the desired manifests via [`crate::render::render_all`].
//!   3. Server-side apply each manifest with the operator's field manager.
//!   4. Read back the StatefulSet's `.status.readyReplicas` and update
//!      the parent `.status.readyReplicas`, `.status.availableReplicas`,
//!      `.status.lastReconciled`, `.status.conditions[*]`.
//!
//! On `Deleted`: the owner-reference chain ([`crate::render`]) ensures
//! the API server cascade-deletes every child object, so the operator
//! does not need an explicit Delete branch.
//!
//! ## Update semantics
//!
//! StatefulSet updates inherit the rolling-update semantics from
//! `kubernetes/apps/v1`: pods are recreated one at a time when the
//! `template.spec` changes. The default `terminationGracePeriodSeconds`
//! of 30s on the rendered template provides headroom for the rustgate
//! `SubsystemHandle` 5s drain budget plus the standard 5s preStop sleep.

use crate::crd::{Condition, RustgateCluster, RustgateClusterStatus};
use crate::error::Result;
use crate::render::{RenderedManifest, render_all};

/// Outcome of a single reconcile pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcileOutcome {
    /// Manifests the controller should server-side apply (in order). Each
    /// entry is a fully-rendered, unmodified manifest the controller can
    /// hand directly to its apply primitive.
    pub manifests: Vec<RenderedManifest>,
    /// Status patch to write back to the parent `RustgateCluster`.
    pub status: RustgateClusterStatus,
}

/// Run a single reconcile pass for the given cluster.
///
/// `now_rfc3339` is the wall-clock timestamp string to record on the
/// status (`lastReconciled` and `conditions[*].lastTransitionTime`). The
/// caller is responsible for producing a stable RFC 3339 timestamp; the
/// reconcile path itself does not call `SystemTime::now()` so the function
/// is fully deterministic and snapshot-testable.
pub fn reconcile(cluster: &RustgateCluster, now_rfc3339: &str) -> Result<ReconcileOutcome> {
    let manifests = render_all(cluster)?;

    // Compute the *desired* status. The operator does not yet read back
    // the live StatefulSet status here — the controller wrapper does that
    // after the apply step. The reconcile contract returns a "desired
    // shape" that the controller fills in with observed-state numbers.
    let status = RustgateClusterStatus {
        ready_replicas: 0,
        available_replicas: 0,
        last_reconciled: Some(now_rfc3339.to_string()),
        conditions: vec![Condition {
            kind: "Progressing".to_string(),
            status: "True".to_string(),
            reason: "ReconcileSucceeded".to_string(),
            message: "Manifests rendered; awaiting StatefulSet rollout".to_string(),
            last_transition_time: now_rfc3339.to_string(),
        }],
    };

    Ok(ReconcileOutcome { manifests, status })
}

/// Build the terminal `Ready=True` condition for a fully-rolled-out
/// cluster. The controller calls this once `observed_ready == spec.replicas`.
pub fn ready_condition(now_rfc3339: &str) -> Condition {
    Condition {
        kind: "Ready".to_string(),
        status: "True".to_string(),
        reason: "AllReplicasReady".to_string(),
        message: "All replicas are ready and serving traffic".to_string(),
        last_transition_time: now_rfc3339.to_string(),
    }
}

/// Build the failure condition for a rejected reconcile attempt.
///
/// Surface as `Ready=False` with a machine-readable reason so the operator
/// console can group failures by class.
pub fn failure_condition(now_rfc3339: &str, reason: &str, message: impl Into<String>) -> Condition {
    Condition {
        kind: "Ready".to_string(),
        status: "False".to_string(),
        reason: reason.to_string(),
        message: message.into(),
        last_transition_time: now_rfc3339.to_string(),
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn fixture_cluster() -> RustgateCluster {
        let mut c = RustgateCluster::new("my-cluster", "rustgate");
        c.spec.replicas = 3;
        c
    }

    #[test]
    fn reconcile_returns_manifests_for_valid_spec() {
        let cluster = fixture_cluster();
        let outcome = reconcile(&cluster, "2026-05-08T12:00:00Z").unwrap();
        // Service x2, ConfigMap, StatefulSet (no certManager).
        assert_eq!(outcome.manifests.len(), 4);
        assert_eq!(
            outcome.status.last_reconciled.as_deref(),
            Some("2026-05-08T12:00:00Z")
        );
        assert_eq!(outcome.status.conditions.len(), 1);
        assert_eq!(outcome.status.conditions[0].kind, "Progressing");
    }

    #[test]
    fn reconcile_rejects_invalid_spec() {
        let mut cluster = fixture_cluster();
        cluster.spec.replicas = 0;
        let result = reconcile(&cluster, "2026-05-08T12:00:00Z");
        assert!(result.is_err());
    }

    #[test]
    fn ready_condition_has_expected_shape() {
        let c = ready_condition("2026-05-08T12:00:00Z");
        assert_eq!(c.kind, "Ready");
        assert_eq!(c.status, "True");
        assert_eq!(c.reason, "AllReplicasReady");
    }

    #[test]
    fn failure_condition_carries_reason_and_message() {
        let c = failure_condition(
            "2026-05-08T12:00:00Z",
            "InvalidSpec",
            "spec.replicas must be >= 1",
        );
        assert_eq!(c.kind, "Ready");
        assert_eq!(c.status, "False");
        assert_eq!(c.reason, "InvalidSpec");
        assert!(c.message.contains("replicas"));
    }
}
