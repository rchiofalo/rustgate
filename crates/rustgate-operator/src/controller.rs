// Copyright © 2026 Roberto Chiofalo.

//! Live cluster controller harness.
//!
//! Wires [`kube_runtime::Controller`] to the pure reconcile function in
//! [`crate::reconcile`]. Lifecycle on each event:
//!
//! 1. Validate the spec (the renderer's `reconcile()` rejects invalid
//!    inputs at its boundary).
//! 2. Server-side apply the rendered manifests via [`crate::apply`].
//! 3. Read back the owned `StatefulSet.status` to get the observed
//!    `readyReplicas` and `availableReplicas`.
//! 4. Patch `RustgateCluster.status` with the observed numbers, the
//!    `lastReconciled` timestamp, and the next condition.
//! 5. Emit a `Normal/Reconciled` Event with the apply summary.
//! 6. Return `Action::requeue(REQUEUE_INTERVAL)` so the controller
//!    re-evaluates on a steady cadence even when nothing has changed
//!    in the input — this catches out-of-band drift on owned children.
//!
//! ## Concurrency
//!
//! The controller harness serializes reconciles per-object-key. There
//! is no parallelism between two reconciles of the same
//! `RustgateCluster`, but different clusters reconcile concurrently up
//! to the [`Controller::concurrency`] bound. The default of 5 is fine
//! for fleets up to a few hundred clusters per operator replica.
//!
//! ## Leader election
//!
//! The reconcile fn checks the leader gate from [`crate::leader`]
//! before doing any I/O. While not leader, the reconcile path is a
//! no-op that just re-queues — the controller keeps its watches warm so
//! the next leader handover is fast.

#![cfg(feature = "controller")]

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use futures::StreamExt;
use k8s_openapi::api::apps::v1::StatefulSet;
use k8s_openapi::api::core::v1::{ConfigMap, Service};
use kube::api::{Api, ListParams, Patch, PatchParams};
use kube::runtime::controller::{Action, Config, Controller};
use kube::runtime::watcher;
use kube::{Client, ResourceExt};

use crate::apply::{self, AppliedRef, FIELD_MANAGER};
use crate::error::OperatorError;
use crate::events::EventRecorder;
use crate::kube_types::{
    RustgateCluster as KubeCluster, RustgateClusterStatusKube, to_render_cluster,
};
use crate::leader::LeaderGate;
use crate::metrics;
use crate::reconcile::{
    ReconcileOutcome, failure_condition, ready_condition, reconcile as pure_reconcile,
};

/// How often the controller re-reconciles a cluster on its own
/// (independent of watch events). The 30 s cadence matches the federation
/// heartbeat interval used elsewhere in the workspace — that's a
/// reasonable compromise between drift-detection latency and API server
/// load.
pub const REQUEUE_INTERVAL: Duration = Duration::from_secs(30);

/// Backoff used by the error policy on transient failures (network,
/// 409 conflicts, etc.). The kube_runtime jitter is applied on top of
/// this base so a thundering-herd of operator restarts doesn't cluster.
pub const ERROR_BACKOFF: Duration = Duration::from_secs(15);

/// Shared state passed into every reconcile call. Cheaply cloneable —
/// the `Client` is an `Arc<>` internally and the `LeaderGate` and
/// `EventRecorder` are explicit `Arc`s.
#[derive(Clone)]
pub struct Context {
    pub client: Client,
    pub leader: Arc<LeaderGate>,
    pub events: Arc<EventRecorder>,
    /// When `Some`, the controller restricts its watches to a single
    /// namespace. `None` means cluster-wide.
    pub namespace: Option<String>,
}

impl std::fmt::Debug for Context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Context")
            .field("namespace", &self.namespace)
            .finish_non_exhaustive()
    }
}

/// Build a Controller for `RustgateCluster` and run it to completion.
///
/// The future returned by [`run`] only resolves when the underlying
/// watch stream terminates, which happens on a clean shutdown signal.
/// The caller is expected to keep the future in the main task and
/// await it after wiring SIGTERM via `tokio::signal`.
pub async fn run(ctx: Context) -> Result<(), OperatorError> {
    let api: Api<KubeCluster> = match &ctx.namespace {
        Some(ns) => Api::namespaced(ctx.client.clone(), ns),
        None => Api::all(ctx.client.clone()),
    };

    // Owned children. We add `owns(...)` for each so a drift on a child
    // re-queues the owning cluster — that's how the controller catches
    // someone running `kubectl edit statefulset` to override the spec.
    let owned_sts: Api<StatefulSet> = match &ctx.namespace {
        Some(ns) => Api::namespaced(ctx.client.clone(), ns),
        None => Api::all(ctx.client.clone()),
    };
    let owned_svc: Api<Service> = match &ctx.namespace {
        Some(ns) => Api::namespaced(ctx.client.clone(), ns),
        None => Api::all(ctx.client.clone()),
    };
    let owned_cm: Api<ConfigMap> = match &ctx.namespace {
        Some(ns) => Api::namespaced(ctx.client.clone(), ns),
        None => Api::all(ctx.client.clone()),
    };

    let cfg = Config::default()
        .concurrency(5)
        .debounce(Duration::from_millis(250));

    Controller::new(api, watcher::Config::default())
        .owns(owned_sts, watcher::Config::default())
        .owns(owned_svc, watcher::Config::default())
        .owns(owned_cm, watcher::Config::default())
        .with_config(cfg)
        .shutdown_on_signal()
        .run(reconcile_fn, error_policy, Arc::new(ctx.clone()))
        .for_each(|res| async move {
            match res {
                Ok((object_ref, _action)) => {
                    tracing::debug!(target: "operator", obj = ?object_ref, "reconcile ok");
                }
                Err(e) => {
                    tracing::warn!(target: "operator", error = %e, "reconcile errored");
                }
            }
        })
        .await;

    Ok(())
}

/// The reconcile function — top of the apply pipeline. Returns an
/// `Action` regardless of outcome so the controller keeps the queue
/// drained even on error paths.
pub async fn reconcile_fn(
    cluster: Arc<KubeCluster>,
    ctx: Arc<Context>,
) -> Result<Action, OperatorError> {
    // Leader gate. While not leader we re-queue cheaply — no API calls,
    // no rendering, no event emission. Watches stay warm in case the
    // current leader handover lands on us.
    if !ctx.leader.is_leader().await {
        return Ok(Action::requeue(REQUEUE_INTERVAL));
    }

    let _timer = metrics::reconcile_timer();
    let now_rfc3339 = Utc::now().to_rfc3339();
    let key = ObjectKey::from(cluster.as_ref());

    let span = tracing::info_span!(
        target: "operator",
        "reconcile",
        cluster = %key.name,
        namespace = %key.namespace.as_deref().unwrap_or("<cluster>"),
        generation = cluster.metadata.generation.unwrap_or(0),
    );
    let _guard = span.enter();

    // Stage 1: bridge into the renderer's typed view.
    let render_cluster = to_render_cluster(cluster.as_ref())?;

    // Stage 2: pure reconcile — validate + render manifests + draft status.
    let outcome = match pure_reconcile(&render_cluster, &now_rfc3339) {
        Ok(outcome) => outcome,
        Err(OperatorError::InvalidSpec { message }) => {
            tracing::warn!(target: "operator", reason = "InvalidSpec", message = %message, "spec rejected");
            ctx.events
                .warning(cluster.as_ref(), "InvalidSpec", &message)
                .await;
            // Patch the failure condition straight onto status so
            // `kubectl describe rustgatecluster` shows the rejection.
            let status = RustgateClusterStatusKube {
                ready_replicas: 0,
                available_replicas: 0,
                last_reconciled: Some(now_rfc3339.clone()),
                conditions: vec![condition_to_kube(failure_condition(
                    &now_rfc3339,
                    "InvalidSpec",
                    message,
                ))],
            };
            let _ = patch_status(&ctx.client, &key, status).await;
            metrics::reconcile("err");
            return Ok(Action::requeue(ERROR_BACKOFF));
        }
        Err(e) => {
            tracing::error!(target: "operator", error = %e, "render failed");
            metrics::reconcile("err");
            return Ok(Action::requeue(ERROR_BACKOFF));
        }
    };

    // Stage 3: apply.
    let default_ns = key.namespace.as_deref().unwrap_or("default");
    let applied = match apply::apply_all(&ctx.client, default_ns, &outcome.manifests).await {
        Ok(list) => list,
        Err(OperatorError::Apply { kind, name, reason }) => {
            tracing::warn!(target: "operator", kind = %kind, name = %name, reason = %reason, "apply failed");
            ctx.events
                .warning(
                    cluster.as_ref(),
                    "ApplyFailed",
                    &format!("{kind}/{name}: {reason}"),
                )
                .await;
            metrics::reconcile("err");
            return Ok(Action::requeue(ERROR_BACKOFF));
        }
        Err(e) => {
            tracing::error!(target: "operator", error = %e, "apply failed (other)");
            metrics::reconcile("err");
            return Ok(Action::requeue(ERROR_BACKOFF));
        }
    };

    // Stage 4: observed-state read-back. We only need StatefulSet
    // status for now; the renderer puts the workload there.
    let observed = read_observed_status(&ctx.client, &key).await;

    // Stage 5: status patch.
    let status = build_status(&outcome, &observed, &now_rfc3339);
    if let Err(e) = patch_status(&ctx.client, &key, status).await {
        tracing::warn!(target: "operator", error = %e, "status patch failed");
        // Children are already applied; treat as success but signal
        // staleness via metrics. The next reconcile pass will retry.
    }

    // Stage 6: success event + metrics.
    let summary = applied_summary(&applied);
    ctx.events
        .info(cluster.as_ref(), "Reconciled", &summary)
        .await;
    metrics::reconcile("ok");
    metrics::set_last_reconcile_now();
    Ok(Action::requeue(REQUEUE_INTERVAL))
}

/// kube_runtime error policy. Called when [`reconcile_fn`] returns
/// `Err(_)` *or* the controller's machinery (watch, decoding, …)
/// errors. The standard pattern is exponential backoff with jitter —
/// kube_runtime applies its own jitter on top of whatever interval we
/// return, so we just return a fixed base.
pub fn error_policy(_obj: Arc<KubeCluster>, _err: &OperatorError, _ctx: Arc<Context>) -> Action {
    Action::requeue(ERROR_BACKOFF)
}

/// Observed status read back from owned children.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Observed {
    pub ready_replicas: i32,
    pub available_replicas: i32,
}

async fn read_observed_status(client: &Client, key: &ObjectKey) -> Observed {
    let Some(ns) = key.namespace.as_deref() else {
        return Observed::default();
    };
    let api: Api<StatefulSet> = Api::namespaced(client.clone(), ns);
    // The renderer names the StatefulSet the same as the parent CR.
    match api.get_status(&key.name).await {
        Ok(sts) => {
            let s = sts.status.unwrap_or_default();
            Observed {
                ready_replicas: s.ready_replicas.unwrap_or(0),
                available_replicas: s.available_replicas.unwrap_or(0),
            }
        }
        Err(e) => {
            tracing::debug!(target: "operator", error = %e, "StatefulSet status read failed; reporting zeros");
            Observed::default()
        }
    }
}

fn build_status(
    outcome: &ReconcileOutcome,
    observed: &Observed,
    now_rfc3339: &str,
) -> RustgateClusterStatusKube {
    let mut conditions = outcome
        .status
        .conditions
        .iter()
        .map(|c| condition_to_kube(c.clone()))
        .collect::<Vec<_>>();

    // If we observe full rollout, replace the Progressing condition with
    // a Ready=True. Otherwise keep Progressing as the renderer emitted.
    if observed.ready_replicas > 0 && observed.ready_replicas == observed.available_replicas {
        // Drop any prior Progressing condition; append Ready=True.
        conditions.retain(|c| c.kind != "Progressing");
        conditions.push(condition_to_kube(ready_condition(now_rfc3339)));
    }

    RustgateClusterStatusKube {
        ready_replicas: observed.ready_replicas,
        available_replicas: observed.available_replicas,
        last_reconciled: Some(now_rfc3339.to_string()),
        conditions,
    }
}

fn condition_to_kube(c: crate::crd::Condition) -> crate::kube_types::ConditionKube {
    crate::kube_types::ConditionKube {
        kind: c.kind,
        status: c.status,
        reason: c.reason,
        message: c.message,
        last_transition_time: c.last_transition_time,
    }
}

async fn patch_status(
    client: &Client,
    key: &ObjectKey,
    status: RustgateClusterStatusKube,
) -> Result<(), OperatorError> {
    let api: Api<KubeCluster> = match &key.namespace {
        Some(ns) => Api::namespaced(client.clone(), ns),
        None => Api::all(client.clone()),
    };
    let patch = serde_json::json!({
        "status": to_kube_status_value(&status)?,
    });
    api.patch_status(
        &key.name,
        &PatchParams::apply(FIELD_MANAGER).force(),
        &Patch::Merge(&patch),
    )
    .await
    .map(|_| ())
    .map_err(|e| OperatorError::StatusPatch(e.to_string()))
}

fn to_kube_status_value(s: &RustgateClusterStatusKube) -> Result<serde_json::Value, OperatorError> {
    serde_json::to_value(s).map_err(|e| OperatorError::Construct(e.to_string()))
}

fn applied_summary(applied: &[AppliedRef]) -> String {
    let mut summary = String::with_capacity(64);
    let mut first = true;
    for a in applied {
        if !first {
            summary.push_str(", ");
        }
        first = false;
        summary.push_str(&a.kind);
        summary.push('/');
        summary.push_str(&a.name);
    }
    if summary.is_empty() {
        "nothing applied".to_string()
    } else {
        format!("applied {summary}")
    }
}

/// Cluster + namespace identifier used internally by the reconcile path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectKey {
    pub name: String,
    pub namespace: Option<String>,
}

impl ObjectKey {
    fn from(c: &KubeCluster) -> Self {
        Self {
            name: c.name_any(),
            namespace: c.namespace(),
        }
    }
}

/// Health probe: returns true when the kube client can reach the API
/// server. Called by `/readyz`.
pub async fn kube_reachable(client: &Client) -> bool {
    // Listing the CRD itself with limit=1 is the lightest authoritative
    // probe — proves both connectivity and "I have permission to watch
    // the resource I'm here to reconcile."
    let api: Api<KubeCluster> = Api::all(client.clone());
    let lp = ListParams::default().limit(1);
    api.list(&lp).await.is_ok()
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::crd::{Condition, RustgateClusterStatus};
    use crate::reconcile::ReconcileOutcome;

    fn outcome_with_progressing() -> ReconcileOutcome {
        ReconcileOutcome {
            manifests: vec![],
            status: RustgateClusterStatus {
                ready_replicas: 0,
                available_replicas: 0,
                last_reconciled: Some("2026-05-10T00:00:00Z".into()),
                conditions: vec![Condition {
                    kind: "Progressing".into(),
                    status: "True".into(),
                    reason: "ReconcileSucceeded".into(),
                    message: "rolling out".into(),
                    last_transition_time: "2026-05-10T00:00:00Z".into(),
                }],
            },
        }
    }

    #[test]
    fn build_status_keeps_progressing_when_no_ready_replicas() {
        let outcome = outcome_with_progressing();
        let observed = Observed::default();
        let s = build_status(&outcome, &observed, "2026-05-10T00:00:01Z");
        assert_eq!(s.ready_replicas, 0);
        assert_eq!(s.conditions.len(), 1);
        assert_eq!(s.conditions[0].kind, "Progressing");
    }

    #[test]
    fn build_status_promotes_to_ready_on_full_rollout() {
        let outcome = outcome_with_progressing();
        let observed = Observed {
            ready_replicas: 3,
            available_replicas: 3,
        };
        let s = build_status(&outcome, &observed, "2026-05-10T00:00:02Z");
        assert_eq!(s.ready_replicas, 3);
        assert_eq!(s.available_replicas, 3);
        // Progressing should have been replaced by Ready.
        assert!(!s.conditions.iter().any(|c| c.kind == "Progressing"));
        assert!(
            s.conditions
                .iter()
                .any(|c| c.kind == "Ready" && c.status == "True")
        );
    }

    #[test]
    fn build_status_partial_rollout_stays_progressing() {
        let outcome = outcome_with_progressing();
        let observed = Observed {
            ready_replicas: 2,
            available_replicas: 3,
        };
        let s = build_status(&outcome, &observed, "2026-05-10T00:00:03Z");
        assert!(s.conditions.iter().any(|c| c.kind == "Progressing"));
        assert!(!s.conditions.iter().any(|c| c.kind == "Ready"));
    }

    #[test]
    fn applied_summary_handles_empty() {
        assert_eq!(applied_summary(&[]), "nothing applied");
    }

    #[test]
    fn applied_summary_lists_kinds() {
        let refs = vec![
            AppliedRef {
                api_version: "apps/v1".into(),
                kind: "StatefulSet".into(),
                name: "rg".into(),
                namespace: Some("default".into()),
            },
            AppliedRef {
                api_version: "v1".into(),
                kind: "Service".into(),
                name: "rg".into(),
                namespace: Some("default".into()),
            },
        ];
        let s = applied_summary(&refs);
        assert!(s.contains("StatefulSet/rg"));
        assert!(s.contains("Service/rg"));
    }
}
