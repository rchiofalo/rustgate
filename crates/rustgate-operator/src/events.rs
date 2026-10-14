// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Kubernetes Event emission via [`kube::runtime::events::Recorder`].
//!
//! Each reconcile pass emits one Event so `kubectl describe
//! rustgatecluster <name>` shows recent progress, errors, and apply
//! summaries. The Recorder dedupes Events with the same
//! `(involvedObject, action, reason, message)` and bumps `count` /
//! `lastTimestamp` instead of creating duplicates, which keeps Event
//! cardinality bounded on long-running operators.
//!
//! ## Reasons we emit
//!
//! | Type | Reason | When |
//! |---|---|---|
//! | `Normal` | `Reconciled` | Apply succeeded; carries the kind/name summary |
//! | `Warning` | `InvalidSpec` | Spec failed validation |
//! | `Warning` | `ApplyFailed` | Server-side apply returned non-2xx |
//! | `Warning` | `StatusPatchFailed` | Status patch returned non-2xx (rare) |
//! | `Warning` | `LeaderLost` | Lease was held but renewal failed |

#![cfg(feature = "controller")]

use std::sync::Arc;

use kube::runtime::events::{Event, EventType, Recorder, Reporter};
use kube::{Client, Resource};

use crate::kube_types::RustgateCluster as KubeCluster;

/// Reporter identity baked into every Event. The Kubernetes Event
/// schema requires both `reportingController` and `reportingInstance`
/// fields on the `events.k8s.io/v1` API.
pub fn reporter() -> Reporter {
    Reporter {
        controller: "rustgate-operator".into(),
        instance: Some(
            std::env::var("HOSTNAME").unwrap_or_else(|_| "rustgate-operator".to_string()),
        ),
    }
}

/// Wraps the kube Recorder in a small, easily-testable surface so the
/// reconcile path doesn't take a direct dependency on the kube API.
pub struct EventRecorder {
    inner: Recorder,
}

impl EventRecorder {
    pub fn new(client: Client) -> Arc<Self> {
        Arc::new(Self {
            inner: Recorder::new(client, reporter()),
        })
    }

    /// Emit a `Normal` Event on the given cluster.
    pub async fn info(&self, cluster: &KubeCluster, reason: &str, message: &str) {
        self.publish(cluster, EventType::Normal, reason, message)
            .await;
    }

    /// Emit a `Warning` Event on the given cluster.
    pub async fn warning(&self, cluster: &KubeCluster, reason: &str, message: &str) {
        self.publish(cluster, EventType::Warning, reason, message)
            .await;
    }

    async fn publish(&self, cluster: &KubeCluster, ty: EventType, reason: &str, message: &str) {
        let ev = Event {
            type_: ty,
            reason: reason.to_string(),
            note: Some(message.to_string()),
            action: "Reconcile".into(),
            secondary: None,
        };
        if let Err(e) = self.inner.publish(&ev, &cluster.object_ref(&())).await {
            // We tolerate Event publish failures — they're observability,
            // not correctness. Surface as a debug log; metrics already
            // captured the underlying reconcile outcome.
            tracing::debug!(target: "operator", error = %e, "Event publish failed");
        }
    }
}

impl std::fmt::Debug for EventRecorder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventRecorder").finish_non_exhaustive()
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn reporter_uses_static_controller_name() {
        let r = reporter();
        assert_eq!(r.controller, "rustgate-operator");
        // Instance is HOSTNAME-derived; in CI the variable may or may
        // not be set, but the value must always be Some(_) so the
        // events.k8s.io/v1 server-side validation accepts the Event.
        assert!(r.instance.is_some());
    }
}
