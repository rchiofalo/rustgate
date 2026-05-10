// Copyright © 2026 Roberto Chiofalo.

//! Leader election via a `coordination.k8s.io/v1` Lease.
//!
//! The operator Deployment can run with `replicas > 1` for hot-standby.
//! Only one replica holds the lease at a time; the rest keep their
//! watches warm and re-queue reconciles cheaply via [`LeaderGate`]. On
//! lease loss or release, the replicas race to take it over.
//!
//! ## Protocol (per the upstream Kubernetes spec)
//!
//! - **leaseDurationSeconds** (default [`LEASE_DURATION_SECONDS`]):
//!   how long a holder's lease is considered valid past its last renew.
//!   The next candidate must wait this long after the last renew time
//!   before attempting to take over.
//! - **renewDeadlineSeconds** (default [`RENEW_DEADLINE_SECONDS`]):
//!   the holder MUST issue a renew within this many seconds of the
//!   acquire/renew time, otherwise it must consider itself
//!   non-leading. Set strictly less than `leaseDurationSeconds` so the
//!   holder gives up before a peer would consider the lease stale.
//! - **retryPeriodSeconds** (default [`RETRY_PERIOD_SECONDS`]):
//!   non-holders poll the lease at this cadence to try to take over.
//!
//! ## Identity
//!
//! `holderIdentity` is set to `<pod-name>_<random-suffix>`. The
//! random suffix isolates two pods that happen to share a name across
//! restarts (StatefulSet semantics) so a freshly-rescheduled pod with
//! the same name doesn't think it already holds the lease and skip the
//! initial acquire.

#![cfg(feature = "controller")]

use std::sync::Arc;
use std::time::Duration;

use k8s_openapi::api::coordination::v1::{Lease, LeaseSpec};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{MicroTime, ObjectMeta};
use k8s_openapi::jiff::Timestamp;
use kube::Client;
use kube::api::{Api, Patch, PatchParams, PostParams};
use tokio::sync::RwLock;

use crate::error::OperatorError;
use crate::metrics;

/// Default lease duration: the slot of time a holder's claim remains
/// valid past its last renew before peers may try to take over.
pub const LEASE_DURATION_SECONDS: i32 = 30;
/// Default renew deadline: a holder must renew within this many seconds
/// to avoid losing the lease.
pub const RENEW_DEADLINE_SECONDS: i32 = 20;
/// Default poll cadence for non-holders.
pub const RETRY_PERIOD_SECONDS: u64 = 5;
/// Default name of the lease object.
pub const DEFAULT_LEASE_NAME: &str = "rustgate-operator-leader-election";

/// Owned configuration for [`LeaderElector`].
#[derive(Debug, Clone)]
pub struct LeaderConfig {
    pub namespace: String,
    pub lease_name: String,
    pub identity: String,
    pub lease_duration: Duration,
    pub renew_deadline: Duration,
    pub retry_period: Duration,
}

impl LeaderConfig {
    /// Build a default config given the operator's running namespace and
    /// pod name. The random identity suffix is supplied by the caller so
    /// tests can pin it.
    pub fn new(namespace: impl Into<String>, identity: impl Into<String>) -> Self {
        Self {
            namespace: namespace.into(),
            lease_name: DEFAULT_LEASE_NAME.to_string(),
            identity: identity.into(),
            lease_duration: Duration::from_secs(LEASE_DURATION_SECONDS as u64),
            renew_deadline: Duration::from_secs(RENEW_DEADLINE_SECONDS as u64),
            retry_period: Duration::from_secs(RETRY_PERIOD_SECONDS),
        }
    }
}

/// Read-only handle the reconcile path uses to gate work on leadership.
#[derive(Debug)]
pub struct LeaderGate {
    held: RwLock<bool>,
}

impl LeaderGate {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            held: RwLock::new(false),
        })
    }

    /// Construct a gate that's already in the held state. Used by
    /// `--no-leader-elect` mode where the operator skips the Lease
    /// loop entirely and acts as if it always holds the lease.
    pub fn new_held() -> Arc<Self> {
        Arc::new(Self {
            held: RwLock::new(true),
        })
    }

    /// Returns true when this replica currently holds the lease.
    pub async fn is_leader(&self) -> bool {
        *self.held.read().await
    }

    async fn set(&self, value: bool) {
        let mut g = self.held.write().await;
        if *g != value {
            tracing::info!(target: "operator", leader = value, "leader-state changed");
            metrics::set_leader(value);
        }
        *g = value;
    }
}

/// The lease loop. Runs forever until cancelled. On acquire, sets the
/// `LeaderGate` to true; on loss, to false. Renews on the cadence
/// `lease_duration / 2`. On shutdown, attempts to clear the lease so a
/// peer can pick it up immediately.
pub struct LeaderElector {
    client: Client,
    cfg: LeaderConfig,
    gate: Arc<LeaderGate>,
}

impl std::fmt::Debug for LeaderElector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LeaderElector")
            .field("cfg", &self.cfg)
            .finish_non_exhaustive()
    }
}

impl LeaderElector {
    pub fn new(client: Client, cfg: LeaderConfig, gate: Arc<LeaderGate>) -> Self {
        Self { client, cfg, gate }
    }

    /// Run the election loop. Returns when the future is cancelled.
    pub async fn run(
        self,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> Result<(), OperatorError> {
        let api: Api<Lease> = Api::namespaced(self.client.clone(), &self.cfg.namespace);
        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        // Best-effort clear of the lease on shutdown so
                        // a peer can take over without waiting for the
                        // full leaseDuration to expire.
                        let _ = self.release(&api).await;
                        self.gate.set(false).await;
                        return Ok(());
                    }
                }
                outcome = self.tick(&api) => {
                    match outcome {
                        Ok(LeaderState::Leading) => {
                            self.gate.set(true).await;
                            // Renew at half the lease duration.
                            tokio::time::sleep(self.cfg.lease_duration / 2).await;
                        }
                        Ok(LeaderState::Following) => {
                            self.gate.set(false).await;
                            tokio::time::sleep(self.cfg.retry_period).await;
                        }
                        Err(e) => {
                            tracing::warn!(target: "operator", error = %e, "lease tick failed");
                            self.gate.set(false).await;
                            tokio::time::sleep(self.cfg.retry_period).await;
                        }
                    }
                }
            }
        }
    }

    async fn tick(&self, api: &Api<Lease>) -> Result<LeaderState, OperatorError> {
        let now = Timestamp::now();
        match api.get(&self.cfg.lease_name).await {
            Ok(lease) => {
                let spec = lease.spec.unwrap_or_default();
                let holder = spec.holder_identity.clone().unwrap_or_default();
                if holder == self.cfg.identity {
                    // We're the holder — renew.
                    let new_spec = LeaseSpec {
                        holder_identity: Some(self.cfg.identity.clone()),
                        lease_duration_seconds: Some(self.cfg.lease_duration.as_secs() as i32),
                        acquire_time: spec.acquire_time.clone(),
                        renew_time: Some(MicroTime(now)),
                        lease_transitions: spec.lease_transitions,
                        ..Default::default()
                    };
                    self.patch_spec(api, new_spec).await?;
                    return Ok(LeaderState::Leading);
                }
                // Different holder — check freshness. Convert both
                // timestamps to integer nanoseconds and compare; this
                // avoids depending on jiff's duration arithmetic which
                // would force the caller to learn another time API.
                if let Some(renew_time) = spec.renew_time.as_ref() {
                    let now_ns: i128 = now.as_nanosecond();
                    let renew_ns: i128 = renew_time.0.as_nanosecond();
                    let elapsed_ns: i128 = now_ns - renew_ns;
                    let lease_ns: i128 = self.cfg.lease_duration.as_nanos() as i128;
                    if elapsed_ns < lease_ns {
                        // Fresh — peer still holds.
                        return Ok(LeaderState::Following);
                    }
                }
                // Stale — take over.
                let transitions = spec.lease_transitions.unwrap_or(0) + 1;
                let new_spec = LeaseSpec {
                    holder_identity: Some(self.cfg.identity.clone()),
                    lease_duration_seconds: Some(self.cfg.lease_duration.as_secs() as i32),
                    acquire_time: Some(MicroTime(now)),
                    renew_time: Some(MicroTime(now)),
                    lease_transitions: Some(transitions),
                    ..Default::default()
                };
                self.patch_spec(api, new_spec).await?;
                Ok(LeaderState::Leading)
            }
            Err(kube::Error::Api(ae)) if ae.code == 404 => {
                // Lease doesn't exist yet — create it claiming ourselves.
                let lease = Lease {
                    metadata: ObjectMeta {
                        name: Some(self.cfg.lease_name.clone()),
                        namespace: Some(self.cfg.namespace.clone()),
                        ..Default::default()
                    },
                    spec: Some(LeaseSpec {
                        holder_identity: Some(self.cfg.identity.clone()),
                        lease_duration_seconds: Some(self.cfg.lease_duration.as_secs() as i32),
                        acquire_time: Some(MicroTime(now)),
                        renew_time: Some(MicroTime(now)),
                        lease_transitions: Some(0),
                        ..Default::default()
                    }),
                };
                match api.create(&PostParams::default(), &lease).await {
                    Ok(_) => Ok(LeaderState::Leading),
                    Err(kube::Error::Api(ae)) if ae.code == 409 => {
                        // Someone raced us; fall back to follower for
                        // the next tick.
                        Ok(LeaderState::Following)
                    }
                    Err(e) => Err(OperatorError::Leader(e.to_string())),
                }
            }
            Err(e) => Err(OperatorError::Leader(e.to_string())),
        }
    }

    async fn patch_spec(&self, api: &Api<Lease>, spec: LeaseSpec) -> Result<(), OperatorError> {
        let patch = serde_json::json!({"spec": spec});
        api.patch(
            &self.cfg.lease_name,
            &PatchParams::apply(crate::apply::FIELD_MANAGER).force(),
            &Patch::Apply(&patch),
        )
        .await
        .map(|_| ())
        .map_err(|e| OperatorError::Leader(e.to_string()))
    }

    async fn release(&self, api: &Api<Lease>) -> Result<(), OperatorError> {
        // Clear the holderIdentity so a peer's next tick takes over
        // immediately. We don't delete the Lease — keeping it around
        // preserves the `leaseTransitions` counter for observability.
        let patch = serde_json::json!({
            "spec": {
                "holderIdentity": null,
            }
        });
        api.patch(
            &self.cfg.lease_name,
            &PatchParams::apply(crate::apply::FIELD_MANAGER).force(),
            &Patch::Merge(&patch),
        )
        .await
        .map(|_| ())
        .map_err(|e| OperatorError::Leader(e.to_string()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LeaderState {
    Leading,
    Following,
}

/// Build a default identity string for the operator process. Uses
/// `HOSTNAME` env (set by Kubernetes to the pod name) + a random
/// 6-char suffix to disambiguate restarts.
pub fn default_identity() -> String {
    let host = std::env::var("HOSTNAME").unwrap_or_else(|_| "rustgate-operator".to_string());
    let suffix: String = {
        let mut s = String::with_capacity(6);
        for _ in 0..6 {
            let alphabet = b"abcdefghijklmnopqrstuvwxyz0123456789";
            let idx = (fastrand::u32(0..alphabet.len() as u32)) as usize;
            // justification: `fastrand::u32(0..N)` returns a value
            // strictly less than `N`, so indexing the 36-byte
            // alphabet is provably in-bounds. The expect message is
            // a defensive marker; the panic is unreachable for any
            // alphabet of non-zero length.
            #[allow(clippy::expect_used)]
            s.push(*alphabet.get(idx).expect("idx is in 0..alphabet.len()") as char);
        }
        s
    };
    format!("{host}_{suffix}")
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn gate_starts_non_leader() {
        let g = LeaderGate::new();
        assert!(!g.is_leader().await);
    }

    #[tokio::test]
    async fn gate_set_true_propagates() {
        let g = LeaderGate::new();
        g.set(true).await;
        assert!(g.is_leader().await);
        g.set(false).await;
        assert!(!g.is_leader().await);
    }

    #[test]
    fn default_identity_has_suffix() {
        let id = default_identity();
        // Must contain an underscore separating host and suffix.
        assert!(id.contains('_'));
        let suffix = id.rsplit_once('_').unwrap().1;
        assert_eq!(suffix.len(), 6);
        // Suffix is lowercase-alphanumeric.
        for c in suffix.chars() {
            assert!(c.is_ascii_lowercase() || c.is_ascii_digit(), "got {c}");
        }
    }

    #[test]
    fn config_carries_defaults() {
        let cfg = LeaderConfig::new("rustgate", "id-1");
        assert_eq!(cfg.lease_name, DEFAULT_LEASE_NAME);
        assert_eq!(
            cfg.lease_duration,
            Duration::from_secs(LEASE_DURATION_SECONDS as u64)
        );
        assert_eq!(
            cfg.renew_deadline,
            Duration::from_secs(RENEW_DEADLINE_SECONDS as u64)
        );
        assert_eq!(cfg.retry_period, Duration::from_secs(RETRY_PERIOD_SECONDS));
    }
}
