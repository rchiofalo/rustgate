# rustgate-operator

Kubernetes operator for the `RustgateCluster` CRD. Closes #874.

## What it does

Manages a `rustgate.io/v1alpha1/RustgateCluster` resource. For each cluster, the
operator owns:

- a `StatefulSet` (rustgate replicas)
- a headless `Service` (stable pod DNS)
- a client-facing `ClusterIP` `Service` (tactical traffic)
- a `ConfigMap` (rendered `rustgate.toml`, including the federation peer list
  when `spec.federation.autoDiscover: true`)
- a `cert-manager.io/v1/Certificate` (when `spec.certManager` is set)

Owner-references are applied so deletion of the parent cascade-deletes
every child object.

## Two operating modes

The binary supports two modes from a single Rust crate:

| Mode | Build | Subcommand | Behaviour |
|---|---|---|---|
| Render-only | `cargo build` (default) | `render`, `validate` | Pure-function renderer; no kube client, no async runtime. Produces YAML for `kubectl apply -f -` |
| Live controller | `cargo build --features controller` | `run` | Full kube-runtime harness: watches `RustgateCluster`, server-side-applies the renderer's output, reads back observed `StatefulSet.status`, patches `RustgateCluster.status`, leader-elects via `coordination.k8s.io/v1` Lease |

The default build stays lean so the renderer is independently usable in CI
pipelines, dry-run workflows, and `kubectl apply -f -` smoke tests. The
release Docker image enables `--features controller` so deploying the
operator into Kubernetes just works.

## Crate layout

| Module          | Always-on | Purpose                                                |
| --------------- | --------- | ------------------------------------------------------ |
| `crd`           | ✓         | Hand-rolled serde projection of `rustgate.io/v1alpha1` |
| `render`        | ✓         | Pure manifest renderer                                 |
| `reconcile`     | ✓         | Validate → render → status-patch contract              |
| `error`         | ✓         | `OperatorError` + `Result<T>`                          |
| `kube_types`    | controller| `#[derive(CustomResource)]` view of `RustgateCluster`  |
| `apply`         | controller| Server-side apply with stable field manager            |
| `controller`    | controller| `kube_runtime::Controller` reconcile loop              |
| `leader`        | controller| Lease-based leader election                            |
| `events`        | controller| Kubernetes Event emission via `Recorder`               |
| `health`        | controller| `axum` HTTP server for `/healthz`, `/readyz`, `/metrics`|
| `metrics`       | controller| Prometheus counters / gauges / histogram               |

## Build

```bash
# Default: pure render binary, no kube deps.
cargo build -p rustgate-operator
cargo nextest run -p rustgate-operator

# Live controller — enables the `run` subcommand.
cargo build -p rustgate-operator --features controller
cargo nextest run -p rustgate-operator --features controller
```

## CLI

```bash
# Render manifests for a RustgateCluster YAML and pipe into kubectl.
rustgate-operator render -i my-cluster.yaml | kubectl apply -f -

# Validate a manifest in CI without contacting the cluster.
rustgate-operator validate -i my-cluster.yaml

# Run the live controller (requires --features controller).
rustgate-operator run                                       # cluster-wide
rustgate-operator run --namespace rustgate                  # single-namespace watch
rustgate-operator run --no-leader-elect                     # only with replicas=1
rustgate-operator run --http-addr 0.0.0.0:8080              # change probe / metrics port

# Print the binary version.
rustgate-operator version
```

## Controller architecture

```
                          ┌───────────────────┐
SIGTERM ─────────────────▶│ signal handler    │──▶ shutdown watch
                          └───────────────────┘          │
┌─────────────────────┐                                  ▼
│ axum HTTP server    │◀── /healthz, /readyz, /metrics
└─────────────────────┘                                  │
┌─────────────────────┐    ┌─────────────────────┐       │
│ Lease election loop │───▶│ LeaderGate (RwLock) │◀──────┤
└─────────────────────┘    └─────────────────────┘       │
                                     │                   │
                                     ▼                   │
                          ┌────────────────────┐         │
                          │ Controller (kube)  │─────────┘
                          │                    │
                          │  watch RGC + owns  │
                          │  StatefulSet/      │
                          │  Service/ConfigMap │
                          └────────────────────┘
                                     │
                                     ▼
                          ┌────────────────────┐
                          │ reconcile_fn       │
                          │                    │
                          │ 1. Gate on leader  │
                          │ 2. Pure reconcile  │──▶ render::render_all
                          │ 3. apply::apply_all│
                          │ 4. Read STS status │
                          │ 5. Patch RGC.status│
                          │ 6. Emit Event      │
                          └────────────────────┘
```

### Reconcile lifecycle

1. **Validate** the spec — invalid specs surface as a `Ready=False/InvalidSpec`
   condition and a `Warning/InvalidSpec` Event.
2. **Render** the owned manifests via the pure `render_all`. The renderer
   already attaches owner references.
3. **Server-side apply** each manifest with field manager
   `rustgate-operator`, `force: true`. Drift from human `kubectl edit`s is
   re-asserted on every pass.
4. **Read back** the observed `StatefulSet.status` (`readyReplicas`,
   `availableReplicas`).
5. **Patch** `RustgateCluster.status` with a merge patch. When
   `readyReplicas == availableReplicas > 0` the `Progressing` condition is
   replaced with `Ready=True`.
6. **Emit** a `Normal/Reconciled` Event with the apply summary so
   `kubectl describe rustgatecluster <name>` shows progress.
7. **Re-queue** for 30 s (drift catch) or for 15 s on the error path.

### Leader election

Multi-replica operator Deployments coordinate via a
`coordination.k8s.io/v1` Lease named `rustgate-operator-leader-election`.
The follower's reconcile loop runs but no-ops (no API calls, no events)
while it doesn't hold the lease, keeping watches warm so leader handover
is fast. On SIGTERM the leader clears the `holderIdentity` so a peer can
take over immediately rather than wait the full `leaseDuration`.

### Observability

| Endpoint | Behaviour |
|---|---|
| `GET /healthz` | Always 200 while the process is up. |
| `GET /readyz` | 200 when the API server is reachable, 503 otherwise. Not gated on leadership — followers are also "ready." |
| `GET /metrics` | Prometheus text exposition of the operator's metrics namespace (`rustgate_operator_*`). |

Metrics:

- `rustgate_operator_reconcile_total{result}`
- `rustgate_operator_reconcile_duration_seconds`
- `rustgate_operator_apply_total{kind, result}`
- `rustgate_operator_clusters_total`
- `rustgate_operator_leader`
- `rustgate_operator_last_reconcile_timestamp_seconds`

## CRD schema

The CRD is shipped as `helm/crds/rustgatecluster.yaml`. Helm 3 installs CRDs
from `helm/crds/*.yaml` once on first install and does not touch them on
upgrade. Apply manually with:

```bash
kubectl apply -f helm/crds/rustgatecluster.yaml
```

## Helm chart

Set `operator.enabled: true` in `helm/values.yaml` to deploy the operator
Deployment + RBAC alongside the bare StatefulSet path. With
`cluster.create: true` the chart also creates a `RustgateCluster` instance
the operator reconciles. The default chart runs with `replicas: 2` and
leader election enabled; set `operator.leaderElection.enabled: false` and
`operator.replicas: 1` for single-replica mode.

## Scope

Live cluster controller, leader election, Prometheus metrics, Kubernetes
Event emission, graceful drain on SIGTERM. Backup/restore controllers and
HorizontalPodAutoscaler integration remain deferred.
