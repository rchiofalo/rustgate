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

## Crate layout

| Module       | Purpose                                                         |
| ------------ | --------------------------------------------------------------- |
| `crd`        | Hand-rolled serde projection of `rustgate.io/v1alpha1`          |
| `render`     | Pure manifest renderer (`render_all` / `render_all_yaml`)       |
| `reconcile`  | Validate → render → return a status-patch contract              |
| `error`      | `OperatorError` + `Result<T>`                                   |

## Build

```bash
cargo build -p rustgate-operator
cargo nextest run -p rustgate-operator
```

## CLI

```bash
# Render manifests for a RustgateCluster YAML and pipe into kubectl.
rustgate-operator render -i my-cluster.yaml | kubectl apply -f -

# Validate a manifest in CI without contacting the cluster.
rustgate-operator validate -i my-cluster.yaml

# Print the binary version.
rustgate-operator version
```

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
the operator reconciles.

## Scope

MVP: CRD types, manifest renderer, golden-render snapshot tests, Helm
chart wiring. Live cluster controller (the apply-loop calling `kube::Api`),
HorizontalPodAutoscaler integration, and backup/restore controllers are
deferred. The renderer is the source of truth for *what* gets created;
the apply-loop is mechanical glue that can be implemented with `kube-rs`
or `kubectl apply` in a sidecar without changing the contract here.
