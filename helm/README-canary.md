# Canary Upgrade Path

This chart ships a `values-canary.yaml` overlay that converts the
default deployment into a manual-canary rolling upgrade pattern. The
overlay is intended for high-risk changes — policy schema bumps,
dependency major versions, framing-codec changes — where the operator
wants a 30-second observation window per pod before the next
replacement begins. Closes #818 (F-142).

## What the overlay changes

| Setting | Default | Canary overlay | Why |
|---|---|---|---|
| `maxSurge` | (controller default) | `1` | One new pod above target during a rollout; bounds canary blast radius |
| `maxUnavailable` | (controller default) | `0` | Cluster never drops below target replicas during the upgrade |
| `minReadySeconds` | `0` | `30` | New pods must serve traffic for 30s before counting as Ready |
| `preStop` | `sleep 5` | drain endpoint poke + `sleep 5` | LB rotation removal before SIGTERM |
| Probe `failureThreshold` | `3` | `3` (explicit) | Pinned for canary observability |
| Pod annotations | none | Linkerd `proxy-await`, Prometheus scrape | Mesh-aware traffic gating + scrape discovery |

## Usage

```bash
# Initial deploy
helm upgrade --install rustgate ./helm \
  -f helm/values.yaml \
  -f helm/values-production.yaml

# Canary upgrade (e.g. policy-schema or framing change)
helm upgrade rustgate ./helm \
  -f helm/values.yaml \
  -f helm/values-production.yaml \
  -f helm/values-canary.yaml \
  --set image.tag=0.9.0
```

The two-file `-f` order matters: `values-canary.yaml` must come last so
its overrides win against the production overlay. `values-production
.yaml` already pins a 3-replica baseline; the canary overlay does not
change `replicaCount` — combining the two yields a 4-pod surge during
rollout (3 + 1) and a guaranteed 3-pod floor.

## Rollback

The canary overlay does not change rollback semantics. A bad rollout
is recovered with:

```bash
helm rollback rustgate
```

For policy-schema rollbacks specifically, the broker also emits the
`authz.reload_rollback` audit event and increments the
`rustgate_reload_rollback_total{subsystem="authz"}` Prometheus counter
when a hot-reload of the on-disk policy fails — see #818 (F-144) for
the operator-visible signal.

## Verifying a rollout

```bash
# Watch the rollout
kubectl rollout status deployment/rustgate

# Confirm new pods served traffic for ≥30s before the next replacement
kubectl get pods -l app.kubernetes.io/name=rustgate \
  --sort-by=.status.startTime

# Cross-check rollback metric (should be flat during a healthy rollout)
kubectl exec -it $(kubectl get pod -l app.kubernetes.io/name=rustgate \
  -o jsonpath='{.items[0].metadata.name}') -- \
  curl -s localhost:9090/metrics | grep rustgate_reload_rollback_total
```

## Linkerd / Istio integration

The overlay sets `config.linkerd.io/proxy-await=enabled` so the Linkerd
proxy holds inbound traffic until the application reports Ready. Istio
users should add the equivalent `proxy.istio.io/config` annotation to
the overlay or to a downstream `values-mesh.yaml`.
