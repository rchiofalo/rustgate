# UDS / Zarf Deployment

This page walks through deploying rustgate to a Kubernetes cluster
via the Defense Unicorns [UDS platform](https://defenseunicorns.com/platform/uds-platform/)
— the airgap-native deployment story built on top of
[Zarf](https://zarf.dev/).

Three deployment paths, in increasing order of operational scope:

1. **Standalone Zarf** — deploy the bare rustgate package against any
   Kubernetes cluster, no UDS Core required.
2. **UDS bundle** — deploy rustgate composed with UDS Core (Istio mTLS
   mesh, Pepr admission, Prometheus + Grafana + Loki).
3. **Iron Bank / Platform One** — same as path 2, but built from
   `Dockerfile.ironbank` with the DoD-approved UBI 9 minimal base.

If you are NOT operating in an airgapped environment or do not need
UDS Core integration, the in-tree Helm chart at `helm/` is still the
right deployment surface (see `docs/deployment.md` / `helm/README.md`).
This page is specifically for the UDS / Zarf path.

## Prerequisites

| Tool | Version | Path 1 (Zarf only) | Path 2 (UDS bundle) | Path 3 (Iron Bank) |
|---|---|---|---|---|
| [Zarf CLI](https://docs.zarf.dev/getting-started/install/) | ≥ v0.34 | required | required | required |
| [UDS CLI](https://uds.defenseunicorns.com/reference/cli/quickstart-and-usage/) | ≥ v0.16 | — | required | required |
| Docker / Podman | any recent | required | required | required |
| `kubectl` | matches cluster | required | required | required |
| Iron Bank robot account | — | — | — | required |

Target Kubernetes cluster: any flavor — k3s, kubeadm, EKS, ROSA,
OpenShift, RKE2. The Helm chart and Zarf package are
distribution-agnostic; UDS Core (path 2/3) supports the same flavors
upstream.

## Path 1: Standalone Zarf

The bare Zarf package deploys rustgate against any Kubernetes
cluster — no UDS Core, no Istio sidecar, no opinionated admission
controller. The minimum viable airgap deployment.

```bash
# From the repo root.

# 1. Build the rustgate Zarf package.
cd zarf
zarf package create --confirm
# Output: zarf-package-rustgate-<arch>-0.9.0.tar.zst

# 2. Stage the .tar.zst across the airgap boundary
#    (USB / S3 / data diode / etc.).

# 3. On the target side, initialize Zarf into the cluster
#    (one-time, from the upstream `zarf-init` package).
zarf init --confirm

# 4. Deploy rustgate.
zarf package deploy zarf-package-rustgate-<arch>-0.9.0.tar.zst --confirm
```

Override Helm values at deploy time via `--set`:

```bash
zarf package deploy zarf-package-rustgate-...tar.zst \
    --set RUSTGATE_REPLICAS=3 \
    --set RUSTGATE_NATS_URL=nats://my-nats:4222 \
    --confirm
```

The deployed resources match what `helm install rustgate helm/`
produces: StatefulSet, Service, NetworkPolicy, PDB, optional HPA
and ServiceMonitor.

## Path 2: UDS bundle (UDS Core integration)

The bundle composes rustgate with UDS Core's init package, getting:

- Kubernetes CRDs (Istio, Pepr, Prometheus operator, cert-manager)
- Istio service mesh with strict mTLS between pods
- Pepr admission controller (enforces the
  [`bundle/uds-package.yaml`](../bundle/uds-package.yaml) admission CR)
- Prometheus + Grafana + Loki observability stack

```bash
# From the repo root.

# 1. Build the Zarf package (sub-step of building the bundle).
cd zarf && zarf package create --confirm && cd ..

# 2. Build the UDS bundle. Composes the Zarf package from step 1
#    with `ghcr.io/defenseunicorns/packages/init`.
cd bundle && uds create --confirm
# Output: uds-bundle-rustgate-<arch>-0.9.0.tar.zst

# 3. Stage the .tar.zst across the airgap boundary.

# 4. On the target side, initialize UDS into the cluster
#    (one-time).
uds init --confirm

# 5. Deploy the bundle.
uds deploy uds-bundle-rustgate-<arch>-0.9.0.tar.zst --confirm
```

Deployer-side overrides via `uds-config.yaml`:

```bash
cp bundle/uds-config.yaml.example uds-config.yaml
$EDITOR uds-config.yaml    # Set NATS URL, replica count, ingress host, etc.
uds deploy uds-bundle-rustgate-...tar.zst \
    --config uds-config.yaml --confirm
```

### Apply the UDS Package admission CR

The UDS Package CR at [`bundle/uds-package.yaml`](../bundle/uds-package.yaml)
wires rustgate into UDS Core's runtime: network policies, Istio
gateway exposure, Prometheus scrape. The Pepr admission controller
processes it post-Helm-install.

```bash
kubectl apply -f bundle/uds-package.yaml
```

A future enhancement may include this CR as a Helm chart
`extraManifest` so it lands inline with the bundle deploy.

### Verify the deployment

```bash
# rustgate pods are running.
kubectl -n rustgate get pods -l app.kubernetes.io/name=rustgate

# Health check.
kubectl -n rustgate exec deploy/rustgate -- \
    curl -fsS http://localhost:9090/health/live

# Pepr admission saw the UDS Package CR.
uds monitor pepr | grep -i rustgate

# Prometheus is scraping /metrics.
kubectl -n monitoring exec deploy/prometheus -- \
    curl -fsS http://prometheus:9090/api/v1/query \
        --data-urlencode 'query=up{job="rustgate"}'
```

### Reach rustgate via the Istio gateway

The admission CR exposes two virtual services:

- `rustgate.<gateway-domain>` → mTLS client port 4433
- `rustgate-ws.<gateway-domain>` → WebSocket port 8443

```bash
# Connect a client (after enrollment for an mTLS cert).
openssl s_client -connect rustgate.<gateway-domain>:443 \
    -cert client.pem -key client-key.pem -CAfile ca.pem
```

## Path 3: Iron Bank / Platform One

For DoD STIG-compliant deployments, build the rustgate image from
[`Dockerfile.ironbank`](../Dockerfile.ironbank). The runtime base is
`registry1.dso.mil/ironbank/redhat/ubi/ubi9-minimal`, which is
already non-root, has no SUID/SGID binaries, and is read-only-
filesystem-compatible out of the box.

```bash
# 1. Authenticate to Iron Bank.
docker login registry1.dso.mil

# 2. Update the digests in Dockerfile.ironbank with your IB-pulled
#    values (the file ships with `:9-latest` placeholders; CI fails
#    if the @sha256 digest is missing on a real build).

# 3. Build the Iron Bank image.
docker build -f Dockerfile.ironbank \
    -t <your-registry>/rustgate:0.9.0-ironbank .

# 4. Push to your private registry (Iron Bank artifacts cannot live
#    in public GHCR).
docker push <your-registry>/rustgate:0.9.0-ironbank

# 5. Override the Zarf package's image reference to point at your
#    private registry. The `zarf/zarf.yaml` build flavor knob (set
#    `build.flavor: ironbank`) is the supported override path —
#    plumb the right tag via your release pipeline.

# 6. From here, follow path 2 (UDS bundle) — the bundle composition
#    is identical; only the image origin changes.
```

The Iron Bank Dockerfile is a drop-in replacement for the default
`Dockerfile`. The CI workflow in PR H5 validates it builds clean on
every PR touching `Dockerfile*` (subject to the deployer's Iron Bank
credentials being available to the workflow — typically only the
release-cut pipeline has those).

## Troubleshooting

### `zarf package create` fails with "image not found"

The image declarations in `zarf/zarf.yaml` must match what's on GHCR.
If you bump `helm/values.yaml`'s `image.tag` or `operator.image.tag`,
ALSO bump `zarf/zarf.yaml`'s `images:` block. The CI workflow in PR
H5 catches this drift.

### `uds deploy` reports "Pepr admission denied"

The UDS Core init package's Pepr admission controller defaults to
deny-all for pods without a corresponding UDS Package CR. Apply the
CR before (or simultaneously with) the deployment:

```bash
kubectl apply -f bundle/uds-package.yaml
```

If the CR is correct but the pod is still denied, check the Pepr
operator logs:

```bash
uds monitor pepr
```

### Pods stuck in `Pending` with no events

The chart's `affinity.podAntiAffinity` requires replicas to land on
different nodes. On a single-node cluster (k3s demo, kind), override
to `preferredDuringSchedulingIgnoredDuringExecution`:

```yaml
# uds-config.yaml
variables:
  rustgate:
    affinity:
      podAntiAffinity:
        preferredDuringSchedulingIgnoredDuringExecution: []
```

### Bundle deploys but no `/metrics` scrape

Two ServiceMonitors will conflict if both the chart's template AND
the UDS Package CR's `monitor:` stanza fire. Disable the chart's:

```yaml
# uds-config.yaml
variables:
  rustgate:
    monitoring.serviceMonitor.enabled: false
```

The UDS Package CR's `monitor:` is the canonical UDS Core path; the
chart's is the standalone path.

## See also

- [`zarf/README.md`](../zarf/README.md) — Zarf package build instructions
- [`bundle/README.md`](../bundle/README.md) — UDS bundle build + deploy
- [`helm/README.md`](../helm/README.md) — Helm chart for non-UDS deployments
- [`docs/deployment.md`](deployment.md) — non-UDS deployment story
- [ADR 0018](adr/0018-schema-first-codec-design.md) — schema-first codec
  discipline (unrelated to UDS but referenced from `docs/architecture.md`)
- [UDS Platform overview](https://defenseunicorns.com/platform/uds-platform/)
- [Iron Bank registry](https://repo1.dso.mil/dsop)
