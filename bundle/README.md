# UDS bundle — `bundle/`

This directory carries the [UDS bundle](https://uds.defenseunicorns.com/)
manifest that composes the rustgate Zarf package with the upstream
**UDS Core** init package for deployment on the Defense Unicorns
[UDS platform](https://defenseunicorns.com/platform/uds-platform/).

## What's in here

- **`uds-bundle.yaml`** — bundle manifest. References:
  - `ghcr.io/defenseunicorns/packages/init` — UDS Core init
    (CRDs, Istio, Pepr, monitoring stack)
  - `../zarf` — the local rustgate Zarf package (PR H1)
- **`uds-config.yaml.example`** — deployer-side override template.
  Copy to `uds-config.yaml` (gitignored), tweak, pass via
  `--config` to `uds deploy`.

## Building the bundle

Prerequisites:

- [UDS CLI](https://uds.defenseunicorns.com/reference/cli/quickstart-and-usage/) ≥ v0.16
- The rustgate Zarf package must build first (so `../zarf` is
  fully resolvable). The CI workflow in PR H5 chains the two
  steps; local users run them in order:

```bash
# 1. Build the Zarf package (from `zarf/zarf.yaml`).
cd zarf && zarf package create --confirm && cd ..

# 2. Build the UDS bundle (from `bundle/uds-bundle.yaml`).
cd bundle && uds create --confirm
```

Output: `uds-bundle-rustgate-<arch>-<version>.tar.zst` — the
single artifact deployers stage across the airgap boundary.

## Deploying the bundle

```bash
# Initialize UDS into the target cluster (one-time).
uds init --confirm

# Deploy rustgate + UDS Core.
uds deploy uds-bundle-rustgate-<arch>-<version>.tar.zst --confirm

# Or with deployer-side overrides.
cp uds-config.yaml.example uds-config.yaml
$EDITOR uds-config.yaml
uds deploy uds-bundle-rustgate-...tar.zst \
    --config uds-config.yaml --confirm
```

## What this bundle composes

| Layer | Source | Purpose |
|---|---|---|
| UDS Core init | `ghcr.io/defenseunicorns/packages/init@v0.42.0` | Kubernetes CRDs, Istio mTLS mesh, Pepr admission controller, Prometheus + Grafana + Loki stack |
| rustgate Zarf | `../zarf` (local) | rustgate StatefulSet + Helm chart from PR H1 |
| NATS (optional, commented) | `ghcr.io/defenseunicorns/uds-package-nats` | NATS server for the `--nats-url` bridge — opt-in via uncomment in `uds-bundle.yaml` |

## What's NOT in the bundle yet

- **Pepr admission CR** (`uds-package.yaml`) — wires network
  policies, Istio sidecar injection, and monitoring scrape into
  the UDS Core runtime. Lands in PR H3.
- **Iron Bank base image alternative** — for Platform One
  deployments. Lands in PR H4.
- **CI validation** that `uds create --confirm` succeeds. Lands
  in PR H5.

## Cross-references

- Zarf package: [`../zarf/`](../zarf/) (PR H1)
- Helm chart: [`../helm/`](../helm/)
- Full deployment walkthrough: `docs/uds-deployment.md` (PR H4)
- ADR 0018 (schema-first codec discipline — unrelated, but the
  same "ship one artifact, validate the discipline at build
  time" philosophy)
