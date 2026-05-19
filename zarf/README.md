# Zarf package — `zarf/`

This directory carries the [Zarf](https://zarf.dev/) package manifest
that bundles rustgate's container image + Helm chart for **airgap /
disconnected deployment**. Zarf is the foundation Defense Unicorns'
[UDS platform](https://defenseunicorns.com/platform/uds-platform/) is
built on; rustgate's UDS bundle (`bundle/uds-bundle.yaml`, lands in
PR H2) composes this Zarf package with the upstream `uds-core` init
package for the full UDS Core deployment experience.

## What this directory does

- **`zarf.yaml`** — declares one required component (the rustgate
  StatefulSet via the in-tree Helm chart) plus an optional NATS
  pointer. References the `helm/` directory by relative path so
  there is exactly one source of truth for the chart.

## Building the package

Prerequisites:

- [Zarf CLI](https://docs.zarf.dev/getting-started/install/) ≥ v0.34
- Docker / Podman to resolve container image digests

```bash
# From the repo root.
cd zarf
zarf package create --confirm
```

Output: `zarf-package-rustgate-<arch>-<version>.tar.zst` in the
`zarf/` directory. This `.tar.zst` is the deliverable — it is
self-contained, signature-ready, and can be staged through a
disconnected boundary on any USB stick / S3 bucket / data diode.

## Deploying the package

```bash
# Initialize Zarf into the target cluster (one-time, from the
# `defenseunicorns/zarf-init` package).
zarf init --confirm

# Deploy rustgate.
zarf package deploy zarf-package-rustgate-<arch>-<version>.tar.zst --confirm
```

Override Helm values at deploy time via `--set`:

```bash
zarf package deploy zarf-package-rustgate-...tar.zst \
  --set RUSTGATE_REPLICAS=3 \
  --set RUSTGATE_NATS_URL=nats://uds-core-nats:4222 \
  --confirm
```

## When to use the UDS bundle instead

For a UDS Core platform (the typical Defense Unicorns deployment
target), prefer the bundle at `../bundle/uds-bundle.yaml` (lands in
PR H2). The bundle composes:

- UDS Core init (CRDs, Istio sidecar injection, Pepr admission
  policies, monitoring)
- This rustgate Zarf package
- Optional NATS via `uds-package-nats`

The bundle wires the network policies + service-mesh integration
that the bare Zarf package doesn't ship.

## CI validation

PR H5 lands a GitHub Action (`zarf-package.yml`) that runs
`zarf package create --confirm` on every PR touching `helm/`,
`zarf/`, or `bundle/`. Until that lands, validate locally before
pushing changes to either the Helm chart or this manifest.
