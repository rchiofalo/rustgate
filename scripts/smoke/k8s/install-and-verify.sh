#!/usr/bin/env bash
# install-and-verify.sh — one-liner sanity test for the rustgate Kubernetes
# operator (closes #874).
#
# Installs the chart against a kind/minikube cluster, applies a sample
# `RustgateCluster`, and waits for the StatefulSet to reach Ready. Used
# as a smoke test in CI; invocable from a developer laptop with a kind
# cluster up.
#
# Usage:
#   scripts/smoke/k8s/install-and-verify.sh [release-name] [namespace]
#
# Requires:
#   - kubectl 1.28+
#   - helm 3.12+
#   - a Kubernetes cluster (kind / minikube / k3d / EKS) reachable via
#     the current kubeconfig
#
# Exit code:
#   0 — RustgateCluster reconciles to Ready within READY_TIMEOUT (60s)
#   1 — install or readiness check failed (caller should `kubectl logs`
#       the operator pod for diagnostics)

set -euo pipefail

RELEASE=${1:-rustgate}
NAMESPACE=${2:-rustgate}
READY_TIMEOUT=${READY_TIMEOUT:-60}

REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
CHART_PATH="${REPO_ROOT}/helm"
CRD_PATH="${REPO_ROOT}/helm/crds/rustgatecluster.yaml"

log() { printf '[smoke] %s\n' "$*" >&2; }
fail() { printf '[smoke] FAIL: %s\n' "$*" >&2; exit 1; }

if ! command -v kubectl >/dev/null; then fail "kubectl not on PATH"; fi
if ! command -v helm >/dev/null; then fail "helm not on PATH"; fi

log "Step 1/5: ensure namespace ${NAMESPACE} exists"
kubectl get ns "${NAMESPACE}" >/dev/null 2>&1 || \
    kubectl create namespace "${NAMESPACE}"

log "Step 2/5: install/update the RustgateCluster CRD"
kubectl apply -f "${CRD_PATH}"

log "Step 3/5: helm upgrade --install ${RELEASE}"
helm upgrade --install "${RELEASE}" "${CHART_PATH}" \
    --namespace "${NAMESPACE}" \
    --set operator.enabled=true \
    --set cluster.create=true \
    --set cluster.replicas=1 \
    --wait \
    --timeout 60s

log "Step 4/5: wait for the operator deployment to become Available"
kubectl rollout status \
    "deployment/${RELEASE}-operator" \
    -n "${NAMESPACE}" \
    --timeout=60s

log "Step 5/5: wait for the RustgateCluster's StatefulSet to be Ready"
# The operator creates the StatefulSet on its first reconcile; poll
# with a bounded retry loop because the watch-based wait below errors
# out when the StatefulSet does not yet exist.
deadline=$(( $(date +%s) + READY_TIMEOUT ))
while [[ $(date +%s) -lt $deadline ]]; do
    if kubectl get statefulset/"${RELEASE}" -n "${NAMESPACE}" >/dev/null 2>&1; then
        break
    fi
    sleep 2
done
kubectl rollout status \
    "statefulset/${RELEASE}" \
    -n "${NAMESPACE}" \
    --timeout="${READY_TIMEOUT}s" || \
    fail "StatefulSet did not become Ready within ${READY_TIMEOUT}s"

log "OK: RustgateCluster is reconciled and Ready."
kubectl get rustgatecluster -n "${NAMESPACE}"
