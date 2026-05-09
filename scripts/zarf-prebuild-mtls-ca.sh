#!/usr/bin/env bash
# zarf-prebuild-mtls-ca.sh — generate or import a development mTLS CA
# for the rustgate Zarf bundle.
#
# Zarf calls this script during `zarf package create` (via the
# `actions.onCreate.before` hook in zarf.yaml). The script's job is to
# make sure a CA certificate and key are present in the package
# directory before the chart files get vendored, so the resulting
# deploy artifact is fully self-contained.
#
# This script writes a self-signed development CA into the
# `./.ca/` directory. It is intended for local testing and
# air-gapped staging. Do NOT use the generated CA for production
# deployments — production deployments must use the operator's
# enterprise PKI.
#
# TODO(operator): For production deployments, replace this script's
# body with one of the following (depending on your trust model):
#
#   1. **Vault PKI** — call `vault write pki/issue/<role> common_name=…`
#      and write the returned `certificate`, `issuing_ca`, and
#      `private_key` into `./.ca/{ca.pem,ca-key.pem}`.
#   2. **External Secrets Operator** — leave this script empty and
#      manage the CA via an `ExternalSecret` referencing your secret
#      backend (Vault, AWS Secrets Manager, GCP Secret Manager).
#   3. **Pre-issued CA on disk** — replace the openssl invocations
#      below with `cp /path/to/your/ca.pem ./.ca/ca.pem` and
#      `cp /path/to/your/ca-key.pem ./.ca/ca-key.pem`. This script
#      MUST NOT log key material; the development version below uses
#      the noise-free `openssl req` invocations and immediately
#      `chmod 0600`s the resulting key file.

set -euo pipefail

CA_DIR="${CA_DIR:-./.ca}"
CA_CN="${CA_CN:-rustgate-dev-ca}"
CA_DAYS="${CA_DAYS:-3650}"

mkdir -p "$CA_DIR"
chmod 0700 "$CA_DIR"

if [[ -f "$CA_DIR/ca.pem" && -f "$CA_DIR/ca-key.pem" ]]; then
    echo "rustgate Zarf prebuild: CA already present at $CA_DIR — skipping generation."
    exit 0
fi

if ! command -v openssl >/dev/null 2>&1; then
    echo "rustgate Zarf prebuild: openssl is required but not installed." >&2
    echo "  Install via: apt install openssl   |   brew install openssl   |   apk add openssl" >&2
    exit 2
fi

echo "rustgate Zarf prebuild: generating development CA at $CA_DIR (CN=$CA_CN, days=$CA_DAYS)"
echo "  Reminder: this CA is for development / staging only."

# Generate the CA private key (P-384, matches the workspace recommendation
# for tactical deployments). Restrict permissions immediately.
openssl ecparam -genkey -name secp384r1 -noout -out "$CA_DIR/ca-key.pem"
chmod 0600 "$CA_DIR/ca-key.pem"

# Generate the self-signed CA certificate.
openssl req -x509 \
    -key "$CA_DIR/ca-key.pem" \
    -out "$CA_DIR/ca.pem" \
    -days "$CA_DAYS" \
    -subj "/CN=$CA_CN/O=rustgate-development" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"

chmod 0644 "$CA_DIR/ca.pem"

echo "rustgate Zarf prebuild: CA written to $CA_DIR/{ca.pem,ca-key.pem}."
echo "  ca.pem fingerprint:"
openssl x509 -in "$CA_DIR/ca.pem" -noout -fingerprint -sha256 | sed 's/^/    /'
