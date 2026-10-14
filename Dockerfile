# syntax=docker/dockerfile:1

# ── Builder stage ────────────────────────────────────────────────────────
# Pinned to the multi-arch manifest digest for rust:1.94-alpine. Rotated
# by dependabot (see .github/dependabot.yml, ecosystem: docker). The
# @sha256 digest is mandatory — the CI "Validate Dockerfile FROM digest
# pinning" step fails any FROM line without it.
#
# TODO(operator): For Iron Bank / Platform One deployment, swap the
# builder base to a hardened image such as:
#
#   FROM registry1.dso.mil/ironbank/redhat/ubi/ubi9-minimal:9.x@sha256:<digest>
#
# Iron Bank pulls require Platform One credentials and a registered
# robot account; substitute the tag and digest from your IB account at
# the time of the build. The default `rust:1.95-alpine` base below is
# suitable for non-IB deployments and is what CI publishes today.
FROM rust:1.95-alpine@sha256:606fd313a0f49743ee2a7bd49a0914bab7deedb12791f3a846a34a4711db7ed2 AS builder

RUN apk add --no-cache musl-dev protobuf-dev make

WORKDIR /src

# Cache dependency build: copy only manifests, create stub sources, build.
COPY Cargo.toml Cargo.lock ./
COPY crates/rustgate-admin/Cargo.toml       crates/rustgate-admin/Cargo.toml
COPY crates/rustgate-archive/Cargo.toml     crates/rustgate-archive/Cargo.toml
COPY crates/rustgate-asterix/Cargo.toml     crates/rustgate-asterix/Cargo.toml
COPY crates/rustgate-authz/Cargo.toml       crates/rustgate-authz/Cargo.toml
COPY crates/rustgate-client/Cargo.toml      crates/rustgate-client/Cargo.toml
COPY crates/rustgate-mqtt/Cargo.toml        crates/rustgate-mqtt/Cargo.toml
COPY crates/rustgate-core/Cargo.toml        crates/rustgate-core/Cargo.toml
COPY crates/rustgate-cot/Cargo.toml         crates/rustgate-cot/Cargo.toml
COPY crates/rustgate-dis/Cargo.toml         crates/rustgate-dis/Cargo.toml
COPY crates/rustgate-enrollment/Cargo.toml  crates/rustgate-enrollment/Cargo.toml
COPY crates/rustgate-federation/Cargo.toml  crates/rustgate-federation/Cargo.toml
COPY crates/rustgate-guard/Cargo.toml       crates/rustgate-guard/Cargo.toml
COPY crates/rustgate-http/Cargo.toml       crates/rustgate-http/Cargo.toml
COPY crates/rustgate-mavlink/Cargo.toml    crates/rustgate-mavlink/Cargo.toml
COPY crates/rustgate-meshtastic/Cargo.toml crates/rustgate-meshtastic/Cargo.toml
COPY crates/rustgate-metrics/Cargo.toml     crates/rustgate-metrics/Cargo.toml
COPY crates/rustgate-nats/Cargo.toml        crates/rustgate-nats/Cargo.toml
COPY crates/rustgate-proto/Cargo.toml       crates/rustgate-proto/Cargo.toml
COPY crates/rustgate-resilience/Cargo.toml  crates/rustgate-resilience/Cargo.toml
COPY crates/rustgate-transport/Cargo.toml   crates/rustgate-transport/Cargo.toml
COPY crates/rustgate-websocket/Cargo.toml   crates/rustgate-websocket/Cargo.toml
COPY crates/rustgate-server/Cargo.toml      crates/rustgate-server/Cargo.toml
COPY crates/rustgate-stanag4586/Cargo.toml  crates/rustgate-stanag4586/Cargo.toml
COPY crates/rustgate-test-utils/Cargo.toml  crates/rustgate-test-utils/Cargo.toml
COPY crates/rustgate-tls/Cargo.toml         crates/rustgate-tls/Cargo.toml
COPY crates/rustgate-router/Cargo.toml      crates/rustgate-router/Cargo.toml
COPY crates/rustgate-sapient/Cargo.toml     crates/rustgate-sapient/Cargo.toml
COPY crates/rustgate-nffi/Cargo.toml        crates/rustgate-nffi/Cargo.toml
COPY crates/rustgate-vmf/Cargo.toml         crates/rustgate-vmf/Cargo.toml
COPY crates/rustgate-link16/Cargo.toml      crates/rustgate-link16/Cargo.toml
COPY crates/rustgate-missions/Cargo.toml    crates/rustgate-missions/Cargo.toml
COPY crates/rustgate-lattice/Cargo.toml     crates/rustgate-lattice/Cargo.toml
COPY crates/rustgate-foundry/Cargo.toml     crates/rustgate-foundry/Cargo.toml
COPY crates/rustgate-dds/Cargo.toml         crates/rustgate-dds/Cargo.toml
COPY crates/rustgate-ogc-sensorthings/Cargo.toml crates/rustgate-ogc-sensorthings/Cargo.toml
COPY crates/rustgate-correlation/Cargo.toml crates/rustgate-correlation/Cargo.toml
COPY crates/rustgate-operator/Cargo.toml    crates/rustgate-operator/Cargo.toml
COPY crates/rustgate-inference/Cargo.toml   crates/rustgate-inference/Cargo.toml
COPY crates/rustgate-codec-schema/Cargo.toml crates/rustgate-codec-schema/Cargo.toml

# Stub lib.rs / main.rs so cargo can resolve and fetch deps.
RUN for d in crates/*/; do mkdir -p "$d/src" && echo "" > "$d/src/lib.rs"; done \
    && mkdir -p crates/rustgate-server/src && echo "fn main() {}" > crates/rustgate-server/src/main.rs \
    && mkdir -p crates/rustgate-operator/src && echo "fn main() {}" > crates/rustgate-operator/src/main.rs

# Proto files are needed at build time by rustgate-proto and rustgate-federation.
COPY crates/rustgate-proto/proto crates/rustgate-proto/proto
COPY crates/rustgate-proto/build.rs crates/rustgate-proto/build.rs
COPY crates/rustgate-federation/proto crates/rustgate-federation/proto
COPY crates/rustgate-federation/build.rs crates/rustgate-federation/build.rs

RUN cargo build --release --features nats,enrollment,proto,full-detail,metrics,federation,federation-ha,websocket,otel,mqtt,http 2>/dev/null || true

# Now copy real source and build for real.
COPY . .
# Touch all source files so cargo sees them as newer than the stubs.
RUN find crates -name "*.rs" -exec touch {} +
RUN cargo build --release --features nats,enrollment,proto,full-detail,metrics,federation,federation-ha,websocket,otel,mqtt,http

# ── Runtime stage ────────────────────────────────────────────────────────
# TODO(operator): For Iron Bank deployment, swap the runtime base to:
#
#   FROM registry1.dso.mil/ironbank/redhat/ubi/ubi9-minimal:9.x@sha256:<digest>
#
# IB images already enforce non-root, no SUID/SGID binaries, and
# read-only filesystem compatibility, so the hardening commands below
# become no-ops (safe to leave in for portability). The default
# `alpine:3.23` base below is what CI publishes today.
FROM alpine:3.23@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11

LABEL org.opencontainers.image.source="https://github.com/rchiofalo/rustgate" \
      org.opencontainers.image.description="Secure tactical message router with mTLS and NATS bridge" \
      org.opencontainers.image.licenses="AGPL-3.0-only"

# Drop SUID/SGID bits from any binaries the base image ships. STIG
# V-RHEL-08-010040 family requires that no setuid/setgid binaries
# remain on a hardened image; we satisfy this by deleting any such
# binaries entirely. Run before the `USER` switch so we still have
# root privileges to chmod/delete; the `|| true` keeps the build
# resilient if the base image already trimmed them.
RUN apk add --no-cache ca-certificates \
    && addgroup -g 10001 -S rustgate && adduser -u 10001 -S rustgate -G rustgate \
    && find / -xdev -type f -perm /6000 -delete 2>/dev/null || true

# Run unprivileged. The Helm chart and Pod Security Standards
# `restricted` profile additionally enforce `runAsNonRoot: true`,
# `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`,
# and drop ALL Linux capabilities — see helm/values-production.yaml.
USER 10001:10001

COPY --from=builder --chmod=755 /src/target/release/rustgate /usr/local/bin/rustgate

EXPOSE 4433 8443 8446 8883 9000 9001 9090

STOPSIGNAL SIGTERM

# Recommended runtime invocation:
#   docker run --read-only --tmpfs /tmp --user 10001:10001 \
#              --cap-drop=ALL --security-opt=no-new-privileges \
#              ghcr.io/rchiofalo/rustgate:<tag>
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --spider -q http://localhost:9090/healthz 2>/dev/null || \
        nc -z localhost 4433 || exit 1

ENTRYPOINT ["rustgate"]
