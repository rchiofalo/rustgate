# syntax=docker/dockerfile:1

# ── Builder stage ────────────────────────────────────────────────────────
FROM rust:1.94-alpine@sha256:7f752ee8ea5deb9f4863d8c3f228a216a6466619882f09a44b9eda9617dc7770 AS builder

RUN apk add --no-cache musl-dev protobuf-dev make

WORKDIR /src

# Cache dependency build: copy only manifests, create stub sources, build.
COPY Cargo.toml Cargo.lock ./
COPY crates/rustgate-core/Cargo.toml        crates/rustgate-core/Cargo.toml
COPY crates/rustgate-cot/Cargo.toml         crates/rustgate-cot/Cargo.toml
COPY crates/rustgate-enrollment/Cargo.toml  crates/rustgate-enrollment/Cargo.toml
COPY crates/rustgate-federation/Cargo.toml  crates/rustgate-federation/Cargo.toml
COPY crates/rustgate-nats/Cargo.toml        crates/rustgate-nats/Cargo.toml
COPY crates/rustgate-proto/Cargo.toml       crates/rustgate-proto/Cargo.toml
COPY crates/rustgate-transport/Cargo.toml   crates/rustgate-transport/Cargo.toml
COPY crates/rustgate-websocket/Cargo.toml   crates/rustgate-websocket/Cargo.toml
COPY crates/rustgate-server/Cargo.toml      crates/rustgate-server/Cargo.toml
COPY crates/rustgate-test-utils/Cargo.toml  crates/rustgate-test-utils/Cargo.toml

# Stub lib.rs / main.rs so cargo can resolve and fetch deps.
RUN for d in crates/*/; do mkdir -p "$d/src" && echo "" > "$d/src/lib.rs"; done \
    && mkdir -p crates/rustgate-server/src && echo "fn main() {}" > crates/rustgate-server/src/main.rs

# Proto files are needed at build time by rustgate-proto and rustgate-federation.
COPY crates/rustgate-proto/proto crates/rustgate-proto/proto
COPY crates/rustgate-proto/build.rs crates/rustgate-proto/build.rs
COPY crates/rustgate-federation/proto crates/rustgate-federation/proto
COPY crates/rustgate-federation/build.rs crates/rustgate-federation/build.rs

RUN cargo build --release --features nats,enrollment,proto,full-detail,metrics,federation,federation-ha,websocket,otel 2>/dev/null || true

# Now copy real source and build for real.
COPY . .
# Touch all source files so cargo sees them as newer than the stubs.
RUN find crates -name "*.rs" -exec touch {} +
RUN cargo build --release --features nats,enrollment,proto,full-detail,metrics,federation,federation-ha,websocket,otel

# ── Runtime stage ────────────────────────────────────────────────────────
FROM alpine:3.23@sha256:25109184c71bdad752c8312a8623239686a9a2071e8825f20acb8f2198c3f659

LABEL org.opencontainers.image.source="https://github.com/rchiofalo/rustgate" \
      org.opencontainers.image.description="Secure tactical message router with mTLS and NATS bridge" \
      org.opencontainers.image.licenses="LicenseRef-Proprietary"

RUN apk add --no-cache ca-certificates \
    && addgroup -g 10001 -S rustgate && adduser -u 10001 -S rustgate -G rustgate

USER 10001

COPY --from=builder --chmod=755 /src/target/release/rustgate /usr/local/bin/rustgate

EXPOSE 4433 8443 8446 9000 9001 9090

STOPSIGNAL SIGTERM

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --spider -q http://localhost:9090/healthz || exit 1

ENTRYPOINT ["rustgate"]
