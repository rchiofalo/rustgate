# syntax=docker/dockerfile:1

# ── Builder stage ────────────────────────────────────────────────────────
FROM rust:1.85-alpine AS builder

RUN apk add --no-cache musl-dev protobuf-dev

WORKDIR /src

# Cache dependency build: copy only manifests, create stub sources, build.
COPY Cargo.toml Cargo.lock ./
COPY crates/rustgate-core/Cargo.toml        crates/rustgate-core/Cargo.toml
COPY crates/rustgate-cot/Cargo.toml         crates/rustgate-cot/Cargo.toml
COPY crates/rustgate-enrollment/Cargo.toml  crates/rustgate-enrollment/Cargo.toml
COPY crates/rustgate-nats/Cargo.toml        crates/rustgate-nats/Cargo.toml
COPY crates/rustgate-proto/Cargo.toml       crates/rustgate-proto/Cargo.toml
COPY crates/rustgate-transport/Cargo.toml   crates/rustgate-transport/Cargo.toml
COPY crates/rustgate-server/Cargo.toml      crates/rustgate-server/Cargo.toml
COPY crates/rustgate-test-utils/Cargo.toml  crates/rustgate-test-utils/Cargo.toml

# Stub lib.rs / main.rs so cargo can resolve and fetch deps.
RUN for d in crates/*/; do mkdir -p "$d/src" && echo "" > "$d/src/lib.rs"; done \
    && mkdir -p crates/rustgate-server/src && echo "fn main() {}" > crates/rustgate-server/src/main.rs

# Proto files are needed at build time by rustgate-proto.
COPY crates/rustgate-proto/proto crates/rustgate-proto/proto
COPY crates/rustgate-proto/build.rs crates/rustgate-proto/build.rs

RUN cargo build --release --all-features 2>/dev/null || true

# Now copy real source and build for real.
COPY . .
# Touch all source files so cargo sees them as newer than the stubs.
RUN find crates -name "*.rs" -exec touch {} +
RUN cargo build --release --all-features

# ── Runtime stage ────────────────────────────────────────────────────────
FROM alpine:3.21

RUN apk add --no-cache ca-certificates \
    && addgroup -S rustgate && adduser -S rustgate -G rustgate

USER rustgate

COPY --from=builder /src/target/release/rustgate /usr/local/bin/rustgate

EXPOSE 4433
ENTRYPOINT ["rustgate"]
