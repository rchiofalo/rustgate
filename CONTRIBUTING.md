# Contributing to rustgate

## Prerequisites

- **Rust 1.93+** — install via [rustup](https://rustup.rs/). The pinned toolchain is defined in `rust-toolchain.toml`.
- **protoc** — Protocol Buffers compiler, required for the `proto` feature. Install via your package manager (`apt install protobuf-compiler`, `brew install protobuf`, etc.).
- **nats-server** — required to run NATS integration tests. Install from [nats.io](https://nats.io/download/) or via `go install github.com/nats-io/nats-server/v2@latest`.
- **cargo-deny** — for license and advisory auditing. Install with `cargo install cargo-deny --locked`.
- **Helm** — for Helm chart linting. Install from [helm.sh](https://helm.sh/docs/intro/install/).

## Building

```bash
# Default build (core transport + routing only)
cargo build

# With all optional features
cargo build --all-features

# Individual features
cargo build --features nats          # NATS bridge
cargo build --features enrollment    # Certificate enrollment
cargo build --features proto         # TAK protobuf translation
cargo build --features federation    # Server-to-server federation
cargo build --features websocket     # WebSocket transport
cargo build --features metrics       # Prometheus metrics + health endpoints
cargo build --features fips          # FIPS 140-3 crypto (requires Go + cmake)
cargo build --features post-quantum  # Post-quantum key exchange (requires Go + cmake)
cargo build --features otel          # OpenTelemetry tracing (requires protoc)
cargo build --features jemalloc      # jemalloc allocator (recommended for musl)
```

## Testing

```bash
# Run all unit tests (default features)
cargo test

# Run all tests including feature-gated ones
cargo test --all-features

# Run a single crate's tests
cargo test -p rustgate-transport

# Run NATS integration tests (requires nats-server on PATH)
cargo test -p rustgate-nats --test integration
```

## Code Quality

CI runs as parallel jobs. All checks must pass before merging to `main` (enforced via branch protection):

| Job | What it checks |
|-----|----------------|
| `commit-lint` | PR title follows Conventional Commits format |
| `lint` | `cargo +nightly fmt --check` + `cargo machete` |
| `clippy` | `cargo clippy` with all features + `cargo doc` |
| `check-features` | `cargo hack` feature powerset (depth 2, excludes fips/jemalloc/post-quantum) |
| `test` | `cargo nextest run` with all features (except fips/jemalloc/post-quantum) + doc tests |
| `coverage` | `cargo tarpaulin` code coverage |
| `fips` | Clippy, build, and tests with `--features fips` |
| `post-quantum` | Clippy, build, and tests with `--features post-quantum` |
| `audit` | `cargo deny check` + `cargo audit` |
| `dependency-review` | Dependency diff review on pull requests (fails on high-severity) |
| `helm` | `helm lint helm/` |
| `docker` | Dockerfile build validation |

Run locally before pushing:

```bash
# Formatting (enforced)
cargo fmt --all -- --check

# Lints (warnings are errors in CI via RUSTFLAGS=-Dwarnings)
cargo clippy --all-features --all-targets

# Dependency auditing (licenses, advisories, bans, sources)
cargo deny check

# Helm chart validation
helm lint helm/
```

### Workspace lint policy

- `unsafe_code = "forbid"` — no unsafe anywhere
- `unwrap_used = "deny"` — use `expect()` with context or proper error handling
- `panic = "deny"` — no `panic!()` or `todo!()` in library/production code
- `dbg_macro = "deny"` — no debug macros in committed code

The `rustgate-test-utils` crate relaxes `panic = "allow"` since test setup failures should panic.

## Project Structure

The workspace is organized as independent crates under `crates/`:

| Crate | Purpose |
|-------|---------|
| `rustgate-core` | Shared types: Identity, RoutableMessage, FramingStrategy |
| `rustgate-cot` | Cursor on Target XML parsing |
| `rustgate-transport` | mTLS listener, codec, CRL, FIPS provider, session management, routing engine |
| `rustgate-websocket` | WebSocket (wss://) listener with mTLS client authentication |
| `rustgate-nats` | NATS bridge for cross-instance messaging |
| `rustgate-enrollment` | HTTPS certificate enrollment server (CSR signing, PKCS#12) |
| `rustgate-proto` | Protobuf translation (XML / proto) |
| `rustgate-federation` | Server-to-server federation: V1 (XML), V2 (gRPC), HA, REST API |
| `rustgate-server` | Binary entry point, wires everything together |
| `rustgate-test-utils` | Shared test helpers (CA and cert generation) |

## Adding a New Crate

1. Create the crate directory under `crates/`
2. Add it to `members` in the root `Cargo.toml`
3. Inherit workspace fields: `version`, `edition`, `rust-version`, `license`, `repository`
4. Add `[lints] workspace = true` (unless the crate needs custom lint overrides)
5. Add a `[[licenses.exceptions]]` entry in `deny.toml` for the proprietary license
6. Add a `description` field for the crate

## Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add new feature
fix: correct bug in X
docs: update README
deps: bump dependency X from Y to Z
ci: update workflow
refactor: restructure module X
test: add tests for Y
chore: miscellaneous maintenance
```

## Pull Requests

- Branch from `main`
- Keep PRs focused — one logical change per PR
- All CI checks must pass before merge (branch protection enforced)
- Update the README if the change affects user-facing behavior
- Add or update tests for any new functionality
