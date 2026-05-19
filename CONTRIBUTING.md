# Contributing to rustgate

## Prerequisites

- **Rust 1.94+** — install via [rustup](https://rustup.rs/). The pinned toolchain is defined in `rust-toolchain.toml`.
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
cargo build --features mqtt          # MQTT 5.0/3.1.1 transport
cargo build --features metrics       # Prometheus metrics + health endpoints
cargo build --features est           # EST (RFC 7030) enrollment endpoints
cargo build --features ocsp          # OCSP stapling and client checking
cargo build --features spiffe        # SPIFFE/SPIRE workload identity
cargo build --features cedar         # Cedar policy language for authz
cargo build --features fips          # FIPS 140-3 crypto (requires Go + cmake)
cargo build --features post-quantum  # Post-quantum key exchange (requires Go + cmake)
cargo build --features otel          # OpenTelemetry tracing (requires protoc)
cargo build --features jemalloc      # jemalloc allocator (recommended for musl)
```

## Testing

```bash
# Run all unit tests (default features) — CI uses nextest
cargo nextest run

# Run all tests including feature-gated ones
cargo nextest run --all-features

# Run a single crate's tests
cargo nextest run -p rustgate-transport

# Run NATS integration tests (requires nats-server on PATH)
cargo nextest run -p rustgate-nats --test integration

# cargo test also works but nextest is the CI runner
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
| `coverage` | `cargo llvm-cov --nextest` code coverage |
| `fips` | Clippy, build, and tests with `--features fips` |
| `post-quantum` | Clippy, build, and tests with `--features post-quantum` |
| `audit` | `cargo deny check` + `cargo audit` |
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

### Allow annotations (F-156)

Every `#[allow(...)]` in production code MUST be preceded by a
`// justification:` comment explaining why the lint cannot be fixed in
place. The rule is enforced in CI by `scripts/check-allow-justified.py`
(the `playbook-lint` job). A missing justification fails the build with a
`::error` annotation pointing at the offending line.

Exemptions — tests only. The rule does not apply to:

- The `rustgate-test-utils` crate (whole crate is test-support).
- Files under `crates/*/tests/` (integration tests).
- Files under `crates/*/benches/` and `crates/*/examples/`.
- `build.rs` build scripts (generated-code paths).
- Items under `#[cfg(test)]` or inside a `mod tests { … }` block.

What counts as a good justification:

- *Why clippy is wrong here* — a generated module (prost/tonic) we cannot
  patch upstream; a feature-conditional type (e.g. `.clone()` on a value
  that is `()` without `--features nats` and `Option<T>` with it) where
  the allowed spelling is the only one that compiles in every config; a
  `dead_code` field read by an accessor the lint cannot see.
- *Why refactoring is worse* — `too_many_arguments` on a dispatch
  entrypoint called from exactly one site, where bundling into a struct
  would move the fan-in upstream with no call-site reduction.
- *Forward reference* — a metric registered for a stable Prometheus
  schema that a later issue wires up; include the issue number.

What does NOT count:

- "Clippy false positive" with no further detail.
- "Fix later" without an issue link.
- "Obvious" — if it were obvious the lint would not fire.

Format:

```rust
// justification: <one or two sentences explaining the trade-off>.
#[allow(clippy::too_many_arguments)]
fn handle(req: Request, providers: &Providers, …) { … }
```

Multi-line justifications are fine — the script just requires that the
first comment line above the `#[allow]` starts with `// justification:`.
See `crates/rustgate-cot/src/delta.rs`,
`crates/rustgate-server/src/metrics.rs`, and
`crates/rustgate-mqtt/src/session.rs` for representative examples of each
category.

## Project Structure

The workspace is organized as independent crates under `crates/`:

| Crate | Purpose |
|-------|---------|
| `rustgate-core` | Shared types: Identity, RoutableMessage, FramingStrategy |
| `rustgate-cot` | Cursor on Target XML parsing |
| `rustgate-authz` | Policy engine for RBAC/ABAC authorization |
| `rustgate-transport` | mTLS listener, codec, CRL, FIPS provider, session management, routing engine |
| `rustgate-websocket` | WebSocket (wss://) listener with mTLS client authentication |
| `rustgate-mqtt` | MQTT 5.0/3.1.1 transport adapter with mTLS |
| `rustgate-nats` | NATS bridge for cross-instance messaging |
| `rustgate-enrollment` | HTTPS certificate enrollment server (CSR signing, PKCS#12) |
| `rustgate-proto` | Protobuf translation (XML / proto) |
| `rustgate-federation` | Server-to-server federation: V1 (XML), V2 (gRPC), HA, REST API |
| `rustgate-client` | Reference client library for connecting to a rustgate server |
| `rustgate-server` | Binary entry point, wires everything together |
| `rustgate-test-utils` | Shared test helpers (CA and cert generation) |

## Adding a New Crate

1. Create the crate directory under `crates/`
2. Add it to `members` in the root `Cargo.toml`
3. Inherit workspace fields: `version`, `edition`, `rust-version`, `license`, `repository`
4. Add `[lints] workspace = true` (unless the crate needs custom lint overrides)
5. Add a `[[licenses.exceptions]]` entry in `deny.toml` for the proprietary license
6. Add a `description` field for the crate

## Adding a new protocol schema-parity test

Every tactical-protocol crate ships a YAML schema and a `schema-parity`
proptest alongside the hand-rolled codec. The schema is a **declarative pin**
of the wire layout; the proptest asserts byte-identical round-trip between
the hand-rolled codec and the SchemaCodec runtime. See
[ADR 0018](docs/adr/0018-schema-first-codec-design.md) for the rationale and
[`docs/codec-schema-grammar.md`](docs/codec-schema-grammar.md) for the full
grammar reference.

**When to skip this step**: XML-based formats (CoT, NFFI) and protobuf-based
formats (SAPIENT, Meshtastic) are not amenable to the codec-schema vocabulary
— it targets fixed-offset binary wire formats only. Skip the schema YAML and
parity test for those; the hand-rolled codec carries the full discipline on
its own.

### Recipe (binary fixed-offset protocols)

1. **Add the schema YAML** at `crates/<crate>/schemas/<message>.yaml`.
   Start with the wire-layout table from the production codec's `decode` /
   `encode_into` source as the docstring. Cite the spec section. Use the
   smallest grammar version that expresses the layout (v1 for simple
   primitives, v3 for bit-packing, v5 for FX-continuation cascades — see the
   table in [`docs/codec-schema-grammar.md`](docs/codec-schema-grammar.md)).

2. **Promote `rustgate-codec-schema` to a dev-dep** in the crate's
   `Cargo.toml`. If the production codec is being migrated to use SchemaCodec
   at runtime (rare today — only STANAG 4586 vehicle_position decode has
   done this), make it a regular `[dependencies]` entry instead. Most new
   schemas should stay dev-only.

   ```toml
   [dev-dependencies]
   proptest = { workspace = true }
   # Schema-parity proptest pins byte-identical round-trip between
   # the hand-rolled codec and SchemaCodec.
   rustgate-codec-schema = { workspace = true }
   ```

3. **Add the parity test** at
   `crates/<crate>/tests/schema_parity_<message>.rs`. Use the inline
   reference-encoder pattern — **do not call the production codec for the
   reference side**. This is the load-bearing #1394 fix; an earlier
   iteration of the test pattern used `production::encode` for one half of
   the round-trip and missed the #1393 STANAG NaN regression because both
   halves shared the broken implementation.

   ```rust
   #![cfg(test)]
   #![allow(clippy::panic, clippy::unwrap_used)]

   use proptest::prelude::*;
   use rustgate_codec_schema::SchemaCodec;
   use rustgate_core::entity::EntityCodec;

   const SCHEMA_YAML: &str = include_str!("../schemas/<message>.yaml");

   fn schema_codec() -> SchemaCodec {
       SchemaCodec::from_schema_text(SCHEMA_YAML).expect("schema must parse + validate")
   }

   // Hand-coded reference encoder — does NOT call the production codec.
   fn reference_encode(input: &<Input>) -> Vec<u8> { /* ... byte-level writes ... */ }

   proptest! {
       #[test]
       fn schema_codec_byte_identical_to_reference(input in <strategy>()) {
           let reference = reference_encode(&input);
           let codec = schema_codec();
           let entity = codec.to_entity(&reference).expect("schema decode");
           let re_encoded = codec.from_entity(&entity).expect("schema encode");
           prop_assert_eq!(&re_encoded[..], &reference[..]);
       }
   }
   ```

   Optional but recommended:
   - A **public-API round-trip proptest** that exercises `production::encode`
     → `production::decode` and asserts every typed field. Catches
     field-zeroing regressions the schema parity test misses by construction
     (since the reference encoder is independent).
   - A **golden fixture** that pins a known wire byte pattern against a
     known logical input. Catches off-by-one regressions even if the proptest
     happens to skip the specific combination.

4. **Add a `### Added` entry to `CHANGELOG.md`** under `[Unreleased]`. Note
   the grammar features the schema exercises so the version arc stays
   discoverable.

5. **Add a row to the reference protocols table** in the workspace
   [`README.md`](README.md#schema-driven-codecs). Format follows the
   existing rows: protocol name, schema YAML link, parity test link, grammar
   features used.

### Quality gates

```bash
cargo nextest run -p rustgate-<crate> --test schema_parity_<message>
cargo +nightly fmt --all
cargo clippy --locked -p rustgate-<crate> --all-targets
```

### When the grammar genuinely cannot express the layout

If the schema validator rejects your YAML with an error you cannot work
around, **first check whether the layout fits one of the deferred grammar
features** (cross-byte spans, signed bit-packed, variable-shift `present-if`,
schema chaining — see the version table in
[`docs/architecture.md`](docs/architecture.md#when-to-add-a-new-grammar-feature)).

If a real protocol needs a feature that does not exist yet:

1. File an issue describing the layout and what grammar feature would
   unblock it. Include a wire-format snippet and the validator error.
2. Decide whether to add the grammar feature (a separate PR following
   ADR 0018's three bars — real protocol forcing function, existing grammar
   genuinely cannot express, backward-compatible) or skip the parity test
   for this protocol and document the gap.

The fallback is always "ship the hand-rolled codec without a parity test"
— that is the same situation every CoT / NFFI / SAPIENT / Meshtastic codec
is in today, and no codec has been blocked from landing because it could
not be schemed.

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

## Contributing a new feature

This is the end-to-end checklist a new contributor should follow when
adding a feature, fixing a bug, or shipping a docs change. The steps
below capture the discipline visible across recent merged PRs — issue
first, branch named after the issue, conventional commits, CHANGELOG
entry, quality gates, and a squash-only merge. If you are sending your
first PR, follow this list in order.

### 1. File a GitHub issue first

Open an issue before writing code. The issue body should describe:

- **The problem.** What is broken, missing, or unsafe today, and how a
  user or operator hits it. Link the runbook, design doc, or prior PR
  the problem was surfaced from.
- **The proposed solution.** A short sketch of the change you intend to
  make — which crate, which surface, and what the public-facing
  contract becomes (config keys, CLI flags, metric names, audit event
  names, error codes).
- **Out-of-scope items.** Explicit list of nearby work the PR will
  *not* do. Recent PRs frequently call this out so the reviewer knows
  which follow-up issues are deferred (see #803, #816, #882, #909
  for examples of multi-sub-item parent issues).

Wait for triage and discussion before starting code. If you would
rather pick from the existing backlog, browse issues labelled
`enhancement` or one of the `coverage`/`docs`/`refactor` labels and
ask in the issue thread before opening a PR.

### 2. Branch naming

Name the branch after the issue you are closing or referencing:

```
<type>/<issue-number>-<short-slug>
```

Allowed prefixes: `feat/`, `fix/`, `docs/`, `ci/`, `refactor/`,
`perf/`, `test/`, `chore/`. Examples from recent merges:

- `feat/952-jwks-rotation`
- `fix/723-cn-normalization`
- `docs/803-x509-stack`
- `refactor/795-federation-circuit`

For a security-flavoured change, **do not** use a `security/` prefix
on the branch — `security` is not one of commit-lint's allowed
conventional-commit types and the `commit-lint` job will fail. Use
`fix/` or `feat/` for the branch name and put the security framing in
the PR title and body instead. `SECURITY.md` covers the threat-model
side; the branch prefix only controls the commit-lint contract.

### 3. Conventional commit message

Commit messages follow Conventional Commits exactly:

```
<type>(<scope>): <description>

<body — what changed and why, references to issues>

Closes #N
```

`<type>` must be one of: `feat`, `fix`, `docs`, `deps`, `ci`,
`refactor`, `test`, `chore`, `style`, `perf`, `build`, `revert`. The
`commit-lint` CI job rejects anything else.

`<scope>` is the affected crate or area (e.g. `transport`,
`federation`, `mqtt`, `authz`). It is optional for cross-cutting
changes (`docs:`, `ci:`, `chore:`).

The commit body must reference the issue with either:

- `Closes #N` — when the PR fully resolves the issue. The issue
  auto-closes on merge.
- `Refs #N` — when the PR addresses one sub-item of a larger umbrella
  issue (e.g. shipping `F-141` of #816 while leaving `F-139`,
  `F-140`, `F-158` open). Do not use `Closes` if any sub-item is
  deferred.

#### Architecture Decision Records (ADRs)

Non-obvious architectural decisions go in `docs/adr/`. Use the
template at [`docs/adr/template.md`](docs/adr/template.md) — slim
Michael Nygard format with status, context, decision, alternatives,
and consequences. The new ADR is given the next four-digit prefix
(see [`docs/adr/README.md`](docs/adr/README.md) for the index) and a
kebab-case slug. Cross-reference the ADR file in the body of the
commit that implements the decision so the rationale travels with
the change. ADRs are for the kind of decision a future contributor
will hit and ask "why was this picked?" — locking primitives,
dependency choices where alternatives were viable, secret-handling
discipline. Routine implementation details, bug fixes, and per-
feature design notes do not need an ADR.

### 4. CHANGELOG entry

Every user-visible change appends an entry to `CHANGELOG.md` under
`## [Unreleased]` in the appropriate section:

- `### Added` — new features, new public API, new endpoints, new
  metrics, new config keys.
- `### Changed` — behaviour changes, refactors with externally
  visible effects, doc reorganisations.
- `### Fixed` — bug fixes (correctness, regressions, race
  conditions).
- `### Removed` — deleted public API, dropped features, retired flags.
- `### Security` — vulnerability fixes, hardening, threat-model
  changes.

Match the style of recent entries: a bold lead phrase with the issue
reference (`**<headline> (closes #N)** — …`), followed by a
multi-paragraph description that covers the problem, the change, and
the user-visible impact. Reviewers expect enough detail in the
CHANGELOG that a downstream operator reading only the changelog can
decide whether the change matters to them.

### 5. Quality gates (run locally before pushing)

```bash
# Format — CI uses nightly fmt
cargo +nightly fmt --all

# Clippy — all features the workspace ships, warnings as errors
cargo clippy --locked --workspace --all-targets \
  --features nats,enrollment,est,proto,full-detail,metrics,federation,federation-ha,websocket,mqtt,otel,http \
  -- -D warnings

# Tests for the affected crate
cargo test -p <affected-crate>

# Workspace tests under a single thread for any change that touches
# global Prometheus state — concurrent registration of the default
# registry is racy and will produce false failures otherwise.
cargo test --workspace --all-features -- --test-threads=1

# Dependency audit
cargo deny check
```

Two more checks the CI playbook-lint job enforces:

- **F-156 — every `#[allow(...)]` in production code requires a
  `// justification:` comment immediately above it** explaining why
  the lint cannot be fixed in place. The `playbook-lint` job runs
  `scripts/check-allow-justified.py` and fails the build with a
  pointer to the offending line if the justification is missing. See
  the "Allow annotations (F-156)" section above for the format.
- **Test files** standardise on
  `#![allow(clippy::panic, clippy::unwrap_used)]` at the top of the
  file. This is the workspace-wide convention so test setup can
  panic and `.unwrap()` on `Result` when convenient. The justification
  rule does not apply to tests (see "Exemptions" above).

### 6. Open the PR

- **Title.** Match the commit subject — Conventional Commits format,
  no trailing period.
- **Body.** Three to five short paragraphs covering the same ground
  as the issue: problem, change, user-visible impact, and any
  follow-ups. Include `Closes #N` or `Refs #N` on its own line so the
  GitHub issue auto-link works. Cross-link runbooks, design docs, or
  related PRs.
- **Cross-links to discipline docs**, where relevant:
  - `SECURITY.md` for any security-relevant change (threat model,
    customer-facing posture, vulnerability triage).
  - `docs/authorization.md` for changes that touch the authz engine,
    PEP boundaries, or obligation chaining.
  - `docs/concurrency-model.md` for changes that introduce or modify
    shared state, locks, or the router/dedup hot path.
  - `docs/runbooks/audit-chain-corruption.md` for any change that
    touches the hash-chained audit log on disk.
  - `.claude/rules/shared-infrastructure.md` for the workspace
    primitives (audit, masking, sanitization, resilience, socket
    helpers). Note: this file is `.gitignore`d locally — reviewers
    consult their own copy. Reference it by path in the PR body when
    you have reused a primitive listed there.

### 7. CI gates

The required CI checks (enforced by branch protection on `main`) all
must pass before a PR is mergeable:

- `commit-lint`, `lint`, `clippy`, `check-features`, `test`,
  `coverage`, `fips`, `post-quantum`, `audit`, `helm`, `docker` (the
  eleven jobs listed in the *Code Quality* section above).
- `msrv` — pins the published minimum supported Rust version (1.94)
  and runs `cargo check` against it. A change that requires a newer
  toolchain must bump `[workspace.package].rust-version` in the root
  `Cargo.toml` and call out the bump in the CHANGELOG.
- `cargo-deny` advisory checks — license, advisory, ban, and source
  audits run as the `audit` job.

### 8. Review and merge

- Maintainers may request changes. Push follow-up commits to the same
  branch — **do not force-push** rewrites of already-reviewed history
  unless explicitly asked. CI re-runs on every push.
- Pre-commit hook failures should be fixed and re-committed as a new
  commit; do not amend after review has started.
- If your PR touches a security-critical path listed in
  [`.github/CODEOWNERS`](.github/CODEOWNERS) (the authz engine, the
  enrollment surface, the TLS verifier, the SPIFFE / cert-reloader /
  quota plumbing, the encrypted-archive key ring, the hash-chained
  audit log, the audit event vocabulary, the secret-file reader, the
  PII masking helpers, or the federation JWT / JWKS layer), the
  maintainer review is requested **automatically** — don't be
  surprised when GitHub adds the review request the moment you push.
- The repo is configured for **squash-only merges**. The squashed
  commit takes the PR title as its subject, so the title must
  satisfy Conventional Commits and `commit-lint` on its own.
- After merge, delete the feature branch and clean up your local
  worktree. The squashed commit on `main` carries the `Closes #N`
  trailer and GitHub closes the issue automatically.
