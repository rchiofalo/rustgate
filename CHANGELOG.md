# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed

- **Federation TTL re-check at forward boundary** — the federation manager now re-evaluates each message's TTL immediately before queuing it to peer outbound channels via the new `FederationManager::forward_with_metadata` API. Messages whose `received_at + ttl` has elapsed between local routing and federation forwarding are dropped with a warning instead of consuming peer bandwidth. A new `rustgate_federation_forward_ttl_expired_total` Prometheus counter (under the `api` feature) tracks drops, and the `federation` snapshot endpoint exposes the same value as `forward_ttl_expired`. The legacy `forward(payload, groups)` entrypoint is preserved for callers that have no TTL context. (#554)

### Added

- **Configurable enrollment CSR signing rate limit** — the enrollment server's per-IP CSR signing throttle is now exposed via the new `--enrollment-rate-limit` CLI flag (env `RUSTGATE_ENROLLMENT_RATE_LIMIT`, default 10 requests per source IP per minute). Rejected requests continue to return HTTP 429 with a `rate limit exceeded` body and emit a structured `rate_limit.triggered` audit event. A new `rustgate_enrollment_rate_limited_total` Prometheus counter is registered under `--features metrics` and incremented from a callback wired into `EnrollmentServer::with_rate_limit_callback`. Setting the flag to 0 disables the throttle (not recommended). (#552)
- **Persistent de-identified access log** — new `--access-log` CLI flag (env `RUSTGATE_ACCESS_LOG`, `"-"` for stdout) opts into a per-message access log written as JSON lines to a dedicated sink. Implemented as a `tracing-subscriber` layer that filters `target="access"` events, mirroring the existing `--audit-log` plumbing. `Router::route` now emits one structured event per routed message with fields `src_cn`, `dst` (`direct:<sha256-cn-hash>` for unicast — the destination CN is hashed and truncated to 12 hex chars to avoid leaking PII — `group:<id>`, or `broadcast`), `msg_uid` (extracted from CoT XML payloads via a bounded scan, empty for non-CoT), `size`, `proto` (source transport), and `outcome` (`delivered`, `dedup`, or `expired`). Emission is gated behind `tracing::enabled!`, so when no access subscriber is attached the cost is a single O(1) filter check. (#558)
- **Global admission control / backpressure** — new `--max-queued-bytes` CLI flag (env `RUSTGATE_MAX_QUEUED_BYTES`, default 512 MiB) caps the total in-flight routed bytes tracked across all sessions. When the counter crosses the high-water mark, the TLS accept loop is **deferred** (not errored) until the counter drops back below the low-water mark, which defaults to 90% of the high-water value and is overridable via `--max-queued-bytes-low-water`. Implemented as a shared `BackpressureGate` (AtomicUsize + `tokio::sync::Notify`) wired into `Router::route` via an RAII permit that releases its byte reservation on drop, making accounting panic-safe. Two new Prometheus metrics track the gate: `rustgate_queued_bytes` (gauge) and `rustgate_admission_deferred_total` (counter). Prevents a flood of slow readers from exhausting server memory on top of the existing per-session circuit breakers. (#551)
- **Per-client store-and-forward with bounded disk queue** — messages destined for a disconnected CN are now persisted to an embedded `redb` (MIT/Apache-2.0) database and drained on reconnect before live traffic resumes. Opt-in via the new `--client-queue-dir` CLI flag (env `RUSTGATE_CLIENT_QUEUE_DIR`); disabled by default, in which case offline messages continue to be dropped as before. A global byte cap configured via `--client-queue-max-bytes` (default 100 MiB, env `RUSTGATE_CLIENT_QUEUE_MAX_BYTES`) bounds total on-disk usage with drop-oldest FIFO eviction across all CNs. The queue survives server restarts: the in-memory index is rebuilt from the existing database on open. Prometheus metrics `rustgate_client_queue_depth`, `rustgate_client_queue_bytes` (gauges labelled by bucketed `identity_cn`), `rustgate_client_queue_drops_total`, and `rustgate_client_queue_drains_total` (counters) are registered under `--features metrics`, with CN label cardinality bounded by the existing `--metrics-identity-allowlist` mechanism. (#548)
- **Cross-path message deduplication** — new `--dedup-window-secs` CLI flag (env `RUSTGATE_DEDUP_WINDOW_SECS`, default 0 = disabled) enables a router-level LRU dedup cache keyed by `SHA-256(uid || 0x00 || time_le || 0x00 || payload)`. When the same logical message arrives via multiple ingress paths (e.g. a direct client and a federation peer that forwarded it) within the configured window, the router suppresses duplicates before dispatch so subscribers receive each message exactly once. For CoT XML the `uid` attribute is extracted from the payload; for non-CoT payloads (protobuf, raw binary) `uid` is empty and the key degenerates to a pure content hash, so byte-identical protobuf/binary payloads are deduped as well. The cache size is bounded via `--dedup-cache-size` (env `RUSTGATE_DEDUP_CACHE_SIZE`, default 100000); evictions follow LRU order, and entries older than the window are lazily replaced on lookup. Suppressed duplicates are counted by the new `rustgate_dedup_hits_total` Prometheus counter, and current occupancy is exposed via `rustgate_dedup_cache_size`. Because the full payload is folded into the hash, messages sharing a `uid` but with different bytes are treated as distinct. Disabled by default to preserve existing behavior. (#549)
- **`rustgate-client` reference crate** — new workspace member providing an ergonomic client API on top of the existing `rustgate-transport` codecs. Exposes `Client::connect`, `Client::send`, `Client::subscribe`, and `Client::disconnect`, plus a `ClientConfig` builder with mTLS PEM file/byte sources, codec selection, plaintext fallback for tests, optional connect timeout, and opt-in auto-reconnect with exponential backoff (100 ms → 30 s, configurable max attempts). Reuses `FramedCodec` from the transport crate so client and server cannot drift. Includes an `examples/echo.rs` reference echo client and replaces ad-hoc TLS bring-up in two transport integration tests. (#550)
- **TOML configuration file support** — new `--config <path>` CLI flag (env `RUSTGATE_CONFIG`) loads a TOML file whose keys mirror the existing CLI flag names (kebab-case). Settings are merged in the order **defaults → file → environment variables → CLI flags**, so command-line arguments and environment variables always override file values. Two new utility subcommands ship alongside the flag: `rustgate print-config` writes the effective merged configuration as TOML to stdout, and `rustgate validate-config` parses the file (rejecting unknown keys and missing required fields) and exits non-zero on error. The config file is loaded via the `figment` crate (Apache-2.0/MIT) with the TOML provider; running the server with no subcommand continues to start the listener as before. (#547)
- **OCSP stapling for server certificates** — new `ocsp` feature flag adds OCSP response stapling to the TLS handshake using the `ocsp-stapler` crate (MPL-2.0). When enabled with `--ocsp-stapling` (env `RUSTGATE_OCSP_STAPLING`), the server's certificate resolver is wrapped with `ocsp_stapler::Stapler`, which fetches OCSP responses for the active certificate in a background tokio task and attaches them to the handshake so clients can verify revocation status without contacting the issuing CA. Coexists with the existing CRL-based client certificate verification (the two operate on opposite sides of the handshake). Most useful with enterprise/private CAs that operate their own OCSP responder; Let's Encrypt dropped OCSP support in 2025. The first handshakes after startup may be served without a stapled response until the background fetcher completes its initial cycle. The stapler is gracefully stopped during shutdown. (#524)
- **Per-identity Prometheus metrics with bounded cardinality** — `rustgate_messages_routed_total` and `rustgate_messages_dropped_total` now carry an `identity_cn` label so operators can attribute routing volume and rate-limit drops to individual clients. Cardinality is bounded by an optional CN allowlist loaded from `--metrics-identity-allowlist` (env `RUSTGATE_METRICS_IDENTITY_ALLOWLIST`, one CN per line, `#` comments allowed); CNs not in the allowlist — and **all** CNs when the allowlist is unset — collapse into the literal `"other"` bucket, capping per-identity cardinality at 1 by default. New `--metrics-per-identity` flag (env `RUSTGATE_METRICS_PER_IDENTITY`, default false) opt-in registers Tier 2 per-identity metrics: `rustgate_per_identity_handshake_failures_total`, `rustgate_per_identity_session_duration_seconds`, `rustgate_per_identity_bytes_sent_total`, and `rustgate_per_identity_bytes_received_total`. Tier 2 metrics are not registered when the flag is disabled, imposing zero overhead. (#526)
- **SIGHUP config reload** — on Unix, sending `SIGHUP` to the running server now reloads the server certificate (via the existing `CertReloader`), the group ACL policy (via the existing `AclReloader`), and re-validates the configured CRL file from disk. Each component is reloaded independently — failures in one do not abort the others — and structured `target="audit", event_type="config.reload"` events are emitted per component with `result=success|failure`. SIGHUP reload is Unix-only; on other platforms the handler is not installed. CRL reload re-parses and freshness-checks the file but does not yet swap CRLs into the live TLS listener; applying CRL changes to in-flight handshakes still requires a server restart. (#528)
- **ACL REST API authentication** — new `--acl-api-token-file` CLI flag (env `RUSTGATE_ACL_API_TOKEN_FILE`) guards the `/api/acl/` endpoints with a bearer token. When unset, the ACL API is not registered at all and `/api/acl/` requests fall through to 404. When set, every request must present `Authorization: Bearer <token>` and the token is compared in constant time. Mutations (`PUT`/`DELETE`) are now persisted atomically to the configured `--group-acl-file` (write-to-tmp + fsync + rename) and the hot reloader's cached hash is updated so the next poll does not re-detect the change. Group identifiers are validated against a strict `[A-Za-z0-9_.:-]{1,128}` allow list. (#538)
- **JSON audit log sink** — new `--audit-log` CLI flag (env `RUSTGATE_AUDIT_LOG`) writes audit events as JSON lines to a dedicated file, separate from the main log stream. Filters only `target="audit"` events using a per-layer `Targets` filter. Use `"-"` for stdout. Audit events now include `session_id` on connect/disconnect for correlation. (#525)
- **ACL deny rules** — `GroupAcl` now supports optional `deny_send` and `deny_receive` lists alongside the existing allow lists. Deny is evaluated first and overrides allow, enabling fine-grained block-list semantics: a CN appearing in a deny list cannot send/receive even when also in the allow list. With an empty allow list, the deny list acts as a pure block list (the group is open except for denied CNs). Legacy ACL JSON files without `deny_send`/`deny_receive` continue to parse unchanged. (#523)
- **ACL management REST API** — new `/api/acl/` endpoints exposed on the metrics HTTP server (mirrors the `/api/federation/` pattern). Supports `GET /api/acl/groups` to list current rules, `PUT /api/acl/groups/{group}` to upsert an entry, `DELETE /api/acl/groups/{group}` to remove one, and `POST /api/acl/reload` to re-read the on-disk ACL file. Mutations rebuild the full policy and atomically swap it on the router via `ArcSwap`. (#522)
- **Hot-reloadable ACL** — the group access control policy can now be updated at runtime without restarting the server. The router's ACL is stored in an `ArcSwap` for lock-free reads, and a new `--acl-reload-interval` CLI flag (env `RUSTGATE_ACL_RELOAD_INTERVAL`, default 0 = disabled) enables periodic polling of the `--group-acl-file` for changes. File changes are detected via SHA-256 hash comparison; only modified files trigger a policy swap. Audit events are emitted on reload success and failure. (#521)
- **Message priority channels** — replaced the single per-session mpsc channel with a dual-channel approach: a high-priority channel (capacity 16) for Position and Alert messages, and a normal-priority channel (capacity 64) for all other message types. Write loops use biased `tokio::select!` to always drain priority messages first, ensuring time-sensitive situational awareness data is delivered ahead of bulk traffic. The circuit breaker applies across both channels. (#519)

### Fixed

- **Store-and-forward ordering, async safety, and naming** — several correctness bugs in the per-client store-and-forward queue (#548): (1) the reconnect sequence now drains the offline queue **before** registering the session with the router, so live traffic routed mid-handshake can no longer slip ahead of queued messages (FIFO across the reconnect boundary is now strict across TLS, plaintext TCP, and WebSocket transports); (2) `ClientQueue::enqueue` no longer performs `redb::begin_write` + `commit` on the async router worker — persistence is handed off via a bounded `tokio::sync::mpsc` channel to a dedicated writer task that commits inside `spawn_blocking`, with a new `rustgate_client_queue_writer_drops_total` counter for overflow; (3) `peek_cn` was renamed to `peek_dest_cn` with corrected docs, and on reopen non-direct (broadcast/group) entries are now skipped and counted via `rustgate_client_queue_skipped_unsupported_total` rather than warned as malformed; (4) TTL is now enforced on drain, skipping expired entries and incrementing `rustgate_client_queue_expired_total`; (5) new `rustgate_client_queue_enqueues_total` counter surfaces the offline write rate; (6) the router's `send_to_session` failure log was corrected from "session channel full or disconnected" to "session channel closed" since `tokio::mpsc::Sender::send().await` only errors on receiver close.

### Changed

- **GroupAcl default semantics restored** — an ACL entry with an empty allow list and empty deny list again denies all sends and receives, matching the pre-deny behavior. The deny-rule extension (#523) accidentally flipped the empty allow list to mean "open", which silently relaxed existing policies. Block-list mode (empty allow, non-empty deny) is unchanged. (#538)
- **Audit log append mode** — the `--audit-log` file is now opened with create+append instead of truncated, preserving existing audit events across restarts. (#538)

## [0.7.0] - 2026-04-05

### Added

- **Post-quantum key exchange** — new `post-quantum` feature flag enables hybrid X25519MLKEM768 key exchange via aws-lc-rs. PQ-capable clients negotiate hybrid PQ+classical key exchange; others fall back to X25519 transparently. Negotiated key exchange group is now logged for every TLS connection (transport, federation, WebSocket). New CLI flag `--prefer-post-quantum` (env `RUSTGATE_PREFER_POST_QUANTUM`). Requires Go 1.20+ and cmake at build time (same as `--features fips`). (#496, #498)
- **Configurable key exchange groups** — new `--kx-groups` CLI flag (env `RUSTGATE_KX_GROUPS`) allows operators to set the TLS key exchange group preference order at runtime. Comma-separated group names: `X25519MLKEM768`, `SECP256R1MLKEM768`, `MLKEM768`, `MLKEM1024`, `X25519`, `secp256r1`, `secp384r1`. Requires `--features post-quantum`. (#497)
- **Post-quantum integration tests** — `pq_kex.rs` test suite verifies PQ provider installation, X25519MLKEM768 key exchange negotiation, mTLS handshake, CRL composition, and `parse_kx_groups()` validation. CI job `post-quantum` runs clippy, build, and tests with `--features post-quantum`. (#499)
- **Certificate revocation and CRL generation** — new `POST /api/revoke` endpoint revokes certificates by serial number, persisted to a JSON revocation database (`--revocation-db`, env `RUSTGATE_REVOCATION_DB`). CRLs are automatically generated and signed by the enrollment CA, served via `GET /api/crl` as PEM. `GET /api/revoked` lists all revoked entries. Configurable CRL validity period (`--crl-validity-days`, env `RUSTGATE_CRL_VALIDITY_DAYS`, default 7). Revocation reasons supported: `key_compromise`, `ca_compromise`, `superseded`, `cessation_of_operation`, `affiliation_changed`, `privilege_withdrawn`. (#411)
- **HA fencing tokens** — peer ownership claims now carry monotonically increasing fencing tokens (NATS KV revisions) to prevent split-brain in multi-pod deployments. During adoption, the fencing token is re-validated after the delay period to detect stale claims. The connection registry stores fencing tokens alongside connection metadata for observability. Backward-compatible: pods without fencing support interoperate via `Option<u64>` with `#[serde(default)]`. (#458)
- **Data package signature verification** — optional detached signature field on data package uploads. When `--package-signature-ca` is set, uploaded signatures are verified against the CA public key (ECDSA P-256 SHA-256 and RSA-PSS SHA-256). Enable `--package-strict-signatures` to reject unsigned packages. Signatures are stored in metadata, returned in upload/search responses, and served via `X-Package-Signature` header on download. Backward-compatible with existing unsigned packages. (#423)
- **Crypto agility strategy** — `docs/crypto-agility.md` documenting the approach to algorithm migration: feature-gated backends, TLS negotiation, backward-compatible rollout, certificate algorithm migration path, federation crypto alignment, and emergency algorithm disable procedures. (#456)
- **REST API reference documentation** — comprehensive `docs/rest-api.md` covering all HTTP endpoints: metrics/health probes, federation peer management, certificate trust store, enrollment/signing, data packages, and WebSocket transport. Includes request/response schemas, authentication requirements, rate limits, curl examples, and status codes. (#454)
- **Operational documentation** — troubleshooting guide, performance tuning guide, disaster recovery procedures, and four new runbooks (certificate rotation, CRL updates, WebSocket connection storms, TLS handshake failures) (#450, #451, #452, #453)
- **NATS JetStream pull consumer** — subscriber uses a durable JetStream pull consumer for real backpressure instead of buffered push subscriptions. Messages are explicitly acknowledged after processing; the NATS server retains undelivered messages in the stream until the consumer catches up. Configurable via `--nats-live-stream` (env `RUSTGATE_NATS_LIVE_STREAM`, default `RUSTGATE_LIVE`) and `--nats-max-ack-pending` (env `RUSTGATE_NATS_MAX_ACK_PENDING`, default 1000). (#415)
- **JetStream resumption checkpoints** — optional checkpoint file (`--nats-checkpoint-path`, env `RUSTGATE_NATS_CHECKPOINT_PATH`) persists the last processed sequence number so restarts resume from the checkpoint instead of replaying the entire history stream. (#413)
- **Federation replay buffer** — bounded per-peer ring buffer (`--federation-replay-buffer-size`, env `RUSTGATE_FEDERATION_REPLAY_BUFFER_SIZE`, default 1000) stores recent forwarded messages. On reconnection, missed messages can be replayed from the buffer before resuming the live stream. Set to 0 to disable. (#409)
- **WebSocket per-connection rate limiting** — configurable frame-rate (`--ws-max-frames-per-sec`) and byte-rate (`--ws-max-bytes-per-sec`) limits per WebSocket connection. Clients exceeding limits have frames dropped; sustained violations trigger disconnection (`--ws-max-violations`, default 10). All disabled by default for backward compatibility. (#422)
- **Session circuit breaker** — disconnects slow sessions after consecutive send failures exceed a configurable threshold (`--circuit-breaker-threshold`, default 10, env `RUSTGATE_CIRCUIT_BREAKER_THRESHOLD`). Prevents a single backpressured client from degrading group routing for other sessions. Set to 0 to disable. (#420)
- **Per-group access control** — optional JSON-based ACL configuration (`--group-acl-file`, env `RUSTGATE_GROUP_ACL_FILE`) enforces per-group send and receive permissions at router dispatch. Groups listed in the ACL file restrict which certificate CNs may send to or receive from the group. Groups not listed operate in open mode (any member can send/receive), preserving backward compatibility. (#416, #417)

## [0.6.0] - 2026-04-04

### Changed

- **Standardized environment variable prefixes** — all environment variables now use the `RUSTGATE_` prefix for consistency and to avoid collisions with other services. `NATS_*` → `RUSTGATE_NATS_*`, `FEDERATION_*` → `RUSTGATE_FEDERATION_*`, `ENROLLMENT_*` → `RUSTGATE_ENROLLMENT_*`, `METRICS_BIND` → `RUSTGATE_METRICS_BIND`, `WEBSOCKET_BIND` → `RUSTGATE_WEBSOCKET_BIND`, `DATA_PACKAGE_DIR` → `RUSTGATE_DATA_PACKAGE_DIR`. `OTEL_*` vars unchanged (OpenTelemetry standard). **Breaking change** — update deployment configs, Helm values, and shell scripts. (#392)
- **WebSocket codec migration** — WebSocket transport now uses the unified `Codec` trait (`Arc<dyn Codec>`) instead of the legacy `WsEncoding` enum and `MessageEncoder` trait. Removed `WsEncoding`, `MessageEncoder`, `RawEncoder`, `CotEncoder`, and `TakProtobufEncoder`. The `WsServerConfig.encoding` field is replaced by `WsServerConfig.codec`. (#391)

### Added

- **Pluggable codec architecture** — unified `Codec` trait in `rustgate-core` replaces the separate `Framing`/`Encoding` dispatch. Each wire protocol (`TakXmlCodec`, `TakProtobufCodec`, `RawLineCodec`, `RawLengthPrefixedCodec`) implements a single trait covering framing strategy, payload decode/encode, and protocol detection. Session handling uses `Arc<dyn Codec>` instead of enum-matching, simplifying the read/write loops and enabling future custom codecs. Existing `--framing`/`--encoding` CLI flags are preserved via a factory function. (#184)
- **Server certificate hot-reload** — `--cert-reload-interval` enables periodic polling of the `--cert` and `--key` files. When changes are detected (via SHA-256 digest comparison), the server certificate is atomically swapped for new TLS handshakes without restart or downtime. Audit events emitted on rotation success/failure. (#291)
- **OpenTelemetry distributed tracing** — optional `otel` feature flag adds OTLP trace export via `--otel-endpoint`. Key spans instrumented: TLS handshake, message routing, federation forwarding, NATS publish/subscribe. Works with Jaeger, Grafana Tempo, and any OTLP-compatible backend. (#281)
- **Dynamic TLS config refresh** — trust store certificate changes (add/remove via REST API or filesystem) take effect on the next TLS handshake without server restart. Inbound V1 uses a `DynamicCertVerifier`, outbound V1 uses a `DynamicPeerConnector` that rebuilds `ClientConfig` on generation change. (#192)
- **Circuit breaker metrics and audit events** — Prometheus counters for circuit breaker trips/recoveries and structured audit events for state transitions (#289)
- **External Secrets Operator support** — optional ExternalSecret templates for NATS, enrollment, and federation secrets with configurable `secretStoreRef` and `refreshInterval` (#275)
- **Anti-replay detection** — sliding-window filter drops messages with duplicate `(uid, time)` pairs within a configurable window, preventing message replay attacks. Configurable via `--replay-window` (default 300s, 0 to disable). (#284)
- **Comprehensive documentation** — configuration reference completeness (plaintext, rate limiting, CRL, archive, federation V2/HA, OTel sections), STRIDE threat model, graceful degradation policy, post-quantum TLS roadmap, expanded NIST 800-53 control mapping (CP, IR, RA, CA families), module-level docs across all source files, XML-to-protobuf field loss documentation, metrics endpoint security warning, position cache TTL semantics (#261, #256, #263, #279, #280, #290, #295, #308, #311)
- **FIPS-enabled release binaries** — release workflow produces FIPS 140-3 binaries (aws-lc-rs) for x86_64-unknown-linux-musl and aarch64-unknown-linux-gnu alongside standard binaries. aarch64 FIPS uses gnu target because aws-lc-fips-sys is incompatible with musl cross-compilation. CI validates FIPS cross-compilation for both targets. (#366)

### Fixed

- **Timestamp parsing panics** — prevent panics when CoT and protobuf parsers encounter malformed timestamps with out-of-range values (#371)

### Security

- **Quarterly advisory review** — upgraded async-nats 0.46→0.47, resolving RUSTSEC-2025-0134 (rustls-pemfile unmaintained) and RUSTSEC-2026-0049 (rustls-webpki CRL matching). RUSTSEC-2026-0042 (aws-lc-sys) was previously resolved. All advisory ignores removed from deny.toml — zero known vulnerabilities. (#239)

## [0.5.0] - 2026-04-01

### Added

- **TLS handshake concurrency limiting** — configurable semaphore to bound concurrent TLS handshakes and prevent resource exhaustion (#345)
- **CRL freshness validation** — warn on stale CRLs whose `nextUpdate` has passed; configurable via `--crl-warn-stale` (#347)
- **Configurable TLS version minimum** — `--tls-min-version` flag to enforce TLS 1.3-only mode; key usage validation on client certificates (#348)
- **Per-connection WebSocket rate limiting** — reuses `--client-message-rate` and `--client-burst` config for WebSocket sessions (#346)
- **NATS mTLS support** — client certificate authentication for NATS broker connections via `NatsTlsConfig` (#342)
- **Sensitive data masking** — `mask_cert_serial`, `mask_ip`, `mask_credential` utilities for structured log fields (#343)
- **Security audit events** — CRL reload, enrollment certificate issued, rate limit triggered, TLS handshake failed audit events (#343)
- **Identity validation** — `Identity::new()` returns `Result` with validation errors for empty CN/fingerprint (#334)
- **Structured fuzzing** — `Arbitrary` trait implementations behind `fuzz` feature flag for `RoutableMessage` and `CotEvent` (#341)
- **Fuzz targets** — JWT parse, CSR parse, NATS wire event, WebSocket frame, CRL parse, and protobuf roundtrip fuzz targets (#344)
- **Image digest pinning** — Helm deployment supports `image.digest` for immutable container references (#340)
- **NetworkPolicy** — Helm template for network-level pod isolation, enabled in production values (#340)
- **Integration tests** — 150+ new tests across core types, proto codec, server CLI/TLS, and feature gates (#359, #361, #362, #363)
- **1100+ tests** — up from 887 in v0.4.0

### Fixed

- **Position cache memory exhaustion** — bounded cache size prevents unbounded growth (#316)
- **JWT revocation cache memory exhaustion** — bounded cache with LRU eviction (#315)
- **ClientThrottle integer overflow** — prevent token refill overflow on long-running connections (#317)
- **Federation forward lock contention** — snapshot client list to reduce hold time during message forwarding (#318)
- **Helm image tag** — corrected to match workspace version (#319)
- **Workspace dependency inheritance** — enforced for socket2, prost-build, tikv-jemallocator (#320)
- **Certificate field sanitization** — escape JSONL output and bound NATS token length (#322)
- **Enrollment rate limiter pruning** — periodic cleanup of expired entries; URL-decode query parameters (#321)
- **JWT HMAC implementation** — replaced custom HMAC with `hmac` crate; enforce minimum secret length (#323)
- **Silent message drops** — added structured logging for dropped messages in router and federation (#324)
- **Async archive I/O** — moved archive writes off the async event loop; removed `block_on` from federation tests (#325)
- **Dead metrics code** — removed unreachable metrics paths; added `Display` impls; fixed CRL serial number formatting (#330)
- **Group membership bounds** — limit groups per CN and federation peer to prevent resource abuse (#332)
- **Hot-path heap allocation** — eliminated per-message allocations in routing; added HashMap capacity hints (#333)
- **`expect()` calls** — replaced remaining `expect()` in federation and server with fallible alternatives (#339)
- **Bounded HA channels** — federation HA peer event channels capped at 256 to prevent unbounded queue growth (#338)

### Changed

- **Structured error types** — `RustgateError::Transport(String)` and `Config(String)` replaced with `TransportError` and `ConfigError` sub-enums for precise error matching (#350)
- **PeerId and ServerName newtypes** — strongly-typed identifiers replace loose `String` usage across federation, server, and audit code (#351)
- **Centralized constants** — duplicated timeout and buffer constants extracted to `rustgate_core::constants` (#349)
- **Shared TCP keepalive** — `configure_tcp_keepalive()` extracted to `rustgate_core::net`, replacing 4 identical implementations (#354)
- **Shared PEM parsing** — `parse_certs`, `parse_key`, `parse_ca_store` extracted to `rustgate_transport::pem` module (#353)
- **Reconnection utilities** — `backoff_delay` and `should_stop_reconnecting` consolidated into `rustgate_federation::reconnect` (#352)
- **Federation module splits** — `v2/convert.rs` split into `cot_to_event`, `routable_message`, `timestamps` submodules (#358); `api.rs` split into `handlers`, `helpers`, `types` submodules (#357); callback creation extracted to helpers (#355)
- **Enrollment module split** — `server.rs` split into `handlers/sign`, `handlers/api`, `handlers/packages`, `handlers/util` (#356)
- **Test helper consolidation** — shared TLS helpers in `rustgate_test_utils::tls` replace duplicated code across 6 test files (#360)
- **Safe indexing** — replaced pointer arithmetic in enrollment with safe slice indexing (#336)
- **Dependency migration** — migrated from `rustls-pemfile` to `rustls-pki-types` PEM parsing (#335)

### Security

- **CI workflow hardening** — minimal token permissions, credential isolation, harden-runner, dependency-review, cargo-auditable (#206, #331)
- **CodeQL SAST** — static analysis scanning with pinned Trivy download (#214)
- **Nightly security scanning** — auto-create issues for dependency vulnerabilities; container image scanning (#210, #212)
- **aws-lc-rs vulnerability fix** — updated aws-lc-rs to resolve 3 HIGH severity CVEs (#208)
- **SECURITY.md** — updated supported versions and environment variable references (#337)

## [0.4.0] - 2026-03-06

### Added

- **Federation TrustStore integration** — dynamic CA trust for federation TLS handshakes; new CAs take effect on the next connection without restart (#191)
- **Federation HA claim manager wiring** — distributed peer ownership via NATS KV atomic claims integrated into the federation manager (#193)
- **Per-peer circuit breaker** — automatic backoff on repeated federation connection failures with configurable thresholds (#182)
- **V1 loop detection** — message deduplication prevents routing loops in V1 federation protocol (#190)
- **V2 provenance checking** — inbound and outbound provenance validation for V2 federation messages (#189)
- **887 tests** — up from 818 in v0.3.0

### Fixed

- **NATS test server startup flakiness** — shared `TestNatsServer` in `rustgate-test-utils` with retry logic and fast-fail on port conflicts (#195)
- **Release docker workflow cascading failures** — best-effort guards on post-push steps prevent attestation/Trivy failures from failing the entire job (#194)
- **Cross-compilation FIPS builds** — install Go 1.22.12 from go.dev in `Cross.toml` (distro `golang` was 1.10.4, `aws-lc-fips-sys` requires >= 1.17.13)
- **Nightly fuzz rustup** — fix cross-device rename error in fuzz CI (#181)
- **Scorecard workflow** — skip on private repos where `persist-credentials: false` blocks cloning
- **Test timeouts** — increase timeouts for coverage instrumentation overhead (#183)

### Changed

- **Project branding** — add project logo, OpenSSF Scorecard badge, and NIST 800-53 security posture to documentation (#180)

## [0.3.0] - 2026-03-05

### Changed

- **CI pipeline** — 10 parallel jobs: commit-lint, lint, clippy, check-features (cargo-hack powerset), test (nextest), coverage (tarpaulin), fips, audit, helm, docker
- **Branch protection** — `main` requires all CI status checks to pass before merge

### Added

- **CRL revocation** — PEM-encoded Certificate Revocation List support via `--crl`; revoked certificates are rejected at the TLS handshake before reaching the application layer
- **FIPS 140-3 crypto** (feature-gated: `fips`) — aws-lc-rs crypto provider for FIPS-validated TLS, certificate signing (rcgen), and PKCS#12 salt generation; runtime enforcement via `--fips-required`
- **TLS session resumption disabled** — forces full handshake with certificate verification on every connection, ensuring CRL checks cannot be bypassed via cached sessions
- **Plaintext input** — TCP (`--tcp-bind`) and UDP (`--udp-bind`) listeners for trusted-network scenarios with configurable default CN and group
- **Per-client rate limiting** — `--client-message-rate` and `--client-burst` for per-connection message throttling
- **CoT event archival** — structured JSONL logging of all received events to date-stamped files via `--archive-dir`
- **Data package expiration** — `--package-max-age-hours` for automatic cleanup of uploaded data packages
- **Audit logging** — structured event logging for connection lifecycle and federation events
- **Marti contact API** — `/Marti/api/contacts/all` and `/Marti/api/clientEndPoints` endpoints for client contact discovery
- **Data package support** — upload, download, and keyword search for data packages via `/Marti/sync/` endpoints
- **Directional group routing** — group-aware message filtering for federation peers
- **Fuzz targets** — cargo-fuzz targets for XML stream codec, CoT parser, TAK frame codec, length-prefixed codec, and federation converter
- **Criterion benchmarks** — throughput benchmarks for CoT parsing, codec encode/decode, and federation XML conversion
- **Container security scanning** — Trivy vulnerability scanning with SARIF upload in release workflow; cargo-audit in CI
- **Binary release artifacts** — cross-compiled static binaries for x86_64 and aarch64 linux-musl via GitHub Release
- **818 tests** — up from 639 in v0.2.0

## [0.2.0] - 2026-03-01

### Added

- **Server-to-server federation** (feature-gated: `federation`) — share situational awareness between independent server networks via the federation protocol
- **V1 federation protocol** — length-prefixed XML over mTLS for legacy server compatibility, with CoT heartbeat monitoring (30s interval, 90s timeout) and automatic reconnection with exponential backoff
- **V2 federation protocol** — gRPC FederatedChannel service over mTLS with 5-stream handshake, group exchange, health checks (5s interval, 15s timeout), and bidirectional event streaming
- **Provenance-based loop detection** — federation messages carry a server chain and hop counter; messages are dropped when a loop is detected or the configurable hop limit (default 10) is exceeded
- **Federation manager** — orchestrates all inbound and outbound peer connections, protocol selection (V1/V2 per-peer), group-aware forwarding, and NATS ↔ federation bridging with echo prevention
- **Dynamic CA trust store** — add and remove trusted CA certificates at runtime without restart; new CAs take effect on the next TLS handshake
- **Persistent peer storage** — JSON file backend for single-pod deployments; NATS KV backend with cross-pod sync for multi-pod clusters
- **HA mode** — distributed peer ownership via NATS KV atomic claims with 30s TTL and 10s refresh; automatic adoption of orphaned peers after pod failure with configurable delay
- **Federation REST API** — peer CRUD, certificate management, connection status, and aggregated statistics endpoints mounted under `/api/federation/`
- **Federation Prometheus metrics** — `federation_connections` gauge, `federation_messages_in_total` / `federation_messages_out_total` / `federation_errors_total` / `federation_heartbeats_total` counters
- **Federation CLI flags** — `--federation-v1-bind`, `--federation-id`, `--federation-peers-file`, `--federation-skip-hostname-verify`, `--federation-max-hops`, `--federation-store-path` with corresponding `RUSTGATE_FEDERATION_*` environment variables
- **Helm chart federation support** — `federation.enabled` toggle, peer config via Secret or values, federation port (9000) in Service and NetworkPolicy
- **639 tests** — up from 198 in v0.1.0, adding comprehensive coverage for federation config, provenance, heartbeat, store, V1/V2 protocols, gRPC service, trust store, HA claims, REST API, and metrics

## [0.1.0] - 2026-03-01

Initial release of rustgate — a Rust-native secure tactical message router.

### Added

- **mTLS transport** — TLS listener with client certificate verification, X.509 identity extraction (CN, OU groups, SHA-256 fingerprint), and TCP keepalive with read/write timeouts
- **Message routing** — broadcast, group-based, and direct (callsign) message delivery with session lifecycle management and atomic session IDs for reconnect handling
- **Framing codecs** — length-prefixed (4-byte header, 16MB max), XML stream, and line-delimited codecs with overflow protection
- **Cursor on Target parsing** — full CoT XML parser with typed detail field extraction (`<contact>`, `<__group>`, `<precisionlocation>`, `<status>`, `<takv>`, `<track>`)
- **Position cache** — per-group position replay on client connect for situational awareness bootstrap
- **NATS bridge** (feature-gated: `nats`) — cross-instance message delivery via NATS pub/sub, JetStream history replay on startup, two-layer echo prevention (protocol tag + instance header)
- **Certificate enrollment** (feature-gated: `enrollment`) — Marti v2 CSR signing protocol over HTTPS with HTTP Basic Auth, subject DN enforcement from authenticated username, TLS handshake + request timeouts, streaming body size limits
- **TAK protobuf translation** (feature-gated: `proto`) — bidirectional XML ↔ protobuf conversion via prost, TAK binary framing codec (0xBF + varint), protocol negotiation handshake (server advertises, client opts in or stays XML), xmlDetail residual preservation
- **Prometheus metrics** (feature-gated: `metrics`) — connection lifecycle, message routing, NATS bridge, and protocol negotiation counters; `/healthz`, `/readyz`, and `/metrics` HTTP endpoints with hardened server (128 connection limit, 15s timeout)
- **Graceful shutdown** — SIGTERM + SIGINT handling, readiness probe returns 503, connection draining with 110s timeout inside K8s terminationGracePeriodSeconds
- **Environment variable configuration** — all CLI flags available as `RUSTGATE_*` env vars (CLI takes precedence)
- **Configurable connection limits** — `--max-connections` / `RUSTGATE_MAX_CONNECTIONS` with semaphore-based enforcement
- **jemalloc allocator** (feature-gated: `jemalloc`) — avoids musl malloc contention for Alpine/musl production builds
- **Helm chart** — Deployment with Pod Security Standards (restricted), PDB, HPA, startup/liveness/readiness probes, pre-stop hook, configurable NATS and enrollment, TLS secret mounting
- **Docker** — multi-stage Dockerfile with OCI labels, HEALTHCHECK, STOPSIGNAL SIGTERM, non-root UID 10001, read-only root filesystem; docker-compose for local development
- **CI pipeline** — GitHub Actions with fmt, clippy, feature matrix testing, cargo-deny (licenses, advisories, bans, sources), Helm lint, Docker build validation
- **Release pipeline** — Docker image build and push to ghcr.io on GitHub Release, cosign signing, SBOM embedding
- **Dependency management** — Dependabot with grouped minor/patch updates and individual major version PRs; cargo-deny with advisory ignore for transitive rustls-pemfile dep
- **198 tests** — unit tests covering mTLS, identity extraction, routing, codecs (XML stream, line-delimited), NATS wire format, CSR signing, enrollment HTTP integration, protobuf conversion, metrics, and CLI configuration; NATS integration tests with embedded nats-server

### Security

- `unsafe_code = "forbid"` across all crates
- `unwrap_used = "deny"` and `panic = "deny"` in clippy lints
- Client certificate subject DN enforced from authenticated username (CSR subject ignored)
- CSR SAN and custom extension stripping to prevent subject injection
- Streaming body size limits (pre-read rejection, not post-buffer)
- SHA-pinned GitHub Actions in CI and release workflows
- `cargo-deny` for license compliance and vulnerability scanning
- Cosign-signed container images with embedded SBOM
- Pod Security Standards (restricted profile) in Helm chart
- Non-root container (UID 10001) with read-only root filesystem and dropped capabilities
