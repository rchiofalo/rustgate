//! CLI argument parsing for the rustgate server binary.
//!
//! Defines the `Cli` struct (via `clap::Parser`), the `Framing` and `Encoding`
//! enums, and the conversion from `Framing` to the transport layer's
//! `FramingStrategy`.

use clap::parser::ValueSource;
use clap::{ArgMatches, CommandFactory, FromArgMatches, Parser, Subcommand, ValueEnum};
use rustgate_core::protocol::{FramingStrategy, HeaderSize};
use serde::{Deserialize, Serialize};

/// Validate that a CLI argument is a valid socket address (ip:port).
fn parse_socket_addr(s: &str) -> Result<String, String> {
    let _ = s
        .parse::<std::net::SocketAddr>()
        .map_err(|e| format!("invalid socket address: {e}"))?;
    Ok(s.to_string())
}

/// Validate max_connections: must be 1..=u32::MAX since it backs a `Semaphore`.
fn parse_max_connections(s: &str) -> Result<usize, String> {
    let n: usize = s.parse().map_err(|e| format!("{e}"))?;
    if n == 0 {
        return Err("must be at least 1".into());
    }
    if n > u32::MAX as usize {
        return Err(format!("must be at most {}", u32::MAX));
    }
    Ok(n)
}

/// Serde `serialize_with` helper that replaces any non-empty secret with the
/// literal string `"<redacted>"` so `print-config` never leaks sensitive
/// values (passwords, tokens) into logs or stdout. `None` and empty strings
/// pass through unchanged so the output still reflects whether the field is
/// set.
fn redact_optional_secret<S>(value: &Option<String>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match value {
        Some(v) if !v.is_empty() => serializer.serialize_some("<redacted>"),
        Some(_) => serializer.serialize_some(""),
        None => serializer.serialize_none(),
    }
}

/// Validate a positive usize (must be >= 1).
fn parse_nonzero_usize(s: &str) -> Result<usize, String> {
    let n: usize = s.parse().map_err(|e| format!("{e}"))?;
    if n == 0 {
        return Err("must be at least 1".into());
    }
    Ok(n)
}

#[derive(Parser, Serialize)]
#[command(name = "rustgate", about = "Secure tactical message router")]
#[serde(rename_all = "kebab-case")]
pub(crate) struct Cli {
    /// Subcommand. When omitted, the server runs normally with the supplied flags.
    #[command(subcommand)]
    #[serde(skip)]
    pub(crate) command: Option<Command>,

    /// Path to a TOML configuration file. Settings are merged in the order
    /// defaults -> file -> environment variables -> CLI flags. Command-line
    /// flags always win.
    #[arg(long, env = "RUSTGATE_CONFIG")]
    #[serde(skip_serializing)]
    pub(crate) config: Option<String>,

    #[arg(short, long, default_value = "0.0.0.0:4433", env = "RUSTGATE_BIND", value_parser = parse_socket_addr)]
    pub(crate) bind: String,

    #[arg(
        long,
        default_value = "",
        env = "RUSTGATE_CERT",
        required_unless_present = "config"
    )]
    pub(crate) cert: String,

    #[arg(
        long,
        default_value = "",
        env = "RUSTGATE_KEY",
        required_unless_present = "config"
    )]
    pub(crate) key: String,

    #[arg(
        long,
        default_value = "",
        env = "RUSTGATE_CA",
        required_unless_present = "config"
    )]
    pub(crate) ca: String,

    /// Path to PEM-encoded Certificate Revocation List file.
    /// Connections using revoked certificates will be rejected at the TLS handshake.
    #[arg(long, env = "RUSTGATE_CRL")]
    pub(crate) crl: Option<String>,

    /// Minimum TLS protocol version the server will accept.
    /// "1.2" allows TLS 1.2 and 1.3 (default). "1.3" enforces TLS 1.3 only.
    #[arg(long, default_value = "1.2", env = "RUSTGATE_TLS_MIN_VERSION")]
    pub(crate) tls_min_version: String,

    /// Warn when loaded CRLs are stale (nextUpdate in the past).
    /// Defaults to true. Set to false to suppress warnings for intentionally stale CRLs.
    #[arg(long, default_value_t = true, env = "RUSTGATE_CRL_WARN_STALE")]
    pub(crate) crl_warn_stale: bool,

    /// Require FIPS 140-3 crypto provider. Startup fails if the FIPS provider
    /// is not active. Build with --features fips to enable.
    #[arg(long, default_value_t = false, env = "RUSTGATE_FIPS_REQUIRED")]
    pub(crate) fips_required: bool,

    /// Prefer post-quantum key exchange (X25519MLKEM768). Build with
    /// --features post-quantum to enable. PQ-capable clients negotiate hybrid
    /// PQ+classical key exchange; others fall back to X25519 transparently.
    #[arg(long, default_value_t = false, env = "RUSTGATE_PREFER_POST_QUANTUM")]
    pub(crate) prefer_post_quantum: bool,

    /// Comma-separated key exchange group preference order. Overrides the
    /// default group ordering from the crypto provider. Requires
    /// --features post-quantum for PQ groups.
    ///
    /// Available groups (with --features post-quantum):
    ///   X25519MLKEM768, SECP256R1MLKEM768, MLKEM768, MLKEM1024,
    ///   X25519, secp256r1, secp384r1
    #[arg(long, env = "RUSTGATE_KX_GROUPS")]
    pub(crate) kx_groups: Option<String>,

    /// Interval in seconds to check for certificate file changes.
    /// When set to a value > 0, the server periodically polls the --cert and
    /// --key files and hot-reloads them on change (zero-downtime rotation).
    /// Set to 0 (default) to disable automatic certificate rotation.
    #[arg(long, default_value_t = 0, env = "RUSTGATE_CERT_RELOAD_INTERVAL")]
    pub(crate) cert_reload_interval: u64,

    /// Enable OCSP stapling for the server certificate. When set, the server
    /// fetches OCSP responses for the active certificate in a background task
    /// and attaches them to the TLS handshake so clients can verify revocation
    /// status without contacting the issuing CA themselves.
    ///
    /// Requires --features ocsp. Most useful with enterprise/private CAs that
    /// run an OCSP responder; Let's Encrypt dropped OCSP support in 2025.
    #[arg(long, default_value_t = false, env = "RUSTGATE_OCSP_STAPLING")]
    pub(crate) ocsp_stapling: bool,

    /// Enable client-certificate OCSP verification (Tier 1, fail-open).
    ///
    /// When set, every accepted client certificate is checked against an
    /// in-memory OCSP cache keyed by Subject Key Identifier. On a cache
    /// miss the inner verifier's decision stands and a background task
    /// fetches an OCSP response so the *next* handshake can be checked.
    /// Cached `Revoked` responses cause the handshake to be rejected.
    ///
    /// Requires --features ocsp. Useful as a near-real-time complement
    /// to CRLs, which only refresh on a schedule.
    #[arg(long, default_value_t = false, env = "RUSTGATE_CLIENT_OCSP")]
    pub(crate) client_ocsp: bool,

    #[arg(long, value_enum, default_value_t = Framing::Xml, env = "RUSTGATE_FRAMING")]
    pub(crate) framing: Framing,

    #[arg(long, value_enum, default_value_t = Encoding::Raw, env = "RUSTGATE_ENCODING")]
    pub(crate) encoding: Encoding,

    /// NATS server URL (enables NATS bridge when set). Requires --features nats.
    #[arg(long, env = "RUSTGATE_NATS_URL")]
    pub(crate) nats_url: Option<String>,

    /// Path to NATS credentials file for JWT/NKey auth.
    #[arg(long, env = "RUSTGATE_NATS_CREDENTIALS")]
    pub(crate) nats_credentials: Option<String>,

    /// Path to PEM-encoded client certificate for NATS mTLS.
    #[arg(long, env = "RUSTGATE_NATS_TLS_CERT")]
    pub(crate) nats_tls_cert: Option<std::path::PathBuf>,

    /// Path to PEM-encoded client private key for NATS mTLS.
    #[arg(long, env = "RUSTGATE_NATS_TLS_KEY")]
    pub(crate) nats_tls_key: Option<std::path::PathBuf>,

    /// Path to PEM-encoded CA certificate for verifying the NATS server.
    #[arg(long, env = "RUSTGATE_NATS_TLS_CA")]
    pub(crate) nats_tls_ca: Option<std::path::PathBuf>,

    /// Require TLS for NATS connections. Fails if TLS is required but
    /// no certificates are provided.
    #[arg(long, default_value_t = false, env = "RUSTGATE_NATS_TLS_REQUIRED")]
    pub(crate) nats_tls_required: bool,

    /// Maximum pending messages per NATS subscription before slow consumer
    /// detection activates. Controls backpressure from the NATS server.
    #[arg(
        long,
        default_value_t = 1024,
        env = "RUSTGATE_NATS_SUBSCRIPTION_CAPACITY"
    )]
    pub(crate) nats_subscription_capacity: usize,

    /// JetStream stream name for live updates. The subscriber creates this
    /// stream to capture `{subject_prefix}.>` subjects via a durable pull
    /// consumer for real backpressure.
    #[arg(
        long,
        default_value = "RUSTGATE_LIVE",
        env = "RUSTGATE_NATS_LIVE_STREAM"
    )]
    pub(crate) nats_live_stream: String,

    /// Maximum unacknowledged messages for the JetStream pull consumer.
    /// Controls how many messages can be in-flight before the server
    /// stops delivering more.
    #[arg(long, default_value_t = 1000, env = "RUSTGATE_NATS_MAX_ACK_PENDING")]
    pub(crate) nats_max_ack_pending: i64,

    /// Path to JetStream replay checkpoint file. When set, the server
    /// persists the last replayed sequence number and resumes from it
    /// on restart instead of replaying the entire history stream.
    #[arg(long, env = "RUSTGATE_NATS_CHECKPOINT_PATH")]
    pub(crate) nats_checkpoint_path: Option<String>,

    /// Bind address for the enrollment HTTPS server (e.g. 0.0.0.0:8446).
    /// Requires --features enrollment.
    #[arg(long, env = "RUSTGATE_ENROLLMENT_BIND", value_parser = parse_socket_addr)]
    pub(crate) enrollment_bind: Option<String>,

    /// Path to the CA private key PEM file (used to sign client CSRs).
    #[arg(long, env = "RUSTGATE_CA_KEY")]
    pub(crate) ca_key: Option<String>,

    /// Username for enrollment HTTP Basic Auth.
    #[arg(long, env = "RUSTGATE_ENROLLMENT_USER")]
    pub(crate) enrollment_user: Option<String>,

    /// Password for enrollment HTTP Basic Auth.
    #[arg(long, env = "RUSTGATE_ENROLLMENT_PASSWORD")]
    #[serde(serialize_with = "redact_optional_secret")]
    pub(crate) enrollment_password: Option<String>,

    /// Organization name for issued client certificates.
    #[arg(long, default_value = "rustgate", env = "RUSTGATE_CA_ORG")]
    pub(crate) ca_organization: String,

    /// Maximum CSR signing requests per source IP per minute on the
    /// enrollment server. CSR signing is an expensive RSA operation, so
    /// this throttle prevents trivial DoS by capping per-IP traffic to
    /// the `/Marti/api/tls/signClient` endpoints. Set to 0 to disable
    /// the throttle (not recommended). Requires `--features enrollment`.
    #[arg(long, default_value_t = 10, env = "RUSTGATE_ENROLLMENT_RATE_LIMIT")]
    pub(crate) enrollment_rate_limit: u32,

    /// Directory for data package storage. Enables the Marti sync API
    /// endpoints when set. Requires --features enrollment.
    #[arg(long, env = "RUSTGATE_DATA_PACKAGE_DIR")]
    pub(crate) data_package_dir: Option<String>,

    /// Path to PEM-encoded CA certificate for verifying data package signatures.
    /// When set, uploaded packages with a signature are verified against this CA.
    #[arg(long, env = "RUSTGATE_PACKAGE_SIGNATURE_CA")]
    pub(crate) package_signature_ca: Option<String>,

    /// Reject unsigned data package uploads. Requires --package-signature-ca.
    #[arg(
        long,
        default_value_t = false,
        env = "RUSTGATE_PACKAGE_STRICT_SIGNATURES"
    )]
    pub(crate) package_strict_signatures: bool,

    /// Path to the certificate revocation database (JSON file).
    /// Enables the `/api/revoke`, `/api/crl`, and `/api/revoked` endpoints
    /// on the enrollment server. Revoked certificates are persisted to this
    /// file and used to generate CRLs signed by the enrollment CA.
    #[arg(long, env = "RUSTGATE_REVOCATION_DB")]
    pub(crate) revocation_db: Option<String>,

    /// CRL validity period in days (default 7).
    #[arg(long, default_value_t = 7, env = "RUSTGATE_CRL_VALIDITY_DAYS")]
    pub(crate) crl_validity_days: u32,

    /// Bind address for the Prometheus metrics HTTP server (e.g. 0.0.0.0:9090).
    /// Requires --features metrics.
    #[arg(long, env = "RUSTGATE_METRICS_BIND", value_parser = parse_socket_addr)]
    pub(crate) metrics_bind: Option<String>,

    /// Enable Tier 2 per-identity Prometheus metrics (handshake failures,
    /// session duration, bytes sent/received) labelled by `identity_cn`.
    /// When disabled the metrics are not registered at all and impose
    /// zero overhead. Cardinality is bounded via the
    /// `--metrics-identity-allowlist` flag.
    #[arg(long, default_value_t = false, env = "RUSTGATE_METRICS_PER_IDENTITY")]
    pub(crate) metrics_per_identity: bool,

    /// Path to a file listing CNs that are exempt from `"other"` bucketing
    /// in per-identity metric labels. One CN per line; lines starting with
    /// `#` are treated as comments. When unset, ALL CNs are bucketed under
    /// the literal `"other"` label, capping per-identity cardinality at 1.
    #[arg(long, env = "RUSTGATE_METRICS_IDENTITY_ALLOWLIST")]
    pub(crate) metrics_identity_allowlist: Option<std::path::PathBuf>,

    /// Maximum concurrent TLS sessions. Prevents resource exhaustion
    /// from connection floods.
    #[arg(long, default_value_t = 1024, env = "RUSTGATE_MAX_CONNECTIONS", value_parser = parse_max_connections)]
    pub(crate) max_connections: usize,

    /// Maximum number of seconds to wait for in-flight queued messages
    /// to be flushed to clients during graceful shutdown. After the
    /// listeners have stopped accepting new connections and SIGTERM has
    /// been observed, every active session is given up to this many
    /// seconds to drain its priority and normal channels before the
    /// process exits. Set to `0` to skip draining (immediate close).
    #[arg(long, default_value_t = 10, env = "RUSTGATE_SHUTDOWN_DRAIN_TIMEOUT")]
    pub(crate) shutdown_drain_timeout: u64,

    /// Maximum number of TLS handshakes that may be in progress simultaneously.
    /// Limits the CPU cost of concurrent cryptographic operations during
    /// connection floods. Incoming connections that exceed this limit will
    /// wait until a handshake slot becomes available.
    #[arg(long, default_value_t = 100, env = "RUSTGATE_MAX_HANDSHAKES", value_parser = parse_nonzero_usize)]
    pub(crate) max_concurrent_handshakes: usize,

    /// Global admission-control high-water mark in bytes. The router tracks
    /// total in-flight queued bytes across all sessions; when the counter
    /// crosses this mark, the TLS accept loop is deferred (not errored)
    /// until the counter drops back below the low-water mark. Prevents a
    /// flood of slow readers from exhausting server memory.
    /// Default: 512 MiB.
    #[arg(
        long,
        default_value_t = rustgate_transport::DEFAULT_MAX_QUEUED_BYTES,
        env = "RUSTGATE_MAX_QUEUED_BYTES"
    )]
    pub(crate) max_queued_bytes: usize,

    /// Optional low-water mark (in bytes) for the admission-control gate.
    /// When the queued-bytes counter drops at or below this value after
    /// crossing the high-water mark, the accept loop resumes. Defaults to
    /// 90% of `--max-queued-bytes` when omitted.
    #[arg(long, env = "RUSTGATE_MAX_QUEUED_BYTES_LOW_WATER")]
    pub(crate) max_queued_bytes_low_water: Option<usize>,

    /// Bind address for the WebSocket (wss://) listener (e.g. 0.0.0.0:8443).
    /// Requires --features websocket.
    #[arg(long, env = "RUSTGATE_WEBSOCKET_BIND", value_parser = parse_socket_addr)]
    pub(crate) websocket_bind: Option<String>,

    /// Maximum WebSocket frames per second per connection (0 = unlimited).
    #[arg(long, default_value_t = 0, env = "RUSTGATE_WS_MAX_FRAMES_PER_SEC")]
    pub(crate) ws_max_frames_per_sec: u32,

    /// Maximum WebSocket bytes per second per connection (0 = unlimited).
    #[arg(long, default_value_t = 0, env = "RUSTGATE_WS_MAX_BYTES_PER_SEC")]
    pub(crate) ws_max_bytes_per_sec: u64,

    /// Consecutive WebSocket rate limit violations before disconnecting client.
    #[arg(long, default_value_t = 10, env = "RUSTGATE_WS_MAX_VIOLATIONS")]
    pub(crate) ws_max_violations: u32,

    // -- Plaintext input flags --
    /// Bind address for plaintext TCP input (e.g. 0.0.0.0:8087).
    /// WARNING: connections are NOT encrypted. Use only on trusted networks.
    #[arg(long, env = "RUSTGATE_TCP_BIND", value_parser = parse_socket_addr)]
    pub(crate) tcp_bind: Option<String>,

    /// Bind address for UDP CoT input (e.g. 0.0.0.0:8087).
    /// WARNING: datagrams are NOT encrypted. Use only on trusted networks.
    #[arg(long, env = "RUSTGATE_UDP_BIND", value_parser = parse_socket_addr)]
    pub(crate) udp_bind: Option<String>,

    /// Default CN for plaintext (TCP/UDP) clients.
    #[arg(long, default_value = "anonymous", env = "RUSTGATE_PLAINTEXT_CN")]
    pub(crate) plaintext_cn: String,

    /// Default group for plaintext (TCP/UDP) clients.
    #[arg(
        long,
        default_value = "__plaintext__",
        env = "RUSTGATE_PLAINTEXT_GROUP"
    )]
    pub(crate) plaintext_group: String,

    // -- Federation flags --
    /// V1 federation listen address (enables federation when set, e.g. 0.0.0.0:9000).
    /// Requires --features federation.
    #[arg(long, env = "RUSTGATE_FEDERATION_V1_BIND", value_parser = parse_socket_addr)]
    pub(crate) federation_v1_bind: Option<String>,

    /// V2 gRPC federation listen address (e.g. 0.0.0.0:9001).
    /// Enables V2 gRPC inbound server when set alongside --federation-v1-bind.
    /// Requires --features federation.
    #[arg(long, env = "RUSTGATE_FEDERATION_V2_BIND", value_parser = parse_socket_addr)]
    pub(crate) federation_v2_bind: Option<String>,

    /// Unique federation server identity.
    #[arg(
        long,
        default_value = "rustgate-federation-1",
        env = "RUSTGATE_FEDERATION_ID"
    )]
    pub(crate) federation_id: String,

    /// Path to JSON file containing federation peer configurations.
    #[arg(long, env = "RUSTGATE_FEDERATION_PEERS_FILE")]
    pub(crate) federation_peers_file: Option<String>,

    /// Interval in seconds to poll the federation peers file for changes.
    /// When set to a value > 0 and `--federation-peers-file` is provided,
    /// the server periodically re-reads the peers file and reconciles the
    /// active peer set on change (adds new peers, gracefully disconnects
    /// removed peers, leaves unchanged peers untouched). SIGHUP also
    /// triggers a reconcile when this is configured.
    /// Set to 0 (default) to disable automatic federation peer reloading.
    #[arg(
        long,
        default_value_t = 0,
        env = "RUSTGATE_FEDERATION_PEERS_RELOAD_INTERVAL"
    )]
    pub(crate) federation_peers_reload_interval: u64,

    /// Skip TLS hostname verification for federation peers.
    #[arg(
        long,
        default_value_t = false,
        env = "RUSTGATE_FEDERATION_SKIP_HOSTNAME_VERIFY"
    )]
    pub(crate) federation_skip_hostname_verify: bool,

    /// Maximum federation hops before dropping a message (loop prevention).
    #[arg(long, default_value_t = 10, env = "RUSTGATE_FEDERATION_MAX_HOPS")]
    pub(crate) federation_max_hops: u32,

    /// Path to persistent federate store (JSON file).
    #[arg(long, env = "RUSTGATE_FEDERATION_STORE_PATH")]
    pub(crate) federation_store_path: Option<String>,

    /// Directory containing additional trusted CA certificates for federation.
    /// PEM/CRT files in this directory are merged with --ca for TLS verification.
    #[arg(long, env = "RUSTGATE_FEDERATION_TRUST_STORE_DIR")]
    pub(crate) federation_trust_store_dir: Option<String>,

    /// Consecutive send failures before tripping a federation peer's circuit breaker.
    #[arg(
        long,
        default_value_t = 5,
        env = "RUSTGATE_FEDERATION_CIRCUIT_BREAKER_THRESHOLD"
    )]
    pub(crate) federation_circuit_breaker_threshold: u32,

    /// Seconds to wait after a circuit breaker trips before probing a federation peer.
    #[arg(
        long,
        default_value_t = 60,
        env = "RUSTGATE_FEDERATION_CIRCUIT_BREAKER_TIMEOUT"
    )]
    pub(crate) federation_circuit_breaker_timeout: u64,

    /// Maximum messages retained per federation peer for reconnection replay.
    /// On reconnect, buffered messages are sent before resuming live delivery.
    /// Set to 0 to disable.
    #[arg(
        long,
        default_value_t = 1000,
        env = "RUSTGATE_FEDERATION_REPLAY_BUFFER_SIZE"
    )]
    pub(crate) federation_replay_buffer_size: usize,

    /// Directory for persisting per-peer federation replay buffers to disk.
    /// When set, replay buffers survive server restarts so a peer that
    /// reconnects after a restart can resume replay from the last
    /// persisted point. The store is a redb database at
    /// `<dir>/federation_replay.redb`.
    #[arg(long, env = "RUSTGATE_FEDERATION_REPLAY_DIR")]
    pub(crate) federation_replay_dir: Option<std::path::PathBuf>,

    /// Global byte cap for the persistent federation replay store
    /// (drop-oldest eviction). Only honored when `--federation-replay-dir`
    /// is set. Defaults to 64 MiB.
    #[arg(
        long,
        default_value_t = 64 * 1024 * 1024,
        env = "RUSTGATE_FEDERATION_REPLAY_MAX_BYTES"
    )]
    pub(crate) federation_replay_max_bytes: u64,

    /// NATS URL for federation HA coordination (enables distributed peer ownership).
    /// When set, only one pod manages each outbound peer in a multi-pod deployment.
    /// Requires --features federation-ha.
    #[arg(long, env = "RUSTGATE_FEDERATION_HA_NATS_URL")]
    pub(crate) federation_ha_nats_url: Option<String>,

    /// Pod identifier for federation HA mode. Defaults to --federation-id if
    /// --federation-ha-nats-url is set.
    #[arg(long, env = "RUSTGATE_FEDERATION_POD_ID")]
    pub(crate) federation_pod_id: Option<String>,

    // -- QoS / rate limiting --
    /// Sliding-window replay detection window in seconds. Messages with the same
    /// (uid, time) pair seen within this window are dropped as replays.
    /// Set to 0 to disable replay detection.
    #[arg(long, default_value_t = 300, env = "RUSTGATE_REPLAY_WINDOW")]
    pub(crate) replay_window: u64,

    /// Cross-path deduplication window in seconds. When > 0, the router
    /// suppresses duplicate messages that arrive via multiple ingress
    /// paths (e.g. direct client + federation) within this window.
    /// Disabled by default.
    #[arg(long, default_value_t = 0, env = "RUSTGATE_DEDUP_WINDOW_SECS")]
    pub(crate) dedup_window_secs: u64,

    /// Maximum number of entries retained in the cross-path dedup cache.
    /// Bounds memory usage; oldest entries are evicted in LRU order.
    #[arg(long, default_value_t = 100_000, env = "RUSTGATE_DEDUP_CACHE_SIZE")]
    pub(crate) dedup_cache_size: usize,

    /// Maximum sustained messages per second per connected client (0 = disabled).
    #[arg(long, default_value_t = 0, env = "RUSTGATE_CLIENT_MSG_RATE")]
    pub(crate) client_message_rate: u32,

    /// Maximum burst size for per-client rate limiting.
    #[arg(long, default_value_t = 200, env = "RUSTGATE_CLIENT_BURST")]
    pub(crate) client_burst: u32,

    /// Consecutive send failures before disconnecting a slow session.
    /// When a session's outbound channel is full for this many consecutive
    /// sends, the circuit breaker trips and the session is terminated.
    /// Set to 0 to disable the circuit breaker.
    #[arg(long, default_value_t = 10, env = "RUSTGATE_CIRCUIT_BREAKER_THRESHOLD")]
    pub(crate) circuit_breaker_threshold: u32,

    /// Path to JSON file containing group access control rules.
    /// When set, per-group send/receive permissions are enforced at
    /// router dispatch time. Groups not listed in the file operate in
    /// open mode (any member can send/receive). See docs for format.
    #[arg(long, env = "RUSTGATE_GROUP_ACL_FILE")]
    pub(crate) group_acl_file: Option<String>,

    /// Interval in seconds to check the group ACL file for changes.
    /// When set to a value > 0 and --group-acl-file is provided, the server
    /// periodically polls the ACL file and hot-reloads the policy on change.
    /// Set to 0 (default) to disable automatic ACL reloading.
    #[arg(long, default_value_t = 0, env = "RUSTGATE_ACL_RELOAD_INTERVAL")]
    pub(crate) acl_reload_interval: u64,

    /// Path to a file containing the bearer token required to access the
    /// `/api/acl/` REST endpoints (both read and mutation routes).
    ///
    /// When unset, the ACL API is not registered at all — requests under
    /// `/api/acl/` fall through to the metrics server's 404 handler.
    /// When set, every request must present `Authorization: Bearer <token>`
    /// and the supplied token is compared to the file contents in constant
    /// time.
    ///
    /// WARNING: the ACL API exposes mutation of routing policy. Bind the
    /// metrics endpoint to a trusted network only; never expose it to the
    /// public internet.
    #[arg(long, env = "RUSTGATE_ACL_API_TOKEN_FILE")]
    pub(crate) acl_api_token_file: Option<String>,

    // -- Data retention / archival --
    /// Directory for CoT event archival (JSONL). Enables structured logging of
    /// all received CoT events to date-stamped files.
    #[arg(long, env = "RUSTGATE_ARCHIVE_DIR")]
    pub(crate) archive_dir: Option<String>,

    /// Path to a JSON key file enabling at-rest ChaCha20-Poly1305 encryption
    /// for the CoT archive (when `--archive-dir` is set) and the audit log
    /// (when `--audit-log` is a file path). The file must contain
    /// `{ "active_key_id": "<id>", "keys": { "<id>": "<64-char hex>" } }`
    /// where each key is 32 bytes. Adding new keys without removing old ones
    /// supports rotation: historical files written under prior keys remain
    /// readable as long as their key id is still present in this file.
    #[arg(long, env = "RUSTGATE_ARCHIVE_KEY_FILE")]
    pub(crate) archive_key_file: Option<std::path::PathBuf>,

    /// Maximum total bytes retained across the CoT archive directory.
    /// When the directory exceeds this cap, the rotation task deletes
    /// the oldest archive files (by mtime) until the total drops below
    /// the cap. `0` = unlimited (no size-based retention).
    #[arg(long, default_value_t = 0, env = "RUSTGATE_ARCHIVE_MAX_SIZE")]
    pub(crate) archive_max_size: u64,

    /// Maximum age (in seconds) for CoT archive files. Files older than
    /// this are deleted by the rotation task. `0` = unlimited (no
    /// time-based retention).
    #[arg(long, default_value_t = 0, env = "RUSTGATE_ARCHIVE_MAX_AGE")]
    pub(crate) archive_max_age: u64,

    /// Interval (in seconds) between archive rotation passes. Defaults
    /// to 60s. Has no effect unless `--archive-dir` is set and at least
    /// one of `--archive-max-size` or `--archive-max-age` is non-zero.
    #[arg(long, default_value_t = 60, env = "RUSTGATE_ARCHIVE_ROTATE_INTERVAL")]
    pub(crate) archive_rotate_interval: u64,

    /// Maximum age (in hours) for uploaded data packages. Packages older than
    /// this are eligible for cleanup. 0 = no expiration.
    #[arg(long, default_value_t = 0, env = "RUSTGATE_PACKAGE_MAX_AGE_HOURS")]
    pub(crate) package_max_age_hours: u64,

    // -- Observability --
    /// Write audit events as JSON lines to a dedicated file. When set,
    /// audit events (target="audit") are written to this file in addition
    /// to the main log stream. Use "-" for stdout.
    #[arg(long, env = "RUSTGATE_AUDIT_LOG")]
    pub(crate) audit_log: Option<String>,

    /// Write per-message access events as JSON lines to a dedicated
    /// file. When set, every routed message produces one access-log
    /// entry (target="access") with src_cn, dst, msg_uid, size, and
    /// outcome (delivered, dedup, expired). Use "-" for stdout.
    #[arg(long, env = "RUSTGATE_ACCESS_LOG")]
    pub(crate) access_log: Option<String>,

    /// Directory in which to keep the per-client store-and-forward
    /// queue database. When unset, offline messages are dropped (the
    /// default pre-v0.7 behavior). When set, messages destined for a
    /// disconnected CN are persisted to a bounded disk queue and
    /// drained on reconnect.
    #[arg(long, env = "RUSTGATE_CLIENT_QUEUE_DIR")]
    pub(crate) client_queue_dir: Option<std::path::PathBuf>,

    /// Global byte cap for the client store-and-forward queue. When
    /// inserting a message would exceed this cap, the oldest entries
    /// across all CNs are evicted until the new message fits. Only
    /// honored when `--client-queue-dir` is also set. Defaults to
    /// 100 MiB.
    #[arg(long, default_value_t = 100 * 1024 * 1024, env = "RUSTGATE_CLIENT_QUEUE_MAX_BYTES")]
    pub(crate) client_queue_max_bytes: u64,

    /// OTLP gRPC endpoint for OpenTelemetry trace export (e.g. http://localhost:4317).
    /// Requires --features otel. When not set, OTel tracing is disabled even if
    /// compiled with the otel feature.
    #[arg(long, env = "OTEL_EXPORTER_OTLP_ENDPOINT")]
    pub(crate) otel_endpoint: Option<String>,

    /// OpenTelemetry service name reported in traces.
    #[arg(long, default_value = "rustgate", env = "OTEL_SERVICE_NAME")]
    pub(crate) otel_service_name: String,

    /// Enable pushing metrics over OTLP alongside the Prometheus
    /// `/metrics` endpoint. Requires `--otel-endpoint` (reused for both
    /// traces and metrics) and the `otel` + `metrics` features to be
    /// compiled in. The Prometheus scrape target is unaffected; this is
    /// purely additive.
    #[arg(long, default_value_t = false, env = "RUSTGATE_OTLP_METRICS")]
    pub(crate) otlp_metrics: bool,

    /// Push interval in seconds for the OTLP metrics exporter.
    /// Only honored when `--otlp-metrics` is set. Must be at least 1.
    #[arg(
        long,
        default_value_t = 60,
        env = "RUSTGATE_OTLP_METRICS_INTERVAL",
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    pub(crate) otlp_metrics_interval: u64,
}

/// Top-level subcommands. The default (no subcommand) runs the server.
#[derive(Subcommand, Clone, Debug)]
pub(crate) enum Command {
    /// Print the effective merged configuration as TOML and exit.
    PrintConfig,
    /// Validate the configuration file (parse + cross-field checks) and exit.
    ValidateConfig,
    /// Decrypt an encrypted archive or audit log file produced when
    /// `--archive-key-file` was active. The output is written verbatim
    /// (e.g. JSONL) and can then be inspected with standard tools.
    DecryptArchive {
        /// Path to the encrypted input file.
        #[arg(long = "in", value_name = "PATH")]
        input: std::path::PathBuf,
        /// Path to write the decrypted plaintext output.
        #[arg(long = "out", value_name = "PATH")]
        output: std::path::PathBuf,
        /// Path to the JSON key file. Must contain the key id referenced
        /// in the input header (the active key need not match).
        #[arg(long = "key-file", value_name = "PATH")]
        key_file: std::path::PathBuf,
    },
    /// Verify the integrity of a hash-chained audit log.
    VerifyAudit {
        /// Path to the audit log file (newline-delimited JSON records).
        #[arg(long)]
        file: String,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Framing {
    Xml,
    LengthPrefixed,
    Line,
    /// TAK protobuf binary framing (0xBF + varint length). Requires --features proto.
    TakProtobuf,
    /// TAK protocol negotiation: starts XML, upgrades to protobuf if the client requests it.
    /// This is the mode real TAK clients expect. Requires --features proto.
    TakNegotiate,
}

#[derive(Debug, Clone, Copy, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Encoding {
    Raw,
    Cot,
    /// TAK protobuf encoding (proto <-> XML at session edge). Requires --features proto.
    TakProtobuf,
}

impl From<Framing> for FramingStrategy {
    fn from(f: Framing) -> Self {
        match f {
            Framing::Xml => FramingStrategy::XmlStream,
            Framing::LengthPrefixed => FramingStrategy::LengthPrefixed {
                header_size: HeaderSize::Four,
            },
            Framing::Line => FramingStrategy::LineDelimited,
            Framing::TakProtobuf => FramingStrategy::TakProtobuf,
            // TakNegotiate starts as XML; negotiation determines the actual framing.
            // This mapping is used as the initial framing before negotiation runs.
            Framing::TakNegotiate => FramingStrategy::XmlStream,
        }
    }
}

/// Build a codec from the CLI `--framing` and `--encoding` flags.
///
/// Maps legacy `(Framing, Encoding)` pairs to the unified [`Codec`](rustgate_core::codec::Codec) trait
/// objects. `TakNegotiate` starts with XML; negotiation upgrades to protobuf
/// inside the session handler.
pub(crate) fn build_codec(
    framing: Framing,
    encoding: Encoding,
) -> std::sync::Arc<dyn rustgate_core::codec::Codec> {
    use std::sync::Arc;

    // Ambiguous combinations (e.g. --framing xml --encoding tak-protobuf)
    // are rejected by validate_framing() before this function is called.
    match (framing, encoding) {
        // TAK protobuf framing always uses the protobuf codec regardless
        // of the encoding flag.
        #[cfg(feature = "proto")]
        (Framing::TakProtobuf, _) => Arc::new(rustgate_proto::TakProtobufCodec),

        // TakNegotiate starts as XML — negotiation may upgrade to protobuf.
        (Framing::TakNegotiate, _) => Arc::new(rustgate_transport::TakXmlCodec),

        // Standard combinations: framing determines the codec, encoding is
        // passthrough (Raw/Cot both use identity payload transform).
        (Framing::Xml, _) => Arc::new(rustgate_transport::TakXmlCodec),
        (Framing::Line, _) => Arc::new(rustgate_transport::RawLineCodec),
        (Framing::LengthPrefixed, _) => Arc::new(rustgate_transport::RawLengthPrefixedCodec),

        // Fallback for proto framing when proto feature is disabled
        // (should be caught by validate_framing, but be safe).
        #[cfg(not(feature = "proto"))]
        (Framing::TakProtobuf, _) => Arc::new(rustgate_transport::TakXmlCodec),
    }
}

// ── Configuration file support ──────────────────────────────────────
//
// `ConfigFile` is a serde-only mirror of `Cli` where every field is optional.
// It is loaded from a TOML file via figment and then merged into a freshly
// parsed `Cli` instance: for each field, if the user did not pass it on the
// command line and did not set its environment variable, the file value
// (when present) replaces the clap default. The result is the precedence
//
//     defaults < file < env < CLI flags
//
// which matches the documented behaviour in the README.

/// Macro to define `ConfigFile` and the corresponding merge routine. Each
/// entry lists the field name (matching `Cli`) and its concrete type.
///
/// The macro keeps `Cli` and `ConfigFile` field names 1:1 so TOML keys map
/// directly onto CLI flag names in kebab-case (hyphens preserved) via
/// `serde(rename_all = "kebab-case")`.
macro_rules! define_config_file {
    ( $( $field:ident : $ty:ty ),* $(,)? ) => {
        /// All-optional mirror of [`Cli`] used for TOML deserialization.
        #[derive(Debug, Default, Deserialize, Serialize)]
        #[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
        pub(crate) struct ConfigFile {
            $( pub(crate) $field: Option<$ty>, )*
        }

        impl ConfigFile {
            /// Apply this file's values to `cli`, overwriting only fields
            /// whose value source is `DefaultValue` (i.e. not supplied by
            /// the user on the command line or via an environment variable).
            fn apply_to(self, cli: &mut Cli, matches: &ArgMatches) {
                $(
                    if let Some(v) = self.$field
                        && matches!(matches.value_source(stringify!($field)), Some(ValueSource::DefaultValue) | None)
                    {
                        cli.$field = v;
                    }
                )*
            }
        }
    };
}

define_config_file! {
    bind: String,
    cert: String,
    key: String,
    ca: String,
    crl: Option<String>,
    tls_min_version: String,
    crl_warn_stale: bool,
    fips_required: bool,
    prefer_post_quantum: bool,
    kx_groups: Option<String>,
    cert_reload_interval: u64,
    ocsp_stapling: bool,
    client_ocsp: bool,
    framing: Framing,
    encoding: Encoding,
    nats_url: Option<String>,
    nats_credentials: Option<String>,
    nats_tls_cert: Option<std::path::PathBuf>,
    nats_tls_key: Option<std::path::PathBuf>,
    nats_tls_ca: Option<std::path::PathBuf>,
    nats_tls_required: bool,
    nats_subscription_capacity: usize,
    nats_live_stream: String,
    nats_max_ack_pending: i64,
    nats_checkpoint_path: Option<String>,
    enrollment_bind: Option<String>,
    ca_key: Option<String>,
    enrollment_user: Option<String>,
    enrollment_password: Option<String>,
    ca_organization: String,
    enrollment_rate_limit: u32,
    data_package_dir: Option<String>,
    package_signature_ca: Option<String>,
    package_strict_signatures: bool,
    revocation_db: Option<String>,
    crl_validity_days: u32,
    metrics_bind: Option<String>,
    metrics_per_identity: bool,
    metrics_identity_allowlist: Option<std::path::PathBuf>,
    max_connections: usize,
    shutdown_drain_timeout: u64,
    max_concurrent_handshakes: usize,
    max_queued_bytes: usize,
    max_queued_bytes_low_water: Option<usize>,
    websocket_bind: Option<String>,
    ws_max_frames_per_sec: u32,
    ws_max_bytes_per_sec: u64,
    ws_max_violations: u32,
    tcp_bind: Option<String>,
    udp_bind: Option<String>,
    plaintext_cn: String,
    plaintext_group: String,
    federation_v1_bind: Option<String>,
    federation_v2_bind: Option<String>,
    federation_id: String,
    federation_peers_file: Option<String>,
    federation_peers_reload_interval: u64,
    federation_skip_hostname_verify: bool,
    federation_max_hops: u32,
    federation_store_path: Option<String>,
    federation_trust_store_dir: Option<String>,
    federation_circuit_breaker_threshold: u32,
    federation_circuit_breaker_timeout: u64,
    federation_replay_buffer_size: usize,
    federation_replay_dir: Option<std::path::PathBuf>,
    federation_replay_max_bytes: u64,
    federation_ha_nats_url: Option<String>,
    federation_pod_id: Option<String>,
    replay_window: u64,
    client_message_rate: u32,
    client_burst: u32,
    circuit_breaker_threshold: u32,
    group_acl_file: Option<String>,
    acl_reload_interval: u64,
    acl_api_token_file: Option<String>,
    archive_dir: Option<String>,
    archive_key_file: Option<std::path::PathBuf>,
    archive_max_size: u64,
    archive_max_age: u64,
    archive_rotate_interval: u64,
    package_max_age_hours: u64,
    audit_log: Option<String>,
    access_log: Option<String>,
    client_queue_dir: Option<std::path::PathBuf>,
    client_queue_max_bytes: u64,
    otel_endpoint: Option<String>,
    otel_service_name: String,
    otlp_metrics: bool,
    otlp_metrics_interval: u64,
    dedup_window_secs: u64,
    dedup_cache_size: usize,
}

impl Cli {
    /// Parse command-line arguments, then layer in any TOML configuration
    /// file specified via `--config` / `RUSTGATE_CONFIG`. CLI flags and
    /// environment variables always override file values.
    pub(crate) fn parse_with_config() -> anyhow::Result<Self> {
        let matches = Cli::command().get_matches();
        let mut cli = Cli::from_arg_matches(&matches)
            .map_err(|e| anyhow::anyhow!("failed to parse CLI: {e}"))?;

        if let Some(ref path) = cli.config {
            let file = load_config_file(path)?;
            file.apply_to(&mut cli, &matches);
        }

        Ok(cli)
    }

    /// Validate cross-field invariants on the merged configuration.
    /// Currently checks that the mTLS material (cert/key/ca) is non-empty,
    /// matching the original required-flag behaviour.
    pub(crate) fn validate(&self) -> anyhow::Result<()> {
        if self.cert.is_empty() {
            anyhow::bail!("--cert (or [cert] in the config file) is required");
        }
        if self.key.is_empty() {
            anyhow::bail!("--key (or [key] in the config file) is required");
        }
        if self.ca.is_empty() {
            anyhow::bail!("--ca (or [ca] in the config file) is required");
        }
        Ok(())
    }

    /// Serialize the merged configuration as TOML for `print-config`.
    pub(crate) fn to_toml(&self) -> anyhow::Result<String> {
        toml::to_string_pretty(self)
            .map_err(|e| anyhow::anyhow!("failed to serialize config to TOML: {e}"))
    }
}

/// Load and parse a TOML configuration file via figment.
pub(crate) fn load_config_file(path: &str) -> anyhow::Result<ConfigFile> {
    use figment::Figment;
    use figment::providers::{Format, Toml};
    Figment::new()
        .merge(Toml::file(path))
        .extract::<ConfigFile>()
        .map_err(|e| anyhow::anyhow!("failed to load config file {path}: {e}"))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn redact_enrollment_password_in_toml() {
        let cli = Cli::try_parse_from([
            "rustgate",
            "--cert",
            "c.pem",
            "--key",
            "k.pem",
            "--ca",
            "ca.pem",
            "--enrollment-password",
            "super-secret-42",
        ])
        .expect("parse");
        let out = cli.to_toml().expect("toml");
        assert!(
            !out.contains("super-secret-42"),
            "password leaked into print-config output: {out}"
        );
        assert!(
            out.contains("<redacted>"),
            "expected <redacted> marker in output: {out}"
        );
    }

    #[test]
    fn cli_parses_defaults() {
        let cli = Cli::try_parse_from([
            "rustgate", "--cert", "c.pem", "--key", "k.pem", "--ca", "ca.pem",
        ])
        .expect("should parse");
        assert_eq!(cli.bind, "0.0.0.0:4433");
        assert_eq!(cli.max_connections, 1024);
        assert_eq!(cli.max_concurrent_handshakes, 100);
    }

    #[test]
    fn cli_max_concurrent_handshakes_override() {
        let cli = Cli::try_parse_from([
            "rustgate",
            "--cert",
            "c.pem",
            "--key",
            "k.pem",
            "--ca",
            "ca.pem",
            "--max-concurrent-handshakes",
            "50",
        ])
        .expect("should parse");
        assert_eq!(cli.max_concurrent_handshakes, 50);
    }

    #[test]
    fn cli_max_connections_override() {
        let cli = Cli::try_parse_from([
            "rustgate",
            "--cert",
            "c.pem",
            "--key",
            "k.pem",
            "--ca",
            "ca.pem",
            "--max-connections",
            "512",
        ])
        .expect("should parse");
        assert_eq!(cli.max_connections, 512);
    }

    #[test]
    fn cli_rejects_non_numeric_max_connections() {
        let result = Cli::try_parse_from([
            "rustgate",
            "--cert",
            "c.pem",
            "--key",
            "k.pem",
            "--ca",
            "ca.pem",
            "--max-connections",
            "abc",
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn cli_metrics_bind_optional() {
        let cli = Cli::try_parse_from([
            "rustgate", "--cert", "c.pem", "--key", "k.pem", "--ca", "ca.pem",
        ])
        .expect("should parse");
        assert!(cli.metrics_bind.is_none());

        let cli = Cli::try_parse_from([
            "rustgate",
            "--cert",
            "c.pem",
            "--key",
            "k.pem",
            "--ca",
            "ca.pem",
            "--metrics-bind",
            "0.0.0.0:9090",
        ])
        .expect("should parse");
        assert_eq!(cli.metrics_bind.as_deref(), Some("0.0.0.0:9090"));
    }

    #[test]
    fn cli_env_vars_declared() {
        // Verify all expected env vars appear in clap's help output.
        // This ensures the env = "..." attributes are wired up correctly.
        use clap::CommandFactory;
        let help = Cli::command().render_long_help().to_string();

        let expected_env_vars = [
            "RUSTGATE_BIND",
            "RUSTGATE_CERT",
            "RUSTGATE_KEY",
            "RUSTGATE_CA",
            "RUSTGATE_CRL",
            "RUSTGATE_TLS_MIN_VERSION",
            "RUSTGATE_CRL_WARN_STALE",
            "RUSTGATE_FIPS_REQUIRED",
            "RUSTGATE_PREFER_POST_QUANTUM",
            "RUSTGATE_KX_GROUPS",
            "RUSTGATE_CERT_RELOAD_INTERVAL",
            "RUSTGATE_FRAMING",
            "RUSTGATE_ENCODING",
            "RUSTGATE_NATS_URL",
            "RUSTGATE_NATS_CREDENTIALS",
            "RUSTGATE_NATS_TLS_CERT",
            "RUSTGATE_NATS_TLS_KEY",
            "RUSTGATE_NATS_TLS_CA",
            "RUSTGATE_NATS_TLS_REQUIRED",
            "RUSTGATE_NATS_SUBSCRIPTION_CAPACITY",
            "RUSTGATE_NATS_LIVE_STREAM",
            "RUSTGATE_NATS_MAX_ACK_PENDING",
            "RUSTGATE_NATS_CHECKPOINT_PATH",
            "RUSTGATE_ENROLLMENT_BIND",
            "RUSTGATE_CA_KEY",
            "RUSTGATE_ENROLLMENT_USER",
            "RUSTGATE_ENROLLMENT_PASSWORD",
            "RUSTGATE_CA_ORG",
            "RUSTGATE_DATA_PACKAGE_DIR",
            "RUSTGATE_PACKAGE_SIGNATURE_CA",
            "RUSTGATE_PACKAGE_STRICT_SIGNATURES",
            "RUSTGATE_METRICS_BIND",
            "RUSTGATE_MAX_CONNECTIONS",
            "RUSTGATE_MAX_HANDSHAKES",
            "RUSTGATE_WEBSOCKET_BIND",
            "RUSTGATE_WS_MAX_FRAMES_PER_SEC",
            "RUSTGATE_WS_MAX_BYTES_PER_SEC",
            "RUSTGATE_WS_MAX_VIOLATIONS",
            "RUSTGATE_TCP_BIND",
            "RUSTGATE_UDP_BIND",
            "RUSTGATE_PLAINTEXT_CN",
            "RUSTGATE_PLAINTEXT_GROUP",
            "RUSTGATE_FEDERATION_V1_BIND",
            "RUSTGATE_FEDERATION_V2_BIND",
            "RUSTGATE_FEDERATION_ID",
            "RUSTGATE_FEDERATION_PEERS_FILE",
            "RUSTGATE_FEDERATION_SKIP_HOSTNAME_VERIFY",
            "RUSTGATE_FEDERATION_MAX_HOPS",
            "RUSTGATE_FEDERATION_STORE_PATH",
            "RUSTGATE_FEDERATION_TRUST_STORE_DIR",
            "RUSTGATE_FEDERATION_CIRCUIT_BREAKER_THRESHOLD",
            "RUSTGATE_FEDERATION_CIRCUIT_BREAKER_TIMEOUT",
            "RUSTGATE_FEDERATION_HA_NATS_URL",
            "RUSTGATE_FEDERATION_POD_ID",
            "RUSTGATE_REPLAY_WINDOW",
            "RUSTGATE_CLIENT_MSG_RATE",
            "RUSTGATE_CLIENT_BURST",
            "RUSTGATE_GROUP_ACL_FILE",
            "RUSTGATE_ARCHIVE_DIR",
            "RUSTGATE_ARCHIVE_MAX_SIZE",
            "RUSTGATE_ARCHIVE_MAX_AGE",
            "RUSTGATE_ARCHIVE_ROTATE_INTERVAL",
            "RUSTGATE_PACKAGE_MAX_AGE_HOURS",
            "RUSTGATE_AUDIT_LOG",
            "OTEL_EXPORTER_OTLP_ENDPOINT",
            "OTEL_SERVICE_NAME",
            "RUSTGATE_OTLP_METRICS",
            "RUSTGATE_OTLP_METRICS_INTERVAL",
        ];

        for var in expected_env_vars {
            assert!(
                help.contains(var),
                "expected env var {var} not found in help output"
            );
        }
    }

    #[test]
    fn cli_all_flags_have_long_option() {
        use clap::CommandFactory;
        let cmd = Cli::command();
        for arg in cmd.get_arguments() {
            if arg.get_id() == "help" || arg.get_id() == "version" {
                continue;
            }
            assert!(
                arg.get_long().is_some(),
                "arg {:?} missing --long flag",
                arg.get_id()
            );
        }
    }

    #[test]
    fn cli_federation_defaults() {
        let cli = Cli::try_parse_from([
            "rustgate", "--cert", "c.pem", "--key", "k.pem", "--ca", "ca.pem",
        ])
        .expect("should parse");
        assert!(cli.federation_v1_bind.is_none());
        assert!(cli.federation_v2_bind.is_none());
        assert_eq!(cli.federation_id, "rustgate-federation-1");
        assert!(cli.federation_peers_file.is_none());
        assert!(!cli.federation_skip_hostname_verify);
        assert_eq!(cli.federation_max_hops, 10);
        assert!(cli.federation_store_path.is_none());
    }

    #[test]
    fn cli_federation_bind_override() {
        let cli = Cli::try_parse_from([
            "rustgate",
            "--cert",
            "c.pem",
            "--key",
            "k.pem",
            "--ca",
            "ca.pem",
            "--federation-v1-bind",
            "0.0.0.0:9000",
            "--federation-v2-bind",
            "0.0.0.0:9001",
            "--federation-id",
            "my-fed-server",
            "--federation-max-hops",
            "5",
        ])
        .expect("should parse");
        assert_eq!(cli.federation_v1_bind.as_deref(), Some("0.0.0.0:9000"));
        assert_eq!(cli.federation_v2_bind.as_deref(), Some("0.0.0.0:9001"));
        assert_eq!(cli.federation_id, "my-fed-server");
        assert_eq!(cli.federation_max_hops, 5);
    }

    #[test]
    fn cli_federation_skip_hostname_verify() {
        let cli = Cli::try_parse_from([
            "rustgate",
            "--cert",
            "c.pem",
            "--key",
            "k.pem",
            "--ca",
            "ca.pem",
            "--federation-skip-hostname-verify",
        ])
        .expect("should parse");
        assert!(cli.federation_skip_hostname_verify);
    }

    #[test]
    fn cli_audit_log_default_none() {
        let cli = Cli::try_parse_from([
            "rustgate", "--cert", "c.pem", "--key", "k.pem", "--ca", "ca.pem",
        ])
        .expect("should parse");
        assert!(cli.audit_log.is_none());
    }

    #[test]
    fn cli_audit_log_file_path() {
        let cli = Cli::try_parse_from([
            "rustgate",
            "--cert",
            "c.pem",
            "--key",
            "k.pem",
            "--ca",
            "ca.pem",
            "--audit-log",
            "/var/log/rustgate/audit.jsonl",
        ])
        .expect("should parse");
        assert_eq!(
            cli.audit_log.as_deref(),
            Some("/var/log/rustgate/audit.jsonl")
        );
    }

    #[test]
    fn cli_audit_log_stdout() {
        let cli = Cli::try_parse_from([
            "rustgate",
            "--cert",
            "c.pem",
            "--key",
            "k.pem",
            "--ca",
            "ca.pem",
            "--audit-log",
            "-",
        ])
        .expect("should parse");
        assert_eq!(cli.audit_log.as_deref(), Some("-"));
    }

    // ── build_codec tests ──────────────────────────────────────────

    #[test]
    fn build_codec_xml_raw_produces_tak_xml() {
        let codec = build_codec(Framing::Xml, Encoding::Raw);
        assert_eq!(codec.protocol_id(), "tak-xml");
    }

    #[test]
    fn build_codec_xml_cot_produces_tak_xml() {
        let codec = build_codec(Framing::Xml, Encoding::Cot);
        assert_eq!(codec.protocol_id(), "tak-xml");
    }

    #[test]
    fn build_codec_line_produces_raw_line() {
        let codec = build_codec(Framing::Line, Encoding::Raw);
        assert_eq!(codec.protocol_id(), "raw-line");
    }

    #[test]
    fn build_codec_length_prefixed_produces_raw_length_prefixed() {
        let codec = build_codec(Framing::LengthPrefixed, Encoding::Raw);
        assert_eq!(codec.protocol_id(), "raw-length-prefixed");
    }

    #[test]
    fn build_codec_tak_negotiate_starts_xml() {
        let codec = build_codec(Framing::TakNegotiate, Encoding::Raw);
        assert_eq!(codec.protocol_id(), "tak-xml");
    }

    #[cfg(feature = "proto")]
    #[test]
    fn build_codec_tak_protobuf_framing_produces_protobuf() {
        let codec = build_codec(Framing::TakProtobuf, Encoding::Raw);
        assert_eq!(codec.protocol_id(), "tak-protobuf");
    }

    #[cfg(feature = "proto")]
    #[test]
    fn build_codec_tak_protobuf_framing_ignores_encoding() {
        // Encoding flag is irrelevant when framing is TakProtobuf
        let codec = build_codec(Framing::TakProtobuf, Encoding::Cot);
        assert_eq!(codec.protocol_id(), "tak-protobuf");
    }
}
