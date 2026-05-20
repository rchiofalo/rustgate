// Copyright © 2026 Roberto Chiofalo.

//! CLI argument parsing for the rustgate server binary.
//!
//! Defines the `Cli` struct (via `clap::Parser`), the `Framing` and `Encoding`
//! enums, and the conversion from `Framing` to the transport layer's
//! `FramingStrategy`.

use clap::parser::ValueSource;
use clap::{ArgMatches, CommandFactory, FromArgMatches, Parser, Subcommand, ValueEnum};
use rustgate_core::config::validate::{
    validate_non_empty as core_validate_non_empty, validate_path_exists as core_validate_path,
};
use rustgate_core::protocol::{FramingStrategy, HeaderSize};
use serde::{Deserialize, Serialize};

/// Hard minimum for `--archive-rotate-interval` (seconds). Rotation cadences
/// below this are rejected at config validation time: they widen the
/// torn-write window and stress disk I/O for no operator benefit. See F-69.
const MIN_ROTATION_INTERVAL_SECS: u64 = 60;

/// Recommended minimum for `--archive-rotate-interval` (seconds). Values
/// between [`MIN_ROTATION_INTERVAL_SECS`] and this constant emit a startup
/// warning but are allowed.
const RECOMMENDED_MIN_ROTATION_INTERVAL_SECS: u64 = 300;

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

/// Validate a positive u64 (must be >= 1).
///
/// Used by knobs that express a duration in seconds — zero would mean
/// "fire the timeout immediately on every connection," which is never
/// what an operator intends.
fn parse_nonzero_u64(s: &str) -> Result<u64, String> {
    let n: u64 = s.parse().map_err(|e| format!("{e}"))?;
    if n == 0 {
        return Err("must be at least 1".into());
    }
    Ok(n)
}

/// Minimum write buffer size: 64 KiB.
const WS_WRITE_BUFFER_MIN: usize = 65_536;
/// Maximum write buffer size: 64 MiB.
const WS_WRITE_BUFFER_MAX: usize = 67_108_864;
/// Default write buffer size: 4 MiB (mirrors
/// `rustgate_websocket::DEFAULT_MAX_WRITE_BUFFER_BYTES`).
const WS_WRITE_BUFFER_DEFAULT: usize = 4_194_304;

/// Validate write buffer size: 64 KiB .. 64 MiB inclusive.
fn parse_write_buffer_bytes(s: &str) -> Result<usize, String> {
    let n: usize = s.parse().map_err(|e| format!("{e}"))?;
    validate_write_buffer_range(n)
}

/// Range-check a write buffer size, usable from both the clap parser and
/// post-merge config validation.
fn validate_write_buffer_range(n: usize) -> Result<usize, String> {
    if n < WS_WRITE_BUFFER_MIN {
        return Err(format!("must be at least {WS_WRITE_BUFFER_MIN} (64 KiB)"));
    }
    if n > WS_WRITE_BUFFER_MAX {
        return Err(format!("must be at most {WS_WRITE_BUFFER_MAX} (64 MiB)"));
    }
    Ok(n)
}

#[derive(Parser, Serialize)]
#[command(
    name = "rustgate",
    about = "Secure tactical message router",
    version,
    // Without this, clap enforces the top-level `--cert/--key/--ca`
    // requirement even when the user is invoking a diagnostic
    // subcommand that has no use for them (e.g. `rustgate cert-info
    // foo.pem`). `subcommand_negates_reqs` tells clap to skip the
    // parent's required-arg checks whenever any subcommand is
    // supplied, which is exactly what every diagnostic wants.
    subcommand_negates_reqs = true,
)]
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

    /// TCP socket address to bind the primary TLS listener on, as
    /// `<host>:<port>`. Use `0.0.0.0:<port>` to accept IPv4 on all
    /// interfaces and `[::]:<port>` to dual-bind IPv4 + IPv6.
    #[arg(short, long, default_value = "0.0.0.0:4433", env = "RUSTGATE_BIND", value_parser = parse_socket_addr)]
    pub(crate) bind: String,

    /// Path to the PEM-encoded TLS server certificate presented to
    /// every mTLS client. Required unless `--spiffe` is set (the
    /// SPIFFE Workload API supplies the SVID instead) or the value is
    /// provided via a config file referenced by `--config`.
    #[arg(
        long,
        default_value = "",
        env = "RUSTGATE_CERT",
        required_unless_present_any = ["config", "spiffe"],
        conflicts_with = "spiffe"
    )]
    pub(crate) cert: String,

    /// Path to the PEM-encoded private key matching `--cert`. The file
    /// is read into a zeroizing buffer and wiped from memory as soon
    /// as rustls has consumed the bytes. Required unless `--spiffe`
    /// or `--config` supplies an equivalent value.
    #[arg(
        long,
        default_value = "",
        env = "RUSTGATE_KEY",
        required_unless_present_any = ["config", "spiffe"],
        conflicts_with = "spiffe"
    )]
    pub(crate) key: String,

    /// Path to the PEM-encoded trust anchor bundle used to verify
    /// client certificates. Every client must present a certificate
    /// chaining to this bundle. Required unless `--spiffe` is set
    /// (trust anchors come from the Workload API) or a config file
    /// supplies the value.
    #[arg(
        long,
        default_value = "",
        env = "RUSTGATE_CA",
        required_unless_present_any = ["config", "spiffe"],
        conflicts_with = "spiffe"
    )]
    pub(crate) ca: String,

    /// Enable SPIFFE workload identity. When set, the server obtains its
    /// TLS certificate, private key, and trust bundle from a SPIRE agent
    /// via the SPIFFE Workload API instead of from `--cert`/`--key`/`--ca`.
    /// Requires `--features spiffe`. Mutually exclusive with `--cert`,
    /// `--key`, `--ca`, and `--enrollment-bind`.
    #[arg(
        long,
        default_value_t = false,
        env = "RUSTGATE_SPIFFE",
        conflicts_with_all = ["cert", "key", "ca", "enrollment_bind"]
    )]
    pub(crate) spiffe: bool,

    /// Path to the SPIRE agent Workload API endpoint. Defaults to the
    /// SPIFFE standard socket at `unix:///tmp/spire-agent/public/api.sock`.
    /// Only used when `--spiffe` is enabled.
    #[arg(
        long,
        default_value = "unix:///tmp/spire-agent/public/api.sock",
        env = "RUSTGATE_SPIFFE_WORKLOAD_API_SOCKET"
    )]
    pub(crate) spiffe_workload_api_socket: String,

    /// Expected SPIFFE trust domain. When set, the SVID fetched from the
    /// Workload API must belong to this trust domain or startup fails.
    /// Only used when `--spiffe` is enabled.
    #[arg(long, env = "RUSTGATE_SPIFFE_TRUST_DOMAIN")]
    pub(crate) spiffe_trust_domain: Option<String>,

    /// Interval in seconds to refresh the SPIFFE X.509-SVID from the
    /// Workload API. Defaults to 300s (5 minutes). SPIFFE SVIDs are
    /// short-lived (typically 1 hour), so the default gives ample margin.
    /// Only used when `--spiffe` is enabled.
    #[arg(
        long,
        default_value_t = 300,
        env = "RUSTGATE_SPIFFE_REFRESH_INTERVAL",
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    pub(crate) spiffe_refresh_interval: u64,

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

    /// Run in air-gap mode. Every external-facing subsystem refuses
    /// non-private endpoints at startup: HTTP egress targets, OTEL
    /// exporters, peer-discovery (Consul / etcd / DNS-SD), and OCSP
    /// fetching. Acceptable hosts are RFC 1918 / loopback / link-local
    /// IPv4, IPv6 ULA / loopback / link-local, plus the
    /// `localhost`, `*.localhost`, `local`, and `*.local` (mDNS) DNS
    /// labels. Violations refuse to start the affected subsystem and
    /// emit `audit::air_gap_violation`. The mTLS data plane is
    /// unaffected — peers may still connect from any address.
    #[arg(long, default_value_t = false, env = "RUSTGATE_AIR_GAP")]
    pub(crate) air_gap: bool,

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

    /// Run in CNSA 2.0 compliance mode. **Scaffolding flag — not yet
    /// fully functional**; the convergence work tracked in #504
    /// blocks on aws-lc-rs resolving the FIPS / ML-DSA mutual
    /// exclusion ([aws-lc-rs #964]).
    ///
    /// What this flag eventually configures (per NSA CNSA 2.0):
    ///
    ///   - ML-KEM-1024 key exchange (NIST Level 5)
    ///   - ML-DSA-87 digital signatures (NIST Level 5)
    ///   - TLS 1.3 minimum
    ///   - AES-256 symmetric (already TLS 1.3 default)
    ///   - SHA-384+ hashing (already used)
    ///
    /// What it does today:
    ///
    ///   - Validates that --features post-quantum is compiled in
    ///     (errors otherwise; clear pointer to the required build
    ///     profile)
    ///   - Logs the phased-readiness state at startup so operators
    ///     understand the gap between "I asked for CNSA 2.0" and
    ///     "what the build actually delivers"
    ///   - Does NOT yet override --kx-groups or --tls-min-version —
    ///     those still come from their dedicated flags. Future work
    ///     (the sub-issues at #500/#501/#502/#503) will wire those
    ///     overrides as each phase lands.
    ///
    /// See [`docs/adr/0019-cnsa2-hybrid-mldsa.md`] for the design
    /// rationale and timeline.
    ///
    /// [aws-lc-rs #964]: https://github.com/aws/aws-lc-rs/issues/964
    /// [`docs/adr/0019-cnsa2-hybrid-mldsa.md`]: ../../docs/adr/0019-cnsa2-hybrid-mldsa.md
    #[arg(long, default_value_t = false, env = "RUSTGATE_CNSA2")]
    pub(crate) cnsa2: bool,

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

    /// Wire framing strategy applied to every accepted client session.
    /// `xml` (default) accepts raw CoT XML streams with depth tracking.
    /// `length-prefixed` reads a 4-byte big-endian length header before
    /// each message. `line` parses newline-delimited records.
    /// `tak-protobuf` requires the `0xBF` magic + varint length frame.
    /// `tak-negotiate` server-advertises both XML and protobuf and
    /// upgrades each session at the client's option. See
    /// [docs/architecture.md § Codec Pipeline](../../docs/architecture.md#codec-pipeline)
    /// for the framing table.
    #[arg(long, value_enum, default_value_t = Framing::Xml, env = "RUSTGATE_FRAMING")]
    pub(crate) framing: Framing,

    /// Per-session payload encoding for length-prefixed frames. `raw`
    /// (default) writes the exact bytes the codec produces. Reserved
    /// for future codec-specific encoding overlays.
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

    /// Maximum JetStream delivery attempts per message before the consumer
    /// gives up (poison-message defence, refs #883 sub-item 3). Default
    /// `5` is the workspace poison-message handling standard. Set to `0`
    /// (or any non-positive value) to opt into the pre-#883 unlimited-
    /// redelivery semantics — useful for legacy migrations where a
    /// JetStream stream contains records the operator wants to keep
    /// retrying indefinitely while they fix the upstream producer. On
    /// the final give-up, the subscriber emits the structured
    /// `nats.poison_dlq` audit event and (if `--nats-dead-letter-subject`
    /// is set) republishes the original payload to that subject before
    /// ACKing.
    #[arg(long, default_value_t = 5, env = "RUSTGATE_NATS_MAX_DELIVER")]
    pub(crate) nats_max_deliver: i64,

    /// Optional NATS subject to republish poison messages to before the
    /// subscriber ACKs them. When unset (default), poison messages are
    /// silently ACKed after the structured `nats.poison_dlq` audit
    /// event fires. When set, the original payload is republished to
    /// this subject with diagnostic headers (`X-Rustgate-DLQ-Reason`,
    /// `X-Rustgate-DLQ-Original-Subject`, `X-Rustgate-DLQ-Timestamp`)
    /// so operators can inspect the malformed bytes. The subject MUST
    /// live outside the live stream's `{subject_prefix}.>` namespace
    /// to avoid an infinite redelivery loop. Refs #883 sub-item 3.
    #[arg(long, env = "RUSTGATE_NATS_DEAD_LETTER_SUBJECT")]
    pub(crate) nats_dead_letter_subject: Option<String>,

    /// Path to JetStream replay checkpoint file. When set, the server
    /// persists the last replayed sequence number and resumes from it
    /// on restart instead of replaying the entire history stream.
    #[arg(long, env = "RUSTGATE_NATS_CHECKPOINT_PATH")]
    pub(crate) nats_checkpoint_path: Option<String>,

    /// Path to TOML file configuring HTTP webhook/REST targets.
    /// Requires --features http.
    #[arg(long, env = "RUSTGATE_HTTP_CONFIG")]
    pub(crate) http_config_file: Option<String>,

    /// Path to TOML file configuring the Anduril Lattice bridge.
    /// The file's `[lattice]` block is parsed by `rustgate-lattice`.
    /// Requires --features lattice (plus a backend feature like
    /// --features lattice-mock for the in-memory mock or
    /// --features lattice-real once the partner SDK is available).
    /// Refs #850.
    #[arg(long, env = "RUSTGATE_LATTICE_CONFIG")]
    pub(crate) lattice_config_file: Option<String>,

    /// Path to TOML file configuring the OGC SensorThings v1.0
    /// polling client. The file's `[sensorthings]` block is parsed
    /// by `rustgate-ogc-sensorthings`. Requires
    /// `--features ogc-sensorthings`. Closes #869 alongside the
    /// parallel NFFI follow-up.
    #[arg(long, env = "RUSTGATE_OGC_SENSORTHINGS_CONFIG")]
    pub(crate) ogc_sensorthings_config_file: Option<String>,

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

    /// Enable EST (RFC 7030) enrollment endpoints on the enrollment server.
    /// Adds `/.well-known/est/` paths for CA certificate distribution and
    /// CSR-based enrollment alongside the existing Marti-compatible endpoints.
    /// Requires `--features est` and `--enrollment-bind`.
    #[arg(long, default_value_t = false, env = "RUSTGATE_EST_ENABLED")]
    pub(crate) est_enabled: bool,

    /// Bind address for the Prometheus metrics HTTP server (e.g. 127.0.0.1:9090).
    /// Defaults to localhost to prevent accidental network exposure.
    /// Requires --features metrics.
    #[arg(long, env = "RUSTGATE_METRICS_BIND", value_parser = parse_socket_addr)]
    pub(crate) metrics_bind: Option<String>,

    /// Path to a file containing a bearer token for the `/metrics` endpoint.
    /// When set, requests to `/metrics` must present `Authorization: Bearer <token>`.
    /// When unset, `/metrics` is unauthenticated (backward compatible).
    /// The token is compared in constant time and stored in zeroizing memory.
    /// The token is read once at startup; restart the server to rotate.
    #[arg(long, env = "RUSTGATE_METRICS_TOKEN_FILE")]
    pub(crate) metrics_token_file: Option<String>,

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

    /// Maximum concurrent connections to the metrics HTTP server.
    #[arg(long, default_value_t = 128, env = "RUSTGATE_METRICS_MAX_CONNECTIONS")]
    pub(crate) metrics_max_connections: usize,

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

    /// Maximum number of seconds the server will wait for a TAK client
    /// to complete protocol-version negotiation (the 0xBF-framed
    /// TakControl request).
    ///
    /// Healthy negotiations finish in well under a second. Combined
    /// with `--max-concurrent-handshakes`, a generous timeout lets a
    /// mass slow-negotiate attack park every handshake slot for the
    /// full window. F-65 reduced the default from 30s to 10s; lower it
    /// further on tactical deployments where every client is on the
    /// LAN, raise it only when slow links demand it.
    ///
    /// The literal default mirrors
    /// `rustgate_proto::NEGOTIATION_TIMEOUT_DEFAULT_SECS`, which the
    /// `cli_negotiation_timeout_default_matches_proto_const` test
    /// asserts when the `proto` feature is on. We keep the literal so
    /// the CLI compiles on featureless builds where `rustgate-proto`
    /// is absent from the dependency graph.
    #[arg(
        long,
        default_value_t = 10,
        env = "RUSTGATE_NEGOTIATION_TIMEOUT_SECS",
        value_parser = parse_nonzero_u64,
    )]
    pub(crate) negotiation_timeout_secs: u64,

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

    /// Minimum milliseconds the queued-bytes counter must stay at/below the
    /// low-water mark before the accept loop resumes after a block. Prevents
    /// rapid oscillation when load hovers around the high-water mark (see
    /// issue #878). Set to `0` for the pre-dwell behaviour of resuming the
    /// instant the counter crosses back below the low-water mark.
    /// Default: 1000 ms.
    #[arg(
        long,
        default_value_t = 1000,
        env = "RUSTGATE_BACKPRESSURE_RESUME_DWELL_MS"
    )]
    pub(crate) backpressure_resume_dwell_ms: u64,

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

    /// Maximum pending write bytes per WebSocket connection before
    /// disconnecting a slow consumer. Prevents memory exhaustion from
    /// clients that read slower than the server writes.
    #[arg(
        long,
        default_value_t = WS_WRITE_BUFFER_DEFAULT,
        env = "RUSTGATE_WS_MAX_WRITE_BUFFER_BYTES",
        value_parser = parse_write_buffer_bytes
    )]
    pub(crate) ws_max_write_buffer_bytes: usize,

    /// Maximum WebSocket frame size in bytes (default: 16 MiB).
    #[arg(
        long,
        default_value_t = 16 * 1024 * 1024,
        env = "RUSTGATE_WS_MAX_FRAME_SIZE"
    )]
    pub(crate) ws_max_frame_size: usize,

    /// Maximum WebSocket message size in bytes (default: 64 MiB).
    #[arg(
        long,
        default_value_t = 64 * 1024 * 1024,
        env = "RUSTGATE_WS_MAX_MESSAGE_SIZE"
    )]
    pub(crate) ws_max_message_size: usize,

    /// WebSocket per-IP connection rate limit: max accepted connections per
    /// sliding window before further connections from the same peer IP are
    /// rejected before TLS. Default `10` matches the pre-#756 hard-coded
    /// behaviour. Production deployments with multi-thousand-peer fleets
    /// should raise this in tandem with `--ws-rate-limit-window-secs`. The
    /// legacy long form `--ws-conn-rate-limit` is retained as a visible
    /// alias so configs from before this PR keep parsing.
    #[arg(
        long = "ws-rate-limit-max",
        visible_alias = "ws-conn-rate-limit",
        default_value_t = 10,
        env = "RUSTGATE_WS_RATE_LIMIT_MAX"
    )]
    pub(crate) ws_rate_limit_max: usize,

    /// WebSocket per-IP connection rate-limit window in seconds. Default `10`
    /// matches the pre-#756 hard-coded behaviour. Tuned in tandem with
    /// `--ws-rate-limit-max`. The legacy long form
    /// `--ws-conn-rate-window-secs` is retained as a visible alias so
    /// configs from before this PR keep parsing.
    #[arg(
        long = "ws-rate-limit-window-secs",
        visible_alias = "ws-conn-rate-window-secs",
        default_value_t = 10,
        env = "RUSTGATE_WS_RATE_LIMIT_WINDOW_SECS"
    )]
    pub(crate) ws_rate_limit_window_secs: u64,

    /// Comma-separated list of WebSocket subprotocol tokens the server
    /// advertises during the upgrade handshake, in server-preference order.
    /// Empty (the default) disables negotiation and preserves historical
    /// behaviour — no `Sec-WebSocket-Protocol` header is sent in the
    /// response.
    ///
    /// When non-empty, the server picks the first client-offered token that
    /// also appears in this list (client-preference scan, server-final
    /// choice, per RFC 6455 §4.2.2). If the client offered nothing or the
    /// intersection is empty, the handshake still succeeds and no response
    /// header is emitted. Tokens are case-sensitive ABNF tokens; leading and
    /// trailing whitespace in each comma-separated element is trimmed.
    ///
    /// Example: `--websocket-subprotocols=cot.v2,tak.proto.v1`.
    #[arg(
        long,
        env = "RUSTGATE_WS_SUBPROTOCOLS",
        value_delimiter = ',',
        num_args = 0..
    )]
    pub(crate) ws_subprotocols: Vec<String>,

    /// When set, a WebSocket client whose `Sec-WebSocket-Protocol` offer
    /// does not intersect `--websocket-subprotocols` is rejected with a
    /// 400 Bad Request. Default off (lenient): the upgrade still completes
    /// and the response simply omits the `Sec-WebSocket-Protocol` header
    /// — TAK and similar tactical clients probe several subprotocols and
    /// fall back to native non-subprotocol framing on no-match. Operators
    /// running a homogeneous client fleet flip this on so a config drift
    /// surfaces in server logs instead of as opaque client-side protocol
    /// errors.
    #[arg(long, default_value_t = false, env = "RUSTGATE_WS_SUBPROTOCOL_STRICT")]
    pub(crate) ws_subprotocol_strict: bool,

    /// Disable `permessage-deflate` (RFC 7692) negotiation entirely. By
    /// default the server accepts the extension at the RFC 7692 maxima
    /// because mTLS already neutralises CRIME-style chosen-plaintext
    /// attacks. Operators on links where compression-oracle attacks are
    /// in scope, or where an upstream deep-inspection device rejects
    /// compressed frames, flip this on — the server emits no
    /// `Sec-WebSocket-Extensions` response header regardless of what the
    /// client offered.
    #[arg(
        long,
        default_value_t = false,
        env = "RUSTGATE_WS_COMPRESSION_DISABLED"
    )]
    pub(crate) ws_compression_disabled: bool,

    /// Interval in seconds between active WebSocket Ping health-check frames.
    /// Set to 0 (default) to disable the active heartbeat — `tokio-tungstenite`
    /// already auto-responds to inbound Pings but never probes the peer, so
    /// silent NAT/proxy middleboxes can leave a session wedged indefinitely.
    /// When enabled, the server emits a Ping every `N` seconds and records
    /// inbound Pong timestamps to detect stalled peers.
    #[arg(long, default_value_t = 0, env = "RUSTGATE_WS_PING_INTERVAL_SECS")]
    pub(crate) ws_ping_interval_secs: u64,

    /// Additional grace seconds beyond `--ws-ping-interval-secs` before a
    /// session with no Pong is dropped. The deadline is
    /// `ping_interval + pong_timeout`; 0 (default) keeps Pings flowing without
    /// ever terminating a silent session — useful for keeping middleboxes
    /// warm when transient Pong loss should be tolerated. Only meaningful
    /// when `--ws-ping-interval-secs` is non-zero.
    #[arg(long, default_value_t = 0, env = "RUSTGATE_WS_PONG_TIMEOUT_SECS")]
    pub(crate) ws_pong_timeout_secs: u64,

    // -- MQTT flags --
    /// Bind address for the MQTT (mqtts://) listener (e.g. 0.0.0.0:8883).
    /// Requires --features mqtt.
    #[arg(long, env = "RUSTGATE_MQTT_BIND", value_parser = parse_socket_addr)]
    pub(crate) mqtt_bind: Option<String>,

    /// Optional topic prefix to strip from MQTT topics before mapping to groups.
    /// For example, with prefix "rustgate/" the MQTT topic "rustgate/alpha" maps
    /// to group "alpha".
    #[arg(long, env = "RUSTGATE_MQTT_TOPIC_PREFIX")]
    pub(crate) mqtt_topic_prefix: Option<String>,

    /// Maximum MQTT packet size in bytes (default: 16 MiB).
    #[arg(
        long,
        default_value_t = 16 * 1024 * 1024,
        env = "RUSTGATE_MQTT_MAX_PACKET_SIZE"
    )]
    pub(crate) mqtt_max_packet_size: usize,

    /// MQTT 5.0 Receive Maximum advertised in CONNACK (default: 32).
    /// Maximum number of QoS 1 / QoS 2 PUBLISHes a client may have
    /// in-flight to the broker without intervening acks. The default
    /// matches `MqttServerConfig::DEFAULT_RECEIVE_MAX`.
    #[arg(long, default_value_t = 32, env = "RUSTGATE_MQTT_RECEIVE_MAX")]
    pub(crate) mqtt_receive_max: u16,

    /// MQTT 5.0 Topic Alias Maximum advertised in CONNACK (default: 0
    /// = topic aliases disabled). Set to a non-zero cap to enable the
    /// per-connection alias table (§3.3.2.3.4); inbound PUBLISH with
    /// alias outside [1, cap] OR referencing an unmapped slot triggers
    /// DISCONNECT 0x94.
    #[arg(long, default_value_t = 0, env = "RUSTGATE_MQTT_TOPIC_ALIAS_MAX")]
    pub(crate) mqtt_topic_alias_max: u16,

    /// Maximum MQTT 5.0 `Session Expiry Interval` (seconds) the broker
    /// will honor for retained sessions (default: 0 = retention OFF).
    /// Set to a positive value to enable session retention per
    /// MQTT 5.0 §3.1.2.11.2; the negotiated expiry returned in CONNACK
    /// is `min(client_request, mqtt_max_session_expiry_secs)`.
    /// Special value 4294967295 (u32::MAX) means "no operator cap".
    #[arg(
        long,
        default_value_t = 0,
        env = "RUSTGATE_MQTT_MAX_SESSION_EXPIRY_SECS"
    )]
    pub(crate) mqtt_max_session_expiry_secs: u32,

    /// Hard cap on simultaneously-retained MQTT sessions (default: 1024).
    /// Only meaningful when --mqtt-max-session-expiry-secs > 0.
    #[arg(
        long,
        default_value_t = 1024,
        env = "RUSTGATE_MQTT_MAX_RETAINED_SESSIONS"
    )]
    pub(crate) mqtt_max_retained_sessions: usize,

    /// Minimum MQTT keep-alive interval in seconds. Clients requesting 0
    /// (disabled) or a value below this floor get this value imposed.
    #[arg(long, default_value_t = 30, env = "RUSTGATE_MQTT_MIN_KEEP_ALIVE_SECS")]
    pub(crate) mqtt_min_keep_alive_secs: u16,

    /// MQTT 5.0 Server Keep Alive override (seconds) advertised in CONNACK
    /// per §3.2.2.3.14 (default: 0 = no override; broker honors the client's
    /// CONNECT-time keep-alive request). When set to a positive value, the
    /// broker advertises the value via the `Server Keep Alive` CONNACK
    /// property and a compliant client MUST switch to that interval; the
    /// broker also enforces the overridden interval on its read-loop
    /// keep-alive timer so a non-compliant client that ignores the property
    /// still gets disconnected on the operator's chosen schedule. v3.1.1 has
    /// no Server Keep Alive feature; the v4 path is unaffected.
    #[arg(
        long,
        default_value_t = 0,
        env = "RUSTGATE_MQTT_SERVER_KEEP_ALIVE_SECS"
    )]
    pub(crate) mqtt_server_keep_alive_secs: u16,

    /// MQTT response channel capacity (per-session).
    #[arg(
        long,
        default_value_t = 64,
        env = "RUSTGATE_MQTT_RESPONSE_CHANNEL_CAPACITY"
    )]
    pub(crate) mqtt_response_channel_capacity: usize,

    /// MQTT SUBSCRIBE wildcard policy. `reject` disables wildcards entirely;
    /// `single-level-only` (default) accepts `+` but rejects `#`; `full`
    /// accepts both `+` and `#`. Wildcard filters are expanded at SUBSCRIBE
    /// time against the client certificate's group SAN — clients never
    /// receive messages from groups they could not have joined explicitly.
    #[arg(
        long,
        default_value_t = MqttWildcardPolicy::default(),
        value_enum,
        env = "RUSTGATE_MQTT_WILDCARD_POLICY"
    )]
    pub(crate) mqtt_wildcard_policy: MqttWildcardPolicy,

    // -- MAVLink signing policy flags (F-72) --
    /// Require the MAVLink v2 SIGNED INCOMPAT bit on every accepted v2
    /// frame. Default `true` — unsigned v2 frames are rejected at the
    /// framing layer with an `UnsignedFrameRejected` typed error and
    /// (when an audit observer is wired) emit
    /// `audit::mavlink_unsigned_rejected`. Set `false` only for
    /// deployments running on a fully trusted link where end-to-end
    /// signing is not yet available; the rejection still surfaces
    /// through the typed error so a SIEM can correlate rollout
    /// progress.
    #[arg(
        long,
        default_value_t = true,
        env = "RUSTGATE_MAVLINK_REQUIRE_SIGNING",
        action = clap::ArgAction::Set,
    )]
    pub(crate) mavlink_require_signing: bool,

    /// Allow legacy MAVLink v1 frames. Default `false` — v1 has no
    /// signature field, so accepting v1 alongside signed v2 traffic
    /// would hand an attacker a downgrade path. Set `true` only for
    /// deployments with mixed fleets where some senders cannot speak
    /// v2 yet; v1 traffic cannot be authenticated at the MAVLink layer
    /// and operators should treat such links as untrusted.
    #[arg(
        long,
        default_value_t = false,
        env = "RUSTGATE_MAVLINK_ALLOW_V1",
        action = clap::ArgAction::Set,
    )]
    pub(crate) mavlink_allow_v1: bool,

    // -- Plaintext input flags --
    /// Bind address for plaintext TCP input (e.g. 0.0.0.0:8087).
    /// WARNING: connections are NOT encrypted. Use only on trusted networks.
    #[arg(long, env = "RUSTGATE_TCP_BIND", value_parser = parse_socket_addr)]
    pub(crate) tcp_bind: Option<String>,

    /// Bind address for UDP CoT input (e.g. 0.0.0.0:8087).
    /// WARNING: datagrams are NOT encrypted. Use only on trusted networks.
    #[arg(long, env = "RUSTGATE_UDP_BIND", value_parser = parse_socket_addr)]
    pub(crate) udp_bind: Option<String>,

    /// Per-IP rate limit in packets per second for UDP input.
    /// Set to 0 (default) to disable rate limiting.
    #[arg(long, default_value = "0", env = "RUSTGATE_UDP_RATE_LIMIT")]
    pub(crate) udp_rate_limit: u32,

    /// Comma-separated list of CIDR prefixes that are allowed to send UDP
    /// datagrams (e.g. "10.0.0.0/8,192.168.0.0/16"). When unset, all
    /// source IPs are accepted.
    #[arg(long, env = "RUSTGATE_UDP_ALLOWED_CIDRS")]
    pub(crate) udp_allowed_cidrs: Option<String>,

    /// Maximum number of concurrent synthetic UDP identities tracked.
    /// Packets from new source IPs are rejected when the cap is reached.
    #[arg(long, default_value = "1024", env = "RUSTGATE_UDP_MAX_IDENTITIES", value_parser = parse_nonzero_usize)]
    pub(crate) udp_max_identities: usize,

    /// Comma-separated IPv4 multicast `host:port` groups to join for CoT
    /// ingress (e.g. `"239.2.3.1:6969,239.2.3.1:17012"`). Empty (the
    /// default) disables multicast. Closes #861.
    ///
    /// ATAK devices on tactical mesh radio networks (MPU5, Silvus) use
    /// multicast for peer-to-peer SA. Setting this lets the server
    /// participate in that fabric — datagrams are routed through the
    /// standard router and tagged with `source_protocol = "udp-multicast"`.
    #[arg(long, env = "RUSTGATE_UDP_MULTICAST_GROUPS")]
    pub(crate) udp_multicast_groups: Option<String>,

    /// IPv4 address of the interface to bind for multicast join.
    /// Defaults to `0.0.0.0` (all interfaces). Operators on hosts with
    /// multiple physical NICs can pin the multicast listener to one
    /// interface.
    #[arg(
        long,
        default_value = "0.0.0.0",
        env = "RUSTGATE_UDP_MULTICAST_INTERFACE"
    )]
    pub(crate) udp_multicast_interface: String,

    /// Enable `IP_MULTICAST_LOOP` on inbound + egress sockets. Default
    /// `false` — tactical deployments don't want loopback. Set to
    /// `true` only for development on a single host.
    #[arg(
        long,
        default_value_t = false,
        env = "RUSTGATE_UDP_MULTICAST_LOOP",
        action = clap::ArgAction::Set
    )]
    pub(crate) udp_multicast_loop: bool,

    /// `IP_MULTICAST_TTL`. Default `1` — same subnet only, the safe
    /// default for mesh radio. Operators with a routed multicast
    /// fabric can raise this.
    #[arg(long, default_value_t = 1, env = "RUSTGATE_UDP_MULTICAST_TTL")]
    pub(crate) udp_multicast_ttl: u32,

    /// Re-broadcast every routed CoT message back out to the configured
    /// multicast groups. Default off — when enabled, the router fans
    /// every CoT-shaped `RoutableMessage` to the multicast egress
    /// socket subject to `--udp-multicast-max-bps`.
    #[arg(
        long,
        default_value_t = false,
        env = "RUSTGATE_UDP_MULTICAST_REBROADCAST",
        action = clap::ArgAction::Set
    )]
    pub(crate) udp_multicast_rebroadcast: bool,

    /// Maximum outbound multicast egress bytes per second. Default
    /// 1_048_576 (1 MiB/s). Tokens are 1 byte each; a full datagram of
    /// `N` bytes consumes `N` tokens. The bucket starts full so the
    /// first 1-second burst is unrestricted.
    #[arg(
        long,
        default_value_t = 1_048_576,
        env = "RUSTGATE_UDP_MULTICAST_MAX_BPS"
    )]
    pub(crate) udp_multicast_max_bps: u64,

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

    /// Maximum federation hops before an inbound message is dropped
    /// (loop prevention). Closes #758. Range is `1..=255`; the default
    /// of 8 preserves the historical inbound enforcement bound that
    /// was previously hard-coded in `rustgate-federation::v2::server::
    /// MAX_FEDERATION_HOPS`. Tactical topologies that need a tighter
    /// or looser bound (e.g. star-shaped two-hub deployments at
    /// `max_hops=3`, or multi-region meshes at `max_hops=16`) can
    /// override here without recompiling.
    #[arg(
        long,
        default_value_t = 8,
        env = "RUSTGATE_FEDERATION_MAX_HOPS",
        value_parser = clap::value_parser!(u8).range(1..=255)
    )]
    pub(crate) federation_max_hops: u8,

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

    /// Maximum groups a single federation V2 peer can advertise.
    #[arg(
        long,
        default_value_t = 1000,
        env = "RUSTGATE_FEDERATION_MAX_GROUPS_PER_PEER"
    )]
    pub(crate) federation_max_groups_per_peer: usize,

    /// Maximum federation V2 group name length in bytes.
    #[arg(
        long,
        default_value_t = 256,
        env = "RUSTGATE_FEDERATION_MAX_GROUP_NAME_LENGTH"
    )]
    pub(crate) federation_max_group_name_length: usize,

    /// Trust wire-claimed `federate_groups` on inbound federated events
    /// as the authoritative group set for the originating client.
    ///
    /// **Default: off (deny-by-default).** A Byzantine federation peer
    /// with a valid mTLS client certificate can otherwise forge
    /// arbitrary group memberships for any origin CN, elevating that
    /// client's privileges across the federation boundary (issue #720).
    /// Only enable this flag when every peer is fully trusted to speak
    /// for every origin CN on its side of the federation — e.g. a
    /// single-operator multi-region deployment sharing one identity
    /// authority. See `docs/federation.md` for the threat model.
    #[arg(
        long,
        default_value_t = false,
        env = "RUSTGATE_FEDERATION_TRUST_PEER_GROUPS"
    )]
    pub(crate) federation_trust_peer_groups: bool,

    /// NATS URL for federation HA coordination (enables distributed peer ownership).
    /// When set, only one pod manages each outbound peer in a multi-pod deployment.
    /// Requires --features federation-ha.
    #[arg(long, env = "RUSTGATE_FEDERATION_HA_NATS_URL")]
    pub(crate) federation_ha_nats_url: Option<String>,

    /// Pod identifier for federation HA mode. Defaults to --federation-id if
    /// --federation-ha-nats-url is set.
    #[arg(long, env = "RUSTGATE_FEDERATION_POD_ID")]
    pub(crate) federation_pod_id: Option<String>,

    /// Geographic region for this federation server (e.g. "us-east", "eu-west").
    /// When set, matrix-mode routing prefers peers in the same region before
    /// falling back to cross-region peers sorted by latency and priority.
    #[arg(long, env = "RUSTGATE_FEDERATION_REGION")]
    pub(crate) federation_region: Option<String>,

    // -- JWKS rotation-window state machine (closes #952) --
    /// Pending → Active promotion window (seconds) for the JWKS rotation
    /// state machine. A newly observed `kid` must persist across at
    /// least one refresh AND remain visible for this many seconds before
    /// the verifier registry trusts it. Defends against typo'd JWKS
    /// pushes that get rolled back within seconds. Default: 60.
    #[arg(long, default_value_t = 60, env = "RUSTGATE_JWKS_PENDING_WINDOW_SECS")]
    pub(crate) jwks_pending_window_secs: u64,

    /// Retiring → Retired grace window (seconds) for the JWKS rotation
    /// state machine. When a `kid` drops from the upstream JWKS, the
    /// local verifier registry continues to honour it for this duration
    /// so JWTs minted just before the upstream removal still verify;
    /// each such verification emits the
    /// `audit::jwt_using_retiring_kid` event. Default: 300 (5 min).
    #[arg(
        long,
        default_value_t = 300,
        env = "RUSTGATE_JWKS_RETIRING_WINDOW_SECS"
    )]
    pub(crate) jwks_retiring_window_secs: u64,

    // -- Federation peer discovery (issue #571) --
    /// Dynamic federation peer discovery backend.
    ///
    /// When set to anything other than `none`, rustgate spawns a background
    /// reconciler that polls the selected backend on a fixed interval and
    /// pipes the result into the same `swap_peers` API used by the file
    /// reloader. Mutually exclusive with `--federation-peers-file`.
    #[arg(
        long,
        value_enum,
        default_value_t = PeerDiscoveryBackend::None,
        env = "RUSTGATE_FEDERATION_PEER_DISCOVERY",
        conflicts_with = "federation_peers_file"
    )]
    pub(crate) federation_peer_discovery: PeerDiscoveryBackend,

    /// Polling interval in seconds for the federation peer discovery
    /// reconciler. Ignored when `--federation-peer-discovery=none`.
    #[arg(
        long,
        default_value_t = 30,
        env = "RUSTGATE_FEDERATION_PEER_DISCOVERY_INTERVAL",
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    pub(crate) federation_peer_discovery_interval: u64,

    /// Service type browsed by the DNS-SD peer discovery backend.
    #[arg(
        long,
        default_value = "_rustgate._tcp.local.",
        env = "RUSTGATE_FEDERATION_PEER_DISCOVERY_DNS_SD_SERVICE"
    )]
    pub(crate) federation_peer_discovery_dns_sd_service: String,

    /// Consul catalog HTTP endpoint used by the Consul peer discovery
    /// backend (e.g. `http://consul.default.svc:8500`).
    #[arg(
        long,
        default_value = "http://127.0.0.1:8500",
        env = "RUSTGATE_FEDERATION_PEER_DISCOVERY_CONSUL_ADDR"
    )]
    pub(crate) federation_peer_discovery_consul_addr: String,

    /// Consul service name queried by the Consul peer discovery backend.
    #[arg(
        long,
        default_value = "rustgate",
        env = "RUSTGATE_FEDERATION_PEER_DISCOVERY_CONSUL_SERVICE"
    )]
    pub(crate) federation_peer_discovery_consul_service: String,

    /// Comma-separated list of etcd gRPC endpoints for the etcd peer
    /// discovery backend (e.g.
    /// `http://etcd-0:2379,http://etcd-1:2379,http://etcd-2:2379`).
    #[arg(
        long,
        default_value = "http://127.0.0.1:2379",
        env = "RUSTGATE_FEDERATION_PEER_DISCOVERY_ETCD_ENDPOINTS"
    )]
    pub(crate) federation_peer_discovery_etcd_endpoints: String,

    /// Key prefix scanned by the etcd peer discovery backend. Each key
    /// under this prefix becomes one federation peer entry.
    #[arg(
        long,
        default_value = "rustgate/peers/",
        env = "RUSTGATE_FEDERATION_PEER_DISCOVERY_ETCD_PREFIX"
    )]
    pub(crate) federation_peer_discovery_etcd_prefix: String,

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

    /// Opt into cross-tenant duplicate suppression. When `false` (the
    /// default), the dedup key folds in the sender's tenant so a
    /// message sent by tenant `A` CANNOT suppress a byte-identical
    /// message sent by tenant `B`. Setting this to `true` forces the
    /// tenant slot empty on every lookup, restoring the pre-#722
    /// behaviour. **Unsafe in any multi-tenant deployment where
    /// tenants do not fully trust each other** — it opens a timing
    /// side-channel where a malicious tenant can probe for specific
    /// messages in another tenant. Leave disabled unless you have a
    /// concrete reason and have accepted the risk.
    #[arg(long, default_value_t = false, env = "RUSTGATE_DEDUP_CROSS_TENANT")]
    pub(crate) dedup_cross_tenant: bool,

    /// Enable per-UID delta encoding for outbound CoT events on XML sessions.
    /// When enabled, each writer task tracks the last-sent event per UID
    /// and emits a compact `<delta>` wrapper carrying only the fields
    /// that changed. Disabled by default. Applies only to XML-framed
    /// sessions; protobuf sessions always receive full events.
    #[arg(long, default_value_t = false, env = "RUSTGATE_COT_DELTA_ENCODING")]
    pub(crate) cot_delta_encoding: bool,

    /// Per-session LRU cache capacity for the CoT delta encoder (entries).
    /// Oldest UIDs are evicted first; the next event for an evicted UID
    /// is emitted as a full event.
    #[arg(long, default_value_t = 512, value_parser = clap::value_parser!(u64).range(1..), env = "RUSTGATE_COT_DELTA_CACHE_SIZE")]
    pub(crate) cot_delta_cache_size: u64,

    /// Ground distance in meters below which position-only CoT updates
    /// are suppressed entirely. Set to `0` to disable suppression and
    /// ship every event (either full or delta, never suppressed).
    #[arg(long, default_value_t = 1.0, env = "RUSTGATE_COT_DELTA_EPSILON_METERS")]
    pub(crate) cot_delta_epsilon_meters: f64,

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

    /// Path to a JSON rustgate-authz policy file.
    ///
    /// When set, the server loads the policy at startup and installs the
    /// resulting engine on the router's RBAC/ABAC enforcement point. The
    /// file is validated before it is swapped in, so a malformed policy
    /// keeps the last known-good policy serving.
    #[arg(long, env = "RUSTGATE_AUTHZ_POLICY_FILE")]
    pub(crate) authz_policy_file: Option<String>,

    /// Authz policy format. `native` is the default rustgate-authz JSON
    /// ruleset; `cedar` loads a Cedar policy corpus via the optional
    /// `cedar` feature. Selecting `cedar` on a binary that was not
    /// compiled with `--features cedar` is rejected at startup.
    #[arg(long, value_enum, default_value_t = AuthzPolicyFormat::Native, env = "RUSTGATE_AUTHZ_POLICY_FORMAT")]
    pub(crate) authz_policy_format: AuthzPolicyFormat,

    /// Interval in seconds to check the authz policy file for changes.
    /// Must be >= 1. Applied only when `--authz-policy-file` is set.
    #[arg(long, default_value_t = 5, env = "RUSTGATE_AUTHZ_RELOAD_INTERVAL")]
    pub(crate) authz_reload_interval: u64,

    /// Fail-open mode: when the initial policy load fails, the server
    /// continues to start without an engine installed (no PEP) instead of
    /// aborting. The default (`false`) is fail-closed: a broken policy at
    /// startup prevents the server from coming up, which matches the
    /// deny-by-default security posture.
    #[arg(long, default_value_t = false, env = "RUSTGATE_AUTHZ_FAIL_OPEN")]
    pub(crate) authz_fail_open: bool,

    /// Allow the router to continue delivery when the authz engine
    /// returns an `Obligation` variant the transport build cannot
    /// actuate (e.g. a deliberately skewed rolling upgrade where new
    /// policy uses a future obligation the running binary does not
    /// understand yet).
    ///
    /// Default (`false`) is fail-closed per issue #728: the outbound
    /// copy is dropped and an audit record is emitted. Setting this
    /// to `true` reverts to the legacy fail-open behaviour (apply
    /// every known obligation, skip the unknown, continue delivery)
    /// and is intended solely as a short-lived operational opt-out.
    #[arg(
        long,
        default_value_t = false,
        env = "RUSTGATE_AUTHZ_ALLOW_UNKNOWN_OBLIGATIONS"
    )]
    pub(crate) authz_allow_unknown_obligations: bool,

    /// Refs #849 item 4: when `true`, every inbound message that lacks
    /// a CAPCO classification marking on its envelope is rejected at
    /// admission with a `classification.missing` audit record. Default
    /// `false` keeps pre-#849 behaviour: unmarked legacy traffic flows
    /// unchanged. Set this for deployments where every message MUST
    /// carry a marking (cross-domain solutions, classified networks).
    #[arg(
        long,
        default_value_t = false,
        env = "RUSTGATE_REQUIRE_CLASSIFICATION_MARKING"
    )]
    pub(crate) require_classification_marking: bool,

    /// Refs #849 item 4: per-listener default CAPCO classification
    /// banner. When set, every inbound message that does NOT already
    /// carry a `Metadata.classification` is stamped with this banner
    /// before policy evaluation. The value MUST parse as a CAPCO
    /// banner string (e.g. `"//UNCLASSIFIED"`, `"//SECRET//NOFORN"`).
    /// Combine with `--require-classification-marking` for a
    /// "stamp-or-reject" pipeline; combine without it to default-tag
    /// only the unmarked traffic.
    #[arg(long, env = "RUSTGATE_DEFAULT_CLASSIFICATION")]
    pub(crate) default_classification: Option<String>,

    /// Sustained per-CN replay rate (events per second) for
    /// `Router::replay_positions` (issue #724). Each reconnect consumes
    /// one token from a per-CN `TokenBucket`; when the bucket is
    /// empty the replay is skipped and an audit event is emitted.
    /// Default `100/sec` is permissive enough that a normal-cadence
    /// reconnect never gets shed; combined with `burst=200` this caps
    /// a 10×/sec flap-loop attack against a 10k-position cache to
    /// 200 replays/sec instead of 200,000 authz evals/sec.
    #[arg(
        long,
        default_value_t = 100,
        env = "RUSTGATE_POSITION_REPLAY_RATE_PER_SEC"
    )]
    pub(crate) position_replay_rate_per_sec: u32,

    /// Burst capacity for the per-CN replay rate limit (issue #724).
    /// Allows short bursts above the sustained rate before the bucket
    /// runs dry. Default `200` covers a worst-case correlated reconnect
    /// burst (e.g. an entire fleet that briefly lost connectivity)
    /// without limiting legitimate operator traffic.
    #[arg(long, default_value_t = 200, env = "RUSTGATE_POSITION_REPLAY_BURST")]
    pub(crate) position_replay_burst: u32,

    /// Path to a JSON file defining per-tenant connection quotas.
    ///
    /// When set, the server loads the quota configuration at startup and
    /// installs a `TenantQuotaTracker` on the router. Connections from
    /// tenants that exceed their `max_connections` limit are rejected at
    /// registration time. Tenants are identified by the certificate
    /// Organization (O) subject field.
    #[arg(long, env = "RUSTGATE_TENANT_QUOTA_FILE")]
    pub(crate) tenant_quota_file: Option<std::path::PathBuf>,

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

    /// Path to a file containing the bearer token required to access the
    /// read-only `/api/cert/`, `/api/crl/`, and `/api/dedup/` management
    /// REST endpoints.
    ///
    /// When unset, the management API is not registered at all — requests
    /// under those prefixes fall through to the metrics server's generic
    /// 404 handler. When set, every request must present
    /// `Authorization: Bearer <token>` and the supplied token is compared
    /// to the file contents in constant time (subject to the same
    /// `[32, 256]` byte length bounds as the ACL API).
    ///
    /// Unlike `--acl-api-token-file`, these endpoints are read-only —
    /// they surface diagnostics (cert expiry, CRL staleness, dedup cache
    /// stats) without allowing mutation. The token can therefore be
    /// issued to narrower scrape/polling jobs than the ACL write token.
    #[arg(long, env = "RUSTGATE_MGMT_API_TOKEN_FILE")]
    pub(crate) mgmt_api_token_file: Option<String>,

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

    /// Per-active-segment byte cap for the CoT archive. When the file
    /// currently being appended to grows beyond this size, the archiver
    /// seals it (writing the encrypted terminator when applicable),
    /// renames it with a `T<hh-mm-ss>` suffix, and opens a fresh
    /// segment at the stable `cot-<date>.jsonl[.enc]` path. Complements
    /// the daily date-based rotation for workloads where a single day
    /// can produce tens of gigabytes — e.g. a misbehaving policy that
    /// emits an audit record per message (#887 Part 4.4).
    ///
    /// Has no effect unless `--archive-dir` is set. `0` = unlimited.
    #[arg(long, default_value_t = 0, env = "RUSTGATE_ARCHIVE_MAX_ACTIVE_BYTES")]
    pub(crate) archive_max_active_bytes: u64,

    /// Interval (in seconds) between archive rotation passes. Defaults
    /// to 60s. Has no effect unless `--archive-dir` is set and at least
    /// one of `--archive-max-size`, `--archive-max-age`, or
    /// `--archive-max-active-bytes` is non-zero.
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

    /// Override the fail-closed continuity check that compares the persisted
    /// anchor (`<audit-log>.anchor`) with the live chain tip at startup. When
    /// the two disagree — which happens after log rotation without carrying
    /// the anchor forward, after a disk restore from backup, or after an
    /// attacker truncates the audit log — the server refuses to start by
    /// default and emits an `audit.chain_discontinuity` record. Setting this
    /// flag demotes the refusal to a warning so the new process can continue
    /// from the current (live) tip. Only use this after manually verifying
    /// the audit log is intact; the `audit.chain_discontinuity` record is
    /// still emitted so the operational skip is preserved in the audit
    /// trail. Has no effect when the audit log is `"-"` (stdout) or when
    /// an archive key file is configured (encrypted audit logs do not
    /// support tip recovery).
    #[arg(
        long,
        default_value_t = false,
        env = "RUSTGATE_AUDIT_ALLOW_CHAIN_BREAK"
    )]
    pub(crate) audit_allow_chain_break: bool,

    /// Write per-message access events as JSON lines to a dedicated
    /// file. When set, every routed message produces one access-log
    /// entry (target="access") with src_cn, dst, msg_uid, size, and
    /// outcome (delivered, dedup, expired). Use "-" for stdout.
    #[arg(long, env = "RUSTGATE_ACCESS_LOG")]
    pub(crate) access_log: Option<String>,

    /// Emit per-recipient `message.delivered` and `message.dropped`
    /// audit events for chain-of-custody trails on classified traffic.
    /// Default off — high-volume in busy deployments because a single
    /// broadcast to N subscribers produces N audit records. When set,
    /// the router invokes per-recipient hooks on every successful
    /// `try_send` (delivered) and every post-admission drop
    /// (backpressure / no_subscribers / etc.) so a SIEM can correlate
    /// individual recipients against the higher-cardinality
    /// `client.connected` / `client.disconnected` timeline. Closes #854.
    #[arg(long, default_value_t = false, env = "RUSTGATE_AUDIT_DELIVERY")]
    pub(crate) audit_delivery: bool,

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

    /// Path to a file containing the 32-byte HMAC-SHA256 key that
    /// integrity-protects stored offline messages. The file must
    /// contain exactly 64 hex characters (optionally followed by
    /// whitespace) and must be readable only by the rustgate owner
    /// (mode 0600). When set, the queue survives restarts without
    /// silently discarding stored messages.
    ///
    /// When unset, the queue refuses to start if pre-existing stored
    /// entries are found — either supply this flag to preserve them,
    /// or use `--client-queue-wipe-on-start` to discard them.
    #[arg(long, env = "RUSTGATE_CLIENT_QUEUE_KEY_FILE")]
    pub(crate) client_queue_key_file: Option<std::path::PathBuf>,

    /// Explicitly wipe the on-disk store-and-forward queue at startup
    /// before generating a fresh ephemeral HMAC key. Emits a
    /// `store_forward.key_rotated` audit event recording the depth of
    /// the discarded entries. Mutually exclusive with
    /// `--client-queue-key-file`. Use only when the operator is
    /// acknowledging deliberate data loss (e.g. during key rotation
    /// without a persisted predecessor).
    #[arg(
        long,
        default_value_t = false,
        env = "RUSTGATE_CLIENT_QUEUE_WIPE_ON_START",
        conflicts_with = "client_queue_key_file"
    )]
    pub(crate) client_queue_wipe_on_start: bool,

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
    /// Validate a config file end-to-end without starting any
    /// listeners, NATS connections, federation discovery, or other
    /// I/O. Wired into CI pipelines and `helm test` to confirm a
    /// rendered config would start cleanly before the pod is allowed
    /// to bind ports.
    ///
    /// Exit codes: `0` = config valid, `1` = config invalid (loaded
    /// but failed validation), `2` = config file unreadable (path
    /// missing, permission denied, malformed TOML).
    ///
    /// Closes #793.
    CheckConfig {
        /// Path to the TOML config file to validate. Required even
        /// when `--config` is also passed at the top level — the
        /// subcommand is intentionally explicit so a misconfigured
        /// alias cannot silently validate a different file.
        #[arg(long, value_name = "PATH")]
        config: std::path::PathBuf,
        /// Additionally check that referenced cert / ACL / authz /
        /// secret-bearing files exist and (on Unix) have
        /// `0o077`-conforming permissions on the secret-bearing
        /// subset (TLS key, metrics token, CA private key, archive
        /// key). Without `--strict` the schema and cross-field
        /// validations still run but referenced files are not
        /// touched on disk — useful when the rendered config
        /// outpaces materialization of the files it points at.
        #[arg(long)]
        strict: bool,
        /// Emit a stable JSON document
        /// (`{status, config_path, strict, errors, warnings}`)
        /// instead of the human layout. Suitable for `helm test`
        /// hooks and CI pipelines that machine-parse the result.
        #[arg(long)]
        json: bool,
    },
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
    /// Inspect a PEM-encoded X.509 certificate (subject, issuer, SANs,
    /// validity, groups, SPIFFE ID, fingerprint). Useful for
    /// debugging mTLS handshake failures without starting the server.
    CertInfo {
        /// Path to the certificate PEM file.
        #[arg(value_name = "FILE")]
        file: std::path::PathBuf,
        /// Emit a stable JSON document instead of the human layout.
        #[arg(long)]
        json: bool,
    },
    /// Inspect a PEM-encoded X.509 CRL (issuer, thisUpdate /
    /// nextUpdate freshness, and each revoked entry's serial,
    /// revocation date, and reason).
    CrlInfo {
        /// Path to the CRL PEM file.
        #[arg(value_name = "FILE")]
        file: std::path::PathBuf,
        /// Emit a stable JSON document instead of the human layout.
        #[arg(long)]
        json: bool,
    },
    /// Check whether one or more PEM-encoded X.509 certificates are
    /// within the warning window of their `notAfter` time, already
    /// expired, or not yet valid. Intended to be wired into cron /
    /// systemd pre-flight: exit code `0` = all clear, `1` = at least
    /// one cert expiring within `--warn-days`, `2` = expired /
    /// not-yet-valid / unreadable.
    CheckCertExpiry {
        /// One or more PEM files. Each file may contain a single cert,
        /// a chain/bundle, or cert blocks mixed with key material; only
        /// `CERTIFICATE` blocks are inspected.
        #[arg(value_name = "FILE", required = true, num_args = 1..)]
        files: Vec<std::path::PathBuf>,
        /// Emit a warning (exit 1) when a cert expires within this many
        /// days from now.
        #[arg(long, default_value_t = crate::diagnostics::check_cert_expiry::DEFAULT_WARN_DAYS)]
        warn_days: u32,
        /// Emit a stable JSON document instead of the human layout.
        #[arg(long)]
        json: bool,
    },
    /// Print an annotated TOML configuration template covering every
    /// option rustgate reads from a config file. Each key is emitted
    /// commented-out with its clap help text and the default the
    /// server would apply when the option is absent, so an operator
    /// can uncomment only the keys they want to override.
    ///
    /// Unlike [`Command::PrintConfig`], this runs before any parsing
    /// and before the server loads any TLS material: it inspects the
    /// CLI schema itself, so the output is a complete template
    /// suitable as a starting point for a new deployment.
    GenerateConfig {
        /// Emit only the bare-essentials configuration: TLS material,
        /// bind address, framing / encoding, and connection limits.
        /// Skip every other option, leaving the server to apply its
        /// defaults. Use this for first-time deployments and re-run
        /// without `--minimal` to see every available knob.
        #[arg(long)]
        minimal: bool,
    },
    /// Probe a single remote endpoint for reachability, without
    /// starting the server. Intended as a pre-flight for cron /
    /// Ansible / systemd `ExecStartPre=` so firewall, DNS, or
    /// service-outage problems are caught before `rustgate` itself
    /// tries to start.
    ///
    /// Exactly one of the `--tcp`, `--tls`, `--nats`, or `--http`
    /// flags must be supplied.
    ///
    /// TCP / NATS / HTTP exit codes: `0` = connected, `1` = refused,
    /// `2` = timeout, `3` = other error (DNS, bad URL, unexpected I/O).
    ///
    /// TLS exit codes (separate ladder, three values only):
    /// `0` = handshake succeeded and peer cert healthy, `1` = handshake
    /// failed for any reason (network, cert validation, timeout),
    /// `2` = handshake succeeded but peer cert expires within
    /// `--peer-cert-warn-days`.
    TestConnection {
        /// Plain TCP probe — three-way handshake only, no bytes sent.
        /// Works against every listener type (TLS, WebSocket, MQTT,
        /// plaintext, enrollment, metrics) without risking a malformed
        /// application-layer probe.
        #[arg(long, value_name = "HOST:PORT", conflicts_with = "tls")]
        tcp: Option<String>,
        /// TLS handshake probe — TCP connect plus a full mTLS handshake
        /// using the supplied client cert / key / CA. Reports the
        /// negotiated cipher and the peer certificate's `notAfter`.
        /// Triggers exit code `2` (separate from the TCP/NATS/HTTP
        /// ladder) when the peer cert is valid but expires within
        /// `--peer-cert-warn-days`.
        #[arg(
            long,
            value_name = "HOST:PORT",
            conflicts_with = "tcp",
            requires_all = ["target_cert", "target_key", "target_ca"],
        )]
        tls: Option<String>,
        /// PEM-encoded client certificate chain for the TLS probe.
        /// Required when `--tls` is supplied.
        #[arg(long, value_name = "PATH", required = false)]
        target_cert: Option<std::path::PathBuf>,
        /// PEM-encoded client private key for the TLS probe.
        /// Required when `--tls` is supplied.
        #[arg(long, value_name = "PATH", required = false)]
        target_key: Option<std::path::PathBuf>,
        /// PEM-encoded CA bundle the TLS probe trusts. Required when
        /// `--tls` is supplied.
        #[arg(long, value_name = "PATH", required = false)]
        target_ca: Option<std::path::PathBuf>,
        /// Server name to send in the TLS SNI extension and to
        /// validate the peer certificate against. Defaults to the host
        /// part of `--tls`.
        #[arg(long, value_name = "NAME")]
        server_name: Option<String>,
        /// Days before the peer certificate's `notAfter` at which the
        /// TLS probe reports `near_expiry` (exit code `2`). Only
        /// applied when `--tls` is supplied.
        #[arg(
            long,
            default_value_t = crate::diagnostics::test_connection::DEFAULT_PEER_CERT_WARN_DAYS,
        )]
        peer_cert_warn_days: u32,
        /// NATS probe — TCP connect plus a read of the server's
        /// `INFO` greeting. Catches listeners that accept TCP but
        /// reject NATS (misconfigured auth, wrong service on the
        /// port).
        #[cfg(feature = "nats")]
        #[arg(
            long,
            value_name = "URL",
            conflicts_with_all = ["tcp", "tls"],
        )]
        nats: Option<String>,
        /// HTTP probe — send `GET /` and classify by status line.
        /// 2xx/3xx/4xx report `connected`, 5xx reports `refused`.
        #[cfg(feature = "http")]
        #[arg(
            long,
            value_name = "URL",
            conflicts_with_all = ["tcp", "tls"],
        )]
        http: Option<String>,
        /// Overall timeout for the probe (seconds). Applies to the
        /// whole operation: DNS resolution, TCP handshake, and any
        /// protocol-level exchange.
        #[arg(
            long,
            default_value_t = crate::diagnostics::test_connection::DEFAULT_TIMEOUT_SECS,
        )]
        timeout_secs: u64,
        /// Emit a stable JSON document instead of the human layout.
        #[arg(long)]
        json: bool,
    },
    /// Emit a JSON Schema describing the `rustgate.toml` configuration
    /// file. The schema is written to stdout and is suitable for wiring
    /// into editor extensions (VS Code "Even Better TOML", IntelliJ /
    /// Helix LSPs) that consume JSON Schema for autocomplete and inline
    /// validation. The committed `schemas/rustgate-vX.Y.json` is
    /// regenerated by piping this subcommand's output into the file.
    ///
    /// Only available when the binary is built with `--features schema`
    /// — the default build keeps the `schemars` dependency out of the
    /// runtime image. Issue #815, F-137.
    #[cfg(feature = "schema")]
    EmitSchema,
    /// Rewrite a TOML configuration file from a previous rustgate
    /// release's schema into the schema this binary understands. The
    /// pipeline preserves blank lines and comments via `toml_edit`,
    /// renames known-obsolete keys, drops removed-with-warning knobs,
    /// and stamps a `# Generated by rustgate migrate-config from
    /// <source>` banner on the rewritten output.
    ///
    /// The source version is detected in the following priority order:
    ///   1. `--from <version>` (when supplied)
    ///   2. A `# rustgate-version: <version>` comment at the top of the
    ///      input file
    ///   3. A heuristic check for known-obsolete top-level keys
    ///   4. Fallback: assume the current schema and produce a no-op
    ///      pass through the chain (only the banner is added)
    ///
    /// Wire this in front of `validate-config` in CI so a config that
    /// would have failed parsing on a new rustgate is auto-rewritten
    /// into a shape the binary accepts:
    ///
    /// ```text
    /// rustgate migrate-config rustgate.toml --output rustgate.next.toml
    /// rustgate --config rustgate.next.toml validate-config
    /// ```
    ///
    /// See `docs/migrations.md` for the full upgrade matrix.
    /// Closes #815 (F-138).
    MigrateConfig {
        /// Path to the TOML file to migrate. Read-only — the input is
        /// never modified in place; the rewritten output goes to
        /// `--output` (when supplied) or stdout.
        #[arg(value_name = "PATH")]
        config: std::path::PathBuf,
        /// Optional path to write the migrated TOML to. When omitted
        /// the rewritten document is emitted on stdout so the
        /// subcommand pipes cleanly into `tee`, `diff`, or another
        /// invocation of rustgate.
        #[arg(long, value_name = "PATH")]
        output: Option<std::path::PathBuf>,
        /// Override the source-version detection. Accepts the
        /// canonical strings (`0.8`, `pre-0.8`) plus the most common
        /// variants an operator might type (`v0.8`, `0.8.0`). Anything
        /// else returns a typed error so a wrapper can branch on the
        /// failure mode.
        #[arg(long, value_name = "VERSION")]
        from: Option<String>,
    },
    /// Capture an on-disk diagnostic snapshot of the server's locally
    /// observable state: build metadata, the merged configuration with
    /// all secret-bearing fields redacted, the configured CRL summary
    /// (if any), and the last 100 lines of the audit log (if
    /// configured). Intended for forensics and bug reports — the
    /// command runs offline against the same `--config` the server
    /// would consume, never connects to a remote endpoint, and never
    /// writes secrets to its output. Closes #900.
    DumpState {
        /// Path to the TOML config file the running server uses. The
        /// command merges flags + env + file the same way the server
        /// would, so the snapshot reflects the actual effective config.
        #[arg(long, value_name = "PATH")]
        config: std::path::PathBuf,
        /// Output format. `json` (the default) emits a stable
        /// machine-readable document for tooling; `toml` emits a more
        /// human-readable layout for ticket attachments.
        #[arg(long, value_enum, default_value_t = DumpFormat::Json)]
        format: DumpFormat,
        /// Optional path to write the snapshot to. When omitted the
        /// snapshot is written to stdout. The file is created with
        /// owner-only permissions (`0o600` on Unix) because even
        /// redacted snapshots leak topology information.
        #[arg(long, value_name = "PATH")]
        output: Option<std::path::PathBuf>,
    },
}

/// Output format for `dump-state`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum DumpFormat {
    /// Stable JSON document — preferred for tooling.
    Json,
    /// TOML — preferred for ticket attachments and human review.
    Toml,
}

#[derive(Debug, Clone, Copy, ValueEnum, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
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
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Encoding {
    Raw,
    Cot,
    /// TAK protobuf encoding (proto <-> XML at session edge). Requires --features proto.
    TakProtobuf,
}

/// Selects which dynamic federation peer discovery backend is used.
///
/// `None` (the default) disables discovery entirely; static peer
/// configuration via `--federation-peers-file` remains the only source of
/// truth. The other variants each map to a backend gated behind its own
/// cargo feature (`peer-discovery-dns-sd`, `peer-discovery-consul`,
/// `peer-discovery-etcd`); selecting a backend whose feature was not
/// compiled in surfaces a startup error.
/// Authz policy-file format selector.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub(crate) enum AuthzPolicyFormat {
    /// Native rustgate-authz JSON ruleset.
    #[default]
    Native,
    /// Cedar policy corpus (requires the `cedar` feature).
    Cedar,
}

/// MQTT SUBSCRIBE wildcard policy selector for the CLI / config file.
///
/// Mirrors `rustgate_mqtt::WildcardPolicy` but is owned by the server
/// crate so `rustgate-mqtt` does not need a clap dependency. A plain
/// code reference is used instead of an intra-doc link because the
/// `rustgate-mqtt` crate is an optional dependency that is absent from
/// the default feature set used by `cargo doc --workspace --no-deps`
/// on the docs-site build. The defaulting behaviour
/// (`single-level-only`) matches the MQTT adapter's own default so
/// operators who omit the flag get spec-conformant single-level (`+`)
/// wildcards without the `#` firehose.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub(crate) enum MqttWildcardPolicy {
    /// Reject both `+` and `#`. Exact-topic subscriptions only.
    Reject,
    /// Accept `+` (single-level). Reject `#` (multi-level). Default.
    #[default]
    SingleLevelOnly,
    /// Accept both `+` and `#`.
    Full,
}

#[cfg(feature = "mqtt")]
impl From<MqttWildcardPolicy> for rustgate_mqtt::WildcardPolicy {
    fn from(policy: MqttWildcardPolicy) -> Self {
        match policy {
            MqttWildcardPolicy::Reject => Self::Reject,
            MqttWildcardPolicy::SingleLevelOnly => Self::SingleLevelOnly,
            MqttWildcardPolicy::Full => Self::Full,
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub(crate) enum PeerDiscoveryBackend {
    #[default]
    None,
    DnsSd,
    Consul,
    Etcd,
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
        #[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
        #[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
        pub(crate) struct ConfigFile {
            $( pub(crate) $field: Option<$ty>, )*
        }

        impl ConfigFile {
            /// Apply this file's values to `cli`, overwriting only fields
            /// whose value source is `DefaultValue` (i.e. not supplied by
            /// the user on the command line or via an environment variable).
            pub(crate) fn apply_to(self, cli: &mut Cli, matches: &ArgMatches) {
                $(
                    if let Some(v) = self.$field
                        && matches!(matches.value_source(stringify!($field)), Some(ValueSource::DefaultValue) | None)
                    {
                        cli.$field = v;
                    }
                )*
            }
        }

        /// Snake-case identifiers of every [`ConfigFile`] field in source
        /// order. This is the authoritative list of keys that
        /// `generate-config` templates and that TOML deserialization
        /// accepts (after the macro's `rename_all = "kebab-case"`).
        pub(crate) const CONFIG_FILE_FIELDS: &[&str] = &[
            $( stringify!($field), )*
        ];
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
    air_gap: bool,
    prefer_post_quantum: bool,
    kx_groups: Option<String>,
    cnsa2: bool,
    cert_reload_interval: u64,
    ocsp_stapling: bool,
    spiffe: bool,
    spiffe_workload_api_socket: String,
    spiffe_trust_domain: Option<String>,
    spiffe_refresh_interval: u64,
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
    nats_max_deliver: i64,
    nats_dead_letter_subject: Option<String>,
    nats_checkpoint_path: Option<String>,
    http_config_file: Option<String>,
    lattice_config_file: Option<String>,
    ogc_sensorthings_config_file: Option<String>,
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
    est_enabled: bool,
    metrics_bind: Option<String>,
    metrics_token_file: Option<String>,
    metrics_per_identity: bool,
    metrics_identity_allowlist: Option<std::path::PathBuf>,
    metrics_max_connections: usize,
    max_connections: usize,
    shutdown_drain_timeout: u64,
    max_concurrent_handshakes: usize,
    negotiation_timeout_secs: u64,
    max_queued_bytes: usize,
    max_queued_bytes_low_water: Option<usize>,
    backpressure_resume_dwell_ms: u64,
    websocket_bind: Option<String>,
    ws_max_frames_per_sec: u32,
    ws_max_bytes_per_sec: u64,
    ws_max_violations: u32,
    ws_max_write_buffer_bytes: usize,
    ws_max_frame_size: usize,
    ws_max_message_size: usize,
    ws_rate_limit_max: usize,
    ws_rate_limit_window_secs: u64,
    ws_subprotocols: Vec<String>,
    ws_subprotocol_strict: bool,
    ws_compression_disabled: bool,
    ws_ping_interval_secs: u64,
    ws_pong_timeout_secs: u64,
    mqtt_bind: Option<String>,
    mqtt_topic_prefix: Option<String>,
    mqtt_max_packet_size: usize,
    mqtt_receive_max: u16,
    mqtt_topic_alias_max: u16,
    mqtt_max_session_expiry_secs: u32,
    mqtt_max_retained_sessions: usize,
    mqtt_min_keep_alive_secs: u16,
    mqtt_server_keep_alive_secs: u16,
    mqtt_response_channel_capacity: usize,
    mqtt_wildcard_policy: MqttWildcardPolicy,
    mavlink_require_signing: bool,
    mavlink_allow_v1: bool,
    tcp_bind: Option<String>,
    udp_bind: Option<String>,
    udp_rate_limit: u32,
    udp_allowed_cidrs: Option<String>,
    udp_max_identities: usize,
    udp_multicast_groups: Option<String>,
    udp_multicast_interface: String,
    udp_multicast_loop: bool,
    udp_multicast_ttl: u32,
    udp_multicast_rebroadcast: bool,
    udp_multicast_max_bps: u64,
    plaintext_cn: String,
    plaintext_group: String,
    federation_v1_bind: Option<String>,
    federation_v2_bind: Option<String>,
    federation_id: String,
    federation_peers_file: Option<String>,
    federation_peers_reload_interval: u64,
    federation_skip_hostname_verify: bool,
    federation_max_hops: u8,
    federation_store_path: Option<String>,
    federation_trust_store_dir: Option<String>,
    federation_circuit_breaker_threshold: u32,
    federation_circuit_breaker_timeout: u64,
    federation_replay_buffer_size: usize,
    federation_replay_dir: Option<std::path::PathBuf>,
    federation_replay_max_bytes: u64,
    federation_max_groups_per_peer: usize,
    federation_max_group_name_length: usize,
    federation_trust_peer_groups: bool,
    federation_ha_nats_url: Option<String>,
    federation_pod_id: Option<String>,
    federation_region: Option<String>,
    federation_peer_discovery: PeerDiscoveryBackend,
    federation_peer_discovery_interval: u64,
    federation_peer_discovery_dns_sd_service: String,
    federation_peer_discovery_consul_addr: String,
    federation_peer_discovery_consul_service: String,
    federation_peer_discovery_etcd_endpoints: String,
    federation_peer_discovery_etcd_prefix: String,
    jwks_pending_window_secs: u64,
    jwks_retiring_window_secs: u64,
    replay_window: u64,
    client_message_rate: u32,
    client_burst: u32,
    circuit_breaker_threshold: u32,
    group_acl_file: Option<String>,
    acl_reload_interval: u64,
    authz_policy_file: Option<String>,
    authz_policy_format: AuthzPolicyFormat,
    authz_reload_interval: u64,
    authz_fail_open: bool,
    authz_allow_unknown_obligations: bool,
    require_classification_marking: bool,
    default_classification: Option<String>,
    position_replay_rate_per_sec: u32,
    position_replay_burst: u32,
    tenant_quota_file: Option<std::path::PathBuf>,
    acl_api_token_file: Option<String>,
    mgmt_api_token_file: Option<String>,
    archive_dir: Option<String>,
    archive_key_file: Option<std::path::PathBuf>,
    archive_max_size: u64,
    archive_max_age: u64,
    archive_max_active_bytes: u64,
    archive_rotate_interval: u64,
    package_max_age_hours: u64,
    audit_log: Option<String>,
    audit_allow_chain_break: bool,
    access_log: Option<String>,
    audit_delivery: bool,
    client_queue_dir: Option<std::path::PathBuf>,
    client_queue_max_bytes: u64,
    client_queue_key_file: Option<std::path::PathBuf>,
    client_queue_wipe_on_start: bool,
    otel_endpoint: Option<String>,
    otel_service_name: String,
    otlp_metrics: bool,
    otlp_metrics_interval: u64,
    dedup_window_secs: u64,
    dedup_cache_size: usize,
    dedup_cross_tenant: bool,
    cot_delta_encoding: bool,
    cot_delta_cache_size: u64,
    cot_delta_epsilon_meters: f64,
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
    ///
    /// Checks mTLS material presence, TLS file existence, federation
    /// prerequisites, rate-limit sanity, authz fail-open guard, and
    /// ACL reload interval bounds. All errors are actionable messages
    /// so operators can fix configuration before the server starts.
    pub(crate) fn validate(&self) -> anyhow::Result<()> {
        // SPIFFE mode obtains cert/key/ca from the Workload API, so
        // file-based TLS checks do not apply.
        if !self.spiffe {
            // Non-empty checks delegate to the shared validator; messages
            // are wrapped to preserve the longstanding operator-facing
            // "(or [<key>] in the config file)" hint that makes the error
            // actionable from either CLI or config-file misconfiguration.
            if core_validate_non_empty(&self.cert, "--cert").is_err() {
                anyhow::bail!("--cert (or [cert] in the config file) is required");
            }
            if core_validate_non_empty(&self.key, "--key").is_err() {
                anyhow::bail!("--key (or [key] in the config file) is required");
            }
            if core_validate_non_empty(&self.ca, "--ca").is_err() {
                anyhow::bail!("--ca (or [ca] in the config file) is required");
            }

            // TLS file existence — catch typos / missing mounts before the
            // TLS stack produces a cryptic I/O error. The operator-facing
            // text below matches the longstanding format ("TLS cert file
            // not found: <path>") that operator runbooks and our own
            // regression tests grep on; the shared validator's structured
            // error is consumed only as a yes/no probe here.
            if !self.cert.is_empty()
                && core_validate_path(std::path::Path::new(&self.cert), "--cert").is_err()
            {
                anyhow::bail!("TLS cert file not found: {}", self.cert);
            }
            if !self.key.is_empty()
                && core_validate_path(std::path::Path::new(&self.key), "--key").is_err()
            {
                anyhow::bail!("TLS key file not found: {}", self.key);
            }
            if !self.ca.is_empty()
                && core_validate_path(std::path::Path::new(&self.ca), "--ca").is_err()
            {
                anyhow::bail!("TLS CA file not found: {}", self.ca);
            }
        }

        // Federation requires an explicit identity.
        let federation_enabled = self.federation_v1_bind.is_some()
            || self.federation_v2_bind.is_some()
            || self.federation_peers_file.is_some();
        if federation_enabled && self.federation_id.is_empty() {
            anyhow::bail!("--federation-id is required when federation is enabled");
        }

        // Rate-limit sanity — burst must absorb at least the steady-state rate.
        if self.client_message_rate > 0 && self.client_burst < self.client_message_rate {
            anyhow::bail!(
                "--client-burst ({}) must be >= --client-message-rate ({})",
                self.client_burst,
                self.client_message_rate,
            );
        }

        // Authz fail-open without a policy file is a no-op; warn rather
        // than bail so the server still starts (harmless misconfiguration).
        if self.authz_fail_open && self.authz_policy_file.is_none() {
            tracing::warn!("--authz-fail-open has no effect without --authz-policy-file");
        }

        // Refs #849: a `--default-classification` value MUST parse as a
        // CAPCO banner string. Catch typos at startup rather than on
        // every inbound message.
        if let Some(ref banner) = self.default_classification
            && let Err(e) = banner.parse::<rustgate_core::classification::ClassificationMarking>()
        {
            anyhow::bail!("--default-classification ({banner:?}) is not a valid CAPCO banner: {e}");
        }

        if self.authz_policy_file.is_some() && self.authz_reload_interval == 0 {
            anyhow::bail!("--authz-reload-interval must be >= 1 when --authz-policy-file is set");
        }

        // ACL reload interval must be non-zero when an ACL file is set,
        // matching the authz_reload_interval check above.
        if self.group_acl_file.is_some() && self.acl_reload_interval == 0 {
            anyhow::bail!("--acl-reload-interval must be >= 1 when --group-acl-file is set");
        }

        // CoT archive rotation cadence must not be too aggressive. Short
        // intervals (e.g., 1 minute) open/close archive files and rewrite
        // the chain-tip anchor frequently, which widens the torn-write
        // window and increases load for no operator benefit. Enforce a
        // hard minimum of MIN_ROTATION_INTERVAL_SECS and warn below the
        // recommended RECOMMENDED_MIN_ROTATION_INTERVAL_SECS.
        let archive_rotation_enabled = self.archive_dir.is_some()
            && (self.archive_max_size > 0
                || self.archive_max_age > 0
                || self.archive_max_active_bytes > 0);
        if archive_rotation_enabled {
            if self.archive_rotate_interval < MIN_ROTATION_INTERVAL_SECS {
                anyhow::bail!(
                    "--archive-rotate-interval ({}) must be >= {} seconds",
                    self.archive_rotate_interval,
                    MIN_ROTATION_INTERVAL_SECS,
                );
            }
            if self.archive_rotate_interval < RECOMMENDED_MIN_ROTATION_INTERVAL_SECS {
                tracing::warn!(
                    interval_secs = self.archive_rotate_interval,
                    recommended_min_secs = RECOMMENDED_MIN_ROTATION_INTERVAL_SECS,
                    "--archive-rotate-interval is below the recommended minimum; \
                     aggressive rotation widens the torn-write window and stresses disk I/O",
                );
            }
        }

        // Validate ws buffer size — CLI args go through the clap value_parser,
        // but TOML config values bypass it and need an explicit check here.
        let _ = validate_write_buffer_range(self.ws_max_write_buffer_bytes)
            .map_err(|e| anyhow::anyhow!("ws-max-write-buffer-bytes: {e}"))?;
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
        // F-65: pin the default at 10s so a future change cannot
        // silently re-introduce the 30s slow-negotiate window.
        assert_eq!(cli.negotiation_timeout_secs, 10);
    }

    #[test]
    fn cli_negotiation_timeout_override() {
        let cli = Cli::try_parse_from([
            "rustgate",
            "--cert",
            "c.pem",
            "--key",
            "k.pem",
            "--ca",
            "ca.pem",
            "--negotiation-timeout-secs",
            "5",
        ])
        .expect("should parse");
        assert_eq!(cli.negotiation_timeout_secs, 5);
    }

    #[test]
    fn cli_rejects_zero_negotiation_timeout() {
        // Zero would short-circuit every negotiation and is never the
        // operator intent; `parse_nonzero_u64` enforces the floor.
        let result = Cli::try_parse_from([
            "rustgate",
            "--cert",
            "c.pem",
            "--key",
            "k.pem",
            "--ca",
            "ca.pem",
            "--negotiation-timeout-secs",
            "0",
        ]);
        assert!(result.is_err(), "zero timeout must be rejected");
    }

    #[cfg(feature = "proto")]
    #[test]
    fn cli_negotiation_timeout_default_matches_proto_const() {
        // The CLI carries the literal default `10` so it compiles
        // without `--features proto`. When `proto` is on, that literal
        // must agree with `rustgate_proto::NEGOTIATION_TIMEOUT_DEFAULT_SECS`
        // so a single-source bump in the proto crate is reflected at
        // the binary surface.
        let cli = Cli::try_parse_from([
            "rustgate", "--cert", "c.pem", "--key", "k.pem", "--ca", "ca.pem",
        ])
        .expect("should parse");
        assert_eq!(
            cli.negotiation_timeout_secs,
            rustgate_proto::NEGOTIATION_TIMEOUT_DEFAULT_SECS,
            "CLI default must mirror the proto crate's authoritative const",
        );
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
            "RUSTGATE_NATS_MAX_DELIVER",
            "RUSTGATE_NATS_DEAD_LETTER_SUBJECT",
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
            "RUSTGATE_NEGOTIATION_TIMEOUT_SECS",
            "RUSTGATE_WEBSOCKET_BIND",
            "RUSTGATE_WS_MAX_FRAMES_PER_SEC",
            "RUSTGATE_WS_MAX_BYTES_PER_SEC",
            "RUSTGATE_WS_MAX_VIOLATIONS",
            "RUSTGATE_WS_MAX_WRITE_BUFFER_BYTES",
            "RUSTGATE_MAVLINK_REQUIRE_SIGNING",
            "RUSTGATE_MAVLINK_ALLOW_V1",
            "RUSTGATE_TCP_BIND",
            "RUSTGATE_UDP_BIND",
            "RUSTGATE_UDP_RATE_LIMIT",
            "RUSTGATE_UDP_ALLOWED_CIDRS",
            "RUSTGATE_UDP_MAX_IDENTITIES",
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
            "RUSTGATE_FEDERATION_REGION",
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
        // Default is 8, matching the historical hard-coded
        // MAX_FEDERATION_HOPS that was the inbound enforcement bound
        // before #758. See `cli_federation_max_hops_default_eight` for
        // the explicit pin.
        assert_eq!(cli.federation_max_hops, 8);
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

    /// Pin the new default for `--federation-max-hops` post-#758.
    /// Before this PR, the CLI defaulted to 10 (only used for V1
    /// outbound metadata), while the V2 inbound bound was a separate
    /// hard-coded constant of 8. Aligning the default to 8 unifies
    /// the two values without changing inbound enforcement behavior.
    #[test]
    fn cli_federation_max_hops_default_eight() {
        let cli = Cli::try_parse_from([
            "rustgate", "--cert", "c.pem", "--key", "k.pem", "--ca", "ca.pem",
        ])
        .expect("should parse");
        assert_eq!(
            cli.federation_max_hops, 8,
            "default --federation-max-hops must be 8 (matches MAX_FEDERATION_HOPS)"
        );
    }

    /// `--federation-max-hops <N>` must accept overrides in the
    /// allowed `1..=255` range and round-trip through the parser.
    #[test]
    fn cli_federation_max_hops_override() {
        let cli = Cli::try_parse_from([
            "rustgate",
            "--cert",
            "c.pem",
            "--key",
            "k.pem",
            "--ca",
            "ca.pem",
            "--federation-max-hops",
            "16",
        ])
        .expect("should parse");
        assert_eq!(cli.federation_max_hops, 16);
    }

    /// `--federation-max-hops 0` must be rejected at CLI parse time:
    /// `0` would reject every inbound message (including the first
    /// hop), breaking federation entirely. The clap value-range
    /// `1..=255` is the front-line guard; this test guarantees the
    /// validator is wired and that the failure surfaces at the CLI
    /// layer rather than deeper in the FederationService builder.
    #[test]
    fn cli_federation_max_hops_rejects_zero() {
        let result = Cli::try_parse_from([
            "rustgate",
            "--cert",
            "c.pem",
            "--key",
            "k.pem",
            "--ca",
            "ca.pem",
            "--federation-max-hops",
            "0",
        ]);
        assert!(
            result.is_err(),
            "--federation-max-hops 0 must be rejected by clap (range 1..=255)"
        );
    }

    /// `--federation-max-hops` above 255 must be rejected at CLI
    /// parse time. The narrower `u8` type and the explicit
    /// `value_parser!(u8).range(1..=255)` together catch operator
    /// typos (e.g. `1000` instead of `100`) before they propagate
    /// into the FederationService builder.
    #[test]
    fn cli_federation_max_hops_rejects_above_255() {
        let result = Cli::try_parse_from([
            "rustgate",
            "--cert",
            "c.pem",
            "--key",
            "k.pem",
            "--ca",
            "ca.pem",
            "--federation-max-hops",
            "256",
        ]);
        assert!(
            result.is_err(),
            "--federation-max-hops 256 must be rejected by clap (range 1..=255)"
        );
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

    #[test]
    fn cli_audit_allow_chain_break_defaults_false() {
        let cli = Cli::try_parse_from([
            "rustgate", "--cert", "c.pem", "--key", "k.pem", "--ca", "ca.pem",
        ])
        .expect("should parse");
        assert!(!cli.audit_allow_chain_break);
    }

    #[test]
    fn cli_audit_allow_chain_break_opt_in() {
        let cli = Cli::try_parse_from([
            "rustgate",
            "--cert",
            "c.pem",
            "--key",
            "k.pem",
            "--ca",
            "ca.pem",
            "--audit-allow-chain-break",
        ])
        .expect("should parse");
        assert!(cli.audit_allow_chain_break);
    }

    #[test]
    fn cli_audit_delivery_defaults_false() {
        // Closes #854. Per-recipient delivery audit is opt-in because
        // it produces one record per recipient — high-volume in busy
        // deployments. The default must keep the routing hot path
        // silent.
        let cli = Cli::try_parse_from([
            "rustgate", "--cert", "c.pem", "--key", "k.pem", "--ca", "ca.pem",
        ])
        .expect("should parse");
        assert!(!cli.audit_delivery);
    }

    #[test]
    fn cli_audit_delivery_opt_in() {
        // Closes #854. The flag is the only way to install the
        // per-recipient delivery audit callbacks; pin the parsing
        // contract so a typo or rename of the long form fails this
        // test instead of silently breaking the operator-facing
        // surface.
        let cli = Cli::try_parse_from([
            "rustgate",
            "--cert",
            "c.pem",
            "--key",
            "k.pem",
            "--ca",
            "ca.pem",
            "--audit-delivery",
        ])
        .expect("should parse");
        assert!(cli.audit_delivery);
    }

    #[test]
    fn cli_jwks_rotation_window_defaults_match_documented_values() {
        // Closes #952. Backward-compat for existing JWKS deployments:
        // operators that do not set --jwks-pending-window-secs or
        // --jwks-retiring-window-secs pick up the documented defaults
        // (60s pending, 300s retiring) — same behaviour they have
        // today plus the rotation-window smoothing.
        let cli = Cli::try_parse_from([
            "rustgate", "--cert", "c.pem", "--key", "k.pem", "--ca", "ca.pem",
        ])
        .expect("should parse");
        assert_eq!(cli.jwks_pending_window_secs, 60);
        assert_eq!(cli.jwks_retiring_window_secs, 300);
    }

    #[test]
    fn cli_jwks_rotation_window_overrides_parse() {
        // Closes #952. Pin the parser contract for both new flags so a
        // typo or rename of the long form fails this test instead of
        // silently breaking the operator-facing surface.
        let cli = Cli::try_parse_from([
            "rustgate",
            "--cert",
            "c.pem",
            "--key",
            "k.pem",
            "--ca",
            "ca.pem",
            "--jwks-pending-window-secs",
            "120",
            "--jwks-retiring-window-secs",
            "600",
        ])
        .expect("should parse");
        assert_eq!(cli.jwks_pending_window_secs, 120);
        assert_eq!(cli.jwks_retiring_window_secs, 600);
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

    #[test]
    fn cli_ws_max_write_buffer_bytes_default() {
        let cli = Cli::try_parse_from([
            "rustgate", "--cert", "c.pem", "--key", "k.pem", "--ca", "ca.pem",
        ])
        .expect("should parse");
        assert_eq!(cli.ws_max_write_buffer_bytes, WS_WRITE_BUFFER_DEFAULT);
    }

    #[test]
    fn cli_ws_max_write_buffer_bytes_override() {
        let cli = Cli::try_parse_from([
            "rustgate",
            "--cert",
            "c.pem",
            "--key",
            "k.pem",
            "--ca",
            "ca.pem",
            "--ws-max-write-buffer-bytes",
            "1048576",
        ])
        .expect("should parse");
        assert_eq!(cli.ws_max_write_buffer_bytes, 1_048_576);
    }

    #[test]
    fn cli_ws_max_write_buffer_bytes_rejects_below_minimum() {
        let result = Cli::try_parse_from([
            "rustgate",
            "--cert",
            "c.pem",
            "--key",
            "k.pem",
            "--ca",
            "ca.pem",
            "--ws-max-write-buffer-bytes",
            "1024",
        ]);
        assert!(result.is_err(), "should reject values below 64 KiB");
    }

    #[test]
    fn cli_ws_max_write_buffer_bytes_rejects_above_maximum() {
        let result = Cli::try_parse_from([
            "rustgate",
            "--cert",
            "c.pem",
            "--key",
            "k.pem",
            "--ca",
            "ca.pem",
            "--ws-max-write-buffer-bytes",
            "134217728",
        ]);
        assert!(result.is_err(), "should reject values above 64 MiB");
    }

    #[test]
    fn cli_ws_max_write_buffer_bytes_accepts_minimum() {
        let cli = Cli::try_parse_from([
            "rustgate",
            "--cert",
            "c.pem",
            "--key",
            "k.pem",
            "--ca",
            "ca.pem",
            "--ws-max-write-buffer-bytes",
            "65536",
        ])
        .expect("should parse minimum (64 KiB)");
        assert_eq!(cli.ws_max_write_buffer_bytes, 65_536);
    }

    #[test]
    fn cli_ws_max_write_buffer_bytes_accepts_maximum() {
        let cli = Cli::try_parse_from([
            "rustgate",
            "--cert",
            "c.pem",
            "--key",
            "k.pem",
            "--ca",
            "ca.pem",
            "--ws-max-write-buffer-bytes",
            "67108864",
        ])
        .expect("should parse maximum (64 MiB)");
        assert_eq!(cli.ws_max_write_buffer_bytes, 67_108_864);
    }

    #[cfg(feature = "websocket")]
    #[test]
    fn ws_write_buffer_default_matches_websocket_crate() {
        assert_eq!(
            WS_WRITE_BUFFER_DEFAULT,
            rustgate_websocket::DEFAULT_MAX_WRITE_BUFFER_BYTES,
            "cli.rs default must stay in sync with rustgate_websocket"
        );
    }

    // ── F-59: --ws-rate-limit-max / --ws-rate-limit-window-secs ───────
    //
    // Pin the new canonical flag names introduced for #756, plus the
    // backward-compat aliases (`--ws-conn-rate-limit`,
    // `--ws-conn-rate-window-secs`) that #1bec522 shipped before this PR.
    // Defaults must match the pre-#756 hard-coded constants in
    // `rustgate_websocket::{DEFAULT_CONN_RATE_LIMIT, DEFAULT_CONN_RATE_WINDOW}`
    // so deployments that do not set the knobs see no behaviour change.

    #[cfg(feature = "websocket")]
    #[test]
    fn ws_listener_config_default_rate_limit_matches_pre_pr_constants() {
        // The shipped default in `WsListenerConfig::default()` is the
        // contract; the CLI default must echo it exactly.
        let cfg = rustgate_websocket::WsListenerConfig::default();
        assert_eq!(cfg.conn_rate_limit, 10, "pre-#756 const = 10");
        assert_eq!(
            cfg.conn_rate_window,
            std::time::Duration::from_secs(10),
            "pre-#756 const = 10s"
        );

        let cli = Cli::try_parse_from([
            "rustgate", "--cert", "c.pem", "--key", "k.pem", "--ca", "ca.pem",
        ])
        .expect("should parse");
        assert_eq!(cli.ws_rate_limit_max, cfg.conn_rate_limit);
        assert_eq!(
            cli.ws_rate_limit_window_secs,
            cfg.conn_rate_window.as_secs()
        );
    }

    #[test]
    fn ws_listener_config_rate_limit_overridable_via_cli() {
        // Production deployments (1000-peer fleets) must be able to raise
        // the cap without recompile. Pin both flags accept overrides.
        let cli = Cli::try_parse_from([
            "rustgate",
            "--cert",
            "c.pem",
            "--key",
            "k.pem",
            "--ca",
            "ca.pem",
            "--ws-rate-limit-max",
            "200",
            "--ws-rate-limit-window-secs",
            "30",
        ])
        .expect("should parse");
        assert_eq!(cli.ws_rate_limit_max, 200);
        assert_eq!(cli.ws_rate_limit_window_secs, 30);
    }

    #[test]
    fn ws_rate_limit_legacy_aliases_still_parse() {
        // `--ws-conn-rate-limit` / `--ws-conn-rate-window-secs` are the
        // pre-#756 names. They are retained as `visible_alias` so configs
        // baked into ops scripts before this PR keep working.
        let cli = Cli::try_parse_from([
            "rustgate",
            "--cert",
            "c.pem",
            "--key",
            "k.pem",
            "--ca",
            "ca.pem",
            "--ws-conn-rate-limit",
            "50",
            "--ws-conn-rate-window-secs",
            "20",
        ])
        .expect("legacy aliases must still parse");
        assert_eq!(cli.ws_rate_limit_max, 50);
        assert_eq!(cli.ws_rate_limit_window_secs, 20);
    }

    #[test]
    fn ws_rate_limit_toml_key_overrides_default() {
        // The TOML key must match the new field name (`ws-rate-limit-max`).
        // This is the operationally-additive path for deployments that
        // express rustgate config via a config file rather than flags.
        let dir = tempfile::tempdir().expect("tmpdir");
        let cert = dir.path().join("c.pem");
        let key = dir.path().join("k.pem");
        let ca = dir.path().join("ca.pem");
        std::fs::write(&cert, "").expect("write cert");
        std::fs::write(&key, "").expect("write key");
        std::fs::write(&ca, "").expect("write ca");

        let cert_s = cert.to_str().unwrap();
        let key_s = key.to_str().unwrap();
        let ca_s = ca.to_str().unwrap();

        let cfg = dir.path().join("ws.toml");
        std::fs::write(
            &cfg,
            format!(
                "cert = \"{cert_s}\"\nkey = \"{key_s}\"\nca = \"{ca_s}\"\n\
                 ws-rate-limit-max = 250\nws-rate-limit-window-secs = 45\n"
            ),
        )
        .expect("write");

        let file = load_config_file(cfg.to_str().unwrap()).expect("load");
        let matches = Cli::command()
            .get_matches_from(["rustgate", "--cert", cert_s, "--key", key_s, "--ca", ca_s]);
        let mut cli = Cli::from_arg_matches(&matches).expect("parse");
        file.apply_to(&mut cli, &matches);
        assert_eq!(cli.ws_rate_limit_max, 250);
        assert_eq!(cli.ws_rate_limit_window_secs, 45);
    }

    // ─── F-72 MAVLink signing-policy CLI flags ───────────────────────

    #[test]
    fn mavlink_signing_defaults_are_secure() {
        // Default-secure posture: signing required, v1 rejected. A
        // deployment that does NOTHING gets the strict policy. Pin the
        // defaults so a refactor that flips them inverts the
        // operational meaning of the flag.
        let cli = Cli::try_parse_from([
            "rustgate", "--cert", "c.pem", "--key", "k.pem", "--ca", "ca.pem",
        ])
        .expect("should parse");
        assert!(cli.mavlink_require_signing, "default: require signing");
        assert!(!cli.mavlink_allow_v1, "default: reject v1");
    }

    #[test]
    fn mavlink_allow_v1_overridable_via_cli() {
        // Mixed-fleet operator escape hatch. Pin the override path so
        // operators can opt back into v1 without rebuilding.
        let cli = Cli::try_parse_from([
            "rustgate",
            "--cert",
            "c.pem",
            "--key",
            "k.pem",
            "--ca",
            "ca.pem",
            "--mavlink-allow-v1",
            "true",
        ])
        .expect("should parse");
        assert!(cli.mavlink_allow_v1);
        // The unrelated default stays put — the two knobs are
        // independent so an operator can opt into v1 *and* keep
        // signing required for any v2 traffic.
        assert!(cli.mavlink_require_signing);
    }

    #[test]
    fn mavlink_require_signing_overridable_via_cli() {
        // Trusted-link escape hatch. Opt out of signing without also
        // having to opt into v1.
        let cli = Cli::try_parse_from([
            "rustgate",
            "--cert",
            "c.pem",
            "--key",
            "k.pem",
            "--ca",
            "ca.pem",
            "--mavlink-require-signing",
            "false",
        ])
        .expect("should parse");
        assert!(!cli.mavlink_require_signing);
        assert!(!cli.mavlink_allow_v1);
    }

    #[test]
    fn config_file_rejects_ws_buffer_below_minimum() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let cert = dir.path().join("c.pem");
        let key = dir.path().join("k.pem");
        let ca = dir.path().join("ca.pem");
        std::fs::write(&cert, "").expect("write cert");
        std::fs::write(&key, "").expect("write key");
        std::fs::write(&ca, "").expect("write ca");

        let cert_s = cert.to_str().unwrap();
        let key_s = key.to_str().unwrap();
        let ca_s = ca.to_str().unwrap();

        let cfg = dir.path().join("bad.toml");
        std::fs::write(
            &cfg,
            format!("cert = \"{cert_s}\"\nkey = \"{key_s}\"\nca = \"{ca_s}\"\nws-max-write-buffer-bytes = 1024\n"),
        )
        .expect("write");

        let file = load_config_file(cfg.to_str().unwrap()).expect("load");
        let matches = Cli::command()
            .get_matches_from(["rustgate", "--cert", cert_s, "--key", key_s, "--ca", ca_s]);
        let mut cli = Cli::from_arg_matches(&matches).expect("parse");
        file.apply_to(&mut cli, &matches);

        let err = cli.validate().unwrap_err();
        assert!(
            err.to_string().contains("at least"),
            "expected range error, got: {err}"
        );
    }

    #[test]
    fn config_file_rejects_ws_buffer_above_maximum() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let cert = dir.path().join("c.pem");
        let key = dir.path().join("k.pem");
        let ca = dir.path().join("ca.pem");
        std::fs::write(&cert, "").expect("write cert");
        std::fs::write(&key, "").expect("write key");
        std::fs::write(&ca, "").expect("write ca");

        let cert_s = cert.to_str().unwrap();
        let key_s = key.to_str().unwrap();
        let ca_s = ca.to_str().unwrap();

        let cfg = dir.path().join("bad.toml");
        std::fs::write(
            &cfg,
            format!("cert = \"{cert_s}\"\nkey = \"{key_s}\"\nca = \"{ca_s}\"\nws-max-write-buffer-bytes = 134217728\n"),
        )
        .expect("write");

        let file = load_config_file(cfg.to_str().unwrap()).expect("load");
        let matches = Cli::command()
            .get_matches_from(["rustgate", "--cert", cert_s, "--key", key_s, "--ca", ca_s]);
        let mut cli = Cli::from_arg_matches(&matches).expect("parse");
        file.apply_to(&mut cli, &matches);

        let err = cli.validate().unwrap_err();
        assert!(
            err.to_string().contains("at most"),
            "expected range error, got: {err}"
        );
    }

    // ── config validation tests ───────────────────────────────────

    /// Helper: create a `Cli` whose TLS paths point to real (empty)
    /// temp-files so that the file-existence check passes. Callers can
    /// then mutate individual fields before calling `validate()`.
    fn cli_with_temp_tls(dir: &tempfile::TempDir) -> Cli {
        let cert = dir.path().join("c.pem");
        let key = dir.path().join("k.pem");
        let ca = dir.path().join("ca.pem");
        std::fs::write(&cert, "").expect("write cert");
        std::fs::write(&key, "").expect("write key");
        std::fs::write(&ca, "").expect("write ca");

        Cli::try_parse_from([
            "rustgate",
            "--cert",
            cert.to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
            "--ca",
            ca.to_str().unwrap(),
        ])
        .expect("should parse")
    }

    #[test]
    fn validate_rejects_missing_cert_file() {
        let cli = Cli::try_parse_from([
            "rustgate",
            "--cert",
            "/tmp/nonexistent-rustgate-test.pem",
            "--key",
            "/tmp/nonexistent-rustgate-test.pem",
            "--ca",
            "/tmp/nonexistent-rustgate-test.pem",
        ])
        .expect("should parse");

        let err = cli.validate().unwrap_err();
        assert!(
            err.to_string().contains("TLS cert file not found"),
            "expected cert-not-found error, got: {err}"
        );
    }

    #[test]
    fn validate_rejects_missing_key_file() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let cert = dir.path().join("c.pem");
        std::fs::write(&cert, "").expect("write cert");

        let cli = Cli::try_parse_from([
            "rustgate",
            "--cert",
            cert.to_str().unwrap(),
            "--key",
            "/tmp/nonexistent-rustgate-key.pem",
            "--ca",
            "/tmp/nonexistent-rustgate-ca.pem",
        ])
        .expect("should parse");

        let err = cli.validate().unwrap_err();
        assert!(
            err.to_string().contains("TLS key file not found"),
            "expected key-not-found error, got: {err}"
        );
    }

    #[test]
    fn validate_rejects_missing_ca_file() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let cert = dir.path().join("c.pem");
        let key = dir.path().join("k.pem");
        std::fs::write(&cert, "").expect("write cert");
        std::fs::write(&key, "").expect("write key");

        let cli = Cli::try_parse_from([
            "rustgate",
            "--cert",
            cert.to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
            "--ca",
            "/tmp/nonexistent-rustgate-ca.pem",
        ])
        .expect("should parse");

        let err = cli.validate().unwrap_err();
        assert!(
            err.to_string().contains("TLS CA file not found"),
            "expected ca-not-found error, got: {err}"
        );
    }

    #[test]
    fn validate_rejects_federation_without_id() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let mut cli = cli_with_temp_tls(&dir);
        cli.federation_v1_bind = Some("0.0.0.0:9000".to_owned());
        cli.federation_id = String::new();

        let err = cli.validate().unwrap_err();
        assert!(
            err.to_string()
                .contains("--federation-id is required when federation is enabled"),
            "expected federation-id error, got: {err}"
        );
    }

    #[test]
    fn validate_rejects_burst_below_rate() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let mut cli = cli_with_temp_tls(&dir);
        cli.client_message_rate = 100;
        cli.client_burst = 50;

        let err = cli.validate().unwrap_err();
        assert!(
            err.to_string()
                .contains("--client-burst (50) must be >= --client-message-rate (100)"),
            "expected burst error, got: {err}"
        );
    }

    #[test]
    fn validate_accepts_burst_equal_to_rate() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let mut cli = cli_with_temp_tls(&dir);
        cli.client_message_rate = 100;
        cli.client_burst = 100;
        cli.validate().expect("burst == rate should be valid");
    }

    #[test]
    fn validate_skips_rate_check_when_disabled() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let mut cli = cli_with_temp_tls(&dir);
        cli.client_message_rate = 0;
        cli.client_burst = 0;
        cli.validate()
            .expect("rate limiting disabled should be valid");
    }

    #[test]
    fn validate_warns_authz_fail_open_without_policy() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let mut cli = cli_with_temp_tls(&dir);
        cli.authz_fail_open = true;
        cli.authz_policy_file = None;

        // Should succeed (warn, not bail).
        cli.validate()
            .expect("authz-fail-open without policy should warn, not error");
    }

    // ── classification CLI flag pins (refs #849) ─────────────────────

    #[test]
    fn cli_require_classification_marking_flag_parses() {
        // Pin the flag name and bool semantics. Operator runbooks key
        // off the exact flag string; a refactor that renamed it would
        // break every helm chart and `--help` example without showing
        // up at compile time.
        let dir = tempfile::tempdir().expect("tmpdir");
        let cert = dir.path().join("c.pem");
        let key = dir.path().join("k.pem");
        let ca = dir.path().join("ca.pem");
        std::fs::write(&cert, "").expect("write cert");
        std::fs::write(&key, "").expect("write key");
        std::fs::write(&ca, "").expect("write ca");

        let cli = Cli::try_parse_from([
            "rustgate",
            "--cert",
            cert.to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
            "--ca",
            ca.to_str().unwrap(),
            "--require-classification-marking",
        ])
        .expect("flag should parse");
        assert!(
            cli.require_classification_marking,
            "--require-classification-marking must set the field to true"
        );

        let cli_default = cli_with_temp_tls(&dir);
        assert!(
            !cli_default.require_classification_marking,
            "default value must be false (legacy traffic flows unchanged)"
        );
    }

    #[test]
    fn cli_default_classification_flag_parses_capco_banner() {
        // Pin both that the flag name parses and that the value
        // round-trips through CAPCO `FromStr` validation. A typo that
        // breaks the validator surfaces at startup, not at runtime.
        let dir = tempfile::tempdir().expect("tmpdir");
        let cert = dir.path().join("c.pem");
        let key = dir.path().join("k.pem");
        let ca = dir.path().join("ca.pem");
        std::fs::write(&cert, "").expect("write cert");
        std::fs::write(&key, "").expect("write key");
        std::fs::write(&ca, "").expect("write ca");

        let cli = Cli::try_parse_from([
            "rustgate",
            "--cert",
            cert.to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
            "--ca",
            ca.to_str().unwrap(),
            "--default-classification",
            "//UNCLASSIFIED",
        ])
        .expect("flag should parse");
        assert_eq!(
            cli.default_classification.as_deref(),
            Some("//UNCLASSIFIED"),
            "value must round-trip verbatim into the field"
        );
        cli.validate()
            .expect("//UNCLASSIFIED is a valid CAPCO banner");
    }

    #[test]
    fn validate_rejects_invalid_default_classification_banner() {
        // Defence-in-depth: a malformed banner caught at startup beats
        // a per-message reject loop. The validator wraps the
        // ParseError with the offending banner verbatim so operators
        // can fix the typo from the error message alone.
        let dir = tempfile::tempdir().expect("tmpdir");
        let mut cli = cli_with_temp_tls(&dir);
        cli.default_classification = Some("not-a-banner".to_string());
        let err = cli.validate().unwrap_err();
        assert!(
            err.to_string().contains("--default-classification"),
            "validator must surface the offending flag, got: {err}"
        );
    }

    #[test]
    fn validate_rejects_acl_reload_interval_zero_with_acl_file() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let mut cli = cli_with_temp_tls(&dir);
        cli.group_acl_file = Some("/tmp/acl.json".to_owned());
        cli.acl_reload_interval = 0;

        let err = cli.validate().unwrap_err();
        assert!(
            err.to_string()
                .contains("--acl-reload-interval must be >= 1 when --group-acl-file is set"),
            "expected acl-reload-interval error, got: {err}"
        );
    }

    #[test]
    fn validate_accepts_federation_with_id() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let mut cli = cli_with_temp_tls(&dir);
        cli.federation_v1_bind = Some("0.0.0.0:9000".to_owned());
        cli.federation_id = "my-server".to_owned();
        cli.validate().expect("federation with ID should be valid");
    }

    #[test]
    fn validate_accepts_valid_config() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let cli = cli_with_temp_tls(&dir);
        cli.validate().expect("default config should be valid");
    }

    #[test]
    fn validate_rejects_aggressive_archive_rotate_interval() {
        // An interval below the hard minimum must be rejected at config
        // validation so operators cannot opt in to a torn-write-inducing
        // cadence by accident. See F-69.
        let dir = tempfile::tempdir().expect("tmpdir");
        let mut cli = cli_with_temp_tls(&dir);
        cli.archive_dir = Some(dir.path().to_string_lossy().into_owned());
        cli.archive_max_size = 1_000_000;
        cli.archive_rotate_interval = 30;

        let err = cli.validate().unwrap_err();
        assert!(
            err.to_string()
                .contains("--archive-rotate-interval (30) must be >= 60 seconds"),
            "expected min-interval error, got: {err}"
        );
    }

    #[test]
    fn validate_accepts_archive_rotate_interval_at_minimum() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let mut cli = cli_with_temp_tls(&dir);
        cli.archive_dir = Some(dir.path().to_string_lossy().into_owned());
        cli.archive_max_size = 1_000_000;
        cli.archive_rotate_interval = 60;
        // Emits a warning but must not bail.
        cli.validate().expect("60s minimum should be accepted");
    }

    #[test]
    fn validate_accepts_archive_rotate_interval_above_recommended() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let mut cli = cli_with_temp_tls(&dir);
        cli.archive_dir = Some(dir.path().to_string_lossy().into_owned());
        cli.archive_max_age = 86400;
        cli.archive_rotate_interval = 600;
        cli.validate()
            .expect("cadence above recommended should be accepted");
    }

    #[test]
    fn validate_skips_rotation_check_when_rotation_disabled() {
        // If --archive-max-size and --archive-max-age are both zero, the
        // rotation task does not spawn — the interval is irrelevant and
        // must not trigger validation.
        let dir = tempfile::tempdir().expect("tmpdir");
        let mut cli = cli_with_temp_tls(&dir);
        cli.archive_dir = Some(dir.path().to_string_lossy().into_owned());
        cli.archive_max_size = 0;
        cli.archive_max_age = 0;
        cli.archive_rotate_interval = 1; // aggressive, but rotation is off
        cli.validate().expect("disabled rotation should skip check");
    }

    /// Pin that loading a TOML config with a misspelled top-level key
    /// fails with a `unknown field` error rather than silently producing
    /// a default-valued field. The `ConfigFile` macro wires
    /// `#[serde(deny_unknown_fields)]` (#815, F-136); a regression that
    /// drops the attribute would let `--bnd = "..."` be silently
    /// ignored and the operator would never see the mistake.
    #[test]
    fn config_file_rejects_unknown_toml_key() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let cfg_path = dir.path().join("rustgate.toml");
        // `bnd` is the typo (should be `bind`). With deny_unknown_fields,
        // figment surfaces the offending key in the error message.
        std::fs::write(&cfg_path, "bnd = \"0.0.0.0:4433\"\n").expect("write toml");

        let result = load_config_file(cfg_path.to_str().expect("path utf8"));
        let err = match result {
            Err(e) => e.to_string(),
            Ok(_) => panic!("typo'd `bnd` must be rejected by deny_unknown_fields"),
        };
        assert!(
            err.contains("unknown field") && err.contains("bnd"),
            "error should name the offending field: {err}"
        );
    }
}
