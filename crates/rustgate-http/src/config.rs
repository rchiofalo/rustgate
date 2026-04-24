// Copyright © 2026 Roberto Chiofalo.

//! Configuration types for the HTTP egress bridge.
//!
//! Defines the TOML-deserializable configuration schema for HTTP targets
//! including per-target URL, authentication, TLS, filtering, retry, and
//! circuit breaker settings. All config structs use kebab-case field
//! names to match the workspace TOML convention.

use rustgate_core::b64;
use serde::Deserialize;

use crate::error::HttpError;

/// Top-level HTTP egress configuration loaded from a TOML file.
///
/// Contains a list of named targets, each representing an independent
/// HTTP endpoint that receives forwarded messages.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct HttpConfig {
    /// Instance identifier included in the `X-Rustgate-Instance` header.
    /// When absent, defaults to `rustgate-{pid}` using the process ID.
    pub instance_id: Option<String>,

    /// Named targets. Each is an independent HTTP endpoint.
    pub targets: Vec<TargetConfig>,

    /// Directory for encrypted dead-letter queue files. When set, messages
    /// that cannot be delivered (circuit open) are persisted as encrypted
    /// ChaCha20-Poly1305 chunks for later forensic recovery.
    pub dlq_dir: Option<String>,

    /// Path to the JSON key file for dead-letter queue encryption.
    /// Required when `dlq-dir` is set. Uses the same `KeyRing` format
    /// as `rustgate-core::encrypted`.
    pub dlq_key_file: Option<String>,

    /// Maximum size in bytes per DLQ file before rotation. Prevents
    /// unbounded disk growth when a target stays down. Default: 256 MiB.
    pub dlq_max_bytes: Option<u64>,

    /// Maximum total DLQ bytes on disk per target across every rotated
    /// file. Once a target's on-disk DLQ footprint exceeds this cap the
    /// oldest sealed file for that target is deleted (drop-oldest FIFO);
    /// the currently-written active segment is always preserved. `None`
    /// or `0` = unlimited (matches historical behaviour).
    ///
    /// Distinguishes from `dlq-max-bytes`, which caps a *single file*
    /// before rotation. `dlq-max-target-bytes` caps the *total* disk
    /// footprint for a single target after many rotations have
    /// accumulated across a long outage. Must be `>= dlq-max-bytes`
    /// when both are set — otherwise the size-triggered rotation
    /// guarantee cannot be honored without also evicting the file the
    /// writer just sealed.
    ///
    /// Closes #881 — unbounded DLQ growth during extended outages.
    pub dlq_max_target_bytes: Option<u64>,

    /// Allow localhost/private IPs as target URLs. **Testing only** —
    /// production configs should leave this unset (defaults to `false`).
    /// Deserialization ignores this field; it can only be set programmatically.
    #[serde(skip)]
    pub allow_private_urls: bool,
}

/// Per-target endpoint configuration.
///
/// Each target is fully independent: its own URL, authentication,
/// TLS settings, payload format, message filter, and retry policy.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct TargetConfig {
    /// Unique name used in metrics labels and structured logging.
    pub name: String,

    /// Full URL with scheme (`https://` or `http://`).
    /// Validated at config parse time.
    pub url: String,

    /// HTTP method (default: POST).
    pub method: Option<HttpMethod>,

    /// Authentication configuration.
    pub auth: Option<AuthConfig>,

    /// Outbound TLS configuration (mTLS client certs, custom CA).
    pub tls: Option<TlsConfig>,

    /// Request timeout in seconds (default: 10).
    pub timeout_secs: Option<u64>,

    /// Payload serialization format (default: JSON).
    pub format: Option<PayloadFormat>,

    /// Message filter — only forward matching messages.
    pub filter: Option<FilterConfig>,

    /// Retry and circuit breaker configuration.
    pub retry: Option<RetryConfig>,

    /// Whether this target is enabled (default: true).
    pub enabled: Option<bool>,

    /// Custom static headers included on every request.
    pub headers: Option<Vec<HeaderEntry>>,

    /// Maximum payload size in bytes before a message is rejected.
    /// Prevents memory exhaustion from oversized messages. Default: 1 MiB.
    pub max_payload_bytes: Option<usize>,

    /// Maximum outbound requests per second to this target.
    /// When unset, requests are unlimited (subject only to circuit breaking).
    /// Prevents overwhelming downstream endpoints with burst traffic.
    pub rate_limit_per_sec: Option<f64>,

    /// Capture and surface the response body on 2xx responses (default: false).
    ///
    /// When enabled, up to [`max_response_body_bytes`](Self::max_response_body_bytes)
    /// bytes of the response body are captured and emitted in a
    /// structured `tracing::debug!` line on success alongside the
    /// per-request `delivery_id`. Operators can grep the access log to
    /// recover downstream acknowledgement IDs (Splunk HEC `ackId`,
    /// Elastic `_id`, Loki `traceID`) that the receiver returns in the
    /// body. Disabled by default so existing deployments are not
    /// spammed with receive payload logs.
    ///
    /// On non-2xx responses the captured snippet is *always* included
    /// in the failure log and error string (independent of this flag)
    /// because structured 4xx/5xx error details from SIEM collectors
    /// are the highest-leverage signal for diagnosing misconfigured
    /// webhook targets. This flag therefore only controls the
    /// success-path log, not the failure-path log.
    pub capture_response_body: Option<bool>,

    /// Maximum bytes of response body to capture on any response
    /// (default: 4 KiB).
    ///
    /// Applies to both success-path capture (gated on
    /// [`capture_response_body`](Self::capture_response_body)) and
    /// failure-path capture (always on). Responses larger than this
    /// limit are truncated at the byte level — no attempt is made to
    /// honour UTF-8 boundaries because the captured bytes are emitted
    /// through structured logging that sanitises invalid UTF-8.
    ///
    /// Bounded explicitly to prevent a malicious server from pushing
    /// unbounded log volume through this path. Capped at 1 MiB by
    /// config validation.
    pub max_response_body_bytes: Option<usize>,

    /// Enable per-target batching — coalesce multiple routable messages
    /// into a single HTTP request (default: `false`).
    ///
    /// When enabled, the publisher buffers serialized message bodies in
    /// a per-target in-memory batcher and flushes a combined request
    /// when either [`batch_max_messages`](Self::batch_max_messages) or
    /// [`batch_max_bytes`](Self::batch_max_bytes) is reached, whichever
    /// fires first. The shape of the combined body is determined by
    /// [`batch_format`](Self::batch_format) (JSON array by default).
    ///
    /// **Scope:** batching is only supported for the `json` payload
    /// format. `raw-xml` and `protobuf` targets are rejected at
    /// validation time when `batch-enabled = true` because there is no
    /// portable wire-level framing to concatenate raw XML documents or
    /// independent protobuf messages without downstream cooperation.
    /// Operators who need batched XML or protobuf delivery should ship
    /// multiple single-message requests instead.
    ///
    /// Closes the batch half of #906.
    pub batch_enabled: Option<bool>,

    /// Flush the batch once it contains this many messages
    /// (default: 100, minimum: 2).
    ///
    /// A single-message "batch" is degenerate — it adds envelope
    /// overhead without amortizing any request cost — so the minimum
    /// is 2. There is no hard upper bound; operators pick a value that
    /// matches the downstream receiver's tolerance for large request
    /// bodies (Splunk HEC: up to 1 MB, Datadog Logs: 5 MB, Elastic
    /// bulk: unbounded but rejected via 413 on overrun).
    pub batch_max_messages: Option<usize>,

    /// Flush the batch once the accumulated serialized bytes reach
    /// this size (default: 1 MiB, minimum: 1 KiB).
    ///
    /// Measured on the serialized single-message bodies *before*
    /// batch rendering overhead (JSON-array commas + brackets, or
    /// NDJSON newlines), so the final request body is slightly
    /// larger than this cap. Operators should set this comfortably
    /// below the downstream receiver's hard request-body limit.
    pub batch_max_bytes: Option<usize>,

    /// How to concatenate batched message bodies on the wire
    /// (default: [`BatchFormat::JsonArray`]).
    ///
    /// - `json-array` — emit `[msg1, msg2, …]` with `Content-Type:
    ///   application/json`. Suitable for endpoints expecting a typed
    ///   array (Datadog Logs, generic webhooks, custom collectors).
    /// - `ndjson` — emit one message per line separated by `\n` with
    ///   `Content-Type: application/x-ndjson`. Suitable for bulk log
    ///   ingestion endpoints (Splunk HEC raw endpoint, Loki push API,
    ///   Elastic `_bulk`).
    pub batch_format: Option<BatchFormat>,
}

/// Custom HTTP header entry.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct HeaderEntry {
    /// Header name (must be a valid HTTP header name).
    pub name: String,
    /// Header value.
    pub value: String,
}

/// HTTP method for outbound requests.
#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum HttpMethod {
    /// HTTP POST (default).
    #[default]
    Post,
    /// HTTP PUT.
    Put,
    /// HTTP PATCH.
    Patch,
}

/// Payload serialization format.
#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PayloadFormat {
    /// JSON envelope with source identity, metadata, and base64-encoded payload.
    #[default]
    Json,
    /// Raw XML payload bytes sent as `application/xml`.
    RawXml,
    /// Protobuf-encoded CoT event via `rustgate-proto` (requires `proto` feature).
    /// Content-Type: `application/x-protobuf`.
    Protobuf,
}

/// Batch framing format for multi-message HTTP requests.
///
/// Selects how the per-message serialized bodies are concatenated into a
/// single request body when
/// [`TargetConfig::batch_enabled`](TargetConfig::batch_enabled) is `true`.
#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum BatchFormat {
    /// JSON array: `[msg1, msg2, …]`. Content-Type: `application/json`.
    /// Suitable for endpoints expecting a typed JSON array.
    #[default]
    JsonArray,
    /// Newline-delimited JSON: `msg1\nmsg2\n…`. Content-Type:
    /// `application/x-ndjson`. Suitable for bulk log ingestion endpoints
    /// (Splunk HEC raw, Loki push, Elastic `_bulk`).
    Ndjson,
}

/// Authentication for outbound requests.
///
/// Secrets are always read from files (never inline in config) to prevent
/// accidental exposure via config dumps or structured logging.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthConfig {
    /// Bearer token read from a file.
    Bearer {
        /// Path to file containing the bearer token.
        #[serde(rename = "token-file")]
        token_file: String,
    },
    /// HTTP Basic Auth with password read from a file.
    Basic {
        /// Username for Basic Auth.
        username: String,
        /// Path to file containing the password.
        #[serde(rename = "password-file")]
        password_file: String,
    },
    /// HMAC-SHA256 request body signing with secret read from a file.
    Hmac {
        /// Path to file containing the HMAC secret.
        #[serde(rename = "secret-file")]
        secret_file: String,
        /// Header name for the signature (default: `X-Signature-256`).
        header: Option<String>,
    },
}

/// Outbound TLS configuration for a target.
///
/// When `client_cert` and `client_key` are both set, the publisher
/// presents a client certificate for mutual TLS authentication.
/// When `pin_sha256` is set, the SHA-256 of the server leaf certificate's
/// **SubjectPublicKeyInfo (SPKI)** is compared against the configured
/// pins in addition to standard WebPKI chain validation — RFC 7469 / HPKP
/// semantics. See [`TlsConfig::pin_sha256`] for the generation recipe.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct TlsConfig {
    /// Custom CA certificate PEM for server verification.
    pub ca_cert: Option<String>,
    /// Client certificate PEM for mutual TLS.
    pub client_cert: Option<String>,
    /// Client private key PEM for mutual TLS.
    pub client_key: Option<String>,
    /// SHA-256 pins of the server's **SubjectPublicKeyInfo (SPKI)**,
    /// base64-encoded — [RFC 7469] / HPKP semantic.
    ///
    /// **Semantic:** each pin is `SHA-256(SPKI DER)`, not a hash of the
    /// whole certificate. This matches the Chromium / Mozilla / OpenSSL
    /// convention. Generate with:
    ///
    /// ```text
    /// openssl x509 -in server.pem -pubkey -noout \
    ///   | openssl pkey -pubin -outform der \
    ///   | openssl dgst -sha256 -binary \
    ///   | base64
    /// ```
    ///
    /// **Implications:**
    ///
    /// - A routine rotation that preserves the key (new serial, validity
    ///   window, or SAN list but the same public key) **still matches**
    ///   existing pins — no config change required.
    /// - A rotation that rolls the key invalidates the pin. Configure
    ///   both the outgoing and incoming pins during the overlap window.
    /// - Pins survive intermediate CA changes (the SPKI is the leaf's
    ///   public key, not the chain).
    ///
    /// **Breaking change vs pre-#948 builds:** older builds hashed the
    /// full leaf certificate DER. Existing full-DER pins do **not**
    /// match the new SPKI semantic and must be regenerated with the
    /// recipe above.
    ///
    /// Requires `ca-cert` to also be set (explicit trust anchor).
    ///
    /// [RFC 7469]: https://datatracker.ietf.org/doc/html/rfc7469
    pub pin_sha256: Option<Vec<String>>,
}

/// Per-target message filter.
///
/// Filters are AND-combined across dimensions: a message must match
/// *all* configured dimensions to be forwarded. Within each dimension,
/// values are OR-combined: matching *any* value in the list passes.
/// `None` for a dimension means "accept all" for that dimension.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct FilterConfig {
    /// Only forward messages from senders in at least one of these groups.
    pub groups: Option<Vec<rustgate_core::identity::GroupId>>,
    /// Only forward messages of these types.
    pub message_types: Option<Vec<String>>,
    /// Only forward messages from these source CNs.
    pub source_cns: Option<Vec<String>>,
    /// Exclude messages originating from these protocols (echo prevention).
    /// `"http"` is always included even if not explicitly configured.
    pub exclude_protocols: Option<Vec<String>>,
}

/// Retry and circuit breaker configuration.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct RetryConfig {
    /// Maximum retry attempts per request (default: 3).
    pub max_attempts: Option<u32>,
    /// Base backoff delay in seconds (default: 1).
    pub backoff_base_secs: Option<u64>,
    /// Consecutive failures before the circuit breaker opens (default: 5).
    pub circuit_breaker_threshold: Option<u32>,
    /// Seconds to wait before a half-open probe (default: 30).
    pub circuit_breaker_cooldown_secs: Option<u64>,
    /// Maximum concurrent probe requests in half-open state (default: 3).
    /// Prevents thundering-herd against a recovering endpoint.
    pub half_open_max_probes: Option<u32>,
    /// Consecutive successful probes required to close the circuit (default: 2).
    /// Avoids flapping on a single lucky request.
    pub half_open_success_threshold: Option<u32>,
}

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

impl TargetConfig {
    /// Effective HTTP method (default: POST).
    pub fn effective_method(&self) -> HttpMethod {
        self.method.unwrap_or_default()
    }

    /// Effective request timeout (default: 10 seconds).
    pub fn effective_timeout_secs(&self) -> u64 {
        self.timeout_secs.unwrap_or(10)
    }

    /// Effective max payload size in bytes (default: 1 MiB).
    pub fn effective_max_payload_bytes(&self) -> usize {
        self.max_payload_bytes.unwrap_or(1024 * 1024)
    }

    /// Effective payload format (default: JSON).
    pub fn effective_format(&self) -> PayloadFormat {
        self.format.unwrap_or_default()
    }

    /// Whether this target is enabled (default: true).
    pub fn is_enabled(&self) -> bool {
        self.enabled.unwrap_or(true)
    }

    /// Effective response-body capture flag (default: false).
    ///
    /// When `true`, the publisher captures up to
    /// [`effective_max_response_body_bytes`](Self::effective_max_response_body_bytes)
    /// bytes of each 2xx response and emits them in a structured
    /// `tracing::debug!` line alongside the per-request `delivery_id`.
    pub fn effective_capture_response_body(&self) -> bool {
        self.capture_response_body.unwrap_or(false)
    }

    /// Effective maximum captured response-body size (default: 4 KiB,
    /// capped at 1 MiB by config validation).
    ///
    /// Applies symmetrically to the success-path capture and the
    /// failure-path capture (which is always on when the body is small
    /// enough to pull cheaply).
    pub fn effective_max_response_body_bytes(&self) -> usize {
        self.max_response_body_bytes.unwrap_or(4 * 1024)
    }

    /// Whether this target batches messages into combined HTTP requests
    /// (default: `false`).
    pub fn effective_batch_enabled(&self) -> bool {
        self.batch_enabled.unwrap_or(false)
    }

    /// Effective batch flush threshold in messages (default:
    /// [`DEFAULT_BATCH_MAX_MESSAGES`]).
    pub fn effective_batch_max_messages(&self) -> usize {
        self.batch_max_messages
            .unwrap_or(DEFAULT_BATCH_MAX_MESSAGES)
    }

    /// Effective batch flush threshold in serialized bytes (default:
    /// [`DEFAULT_BATCH_MAX_BYTES`]).
    pub fn effective_batch_max_bytes(&self) -> usize {
        self.batch_max_bytes.unwrap_or(DEFAULT_BATCH_MAX_BYTES)
    }

    /// Effective batch framing format (default: [`BatchFormat::JsonArray`]).
    pub fn effective_batch_format(&self) -> BatchFormat {
        self.batch_format.unwrap_or_default()
    }
}

/// Default per-target batch flush threshold in messages.
///
/// Chosen to amortise TLS/TCP per-request cost meaningfully while
/// staying well below every major receiver's batch size cap (Splunk HEC
/// batch endpoint: effectively unbounded but rate-limited per event;
/// Datadog Logs: 1000; Elastic `_bulk`: unbounded on size, not count).
pub const DEFAULT_BATCH_MAX_MESSAGES: usize = 100;

/// Default per-target batch flush threshold in serialized bytes (1 MiB).
///
/// Matches Splunk HEC's default 1 MB request body cap, which is the
/// tightest of the major receivers' defaults.
pub const DEFAULT_BATCH_MAX_BYTES: usize = 1024 * 1024;

/// Absolute floor for `batch-max-messages`. A batch of 1 is degenerate
/// (adds envelope overhead without amortizing any request cost), so
/// operators must configure at least 2.
pub(crate) const MIN_BATCH_MAX_MESSAGES: usize = 2;

/// Absolute floor for `batch-max-bytes`. Below 1 KiB the flush
/// threshold fires on every realistic JSON envelope, which is
/// indistinguishable from batching being off and wastes batcher state.
pub(crate) const MIN_BATCH_MAX_BYTES: usize = 1024;

impl RetryConfig {
    /// Effective max retry attempts (default: 3).
    pub fn effective_max_attempts(&self) -> u32 {
        self.max_attempts.unwrap_or(3)
    }

    /// Effective base backoff delay in seconds (default: 1).
    pub fn effective_backoff_base_secs(&self) -> u64 {
        self.backoff_base_secs.unwrap_or(1)
    }

    /// Effective circuit breaker failure threshold (default: 5).
    pub fn effective_circuit_threshold(&self) -> u32 {
        self.circuit_breaker_threshold.unwrap_or(5)
    }

    /// Effective circuit breaker cooldown in seconds (default: 30).
    pub fn effective_circuit_cooldown_secs(&self) -> u64 {
        self.circuit_breaker_cooldown_secs.unwrap_or(30)
    }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

impl HttpConfig {
    /// Validate the configuration, returning all errors found.
    ///
    /// Checks URL format, TLS consistency, auth file paths, target name
    /// uniqueness, and header name validity.
    pub fn validate(&self) -> Result<(), HttpError> {
        let mut errors = Vec::new();

        if self.targets.is_empty() {
            errors.push("at least one target must be defined".to_string());
        }

        // Check target name uniqueness
        let mut seen_names = std::collections::HashSet::new();
        for target in &self.targets {
            if target.name.is_empty() {
                errors.push("target name must not be empty".to_string());
            } else if !seen_names.insert(&target.name) {
                errors.push(format!("duplicate target name `{}`", target.name));
            }

            // Validate name is suitable for Prometheus labels (alphanumeric + underscore + hyphen)
            if !target.name.is_empty()
                && !target
                    .name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
            {
                errors.push(format!(
                    "target name `{}` contains invalid characters (use alphanumeric, _, -)",
                    target.name
                ));
            }

            Self::validate_target(target, self.allow_private_urls, &mut errors);
        }

        // DLQ validation: dir and key file must both be present
        match (&self.dlq_dir, &self.dlq_key_file) {
            (Some(_), None) => {
                errors.push("dlq-dir requires dlq-key-file to be set".to_string());
            }
            (None, Some(_)) => {
                errors.push("dlq-key-file requires dlq-dir to be set".to_string());
            }
            _ => {}
        }

        // `dlq-max-target-bytes` must be at least `dlq-max-bytes`
        // otherwise the per-target eviction sweep may run before the
        // writer has finished sealing the rotated file, producing a
        // window where the active segment is the only on-disk record
        // for the target. Configurations that want a tight per-target
        // cap should lower `dlq-max-bytes` rather than invert the two.
        if let (Some(target_cap), Some(file_cap)) = (self.dlq_max_target_bytes, self.dlq_max_bytes)
            && target_cap > 0
            && target_cap < file_cap
        {
            errors.push(format!(
                "dlq-max-target-bytes ({target_cap}) must be >= dlq-max-bytes ({file_cap}); \
                 the per-target cap bounds the total on-disk footprint across rotations and \
                 cannot be smaller than a single rotated file"
            ));
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(HttpError::Config(errors.join("; ")))
        }
    }

    /// Headers that must not be used by custom config or HMAC signature headers.
    /// Includes protocol-sensitive headers that could influence connection
    /// behavior, enable request smuggling, or leak credentials to proxies.
    const RESERVED_HMAC_HEADERS: &[&str] = &[
        "host",
        "content-type",
        "content-length",
        "content-digest",
        "transfer-encoding",
        "authorization",
        "connection",
        "proxy-authorization",
        "cookie",
        "te",
        "upgrade",
        "x-rustgate-instance",
        "x-rustgate-delivery-id",
        "x-rustgate-timestamp",
    ];

    fn validate_target(target: &TargetConfig, allow_private_urls: bool, errors: &mut Vec<String>) {
        // Validate URL
        if target.url.is_empty() {
            errors.push(format!("target `{}`: URL must not be empty", target.name));
        } else {
            match reqwest::Url::parse(&target.url) {
                Ok(url) => {
                    let scheme = url.scheme();
                    if scheme != "http" && scheme != "https" {
                        errors.push(format!(
                            "target `{}`: URL scheme must be http or https, got `{scheme}`",
                            target.name
                        ));
                    }

                    // SSRF protection: reject URLs pointing to private/reserved
                    // IP addresses (RFC 1918, loopback, link-local, IMDS).
                    // Note: host_str() wraps IPv6 in brackets (e.g. "[::1]"),
                    // so we strip them before parsing as IpAddr.
                    if !allow_private_urls && let Some(host) = url.host_str() {
                        let bare = host
                            .strip_prefix('[')
                            .and_then(|s| s.strip_suffix(']'))
                            .unwrap_or(host);
                        if let Ok(ip) = bare.parse::<std::net::IpAddr>() {
                            if is_private_ip(ip) {
                                errors.push(format!(
                                    "target `{}`: URL host `{bare}` is a private/reserved IP address (SSRF protection)",
                                    target.name
                                ));
                            }
                        } else if bare == "localhost" {
                            errors.push(format!(
                                "target `{}`: URL host `localhost` is not allowed (SSRF protection)",
                                target.name
                            ));
                        }
                    }
                }
                Err(e) => {
                    errors.push(format!("target `{}`: invalid URL: {e}", target.name));
                }
            }
        }

        // Warn when auth credentials would be sent over plaintext HTTP.
        // This is a security misconfiguration — bearer tokens, passwords, and
        // HMAC signatures will be visible to any network observer.
        if target.auth.is_some() && target.url.starts_with("http://") && !allow_private_urls {
            errors.push(format!(
                "target `{}`: auth credentials configured with plaintext http:// URL; \
                 use https:// to protect secrets in transit",
                target.name
            ));
        }

        // Validate TLS consistency
        if let Some(tls) = &target.tls {
            let has_cert = tls.client_cert.is_some();
            let has_key = tls.client_key.is_some();
            if has_cert != has_key {
                errors.push(format!(
                    "target `{}`: client-cert and client-key must both be set or both absent",
                    target.name
                ));
            }

            // Certificate pinning requires an explicit CA trust anchor.
            // Using the Mozilla root store with pins is insecure because
            // any public CA could issue a cert matching the hostname.
            if let Some(pins) = &tls.pin_sha256 {
                if !pins.is_empty() && tls.ca_cert.is_none() {
                    errors.push(format!(
                        "target `{}`: pin-sha256 requires ca-cert to be set (explicit trust anchor)",
                        target.name
                    ));
                }
                for (i, pin) in pins.iter().enumerate() {
                    if pin.is_empty() {
                        errors.push(format!(
                            "target `{}`: pin-sha256[{i}] must not be empty",
                            target.name
                        ));
                    } else if b64::decode(pin).is_err() {
                        errors.push(format!(
                            "target `{}`: pin-sha256[{i}] is not valid base64",
                            target.name
                        ));
                    }
                }
            }
        }

        // Protobuf format requires the `proto` feature at compile time
        #[cfg(not(feature = "proto"))]
        if target.format == Some(PayloadFormat::Protobuf) {
            errors.push(format!(
                "target `{}`: protobuf format requires the `proto` feature",
                target.name
            ));
        }

        // Validate auth file paths
        if let Some(auth) = &target.auth {
            match auth {
                AuthConfig::Bearer { token_file } => {
                    if token_file.is_empty() {
                        errors.push(format!(
                            "target `{}`: bearer token-file must not be empty",
                            target.name
                        ));
                    }
                }
                AuthConfig::Basic {
                    username,
                    password_file,
                } => {
                    if username.is_empty() {
                        errors.push(format!(
                            "target `{}`: basic auth username must not be empty",
                            target.name
                        ));
                    }
                    if password_file.is_empty() {
                        errors.push(format!(
                            "target `{}`: basic auth password-file must not be empty",
                            target.name
                        ));
                    }
                }
                AuthConfig::Hmac {
                    secret_file,
                    header,
                } => {
                    if secret_file.is_empty() {
                        errors.push(format!(
                            "target `{}`: HMAC secret-file must not be empty",
                            target.name
                        ));
                    }
                    if let Some(h) = header {
                        if h.is_empty() {
                            errors.push(format!(
                                "target `{}`: HMAC header name must not be empty when specified",
                                target.name
                            ));
                        } else if reqwest::header::HeaderName::try_from(h.as_str()).is_err() {
                            errors.push(format!(
                                "target `{}`: HMAC header `{}` is not a valid HTTP header name",
                                target.name, h
                            ));
                        } else if Self::RESERVED_HMAC_HEADERS
                            .contains(&h.to_ascii_lowercase().as_str())
                        {
                            errors.push(format!(
                                "target `{}`: HMAC header `{}` collides with a reserved header",
                                target.name, h
                            ));
                        }
                    }
                }
            }
        }

        // Validate custom header names and values
        if let Some(headers) = &target.headers {
            for entry in headers {
                if entry.name.is_empty() {
                    errors.push(format!(
                        "target `{}`: custom header name must not be empty",
                        target.name
                    ));
                } else if reqwest::header::HeaderName::try_from(&entry.name).is_err() {
                    errors.push(format!(
                        "target `{}`: invalid HTTP header name `{}`",
                        target.name, entry.name
                    ));
                } else if Self::RESERVED_HMAC_HEADERS
                    .contains(&entry.name.to_ascii_lowercase().as_str())
                {
                    errors.push(format!(
                        "target `{}`: custom header `{}` is reserved and cannot be overridden",
                        target.name, entry.name
                    ));
                }

                // Validate header values: reject control characters that could
                // enable header injection (CRLF injection, null byte smuggling).
                // reqwest rejects these at request time, but validating at config
                // parse gives operators a clear startup error instead of silent
                // per-request failures.
                if reqwest::header::HeaderValue::from_str(&entry.value).is_err() {
                    errors.push(format!(
                        "target `{}`: custom header `{}` has an invalid value \
                         (contains control characters or non-ASCII bytes)",
                        target.name, entry.name
                    ));
                }
            }
        }

        // Validate timeout
        if let Some(timeout) = target.timeout_secs
            && timeout == 0
        {
            errors.push(format!(
                "target `{}`: timeout-secs must be greater than 0",
                target.name
            ));
        }

        // Response body capture cap — bounded to 1 MiB to prevent a
        // misconfigured deployment from turning every failed request
        // into a megabyte of structured log spam.
        if let Some(cap) = target.max_response_body_bytes
            && cap > 1024 * 1024
        {
            errors.push(format!(
                "target `{}`: max-response-body-bytes ({cap}) exceeds the 1 MiB cap",
                target.name
            ));
        }

        // Batch configuration: only validate the shape when opt-in.
        // Pre-#906 configs leave every batch-* field `None` and must
        // not trigger any new error path.
        if target.batch_enabled == Some(true) {
            // Batching only frames JSON bodies. Raw XML and protobuf
            // do not have a portable "array of messages" encoding that
            // every downstream would accept; rejecting at validation
            // time keeps operators from discovering the mismatch as
            // silent 4xx responses at runtime.
            let fmt = target.effective_format();
            if fmt != PayloadFormat::Json {
                errors.push(format!(
                    "target `{}`: batch-enabled = true requires format = json (got {fmt:?}); \
                     raw-xml and protobuf do not have a portable batch wire format",
                    target.name
                ));
            }

            if let Some(n) = target.batch_max_messages
                && n < MIN_BATCH_MAX_MESSAGES
            {
                errors.push(format!(
                    "target `{}`: batch-max-messages ({n}) must be >= {MIN_BATCH_MAX_MESSAGES} \
                     (a batch of 1 is degenerate — adds envelope overhead without amortizing cost)",
                    target.name
                ));
            }

            if let Some(n) = target.batch_max_bytes
                && n < MIN_BATCH_MAX_BYTES
            {
                errors.push(format!(
                    "target `{}`: batch-max-bytes ({n}) must be >= {MIN_BATCH_MAX_BYTES} \
                     (below 1 KiB every realistic message body triggers an immediate flush)",
                    target.name
                ));
            }
        }
    }
}

/// Returns `true` if the IP address is in a private, loopback, link-local,
/// or cloud-metadata range that should be blocked for SSRF prevention.
///
/// Covers:
/// - **IPv4**: loopback, RFC 1918 private, link-local (incl. AWS IMDS), broadcast, unspecified
/// - **IPv6**: loopback, unspecified, IPv4-mapped (e.g. `::ffff:127.0.0.1`),
///   unique-local (`fc00::/7`), link-local (`fe80::/10`)
///
/// The IPv4-mapped check prevents a common SSRF bypass where attackers use
/// `::ffff:127.0.0.1` to evade IPv4-only blocklists (CVE-2023-26431 pattern).
pub(crate) fn is_private_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => is_private_ipv4(v4),
        std::net::IpAddr::V6(v6) => {
            v6.is_loopback()               // ::1
                || v6.is_unspecified()      // ::
                // IPv4-mapped IPv6 (::ffff:x.x.x.x) — extract embedded v4 and re-check.
                // Without this, ::ffff:127.0.0.1 bypasses the IPv4 blocklist.
                || v6.to_ipv4_mapped().is_some_and(is_private_ipv4)
                // Unique-local (fc00::/7) — IPv6 equivalent of RFC 1918
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                // Link-local (fe80::/10)
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                // Multicast (ff00::/8)
                || v6.is_multicast()
        }
    }
}

/// IPv4-specific private/reserved IP check, factored out so it can be
/// reused for IPv4-mapped IPv6 addresses.
fn is_private_ipv4(v4: std::net::Ipv4Addr) -> bool {
    v4.is_loopback()           // 127.0.0.0/8
        || v4.is_private()     // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
        || v4.is_link_local()  // 169.254.0.0/16 (includes AWS IMDS 169.254.169.254)
        || v4.is_broadcast()   // 255.255.255.255
        || v4.is_unspecified() // 0.0.0.0
        || v4.is_multicast() // 224.0.0.0/4
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use super::*;

    fn minimal_target(name: &str, url: &str) -> TargetConfig {
        TargetConfig {
            name: name.to_string(),
            url: url.to_string(),
            method: None,
            auth: None,
            tls: None,
            timeout_secs: None,
            format: None,
            filter: None,
            retry: None,
            enabled: None,
            headers: None,
            max_payload_bytes: None,
            rate_limit_per_sec: None,
            capture_response_body: None,
            max_response_body_bytes: None,
            batch_enabled: None,
            batch_max_messages: None,
            batch_max_bytes: None,
            batch_format: None,
        }
    }

    fn config_with_targets(targets: Vec<TargetConfig>) -> HttpConfig {
        HttpConfig {
            instance_id: None,
            targets,
            dlq_dir: None,
            dlq_key_file: None,
            dlq_max_bytes: None,
            dlq_max_target_bytes: None,
            allow_private_urls: false,
        }
    }

    #[test]
    fn valid_minimal_config() {
        let cfg = config_with_targets(vec![minimal_target("t1", "https://example.com/webhook")]);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn valid_http_scheme() {
        let cfg = config_with_targets(vec![minimal_target("t1", "http://internal:8080/api")]);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn rejects_empty_targets() {
        let cfg = config_with_targets(vec![]);
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("at least one target"));
    }

    #[test]
    fn rejects_empty_target_name() {
        let cfg = config_with_targets(vec![minimal_target("", "https://example.com")]);
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("name must not be empty"));
    }

    #[test]
    fn rejects_duplicate_target_names() {
        let cfg = config_with_targets(vec![
            minimal_target("dup", "https://a.com"),
            minimal_target("dup", "https://b.com"),
        ]);
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("duplicate target name"));
    }

    #[test]
    fn rejects_invalid_name_characters() {
        let cfg = config_with_targets(vec![minimal_target("bad name!", "https://example.com")]);
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("invalid characters"));
    }

    #[test]
    fn allows_valid_name_characters() {
        let cfg = config_with_targets(vec![minimal_target("my-target_01", "https://example.com")]);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn rejects_empty_url() {
        let cfg = config_with_targets(vec![minimal_target("t1", "")]);
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("URL must not be empty"));
    }

    #[test]
    fn rejects_malformed_url() {
        let cfg = config_with_targets(vec![minimal_target("t1", "not a url")]);
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("invalid URL"));
    }

    #[test]
    fn rejects_non_http_scheme() {
        let cfg = config_with_targets(vec![minimal_target("t1", "ftp://example.com/file")]);
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("scheme must be http or https"));
    }

    #[test]
    fn rejects_file_scheme() {
        let cfg = config_with_targets(vec![minimal_target("t1", "file:///etc/passwd")]);
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("scheme must be http or https"));
    }

    #[test]
    fn rejects_tls_cert_without_key() {
        let mut target = minimal_target("t1", "https://example.com");
        target.tls = Some(TlsConfig {
            ca_cert: None,
            client_cert: Some("/path/cert.pem".to_string()),
            client_key: None,
            pin_sha256: None,
        });
        let cfg = config_with_targets(vec![target]);
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("client-cert and client-key"));
    }

    #[test]
    fn rejects_tls_key_without_cert() {
        let mut target = minimal_target("t1", "https://example.com");
        target.tls = Some(TlsConfig {
            ca_cert: None,
            client_cert: None,
            client_key: Some("/path/key.pem".to_string()),
            pin_sha256: None,
        });
        let cfg = config_with_targets(vec![target]);
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("client-cert and client-key"));
    }

    #[test]
    fn valid_tls_with_both_cert_and_key() {
        let mut target = minimal_target("t1", "https://example.com");
        target.tls = Some(TlsConfig {
            ca_cert: Some("/path/ca.pem".to_string()),
            client_cert: Some("/path/cert.pem".to_string()),
            client_key: Some("/path/key.pem".to_string()),
            pin_sha256: None,
        });
        let cfg = config_with_targets(vec![target]);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn rejects_empty_bearer_token_file() {
        let mut target = minimal_target("t1", "https://example.com");
        target.auth = Some(AuthConfig::Bearer {
            token_file: String::new(),
        });
        let cfg = config_with_targets(vec![target]);
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("token-file must not be empty"));
    }

    #[test]
    fn rejects_empty_basic_username() {
        let mut target = minimal_target("t1", "https://example.com");
        target.auth = Some(AuthConfig::Basic {
            username: String::new(),
            password_file: "/path/pass".to_string(),
        });
        let cfg = config_with_targets(vec![target]);
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("username must not be empty"));
    }

    #[test]
    fn rejects_empty_basic_password_file() {
        let mut target = minimal_target("t1", "https://example.com");
        target.auth = Some(AuthConfig::Basic {
            username: "user".to_string(),
            password_file: String::new(),
        });
        let cfg = config_with_targets(vec![target]);
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("password-file must not be empty"));
    }

    #[test]
    fn rejects_empty_hmac_secret_file() {
        let mut target = minimal_target("t1", "https://example.com");
        target.auth = Some(AuthConfig::Hmac {
            secret_file: String::new(),
            header: None,
        });
        let cfg = config_with_targets(vec![target]);
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("secret-file must not be empty"));
    }

    #[test]
    fn rejects_empty_hmac_header_when_specified() {
        let mut target = minimal_target("t1", "https://example.com");
        target.auth = Some(AuthConfig::Hmac {
            secret_file: "/path/secret".to_string(),
            header: Some(String::new()),
        });
        let cfg = config_with_targets(vec![target]);
        let err = cfg.validate().unwrap_err();
        assert!(
            err.to_string()
                .contains("header name must not be empty when specified")
        );
    }

    #[test]
    fn rejects_invalid_custom_header_name() {
        let mut target = minimal_target("t1", "https://example.com");
        target.headers = Some(vec![HeaderEntry {
            name: "invalid header!".to_string(),
            value: "val".to_string(),
        }]);
        let cfg = config_with_targets(vec![target]);
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("invalid HTTP header name"));
    }

    #[test]
    fn rejects_empty_custom_header_name() {
        let mut target = minimal_target("t1", "https://example.com");
        target.headers = Some(vec![HeaderEntry {
            name: String::new(),
            value: "val".to_string(),
        }]);
        let cfg = config_with_targets(vec![target]);
        let err = cfg.validate().unwrap_err();
        assert!(
            err.to_string()
                .contains("custom header name must not be empty")
        );
    }

    #[test]
    fn valid_custom_headers() {
        let mut target = minimal_target("t1", "https://example.com");
        target.headers = Some(vec![
            HeaderEntry {
                name: "X-Api-Key".to_string(),
                value: "abc123".to_string(),
            },
            HeaderEntry {
                name: "X-Tenant".to_string(),
                value: "division-alpha".to_string(),
            },
        ]);
        let cfg = config_with_targets(vec![target]);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn rejects_zero_timeout() {
        let mut target = minimal_target("t1", "https://example.com");
        target.timeout_secs = Some(0);
        let cfg = config_with_targets(vec![target]);
        let err = cfg.validate().unwrap_err();
        assert!(
            err.to_string()
                .contains("timeout-secs must be greater than 0")
        );
    }

    #[test]
    fn rejects_loopback_ip() {
        let cfg = config_with_targets(vec![minimal_target("t1", "http://127.0.0.1:8080/webhook")]);
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("SSRF"));
    }

    #[test]
    fn rejects_private_rfc1918_ip() {
        let cfg = config_with_targets(vec![minimal_target("t1", "https://10.0.0.1:443/api")]);
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("SSRF"));
    }

    #[test]
    fn rejects_link_local_ip() {
        let cfg = config_with_targets(vec![minimal_target(
            "t1",
            "http://169.254.169.254/latest/meta-data/",
        )]);
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("SSRF"));
    }

    #[test]
    fn rejects_localhost_hostname() {
        let cfg = config_with_targets(vec![minimal_target("t1", "http://localhost:8080/api")]);
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("SSRF"));
    }

    #[test]
    fn rejects_ipv6_loopback() {
        let cfg = config_with_targets(vec![minimal_target("t1", "http://[::1]:8080/api")]);
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("SSRF"));
    }

    #[test]
    fn rejects_ipv4_mapped_v6_loopback() {
        let cfg = config_with_targets(vec![minimal_target(
            "t1",
            "http://[::ffff:127.0.0.1]:8080/api",
        )]);
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("SSRF"));
    }

    #[test]
    fn rejects_ipv4_mapped_v6_private() {
        let cfg = config_with_targets(vec![minimal_target(
            "t1",
            "http://[::ffff:10.0.0.1]:8080/api",
        )]);
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("SSRF"));
    }

    #[test]
    fn rejects_ipv4_mapped_v6_link_local() {
        let cfg = config_with_targets(vec![minimal_target(
            "t1",
            "http://[::ffff:169.254.169.254]/metadata",
        )]);
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("SSRF"));
    }

    #[test]
    fn rejects_v6_unique_local() {
        let cfg = config_with_targets(vec![minimal_target("t1", "http://[fc00::1]:8080/api")]);
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("SSRF"));
    }

    #[test]
    fn rejects_v6_link_local() {
        let cfg = config_with_targets(vec![minimal_target("t1", "http://[fe80::1]:8080/api")]);
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("SSRF"));
    }

    #[test]
    fn allows_public_ip() {
        let cfg = config_with_targets(vec![minimal_target("t1", "https://8.8.8.8:443/webhook")]);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn rejects_reserved_custom_header() {
        let mut target = minimal_target("t1", "https://example.com");
        target.headers = Some(vec![HeaderEntry {
            name: "Authorization".to_string(),
            value: "Bearer hack".to_string(),
        }]);
        let cfg = config_with_targets(vec![target]);
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("reserved"));
    }

    #[test]
    fn rejects_content_type_override() {
        let mut target = minimal_target("t1", "https://example.com");
        target.headers = Some(vec![HeaderEntry {
            name: "Content-Type".to_string(),
            value: "text/plain".to_string(),
        }]);
        let cfg = config_with_targets(vec![target]);
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("reserved"));
    }

    #[test]
    fn rejects_connection_header_override() {
        let mut target = minimal_target("t1", "https://example.com");
        target.headers = Some(vec![HeaderEntry {
            name: "Connection".to_string(),
            value: "keep-alive".to_string(),
        }]);
        let cfg = config_with_targets(vec![target]);
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("reserved"));
    }

    #[test]
    fn rejects_cookie_header_override() {
        let mut target = minimal_target("t1", "https://example.com");
        target.headers = Some(vec![HeaderEntry {
            name: "Cookie".to_string(),
            value: "session=abc".to_string(),
        }]);
        let cfg = config_with_targets(vec![target]);
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("reserved"));
    }

    #[test]
    fn rejects_proxy_authorization_header_override() {
        let mut target = minimal_target("t1", "https://example.com");
        target.headers = Some(vec![HeaderEntry {
            name: "Proxy-Authorization".to_string(),
            value: "Basic creds".to_string(),
        }]);
        let cfg = config_with_targets(vec![target]);
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("reserved"));
    }

    #[test]
    fn rejects_hmac_header_colliding_with_reserved() {
        let mut target = minimal_target("t1", "https://example.com");
        target.auth = Some(AuthConfig::Hmac {
            secret_file: "/tmp/fake-secret".to_string(),
            header: Some("Authorization".to_string()),
        });
        let cfg = config_with_targets(vec![target]);
        let err = cfg.validate().unwrap_err();
        assert!(
            err.to_string().contains("collides with a reserved header"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_hmac_header_transfer_encoding() {
        let mut target = minimal_target("t1", "https://example.com");
        target.auth = Some(AuthConfig::Hmac {
            secret_file: "/tmp/fake-secret".to_string(),
            header: Some("Transfer-Encoding".to_string()),
        });
        let cfg = config_with_targets(vec![target]);
        let err = cfg.validate().unwrap_err();
        assert!(
            err.to_string().contains("collides with a reserved header"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_hmac_header_invalid_name() {
        let mut target = minimal_target("t1", "https://example.com");
        target.auth = Some(AuthConfig::Hmac {
            secret_file: "/tmp/fake-secret".to_string(),
            header: Some("Invalid Header!".to_string()),
        });
        let cfg = config_with_targets(vec![target]);
        let err = cfg.validate().unwrap_err();
        assert!(
            err.to_string().contains("not a valid HTTP header name"),
            "got: {err}"
        );
    }

    #[test]
    fn accepts_valid_custom_hmac_header() {
        let mut target = minimal_target("t1", "https://example.com");
        target.auth = Some(AuthConfig::Hmac {
            secret_file: "/tmp/fake-secret".to_string(),
            header: Some("X-Custom-Signature".to_string()),
        });
        let cfg = config_with_targets(vec![target]);
        // Should pass validation (secret file won't exist but validation
        // doesn't read files — only from_config does)
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn rejects_unknown_config_fields() {
        // deny_unknown_fields should reject typos
        let toml_str = r#"
[[targets]]
name = "t1"
url = "https://example.com"
tiemout-secs = 10
"#;
        let result: Result<HttpConfig, _> = toml::from_str(toml_str);
        assert!(
            result.is_err(),
            "should reject unknown field 'tiemout-secs'"
        );
    }

    #[test]
    fn multiple_errors_collected() {
        let cfg = config_with_targets(vec![
            minimal_target("", ""),
            minimal_target("t1", "ftp://bad"),
        ]);
        let err = cfg.validate().unwrap_err();
        let msg = err.to_string();
        // Should contain multiple errors separated by semicolons
        assert!(msg.contains(';'));
        assert!(msg.contains("name must not be empty"));
        assert!(msg.contains("scheme must be http or https"));
    }

    #[test]
    fn default_values() {
        let target = minimal_target("t1", "https://example.com");
        assert_eq!(target.effective_method(), HttpMethod::Post);
        assert_eq!(target.effective_timeout_secs(), 10);
        assert_eq!(target.effective_format(), PayloadFormat::Json);
        assert!(target.is_enabled());
    }

    #[test]
    fn retry_default_values() {
        let retry = RetryConfig::default();
        assert_eq!(retry.effective_max_attempts(), 3);
        assert_eq!(retry.effective_backoff_base_secs(), 1);
        assert_eq!(retry.effective_circuit_threshold(), 5);
        assert_eq!(retry.effective_circuit_cooldown_secs(), 30);
    }

    #[test]
    fn toml_deserialization() {
        let toml_str = r#"
instance-id = "test-01"

[[targets]]
name = "siem"
url = "https://siem.internal:8443/api/v1/events"
method = "post"
format = "json"
timeout-secs = 15
enabled = true

[targets.auth]
type = "bearer"
token-file = "/etc/secrets/token"

[targets.tls]
ca-cert = "/etc/tls/ca.pem"

[targets.filter]
groups = ["alpha", "bravo"]
message-types = ["position"]

[targets.retry]
max-attempts = 5
backoff-base-secs = 2
circuit-breaker-threshold = 10
circuit-breaker-cooldown-secs = 60

[[targets.headers]]
name = "X-Api-Version"
value = "2"
"#;
        let config: HttpConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.instance_id.as_deref(), Some("test-01"));
        assert_eq!(config.targets.len(), 1);

        let t = &config.targets[0];
        assert_eq!(t.name, "siem");
        assert_eq!(t.effective_method(), HttpMethod::Post);
        assert_eq!(t.effective_timeout_secs(), 15);
        assert_eq!(t.effective_format(), PayloadFormat::Json);
        assert!(t.is_enabled());

        let retry = t.retry.as_ref().unwrap();
        assert_eq!(retry.effective_max_attempts(), 5);
        assert_eq!(retry.effective_backoff_base_secs(), 2);
        assert_eq!(retry.effective_circuit_threshold(), 10);
        assert_eq!(retry.effective_circuit_cooldown_secs(), 60);

        let filter = t.filter.as_ref().unwrap();
        assert_eq!(
            filter.groups.as_deref(),
            Some(&["alpha".to_string(), "bravo".to_string()][..])
        );

        let headers = t.headers.as_ref().unwrap();
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].name, "X-Api-Version");
    }

    #[test]
    fn toml_hmac_auth() {
        let toml_str = r#"
[[targets]]
name = "webhook"
url = "https://example.com/hook"

[targets.auth]
type = "hmac"
secret-file = "/etc/secrets/key"
header = "X-Signature-256"
"#;
        let config: HttpConfig = toml::from_str(toml_str).unwrap();
        let auth = config.targets[0].auth.as_ref().unwrap();
        match auth {
            AuthConfig::Hmac {
                secret_file,
                header,
            } => {
                assert_eq!(secret_file, "/etc/secrets/key");
                assert_eq!(header.as_deref(), Some("X-Signature-256"));
            }
            _ => panic!("expected HMAC auth"),
        }
    }

    #[test]
    fn toml_basic_auth() {
        let toml_str = r#"
[[targets]]
name = "api"
url = "https://example.com/api"

[targets.auth]
type = "basic"
username = "user"
password-file = "/etc/secrets/pass"
"#;
        let config: HttpConfig = toml::from_str(toml_str).unwrap();
        let auth = config.targets[0].auth.as_ref().unwrap();
        match auth {
            AuthConfig::Basic {
                username,
                password_file,
            } => {
                assert_eq!(username, "user");
                assert_eq!(password_file, "/etc/secrets/pass");
            }
            _ => panic!("expected Basic auth"),
        }
    }

    #[test]
    fn toml_raw_xml_format() {
        let toml_str = r#"
[[targets]]
name = "xml-consumer"
url = "https://example.com/xml"
format = "raw_xml"
"#;
        let config: HttpConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.targets[0].effective_format(), PayloadFormat::RawXml);
    }

    #[test]
    fn toml_put_method() {
        let toml_str = r#"
[[targets]]
name = "put-api"
url = "https://example.com/api"
method = "put"
"#;
        let config: HttpConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.targets[0].effective_method(), HttpMethod::Put);
    }

    #[test]
    fn rejects_pin_without_ca_cert() {
        let mut target = minimal_target("t1", "https://example.com");
        target.tls = Some(TlsConfig {
            ca_cert: None,
            client_cert: None,
            client_key: None,
            pin_sha256: Some(vec!["dGVzdA==".to_string()]),
        });
        let cfg = config_with_targets(vec![target]);
        let err = cfg.validate().unwrap_err();
        assert!(
            err.to_string().contains("pin-sha256 requires ca-cert"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_invalid_base64_pin() {
        let mut target = minimal_target("t1", "https://example.com");
        target.tls = Some(TlsConfig {
            ca_cert: Some("/path/ca.pem".to_string()),
            client_cert: None,
            client_key: None,
            pin_sha256: Some(vec!["not-valid-base64!!!".to_string()]),
        });
        let cfg = config_with_targets(vec![target]);
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("not valid base64"), "got: {err}");
    }

    #[test]
    fn accepts_valid_pin_with_ca_cert() {
        let mut target = minimal_target("t1", "https://example.com");
        // Valid base64-encoded SHA-256 hash (32 bytes → 44 base64 chars)
        target.tls = Some(TlsConfig {
            ca_cert: Some("/path/ca.pem".to_string()),
            client_cert: None,
            client_key: None,
            pin_sha256: Some(vec![
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
            ]),
        });
        let cfg = config_with_targets(vec![target]);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn rejects_dlq_dir_without_key_file() {
        let cfg = HttpConfig {
            instance_id: None,
            targets: vec![minimal_target("t1", "https://example.com")],
            dlq_dir: Some("/tmp/dlq".to_string()),
            dlq_key_file: None,
            dlq_max_bytes: None,
            dlq_max_target_bytes: None,
            allow_private_urls: false,
        };
        let err = cfg.validate().unwrap_err();
        assert!(
            err.to_string().contains("dlq-dir requires dlq-key-file"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_dlq_key_file_without_dir() {
        let cfg = HttpConfig {
            instance_id: None,
            targets: vec![minimal_target("t1", "https://example.com")],
            dlq_dir: None,
            dlq_key_file: Some("/path/keys.json".to_string()),
            dlq_max_bytes: None,
            dlq_max_target_bytes: None,
            allow_private_urls: false,
        };
        let err = cfg.validate().unwrap_err();
        assert!(
            err.to_string().contains("dlq-key-file requires dlq-dir"),
            "got: {err}"
        );
    }

    #[test]
    fn toml_protobuf_format() {
        let toml_str = r#"
[[targets]]
name = "proto-test"
url = "https://example.com/api"
format = "protobuf"
"#;
        let config: HttpConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(
            config.targets[0].effective_format(),
            PayloadFormat::Protobuf
        );
    }

    #[test]
    fn toml_pin_sha256() {
        let toml_str = r#"
[[targets]]
name = "pinned"
url = "https://example.com/api"

[targets.tls]
ca-cert = "/path/ca.pem"
pin-sha256 = ["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="]
"#;
        let config: HttpConfig = toml::from_str(toml_str).unwrap();
        let tls = config.targets[0].tls.as_ref().unwrap();
        assert_eq!(tls.pin_sha256.as_ref().unwrap().len(), 1);
    }

    #[test]
    fn rejects_header_value_with_newline() {
        let mut target = minimal_target("t1", "https://example.com");
        target.headers = Some(vec![HeaderEntry {
            name: "X-Custom".to_string(),
            value: "value\r\nInjected: header".to_string(),
        }]);
        let cfg = config_with_targets(vec![target]);
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("invalid value"), "got: {err}");
    }

    #[test]
    fn rejects_header_value_with_null_byte() {
        let mut target = minimal_target("t1", "https://example.com");
        target.headers = Some(vec![HeaderEntry {
            name: "X-Custom".to_string(),
            value: "before\0after".to_string(),
        }]);
        let cfg = config_with_targets(vec![target]);
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("invalid value"), "got: {err}");
    }

    #[test]
    fn toml_dlq_config() {
        let toml_str = r#"
dlq-dir = "/var/lib/rustgate/dlq"
dlq-key-file = "/etc/rustgate/keys/dlq.json"

[[targets]]
name = "t1"
url = "https://example.com"
"#;
        let config: HttpConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.dlq_dir.as_deref(), Some("/var/lib/rustgate/dlq"));
        assert_eq!(
            config.dlq_key_file.as_deref(),
            Some("/etc/rustgate/keys/dlq.json")
        );
    }

    /// Pins the #881a validation rule: `dlq-max-target-bytes` must be
    /// at least `dlq-max-bytes`. A target cap smaller than a single
    /// rotated file would invite the eviction sweep to delete the
    /// just-sealed segment before the writer has a chance to open a
    /// replacement, leaving a brief window with zero sealed files for
    /// the target — exactly the forensic gap the DLQ exists to avoid.
    #[test]
    fn rejects_dlq_max_target_bytes_smaller_than_dlq_max_bytes() {
        let cfg = HttpConfig {
            instance_id: None,
            targets: vec![minimal_target("t1", "https://example.com")],
            dlq_dir: None,
            dlq_key_file: None,
            dlq_max_bytes: Some(1024),
            dlq_max_target_bytes: Some(512),
            allow_private_urls: false,
        };
        let err = cfg.validate().unwrap_err();
        assert!(
            err.to_string().contains("dlq-max-target-bytes"),
            "got: {err}"
        );
    }

    /// Pins that `dlq-max-target-bytes = 0` is accepted and treated as
    /// "unlimited" (the documented historical behaviour), not rejected
    /// as smaller than `dlq-max-bytes`. Without the `target_cap > 0`
    /// guard in the validator the comparison `0 < file_cap` would
    /// incorrectly reject every operator who sets the cap to zero.
    #[test]
    fn accepts_dlq_max_target_bytes_zero_as_unlimited() {
        let cfg = HttpConfig {
            instance_id: None,
            targets: vec![minimal_target("t1", "https://example.com")],
            dlq_dir: None,
            dlq_key_file: None,
            dlq_max_bytes: Some(1024),
            dlq_max_target_bytes: Some(0),
            allow_private_urls: false,
        };
        assert!(cfg.validate().is_ok());
    }

    /// Pins that `dlq-max-target-bytes` equal to `dlq-max-bytes` is the
    /// boundary — must NOT be rejected. The inequality is `<`, not
    /// `<=`.
    #[test]
    fn accepts_dlq_max_target_bytes_equal_to_dlq_max_bytes() {
        let cfg = HttpConfig {
            instance_id: None,
            targets: vec![minimal_target("t1", "https://example.com")],
            dlq_dir: None,
            dlq_key_file: None,
            dlq_max_bytes: Some(1024),
            dlq_max_target_bytes: Some(1024),
            allow_private_urls: false,
        };
        assert!(cfg.validate().is_ok());
    }

    /// Pins the TOML roundtrip: `dlq-max-target-bytes` parses from the
    /// kebab-case config key into the snake_case struct field. Operator
    /// docs advertise the kebab-case name, so a regression that drops
    /// `rename_all = "kebab-case"` or renames the field would break
    /// every operator's config file.
    #[test]
    fn toml_dlq_max_target_bytes_roundtrips_kebab_case() {
        let toml_str = r#"
dlq-dir = "/var/lib/rustgate/dlq"
dlq-key-file = "/etc/rustgate/keys/dlq.json"
dlq-max-bytes = 268435456
dlq-max-target-bytes = 1073741824

[[targets]]
name = "t1"
url = "https://example.com"
"#;
        let config: HttpConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.dlq_max_bytes, Some(268_435_456));
        assert_eq!(config.dlq_max_target_bytes, Some(1_073_741_824));
    }

    // ── Response body capture (issue #906) ────────────────────────────

    /// Defaults: capture off, cap at 4 KiB. Keeps existing deployments
    /// from suddenly logging response bodies after the upgrade.
    #[test]
    fn response_body_defaults_are_conservative() {
        let t = minimal_target("t1", "https://example.com");
        assert!(
            !t.effective_capture_response_body(),
            "capture must default to off"
        );
        assert_eq!(
            t.effective_max_response_body_bytes(),
            4 * 1024,
            "cap must default to 4 KiB"
        );
    }

    /// Custom values round-trip through the effective accessors.
    #[test]
    fn response_body_explicit_values_round_trip() {
        let mut t = minimal_target("t1", "https://example.com");
        t.capture_response_body = Some(true);
        t.max_response_body_bytes = Some(16 * 1024);
        assert!(t.effective_capture_response_body());
        assert_eq!(t.effective_max_response_body_bytes(), 16 * 1024);
    }

    /// The 1 MiB cap is enforced at validation time — no deployment can
    /// configure a per-target cap higher than this.
    #[test]
    fn rejects_max_response_body_bytes_above_1mib() {
        let mut t = minimal_target("t1", "https://example.com");
        t.max_response_body_bytes = Some(1024 * 1024 + 1);
        let cfg = config_with_targets(vec![t]);
        let err = cfg.validate().unwrap_err();
        assert!(
            err.to_string().contains("exceeds the 1 MiB cap"),
            "got: {err}"
        );
    }

    /// The 1 MiB boundary is the *inclusive* upper limit. A target
    /// configured with exactly 1 MiB must pass validation.
    #[test]
    fn accepts_max_response_body_bytes_at_1mib_boundary() {
        let mut t = minimal_target("t1", "https://example.com");
        t.max_response_body_bytes = Some(1024 * 1024);
        let cfg = config_with_targets(vec![t]);
        assert!(cfg.validate().is_ok());
    }

    /// TOML round-trip: kebab-case config keys deserialise into the
    /// struct fields. Operator docs advertise kebab-case, so a
    /// regression that drops `rename_all = "kebab-case"` or renames
    /// either field would silently break deployed configs.
    #[test]
    fn toml_response_body_fields_roundtrip_kebab_case() {
        let toml_str = r#"
[[targets]]
name = "splunk-hec"
url = "https://example.com/services/collector/event"
capture-response-body = true
max-response-body-bytes = 8192
"#;
        let config: HttpConfig = toml::from_str(toml_str).unwrap();
        let t = &config.targets[0];
        assert_eq!(t.capture_response_body, Some(true));
        assert_eq!(t.max_response_body_bytes, Some(8192));
        assert!(t.effective_capture_response_body());
        assert_eq!(t.effective_max_response_body_bytes(), 8192);
    }
}
