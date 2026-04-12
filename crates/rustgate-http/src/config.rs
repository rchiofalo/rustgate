// Copyright © 2026 Roberto Chiofalo.

//! Configuration types for the HTTP egress bridge.
//!
//! Defines the TOML-deserializable configuration schema for HTTP targets
//! including per-target URL, authentication, TLS, filtering, retry, and
//! circuit breaker settings. All config structs use kebab-case field
//! names to match the workspace TOML convention.

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
    /// When absent, defaults to the system hostname.
    pub instance_id: Option<String>,

    /// Named targets. Each is an independent HTTP endpoint.
    pub targets: Vec<TargetConfig>,

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
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct TlsConfig {
    /// Custom CA certificate PEM for server verification.
    pub ca_cert: Option<String>,
    /// Client certificate PEM for mutual TLS.
    pub client_cert: Option<String>,
    /// Client private key PEM for mutual TLS.
    pub client_key: Option<String>,
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
    pub groups: Option<Vec<String>>,
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
}

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

        if errors.is_empty() {
            Ok(())
        } else {
            Err(HttpError::Config(errors.join("; ")))
        }
    }

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
                    if let Some(h) = header
                        && h.is_empty()
                    {
                        errors.push(format!(
                            "target `{}`: HMAC header name must not be empty when specified",
                            target.name
                        ));
                    }
                }
            }
        }

        // Validate custom header names
        if let Some(headers) = &target.headers {
            // Headers that must not be overridden by custom config
            const RESERVED_HEADERS: &[&str] = &[
                "host",
                "content-type",
                "content-length",
                "transfer-encoding",
                "authorization",
                "x-rustgate-instance",
                "x-rustgate-delivery-id",
            ];

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
                } else if RESERVED_HEADERS.contains(&entry.name.to_ascii_lowercase().as_str()) {
                    errors.push(format!(
                        "target `{}`: custom header `{}` is reserved and cannot be overridden",
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
    }
}

/// Returns `true` if the IP address is in a private, loopback, link-local,
/// or cloud-metadata range that should be blocked for SSRF prevention.
fn is_private_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            v4.is_loopback()               // 127.0.0.0/8
                || v4.is_private()          // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
                || v4.is_link_local()       // 169.254.0.0/16 (includes AWS IMDS 169.254.169.254)
                || v4.is_broadcast()        // 255.255.255.255
                || v4.is_unspecified() // 0.0.0.0
        }
        std::net::IpAddr::V6(v6) => {
            v6.is_loopback()               // ::1
                || v6.is_unspecified() // ::
        }
    }
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
        }
    }

    fn config_with_targets(targets: Vec<TargetConfig>) -> HttpConfig {
        HttpConfig {
            instance_id: None,
            targets,
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
}
