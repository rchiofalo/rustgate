// Copyright © 2026 Roberto Chiofalo.

//! SSRF-safe DNS resolver for outbound HTTP connections.
//!
//! Wraps the system DNS resolver to validate resolved IP addresses
//! against the private/reserved IP blocklist **at connection time**,
//! eliminating the TOCTOU gap between config-time URL validation and
//! runtime DNS resolution.
//!
//! This defends against DNS rebinding attacks where an attacker controls
//! a domain that initially resolves to a safe public IP (passing config
//! validation) but later resolves to a private IP (e.g., `127.0.0.1`,
//! `169.254.169.254`) when the actual HTTP request is made.

use std::net::SocketAddr;

use reqwest::dns::{Addrs, Name, Resolve, Resolving};

use crate::config::is_private_ip;

/// DNS resolver that rejects private/reserved IP addresses at resolution time.
///
/// Attached to each target's `reqwest::Client` via `ClientBuilder::dns_resolver()`.
/// When `allow_private` is true (testing only), IP filtering is skipped.
pub(crate) struct SsrfSafeResolver {
    allow_private: bool,
}

impl SsrfSafeResolver {
    pub(crate) fn new(allow_private: bool) -> Self {
        Self { allow_private }
    }
}

impl Resolve for SsrfSafeResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let allow_private = self.allow_private;
        Box::pin(async move {
            let host = format!("{}:0", name.as_str());
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host(&host)
                .await
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?
                .collect();

            if allow_private {
                return Ok(Box::new(addrs.into_iter()) as Addrs);
            }

            let safe: Vec<SocketAddr> = addrs
                .into_iter()
                .filter(|addr| !is_private_ip(addr.ip()))
                .collect();

            if safe.is_empty() {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!(
                        "DNS resolution for `{}` returned only private/reserved IPs (SSRF protection)",
                        name.as_str()
                    ),
                ))
                    as Box<dyn std::error::Error + Send + Sync>);
            }

            Ok(Box::new(safe.into_iter()) as Addrs)
        })
    }
}
