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

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, unused_results)]
mod tests {
    use std::str::FromStr;

    use reqwest::dns::{Name, Resolve};

    use super::*;

    /// Helper that builds a [`reqwest::dns::Name`] without exposing the
    /// `FromStr` error path in every test body. The host strings we pass
    /// in are always valid DNS labels, so `unwrap` is accurate.
    fn name(s: &str) -> Name {
        Name::from_str(s).expect("valid DNS name")
    }

    #[test]
    fn new_preserves_allow_private_true() {
        let r = SsrfSafeResolver::new(true);
        assert!(
            r.allow_private,
            "allow_private=true must be stored so resolve() skips IP filtering"
        );
    }

    #[test]
    fn new_preserves_allow_private_false() {
        let r = SsrfSafeResolver::new(false);
        assert!(
            !r.allow_private,
            "allow_private=false must be stored so resolve() rejects private IPs"
        );
    }

    /// `localhost` resolves to a loopback address via `/etc/hosts`; with
    /// `allow_private = false` (the production default) the resolver must
    /// reject it to close the DNS-rebinding SSRF gap that `config.rs` URL
    /// validation cannot cover at runtime.
    #[tokio::test]
    async fn resolve_rejects_localhost_by_default() {
        let resolver = SsrfSafeResolver::new(false);
        let err = resolver
            .resolve(name("localhost"))
            .await
            .err()
            .expect("SSRF filter must reject localhost");

        let msg = err.to_string();
        assert!(
            msg.contains("SSRF protection"),
            "error message must name SSRF protection for operators to grep logs: {msg}"
        );
        assert!(
            msg.contains("private/reserved"),
            "error message must describe why it was rejected: {msg}"
        );
        assert!(
            msg.contains("localhost"),
            "error message must echo the offending name to aid diagnosis: {msg}"
        );
    }

    /// The resolver surfaces the same rejection as an
    /// [`std::io::ErrorKind::PermissionDenied`] so upstream callers that
    /// classify failures by kind see a stable signal. A regression that
    /// swaps it for, e.g., `InvalidData` would silently change retry and
    /// circuit-breaker behaviour.
    #[tokio::test]
    async fn resolve_rejection_surfaces_as_permission_denied() {
        let resolver = SsrfSafeResolver::new(false);
        let err = resolver
            .resolve(name("localhost"))
            .await
            .err()
            .expect("SSRF filter must reject localhost");

        let io_err = err
            .downcast_ref::<std::io::Error>()
            .expect("filter error must be an std::io::Error so downstream can classify it");
        assert_eq!(
            io_err.kind(),
            std::io::ErrorKind::PermissionDenied,
            "SSRF rejection must map to PermissionDenied to avoid being retried as a transient failure"
        );
    }

    /// `allow_private = true` is the escape hatch for test fixtures — it
    /// must bypass the filter entirely so integration tests can hit
    /// `127.0.0.1` and ephemeral wiremock servers.
    #[tokio::test]
    async fn resolve_allows_localhost_when_escape_hatch_set() {
        let resolver = SsrfSafeResolver::new(true);
        let addrs: Vec<_> = resolver
            .resolve(name("localhost"))
            .await
            .expect("allow_private=true must pass localhost through")
            .collect();

        assert!(
            !addrs.is_empty(),
            "localhost must resolve to at least one loopback address on a sane host"
        );
        for addr in &addrs {
            assert!(
                addr.ip().is_loopback(),
                "every address yielded for localhost must be loopback, got {addr}"
            );
        }
    }

    /// DNS lookup failures must propagate as-is — the filter only acts on
    /// a successful lookup. A broken lookup should not look like an SSRF
    /// rejection (different error kind, different message) so callers can
    /// tell "name doesn't exist" from "name resolves to a blocked IP".
    ///
    /// `.invalid` is RFC 6761 §6.4-reserved for this exact purpose: it is
    /// guaranteed to never resolve, so the test is deterministic on any
    /// host without network access.
    #[tokio::test]
    async fn resolve_propagates_dns_failure_without_wrapping() {
        let resolver = SsrfSafeResolver::new(false);
        let err = resolver
            .resolve(name("host-does-not-exist.invalid"))
            .await
            .err()
            .expect("RFC 6761 .invalid TLD must fail DNS");

        let msg = err.to_string();
        assert!(
            !msg.contains("SSRF protection"),
            "DNS failure must not be relabelled as an SSRF rejection: {msg}"
        );
        assert!(
            !msg.contains("private/reserved"),
            "DNS failure must not be relabelled as an SSRF rejection: {msg}"
        );
    }

    /// Sanity check that a sender's `allow_private = true` path also
    /// accepts non-loopback hostnames. `localhost` + escape hatch covers
    /// the common test wiring, but this test pins that the filter is a
    /// pure pass-through, not a loopback-only special case.
    #[tokio::test]
    async fn resolve_escape_hatch_does_not_filter_public_hostnames() {
        let resolver = SsrfSafeResolver::new(true);
        // `.invalid` fails DNS — what we want to pin is that the error
        // comes from DNS, not from the filter. A pure pass-through must
        // never inject its own rejection on the allow_private path.
        let err = resolver
            .resolve(name("pass-through.invalid"))
            .await
            .err()
            .expect(".invalid must fail DNS on any host");

        let msg = err.to_string();
        assert!(
            !msg.contains("SSRF protection"),
            "allow_private=true must bypass the filter entirely, even on DNS failure: {msg}"
        );
    }
}
