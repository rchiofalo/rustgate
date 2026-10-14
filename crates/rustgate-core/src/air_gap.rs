// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Air-gap mode configuration and host classification.
//!
//! Air-gap mode is a runtime posture that disables every code path that
//! reaches outside the local trust domain (RFC 1918, loopback, link-local,
//! IPv6 Unique Local). It is enabled at the binary entrypoint via the
//! `--air-gap` CLI flag (or the `RUSTGATE_AIR_GAP` environment variable)
//! and propagated through [`AirGapConfig`] into every subsystem that
//! could otherwise dial an external endpoint:
//!
//! - **HTTP egress targets** (`rustgate-http`) — every URL is
//!   classified at startup; non-private targets refuse to load and emit
//!   [`crate::audit::air_gap_violation`].
//! - **OTEL exporter endpoints** (`--otel-endpoint`) — refused unless
//!   the resolved host is private.
//! - **Peer discovery** (Consul, etcd, DNS-SD) — refused unless the
//!   discovery endpoint is private.
//! - **OCSP fetching** — disabled entirely; the runtime falls back to
//!   CRL-only revocation checking.
//!
//! # Why a single classifier
//!
//! Each subsystem previously had its own ad-hoc "is it OK to dial this?"
//! check (see `rustgate-http`'s config validation for SSRF-style RFC 1918
//! blocking, which is the *inverse* of air-gap mode — SSRF protection
//! refuses private targets, air-gap mode requires them). Centralising
//! the classifier here keeps the IPv4 / IPv6 boundary cases and the
//! corner-case handling (IPv4-mapped IPv6, IPv6 ULA `fc00::/7`,
//! `.local` mDNS hostnames) in one place so a CVE in one of those
//! corner cases is fixed once, not five times.
//!
//! # Hostname classification
//!
//! When the host is not a literal IP address, the classifier accepts:
//!
//! - `localhost` (case-insensitive) — the canonical loopback name.
//! - `*.localhost` — RFC 6761 reserves the entire `localhost.` zone.
//! - `*.local` — RFC 6762 multicast DNS (mDNS) zone, used for in-LAN
//!   service discovery (Bonjour, Avahi, DNS-SD on the local segment).
//!
//! The classifier deliberately does **not** perform DNS resolution. A
//! hostname like `internal.corp.example` may resolve to a private
//! address inside the air-gapped network, but the classifier cannot
//! verify that without making a network call — and the whole point of
//! air-gap mode is that the binary should not be making opportunistic
//! network calls. Operators who need to allow such hostnames must
//! either configure a literal IP, use a name in `*.local`, or rely on
//! `/etc/hosts` overlays at the OS layer (which `nsswitch` resolves
//! synchronously and which the operator already controls in an
//! air-gapped deployment).

use std::net::IpAddr;

/// Configuration block controlling air-gap mode.
///
/// Default is `enabled: false` so air-gap is fully opt-in. When enabled,
/// the binary entrypoint MUST validate every operator-supplied external
/// endpoint via [`is_private_host`] before initiating any I/O against
/// it. Validation failures emit
/// [`crate::audit::air_gap_violation`] and refuse to start the affected
/// subsystem.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct AirGapConfig {
    /// When `true`, every external-facing subsystem refuses non-private
    /// endpoints at startup.
    pub enabled: bool,
}

impl AirGapConfig {
    /// Returns a config with air-gap mode enabled.
    pub fn enabled() -> Self {
        Self { enabled: true }
    }

    /// Returns `true` when the supplied host is acceptable under the
    /// current configuration. When air-gap mode is disabled, every host
    /// is acceptable. When enabled, only private / loopback / link-local
    /// hosts are acceptable; see [`is_private_host`] for the exact set.
    pub fn permits_host(&self, host: &str) -> bool {
        if !self.enabled {
            return true;
        }
        is_private_host(host)
    }
}

/// Classify a hostname or IP literal as private (true) or external (false).
///
/// Pure function: never performs DNS resolution, file I/O, or any
/// network call. Returns `true` when:
///
/// - The host is a literal IP that satisfies [`is_private_ip`].
/// - The host is `localhost` or `*.localhost` (RFC 6761).
/// - The host is `*.local` (RFC 6762 multicast DNS).
///
/// Hostnames are matched case-insensitively. IPv6 literals may be
/// supplied with or without surrounding brackets (`[::1]` and `::1`
/// both classify as private).
///
/// # Examples
///
/// ```
/// use rustgate_core::air_gap::is_private_host;
///
/// // Loopback
/// assert!(is_private_host("127.0.0.1"));
/// assert!(is_private_host("localhost"));
/// assert!(is_private_host("[::1]"));
/// assert!(is_private_host("::1"));
///
/// // RFC 1918 private
/// assert!(is_private_host("10.0.0.1"));
/// assert!(is_private_host("192.168.1.1"));
/// assert!(is_private_host("172.16.0.1"));
///
/// // Link-local
/// assert!(is_private_host("169.254.169.254"));
///
/// // IPv6 ULA (fc00::/7)
/// assert!(is_private_host("fc00::1"));
/// assert!(is_private_host("fd12:3456:789a::1"));
///
/// // mDNS
/// assert!(is_private_host("printer.local"));
///
/// // External
/// assert!(!is_private_host("example.com"));
/// assert!(!is_private_host("8.8.8.8"));
/// assert!(!is_private_host("2001:db8::1"));
/// ```
pub fn is_private_host(host: &str) -> bool {
    // Strip surrounding brackets for IPv6 literals supplied as `[::1]`.
    let bare = host
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(host);

    // Try IP literal first — this short-circuits before the hostname
    // match so a string that *looks* like a hostname but parses as an IP
    // (e.g. all-numeric labels) is classified by IP rules.
    if let Ok(ip) = bare.parse::<IpAddr>() {
        return is_private_ip(ip);
    }

    // Fall through to hostname classification. Comparisons are
    // case-insensitive because DNS names are case-insensitive (RFC 1035
    // §2.3.3) and an attacker could otherwise bypass the check via
    // `LOCALHOST` or `Local`.
    let lower = bare.to_ascii_lowercase();

    if lower == "localhost" {
        return true;
    }
    // RFC 6761 reserves the entire `localhost.` zone.
    if lower.ends_with(".localhost") {
        return true;
    }
    // RFC 6762 multicast DNS (mDNS) zone for LAN service discovery.
    if lower.ends_with(".local") || lower == "local" {
        return true;
    }

    false
}

/// Extract the host component of a URL-like string for classification.
///
/// Accepts any string with a `scheme://[userinfo@]host[:port][/...]`
/// shape and returns the host. Returns `None` when the string is not a
/// well-formed URL — callers should treat that case as a configuration
/// error and refuse the endpoint outright (the caller chooses whether
/// to bail or ignore; this helper does not log).
///
/// This is intentionally a small, dependency-free parser. The full
/// `url` crate is available in the workspace but reaches us only
/// transitively (through reqwest), and pulling it into
/// `rustgate-core` would force `url` onto every leaf crate. For the
/// air-gap classifier we only need the host portion, so a hand-rolled
/// extractor avoids the dependency churn.
///
/// IPv6 literals are returned **without** surrounding brackets, so the
/// caller can pass the result directly to [`is_private_host`] /
/// [`is_private_ip`].
pub fn extract_host(url: &str) -> Option<&str> {
    // Strip the scheme and the optional `//` authority marker. We accept
    // both `https://example.com` and `etcd://example.com` (the etcd
    // discovery configuration uses non-HTTP schemes).
    let after_scheme = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);

    // Strip userinfo if present (`user:pass@host`).
    let after_userinfo = after_scheme
        .rsplit_once('@')
        .map(|(_, rest)| rest)
        .unwrap_or(after_scheme);

    // Cut at the first path / query / fragment delimiter.
    let host_port = after_userinfo
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_userinfo);

    // IPv6 literals are bracketed. The closing bracket precedes any
    // optional `:port` so we cut at it first; otherwise we cut at the
    // last `:` (host:port).
    if let Some(stripped) = host_port.strip_prefix('[') {
        let end = stripped.find(']')?;
        return Some(&stripped[..end]);
    }
    let host = host_port.rsplit_once(':').map_or(host_port, |(h, _)| h);
    if host.is_empty() { None } else { Some(host) }
}

/// Classify an [`IpAddr`] as private (true) or external (false).
///
/// This is the IP-literal half of [`is_private_host`]; callers that
/// have already parsed an [`IpAddr`] can call it directly. The set
/// returned as `true` covers:
///
/// - **IPv4**: loopback (`127.0.0.0/8`), private (RFC 1918 — `10/8`,
///   `172.16/12`, `192.168/16`), link-local (`169.254/16` — note this
///   includes the AWS IMDS address `169.254.169.254`), broadcast,
///   unspecified (`0.0.0.0`), multicast (`224/4`).
/// - **IPv6**: loopback (`::1`), unspecified (`::`), IPv4-mapped IPv6
///   (`::ffff:0:0/96` — the embedded v4 is re-classified to prevent the
///   `::ffff:127.0.0.1` SSRF-style bypass), unique local (`fc00::/7`),
///   link-local (`fe80::/10`), multicast (`ff00::/8`).
pub fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || v4.is_multicast()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.to_ipv4_mapped().is_some_and(|v4| {
                    v4.is_loopback()
                        || v4.is_private()
                        || v4.is_link_local()
                        || v4.is_broadcast()
                        || v4.is_unspecified()
                        || v4.is_multicast()
                })
                // Unique-local addresses (fc00::/7), the IPv6 equivalent
                // of RFC 1918.
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                // Link-local addresses (fe80::/10).
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                || v6.is_multicast()
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn ipv4_loopback_is_private() {
        assert!(is_private_host("127.0.0.1"));
        assert!(is_private_host("127.255.255.255"));
        assert!(is_private_host("127.1.2.3"));
    }

    #[test]
    fn ipv4_rfc1918_is_private() {
        // 10/8
        assert!(is_private_host("10.0.0.1"));
        assert!(is_private_host("10.255.255.255"));
        // 172.16/12
        assert!(is_private_host("172.16.0.1"));
        assert!(is_private_host("172.31.255.255"));
        // The 172.32 boundary is *not* private — sanity-check the cutoff.
        assert!(!is_private_host("172.32.0.1"));
        // 192.168/16
        assert!(is_private_host("192.168.0.1"));
        assert!(is_private_host("192.168.255.255"));
    }

    #[test]
    fn ipv4_link_local_is_private() {
        assert!(is_private_host("169.254.0.1"));
        // AWS / Azure / GCP IMDS — explicitly want this classified as
        // private so an air-gapped operator's "no metadata service"
        // posture is preserved.
        assert!(is_private_host("169.254.169.254"));
    }

    #[test]
    fn ipv4_public_is_not_private() {
        assert!(!is_private_host("8.8.8.8"));
        assert!(!is_private_host("1.1.1.1"));
        assert!(!is_private_host("172.15.0.1")); // just below RFC 1918
        assert!(!is_private_host("11.0.0.1")); // just above 10/8
    }

    #[test]
    fn ipv4_unspecified_and_broadcast_are_private() {
        assert!(is_private_host("0.0.0.0"));
        assert!(is_private_host("255.255.255.255"));
    }

    #[test]
    fn ipv6_loopback_is_private() {
        assert!(is_private_host("::1"));
        assert!(is_private_host("[::1]"));
    }

    #[test]
    fn ipv6_ula_is_private() {
        // fc00::/7 covers fc00:: through fdff:..
        assert!(is_private_host("fc00::1"));
        assert!(is_private_host("fd00::1"));
        assert!(is_private_host("fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"));
        // fe00:: is *outside* the ULA range — ULA is fc00::/7, so the
        // mask catches fc00–fdff only.
        assert!(!is_private_host("fe00::1"));
    }

    #[test]
    fn ipv6_link_local_is_private() {
        assert!(is_private_host("fe80::1"));
        assert!(is_private_host("fe80::abcd:ef01"));
        // fec0:: was the deprecated site-local range; we don't classify
        // it as private (the RFC classifies it as global).
        assert!(!is_private_host("fec0::1"));
    }

    #[test]
    fn ipv6_public_is_not_private() {
        assert!(!is_private_host("2001:db8::1"));
        assert!(!is_private_host("2606:4700:4700::1111"));
    }

    #[test]
    fn ipv6_mapped_ipv4_is_classified_through_inner_address() {
        // Common SSRF bypass: if a check only looks at IPv6, the
        // attacker can wrap a private v4 address in the ::ffff:/96
        // mapping and slip past. Make sure we re-classify through.
        assert!(is_private_host("::ffff:127.0.0.1"));
        assert!(is_private_host("::ffff:10.0.0.1"));
        assert!(is_private_host("::ffff:192.168.1.1"));
        // And the inverse — a public v4 wrapped in the prefix is still
        // public.
        assert!(!is_private_host("::ffff:8.8.8.8"));
    }

    #[test]
    fn localhost_hostname_is_private() {
        assert!(is_private_host("localhost"));
        assert!(is_private_host("LOCALHOST"));
        assert!(is_private_host("LocalHost"));
    }

    #[test]
    fn dot_localhost_subdomains_are_private() {
        // RFC 6761: the entire `localhost.` zone is reserved.
        assert!(is_private_host("foo.localhost"));
        assert!(is_private_host("api.dev.localhost"));
        assert!(is_private_host("API.DEV.LOCALHOST"));
    }

    #[test]
    fn dot_local_mdns_is_private() {
        // RFC 6762 mDNS — used by Bonjour, Avahi, DNS-SD.
        assert!(is_private_host("printer.local"));
        assert!(is_private_host("rustgate.local"));
        assert!(is_private_host("PRINTER.LOCAL"));
        assert!(is_private_host("local"));
    }

    #[test]
    fn public_hostnames_are_not_private() {
        assert!(!is_private_host("example.com"));
        assert!(!is_private_host("api.production.example"));
        // A name that contains "local" as a substring but not as a suffix.
        assert!(!is_private_host("locally-hosted.example.com"));
        assert!(!is_private_host("locales.example.com"));
    }

    #[test]
    fn empty_host_is_not_private() {
        // An empty host is a configuration error, not a private host.
        assert!(!is_private_host(""));
    }

    #[test]
    fn config_default_permits_everything() {
        let cfg = AirGapConfig::default();
        assert!(!cfg.enabled);
        assert!(cfg.permits_host("example.com"));
        assert!(cfg.permits_host("8.8.8.8"));
        assert!(cfg.permits_host("127.0.0.1"));
    }

    #[test]
    fn config_enabled_permits_only_private_hosts() {
        let cfg = AirGapConfig::enabled();
        assert!(cfg.enabled);
        assert!(!cfg.permits_host("example.com"));
        assert!(!cfg.permits_host("8.8.8.8"));
        assert!(cfg.permits_host("127.0.0.1"));
        assert!(cfg.permits_host("10.0.0.1"));
        assert!(cfg.permits_host("localhost"));
        assert!(cfg.permits_host("printer.local"));
        assert!(cfg.permits_host("[fc00::1]"));
    }

    #[test]
    fn extract_host_handles_https_url() {
        assert_eq!(
            extract_host("https://example.com/path"),
            Some("example.com")
        );
        assert_eq!(
            extract_host("https://example.com:8443/path?q=1"),
            Some("example.com")
        );
    }

    #[test]
    fn extract_host_handles_userinfo() {
        assert_eq!(
            extract_host("https://user:pass@example.com/path"),
            Some("example.com")
        );
    }

    #[test]
    fn extract_host_handles_ipv6_literal() {
        assert_eq!(extract_host("https://[::1]:8443/path"), Some("::1"));
        assert_eq!(extract_host("https://[fc00::1]/path"), Some("fc00::1"));
    }

    #[test]
    fn extract_host_handles_etcd_scheme() {
        assert_eq!(extract_host("etcd://10.0.0.1:2379"), Some("10.0.0.1"));
    }

    #[test]
    fn extract_host_handles_grpc_otel() {
        assert_eq!(
            extract_host("grpc://otel-collector.observability:4317"),
            Some("otel-collector.observability")
        );
    }

    #[test]
    fn extract_host_handles_bare_host_port() {
        // Host:port with no scheme — supported because some operators
        // configure OTEL endpoints in this shape.
        assert_eq!(extract_host("collector:4317"), Some("collector"));
        assert_eq!(extract_host("10.0.0.1:2379"), Some("10.0.0.1"));
    }

    #[test]
    fn extract_host_returns_none_on_empty() {
        assert_eq!(extract_host(""), None);
        assert_eq!(extract_host("https://"), None);
    }

    #[test]
    fn ipv4_multicast_is_private() {
        // 224/4 — local routing scope; not something we want to dial
        // outbound under air-gap.
        assert!(is_private_host("224.0.0.1"));
        assert!(is_private_host("239.255.255.250"));
    }
}
