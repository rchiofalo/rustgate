// Copyright © 2026 Roberto Chiofalo.

//! Shared per-datagram admission control for connectionless UDP ingress.
//!
//! Connectionless tactical ingress (CoT over UDP, and the generic
//! [`crate::codec_ingress`] listener for DIS / ASTERIX / VMF and future
//! datagram codecs) accepts unauthenticated datagrams from anyone who can
//! reach the bound port. There is no mTLS to anchor identity, so the only
//! pre-routing trust controls are:
//!
//! 1. **Source CIDR allowlist** — drop datagrams from IPs outside the
//!    configured prefixes.
//! 2. **Per-IP rate limit** — a sliding-window cap on datagrams/sec per
//!    source IP, bounding flood / amplification.
//! 3. **Identity cap** — a bounded LRU of seen source IPs so a spray of
//!    spoofed sources cannot exhaust memory; once full, datagrams from
//!    *new* IPs are rejected (existing IPs keep flowing).
//!
//! These three checks are security-critical and must be applied
//! identically by every connectionless listener. Per the tactical-codec
//! ingress design note (#1473, decision D1), this helper is the **single
//! source of truth** for them so the controls are written, reviewed, and
//! fuzzed once rather than copied — and re-copied, with drift — into every
//! per-protocol listener. Order matters: cheapest/most-decisive check
//! first (CIDR), then rate limit, then the lock-taking identity cap.

use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::num::NonZeroUsize;

use lru::LruCache;
use parking_lot::Mutex;
use rustgate_resilience::SlidingWindowLimiter;
use tokio::net::UdpSocket;

use crate::udp::CidrPrefix;

/// Bind an IPv4 UDP socket to `0.0.0.0:port` with `SO_REUSEADDR`, then join
/// the multicast group `group` on `interface`.
///
/// This is the **single source of truth** for the connectionless multicast
/// receive-socket setup shared by every UDP listener that can optionally
/// join a group: the CoT-specific [`crate::udp_multicast`] listener and the
/// generic codec listener ([`crate::codec_ingress`]). Factoring it here keeps
/// the `SO_REUSEADDR` + wildcard-bind + `join_multicast_v4` sequence written,
/// reviewed, and corrected once rather than copied (the same D1 single-path
/// argument as [`UdpAdmission`]).
///
/// `SO_REUSEADDR` lets multiple processes (e.g. a sensor app and the router
/// on one host during an exercise) bind the same multicast port. The socket
/// binds the wildcard address rather than the group address itself: binding
/// to the multicast address is portable on Linux but rejected on Windows,
/// whereas the wildcard works everywhere.
///
/// Returns the joined, non-blocking [`UdpSocket`]; the caller applies any
/// further options (e.g. `set_multicast_loop_v4`) before entering its
/// receive loop.
pub fn bind_multicast_socket_v4(
    group: Ipv4Addr,
    port: u16,
    interface: Ipv4Addr,
) -> std::io::Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};

    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    let bind_addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port);
    socket.bind(&bind_addr.into())?;
    socket.set_nonblocking(true)?;
    let std_socket: std::net::UdpSocket = socket.into();
    let tokio_socket = UdpSocket::from_std(std_socket)?;
    tokio_socket.join_multicast_v4(group, interface)?;
    Ok(tokio_socket)
}

/// Outcome of an admission check for a single datagram's source IP.
///
/// The reject variants are distinct so the caller can emit the matching
/// audit event (`connection_rejected` / `security_rate_limited` / an
/// identity-cap rejection) and the matching metric, rather than collapsing
/// every drop into one undifferentiated counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmitDecision {
    /// The datagram may proceed to decode + routing.
    Accept,
    /// Source IP is not in the configured CIDR allowlist.
    DeniedCidr,
    /// Source IP exceeded its per-second datagram budget.
    RateLimited,
    /// The synthetic-identity LRU is full and this is a new source IP.
    IdentityCapReached,
}

/// Shared connectionless-UDP admission gate: CIDR allowlist, per-IP rate
/// limit, and a bounded synthetic-identity LRU.
///
/// Construct once per listener and call [`UdpAdmission::admit`] for every
/// received datagram's source IP before any decode or routing work.
pub struct UdpAdmission {
    /// `None` disables rate limiting (the historical CoT-UDP default; the
    /// generic codec listener always supplies a non-zero default).
    rate_limiter: Option<SlidingWindowLimiter>,
    /// `None` accepts all source IPs; `Some` is a strict allowlist.
    allowed_cidrs: Option<Vec<CidrPrefix>>,
    /// LRU of seen source IPs, bounded to `max_identities`.
    identity_cache: Mutex<LruCache<IpAddr, ()>>,
    /// The configured cap (mirrored for the "is the cache full?" check).
    max_identities: usize,
}

impl std::fmt::Debug for UdpAdmission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpAdmission")
            .field("rate_limiter_enabled", &self.rate_limiter.is_some())
            .field("allowed_cidrs", &self.allowed_cidrs)
            .field("max_identities", &self.max_identities)
            .finish()
    }
}

impl UdpAdmission {
    /// Build an admission gate.
    ///
    /// - `max_pps` — per-IP datagrams/sec; `None` disables rate limiting.
    /// - `allowed_cidrs` — source allowlist; `None` accepts all sources.
    /// - `max_identities` — synthetic-identity LRU bound (clamped to ≥ 1).
    pub fn new(
        max_pps: Option<usize>,
        allowed_cidrs: Option<Vec<CidrPrefix>>,
        max_identities: usize,
    ) -> Self {
        let rate_limiter = max_pps.map(|pps| {
            // Tagged "connection" for SIEM continuity with the TLS/CoT-UDP
            // listeners; the IPv6 /64 collapse stops a single /64 from
            // dodging the per-IP cap by rotating host bits.
            SlidingWindowLimiter::new(pps, std::time::Duration::from_secs(1), "connection")
                .with_ipv6_64_collapse(true)
        });
        // Clamp to ≥ 1 and store the *clamped* value so the LRU capacity
        // and the "is the cache full?" comparison in `admit` agree. (A raw
        // 0 would make `cache.len() >= 0` always true and reject every
        // datagram — fail-closed, but not the documented clamp-to-one.)
        let max_identities = max_identities.max(1);
        let cap = NonZeroUsize::new(max_identities).unwrap_or(NonZeroUsize::MIN);
        Self {
            rate_limiter,
            allowed_cidrs,
            identity_cache: Mutex::new(LruCache::new(cap)),
            max_identities,
        }
    }

    /// Apply the three checks in order and return the decision.
    ///
    /// On [`AdmitDecision::Accept`] the source IP has been recorded/promoted
    /// in the identity LRU. The lock is held only for the cap check and is
    /// never held across an `.await` (this method is synchronous).
    pub fn admit(&self, peer_ip: IpAddr) -> AdmitDecision {
        // 1. CIDR allowlist — most decisive, no lock, no state.
        if let Some(ref cidrs) = self.allowed_cidrs
            && !cidrs.iter().any(|c| c.contains(peer_ip))
        {
            return AdmitDecision::DeniedCidr;
        }

        // 2. Per-IP rate limit.
        if let Some(ref limiter) = self.rate_limiter
            && limiter.is_limited(peer_ip)
        {
            return AdmitDecision::RateLimited;
        }

        // 3. Identity cap. Reject (not evict) new IPs at capacity so an
        //    attacker rotating spoofed sources cannot displace legitimate
        //    entries.
        let mut cache = self.identity_cache.lock();
        if cache.get(&peer_ip).is_none() {
            if cache.len() >= self.max_identities {
                return AdmitDecision::IdentityCapReached;
            }
            let _ = cache.put(peer_ip, ());
        } else {
            let _ = cache.promote(&peer_ip);
        }
        AdmitDecision::Accept
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn accepts_when_no_controls_configured() {
        let a = UdpAdmission::new(None, None, 1024);
        assert_eq!(a.admit(ip("203.0.113.7")), AdmitDecision::Accept);
    }

    #[test]
    fn cidr_allowlist_accepts_inside_rejects_outside() {
        let cidrs = vec![CidrPrefix::new(ip("10.0.0.0"), 8).unwrap()];
        let a = UdpAdmission::new(None, Some(cidrs), 1024);
        assert_eq!(a.admit(ip("10.1.2.3")), AdmitDecision::Accept);
        assert_eq!(a.admit(ip("192.0.2.1")), AdmitDecision::DeniedCidr);
    }

    #[test]
    fn cidr_checked_before_identity_cap() {
        // A denied-by-CIDR datagram must not consume an identity slot.
        let cidrs = vec![CidrPrefix::new(ip("10.0.0.0"), 8).unwrap()];
        let a = UdpAdmission::new(None, Some(cidrs), 1);
        // Out-of-allowlist IP rejected by CIDR, no slot taken.
        assert_eq!(a.admit(ip("192.0.2.1")), AdmitDecision::DeniedCidr);
        // The single in-allowlist IP still gets the one slot.
        assert_eq!(a.admit(ip("10.0.0.5")), AdmitDecision::Accept);
    }

    #[test]
    fn rate_limit_caps_per_ip_burst() {
        let a = UdpAdmission::new(Some(2), None, 1024);
        let peer = ip("198.51.100.4");
        assert_eq!(a.admit(peer), AdmitDecision::Accept);
        assert_eq!(a.admit(peer), AdmitDecision::Accept);
        // Third within the same one-second window is limited.
        assert_eq!(a.admit(peer), AdmitDecision::RateLimited);
    }

    #[test]
    fn identity_cap_rejects_new_ips_at_capacity_but_keeps_known() {
        let a = UdpAdmission::new(None, None, 2);
        let ip1 = ip("10.0.0.1");
        let ip2 = ip("10.0.0.2");
        let ip3 = ip("10.0.0.3");
        assert_eq!(a.admit(ip1), AdmitDecision::Accept);
        assert_eq!(a.admit(ip2), AdmitDecision::Accept);
        // Cache full → a brand-new IP is rejected (not evicting ip1/ip2).
        assert_eq!(a.admit(ip3), AdmitDecision::IdentityCapReached);
        // Already-seen IPs keep flowing.
        assert_eq!(a.admit(ip1), AdmitDecision::Accept);
        assert_eq!(a.admit(ip2), AdmitDecision::Accept);
    }

    #[test]
    fn zero_max_identities_is_clamped_to_one() {
        // A misconfigured 0 must not panic the LRU (NonZeroUsize) nor
        // accept everything; it clamps to a single slot.
        let a = UdpAdmission::new(None, None, 0);
        assert_eq!(a.admit(ip("10.0.0.1")), AdmitDecision::Accept);
        assert_eq!(a.admit(ip("10.0.0.2")), AdmitDecision::IdentityCapReached);
    }
}
