// Copyright © 2026 Roberto Chiofalo.

//! Foundational scaffold for the Meshtastic LoRa / serial ingress
//! seam (design note `docs/design/meshtastic-serial-ingress.md`,
//! ADR 0032).
//!
//! This module is the first real slice of the ingress work: the
//! transport-agnostic **config type**, the ingress **error enum**,
//! and the **non-IP admission key** that a later PR's live listener
//! will consume. It performs **no I/O**, holds **no key material**,
//! opens **no serial device or socket**, and pulls in **no new
//! dependency** — the whole module is gated behind the off-by-default
//! `meshtastic-ingress` Cargo feature and is inert at runtime.
//!
//! # Why a stub, not the listener
//!
//! The design note surfaces one genuine open fork the maintainer
//! owns (design-note **D1**): whether the live transport is a
//! **direct serial reader** (a new `tokio-serial` workspace
//! dependency, with rustgate owning the Meshtastic serial framing
//! and link-layer AES decryption) or a **defined UDP/TCP
//! "Meshtastic bridge" wire contract** (no new dependency; an
//! external adapter owns the serial device and the crypto, and
//! rustgate reuses the existing datagram / stream ingress seam).
//! Because the two transports diverge on exactly one field — how the
//! bytes arrive — the scaffold here commits to **neither** and adds
//! **no** dependency, so accepting the design note does not foreclose
//! the fork. The transport-specific field lands with the chosen
//! transport in the follow-up implementation PR.
//!
//! # Inherited invariants (ADR 0023 → ADR 0032)
//!
//! - **Synthetic identity only.** The default CN is
//!   [`DEFAULT_INGRESS_CN`]; the operator assigns exactly one ingress
//!   group that ACL / authz gate on. The spoofable Meshtastic node ID
//!   is a decoded-`Entity` attribute for correlation / dedup only —
//!   **never** a CN or authorization input.
//! - **Per-ingress admission.** A serial radio has no source IP, so
//!   the rate-limit / fan-out budget is keyed on the configured
//!   ingress ([`MeshIngressKey`]), not on a per-peer address, with a
//!   secure non-zero rate-limit default.
//! - **Validate-and-drop.** The live listener (follow-up PR) will run
//!   the full [`crate::codec::MeshtasticCodec`] decode on the
//!   already-decrypted payload and drop + audit anything that does not
//!   yield a valid entity. Decode stays pure and key-free; the
//!   transport owns de-encapsulation and link-layer decryption.

/// Default synthetic common-name for a Meshtastic ingress when the
/// operator does not override the prefix.
///
/// Mirrors the `"<proto>-anonymous"` shape the CoT-UDP and tactical
/// datagram listeners use. The wire-carried Meshtastic node ID is
/// **never** folded into this value (ADR 0023 D3 / ADR 0032 D3).
pub const DEFAULT_INGRESS_CN: &str = "meshtastic-anonymous";

/// Secure-default per-ingress datagram/packet budget (packets/sec)
/// applied when [`MeshIngressConfig::rate_limit_pps`] is left unset.
///
/// A Meshtastic ingress is an unauthenticated feed, so — as in the
/// tactical datagram note's mandatory hardening — the limiter is never
/// simply off; omitting the knob selects this bound rather than
/// "unlimited". The value is intentionally conservative for a
/// bandwidth-constrained LoRa mesh (a Meshtastic channel carries far
/// fewer than 100 application packets/sec in practice).
pub const DEFAULT_RATE_LIMIT_PPS: u32 = 100;

/// The non-IP admission key for a Meshtastic ingress.
///
/// The shared `rustgate_transport::UdpAdmission` gate is keyed on the
/// datagram source `IpAddr`; a LoRa serial radio has no source IP, so
/// admission (rate limit, bounded fan-out) is instead keyed on **the
/// operator-configured ingress channel itself** — one serial device or
/// one bridge socket is one budget. This is the type that identifies
/// that channel for admission and audit; it is deliberately *not* the
/// spoofable mesh node ID, which never authorizes.
///
/// The variants track the design-note **D1** fork without deciding it:
/// a direct serial reader keys on the device path, a bridge keys on the
/// socket's already-IP-keyed peer. The live listener (follow-up PR)
/// selects the variant that matches the chosen transport.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum MeshIngressKey {
    /// A direct-serial ingress (design-note D1a), identified by the
    /// operator-configured device label (e.g. `"/dev/ttyUSB0"`). Used
    /// verbatim only for audit / metrics correlation, never as an
    /// authorization input.
    Serial {
        /// Operator-configured device label for this ingress.
        device: String,
    },
    /// A bridge ingress (design-note D1b), identified by the
    /// operator-configured bind label (e.g. `"127.0.0.1:4403"`). Under
    /// this transport the bridge socket additionally gets the existing
    /// IP-keyed `UdpAdmission` controls for free.
    Bridge {
        /// Operator-configured bind label for this ingress.
        bind: String,
    },
}

impl MeshIngressKey {
    /// Stable, log-safe label for this ingress key, for audit / metric
    /// correlation.
    ///
    /// The returned string is the operator-configured label, which is
    /// **not** attacker-controlled wire data; callers that log it
    /// alongside untrusted fields should still route those other fields
    /// through `sanitize_for_log`.
    #[must_use]
    pub fn label(&self) -> &str {
        match self {
            Self::Serial { device } => device,
            Self::Bridge { bind } => bind,
        }
    }
}

/// Transport-agnostic configuration for a Meshtastic ingress.
///
/// Carries only the fields common to both design-note **D1** transports
/// (serial reader and bridge). The transport-specific field — a
/// `serial-device` path for D1a or a `bridge-bind` socket for D1b —
/// lands with the chosen transport in the follow-up implementation PR,
/// so this struct does not pre-commit the fork.
///
/// Off by default: a Meshtastic ingress exists only if the operator
/// explicitly configures one, matching every other listener's
/// default-deny posture.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct MeshIngressConfig {
    /// Routing destination group for accepted messages. ACL / authz
    /// apply to the routed message exactly as for plaintext CoT; this
    /// operator-assigned group is the sole trust decision.
    pub group: String,
    /// Synthetic-CN prefix for the transport-derived identity. Defaults
    /// to [`DEFAULT_INGRESS_CN`]. The mesh node ID is never folded in.
    pub ingress_cn: String,
    /// Per-ingress packet budget (packets/sec). `None` selects
    /// [`DEFAULT_RATE_LIMIT_PPS`] — the limiter is never simply off.
    pub rate_limit_pps: Option<u32>,
}

impl MeshIngressConfig {
    /// Construct a config for `group`, applying the secure defaults for
    /// the CN prefix and rate limit.
    #[must_use]
    pub fn new(group: impl Into<String>) -> Self {
        Self {
            group: group.into(),
            ingress_cn: DEFAULT_INGRESS_CN.to_string(),
            rate_limit_pps: None,
        }
    }

    /// The effective per-ingress rate limit: the operator override, or
    /// the secure [`DEFAULT_RATE_LIMIT_PPS`] default when unset.
    #[must_use]
    pub fn effective_rate_limit_pps(&self) -> u32 {
        self.rate_limit_pps.unwrap_or(DEFAULT_RATE_LIMIT_PPS)
    }

    /// Validate the config, rejecting shapes that cannot serve traffic.
    ///
    /// Fail-closed: an empty routing group or a zero rate limit is a
    /// startup error rather than a listener that silently drops (a zero
    /// limit) or routes to nowhere (an empty group). Mirrors the
    /// `validate()` discipline of the datagram / stream ingress config.
    ///
    /// # Errors
    ///
    /// Returns [`MeshIngressError::EmptyGroup`] when the routing group
    /// is blank, or [`MeshIngressError::ZeroRateLimit`] when an explicit
    /// rate limit of `0` was supplied.
    pub fn validate(&self) -> Result<(), MeshIngressError> {
        if self.group.trim().is_empty() {
            return Err(MeshIngressError::EmptyGroup);
        }
        if self.rate_limit_pps == Some(0) {
            return Err(MeshIngressError::ZeroRateLimit);
        }
        Ok(())
    }
}

/// Typed failure modes for the Meshtastic ingress path.
///
/// Distinct from [`crate::error::MeshtasticError`] (the codec's
/// decode/encode errors): these are the *transport / admission*
/// failures a live listener surfaces. `#[non_exhaustive]` so the
/// follow-up transport PR can add serial-open / bridge-bind /
/// decryption variants without a breaking change at the consumer
/// boundary.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MeshIngressError {
    /// The configured routing group is empty — the ingress would route
    /// accepted messages to nowhere. Fail-closed at config validation.
    #[error("Meshtastic ingress routing group must not be empty")]
    EmptyGroup,

    /// An explicit `rate-limit-pps = 0` was supplied. A zero limit
    /// silently drops every packet; the operator must either omit the
    /// knob (to take the secure [`DEFAULT_RATE_LIMIT_PPS`] default) or
    /// set a positive value. Fail-closed at config validation.
    #[error("Meshtastic ingress rate limit must be positive (omit to use the default)")]
    ZeroRateLimit,
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn new_applies_secure_defaults() {
        let cfg = MeshIngressConfig::new("mesh-feed");
        assert_eq!(cfg.group, "mesh-feed");
        assert_eq!(cfg.ingress_cn, DEFAULT_INGRESS_CN);
        assert_eq!(cfg.rate_limit_pps, None);
        assert_eq!(cfg.effective_rate_limit_pps(), DEFAULT_RATE_LIMIT_PPS);
    }

    #[test]
    fn override_rate_limit_is_honored() {
        let mut cfg = MeshIngressConfig::new("mesh-feed");
        cfg.rate_limit_pps = Some(25);
        assert_eq!(cfg.effective_rate_limit_pps(), 25);
    }

    #[test]
    fn validate_rejects_empty_group() {
        let cfg = MeshIngressConfig::new("   ");
        assert!(matches!(cfg.validate(), Err(MeshIngressError::EmptyGroup)));
    }

    #[test]
    fn validate_rejects_zero_rate_limit() {
        let mut cfg = MeshIngressConfig::new("mesh-feed");
        cfg.rate_limit_pps = Some(0);
        assert!(matches!(
            cfg.validate(),
            Err(MeshIngressError::ZeroRateLimit)
        ));
    }

    #[test]
    fn validate_accepts_default_config() {
        assert!(MeshIngressConfig::new("mesh-feed").validate().is_ok());
    }

    #[test]
    fn ingress_key_label_is_the_configured_source() {
        let serial = MeshIngressKey::Serial {
            device: "/dev/ttyUSB0".to_string(),
        };
        assert_eq!(serial.label(), "/dev/ttyUSB0");
        let bridge = MeshIngressKey::Bridge {
            bind: "127.0.0.1:4403".to_string(),
        };
        assert_eq!(bridge.label(), "127.0.0.1:4403");
    }
}
