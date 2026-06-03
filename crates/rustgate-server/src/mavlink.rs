// Copyright © 2026 Roberto Chiofalo.

//! Server-side wiring for the MAVLink UDP/TCP listeners (PR 6 of #731).
//!
//! The `rustgate-mavlink` crate provides the framing codec, signing
//! trust boundary, listeners, and obligation actuators. This module is
//! the glue that turns operator-facing CLI flags + a TOML link manifest
//! into running listeners wired to the [`Router`], following ADR 0020.
//!
//! # Link manifest (ADR 0020 §1)
//!
//! MAVLink over UDP has no TLS, so the v2 signing `link_id` *is* the
//! identity primitive. The operator provides a TOML manifest mapping each
//! `link_id` to a rustgate identity and its 32-byte signing key:
//!
//! ```toml
//! [links.0x42]
//! cn = "drone-007"
//! groups = ["tactical/uav", "ops/team-alpha"]
//! signing-key-hex = "…64 hex chars…"   # 32-byte HMAC-SHA256 key
//!
//! [links.7]                            # decimal link ids also accepted
//! cn = "rover-12"
//! groups = ["tactical/ugv"]
//! signing-key-hex = "…64 hex chars…"
//! ```
//!
//! The file is read into [`Zeroizing`] memory, parsed, and each key is
//! hex-decoded into the [`SigningKeyStore`]; the hex strings are wiped
//! after decode. The same manifest populates the [`LinkRegistry`] that
//! resolves a verified `link_id` to an [`Identity`].
//!
//! # What is deliberately absent
//!
//! - **Hot reload.** The manifest is loaded once at startup. SIGHUP
//!   reload (ADR 0020 §1, via the ArcSwap pattern) is a follow-up.
//! - **PQ rekey control channel.** The `mavlink-pq` rekey envelope
//!   (ADR 0020 §4–§6) is implemented and unit-tested in
//!   `rustgate_mavlink::rekey`, but the receive-socket wiring that feeds
//!   envelopes into the running [`SigningKeyStore`] is a follow-up — the
//!   transport for the envelope is not pinned by the ADR.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context as _;
use rustgate_core::identity::Identity;
use rustgate_core::tasks::{SubsystemHandle, spawn_background};
use rustgate_mavlink::{
    LinkRegistry, MavlinkDestination, MavlinkListenerConfig, OnMavlinkMessage, SigningKeyStore,
    spawn_tcp_listener, spawn_udp_listener,
};
use rustgate_router::Router;
use serde::Deserialize;
use zeroize::{Zeroize, Zeroizing};

use crate::cli::Cli;

/// Length of a MAVLink v2 signing key in bytes (mirrors
/// [`rustgate_mavlink::SIGNING_KEY_LEN`]).
const SIGNING_KEY_LEN: usize = 32;

/// One `link_id` entry in the TOML link manifest.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct LinkEntry {
    /// The rustgate CN this link's traffic is attributed to.
    cn: String,
    /// Group memberships used for ACL / authz.
    #[serde(default)]
    groups: Vec<String>,
    /// 64-hex-char (32-byte) MAVLink v2 signing key.
    signing_key_hex: String,
}

/// Root of the TOML link manifest.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct LinkManifest {
    /// `link_id` → entry. Keys are decimal (`7`) or hex (`0x42`).
    #[serde(default)]
    links: BTreeMap<String, LinkEntry>,
}

/// The built MAVLink runtime: signing store + identity registry, ready to
/// hand to the listeners.
struct MavlinkRuntime {
    signing: Arc<SigningKeyStore>,
    links: Arc<LinkRegistry>,
}

/// Parse a `link_id` table key: decimal (`"7"`) or hex (`"0x42"` /
/// `"0X42"`), in the `u8` range.
fn parse_link_id(key: &str) -> anyhow::Result<u8> {
    let trimmed = key.trim();
    let parsed = if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        u8::from_str_radix(hex, 16)
    } else {
        trimmed.parse::<u8>()
    };
    parsed.with_context(|| {
        format!("invalid MAVLink link id `{key}` (expected 0-255, decimal or 0x-hex)")
    })
}

/// Decode a 64-char hex string into a 32-byte key, wiping the hex input.
fn decode_key(hex: &mut String, link_id: u8) -> anyhow::Result<[u8; SIGNING_KEY_LEN]> {
    let bytes = hex::decode(hex.trim())
        .with_context(|| format!("MAVLink signing key for link {link_id} is not valid hex"))?;
    hex.zeroize();
    let arr: [u8; SIGNING_KEY_LEN] = bytes.as_slice().try_into().map_err(|_| {
        anyhow::anyhow!(
            "MAVLink signing key for link {link_id} must be {SIGNING_KEY_LEN} bytes \
             ({} hex chars), got {} bytes",
            SIGNING_KEY_LEN * 2,
            bytes.len()
        )
    })?;
    Ok(arr)
}

/// Build the signing store + link registry from the manifest file and CLI.
fn build_runtime(cli: &Cli) -> anyhow::Result<MavlinkRuntime> {
    let mut store = SigningKeyStore::new();
    let mut registry = LinkRegistry::new();

    if let Some(path) = cli.mavlink.mavlink_signing_key_file.as_ref() {
        let raw = Zeroizing::new(
            std::fs::read_to_string(path)
                .with_context(|| format!("reading MAVLink signing key file `{path}`"))?,
        );
        let mut manifest: LinkManifest = toml::from_str(&raw)
            .with_context(|| format!("parsing MAVLink signing key file `{path}`"))?;

        for (key, entry) in manifest.links.iter_mut() {
            let link_id = parse_link_id(key)?;
            let key_bytes = decode_key(&mut entry.signing_key_hex, link_id)?;
            store.insert_key(link_id, key_bytes);

            let groups: BTreeSet<String> = entry.groups.iter().cloned().collect();
            let identity = Identity::plaintext(entry.cn.clone(), groups)
                .with_context(|| format!("invalid CN for MAVLink link {link_id}"))?;
            registry = registry.with_link(link_id, identity);
        }
    }

    if cli.mavlink.mavlink_allow_v1 {
        let cn = cli.mavlink.mavlink_v1_fallback_cn.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "--mavlink-allow-v1 requires --mavlink-v1-fallback-cn: v1 frames have no \
                 signing identity, so a shared fallback CN must be configured"
            )
        })?;
        let identity = Identity::plaintext(cn.clone(), BTreeSet::new())
            .context("invalid --mavlink-v1-fallback-cn")?;
        registry = registry.with_v1_fallback(identity);
        tracing::warn!(
            fallback_cn = %cn,
            "MAVLink v1 ingress enabled — v1 has no signing; all v1 traffic shares one identity"
        );
    }

    Ok(MavlinkRuntime {
        signing: Arc::new(store),
        links: Arc::new(registry),
    })
}

/// Build the destination every ingested frame routes to (ADR 0020 §2):
/// a group when `--mavlink-group` is set, broadcast otherwise.
fn destination(cli: &Cli) -> MavlinkDestination {
    match cli.mavlink.mavlink_group.as_ref() {
        Some(g) => MavlinkDestination::Group(Arc::from(g.as_str())),
        None => MavlinkDestination::Broadcast,
    }
}

/// Build the router sink. The listener calls this once per accepted frame;
/// async routing is dispatched off the read loop via `spawn_background`
/// (the workspace `Fn`-not-`AsyncFn` convention).
fn router_sink(router: &Arc<Router>) -> OnMavlinkMessage {
    let router = Arc::clone(router);
    Arc::new(move |msg| {
        let router = Arc::clone(&router);
        spawn_background("mavlink-route", async move {
            router.route(msg).await;
        });
    })
}

/// Start the MAVLink UDP and/or TCP listeners if their binds are set.
///
/// Returns the spawned subsystem handles (UDP, then TCP) for the
/// shutdown set. An empty vec means MAVLink ingress is not configured.
///
/// # Errors
///
/// Returns an error if a bind address fails to parse, the signing-key
/// manifest is malformed, the v1 fallback is requested without a CN, or a
/// socket fails to bind.
pub(crate) async fn start_mavlink(
    cli: &Cli,
    router: &Arc<Router>,
) -> anyhow::Result<Vec<SubsystemHandle>> {
    if cli.mavlink.mavlink_bind.is_none() && cli.mavlink.mavlink_tcp_bind.is_none() {
        return Ok(Vec::new());
    }

    let runtime = build_runtime(cli)?;
    let dest = destination(cli);
    let mut handles = Vec::new();

    if let Some(bind) = cli.mavlink.mavlink_bind.as_ref() {
        let addr: SocketAddr = bind
            .parse()
            .with_context(|| format!("parsing --mavlink-bind `{bind}`"))?;
        let config = MavlinkListenerConfig {
            bind: addr,
            destination: dest.clone(),
            require_signing: cli.mavlink.mavlink_require_signing,
            allow_v1: cli.mavlink.mavlink_allow_v1,
        };
        tracing::warn!(addr = %addr, "MAVLink UDP input enabled — datagrams are NOT encrypted");
        let handle = spawn_udp_listener(
            config,
            Arc::clone(&runtime.signing),
            Arc::clone(&runtime.links),
            router_sink(router),
        )
        .await
        .with_context(|| format!("binding MAVLink UDP listener on {addr}"))?;
        handles.push(handle);
    }

    if let Some(bind) = cli.mavlink.mavlink_tcp_bind.as_ref() {
        let addr: SocketAddr = bind
            .parse()
            .with_context(|| format!("parsing --mavlink-tcp-bind `{bind}`"))?;
        let config = MavlinkListenerConfig {
            bind: addr,
            destination: dest,
            require_signing: cli.mavlink.mavlink_require_signing,
            allow_v1: cli.mavlink.mavlink_allow_v1,
        };
        tracing::warn!(addr = %addr, "MAVLink TCP input enabled — connections are NOT encrypted");
        let handle = spawn_tcp_listener(
            config,
            Arc::clone(&runtime.signing),
            Arc::clone(&runtime.links),
            router_sink(router),
        )
        .await
        .with_context(|| format!("binding MAVLink TCP listener on {addr}"))?;
        handles.push(handle);
    }

    Ok(handles)
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, unused_results)]
mod tests {
    use super::*;

    #[test]
    fn parse_link_id_decimal_and_hex() {
        assert_eq!(parse_link_id("7").unwrap(), 7);
        assert_eq!(parse_link_id("0x42").unwrap(), 0x42);
        assert_eq!(parse_link_id("0X0A").unwrap(), 10);
        assert_eq!(parse_link_id(" 255 ").unwrap(), 255);
    }

    #[test]
    fn parse_link_id_rejects_out_of_range_and_garbage() {
        assert!(parse_link_id("256").is_err());
        assert!(parse_link_id("0x100").is_err());
        assert!(parse_link_id("nope").is_err());
        assert!(parse_link_id("").is_err());
    }

    #[test]
    fn decode_key_accepts_64_hex_and_wipes_input() {
        let mut hex = "ab".repeat(32); // 64 chars
        let key = decode_key(&mut hex, 1).unwrap();
        assert_eq!(key, [0xAB; 32]);
        assert!(
            hex.is_empty(),
            "hex input must be zeroized/cleared after decode"
        );
    }

    #[test]
    fn decode_key_rejects_wrong_length_and_non_hex() {
        let mut short = "ab".repeat(16);
        assert!(decode_key(&mut short, 1).is_err());
        let mut nonhex = "zz".repeat(32);
        assert!(decode_key(&mut nonhex, 1).is_err());
    }

    #[test]
    fn manifest_round_trips_through_toml() {
        let toml = r#"
            [links.0x01]
            cn = "drone-1"
            groups = ["tactical/uav"]
            signing-key-hex = "1111111111111111111111111111111111111111111111111111111111111111"

            [links.2]
            cn = "rover-2"
            signing-key-hex = "2222222222222222222222222222222222222222222222222222222222222222"
        "#;
        let manifest: LinkManifest = toml::from_str(toml).unwrap();
        assert_eq!(manifest.links.len(), 2);
        assert_eq!(manifest.links["0x01"].cn, "drone-1");
        assert_eq!(manifest.links["0x01"].groups, vec!["tactical/uav"]);
        assert!(manifest.links["2"].groups.is_empty());
    }

    #[test]
    fn manifest_rejects_unknown_fields() {
        let toml = r#"
            [links.1]
            cn = "x"
            signing-key-hex = "00"
            bogus = true
        "#;
        assert!(toml::from_str::<LinkManifest>(toml).is_err());
    }
}
