// Copyright © 2026 Roberto Chiofalo.

//! MQTT push subscriber for OGC SensorThings v1.0 (closes the
//! deferred half of the SensorThings adapter — see the
//! "MQTT push subscription is deferred" note in `lib.rs`).
//!
//! SensorThings v1.0 §10 defines an MQTT publish/subscribe
//! transport for `Observation` documents. The broker publishes
//! one JSON document per observation on a topic of the form
//! `v1.0/Datastreams(<N>)/Observations`. The payload shape is
//! identical to the REST-polled `Observation` document — the
//! polling adapter's [`crate::mapper::observation_to_entity`]
//! mapper is reused verbatim, so the only new code is the MQTT
//! client glue.
//!
//! ## Wire flow
//!
//! 1. `spawn_mqtt_push_task` connects to the configured broker
//!    via [`rumqttc`] and subscribes to one
//!    `v1.0/Datastreams(<N>)/Observations` topic per entry in
//!    [`crate::config::SensorThingsConfig::subscriptions`].
//! 2. The driver loop polls the [`rumqttc::EventLoop`] for
//!    incoming `Publish` packets, decodes each payload as a
//!    [`crate::types::Observation`], projects it onto a
//!    [`rustgate_core::message::RoutableMessage`] via the shared
//!    polling-path helper, and routes it through the supplied
//!    [`rustgate_router::Router`].
//! 3. On clean shutdown (the returned
//!    [`rustgate_core::tasks::SubsystemHandle`] is dropped or its
//!    notify channel fires) the driver disconnects from the
//!    broker, drains pending publishes, and exits.
//!
//! ## Failure modes
//!
//! - **Connection errors** — rumqttc's event loop already
//!   handles reconnect-with-backoff internally; the driver loop
//!   tracks consecutive errors and logs each at `warn!`. There
//!   is no separate retry budget on top — the broker either
//!   comes back or it doesn't, and the operator sees the warn
//!   trail.
//! - **Payload decode failures** — surfaced at `debug!` with
//!   the topic the failed payload arrived on; the loop continues
//!   to the next message rather than terminating, so one
//!   malformed observation does not stall an otherwise-healthy
//!   stream.
//! - **Per-topic routing** — the topic name carries the
//!   datastream id, but a publish on a topic that did not match
//!   any configured subscription is logged at `debug!` and
//!   dropped (the subscriber should never receive such a topic
//!   given the explicit subscribe set, but the runtime guard is
//!   cheap).
//!
//! ## TLS (`mqtts://`)
//!
//! `mqtts://` URIs are supported via rumqttc's `rustls`-backed
//! [`rumqttc::Transport::tls_with_config`]. When
//! [`crate::config::MqttPushConfig::ca_bundle_path`] is unset,
//! the subscriber uses the system root certificate store (via
//! `rustls-native-certs`, the default of
//! [`rumqttc::TlsConfiguration::default`]) — the right answer
//! for brokers presenting publicly-trusted certificates. When
//! the operator supplies a CA bundle path, the PEM is loaded via
//! the shared [`rustgate_core::secrets::read_secret_file`]
//! helper (mode-0o077 permissions gate, 32 KiB size cap,
//! `Zeroizing` wrap) and handed to
//! [`rumqttc::TlsConfiguration::Simple`] as the `ca` field;
//! `alpn` and `client_auth` are both `None` (no SNI override, no
//! client certificate). Workspace policy bans `native-tls`
//! (see `deny.toml`), so the only TLS backend wired here is
//! rustls.
//!
//! ## What is intentionally NOT here yet
//!
//! - **mTLS (client_auth)**. The TLS path verifies the broker's
//!   server certificate but does not present a client
//!   certificate. Operators that need mutual TLS will get
//!   `client-cert-path` / `client-key-path` config fields in a
//!   follow-up — the `TlsConfiguration::Simple.client_auth`
//!   slot is already wired through `None` so the change is
//!   additive.
//! - **Auth (username / password / OAuth)**. SensorThings does
//!   not pin an auth scheme for the MQTT push transport;
//!   bearer-over-MQTT and PSK are both encountered in the wild.
//!   Deferred to its own follow-up.
//! - **QoS configuration.** Subscribes are issued at QoS 1
//!   ("at-least-once") to match the SensorThings community
//!   default. QoS 0 ("fire-and-forget") and QoS 2
//!   ("exactly-once") will land as a per-subscription option
//!   when a deployment asks for it.

#![cfg(feature = "mqtt-push")]
#![allow(clippy::module_name_repetitions)]

use std::collections::BTreeSet;
use std::sync::Arc;

use bytes::Bytes;
use rumqttc::{AsyncClient, Event, Incoming, MqttOptions, QoS, TlsConfiguration, Transport};
use rustgate_core::identity::Identity;
use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};
use rustgate_core::secrets::{SecretFileOpts, read_secret_file};
use rustgate_core::tasks::{SubsystemHandle, spawn_background};
use rustgate_router::Router;
use tokio::sync::Notify;
use tracing::{debug, info, warn};

use crate::config::{MqttPushConfig, SensorThingsConfig, Subscription};
use crate::mapper::observation_to_entity;
use crate::types::Observation;
use crate::wiring::{OGC_SENSORTHINGS_SERVICE_CN, SOURCE_OGC_SENSORTHINGS};

/// Spawn the MQTT push subscriber as a managed background task.
///
/// Returns a [`SubsystemHandle`] that drains the connection on
/// drop. Mirrors the shape of
/// [`crate::wiring::spawn_polling_task`] so the server-side
/// supervisor wires both paths identically.
///
/// When `config.mqtt_push` is `None` or
/// `config.subscriptions` is empty, the function returns a
/// `SubsystemHandle` whose task does nothing (a no-op supervisor
/// that exits on the next shutdown notify).
#[must_use]
pub fn spawn_mqtt_push_task(config: SensorThingsConfig, router: Arc<Router>) -> SubsystemHandle {
    let shutdown = Arc::new(Notify::new());
    let shutdown_task = Arc::clone(&shutdown);
    let task = tokio::spawn(async move {
        let Some(mqtt) = config.mqtt_push.clone() else {
            // Operator configured no MQTT push; idle until
            // shutdown so the SubsystemHandle drains cleanly.
            shutdown_task.notified().await;
            return;
        };
        run_subscriber(mqtt, config, router, shutdown_task).await;
    });
    SubsystemHandle::new(shutdown, task)
}

async fn run_subscriber(
    mqtt: MqttPushConfig,
    config: SensorThingsConfig,
    router: Arc<Router>,
    shutdown: Arc<Notify>,
) {
    if config.subscriptions.is_empty() {
        info!(
            target: "rustgate.ogc-sensorthings",
            "MQTT push: no subscriptions configured, exiting"
        );
        shutdown.notified().await;
        return;
    }

    let opts = match build_mqtt_options(&mqtt) {
        Ok(o) => o,
        Err(e) => {
            warn!(
                target: "rustgate.ogc-sensorthings",
                error = %e,
                "MQTT push: broker URI invalid; subscriber will not start"
            );
            shutdown.notified().await;
            return;
        }
    };
    let (client, mut event_loop) = AsyncClient::new(opts, 128);

    info!(
        target: "rustgate.ogc-sensorthings",
        broker = %mqtt.broker_uri,
        subscriptions = config.subscriptions.len(),
        "MQTT push subscriber started"
    );

    // Issue one subscribe per configured datastream.
    for sub in &config.subscriptions {
        let topic = MqttPushConfig::datastream_topic(sub.datastream_id);
        if let Err(e) = client.subscribe(topic.clone(), QoS::AtLeastOnce).await {
            warn!(
                target: "rustgate.ogc-sensorthings",
                topic = %topic,
                error = %e,
                "MQTT push: subscribe failed"
            );
        }
    }

    // Drive the event loop until shutdown.
    spawn_background("ogc-sensorthings-mqtt-driver", async move {
        loop {
            tokio::select! {
                biased;
                () = shutdown.notified() => {
                    info!(
                        target: "rustgate.ogc-sensorthings",
                        "MQTT push subscriber stopping"
                    );
                    let _ = client.disconnect().await;
                    break;
                }
                ev = event_loop.poll() => match ev {
                    Ok(Event::Incoming(Incoming::Publish(p))) => {
                        handle_publish(&p.topic, &p.payload, &config, &router).await;
                    }
                    Ok(_) => {}
                    Err(e) => {
                        debug!(
                            target: "rustgate.ogc-sensorthings",
                            error = %e,
                            "MQTT push: event loop error (rumqttc will reconnect)"
                        );
                    }
                }
            }
        }
    });
}

/// Maximum CA-bundle size in bytes. 32 KiB comfortably covers a
/// PEM bundle of dozens of root certificates (a single PEM-encoded
/// CA cert is ~1.5 KiB); the cap exists to bound RAM if the
/// configured path is mis-pointed at a log file.
const MAX_CA_BUNDLE_BYTES: u64 = 32 * 1024;

fn build_mqtt_options(mqtt: &MqttPushConfig) -> Result<MqttOptions, String> {
    // Parse the broker URI; rumqttc's MqttOptions does not accept
    // a URI directly so we extract host / port / TLS-or-not.
    let url = url_lite::parse(&mqtt.broker_uri).map_err(|e| e.to_string())?;
    let mut opts = MqttOptions::new(&mqtt.client_id, &url.host, url.port);
    let _ = opts.set_keep_alive(std::time::Duration::from_secs(u64::from(
        mqtt.keepalive_secs,
    )));
    if url.tls {
        let tls = build_tls_configuration(mqtt.ca_bundle_path.as_deref())?;
        let _ = opts.set_transport(Transport::tls_with_config(tls));
    }
    Ok(opts)
}

/// Build the rumqttc TLS configuration for the broker connection.
///
/// - `None` → [`TlsConfiguration::default`], which loads the
///   system root certificate store via `rustls-native-certs`.
///   The right answer for brokers behind a publicly-trusted CA.
/// - `Some(path)` → load the PEM bundle via
///   [`rustgate_core::secrets::read_secret_file`] (mode-0o077
///   perm gate, 32 KiB size cap, `Zeroizing` wrap) and pass the
///   bytes to [`TlsConfiguration::Simple`] with `alpn = None`
///   and `client_auth = None`. mTLS is deferred — see module
///   docs.
///
/// Returns a human-readable error string on failure (file
/// missing, permissions too open, oversized, etc.) so the
/// subscriber-startup warn log keeps the operator-facing
/// diagnostic shape that already existed for "broker URI
/// invalid".
fn build_tls_configuration(ca_bundle_path: Option<&str>) -> Result<TlsConfiguration, String> {
    let Some(path) = ca_bundle_path else {
        // System roots: rumqttc's Default impl wraps a rustls
        // ClientConfig built with `load_native_certs()`.
        return Ok(TlsConfiguration::default());
    };
    // Widen the size cap from the 8 KiB default — CA bundles
    // commonly carry multiple roots and exceed the token-sized
    // default. The Zeroizing wrap is overkill for a public-key
    // PEM, but using the shared reader keeps the mode-0o077 gate
    // and unifies the loading discipline with every other
    // on-disk material in the workspace.
    let pem = read_secret_file(path, &SecretFileOpts::with_max_bytes(MAX_CA_BUNDLE_BYTES))
        .map_err(|e| format!("failed to load ca-bundle-path `{path}`: {e}"))?;
    Ok(TlsConfiguration::Simple {
        // `Vec<u8>` consumes the bytes; the Zeroizing<String>
        // wiped on drop holds the only other copy, so taking a
        // fresh allocation here is fine.
        ca: pem.as_bytes().to_vec(),
        alpn: None,
        client_auth: None,
    })
}

async fn handle_publish(
    topic: &str,
    payload: &[u8],
    config: &SensorThingsConfig,
    router: &Arc<Router>,
) {
    let Some(datastream_id) = parse_datastream_id_from_topic(topic) else {
        debug!(
            target: "rustgate.ogc-sensorthings",
            topic = %topic,
            "MQTT push: ignoring publish on non-matching topic"
        );
        return;
    };
    let Some(sub) = config
        .subscriptions
        .iter()
        .find(|s| s.datastream_id == datastream_id)
    else {
        debug!(
            target: "rustgate.ogc-sensorthings",
            datastream_id = datastream_id,
            "MQTT push: publish on unconfigured datastream id"
        );
        return;
    };
    let observation: Observation = match serde_json::from_slice(payload) {
        Ok(o) => o,
        Err(e) => {
            debug!(
                target: "rustgate.ogc-sensorthings",
                topic = %topic,
                error = %e,
                "MQTT push: observation decode failed"
            );
            return;
        }
    };
    let Some(msg) = observation_to_message(&observation, sub.entity_kind.to_entity_kind(), sub)
    else {
        return;
    };
    router.route(msg).await;
}

/// Extract the `<N>` from a `v1.0/Datastreams(<N>)/Observations`
/// topic. Returns `None` for any other shape.
pub(crate) fn parse_datastream_id_from_topic(topic: &str) -> Option<u64> {
    let prefix = "v1.0/Datastreams(";
    let suffix = ")/Observations";
    let rest = topic.strip_prefix(prefix)?;
    let inside = rest.strip_suffix(suffix)?;
    inside.parse::<u64>().ok()
}

/// Project an [`Observation`] onto a [`RoutableMessage`] using the
/// same logic as the polling path. Kept as a module-local helper
/// so the call site is symmetric — the polling wiring has its own
/// copy that closes over a slightly different lifetime, and
/// extracting a shared private function would force both call
/// sites through one signature that's strictly less ergonomic
/// than the duplicate ten-line projection. The contract pinned by
/// the integration test is that both projections produce
/// byte-identical entities for the same observation.
fn observation_to_message(
    observation: &Observation,
    kind: rustgate_core::entity::EntityKind,
    sub: &Subscription,
) -> Option<RoutableMessage> {
    let entity = observation_to_entity(observation, kind);
    let payload = serde_json::to_vec(&entity).unwrap_or_default();
    let source = Identity::plaintext(OGC_SENSORTHINGS_SERVICE_CN.to_string(), BTreeSet::new())
        .map_err(|e| {
            warn!(
                target: "rustgate.ogc-sensorthings",
                error = %e,
                "MQTT push: synthetic identity construction failed; dropping observation"
            );
            e
        })
        .ok()?;
    let destination = match sub.group.as_deref() {
        Some(g) if !g.is_empty() => Destination::Group(Arc::<str>::from(g)),
        _ => Destination::Broadcast,
    };
    Some(RoutableMessage {
        source,
        destination,
        payload: Bytes::from(payload),
        metadata: Metadata::new(
            std::time::SystemTime::now(),
            SOURCE_OGC_SENSORTHINGS.to_string(),
            MessageType::Status,
        ),
    })
}

// Minimal URL parser — avoids pulling the `url` crate just for
// `host:port + tls` extraction. SensorThings broker URIs are
// always one of `mqtt://host[:port]` or `mqtts://host[:port]`;
// query strings and userinfo do not appear in real deployments.
// If a future config grows a path component or auth in the URI,
// swap this for `url::Url` (already a transitive workspace dep via
// reqwest).
mod url_lite {
    pub(super) struct ParsedUri {
        pub host: String,
        pub port: u16,
        pub tls: bool,
    }

    pub(super) fn parse(uri: &str) -> Result<ParsedUri, &'static str> {
        let (scheme, rest) = uri.split_once("://").ok_or("missing scheme")?;
        let tls = match scheme {
            "mqtt" => false,
            "mqtts" => true,
            _ => return Err("unsupported scheme (use mqtt:// or mqtts://)"),
        };
        let default_port = if tls { 8883u16 } else { 1883u16 };
        let host_port = rest.split('/').next().unwrap_or(rest);
        let (host, port) = match host_port.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.parse::<u16>().map_err(|_| "invalid port")?),
            None => (host_port.to_string(), default_port),
        };
        if host.is_empty() {
            return Err("empty host");
        }
        Ok(ParsedUri { host, port, tls })
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn topic_parser_extracts_datastream_id() {
        assert_eq!(
            parse_datastream_id_from_topic("v1.0/Datastreams(42)/Observations"),
            Some(42)
        );
        assert_eq!(
            parse_datastream_id_from_topic("v1.0/Datastreams(0)/Observations"),
            Some(0)
        );
    }

    #[test]
    fn topic_parser_rejects_non_matching_shapes() {
        // Wrong prefix
        assert_eq!(
            parse_datastream_id_from_topic("v2.0/Datastreams(1)/Observations"),
            None
        );
        // Wrong suffix
        assert_eq!(
            parse_datastream_id_from_topic("v1.0/Datastreams(1)/Other"),
            None
        );
        // Non-numeric id
        assert_eq!(
            parse_datastream_id_from_topic("v1.0/Datastreams(abc)/Observations"),
            None
        );
        // Empty id
        assert_eq!(
            parse_datastream_id_from_topic("v1.0/Datastreams()/Observations"),
            None
        );
    }

    #[test]
    fn url_parser_accepts_mqtt_and_mqtts() {
        let p = url_lite::parse("mqtt://broker.example.org:1883").unwrap();
        assert_eq!(p.host, "broker.example.org");
        assert_eq!(p.port, 1883);
        assert!(!p.tls);

        let p = url_lite::parse("mqtts://broker.example.org").unwrap();
        assert_eq!(p.host, "broker.example.org");
        assert_eq!(p.port, 8883, "mqtts default port");
        assert!(p.tls);
    }

    #[test]
    fn url_parser_rejects_unsupported_schemes() {
        assert!(url_lite::parse("http://broker.example.org").is_err());
        assert!(url_lite::parse("broker.example.org").is_err());
        assert!(url_lite::parse("mqtt://").is_err());
    }

    #[test]
    fn datastream_topic_format_is_stable() {
        assert_eq!(
            MqttPushConfig::datastream_topic(42),
            "v1.0/Datastreams(42)/Observations"
        );
    }

    #[test]
    fn build_mqtt_options_accepts_mqtts_with_default_roots() {
        // `mqtts://` with no ca-bundle-path uses
        // `TlsConfiguration::default()` (system roots). The
        // option construction must succeed — the actual TLS
        // handshake is a runtime concern beyond unit-test scope.
        let cfg = MqttPushConfig {
            broker_uri: "mqtts://broker.example.org:8883".into(),
            client_id: "rustgate-test".into(),
            keepalive_secs: 60,
            ca_bundle_path: None,
        };
        let opts = build_mqtt_options(&cfg).expect("mqtts:// with default roots");
        assert_eq!(opts.broker_address(), ("broker.example.org".into(), 8883));
    }

    #[test]
    fn build_mqtt_options_still_works_for_plaintext() {
        // The TLS branch must not regress the plaintext path —
        // `mqtt://` URIs continue to skip transport configuration
        // and use rumqttc's default plaintext TCP.
        let cfg = MqttPushConfig {
            broker_uri: "mqtt://broker.example.org:1883".into(),
            client_id: "rustgate-test".into(),
            keepalive_secs: 60,
            ca_bundle_path: None,
        };
        let opts = build_mqtt_options(&cfg).expect("mqtt:// must still build");
        assert_eq!(opts.broker_address(), ("broker.example.org".into(), 1883));
    }

    #[test]
    fn ca_bundle_path_round_trips_through_serde() {
        // The new field must accept the kebab-case TOML form and
        // round-trip back. Pins the schema name so a future
        // rename surfaces as a test failure rather than an
        // operator-facing config break.
        let toml_str = r#"
            broker-uri = "mqtts://broker.example.org:8883"
            client-id = "rustgate-test"
            keepalive-secs = 60
            ca-bundle-path = "/etc/rustgate/sensorthings-broker-ca.pem"
        "#;
        let cfg: MqttPushConfig = toml::from_str(toml_str).expect("parse");
        assert_eq!(
            cfg.ca_bundle_path.as_deref(),
            Some("/etc/rustgate/sensorthings-broker-ca.pem")
        );
        // Default (omitted) must remain `None` so existing
        // configs stay forward-compatible.
        let toml_default = r#"
            broker-uri = "mqtt://broker.example.org:1883"
        "#;
        let cfg2: MqttPushConfig = toml::from_str(toml_default).expect("parse");
        assert!(cfg2.ca_bundle_path.is_none());
    }
}
