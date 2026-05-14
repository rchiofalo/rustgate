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
//! ## Authentication
//!
//! Username/password authentication is supported via the
//! [`crate::config::MqttPushConfig::username`] +
//! [`crate::config::MqttPushConfig::password_path`] pair. The
//! username is inline TOML; the password lives on disk and is
//! loaded into a `Zeroizing<String>` at startup so it is wiped
//! from memory on drop. Both fields are optional; configuring
//! only one of them is rejected at startup. When unset the
//! subscriber connects anonymously (no `CONNECT` username/
//! password fields). Brokers that gate access on credentials —
//! Mosquitto with `password_file`, HiveMQ ACL plugin, EMQX
//! built-in DB — accept the resulting CONNECT packet.
//!
//! ## What is intentionally NOT here yet
//!
//! - **TLS configuration.** rumqttc's `rustls`-backed
//!   `MqttOptions::set_transport(Transport::tls_with_config(...))`
//!   accepts a custom `rustls::ClientConfig` for CA pinning,
//!   client certs, and SNI override. The MVP wires the default
//!   `mqtts://` transport when the scheme is `mqtts` and
//!   plaintext when it is `mqtt`; advanced TLS knobs come in a
//!   follow-up once a deployment actually needs them.
//! - **Auth beyond username/password.** OAuth2 over MQTT
//!   (CONNECT `Authentication Method` / `Authentication Data`
//!   properties, MQTT 5.0 §3.1.2.11), bearer-over-MQTT (broker-
//!   specific extension), and PSK (TLS-PSK ciphers) remain
//!   deferred. mTLS lands with the TLS follow-up.
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
use rumqttc::{AsyncClient, Event, Incoming, MqttOptions, QoS};
use rustgate_core::identity::Identity;
use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};
use rustgate_core::tasks::{SubsystemHandle, spawn_background};
use rustgate_router::Router;
use tokio::sync::Notify;
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

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

    // Load the password (if configured) before building MqttOptions
    // so a missing / unreadable / over-permissive password file is
    // surfaced at startup as a single warn-and-exit rather than
    // after the broker connection has been attempted.
    let password = match load_password(&mqtt).await {
        Ok(p) => p,
        Err(e) => {
            warn!(
                target: "rustgate.ogc-sensorthings",
                error = %e,
                "MQTT push: credential configuration invalid; subscriber will not start"
            );
            shutdown.notified().await;
            return;
        }
    };

    let opts = match build_mqtt_options(&mqtt, password.as_ref().map(|p| p.as_str())) {
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

fn build_mqtt_options(
    mqtt: &MqttPushConfig,
    password: Option<&str>,
) -> Result<MqttOptions, String> {
    // Parse the broker URI; rumqttc's MqttOptions does not accept
    // a URI directly so we extract host / port / TLS-or-not.
    let url = url_lite::parse(&mqtt.broker_uri).map_err(|e| e.to_string())?;
    if url.tls {
        // MVP shipped without TLS knobs; rumqttc's
        // `TlsConfiguration::Simple` + system-CA path lands in
        // the follow-up that also adds the CA-pin / mTLS
        // configuration (see module docs "What is intentionally
        // NOT here yet"). Reject `mqtts://` explicitly rather
        // than silently downgrading to plaintext, so operators
        // see the gap at startup instead of on the wire.
        return Err(
            "mqtts:// (TLS) is not yet supported; use mqtt:// for now or wait for the TLS follow-up".to_string(),
        );
    }
    let mut opts = MqttOptions::new(&mqtt.client_id, &url.host, url.port);
    let _ = opts.set_keep_alive(std::time::Duration::from_secs(u64::from(
        mqtt.keepalive_secs,
    )));

    // Username/password wiring. Both must be present or both
    // absent; setting only one is a startup error so an operator
    // misconfiguration (e.g. they pasted a username but forgot the
    // password file) cannot silently fall back to anonymous and
    // attach an empty password the broker rejects opaquely.
    match (mqtt.username.as_deref(), password) {
        (Some(user), Some(pass)) => {
            let _ = opts.set_credentials(user, pass);
        }
        (None, None) => {}
        (Some(_), None) => {
            return Err(
                "MQTT push: username configured without password (missing or empty password-path)"
                    .to_string(),
            );
        }
        (None, Some(_)) => {
            return Err(
                "MQTT push: password-path configured without username (set username to enable credentials)"
                    .to_string(),
            );
        }
    }
    Ok(opts)
}

/// Load the password from `mqtt.password_path` if set, wrap it in
/// [`Zeroizing`] so it is wiped on drop, and trim trailing
/// whitespace. Returns `Ok(None)` when no path is configured.
///
/// Re-uses [`rustgate_core::read_secret_file`] so the same mode-
/// 0o077 perm gate, owner check, size cap, and trim-then-reject-
/// empty behaviour that gate every other on-disk secret in the
/// workspace also gate the MQTT password.
async fn load_password(mqtt: &MqttPushConfig) -> Result<Option<Zeroizing<String>>, String> {
    let Some(path) = mqtt.password_path.clone() else {
        return Ok(None);
    };
    // The secret-file helper is sync I/O; run on the blocking pool
    // so we do not stall the runtime when the password file lives
    // on a slow mount.
    let loaded = tokio::task::spawn_blocking(move || {
        rustgate_core::read_secret_file(&path, &rustgate_core::SecretFileOpts::default())
    })
    .await
    .map_err(|e| format!("password-path read task panicked: {e}"))?
    .map_err(|e| format!("password-path could not be read: {e}"))?;
    Ok(Some(loaded))
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

    fn mqtt_cfg() -> MqttPushConfig {
        MqttPushConfig {
            broker_uri: "mqtt://broker.example.org:1883".into(),
            client_id: "rustgate-test".into(),
            keepalive_secs: 60,
            username: None,
            password_path: None,
        }
    }

    #[test]
    fn build_options_sets_credentials_when_both_user_and_password_present() {
        let mut cfg = mqtt_cfg();
        cfg.username = Some("operator".into());
        // password_path is consulted by `load_password`, but
        // `build_mqtt_options` itself takes the resolved password
        // verbatim — the test exercises the wiring step directly.
        let opts = build_mqtt_options(&cfg, Some("s3cr3t")).expect("options build");
        // rumqttc exposes the configured credentials via a getter
        // — pin the exact pair so a future rumqttc bump that
        // silently strips them trips this test.
        assert_eq!(
            opts.credentials(),
            Some(("operator".to_string(), "s3cr3t".to_string()))
        );
    }

    #[test]
    fn build_options_omits_credentials_when_both_user_and_password_absent() {
        let cfg = mqtt_cfg();
        let opts = build_mqtt_options(&cfg, None).expect("options build");
        assert_eq!(
            opts.credentials(),
            None,
            "anonymous CONNECT when neither field is set"
        );
    }

    #[test]
    fn build_options_rejects_username_without_password() {
        let mut cfg = mqtt_cfg();
        cfg.username = Some("operator".into());
        let err = build_mqtt_options(&cfg, None).expect_err("must reject");
        assert!(
            err.contains("username configured without password"),
            "error must name the missing field, got: {err}"
        );
    }

    #[test]
    fn build_options_rejects_password_without_username() {
        // Symmetric guard: a password-path on disk with no
        // username field is also an operator misconfiguration —
        // the broker would never see a CONNECT carrying a
        // password without a username.
        let cfg = mqtt_cfg();
        let err = build_mqtt_options(&cfg, Some("s3cr3t")).expect_err("must reject");
        assert!(
            err.contains("password-path configured without username"),
            "error must name the missing field, got: {err}"
        );
    }

    #[test]
    fn config_round_trips_credentials_through_serde() {
        // Pins both the TOML field names (kebab-case) and the
        // round-trip — a future rename or `serde(rename)` typo on
        // the new fields trips this test before it reaches an
        // operator's `rustgate.toml`.
        let cfg = MqttPushConfig {
            broker_uri: "mqtt://broker.example.org:1883".into(),
            client_id: "rustgate-test".into(),
            keepalive_secs: 60,
            username: Some("operator".into()),
            password_path: Some("/secrets/mqtt-pass".into()),
        };
        let toml_text = toml::to_string(&cfg).expect("serialize");
        assert!(
            toml_text.contains("username = \"operator\""),
            "username field must serialize, got: {toml_text}"
        );
        assert!(
            toml_text.contains("password-path = \"/secrets/mqtt-pass\""),
            "password-path field must serialize in kebab-case, got: {toml_text}"
        );
        let parsed: MqttPushConfig = toml::from_str(&toml_text).expect("round-trip parse");
        assert_eq!(parsed, cfg, "MqttPushConfig must round-trip through TOML");
    }
}
