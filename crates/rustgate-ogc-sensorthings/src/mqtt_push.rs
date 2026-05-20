// Copyright © 2026 Roberto Chiofalo.

//! OGC SensorThings v1.0 §10 MQTT push subscriber.
//!
//! A SensorThings-compliant broker publishes one JSON document per
//! `Observation` on a topic of the form
//! `v1.0/Datastreams(<id>)/Observations`, where `<id>` is the
//! numeric `Datastream` id. The payload shape is identical to the
//! REST-polled `Observation` document, so the existing
//! [`crate::mapper::observation_to_entity`] mapper handles the
//! projection unchanged.
//!
//! # MVP scope
//!
//! - Broker URIs of the form `mqtt://host[:port][/path]` are
//!   accepted. `mqtts://` is rejected at startup with
//!   [`SensorThingsError::MqttsNotSupported`]; TLS for the push
//!   transport lands in a follow-up alongside the CA-pin / mTLS /
//!   SNI override knobs.
//! - Subscribes at QoS 1 (the SensorThings community default).
//! - No auth — SensorThings does not pin an auth scheme. Adding
//!   username/password is a future extension to
//!   [`crate::config::MqttPushConfig`].
//! - The list of subscribed topics is composed from
//!   [`crate::config::SensorThingsConfig::subscriptions`] — the
//!   same list the polling path uses. Operators who want push for
//!   a subset of datastreams can list only those in the
//!   subscription block.
//!
//! # Identity, source-protocol, dedup
//!
//! Every push-delivered `Observation` is wrapped in a
//! [`rustgate_core::message::RoutableMessage`] with the same
//! synthetic identity, `MessageType::Status`, and `source_protocol`
//! the polling path uses. The cross-path dedup cache
//! (`rustgate_router::dedup`) collapses duplicates when an
//! operator runs polling and push simultaneously against the same
//! datastream.
//!
//! # Backoff and reconnection
//!
//! `rumqttc` owns the reconnect loop. The subscriber task tails its
//! event stream; transient connection failures are logged at warn
//! and the underlying event loop retries with rumqttc's defaults.
//! On a clean shutdown the supervisor disconnects the client and
//! drops the event loop.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use rumqttc::{AsyncClient, Event, EventLoop, MqttOptions, Packet, QoS};
use rustgate_core::identity::Identity;
use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};
use rustgate_core::tasks::SubsystemHandle;
use rustgate_router::Router;
use tokio::sync::Notify;
use tracing::{debug, info, warn};

use crate::config::{SensorThingsConfig, Subscription};
use crate::error::SensorThingsError;
use crate::mapper::observation_to_entity;
use crate::types::Observation;
use crate::wiring::{OGC_SENSORTHINGS_SERVICE_CN, SOURCE_OGC_SENSORTHINGS};

/// Bound on the rumqttc channel between the network event loop and
/// the application-side polling. 64 mirrors the rumqttc example
/// for a server-side subscriber — high enough that a burst of
/// observations does not back-pressure the network task, low
/// enough that a stuck consumer is visible quickly.
const RUMQTTC_CHANNEL_CAPACITY: usize = 64;

/// Spawn the MQTT push subscriber as a managed subsystem.
///
/// Mirrors the shape of [`crate::wiring::spawn_polling_task`]:
/// returns a [`SubsystemHandle`] whose
/// [`rustgate_core::tasks::stop_subsystem`] drains the event loop
/// and disconnects the client cleanly.
///
/// # Errors
///
/// Returns [`SensorThingsError::MqttsNotSupported`] when the
/// configured `broker_uri` uses the `mqtts://` scheme. Returns
/// [`SensorThingsError::Config`] for every other URI parse
/// failure. Callers should propagate; there is no useful retry
/// for either case without operator action.
pub fn spawn_mqtt_push_task(
    config: SensorThingsConfig,
    router: Arc<Router>,
) -> Result<SubsystemHandle, SensorThingsError> {
    let mqtt = config
        .mqtt_push
        .as_ref()
        .ok_or_else(|| SensorThingsError::Config {
            message: "spawn_mqtt_push_task called without [sensorthings.mqtt-push] config".into(),
        })?
        .clone();

    let (host, port) = parse_broker_uri(&mqtt.broker_uri)?;

    let mut opts = MqttOptions::new(&mqtt.client_id, host, port);
    let _ = opts.set_keep_alive(Duration::from_secs(u64::from(mqtt.keepalive_secs)));

    let (client, event_loop) = AsyncClient::new(opts, RUMQTTC_CHANNEL_CAPACITY);

    let topics: Vec<String> = config
        .subscriptions
        .iter()
        .map(observation_topic_for)
        .collect();

    let shutdown = Arc::new(Notify::new());
    let shutdown_task = Arc::clone(&shutdown);
    let task = tokio::spawn(async move {
        run_subscriber(client, event_loop, topics, router, shutdown_task).await;
    });
    Ok(SubsystemHandle::new(shutdown, task))
}

/// Compose the SensorThings MQTT topic for a single subscription.
///
/// SensorThings v1.0 §10.1 mandates
/// `v1.0/Datastreams(<id>)/Observations`. The version prefix is
/// fixed; bumping to a future `v1.1`-only broker is operator-facing
/// configuration that lands alongside the future SensorThings v1.1
/// support.
pub fn observation_topic_for(sub: &Subscription) -> String {
    format!("v1.0/Datastreams({})/Observations", sub.datastream_id)
}

/// Parse the configured broker URI.
///
/// Accepts `mqtt://host[:port][/path]`. Returns
/// [`SensorThingsError::MqttsNotSupported`] for `mqtts://` and
/// [`SensorThingsError::Config`] for every other malformed URI.
///
/// The path component, query string, and fragment are ignored —
/// SensorThings topics are absolute strings supplied at SUBSCRIBE
/// time, not URI components.
pub fn parse_broker_uri(uri: &str) -> Result<(String, u16), SensorThingsError> {
    let trimmed = uri.trim();
    if trimmed.is_empty() {
        return Err(SensorThingsError::Config {
            message: "mqtt-push broker-uri must be a non-empty URI".into(),
        });
    }
    if let Some(rest) = trimmed.strip_prefix("mqtts://") {
        // Tail bytes that follow `mqtts://` are intentionally
        // ignored; the variant carries the discriminating signal
        // and the diagnostic does not need to leak the rest of the
        // URI (which may contain user-supplied tokens).
        let _ = rest;
        return Err(SensorThingsError::MqttsNotSupported);
    }
    let body = trimmed
        .strip_prefix("mqtt://")
        .ok_or_else(|| SensorThingsError::Config {
            message: format!(
                "mqtt-push broker-uri must start with `mqtt://`, got `{}`",
                trimmed,
            ),
        })?;
    // Drop everything from the first `/` onwards — the path
    // component is not meaningful at the MQTT layer.
    let authority = body.split('/').next().unwrap_or("");
    if authority.is_empty() {
        return Err(SensorThingsError::Config {
            message: "mqtt-push broker-uri must include a host".into(),
        });
    }
    // Split host:port. IPv6 literals must be bracketed
    // (`mqtt://[::1]:1883`); reject unbracketed colons in IPv6
    // territory to keep the parser tractable.
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (h, tail) = rest
            .split_once(']')
            .ok_or_else(|| SensorThingsError::Config {
                message: "mqtt-push broker-uri IPv6 host must be bracketed `[host]:port`".into(),
            })?;
        if h.is_empty() {
            return Err(SensorThingsError::Config {
                message: "mqtt-push broker-uri bracketed host is empty".into(),
            });
        }
        let port = if let Some(p) = tail.strip_prefix(':') {
            parse_port(p)?
        } else if tail.is_empty() {
            1883
        } else {
            return Err(SensorThingsError::Config {
                message: format!(
                    "mqtt-push broker-uri has unexpected trailer after bracketed host: `{}`",
                    tail,
                ),
            });
        };
        (h.to_string(), port)
    } else {
        // Multiple colons in an unbracketed authority is ambiguous
        // between an IPv6 literal (which MUST be bracketed) and a
        // host:port mistake. Reject so the operator surfaces the
        // bracketed form rather than silently picking a wrong
        // host/port split.
        if authority.matches(':').count() > 1 {
            return Err(SensorThingsError::Config {
                message: format!(
                    "mqtt-push broker-uri host `{}` contains multiple `:` — IPv6 literals must be bracketed (`mqtt://[host]:port`)",
                    authority,
                ),
            });
        }
        match authority.rsplit_once(':') {
            Some((h, p)) => {
                if h.is_empty() {
                    return Err(SensorThingsError::Config {
                        message: "mqtt-push broker-uri must include a non-empty host".into(),
                    });
                }
                (h.to_string(), parse_port(p)?)
            }
            None => (authority.to_string(), 1883),
        }
    };
    Ok((host, port))
}

fn parse_port(s: &str) -> Result<u16, SensorThingsError> {
    s.parse::<u16>().map_err(|_| SensorThingsError::Config {
        message: format!("mqtt-push broker-uri port `{}` is not a valid u16", s),
    })
}

/// Extract the numeric `<id>` from a SensorThings MQTT observation
/// topic of the form `v1.0/Datastreams(<id>)/Observations`.
///
/// Returns `None` for any topic that does not match the SensorThings
/// shape exactly — the subscriber logs and drops in that case
/// rather than feeding ambiguous payloads to the mapper. The MVP
/// accepts only the `v1.0/` prefix; supporting a future `v1.1/`
/// prefix is a one-line allow-list change.
pub fn datastream_id_from_topic(topic: &str) -> Option<u64> {
    let rest = topic.strip_prefix("v1.0/Datastreams(")?;
    let (id_str, tail) = rest.split_once(')')?;
    if tail != "/Observations" {
        return None;
    }
    id_str.parse::<u64>().ok()
}

/// Drive the subscriber: subscribe to every configured topic, then
/// loop on the rumqttc event stream until shutdown is requested.
async fn run_subscriber(
    client: AsyncClient,
    mut event_loop: EventLoop,
    topics: Vec<String>,
    router: Arc<Router>,
    shutdown: Arc<Notify>,
) {
    // Subscribe to every configured topic before the event loop
    // starts pumping. rumqttc queues the SUBSCRIBE packets and
    // flushes them once the CONNACK arrives, so the order is
    // deterministic — every topic is bound before the first
    // PUBLISH would reach the subscriber.
    for topic in &topics {
        if let Err(err) = client.subscribe(topic, QoS::AtLeastOnce).await {
            warn!(
                target: "rustgate.ogc-sensorthings",
                topic = %topic,
                error = %err,
                "SensorThings MQTT subscribe failed; subscriber will retry on reconnect"
            );
        }
    }
    info!(
        target: "rustgate.ogc-sensorthings",
        topic_count = topics.len(),
        "OGC SensorThings MQTT push subscriber started"
    );

    loop {
        tokio::select! {
            biased;
            () = shutdown.notified() => {
                info!(
                    target: "rustgate.ogc-sensorthings",
                    "OGC SensorThings MQTT push subscriber stopping"
                );
                // Disconnect cleanly. The event loop will exit on
                // the next poll once the disconnect lands.
                let _ = client.disconnect().await;
                break;
            }
            event = event_loop.poll() => {
                match event {
                    Ok(Event::Incoming(Packet::Publish(publish))) => {
                        handle_publish(&publish.topic, publish.payload.as_ref(), &router).await;
                    }
                    Ok(Event::Incoming(Packet::ConnAck(_))) => {
                        debug!(
                            target: "rustgate.ogc-sensorthings",
                            "MQTT CONNACK received"
                        );
                    }
                    Ok(_) => {
                        // Other events (PingResp, PubAck, …) are
                        // operationally uninteresting at this
                        // level; rumqttc handles their accounting.
                    }
                    Err(err) => {
                        warn!(
                            target: "rustgate.ogc-sensorthings",
                            error = %err,
                            "MQTT event loop returned an error; rumqttc will retry"
                        );
                        // Avoid a tight reconnect loop in case the
                        // upstream is wedged. rumqttc itself does
                        // not back off; the sleep here mirrors the
                        // polling task's fixed-interval retry.
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }
            }
        }
    }
}

/// Decode one inbound PUBLISH frame and route the resulting
/// observation through the same path the polling task uses.
async fn handle_publish(topic: &str, payload: &[u8], router: &Arc<Router>) {
    let Some(datastream_id) = datastream_id_from_topic(topic) else {
        debug!(
            target: "rustgate.ogc-sensorthings",
            topic = %topic,
            "MQTT message on unrecognised topic shape — dropping"
        );
        return;
    };
    let observation: Observation = match serde_json::from_slice(payload) {
        Ok(o) => o,
        Err(err) => {
            warn!(
                target: "rustgate.ogc-sensorthings",
                topic = %topic,
                datastream_id = datastream_id,
                error = %err,
                "MQTT payload did not decode as a SensorThings Observation; dropping"
            );
            return;
        }
    };
    let entity = observation_to_entity(&observation, rustgate_core::entity::EntityKind::Sensor);
    let payload = serde_json::to_vec(&entity).unwrap_or_default();
    let source = match Identity::plaintext(OGC_SENSORTHINGS_SERVICE_CN.to_string(), BTreeSet::new())
    {
        Ok(id) => id,
        Err(err) => {
            warn!(
                target: "rustgate.ogc-sensorthings",
                topic = %topic,
                datastream_id = datastream_id,
                error = %err,
                "MQTT push dropped: synthetic identity could not be constructed"
            );
            return;
        }
    };
    let msg = RoutableMessage {
        source,
        destination: Destination::Broadcast,
        payload: Bytes::from(payload),
        metadata: Metadata::new(
            SystemTime::now(),
            SOURCE_OGC_SENSORTHINGS.to_string(),
            MessageType::Status,
        ),
    };
    router.route(msg).await;
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::config::{EntityKindTag, MqttPushConfig};

    fn sub(id: u64) -> Subscription {
        Subscription {
            datastream_id: id,
            entity_kind: EntityKindTag::Sensor,
            group: None,
            poll_interval_secs: None,
            page_size: None,
        }
    }

    #[test]
    fn observation_topic_for_uses_spec_shape() {
        assert_eq!(
            observation_topic_for(&sub(42)),
            "v1.0/Datastreams(42)/Observations"
        );
    }

    #[test]
    fn datastream_id_from_topic_parses_spec_shape() {
        assert_eq!(
            datastream_id_from_topic("v1.0/Datastreams(7)/Observations"),
            Some(7)
        );
    }

    #[test]
    fn datastream_id_from_topic_rejects_unknown_version() {
        assert_eq!(
            datastream_id_from_topic("v1.1/Datastreams(7)/Observations"),
            None
        );
    }

    #[test]
    fn datastream_id_from_topic_rejects_trailing_segments() {
        assert_eq!(
            datastream_id_from_topic("v1.0/Datastreams(7)/Observations/extra"),
            None
        );
    }

    #[test]
    fn datastream_id_from_topic_rejects_non_numeric_id() {
        assert_eq!(
            datastream_id_from_topic("v1.0/Datastreams(seven)/Observations"),
            None
        );
    }

    #[test]
    fn datastream_id_from_topic_rejects_unrelated_topic() {
        assert_eq!(datastream_id_from_topic("hello/world"), None);
        assert_eq!(datastream_id_from_topic(""), None);
        assert_eq!(datastream_id_from_topic("v1.0/Things(7)/Datastreams"), None);
    }

    #[test]
    fn parse_broker_uri_accepts_default_port() {
        let (host, port) = parse_broker_uri("mqtt://broker.example.com").unwrap();
        assert_eq!(host, "broker.example.com");
        assert_eq!(port, 1883);
    }

    #[test]
    fn parse_broker_uri_accepts_explicit_port() {
        let (host, port) = parse_broker_uri("mqtt://broker.example.com:8883").unwrap();
        assert_eq!(host, "broker.example.com");
        assert_eq!(port, 8883);
    }

    #[test]
    fn parse_broker_uri_strips_path() {
        let (host, port) = parse_broker_uri("mqtt://broker.example.com:1883/anything").unwrap();
        assert_eq!(host, "broker.example.com");
        assert_eq!(port, 1883);
    }

    #[test]
    fn parse_broker_uri_accepts_bracketed_ipv6() {
        let (host, port) = parse_broker_uri("mqtt://[::1]:1883").unwrap();
        assert_eq!(host, "::1");
        assert_eq!(port, 1883);
    }

    #[test]
    fn parse_broker_uri_accepts_bracketed_ipv6_default_port() {
        let (host, port) = parse_broker_uri("mqtt://[fe80::1]").unwrap();
        assert_eq!(host, "fe80::1");
        assert_eq!(port, 1883);
    }

    #[test]
    fn parse_broker_uri_rejects_mqtts() {
        let err = parse_broker_uri("mqtts://broker.example.com").unwrap_err();
        assert!(matches!(err, SensorThingsError::MqttsNotSupported));
        assert!(!err.is_transient());
    }

    #[test]
    fn parse_broker_uri_rejects_other_schemes() {
        for bad in &[
            "tcp://broker:1883",
            "broker.example.com:1883",
            "ws://broker:8080",
            "https://broker:8883",
        ] {
            let err = parse_broker_uri(bad).unwrap_err();
            assert!(matches!(err, SensorThingsError::Config { .. }), "{}", bad);
        }
    }

    #[test]
    fn parse_broker_uri_rejects_empty() {
        assert!(matches!(
            parse_broker_uri("   ").unwrap_err(),
            SensorThingsError::Config { .. }
        ));
        assert!(matches!(
            parse_broker_uri("").unwrap_err(),
            SensorThingsError::Config { .. }
        ));
    }

    #[test]
    fn parse_broker_uri_rejects_missing_host() {
        assert!(matches!(
            parse_broker_uri("mqtt://").unwrap_err(),
            SensorThingsError::Config { .. }
        ));
        assert!(matches!(
            parse_broker_uri("mqtt://:1883").unwrap_err(),
            SensorThingsError::Config { .. }
        ));
    }

    #[test]
    fn parse_broker_uri_rejects_bad_port() {
        assert!(matches!(
            parse_broker_uri("mqtt://broker:nope").unwrap_err(),
            SensorThingsError::Config { .. }
        ));
        assert!(matches!(
            parse_broker_uri("mqtt://broker:99999").unwrap_err(),
            SensorThingsError::Config { .. }
        ));
    }

    #[test]
    fn parse_broker_uri_rejects_unbracketed_ipv6() {
        // Multiple colons in an unbracketed authority would be
        // ambiguous between "ipv6 fe80::1 on default port" and
        // "host fe80:: on port 1". Reject so the operator surfaces
        // the bracketed form.
        let err = parse_broker_uri("mqtt://fe80::1:1883").unwrap_err();
        assert!(matches!(err, SensorThingsError::Config { .. }));
    }

    #[test]
    fn mqtt_push_config_round_trips_via_toml() {
        let toml_src = r#"
            broker-uri = "mqtt://broker.example.com:1883"
            client-id = "rustgate-edge-7"
            keepalive-secs = 30
        "#;
        let cfg: MqttPushConfig = toml::from_str(toml_src).expect("parses");
        assert_eq!(cfg.broker_uri, "mqtt://broker.example.com:1883");
        assert_eq!(cfg.client_id, "rustgate-edge-7");
        assert_eq!(cfg.keepalive_secs, 30);
    }

    #[test]
    fn mqtt_push_config_defaults_keepalive() {
        let toml_src = r#"
            broker-uri = "mqtt://broker"
            client-id = "x"
        "#;
        let cfg: MqttPushConfig = toml::from_str(toml_src).expect("parses");
        assert_eq!(
            cfg.keepalive_secs,
            super::super::config::DEFAULT_MQTT_KEEPALIVE_SECS
        );
    }

    #[test]
    fn mqtt_push_config_rejects_unknown_field() {
        let toml_src = r#"
            broker-uri = "mqtt://broker"
            client-id = "x"
            keepalive_secs = 30
        "#;
        let _ = toml::from_str::<MqttPushConfig>(toml_src).expect_err("unknown field rejected");
    }
}
