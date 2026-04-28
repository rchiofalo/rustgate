# rustgate-mqtt

MQTT 5.0 / 3.1.1 transport adapter with mandatory mTLS.

## Role in the workspace

`rustgate-mqtt` accepts MQTT connections over mTLS, translates MQTT
PUBLISH and SUBSCRIBE operations into router actions, and delivers routed
messages back to subscribed sessions as MQTT PUBLISH packets. It depends on
[rustgate-core](../rustgate-core/README.md),
[rustgate-resilience](../rustgate-resilience/README.md) (per-IP connection
limiter), and [rustgate-transport](../rustgate-transport/README.md) (TLS
config, identity extraction, router). Wired into
[rustgate-server](../rustgate-server/README.md) under `--features mqtt`.

## Public API surface

- `MqttListener` — TLS-fronted MQTT accept loop with per-IP rate limiting
- `MqttServer` — manages the accept loop and per-session state machine,
  including the retained-message store and session-takeover semantics
- `MqttServerConfig`, `MqttSessionHooks`, `MqttForwardingHooks` —
  configuration and lifecycle hooks
- `OnMqttAccept`, `OnMqttReject`, `OnMqttPublish`, `OnMqttPublishReject`,
  `OnMqttSubscribe`, `OnMqttSubscribeReject`, `OnMqttRetainStored`,
  `OnMqttRetainReplayed`, `OnMqttRetainCleared`, `OnMqttWillPublished` —
  observation callbacks the server binary wires to Prometheus + audit
- `topic::*` — topic / filter validation and group mapping:
  `topic_to_group`, `validate_publish_topic`, `validate_subscribe_filter`,
  `validate_topic_prefix`, `filter_has_wildcards`, `filter_matches`,
  `WildcardPolicy`
- `MqttError` — typed error enum for codec, auth, and session failures
- `TRANSPORT_LABEL` (`"mqtt"`) — canonical value of the `transport` field
  in structured-log events emitted by this crate

## Feature flags

_None._

## Topology / deployment notes

Identity is derived exclusively from the X.509 client certificate;
MQTT-level USERNAME / PASSWORD fields are not honoured. MQTT topics map to
rustgate groups (1:1 by default, with optional prefix stripping); the
router's authz PEP is consulted on every PUBLISH and SUBSCRIBE.
QoS 0 (at-most-once) and QoS 1 (at-least-once) are supported; QoS 2 is not
implemented. Both MQTT 5.0 (full user properties, reason codes, session
expiry) and 3.1.1 are accepted via protocol-level negotiation in CONNECT.

## Where to look first

- `crates/rustgate-mqtt/src/listener.rs` — TLS accept loop and
  per-connection bring-up
- `crates/rustgate-mqtt/src/session.rs` — per-session state machine,
  PUBLISH dispatch, and the retained-message store integration
