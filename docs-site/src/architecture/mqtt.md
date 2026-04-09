# MQTT Transport

The `rustgate-mqtt` crate provides an MQTT 5.0/3.1.1 transport adapter, gated behind the `mqtt` feature flag. It allows MQTT clients to participate in the same routing mesh as TLS, WebSocket, and plaintext TCP clients.

## Protocol Support

| Feature | Support |
|---|---|
| MQTT 5.0 | Full CONNECT/CONNACK negotiation |
| MQTT 3.1.1 | Backwards-compatible fallback |
| QoS 0 (at most once) | Supported |
| QoS 1 (at least once) | Supported (PUBACK) |
| QoS 2 (exactly once) | Rejected at SUBSCRIBE time |
| SUBSCRIBE / UNSUBSCRIBE | Dynamic group membership |
| PINGREQ / PINGRESP | Keep-alive |
| DISCONNECT | Clean session teardown |

## Topic-to-Group Mapping

MQTT topic names map bidirectionally to rustgate routing groups. An optional prefix (`--mqtt-topic-prefix`) is stripped on inbound and prepended on outbound, so MQTT clients see a topic namespace while the router operates on flat group names.

For example, with `--mqtt-topic-prefix tak/`:
- MQTT topic `tak/TeamAlpha` maps to router group `TeamAlpha`
- Router group `TeamAlpha` publishes to MQTT topic `tak/TeamAlpha`

## Authentication and Authorization

MQTT sessions authenticate via mTLS — the client certificate's CN becomes the session identity, and OU fields determine group membership. Clients can only subscribe to groups listed in their certificate; attempts to subscribe to unauthorized groups are rejected.

## Configuration

| Flag | Env | Default |
|---|---|---|
| `--mqtt-bind` | `RUSTGATE_MQTT_BIND` | (disabled) |
| `--mqtt-topic-prefix` | `RUSTGATE_MQTT_TOPIC_PREFIX` | (none) |
| `--mqtt-max-packet-size` | `RUSTGATE_MQTT_MAX_PACKET_SIZE` | 16 MiB |

## Session Lifecycle

1. **TLS handshake** with mTLS client cert verification (same CA trust store as the main listener).
2. **CONNECT** packet parsed; protocol version negotiated (5.0 preferred, 3.1.1 fallback).
3. **CONNACK** returned with session present flag and negotiated settings.
4. **SUBSCRIBE** packets create dynamic group memberships via `Router::join_group`.
5. **PUBLISH** packets (inbound) are wrapped as `RoutableMessage` and routed through the standard router pipeline.
6. **Outbound** messages for subscribed groups are delivered as PUBLISH packets to the MQTT client.
7. **DISCONNECT** or connection drop triggers `Router::leave_group` for all subscriptions and session cleanup.

## Related

- [Transport & mTLS](./transport.md) for the core transport layer.
- [Wire Protocol](./protocol.md) for the message format.
- [TLS Certificates & mTLS](../security/mtls.md) for the certificate model.
