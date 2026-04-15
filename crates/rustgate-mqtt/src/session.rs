// Copyright © 2026 Roberto Chiofalo.

//! Per-connection MQTT session state machine.
//!
//! Handles the CONNECT handshake, PUBLISH/SUBSCRIBE/PINGREQ/DISCONNECT
//! packet processing, and read/write loops. Each session registers with
//! the [`Router`](rustgate_transport::Router) and receives routed messages
//! for delivery to the MQTT client.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::SystemTime;

use bytes::BytesMut;
use parking_lot::Mutex;
use rustgate_core::constants::WRITE_TIMEOUT;
use rustgate_core::identity::Identity;
use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};
use rustgate_transport::{
    NORMAL_CHANNEL_CAPACITY, PRIORITY_CHANNEL_CAPACITY, Router, SessionHandle,
};
use tokio::sync::{OwnedSemaphorePermit, mpsc};
use tracing::{debug, info, warn};

use crate::error::MqttError;
use crate::listener::MqttPreSession;
use crate::packet::{MqttPacket, PacketCodec, PacketReader, PacketWriter, ProtocolLevel};
use crate::topic;

/// Keep-alive multiplier per MQTT spec: the server MUST allow 1.5x the
/// client's requested keep-alive before considering the connection dead.
const KEEP_ALIVE_FACTOR: f64 = 1.5;

/// Minimum keep-alive in seconds. Clients requesting 0 (disabled) get
/// this value imposed to prevent idle connections from lingering.
const MIN_KEEP_ALIVE_SECS: u16 = 30;

/// Topic prefix for broadcast messages routed to MQTT subscribers.
const BROADCAST_TOPIC_SUFFIX: &str = "$broadcast";

/// Channel capacity for response packets flowing from read loop to write loop.
const RESPONSE_CHANNEL_CAPACITY: usize = 64;

/// Shared registry tracking which MQTT client IDs are in use and by which CN.
///
/// Prevents client ID collision attacks where two different mTLS identities
/// attempt to use the same MQTT client ID, which could cause session confusion
/// or denial of service (mirrors CVE patterns in Eclipse Mosquitto).
///
/// The registry is shared across all MQTT sessions via `Arc`.
#[derive(Debug, Default)]
pub(crate) struct ClientIdRegistry {
    /// Maps MQTT client_id → (CN, session_id).
    inner: Mutex<HashMap<String, (String, u64)>>,
}

impl ClientIdRegistry {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Attempt to claim a client ID for the given CN and session.
    ///
    /// - If the client_id is not in use, registers it and returns `Ok`.
    /// - If the client_id is already in use by the *same* CN, updates
    ///   the session_id (reconnect) and returns `Ok`.
    /// - If the client_id is in use by a *different* CN, returns `Err`.
    pub(crate) fn try_claim(
        &self,
        client_id: &str,
        cn: &str,
        session_id: u64,
    ) -> Result<(), MqttError> {
        // Empty client IDs are allowed by MQTT spec (server may assign one).
        // We skip tracking them since they cannot collide meaningfully.
        if client_id.is_empty() {
            return Ok(());
        }
        let mut map = self.inner.lock();
        if let Some((existing_cn, _)) = map.get(client_id)
            && existing_cn != cn
        {
            warn!(
                client_id = %client_id,
                existing_cn = %existing_cn,
                new_cn = %cn,
                "MQTT client ID collision: different identity attempted to reuse client ID"
            );
            return Err(MqttError::ClientIdInUse(client_id.to_string()));
        }
        let _ = map.insert(client_id.to_string(), (cn.to_string(), session_id));
        Ok(())
    }

    /// Release a client ID, but only if it is still owned by the given session.
    pub(crate) fn release(&self, client_id: &str, session_id: u64) {
        let mut map = self.inner.lock();
        if let Some((_, sid)) = map.get(client_id)
            && *sid == session_id
        {
            let _ = map.remove(client_id);
        }
    }
}

/// RAII guard that releases the client ID from the registry on drop.
struct ClientIdGuard {
    registry: Arc<ClientIdRegistry>,
    client_id: String,
    session_id: u64,
}

impl Drop for ClientIdGuard {
    fn drop(&mut self) {
        self.registry.release(&self.client_id, self.session_id);
    }
}

/// A serialized MQTT response packet ready to be written to the TLS stream.
/// Produced by the read loop, consumed by the write loop.
struct ResponsePacket {
    bytes: BytesMut,
}

/// Handle a single MQTT session from TLS handshake through disconnect.
///
/// Performs the CONNECT handshake, registers with the router, runs the
/// read/write loops concurrently, and unregisters on exit.
pub(crate) async fn handle_mqtt_session(
    pre: MqttPreSession,
    router: Arc<Router>,
    topic_prefix: Option<String>,
    max_packet_size: usize,
    client_id_registry: Arc<ClientIdRegistry>,
    _permit: OwnedSemaphorePermit,
) {
    let identity = pre.identity;
    let peer_addr = pre.peer_addr;
    let cn = identity.cn.clone();

    let mut codec = PacketCodec::new(pre.stream, max_packet_size);

    // --- CONNECT handshake ---
    let (keep_alive, client_id) = match connect_handshake(&mut codec, &identity).await {
        Ok(result) => result,
        Err(e) => {
            debug!(cn = %cn, peer = %peer_addr, error = %e, "CONNECT handshake failed");
            return;
        }
    };

    let protocol = codec.protocol.unwrap_or(ProtocolLevel::V50);

    // --- Split codec into read/write halves for concurrent loops ---
    let (mut reader, mut writer) = codec.into_split();

    // --- Channel setup and router registration ---
    let (priority_tx, mut priority_rx) =
        mpsc::channel::<rustgate_transport::RoutedMessage>(PRIORITY_CHANNEL_CAPACITY);
    let (normal_tx, mut normal_rx) =
        mpsc::channel::<rustgate_transport::RoutedMessage>(NORMAL_CHANNEL_CAPACITY);
    let handle = SessionHandle::new(Arc::clone(&identity), priority_tx, normal_tx);
    let session_id = handle.id;

    // --- Client ID collision check ---
    // Must happen after session_id is available but before router registration.
    if !client_id.is_empty()
        && let Err(e) = client_id_registry.try_claim(&client_id, &cn, session_id)
    {
        debug!(cn = %cn, peer = %peer_addr, error = %e, "client ID rejected");
        // MQTT 5.0: send DISCONNECT with reason before closing so the client
        // gets a meaningful error code instead of a bare TCP reset. MQTT 3.1.1
        // has no server-initiated DISCONNECT packet, so we can only drop.
        if protocol == ProtocolLevel::V50 {
            let disconnect = mqttbytes::v5::Disconnect {
                reason_code: mqttbytes::v5::DisconnectReasonCode::NotAuthorized,
                properties: None,
            };
            let _ = writer
                .write_v5(&mqttbytes::v5::Packet::Disconnect(disconnect))
                .await;
        }
        return;
    }
    // RAII guard ensures the client ID is released when the session ends.
    let _client_id_guard = if !client_id.is_empty() {
        Some(ClientIdGuard {
            registry: Arc::clone(&client_id_registry),
            client_id: client_id.clone(),
            session_id,
        })
    } else {
        None
    };

    info!(
        peer = %peer_addr,
        cn = %cn,
        groups = ?identity.groups,
        protocol = ?protocol,
        keep_alive = keep_alive,
        client_id = %client_id,
        "MQTT session started"
    );

    // Response channel: read loop produces serialized response packets,
    // write loop consumes and writes them to the TLS stream.
    let (resp_tx, mut resp_rx) = mpsc::channel::<ResponsePacket>(RESPONSE_CHANNEL_CAPACITY);

    // Drain offline queue BEFORE register so queued messages arrive first.
    // Filter through current ACL/authz policy to prevent stale permissions.
    let buffered = router.drain_offline_messages(&cn).await;
    let before = buffered.len();
    let buffered = router.filter_offline_messages(&identity, buffered);
    let filtered_count = before - buffered.len();
    if filtered_count > 0 {
        info!(
            cn = %cn,
            filtered = filtered_count,
            delivered = buffered.len(),
            "filtered offline messages on MQTT reconnect",
        );
    }
    if !router.register(handle.clone()).await {
        warn!(cn = %cn, "connection rejected: tenant quota exceeded");
        return;
    }
    for pending in buffered {
        let (msg, audit) = pending.into_parts();
        if handle.send(Arc::new(msg)).await.is_err() {
            // Drop `audit` without emitting: the drain-path
            // classified_delivery record fires only on actual delivery.
            break;
        }
        audit.emit_on_delivered();
    }
    router.replay_positions(&handle).await;

    // --- Concurrent read/write loops ---
    let keep_alive_duration = std::time::Duration::from_secs_f64(
        f64::from(keep_alive.max(MIN_KEEP_ALIVE_SECS)) * KEEP_ALIVE_FACTOR,
    );

    let prefix = topic_prefix.as_deref().unwrap_or("");

    let mut read_params = ReadLoopParams {
        reader: &mut reader,
        resp_tx: &resp_tx,
        protocol,
        identity: &identity,
        router: &router,
        session_id,
        topic_prefix: topic_prefix.as_deref(),
        keep_alive: keep_alive_duration,
    };

    let read_result = tokio::select! {
        r = mqtt_read_loop(&mut read_params) => r,
        r = mqtt_write_loop(
            &mut writer,
            protocol,
            prefix,
            &mut priority_rx,
            &mut normal_rx,
            &mut resp_rx,
        ) => r,
    };

    // Flush pending outbound messages before unregistering.
    if read_result.is_ok() {
        flush_pending(
            &mut writer,
            protocol,
            prefix,
            &mut resp_rx,
            &mut priority_rx,
            &mut normal_rx,
        )
        .await;
    }

    if let Err(ref e) = read_result {
        debug!(cn = %cn, error = %e, "MQTT session ended with error");
    }

    router.unregister(&cn, session_id).await;
    info!(cn = %cn, peer = %peer_addr, "MQTT session ended");
}

/// Perform the MQTT CONNECT handshake.
///
/// Reads the first packet (must be CONNECT), validates constraints
/// (clean session, no will, QoS ≤ 1), and sends CONNACK. Returns the
/// negotiated keep-alive value in seconds.
async fn connect_handshake(
    codec: &mut PacketCodec,
    identity: &Identity,
) -> Result<(u16, String), MqttError> {
    let packet = codec.read_packet().await?;

    match packet {
        MqttPacket::V4(mqttbytes::v4::Packet::Connect(connect)) => {
            if !connect.clean_session {
                codec
                    .write_connack_v4(mqttbytes::v4::ConnectReturnCode::RefusedProtocolVersion)
                    .await?;
                return Err(MqttError::PersistentSessionUnsupported);
            }
            if connect.last_will.is_some() {
                codec
                    .write_connack_v4(mqttbytes::v4::ConnectReturnCode::RefusedProtocolVersion)
                    .await?;
                return Err(MqttError::WillUnsupported);
            }

            let client_id = connect.client_id.clone();

            debug!(
                cn = %identity.cn,
                client_id = %client_id,
                keep_alive = connect.keep_alive,
                "MQTT v3.1.1 CONNECT accepted"
            );

            codec
                .write_connack_v4(mqttbytes::v4::ConnectReturnCode::Success)
                .await?;
            Ok((connect.keep_alive, client_id))
        }
        MqttPacket::V5(boxed) => {
            if let mqttbytes::v5::Packet::Connect(connect) = *boxed {
                if !connect.clean_session {
                    codec
                        .write_connack_v5(
                            mqttbytes::v5::ConnectReturnCode::ImplementationSpecificError,
                        )
                        .await?;
                    return Err(MqttError::PersistentSessionUnsupported);
                }
                if connect.last_will.is_some() {
                    codec
                        .write_connack_v5(
                            mqttbytes::v5::ConnectReturnCode::ImplementationSpecificError,
                        )
                        .await?;
                    return Err(MqttError::WillUnsupported);
                }

                let client_id = connect.client_id.clone();

                debug!(
                    cn = %identity.cn,
                    client_id = %client_id,
                    keep_alive = connect.keep_alive,
                    "MQTT v5.0 CONNECT accepted"
                );

                codec
                    .write_connack_v5(mqttbytes::v5::ConnectReturnCode::Success)
                    .await?;
                Ok((connect.keep_alive, client_id))
            } else {
                Err(MqttError::ConnectExpected)
            }
        }
        _ => Err(MqttError::ConnectExpected),
    }
}

// ---------------------------------------------------------------------------
// Response packet serialization helpers
// ---------------------------------------------------------------------------

/// Serialize a v4 response packet into a `ResponsePacket`.
fn serialize_v4(packet: &mqttbytes::v4::Packet) -> Result<ResponsePacket, MqttError> {
    let mut bytes = BytesMut::with_capacity(128);
    crate::packet::write_v4_to_buf(packet, &mut bytes)?;
    Ok(ResponsePacket { bytes })
}

/// Serialize a v5 response packet into a `ResponsePacket`.
fn serialize_v5(packet: &mqttbytes::v5::Packet) -> Result<ResponsePacket, MqttError> {
    let mut bytes = BytesMut::with_capacity(128);
    crate::packet::write_v5_to_buf(packet, &mut bytes)?;
    Ok(ResponsePacket { bytes })
}

/// Serialize a PINGRESP into a `ResponsePacket`.
fn serialize_pingresp(protocol: ProtocolLevel) -> Result<ResponsePacket, MqttError> {
    match protocol {
        ProtocolLevel::V311 => serialize_v4(&mqttbytes::v4::Packet::PingResp),
        ProtocolLevel::V50 => serialize_v5(&mqttbytes::v5::Packet::PingResp),
    }
}

/// Send a serialized response packet to the write loop.
async fn send_response(
    resp_tx: &mpsc::Sender<ResponsePacket>,
    pkt: ResponsePacket,
) -> Result<(), MqttError> {
    resp_tx.send(pkt).await.map_err(|_| {
        MqttError::Io(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "write loop closed",
        ))
    })
}

// ---------------------------------------------------------------------------
// Read loop
// ---------------------------------------------------------------------------

/// Parameters for the MQTT read loop, bundled to stay within Clippy's
/// argument-count limit.
struct ReadLoopParams<'a> {
    reader: &'a mut PacketReader,
    resp_tx: &'a mpsc::Sender<ResponsePacket>,
    protocol: ProtocolLevel,
    identity: &'a Arc<Identity>,
    router: &'a Router,
    session_id: u64,
    topic_prefix: Option<&'a str>,
    keep_alive: std::time::Duration,
}

/// Read loop: process inbound MQTT packets from the client.
///
/// Handles PUBLISH (route to group), SUBSCRIBE (validate and ACK),
/// UNSUBSCRIBE (ACK), PINGREQ (respond), and DISCONNECT (clean exit).
///
/// Response packets are serialized and sent to the write loop via `resp_tx`
/// so both loops can operate on independent halves of the TLS stream.
async fn mqtt_read_loop(params: &mut ReadLoopParams<'_>) -> Result<(), MqttError> {
    let reader = &mut *params.reader;
    let resp_tx = params.resp_tx;
    let protocol = params.protocol;
    let identity = params.identity;
    let router = params.router;
    let session_id = params.session_id;
    let topic_prefix = params.topic_prefix;
    let keep_alive = params.keep_alive;
    loop {
        let packet = match tokio::time::timeout(keep_alive, reader.read_packet()).await {
            Ok(Ok(pkt)) => pkt,
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                let secs = keep_alive.as_secs() as u16;
                return Err(MqttError::KeepAliveTimeout(secs));
            }
        };

        match packet {
            // --- v5 packets ---
            MqttPacket::V5(boxed) => match *boxed {
                mqttbytes::v5::Packet::Publish(publish) => {
                    handle_publish_v5(resp_tx, identity, router, topic_prefix, publish).await?;
                }
                mqttbytes::v5::Packet::Subscribe(sub) => {
                    handle_subscribe_v5(resp_tx, identity, router, session_id, topic_prefix, sub)
                        .await?;
                }
                mqttbytes::v5::Packet::Unsubscribe(unsub) => {
                    handle_unsubscribe_v5(
                        resp_tx,
                        identity,
                        router,
                        session_id,
                        topic_prefix,
                        unsub,
                    )
                    .await?;
                }
                mqttbytes::v5::Packet::PingReq => {
                    send_response(resp_tx, serialize_pingresp(protocol)?).await?;
                }
                mqttbytes::v5::Packet::Disconnect(_) => {
                    debug!(cn = %identity.cn, "MQTT v5 DISCONNECT received");
                    return Ok(());
                }
                other => {
                    debug!(cn = %identity.cn, packet = ?other, "ignoring unexpected v5 packet");
                }
            },
            // --- v4 packets ---
            MqttPacket::V4(v4_pkt) => match v4_pkt {
                mqttbytes::v4::Packet::Publish(publish) => {
                    handle_publish_v4(resp_tx, identity, router, topic_prefix, publish).await?;
                }
                mqttbytes::v4::Packet::Subscribe(sub) => {
                    handle_subscribe_v4(resp_tx, identity, router, session_id, topic_prefix, sub)
                        .await?;
                }
                mqttbytes::v4::Packet::Unsubscribe(unsub) => {
                    handle_unsubscribe_v4(
                        resp_tx,
                        identity,
                        router,
                        session_id,
                        topic_prefix,
                        unsub,
                    )
                    .await?;
                }
                mqttbytes::v4::Packet::PingReq => {
                    send_response(resp_tx, serialize_pingresp(protocol)?).await?;
                }
                mqttbytes::v4::Packet::Disconnect => {
                    debug!(cn = %identity.cn, "MQTT v4 DISCONNECT received");
                    return Ok(());
                }
                other => {
                    debug!(cn = %identity.cn, packet = ?other, "ignoring unexpected v4 packet");
                }
            },
        }
    }
}

// ---------------------------------------------------------------------------
// PUBLISH handlers
// ---------------------------------------------------------------------------

async fn handle_publish_v5(
    resp_tx: &mpsc::Sender<ResponsePacket>,
    identity: &Arc<Identity>,
    router: &Router,
    topic_prefix: Option<&str>,
    publish: mqttbytes::v5::Publish,
) -> Result<(), MqttError> {
    if publish.qos == mqttbytes::QoS::ExactlyOnce {
        return Err(MqttError::Qos2Unsupported);
    }

    topic::validate_publish_topic(&publish.topic)?;
    let group = topic::topic_to_group(&publish.topic, topic_prefix)?;

    // Authorization: the client must be a member of the target group.
    if !identity.is_member_of(&group) {
        return Err(MqttError::NotAuthorized(format!(
            "not authorized to publish to group '{group}'"
        )));
    }

    let msg = RoutableMessage {
        source: Identity::clone(identity),
        destination: Destination::Group(group.into_owned()),
        payload: publish.payload.clone(),
        metadata: Metadata {
            received_at: SystemTime::now(),
            source_protocol: "mqtt".into(),
            message_type: MessageType::Other("mqtt".into()),
            ttl: None,
        },
    };

    router.route(msg).await;

    // QoS 1: acknowledge receipt.
    if publish.qos == mqttbytes::QoS::AtLeastOnce && publish.pkid != 0 {
        let puback = mqttbytes::v5::PubAck {
            pkid: publish.pkid,
            reason: mqttbytes::v5::PubAckReason::Success,
            properties: None,
        };
        send_response(
            resp_tx,
            serialize_v5(&mqttbytes::v5::Packet::PubAck(puback))?,
        )
        .await?;
    }

    Ok(())
}

async fn handle_publish_v4(
    resp_tx: &mpsc::Sender<ResponsePacket>,
    identity: &Arc<Identity>,
    router: &Router,
    topic_prefix: Option<&str>,
    publish: mqttbytes::v4::Publish,
) -> Result<(), MqttError> {
    if publish.qos == mqttbytes::QoS::ExactlyOnce {
        return Err(MqttError::Qos2Unsupported);
    }

    topic::validate_publish_topic(&publish.topic)?;
    let group = topic::topic_to_group(&publish.topic, topic_prefix)?;

    // Authorization: the client must be a member of the target group.
    if !identity.is_member_of(&group) {
        return Err(MqttError::NotAuthorized(format!(
            "not authorized to publish to group '{group}'"
        )));
    }

    let msg = RoutableMessage {
        source: Identity::clone(identity),
        destination: Destination::Group(group.into_owned()),
        payload: publish.payload.clone(),
        metadata: Metadata {
            received_at: SystemTime::now(),
            source_protocol: "mqtt".into(),
            message_type: MessageType::Other("mqtt".into()),
            ttl: None,
        },
    };

    router.route(msg).await;

    // QoS 1: acknowledge receipt.
    if publish.qos == mqttbytes::QoS::AtLeastOnce && publish.pkid != 0 {
        let puback = mqttbytes::v4::PubAck::new(publish.pkid);
        send_response(
            resp_tx,
            serialize_v4(&mqttbytes::v4::Packet::PubAck(puback))?,
        )
        .await?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// SUBSCRIBE handlers
// ---------------------------------------------------------------------------

async fn handle_subscribe_v5(
    resp_tx: &mpsc::Sender<ResponsePacket>,
    identity: &Arc<Identity>,
    router: &Router,
    session_id: u64,
    topic_prefix: Option<&str>,
    sub: mqttbytes::v5::Subscribe,
) -> Result<(), MqttError> {
    let mut return_codes = Vec::with_capacity(sub.filters.len());

    for filter in &sub.filters {
        if filter.qos == mqttbytes::QoS::ExactlyOnce {
            return_codes.push(mqttbytes::v5::SubscribeReasonCode::ImplementationSpecific);
            continue;
        }

        let code =
            match try_join_group(identity, router, session_id, &filter.path, topic_prefix).await {
                Ok(()) => match filter.qos {
                    mqttbytes::QoS::AtMostOnce => mqttbytes::v5::SubscribeReasonCode::QoS0,
                    mqttbytes::QoS::AtLeastOnce => mqttbytes::v5::SubscribeReasonCode::QoS1,
                    mqttbytes::QoS::ExactlyOnce => unreachable!(),
                },
                Err(_) => mqttbytes::v5::SubscribeReasonCode::NotAuthorized,
            };
        return_codes.push(code);
    }

    let suback = mqttbytes::v5::SubAck::new(sub.pkid, return_codes);
    send_response(
        resp_tx,
        serialize_v5(&mqttbytes::v5::Packet::SubAck(suback))?,
    )
    .await?;

    Ok(())
}

async fn handle_subscribe_v4(
    resp_tx: &mpsc::Sender<ResponsePacket>,
    identity: &Arc<Identity>,
    router: &Router,
    session_id: u64,
    topic_prefix: Option<&str>,
    sub: mqttbytes::v4::Subscribe,
) -> Result<(), MqttError> {
    let mut return_codes = Vec::with_capacity(sub.filters.len());

    for filter in &sub.filters {
        if filter.qos == mqttbytes::QoS::ExactlyOnce {
            return_codes.push(mqttbytes::v4::SubscribeReasonCode::Failure);
            continue;
        }

        let code =
            match try_join_group(identity, router, session_id, &filter.path, topic_prefix).await {
                Ok(()) => mqttbytes::v4::SubscribeReasonCode::Success(filter.qos),
                Err(_) => mqttbytes::v4::SubscribeReasonCode::Failure,
            };
        return_codes.push(code);
    }

    let suback = mqttbytes::v4::SubAck::new(sub.pkid, return_codes);
    send_response(
        resp_tx,
        serialize_v4(&mqttbytes::v4::Packet::SubAck(suback))?,
    )
    .await?;

    Ok(())
}

/// Validate a subscription filter and dynamically join the mapped group.
async fn try_join_group(
    identity: &Identity,
    router: &Router,
    session_id: u64,
    filter: &str,
    topic_prefix: Option<&str>,
) -> Result<(), MqttError> {
    topic::validate_subscribe_filter(filter)?;
    let group = topic::topic_to_group(filter, topic_prefix)?;

    if !identity.is_member_of(&group) {
        return Err(MqttError::NotAuthorized(format!(
            "not a member of group '{group}'"
        )));
    }

    if !router.join_group(&identity.cn, session_id, &group).await {
        return Err(MqttError::NotAuthorized(format!(
            "failed to join group '{group}' (limit exceeded)"
        )));
    }

    debug!(cn = %identity.cn, group = %group, "MQTT subscribed to group");
    Ok(())
}

// ---------------------------------------------------------------------------
// UNSUBSCRIBE handlers
// ---------------------------------------------------------------------------

async fn handle_unsubscribe_v5(
    resp_tx: &mpsc::Sender<ResponsePacket>,
    identity: &Identity,
    router: &Router,
    session_id: u64,
    topic_prefix: Option<&str>,
    unsub: mqttbytes::v5::Unsubscribe,
) -> Result<(), MqttError> {
    let mut reasons = Vec::with_capacity(unsub.filters.len());

    for filter in &unsub.filters {
        let reason = match topic::topic_to_group(filter, topic_prefix) {
            Ok(group) => {
                let _ = router.leave_group(&identity.cn, session_id, &group).await;
                debug!(cn = %identity.cn, group = %group, "MQTT unsubscribed from group");
                mqttbytes::v5::UnsubAckReason::Success
            }
            Err(_) => mqttbytes::v5::UnsubAckReason::TopicFilterInvalid,
        };
        reasons.push(reason);
    }

    let unsuback = mqttbytes::v5::UnsubAck {
        pkid: unsub.pkid,
        reasons,
        properties: None,
    };
    send_response(
        resp_tx,
        serialize_v5(&mqttbytes::v5::Packet::UnsubAck(unsuback))?,
    )
    .await?;
    Ok(())
}

async fn handle_unsubscribe_v4(
    resp_tx: &mpsc::Sender<ResponsePacket>,
    identity: &Identity,
    router: &Router,
    session_id: u64,
    topic_prefix: Option<&str>,
    unsub: mqttbytes::v4::Unsubscribe,
) -> Result<(), MqttError> {
    for filter in &unsub.topics {
        if let Ok(group) = topic::topic_to_group(filter, topic_prefix) {
            let _ = router.leave_group(&identity.cn, session_id, &group).await;
            debug!(cn = %identity.cn, group = %group, "MQTT unsubscribed from group");
        }
    }

    let unsuback = mqttbytes::v4::UnsubAck { pkid: unsub.pkid };
    send_response(
        resp_tx,
        serialize_v4(&mqttbytes::v4::Packet::UnsubAck(unsuback))?,
    )
    .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Write loop
// ---------------------------------------------------------------------------

/// Write loop: deliver routed messages and response packets to the MQTT
/// client in real-time.
///
/// Prioritises: response packets (PUBACK, SUBACK, PINGRESP) first, then
/// priority routed messages, then normal routed messages. Each message is
/// written as an MQTT PUBLISH packet on the TLS stream. Terminates when
/// all channels close.
async fn mqtt_write_loop(
    writer: &mut PacketWriter,
    protocol: ProtocolLevel,
    prefix: &str,
    priority_rx: &mut mpsc::Receiver<rustgate_transport::RoutedMessage>,
    normal_rx: &mut mpsc::Receiver<rustgate_transport::RoutedMessage>,
    resp_rx: &mut mpsc::Receiver<ResponsePacket>,
) -> Result<(), MqttError> {
    let mut priority_open = true;
    let mut normal_open = true;
    let mut resp_open = true;

    loop {
        if !priority_open && !normal_open && !resp_open {
            return Ok(());
        }

        // Use biased select: response packets first (they are latency-sensitive
        // request/response), then priority routed messages, then normal.
        tokio::select! {
            biased;
            resp = resp_rx.recv(), if resp_open => match resp {
                Some(pkt) => {
                    writer.write_raw(&pkt.bytes).await?;
                }
                None => {
                    resp_open = false;
                }
            },
            msg = priority_rx.recv(), if priority_open => match msg {
                Some(m) => {
                    write_routed_message(writer, protocol, prefix, &m).await?;
                }
                None => {
                    priority_open = false;
                }
            },
            msg = normal_rx.recv(), if normal_open => match msg {
                Some(m) => {
                    write_routed_message(writer, protocol, prefix, &m).await?;
                }
                None => {
                    normal_open = false;
                }
            },
        }
    }
}

/// Write a single routed message as an MQTT PUBLISH to the client.
async fn write_routed_message(
    writer: &mut PacketWriter,
    protocol: ProtocolLevel,
    prefix: &str,
    msg: &RoutableMessage,
) -> Result<(), MqttError> {
    let topic = msg_to_topic(msg, prefix);

    let result = match protocol {
        ProtocolLevel::V311 => {
            let publish = mqttbytes::v4::Publish::from_bytes(
                topic,
                mqttbytes::QoS::AtMostOnce,
                msg.payload.clone(),
            );
            tokio::time::timeout(
                WRITE_TIMEOUT,
                writer.write_v4(&mqttbytes::v4::Packet::Publish(publish)),
            )
            .await
        }
        ProtocolLevel::V50 => {
            let publish = mqttbytes::v5::Publish::from_bytes(
                topic,
                mqttbytes::QoS::AtMostOnce,
                msg.payload.clone(),
            );
            tokio::time::timeout(
                WRITE_TIMEOUT,
                writer.write_v5(&mqttbytes::v5::Packet::Publish(publish)),
            )
            .await
        }
    };

    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => {
            debug!(error = %e, "MQTT write error");
            Err(e)
        }
        Err(_) => {
            debug!("MQTT write timeout");
            Err(MqttError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "write timeout",
            )))
        }
    }
}

/// Flush any pending response and routed messages to the client before
/// disconnecting. Best-effort with bounded draining.
async fn flush_pending(
    writer: &mut PacketWriter,
    protocol: ProtocolLevel,
    prefix: &str,
    resp_rx: &mut mpsc::Receiver<ResponsePacket>,
    priority_rx: &mut mpsc::Receiver<rustgate_transport::RoutedMessage>,
    normal_rx: &mut mpsc::Receiver<rustgate_transport::RoutedMessage>,
) {
    let mut flushed = 0u32;

    // Close all channels and drain whatever is buffered.
    resp_rx.close();
    priority_rx.close();
    normal_rx.close();

    // Drain pending response packets first (PUBACK, SUBACK, etc.)
    while let Ok(pkt) = resp_rx.try_recv() {
        if writer.write_raw(&pkt.bytes).await.is_err() {
            return;
        }
        flushed += 1;
    }

    // Drain routed messages (priority first, then normal).
    loop {
        let msg = match priority_rx.try_recv() {
            Ok(m) => m,
            Err(_) => match normal_rx.try_recv() {
                Ok(m) => m,
                Err(_) => break,
            },
        };

        if write_routed_message(writer, protocol, prefix, &msg)
            .await
            .is_ok()
        {
            flushed += 1;
        } else {
            break;
        }
    }

    if flushed > 0 {
        debug!(flushed, "flushed pending messages before disconnect");
    }
}

/// Derive an MQTT topic name from a routed message's destination.
fn msg_to_topic(msg: &RoutableMessage, prefix: &str) -> String {
    match &msg.destination {
        Destination::Group(group) => {
            if prefix.is_empty() {
                group.to_string()
            } else {
                format!("{prefix}{group}")
            }
        }
        Destination::Direct(target) => format!("{prefix}direct/{}", target.cn),
        Destination::Broadcast | Destination::Multicast(_) => {
            if prefix.is_empty() {
                BROADCAST_TOPIC_SUFFIX.to_owned()
            } else {
                format!("{prefix}{BROADCAST_TOPIC_SUFFIX}")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn client_id_claim_same_cn_allowed() {
        let reg = ClientIdRegistry::new();
        reg.try_claim("sensor-1", "device-a", 1).unwrap();
        // Same CN reconnecting with the same client_id is fine.
        reg.try_claim("sensor-1", "device-a", 2).unwrap();
    }

    #[test]
    fn client_id_claim_different_cn_rejected() {
        let reg = ClientIdRegistry::new();
        reg.try_claim("sensor-1", "device-a", 1).unwrap();
        let err = reg.try_claim("sensor-1", "device-b", 2).unwrap_err();
        assert!(
            matches!(err, MqttError::ClientIdInUse(_)),
            "expected ClientIdInUse, got: {err}"
        );
    }

    #[test]
    fn client_id_release_allows_reuse() {
        let reg = ClientIdRegistry::new();
        reg.try_claim("sensor-1", "device-a", 1).unwrap();
        reg.release("sensor-1", 1);
        // After release, a different CN can claim the same client_id.
        reg.try_claim("sensor-1", "device-b", 2).unwrap();
    }

    #[test]
    fn client_id_release_wrong_session_no_op() {
        let reg = ClientIdRegistry::new();
        reg.try_claim("sensor-1", "device-a", 1).unwrap();
        // Release with wrong session_id should be a no-op.
        reg.release("sensor-1", 999);
        // Original claim should still hold — different CN rejected.
        assert!(reg.try_claim("sensor-1", "device-b", 2).is_err());
    }

    #[test]
    fn client_id_guard_releases_on_drop() {
        let reg = ClientIdRegistry::new();
        reg.try_claim("sensor-1", "device-a", 1).unwrap();
        {
            let _guard = ClientIdGuard {
                registry: Arc::clone(&reg),
                client_id: "sensor-1".to_string(),
                session_id: 1,
            };
            // While guard is alive, different CN is rejected.
            assert!(reg.try_claim("sensor-1", "device-b", 2).is_err());
        }
        // After guard drops, the client_id is released.
        reg.try_claim("sensor-1", "device-b", 2).unwrap();
    }

    #[test]
    fn empty_client_id_not_tracked() {
        // Empty client IDs are allowed by MQTT spec (server-assigned).
        // We skip registry tracking for them.
        let reg = ClientIdRegistry::new();
        reg.try_claim("", "device-a", 1).unwrap();
        // Another session with empty client_id should also succeed.
        reg.try_claim("", "device-b", 2).unwrap();
    }

    #[test]
    fn client_id_concurrent_claim_contention() {
        let reg = ClientIdRegistry::new();
        let barrier = std::sync::Barrier::new(10);

        let results: Vec<_> = std::thread::scope(|s| {
            (0..10u64)
                .map(|i| {
                    let reg = &reg;
                    let barrier = &barrier;
                    s.spawn(move || {
                        let _ = barrier.wait();
                        reg.try_claim("contested-id", &format!("cn-{i}"), i)
                    })
                })
                .collect::<Vec<_>>()
                .into_iter()
                .map(|h| h.join().unwrap())
                .collect()
        });

        let successes = results.iter().filter(|r| r.is_ok()).count();
        let failures = results.iter().filter(|r| r.is_err()).count();
        assert_eq!(successes, 1, "exactly one CN should claim the client ID");
        assert_eq!(failures, 9, "all others should be rejected");
    }
}
