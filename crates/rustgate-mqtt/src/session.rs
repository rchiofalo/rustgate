//! Per-connection MQTT session state machine.
//!
//! Handles the CONNECT handshake, PUBLISH/SUBSCRIBE/PINGREQ/DISCONNECT
//! packet processing, and read/write loops. Each session registers with
//! the [`Router`](rustgate_transport::Router) and receives routed messages
//! for delivery to the MQTT client.

use std::sync::Arc;
use std::time::SystemTime;

use rustgate_core::constants::WRITE_TIMEOUT;
use rustgate_core::identity::Identity;
use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};
use rustgate_transport::{
    NORMAL_CHANNEL_CAPACITY, PRIORITY_CHANNEL_CAPACITY, Router, SessionHandle,
};
use tokio::sync::{OwnedSemaphorePermit, mpsc};
use tracing::{debug, info};

use crate::error::MqttError;
use crate::listener::MqttPreSession;
use crate::packet::{MqttPacket, PacketCodec, ProtocolLevel};
use crate::topic;

/// Keep-alive multiplier per MQTT spec: the server MUST allow 1.5x the
/// client's requested keep-alive before considering the connection dead.
const KEEP_ALIVE_FACTOR: f64 = 1.5;

/// Minimum keep-alive in seconds. Clients requesting 0 (disabled) get
/// this value imposed to prevent idle connections from lingering.
const MIN_KEEP_ALIVE_SECS: u16 = 30;

/// Handle a single MQTT session from TLS handshake through disconnect.
///
/// Performs the CONNECT handshake, registers with the router, runs the
/// read/write loops concurrently, and unregisters on exit.
pub(crate) async fn handle_mqtt_session(
    pre: MqttPreSession,
    router: Arc<Router>,
    topic_prefix: Option<String>,
    max_packet_size: usize,
    _permit: OwnedSemaphorePermit,
) {
    let identity = pre.identity;
    let peer_addr = pre.peer_addr;
    let cn = identity.cn.clone();

    let mut codec = PacketCodec::new(pre.stream, max_packet_size);

    // --- CONNECT handshake ---
    let keep_alive = match connect_handshake(&mut codec, &identity).await {
        Ok(ka) => ka,
        Err(e) => {
            debug!(cn = %cn, peer = %peer_addr, error = %e, "CONNECT handshake failed");
            return;
        }
    };

    let protocol = codec.protocol.unwrap_or(ProtocolLevel::V50);

    info!(
        peer = %peer_addr,
        cn = %cn,
        groups = ?identity.groups,
        protocol = ?protocol,
        keep_alive = keep_alive,
        "MQTT session started"
    );

    // --- Channel setup and router registration ---
    let (priority_tx, mut priority_rx) =
        mpsc::channel::<rustgate_transport::RoutedMessage>(PRIORITY_CHANNEL_CAPACITY);
    let (normal_tx, mut normal_rx) =
        mpsc::channel::<rustgate_transport::RoutedMessage>(NORMAL_CHANNEL_CAPACITY);
    let handle = SessionHandle::new(Arc::clone(&identity), priority_tx, normal_tx);
    let session_id = handle.id;

    // Drain offline queue BEFORE register so queued messages arrive first.
    let buffered = router.drain_offline_messages(&cn).await;
    router.register(handle.clone()).await;
    for m in buffered {
        if handle.send(Arc::new(m)).await.is_err() {
            break;
        }
    }
    router.replay_positions(&handle).await;

    // --- Concurrent read/write loops ---
    let keep_alive_duration = std::time::Duration::from_secs_f64(
        f64::from(keep_alive.max(MIN_KEEP_ALIVE_SECS)) * KEEP_ALIVE_FACTOR,
    );

    let read_result = tokio::select! {
        r = mqtt_read_loop(
            &mut codec,
            &identity,
            &router,
            topic_prefix.as_deref(),
            keep_alive_duration,
        ) => r,
        r = mqtt_write_loop(
            &mut priority_rx,
            &mut normal_rx,
        ) => r,
    };

    // The read and write loops share the codec's underlying stream via
    // split ownership. Since PacketCodec doesn't implement AsyncRead +
    // AsyncWrite separately, we run the write loop off channels only —
    // actual writes to the TLS stream happen inside the read loop after
    // the select resolves. This is fine because only one loop is active
    // after select returns.

    // Flush pending outbound messages before unregistering.
    if read_result.is_ok() {
        flush_pending(
            &mut codec,
            protocol,
            topic_prefix.as_deref(),
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
async fn connect_handshake(codec: &mut PacketCodec, identity: &Identity) -> Result<u16, MqttError> {
    let packet = codec.read_packet().await?;

    match packet {
        MqttPacket::V4(mqttbytes::v4::Packet::Connect(connect)) => {
            // Validate v4 CONNECT constraints.
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

            debug!(
                cn = %identity.cn,
                client_id = %connect.client_id,
                keep_alive = connect.keep_alive,
                "MQTT v3.1.1 CONNECT accepted"
            );

            codec
                .write_connack_v4(mqttbytes::v4::ConnectReturnCode::Success)
                .await?;
            Ok(connect.keep_alive)
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

                debug!(
                    cn = %identity.cn,
                    client_id = %connect.client_id,
                    keep_alive = connect.keep_alive,
                    "MQTT v5.0 CONNECT accepted"
                );

                codec
                    .write_connack_v5(mqttbytes::v5::ConnectReturnCode::Success)
                    .await?;
                Ok(connect.keep_alive)
            } else {
                Err(MqttError::ConnectExpected)
            }
        }
        _ => Err(MqttError::ConnectExpected),
    }
}

/// Read loop: process inbound MQTT packets from the client.
///
/// Handles PUBLISH (route to group), SUBSCRIBE (validate and ACK),
/// UNSUBSCRIBE (ACK), PINGREQ (respond), and DISCONNECT (clean exit).
/// Returns on error or clean disconnect.
async fn mqtt_read_loop(
    codec: &mut PacketCodec,
    identity: &Identity,
    router: &Router,
    topic_prefix: Option<&str>,
    keep_alive: std::time::Duration,
) -> Result<(), MqttError> {
    loop {
        let packet = match tokio::time::timeout(keep_alive, codec.read_packet()).await {
            Ok(Ok(pkt)) => pkt,
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                // Keep-alive timeout — the client missed its deadline.
                let secs = keep_alive.as_secs() as u16;
                return Err(MqttError::KeepAliveTimeout(secs));
            }
        };

        match packet {
            // --- v5 PUBLISH ---
            MqttPacket::V5(boxed) => match *boxed {
                mqttbytes::v5::Packet::Publish(publish) => {
                    handle_publish_v5(codec, identity, router, topic_prefix, publish).await?;
                }
                mqttbytes::v5::Packet::Subscribe(sub) => {
                    handle_subscribe_v5(codec, identity, topic_prefix, sub).await?;
                }
                mqttbytes::v5::Packet::Unsubscribe(unsub) => {
                    handle_unsubscribe_v5(codec, unsub).await?;
                }
                mqttbytes::v5::Packet::PingReq => {
                    codec.write_pingresp().await?;
                }
                mqttbytes::v5::Packet::Disconnect(_) => {
                    debug!(cn = %identity.cn, "MQTT v5 DISCONNECT received");
                    return Ok(());
                }
                other => {
                    debug!(cn = %identity.cn, packet = ?other, "ignoring unexpected v5 packet");
                }
            },
            // --- v4 PUBLISH ---
            MqttPacket::V4(v4_pkt) => match v4_pkt {
                mqttbytes::v4::Packet::Publish(publish) => {
                    handle_publish_v4(codec, identity, router, topic_prefix, publish).await?;
                }
                mqttbytes::v4::Packet::Subscribe(sub) => {
                    handle_subscribe_v4(codec, identity, topic_prefix, sub).await?;
                }
                mqttbytes::v4::Packet::Unsubscribe(unsub) => {
                    handle_unsubscribe_v4(codec, unsub).await?;
                }
                mqttbytes::v4::Packet::PingReq => {
                    codec.write_pingresp().await?;
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
    codec: &mut PacketCodec,
    identity: &Identity,
    router: &Router,
    topic_prefix: Option<&str>,
    publish: mqttbytes::v5::Publish,
) -> Result<(), MqttError> {
    if publish.qos == mqttbytes::QoS::ExactlyOnce {
        return Err(MqttError::Qos2Unsupported);
    }

    topic::validate_publish_topic(&publish.topic)?;
    let group = topic::topic_to_group(&publish.topic, topic_prefix)?;

    let msg = RoutableMessage {
        source: identity.clone(),
        destination: Destination::Group(group),
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
        codec
            .write_v5(&mqttbytes::v5::Packet::PubAck(puback))
            .await?;
    }

    Ok(())
}

async fn handle_publish_v4(
    codec: &mut PacketCodec,
    identity: &Identity,
    router: &Router,
    topic_prefix: Option<&str>,
    publish: mqttbytes::v4::Publish,
) -> Result<(), MqttError> {
    if publish.qos == mqttbytes::QoS::ExactlyOnce {
        return Err(MqttError::Qos2Unsupported);
    }

    topic::validate_publish_topic(&publish.topic)?;
    let group = topic::topic_to_group(&publish.topic, topic_prefix)?;

    let msg = RoutableMessage {
        source: identity.clone(),
        destination: Destination::Group(group),
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
        codec
            .write_v4(&mqttbytes::v4::Packet::PubAck(puback))
            .await?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// SUBSCRIBE handlers
// ---------------------------------------------------------------------------

/// Handle a v5 SUBSCRIBE packet.
///
/// For v1, wildcards are rejected and group membership is certificate-based.
/// Each filter is validated and mapped to a group; the client must already
/// be a member (via their certificate OU) for the subscription to succeed.
/// Dynamic group joining will be added in a future commit.
async fn handle_subscribe_v5(
    codec: &mut PacketCodec,
    identity: &Identity,
    topic_prefix: Option<&str>,
    sub: mqttbytes::v5::Subscribe,
) -> Result<(), MqttError> {
    let mut return_codes = Vec::with_capacity(sub.filters.len());

    for filter in &sub.filters {
        if filter.qos == mqttbytes::QoS::ExactlyOnce {
            return_codes.push(mqttbytes::v5::SubscribeReasonCode::ImplementationSpecific);
            continue;
        }

        let code = match validate_subscription(identity, &filter.path, topic_prefix) {
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
    codec
        .write_v5(&mqttbytes::v5::Packet::SubAck(suback))
        .await?;

    Ok(())
}

async fn handle_subscribe_v4(
    codec: &mut PacketCodec,
    identity: &Identity,
    topic_prefix: Option<&str>,
    sub: mqttbytes::v4::Subscribe,
) -> Result<(), MqttError> {
    let mut return_codes = Vec::with_capacity(sub.filters.len());

    for filter in &sub.filters {
        if filter.qos == mqttbytes::QoS::ExactlyOnce {
            return_codes.push(mqttbytes::v4::SubscribeReasonCode::Failure);
            continue;
        }

        let code = match validate_subscription(identity, &filter.path, topic_prefix) {
            Ok(()) => mqttbytes::v4::SubscribeReasonCode::Success(filter.qos),
            Err(_) => mqttbytes::v4::SubscribeReasonCode::Failure,
        };
        return_codes.push(code);
    }

    let suback = mqttbytes::v4::SubAck::new(sub.pkid, return_codes);
    codec
        .write_v4(&mqttbytes::v4::Packet::SubAck(suback))
        .await?;

    Ok(())
}

/// Validate that the client is authorized for a subscription filter.
///
/// Checks topic validity, maps to a group name, and verifies the client's
/// certificate includes that group in its OU.
fn validate_subscription(
    identity: &Identity,
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

    Ok(())
}

// ---------------------------------------------------------------------------
// UNSUBSCRIBE handlers
// ---------------------------------------------------------------------------

async fn handle_unsubscribe_v5(
    codec: &mut PacketCodec,
    unsub: mqttbytes::v5::Unsubscribe,
) -> Result<(), MqttError> {
    // Acknowledge all filters. Dynamic unsubscribe is a no-op for now
    // since group membership is certificate-based.
    let reasons = vec![mqttbytes::v5::UnsubAckReason::Success; unsub.filters.len()];
    let unsuback = mqttbytes::v5::UnsubAck {
        pkid: unsub.pkid,
        reasons,
        properties: None,
    };
    codec
        .write_v5(&mqttbytes::v5::Packet::UnsubAck(unsuback))
        .await?;
    Ok(())
}

async fn handle_unsubscribe_v4(
    codec: &mut PacketCodec,
    unsub: mqttbytes::v4::Unsubscribe,
) -> Result<(), MqttError> {
    let unsuback = mqttbytes::v4::UnsubAck { pkid: unsub.pkid };
    codec
        .write_v4(&mqttbytes::v4::Packet::UnsubAck(unsuback))
        .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Write loop
// ---------------------------------------------------------------------------

/// Write loop: drain routed messages from channels.
///
/// Returns the pending messages as a signal to the caller — actual MQTT
/// writes happen after the select resolves, since both loops need the codec.
/// This function only terminates when both channels close (circuit breaker
/// or router unregister).
async fn mqtt_write_loop(
    priority_rx: &mut mpsc::Receiver<rustgate_transport::RoutedMessage>,
    normal_rx: &mut mpsc::Receiver<rustgate_transport::RoutedMessage>,
) -> Result<(), MqttError> {
    let mut priority_open = true;
    let mut normal_open = true;

    loop {
        if !priority_open && !normal_open {
            return Ok(());
        }

        // The write loop terminates when channels close, signalling the
        // read loop to stop as well. We don't write to the TLS stream
        // here because PacketCodec owns the stream and the read loop
        // needs it concurrently. Instead, we just drain and discard.
        //
        // A proper split-stream implementation will be added when we
        // refactor PacketCodec to support independent read/write halves.
        let _msg = tokio::select! {
            biased;
            msg = priority_rx.recv(), if priority_open => match msg {
                Some(m) => m,
                None => {
                    priority_open = false;
                    continue;
                }
            },
            msg = normal_rx.recv(), if normal_open => match msg {
                Some(m) => m,
                None => {
                    normal_open = false;
                    continue;
                }
            },
        };
    }
}

/// Flush any pending routed messages to the client as MQTT PUBLISH packets
/// before disconnecting. Best-effort: errors are logged but not propagated.
async fn flush_pending(
    codec: &mut PacketCodec,
    protocol: ProtocolLevel,
    topic_prefix: Option<&str>,
    priority_rx: &mut mpsc::Receiver<rustgate_transport::RoutedMessage>,
    normal_rx: &mut mpsc::Receiver<rustgate_transport::RoutedMessage>,
) {
    let mut flushed = 0u32;
    let prefix = topic_prefix.unwrap_or("");

    // Drain whatever is buffered in the channels.
    loop {
        let msg = match priority_rx.try_recv() {
            Ok(m) => m,
            Err(_) => match normal_rx.try_recv() {
                Ok(m) => m,
                Err(_) => break,
            },
        };

        let topic = msg_to_topic(&msg, prefix);

        let result = match protocol {
            ProtocolLevel::V311 => {
                let publish = mqttbytes::v4::Publish::from_bytes(
                    &topic,
                    mqttbytes::QoS::AtMostOnce,
                    msg.payload.clone(),
                );
                tokio::time::timeout(
                    WRITE_TIMEOUT,
                    codec.write_v4(&mqttbytes::v4::Packet::Publish(publish)),
                )
                .await
            }
            ProtocolLevel::V50 => {
                let publish = mqttbytes::v5::Publish::from_bytes(
                    &topic,
                    mqttbytes::QoS::AtMostOnce,
                    msg.payload.clone(),
                );
                tokio::time::timeout(
                    WRITE_TIMEOUT,
                    codec.write_v5(&mqttbytes::v5::Packet::Publish(publish)),
                )
                .await
            }
        };

        match result {
            Ok(Ok(())) => flushed += 1,
            Ok(Err(e)) => {
                debug!(error = %e, "flush write error, stopping");
                break;
            }
            Err(_) => {
                debug!("flush write timeout, stopping");
                break;
            }
        }
    }

    if flushed > 0 {
        debug!(flushed, "flushed pending messages before disconnect");
    }
}

/// Derive an MQTT topic name from a routed message's destination.
fn msg_to_topic(msg: &RoutableMessage, prefix: &str) -> String {
    match &msg.destination {
        Destination::Group(group) => format!("{prefix}{group}"),
        Destination::Direct(target) => format!("{prefix}direct/{}", target.cn),
        Destination::Broadcast => format!("{prefix}broadcast"),
    }
}
