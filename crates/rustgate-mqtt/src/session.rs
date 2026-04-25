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
use rustgate_core::masking::hash_cn;
use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};
use rustgate_core::sanitize::sanitize_for_log;
use rustgate_transport::{
    NORMAL_CHANNEL_CAPACITY, PRIORITY_CHANNEL_CAPACITY, Router, SessionHandle,
};
use tokio::sync::{OwnedSemaphorePermit, mpsc};
use tracing::{debug, info, warn};

use crate::TRANSPORT_LABEL;
use crate::error::MqttError;
use crate::listener::MqttPreSession;
use crate::packet::{MqttPacket, PacketCodec, PacketReader, PacketWriter, ProtocolLevel};
use crate::retain::{RetainOutcome, RetainStore};
use crate::topic::{self, WildcardPolicy};

/// Keep-alive multiplier per MQTT spec: the server MUST allow 1.5x the
/// client's requested keep-alive before considering the connection dead.
const KEEP_ALIVE_FACTOR: f64 = 1.5;

/// Topic prefix for broadcast messages routed to MQTT subscribers.
const BROADCAST_TOPIC_SUFFIX: &str = "$broadcast";

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
            // F-153: both CNs are validated by `Identity::new()` (no control
            // chars) but we still hash them for PII-safe production logs.
            // `client_id` is untrusted — keep the CR/LF-safe sanitizer.
            warn!(
                transport = TRANSPORT_LABEL,
                client_id = %sanitize_for_log(client_id),
                existing_cn = %hash_cn(existing_cn),
                new_cn = %hash_cn(cn),
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
// justification: entry-point for a per-connection task spawned exactly once
// by `listener::accept_loop`. Every argument maps to a distinct config or
// runtime handle that must be owned by this task (pre-handshake state,
// router Arc, prefix, three size/time caps, wildcard policy, client-id
// registry, admission permit, optional metrics hooks). Packaging into a
// struct would duplicate the listener's own config surface for zero
// call-site reduction.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_mqtt_session(
    pre: MqttPreSession,
    router: Arc<Router>,
    topic_prefix: Option<String>,
    max_packet_size: usize,
    min_keep_alive_secs: u16,
    response_channel_capacity: usize,
    wildcard_policy: WildcardPolicy,
    client_id_registry: Arc<ClientIdRegistry>,
    retain_store: Arc<RetainStore>,
    _permit: OwnedSemaphorePermit,
    session_hooks: Option<crate::config::MqttSessionHooks>,
    forwarding_hooks: Option<crate::config::MqttForwardingHooks>,
) {
    let identity = pre.identity;
    let peer_addr = pre.peer_addr;
    let cn = identity.cn.clone();

    let mut codec = PacketCodec::new(pre.stream, max_packet_size);

    // --- CONNECT handshake ---
    let (keep_alive, client_id) = match connect_handshake(&mut codec, &identity).await {
        Ok(result) => result,
        Err(e) => {
            debug!(cn = %hash_cn(&cn), peer = %peer_addr, error = %e, "CONNECT handshake failed");
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
        debug!(cn = %hash_cn(&cn), peer = %peer_addr, error = %e, "client ID rejected");
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
        transport = TRANSPORT_LABEL,
        peer = %peer_addr,
        cn = %hash_cn(&cn),
        groups = ?identity.groups,
        protocol = ?protocol,
        keep_alive = keep_alive,
        client_id = %sanitize_for_log(&client_id),
        "MQTT session started"
    );

    // Response channel: read loop produces serialized response packets,
    // write loop consumes and writes them to the TLS stream.
    let (resp_tx, mut resp_rx) = mpsc::channel::<ResponsePacket>(response_channel_capacity);

    // Drain offline queue BEFORE register so queued messages arrive first.
    // Filter through current ACL/authz policy to prevent stale permissions.
    let buffered = router.drain_offline_messages(&cn).await;
    let before = buffered.len();
    let buffered = router.filter_offline_messages(&identity, buffered);
    let filtered_count = before - buffered.len();
    if filtered_count > 0 {
        info!(
            transport = TRANSPORT_LABEL,
            cn = %hash_cn(&cn),
            filtered = filtered_count,
            delivered = buffered.len(),
            "filtered offline messages on MQTT reconnect",
        );
    }
    if !router.register(handle.clone()).await {
        warn!(
            transport = TRANSPORT_LABEL,
            cn = %hash_cn(&cn),
            "connection rejected: tenant quota exceeded",
        );
        rustgate_core::audit::connection_rejected(peer_addr, "tenant quota exceeded");
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
        f64::from(keep_alive.max(min_keep_alive_secs)) * KEEP_ALIVE_FACTOR,
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
        wildcard_policy,
        keep_alive: keep_alive_duration,
        session_hooks: session_hooks.as_ref(),
        forwarding_hooks: forwarding_hooks.as_ref(),
        retain_store: &retain_store,
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
        debug!(cn = %hash_cn(&cn), error = %e, "MQTT session ended with error");
    }

    router.unregister(&cn, session_id).await;
    info!(
        transport = TRANSPORT_LABEL,
        cn = %hash_cn(&cn),
        peer = %peer_addr,
        "MQTT session ended",
    );
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
                cn = %hash_cn(&identity.cn),
                client_id = %sanitize_for_log(&client_id),
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
                    cn = %hash_cn(&identity.cn),
                    client_id = %sanitize_for_log(&client_id),
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
// Session hook dispatch
//
// The four helpers below are the only places `MqttSessionHooks` is looked
// up from inside the publish / subscribe hot paths. Centralising them here
// lets the individual callers stay readable (`fire_publish_reject(hooks)`)
// without every call site paying the closure-option dance — and makes the
// fire-site wiring a one-liner that shows up in test coverage directly.
// ---------------------------------------------------------------------------

fn fire_publish_accept(hooks: Option<&crate::config::MqttSessionHooks>) {
    if let Some(h) = hooks
        && let Some(cb) = &h.on_publish
    {
        cb();
    }
}

fn fire_publish_reject(hooks: Option<&crate::config::MqttSessionHooks>) {
    if let Some(h) = hooks
        && let Some(cb) = &h.on_publish_reject
    {
        cb();
    }
}

fn fire_subscribe_accept(hooks: Option<&crate::config::MqttSessionHooks>) {
    if let Some(h) = hooks
        && let Some(cb) = &h.on_subscribe
    {
        cb();
    }
}

fn fire_subscribe_reject(hooks: Option<&crate::config::MqttSessionHooks>) {
    if let Some(h) = hooks
        && let Some(cb) = &h.on_subscribe_reject
    {
        cb();
    }
}

/// Fan out the post-Send-PEP routed message to NATS / federation / HTTP
/// egress sinks.
///
/// Mirrors the WebSocket write-loop's fan-out block verbatim so that an
/// MQTT PUBLISH that survives the router's obligations (dedup, TTL,
/// Send-PEP deny, oversize multicast) is visible to every external
/// sink in exactly the same way a WebSocket inbound message would be.
/// Each sink is independent — a `None` field is a no-op and never
/// allocates.
fn fire_forwarding(hooks: Option<&crate::config::MqttForwardingHooks>, routed: &RoutableMessage) {
    let Some(h) = hooks else {
        return;
    };
    if let Some(cb) = &h.nats_publish {
        cb(routed.clone());
    }
    if let Some(fwd) = &h.federation_forward {
        let groups: Vec<String> = routed.source.groups.iter().cloned().collect();
        fwd(routed.payload.clone(), groups, routed.metadata.clone());
    }
    if let Some(fwd) = &h.http_forward {
        fwd(routed.clone());
    }
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
    wildcard_policy: WildcardPolicy,
    keep_alive: std::time::Duration,
    session_hooks: Option<&'a crate::config::MqttSessionHooks>,
    forwarding_hooks: Option<&'a crate::config::MqttForwardingHooks>,
    /// Shared retain store for storing PUBLISH retain=1 messages and
    /// replaying them to new subscribers. Borrowed from
    /// [`handle_mqtt_session`]'s `Arc<RetainStore>` so the per-session
    /// task does not own a refcount of its own — the parent handle
    /// outlives the read loop by construction.
    retain_store: &'a RetainStore,
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
    let wildcard_policy = params.wildcard_policy;
    let keep_alive = params.keep_alive;
    let session_hooks = params.session_hooks;
    let forwarding_hooks = params.forwarding_hooks;
    let retain_store = params.retain_store;
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
                    handle_publish_v5(
                        resp_tx,
                        identity,
                        router,
                        topic_prefix,
                        session_hooks,
                        forwarding_hooks,
                        retain_store,
                        publish,
                    )
                    .await?;
                }
                mqttbytes::v5::Packet::Subscribe(sub) => {
                    handle_subscribe_v5(
                        resp_tx,
                        identity,
                        router,
                        session_id,
                        topic_prefix,
                        wildcard_policy,
                        session_hooks,
                        retain_store,
                        sub,
                    )
                    .await?;
                }
                mqttbytes::v5::Packet::Unsubscribe(unsub) => {
                    handle_unsubscribe_v5(
                        resp_tx,
                        identity,
                        router,
                        session_id,
                        topic_prefix,
                        wildcard_policy,
                        unsub,
                    )
                    .await?;
                }
                mqttbytes::v5::Packet::PingReq => {
                    send_response(resp_tx, serialize_pingresp(protocol)?).await?;
                }
                mqttbytes::v5::Packet::Disconnect(_) => {
                    debug!(cn = %hash_cn(&identity.cn), "MQTT v5 DISCONNECT received");
                    return Ok(());
                }
                other => {
                    debug!(cn = %hash_cn(&identity.cn), packet = ?other, "ignoring unexpected v5 packet");
                }
            },
            // --- v4 packets ---
            MqttPacket::V4(v4_pkt) => match v4_pkt {
                mqttbytes::v4::Packet::Publish(publish) => {
                    handle_publish_v4(
                        resp_tx,
                        identity,
                        router,
                        topic_prefix,
                        session_hooks,
                        forwarding_hooks,
                        retain_store,
                        publish,
                    )
                    .await?;
                }
                mqttbytes::v4::Packet::Subscribe(sub) => {
                    handle_subscribe_v4(
                        resp_tx,
                        identity,
                        router,
                        session_id,
                        topic_prefix,
                        wildcard_policy,
                        session_hooks,
                        retain_store,
                        sub,
                    )
                    .await?;
                }
                mqttbytes::v4::Packet::Unsubscribe(unsub) => {
                    handle_unsubscribe_v4(
                        resp_tx,
                        identity,
                        router,
                        session_id,
                        topic_prefix,
                        wildcard_policy,
                        unsub,
                    )
                    .await?;
                }
                mqttbytes::v4::Packet::PingReq => {
                    send_response(resp_tx, serialize_pingresp(protocol)?).await?;
                }
                mqttbytes::v4::Packet::Disconnect => {
                    debug!(cn = %hash_cn(&identity.cn), "MQTT v4 DISCONNECT received");
                    return Ok(());
                }
                other => {
                    debug!(cn = %hash_cn(&identity.cn), packet = ?other, "ignoring unexpected v4 packet");
                }
            },
        }
    }
}

// ---------------------------------------------------------------------------
// PUBLISH handlers
// ---------------------------------------------------------------------------

// justification: adds a second hooks-bundle arg (`forwarding_hooks`) to the
// v5 publish handler, bringing the count to seven. Both hook bundles are
// distinct concerns — `session_hooks` drives admission-outcome counters
// while `forwarding_hooks` drives post-route egress fan-out — and both
// are threaded all the way down from `MqttServerConfig`. Merging them
// would force unrelated concerns into the same bundle and complicate the
// `MqttSessionHooks` / `MqttForwardingHooks` public types that callers
// construct independently.
#[allow(clippy::too_many_arguments)]
async fn handle_publish_v5(
    resp_tx: &mpsc::Sender<ResponsePacket>,
    identity: &Arc<Identity>,
    router: &Router,
    topic_prefix: Option<&str>,
    session_hooks: Option<&crate::config::MqttSessionHooks>,
    forwarding_hooks: Option<&crate::config::MqttForwardingHooks>,
    retain_store: &RetainStore,
    publish: mqttbytes::v5::Publish,
) -> Result<(), MqttError> {
    if publish.qos == mqttbytes::QoS::ExactlyOnce {
        fire_publish_reject(session_hooks);
        return Err(MqttError::Qos2Unsupported);
    }

    if let Err(e) = topic::validate_publish_topic(&publish.topic) {
        fire_publish_reject(session_hooks);
        return Err(e);
    }
    let group = match topic::topic_to_group(&publish.topic, topic_prefix) {
        Ok(g) => g,
        Err(e) => {
            fire_publish_reject(session_hooks);
            return Err(e);
        }
    };

    // Authorization: the client must be a member of the target group.
    if !identity.is_member_of(&group) {
        fire_publish_reject(session_hooks);
        return Err(MqttError::NotAuthorized(format!(
            "not authorized to publish to group '{group}'"
        )));
    }

    // Update the retained-message store BEFORE routing. The retain
    // store is independent of the live fan-out — even if the router
    // drops the message via dedup or TTL, the retain semantics
    // require the broker to remember the latest payload for new
    // subscribers. The auth check above gates retain just like it
    // gates routing, so a non-member CN cannot poison the store.
    let outcome = retain_store.publish(
        &publish.topic,
        &publish.payload,
        publish.qos,
        publish.retain,
    );
    if outcome != RetainOutcome::Passthrough {
        debug!(
            cn = %hash_cn(&identity.cn),
            topic = %sanitize_for_log(&publish.topic),
            outcome = ?outcome,
            "MQTT retain store updated"
        );
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

    // Capture the post-Send-PEP form so NATS / federation / HTTP egress
    // forwarders receive the mutated payload (obligations such as
    // `MaskPoint` applied). `None` means the router dropped the message
    // — dedup, TTL, Send-PEP deny, oversize multicast — and all egress
    // MUST be skipped to keep external sinks consistent with local
    // delivery.
    let Some(routed) = router.route_for_egress(msg).await else {
        fire_publish_accept(session_hooks);
        return ack_publish_v5(resp_tx, &publish).await;
    };

    fire_forwarding(forwarding_hooks, &routed);
    fire_publish_accept(session_hooks);

    ack_publish_v5(resp_tx, &publish).await
}

/// Emit the QoS 1 PUBACK (if required) for a v5 PUBLISH. Factored out so
/// both the routed and the router-dropped paths share the same ack code
/// verbatim.
async fn ack_publish_v5(
    resp_tx: &mpsc::Sender<ResponsePacket>,
    publish: &mqttbytes::v5::Publish,
) -> Result<(), MqttError> {
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

// justification: mirrors `handle_publish_v5` for the MQTT 3.1.1 wire format.
// The v5 sibling already carries the same eight args and unifying them
// would force an unrelated wrapper struct through every dispatch branch.
#[allow(clippy::too_many_arguments)]
async fn handle_publish_v4(
    resp_tx: &mpsc::Sender<ResponsePacket>,
    identity: &Arc<Identity>,
    router: &Router,
    topic_prefix: Option<&str>,
    session_hooks: Option<&crate::config::MqttSessionHooks>,
    forwarding_hooks: Option<&crate::config::MqttForwardingHooks>,
    retain_store: &RetainStore,
    publish: mqttbytes::v4::Publish,
) -> Result<(), MqttError> {
    if publish.qos == mqttbytes::QoS::ExactlyOnce {
        fire_publish_reject(session_hooks);
        return Err(MqttError::Qos2Unsupported);
    }

    if let Err(e) = topic::validate_publish_topic(&publish.topic) {
        fire_publish_reject(session_hooks);
        return Err(e);
    }
    let group = match topic::topic_to_group(&publish.topic, topic_prefix) {
        Ok(g) => g,
        Err(e) => {
            fire_publish_reject(session_hooks);
            return Err(e);
        }
    };

    // Authorization: the client must be a member of the target group.
    if !identity.is_member_of(&group) {
        fire_publish_reject(session_hooks);
        return Err(MqttError::NotAuthorized(format!(
            "not authorized to publish to group '{group}'"
        )));
    }

    // See `handle_publish_v5` for the rationale — retain semantics are
    // identical across MQTT 3.1.1 and 5.0 and live above the routing
    // layer so even router-dropped messages update the store.
    let outcome = retain_store.publish(
        &publish.topic,
        &publish.payload,
        publish.qos,
        publish.retain,
    );
    if outcome != RetainOutcome::Passthrough {
        debug!(
            cn = %hash_cn(&identity.cn),
            topic = %sanitize_for_log(&publish.topic),
            outcome = ?outcome,
            "MQTT retain store updated"
        );
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

    // See `handle_publish_v5` for the identical rationale — the egress
    // fan-out only fires when the router accepts the message.
    let Some(routed) = router.route_for_egress(msg).await else {
        fire_publish_accept(session_hooks);
        return ack_publish_v4(resp_tx, &publish).await;
    };

    fire_forwarding(forwarding_hooks, &routed);
    fire_publish_accept(session_hooks);

    ack_publish_v4(resp_tx, &publish).await
}

/// Emit the QoS 1 PUBACK (if required) for a v4 PUBLISH. Factored out so
/// both the routed and the router-dropped paths share the same ack code
/// verbatim.
async fn ack_publish_v4(
    resp_tx: &mpsc::Sender<ResponsePacket>,
    publish: &mqttbytes::v4::Publish,
) -> Result<(), MqttError> {
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

// justification: nine args — the original seven the SUBSCRIBE handler
// needs (response tx, session identity, router, session id, prefix,
// wildcard policy, packet) plus the optional per-filter metrics hooks
// and the shared retain store. The handler is dispatched from the read
// loop once per SUBSCRIBE packet; a wrapper struct would be built fresh
// at every call with no shared lifetime benefit.
#[allow(clippy::too_many_arguments)]
async fn handle_subscribe_v5(
    resp_tx: &mpsc::Sender<ResponsePacket>,
    identity: &Arc<Identity>,
    router: &Router,
    session_id: u64,
    topic_prefix: Option<&str>,
    wildcard_policy: WildcardPolicy,
    session_hooks: Option<&crate::config::MqttSessionHooks>,
    retain_store: &RetainStore,
    sub: mqttbytes::v5::Subscribe,
) -> Result<(), MqttError> {
    let mut return_codes = Vec::with_capacity(sub.filters.len());
    // Buffer of retained-message PUBLISHes to send AFTER the SUBACK.
    // MQTT 5.0 §3.8.4 requires retained messages to be delivered in
    // response to a SUBSCRIBE; the spec leaves the relative order
    // (SUBACK first vs retained PUBLISHes first) implementation-
    // defined. We send SUBACK first so the client's subscription
    // state is updated before the retained payloads land — this
    // matches Eclipse Mosquitto and HiveMQ behaviour.
    let mut retained_to_send: Vec<(String, crate::retain::RetainedMessage, mqttbytes::QoS)> =
        Vec::new();

    for filter in &sub.filters {
        if filter.qos == mqttbytes::QoS::ExactlyOnce {
            return_codes.push(mqttbytes::v5::SubscribeReasonCode::ImplementationSpecific);
            fire_subscribe_reject(session_hooks);
            continue;
        }

        let code = match try_join_filter(
            identity,
            router,
            session_id,
            &filter.path,
            topic_prefix,
            wildcard_policy,
        )
        .await
        {
            Ok(()) => {
                fire_subscribe_accept(session_hooks);
                // Collect retained messages now while the filter is
                // confirmed-authorised; defer the actual send until
                // after SUBACK so a slow client back-pressuring the
                // response channel cannot block the SUBACK itself.
                collect_retained_for_filter(
                    retain_store,
                    identity,
                    &filter.path,
                    filter.qos,
                    topic_prefix,
                    &mut retained_to_send,
                );
                match filter.qos {
                    mqttbytes::QoS::AtMostOnce => mqttbytes::v5::SubscribeReasonCode::QoS0,
                    mqttbytes::QoS::AtLeastOnce => mqttbytes::v5::SubscribeReasonCode::QoS1,
                    mqttbytes::QoS::ExactlyOnce => unreachable!(),
                }
            }
            Err(MqttError::InvalidTopic(_)) => {
                fire_subscribe_reject(session_hooks);
                mqttbytes::v5::SubscribeReasonCode::TopicFilterInvalid
            }
            Err(_) => {
                fire_subscribe_reject(session_hooks);
                mqttbytes::v5::SubscribeReasonCode::NotAuthorized
            }
        };
        return_codes.push(code);
    }

    let suback = mqttbytes::v5::SubAck::new(sub.pkid, return_codes);
    send_response(
        resp_tx,
        serialize_v5(&mqttbytes::v5::Packet::SubAck(suback))?,
    )
    .await?;

    // Deliver retained messages AFTER SUBACK. Each PUBLISH carries
    // `retain=true` on the wire per MQTT 5.0 §3.3.1.3 so the client
    // can distinguish a fresh publication from a retained replay.
    for (topic, retained, subscriber_qos) in retained_to_send {
        // Downgrade publisher's QoS to min(publisher_qos,
        // subscriber_qos) per MQTT 5.0 §3.8.4 ("the QoS of Payload
        // messages sent in response to a Subscription MUST be the
        // minimum of the QoS of the originally published message and
        // the Maximum QoS granted by the Server").
        let effective_qos = min_qos(retained.qos, subscriber_qos);
        let mut publish =
            mqttbytes::v5::Publish::from_bytes(topic, effective_qos, retained.payload);
        publish.retain = true;
        // Pkid 0 is correct for QoS 0 retained PUBLISHes; for QoS 1
        // we currently rely on the receiver tolerating pkid 0 on a
        // retained replay (the spec allows this when the broker has
        // not allocated a packet id, which is our case since we do
        // not track per-subscriber retained-PUBLISH acks). The full
        // QoS 1 retained-replay round-trip lands with the broader
        // session-persistence work tracked under #880.
        send_response(
            resp_tx,
            serialize_v5(&mqttbytes::v5::Packet::Publish(publish))?,
        )
        .await?;
    }

    Ok(())
}

// justification: mirrors `handle_subscribe_v5` for the MQTT 3.1.1 wire
// format with the same nine args including the optional metrics hooks
// and the shared retain store. Unifying the pair under a struct would
// force every branch in the read-loop dispatch to unpack fields that
// differ only in the generic `sub` packet type.
#[allow(clippy::too_many_arguments)]
async fn handle_subscribe_v4(
    resp_tx: &mpsc::Sender<ResponsePacket>,
    identity: &Arc<Identity>,
    router: &Router,
    session_id: u64,
    topic_prefix: Option<&str>,
    wildcard_policy: WildcardPolicy,
    session_hooks: Option<&crate::config::MqttSessionHooks>,
    retain_store: &RetainStore,
    sub: mqttbytes::v4::Subscribe,
) -> Result<(), MqttError> {
    let mut return_codes = Vec::with_capacity(sub.filters.len());
    let mut retained_to_send: Vec<(String, crate::retain::RetainedMessage, mqttbytes::QoS)> =
        Vec::new();

    for filter in &sub.filters {
        if filter.qos == mqttbytes::QoS::ExactlyOnce {
            return_codes.push(mqttbytes::v4::SubscribeReasonCode::Failure);
            fire_subscribe_reject(session_hooks);
            continue;
        }

        // MQTT 3.1.1 collapses all subscribe failures to `Failure` — there is
        // no distinct `TopicFilterInvalid` / `NotAuthorized` code on the wire.
        let code = match try_join_filter(
            identity,
            router,
            session_id,
            &filter.path,
            topic_prefix,
            wildcard_policy,
        )
        .await
        {
            Ok(()) => {
                fire_subscribe_accept(session_hooks);
                collect_retained_for_filter(
                    retain_store,
                    identity,
                    &filter.path,
                    filter.qos,
                    topic_prefix,
                    &mut retained_to_send,
                );
                mqttbytes::v4::SubscribeReasonCode::Success(filter.qos)
            }
            Err(_) => {
                fire_subscribe_reject(session_hooks);
                mqttbytes::v4::SubscribeReasonCode::Failure
            }
        };
        return_codes.push(code);
    }

    let suback = mqttbytes::v4::SubAck::new(sub.pkid, return_codes);
    send_response(
        resp_tx,
        serialize_v4(&mqttbytes::v4::Packet::SubAck(suback))?,
    )
    .await?;

    // Deliver retained messages after SUBACK; see `handle_subscribe_v5`
    // for the rationale on ordering and QoS downgrade.
    for (topic, retained, subscriber_qos) in retained_to_send {
        let effective_qos = min_qos(retained.qos, subscriber_qos);
        let mut publish =
            mqttbytes::v4::Publish::from_bytes(topic, effective_qos, retained.payload);
        publish.retain = true;
        send_response(
            resp_tx,
            serialize_v4(&mqttbytes::v4::Packet::Publish(publish))?,
        )
        .await?;
    }

    Ok(())
}

/// Validate a subscription filter and dynamically join each mapped group.
///
/// For wildcard-free filters the filter maps 1:1 to a single rustgate
/// group, which is joined after the membership check. For wildcard
/// filters (`+` / `#`, subject to `wildcard_policy`) the filter is
/// expanded against `identity.groups` — the client's certificate-derived
/// group set — and each matching group is joined individually. The
/// server never synthesises new groups from a wildcard; the cert is the
/// authorisation boundary.
///
/// Returns `InvalidTopic` for syntactically malformed filters (including
/// wildcards disabled by policy) and `NotAuthorized` when the filter
/// resolves to no authorised groups.
async fn try_join_filter(
    identity: &Identity,
    router: &Router,
    session_id: u64,
    filter: &str,
    topic_prefix: Option<&str>,
    wildcard_policy: WildcardPolicy,
) -> Result<(), MqttError> {
    topic::validate_subscribe_filter(filter, wildcard_policy)?;

    if !topic::filter_has_wildcards(filter) {
        // Exact-topic path: preserves pre-wildcard behaviour byte-for-byte.
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
        debug!(cn = %hash_cn(&identity.cn), group = %group, "MQTT subscribed to group");
        return Ok(());
    }

    // Wildcard path: expand against identity's certificate-derived groups.
    // Strip the listener's topic prefix from the filter (if configured and
    // present) so matching happens in the group-name coordinate space.
    let stripped_filter = match topic_prefix {
        Some(pfx) => filter.strip_prefix(pfx).ok_or_else(|| {
            MqttError::InvalidTopic(format!("wildcard filter must start with prefix '{pfx}'"))
        })?,
        None => filter,
    };

    let mut joined = 0usize;
    for group in &identity.groups {
        if !topic::filter_matches(stripped_filter, group) {
            continue;
        }
        if router.join_group(&identity.cn, session_id, group).await {
            joined += 1;
            debug!(
                cn = %hash_cn(&identity.cn),
                group = %group,
                filter = %filter,
                "MQTT wildcard expanded subscription"
            );
        }
    }

    if joined == 0 {
        return Err(MqttError::NotAuthorized(format!(
            "wildcard filter '{filter}' matched no authorised groups"
        )));
    }
    Ok(())
}

/// Pick the lower of two `QoS` values per MQTT spec semantics
/// (downgrade to `min(publisher_qos, subscriber_qos)`).
///
/// `mqttbytes::QoS` does not implement `Ord` because the spec
/// distinguishes 0/1/2 by behaviour, not by ordering on the wire.
/// We define our own `min` here to keep the QoS-downgrade logic
/// readable at the retained-PUBLISH call sites.
fn min_qos(a: mqttbytes::QoS, b: mqttbytes::QoS) -> mqttbytes::QoS {
    let rank = |q| match q {
        mqttbytes::QoS::AtMostOnce => 0u8,
        mqttbytes::QoS::AtLeastOnce => 1u8,
        mqttbytes::QoS::ExactlyOnce => 2u8,
    };
    if rank(a) <= rank(b) { a } else { b }
}

/// Look up retained messages whose topic matches `filter` AND whose
/// derived group is authorised for `identity`, and append them to
/// `out` paired with the subscriber's requested `subscriber_qos`.
///
/// Called once per accepted filter inside the SUBSCRIBE handlers.
/// The double check (filter pattern + group membership) mirrors the
/// auth model used by `try_join_filter`: a wildcard filter is
/// expanded against the certificate-derived group set, never against
/// the synthesised superset of all retained topics. So an attacker
/// who somehow placed a retained message on a topic they no longer
/// have rights to cannot leak it to a subscriber that lacks the
/// matching group either.
///
/// Topics that appear in the retain store but no longer map to a
/// valid group (e.g. a misconfigured prefix change) are skipped
/// silently — the retain store is best-effort and a stale entry must
/// not break a fresh SUBSCRIBE.
fn collect_retained_for_filter(
    retain_store: &RetainStore,
    identity: &Identity,
    filter: &str,
    subscriber_qos: mqttbytes::QoS,
    topic_prefix: Option<&str>,
    out: &mut Vec<(String, crate::retain::RetainedMessage, mqttbytes::QoS)>,
) {
    for (topic, msg) in retain_store.matching(filter, topic_prefix) {
        // The auth boundary is the certificate-derived group set, same
        // as for the live PUBLISH path. Stale retained entries whose
        // topic no longer maps to a valid group are skipped — they
        // cannot leak to anyone.
        match topic::topic_to_group(&topic, topic_prefix) {
            Ok(group) if identity.is_member_of(&group) => {
                out.push((topic, msg, subscriber_qos));
            }
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------
// UNSUBSCRIBE handlers
// ---------------------------------------------------------------------------

// justification: symmetric with the SUBSCRIBE handlers above — same seven
// inputs, same call-once-per-packet dispatch pattern. Keeping the signature
// shape consistent across all four handlers lets maintainers grep the whole
// MQTT dispatch surface with one pattern.
#[allow(clippy::too_many_arguments)]
async fn handle_unsubscribe_v5(
    resp_tx: &mpsc::Sender<ResponsePacket>,
    identity: &Identity,
    router: &Router,
    session_id: u64,
    topic_prefix: Option<&str>,
    wildcard_policy: WildcardPolicy,
    unsub: mqttbytes::v5::Unsubscribe,
) -> Result<(), MqttError> {
    let mut reasons = Vec::with_capacity(unsub.filters.len());

    for filter in &unsub.filters {
        let reason = match leave_filter(
            identity,
            router,
            session_id,
            filter,
            topic_prefix,
            wildcard_policy,
        )
        .await
        {
            Ok(_) => mqttbytes::v5::UnsubAckReason::Success,
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

// justification: v4 counterpart to `handle_unsubscribe_v5`. Same seven-arg
// shape; kept symmetric with the v5 and SUBSCRIBE handlers above so the
// dispatch table has one uniform signature per MQTT packet kind.
#[allow(clippy::too_many_arguments)]
async fn handle_unsubscribe_v4(
    resp_tx: &mpsc::Sender<ResponsePacket>,
    identity: &Identity,
    router: &Router,
    session_id: u64,
    topic_prefix: Option<&str>,
    wildcard_policy: WildcardPolicy,
    unsub: mqttbytes::v4::Unsubscribe,
) -> Result<(), MqttError> {
    for filter in &unsub.topics {
        // MQTT 3.1.1 UNSUBACK has no reason codes — failures are silent.
        let _ = leave_filter(
            identity,
            router,
            session_id,
            filter,
            topic_prefix,
            wildcard_policy,
        )
        .await;
    }

    let unsuback = mqttbytes::v4::UnsubAck { pkid: unsub.pkid };
    send_response(
        resp_tx,
        serialize_v4(&mqttbytes::v4::Packet::UnsubAck(unsuback))?,
    )
    .await?;
    Ok(())
}

/// Mirror of [`try_join_filter`] for UNSUBSCRIBE: validates the filter
/// under the same policy and calls `leave_group` on every group the
/// filter matches. Returns `InvalidTopic` on syntax errors so v5 can
/// surface `TopicFilterInvalid`; the router's `leave_group` call is
/// idempotent and silently no-ops when the session is not in the group.
async fn leave_filter(
    identity: &Identity,
    router: &Router,
    session_id: u64,
    filter: &str,
    topic_prefix: Option<&str>,
    wildcard_policy: WildcardPolicy,
) -> Result<(), MqttError> {
    topic::validate_subscribe_filter(filter, wildcard_policy)?;

    if !topic::filter_has_wildcards(filter) {
        let group = topic::topic_to_group(filter, topic_prefix)?;
        let _ = router.leave_group(&identity.cn, session_id, &group).await;
        debug!(cn = %hash_cn(&identity.cn), group = %group, "MQTT unsubscribed from group");
        return Ok(());
    }

    let stripped_filter = match topic_prefix {
        Some(pfx) => filter.strip_prefix(pfx).ok_or_else(|| {
            MqttError::InvalidTopic(format!("wildcard filter must start with prefix '{pfx}'"))
        })?,
        None => filter,
    };

    for group in &identity.groups {
        if !topic::filter_matches(stripped_filter, group) {
            continue;
        }
        let _ = router.leave_group(&identity.cn, session_id, group).await;
        debug!(
            cn = %hash_cn(&identity.cn),
            group = %group,
            filter = %filter,
            "MQTT wildcard expanded unsubscription"
        );
    }
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

    // -----------------------------------------------------------------------
    // Constant pins
    //
    // These constants are part of the public MQTT contract even though the
    // Rust bindings keep them module-private — clients calibrate keep-alive
    // timers against the 1.5x factor (MQTT 3.1.1 §3.1.2.10 / MQTT 5.0
    // §3.1.2.10) and subscribe to the `$broadcast` topic by literal string
    // on the wire. Bumping either value silently would break existing
    // deployments, so the tests pin the literal value and the test name
    // doubles as the canary.
    // -----------------------------------------------------------------------

    #[test]
    fn keep_alive_factor_pinned_at_1_5x_per_mqtt_spec() {
        // MQTT 3.1.1 §3.1.2.10 and MQTT 5.0 §3.1.2.10 both mandate that the
        // server MUST close the connection if it does not receive a packet
        // within 1.5x the client-requested keep-alive. Any other multiplier
        // is a spec violation; pin the literal f64.
        assert_eq!(
            KEEP_ALIVE_FACTOR, 1.5_f64,
            "KEEP_ALIVE_FACTOR must be exactly 1.5 per MQTT spec"
        );
    }

    #[test]
    fn broadcast_topic_suffix_pinned_string() {
        // MQTT reserves `$`-prefixed topic names for system-level topics
        // (§4.7.2). The `$broadcast` suffix is the rustgate convention for
        // surface-of-all-sessions fan-out. Clients subscribing to
        // `"$broadcast"` (or `"<prefix>$broadcast"` when a topic prefix is
        // configured) rely on the exact literal; renaming it silently would
        // orphan every existing subscription.
        assert_eq!(BROADCAST_TOPIC_SUFFIX, "$broadcast");
    }

    #[test]
    fn broadcast_topic_suffix_is_dollar_prefixed() {
        // Defence-in-depth: even if a future rename changes the trailing
        // text, the leading `$` must stay so the token continues to live
        // in MQTT's reserved system-topic namespace and cannot collide
        // with an ordinary client-published topic like `broadcast`.
        assert!(
            BROADCAST_TOPIC_SUFFIX.starts_with('$'),
            "broadcast suffix must live in MQTT's reserved $-topic namespace",
        );
    }

    // -----------------------------------------------------------------------
    // Observer fire-helper dispatch
    //
    // The four `fire_*` helpers sit on the publish/subscribe hot path and
    // are the only bridge between the session loop and the
    // `MqttSessionHooks` observer. Their defensive contract is:
    //
    //   (a) `None` at the outer `Option<&MqttSessionHooks>` is a no-op;
    //   (b) `None` at the individual `Option<Arc<...>>` field is a no-op;
    //   (c) when both Somes are present, *only* the matching callback fires;
    //   (d) repeated calls increment, never dedup.
    //
    // The counters use `AtomicUsize` so the test is deterministic and
    // preserves interior-mutability across the `Arc<dyn Fn()>` callback
    // boundary.
    // -----------------------------------------------------------------------

    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Build a counter-incrementing callback that matches every `On*` alias
    /// in `crate::config` (`Arc<dyn Fn() + Send + Sync>`).
    fn counter_cb(slot: &Arc<AtomicUsize>) -> Arc<dyn Fn() + Send + Sync> {
        let slot = Arc::clone(slot);
        Arc::new(move || {
            let _ = slot.fetch_add(1, Ordering::SeqCst);
        })
    }

    /// Build a fully-populated hooks bundle where every field is wired to
    /// an independent counter, returned in fixed order so the test can
    /// assert which callback fired.
    fn hooks_with_all_counters() -> (
        crate::config::MqttSessionHooks,
        Arc<AtomicUsize>, // publish
        Arc<AtomicUsize>, // publish_reject
        Arc<AtomicUsize>, // subscribe
        Arc<AtomicUsize>, // subscribe_reject
    ) {
        let pub_c = Arc::new(AtomicUsize::new(0));
        let pub_rej_c = Arc::new(AtomicUsize::new(0));
        let sub_c = Arc::new(AtomicUsize::new(0));
        let sub_rej_c = Arc::new(AtomicUsize::new(0));
        let hooks = crate::config::MqttSessionHooks {
            on_publish: Some(counter_cb(&pub_c)),
            on_publish_reject: Some(counter_cb(&pub_rej_c)),
            on_subscribe: Some(counter_cb(&sub_c)),
            on_subscribe_reject: Some(counter_cb(&sub_rej_c)),
        };
        (hooks, pub_c, pub_rej_c, sub_c, sub_rej_c)
    }

    #[test]
    fn fire_helpers_nop_when_hooks_bundle_is_none() {
        // Passing `None` at the top level is the common production path
        // when metrics are disabled; none of the four helpers may touch
        // anything (no allocations, no panics, no side effects). We just
        // exercise every helper and rely on the absence of a panic + the
        // `#![deny(clippy::panic)]` workspace lint to enforce it.
        fire_publish_accept(None);
        fire_publish_reject(None);
        fire_subscribe_accept(None);
        fire_subscribe_reject(None);
    }

    #[test]
    fn fire_helpers_nop_when_individual_callback_is_none() {
        // An operator may opt into the hook struct but wire only a subset
        // of callbacks (e.g. accept metrics but not reject metrics). The
        // helpers must tolerate partial population — a missing callback on
        // the matching field must not dispatch any other field as a
        // fallback.
        let (_, pub_c, pub_rej_c, sub_c, sub_rej_c) = hooks_with_all_counters();
        let empty = crate::config::MqttSessionHooks::default();
        fire_publish_accept(Some(&empty));
        fire_publish_reject(Some(&empty));
        fire_subscribe_accept(Some(&empty));
        fire_subscribe_reject(Some(&empty));
        assert_eq!(pub_c.load(Ordering::SeqCst), 0);
        assert_eq!(pub_rej_c.load(Ordering::SeqCst), 0);
        assert_eq!(sub_c.load(Ordering::SeqCst), 0);
        assert_eq!(sub_rej_c.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn fire_publish_accept_fires_only_its_own_callback() {
        let (hooks, pub_c, pub_rej_c, sub_c, sub_rej_c) = hooks_with_all_counters();
        fire_publish_accept(Some(&hooks));
        assert_eq!(pub_c.load(Ordering::SeqCst), 1, "publish accept must fire");
        assert_eq!(pub_rej_c.load(Ordering::SeqCst), 0);
        assert_eq!(sub_c.load(Ordering::SeqCst), 0);
        assert_eq!(sub_rej_c.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn fire_publish_reject_fires_only_its_own_callback() {
        let (hooks, pub_c, pub_rej_c, sub_c, sub_rej_c) = hooks_with_all_counters();
        fire_publish_reject(Some(&hooks));
        assert_eq!(pub_c.load(Ordering::SeqCst), 0);
        assert_eq!(
            pub_rej_c.load(Ordering::SeqCst),
            1,
            "publish reject must fire"
        );
        assert_eq!(sub_c.load(Ordering::SeqCst), 0);
        assert_eq!(sub_rej_c.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn fire_subscribe_accept_fires_only_its_own_callback() {
        let (hooks, pub_c, pub_rej_c, sub_c, sub_rej_c) = hooks_with_all_counters();
        fire_subscribe_accept(Some(&hooks));
        assert_eq!(pub_c.load(Ordering::SeqCst), 0);
        assert_eq!(pub_rej_c.load(Ordering::SeqCst), 0);
        assert_eq!(
            sub_c.load(Ordering::SeqCst),
            1,
            "subscribe accept must fire"
        );
        assert_eq!(sub_rej_c.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn fire_subscribe_reject_fires_only_its_own_callback() {
        let (hooks, pub_c, pub_rej_c, sub_c, sub_rej_c) = hooks_with_all_counters();
        fire_subscribe_reject(Some(&hooks));
        assert_eq!(pub_c.load(Ordering::SeqCst), 0);
        assert_eq!(pub_rej_c.load(Ordering::SeqCst), 0);
        assert_eq!(sub_c.load(Ordering::SeqCst), 0);
        assert_eq!(
            sub_rej_c.load(Ordering::SeqCst),
            1,
            "subscribe reject must fire"
        );
    }

    #[test]
    fn fire_helpers_increment_per_call_without_deduping() {
        // The helpers fire per call — the Prometheus counter that each
        // callback backs is a monotonic total, not a rate. A dedup or
        // "once-per-session" bug would collapse 100 admissions into 1
        // and wreck SLO alerting. Hammer each helper and assert the
        // counter matches call count exactly.
        let (hooks, pub_c, pub_rej_c, sub_c, sub_rej_c) = hooks_with_all_counters();
        for _ in 0..100 {
            fire_publish_accept(Some(&hooks));
            fire_publish_reject(Some(&hooks));
            fire_subscribe_accept(Some(&hooks));
            fire_subscribe_reject(Some(&hooks));
        }
        assert_eq!(pub_c.load(Ordering::SeqCst), 100);
        assert_eq!(pub_rej_c.load(Ordering::SeqCst), 100);
        assert_eq!(sub_c.load(Ordering::SeqCst), 100);
        assert_eq!(sub_rej_c.load(Ordering::SeqCst), 100);
    }

    // -----------------------------------------------------------------------
    // `msg_to_topic` destination → topic-string contract
    //
    // Every branch of `Destination` has a distinct topic shape the write
    // loop publishes. The rules we pin here are:
    //
    //   Group      → `{prefix}{group}`           (empty prefix → bare group)
    //   Direct(id) → `{prefix}direct/{cn}`       (always prefixed with
    //                                             `direct/` so it cannot
    //                                             collide with a group name)
    //   Broadcast  → `{prefix}$broadcast`        (bare `$broadcast` with
    //                                             empty prefix)
    //   Multicast  → aliased to Broadcast        (fan-out collapses at the
    //                                             MQTT wire boundary)
    //
    // Tests here don't need a live Router — `msg_to_topic` is a pure
    // function over destination + prefix.
    // -----------------------------------------------------------------------

    use std::collections::BTreeSet;

    use bytes::Bytes;

    /// Minimal `RoutableMessage` builder used by the `msg_to_topic` tests.
    fn mk_msg(dest: Destination) -> RoutableMessage {
        let source = Identity::new(
            "source-cn".into(),
            "fingerprint".into(),
            BTreeSet::from(["g1".to_string()]),
        )
        .unwrap();
        RoutableMessage {
            source,
            destination: dest,
            payload: Bytes::from_static(b""),
            metadata: Metadata {
                received_at: SystemTime::now(),
                source_protocol: "test".into(),
                message_type: MessageType::Other("test".into()),
                ttl: None,
            },
        }
    }

    /// Build an `Identity` for use inside `Destination::Direct(_)`.
    fn mk_direct_identity(cn: &str) -> Identity {
        Identity::new(cn.into(), "fp".into(), BTreeSet::new()).unwrap()
    }

    #[test]
    fn msg_to_topic_group_with_empty_prefix_is_bare_group() {
        let msg = mk_msg(Destination::Group("alpha".into()));
        assert_eq!(msg_to_topic(&msg, ""), "alpha");
    }

    #[test]
    fn msg_to_topic_group_with_prefix_concatenates_verbatim() {
        // The prefix is a literal string — rustgate does not inject a
        // separator, so operators wire the trailing `/` themselves. This
        // test pins that contract: `rg/` + `alpha` yields `rg/alpha`
        // (not `rg//alpha`).
        let msg = mk_msg(Destination::Group("alpha".into()));
        assert_eq!(msg_to_topic(&msg, "rg/"), "rg/alpha");
    }

    #[test]
    fn msg_to_topic_direct_always_prepends_direct_segment() {
        // `direct/` is hard-coded so a direct-to-CN topic cannot collide
        // with a group named the same as a CN. The prefix precedes the
        // `direct/` segment, never the other way round.
        let msg = mk_msg(Destination::Direct(mk_direct_identity("alice")));
        assert_eq!(msg_to_topic(&msg, "rg/"), "rg/direct/alice");
    }

    #[test]
    fn msg_to_topic_direct_with_empty_prefix_still_has_direct_segment() {
        let msg = mk_msg(Destination::Direct(mk_direct_identity("alice")));
        assert_eq!(msg_to_topic(&msg, ""), "direct/alice");
    }

    #[test]
    fn msg_to_topic_broadcast_empty_prefix_is_bare_suffix() {
        // Bare `$broadcast` — no synthetic leading slash. Clients
        // subscribing to the broadcast topic with no configured prefix
        // filter on the exact three-syllable string.
        let msg = mk_msg(Destination::Broadcast);
        assert_eq!(msg_to_topic(&msg, ""), "$broadcast");
    }

    #[test]
    fn msg_to_topic_broadcast_with_prefix_concatenates_verbatim() {
        let msg = mk_msg(Destination::Broadcast);
        assert_eq!(msg_to_topic(&msg, "rg/"), "rg/$broadcast");
    }

    #[test]
    fn msg_to_topic_multicast_aliases_broadcast_regardless_of_group_list() {
        // Multicast at the router layer fans to multiple groups in one
        // routing pass, but at the MQTT wire boundary there is a single
        // PUBLISH per session — so Multicast collapses to the same
        // `$broadcast` topic as `Broadcast`. A non-empty group vector
        // must not leak into the topic string.
        let msg = mk_msg(Destination::Multicast(vec![
            "group-a".into(),
            "group-b".into(),
            "group-c".into(),
        ]));
        assert_eq!(msg_to_topic(&msg, ""), "$broadcast");
        let msg2 = mk_msg(Destination::Multicast(vec![
            "group-a".into(),
            "group-b".into(),
        ]));
        assert_eq!(msg_to_topic(&msg2, "rg/"), "rg/$broadcast");
    }

    #[test]
    fn msg_to_topic_multicast_with_empty_group_vector_still_aliases_broadcast() {
        // Defence: `Multicast(vec![])` is structurally possible — it's a
        // routing-layer degenerate case. The MQTT topic must still be
        // `$broadcast` and not, say, the empty string.
        let msg = mk_msg(Destination::Multicast(Vec::new()));
        assert_eq!(msg_to_topic(&msg, ""), "$broadcast");
        assert_eq!(msg_to_topic(&msg, "rg/"), "rg/$broadcast");
    }

    // -----------------------------------------------------------------------
    // `ClientIdGuard` / `ClientIdRegistry` — extra edge cases
    //
    // The existing six tests cover the happy path and one concurrent-
    // contention case. The additions below pin behaviour on the error
    // paths: a stale guard must not clobber a live claim, the registry
    // must be `Send + Sync + 'static`, and many distinct client IDs must
    // coexist without any cross-key interference.
    // -----------------------------------------------------------------------

    #[test]
    fn client_id_guard_with_stale_session_id_does_not_clobber_live_claim() {
        // A guard whose session_id does not match the currently-stored
        // session_id (e.g. after a reconnect where `try_claim` updated
        // the session_id but the old guard is still on the stack) must
        // be a no-op on drop. Otherwise the reconnect path would
        // silently release the live claim and let a third CN steal it.
        let reg = ClientIdRegistry::new();
        reg.try_claim("sensor-1", "device-a", 1).unwrap();
        // session_id=1 got bumped to 2 by a reconnect of the same CN.
        reg.try_claim("sensor-1", "device-a", 2).unwrap();
        {
            // Stale guard from the pre-reconnect session.
            let _stale = ClientIdGuard {
                registry: Arc::clone(&reg),
                client_id: "sensor-1".into(),
                session_id: 1,
            };
        }
        // The live claim (session 2, device-a) must still be intact —
        // a different CN must still be rejected.
        assert!(reg.try_claim("sensor-1", "device-b", 3).is_err());
    }

    #[test]
    fn client_id_registry_is_send_sync_and_static() {
        // The registry is shared via `Arc<ClientIdRegistry>` across every
        // per-session spawn. Pinning the auto-trait set here catches a
        // future refactor that introduces a non-Send/Sync field (e.g.
        // `Rc<_>` or `Cell<_>`) before it breaks the tokio spawn site.
        fn assert_send_sync_static<T: Send + Sync + 'static>() {}
        assert_send_sync_static::<ClientIdRegistry>();
        assert_send_sync_static::<Arc<ClientIdRegistry>>();
    }

    #[test]
    fn client_id_registry_isolates_distinct_keys() {
        // A claim on one client_id must not affect claims on other
        // client_ids. This rules out a future bug where the hash-map
        // internal state bleeds across keys (e.g. through a shared
        // counter or monotonic id collision).
        let reg = ClientIdRegistry::new();
        reg.try_claim("sensor-1", "device-a", 1).unwrap();
        reg.try_claim("sensor-2", "device-b", 2).unwrap();
        reg.try_claim("sensor-3", "device-a", 3).unwrap();
        // Each key has its own owner; cross-CN attempts on each are
        // independently rejected.
        assert!(reg.try_claim("sensor-1", "device-b", 4).is_err());
        assert!(reg.try_claim("sensor-2", "device-a", 5).is_err());
        assert!(reg.try_claim("sensor-3", "device-b", 6).is_err());
        // Releasing one key must not release the others.
        reg.release("sensor-2", 2);
        assert!(reg.try_claim("sensor-1", "device-b", 7).is_err());
        assert!(reg.try_claim("sensor-3", "device-b", 8).is_err());
        // The released key is freely reclaimable.
        reg.try_claim("sensor-2", "device-z", 9).unwrap();
    }

    #[test]
    fn client_id_registry_debug_does_not_panic() {
        // `ClientIdRegistry` derives `Debug`; exercise it so a future
        // field whose `Debug` impl panics (exceedingly rare but possible
        // with third-party types) is caught before a diagnostic log in
        // production tries to format it.
        let reg = ClientIdRegistry::new();
        reg.try_claim("sensor-1", "device-a", 1).unwrap();
        let rendered = format!("{reg:?}");
        assert!(!rendered.is_empty());
    }

    // -----------------------------------------------------------------------
    // Response-packet serializers
    //
    // `serialize_v4`, `serialize_v5`, and `serialize_pingresp` are the
    // three ways the read loop hands serialized packet bytes to the
    // write loop. They wrap the codec `write_*_to_buf` helpers and are
    // the only place the read loop can produce a `ResponsePacket`. The
    // tests below check that every path produces non-empty, reasonably-
    // shaped output — the byte-level structure is owned by the packet
    // crate's tests, so we check only the framing we care about at this
    // layer.
    // -----------------------------------------------------------------------

    #[test]
    fn serialize_pingresp_v311_produces_two_byte_frame() {
        // MQTT 3.1.1 PINGRESP is the shortest control packet: fixed
        // header byte 0xD0 followed by remaining-length 0x00 — exactly
        // two bytes on the wire (§3.13).
        let pkt = serialize_pingresp(ProtocolLevel::V311).unwrap();
        assert_eq!(pkt.bytes.len(), 2);
        assert_eq!(pkt.bytes[0], 0xD0);
        assert_eq!(pkt.bytes[1], 0x00);
    }

    #[test]
    fn serialize_pingresp_v50_produces_two_byte_frame() {
        // MQTT 5.0 PINGRESP has identical wire shape to v3.1.1 (§3.13);
        // no properties, no reason code. Pin the exact bytes so a future
        // rewrite that accidentally introduces a reason-code byte gets
        // caught.
        let pkt = serialize_pingresp(ProtocolLevel::V50).unwrap();
        assert_eq!(pkt.bytes.len(), 2);
        assert_eq!(pkt.bytes[0], 0xD0);
        assert_eq!(pkt.bytes[1], 0x00);
    }

    #[test]
    fn serialize_v4_puback_round_trips_pkid() {
        // PUBACK (v3.1.1) is 4 bytes total: fixed header `0x40 0x02`
        // followed by the 2-byte packet identifier big-endian. We
        // build a PUBACK for pkid 0x1234 and assert the encoded bytes
        // line up with §3.4.
        let puback = mqttbytes::v4::PubAck::new(0x1234);
        let pkt = serialize_v4(&mqttbytes::v4::Packet::PubAck(puback)).unwrap();
        assert_eq!(pkt.bytes.len(), 4);
        assert_eq!(pkt.bytes[0], 0x40);
        assert_eq!(pkt.bytes[1], 0x02);
        assert_eq!(pkt.bytes[2], 0x12);
        assert_eq!(pkt.bytes[3], 0x34);
    }

    #[test]
    fn serialize_v5_puback_success_has_zero_reason_byte() {
        // MQTT 5.0 PUBACK collapses to the v3.1.1 wire shape when the
        // reason code is Success and no properties are set (§3.4.2.1),
        // yielding a four-byte frame. Pin that collapse so a future
        // property-bag addition doesn't silently inflate every ACK.
        let puback = mqttbytes::v5::PubAck {
            pkid: 0x0001,
            reason: mqttbytes::v5::PubAckReason::Success,
            properties: None,
        };
        let pkt = serialize_v5(&mqttbytes::v5::Packet::PubAck(puback)).unwrap();
        assert_eq!(pkt.bytes.len(), 4);
        assert_eq!(pkt.bytes[0], 0x40);
        assert_eq!(pkt.bytes[1], 0x02);
    }

    #[test]
    fn serialize_v4_and_v5_produce_independent_buffers() {
        // Build two packets back-to-back and assert their byte buffers
        // are distinct allocations — catches a future refactor that
        // accidentally shares a `BytesMut` between serializers and
        // corrupts earlier packets in the response pipeline.
        let pkt_a = serialize_pingresp(ProtocolLevel::V311).unwrap();
        let pkt_b = serialize_pingresp(ProtocolLevel::V311).unwrap();
        // The bytes are equal (same PINGRESP) but the buffers are
        // separately-owned; mutating one must not affect the other.
        let mut bytes_a = pkt_a.bytes;
        let bytes_b = pkt_b.bytes;
        bytes_a.clear();
        assert_eq!(bytes_b.len(), 2, "second buffer must be untouched");
    }
}
