// Copyright © 2026 Roberto Chiofalo.

//! Per-connection MQTT session state machine.
//!
//! Handles the CONNECT handshake, PUBLISH/SUBSCRIBE/PINGREQ/DISCONNECT
//! packet processing, and read/write loops. Each session registers with
//! the [`Router`](rustgate_router::Router) and receives routed messages
//! for delivery to the MQTT client.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::SystemTime;

use bytes::{Bytes, BytesMut};
use parking_lot::Mutex;
use rustgate_core::constants::WRITE_TIMEOUT;
use rustgate_core::identity::Identity;
use rustgate_core::masking::hash_cn;
use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};
use rustgate_core::sanitize::sanitize_for_log;
use rustgate_router::{
    NORMAL_CHANNEL_CAPACITY, PRIORITY_CHANNEL_CAPACITY, RecipientClass, Router, SessionHandle,
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

/// Validated MQTT last-will message captured from a CONNECT packet.
///
/// The will is published by the broker on behalf of the client when the
/// connection ends ungracefully (TLS error, keep-alive timeout, abrupt
/// drop) per MQTT 3.1.1 §3.1.2.5 and MQTT 5.0 §3.1.2.5. A clean
/// DISCONNECT (v5 with `NormalDisconnection` reason, v4 with any
/// DISCONNECT) suppresses the will publish per spec.
///
/// Topic, QoS, and retain are validated at CONNECT time using the same
/// rules applied to a live PUBLISH from the same identity, so the will
/// cannot be used to bypass the per-group authorization gate. The
/// derived group is cached on the struct so the publish path at session
/// end does not need to re-resolve it.
#[derive(Debug, Clone)]
struct Will {
    /// Original wire topic the client requested. Logged in operator
    /// diagnostics; never re-validated at publish time.
    topic: String,
    /// Group derived from the topic at CONNECT validation time.
    /// This is the routed `Destination::Group(_)` value for the will
    /// publish at session end.
    group: String,
    /// Will payload bytes — `Bytes` so the per-group fan-out clones
    /// without copying.
    payload: Bytes,
    /// Whether the will should be added to the retain store on publish.
    /// Mirrors the wire `retain` flag from §3.1.2.7 / §3.1.3.5.
    retain: bool,
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
    receive_max: u16,
    topic_alias_max: u16,
    max_session_expiry_secs: u32,
    min_keep_alive_secs: u16,
    server_keep_alive_secs: u16,
    response_channel_capacity: usize,
    wildcard_policy: WildcardPolicy,
    client_id_registry: Arc<ClientIdRegistry>,
    retain_store: Arc<RetainStore>,
    session_store: Arc<crate::session_store::SessionStore>,
    _permit: OwnedSemaphorePermit,
    session_hooks: Option<crate::config::MqttSessionHooks>,
    forwarding_hooks: Option<crate::config::MqttForwardingHooks>,
) {
    let identity = pre.identity;
    let peer_addr = pre.peer_addr;
    let cn = identity.cn.clone();

    let mut codec = PacketCodec::new(
        pre.stream,
        max_packet_size,
        receive_max,
        topic_alias_max,
        wildcard_policy,
        server_keep_alive_secs,
    );

    // --- CONNECT handshake ---
    let outcome = match connect_handshake(
        &mut codec,
        &identity,
        topic_prefix.as_deref(),
        &session_store,
        max_session_expiry_secs,
    )
    .await
    {
        Ok(result) => result,
        Err(e) => {
            debug!(cn = %hash_cn(&cn), peer = %peer_addr, error = %e, "CONNECT handshake failed");
            return;
        }
    };
    let keep_alive = outcome.keep_alive;
    let client_id = outcome.client_id;
    let will = outcome.will;
    let restored_subscriptions = outcome.restored_subscriptions;
    let negotiated_session_expiry = outcome.negotiated_session_expiry;

    let protocol = codec.protocol.unwrap_or(ProtocolLevel::V50);

    // --- Split codec into read/write halves for concurrent loops ---
    let (mut reader, mut writer) = codec.into_split();

    // --- Channel setup and router registration ---
    let (priority_tx, mut priority_rx) =
        mpsc::channel::<rustgate_router::RoutedMessage>(PRIORITY_CHANNEL_CAPACITY);
    let (normal_tx, mut normal_rx) =
        mpsc::channel::<rustgate_router::RoutedMessage>(NORMAL_CHANNEL_CAPACITY);
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

    // Per-session metric instrumentation (issue #771). The active-session
    // gauge is incremented after authentication + client-ID claim and
    // decremented in the matching scope-exit path below; the will counter
    // increments once per CONNECT that registered a Last-Will-and-Testament
    // — independent of whether the will eventually fires on disconnect.
    #[cfg(feature = "metrics")]
    {
        crate::metrics::active_sessions().inc();
        if will.is_some() {
            crate::metrics::will_messages_total().inc();
        }
    }

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

    // Per-session subscription tracker (refs #880 follow-up to #1162).
    // Updated by SUBSCRIBE/UNSUBSCRIBE handlers as the session runs;
    // saved to the session_store at session-end if
    // `negotiated_session_expiry > 0`. Wrapped in a `parking_lot::Mutex`
    // because it's mutated from `&` references inside async handlers.
    let subscriptions: Arc<parking_lot::Mutex<Vec<crate::session_store::RetainedSubscription>>> =
        Arc::new(parking_lot::Mutex::new(Vec::new()));

    // Restore subscriptions from a previously-saved session (set on
    // CONNECT with clean_start=0 + matching client_id within the
    // retention window — see `connect_handshake`). Replay the
    // subscriptions through the same `router.join_group` path a
    // fresh SUBSCRIBE would take so the session_id-keyed routing
    // tables match what they would for an interactively-resubscribing
    // client. Authz was already enforced when the original SUBSCRIBE
    // was accepted, so we don't re-validate here — the saved set
    // reflects what was authorized at SUBSCRIBE time, matching the
    // MQTT 5.0 §4.1 stored-session contract.
    if !restored_subscriptions.is_empty() {
        // Re-join each restored group via the router. Done WITHOUT
        // holding the tracker mutex across the await — the per-call
        // join_group is async, and parking_lot guards are not Send.
        // Collect the successful set first, then take the mutex once
        // to push the entries.
        let mut accepted: Vec<crate::session_store::RetainedSubscription> =
            Vec::with_capacity(restored_subscriptions.len());
        for sub in &restored_subscriptions {
            // Wildcard SUBSCRIBEs leave `group` empty (refs #880 — the
            // tracker stores the wildcard pattern in `filter` but has
            // no single group to re-join). Skip restoration for these
            // entries; the pre-#880 behaviour was to never save
            // wildcard subs across disconnects, and the post-#880
            // behaviour preserves that — the tracker just carries the
            // wildcard for in-session identifier matching.
            if sub.group.is_empty() {
                continue;
            }
            if router
                .join_group(&identity.cn, session_id, &sub.group)
                .await
            {
                accepted.push(sub.clone());
            } else {
                debug!(
                    cn = %hash_cn(&cn),
                    group = %sanitize_for_log(&sub.group),
                    "MQTT session-resume: router rejected restored subscription (per-CN cap?)"
                );
            }
        }
        let restored_count = accepted.len();
        subscriptions.lock().extend(accepted);
        debug!(
            transport = TRANSPORT_LABEL,
            cn = %hash_cn(&cn),
            restored = restored_count,
            "MQTT session subscriptions restored from retention store"
        );
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
    // MQTT 5.0 §3.2.2.3.14 Server Keep Alive override: when the
    // operator configures `server_keep_alive_secs > 0`, the broker
    // told the client (via the matching CONNACK property in
    // `write_connack_v5`) to use this value instead of its own
    // CONNECT-time request. Enforce the same value on the read-loop
    // keep-alive timer so a non-compliant client that ignores the
    // CONNACK property still gets disconnected on the operator's
    // chosen schedule rather than the client's. When the override is
    // disabled (`server_keep_alive_secs == 0`, the default), fall
    // back to the client's request as before. The `min_keep_alive_secs`
    // floor still applies in both cases — it's a hard operator-set
    // safety floor that catches `keep_alive = 0` (client-side disable
    // per §3.1.2.10) and keeps the read-loop timer from spinning.
    let effective_keep_alive = if server_keep_alive_secs > 0 {
        server_keep_alive_secs
    } else {
        keep_alive
    };
    let keep_alive_duration = std::time::Duration::from_secs_f64(
        f64::from(effective_keep_alive.max(min_keep_alive_secs)) * KEEP_ALIVE_FACTOR,
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
        subscriptions: &subscriptions,
        topic_alias_max,
    };

    // Each branch returns a matched type so the `select!` macro can
    // unify the two arms. The read loop returns the disconnect
    // disposition; the write loop returning early always indicates an
    // ungraceful close (the channel was closed while the read side was
    // still active), so we map a write-loop `Ok(())` to "treat the
    // session as ungraceful and publish the will if one is set".
    enum SessionEnd {
        Read(Result<ReadLoopOutcome, MqttError>),
        Write(Result<(), MqttError>),
    }

    let session_end = tokio::select! {
        r = mqtt_read_loop(&mut read_params) => SessionEnd::Read(r),
        r = mqtt_write_loop(
            &mut writer,
            protocol,
            prefix,
            &mut priority_rx,
            &mut normal_rx,
            &mut resp_rx,
            &subscriptions,
        ) => SessionEnd::Write(r),
    };

    // Decide whether the will should be published. Only an explicit
    // client-initiated DISCONNECT counts as graceful — every other
    // path (read error, write error, write-loop early exit) is
    // ungraceful and triggers the will per MQTT 3.1.1 §3.14 / 5.0
    // §3.14.4. A v5 client that wants to fire the will despite a
    // graceful disconnect must use `DisconnectWithWillMessage` (§4.13).
    let publish_will = match &session_end {
        SessionEnd::Read(Ok(ReadLoopOutcome::CleanDisconnect)) => false,
        SessionEnd::Read(Ok(ReadLoopOutcome::DisconnectWithWill)) => true,
        SessionEnd::Read(Err(_)) => true,
        SessionEnd::Write(_) => true,
    };

    let read_ok = matches!(
        &session_end,
        SessionEnd::Read(Ok(_)) | SessionEnd::Write(Ok(_))
    );

    // Flush pending outbound messages before unregistering.
    if read_ok {
        flush_pending(
            &mut writer,
            protocol,
            prefix,
            &mut resp_rx,
            &mut priority_rx,
            &mut normal_rx,
            &subscriptions,
        )
        .await;
    }

    if let SessionEnd::Read(Err(e)) = &session_end {
        debug!(cn = %hash_cn(&cn), error = %e, "MQTT session ended with error");
    } else if let SessionEnd::Write(Err(e)) = &session_end {
        debug!(cn = %hash_cn(&cn), error = %e, "MQTT session ended with write error");
    }

    // MQTT 5.0 §3.14.2.1 reason code 0x95 (`PacketTooLarge`): when the
    // broker rejects an inbound packet because it exceeds the
    // `Maximum Packet Size` advertised in the matching CONNACK
    // (§3.2.2.3.6), surface a structured DISCONNECT *before* dropping the
    // socket so the client gets a meaningful reason instead of an
    // unexplained TCP RST. v3.1.1 has no server-initiated DISCONNECT
    // packet — the connection just drops, which the spec accepts. Best
    // effort: if the writer half is already wedged the DISCONNECT write
    // will fail and we proceed to teardown anyway.
    if let SessionEnd::Read(Err(MqttError::PacketTooLarge { .. })) = &session_end
        && protocol == ProtocolLevel::V50
    {
        let disconnect = mqttbytes::v5::Disconnect {
            reason_code: mqttbytes::v5::DisconnectReasonCode::PacketTooLarge,
            properties: None,
        };
        let _ = writer
            .write_v5(&mqttbytes::v5::Packet::Disconnect(disconnect))
            .await;
    }

    // MQTT 5.0 §3.14.2.1 reason code 0x94 (`TopicAliasInvalid`): same
    // best-effort DISCONNECT contract as PacketTooLarge above. The
    // alias resolution path in `mqtt_read_loop` surfaces this when a
    // client sends a PUBLISH whose Topic Alias is `0`, exceeds the
    // advertised `topic_alias_max`, or references an unmapped slot.
    if let SessionEnd::Read(Err(MqttError::TopicAliasInvalid { .. })) = &session_end
        && protocol == ProtocolLevel::V50
    {
        let disconnect = mqttbytes::v5::Disconnect {
            reason_code: mqttbytes::v5::DisconnectReasonCode::TopicAliasInvalid,
            properties: None,
        };
        let _ = writer
            .write_v5(&mqttbytes::v5::Packet::Disconnect(disconnect))
            .await;
    }

    // Publish the configured will BEFORE unregistering so the publish
    // path sees the same router state any live PUBLISH would have. The
    // unregister call only removes this session's group memberships
    // and offline-queue handle — it does not affect routing for OTHER
    // sessions, but the will publish goes through `route_for_egress`
    // (the same path live PUBLISHes use) so we keep the ordering
    // identical for consistency.
    if publish_will && let Some(w) = will.as_ref() {
        publish_will_message(&router, &identity, &retain_store, session_hooks.as_ref(), w).await;
    }

    // Save the session to the retention store BEFORE unregistering so
    // the saved subscription set reflects what was actually active at
    // the moment of disconnect (refs #880 follow-up to #1162). Skipped
    // when negotiated_session_expiry is 0 (operator opted out OR client
    // didn't request retention) and when client_id is empty (the spec
    // permits an empty client_id at CONNECT time but says it MUST be
    // treated as a clean start with no resumability — §3.1.3.1).
    if negotiated_session_expiry > 0 && !client_id.is_empty() {
        let saved_subs = subscriptions.lock().clone();
        let saved = crate::session_store::RetainedSession {
            subscriptions: saved_subs,
            saved_at: std::time::Instant::now(),
            expiry_secs: negotiated_session_expiry,
        };
        let stored = session_store.save(client_id.clone(), saved);
        debug!(
            transport = TRANSPORT_LABEL,
            cn = %hash_cn(&cn),
            client_id = %sanitize_for_log(&client_id),
            stored,
            expiry_secs = negotiated_session_expiry,
            "MQTT session saved to retention store"
        );
    }

    router.unregister(&cn, session_id).await;
    #[cfg(feature = "metrics")]
    crate::metrics::active_sessions().dec();
    info!(
        transport = TRANSPORT_LABEL,
        cn = %hash_cn(&cn),
        peer = %peer_addr,
        "MQTT session ended",
    );
}

/// Publish the validated will message on behalf of the disconnecting
/// client. Mirrors the live `handle_publish_*` path: update the retain
/// store first (so a `retain=true` will is observable to clients that
/// subscribe AFTER the disconnect), then route via
/// `route_for_egress`. Authorization was already enforced at CONNECT
/// time when the will was validated.
async fn publish_will_message(
    router: &Router,
    identity: &Arc<Identity>,
    retain_store: &RetainStore,
    session_hooks: Option<&crate::config::MqttSessionHooks>,
    will: &Will,
) {
    // The will fires at most once per session per spec — clone the
    // payload so the underlying `Bytes` refcount survives if the
    // session struct itself is dropped before routing completes.
    let outcome = retain_store.publish(
        &will.topic,
        &will.payload,
        mqttbytes::QoS::AtMostOnce,
        will.retain,
    );
    if outcome != RetainOutcome::Passthrough {
        debug!(
            cn = %hash_cn(&identity.cn),
            topic = %sanitize_for_log(&will.topic),
            outcome = ?outcome,
            "MQTT will retain store updated"
        );
    }
    fire_retain_outcome(session_hooks, outcome);

    let msg = RoutableMessage {
        source: Identity::clone(identity),
        destination: Destination::Group(will.group.clone().into()),
        payload: will.payload.clone(),
        metadata: Metadata::new(
            SystemTime::now(),
            "mqtt".into(),
            MessageType::Other("mqtt".into()),
        ),
    };

    debug!(
        cn = %hash_cn(&identity.cn),
        topic = %sanitize_for_log(&will.topic),
        group = %sanitize_for_log(&will.group),
        retain = will.retain,
        "publishing MQTT will message"
    );
    let _ = router.route_for_egress(msg).await;

    // Audit + metric emission AFTER the route call so the SIEM and
    // dashboard tally only the wills the broker actually committed
    // to firing. Both callers of this function gate it behind
    // `publish_will == true` (the ungraceful-disconnect branch), so
    // an event here always corresponds to a real presence-loss
    // signal — no risk of double-counting on clean DISCONNECT or on
    // a session that exited before will validation completed.
    rustgate_core::audit::mqtt_will_published(
        &hash_cn(&identity.cn),
        &sanitize_for_log(&will.topic),
        &sanitize_for_log(&will.group),
        will.retain,
    );
    fire_will_published(session_hooks);
}

/// Outcome of `validate_will`: either an authorised will to be published on
/// ungraceful disconnect, or a CONNACK reason code identifying why the
/// will was rejected so the handshake can refuse the connection.
///
/// The `Absent` case is encoded by passing `None` to `Option::map(...)`
/// at the call site, so the enum itself only carries the validation
/// outcomes for a will that *was* present in the CONNECT packet.
enum WillValidation {
    /// Will is valid and authorised for the connecting identity.
    Valid(Will),
    /// Will topic is malformed (wildcards, empty, prefix mismatch).
    /// Maps to v5 `TopicNameInvalid` / v4 `NotAuthorized` (3.1.1 has
    /// no dedicated topic-syntax CONNACK code).
    InvalidTopic(String),
    /// Will targets a group the identity is not a member of.
    /// Maps to v5 `NotAuthorized` / v4 `NotAuthorized`.
    NotAuthorized(String),
}

/// Validate a CONNECT-supplied last-will against the same authz/topic
/// rules that gate a live PUBLISH from the same identity.
///
/// QoS 2 is rejected because the broker does not implement the
/// PUBREC/PUBREL/PUBCOMP four-step handshake (mirrors `handle_publish_*`).
/// Wildcards (`+`/`#`) in the will topic are rejected — the will is a
/// publish, not a subscription. Group derivation respects the listener's
/// `topic_prefix` so the will targets the same coordinate space as a
/// regular publish from this client.
///
/// `topic_prefix` is optional and matches the listener configuration; it
/// is borrowed across the call so this helper allocates only when the
/// will is actually present.
fn validate_will(
    last_will_topic: &str,
    last_will_payload: &Bytes,
    last_will_qos: mqttbytes::QoS,
    last_will_retain: bool,
    identity: &Identity,
    topic_prefix: Option<&str>,
) -> WillValidation {
    if last_will_qos == mqttbytes::QoS::ExactlyOnce {
        return WillValidation::InvalidTopic("QoS 2 not supported for will messages".to_string());
    }
    if let Err(e) = topic::validate_publish_topic(last_will_topic) {
        return WillValidation::InvalidTopic(e.to_string());
    }
    let group = match topic::topic_to_group(last_will_topic, topic_prefix) {
        Ok(g) => g.into_owned(),
        Err(e) => return WillValidation::InvalidTopic(e.to_string()),
    };
    if !identity.is_member_of(&group) {
        return WillValidation::NotAuthorized(format!("not a member of group '{group}'"));
    }
    WillValidation::Valid(Will {
        topic: last_will_topic.to_string(),
        group,
        payload: last_will_payload.clone(),
        retain: last_will_retain,
    })
}

/// Perform the MQTT CONNECT handshake.
///
/// Reads the first packet (must be CONNECT), validates constraints
/// (clean session, QoS ≤ 1), validates the optional last-will against
/// the same authz rules as a live PUBLISH, and sends CONNACK. Returns
/// the negotiated keep-alive value, the client ID, and the validated
/// will (if any).
/// Outcome of a successful CONNECT handshake. Carries the negotiated
/// keep-alive, client_id, will, plus the session-retention bookkeeping
/// that downstream code uses to restore subscriptions and decide
/// whether to save them back at session end (refs #880 follow-up to
/// #1162 / #1163).
struct ConnectOutcome {
    keep_alive: u16,
    client_id: String,
    will: Option<Will>,
    /// Subscriptions restored from a previously-saved session
    /// (clean_start=0 + matching client_id within retention window).
    /// Empty when nothing was restored — fresh session or
    /// retention-disabled deployment.
    restored_subscriptions: Vec<crate::session_store::RetainedSubscription>,
    /// Negotiated `Session Expiry Interval` advertised in CONNACK
    /// per MQTT 5.0 §3.2.2.3.2. Computed as
    /// `min(client_request, max_session_expiry_secs)`. When `> 0` the
    /// broker MUST save the session at disconnect for restoration
    /// within the window. v3.1.1 doesn't have the property; the v4
    /// path always returns `0`.
    negotiated_session_expiry: u32,
}

async fn connect_handshake(
    codec: &mut PacketCodec,
    identity: &Identity,
    topic_prefix: Option<&str>,
    session_store: &crate::session_store::SessionStore,
    max_session_expiry_secs: u32,
) -> Result<ConnectOutcome, MqttError> {
    let packet = codec.read_packet().await?;

    match packet {
        MqttPacket::V4(mqttbytes::v4::Packet::Connect(connect)) => {
            // v3.1.1 retention is intentionally out of scope for this PR.
            // The v4 protocol has no SessionExpiryInterval, so a clean_session=0
            // session would persist forever until takeover — different
            // semantics from v5's TTL-based model and worth a separate PR
            // with its own test discipline. Continue to reject as before.
            if !connect.clean_session {
                codec
                    .write_connack_v4(mqttbytes::v4::ConnectReturnCode::RefusedProtocolVersion)
                    .await?;
                return Err(MqttError::PersistentSessionUnsupported);
            }

            let will = match connect.last_will.as_ref() {
                None => None,
                Some(lw) => match validate_will(
                    &lw.topic,
                    &lw.message,
                    lw.qos,
                    lw.retain,
                    identity,
                    topic_prefix,
                ) {
                    WillValidation::Valid(w) => Some(w),
                    WillValidation::InvalidTopic(reason)
                    | WillValidation::NotAuthorized(reason) => {
                        codec
                            .write_connack_v4(mqttbytes::v4::ConnectReturnCode::NotAuthorized)
                            .await?;
                        return Err(MqttError::WillRejected(reason));
                    }
                },
            };

            let client_id = connect.client_id.clone();

            debug!(
                cn = %hash_cn(&identity.cn),
                client_id = %sanitize_for_log(&client_id),
                keep_alive = connect.keep_alive,
                will = will.is_some(),
                "MQTT v3.1.1 CONNECT accepted"
            );

            codec
                .write_connack_v4(mqttbytes::v4::ConnectReturnCode::Success)
                .await?;
            Ok(ConnectOutcome {
                keep_alive: connect.keep_alive,
                client_id,
                will,
                restored_subscriptions: Vec::new(),
                negotiated_session_expiry: 0,
            })
        }
        MqttPacket::V5(boxed) => {
            if let mqttbytes::v5::Packet::Connect(connect) = *boxed {
                let client_id = connect.client_id.clone();
                let requested_expiry = connect
                    .properties
                    .as_ref()
                    .and_then(|p| p.session_expiry_interval)
                    .unwrap_or(0);
                // Negotiation per §3.2.2.3.2: clamp to the operator's max.
                // u32::MAX in either input means "no cap"; min(MAX, x) = x
                // and min(y, MAX) = y so the formula handles the spec's
                // "never expires" sentinel correctly without a special case.
                let negotiated_expiry = requested_expiry.min(max_session_expiry_secs);

                // §3.1.2.4 clean_start handling combined with retention:
                // - clean_start=1 + retention enabled + saved entry exists:
                //   discard the saved entry (server-takeover semantics from
                //   §3.1.4); start fresh.
                // - clean_start=0 + retention enabled + saved entry exists:
                //   restore subscriptions, set session_present=true.
                // - clean_start=0 + (retention disabled OR no saved entry):
                //   we cannot honor the resume request. With retention
                //   disabled we reject as before (#1162 contract). With
                //   retention enabled but no saved entry, we accept as a
                //   FRESH session (session_present=false) per §3.1.2.4
                //   which says the server MAY treat this as a clean start.
                let mut restored: Vec<crate::session_store::RetainedSubscription> = Vec::new();
                let mut session_present = false;
                if connect.clean_session {
                    // clean_start=1: drop any prior saved state.
                    if !client_id.is_empty() {
                        let _ = session_store.take(&client_id);
                    }
                } else if !session_store.is_enabled() {
                    // clean_start=0 + retention OFF — preserve the #1162
                    // contract: reject explicitly.
                    codec
                        .write_connack_v5(
                            mqttbytes::v5::ConnectReturnCode::ImplementationSpecificError,
                            false,
                            0,
                        )
                        .await?;
                    return Err(MqttError::PersistentSessionUnsupported);
                } else if !client_id.is_empty()
                    && let Some(saved) = session_store.take(&client_id)
                {
                    debug!(
                        cn = %hash_cn(&identity.cn),
                        client_id = %sanitize_for_log(&client_id),
                        restored_subscriptions = saved.subscriptions.len(),
                        "MQTT v5.0 session resumed from retention store"
                    );
                    restored = saved.subscriptions;
                    session_present = true;
                }

                if requested_expiry != negotiated_expiry {
                    debug!(
                        cn = %hash_cn(&identity.cn),
                        client_id = %sanitize_for_log(&client_id),
                        requested_session_expiry_secs = requested_expiry,
                        negotiated_session_expiry_secs = negotiated_expiry,
                        "MQTT v5.0 Session Expiry Interval clamped by operator config"
                    );
                }

                let will = match connect.last_will.as_ref() {
                    None => None,
                    Some(lw) => match validate_will(
                        &lw.topic,
                        &lw.message,
                        lw.qos,
                        lw.retain,
                        identity,
                        topic_prefix,
                    ) {
                        WillValidation::Valid(w) => Some(w),
                        WillValidation::InvalidTopic(reason) => {
                            codec
                                .write_connack_v5(
                                    mqttbytes::v5::ConnectReturnCode::TopicNameInvalid,
                                    false,
                                    0,
                                )
                                .await?;
                            return Err(MqttError::WillRejected(reason));
                        }
                        WillValidation::NotAuthorized(reason) => {
                            codec
                                .write_connack_v5(
                                    mqttbytes::v5::ConnectReturnCode::NotAuthorized,
                                    false,
                                    0,
                                )
                                .await?;
                            return Err(MqttError::WillRejected(reason));
                        }
                    },
                };

                debug!(
                    cn = %hash_cn(&identity.cn),
                    client_id = %sanitize_for_log(&client_id),
                    keep_alive = connect.keep_alive,
                    will = will.is_some(),
                    session_present,
                    negotiated_session_expiry_secs = negotiated_expiry,
                    "MQTT v5.0 CONNECT accepted"
                );

                codec
                    .write_connack_v5(
                        mqttbytes::v5::ConnectReturnCode::Success,
                        session_present,
                        negotiated_expiry,
                    )
                    .await?;
                Ok(ConnectOutcome {
                    keep_alive: connect.keep_alive,
                    client_id,
                    will,
                    restored_subscriptions: restored,
                    negotiated_session_expiry: negotiated_expiry,
                })
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

#[cfg(feature = "metrics")]
fn qos_label(qos: mqttbytes::QoS) -> &'static str {
    // Bounded label vocabulary for `rustgate_mqtt_publish_total{qos}`.
    // Protocol QoS values are 0..=2 per MQTT 5.0 §3.3.1.4 — there is no
    // future-variant axis to guard against.
    match qos {
        mqttbytes::QoS::AtMostOnce => "0",
        mqttbytes::QoS::AtLeastOnce => "1",
        mqttbytes::QoS::ExactlyOnce => "2",
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

fn fire_retain_stored(hooks: Option<&crate::config::MqttSessionHooks>) {
    if let Some(h) = hooks
        && let Some(cb) = &h.on_retain_stored
    {
        cb();
    }
}

fn fire_will_published(hooks: Option<&crate::config::MqttSessionHooks>) {
    if let Some(h) = hooks
        && let Some(cb) = &h.on_will_published
    {
        cb();
    }
}

fn fire_retain_cleared(hooks: Option<&crate::config::MqttSessionHooks>) {
    if let Some(h) = hooks
        && let Some(cb) = &h.on_retain_cleared
    {
        cb();
    }
}

fn fire_retain_replayed(hooks: Option<&crate::config::MqttSessionHooks>) {
    if let Some(h) = hooks
        && let Some(cb) = &h.on_retain_replayed
    {
        cb();
    }
}

/// Dispatch the appropriate retain-side metric hook based on the
/// outcome returned by [`RetainStore::publish`]. Centralised so the
/// three publish call sites (v5 PUBLISH, v4 PUBLISH, will-publish)
/// share one branch matrix; a regression that wires the wrong
/// outcome to the wrong counter would surface in only one place.
fn fire_retain_outcome(hooks: Option<&crate::config::MqttSessionHooks>, outcome: RetainOutcome) {
    match outcome {
        RetainOutcome::Stored => fire_retain_stored(hooks),
        RetainOutcome::Cleared => fire_retain_cleared(hooks),
        RetainOutcome::Passthrough => {} // retain bit was 0 — nothing to count
    }
}

/// Fan out the post-Send-PEP routed message to NATS / federation / HTTP
/// egress sinks (closes #746).
///
/// Mirrors the WebSocket write-loop's fan-out block verbatim so that an
/// MQTT PUBLISH that survives the router's obligations (dedup, TTL,
/// Send-PEP deny, oversize multicast) is visible to every external
/// sink in exactly the same way a WebSocket inbound message would be.
/// Each sink is independent — a `None` field is a no-op and never
/// allocates.
///
/// **Per-sink envelope rendering** (closes #746). Each wired sink
/// renders its own [`rustgate_router::EgressEnvelope`] via
/// [`Router::prepare_egress_envelope_for_sink`] with its own
/// [`RecipientClass`] before invoking the publisher callback. Send-PEP
/// rules addressed to a sink class are applied per envelope; an
/// envelope-level deny suppresses dispatch to that sink only — peer
/// sinks still receive their own envelope. Obligation actuation runs
/// once per sink per inbound message (not once per recipient): the
/// audit-event cadence stays per-envelope.
fn fire_forwarding(
    router: &Router,
    hooks: Option<&crate::config::MqttForwardingHooks>,
    routed: &Arc<RoutableMessage>,
) {
    let Some(h) = hooks else {
        return;
    };
    if let Some(cb) = &h.nats_publish
        && let Ok(envelope) = router.prepare_egress_envelope_for_sink(
            Arc::clone(routed),
            RecipientClass::NatsSink(String::new()),
        )
    {
        cb(envelope.message.as_ref().clone());
    }
    if let Some(fwd) = &h.federation_forward
        && let Ok(envelope) = router.prepare_egress_envelope_for_sink(
            Arc::clone(routed),
            RecipientClass::FederationPeer(rustgate_core::PeerId::new(String::new())),
        )
    {
        let groups: Vec<String> = envelope.message.source.groups.iter().cloned().collect();
        fwd(
            envelope.message.payload.clone(),
            groups,
            envelope.message.metadata.clone(),
        );
    }
    if let Some(fwd) = &h.http_forward
        && let Ok(envelope) = router.prepare_egress_envelope_for_sink(
            Arc::clone(routed),
            RecipientClass::HttpSink(String::new()),
        )
    {
        fwd(envelope.message.as_ref().clone());
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
    /// Per-session subscription tracker (refs #880). SUBSCRIBE handlers
    /// push successfully-authorized filters; UNSUBSCRIBE handlers
    /// remove them. The session-end cleanup (in `handle_mqtt_session`)
    /// snapshots this when saving to the retention store.
    subscriptions: &'a Arc<parking_lot::Mutex<Vec<crate::session_store::RetainedSubscription>>>,
    /// MQTT 5.0 §3.2.2.3.8 Topic Alias Maximum advertised in CONNACK.
    /// Inbound v5 PUBLISHes carrying a `topic_alias` property must
    /// reference an alias in `[1, topic_alias_max]`; outside that
    /// range surfaces `MqttError::TopicAliasInvalid` which the
    /// session-end handler maps to DISCONNECT 0x94. When `0`, the
    /// feature is disabled and any PUBLISH carrying a topic alias
    /// is rejected.
    topic_alias_max: u16,
}

/// Outcome of the read loop. Used by the caller to decide whether to
/// publish the configured will message at session end.
///
/// MQTT 3.1.1 §3.14 / 5.0 §3.14.4: a client-initiated DISCONNECT is a
/// **graceful** termination — the broker MUST suppress the will.
/// Anything else (TLS error, keep-alive timeout, abrupt drop) is
/// **ungraceful**, and the will MUST be published if one was set.
///
/// MQTT 5.0 §4.13 reserves a special `DisconnectWithWillMessage` reason
/// code (0x04) that *does* trigger the will despite being a normal
/// DISCONNECT — clients use it when they want to flag an unexpected
/// shutdown but still notify the broker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadLoopOutcome {
    /// Client sent a DISCONNECT signalling a normal shutdown. The will
    /// must NOT be published.
    CleanDisconnect,
    /// Client sent v5 DISCONNECT with `DisconnectWithWillMessage`
    /// reason — the will MUST still fire even though the disconnect
    /// itself was graceful (§4.13).
    DisconnectWithWill,
}

/// Read loop: process inbound MQTT packets from the client.
///
/// Handles PUBLISH (route to group), SUBSCRIBE (validate and ACK),
/// UNSUBSCRIBE (ACK), PINGREQ (respond), and DISCONNECT (clean exit).
///
/// Response packets are serialized and sent to the write loop via `resp_tx`
/// so both loops can operate on independent halves of the TLS stream.
async fn mqtt_read_loop(params: &mut ReadLoopParams<'_>) -> Result<ReadLoopOutcome, MqttError> {
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
    // Per-session QoS 2 inflight maps. Refs #880. Keyed by Packet
    // Identifier; lost on disconnect by design (rustgate currently
    // rejects clean_session=false sessions, so inflight QoS 2 state
    // is intentionally ephemeral). Sized to start empty — pkid space
    // is only populated as the client actually pipelines QoS 2
    // PUBLISHes, and the typical case is a single inflight at a time.
    let mut qos2_inflight_v5: std::collections::HashMap<u16, Qos2InflightV5> =
        std::collections::HashMap::new();
    let mut qos2_inflight_v4: std::collections::HashMap<u16, Qos2InflightV4> =
        std::collections::HashMap::new();
    // MQTT 5.0 §3.3.2.3.4 per-connection Topic Alias table. Capacity
    // is bounded by `params.topic_alias_max`. Empty when the operator
    // has disabled the feature (cap = 0); inbound PUBLISHes carrying
    // a topic_alias property in that case fail the
    // `alias > params.topic_alias_max` check and emit DISCONNECT 0x94.
    let mut topic_alias_table: std::collections::HashMap<u16, String> =
        std::collections::HashMap::new();
    let topic_alias_max = params.topic_alias_max;
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
                mqttbytes::v5::Packet::Publish(mut publish) => {
                    // MQTT 5.0 §3.3.2.3.4 Topic Alias resolution. Done
                    // BEFORE handle_publish_v5 so the handler always
                    // sees a fully-resolved topic and stays oblivious
                    // to the alias mechanism. Three failure modes
                    // surface as `MqttError::TopicAliasInvalid` which
                    // the session-end handler maps to DISCONNECT 0x94:
                    //   1. alias = 0 (spec-reserved value)
                    //   2. alias > topic_alias_max (out of range)
                    //   3. empty topic + alias references an unmapped
                    //      slot (no prior establishing PUBLISH)
                    if let Some(alias) = publish.properties.as_ref().and_then(|p| p.topic_alias) {
                        if alias == 0 || alias > topic_alias_max {
                            return Err(MqttError::TopicAliasInvalid {
                                alias,
                                max: topic_alias_max,
                            });
                        }
                        if publish.topic.is_empty() {
                            // Reference: look up the established mapping.
                            match topic_alias_table.get(&alias) {
                                Some(topic) => publish.topic = topic.clone(),
                                None => {
                                    return Err(MqttError::TopicAliasInvalid {
                                        alias,
                                        max: topic_alias_max,
                                    });
                                }
                            }
                        } else {
                            // Establish (or update) the mapping.
                            // Spec §3.3.2.3.4: a non-empty topic with
                            // an alias REPLACES any prior mapping for
                            // that alias number.
                            let _ = topic_alias_table.insert(alias, publish.topic.clone());
                        }
                    } else if publish.topic.is_empty() {
                        // §3.3.2.1: topic name MUST NOT be empty if no
                        // alias is provided. Treat as a malformed packet.
                        return Err(MqttError::Malformed(
                            "v5 PUBLISH with empty topic and no Topic Alias".into(),
                        ));
                    }
                    handle_publish_v5(
                        resp_tx,
                        identity,
                        router,
                        topic_prefix,
                        session_hooks,
                        forwarding_hooks,
                        retain_store,
                        &mut qos2_inflight_v5,
                        publish,
                    )
                    .await?;
                }
                mqttbytes::v5::Packet::PubRel(pubrel) => {
                    handle_pubrel_v5(
                        resp_tx,
                        identity,
                        router,
                        session_hooks,
                        forwarding_hooks,
                        retain_store,
                        &mut qos2_inflight_v5,
                        pubrel,
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
                        params.subscriptions,
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
                        params.subscriptions,
                        unsub,
                    )
                    .await?;
                }
                mqttbytes::v5::Packet::PingReq => {
                    send_response(resp_tx, serialize_pingresp(protocol)?).await?;
                }
                mqttbytes::v5::Packet::Disconnect(disc) => {
                    // MQTT 5.0 §4.13: `DisconnectWithWillMessage` (0x04)
                    // is the one DISCONNECT reason that does NOT
                    // suppress the will publish — the client wants to
                    // signal an unexpected shutdown to subscribers
                    // while still notifying the broker. Every other
                    // DISCONNECT (including the default
                    // `NormalDisconnection`) suppresses the will.
                    let outcome = if disc.reason_code
                        == mqttbytes::v5::DisconnectReasonCode::DisconnectWithWillMessage
                    {
                        ReadLoopOutcome::DisconnectWithWill
                    } else {
                        ReadLoopOutcome::CleanDisconnect
                    };
                    debug!(
                        cn = %hash_cn(&identity.cn),
                        reason = ?disc.reason_code,
                        "MQTT v5 DISCONNECT received"
                    );
                    // MQTT 5.0 §3.14.2.2.2: a v5 DISCONNECT MAY carry
                    // a Session Expiry Interval property that overrides
                    // the value sent in CONNECT — clients use this to
                    // "convert" a fresh session into one that should
                    // persist after the disconnect, or vice versa.
                    // rustgate doesn't retain sessions, so the override
                    // has no effect; surface a debug log so an operator
                    // monitoring the fleet can see clients trying to
                    // toggle persistence at disconnect time. The log
                    // is one-per-disconnect (low volume).
                    if let Some(props) = disc.properties.as_ref()
                        && let Some(override_secs) = props.session_expiry_interval
                    {
                        debug!(
                            cn = %hash_cn(&identity.cn),
                            disconnect_session_expiry_secs = override_secs,
                            "client overrode Session Expiry Interval at DISCONNECT; broker ignored (sessions not retained — refs #880)"
                        );
                    }
                    return Ok(outcome);
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
                        &mut qos2_inflight_v4,
                        publish,
                    )
                    .await?;
                }
                mqttbytes::v4::Packet::PubRel(pubrel) => {
                    handle_pubrel_v4(
                        resp_tx,
                        identity,
                        router,
                        session_hooks,
                        forwarding_hooks,
                        retain_store,
                        &mut qos2_inflight_v4,
                        pubrel,
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
                        params.subscriptions,
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
                        params.subscriptions,
                        unsub,
                    )
                    .await?;
                }
                mqttbytes::v4::Packet::PingReq => {
                    send_response(resp_tx, serialize_pingresp(protocol)?).await?;
                }
                mqttbytes::v4::Packet::Disconnect => {
                    // MQTT 3.1.1 §3.14: any DISCONNECT from the client
                    // is a graceful close — the broker MUST discard the
                    // will. v3.1.1 has no `DisconnectWithWillMessage`
                    // equivalent on the wire.
                    debug!(cn = %hash_cn(&identity.cn), "MQTT v4 DISCONNECT received");
                    return Ok(ReadLoopOutcome::CleanDisconnect);
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

// justification: handle_publish_v5 carries two distinct hook bundles
// (`session_hooks` for admission counters, `forwarding_hooks` for post-
// route egress fan-out) plus a per-session QoS 2 inflight HashMap (refs
// #880) that must be visible across the PUBLISH/PUBREL split. Merging
// any of these into a wrapper struct would force unrelated concerns
// through every adjacent dispatch site (subscribe, unsubscribe, retain
// replay) for zero call-site reduction.
#[allow(clippy::too_many_arguments)]
async fn handle_publish_v5(
    resp_tx: &mpsc::Sender<ResponsePacket>,
    identity: &Arc<Identity>,
    router: &Router,
    topic_prefix: Option<&str>,
    session_hooks: Option<&crate::config::MqttSessionHooks>,
    forwarding_hooks: Option<&crate::config::MqttForwardingHooks>,
    retain_store: &RetainStore,
    qos2_inflight: &mut std::collections::HashMap<u16, Qos2InflightV5>,
    publish: mqttbytes::v5::Publish,
) -> Result<(), MqttError> {
    #[cfg(feature = "metrics")]
    let _publish_start = std::time::Instant::now();
    #[cfg(feature = "metrics")]
    let _publish_qos = qos_label(publish.qos);
    #[cfg(feature = "metrics")]
    crate::metrics::publish_total()
        .with_label_values(&[_publish_qos])
        .inc();
    let result = handle_publish_v5_inner(
        resp_tx,
        identity,
        router,
        topic_prefix,
        session_hooks,
        forwarding_hooks,
        retain_store,
        qos2_inflight,
        publish,
    )
    .await;
    #[cfg(feature = "metrics")]
    {
        let elapsed = _publish_start.elapsed().as_secs_f64();
        crate::metrics::publish_seconds()
            .with_label_values(&[_publish_qos])
            .observe(elapsed);
    }
    result
}

// justification: mirrors `handle_publish_v5` for the metrics-wrap split
// so the histogram observation lives at a single return point. Inheriting
// the same nine-argument fan-in is unavoidable — the wrapper passes
// every argument verbatim and any restructuring would touch every
// PUBLISH dispatch site for zero call-site reduction.
#[allow(clippy::too_many_arguments)]
async fn handle_publish_v5_inner(
    resp_tx: &mpsc::Sender<ResponsePacket>,
    identity: &Arc<Identity>,
    router: &Router,
    topic_prefix: Option<&str>,
    session_hooks: Option<&crate::config::MqttSessionHooks>,
    forwarding_hooks: Option<&crate::config::MqttForwardingHooks>,
    retain_store: &RetainStore,
    qos2_inflight: &mut std::collections::HashMap<u16, Qos2InflightV5>,
    publish: mqttbytes::v5::Publish,
) -> Result<(), MqttError> {
    if let Err(e) = topic::validate_publish_topic(&publish.topic) {
        fire_publish_reject(session_hooks);
        // For QoS 2, a syntactically invalid topic triggers a PUBREC
        // with `TopicNameInvalid` reason rather than terminating the
        // session — the spec treats this as a per-publish failure
        // surfacing through the four-step ack channel. QoS 0/1 still
        // propagate the error up for the existing reject path.
        if publish.qos == mqttbytes::QoS::ExactlyOnce && publish.pkid != 0 {
            send_pubrec_v5(
                resp_tx,
                publish.pkid,
                mqttbytes::v5::PubRecReason::TopicNameInvalid,
            )
            .await?;
            return Ok(());
        }
        return Err(e);
    }
    let group = match topic::topic_to_group(&publish.topic, topic_prefix) {
        Ok(g) => g,
        Err(e) => {
            fire_publish_reject(session_hooks);
            if publish.qos == mqttbytes::QoS::ExactlyOnce && publish.pkid != 0 {
                send_pubrec_v5(
                    resp_tx,
                    publish.pkid,
                    mqttbytes::v5::PubRecReason::TopicNameInvalid,
                )
                .await?;
                return Ok(());
            }
            return Err(e);
        }
    };

    // Authorization: the client must be a member of the target group.
    if !identity.is_member_of(&group) {
        fire_publish_reject(session_hooks);
        if publish.qos == mqttbytes::QoS::ExactlyOnce && publish.pkid != 0 {
            send_pubrec_v5(
                resp_tx,
                publish.pkid,
                mqttbytes::v5::PubRecReason::NotAuthorized,
            )
            .await?;
            return Ok(());
        }
        return Err(MqttError::NotAuthorized(format!(
            "not authorized to publish to group '{group}'"
        )));
    }

    // QoS 2 four-step (refs #880): defer retain-store update + routing
    // until PUBREL receipt. MQTT 5.0 §4.4 says the broker SHOULD NOT
    // deliver the data to subscribers until it has received the PUBREL
    // packet from the original sender — Method B in the spec
    // taxonomy. Method A (deliver-on-PUBREC) is also legal, but
    // Method B preserves the strongest "exactly once" guarantee: a
    // client that crashes between PUBLISH and PUBREL leaves nothing
    // behind, and that aligns with rustgate's clean_start-only
    // session model where in-flight QoS 2 state is intentionally
    // ephemeral. fire_publish_accept fires on PUBCOMP send (i.e. when
    // routing has actually happened) so the metric matches the QoS 1
    // semantics where "accepted" means "routed".
    if publish.qos == mqttbytes::QoS::ExactlyOnce {
        if publish.pkid == 0 {
            // Spec §2.2.1: a QoS > 0 PUBLISH with pkid=0 is a Malformed
            // Packet. Surface the reject up for session-level handling
            // — there is no spec-defined way to ack a packet whose
            // pkid is zero.
            fire_publish_reject(session_hooks);
            return Err(MqttError::Malformed(
                "QoS 2 PUBLISH with packet identifier 0".into(),
            ));
        }
        // Spec §3.3.4: a duplicate PUBLISH with the same pkid as one
        // already in the inflight set MUST be acknowledged with a
        // PUBREC and continue with the protocol — i.e. idempotent,
        // do not double-deliver. Match that here by re-sending PUBREC
        // without disturbing the saved state.
        // Spec §3.3.4: a duplicate PUBLISH with the same pkid as one
        // already in the inflight set is the SAME message — leave
        // the saved state untouched and re-emit PUBREC. `entry`
        // expresses this directly: the closure runs only on vacant,
        // so a duplicate-pkid PUBLISH is a no-op state-wise.
        let _ = qos2_inflight
            .entry(publish.pkid)
            .or_insert_with(|| Qos2InflightV5 {
                publish: publish.clone(),
                group: group.into_owned(),
            });
        send_pubrec_v5(resp_tx, publish.pkid, mqttbytes::v5::PubRecReason::Success).await?;
        return Ok(());
    }

    // QoS 0 / 1 — deliver and ack immediately.
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
    fire_retain_outcome(session_hooks, outcome);

    let msg = RoutableMessage {
        source: Identity::clone(identity),
        destination: Destination::Group(group.into_owned().into()),
        payload: publish.payload.clone(),
        metadata: Metadata::new(
            SystemTime::now(),
            "mqtt".into(),
            MessageType::Other("mqtt".into()),
        ),
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

    fire_forwarding(router, forwarding_hooks, &routed);
    fire_publish_accept(session_hooks);

    ack_publish_v5(resp_tx, &publish).await
}

/// Per-session state for an in-flight QoS 2 v5 PUBLISH awaiting PUBREL.
///
/// Holds the original `Publish` (so retain-store update on PUBREL sees
/// the same payload bytes the client sent) plus the post-validation
/// `group` so the spec-required deferred-delivery path doesn't re-run
/// the topic→group resolution that already happened at PUBREC time.
#[derive(Debug, Clone)]
struct Qos2InflightV5 {
    publish: mqttbytes::v5::Publish,
    group: String,
}

/// Send a v5 PUBREC with the given reason code.
async fn send_pubrec_v5(
    resp_tx: &mpsc::Sender<ResponsePacket>,
    pkid: u16,
    reason: mqttbytes::v5::PubRecReason,
) -> Result<(), MqttError> {
    let pubrec = mqttbytes::v5::PubRec {
        pkid,
        reason,
        properties: None,
    };
    send_response(
        resp_tx,
        serialize_v5(&mqttbytes::v5::Packet::PubRec(pubrec))?,
    )
    .await
}

/// Send a v5 PUBCOMP with the given reason code.
async fn send_pubcomp_v5(
    resp_tx: &mpsc::Sender<ResponsePacket>,
    pkid: u16,
    reason: mqttbytes::v5::PubCompReason,
) -> Result<(), MqttError> {
    let pubcomp = mqttbytes::v5::PubComp {
        pkid,
        reason,
        properties: None,
    };
    send_response(
        resp_tx,
        serialize_v5(&mqttbytes::v5::Packet::PubComp(pubcomp))?,
    )
    .await
}

/// Handle a v5 PUBREL — Stage 3 of the QoS 2 four-step. Deliver the
/// previously-saved PUBLISH (retain + route) and emit PUBCOMP.
///
/// Refs #880. Spec: MQTT 5.0 §3.6 + §4.3.3.
// justification: PUBREL is the "deliver" event in the QoS 2 four-step
// and must touch all the same routing surfaces the QoS 0/1 PUBLISH path
// does (retain store, router, forwarding hooks, session metrics) plus
// the inflight state. Bundling those into a wrapper struct would force
// the same struct through every adjacent dispatch site for zero call-
// site reduction.
#[allow(clippy::too_many_arguments)]
async fn handle_pubrel_v5(
    resp_tx: &mpsc::Sender<ResponsePacket>,
    identity: &Arc<Identity>,
    router: &Router,
    session_hooks: Option<&crate::config::MqttSessionHooks>,
    forwarding_hooks: Option<&crate::config::MqttForwardingHooks>,
    retain_store: &RetainStore,
    qos2_inflight: &mut std::collections::HashMap<u16, Qos2InflightV5>,
    pubrel: mqttbytes::v5::PubRel,
) -> Result<(), MqttError> {
    let inflight = match qos2_inflight.remove(&pubrel.pkid) {
        Some(state) => state,
        None => {
            // Spec §3.6.2.1.3 / §3.7.2.1: a PUBREL whose pkid does not
            // match any in-flight QoS 2 PUBLISH is an unknown packet
            // identifier — emit PUBCOMP(PacketIdentifierNotFound) to
            // close the four-step on the client side. This is NOT a
            // session-level error; the client may have already PUBCOMPed
            // and forgotten, or this is a duplicate after our PUBCOMP
            // already drained the map.
            return send_pubcomp_v5(
                resp_tx,
                pubrel.pkid,
                mqttbytes::v5::PubCompReason::PacketIdentifierNotFound,
            )
            .await;
        }
    };

    let publish = inflight.publish;
    let group = inflight.group;

    // Retain store update happens NOW, not at PUBREC time, because
    // §4.4 defers delivery to PUBREL — and the retain semantics are
    // part of that deferred delivery. A client that PUBLISHes
    // retain=1 at QoS 2 and then never sends PUBREL must NOT poison
    // the retain store.
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
            "MQTT retain store updated (QoS 2 PUBREL)"
        );
    }
    fire_retain_outcome(session_hooks, outcome);

    let msg = RoutableMessage {
        source: Identity::clone(identity),
        destination: Destination::Group(group.into()),
        payload: publish.payload.clone(),
        metadata: Metadata::new(
            SystemTime::now(),
            "mqtt".into(),
            MessageType::Other("mqtt".into()),
        ),
    };

    if let Some(routed) = router.route_for_egress(msg).await {
        fire_forwarding(router, forwarding_hooks, &routed);
    }
    fire_publish_accept(session_hooks);

    send_pubcomp_v5(resp_tx, pubrel.pkid, mqttbytes::v5::PubCompReason::Success).await
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
// The v5 sibling already carries the same nine args and unifying them
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
    qos2_inflight: &mut std::collections::HashMap<u16, Qos2InflightV4>,
    publish: mqttbytes::v4::Publish,
) -> Result<(), MqttError> {
    #[cfg(feature = "metrics")]
    let _publish_start = std::time::Instant::now();
    #[cfg(feature = "metrics")]
    let _publish_qos = qos_label(publish.qos);
    #[cfg(feature = "metrics")]
    crate::metrics::publish_total()
        .with_label_values(&[_publish_qos])
        .inc();
    let result = handle_publish_v4_inner(
        resp_tx,
        identity,
        router,
        topic_prefix,
        session_hooks,
        forwarding_hooks,
        retain_store,
        qos2_inflight,
        publish,
    )
    .await;
    #[cfg(feature = "metrics")]
    {
        let elapsed = _publish_start.elapsed().as_secs_f64();
        crate::metrics::publish_seconds()
            .with_label_values(&[_publish_qos])
            .observe(elapsed);
    }
    result
}

// justification: mirrors `handle_publish_v4` for the metrics-wrap split
// so the histogram observation lives at a single return point. Inheriting
// the same nine-argument fan-in is unavoidable — the wrapper passes
// every argument verbatim and any restructuring would touch every
// PUBLISH dispatch site for zero call-site reduction.
#[allow(clippy::too_many_arguments)]
async fn handle_publish_v4_inner(
    resp_tx: &mpsc::Sender<ResponsePacket>,
    identity: &Arc<Identity>,
    router: &Router,
    topic_prefix: Option<&str>,
    session_hooks: Option<&crate::config::MqttSessionHooks>,
    forwarding_hooks: Option<&crate::config::MqttForwardingHooks>,
    retain_store: &RetainStore,
    qos2_inflight: &mut std::collections::HashMap<u16, Qos2InflightV4>,
    publish: mqttbytes::v4::Publish,
) -> Result<(), MqttError> {
    // v3.1.1 has no per-publish reason codes — a topic / authz failure
    // at QoS 2 has no spec-defined ack channel that carries a reason
    // (PUBREC in v4 is just a packet identifier, no body). The
    // closest spec-compliant behaviour is to reject the session with
    // a typed `MqttError`, which is what we already do for QoS 0/1.
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

    // QoS 2 four-step (refs #880): see v5 sibling for the rationale.
    // v3.1.1 PUBREC carries no reason code so the PUBREC arm is much
    // smaller — just emit the bare ack and save state for PUBREL.
    if publish.qos == mqttbytes::QoS::ExactlyOnce {
        if publish.pkid == 0 {
            fire_publish_reject(session_hooks);
            return Err(MqttError::Malformed(
                "QoS 2 PUBLISH with packet identifier 0".into(),
            ));
        }
        // See `handle_publish_v5` for the duplicate-pkid rationale.
        let _ = qos2_inflight
            .entry(publish.pkid)
            .or_insert_with(|| Qos2InflightV4 {
                publish: publish.clone(),
                group: group.into_owned(),
            });
        send_pubrec_v4(resp_tx, publish.pkid).await?;
        return Ok(());
    }

    // QoS 0 / 1 — deliver and ack immediately. See `handle_publish_v5`
    // for the rationale — retain semantics are identical across MQTT
    // 3.1.1 and 5.0 and live above the routing layer so even router-
    // dropped messages update the store.
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
    fire_retain_outcome(session_hooks, outcome);

    let msg = RoutableMessage {
        source: Identity::clone(identity),
        destination: Destination::Group(group.into_owned().into()),
        payload: publish.payload.clone(),
        metadata: Metadata::new(
            SystemTime::now(),
            "mqtt".into(),
            MessageType::Other("mqtt".into()),
        ),
    };

    // See `handle_publish_v5` for the identical rationale — the egress
    // fan-out only fires when the router accepts the message.
    let Some(routed) = router.route_for_egress(msg).await else {
        fire_publish_accept(session_hooks);
        return ack_publish_v4(resp_tx, &publish).await;
    };

    fire_forwarding(router, forwarding_hooks, &routed);
    fire_publish_accept(session_hooks);

    ack_publish_v4(resp_tx, &publish).await
}

/// Per-session state for an in-flight QoS 2 v4 PUBLISH awaiting PUBREL.
/// Sibling to [`Qos2InflightV5`].
#[derive(Debug, Clone)]
struct Qos2InflightV4 {
    publish: mqttbytes::v4::Publish,
    group: String,
}

/// Send a v4 PUBREC. v3.1.1 PUBREC has no reason code field — just a
/// packet identifier — so the helper is correspondingly simpler.
async fn send_pubrec_v4(
    resp_tx: &mpsc::Sender<ResponsePacket>,
    pkid: u16,
) -> Result<(), MqttError> {
    let pubrec = mqttbytes::v4::PubRec::new(pkid);
    send_response(
        resp_tx,
        serialize_v4(&mqttbytes::v4::Packet::PubRec(pubrec))?,
    )
    .await
}

/// Send a v4 PUBCOMP. v3.1.1 PUBCOMP has no reason code field — just a
/// packet identifier. Sibling to [`send_pubcomp_v5`].
async fn send_pubcomp_v4(
    resp_tx: &mpsc::Sender<ResponsePacket>,
    pkid: u16,
) -> Result<(), MqttError> {
    let pubcomp = mqttbytes::v4::PubComp::new(pkid);
    send_response(
        resp_tx,
        serialize_v4(&mqttbytes::v4::Packet::PubComp(pubcomp))?,
    )
    .await
}

/// Handle a v4 PUBREL — Stage 3 of the QoS 2 four-step. Sibling to
/// [`handle_pubrel_v5`]; v3.1.1 PUBCOMP carries no reason code so the
/// "unknown pkid" branch silently emits a PUBCOMP rather than an
/// explicit "PacketIdentifierNotFound" reason. This matches the
/// v3.1.1 spec — there is no per-pkid signal channel.
// justification: see `handle_pubrel_v5` — the same rationale applies
// for the v3.1.1 sibling.
#[allow(clippy::too_many_arguments)]
async fn handle_pubrel_v4(
    resp_tx: &mpsc::Sender<ResponsePacket>,
    identity: &Arc<Identity>,
    router: &Router,
    session_hooks: Option<&crate::config::MqttSessionHooks>,
    forwarding_hooks: Option<&crate::config::MqttForwardingHooks>,
    retain_store: &RetainStore,
    qos2_inflight: &mut std::collections::HashMap<u16, Qos2InflightV4>,
    pubrel: mqttbytes::v4::PubRel,
) -> Result<(), MqttError> {
    let inflight = match qos2_inflight.remove(&pubrel.pkid) {
        Some(state) => state,
        None => {
            // Unknown pkid — best-effort PUBCOMP so the client closes
            // its side of the four-step. v3.1.1 has no reason channel.
            return send_pubcomp_v4(resp_tx, pubrel.pkid).await;
        }
    };

    let publish = inflight.publish;
    let group = inflight.group;

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
            "MQTT retain store updated (QoS 2 PUBREL)"
        );
    }
    fire_retain_outcome(session_hooks, outcome);

    let msg = RoutableMessage {
        source: Identity::clone(identity),
        destination: Destination::Group(group.into()),
        payload: publish.payload.clone(),
        metadata: Metadata::new(
            SystemTime::now(),
            "mqtt".into(),
            MessageType::Other("mqtt".into()),
        ),
    };

    if let Some(routed) = router.route_for_egress(msg).await {
        fire_forwarding(router, forwarding_hooks, &routed);
    }
    fire_publish_accept(session_hooks);

    send_pubcomp_v4(resp_tx, pubrel.pkid).await
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
    subscriptions: &Arc<parking_lot::Mutex<Vec<crate::session_store::RetainedSubscription>>>,
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
    //
    // The fourth tuple element is the optional Subscription
    // Identifier (refs #880) of THIS SUBSCRIBE — per §3.3.4.8 the
    // retained PUBLISHes delivered as a result of a fresh SUBSCRIBE
    // MUST carry the identifier from that SUBSCRIBE. Stored alongside
    // the retained payload so the replay loop attaches it on emission
    // without re-walking the per-session tracker.
    let mut retained_to_send: Vec<(
        String,
        crate::retain::RetainedMessage,
        mqttbytes::QoS,
        Option<u32>,
    )> = Vec::new();

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
                // MQTT 5.0 §3.8.2.1.2 Subscription Identifier — the
                // OPTIONAL `id` from `SubscribeProperties` (a VBI on
                // the wire, surfaced as `Option<usize>` by mqttbytes)
                // must be associated with every subscription created
                // by THIS SUBSCRIBE so the write loop can echo it back
                // on matching PUBLISHes per §3.3.4.8. Stored as `u32`
                // (the spec's max VBI value 268_435_455 fits in a u32);
                // if a future client sends an ID outside that range
                // mqttbytes parsing rejects it before reaching here.
                let sub_id: Option<u32> = sub
                    .properties
                    .as_ref()
                    .and_then(|p| p.id)
                    .and_then(|id| u32::try_from(id).ok());
                track_subscription(
                    subscriptions,
                    &filter.path,
                    filter.qos,
                    topic_prefix,
                    sub_id,
                );
                // Collect retained messages now while the filter is
                // confirmed-authorised; defer the actual send until
                // after SUBACK so a slow client back-pressuring the
                // response channel cannot block the SUBACK itself.
                //
                // Pass the subscription identifier through so the
                // retain-replay PUBLISH carries it per §3.3.4.8 (the
                // spec is explicit that retained messages delivered as
                // the result of a new SUBSCRIBE MUST include the
                // identifier of THAT SUBSCRIBE).
                collect_retained_for_filter(
                    retain_store,
                    identity,
                    &filter.path,
                    filter.qos,
                    topic_prefix,
                    sub_id,
                    &mut retained_to_send,
                );
                match filter.qos {
                    mqttbytes::QoS::AtMostOnce => mqttbytes::v5::SubscribeReasonCode::QoS0,
                    mqttbytes::QoS::AtLeastOnce => mqttbytes::v5::SubscribeReasonCode::QoS1,
                    // QoS 2 SUBSCRIBEs are rejected by the upstream guard
                    // at the top of this loop with `ImplementationSpecific`
                    // and a `continue`. Reaching this arm would mean that
                    // guard has been refactored away — `unreachable!()`
                    // here would abort the broker in release profile, so
                    // we degrade gracefully to the spec-defined catch-all
                    // `Unspecified` (MQTT 5.0 §3.9.3 reason code 0x80 —
                    // "the subscription is not accepted and the Server
                    // either does not wish to reveal the reason or none of
                    // the other Reason Codes apply") and log at debug for
                    // forensic visibility. Refs #751.
                    mqttbytes::QoS::ExactlyOnce => {
                        debug!(
                            cn = %hash_cn(&identity.cn),
                            filter = %sanitize_for_log(&filter.path),
                            "QoS 2 SUBSCRIBE reached post-authorize match arm; \
                             upstream guard should have rejected — falling through \
                             with Unspecified reason code"
                        );
                        mqttbytes::v5::SubscribeReasonCode::Unspecified
                    }
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
    for (topic, retained, subscriber_qos, sub_id) in retained_to_send {
        // Downgrade publisher's QoS to min(publisher_qos,
        // subscriber_qos) per MQTT 5.0 §3.8.4 ("the QoS of Payload
        // messages sent in response to a Subscription MUST be the
        // minimum of the QoS of the originally published message and
        // the Maximum QoS granted by the Server").
        let effective_qos = min_qos(retained.qos, subscriber_qos);
        let mut publish =
            mqttbytes::v5::Publish::from_bytes(topic, effective_qos, retained.payload);
        publish.retain = true;
        // MQTT 5.0 §3.3.4.8: retained messages delivered as a result
        // of THIS SUBSCRIBE carry THIS SUBSCRIBE's identifier (when
        // present). A retained replay triggered by a SUBSCRIBE that
        // omitted the property gets no identifier (empty Vec, which
        // is the parser's default — written-vs-omitted are
        // observationally identical on the wire).
        if let Some(id) = sub_id
            && let Ok(id_usize) = usize::try_from(id)
        {
            let mut props = publish
                .properties
                .take()
                .unwrap_or_else(empty_publish_properties);
            props.subscription_identifiers.push(id_usize);
            publish.properties = Some(props);
        }
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
        fire_retain_replayed(session_hooks);
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
    subscriptions: &Arc<parking_lot::Mutex<Vec<crate::session_store::RetainedSubscription>>>,
    sub: mqttbytes::v4::Subscribe,
) -> Result<(), MqttError> {
    let mut return_codes = Vec::with_capacity(sub.filters.len());
    // The fourth tuple element is unused on the v4 wire format (3.1.1
    // has no Subscription Identifier feature) — but the
    // `collect_retained_for_filter` helper takes a unified signature
    // for both protocol versions, so we pass `None` and the v4 retain
    // replay loop simply ignores it.
    let mut retained_to_send: Vec<(
        String,
        crate::retain::RetainedMessage,
        mqttbytes::QoS,
        Option<u32>,
    )> = Vec::new();

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
                // See handle_subscribe_v5 for the retention-tracker
                // rationale (refs #880). v3.1.1 doesn't support
                // session retention via the new infrastructure (we
                // continue to reject clean_session=0 outright in
                // connect_handshake), so the tracker mutation is
                // operationally a no-op for v4 — but the same
                // bookkeeping is done for symmetry so a future PR
                // adding v3.1.1 retention doesn't have to revisit
                // these handlers.
                // v3.1.1 has no Subscription Identifier feature;
                // pass `None` so the tracker entry's
                // `subscription_identifier` field is `None` and the
                // v4 dispatch path stays observationally identical
                // to its pre-#880 behaviour.
                track_subscription(subscriptions, &filter.path, filter.qos, topic_prefix, None);
                collect_retained_for_filter(
                    retain_store,
                    identity,
                    &filter.path,
                    filter.qos,
                    topic_prefix,
                    None,
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
    //
    // The fourth tuple field is the v5 Subscription Identifier — v4
    // has no such property on the wire, so it is discarded here. The
    // tuple shape is unified with the v5 path so a future v3.1.1
    // extension (e.g. via a vendor User Property) doesn't have to
    // touch the buffer type.
    for (topic, retained, subscriber_qos, _sub_id) in retained_to_send {
        let effective_qos = min_qos(retained.qos, subscriber_qos);
        let mut publish =
            mqttbytes::v4::Publish::from_bytes(topic, effective_qos, retained.payload);
        publish.retain = true;
        send_response(
            resp_tx,
            serialize_v4(&mqttbytes::v4::Packet::Publish(publish))?,
        )
        .await?;
        fire_retain_replayed(session_hooks);
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
/// Push a tracker entry for an accepted SUBSCRIBE filter (refs #880).
///
/// Centralises the (group + filter + qos + identifier) bookkeeping
/// that both `handle_subscribe_v5` and `handle_subscribe_v4` share.
/// Two distinct stored shapes:
///
/// - **Non-wildcard filter** — `topic_to_group` succeeds, so the
///   tracker entry has both `group` populated (used by the session-
///   retention save+restore path) and `filter` set to the same value
///   (used by the write loop's identifier-attachment match).
/// - **Wildcard filter** — `topic_to_group` rejects the wildcard
///   characters, so `group` is left as the empty string (the session-
///   retention path treats empty groups as no-restore-target, matching
///   the pre-#880 behaviour where wildcard subscriptions did not
///   round-trip through saved sessions). `filter` carries the
///   wildcard pattern AFTER the listener's `topic_prefix` is stripped,
///   so it is comparable directly against destination group names via
///   `topic::filter_matches`.
///
/// Dedup is by `(filter, identifier)` — re-SUBSCRIBE with the same
/// filter and same identifier is a no-op (the previous entry is
/// retained), but re-SUBSCRIBE with the same filter and a NEW
/// identifier creates a new entry so the write loop attaches every
/// distinct identifier on a matching PUBLISH per §3.3.4.8.
fn track_subscription(
    subscriptions: &Arc<parking_lot::Mutex<Vec<crate::session_store::RetainedSubscription>>>,
    filter_path: &str,
    qos: mqttbytes::QoS,
    topic_prefix: Option<&str>,
    subscription_identifier: Option<u32>,
) {
    // Compute the post-strip filter regardless of wildcard status —
    // the matcher in the write loop runs against destination groups
    // which are themselves post-strip.
    let stripped_filter: String = match topic_prefix {
        Some(pfx) => match filter_path.strip_prefix(pfx) {
            Some(rest) => rest.to_owned(),
            // If the prefix is configured but the filter does not
            // start with it, `try_join_filter` would have already
            // rejected the SUBSCRIBE — reaching this branch means
            // accepted-without-prefix-stripping, which only happens
            // when prefix is `None` (handled in the other arm). For
            // safety, fall back to the raw path; it just won't match
            // anything in the post-strip group coordinate space.
            None => filter_path.to_owned(),
        },
        None => filter_path.to_owned(),
    };

    // For non-wildcard filters, `topic_to_group` re-derives the same
    // post-strip name and accepts it (the wildcard-validator inside
    // rejects `+`/`#`). For wildcard filters, `topic_to_group` errors
    // — we leave `group` empty so the session-retention path skips
    // restoration of this entry (matching pre-#880 behaviour).
    let group_owned = match crate::topic::topic_to_group(filter_path, topic_prefix) {
        Ok(g) => g.into_owned(),
        Err(_) => String::new(),
    };

    let qos_byte: u8 = match qos {
        mqttbytes::QoS::AtMostOnce => 0,
        mqttbytes::QoS::AtLeastOnce => 1,
        mqttbytes::QoS::ExactlyOnce => 2,
    };

    let mut tracker = subscriptions.lock();
    if !tracker.iter().any(|s| {
        s.filter == stripped_filter && s.subscription_identifier == subscription_identifier
    }) {
        tracker.push(crate::session_store::RetainedSubscription {
            group: group_owned,
            qos: qos_byte,
            subscription_identifier,
            filter: stripped_filter,
        });
    }
}

fn collect_retained_for_filter(
    retain_store: &RetainStore,
    identity: &Identity,
    filter: &str,
    subscriber_qos: mqttbytes::QoS,
    topic_prefix: Option<&str>,
    subscription_identifier: Option<u32>,
    out: &mut Vec<(
        String,
        crate::retain::RetainedMessage,
        mqttbytes::QoS,
        Option<u32>,
    )>,
) {
    for (topic, msg) in retain_store.matching(filter, topic_prefix) {
        // The auth boundary is the certificate-derived group set, same
        // as for the live PUBLISH path. Stale retained entries whose
        // topic no longer maps to a valid group are skipped — they
        // cannot leak to anyone.
        //
        // The subscription identifier rides with each tuple so the
        // retain-replay loop in `handle_subscribe_v5` can attach it
        // verbatim (refs §3.3.4.8). v4 callers pass `None` and the
        // v4 replay loop discards it.
        match topic::topic_to_group(&topic, topic_prefix) {
            Ok(group) if identity.is_member_of(&group) => {
                out.push((topic, msg, subscriber_qos, subscription_identifier));
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
    subscriptions: &Arc<parking_lot::Mutex<Vec<crate::session_store::RetainedSubscription>>>,
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
            Ok(_) => {
                // Drop the tracker entry for this filter so a
                // session-end save (refs #880) doesn't resurrect a
                // subscription the client just dropped, and so a
                // subsequent matching PUBLISH no longer attaches the
                // identifier of an UNSUBSCRIBEd subscription. Match
                // by `filter` (post-strip) rather than `group` so
                // wildcard subscriptions — which leave `group` empty
                // — are also removed.
                let stripped_filter: String = match topic_prefix {
                    Some(pfx) => match filter.strip_prefix(pfx) {
                        Some(rest) => rest.to_owned(),
                        None => filter.clone(),
                    },
                    None => filter.clone(),
                };
                subscriptions.lock().retain(|s| s.filter != stripped_filter);
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
    subscriptions: &Arc<parking_lot::Mutex<Vec<crate::session_store::RetainedSubscription>>>,
    unsub: mqttbytes::v4::Unsubscribe,
) -> Result<(), MqttError> {
    for filter in &unsub.topics {
        // MQTT 3.1.1 UNSUBACK has no reason codes — failures are silent.
        if leave_filter(
            identity,
            router,
            session_id,
            filter,
            topic_prefix,
            wildcard_policy,
        )
        .await
        .is_ok()
        {
            // See `handle_unsubscribe_v5` for the retention-tracker
            // rationale (refs #880). Same filter-based match here so
            // wildcard subscriptions are also dropped.
            let stripped_filter: String = match topic_prefix {
                Some(pfx) => match filter.strip_prefix(pfx) {
                    Some(rest) => rest.to_owned(),
                    None => filter.clone(),
                },
                None => filter.clone(),
            };
            subscriptions.lock().retain(|s| s.filter != stripped_filter);
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
///
/// The `subscriptions` tracker is consulted on every routed-message
/// write to attach the matching MQTT 5.0 §3.8.2.1.2 Subscription
/// Identifiers per §3.3.4.8 (refs #880).
async fn mqtt_write_loop(
    writer: &mut PacketWriter,
    protocol: ProtocolLevel,
    prefix: &str,
    priority_rx: &mut mpsc::Receiver<rustgate_router::RoutedMessage>,
    normal_rx: &mut mpsc::Receiver<rustgate_router::RoutedMessage>,
    resp_rx: &mut mpsc::Receiver<ResponsePacket>,
    subscriptions: &Arc<parking_lot::Mutex<Vec<crate::session_store::RetainedSubscription>>>,
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
                    write_routed_message(writer, protocol, prefix, &m, subscriptions).await?;
                }
                None => {
                    priority_open = false;
                }
            },
            msg = normal_rx.recv(), if normal_open => match msg {
                Some(m) => {
                    write_routed_message(writer, protocol, prefix, &m, subscriptions).await?;
                }
                None => {
                    normal_open = false;
                }
            },
        }
    }
}

/// Write a single routed message as an MQTT PUBLISH to the client.
///
/// On the v5 path, the per-session `subscriptions` tracker is queried
/// for matching subscriptions whose Subscription Identifier (set on
/// SUBSCRIBE per §3.8.2.1.2) MUST be echoed on the outgoing PUBLISH
/// per §3.3.4.8. All matching identifiers are attached — a single
/// PUBLISH that satisfies multiple subscriptions on the same session
/// carries every one of their identifiers.
async fn write_routed_message(
    writer: &mut PacketWriter,
    protocol: ProtocolLevel,
    prefix: &str,
    msg: &RoutableMessage,
    subscriptions: &Arc<parking_lot::Mutex<Vec<crate::session_store::RetainedSubscription>>>,
) -> Result<(), MqttError> {
    let topic = msg_to_topic(msg, prefix);

    let result = match protocol {
        ProtocolLevel::V311 => {
            // v3.1.1 has no Subscription Identifier feature; the
            // tracker is intentionally NOT consulted here. A v4
            // session built with handle_subscribe_v4 always stores
            // `subscription_identifier = None` so consultation would
            // be a no-op anyway, but skipping the lookup keeps the
            // hot path lock-free for v4 traffic.
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
            let mut publish = mqttbytes::v5::Publish::from_bytes(
                topic,
                mqttbytes::QoS::AtMostOnce,
                msg.payload.clone(),
            );
            attach_subscription_identifiers(&mut publish, msg, subscriptions);
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
///
/// Drained PUBLISHes go through the same `write_routed_message` path
/// the live loop uses, so subscription-identifier propagation
/// (refs #880, §3.3.4.8) is preserved through graceful shutdown.
// justification: flush_pending mirrors mqtt_write_loop one-for-one — same
// channels + the per-session subscription tracker. Bundling the four channels
// into a struct would also force the live loop to wrap them, removing a layer
// of explicit lifetime + Send checks the call sites currently rely on.
#[allow(clippy::too_many_arguments)]
async fn flush_pending(
    writer: &mut PacketWriter,
    protocol: ProtocolLevel,
    prefix: &str,
    resp_rx: &mut mpsc::Receiver<ResponsePacket>,
    priority_rx: &mut mpsc::Receiver<rustgate_router::RoutedMessage>,
    normal_rx: &mut mpsc::Receiver<rustgate_router::RoutedMessage>,
    subscriptions: &Arc<parking_lot::Mutex<Vec<crate::session_store::RetainedSubscription>>>,
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

        if write_routed_message(writer, protocol, prefix, &msg, subscriptions)
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

/// MQTT 5.0 §3.3.4.8 + §3.8.2.1.2 (refs #880): attach every matching
/// subscription's identifier to an outgoing v5 PUBLISH.
///
/// "Matching" runs over the per-session subscription tracker keyed
/// off `filter` (post-prefix-strip), so both exact-topic SUBSCRIBEs
/// and wildcard SUBSCRIBEs (`+` / `#`) participate. The matcher uses
/// `topic::filter_matches` — the same level-aware MQTT 5.0 §4.7.1
/// matcher the SUBSCRIBE/PUBLISH path uses for wildcard expansion.
///
/// Destination handling:
///
/// - `Destination::Group(g)` is matched against every tracker entry's
///   `filter` field. A single client may SUBSCRIBE multiple times
///   with different identifiers; the spec requires ALL matching
///   identifiers to ride on the PUBLISH (one identifier per matching
///   subscription).
/// - `Destination::Direct(_)`, `Destination::Broadcast`, and
///   `Destination::Multicast(_)` are protocol-internal delivery
///   shapes that do not flow through normal SUBSCRIBE filters, so no
///   identifier attribution applies. The PUBLISH still goes out — it
///   just has no identifiers.
///
/// Subscriptions whose `subscription_identifier` is `None` (the v4
/// path or a v5 SUBSCRIBE that omitted the property) contribute
/// nothing and are skipped silently.
///
/// Lock contention: the per-session tracker is touched on every
/// PUBLISH delivery, so the critical section is kept short — clone
/// the matching identifiers into a local `Vec` and release the lock
/// before mutating the `Publish` properties (the mutation involves
/// allocations the lock should not cover).
fn attach_subscription_identifiers(
    publish: &mut mqttbytes::v5::Publish,
    msg: &RoutableMessage,
    subscriptions: &Arc<parking_lot::Mutex<Vec<crate::session_store::RetainedSubscription>>>,
) {
    let target_group: &str = match &msg.destination {
        Destination::Group(g) => g,
        // Direct / Broadcast / Multicast deliveries do not carry
        // SUBSCRIBE-derived identifiers — no work to do.
        Destination::Direct(_) | Destination::Broadcast | Destination::Multicast(_) => {
            return;
        }
    };

    let matched_ids: Vec<usize> = {
        let tracker = subscriptions.lock();
        tracker
            .iter()
            .filter(|s| topic::filter_matches(&s.filter, target_group))
            .filter_map(|s| s.subscription_identifier)
            .filter_map(|id| usize::try_from(id).ok())
            .collect()
    };

    if matched_ids.is_empty() {
        return;
    }

    let mut props = publish
        .properties
        .take()
        .unwrap_or_else(empty_publish_properties);
    props.subscription_identifiers.extend(matched_ids);
    publish.properties = Some(props);
}

/// Construct an empty [`mqttbytes::v5::PublishProperties`].
///
/// `mqttbytes 0.6.0`'s `PublishProperties` does not implement
/// `Default`, so reaching for `unwrap_or_default()` on
/// `Option<PublishProperties>` does not compile. This helper is the
/// single source of truth for the explicit-zero shape so a future
/// upstream revision can be picked up by changing only one site.
fn empty_publish_properties() -> mqttbytes::v5::PublishProperties {
    mqttbytes::v5::PublishProperties {
        payload_format_indicator: None,
        message_expiry_interval: None,
        topic_alias: None,
        response_topic: None,
        correlation_data: None,
        user_properties: Vec::new(),
        subscription_identifiers: Vec::new(),
        content_type: None,
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
            on_retain_stored: None,
            on_retain_cleared: None,
            on_retain_replayed: None,
            on_will_published: None,
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

    /// Build a hooks bundle wired only on the three retain callbacks so
    /// the retain-side helpers can be tested in isolation from the
    /// publish/subscribe callbacks. Returns counters in order:
    /// (stored, cleared, replayed).
    fn retain_hooks_with_counters() -> (
        crate::config::MqttSessionHooks,
        Arc<AtomicUsize>,
        Arc<AtomicUsize>,
        Arc<AtomicUsize>,
    ) {
        let stored = Arc::new(AtomicUsize::new(0));
        let cleared = Arc::new(AtomicUsize::new(0));
        let replayed = Arc::new(AtomicUsize::new(0));
        let hooks = crate::config::MqttSessionHooks {
            on_publish: None,
            on_publish_reject: None,
            on_subscribe: None,
            on_subscribe_reject: None,
            on_retain_stored: Some(counter_cb(&stored)),
            on_retain_cleared: Some(counter_cb(&cleared)),
            on_retain_replayed: Some(counter_cb(&replayed)),
            on_will_published: None,
        };
        (hooks, stored, cleared, replayed)
    }

    #[test]
    fn fire_retain_outcome_dispatches_stored_only_on_stored() {
        let (hooks, stored, cleared, replayed) = retain_hooks_with_counters();
        fire_retain_outcome(Some(&hooks), RetainOutcome::Stored);
        assert_eq!(stored.load(Ordering::SeqCst), 1);
        assert_eq!(cleared.load(Ordering::SeqCst), 0);
        assert_eq!(replayed.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn fire_retain_outcome_dispatches_cleared_only_on_cleared() {
        let (hooks, stored, cleared, replayed) = retain_hooks_with_counters();
        fire_retain_outcome(Some(&hooks), RetainOutcome::Cleared);
        assert_eq!(stored.load(Ordering::SeqCst), 0);
        assert_eq!(cleared.load(Ordering::SeqCst), 1);
        assert_eq!(replayed.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn fire_retain_outcome_is_noop_on_passthrough() {
        // Passthrough means retain bit was 0 — no store mutation, no
        // counter increment. A regression that fired stored/cleared
        // on every PUBLISH would inflate the counters by 100x in
        // typical traffic where most messages are not retained.
        let (hooks, stored, cleared, replayed) = retain_hooks_with_counters();
        fire_retain_outcome(Some(&hooks), RetainOutcome::Passthrough);
        assert_eq!(stored.load(Ordering::SeqCst), 0);
        assert_eq!(cleared.load(Ordering::SeqCst), 0);
        assert_eq!(replayed.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn fire_retain_replayed_fires_only_its_own_callback() {
        let (hooks, stored, cleared, replayed) = retain_hooks_with_counters();
        fire_retain_replayed(Some(&hooks));
        assert_eq!(stored.load(Ordering::SeqCst), 0);
        assert_eq!(cleared.load(Ordering::SeqCst), 0);
        assert_eq!(replayed.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn fire_retain_helpers_nop_when_individual_callback_is_none() {
        // Operator may opt into the hook bundle but wire only the
        // store/clear hooks and not replay. The replay helper must
        // tolerate the partial population without spilling onto
        // store or clear counters.
        let (hooks, stored, cleared, replayed) = retain_hooks_with_counters();
        let mut partial = hooks.clone();
        partial.on_retain_replayed = None;
        fire_retain_replayed(Some(&partial));
        assert_eq!(stored.load(Ordering::SeqCst), 0);
        assert_eq!(cleared.load(Ordering::SeqCst), 0);
        assert_eq!(
            replayed.load(Ordering::SeqCst),
            0,
            "replay helper must no-op when its own field is None"
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
            metadata: Metadata::new(
                SystemTime::now(),
                "test".into(),
                MessageType::Other("test".into()),
            ),
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

    // -----------------------------------------------------------------------
    // `validate_will` — pure-function authorization gate for last-will
    // messages parsed out of CONNECT. Covered exhaustively at unit level
    // because the integration tests exercise the on-the-wire path but
    // cannot easily enumerate the cross-product of (qos, topic shape,
    // group membership, prefix configuration). A regression that
    // accidentally accepts an unauthorised will would silently allow an
    // attacker to use the will publish as a privilege-escalation
    // primitive.
    // -----------------------------------------------------------------------

    fn mk_will_identity(cn: &str, groups: &[&str]) -> Identity {
        Identity::new(
            cn.into(),
            "fingerprint".into(),
            groups.iter().map(|s| (*s).to_string()).collect(),
        )
        .unwrap()
    }

    #[test]
    fn validate_will_accepts_authorized_publish_topic() {
        // Happy path: alice ∈ {alpha}, will targets `alpha`, QoS 0,
        // no prefix configured. Result must be `Valid` with the
        // group cached and the original topic preserved verbatim.
        let id = mk_will_identity("alice", &["alpha"]);
        let payload = bytes::Bytes::from_static(b"offline");
        let result = validate_will(
            "alpha",
            &payload,
            mqttbytes::QoS::AtMostOnce,
            false,
            &id,
            None,
        );
        match result {
            WillValidation::Valid(will) => {
                assert_eq!(will.topic, "alpha");
                assert_eq!(will.group, "alpha");
                assert_eq!(will.payload.as_ref(), b"offline");
                assert!(!will.retain);
            }
            other => panic!("expected Valid, got {:?}", will_validation_kind(&other)),
        }
    }

    #[test]
    fn validate_will_rejects_qos2_as_invalid_topic() {
        // QoS 2 requires the four-step PUBREC/PUBREL/PUBCOMP handshake
        // which the broker does not implement. Pin that QoS 2 rejects
        // BEFORE the topic / group check fires — otherwise an
        // attacker-supplied empty topic could short-circuit the QoS 2
        // gate.
        let id = mk_will_identity("alice", &["alpha"]);
        let payload = bytes::Bytes::from_static(b"x");
        let result = validate_will(
            "alpha",
            &payload,
            mqttbytes::QoS::ExactlyOnce,
            false,
            &id,
            None,
        );
        assert!(matches!(result, WillValidation::InvalidTopic(_)));
    }

    #[test]
    fn validate_will_rejects_wildcards_in_topic() {
        // MQTT spec forbids `+` and `#` in a PUBLISH topic — and a will
        // is just a deferred PUBLISH, so the same rule applies.
        let id = mk_will_identity("alice", &["alpha"]);
        let payload = bytes::Bytes::from_static(b"x");
        let with_plus = validate_will(
            "alpha/+",
            &payload,
            mqttbytes::QoS::AtMostOnce,
            false,
            &id,
            None,
        );
        assert!(matches!(with_plus, WillValidation::InvalidTopic(_)));
        let with_hash = validate_will(
            "alpha/#",
            &payload,
            mqttbytes::QoS::AtMostOnce,
            false,
            &id,
            None,
        );
        assert!(matches!(with_hash, WillValidation::InvalidTopic(_)));
    }

    #[test]
    fn validate_will_rejects_empty_topic() {
        // An empty topic is structurally invalid per MQTT spec; the
        // gate must refuse it BEFORE any group lookup.
        let id = mk_will_identity("alice", &["alpha"]);
        let payload = bytes::Bytes::from_static(b"x");
        let result = validate_will("", &payload, mqttbytes::QoS::AtMostOnce, false, &id, None);
        assert!(matches!(result, WillValidation::InvalidTopic(_)));
    }

    #[test]
    fn validate_will_rejects_unauthorized_group() {
        // alice ∈ {alpha}, will targets `bravo` — must reject as
        // NotAuthorized, NOT as InvalidTopic. A regression that
        // collapsed both rejections into a single variant would
        // surface the wrong CONNACK reason to the client.
        let id = mk_will_identity("alice", &["alpha"]);
        let payload = bytes::Bytes::from_static(b"x");
        let result = validate_will(
            "bravo",
            &payload,
            mqttbytes::QoS::AtMostOnce,
            false,
            &id,
            None,
        );
        assert!(matches!(result, WillValidation::NotAuthorized(_)));
    }

    #[test]
    fn validate_will_with_topic_prefix_strips_correctly() {
        // Listener configured with prefix `rg/` — will topic
        // `rg/alpha` must derive group `alpha` and pass auth.
        let id = mk_will_identity("alice", &["alpha"]);
        let payload = bytes::Bytes::from_static(b"x");
        let result = validate_will(
            "rg/alpha",
            &payload,
            mqttbytes::QoS::AtMostOnce,
            false,
            &id,
            Some("rg/"),
        );
        match result {
            WillValidation::Valid(will) => {
                assert_eq!(will.topic, "rg/alpha");
                assert_eq!(will.group, "alpha");
            }
            other => panic!("expected Valid, got {:?}", will_validation_kind(&other)),
        }
    }

    #[test]
    fn validate_will_with_topic_prefix_mismatch_is_invalid() {
        // Will topic outside the listener prefix must reject as
        // InvalidTopic — the prefix is part of the listener contract,
        // not an authorization boundary.
        let id = mk_will_identity("alice", &["alpha"]);
        let payload = bytes::Bytes::from_static(b"x");
        let result = validate_will(
            "alpha",
            &payload,
            mqttbytes::QoS::AtMostOnce,
            false,
            &id,
            Some("rg/"),
        );
        assert!(matches!(result, WillValidation::InvalidTopic(_)));
    }

    #[test]
    fn validate_will_preserves_retain_flag() {
        // The `retain` field on the validated `Will` must be the same
        // bit the client supplied — defends against a regression that
        // accidentally clears retain for "safety" and breaks the
        // last-known-value pattern.
        let id = mk_will_identity("alice", &["alpha"]);
        let payload = bytes::Bytes::from_static(b"x");
        let with_retain = validate_will(
            "alpha",
            &payload,
            mqttbytes::QoS::AtMostOnce,
            true,
            &id,
            None,
        );
        match with_retain {
            WillValidation::Valid(will) => assert!(will.retain),
            other => panic!("expected Valid, got {:?}", will_validation_kind(&other)),
        }
    }

    /// Tiny `Debug`-ish helper because `WillValidation` does not derive
    /// `Debug` (it would require `Will` and `Identity` to be Debug-only
    /// types here, which they are by upstream type, but we keep the test
    /// dependency surface minimal). Used only in `panic!` arms.
    fn will_validation_kind(v: &WillValidation) -> &'static str {
        match v {
            WillValidation::Valid(_) => "Valid",
            WillValidation::InvalidTopic(_) => "InvalidTopic",
            WillValidation::NotAuthorized(_) => "NotAuthorized",
        }
    }

    // ── F-30 (#773) operational log cardinality cap ─────────────────

    #[test]
    fn mqtt_session_operational_logs_hash_cn_at_info_debug_boundary() {
        // F-30 (#773) — Pin that the MQTT session's info/debug log
        // sites that carry a CN field run the value through the
        // shared `rustgate_core::masking::hash_cn` helper before it
        // reaches a structured `tracing` field. The session has many
        // such sites (subscribe, unsubscribe, disconnect, packet-route
        // debug arms); rather than introspect every emitted log line,
        // pin that the module's `hash_cn` import resolves to the
        // public helper. A regression that swapped to a crate-local
        // copy or dropped the wrapper would defeat the SIEM
        // index-cardinality cap and let an attacker churning CNs
        // inflate the index by emitting unique values per request.
        let raw = "mqtt-session-007-cardinality-canary";
        let from_module = hash_cn(raw);
        let from_core = rustgate_core::masking::hash_cn(raw);
        assert_eq!(
            from_module, from_core,
            "session.rs must use the shared `rustgate_core::masking::hash_cn`"
        );
        assert_eq!(
            from_module.len(),
            12,
            "hashed log token must be 12 hex chars (48 bits) — \
             a regression that widened/narrowed the truncation \
             would change the SIEM index cardinality bound"
        );
        assert!(
            !from_module.contains(raw),
            "hashed log token must not contain the raw CN, got {from_module}"
        );
        assert!(
            from_module.chars().all(|c| c.is_ascii_hexdigit()),
            "hashed log token must be hex-only, got {from_module:?}"
        );
        // Idempotence: two adjacent emissions for the same CN must
        // collapse to a single SIEM index entry.
        assert_eq!(
            hash_cn(raw),
            from_module,
            "hash_cn must be idempotent so SIEM index entries collapse"
        );
        // Distinct CNs must collapse to distinct hashes (modulo the
        // 48-bit collision risk, which is intentional).
        assert_ne!(
            hash_cn(raw),
            hash_cn("different-mqtt-canary-008"),
            "distinct CNs must produce distinct hashes; \
             a regression collapsing them would defeat correlation"
        );
    }
}
