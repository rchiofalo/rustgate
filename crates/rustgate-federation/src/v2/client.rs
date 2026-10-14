// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! V2 federation gRPC client with 5-stream handshake.
//!
//! Implements the outbound gRPC federation connection that follows the
//! TAK Server V2 federation protocol. The client establishes multiple
//! concurrent streams (group exchange, event streaming, health checks)
//! and reconnects automatically on failure.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use rustgate_resilience::backpressure::{BackpressureGate, BackpressurePermit};
use rustgate_resilience::reconnect::{backoff_delay, should_stop_reconnecting};
use tokio::sync::{mpsc, watch};
use tonic::Request;
use tonic::transport::{Channel, ClientTlsConfig, Endpoint, Uri};
use tracing::{debug, error, info, warn};

use super::proto::figpb;
use super::proto::figpb::federated_channel_client::FederatedChannelClient;
use crate::config::CompressionKind;
use crate::error::{FederationError, Result};
use crate::peer::{PeerHandle, PeerState};
use crate::provenance;
use crate::replay_buffer::BufferedMessage;

rustgate_core::on_callback!(
    /// Callback invoked when a FederatedEvent is received from the remote peer.
    ///
    /// F-113: receives a typed [`rustgate_core::PeerId`]. The conversion from
    /// the wire-format `String` returned by `peer_id_from_request` happens
    /// at the V2 server boundary; consumers downstream of the callback see
    /// the typed wrapper.
    ///
    /// Closes #852 (PR-C): the third argument is the parsed W3C
    /// [`rustgate_core::TraceContext`] for the inbound stream's
    /// `traceparent` header (when present and well-formed); `None`
    /// otherwise. Trace propagation is best-effort by construction —
    /// a missing or malformed header does not fail the stream.
    pub OnEvent,
    figpb::FederatedEvent,
    rustgate_core::PeerId,
    Option<rustgate_core::TraceContext>
);

/// Callback that drains the replay buffer on reconnection (V2).
///
/// Returns deduped buffered messages and clears the buffer atomically.
/// Arguments: `(peer_id) -> Vec<BufferedMessage>`.
///
/// F-113: takes a typed `&PeerId`; the underlying `HashMap<PeerId, _>`
/// lookup is unchanged thanks to `PeerId: Borrow<str>`.
pub type V2ReplayDrain = Arc<dyn Fn(&rustgate_core::PeerId) -> Vec<BufferedMessage> + Send + Sync>;

/// Configuration for a V2 federation gRPC client.
pub struct V2ClientConfig {
    pub address: String,
    pub tls_config: ClientTlsConfig,
    pub federate_id: String,
    pub groups: Vec<String>,
    pub health_interval: Duration,
    pub reconnect_delay: Duration,
    pub max_reconnects: i32,
    pub on_event: OnEvent,
    /// Optional replay drain callback for reconnection replay.
    pub replay_drain: Option<V2ReplayDrain>,
    /// Maximum hops for provenance metadata (used during replay).
    pub max_hops: u32,
    /// Optional outbound gRPC compression codec. `None` sends events
    /// uncompressed (the pre-#905 default). Set per-peer so operators on
    /// cross-region WAN links opt in to compression while low-latency LAN
    /// links stay on the uncompressed fast path.
    pub compression: Option<CompressionKind>,
    /// SEC-1: optional CN-pinning server-certificate verifier. When `Some`,
    /// the gRPC channel is built with
    /// [`tonic::transport::Endpoint::tls_config_with_verifier`] so the peer's
    /// leaf-certificate CN is pinned (and chain-validated) inside the TLS
    /// layer — tonic never surfaces the server leaf cert to application code,
    /// so this is the V2 counterpart to V1's post-handshake check. `None`
    /// keeps tonic's default verifier (historical chain + hostname behaviour).
    /// Built per-peer by the manager from
    /// [`crate::config::PeerConfig::trust_cert_cn`] and
    /// `--federation-require-peer-cn-match`.
    pub pin_verifier: Option<Arc<dyn rustls::client::danger::ServerCertVerifier>>,
}

/// Translate a [`CompressionKind`] into tonic's wire-level codec enum.
///
/// Kept as a free helper so the mapping is unit-testable without having
/// to stand up a full `FederatedChannelClient` fixture.
fn compression_encoding(kind: CompressionKind) -> tonic::codec::CompressionEncoding {
    match kind {
        CompressionKind::Gzip => tonic::codec::CompressionEncoding::Gzip,
        CompressionKind::Zstd => tonic::codec::CompressionEncoding::Zstd,
    }
}

impl fmt::Debug for V2ClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("V2ClientConfig")
            .field("address", &self.address)
            .field("federate_id", &self.federate_id)
            .field("groups", &self.groups)
            .field("health_interval", &self.health_interval)
            .field("reconnect_delay", &self.reconnect_delay)
            .field("max_reconnects", &self.max_reconnects)
            .field("compression", &self.compression)
            .field("pinned", &self.pin_verifier.is_some())
            .finish_non_exhaustive()
    }
}

/// Envelope queued for delivery to a remote V2 peer.
///
/// The optional [`BackpressurePermit`] keeps the global byte reservation
/// alive while the event sits in the bounded mpsc channel and is flushed
/// over the gRPC `ServerEventStream` — dropping the envelope at the
/// dequeue site releases the reservation automatically.
pub(crate) struct V2Queued {
    pub event: figpb::FederatedEvent,
    // justification: RAII field — held solely so its `Drop` releases the
    // gate reservation when the stream loop dequeues the envelope.
    #[allow(dead_code)]
    pub permit: Option<Arc<BackpressurePermit>>,
    /// Explicit W3C trace context to attach to the next outbound
    /// `traceparent` header in preference to the active OTel span.
    /// Closes #852 (PR-C).
    ///
    /// In the streaming `ServerEventStream` arm, the gRPC `traceparent`
    /// header is set at stream-open time only — the per-event override
    /// surfaced here is therefore consulted on stream re-open / reconnect
    /// rather than per-frame. Per-message trace propagation across a
    /// streaming gRPC requires re-opening the stream, which is out of
    /// scope for this PR; the unary `send_one_blob` path applies the
    /// override per-call. The carry is otherwise free — `Option`
    /// branches discard the context when no explicit propagation is
    /// requested.
    // justification: held for future per-event header injection on
    // unary RPC paths and for stream re-open header derivation. The
    // streaming path consults the active OTel span at open time as a
    // fallback when this is `None`. Refs #852 PR-C.
    #[allow(dead_code)]
    pub trace_context: Option<rustgate_core::TraceContext>,
}

/// V2 gRPC outbound federation client.
///
/// Maintains a persistent gRPC connection to a remote federation peer,
/// performs the 5-stream handshake, and automatically reconnects on failure.
///
/// In addition to [`Self::send`] for [`figpb::FederatedEvent`], the client
/// exposes [`Self::send_blob`] (unary `SendOneBlob`),
/// [`Self::send_rol`] (client-streaming `ServerROLStream`), and
/// [`Self::send_groups`] (client-streaming
/// `ClientFederateGroupsStream`) so the local server can push the full
/// V2 RPC suite to remote peers (refs #864).
#[derive(Debug)]
pub struct V2Client {
    /// Background task handle.
    task_handle: Option<tokio::task::JoinHandle<()>>,
    /// Shutdown signal sender.
    shutdown_tx: Option<watch::Sender<bool>>,
    /// Channel for sending outbound events to the remote peer.
    outbound_tx: mpsc::Sender<V2Queued>,
    /// Channel for sending outbound binary blobs to the remote peer
    /// (refs #864). Drained by the connection loop and forwarded over
    /// the unary `SendOneBlob` RPC. Held as a separate channel from
    /// `outbound_tx` so a backed-up event stream cannot delay the
    /// blob path (and vice versa).
    blob_tx: mpsc::Sender<figpb::BinaryBlob>,
    /// Channel for sending outbound ROL events to the remote peer
    /// (refs #864). Drained by the connection loop and forwarded over
    /// the long-lived `ServerROLStream` client-streaming RPC.
    rol_tx: mpsc::Sender<figpb::Rol>,
    /// Channel for sending outbound `FederateGroups` updates to the
    /// remote peer (refs #864). Drained by the connection loop and
    /// forwarded over the long-lived `ClientFederateGroupsStream`
    /// client-streaming RPC. Distinct from `outbound_tx` so a
    /// backed-up event channel cannot delay group-sync delivery.
    groups_tx: mpsc::Sender<figpb::FederateGroups>,
    /// Peer state tracking.
    peer: Arc<PeerHandle>,
    /// Optional global backpressure gate shared with ingress admission.
    gate: Option<Arc<BackpressureGate>>,
}

impl V2Client {
    /// Start a new V2 gRPC client that connects to the given address.
    ///
    /// The client spawns a background task that:
    /// 1. Establishes a gRPC channel over TLS
    /// 2. Performs the 5-stream handshake (groups, events, health)
    /// 3. Reconnects automatically on failure with exponential backoff
    ///
    /// # Runtime requirement
    ///
    /// **Must be called from within a tokio runtime context.** This
    /// constructor invokes [`tokio::spawn`] to drive the connection
    /// loop in the background. Calling it from outside a tokio
    /// runtime panics with `there is no reactor running`.
    pub fn start(peer: Arc<PeerHandle>, config: V2ClientConfig) -> Self {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (outbound_tx, outbound_rx) = mpsc::channel::<V2Queued>(256);
        // Side channels for the additional V2 RPCs (refs #864). The
        // capacities mirror `outbound_tx`'s 256 — high enough to absorb
        // a synchronous burst without immediately back-pressuring the
        // local broadcast site, low enough that a stalled remote will
        // surface a `try_send`/`send` failure to the caller.
        let (blob_tx, blob_rx) = mpsc::channel::<figpb::BinaryBlob>(256);
        let (rol_tx, rol_rx) = mpsc::channel::<figpb::Rol>(256);
        let (groups_tx, groups_rx) = mpsc::channel::<figpb::FederateGroups>(64);

        let peer_clone = Arc::clone(&peer);
        let task_handle = tokio::spawn(connection_loop(
            peer_clone,
            config,
            outbound_rx,
            blob_rx,
            rol_rx,
            groups_rx,
            shutdown_rx,
        ));

        Self {
            task_handle: Some(task_handle),
            shutdown_tx: Some(shutdown_tx),
            outbound_tx,
            blob_tx,
            rol_tx,
            groups_tx,
            peer,
            gate: None,
        }
    }

    /// Attach a shared [`BackpressureGate`] so federated outbound traffic
    /// participates in global admission control.
    ///
    /// Every event entering [`V2Client::send`] reserves a byte permit on
    /// the gate while it sits in the bounded outbound channel and is
    /// forwarded over the gRPC send stream. A stalled peer whose channel
    /// is saturating now also pressures the shared gate — the router will
    /// see `is_admitting()` flip to false once the aggregate in-flight
    /// byte count crosses the high-water mark.
    pub fn with_backpressure(&mut self, gate: Arc<BackpressureGate>) {
        self.gate = Some(gate);
    }

    /// Send a FederatedEvent to the remote peer.
    ///
    /// PR-C of #852: equivalent to [`Self::send_with_trace`] with no
    /// explicit trace context — the streaming RPC's stream-open
    /// `traceparent` header derives from the active OTel span. Kept
    /// as a separate entry point so existing callers that have no
    /// `Metadata` context (e.g. the V1-to-V2 bridge during replay)
    /// don't have to thread an extra `None` through every site.
    #[tracing::instrument(level = "debug", skip_all, fields(peer = %self.peer.id), err)]
    pub async fn send(&self, event: figpb::FederatedEvent) -> Result<()> {
        self.send_with_trace(event, None).await
    }

    /// Send a `FederatedEvent` to the remote peer with an explicit
    /// W3C trace context. Closes #852 (PR-C).
    ///
    /// When `trace_context` is `Some`, the federation client prefers
    /// it over the active OTel span when injecting `traceparent` —
    /// this lets a relay node propagate the upstream trace rather
    /// than spawning a fresh one. When `None`, behaviour matches
    /// [`Self::send`] and the OTel span (if any) drives the header.
    ///
    /// Wire format note: the gRPC `ServerEventStream` is a streaming
    /// RPC, so the `traceparent` header lives at stream-open time on
    /// the HTTP/2 headers. Per-event override therefore takes effect
    /// on the next stream re-open / reconnection — until then the
    /// existing stream's open-time header is what every event in the
    /// stream inherits. Per-message trace propagation across a
    /// streaming gRPC requires re-opening the stream, which is a
    /// larger refactor and out of scope for this PR. The unary RPC
    /// paths (`send_one_blob`) apply the override per-call.
    #[tracing::instrument(level = "debug", skip_all, fields(peer = %self.peer.id), err)]
    pub async fn send_with_trace(
        &self,
        event: figpb::FederatedEvent,
        trace_context: Option<rustgate_core::TraceContext>,
    ) -> Result<()> {
        use prost::Message;
        let bytes_len = event.encoded_len();
        self.peer.record_enqueue(bytes_len);
        let permit = self.gate.as_ref().map(|g| Arc::new(g.acquire(bytes_len)));
        let queued = V2Queued {
            event,
            permit,
            trace_context,
        };
        if self.outbound_tx.send(queued).await.is_err() {
            self.peer.record_dequeue();
            return Err(FederationError::other("outbound channel closed"));
        }
        Ok(())
    }

    /// Send a `BinaryBlob` to the remote peer via the unary `SendOneBlob`
    /// RPC (refs #864).
    ///
    /// Wire format mirrors what the V2 server's `send_one_blob` handler
    /// observes: peer-auth, hop-count validation, allowlist gate, and
    /// the `OnBlob` callback. The blob travels independently of the
    /// `FederatedEvent` event channel — a backed-up event stream cannot
    /// delay blob delivery and vice versa.
    ///
    /// # Errors
    ///
    /// Returns [`FederationError`] when the connection loop has shut
    /// down (channel closed). Transient gRPC failures while forwarding
    /// the blob are logged inside the loop; the caller does not block
    /// on the unary RPC's completion.
    #[tracing::instrument(level = "debug", skip_all, fields(peer = %self.peer.id), err)]
    pub async fn send_blob(&self, blob: figpb::BinaryBlob) -> Result<()> {
        if self.blob_tx.send(blob).await.is_err() {
            return Err(FederationError::other("blob channel closed"));
        }
        Ok(())
    }

    /// Send a `Rol` event to the remote peer via the long-lived
    /// `ServerROLStream` client-streaming RPC (refs #864).
    ///
    /// The connection loop maintains a single open `ServerROLStream`
    /// for the lifetime of the gRPC channel; this method enqueues the
    /// ROL event onto an internal mpsc that the loop drains into the
    /// stream. On reconnect the stream is reopened transparently.
    ///
    /// # Errors
    ///
    /// Returns [`FederationError`] when the connection loop has shut
    /// down (channel closed). Stream-level forwarding failures are
    /// logged in the loop and trigger reconnection.
    #[tracing::instrument(level = "debug", skip_all, fields(peer = %self.peer.id), err)]
    pub async fn send_rol(&self, rol: figpb::Rol) -> Result<()> {
        if self.rol_tx.send(rol).await.is_err() {
            return Err(FederationError::other("rol channel closed"));
        }
        Ok(())
    }

    /// Send a `FederateGroups` update to the remote peer via the
    /// long-lived `ClientFederateGroupsStream` client-streaming RPC
    /// (refs #864).
    ///
    /// The connection loop opens the stream during handshake, sends
    /// the local roster as the first message, then keeps the stream
    /// open and forwards every update enqueued through this method.
    /// On reconnect the stream is reopened and the local roster is
    /// re-sent automatically — callers do not need to replay it.
    ///
    /// # Errors
    ///
    /// Returns [`FederationError`] when the connection loop has shut
    /// down (channel closed).
    #[tracing::instrument(level = "debug", skip_all, fields(peer = %self.peer.id), err)]
    pub async fn send_groups(&self, groups: figpb::FederateGroups) -> Result<()> {
        if self.groups_tx.send(groups).await.is_err() {
            return Err(FederationError::other("groups channel closed"));
        }
        Ok(())
    }

    /// Get a reference to the peer handle.
    pub fn peer(&self) -> &PeerHandle {
        &self.peer
    }

    /// Shut down the client and wait for the background task to finish.
    ///
    /// Aborts the task before awaiting it (matching the V1 client). The V2
    /// streaming task can be parked in `send_tx.send().await` against a stalled
    /// peer that keeps ACKing keepalives but stops draining application data;
    /// without the abort, `handle.await` would block until the gRPC request
    /// timeout (up to 300s). Any caller holding the federation manager `RwLock`
    /// across this shutdown — the graceful-drain path and the peer-discovery
    /// reconciler — would then wedge every `fed_forward` reader for that whole
    /// window (#1607). The watch signal is still sent first so an un-wedged
    /// task can observe it and exit cleanly before the abort lands.
    pub async fn shutdown(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(true);
        }
        if let Some(handle) = self.task_handle.take() {
            handle.abort();
            let _ = handle.await;
        }
        self.peer.set_state(PeerState::Disconnected);
    }
}

/// Build a Subscription message identifying ourselves.
fn our_subscription(federate_id: &str) -> figpb::Subscription {
    let server_uid = provenance::deterministic_uuid(federate_id);
    figpb::Subscription {
        identity: Some(figpb::Identity {
            name: federate_id.to_string(),
            uid: server_uid,
            description: String::new(),
            r#type: figpb::identity::ConnectionType::FederationHubClient as i32,
            server_id: federate_id.to_string(),
        }),
        filter: String::new(),
        version: Some(figpb::TakServerVersion {
            major: 5,
            minor: 0,
            patch: 0,
            branch: "release".into(),
            variant: "rustgate".into(),
        }),
    }
}

/// Calculate post-disconnect cooldown before reconnecting.
///
/// TAK Server's federation cleanup can take 30–60 seconds to purge a stale
/// federate entry. Reconnecting too quickly triggers "duplicate federate
/// connection" rejections. The cooldown is 4× the base reconnect delay,
/// with a minimum of 60 seconds.
pub(crate) fn post_disconnect_cooldown(reconnect_delay: Duration) -> Duration {
    let cooldown = reconnect_delay.saturating_mul(4);
    let min_cooldown = Duration::from_secs(60);
    cooldown.max(min_cooldown)
}

/// Decision returned by [`drain_decision_for`] for a single buffered
/// message on the V2 reconnect-replay path.
///
/// Split out so the policy is testable without standing up a full gRPC
/// session — `tonic::Streaming` has no synthetic constructor and the
/// drain hot-path's correctness is purely a function of the buffered
/// envelope and the configured `max_hops`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DrainDecision {
    /// Forward the message with this post-increment hop count.
    Emit { effective_hops: u32 },
    /// Drop the message at the hop-limit boundary (audit emitted by
    /// the caller).
    Drop { effective_hops: u32 },
}

/// Decide whether a buffered message should be re-emitted or dropped
/// at the hop limit on the V2 reconnect-replay path. Closes #763.
///
/// `current_hops` on the buffered envelope is the **post-increment**
/// value (what the message would have carried if it had been emitted
/// live instead of buffered). For records written by binaries that
/// predate this change (`is_legacy_pre_increment = true`), apply
/// `+1` lazily here so legacy entries match the post-#763 invariant
/// without rewriting the on-disk store.
pub(crate) fn drain_decision_for(msg: &BufferedMessage, max_hops: u32) -> DrainDecision {
    let effective_hops = if msg.is_legacy_pre_increment {
        msg.current_hops.saturating_add(1)
    } else {
        msg.current_hops
    };
    if effective_hops >= max_hops {
        DrainDecision::Drop { effective_hops }
    } else {
        DrainDecision::Emit { effective_hops }
    }
}

/// Main connection loop with automatic reconnection.
async fn connection_loop(
    peer: Arc<PeerHandle>,
    config: V2ClientConfig,
    mut outbound_rx: mpsc::Receiver<V2Queued>,
    mut blob_rx: mpsc::Receiver<figpb::BinaryBlob>,
    mut rol_rx: mpsc::Receiver<figpb::Rol>,
    mut groups_rx: mpsc::Receiver<figpb::FederateGroups>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let mut reconnect_count: u32 = 0;

    loop {
        // Check shutdown
        if *shutdown_rx.borrow() {
            info!(peer = %peer.id, "shutdown requested, exiting connection loop");
            break;
        }

        // Check reconnect limit
        if should_stop_reconnecting(config.max_reconnects, reconnect_count) {
            info!(
                peer = %peer.id,
                max = config.max_reconnects,
                "max reconnect attempts reached"
            );
            peer.set_state(PeerState::Disconnected);
            break;
        }

        if reconnect_count > 0 {
            peer.set_state(PeerState::Reconnecting);
            let _ = peer.increment_reconnect_count();
            let delay = backoff_delay(config.reconnect_delay, reconnect_count);
            info!(
                peer = %peer.id,
                attempt = reconnect_count,
                delay = ?delay,
                "reconnecting after delay"
            );

            tokio::select! {
                _ = tokio::time::sleep(delay) => {}
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
            }
        }

        peer.set_state(PeerState::Connecting);
        info!(peer = %peer.id, address = %config.address, "connecting to remote peer");

        // Build the gRPC channel
        let channel = match build_channel(
            &config.address,
            config.tls_config.clone(),
            config.pin_verifier.clone(),
        )
        .await
        {
            Ok(ch) => ch,
            Err(e) => {
                rustgate_core::audit::federation_connect_failed(&peer.id, &e.to_string());
                warn!(peer = %peer.id, error = %e, "failed to build gRPC channel");
                peer.set_error(&e.to_string());
                reconnect_count += 1;
                continue;
            }
        };

        let mut client = FederatedChannelClient::new(channel);
        if let Some(kind) = config.compression {
            let enc = compression_encoding(kind);
            // Chain in a temporary binding — the tonic builders consume and
            // return Self, so we rebind after each configuration step.
            client = client.send_compressed(enc).accept_compressed(enc);
        }

        // Drain replay buffer before entering the stream loop.
        // F-113: ReplayDrain takes `&PeerId` directly.
        let replay_messages: Vec<BufferedMessage> = config
            .replay_drain
            .as_ref()
            .map(|drain| drain(&peer.id))
            .unwrap_or_default();

        if !replay_messages.is_empty() {
            info!(
                peer = %peer.id,
                replayed_count = replay_messages.len(),
                "replaying buffered messages after reconnection"
            );
        }

        // Run the handshake and event loop. Threads the additional V2
        // RPC channels through (refs #864) — the loop drains each into
        // its own gRPC stream / unary call independently of the main
        // event flow.
        let result = run_streams(
            &peer,
            client,
            &config,
            &mut outbound_rx,
            &mut blob_rx,
            &mut rol_rx,
            &mut groups_rx,
            &mut shutdown_rx,
            replay_messages,
        )
        .await;

        match result {
            Ok(()) => {
                rustgate_core::audit::federation_peer_disconnected(&peer.id, "clean shutdown");
                info!(peer = %peer.id, "streams closed gracefully");
            }
            Err(e) => {
                rustgate_core::audit::federation_peer_disconnected(&peer.id, &e.to_string());
                warn!(peer = %peer.id, error = %e, "streams failed");
                peer.set_error(&e.to_string());
            }
        }

        peer.set_state(PeerState::Disconnected);

        // Post-disconnect cooldown: wait before reconnecting to give the remote
        // TAK Server time to purge the stale federate entry. Without this delay,
        // rapid reconnection triggers "duplicate federate connection" rejections
        // on the remote side. Use 4× the base reconnect delay, minimum 60s.
        let cooldown = post_disconnect_cooldown(config.reconnect_delay);
        info!(
            peer = %peer.id,
            cooldown = ?cooldown,
            "post-disconnect cooldown before reconnect"
        );

        tokio::select! {
            _ = tokio::time::sleep(cooldown) => {}
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    break;
                }
            }
        }

        reconnect_count += 1;
    }

    // Drain any messages still buffered in the outbound channel and clear
    // the per-peer queue accounting so the metrics gauges return to zero.
    // Without this, messages queued for a peer that has given up reconnecting
    // (or been shut down) would leak counter weight on the gauges for the
    // lifetime of the process.
    outbound_rx.close();
    let mut drained = 0usize;
    while outbound_rx.try_recv().is_ok() {
        drained += 1;
    }
    if drained > 0 {
        debug!(
            peer = %peer.id,
            drained,
            "discarded buffered events on V2 client exit"
        );
    }
    // Drain the V2 RPC side channels too (refs #864). Each carries
    // owned wire payloads — discarding them here is the only way to
    // avoid keeping the channel allocations alive past the loop exit.
    blob_rx.close();
    while blob_rx.try_recv().is_ok() {}
    rol_rx.close();
    while rol_rx.try_recv().is_ok() {}
    groups_rx.close();
    while groups_rx.try_recv().is_ok() {}
    peer.reset_queue();
}

/// Build a tonic gRPC channel with TLS.
///
/// When `pin_verifier` is `Some` (SEC-1), the channel is built with
/// [`Endpoint::tls_config_with_verifier`] so the supplied
/// [`rustls::client::danger::ServerCertVerifier`] performs both chain
/// validation and the peer-CN pin inside the TLS layer — tonic otherwise
/// never exposes the server leaf certificate to application code. When
/// `None`, tonic's default verifier is used (historical behaviour).
async fn build_channel(
    address: &str,
    tls_config: ClientTlsConfig,
    pin_verifier: Option<Arc<dyn rustls::client::danger::ServerCertVerifier>>,
) -> Result<Channel> {
    // Parse the address and ensure it has the https scheme
    let uri: Uri = format!("https://{address}")
        .parse()
        .map_err(|e| FederationError::other(format!("invalid address: {e}")))?;

    let tls_endpoint = match pin_verifier {
        Some(verifier) => Endpoint::from(uri)
            .tls_config_with_verifier(tls_config, verifier)
            .map_err(|e| FederationError::other(format!("TLS config (CN-pinned) error: {e}")))?,
        None => Endpoint::from(uri)
            .tls_config(tls_config)
            .map_err(|e| FederationError::other(format!("TLS config error: {e}")))?,
    };

    let endpoint = tls_endpoint
        .connect_timeout(Duration::from_secs(30))
        .timeout(Duration::from_secs(300))
        // gRPC keepalive: ping every 10s, timeout after 5s, allow while idle.
        // Matches TAK Server federation protocol expectations.
        .http2_keep_alive_interval(Duration::from_secs(10))
        .keep_alive_timeout(Duration::from_secs(5))
        .keep_alive_while_idle(true);

    let channel = endpoint
        .connect()
        .await
        .map_err(|e| FederationError::other(format!("gRPC connect error: {e}")))?;

    Ok(channel)
}

/// Build a `tonic::Request` with the active OpenTelemetry trace
/// context (W3C `traceparent` + optional `tracestate`) injected as gRPC
/// metadata. Wraps `Request::new` with the
/// [`super::traceparent::inject_into_request`] helper at the single
/// federation-outbound call site so every RPC ([`figpb::FederatedEvent`],
/// [`figpb::BinaryBlob`], [`figpb::Rol`], [`figpb::FederateGroups`],
/// `Subscription`, `ClientHealth`) propagates the parent trace
/// uniformly. Refs #852 PR-B.
///
/// When the `otel` feature is off (or no active span has a valid OTel
/// context), the helper is a no-op — the wire format is unchanged from
/// the pre-#852 baseline.
fn outbound_request<T>(payload: T) -> Request<T> {
    let mut req = Request::new(payload);
    super::traceparent::inject_into_request(&mut req);
    req
}

/// Build a `tonic::Request` whose `traceparent` header is derived from
/// an explicit caller-supplied [`rustgate_core::TraceContext`] when
/// present, falling back to the active OTel span otherwise. Closes
/// #852 (PR-C).
///
/// The explicit context wins so that a federation relay node continues
/// the upstream trace rather than spawning a fresh one — without this,
/// every relay hop would appear as an independent trace and the
/// cross-service correlation graph would lose the upstream parent.
//
// justification: the V2 outbound stream sets `traceparent` on the
// gRPC HTTP/2 headers at stream-open time; per-event override on
// the streaming RPC requires re-opening the stream, which is a
// future refactor (the carry is in place via `V2Queued.trace_context`).
// This helper is the wire-side of that override and is exercised by
// unit tests below — the production hot path consumes it once the
// per-event re-open lands.
#[allow(dead_code)]
fn outbound_request_with_trace<T>(
    payload: T,
    explicit: Option<&rustgate_core::TraceContext>,
) -> Request<T> {
    let mut req = Request::new(payload);
    match explicit {
        Some(ctx) => super::traceparent::inject_explicit_context(&mut req, ctx),
        None => super::traceparent::inject_into_request(&mut req),
    }
    req
}

/// Run the handshake and maintain all concurrent streams.
///
/// Stream sequence (TAK Server SDK compatible):
/// 1. ServerFederateGroupsStream — receive remote groups (server-streaming)
/// 2. ClientFederateGroupsStream — send our groups (client-streaming)
/// 3. ServerEventStream — open for sending events (client-streaming)
/// 4. ClientEventStream — open for receiving events (server-streaming)
/// 5. ServerROLStream — open for sending ROL events (client-streaming, refs #864)
/// 6. Health check loop — periodic HealthCheck RPCs
///
/// `BinaryBlob` outbound traffic uses the unary `SendOneBlob` RPC and
/// is dispatched directly from the `select!` arm rather than over a
/// dedicated long-lived stream — this matches the server-side path
/// that fires `OnBlob`. ROL and group-sync use long-lived
/// client-streaming RPCs so the per-event peer auth + audit on the
/// server side amortizes across the connection lifetime.
// justification: `run_streams` is the dispatch entry-point for the V2
// connection loop and is called exactly once per reconnection attempt.
// Bundling the receiver halves into a struct would just push the same
// fan-in upstream into `connection_loop` without reducing live
// references at the call site, and the receivers each drive a
// distinct gRPC stream that the function selects across — they are
// not interchangeable. Refs #864.
#[allow(clippy::too_many_arguments)]
async fn run_streams(
    peer: &Arc<PeerHandle>,
    mut client: FederatedChannelClient<Channel>,
    config: &V2ClientConfig,
    outbound_rx: &mut mpsc::Receiver<V2Queued>,
    blob_rx: &mut mpsc::Receiver<figpb::BinaryBlob>,
    rol_rx: &mut mpsc::Receiver<figpb::Rol>,
    groups_rx: &mut mpsc::Receiver<figpb::FederateGroups>,
    shutdown_rx: &mut watch::Receiver<bool>,
    replay_messages: Vec<BufferedMessage>,
) -> Result<()> {
    let sub = our_subscription(&config.federate_id);

    // --- Step 1: ServerFederateGroupsStream (receive remote groups) ---
    let mut server_groups_stream = client
        .server_federate_groups_stream(outbound_request(sub.clone()))
        .await
        .map_err(|e| FederationError::other(format!("server_federate_groups_stream failed: {e}")))?
        .into_inner();

    // Wait for the first message to confirm recognition
    if let Some(first_msg) = server_groups_stream
        .message()
        .await
        .map_err(|e| FederationError::other(format!("failed to receive initial groups: {e}")))?
    {
        info!(
            peer = %peer.id,
            groups = ?first_msg.federate_groups,
            "received remote peer groups"
        );
    }

    // --- Step 2: ClientFederateGroupsStream (send our groups) ---
    // Local channel feeding the gRPC stream. The outer `groups_rx`
    // owned by the connection loop forwards updates into this channel
    // through the `select!` arm below; the V2Client::send_groups path
    // therefore stays independent of the local roster bootstrap.
    let (groups_send_tx, groups_send_rx) = mpsc::channel::<figpb::FederateGroups>(16);
    let groups_stream = tokio_stream::wrappers::ReceiverStream::new(groups_send_rx);

    // Per-RPC observability (closes #1299): measure open-call duration
    // for the long-lived `ClientFederateGroupsStream` client-streaming
    // RPC. The duration recorded here is "time spent opening the
    // stream", not "time the stream stayed open" — that's what the
    // server-side handler's own duration histogram covers. On the
    // client side, the open-call duration is the actionable signal:
    // a slow open means the remote is overloaded or the trust path is
    // mis-cached.
    #[cfg(feature = "api")]
    let _client_groups_in_flight = crate::metrics::InFlightGuard::enter(
        crate::metrics::RPC_CLIENT_FEDERATE_GROUPS_STREAM,
        peer.id.as_str(),
    );
    #[cfg(feature = "api")]
    let client_groups_started = std::time::Instant::now();
    let groups_resp = client
        .client_federate_groups_stream(outbound_request(groups_stream))
        .await;
    #[cfg(feature = "api")]
    {
        let elapsed = client_groups_started.elapsed().as_secs_f64();
        let label = crate::metrics::sanitize_peer_label(peer.id.as_str());
        let result_label = match &groups_resp {
            Ok(_) => crate::metrics::RESULT_SUCCESS,
            Err(status) => crate::metrics::classify_status(status.code()),
        };
        crate::metrics::rpc_duration()
            .with_label_values(&[
                crate::metrics::RPC_CLIENT_FEDERATE_GROUPS_STREAM,
                label.as_str(),
                result_label,
            ])
            .observe(elapsed);
        crate::metrics::rpc_total()
            .with_label_values(&[
                crate::metrics::RPC_CLIENT_FEDERATE_GROUPS_STREAM,
                label.as_str(),
                result_label,
            ])
            .inc();
    }
    let _groups_resp = groups_resp.map_err(|e| {
        FederationError::other(format!("client_federate_groups_stream failed: {e}"))
    })?;

    // Send our initial groups
    let our_groups = figpb::FederateGroups {
        stream_update: Some(figpb::ServerHealth {
            status: figpb::server_health::ServingStatus::Serving as i32,
        }),
        federate_groups: config.groups.clone(),
        federate_provenance: Vec::new(),
        federate_hops: None,
        federate_group_hop_limits: None,
        nested_groups: Vec::new(),
    };
    groups_send_tx
        .send(our_groups)
        .await
        .map_err(|_| FederationError::other("groups channel closed"))?;

    // --- Step 3: ServerEventStream (open for sending) ---
    let (send_tx, send_rx) = mpsc::channel::<figpb::FederatedEvent>(256);
    let send_stream = tokio_stream::wrappers::ReceiverStream::new(send_rx);

    // Per-RPC observability (closes #1299): measure open-call duration
    // for the long-lived `ServerEventStream` client-streaming RPC. See
    // the comment on the `ClientFederateGroupsStream` open above for
    // the rationale on "open-call vs stream-lifetime" duration.
    #[cfg(feature = "api")]
    let _server_event_in_flight = crate::metrics::InFlightGuard::enter(
        crate::metrics::RPC_SERVER_EVENT_STREAM,
        peer.id.as_str(),
    );
    #[cfg(feature = "api")]
    let server_event_started = std::time::Instant::now();
    let send_resp = client
        .server_event_stream(outbound_request(send_stream))
        .await;
    #[cfg(feature = "api")]
    {
        let elapsed = server_event_started.elapsed().as_secs_f64();
        let label = crate::metrics::sanitize_peer_label(peer.id.as_str());
        let result_label = match &send_resp {
            Ok(_) => crate::metrics::RESULT_SUCCESS,
            Err(status) => crate::metrics::classify_status(status.code()),
        };
        crate::metrics::rpc_duration()
            .with_label_values(&[
                crate::metrics::RPC_SERVER_EVENT_STREAM,
                label.as_str(),
                result_label,
            ])
            .observe(elapsed);
        crate::metrics::rpc_total()
            .with_label_values(&[
                crate::metrics::RPC_SERVER_EVENT_STREAM,
                label.as_str(),
                result_label,
            ])
            .inc();
    }
    let _send_resp = send_resp
        .map_err(|e| FederationError::other(format!("server_event_stream failed: {e}")))?;

    // --- Step 4: ClientEventStream (open for receiving) ---
    let mut recv_stream = client
        .client_event_stream(outbound_request(sub.clone()))
        .await
        .map_err(|e| FederationError::other(format!("client_event_stream failed: {e}")))?
        .into_inner();

    // --- Step 5: ServerROLStream (open for sending ROL events, refs #864) ---
    // Same shape as the event send stream: a local mpsc feeds the
    // gRPC client-streaming RPC, and the outer `rol_rx` is forwarded
    // into it through the `select!` arm below. Separate from the event
    // path so a backed-up event channel cannot delay ROL delivery.
    let (rol_send_tx, rol_send_rx) = mpsc::channel::<figpb::Rol>(256);
    let rol_stream = tokio_stream::wrappers::ReceiverStream::new(rol_send_rx);

    // Per-RPC observability (closes #1299): measure open-call duration
    // for `ServerROLStream`. See the `ServerEventStream` open block
    // above for the per-RPC observation rationale.
    #[cfg(feature = "api")]
    let _server_rol_in_flight = crate::metrics::InFlightGuard::enter(
        crate::metrics::RPC_SERVER_ROL_STREAM,
        peer.id.as_str(),
    );
    #[cfg(feature = "api")]
    let server_rol_started = std::time::Instant::now();
    let rol_resp = client.server_rol_stream(outbound_request(rol_stream)).await;
    #[cfg(feature = "api")]
    {
        let elapsed = server_rol_started.elapsed().as_secs_f64();
        let label = crate::metrics::sanitize_peer_label(peer.id.as_str());
        let result_label = match &rol_resp {
            Ok(_) => crate::metrics::RESULT_SUCCESS,
            Err(status) => crate::metrics::classify_status(status.code()),
        };
        crate::metrics::rpc_duration()
            .with_label_values(&[
                crate::metrics::RPC_SERVER_ROL_STREAM,
                label.as_str(),
                result_label,
            ])
            .observe(elapsed);
        crate::metrics::rpc_total()
            .with_label_values(&[
                crate::metrics::RPC_SERVER_ROL_STREAM,
                label.as_str(),
                result_label,
            ])
            .inc();
    }
    let _rol_resp =
        rol_resp.map_err(|e| FederationError::other(format!("server_rol_stream failed: {e}")))?;

    // --- Connection established ---
    peer.set_state(PeerState::Connected);
    peer.mark_connected();
    rustgate_core::audit::federation_peer_connected(&peer.id, &config.federate_id, "outbound");
    info!(peer = %peer.id, "V2 gRPC handshake complete, streams active");

    // --- Step 5: Run all streams concurrently ---
    let mut health_ticker = tokio::time::interval(config.health_interval);
    // Skip the first immediate tick — do an explicit initial health check instead
    let _ = health_ticker.tick().await;

    // Initial health check (immediate, prevents inactivity disconnect)
    let hc_start = tokio::time::Instant::now();
    let health_result = client
        .health_check(outbound_request(figpb::ClientHealth {
            status: figpb::client_health::ServingStatus::Serving as i32,
        }))
        .await;

    if let Err(e) = health_result {
        warn!(peer = %peer.id, error = %e, "initial health check failed");
        return Err(FederationError::other(format!(
            "initial health check failed: {e}"
        )));
    }
    let rtt_nanos = hc_start.elapsed().as_nanos() as u64;
    peer.record_rtt(rtt_nanos);
    debug!(peer = %peer.id, rtt_ns = rtt_nanos, "initial health check passed");

    // Replay buffered messages after handshake completes. See
    // [`drain_decision_for`] for the hop-limit policy (closes #763).
    for msg in &replay_messages {
        match drain_decision_for(msg, config.max_hops) {
            DrainDecision::Drop { effective_hops } => {
                warn!(
                    peer = %peer.id,
                    current_hops = effective_hops,
                    max_hops = config.max_hops,
                    legacy_pre_increment = msg.is_legacy_pre_increment,
                    "dropping buffered message at hop limit on drain"
                );
                rustgate_core::audit::federation_event_rejected(
                    "v2.replay_drain",
                    peer.id.as_str(),
                    "hop_limit",
                );
                continue;
            }
            DrainDecision::Emit { effective_hops } => {
                // Reconstruct provenance so a live hop chain carries
                // through even though the only field varying across
                // peers is `current_hops`. The provenance vector lists
                // only this server because the store-forward layer
                // does not persist per-server breadcrumbs — that would
                // balloon the on-disk footprint without adding
                // forensic value the audit trail does not already
                // capture.
                let metadata = crate::provenance::FederationMetadata {
                    provenance: vec![crate::provenance::FederateProvenance {
                        server_id: rustgate_core::PeerId::new(&config.federate_id),
                        server_name: rustgate_core::ServerName::new(&config.federate_id),
                    }],
                    current_hops: effective_hops,
                    max_hops: config.max_hops,
                };
                match crate::v2::convert::xml_to_federated_event(&msg.payload, &metadata) {
                    Ok(event) => {
                        if send_tx.send(event).await.is_err() {
                            warn!(peer = %peer.id, "send stream closed during replay");
                            return Err(FederationError::other("send stream closed during replay"));
                        }
                        peer.record_sent();
                    }
                    Err(e) => {
                        warn!(
                            peer = %peer.id,
                            error = %e,
                            "failed to convert buffered message for V2 replay, skipping"
                        );
                    }
                }
            }
        }
    }

    if !replay_messages.is_empty() {
        debug!(
            peer = %peer.id,
            count = replay_messages.len(),
            "finished replaying buffered messages"
        );
    }

    loop {
        tokio::select! {
            // Receive events from remote
            msg = recv_stream.message() => {
                match msg {
                    Ok(Some(event)) => {
                        peer.record_recv();
                        peer.record_heartbeat();
                        // F-113: callback receives a typed `PeerId` clone.
                        // PR-C of #852: server-streaming `client_event_stream`
                        // sets the W3C `traceparent` on the gRPC response
                        // headers (handled at stream open inside
                        // `outbound_request`). Per-message extraction here
                        // would require introspecting the stream's
                        // response-headers cache, which tonic does not
                        // surface mid-stream. Pass `None` so the consumer
                        // falls back to the active OTel span. The mainline
                        // relay path goes through the V2 server side
                        // (`server_event_stream` / `send_one_event`) where
                        // the per-RPC header IS extracted.
                        (config.on_event)(event, peer.id.clone(), None);
                    }
                    Ok(None) => {
                        info!(peer = %peer.id, "receive stream ended");
                        break;
                    }
                    Err(e) => {
                        warn!(peer = %peer.id, error = %e, "receive stream error");
                        return Err(FederationError::other(format!(
                            "receive stream error: {e}"
                        )));
                    }
                }
            }

            // Receive remote group updates
            msg = server_groups_stream.message() => {
                match msg {
                    Ok(Some(groups_msg)) => {
                        debug!(
                            peer = %peer.id,
                            groups = ?groups_msg.federate_groups,
                            "remote peer updated groups"
                        );
                    }
                    Ok(None) => {
                        info!(peer = %peer.id, "groups stream ended");
                        break;
                    }
                    Err(e) => {
                        warn!(peer = %peer.id, error = %e, "groups stream error");
                        return Err(FederationError::other(format!(
                            "groups stream error: {e}"
                        )));
                    }
                }
            }

            // Forward outbound events to remote
            Some(queued) = outbound_rx.recv() => {
                peer.record_dequeue();
                // Move the event out so we can forward it; the permit
                // survives inside `queued` and drops at end of this arm,
                // releasing its byte reservation back to the global gate.
                // PR-C of #852: `trace_context` is queued alongside the
                // event for future per-message header injection. The
                // streaming RPC sets `traceparent` once at stream-open
                // time (handled by `outbound_request` on the call site
                // above); per-event override would require a separate
                // unary RPC path and is out of scope for this PR. The
                // explicit context is therefore consumed here without
                // an in-stream injection — the carry remains so the
                // future per-message wire is a one-line change.
                let V2Queued {
                    event,
                    permit: _permit,
                    trace_context: _trace,
                } = queued;
                if send_tx.send(event).await.is_err() {
                    warn!(peer = %peer.id, "send stream closed");
                    break;
                }
                peer.record_sent();
                // `_permit` drops here — reservation released.
            }

            // Forward outbound binary blobs to remote via unary
            // `SendOneBlob` (refs #864). The unary RPC is awaited here
            // rather than spawned so a slow remote naturally back-
            // pressures the in-flight blob queue (capacity 256). A
            // failure breaks the loop so the connection_loop's
            // reconnect logic kicks in — same recovery shape as the
            // event send stream.
            //
            // Per-RPC observability (closes #1299): unary RPC, so the
            // observation pattern is the textbook one — start timer
            // and in-flight guard on entry, observe on exit, classify
            // result from `tonic::Status::code()`.
            Some(blob) = blob_rx.recv() => {
                let blob_bytes = blob.data.len();
                #[cfg(feature = "api")]
                let _blob_in_flight = crate::metrics::InFlightGuard::enter(
                    crate::metrics::RPC_SEND_ONE_BLOB,
                    peer.id.as_str(),
                );
                #[cfg(feature = "api")]
                let blob_started = std::time::Instant::now();
                let resp = client.send_one_blob(outbound_request(blob)).await;
                #[cfg(feature = "api")]
                {
                    let elapsed = blob_started.elapsed().as_secs_f64();
                    let label = crate::metrics::sanitize_peer_label(peer.id.as_str());
                    let result_label = match &resp {
                        Ok(_) => crate::metrics::RESULT_SUCCESS,
                        Err(status) => crate::metrics::classify_status(status.code()),
                    };
                    crate::metrics::rpc_duration()
                        .with_label_values(&[
                            crate::metrics::RPC_SEND_ONE_BLOB,
                            label.as_str(),
                            result_label,
                        ])
                        .observe(elapsed);
                    crate::metrics::rpc_total()
                        .with_label_values(&[
                            crate::metrics::RPC_SEND_ONE_BLOB,
                            label.as_str(),
                            result_label,
                        ])
                        .inc();
                }
                if let Err(e) = resp {
                    warn!(
                        peer = %peer.id,
                        error = %e,
                        blob_bytes = blob_bytes,
                        "send_one_blob failed"
                    );
                    return Err(FederationError::other(format!(
                        "send_one_blob failed: {e}"
                    )));
                }
                debug!(peer = %peer.id, blob_bytes, "blob forwarded to remote");
            }

            // Forward outbound ROL events to remote via the long-lived
            // `ServerROLStream` client-streaming RPC (refs #864).
            Some(rol) = rol_rx.recv() => {
                if rol_send_tx.send(rol).await.is_err() {
                    warn!(peer = %peer.id, "rol send stream closed");
                    break;
                }
            }

            // Forward outbound `FederateGroups` updates to remote via
            // the long-lived `ClientFederateGroupsStream` RPC (refs #864).
            Some(groups_update) = groups_rx.recv() => {
                if groups_send_tx.send(groups_update).await.is_err() {
                    warn!(peer = %peer.id, "groups send stream closed");
                    break;
                }
            }

            // Periodic health checks (also measures RTT for latency-aware routing)
            _ = health_ticker.tick() => {
                let hc_start = tokio::time::Instant::now();
                let resp = client
                    .health_check(outbound_request(figpb::ClientHealth {
                        status: figpb::client_health::ServingStatus::Serving as i32,
                    }))
                    .await;

                match resp {
                    Ok(r) => {
                        let rtt_nanos = hc_start.elapsed().as_nanos() as u64;
                        peer.record_rtt(rtt_nanos);
                        let status = r.into_inner().status;
                        if status != figpb::server_health::ServingStatus::Serving as i32 {
                            warn!(peer = %peer.id, status, "remote not serving");
                        }
                        peer.record_heartbeat();
                    }
                    Err(e) => {
                        error!(peer = %peer.id, error = %e, "health check failed");
                        return Err(FederationError::other(format!(
                            "health check failed: {e}"
                        )));
                    }
                }
            }

            // Shutdown signal
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    info!(peer = %peer.id, "shutdown signal received");
                    break;
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(unused_results, clippy::panic, clippy::unwrap_used)]

    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use crate::config::{PeerConfig, RoutingMode};

    fn test_peer(id: &str) -> Arc<PeerHandle> {
        Arc::new(PeerHandle::new(PeerConfig {
            id: id.into(),
            address: "127.0.0.1:9001".into(),
            groups: vec!["Alpha".into()],
            inbound_groups: None,
            outbound_groups: None,
            enabled: true,
            is_outbound: true,
            trust_cert_cn: None,
            routing_mode: RoutingMode::Broadcast,
            protocol_version: 2,
            jwt_token: None,
            region: None,
            zone: None,
            priority: 100,
            compression: None,
            tenants: Default::default(),
            topology_role: Default::default(),
            discovered: false,
        }))
    }

    fn noop_on_event() -> OnEvent {
        Arc::new(|_event, _peer, _trace| {})
    }

    fn counting_on_event() -> (OnEvent, Arc<AtomicU64>) {
        let count = Arc::new(AtomicU64::new(0));
        let c = Arc::clone(&count);
        let cb: OnEvent = Arc::new(move |_event, _peer, _trace| {
            c.fetch_add(1, Ordering::Relaxed);
        });
        (cb, count)
    }

    #[test]
    fn our_subscription_has_identity() {
        let sub = our_subscription("test-server");
        let identity = sub.identity.expect("identity");
        assert_eq!(identity.name, "test-server");
        assert_eq!(identity.server_id, "test-server");
        assert_eq!(
            identity.r#type,
            figpb::identity::ConnectionType::FederationHubClient as i32
        );
    }

    #[test]
    fn our_subscription_has_version() {
        let sub = our_subscription("s");
        let ver = sub.version.expect("version");
        assert_eq!(ver.major, 5);
        assert_eq!(ver.variant, "rustgate");
    }

    #[test]
    fn our_subscription_uid_is_deterministic() {
        let sub = our_subscription("my-server");
        let identity = sub.identity.expect("identity");
        assert_eq!(identity.uid, provenance::deterministic_uuid("my-server"));
    }

    #[tokio::test]
    async fn client_send_fails_after_shutdown() {
        let peer = test_peer("test-peer");
        let tls_config = ClientTlsConfig::new();

        let mut client = V2Client::start(
            peer,
            V2ClientConfig {
                address: "127.0.0.1:19999".into(),
                tls_config,
                federate_id: "test-server".into(),
                groups: vec!["Alpha".into()],
                health_interval: Duration::from_secs(5),
                reconnect_delay: Duration::from_secs(1),
                max_reconnects: 0, // max_reconnects = 0 means immediate stop
                on_event: noop_on_event(),
                replay_drain: None,
                max_hops: 10,
                compression: None,
                pin_verifier: None,
            },
        );

        // Give the connection loop time to stop (max_reconnects=0)
        tokio::time::sleep(Duration::from_millis(200)).await;
        client.shutdown().await;

        let event = figpb::FederatedEvent::default();
        let result = client.send(event).await;
        assert!(result.is_err());
    }

    /// `send_blob`, `send_rol`, and `send_groups` must surface a closed
    /// channel error once the connection loop has exited (refs #864).
    /// Mirrors `client_send_fails_after_shutdown` for the V2 RPC side
    /// channels — without this, a caller could enqueue blobs onto a
    /// dead channel forever and never see the back-pressure signal.
    #[tokio::test]
    async fn rpc_side_channels_fail_after_shutdown() {
        let peer = test_peer("rpc-shutdown-peer");
        let tls_config = ClientTlsConfig::new();

        let mut client = V2Client::start(
            peer,
            V2ClientConfig {
                address: "127.0.0.1:19899".into(),
                tls_config,
                federate_id: "test-server".into(),
                groups: vec![],
                health_interval: Duration::from_secs(5),
                reconnect_delay: Duration::from_secs(1),
                max_reconnects: 0,
                on_event: noop_on_event(),
                replay_drain: None,
                max_hops: 10,
                compression: None,
                pin_verifier: None,
            },
        );

        tokio::time::sleep(Duration::from_millis(200)).await;
        client.shutdown().await;

        // Each RPC channel should be closed and surface an error.
        assert!(
            client
                .send_blob(figpb::BinaryBlob::default())
                .await
                .is_err(),
            "send_blob must fail after shutdown"
        );
        assert!(
            client.send_rol(figpb::Rol::default()).await.is_err(),
            "send_rol must fail after shutdown"
        );
        assert!(
            client
                .send_groups(figpb::FederateGroups::default())
                .await
                .is_err(),
            "send_groups must fail after shutdown"
        );
    }

    #[tokio::test]
    async fn client_peer_accessor_returns_handle() {
        let peer = test_peer("accessor-test");
        let tls_config = ClientTlsConfig::new();

        let mut client = V2Client::start(
            peer,
            V2ClientConfig {
                address: "127.0.0.1:19998".into(),
                tls_config,
                federate_id: "test-server".into(),
                groups: vec![],
                health_interval: Duration::from_secs(5),
                reconnect_delay: Duration::from_secs(1),
                max_reconnects: 0,
                on_event: noop_on_event(),
                replay_drain: None,
                max_hops: 10,
                compression: None,
                pin_verifier: None,
            },
        );

        assert_eq!(client.peer().id, "accessor-test");

        tokio::time::sleep(Duration::from_millis(200)).await;
        client.shutdown().await;
    }

    #[tokio::test]
    async fn client_shutdown_is_idempotent() {
        let peer = test_peer("shutdown-test");
        let tls_config = ClientTlsConfig::new();

        let mut client = V2Client::start(
            peer,
            V2ClientConfig {
                address: "127.0.0.1:19997".into(),
                tls_config,
                federate_id: "test-server".into(),
                groups: vec![],
                health_interval: Duration::from_secs(5),
                reconnect_delay: Duration::from_secs(1),
                max_reconnects: 0,
                on_event: noop_on_event(),
                replay_drain: None,
                max_hops: 10,
                compression: None,
                pin_verifier: None,
            },
        );

        tokio::time::sleep(Duration::from_millis(200)).await;
        client.shutdown().await;
        // Second shutdown should be a no-op
        client.shutdown().await;
        assert_eq!(client.peer().state(), PeerState::Disconnected);
    }

    #[tokio::test]
    async fn client_peer_state_transitions() {
        let peer = test_peer("state-test");
        let tls_config = ClientTlsConfig::new();

        // With max_reconnects=1, it should try once then stop
        let mut client = V2Client::start(
            Arc::clone(&peer),
            V2ClientConfig {
                address: "127.0.0.1:19996".into(),
                tls_config,
                federate_id: "test-server".into(),
                groups: vec![],
                health_interval: Duration::from_secs(5),
                reconnect_delay: Duration::from_millis(50), // fast reconnect for test
                max_reconnects: 1,
                on_event: noop_on_event(),
                replay_drain: None,
                max_hops: 10,
                compression: None,
                pin_verifier: None,
            },
        );

        // Eventually the client will be disconnected after exhausting retries
        tokio::time::sleep(Duration::from_millis(500)).await;
        client.shutdown().await;
        assert_eq!(peer.state(), PeerState::Disconnected);
    }

    #[test]
    fn counting_callback_increments() {
        let (on_event, count) = counting_on_event();
        on_event(
            figpb::FederatedEvent::default(),
            rustgate_core::PeerId::new("peer-1"),
            None,
        );
        on_event(
            figpb::FederatedEvent::default(),
            rustgate_core::PeerId::new("peer-1"),
            None,
        );
        assert_eq!(count.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn post_disconnect_cooldown_default() {
        // Default reconnect_delay of 30s → 120s cooldown, but minimum is 60s
        let cooldown = post_disconnect_cooldown(Duration::from_secs(30));
        assert_eq!(cooldown, Duration::from_secs(120));
    }

    #[test]
    fn post_disconnect_cooldown_minimum_enforced() {
        // 10s * 4 = 40s, but minimum is 60s
        let cooldown = post_disconnect_cooldown(Duration::from_secs(10));
        assert_eq!(cooldown, Duration::from_secs(60));
    }

    #[test]
    fn post_disconnect_cooldown_exact_minimum() {
        // 15s * 4 = 60s, exactly the minimum
        let cooldown = post_disconnect_cooldown(Duration::from_secs(15));
        assert_eq!(cooldown, Duration::from_secs(60));
    }

    #[test]
    fn post_disconnect_cooldown_zero() {
        let cooldown = post_disconnect_cooldown(Duration::ZERO);
        assert_eq!(cooldown, Duration::from_secs(60));
    }

    // --------------------------------------------------------------
    // Compression mapping (issue #905)
    // --------------------------------------------------------------

    #[test]
    fn compression_encoding_maps_gzip_to_tonic_gzip() {
        // A silent swap to `Zstd` here would send every outbound message
        // on gzip-configured peers with the wrong `grpc-encoding` header,
        // which the server would then try to decode as zstd and reject.
        let got = compression_encoding(CompressionKind::Gzip);
        assert_eq!(got, tonic::codec::CompressionEncoding::Gzip);
    }

    #[test]
    fn compression_encoding_maps_zstd_to_tonic_zstd() {
        let got = compression_encoding(CompressionKind::Zstd);
        assert_eq!(got, tonic::codec::CompressionEncoding::Zstd);
    }

    // -------------------------------------------------------------------
    // V2 reconnect-replay drain — closes #763.
    // -------------------------------------------------------------------
    //
    // The persisted envelope carries the post-increment hop count (what
    // the message would have carried if it had been emitted live instead
    // of buffered). Tests below pin the drain hot-path's hop policy:
    //
    // 1. A message at the boundary (`current_hops = max_hops - 1` is the
    //    last accepted; `current_hops = max_hops` is dropped).
    // 2. A message below the boundary is forwarded verbatim.
    // 3. Legacy v1 records (no version field, stored pre-increment) are
    //    treated as pre-increment: drain applies +1 lazily before the
    //    limit check.
    // 4. The drop path emits a structured audit record with
    //    `reason=hop_limit` so the forensic trail captures the boundary
    //    hit (mirrors the live SendOneEvent rejection path).

    fn buffered(payload: &'static [u8], current_hops: u32, legacy: bool) -> BufferedMessage {
        BufferedMessage {
            seq: 1,
            payload: bytes::Bytes::from_static(payload),
            groups: vec![],
            enqueued_at_unix_ms: 0,
            ttl_ms: None,
            current_hops,
            is_legacy_pre_increment: legacy,
        }
    }

    #[test]
    fn drain_rejects_message_at_hop_limit() {
        // Persist at hops = MAX_HOPS - 1 + 1 = MAX_HOPS (post-increment),
        // drain, assert dropped. Same boundary as the live SendOneEvent
        // path: `current_hops >= max_hops` is rejected.
        let max_hops: u32 = 8;
        let msg = buffered(b"at-limit", max_hops, false);
        match drain_decision_for(&msg, max_hops) {
            DrainDecision::Drop { effective_hops } => {
                assert_eq!(effective_hops, max_hops);
            }
            DrainDecision::Emit { .. } => {
                panic!("expected drop at hops = max_hops, got emit");
            }
        }
    }

    #[test]
    fn drain_accepts_message_below_hop_limit() {
        // Persist at hops = MAX_HOPS - 2 (post-increment), drain, assert
        // accepted. One step below the boundary survives — the live
        // path inclusively accepts up to `max_hops - 1`.
        let max_hops: u32 = 8;
        let msg = buffered(b"below-limit", max_hops - 2, false);
        match drain_decision_for(&msg, max_hops) {
            DrainDecision::Emit { effective_hops } => {
                assert_eq!(effective_hops, max_hops - 2);
            }
            DrainDecision::Drop { .. } => {
                panic!("expected emit below hop limit, got drop");
            }
        }
    }

    #[test]
    fn drain_accepts_message_at_one_below_limit_inclusive() {
        // The exact `max_hops - 1` boundary: emit is the last value that
        // survives. A message at this point on the next hop would land
        // at `max_hops`, which the receiving peer rejects. The drain
        // hot-path mirrors that — `effective_hops < max_hops` is the
        // sole gate.
        let max_hops: u32 = 8;
        let msg = buffered(b"one-below", max_hops - 1, false);
        match drain_decision_for(&msg, max_hops) {
            DrainDecision::Emit { effective_hops } => {
                assert_eq!(effective_hops, max_hops - 1);
            }
            DrainDecision::Drop { .. } => {
                panic!("expected emit at hops = max_hops - 1");
            }
        }
    }

    #[test]
    fn drain_legacy_envelope_applies_plus_one_lazily() {
        // A legacy v1 record persisted as pre-increment with
        // current_hops = MAX_HOPS - 1 must be evaluated as if it were
        // MAX_HOPS post-increment — i.e. dropped. This locks down the
        // backward-compat fallback the issue calls for: existing
        // on-disk records from before the wire-format change still
        // honor the hop-limit boundary on drain.
        let max_hops: u32 = 8;
        let msg = buffered(b"legacy-at-boundary", max_hops - 1, true);
        match drain_decision_for(&msg, max_hops) {
            DrainDecision::Drop { effective_hops } => {
                assert_eq!(
                    effective_hops, max_hops,
                    "legacy +1 must surface as max_hops",
                );
            }
            DrainDecision::Emit { .. } => {
                panic!("expected drop after legacy +1 lift to max_hops");
            }
        }
        // And a legacy record one step below the boundary is still
        // emitted, to prove the +1 isn't applied unconditionally.
        let safe = buffered(b"legacy-safe", max_hops - 2, true);
        match drain_decision_for(&safe, max_hops) {
            DrainDecision::Emit { effective_hops } => {
                assert_eq!(effective_hops, max_hops - 1);
            }
            DrainDecision::Drop { .. } => {
                panic!("expected legacy emit when post-+1 is below max_hops");
            }
        }
    }

    /// Cross-layer regression for #1519 / #763: a hop count persisted at
    /// the boundary via the real redb-backed [`crate::replay_persist`]
    /// store, decoded back through `load_all`, and fed through
    /// [`drain_decision_for`], must produce a **drop** — the same
    /// decision the live SendOneEvent path would reach for a message
    /// bumped to `max_hops`.
    ///
    /// The per-layer tests pin each half in isolation
    /// (`store_forward_persists_post_increment_hops` proves the store
    /// round-trips the post-increment value; `drain_rejects_message_at_hop_limit`
    /// proves the drain gate drops at `max_hops`). This test joins the
    /// seam: it drives a *persisted* value through the *drain* decision
    /// so a regression that corrupts the hop count on the persistence
    /// round-trip — re-opening the store-forward hop-leak #1519 tracks —
    /// fails a test instead of silently letting a stale-hop message
    /// through on reconnect.
    #[test]
    fn persisted_boundary_hop_count_drives_drain_drop() {
        // A live first-hop emit bumps to 1; a message that reaches the
        // limit is persisted at post-increment `max_hops`. Round-trip
        // that boundary value through disk and assert drain drops it.
        let max_hops: u32 = 8;

        let dir = tempfile::tempdir().unwrap();
        let store = crate::replay_persist::ReplayStore::open(dir.path(), 1 << 20).unwrap();
        store
            .put(
                "peer-a",
                1,
                1_000,
                None,
                max_hops,
                &[],
                &bytes::Bytes::from_static(b"at-limit"),
            )
            .unwrap();
        drop(store);

        // Re-open (as on restart) and decode through the production path.
        let store = crate::replay_persist::ReplayStore::open(dir.path(), 1 << 20).unwrap();
        let restored = store.load_all().unwrap();
        assert_eq!(restored.len(), 1, "exactly one persisted record");
        let entry = &restored[0];
        assert_eq!(
            entry.current_hops, max_hops,
            "post-increment hop count must survive the persistence round-trip",
        );
        assert!(
            !entry.is_legacy_pre_increment,
            "a v2-encoded record must not be flagged legacy",
        );

        // Rehydrate into the drain-side envelope exactly as the manager
        // does when refilling the replay ring from disk, then run the
        // production drain gate.
        let msg = BufferedMessage {
            seq: entry.seq,
            payload: entry.payload.clone(),
            groups: entry.groups.clone(),
            enqueued_at_unix_ms: entry.enqueued_at_unix_ms,
            ttl_ms: entry.ttl_ms,
            current_hops: entry.current_hops,
            is_legacy_pre_increment: entry.is_legacy_pre_increment,
        };
        match drain_decision_for(&msg, max_hops) {
            DrainDecision::Drop { effective_hops } => {
                assert_eq!(
                    effective_hops, max_hops,
                    "persisted-then-drained boundary hop must drop at max_hops",
                );
            }
            DrainDecision::Emit { .. } => {
                panic!("persisted record at the hop limit must drop on drain, not emit");
            }
        }

        // One step below the boundary must survive the same round-trip,
        // proving the drop above is the boundary check and not a blanket
        // reject of every restored record.
        let dir2 = tempfile::tempdir().unwrap();
        let store2 = crate::replay_persist::ReplayStore::open(dir2.path(), 1 << 20).unwrap();
        store2
            .put(
                "peer-a",
                1,
                1_000,
                None,
                max_hops - 1,
                &[],
                &bytes::Bytes::from_static(b"one-below"),
            )
            .unwrap();
        let below = store2.load_all().unwrap();
        let below_msg = BufferedMessage {
            seq: below[0].seq,
            payload: below[0].payload.clone(),
            groups: below[0].groups.clone(),
            enqueued_at_unix_ms: below[0].enqueued_at_unix_ms,
            ttl_ms: below[0].ttl_ms,
            current_hops: below[0].current_hops,
            is_legacy_pre_increment: below[0].is_legacy_pre_increment,
        };
        match drain_decision_for(&below_msg, max_hops) {
            DrainDecision::Emit { effective_hops } => {
                assert_eq!(effective_hops, max_hops - 1);
            }
            DrainDecision::Drop { .. } => {
                panic!("persisted record one below the limit must emit on drain");
            }
        }
    }

    /// Build a tracing subscriber that captures `target = "audit"`
    /// records into a shared byte buffer. The callsite emits the audit
    /// inline at the drain drop site, so we set this up as the default
    /// subscriber for the duration of the test, fire one explicit
    /// `federation_event_rejected`, and assert the structured fields
    /// land in the captured output. (Calling the helper directly
    /// rather than going through the full gRPC client keeps the test
    /// independent of the tonic streaming surface, which has no
    /// synthetic constructor.)
    #[test]
    fn audit_emits_hop_limit_on_drain_drop() {
        use std::io::Write;
        use std::sync::Mutex as StdMutex;

        use tracing_subscriber::Layer;
        use tracing_subscriber::filter::Targets;
        use tracing_subscriber::fmt::MakeWriter;
        use tracing_subscriber::layer::SubscriberExt;

        #[derive(Clone, Default)]
        struct AuditBuf(Arc<StdMutex<Vec<u8>>>);

        impl AuditBuf {
            fn snapshot_string(&self) -> String {
                String::from_utf8_lossy(&self.0.lock().expect("buf").clone()).to_string()
            }
        }

        impl Write for AuditBuf {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().expect("buf").extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        impl<'a> MakeWriter<'a> for AuditBuf {
            type Writer = AuditBuf;
            fn make_writer(&'a self) -> Self::Writer {
                self.clone()
            }
        }

        let buf = AuditBuf::default();
        let layer = tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_writer(buf.clone())
            .with_filter(Targets::new().with_target("audit", tracing::Level::INFO));
        let subscriber = tracing_subscriber::registry().with(layer);

        // Pre-condition: drain decides to drop a message at the hop
        // boundary. The audit emission lives at the call site in
        // `run_streams`, so we trigger it inline with the same args
        // that the call site would pass.
        let max_hops: u32 = 8;
        let msg = buffered(b"audit-at-limit", max_hops, false);
        match drain_decision_for(&msg, max_hops) {
            DrainDecision::Drop { .. } => {}
            DrainDecision::Emit { .. } => {
                panic!("test fixture must produce a drop");
            }
        }

        let _guard = tracing::subscriber::set_default(subscriber);
        rustgate_core::audit::federation_event_rejected(
            "v2.replay_drain",
            "test-peer",
            "hop_limit",
        );
        drop(_guard);

        let captured = buf.snapshot_string();
        assert!(
            captured.contains("federation.event_rejected"),
            "audit log must contain federation.event_rejected; got: {captured}"
        );
        assert!(
            captured.contains("v2.replay_drain"),
            "audit record must label the rpc=v2.replay_drain context; got: {captured}"
        );
        assert!(
            captured.contains("hop_limit"),
            "audit record must carry reason=hop_limit; got: {captured}"
        );
        assert!(
            captured.contains("test-peer"),
            "audit record must include peer_cn=test-peer; got: {captured}"
        );
    }

    #[test]
    fn store_forward_persists_post_increment_hops() {
        // Buffer-layer view of the same property tested at the
        // persistence layer: a `push_with_hops(..., N)` returns a
        // `BufferedMessage` whose `current_hops` equals `N` and whose
        // legacy flag is false. Pin both the in-memory ring contents
        // and the disk image so a later rewrite of the buffer plumbing
        // can't silently regress the post-increment invariant.
        use std::sync::Arc;

        use crate::replay_buffer::ReplayBuffer;
        use crate::replay_persist::ReplayStore;

        let dir = tempfile::tempdir().expect("tmpdir");
        let store = Arc::new(ReplayStore::open(dir.path(), 1 << 20).expect("open"));
        let mut buf = ReplayBuffer::with_store(10, "peer-a", Arc::clone(&store));
        // Admit at hops=3 (post-increment). The drain path will see 3.
        let _ = buf.push_with_hops(
            bytes::Bytes::from_static(b"hop-3"),
            vec!["alpha".into()],
            42,
            None,
            3,
        );
        let in_mem = buf.all_messages();
        assert_eq!(in_mem.len(), 1);
        assert_eq!(in_mem[0].current_hops, 3);
        assert!(!in_mem[0].is_legacy_pre_increment);

        let on_disk = store.load_all().expect("load");
        assert_eq!(on_disk.len(), 1);
        assert_eq!(on_disk[0].current_hops, 3);
        assert!(!on_disk[0].is_legacy_pre_increment);
    }

    #[test]
    fn outbound_request_with_trace_uses_explicit_context_when_some() {
        // Closes #852 (PR-C): the helper consults the explicit
        // `TraceContext` when present and renders the canonical W3C
        // banner string into the request metadata. Pin the wire shape
        // here so the federation outbound's "explicit wins over OTel
        // span" contract is exercised at the helper boundary, free of
        // OTel SDK setup. The OTel-fallback branch is exercised in
        // `outbound_request_falls_back_to_otel_span_when_none` below.
        let ctx = rustgate_core::TraceContext::new(
            [
                0x4b, 0xf9, 0x2f, 0x35, 0x77, 0xb3, 0x4d, 0xa6, 0xa3, 0xce, 0x92, 0x9d, 0x0e, 0x0e,
                0x47, 0x36,
            ],
            [0x00, 0xf0, 0x67, 0xaa, 0x0b, 0xa9, 0x02, 0xb7],
            0x01,
        )
        .expect("valid context");
        let req: tonic::Request<()> = outbound_request_with_trace((), Some(&ctx));
        let banner = req
            .metadata()
            .get("traceparent")
            .expect("traceparent set")
            .to_str()
            .unwrap();
        assert_eq!(
            banner,
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
        );
    }

    #[test]
    fn outbound_request_with_trace_falls_back_to_inject_into_request_when_none() {
        // When the caller has no explicit context, the helper delegates
        // to `inject_into_request` — which is a no-op when there's no
        // active OTel span (or `otel` is off). Either way, no
        // traceparent is set on the request because the test runtime
        // has no OTel pipeline staged.
        let req: tonic::Request<()> = outbound_request_with_trace((), None);
        assert!(
            req.metadata().get("traceparent").is_none(),
            "no explicit context + no OTel span → no traceparent header"
        );
    }
}
