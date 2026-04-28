// Copyright © 2026 Roberto Chiofalo.

//! V2 federation gRPC server implementing the FederatedChannel service.
//!
//! Handles inbound federation connections from remote peers over gRPC/mTLS.
//! Implements the TAK Server V2 federation protocol with group exchange,
//! event streaming, health checks, and provenance tracking.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rustgate_core::sanitize::sanitize_for_log;
use tokio::sync::{RwLock, mpsc};
use tokio::task::JoinHandle;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, Streaming};
use tracing::{debug, info, warn};

use super::proto::figpb;
use super::proto::figpb::federated_channel_server::FederatedChannel;
use crate::provenance;

/// Default maximum number of federation hops before an inbound message
/// is dropped (closes #758).
///
/// Prevents routing loops between misconfigured federation peers.
/// Messages arriving with `current_hops` at or exceeding this limit are
/// silently discarded with a warning log.
///
/// **This is a default-only fallback.** The active limit lives on a
/// private `max_hops` field of `FederationService` and can be tuned
/// per-deployment via [`FederationService::with_max_hops`] (CLI flag
/// `--federation-max-hops`, env `RUSTGATE_FEDERATION_MAX_HOPS`). The
/// constant remains exported for tests and external callers that want
/// to assert against the workspace-default boundary without duplicating
/// the literal `8`.
pub const MAX_FEDERATION_HOPS: u8 = 8;

/// Canonical `rpc` label used for `SendOneEvent` audit and metric records.
///
/// Co-located with the handler so the value can be referenced from
/// tests without re-deriving the string.
pub(crate) const RPC_SEND_ONE_EVENT: &str = "send_one_event";

/// Canonical `rpc` label used for `SendOneBlob` audit and metric records
/// (refs #864). Mirrors `RPC_SEND_ONE_EVENT` so a SIEM dashboard joining
/// the two streams sees a uniform `rpc` label vocabulary.
pub(crate) const RPC_SEND_ONE_BLOB: &str = "send_one_blob";

/// Canonical `rpc` label used for `ServerROLStream` audit and metric
/// records (refs #864). The `ServerROLStream` RPC is client-streaming:
/// the remote peer pushes a stream of `ROL` messages and we return a
/// single `Subscription` once they finish. Each inbound `ROL` is
/// observed individually (peer-auth + hop validation + audit + metric +
/// callback) — the stub does not propagate ROL state internally yet.
pub(crate) const RPC_SERVER_ROL_STREAM: &str = "server_rol_stream";

/// Canonical `rpc` label used for `ClientROLStream` audit and metric
/// records (refs #864). The `ClientROLStream` RPC is server-streaming:
/// the remote peer sends a single `Subscription` and we open a stream
/// of `ROL` messages back to them. The observable-stub here records
/// the subscription open with peer-auth + allowlist check + audit +
/// metric, but does not push any ROL events back (the stub holds the
/// stream open without producing payloads — the routing-side machinery
/// for ROL state lands in a separate follow-up).
pub(crate) const RPC_CLIENT_ROL_STREAM: &str = "client_rol_stream";

/// Canonical `rpc` label used for `ServerFederateGroupsStream` audit
/// and metric records (refs #864). The `ServerFederateGroupsStream` RPC
/// is server-streaming: the remote peer sends a single `Subscription`
/// and we push a stream of `FederateGroups` updates back. The
/// observable-stub here records the subscription open with peer-auth +
/// allowlist check + audit + metric, sends the initial groups roster,
/// then holds the stream open without producing further updates — the
/// routing-side machinery for incremental group-sync state lands in a
/// separate follow-up.
pub(crate) const RPC_SERVER_FEDERATE_GROUPS_STREAM: &str = "server_federate_groups_stream";

/// Canonical `rpc` label used for `ClientFederateGroupsStream` audit
/// and metric records (refs #864). The `ClientFederateGroupsStream` RPC
/// is client-streaming: the remote peer pushes a stream of
/// `FederateGroups` updates and we return one `Subscription` once they
/// finish. Each inbound `FederateGroups` is observed individually
/// (peer-auth + hop validation + audit + metric + callback) on top of
/// the existing peer-group bookkeeping (count + name-length limits) the
/// receive loop already performs. The stub does not propagate
/// group-sync state internally yet.
pub(crate) const RPC_CLIENT_FEDERATE_GROUPS_STREAM: &str = "client_federate_groups_stream";

/// Default maximum number of groups a single federation peer can advertise.
///
/// Re-exported from [`crate::config`] for backward compatibility.
pub const DEFAULT_MAX_GROUPS_PER_PEER: usize = crate::config::DEFAULT_MAX_GROUPS_PER_PEER;

/// Default maximum length of a federation group name in bytes.
///
/// Re-exported from [`crate::config`] for backward compatibility.
pub const DEFAULT_MAX_GROUP_NAME_LENGTH: usize = crate::config::DEFAULT_MAX_GROUP_NAME_LENGTH;

/// Callback invoked when a FederatedEvent is received from a remote peer.
///
/// F-113: receives a typed [`rustgate_core::PeerId`] (the connecting
/// peer's mTLS-cert CN) so consumers can no longer accidentally
/// confuse it with a free-form `String` (a server name, group name,
/// or unrelated UID). The CN is converted to `PeerId` at the gRPC
/// boundary inside [`FederationService`]; the wire format is the
/// bare string under TLS, exactly as before.
pub type OnEvent = Arc<dyn Fn(figpb::FederatedEvent, rustgate_core::PeerId) + Send + Sync>;

/// Callback invoked when a BinaryBlob is received from a remote peer
/// via the `SendOneBlob` unary RPC (refs #864). The second argument
/// is the peer's CN (extracted from the mTLS client certificate).
///
/// Defaults to a no-op closure when not configured via
/// [`FederationService::with_on_blob`] — the V2 federation transport
/// continues to accept binary-blob RPCs and emit audit + metrics for
/// each one, but the payload is discarded if the deployment hasn't
/// wired a consumer. This preserves the existing behaviour for
/// callers that don't yet need binary-blob ingress while making the
/// hop-count + authz validation always-on for forensic completeness.
pub type OnBlob = Arc<dyn Fn(figpb::BinaryBlob, rustgate_core::PeerId) + Send + Sync>;

/// Factory for the default no-op `OnBlob` callback. Discards the
/// blob without doing any work — chosen over `Option<OnBlob>` so
/// the call site stays an unconditional `(self.on_blob)(...)`
/// rather than threading an `if let Some(...)` through the hot
/// path. The Arc allocation is one-time per FederationService
/// instance.
fn noop_on_blob() -> OnBlob {
    Arc::new(|_blob, _peer| {})
}

/// Callback invoked when a `ROL` (Region of Interest) message is
/// received from a remote peer via the V2 `ServerROLStream` RPC
/// (refs #864). The second argument is the peer's CN (extracted from
/// the mTLS client certificate).
///
/// Defaults to a no-op closure when not configured via
/// [`FederationService::with_on_rol_event`] — the V2 federation
/// transport continues to accept ROL streams and emit audit + metrics
/// for each event, but the payload is discarded if the deployment
/// hasn't wired a consumer. This preserves the existing behaviour for
/// callers that don't yet need ROL ingress while making the hop-count
/// and authz validation always-on for forensic completeness, mirroring
/// the discipline established by [`OnEvent`] and [`OnBlob`].
pub type OnRolEvent = Arc<dyn Fn(figpb::Rol, rustgate_core::PeerId) + Send + Sync>;

/// Factory for the default no-op `OnRolEvent` callback. Mirrors
/// [`noop_on_blob`]: discards the ROL message without doing any work
/// so the call site stays an unconditional `(self.on_rol_event)(...)`
/// rather than threading an `if let Some(...)` through the per-event
/// hot path inside the streaming receive loop.
fn noop_on_rol_event() -> OnRolEvent {
    Arc::new(|_rol, _peer| {})
}

/// Callback invoked when a `FederateGroups` update is received from a
/// remote peer via the V2 `ClientFederateGroupsStream` RPC (refs #864).
/// The second argument is the peer's CN (extracted from the mTLS client
/// certificate).
///
/// Defaults to a no-op closure when not configured via
/// [`FederationService::with_on_group_sync`] — the V2 federation
/// transport continues to accept group-sync streams and emit audit +
/// metrics for each update, but the payload is discarded if the
/// deployment hasn't wired a consumer. This preserves the existing
/// behaviour for callers that don't yet need group-sync ingress while
/// making the hop-count + authz validation always-on for forensic
/// completeness, mirroring the discipline established by [`OnEvent`],
/// [`OnBlob`], and [`OnRolEvent`]. The existing per-peer group
/// bookkeeping (count + name-length limits, in-memory `peer_groups`
/// map) runs unchanged alongside the callback — the callback is the
/// observation hook for downstream consumers, not a replacement for
/// the receive-loop's group tracking.
pub type OnGroupSync = Arc<dyn Fn(figpb::FederateGroups, rustgate_core::PeerId) + Send + Sync>;

/// Factory for the default no-op `OnGroupSync` callback. Mirrors
/// [`noop_on_rol_event`] / [`noop_on_blob`]: discards the group-sync
/// update without doing any work so the call site stays an
/// unconditional `(self.on_group_sync)(...)` rather than threading an
/// `if let Some(...)` through the per-update hot path inside the
/// streaming receive loop.
fn noop_on_group_sync() -> OnGroupSync {
    Arc::new(|_groups, _peer| {})
}

/// V2 gRPC FederatedChannel service implementation.
///
/// Manages inbound federation connections, tracks per-peer outbound streams
/// and advertised groups, and forwards events to local consumers via callbacks.
pub struct FederationService {
    /// Our federation server identity.
    federate_id: String,
    /// Deterministic UUID derived from federate_id.
    server_uid: String,
    /// Groups we advertise to peers.
    groups: Vec<String>,
    /// Per-peer outbound event streams (peer_id → sender).
    outbound_streams: Arc<RwLock<HashMap<String, mpsc::Sender<figpb::FederatedEvent>>>>,
    /// Per-peer advertised groups.
    peer_groups: Arc<RwLock<HashMap<String, Vec<String>>>>,
    /// Callback for inbound events.
    on_event: OnEvent,
    /// Callback for inbound binary blobs (refs #864). Defaults to a
    /// no-op so existing deployments don't have to opt in; install a
    /// real handler via [`FederationService::with_on_blob`] when the
    /// receiving end wants to consume the blob payload.
    on_blob: OnBlob,
    /// Callback for inbound ROL messages received via `ServerROLStream`
    /// (refs #864). Defaults to a no-op so existing deployments don't
    /// have to opt in; install a real handler via
    /// [`FederationService::with_on_rol_event`] when the receiving end
    /// wants to consume ROL payloads. The callback fires per ROL event
    /// after peer-auth, hop-count, and allowlist validation pass.
    on_rol_event: OnRolEvent,
    /// Callback for inbound `FederateGroups` updates received via
    /// `ClientFederateGroupsStream` (refs #864). Defaults to a no-op so
    /// existing deployments don't have to opt in; install a real
    /// handler via [`FederationService::with_on_group_sync`] when the
    /// receiving end wants to observe group-sync ingress. The callback
    /// fires per inbound update after peer-auth, hop-count, and
    /// allowlist validation pass — it is independent of the existing
    /// per-peer group bookkeeping (count + name-length limits, in-memory
    /// `peer_groups` map) which runs alongside.
    on_group_sync: OnGroupSync,
    /// Maximum number of groups a single peer can advertise.
    max_groups_per_peer: usize,
    /// Maximum length of a group name in bytes.
    max_group_name_length: usize,
    /// Per-peer inbound group allowlist for validating event group claims.
    ///
    /// When configured, inbound events from a peer are rejected if they
    /// claim groups not in the peer's allowlist. When `None`, all groups
    /// are accepted (backward-compatible open mode).
    allowed_peer_groups: Option<Arc<HashMap<String, HashSet<String>>>>,
    /// Maximum number of federation hops before an inbound message is
    /// dropped (closes #758). Defaults to [`MAX_FEDERATION_HOPS`] (8);
    /// override via [`FederationService::with_max_hops`] for tactical
    /// topologies that need a tighter or looser loop-prevention bound.
    /// Range is `1..=255`; the type is `u8` because the value never
    /// needs to exceed 255 hops in practice and the narrower range
    /// catches operator typos at the CLI layer (`clap::value_parser!(u8)`).
    /// Compared against the wire field `FederateHops::current_hops` (i64)
    /// after a widening cast — values above 255 are always rejected
    /// because they would exceed any configured `max_hops`.
    max_hops: u8,
}

impl std::fmt::Debug for FederationService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FederationService")
            .field("federate_id", &self.federate_id)
            .field("server_uid", &self.server_uid)
            .field("groups", &self.groups)
            .field("max_groups_per_peer", &self.max_groups_per_peer)
            .field("max_group_name_length", &self.max_group_name_length)
            .field("max_hops", &self.max_hops)
            .field(
                "allowed_peer_groups_configured",
                &self.allowed_peer_groups.is_some(),
            )
            .finish_non_exhaustive()
    }
}

impl FederationService {
    /// Create a new FederationService with default peer group limits.
    pub fn new(federate_id: String, groups: Vec<String>, on_event: OnEvent) -> Self {
        Self::with_limits(
            federate_id,
            groups,
            on_event,
            DEFAULT_MAX_GROUPS_PER_PEER,
            DEFAULT_MAX_GROUP_NAME_LENGTH,
        )
    }

    /// Create a new FederationService with custom peer group limits.
    ///
    /// - `max_groups_per_peer`: maximum groups a single peer can advertise
    /// - `max_group_name_length`: maximum length of a group name in bytes
    pub fn with_limits(
        federate_id: String,
        groups: Vec<String>,
        on_event: OnEvent,
        max_groups_per_peer: usize,
        max_group_name_length: usize,
    ) -> Self {
        let server_uid = provenance::deterministic_uuid(&federate_id);
        Self {
            federate_id,
            server_uid,
            groups,
            outbound_streams: Arc::new(RwLock::new(HashMap::new())),
            peer_groups: Arc::new(RwLock::new(HashMap::new())),
            on_event,
            on_blob: noop_on_blob(),
            on_rol_event: noop_on_rol_event(),
            on_group_sync: noop_on_group_sync(),
            max_groups_per_peer,
            max_group_name_length,
            allowed_peer_groups: None,
            max_hops: MAX_FEDERATION_HOPS,
        }
    }

    /// Install a callback that fires when the V2 `SendOneBlob` RPC
    /// receives a `BinaryBlob` from a remote peer (refs #864).
    ///
    /// Returns `self` so the call composes with the other
    /// `with_*` builder methods. The default callback (set by
    /// [`Self::new`] / [`Self::with_limits`]) is a no-op that
    /// discards the payload — the V2 transport continues to validate
    /// the hop count and peer-allowlist authz and emit audit + metrics
    /// for every accepted blob even when the consumer isn't wired,
    /// so a deployment can observe ingress before committing to a
    /// downstream sink.
    pub fn with_on_blob(mut self, on_blob: OnBlob) -> Self {
        self.on_blob = on_blob;
        self
    }

    /// Install a callback that fires when the V2 `ServerROLStream` RPC
    /// receives a `ROL` message from a remote peer (refs #864).
    ///
    /// Returns `self` so the call composes with the other `with_*`
    /// builder methods. The default callback (set by [`Self::new`] /
    /// [`Self::with_limits`]) is a no-op that discards the payload —
    /// the V2 transport continues to validate the hop count and
    /// peer-allowlist authz and emit audit + metrics for every accepted
    /// ROL event even when the consumer isn't wired, so a deployment
    /// can observe ingress before committing to a downstream sink.
    /// Mirrors the discipline established by [`Self::with_on_blob`].
    pub fn with_on_rol_event(mut self, on_rol_event: OnRolEvent) -> Self {
        self.on_rol_event = on_rol_event;
        self
    }

    /// Install a callback that fires when the V2
    /// `ClientFederateGroupsStream` RPC receives a `FederateGroups`
    /// update from a remote peer (refs #864).
    ///
    /// Returns `self` so the call composes with the other `with_*`
    /// builder methods. The default callback (set by [`Self::new`] /
    /// [`Self::with_limits`]) is a no-op that discards the payload —
    /// the V2 transport continues to validate the hop count and
    /// peer-allowlist authz and emit audit + metrics for every accepted
    /// update even when the consumer isn't wired, so a deployment can
    /// observe ingress before committing to a downstream sink. Mirrors
    /// the discipline established by [`Self::with_on_blob`] and
    /// [`Self::with_on_rol_event`]. The existing per-peer group
    /// bookkeeping (count + name-length limits) runs alongside the
    /// callback regardless of whether one is wired.
    pub fn with_on_group_sync(mut self, on_group_sync: OnGroupSync) -> Self {
        self.on_group_sync = on_group_sync;
        self
    }

    /// Configure per-peer inbound group allowlists.
    ///
    /// When set, inbound events are validated against the peer's allowlist.
    /// Events claiming groups the peer is not authorized for are rejected.
    /// When not set (the default), all groups are accepted for backward
    /// compatibility.
    pub fn with_allowed_peer_groups(
        mut self,
        peer_groups: HashMap<String, HashSet<String>>,
    ) -> Self {
        self.allowed_peer_groups = Some(Arc::new(peer_groups));
        self
    }

    /// Configure the inbound federation hop limit (closes #758).
    ///
    /// Defaults to [`MAX_FEDERATION_HOPS`] (8). Set this when the local
    /// topology demands a tighter or looser loop-prevention bound — a
    /// star-shaped two-hub deployment can comfortably run with `max_hops
    /// = 3`, while a multi-region mesh with intentional indirection
    /// might need `max_hops = 16`.
    ///
    /// **Validation:** `max_hops` must be in `1..=255`. A `0` argument
    /// is a programming error (it would reject every inbound message,
    /// including the first hop, breaking federation entirely):
    ///
    /// - In **debug** builds, `with_max_hops(0)` panics so the bug
    ///   surfaces during development.
    /// - In **release** builds, `with_max_hops(0)` saturates to `1`
    ///   so a misconfigured operator deployment degrades to "first-hop
    ///   only" rather than "no federation". The `--federation-max-hops`
    ///   CLI flag separately rejects `0` at parse time via
    ///   `clap::value_parser!(u8).range(1..=255)`, so this fallback
    ///   only fires for direct API callers that bypass the CLI.
    ///
    /// Returns `self` so the call composes with the other `with_*`
    /// builder methods, matching the established shape of
    /// [`Self::with_on_blob`], [`Self::with_on_rol_event`], and
    /// [`Self::with_on_group_sync`].
    pub fn with_max_hops(mut self, max_hops: u8) -> Self {
        debug_assert!(
            max_hops > 0,
            "FederationService::with_max_hops(0) would reject every inbound \
             message; pass a value in 1..=255 (default {MAX_FEDERATION_HOPS})"
        );
        self.max_hops = max_hops.max(1);
        self
    }

    /// Send a FederatedEvent to all connected peers.
    pub async fn broadcast(&self, event: figpb::FederatedEvent) -> usize {
        let streams = self.outbound_streams.read().await;
        let mut sent = 0;
        let mut dropped = 0u32;
        for (peer_id, tx) in streams.iter() {
            if tx.send(event.clone()).await.is_ok() {
                sent += 1;
                debug!(peer = %peer_id, "broadcast event to peer");
            } else {
                dropped += 1;
            }
        }
        if dropped > 0 {
            warn!(
                dropped = dropped,
                total = streams.len(),
                "federation events dropped during broadcast: peer channel full or disconnected"
            );
        }
        sent
    }

    /// Send a FederatedEvent only to peers whose groups overlap with the given groups.
    pub async fn broadcast_to_groups(
        &self,
        event: figpb::FederatedEvent,
        groups: &[String],
    ) -> usize {
        let streams = self.outbound_streams.read().await;
        let peer_groups = self.peer_groups.read().await;
        let mut sent = 0;
        let mut dropped = 0u32;

        for (peer_id, tx) in streams.iter() {
            let shares_group = peer_groups
                .get(peer_id.as_str())
                .is_some_and(|pg| pg.iter().any(|g| groups.contains(g)));

            // If we don't track groups for this peer, send anyway (backward compat).
            // Combined with group overlap check into a single condition.
            if shares_group || !peer_groups.contains_key(peer_id.as_str()) {
                if tx.send(event.clone()).await.is_ok() {
                    sent += 1;
                } else {
                    dropped += 1;
                }
            }
        }
        if dropped > 0 {
            warn!(
                dropped = dropped,
                total = streams.len(),
                "federation events dropped during group broadcast: peer channel full or disconnected"
            );
        }
        sent
    }

    /// Number of connected outbound streams.
    pub async fn connection_count(&self) -> usize {
        self.outbound_streams.read().await.len()
    }

    /// Build the subscription response we send to peers.
    fn our_subscription(&self) -> figpb::Subscription {
        figpb::Subscription {
            identity: Some(figpb::Identity {
                name: self.federate_id.clone(),
                uid: self.server_uid.clone(),
                description: String::new(),
                r#type: figpb::identity::ConnectionType::FederationHubServer as i32,
                server_id: self.federate_id.clone(),
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

    /// Validate that an inbound event's hop count is within limits.
    ///
    /// Returns `true` if the event should be processed, or `false`
    /// if the hop count is invalid (negative or at/above `max_hops`).
    /// Events without hop metadata are allowed (treated as first-hop for
    /// backward compat with peers that predate hop tracking).
    ///
    /// Static helper (closes #758): the `max_hops` argument is the
    /// configured limit on the parent [`FederationService`] — passed
    /// in explicitly so the helper stays callable from spawned tasks
    /// that capture only specific fields rather than the whole `&self`.
    /// The wire `current_hops` is `i64` (per-proto), so the comparison
    /// widens `max_hops` to `i64`; the negative-hops branch separately
    /// catches malformed peers.
    fn validate_hop_count(event: &figpb::FederatedEvent, peer_id: &str, max_hops: u8) -> bool {
        let max_hops_i64 = i64::from(max_hops);
        if let Some(ref hops) = event.federate_hops
            && (hops.current_hops < 0 || hops.current_hops >= max_hops_i64)
        {
            warn!(
                peer = %peer_id,
                current_hops = hops.current_hops,
                max = max_hops_i64,
                "rejecting federated event: hop count exceeded"
            );
            return false;
        }
        true
    }

    /// Hop-count validation for `BinaryBlob` (refs #864). The
    /// `FederateHops` proto field shape is the same as on
    /// `FederatedEvent` (it's a sibling message), but the field
    /// reference is on a different parent type so this gets its own
    /// helper rather than a generic over the parent. Same semantics
    /// as [`Self::validate_hop_count`]: blobs without hop metadata
    /// are treated as first-hop for backward compat.
    fn validate_blob_hop_count(blob: &figpb::BinaryBlob, peer_id: &str, max_hops: u8) -> bool {
        let max_hops_i64 = i64::from(max_hops);
        if let Some(ref hops) = blob.federate_hops
            && (hops.current_hops < 0 || hops.current_hops >= max_hops_i64)
        {
            warn!(
                peer = %peer_id,
                current_hops = hops.current_hops,
                max = max_hops_i64,
                "rejecting federated blob: hop count exceeded"
            );
            return false;
        }
        true
    }

    /// Hop-count validation for `ROL` (refs #864). The `FederateHops`
    /// proto field is shared with `FederatedEvent` and `BinaryBlob` —
    /// same shape, different parent message — so this is a sibling of
    /// [`Self::validate_hop_count`] / [`Self::validate_blob_hop_count`]
    /// rather than a generic. Same semantics: ROL events without hop
    /// metadata are treated as first-hop for backward compat with
    /// peers that predate hop tracking.
    fn validate_rol_hop_count(rol: &figpb::Rol, peer_id: &str, max_hops: u8) -> bool {
        let max_hops_i64 = i64::from(max_hops);
        if let Some(ref hops) = rol.federate_hops
            && (hops.current_hops < 0 || hops.current_hops >= max_hops_i64)
        {
            warn!(
                peer = %peer_id,
                current_hops = hops.current_hops,
                max = max_hops_i64,
                "rejecting federated ROL: hop count exceeded"
            );
            return false;
        }
        true
    }

    /// Apply the observable-stub hooks to a single inbound ROL event
    /// from `ServerROLStream` (refs #864). Static helper so the
    /// `tokio::spawn` drain loop in [`Self::server_rol_stream`] AND
    /// unit tests can drive the same body — `tonic::Streaming<Rol>`
    /// has no synthetic constructor, so a per-event helper is the
    /// cleanest way to pin the policy under test. Returns `true` when
    /// the event passed validation and the callback fired; `false`
    /// when it was rejected (the hop-limit gate, which emits an
    /// `event_rejected` audit and skips the callback).
    fn observe_inbound_rol_event(
        on_rol_event: &OnRolEvent,
        peer_id: &str,
        rol: figpb::Rol,
        max_hops: u8,
    ) -> bool {
        if !Self::validate_rol_hop_count(&rol, peer_id, max_hops) {
            rustgate_core::audit::federation_event_rejected(
                RPC_SERVER_ROL_STREAM,
                peer_id,
                "hop_limit",
            );
            return false;
        }

        // Success path: increment counters and emit the audit record
        // BEFORE invoking the callback so the forensic trail captures
        // ingress even if a downstream consumer panics. Same ordering
        // as SendOneEvent / SendOneBlob.
        #[cfg(feature = "api")]
        {
            crate::metrics::messages_in().inc();
            crate::metrics::messages_in_by_rpc()
                .with_label_values(&[RPC_SERVER_ROL_STREAM])
                .inc();
        }
        rustgate_core::audit::federation_event_received(RPC_SERVER_ROL_STREAM, peer_id);

        debug!(
            peer = %peer_id,
            program = %sanitize_for_log(&rol.program),
            payload_count = rol.payload.len(),
            "received ROL event"
        );
        // F-113: lift the bare CN into a typed `PeerId` at the callback edge.
        on_rol_event(rol, rustgate_core::PeerId::new(peer_id));
        true
    }

    /// Hop-count validation for `FederateGroups` (refs #864). The
    /// `FederateHops` proto field is shared with `FederatedEvent`,
    /// `BinaryBlob`, and `Rol` — same shape, different parent message —
    /// so this is a sibling of the existing `validate_*_hop_count`
    /// helpers rather than a generic. Same semantics: group-sync
    /// updates without hop metadata are treated as first-hop for
    /// backward compat with peers that predate hop tracking.
    fn validate_group_sync_hop_count(
        groups: &figpb::FederateGroups,
        peer_id: &str,
        max_hops: u8,
    ) -> bool {
        let max_hops_i64 = i64::from(max_hops);
        if let Some(ref hops) = groups.federate_hops
            && (hops.current_hops < 0 || hops.current_hops >= max_hops_i64)
        {
            warn!(
                peer = %peer_id,
                current_hops = hops.current_hops,
                max = max_hops_i64,
                "rejecting federated groups update: hop count exceeded"
            );
            return false;
        }
        true
    }

    /// Apply the observable-stub hooks to a single inbound
    /// `FederateGroups` update from `ClientFederateGroupsStream` (refs
    /// #864). Static helper so the `tokio::spawn` drain loop in
    /// [`Self::client_federate_groups_stream`] AND unit tests can drive
    /// the same body — `tonic::Streaming<FederateGroups>` has no
    /// synthetic constructor, so a per-update helper is the cleanest
    /// way to pin the policy under test. Returns `true` when the
    /// update passed validation and the callback fired; `false` when
    /// it was rejected (the hop-limit gate, which emits an
    /// `event_rejected` audit and skips the callback).
    fn observe_inbound_group_sync(
        on_group_sync: &OnGroupSync,
        peer_id: &str,
        groups: figpb::FederateGroups,
        max_hops: u8,
    ) -> bool {
        if !Self::validate_group_sync_hop_count(&groups, peer_id, max_hops) {
            rustgate_core::audit::federation_event_rejected(
                RPC_CLIENT_FEDERATE_GROUPS_STREAM,
                peer_id,
                "hop_limit",
            );
            return false;
        }

        // Success path: increment counters and emit the audit record
        // BEFORE invoking the callback so the forensic trail captures
        // ingress even if a downstream consumer panics. Same ordering
        // as SendOneEvent / SendOneBlob / ServerROLStream.
        #[cfg(feature = "api")]
        {
            crate::metrics::messages_in().inc();
            crate::metrics::messages_in_by_rpc()
                .with_label_values(&[RPC_CLIENT_FEDERATE_GROUPS_STREAM])
                .inc();
        }
        rustgate_core::audit::federation_event_received(RPC_CLIENT_FEDERATE_GROUPS_STREAM, peer_id);

        debug!(
            peer = %peer_id,
            group_count = groups.federate_groups.len(),
            nested_count = groups.nested_groups.len(),
            "received federate-groups update"
        );
        // F-113: lift the bare CN into a typed `PeerId` at the callback edge.
        on_group_sync(groups, rustgate_core::PeerId::new(peer_id));
        true
    }

    /// Check if a peer is authorized for the groups claimed in an event.
    ///
    /// Returns `Ok(())` when group validation passes, or `Err(Status)` when the
    /// peer claims groups it is not authorized for. When no `allowed_peer_groups`
    /// is configured, all events are accepted (open mode / backward compat).
    fn validate_event_groups(
        &self,
        peer_id: &str,
        event: &figpb::FederatedEvent,
    ) -> Result<(), Status> {
        let Some(ref allowed) = self.allowed_peer_groups else {
            // No allowlist configured: open mode (backward compat)
            return Ok(());
        };

        let Some(peer_allowed) = allowed.get(peer_id) else {
            // Peer not in allowlist: deny by default
            warn!(
                peer = %peer_id,
                "federation peer not in group allowlist, rejecting event"
            );
            return Err(Status::permission_denied(
                "peer not authorized for any group",
            ));
        };

        for group in &event.federate_groups {
            if !peer_allowed.contains(group.as_str()) {
                // F-153: `group` is peer-controlled — sanitize before
                // logging so a malicious peer cannot inject `\r\n` into
                // text-mode log output and forge audit records.
                warn!(
                    peer = %peer_id,
                    group = %sanitize_for_log(group),
                    "federation peer not authorized for group"
                );
                return Err(Status::permission_denied(
                    "peer not authorized for requested group",
                ));
            }
        }

        Ok(())
    }

    /// Maximum length for a peer CN extracted from a certificate.
    ///
    /// Matches the validation in `rustgate_core::identity::Identity::new()`.
    const MAX_PEER_CN_LENGTH: usize = 256;

    /// Extract peer ID from the mTLS client certificate CN.
    ///
    /// Returns the Common Name (CN) from the peer's TLS certificate
    /// subject, which is authenticated via mTLS and cannot be spoofed.
    /// The extracted CN is sanitized (length-capped, control characters
    /// stripped) to prevent log-injection from malicious certificates.
    ///
    /// # Errors
    ///
    /// Returns `Status::unauthenticated` when the peer cannot be
    /// identified by certificate CN. Historically the server fell back
    /// to the remote IP address in this path, which silently matched
    /// IP-keyed `peer_groups` entries regardless of whether the TLS
    /// identity was present. An expired or malformed client cert would
    /// then inherit the groups of any legitimate peer previously seen
    /// at the same address. The rejection short-circuits every RPC
    /// handler before any group or hop-count evaluation runs, and
    /// emits `audit::federation_peer_rejected` tagged with the remote
    /// address for forensic correlation. Operators relying on the
    /// previous IP-fallback behaviour for non-mTLS testing must now
    /// supply a real client certificate.
    fn peer_id_from_request<T>(request: &Request<T>) -> Result<String, Status> {
        // Tests cannot attach a real client certificate to a `tonic::Request`
        // without running a full TLS handshake. They inject a synthesized
        // CN via `Request::extensions_mut()` instead; the prod path below
        // is unchanged. Release builds never see this extension because
        // nothing outside the test harness inserts it.
        #[cfg(test)]
        if let Some(test_cn) = request.extensions().get::<TestPeerCn>() {
            return Ok(test_cn.0.clone());
        }

        // Try to extract CN from the mTLS peer certificate.
        // Uses an iterator chain to avoid nested if-let that triggers
        // clippy::collapsible_if.
        let (cn, cert_present) = request
            .peer_certs()
            .and_then(|certs| certs.first().cloned())
            .map(|cert_der| {
                let cn = x509_parser::parse_x509_certificate(cert_der.as_ref())
                    .ok()
                    .and_then(|(_, parsed)| {
                        parsed
                            .subject()
                            .iter_common_name()
                            .next()
                            .and_then(|cn| cn.as_str().ok())
                            .map(|raw| {
                                // Sanitize: cap length and strip control characters
                                // to prevent log-injection from malicious CNs.
                                let sanitized: String = raw
                                    .chars()
                                    .take(Self::MAX_PEER_CN_LENGTH)
                                    .filter(|c| !c.is_control())
                                    .collect();
                                sanitized
                            })
                            .filter(|s| !s.is_empty())
                    });
                (cn, true)
            })
            .unwrap_or((None, false));

        if let Some(cn) = cn {
            return Ok(cn);
        }

        // mTLS CN extraction failed — refuse the RPC and record the
        // attempt. Fallback to IP (the pre-F-44 behaviour) is the
        // security bug this path closes.
        let remote = request
            .remote_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        let reason = if cert_present {
            "peer_cert_unparseable_or_empty_cn"
        } else {
            "peer_cert_missing"
        };
        warn!(
            remote_addr = %remote,
            reason = %reason,
            "federation peer rejected — mTLS client certificate CN unavailable"
        );
        rustgate_core::audit::federation_peer_rejected(&remote, reason);
        Err(Status::unauthenticated(
            "federation peer identity unavailable: mTLS client certificate required",
        ))
    }

    /// Create a pre-configured `tonic::transport::Server` with federation
    /// keepalive and message size settings.
    ///
    /// Configures:
    /// - HTTP/2 keepalive timeout: 20 seconds
    /// - HTTP/2 keepalive interval: None (passive — relies on client pings)
    /// - Max frame size and initial window sizes tuned for large CoT payloads
    ///
    /// The caller is responsible for binding to an address and adding TLS config.
    pub fn configured_server(max_message_size: usize) -> tonic::transport::Server {
        tonic::transport::Server::builder()
            .http2_keepalive_timeout(Some(Duration::from_secs(20)))
            .initial_stream_window_size(Some(1024 * 1024)) // 1 MB
            .initial_connection_window_size(Some(2 * 1024 * 1024)) // 2 MB
            .max_frame_size(Some(max_message_size.min(u32::MAX as usize) as u32))
    }

    /// Start the V2 gRPC inbound server on the given address with mTLS.
    ///
    /// Returns a `JoinHandle` that resolves when the server shuts down.
    /// Abort the handle to stop the server.
    pub fn start(
        bind: SocketAddr,
        tls_config: tonic::transport::ServerTlsConfig,
        service: FederationService,
        max_message_size: usize,
    ) -> JoinHandle<Result<(), tonic::transport::Error>> {
        use super::proto::figpb::federated_channel_server::FederatedChannelServer;

        // The server accepts both codecs unconditionally so any peer that
        // opts into send-side compression (gzip or zstd, per its own
        // per-peer config) transparently decompresses here without any
        // matching server-side knob. Enabling accept has zero cost when
        // no peer sends compressed payloads — tonic inspects the
        // `grpc-encoding` header and only decodes if it is set.
        let svc = FederatedChannelServer::new(service)
            .max_decoding_message_size(max_message_size)
            .max_encoding_message_size(max_message_size)
            .accept_compressed(tonic::codec::CompressionEncoding::Gzip)
            .accept_compressed(tonic::codec::CompressionEncoding::Zstd);

        tokio::spawn(async move {
            info!(addr = %bind, "V2 gRPC federation server starting");
            Self::configured_server(max_message_size)
                .tls_config(tls_config)?
                .serve(bind, svc)
                .await
        })
    }
}

#[tonic::async_trait]
impl FederatedChannel for FederationService {
    // --- Unary RPCs ---

    async fn send_one_event(
        &self,
        request: Request<figpb::FederatedEvent>,
    ) -> Result<Response<figpb::Empty>, Status> {
        // mTLS extraction failure already emits federation_peer_rejected
        // and returns Unauthenticated — no extra audit here.
        let peer_id = Self::peer_id_from_request(&request)?;
        let event = request.into_inner();

        if !Self::validate_hop_count(&event, &peer_id, self.max_hops) {
            // Hop-count rejection is observable at the audit layer so the
            // forensic trail records the policy decision even though the
            // RPC contract returns Empty (the V2 protocol cannot signal
            // hop-limit drops to the sender — it only retries on a
            // transport error, which we do not want here).
            rustgate_core::audit::federation_event_rejected(
                RPC_SEND_ONE_EVENT,
                &peer_id,
                "hop_limit",
            );
            return Ok(Response::new(figpb::Empty {}));
        }

        debug!(peer = %peer_id, "received single event");
        if let Err(status) = self.validate_event_groups(&peer_id, &event) {
            // Distinguish "peer not in allowlist at all" from
            // "peer claimed an unauthorized group" — the same audit
            // event covers both, but the reason token differs so
            // downstream alerting can split them.
            let reason = if self
                .allowed_peer_groups
                .as_ref()
                .is_some_and(|allowed| !allowed.contains_key(&peer_id))
            {
                "peer_not_in_allowlist"
            } else {
                "unauthorized_group"
            };
            rustgate_core::audit::federation_event_rejected(RPC_SEND_ONE_EVENT, &peer_id, reason);
            return Err(status);
        }

        // Success path: increment counters and emit the audit record
        // before invoking the callback so the forensic trail captures
        // ingress even if downstream routing panics or drops the event.
        #[cfg(feature = "api")]
        {
            crate::metrics::messages_in().inc();
            crate::metrics::messages_in_by_rpc()
                .with_label_values(&[RPC_SEND_ONE_EVENT])
                .inc();
        }
        rustgate_core::audit::federation_event_received(RPC_SEND_ONE_EVENT, &peer_id);

        // F-113: lift the wire-format CN (`String`) into the typed
        // `PeerId` newtype at the gRPC boundary so the OnEvent callback
        // signature stays type-safe end to end.
        (self.on_event)(event, rustgate_core::PeerId::new(peer_id));
        Ok(Response::new(figpb::Empty {}))
    }

    async fn get_identity(
        &self,
        _request: Request<figpb::Empty>,
    ) -> Result<Response<figpb::Identity>, Status> {
        Ok(Response::new(figpb::Identity {
            name: self.federate_id.clone(),
            uid: self.server_uid.clone(),
            description: String::new(),
            r#type: figpb::identity::ConnectionType::FederationHubServer as i32,
            server_id: self.federate_id.clone(),
        }))
    }

    async fn health_check(
        &self,
        request: Request<figpb::ClientHealth>,
    ) -> Result<Response<figpb::ServerHealth>, Status> {
        let peer_id = Self::peer_id_from_request(&request)?;
        debug!(peer = %peer_id, "health check received");
        Ok(Response::new(figpb::ServerHealth {
            status: figpb::server_health::ServingStatus::Serving as i32,
        }))
    }

    async fn send_one_blob(
        &self,
        request: Request<figpb::BinaryBlob>,
    ) -> Result<Response<figpb::Empty>, Status> {
        // mTLS extraction failure already emits federation_peer_rejected
        // and returns Unauthenticated — no extra audit here.
        let peer_id = Self::peer_id_from_request(&request)?;
        let blob = request.into_inner();

        // Hop-count validation (refs #864): mirrors `send_one_event` —
        // a blob arriving at or beyond the hop limit is silently
        // dropped at the protocol layer (BinaryBlob has no per-RPC
        // signal channel for "too many hops" beyond the standard
        // success/error split, so the audit is the only forensic
        // vantage point).
        if !Self::validate_blob_hop_count(&blob, &peer_id, self.max_hops) {
            rustgate_core::audit::federation_event_rejected(
                RPC_SEND_ONE_BLOB,
                &peer_id,
                "hop_limit",
            );
            return Ok(Response::new(figpb::Empty {}));
        }

        // Authz: peer must be in the allowlist when one is configured.
        // BinaryBlob carries no `federate_groups` field of its own
        // (unlike FederatedEvent), so the only check is "is this peer
        // allowed to talk to us at all" — split out so the rejection
        // audit token matches what the SendOneEvent path emits for
        // the same condition (`peer_not_in_allowlist`).
        if let Some(ref allowed) = self.allowed_peer_groups
            && !allowed.contains_key(&peer_id)
        {
            rustgate_core::audit::federation_event_rejected(
                RPC_SEND_ONE_BLOB,
                &peer_id,
                "peer_not_in_allowlist",
            );
            return Err(Status::permission_denied("peer not in inbound allowlist"));
        }

        // Success path: increment counters and emit the audit record
        // BEFORE invoking the callback so the forensic trail captures
        // ingress even if the downstream consumer panics. Same
        // ordering as the SendOneEvent path for consistency.
        #[cfg(feature = "api")]
        {
            crate::metrics::messages_in().inc();
            crate::metrics::messages_in_by_rpc()
                .with_label_values(&[RPC_SEND_ONE_BLOB])
                .inc();
        }
        rustgate_core::audit::federation_event_received(RPC_SEND_ONE_BLOB, &peer_id);

        debug!(
            peer = %peer_id,
            blob_type = ?blob.r#type,
            blob_bytes = blob.data.len(),
            "received single blob"
        );
        // F-113: wrap the CN in a typed `PeerId` at the gRPC boundary.
        (self.on_blob)(blob, rustgate_core::PeerId::new(peer_id));
        Ok(Response::new(figpb::Empty {}))
    }

    async fn get_auth_token_by_x509(
        &self,
        _request: Request<figpb::BinaryBlob>,
    ) -> Result<Response<figpb::FederateTokenResponse>, Status> {
        // Token auth not used in mTLS mode
        Ok(Response::new(figpb::FederateTokenResponse {
            token: String::new(),
        }))
    }

    async fn getx509_identity(
        &self,
        _request: Request<figpb::Empty>,
    ) -> Result<Response<figpb::BinaryBlob>, Status> {
        Ok(Response::new(figpb::BinaryBlob::default()))
    }

    // --- Client-streaming RPCs (we receive a stream from the remote) ---

    async fn server_event_stream(
        &self,
        request: Request<Streaming<figpb::FederatedEvent>>,
    ) -> Result<Response<figpb::Subscription>, Status> {
        let peer_id = Self::peer_id_from_request(&request)?;
        let mut stream = request.into_inner();

        info!(peer = %peer_id, "server_event_stream opened (receiving events)");

        let on_event = Arc::clone(&self.on_event);
        let allowed = self.allowed_peer_groups.clone();
        let pid = peer_id.clone();
        // Capture the configured hop limit by value (u8 is Copy) so the
        // spawned drain task does not need a `self` reference. The
        // limit is fixed at the time the stream is opened — a SIGHUP
        // that swaps the limit affects subsequent stream opens, not
        // streams already in progress.
        let max_hops = self.max_hops;

        const MAX_CONSECUTIVE_VIOLATIONS: u32 = 10;

        drop(tokio::spawn(async move {
            let mut consecutive_violations: u32 = 0;

            while let Ok(Some(event)) = stream.message().await {
                if !FederationService::validate_hop_count(&event, &pid, max_hops) {
                    continue;
                }

                // Validate group membership when an allowlist is configured
                if let Some(ref allowed_map) = allowed {
                    let authorized = if let Some(peer_allowed) = allowed_map.get(&pid) {
                        event
                            .federate_groups
                            .iter()
                            .all(|g| peer_allowed.contains(g.as_str()))
                    } else {
                        // Peer not in allowlist: deny
                        false
                    };

                    if !authorized {
                        consecutive_violations += 1;
                        // F-153: `event.federate_groups` is peer-controlled;
                        // sanitize each element before logging so `\r\n` in a
                        // group name can't forge log lines in text-mode output.
                        let sanitized_groups: Vec<String> = event
                            .federate_groups
                            .iter()
                            .map(|g| sanitize_for_log(g))
                            .collect();
                        warn!(
                            peer = %pid,
                            groups = ?sanitized_groups,
                            consecutive_violations = consecutive_violations,
                            "federation peer not authorized for claimed groups, skipping event"
                        );
                        if consecutive_violations >= MAX_CONSECUTIVE_VIOLATIONS {
                            warn!(
                                peer = %pid,
                                violations = consecutive_violations,
                                "disconnecting federation peer: too many consecutive group violations"
                            );
                            break;
                        }
                        continue;
                    }
                }

                // Valid event resets the violation counter
                consecutive_violations = 0;
                // F-113: lift the bare CN into a typed `PeerId` at the
                // callback edge — `pid` itself stays a `String` because
                // the surrounding allowlist lookup uses `HashMap<String, _>`
                // keys for now.
                on_event(event, rustgate_core::PeerId::new(pid.as_str()));
            }
            info!(peer = %pid, "server_event_stream closed");
        }));

        Ok(Response::new(self.our_subscription()))
    }

    async fn binary_message_stream(
        &self,
        request: Request<Streaming<figpb::BinaryBlob>>,
    ) -> Result<Response<figpb::Empty>, Status> {
        let peer_id = Self::peer_id_from_request(&request)?;
        let mut stream = request.into_inner();

        // Drain the stream without processing (binary blobs not supported)
        drop(tokio::spawn(async move {
            while let Ok(Some(_blob)) = stream.message().await {
                debug!(peer = %peer_id, "received binary blob (ignored)");
            }
        }));

        Ok(Response::new(figpb::Empty {}))
    }

    async fn server_rol_stream(
        &self,
        request: Request<Streaming<figpb::Rol>>,
    ) -> Result<Response<figpb::Subscription>, Status> {
        // mTLS extraction failure already emits federation_peer_rejected
        // and returns Unauthenticated before any payload processing —
        // matches the SendOneEvent / SendOneBlob discipline.
        let peer_id = Self::peer_id_from_request(&request)?;

        // Pre-flight allowlist check on stream open. ROL has no
        // `federate_groups` semantics shared with BinaryBlob's
        // peer-not-in-allowlist gate (the field exists on the wire,
        // but the per-message group authz mirrors blob — peer must be
        // in the inbound allowlist when one is configured). Emit the
        // `peer_not_in_allowlist` reject audit BEFORE accepting the
        // stream so the forensic trail records the policy decision
        // even though the RPC contract for `ServerROLStream` is
        // single-Subscription return: a Byzantine peer cannot probe
        // the system by opening a stream and sending nothing.
        if let Some(ref allowed) = self.allowed_peer_groups
            && !allowed.contains_key(&peer_id)
        {
            rustgate_core::audit::federation_event_rejected(
                RPC_SERVER_ROL_STREAM,
                &peer_id,
                "peer_not_in_allowlist",
            );
            return Err(Status::permission_denied("peer not in inbound allowlist"));
        }

        info!(peer = %peer_id, "server_rol_stream opened (receiving ROL events)");
        let mut stream = request.into_inner();

        // Per-event policy lives in `observe_inbound_rol_event` so
        // unit tests can exercise it without a synthetic
        // `tonic::Streaming<Rol>`. The drain task captures the
        // callback by `Arc` clone — same shape as `server_event_stream`.
        let on_rol_event = Arc::clone(&self.on_rol_event);
        let pid = peer_id.clone();
        let max_hops = self.max_hops;
        drop(tokio::spawn(async move {
            while let Ok(Some(rol)) = stream.message().await {
                let _ = FederationService::observe_inbound_rol_event(
                    &on_rol_event,
                    &pid,
                    rol,
                    max_hops,
                );
            }
            info!(peer = %pid, "server_rol_stream closed");
        }));

        Ok(Response::new(self.our_subscription()))
    }

    async fn client_federate_groups_stream(
        &self,
        request: Request<Streaming<figpb::FederateGroups>>,
    ) -> Result<Response<figpb::Subscription>, Status> {
        // mTLS extraction failure already emits federation_peer_rejected
        // and returns Unauthenticated before any payload processing —
        // matches the SendOneEvent / SendOneBlob / ServerROLStream
        // discipline.
        let peer_id = Self::peer_id_from_request(&request)?;

        // Pre-flight allowlist check on stream open. Mirrors the
        // ServerROLStream gate so the audit reason vocabulary stays
        // uniform across the streaming RPC suite — a peer not in the
        // inbound allowlist must not be able to push group-sync
        // updates, and the rejection is audited BEFORE the stream is
        // accepted so a Byzantine peer cannot probe the system by
        // opening a stream and sending nothing.
        if let Some(ref allowed) = self.allowed_peer_groups
            && !allowed.contains_key(&peer_id)
        {
            rustgate_core::audit::federation_event_rejected(
                RPC_CLIENT_FEDERATE_GROUPS_STREAM,
                &peer_id,
                "peer_not_in_allowlist",
            );
            return Err(Status::permission_denied("peer not in inbound allowlist"));
        }

        info!(peer = %peer_id, "client_federate_groups_stream opened (receiving groups)");
        let mut stream = request.into_inner();

        let peer_groups = Arc::clone(&self.peer_groups);
        let on_group_sync = Arc::clone(&self.on_group_sync);
        let pid = peer_id.clone();
        let max_groups = self.max_groups_per_peer;
        let max_name_len = self.max_group_name_length;
        let max_hops = self.max_hops;

        drop(tokio::spawn(async move {
            while let Ok(Some(groups_msg)) = stream.message().await {
                // Per-update observation hook: hop validation + audit +
                // metric + callback. The existing per-peer bookkeeping
                // (count + name-length limits) runs alongside on every
                // accepted update — the observation hook is independent
                // of the in-memory `peer_groups` map. A hop-limit-rejected
                // update skips both the bookkeeping AND the callback so
                // the in-memory state never reflects an event the
                // forensic trail recorded as rejected.
                let groups_msg_for_observe = groups_msg.clone();
                if !FederationService::observe_inbound_group_sync(
                    &on_group_sync,
                    &pid,
                    groups_msg_for_observe,
                    max_hops,
                ) {
                    continue;
                }

                let mut groups = groups_msg.federate_groups;

                // Filter out group names that exceed the length limit
                let original_len = groups.len();
                groups.retain(|g| {
                    if g.len() > max_name_len {
                        warn!(
                            peer = %pid,
                            group_name_length = g.len(),
                            limit = max_name_len,
                            "federation group name rejected: exceeds max length"
                        );
                        false
                    } else {
                        true
                    }
                });

                // Enforce per-peer group count limit
                if groups.len() > max_groups {
                    warn!(
                        peer = %pid,
                        advertised = original_len,
                        accepted = max_groups,
                        limit = max_groups,
                        "federation peer groups truncated: exceeds max groups per peer"
                    );
                    groups.truncate(max_groups);
                }

                info!(peer = %pid, count = groups.len(), "peer updated groups");
                let _ = peer_groups.write().await.insert(pid.clone(), groups);
            }
            info!(peer = %pid, "client_federate_groups_stream closed");
            let _ = peer_groups.write().await.remove(&pid);
        }));

        Ok(Response::new(self.our_subscription()))
    }

    // --- Server-streaming RPCs (we send a stream to the remote) ---

    type ClientEventStreamStream = ReceiverStream<Result<figpb::FederatedEvent, Status>>;

    async fn client_event_stream(
        &self,
        request: Request<figpb::Subscription>,
    ) -> Result<Response<Self::ClientEventStreamStream>, Status> {
        let sub = request.into_inner();
        let peer_id = sub
            .identity
            .as_ref()
            .map(|i| {
                if !i.name.is_empty() {
                    i.name.clone()
                } else {
                    i.uid.clone()
                }
            })
            .unwrap_or_else(|| "unknown".to_string());

        info!(peer = %peer_id, "client_event_stream opened (sending events)");

        let (event_tx, mut event_rx) = mpsc::channel::<figpb::FederatedEvent>(256);
        let (stream_tx, stream_rx) = mpsc::channel::<Result<figpb::FederatedEvent, Status>>(256);

        // Store the outbound channel for broadcasting
        let _ = self
            .outbound_streams
            .write()
            .await
            .insert(peer_id.clone(), event_tx);

        // Forward events from the mpsc channel to the gRPC stream
        let outbound_streams = Arc::clone(&self.outbound_streams);
        let pid = peer_id.clone();
        drop(tokio::spawn(async move {
            while let Some(event) = event_rx.recv().await {
                if stream_tx.send(Ok(event)).await.is_err() {
                    warn!(peer = %pid, "event dropped: gRPC stream closed or full, stopping forwarding");
                    break;
                }
            }
            info!(peer = %pid, "client_event_stream closed");
            let _ = outbound_streams.write().await.remove(&pid);
        }));

        Ok(Response::new(ReceiverStream::new(stream_rx)))
    }

    type ClientROLStreamStream = ReceiverStream<Result<figpb::Rol, Status>>;

    async fn client_rol_stream(
        &self,
        request: Request<figpb::Subscription>,
    ) -> Result<Response<Self::ClientROLStreamStream>, Status> {
        // `ClientROLStream` is server-streaming in the proto: the peer
        // sends one Subscription and we open a stream of ROL events
        // back. The observable-stub here records the subscription
        // open with the same peer-auth + allowlist + audit + metric
        // shape as `ServerROLStream`'s receive side, then returns an
        // empty stream that stays open. Routing-side machinery for
        // pushing ROL state out lands in a separate follow-up — the
        // stub explicitly does NOT push payloads.
        let peer_id = Self::peer_id_from_request(&request)?;

        // Allowlist check on subscription open — a peer not in the
        // inbound allowlist must not be able to keep an outbound ROL
        // stream half-open. Mirrors the SendOneBlob /
        // ServerROLStream gate so the audit reason vocabulary stays
        // uniform across the RPC suite.
        if let Some(ref allowed) = self.allowed_peer_groups
            && !allowed.contains_key(&peer_id)
        {
            rustgate_core::audit::federation_event_rejected(
                RPC_CLIENT_ROL_STREAM,
                &peer_id,
                "peer_not_in_allowlist",
            );
            return Err(Status::permission_denied("peer not in inbound allowlist"));
        }

        // Subscription accepted: increment counter and emit the audit
        // record before returning the stream so a peer that opens
        // and immediately closes the connection still appears in the
        // forensic trail. The metric counts the SUBSCRIPTION, not
        // ROL events — `ClientROLStream` doesn't receive any ROL
        // events from the peer (the proto is one-Subscription-in,
        // many-ROL-out), so per-event observation isn't a meaningful
        // shape on this side.
        #[cfg(feature = "api")]
        {
            crate::metrics::messages_in().inc();
            crate::metrics::messages_in_by_rpc()
                .with_label_values(&[RPC_CLIENT_ROL_STREAM])
                .inc();
        }
        rustgate_core::audit::federation_event_received(RPC_CLIENT_ROL_STREAM, &peer_id);

        info!(peer = %peer_id, "client_rol_stream opened (sending ROL events — stub, no payloads)");

        // Empty stream that stays open. Holding `tx` in a background
        // task pinned on `pending::<()>()` keeps the stream alive
        // until the peer disconnects and tonic drops `rx` — same
        // pattern as `server_federate_groups_stream`.
        let (tx, rx) = mpsc::channel(1);
        drop(tokio::spawn(async move {
            futures::future::pending::<()>().await;
            drop(tx);
        }));
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    type ServerFederateGroupsStreamStream = ReceiverStream<Result<figpb::FederateGroups, Status>>;

    async fn server_federate_groups_stream(
        &self,
        request: Request<figpb::Subscription>,
    ) -> Result<Response<Self::ServerFederateGroupsStreamStream>, Status> {
        // `ServerFederateGroupsStream` is server-streaming in the proto:
        // the peer sends one `Subscription` and we open a stream of
        // `FederateGroups` updates back. The observable-stub here
        // records the subscription open with the same peer-auth +
        // allowlist + audit + metric shape as `ClientROLStream`'s open
        // path, sends the initial groups roster, then holds the stream
        // open without producing further updates — the routing-side
        // machinery for incremental group-sync state lands in a
        // separate follow-up.
        let peer_id = Self::peer_id_from_request(&request)?;

        // Allowlist check on subscription open. Mirrors the
        // `ClientROLStream` / `ClientFederateGroupsStream` gates so the
        // audit reason vocabulary stays uniform across the RPC suite —
        // a peer not in the inbound allowlist must not be able to keep
        // an outbound groups stream half-open.
        if let Some(ref allowed) = self.allowed_peer_groups
            && !allowed.contains_key(&peer_id)
        {
            rustgate_core::audit::federation_event_rejected(
                RPC_SERVER_FEDERATE_GROUPS_STREAM,
                &peer_id,
                "peer_not_in_allowlist",
            );
            return Err(Status::permission_denied("peer not in inbound allowlist"));
        }

        // Subscription accepted: increment counter and emit the audit
        // record before returning the stream so a peer that opens and
        // immediately closes the connection still appears in the
        // forensic trail. The metric counts the SUBSCRIPTION, not
        // group-sync updates — `ServerFederateGroupsStream` doesn't
        // RECEIVE any updates from the peer (the proto is
        // one-Subscription-in, many-FederateGroups-out), so per-update
        // observation isn't a meaningful shape on this side.
        #[cfg(feature = "api")]
        {
            crate::metrics::messages_in().inc();
            crate::metrics::messages_in_by_rpc()
                .with_label_values(&[RPC_SERVER_FEDERATE_GROUPS_STREAM])
                .inc();
        }
        rustgate_core::audit::federation_event_received(
            RPC_SERVER_FEDERATE_GROUPS_STREAM,
            &peer_id,
        );

        info!(peer = %peer_id, "server_federate_groups_stream opened (sending our groups)");

        let (tx, rx) = mpsc::channel(16);

        // Send our initial groups with SERVING status
        let groups_msg = figpb::FederateGroups {
            stream_update: Some(figpb::ServerHealth {
                status: figpb::server_health::ServingStatus::Serving as i32,
            }),
            federate_groups: self.groups.clone(),
            federate_provenance: Vec::new(),
            federate_hops: None,
            federate_group_hop_limits: None,
            nested_groups: Vec::new(),
        };

        if tx.send(Ok(groups_msg)).await.is_err() {
            warn!(peer = %peer_id, "initial groups message dropped: peer channel disconnected");
        }

        // Hold the sender alive in a background task so the stream stays open.
        // The stream closes when the remote disconnects (rx is dropped by tonic).
        drop(tokio::spawn(async move {
            // Keep tx alive until the connection drops — pending never resolves
            futures::future::pending::<()>().await;
            drop(tx);
        }));

        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

/// Test-only extension that carries a synthesized peer CN through a
/// `tonic::Request`. Tests cannot complete a real mTLS handshake in
/// unit scope, so `peer_id_from_request` consults this extension (and
/// only this extension) under `#[cfg(test)]` before following the
/// production cert-extraction path. Release builds never observe the
/// type because its constructor lives behind the same cfg.
#[cfg(test)]
#[derive(Clone)]
struct TestPeerCn(String);

#[cfg(test)]
#[allow(unused_results, clippy::unwrap_used, clippy::panic)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    /// Build a `tonic::Request` carrying a synthesized peer CN. Mirrors
    /// what the prod path would extract from a real mTLS client cert.
    fn request_with_peer_cn<T>(inner: T, cn: &str) -> Request<T> {
        let mut req = Request::new(inner);
        req.extensions_mut().insert(TestPeerCn(cn.to_string()));
        req
    }

    fn noop_on_event() -> OnEvent {
        Arc::new(|_event, _peer| {})
    }

    fn counting_on_event() -> (OnEvent, Arc<AtomicU64>) {
        let count = Arc::new(AtomicU64::new(0));
        let c = Arc::clone(&count);
        let cb: OnEvent = Arc::new(move |_event, _peer| {
            c.fetch_add(1, Ordering::Relaxed);
        });
        (cb, count)
    }

    /// Sibling of [`counting_on_event`] for the SendOneBlob path
    /// (refs #864). Returns an `OnBlob` callback that increments a
    /// shared atomic counter on every invocation, plus the counter
    /// itself for assertion.
    fn counting_on_blob() -> (OnBlob, Arc<AtomicU64>) {
        let count = Arc::new(AtomicU64::new(0));
        let c = Arc::clone(&count);
        let cb: OnBlob = Arc::new(move |_blob, _peer| {
            c.fetch_add(1, Ordering::Relaxed);
        });
        (cb, count)
    }

    #[test]
    fn service_debug_output() {
        let svc =
            FederationService::new("test-server".into(), vec!["Alpha".into()], noop_on_event());
        let dbg = format!("{svc:?}");
        assert!(dbg.contains("test-server"));
        assert!(dbg.contains("Alpha"));
    }

    #[test]
    fn service_uid_is_deterministic() {
        let svc = FederationService::new("server-1".into(), vec![], noop_on_event());
        assert_eq!(svc.server_uid, provenance::deterministic_uuid("server-1"));
    }

    #[test]
    fn our_subscription_has_identity() {
        let svc =
            FederationService::new("fed-server".into(), vec!["Group1".into()], noop_on_event());
        let sub = svc.our_subscription();
        let identity = sub.identity.expect("identity");
        assert_eq!(identity.name, "fed-server");
        assert_eq!(
            identity.r#type,
            figpb::identity::ConnectionType::FederationHubServer as i32
        );
    }

    #[test]
    fn our_subscription_has_version() {
        let svc = FederationService::new("s".into(), vec![], noop_on_event());
        let sub = svc.our_subscription();
        let ver = sub.version.expect("version");
        assert_eq!(ver.major, 5);
        assert_eq!(ver.variant, "rustgate");
    }

    #[tokio::test]
    async fn connection_count_starts_at_zero() {
        let svc = FederationService::new("s".into(), vec![], noop_on_event());
        assert_eq!(svc.connection_count().await, 0);
    }

    #[tokio::test]
    async fn broadcast_with_no_peers_returns_zero() {
        let svc = FederationService::new("s".into(), vec![], noop_on_event());
        let event = figpb::FederatedEvent::default();
        assert_eq!(svc.broadcast(event).await, 0);
    }

    #[tokio::test]
    async fn broadcast_to_groups_with_no_peers_returns_zero() {
        let svc = FederationService::new("s".into(), vec![], noop_on_event());
        let event = figpb::FederatedEvent::default();
        assert_eq!(svc.broadcast_to_groups(event, &["Alpha".into()]).await, 0);
    }

    #[tokio::test]
    async fn broadcast_sends_to_registered_peer() {
        let svc = FederationService::new("s".into(), vec![], noop_on_event());
        let (tx, mut rx) = mpsc::channel(16);

        // Manually register a peer stream
        svc.outbound_streams
            .write()
            .await
            .insert("peer-1".into(), tx);

        let event = figpb::FederatedEvent {
            event: Some(figpb::GeoEvent {
                uid: "broadcast-test".into(),
                ..Default::default()
            }),
            ..Default::default()
        };

        let sent = svc.broadcast(event).await;
        assert_eq!(sent, 1);

        let received = rx.recv().await.expect("should receive event");
        assert_eq!(received.event.expect("event").uid, "broadcast-test");
    }

    #[tokio::test]
    async fn broadcast_to_groups_sends_only_to_matching_peers() {
        let svc = FederationService::new("s".into(), vec![], noop_on_event());
        let (tx_alpha, mut rx_alpha) = mpsc::channel(16);
        let (tx_bravo, mut rx_bravo) = mpsc::channel(16);

        // Register two peers with different groups
        {
            let mut streams = svc.outbound_streams.write().await;
            streams.insert("peer-alpha".into(), tx_alpha);
            streams.insert("peer-bravo".into(), tx_bravo);
        }
        {
            let mut groups = svc.peer_groups.write().await;
            groups.insert("peer-alpha".into(), vec!["Alpha".into()]);
            groups.insert("peer-bravo".into(), vec!["Bravo".into()]);
        }

        let event = figpb::FederatedEvent::default();
        let sent = svc.broadcast_to_groups(event, &["Alpha".into()]).await;
        assert_eq!(sent, 1);

        // Alpha should get it
        assert!(rx_alpha.try_recv().is_ok());
        // Bravo should not
        assert!(rx_bravo.try_recv().is_err());
    }

    #[tokio::test]
    async fn broadcast_to_groups_sends_to_peers_without_groups() {
        let svc = FederationService::new("s".into(), vec![], noop_on_event());
        let (tx, mut rx) = mpsc::channel(16);

        // Register peer with NO groups tracked (backward compat: should receive)
        svc.outbound_streams
            .write()
            .await
            .insert("peer-nogroups".into(), tx);
        // Don't add to peer_groups

        let event = figpb::FederatedEvent::default();
        let sent = svc.broadcast_to_groups(event, &["Alpha".into()]).await;
        assert_eq!(sent, 1);
        assert!(rx.try_recv().is_ok());
    }

    #[tokio::test]
    async fn get_identity_returns_server_info() {
        let svc = FederationService::new("my-server".into(), vec!["G1".into()], noop_on_event());
        let resp = svc
            .get_identity(Request::new(figpb::Empty {}))
            .await
            .expect("get_identity");
        let identity = resp.into_inner();
        assert_eq!(identity.name, "my-server");
        assert_eq!(identity.server_id, "my-server");
    }

    #[tokio::test]
    async fn health_check_returns_serving() {
        let svc = FederationService::new("s".into(), vec![], noop_on_event());
        let resp = svc
            .health_check(request_with_peer_cn(
                figpb::ClientHealth {
                    status: figpb::client_health::ServingStatus::Serving as i32,
                },
                "test-peer",
            ))
            .await
            .expect("health_check");
        let health = resp.into_inner();
        assert_eq!(
            health.status,
            figpb::server_health::ServingStatus::Serving as i32
        );
    }

    #[tokio::test]
    async fn send_one_event_invokes_callback() {
        let (on_event, count) = counting_on_event();
        let svc = FederationService::new("s".into(), vec![], on_event);
        let event = figpb::FederatedEvent {
            event: Some(figpb::GeoEvent {
                uid: "test".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let _ = svc
            .send_one_event(request_with_peer_cn(event, "unknown"))
            .await
            .expect("send_one_event");
        assert_eq!(count.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn send_one_blob_routes_to_callback_on_success() {
        // Refs #864: the SendOneBlob handler MUST invoke the
        // installed `on_blob` callback exactly once per accepted
        // blob, mirroring SendOneEvent's per-event callback contract.
        // A regression that dropped the callback wiring would
        // silently swallow every binary blob without surfacing.
        let (on_blob, count) = counting_on_blob();
        let svc = FederationService::new("s".into(), vec![], noop_on_event()).with_on_blob(on_blob);

        let blob = figpb::BinaryBlob {
            r#type: figpb::BinaryTypes::Image as i32,
            data: b"\x89PNG\r\n\x1a\n... fake PNG header".to_vec(),
            filename: "screenshot.png".into(),
            timestamp: 1_700_000_000,
            description: "test image".into(),
            ..Default::default()
        };

        let resp = svc
            .send_one_blob(request_with_peer_cn(blob, "peer-cn"))
            .await
            .expect("send_one_blob must succeed for an authorized peer");
        let _ = resp.into_inner();

        assert_eq!(
            count.load(Ordering::Relaxed),
            1,
            "on_blob callback must fire exactly once for an accepted blob"
        );
    }

    #[tokio::test]
    async fn get_auth_token_returns_empty() {
        let svc = FederationService::new("s".into(), vec![], noop_on_event());
        let resp = svc
            .get_auth_token_by_x509(Request::new(figpb::BinaryBlob::default()))
            .await
            .expect("get_auth_token");
        assert_eq!(resp.into_inner().token, "");
    }

    #[tokio::test]
    async fn getx509_identity_returns_default() {
        let svc = FederationService::new("s".into(), vec![], noop_on_event());
        let _ = svc
            .getx509_identity(Request::new(figpb::Empty {}))
            .await
            .expect("getx509_identity");
    }

    #[tokio::test]
    async fn connection_count_reflects_registered_peers() {
        let svc = FederationService::new("s".into(), vec![], noop_on_event());
        assert_eq!(svc.connection_count().await, 0);

        let (tx1, _rx1) = mpsc::channel(1);
        let (tx2, _rx2) = mpsc::channel(1);
        {
            let mut streams = svc.outbound_streams.write().await;
            streams.insert("peer-1".into(), tx1);
            streams.insert("peer-2".into(), tx2);
        }
        assert_eq!(svc.connection_count().await, 2);
    }

    #[tokio::test]
    async fn peer_groups_enforces_max_count() {
        let svc = FederationService::with_limits(
            "s".into(),
            vec![],
            noop_on_event(),
            3,   // max 3 groups per peer
            256, // max name length
        );

        // Simulate peer advertising 5 groups
        let groups: Vec<String> = (0..5).map(|i| format!("group-{i}")).collect();
        {
            // Apply the same validation logic used in client_federate_groups_stream
            let mut filtered = groups.clone();
            filtered.retain(|g| g.len() <= svc.max_group_name_length);
            if filtered.len() > svc.max_groups_per_peer {
                filtered.truncate(svc.max_groups_per_peer);
            }
            svc.peer_groups
                .write()
                .await
                .insert("peer-1".into(), filtered);
        }

        let pg = svc.peer_groups.read().await;
        let peer_groups = pg.get("peer-1").expect("peer-1 should exist");
        assert_eq!(
            peer_groups.len(),
            3,
            "peer groups should be truncated to max_groups_per_peer"
        );
    }

    #[tokio::test]
    async fn peer_groups_enforces_max_name_length() {
        let svc = FederationService::with_limits(
            "s".into(),
            vec![],
            noop_on_event(),
            1_000,
            10, // max 10 bytes per group name
        );

        let groups = vec![
            "short".to_string(),
            "this-is-a-very-long-group-name-that-exceeds-the-limit".to_string(),
            "ok".to_string(),
        ];

        {
            let mut filtered = groups.clone();
            filtered.retain(|g| g.len() <= svc.max_group_name_length);
            svc.peer_groups
                .write()
                .await
                .insert("peer-1".into(), filtered);
        }

        let pg = svc.peer_groups.read().await;
        let peer_groups = pg.get("peer-1").expect("peer-1 should exist");
        assert_eq!(
            peer_groups.len(),
            2,
            "only group names within length limit should be accepted"
        );
        assert!(peer_groups.contains(&"short".to_string()));
        assert!(peer_groups.contains(&"ok".to_string()));
    }

    #[test]
    fn with_limits_sets_custom_values() {
        let svc = FederationService::with_limits("s".into(), vec![], noop_on_event(), 500, 128);
        assert_eq!(svc.max_groups_per_peer, 500);
        assert_eq!(svc.max_group_name_length, 128);
    }

    #[test]
    fn test_configured_server_default_size() {
        let _server = FederationService::configured_server(10 * 1024 * 1024);
    }

    #[test]
    fn test_configured_server_zero_size() {
        let _server = FederationService::configured_server(0);
    }

    #[test]
    fn test_configured_server_u32_max_clamp() {
        // max_frame_size uses .min(u32::MAX) so very large values are clamped
        let _server = FederationService::configured_server(usize::MAX);
    }

    #[test]
    fn peer_id_rejects_request_without_tls_cert() {
        // Without TLS extensions the RPC must be refused — see F-44 /
        // issue #759. The previous IP-fallback behaviour let a peer
        // without a parseable mTLS cert inherit IP-keyed `peer_groups`
        // entries; this test guards that the function never returns a
        // synthetic identity on that path again.
        let request = Request::new(figpb::Empty {});
        let err = FederationService::peer_id_from_request(&request)
            .expect_err("peer_id extraction must fail without a client cert");
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn hop_count_validation_rejects_exceeded() {
        let (on_event, count) = counting_on_event();
        let svc = FederationService::new("s".into(), vec![], on_event);

        let event = figpb::FederatedEvent {
            event: Some(figpb::GeoEvent {
                uid: "over-limit".into(),
                ..Default::default()
            }),
            federate_hops: Some(figpb::FederateHops {
                current_hops: i64::from(MAX_FEDERATION_HOPS) + 1,
                max_hops: 20,
            }),
            ..Default::default()
        };

        let _ = svc
            .send_one_event(request_with_peer_cn(event, "unknown"))
            .await
            .expect("send_one_event");

        assert_eq!(
            count.load(Ordering::Relaxed),
            0,
            "event exceeding max hops should not reach callback"
        );
    }

    #[tokio::test]
    async fn hop_count_validation_allows_valid() {
        let (on_event, count) = counting_on_event();
        let svc = FederationService::new("s".into(), vec![], on_event);

        let event = figpb::FederatedEvent {
            event: Some(figpb::GeoEvent {
                uid: "within-limit".into(),
                ..Default::default()
            }),
            federate_hops: Some(figpb::FederateHops {
                current_hops: i64::from(MAX_FEDERATION_HOPS) - 1,
                max_hops: 20,
            }),
            ..Default::default()
        };

        let _ = svc
            .send_one_event(request_with_peer_cn(event, "unknown"))
            .await
            .expect("send_one_event");

        assert_eq!(
            count.load(Ordering::Relaxed),
            1,
            "event within hop limit should reach callback"
        );
    }

    #[tokio::test]
    async fn federation_rejects_unauthorized_group() {
        let (on_event, count) = counting_on_event();
        let mut allowed = HashMap::new();
        allowed.insert("unknown".to_string(), HashSet::from(["Alpha".to_string()]));
        let svc =
            FederationService::new("s".into(), vec![], on_event).with_allowed_peer_groups(allowed);

        // Peer sends to group "Beta" but is only authorized for "Alpha"
        let event = figpb::FederatedEvent {
            federate_groups: vec!["Beta".into()],
            ..Default::default()
        };
        let result = svc
            .send_one_event(request_with_peer_cn(event, "unknown"))
            .await;
        assert!(result.is_err());
        let status = result.unwrap_err();
        assert_eq!(status.code(), tonic::Code::PermissionDenied);
        assert_eq!(count.load(Ordering::Relaxed), 0, "callback must not fire");
    }

    #[tokio::test]
    async fn federation_allows_authorized_group() {
        let (on_event, count) = counting_on_event();
        let mut allowed = HashMap::new();
        allowed.insert("unknown".to_string(), HashSet::from(["Alpha".to_string()]));
        let svc =
            FederationService::new("s".into(), vec![], on_event).with_allowed_peer_groups(allowed);

        // Peer sends to "Alpha" which it is authorized for
        let event = figpb::FederatedEvent {
            federate_groups: vec!["Alpha".into()],
            ..Default::default()
        };
        let result = svc
            .send_one_event(request_with_peer_cn(event, "unknown"))
            .await;
        assert!(result.is_ok());
        assert_eq!(count.load(Ordering::Relaxed), 1, "callback should fire");
    }

    #[tokio::test]
    async fn federation_allows_all_when_no_peer_groups() {
        let (on_event, count) = counting_on_event();
        // No allowed_peer_groups configured = open mode
        let svc = FederationService::new("s".into(), vec![], on_event);

        let event = figpb::FederatedEvent {
            federate_groups: vec!["AnyGroup".into()],
            ..Default::default()
        };
        let result = svc
            .send_one_event(request_with_peer_cn(event, "unknown"))
            .await;
        assert!(result.is_ok());
        assert_eq!(
            count.load(Ordering::Relaxed),
            1,
            "callback should fire in open mode"
        );
    }

    #[tokio::test]
    async fn hop_count_none_is_accepted() {
        let (on_event, count) = counting_on_event();
        let svc = FederationService::new("s".into(), vec![], on_event);

        let event = figpb::FederatedEvent {
            event: Some(figpb::GeoEvent {
                uid: "no-hops".into(),
                ..Default::default()
            }),
            federate_hops: None,
            ..Default::default()
        };

        let _ = svc
            .send_one_event(request_with_peer_cn(event, "unknown"))
            .await
            .expect("send_one_event");

        assert_eq!(
            count.load(Ordering::Relaxed),
            1,
            "event with no hop count (backward compat) should reach callback"
        );
    }

    #[tokio::test]
    async fn hop_count_at_exact_limit_is_rejected() {
        let (on_event, count) = counting_on_event();
        let svc = FederationService::new("s".into(), vec![], on_event);

        let event = figpb::FederatedEvent {
            event: Some(figpb::GeoEvent {
                uid: "at-limit".into(),
                ..Default::default()
            }),
            federate_hops: Some(figpb::FederateHops {
                current_hops: i64::from(MAX_FEDERATION_HOPS),
                max_hops: 20,
            }),
            ..Default::default()
        };

        let _ = svc
            .send_one_event(request_with_peer_cn(event, "unknown"))
            .await
            .expect("send_one_event");

        assert_eq!(
            count.load(Ordering::Relaxed),
            0,
            "event at exactly the hop limit should be rejected (>= boundary)"
        );
    }

    #[tokio::test]
    async fn hop_count_one_below_limit_is_accepted() {
        let (on_event, count) = counting_on_event();
        let svc = FederationService::new("s".into(), vec![], on_event);

        let event = figpb::FederatedEvent {
            event: Some(figpb::GeoEvent {
                uid: "one-below".into(),
                ..Default::default()
            }),
            federate_hops: Some(figpb::FederateHops {
                current_hops: i64::from(MAX_FEDERATION_HOPS) - 1,
                max_hops: 20,
            }),
            ..Default::default()
        };

        let _ = svc
            .send_one_event(request_with_peer_cn(event, "unknown"))
            .await
            .expect("send_one_event");

        assert_eq!(
            count.load(Ordering::Relaxed),
            1,
            "event one below the hop limit should be accepted"
        );
    }

    #[tokio::test]
    async fn negative_hop_count_is_rejected() {
        let (on_event, count) = counting_on_event();
        let svc = FederationService::new("s".into(), vec![], on_event);

        let event = figpb::FederatedEvent {
            event: Some(figpb::GeoEvent {
                uid: "negative-hops".into(),
                ..Default::default()
            }),
            federate_hops: Some(figpb::FederateHops {
                current_hops: -1,
                max_hops: 20,
            }),
            ..Default::default()
        };

        let _ = svc
            .send_one_event(request_with_peer_cn(event, "unknown"))
            .await
            .expect("send_one_event");

        assert_eq!(
            count.load(Ordering::Relaxed),
            0,
            "event with negative hop count should be rejected"
        );
    }

    #[test]
    fn peer_id_sanitizes_control_characters() {
        // peer_id_from_request relies on TLS certs which we can't easily mock,
        // so validate the sanitization logic directly: control chars are stripped,
        // length is capped at MAX_PEER_CN_LENGTH.
        let raw = "alice\n\rinjection\x00attempt";
        let sanitized: String = raw
            .chars()
            .take(FederationService::MAX_PEER_CN_LENGTH)
            .filter(|c| !c.is_control())
            .collect();
        assert_eq!(sanitized, "aliceinjectionattempt");
    }

    #[test]
    fn peer_id_sanitization_caps_length() {
        let raw = "a".repeat(300);
        let sanitized: String = raw
            .chars()
            .take(FederationService::MAX_PEER_CN_LENGTH)
            .filter(|c| !c.is_control())
            .collect();
        assert_eq!(sanitized.len(), FederationService::MAX_PEER_CN_LENGTH);
    }

    #[test]
    fn peer_id_sanitization_empty_after_stripping() {
        // A CN consisting entirely of control characters should be filtered to empty
        let raw = "\n\r\x00\x01";
        let sanitized: String = raw
            .chars()
            .take(FederationService::MAX_PEER_CN_LENGTH)
            .filter(|c| !c.is_control())
            .collect();
        assert!(sanitized.is_empty());
    }

    #[tokio::test]
    async fn federation_rejects_unknown_peer_with_allowlist() {
        let (on_event, count) = counting_on_event();
        // Allowlist configured but no entry for this peer
        let allowed = HashMap::new();
        let svc =
            FederationService::new("s".into(), vec![], on_event).with_allowed_peer_groups(allowed);

        let event = figpb::FederatedEvent {
            federate_groups: vec!["Alpha".into()],
            ..Default::default()
        };
        let result = svc
            .send_one_event(request_with_peer_cn(event, "unknown"))
            .await;
        assert!(result.is_err());
        let status = result.unwrap_err();
        assert_eq!(status.code(), tonic::Code::PermissionDenied);
        assert_eq!(count.load(Ordering::Relaxed), 0, "callback must not fire");
    }

    #[tokio::test]
    async fn federation_allows_event_with_empty_groups() {
        let (on_event, count) = counting_on_event();
        let mut allowed = HashMap::new();
        allowed.insert("unknown".to_string(), HashSet::from(["Alpha".to_string()]));
        let svc =
            FederationService::new("s".into(), vec![], on_event).with_allowed_peer_groups(allowed);

        // Event with no groups claimed should pass (nothing to reject)
        let event = figpb::FederatedEvent {
            federate_groups: vec![],
            ..Default::default()
        };
        let result = svc
            .send_one_event(request_with_peer_cn(event, "unknown"))
            .await;
        assert!(result.is_ok());
        assert_eq!(count.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn with_allowed_peer_groups_configures_allowlist() {
        let mut allowed = HashMap::new();
        allowed.insert(
            "peer-1".to_string(),
            HashSet::from(["Alpha".to_string(), "Bravo".to_string()]),
        );
        let svc = FederationService::new("s".into(), vec![], noop_on_event())
            .with_allowed_peer_groups(allowed);
        assert!(svc.allowed_peer_groups.is_some());
        let dbg = format!("{svc:?}");
        assert!(dbg.contains("allowed_peer_groups_configured: true"));
    }

    #[test]
    fn default_service_has_no_peer_group_allowlist() {
        let svc = FederationService::new("s".into(), vec![], noop_on_event());
        assert!(svc.allowed_peer_groups.is_none());
        let dbg = format!("{svc:?}");
        assert!(dbg.contains("allowed_peer_groups_configured: false"));
    }

    /// Verify that an event claiming multiple groups is rejected when the peer
    /// is only authorized for a subset. The security invariant is reject-on-any-
    /// unauthorized: even one disallowed group in `federate_groups` causes the
    /// entire event to be denied.
    #[tokio::test]
    async fn federation_rejects_partial_group_authorization() {
        let (on_event, count) = counting_on_event();
        let mut allowed = HashMap::new();
        // Peer is only authorized for "alpha", not "bravo"
        allowed.insert("unknown".to_string(), HashSet::from(["alpha".to_string()]));
        let svc =
            FederationService::new("s".into(), vec![], on_event).with_allowed_peer_groups(allowed);

        // Event claims both "alpha" (authorized) and "bravo" (unauthorized)
        let event = figpb::FederatedEvent {
            federate_groups: vec!["alpha".into(), "bravo".into()],
            ..Default::default()
        };
        let result = svc
            .send_one_event(request_with_peer_cn(event, "unknown"))
            .await;
        assert!(
            result.is_err(),
            "event must be rejected when any claimed group is unauthorized"
        );
        let status = result.unwrap_err();
        assert_eq!(status.code(), tonic::Code::PermissionDenied);
        assert_eq!(
            count.load(Ordering::Relaxed),
            0,
            "callback must not fire for partially authorized event"
        );
    }

    /// Regression test for F-153: peer-supplied group names containing
    /// CR/LF must not be able to forge log lines. `validate_event_groups`
    /// emits a `warn!` when a group is not authorized; the `group` field
    /// is peer-controlled. We attach a capturing subscriber in both
    /// text-mode and JSON-mode, push an event with an attacker-crafted
    /// group containing `\r\n`, and assert the captured bytes do not
    /// contain a bare `\r` or `\n` inside the formatted `group=` field.
    #[tokio::test]
    async fn federation_sanitizes_crlf_in_unauthorized_group_log() {
        use std::io::Write;
        use std::sync::Mutex as StdMutex;

        use tracing_subscriber::Layer;
        use tracing_subscriber::filter::Targets;
        use tracing_subscriber::fmt::MakeWriter;
        use tracing_subscriber::layer::SubscriberExt;

        #[derive(Clone, Default)]
        struct SharedBuf(Arc<StdMutex<Vec<u8>>>);

        impl SharedBuf {
            fn snapshot(&self) -> Vec<u8> {
                self.0.lock().unwrap().clone()
            }
        }

        impl Write for SharedBuf {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        impl<'a> MakeWriter<'a> for SharedBuf {
            type Writer = SharedBuf;
            fn make_writer(&'a self) -> Self::Writer {
                self.clone()
            }
        }

        // Build a federation service that only authorizes peer "unknown"
        // for "alpha". A distinct attacker-controlled group name with
        // embedded CR/LF will be rejected and logged — that log line
        // must not be forgeable.
        let mut allowed = HashMap::new();
        allowed.insert("unknown".to_string(), HashSet::from(["alpha".to_string()]));
        let svc = FederationService::new("s".into(), vec![], noop_on_event())
            .with_allowed_peer_groups(allowed);

        // Attacker-crafted group: CR/LF followed by a fake audit record.
        // A naive log formatter would emit two lines; `sanitize_for_log`
        // replaces control chars with U+FFFD so the string stays a
        // single field value.
        let malicious = "bravo\r\n[audit] forged=true\r\nend";
        let event = figpb::FederatedEvent {
            federate_groups: vec!["alpha".into(), malicious.into()],
            ..Default::default()
        };

        // Text formatter — the vulnerable case without sanitize_for_log.
        let text_buf = SharedBuf::default();
        let text_layer = tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_writer(text_buf.clone())
            .with_filter(
                Targets::new().with_target("rustgate_federation::v2::server", tracing::Level::WARN),
            );
        let text_sub = tracing_subscriber::registry().with(text_layer);

        {
            let _guard = tracing::subscriber::set_default(text_sub);
            let _ = svc.send_one_event(Request::new(event.clone())).await;
        }

        let captured = text_buf.snapshot();
        assert!(!captured.is_empty(), "text layer captured no log output");
        // The malicious payload must not appear unescaped anywhere in the
        // captured bytes — the sanitizer replaces CR and LF with U+FFFD
        // (EF BF BD) so a raw `\r\n` sequence cannot survive.
        assert!(
            !captured.windows(2).any(|w| w == b"\r\n"),
            "raw CR/LF survived into text log output: forgeable log line\ncaptured = {:?}",
            String::from_utf8_lossy(&captured)
        );
        // Defense in depth: the forged-record marker must not appear
        // at the start of a line (which would indicate successful log
        // injection).
        let s = String::from_utf8_lossy(&captured);
        for line in s.lines() {
            assert!(
                !line.starts_with("[audit] forged=true"),
                "attacker-controlled record began a new log line: {line}"
            );
        }
    }

    // ── SendOneEvent V2 RPC coverage (issue #864) ─────────────────────
    //
    // Four tests below cover the contract required by the SendOneEvent
    // RPC implementation: success routing into the on_event callback
    // (which production wires through `Router::dispatch_inbound` via
    // `manager::create_v2_event_handler`), audit emission on a
    // post-auth policy rejection, the metrics counter increment under
    // the `api` feature, and the unauthenticated rejection from the
    // mTLS peer-id extraction path.

    /// Capture a tracing subscriber's audit-target output to a shared
    /// byte buffer. Used by the audit-emission test below.
    #[derive(Clone, Default)]
    struct AuditBuf(Arc<std::sync::Mutex<Vec<u8>>>);

    impl AuditBuf {
        fn snapshot_string(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().unwrap().clone()).to_string()
        }
    }

    impl std::io::Write for AuditBuf {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for AuditBuf {
        type Writer = AuditBuf;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// SendOneEvent must dispatch the inbound event to the registered
    /// `on_event` callback when mTLS, hop-count, and group checks all
    /// pass. The callback is the bridge to `Router::dispatch_inbound`
    /// in production (`manager::create_v2_event_handler`), so this
    /// test guarantees every accepted event reaches the routing layer.
    #[tokio::test]
    async fn send_one_event_routes_to_router_on_success() {
        let (on_event, count) = counting_on_event();
        let svc = FederationService::new("s".into(), vec!["Alpha".into()], on_event);

        let event = figpb::FederatedEvent {
            event: Some(figpb::GeoEvent {
                uid: "router-route".into(),
                r#type: "a-f-G-U-C".into(),
                lat: 38.8977,
                lon: -77.0365,
                ..Default::default()
            }),
            federate_groups: vec!["Alpha".into()],
            ..Default::default()
        };

        let resp = svc
            .send_one_event(request_with_peer_cn(event, "peer-cn"))
            .await
            .expect("send_one_event must succeed for an authorized event");
        let _ = resp.into_inner();

        assert_eq!(
            count.load(Ordering::Relaxed),
            1,
            "router callback must be invoked exactly once for an accepted event"
        );
    }

    /// A peer claiming a group it is not authorized for must be rejected
    /// with PermissionDenied AND must produce an audit-target
    /// `federation.event_rejected` record. This guards the post-auth
    /// policy gate: mTLS-extracted CN passes, but the event payload
    /// fails the allowlist — exactly the path operators want to alert
    /// on for misconfiguration / Byzantine-peer detection.
    #[tokio::test]
    async fn send_one_event_emits_audit_on_failure() {
        use tracing_subscriber::Layer;
        use tracing_subscriber::filter::Targets;
        use tracing_subscriber::layer::SubscriberExt;

        let buf = AuditBuf::default();
        let layer = tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_writer(buf.clone())
            .with_filter(Targets::new().with_target("audit", tracing::Level::INFO));
        let subscriber = tracing_subscriber::registry().with(layer);

        let mut allowed = HashMap::new();
        allowed.insert("peer-cn".to_string(), HashSet::from(["Alpha".to_string()]));
        let (on_event, count) = counting_on_event();
        let svc =
            FederationService::new("s".into(), vec![], on_event).with_allowed_peer_groups(allowed);

        // Claim "Bravo" — peer is only authorized for "Alpha".
        let event = figpb::FederatedEvent {
            federate_groups: vec!["Bravo".into()],
            ..Default::default()
        };

        let result = {
            let _guard = tracing::subscriber::set_default(subscriber);
            svc.send_one_event(request_with_peer_cn(event, "peer-cn"))
                .await
        };

        let err = result.expect_err("unauthorized-group event must be rejected");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert_eq!(
            count.load(Ordering::Relaxed),
            0,
            "router callback must not fire for a rejected event"
        );

        let captured = buf.snapshot_string();
        assert!(
            captured.contains("federation.event_rejected"),
            "audit log must contain federation.event_rejected; got: {captured}"
        );
        assert!(
            captured.contains("send_one_event"),
            "audit record must include the rpc=send_one_event label; got: {captured}"
        );
        assert!(
            captured.contains("unauthorized_group"),
            "audit record must include reason=unauthorized_group; got: {captured}"
        );
    }

    /// Successful SendOneEvent calls must increment both
    /// `messages_in` (legacy unlabelled) and
    /// `messages_in_by_rpc{rpc="send_one_event"}` (per-RPC). The
    /// counter wiring is gated on the `api` feature because the
    /// metrics module itself is only compiled when `api` is enabled.
    #[cfg(feature = "api")]
    #[tokio::test]
    async fn send_one_event_increments_metrics_counter() {
        // The metrics registry is global, so seed it once and read the
        // delta — parallel tests may also be incrementing.
        let _ = crate::metrics::init();

        let svc = FederationService::new("s".into(), vec![], noop_on_event());

        let total_before = crate::metrics::messages_in().get();
        let by_rpc_before = crate::metrics::messages_in_by_rpc()
            .with_label_values(&[RPC_SEND_ONE_EVENT])
            .get();

        let event = figpb::FederatedEvent {
            event: Some(figpb::GeoEvent {
                uid: "metric-tick".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let _ = svc
            .send_one_event(request_with_peer_cn(event, "peer-cn"))
            .await
            .expect("send_one_event must succeed");

        let total_after = crate::metrics::messages_in().get();
        let by_rpc_after = crate::metrics::messages_in_by_rpc()
            .with_label_values(&[RPC_SEND_ONE_EVENT])
            .get();

        // Parallel tests share the global registry, so we bound the
        // delta with `>=` rather than `==` — what we actually want to
        // guarantee is that *this* RPC contributed at least once.
        assert!(
            total_after > total_before,
            "messages_in counter must advance on accepted SendOneEvent"
        );
        assert!(
            by_rpc_after > by_rpc_before,
            "messages_in_by_rpc[rpc=send_one_event] must advance: before={by_rpc_before}, after={by_rpc_after}"
        );
    }

    /// SendOneEvent must reject any request whose `tonic::Request`
    /// carries no mTLS client certificate (and no test-only synthetic
    /// CN). This is the F-44 / #759 invariant — the previous
    /// IP-fallback behaviour silently accepted RPCs without a verified
    /// peer identity. The handler must short-circuit with
    /// `Unauthenticated` *before* any group or hop-count evaluation.
    #[tokio::test]
    async fn send_one_event_rejects_unauthenticated() {
        let (on_event, count) = counting_on_event();
        let svc = FederationService::new("s".into(), vec![], on_event);

        let event = figpb::FederatedEvent {
            federate_groups: vec!["Alpha".into()],
            ..Default::default()
        };
        // Plain Request — no test-only TestPeerCn extension, so the
        // production peer_id_from_request path runs and finds no cert.
        let result = svc.send_one_event(Request::new(event)).await;

        let err = result.expect_err("RPC without mTLS cert must be refused");
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
        assert_eq!(
            count.load(Ordering::Relaxed),
            0,
            "router callback must not fire on unauthenticated request"
        );
    }

    // ── SendOneBlob (refs #864) ───────────────────────────────────────────
    //
    // Parallel coverage to the SendOneEvent test set above. Each test
    // pins one of the four spec edge cases:
    //   1. peer_not_in_allowlist → PermissionDenied + audit reject
    //   2. hop-limit drop        → Ok(Empty) + audit reject (no client
    //                              channel for hop signals)
    //   3. metrics increment     → both messages_in and per-RPC label
    //   4. unauthenticated       → Unauthenticated, callback never fires

    #[tokio::test]
    async fn send_one_blob_emits_audit_on_peer_not_in_allowlist() {
        use tracing_subscriber::Layer;
        use tracing_subscriber::filter::Targets;
        use tracing_subscriber::layer::SubscriberExt;

        let buf = AuditBuf::default();
        let layer = tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_writer(buf.clone())
            .with_filter(Targets::new().with_target("audit", tracing::Level::INFO));
        let subscriber = tracing_subscriber::registry().with(layer);

        // Allowlist contains *only* "good-cn"; "bad-cn" is rejected.
        let mut allowed = HashMap::new();
        allowed.insert("good-cn".to_string(), HashSet::from(["Alpha".to_string()]));
        let (on_blob, count) = counting_on_blob();
        let svc = FederationService::new("s".into(), vec![], noop_on_event())
            .with_on_blob(on_blob)
            .with_allowed_peer_groups(allowed);

        let blob = figpb::BinaryBlob {
            data: b"unauthorized blob".to_vec(),
            ..Default::default()
        };

        let result = {
            let _guard = tracing::subscriber::set_default(subscriber);
            svc.send_one_blob(request_with_peer_cn(blob, "bad-cn"))
                .await
        };

        let err = result.expect_err("blob from peer-not-in-allowlist must be rejected");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert_eq!(
            count.load(Ordering::Relaxed),
            0,
            "on_blob callback must not fire for a rejected blob"
        );

        let captured = buf.snapshot_string();
        assert!(
            captured.contains("federation.event_rejected"),
            "audit log must contain federation.event_rejected; got: {captured}"
        );
        assert!(
            captured.contains("send_one_blob"),
            "audit record must include rpc=send_one_blob; got: {captured}"
        );
        assert!(
            captured.contains("peer_not_in_allowlist"),
            "audit record must include reason=peer_not_in_allowlist; got: {captured}"
        );
    }

    #[tokio::test]
    async fn send_one_blob_drops_at_hop_limit_with_audit() {
        use tracing_subscriber::Layer;
        use tracing_subscriber::filter::Targets;
        use tracing_subscriber::layer::SubscriberExt;

        let buf = AuditBuf::default();
        let layer = tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_writer(buf.clone())
            .with_filter(Targets::new().with_target("audit", tracing::Level::INFO));
        let subscriber = tracing_subscriber::registry().with(layer);

        let (on_blob, count) = counting_on_blob();
        let svc = FederationService::new("s".into(), vec![], noop_on_event()).with_on_blob(on_blob);

        // Blob arrives already at the hop limit — the V2 protocol
        // cannot signal hop drops to the sender (BinaryBlob → Empty
        // has no error channel for "too many hops"), so the handler
        // returns Ok(Empty) AND emits an audit reject record. The
        // forensic trail is the only vantage point.
        let blob = figpb::BinaryBlob {
            data: b"too-many-hops".to_vec(),
            federate_hops: Some(figpb::FederateHops {
                current_hops: i64::from(MAX_FEDERATION_HOPS),
                max_hops: i64::from(MAX_FEDERATION_HOPS) + 1,
            }),
            ..Default::default()
        };

        let result = {
            let _guard = tracing::subscriber::set_default(subscriber);
            svc.send_one_blob(request_with_peer_cn(blob, "peer-cn"))
                .await
        };

        let resp = result.expect("hop-limit drop returns Ok(Empty), not an error");
        let _ = resp.into_inner();
        assert_eq!(
            count.load(Ordering::Relaxed),
            0,
            "on_blob callback must not fire for a hop-dropped blob"
        );

        let captured = buf.snapshot_string();
        assert!(
            captured.contains("federation.event_rejected"),
            "audit log must contain federation.event_rejected for hop-limit drops; got: {captured}"
        );
        assert!(
            captured.contains("send_one_blob"),
            "audit record must include rpc=send_one_blob; got: {captured}"
        );
        assert!(
            captured.contains("hop_limit"),
            "audit record must include reason=hop_limit; got: {captured}"
        );
    }

    #[cfg(feature = "api")]
    #[tokio::test]
    async fn send_one_blob_increments_metrics_counter() {
        let _ = crate::metrics::init();

        let svc = FederationService::new("s".into(), vec![], noop_on_event());

        let total_before = crate::metrics::messages_in().get();
        let by_rpc_before = crate::metrics::messages_in_by_rpc()
            .with_label_values(&[RPC_SEND_ONE_BLOB])
            .get();

        let blob = figpb::BinaryBlob {
            data: b"metric-blob".to_vec(),
            ..Default::default()
        };
        let _ = svc
            .send_one_blob(request_with_peer_cn(blob, "peer-cn"))
            .await
            .expect("send_one_blob must succeed");

        let total_after = crate::metrics::messages_in().get();
        let by_rpc_after = crate::metrics::messages_in_by_rpc()
            .with_label_values(&[RPC_SEND_ONE_BLOB])
            .get();

        assert!(
            total_after > total_before,
            "messages_in counter must advance on accepted SendOneBlob"
        );
        assert!(
            by_rpc_after > by_rpc_before,
            "messages_in_by_rpc[rpc=send_one_blob] must advance: before={by_rpc_before}, after={by_rpc_after}"
        );
    }

    #[tokio::test]
    async fn send_one_blob_rejects_unauthenticated() {
        // Same F-44 / #759 invariant as SendOneEvent: a request
        // without a verified mTLS peer identity MUST short-circuit
        // with `Unauthenticated` BEFORE any payload processing or
        // callback dispatch.
        let (on_blob, count) = counting_on_blob();
        let svc = FederationService::new("s".into(), vec![], noop_on_event()).with_on_blob(on_blob);

        let blob = figpb::BinaryBlob {
            data: b"no-cn".to_vec(),
            ..Default::default()
        };
        // Plain Request — no test-only TestPeerCn extension.
        let result = svc.send_one_blob(Request::new(blob)).await;

        let err = result.expect_err("RPC without mTLS cert must be refused");
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
        assert_eq!(
            count.load(Ordering::Relaxed),
            0,
            "on_blob callback must not fire on unauthenticated request"
        );
    }

    // ── ServerROLStream + ClientROLStream (refs #864) ─────────────────────
    //
    // Observable-stub coverage for the V2 ROL streaming RPCs. Mirrors
    // SendOneBlob's five-test discipline:
    //   1. routes_to_callback / subscription_open_succeeds
    //   2. peer_not_in_allowlist  → PermissionDenied + audit reject
    //   3. hop_limit drop         → silent drop + audit reject
    //   4. metrics increment      → both messages_in and per-RPC label
    //   5. unauthenticated        → Unauthenticated, callback never fires
    //
    // `tonic::Streaming<T>` has no public synthetic constructor for an
    // empty stream that yields immediately, so the tests use a tiny
    // helper (`empty_streaming_request`) built on http_body_util::Empty
    // + tonic_prost::ProstDecoder. The per-event policy is also
    // exposed via `observe_inbound_rol_event`, exercised directly by
    // tests 1, 3, and 4 to avoid the streaming-construction
    // complexity for cases that don't need to test the handler entry
    // point.

    /// `OnRolEvent` callback that increments a shared atomic counter on
    /// every invocation, plus the counter itself for assertion. Sibling
    /// of [`counting_on_event`] / [`counting_on_blob`] so the three RPC
    /// test suites stay structurally identical.
    fn counting_on_rol_event() -> (OnRolEvent, Arc<AtomicU64>) {
        let count = Arc::new(AtomicU64::new(0));
        let c = Arc::clone(&count);
        let cb: OnRolEvent = Arc::new(move |_rol, _peer| {
            c.fetch_add(1, Ordering::Relaxed);
        });
        (cb, count)
    }

    /// Build a `tonic::Request<Streaming<T>>` that yields zero
    /// messages and immediately reports end-of-stream. Used by the
    /// peer-auth and allowlist tests below — they exercise the
    /// pre-stream gate and don't care what (if anything) the peer
    /// would have sent. Layered on `http_body_util::Empty` because
    /// `tonic::Streaming` has no `new_empty_request` shortcut and the
    /// production codepath uses prost decoders for figpb messages.
    ///
    /// Gated on `feature = "api"` because `http_body_util` is an
    /// `api`-only optional dep.
    #[cfg(feature = "api")]
    fn empty_streaming_request<T>(cn: Option<&str>) -> Request<Streaming<T>>
    where
        T: prost::Message + Default + 'static,
    {
        use http_body_util::Empty;
        use tonic_prost::ProstDecoder;
        let body = Empty::<bytes::Bytes>::new();
        let decoder = ProstDecoder::<T>::default();
        let stream = Streaming::new_request(decoder, body, None, None);
        let mut req = Request::new(stream);
        if let Some(cn) = cn {
            req.extensions_mut().insert(TestPeerCn(cn.to_string()));
        }
        req
    }

    // ── server_rol_stream tests ───────────────────────────────────────────

    /// `ServerROLStream` per-event policy must dispatch the inbound ROL
    /// event to the registered `on_rol_event` callback when hop-count
    /// validation passes. The callback is the bridge to a future
    /// router-side ROL ingress consumer; this test pins the
    /// observation-first invariant — every accepted ROL reaches the
    /// callback exactly once.
    #[tokio::test]
    async fn server_rol_stream_routes_to_callback_on_success() {
        let (on_rol_event, count) = counting_on_rol_event();
        let svc = FederationService::new("s".into(), vec![], noop_on_event())
            .with_on_rol_event(on_rol_event);

        let rol = figpb::Rol {
            program: "deploy resource".into(),
            ..Default::default()
        };

        let routed = FederationService::observe_inbound_rol_event(
            &svc.on_rol_event,
            "peer-cn",
            rol,
            svc.max_hops,
        );

        assert!(routed, "valid ROL event must pass the observation hook");
        assert_eq!(
            count.load(Ordering::Relaxed),
            1,
            "on_rol_event callback must fire exactly once for an accepted ROL event"
        );
    }

    /// A peer not in the inbound allowlist must be rejected at
    /// `ServerROLStream` open with `PermissionDenied` AND must produce
    /// a `federation.event_rejected` audit record tagged with
    /// `rpc=server_rol_stream`, `reason=peer_not_in_allowlist`. Mirrors
    /// the `SendOneBlob` peer-not-in-allowlist gate.
    // justification: the test uses `empty_streaming_request` which is gated
    // on `feature = "api"` (depends on `http_body_util`); fips and
    // post-quantum builds skip `api`.
    #[cfg(feature = "api")]
    #[tokio::test]
    async fn server_rol_stream_emits_audit_on_peer_not_in_allowlist() {
        use tracing_subscriber::Layer;
        use tracing_subscriber::filter::Targets;
        use tracing_subscriber::layer::SubscriberExt;

        let buf = AuditBuf::default();
        let layer = tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_writer(buf.clone())
            .with_filter(Targets::new().with_target("audit", tracing::Level::INFO));
        let subscriber = tracing_subscriber::registry().with(layer);

        // Allowlist contains *only* "good-cn"; "bad-cn" is rejected.
        let mut allowed = HashMap::new();
        allowed.insert("good-cn".to_string(), HashSet::from(["Alpha".to_string()]));
        let (on_rol_event, count) = counting_on_rol_event();
        let svc = FederationService::new("s".into(), vec![], noop_on_event())
            .with_on_rol_event(on_rol_event)
            .with_allowed_peer_groups(allowed);

        let request = empty_streaming_request::<figpb::Rol>(Some("bad-cn"));

        let result = {
            let _guard = tracing::subscriber::set_default(subscriber);
            svc.server_rol_stream(request).await
        };

        let err = result.expect_err("ROL stream from peer-not-in-allowlist must be rejected");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert_eq!(
            count.load(Ordering::Relaxed),
            0,
            "on_rol_event callback must not fire when the stream open is rejected"
        );

        let captured = buf.snapshot_string();
        assert!(
            captured.contains("federation.event_rejected"),
            "audit log must contain federation.event_rejected; got: {captured}"
        );
        assert!(
            captured.contains("server_rol_stream"),
            "audit record must include rpc=server_rol_stream; got: {captured}"
        );
        assert!(
            captured.contains("peer_not_in_allowlist"),
            "audit record must include reason=peer_not_in_allowlist; got: {captured}"
        );
    }

    /// A ROL event arriving at or beyond `MAX_FEDERATION_HOPS` must be
    /// silently dropped at the protocol layer (the response is a
    /// single Subscription, not a per-message ack — the V2 protocol
    /// has no channel for "too many hops" beyond the standard
    /// Ok/Err split). The forensic trail is the only vantage point:
    /// `federation.event_rejected` with `reason=hop_limit`.
    #[tokio::test]
    async fn server_rol_stream_drops_at_hop_limit_with_audit() {
        use tracing_subscriber::Layer;
        use tracing_subscriber::filter::Targets;
        use tracing_subscriber::layer::SubscriberExt;

        let buf = AuditBuf::default();
        let layer = tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_writer(buf.clone())
            .with_filter(Targets::new().with_target("audit", tracing::Level::INFO));
        let subscriber = tracing_subscriber::registry().with(layer);

        let (on_rol_event, count) = counting_on_rol_event();
        let svc = FederationService::new("s".into(), vec![], noop_on_event())
            .with_on_rol_event(on_rol_event);

        let rol = figpb::Rol {
            program: "loop-bait".into(),
            federate_hops: Some(figpb::FederateHops {
                current_hops: i64::from(MAX_FEDERATION_HOPS),
                max_hops: i64::from(MAX_FEDERATION_HOPS) + 1,
            }),
            ..Default::default()
        };

        let routed = {
            let _guard = tracing::subscriber::set_default(subscriber);
            FederationService::observe_inbound_rol_event(
                &svc.on_rol_event,
                "peer-cn",
                rol,
                svc.max_hops,
            )
        };

        assert!(
            !routed,
            "hop-limit event must not pass the observation hook"
        );
        assert_eq!(
            count.load(Ordering::Relaxed),
            0,
            "on_rol_event callback must not fire for a hop-dropped event"
        );

        let captured = buf.snapshot_string();
        assert!(
            captured.contains("federation.event_rejected"),
            "audit log must contain federation.event_rejected for hop-limit drops; got: {captured}"
        );
        assert!(
            captured.contains("server_rol_stream"),
            "audit record must include rpc=server_rol_stream; got: {captured}"
        );
        assert!(
            captured.contains("hop_limit"),
            "audit record must include reason=hop_limit; got: {captured}"
        );
    }

    /// Successful ROL events must increment both the legacy
    /// `messages_in` counter and the per-RPC
    /// `messages_in_by_rpc{rpc="server_rol_stream"}` label. Gated on
    /// `feature = "api"` because the metrics module itself only
    /// compiles with that feature.
    #[cfg(feature = "api")]
    #[tokio::test]
    async fn server_rol_stream_increments_metrics_counter_per_event() {
        let _ = crate::metrics::init();

        let svc = FederationService::new("s".into(), vec![], noop_on_event());

        let total_before = crate::metrics::messages_in().get();
        let by_rpc_before = crate::metrics::messages_in_by_rpc()
            .with_label_values(&[RPC_SERVER_ROL_STREAM])
            .get();

        let rol = figpb::Rol {
            program: "metric-tick".into(),
            ..Default::default()
        };
        let _ = FederationService::observe_inbound_rol_event(
            &svc.on_rol_event,
            "peer-cn",
            rol,
            svc.max_hops,
        );

        let total_after = crate::metrics::messages_in().get();
        let by_rpc_after = crate::metrics::messages_in_by_rpc()
            .with_label_values(&[RPC_SERVER_ROL_STREAM])
            .get();

        // Parallel tests share the global registry, so `>=` rather
        // than `==`. The guarantee is "this RPC contributed at
        // least once".
        assert!(
            total_after > total_before,
            "messages_in counter must advance on accepted ServerROLStream event"
        );
        assert!(
            by_rpc_after > by_rpc_before,
            "messages_in_by_rpc[rpc=server_rol_stream] must advance: before={by_rpc_before}, after={by_rpc_after}"
        );
    }

    /// `ServerROLStream` must reject any request whose `tonic::Request`
    /// carries no mTLS client certificate (and no test-only synthetic
    /// CN). F-44 / #759 invariant: short-circuit with `Unauthenticated`
    /// BEFORE any payload processing.
    // justification: uses `empty_streaming_request` which is api-feature-gated.
    #[cfg(feature = "api")]
    #[tokio::test]
    async fn server_rol_stream_rejects_unauthenticated() {
        let (on_rol_event, count) = counting_on_rol_event();
        let svc = FederationService::new("s".into(), vec![], noop_on_event())
            .with_on_rol_event(on_rol_event);

        let request = empty_streaming_request::<figpb::Rol>(None);
        let result = svc.server_rol_stream(request).await;

        let err = result.expect_err("RPC without mTLS cert must be refused");
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
        assert_eq!(
            count.load(Ordering::Relaxed),
            0,
            "on_rol_event callback must not fire on unauthenticated request"
        );
    }

    // ── client_rol_stream tests ───────────────────────────────────────────
    //
    // `ClientROLStream` is server-streaming — peer sends ONE Subscription,
    // we open a stream of ROL events back. The observable-stub records
    // the subscription open event with peer-auth + allowlist + audit +
    // metric, then returns an empty open stream. The five tests below
    // mirror the `ServerROLStream` shape: subscription accepted (in
    // place of "routes to callback"), peer-not-in-allowlist rejection,
    // hop-limit n/a (Subscription has no hops field, pinned via the
    // metric/audit count not changing on a no-hop subscription),
    // metrics increment per accepted subscription, and unauthenticated
    // rejection.

    /// `ClientROLStream` must accept a subscription from a known peer
    /// (no allowlist, or peer is in the allowlist) and return a stream
    /// without erroring. The stream itself stays empty in the stub
    /// (the routing-side machinery for pushing ROL events out lands
    /// in a follow-up); this test only pins that the open path works.
    #[tokio::test]
    async fn client_rol_stream_routes_to_callback_on_success() {
        // No allowed_peer_groups configured = open mode.
        let svc = FederationService::new("s".into(), vec![], noop_on_event());

        let mut req = Request::new(figpb::Subscription {
            identity: Some(figpb::Identity {
                name: "peer-cn".into(),
                ..Default::default()
            }),
            filter: String::new(),
            version: None,
        });
        req.extensions_mut().insert(TestPeerCn("peer-cn".into()));

        let resp = svc
            .client_rol_stream(req)
            .await
            .expect("client_rol_stream must succeed for an authorized peer in open mode");
        // Drop the response so the held-open background task stops
        // pinning resources after the assertion.
        drop(resp);
    }

    /// A peer not in the inbound allowlist must be rejected at
    /// `ClientROLStream` open with `PermissionDenied` AND must produce
    /// a `federation.event_rejected` audit record tagged with
    /// `rpc=client_rol_stream`, `reason=peer_not_in_allowlist`.
    #[tokio::test]
    async fn client_rol_stream_emits_audit_on_peer_not_in_allowlist() {
        use tracing_subscriber::Layer;
        use tracing_subscriber::filter::Targets;
        use tracing_subscriber::layer::SubscriberExt;

        let buf = AuditBuf::default();
        let layer = tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_writer(buf.clone())
            .with_filter(Targets::new().with_target("audit", tracing::Level::INFO));
        let subscriber = tracing_subscriber::registry().with(layer);

        let mut allowed = HashMap::new();
        allowed.insert("good-cn".to_string(), HashSet::from(["Alpha".to_string()]));
        let svc = FederationService::new("s".into(), vec![], noop_on_event())
            .with_allowed_peer_groups(allowed);

        let mut req = Request::new(figpb::Subscription::default());
        req.extensions_mut().insert(TestPeerCn("bad-cn".into()));

        let result = {
            let _guard = tracing::subscriber::set_default(subscriber);
            svc.client_rol_stream(req).await
        };

        let err = result.expect_err("ClientROLStream from peer-not-in-allowlist must be rejected");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);

        let captured = buf.snapshot_string();
        assert!(
            captured.contains("federation.event_rejected"),
            "audit log must contain federation.event_rejected; got: {captured}"
        );
        assert!(
            captured.contains("client_rol_stream"),
            "audit record must include rpc=client_rol_stream; got: {captured}"
        );
        assert!(
            captured.contains("peer_not_in_allowlist"),
            "audit record must include reason=peer_not_in_allowlist; got: {captured}"
        );
    }

    /// `ClientROLStream` carries no per-event hop count: the proto
    /// shape is one-Subscription-in, many-ROL-out, and `Subscription`
    /// has no `federate_hops` field. This test pins that the
    /// hop-limit gate is **not applicable** here — opening a stream
    /// succeeds and emits an `event_received` audit record with no
    /// `event_rejected` counterpart. A future revision that adds a
    /// hop-style gate to the subscription open path must update this
    /// test deliberately.
    #[tokio::test]
    async fn client_rol_stream_drops_at_hop_limit_with_audit() {
        use tracing_subscriber::Layer;
        use tracing_subscriber::filter::Targets;
        use tracing_subscriber::layer::SubscriberExt;

        let buf = AuditBuf::default();
        let layer = tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_writer(buf.clone())
            .with_filter(Targets::new().with_target("audit", tracing::Level::INFO));
        let subscriber = tracing_subscriber::registry().with(layer);

        let svc = FederationService::new("s".into(), vec![], noop_on_event());

        let mut req = Request::new(figpb::Subscription::default());
        req.extensions_mut().insert(TestPeerCn("peer-cn".into()));

        let resp = {
            let _guard = tracing::subscriber::set_default(subscriber);
            svc.client_rol_stream(req)
                .await
                .expect("ClientROLStream open must succeed: hop-limit gate does not apply")
        };
        drop(resp);

        let captured = buf.snapshot_string();
        // Pin "no hop_limit reject was emitted" — the gate is N/A for
        // this RPC. A regression that wires a hop-style check into
        // the subscription open path would surface here.
        assert!(
            !captured.contains("hop_limit"),
            "ClientROLStream must not emit a hop_limit reject (gate is N/A); got: {captured}"
        );
        // The `event_received` audit record IS expected on a clean
        // open — pin it explicitly so the hop-limit test still
        // validates the success path's forensic trail.
        assert!(
            captured.contains("federation.event_received"),
            "audit log must contain federation.event_received on accepted subscription; got: {captured}"
        );
        assert!(
            captured.contains("client_rol_stream"),
            "audit record must include rpc=client_rol_stream; got: {captured}"
        );
    }

    /// Successful `ClientROLStream` opens must increment both
    /// `messages_in` and `messages_in_by_rpc{rpc="client_rol_stream"}`.
    /// Note: the metric counts SUBSCRIPTIONS, not ROL events, because
    /// the proto shape is one-Subscription-in (the only thing the
    /// peer sends) — there is no per-event observation surface on
    /// this side until the bidirectional follow-up lands.
    #[cfg(feature = "api")]
    #[tokio::test]
    async fn client_rol_stream_increments_metrics_counter_per_event() {
        let _ = crate::metrics::init();

        let svc = FederationService::new("s".into(), vec![], noop_on_event());

        let total_before = crate::metrics::messages_in().get();
        let by_rpc_before = crate::metrics::messages_in_by_rpc()
            .with_label_values(&[RPC_CLIENT_ROL_STREAM])
            .get();

        let mut req = Request::new(figpb::Subscription::default());
        req.extensions_mut().insert(TestPeerCn("peer-cn".into()));
        let resp = svc
            .client_rol_stream(req)
            .await
            .expect("client_rol_stream must succeed");
        drop(resp);

        let total_after = crate::metrics::messages_in().get();
        let by_rpc_after = crate::metrics::messages_in_by_rpc()
            .with_label_values(&[RPC_CLIENT_ROL_STREAM])
            .get();

        assert!(
            total_after > total_before,
            "messages_in counter must advance on accepted ClientROLStream subscription"
        );
        assert!(
            by_rpc_after > by_rpc_before,
            "messages_in_by_rpc[rpc=client_rol_stream] must advance: before={by_rpc_before}, after={by_rpc_after}"
        );
    }

    /// `ClientROLStream` must reject any request whose `tonic::Request`
    /// carries no mTLS client certificate. F-44 / #759 invariant.
    #[tokio::test]
    async fn client_rol_stream_rejects_unauthenticated() {
        let svc = FederationService::new("s".into(), vec![], noop_on_event());

        // Plain Request — no test-only TestPeerCn extension.
        let result = svc
            .client_rol_stream(Request::new(figpb::Subscription::default()))
            .await;

        let err = result.expect_err("RPC without mTLS cert must be refused");
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    // ── builder + default plumbing ────────────────────────────────────────

    #[test]
    fn with_on_rol_event_overrides_default_noop() {
        let (on_rol_event, count) = counting_on_rol_event();
        let svc = FederationService::new("s".into(), vec![], noop_on_event())
            .with_on_rol_event(on_rol_event);

        // Drive the callback directly to confirm the override took
        // effect — the default is a no-op that never increments.
        (svc.on_rol_event)(figpb::Rol::default(), "peer-cn".into());
        assert_eq!(
            count.load(Ordering::Relaxed),
            1,
            "with_on_rol_event must replace the default no-op callback"
        );
    }

    #[test]
    fn default_service_uses_noop_on_rol_event() {
        let svc = FederationService::new("s".into(), vec![], noop_on_event());
        // Invoking the default no-op must not panic and must not
        // observe any side effects.
        (svc.on_rol_event)(figpb::Rol::default(), "peer-cn".into());
    }

    // ── ServerFederateGroupsStream + ClientFederateGroupsStream
    //    (refs #864) ─────────────────────────────────────────────────────
    //
    // Observable-stub coverage for the V2 GroupSync streaming RPCs.
    // Mirrors the ROL stub's five-test discipline:
    //   1. routes_to_callback / subscription_open_succeeds
    //   2. peer_not_in_allowlist  → PermissionDenied + audit reject
    //   3. hop_limit drop         → silent drop + audit reject (only
    //                                applies to the client-streaming
    //                                direction; ServerFederateGroupsStream's
    //                                Subscription has no hops field)
    //   4. metrics increment      → both messages_in and per-RPC label
    //   5. unauthenticated        → Unauthenticated, callback never fires

    /// `OnGroupSync` callback that increments a shared atomic counter
    /// on every invocation, plus the counter itself for assertion.
    /// Sibling of [`counting_on_blob`] / [`counting_on_rol_event`] so
    /// the four observable RPC test suites stay structurally identical.
    fn counting_on_group_sync() -> (OnGroupSync, Arc<AtomicU64>) {
        let count = Arc::new(AtomicU64::new(0));
        let c = Arc::clone(&count);
        let cb: OnGroupSync = Arc::new(move |_groups, _peer| {
            c.fetch_add(1, Ordering::Relaxed);
        });
        (cb, count)
    }

    // ── client_federate_groups_stream tests ───────────────────────────────

    /// `ClientFederateGroupsStream` per-update policy must dispatch the
    /// inbound `FederateGroups` update to the registered
    /// `on_group_sync` callback when hop-count validation passes. The
    /// callback is the bridge to a future router-side group-sync
    /// consumer; this test pins the observation-first invariant —
    /// every accepted update reaches the callback exactly once.
    #[tokio::test]
    async fn client_federate_groups_stream_routes_to_callback_on_success() {
        let (on_group_sync, count) = counting_on_group_sync();
        let svc = FederationService::new("s".into(), vec![], noop_on_event())
            .with_on_group_sync(on_group_sync);

        let groups = figpb::FederateGroups {
            federate_groups: vec!["Alpha".into(), "Bravo".into()],
            ..Default::default()
        };

        let routed = FederationService::observe_inbound_group_sync(
            &svc.on_group_sync,
            "peer-cn",
            groups,
            svc.max_hops,
        );

        assert!(
            routed,
            "valid FederateGroups update must pass the observation hook"
        );
        assert_eq!(
            count.load(Ordering::Relaxed),
            1,
            "on_group_sync callback must fire exactly once for an accepted update"
        );
    }

    /// A peer not in the inbound allowlist must be rejected at
    /// `ClientFederateGroupsStream` open with `PermissionDenied` AND
    /// must produce a `federation.event_rejected` audit record tagged
    /// with `rpc=client_federate_groups_stream`,
    /// `reason=peer_not_in_allowlist`. Mirrors the `ServerROLStream`
    /// peer-not-in-allowlist gate.
    // justification: the test uses `empty_streaming_request` which is gated
    // on `feature = "api"` (depends on `http_body_util`); fips and
    // post-quantum builds skip `api`.
    #[cfg(feature = "api")]
    #[tokio::test]
    async fn client_federate_groups_stream_emits_audit_on_peer_not_in_allowlist() {
        use tracing_subscriber::Layer;
        use tracing_subscriber::filter::Targets;
        use tracing_subscriber::layer::SubscriberExt;

        let buf = AuditBuf::default();
        let layer = tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_writer(buf.clone())
            .with_filter(Targets::new().with_target("audit", tracing::Level::INFO));
        let subscriber = tracing_subscriber::registry().with(layer);

        // Allowlist contains *only* "good-cn"; "bad-cn" is rejected.
        let mut allowed = HashMap::new();
        allowed.insert("good-cn".to_string(), HashSet::from(["Alpha".to_string()]));
        let (on_group_sync, count) = counting_on_group_sync();
        let svc = FederationService::new("s".into(), vec![], noop_on_event())
            .with_on_group_sync(on_group_sync)
            .with_allowed_peer_groups(allowed);

        let request = empty_streaming_request::<figpb::FederateGroups>(Some("bad-cn"));

        let result = {
            let _guard = tracing::subscriber::set_default(subscriber);
            svc.client_federate_groups_stream(request).await
        };

        let err =
            result.expect_err("group-sync stream from peer-not-in-allowlist must be rejected");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert_eq!(
            count.load(Ordering::Relaxed),
            0,
            "on_group_sync callback must not fire when the stream open is rejected"
        );

        let captured = buf.snapshot_string();
        assert!(
            captured.contains("federation.event_rejected"),
            "audit log must contain federation.event_rejected; got: {captured}"
        );
        assert!(
            captured.contains("client_federate_groups_stream"),
            "audit record must include rpc=client_federate_groups_stream; got: {captured}"
        );
        assert!(
            captured.contains("peer_not_in_allowlist"),
            "audit record must include reason=peer_not_in_allowlist; got: {captured}"
        );
    }

    /// A `FederateGroups` update arriving at or beyond
    /// `MAX_FEDERATION_HOPS` must be silently dropped at the protocol
    /// layer (the response is a single Subscription, not a per-message
    /// ack — the V2 protocol has no channel for "too many hops" beyond
    /// the standard Ok/Err split). The forensic trail is the only
    /// vantage point: `federation.event_rejected` with
    /// `reason=hop_limit`. Mirrors the ROL stub's hop-limit pin.
    #[tokio::test]
    async fn client_federate_groups_stream_drops_at_hop_limit_with_audit() {
        use tracing_subscriber::Layer;
        use tracing_subscriber::filter::Targets;
        use tracing_subscriber::layer::SubscriberExt;

        let buf = AuditBuf::default();
        let layer = tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_writer(buf.clone())
            .with_filter(Targets::new().with_target("audit", tracing::Level::INFO));
        let subscriber = tracing_subscriber::registry().with(layer);

        let (on_group_sync, count) = counting_on_group_sync();
        let svc = FederationService::new("s".into(), vec![], noop_on_event())
            .with_on_group_sync(on_group_sync);

        let groups = figpb::FederateGroups {
            federate_groups: vec!["Alpha".into()],
            federate_hops: Some(figpb::FederateHops {
                current_hops: i64::from(MAX_FEDERATION_HOPS),
                max_hops: i64::from(MAX_FEDERATION_HOPS) + 1,
            }),
            ..Default::default()
        };

        let routed = {
            let _guard = tracing::subscriber::set_default(subscriber);
            FederationService::observe_inbound_group_sync(
                &svc.on_group_sync,
                "peer-cn",
                groups,
                svc.max_hops,
            )
        };

        assert!(
            !routed,
            "hop-limit update must not pass the observation hook"
        );
        assert_eq!(
            count.load(Ordering::Relaxed),
            0,
            "on_group_sync callback must not fire for a hop-dropped update"
        );

        let captured = buf.snapshot_string();
        assert!(
            captured.contains("federation.event_rejected"),
            "audit log must contain federation.event_rejected for hop-limit drops; got: {captured}"
        );
        assert!(
            captured.contains("client_federate_groups_stream"),
            "audit record must include rpc=client_federate_groups_stream; got: {captured}"
        );
        assert!(
            captured.contains("hop_limit"),
            "audit record must include reason=hop_limit; got: {captured}"
        );
    }

    /// Successful `FederateGroups` updates must increment both the
    /// legacy `messages_in` counter and the per-RPC
    /// `messages_in_by_rpc{rpc="client_federate_groups_stream"}` label.
    /// Gated on `feature = "api"` because the metrics module itself
    /// only compiles with that feature.
    #[cfg(feature = "api")]
    #[tokio::test]
    async fn client_federate_groups_stream_increments_metrics_counter_per_update() {
        let _ = crate::metrics::init();

        let svc = FederationService::new("s".into(), vec![], noop_on_event());

        let total_before = crate::metrics::messages_in().get();
        let by_rpc_before = crate::metrics::messages_in_by_rpc()
            .with_label_values(&[RPC_CLIENT_FEDERATE_GROUPS_STREAM])
            .get();

        let groups = figpb::FederateGroups {
            federate_groups: vec!["metric-tick".into()],
            ..Default::default()
        };
        let _ = FederationService::observe_inbound_group_sync(
            &svc.on_group_sync,
            "peer-cn",
            groups,
            svc.max_hops,
        );

        let total_after = crate::metrics::messages_in().get();
        let by_rpc_after = crate::metrics::messages_in_by_rpc()
            .with_label_values(&[RPC_CLIENT_FEDERATE_GROUPS_STREAM])
            .get();

        // Parallel tests share the global registry, so `>=` rather
        // than `==`. The guarantee is "this RPC contributed at least
        // once".
        assert!(
            total_after > total_before,
            "messages_in counter must advance on accepted ClientFederateGroupsStream update"
        );
        assert!(
            by_rpc_after > by_rpc_before,
            "messages_in_by_rpc[rpc=client_federate_groups_stream] must advance: before={by_rpc_before}, after={by_rpc_after}"
        );
    }

    /// `ClientFederateGroupsStream` must reject any request whose
    /// `tonic::Request` carries no mTLS client certificate (and no
    /// test-only synthetic CN). F-44 / #759 invariant: short-circuit
    /// with `Unauthenticated` BEFORE any payload processing.
    // justification: uses `empty_streaming_request` which is api-feature-gated.
    #[cfg(feature = "api")]
    #[tokio::test]
    async fn client_federate_groups_stream_rejects_unauthenticated() {
        let (on_group_sync, count) = counting_on_group_sync();
        let svc = FederationService::new("s".into(), vec![], noop_on_event())
            .with_on_group_sync(on_group_sync);

        let request = empty_streaming_request::<figpb::FederateGroups>(None);
        let result = svc.client_federate_groups_stream(request).await;

        let err = result.expect_err("RPC without mTLS cert must be refused");
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
        assert_eq!(
            count.load(Ordering::Relaxed),
            0,
            "on_group_sync callback must not fire on unauthenticated request"
        );
    }

    // ── server_federate_groups_stream tests ───────────────────────────────
    //
    // `ServerFederateGroupsStream` is server-streaming — peer sends ONE
    // Subscription, we open a stream of FederateGroups updates back.
    // The observation stub records the subscription open with peer-auth
    // + allowlist + audit + metric, sends the initial groups roster,
    // then holds the stream open without producing further updates.
    // The five tests below mirror the `ClientROLStream` shape: open
    // path succeeds, peer-not-in-allowlist rejection at subscription
    // open, hop-limit n/a (Subscription has no hops field, pinned via
    // the audit record not containing a hop_limit reject), metrics
    // increment per accepted subscription, and unauthenticated
    // rejection.

    /// `ServerFederateGroupsStream` must accept a subscription from a
    /// known peer (no allowlist, or peer is in the allowlist) and
    /// return a stream without erroring. The first message on the
    /// stream is the initial groups roster — pinning that survives the
    /// observation-stub graduation.
    #[tokio::test]
    async fn server_federate_groups_stream_routes_to_callback_on_success() {
        // No allowed_peer_groups configured = open mode.
        let svc = FederationService::new(
            "s".into(),
            vec!["Alpha".into(), "Bravo".into()],
            noop_on_event(),
        );

        let mut req = Request::new(figpb::Subscription {
            identity: Some(figpb::Identity {
                name: "peer-cn".into(),
                ..Default::default()
            }),
            filter: String::new(),
            version: None,
        });
        req.extensions_mut().insert(TestPeerCn("peer-cn".into()));

        let resp = svc.server_federate_groups_stream(req).await.expect(
            "server_federate_groups_stream must succeed for an authorized peer in open mode",
        );
        // Pull the first message off the stream — it should be the
        // initial groups roster. This pins that the observable-stub
        // graduation didn't break the existing payload contract.
        use tokio_stream::StreamExt;
        let mut stream = resp.into_inner();
        let msg = stream
            .next()
            .await
            .expect("initial groups message must be sent on open")
            .expect("initial message must be Ok(FederateGroups)");
        assert_eq!(msg.federate_groups, vec!["Alpha", "Bravo"]);
        // Drop the stream so the held-open background task stops
        // pinning resources after the assertion.
        drop(stream);
    }

    /// A peer not in the inbound allowlist must be rejected at
    /// `ServerFederateGroupsStream` open with `PermissionDenied` AND
    /// must produce a `federation.event_rejected` audit record tagged
    /// with `rpc=server_federate_groups_stream`,
    /// `reason=peer_not_in_allowlist`.
    #[tokio::test]
    async fn server_federate_groups_stream_emits_audit_on_peer_not_in_allowlist() {
        use tracing_subscriber::Layer;
        use tracing_subscriber::filter::Targets;
        use tracing_subscriber::layer::SubscriberExt;

        let buf = AuditBuf::default();
        let layer = tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_writer(buf.clone())
            .with_filter(Targets::new().with_target("audit", tracing::Level::INFO));
        let subscriber = tracing_subscriber::registry().with(layer);

        let mut allowed = HashMap::new();
        allowed.insert("good-cn".to_string(), HashSet::from(["Alpha".to_string()]));
        let svc = FederationService::new("s".into(), vec![], noop_on_event())
            .with_allowed_peer_groups(allowed);

        let mut req = Request::new(figpb::Subscription::default());
        req.extensions_mut().insert(TestPeerCn("bad-cn".into()));

        let result = {
            let _guard = tracing::subscriber::set_default(subscriber);
            svc.server_federate_groups_stream(req).await
        };

        let err = result
            .expect_err("ServerFederateGroupsStream from peer-not-in-allowlist must be rejected");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);

        let captured = buf.snapshot_string();
        assert!(
            captured.contains("federation.event_rejected"),
            "audit log must contain federation.event_rejected; got: {captured}"
        );
        assert!(
            captured.contains("server_federate_groups_stream"),
            "audit record must include rpc=server_federate_groups_stream; got: {captured}"
        );
        assert!(
            captured.contains("peer_not_in_allowlist"),
            "audit record must include reason=peer_not_in_allowlist; got: {captured}"
        );
    }

    /// `ServerFederateGroupsStream` carries no per-event hop count: the
    /// proto shape is one-Subscription-in, many-FederateGroups-out, and
    /// `Subscription` has no `federate_hops` field. This test pins
    /// that the hop-limit gate is **not applicable** here — opening a
    /// stream succeeds and emits an `event_received` audit record with
    /// no `event_rejected` counterpart. A future revision that adds a
    /// hop-style gate to the subscription open path must update this
    /// test deliberately.
    #[tokio::test]
    async fn server_federate_groups_stream_drops_at_hop_limit_with_audit() {
        use tracing_subscriber::Layer;
        use tracing_subscriber::filter::Targets;
        use tracing_subscriber::layer::SubscriberExt;

        let buf = AuditBuf::default();
        let layer = tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_writer(buf.clone())
            .with_filter(Targets::new().with_target("audit", tracing::Level::INFO));
        let subscriber = tracing_subscriber::registry().with(layer);

        let svc = FederationService::new("s".into(), vec!["Alpha".into()], noop_on_event());

        let mut req = Request::new(figpb::Subscription::default());
        req.extensions_mut().insert(TestPeerCn("peer-cn".into()));

        let resp = {
            let _guard = tracing::subscriber::set_default(subscriber);
            svc.server_federate_groups_stream(req).await.expect(
                "ServerFederateGroupsStream open must succeed: hop-limit gate does not apply",
            )
        };
        // Drop the held-open stream so the background task stops
        // pinning resources after the assertion.
        drop(resp);

        let captured = buf.snapshot_string();
        // Pin "no hop_limit reject was emitted" — the gate is N/A for
        // this RPC. A regression that wired a hop-style check into the
        // subscription open path would surface here.
        assert!(
            !captured.contains("hop_limit"),
            "ServerFederateGroupsStream must not emit a hop_limit reject (gate is N/A); got: {captured}"
        );
        // The `event_received` audit record IS expected on a clean
        // open — pin it explicitly so the hop-limit test still
        // validates the success path's forensic trail.
        assert!(
            captured.contains("federation.event_received"),
            "audit log must contain federation.event_received on accepted subscription; got: {captured}"
        );
        assert!(
            captured.contains("server_federate_groups_stream"),
            "audit record must include rpc=server_federate_groups_stream; got: {captured}"
        );
    }

    /// Successful `ServerFederateGroupsStream` opens must increment
    /// both `messages_in` and
    /// `messages_in_by_rpc{rpc="server_federate_groups_stream"}`. Note:
    /// the metric counts SUBSCRIPTIONS, not FederateGroups updates,
    /// because the proto shape is one-Subscription-in (the only thing
    /// the peer sends) — there is no per-update observation surface on
    /// this side until a bidirectional follow-up lands.
    #[cfg(feature = "api")]
    #[tokio::test]
    async fn server_federate_groups_stream_increments_metrics_counter_per_update() {
        let _ = crate::metrics::init();

        let svc = FederationService::new("s".into(), vec!["Alpha".into()], noop_on_event());

        let total_before = crate::metrics::messages_in().get();
        let by_rpc_before = crate::metrics::messages_in_by_rpc()
            .with_label_values(&[RPC_SERVER_FEDERATE_GROUPS_STREAM])
            .get();

        let mut req = Request::new(figpb::Subscription::default());
        req.extensions_mut().insert(TestPeerCn("peer-cn".into()));
        let resp = svc
            .server_federate_groups_stream(req)
            .await
            .expect("server_federate_groups_stream must succeed");
        drop(resp);

        let total_after = crate::metrics::messages_in().get();
        let by_rpc_after = crate::metrics::messages_in_by_rpc()
            .with_label_values(&[RPC_SERVER_FEDERATE_GROUPS_STREAM])
            .get();

        assert!(
            total_after > total_before,
            "messages_in counter must advance on accepted ServerFederateGroupsStream subscription"
        );
        assert!(
            by_rpc_after > by_rpc_before,
            "messages_in_by_rpc[rpc=server_federate_groups_stream] must advance: before={by_rpc_before}, after={by_rpc_after}"
        );
    }

    /// `ServerFederateGroupsStream` must reject any request whose
    /// `tonic::Request` carries no mTLS client certificate. F-44 /
    /// #759 invariant.
    #[tokio::test]
    async fn server_federate_groups_stream_rejects_unauthenticated() {
        let svc = FederationService::new("s".into(), vec!["Alpha".into()], noop_on_event());

        // Plain Request — no test-only TestPeerCn extension.
        let result = svc
            .server_federate_groups_stream(Request::new(figpb::Subscription::default()))
            .await;

        let err = result.expect_err("RPC without mTLS cert must be refused");
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    // ── builder + default plumbing ────────────────────────────────────────

    #[test]
    fn with_on_group_sync_overrides_default_noop() {
        let (on_group_sync, count) = counting_on_group_sync();
        let svc = FederationService::new("s".into(), vec![], noop_on_event())
            .with_on_group_sync(on_group_sync);

        // Drive the callback directly to confirm the override took
        // effect — the default is a no-op that never increments.
        (svc.on_group_sync)(figpb::FederateGroups::default(), "peer-cn".into());
        assert_eq!(
            count.load(Ordering::Relaxed),
            1,
            "with_on_group_sync must replace the default no-op callback"
        );
    }

    #[test]
    fn default_service_uses_noop_on_group_sync() {
        let svc = FederationService::new("s".into(), vec![], noop_on_event());
        // Invoking the default no-op must not panic and must not
        // observe any side effects.
        (svc.on_group_sync)(figpb::FederateGroups::default(), "peer-cn".into());
    }

    // ── runtime-configurable hop limit (closes #758) ─────────────────────
    //
    // These five tests pin the contract for `FederationService::with_max_hops`:
    // the override takes effect, the default falls back to MAX_FEDERATION_HOPS,
    // hop validation reads the per-instance value (not the constant), the
    // boundary is `>=` (event AT max_hops is rejected), and the `0` argument
    // is rejected in debug / saturated to 1 in release.

    /// `with_max_hops` must override the default for the instance it
    /// returns. Pinning the field's stored value directly — no tonic
    /// round-trip needed because the read sites all consult the same
    /// `self.max_hops` field.
    #[test]
    fn with_max_hops_overrides_default() {
        let svc = FederationService::new("s".into(), vec![], noop_on_event()).with_max_hops(16);
        assert_eq!(
            svc.max_hops, 16,
            "with_max_hops must overwrite the default-8 hop limit"
        );
    }

    /// A FederationService built without `with_max_hops` must default
    /// to `MAX_FEDERATION_HOPS` (8). This is the migration safety
    /// invariant — every existing deployment that did not opt into the
    /// new builder method continues to enforce the historical limit.
    #[test]
    fn with_max_hops_default_is_eight() {
        let svc = FederationService::new("s".into(), vec![], noop_on_event());
        assert_eq!(
            svc.max_hops, MAX_FEDERATION_HOPS,
            "default max_hops must equal MAX_FEDERATION_HOPS for backward compatibility"
        );
        assert_eq!(MAX_FEDERATION_HOPS, 8, "MAX_FEDERATION_HOPS default is 8");
    }

    /// The hop-validation gate must read the per-instance `max_hops`,
    /// not the compile-time constant. Build a service with
    /// `max_hops=2`, send an event with `current_hops=3`, and assert
    /// it's dropped before the callback fires. If validation still
    /// hard-coded MAX_FEDERATION_HOPS=8, the event would slip through.
    #[tokio::test]
    async fn hop_validation_uses_configured_max() {
        let (on_event, count) = counting_on_event();
        let svc = FederationService::new("s".into(), vec![], on_event).with_max_hops(2);

        let event = figpb::FederatedEvent {
            event: Some(figpb::GeoEvent {
                uid: "tight-limit".into(),
                ..Default::default()
            }),
            federate_hops: Some(figpb::FederateHops {
                current_hops: 3,
                max_hops: 20,
            }),
            ..Default::default()
        };

        let _ = svc
            .send_one_event(request_with_peer_cn(event, "unknown"))
            .await
            .expect("send_one_event returns Ok(Empty) on hop drop");

        assert_eq!(
            count.load(Ordering::Relaxed),
            0,
            "event with current_hops=3 must be rejected when max_hops=2 (boundary inclusive)"
        );
    }

    /// Boundary semantics for the configurable limit: an event AT the
    /// configured `max_hops` is rejected (the comparison is `>=`, not
    /// `>`), an event one below it is accepted. Mirrors the pre-#758
    /// `hop_count_at_exact_limit_is_rejected` /
    /// `hop_count_one_below_limit_is_accepted` discipline against a
    /// non-default limit so a regression that flipped the comparison
    /// to `>` would surface here.
    #[tokio::test]
    async fn hop_validation_at_boundary() {
        // Boundary case 1: current_hops == max_hops → rejected.
        let (on_event, count_at) = counting_on_event();
        let svc_at = FederationService::new("s".into(), vec![], on_event).with_max_hops(2);
        let event_at = figpb::FederatedEvent {
            event: Some(figpb::GeoEvent {
                uid: "at".into(),
                ..Default::default()
            }),
            federate_hops: Some(figpb::FederateHops {
                current_hops: 2,
                max_hops: 20,
            }),
            ..Default::default()
        };
        let _ = svc_at
            .send_one_event(request_with_peer_cn(event_at, "unknown"))
            .await
            .expect("hop drop returns Ok(Empty)");
        assert_eq!(
            count_at.load(Ordering::Relaxed),
            0,
            "event with current_hops=2 must be rejected when max_hops=2 (>= boundary)"
        );

        // Boundary case 2: current_hops == max_hops - 1 → accepted.
        let (on_event_below, count_below) = counting_on_event();
        let svc_below = FederationService::new("s".into(), vec![], on_event_below).with_max_hops(2);
        let event_below = figpb::FederatedEvent {
            event: Some(figpb::GeoEvent {
                uid: "below".into(),
                ..Default::default()
            }),
            federate_hops: Some(figpb::FederateHops {
                current_hops: 1,
                max_hops: 20,
            }),
            ..Default::default()
        };
        let _ = svc_below
            .send_one_event(request_with_peer_cn(event_below, "unknown"))
            .await
            .expect("send_one_event");
        assert_eq!(
            count_below.load(Ordering::Relaxed),
            1,
            "event with current_hops=1 must be accepted when max_hops=2 (one below the boundary)"
        );
    }

    /// `with_max_hops(0)` is a programming error: it would reject every
    /// inbound message including the first hop, breaking federation
    /// entirely. In debug builds it must panic so the bug surfaces
    /// during development; in release builds it must saturate to 1 so
    /// a misconfigured deployment degrades to "first-hop only" rather
    /// than "no federation". This test pins both branches of the
    /// `cfg(debug_assertions)` split.
    #[test]
    #[cfg(debug_assertions)]
    fn with_max_hops_zero_rejected() {
        let result = std::panic::catch_unwind(|| {
            let _ = FederationService::new("s".into(), vec![], noop_on_event()).with_max_hops(0);
        });
        assert!(
            result.is_err(),
            "with_max_hops(0) must panic in debug builds"
        );
    }

    /// Release-build counterpart of `with_max_hops_zero_rejected`. With
    /// the panic-bypass `debug_assertions` cfg flipped off, the
    /// builder must saturate to `max_hops=1` so federation degrades
    /// gracefully to first-hop-only rather than tearing down with a
    /// panic in production.
    #[test]
    #[cfg(not(debug_assertions))]
    fn with_max_hops_zero_saturates_to_one_in_release() {
        let svc = FederationService::new("s".into(), vec![], noop_on_event()).with_max_hops(0);
        assert_eq!(
            svc.max_hops, 1,
            "with_max_hops(0) must saturate to 1 in release builds"
        );
    }
}
