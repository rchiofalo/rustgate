// Copyright © 2026 Roberto Chiofalo.

//! Routing engine for rustgate.
//!
//! This crate provides the core routing primitives: [`Router`], [`SessionHandle`],
//! ACL evaluation, deduplication, store-and-forward queuing, position-cache
//! replay, message filtering, throttling, tenant quotas, obligations, and
//! egress envelope rendering. It is consumed by `rustgate-transport` (TCP/UDP
//! ingress) and the sink crates (federation, NATS, HTTP, MQTT, websocket)
//! that fan messages out.
//!
//! TLS, certificate handling, and TCP listeners live in `rustgate-tls`. Codec
//! and protocol framing primitives stay in `rustgate-transport`. This crate
//! is post-handshake, post-decode: it operates on `RoutableMessage` from
//! `rustgate-core`.
//!
//! # Error handling
//!
//! Most fallible APIs in this crate return [`rustgate_core::error::Result`],
//! whose error type is [`rustgate_core::error::RustgateError`]. Specialised
//! submodules expose typed enums for matchable failure modes (e.g.
//! [`store_forward::StoreForwardError`], [`obligations::ObligationError`],
//! [`egress::EgressError`]).

#![forbid(unsafe_code)]

pub mod acl;
pub mod cache;
#[cfg(feature = "cjadc2")]
pub mod cjadc2;
pub mod dedup;
pub mod egress;
pub mod filter;
pub mod obligations;
pub mod quota;
pub mod repeater;
pub mod replay;
pub mod router;
pub mod store_forward;
pub mod throttle;

pub use acl::{GroupAcl, GroupAclPolicy};
pub use cache::{OnCacheSize, PositionCache};
#[cfg(feature = "cjadc2")]
pub use cjadc2::{DestinationEnvelope, plan_routing_fanout};
pub use dedup::{
    DEFAULT_MAX_ENTRIES as DEFAULT_DEDUP_MAX_ENTRIES, DedupCache, DedupStats, OnDuplicate, OnInsert,
};
pub use egress::{EgressEnvelope, EgressError, RecipientClass};
pub use filter::{GeoBounds, MessageFilter};
pub use quota::{
    DEFAULT_TENANT_KEY, OnTenantThroughputConsumed, OnTenantThroughputRejection, QuotaConfig,
    TenantQuota, TenantQuotaTracker, TenantThroughputRejection,
};
pub use repeater::EmergencyRepeater;
pub use replay::ReplayFilter;
pub use router::{
    ACCESS_LOG_TARGET, AuthzEvent, AuthzObserver, NORMAL_CHANNEL_CAPACITY, OnAuthzInFlightChanged,
    OnDropped, OnDroppedByTenant, OnFanout, OnFanoutByTenant, OnMessageDelivered, OnMessageDropped,
    OnMulticastForward, OnMulticastOversizeDropped, OnObligationApplied, OnPepDecision, OnRouted,
    OnRoutedByKind, PRIORITY_CHANNEL_CAPACITY, PendingAudit, PendingDelivery,
    PositionReplayLimitConfig, RoutedMessage, Router, SessionHandle,
};
pub use store_forward::{
    ClientQueue, DEFAULT_CLIENT_QUEUE_MAX_BYTES, OnDrainObservation, QueueStats, StoreForwardError,
};
pub use throttle::{ClientThrottle, ThrottleConfig};
