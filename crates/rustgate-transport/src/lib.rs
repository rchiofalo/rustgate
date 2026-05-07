// Copyright © 2026 Roberto Chiofalo.

//! Routing, session management, dedup, ACL, codecs, store-and-forward,
//! throttling, replay filtering, and UDP / multicast I/O for rustgate.
//!
//! TLS, certificate handling, OCSP, SPIFFE, and the TCP listeners
//! (`TlsListener`, `PlaintextListener`) live in `rustgate-tls` as of
//! #890. This crate consumes those primitives but no longer owns them.
//!
//! # Error handling
//!
//! Most fallible APIs in this crate return [`rustgate_core::error::Result`],
//! whose error type is [`rustgate_core::error::RustgateError`] — the
//! boundary-layer aggregator wrapping [`TransportError`] / [`ConfigError`] /
//! [`std::io::Error`]. Specialised submodules expose their own typed enums
//! for matchable failure modes (e.g. [`store_forward::StoreForwardError`],
//! [`obligations::ObligationError`], [`codec::FramedCodecError`]). Binary
//! callers map any propagated error into [`rustgate_core::error::RustgateError`]
//! at the boundary; per-crate enums are not auto-converted into the
//! aggregator.
//!
//! [`TransportError`]: rustgate_core::error::TransportError
//! [`ConfigError`]: rustgate_core::error::ConfigError

mod acl;
/// Re-export of the relocated backpressure module for source-level
/// compatibility with callers that used `rustgate_transport::backpressure::*`.
/// The gate now lives in `rustgate_resilience::backpressure` so HTTP, NATS,
/// and federation publishers can share it without a transport dependency.
pub use rustgate_resilience::backpressure;
mod cache;
mod codec;
mod codecs;
mod dedup;
pub mod egress;
mod filter;
pub mod hw_identity;
pub mod obligations;
mod repeater;
mod replay;
mod router;
pub mod store_forward;
mod throttle;

pub use acl::{GroupAcl, GroupAclPolicy};
pub use cache::{OnCacheSize, PositionCache};
pub use codec::{
    FramedCodec, FramedCodecError, LengthPrefixedCodec, LineDelimitedCodec, XmlStreamCodec,
};
pub use codecs::{RawLengthPrefixedCodec, RawLineCodec, TakXmlCodec};
pub use dedup::{
    DEFAULT_MAX_ENTRIES as DEFAULT_DEDUP_MAX_ENTRIES, DedupCache, DedupStats, OnDuplicate, OnInsert,
};
pub use egress::{EgressEnvelope, EgressError, RecipientClass};
pub use filter::{GeoBounds, MessageFilter};
pub use hw_identity::{
    HardwareIdentity, HardwareIdentityError, HardwareIdentityResolver, Pkcs11StubBackend,
    SignatureAlgorithm as HardwareSignatureAlgorithm,
};
pub use quota::{
    DEFAULT_TENANT_KEY, OnTenantThroughputConsumed, OnTenantThroughputRejection, QuotaConfig,
    TenantQuota, TenantQuotaTracker, TenantThroughputRejection,
};
pub use repeater::EmergencyRepeater;
pub use replay::ReplayFilter;
pub use router::{
    ACCESS_LOG_TARGET, AuthzEvent, AuthzObserver, NORMAL_CHANNEL_CAPACITY, OnAuthzInFlightChanged,
    OnDropped, OnFanout, OnMessageDelivered, OnMessageDropped, OnMulticastOversizeDropped,
    OnObligationApplied, OnPepDecision, OnRoutedByKind, PRIORITY_CHANNEL_CAPACITY, PendingAudit,
    PendingDelivery, PositionReplayLimitConfig, RoutedMessage, Router, SessionHandle,
};
pub use rustgate_authz;
#[cfg(feature = "proto")]
pub use rustgate_proto::TakFrameCodec;
pub use rustgate_resilience::backpressure::{
    BackpressureGate, BackpressurePermit, DEFAULT_MAX_QUEUED_BYTES, OnBytesChanged, OnDeferred,
};
pub use rustls::server::ResolvesServerCert;
pub use rustls::server::danger::ClientCertVerifier;
pub use store_forward::{
    ClientQueue, DEFAULT_CLIENT_QUEUE_MAX_BYTES, OnDrainObservation, QueueStats, StoreForwardError,
};
pub use throttle::{ClientThrottle, ThrottleConfig};

pub mod quota;

pub mod udp;
pub mod udp_multicast;

pub use udp::{CidrPrefix, UdpInput, UdpInputConfig};
pub use udp_multicast::{
    DEFAULT_MAX_BPS as DEFAULT_MULTICAST_MAX_BPS, DEFAULT_MULTICAST_TTL, MulticastConfig,
    MulticastGroup, OnMulticastForward, SOURCE_UDP_MULTICAST,
};
