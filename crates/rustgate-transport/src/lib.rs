// Copyright © 2026 Roberto Chiofalo.

//! TLS transport, session management, and message routing for rustgate.

mod acl;
/// Re-export of the relocated backpressure module for source-level
/// compatibility with callers that used `rustgate_transport::backpressure::*`.
/// The gate now lives in `rustgate_resilience::backpressure` so HTTP, NATS,
/// and federation publishers can share it without a transport dependency.
pub use rustgate_resilience::backpressure;
mod cache;
pub mod cert_reloader;
mod codec;
mod codecs;
mod config;
mod dedup;
mod extract;
mod filter;
mod listener;
pub mod obligations;
mod repeater;
mod replay;
mod router;
mod session;
pub mod store_forward;
mod throttle;
mod verifier;

pub mod client_ocsp;

#[cfg(feature = "ocsp")]
pub mod ocsp;

#[cfg(feature = "spiffe")]
pub mod spiffe;

pub use acl::{GroupAcl, GroupAclPolicy};
pub use cache::{OnCacheSize, PositionCache};
pub use cert_reloader::CertReloader;
#[cfg(feature = "ocsp")]
pub use client_ocsp::OcspStaplerFetcher;
pub use client_ocsp::{ClientOcspVerifier, FetchFuture, OcspFetcher, OnCacheHit, OnCacheMiss};
pub use codec::{
    FramedCodec, FramedCodecError, LengthPrefixedCodec, LineDelimitedCodec, XmlStreamCodec,
};
pub use codecs::{RawLengthPrefixedCodec, RawLineCodec, TakXmlCodec};
#[cfg(feature = "fips")]
pub use config::install_fips_provider;
pub use config::{
    CrlFileSummary, TlsConfig, TlsMinVersion, check_crl_freshness, crl_max_age_seconds,
    is_fips_provider_active, is_pq_provider_active,
};
#[cfg(feature = "post-quantum")]
pub use config::{install_pq_provider, install_provider_with_kx_groups};
pub use dedup::{
    DEFAULT_MAX_ENTRIES as DEFAULT_DEDUP_MAX_ENTRIES, DedupCache, OnDuplicate, OnInsert,
};
pub use extract::{ExpectedKeyUsage, extract_identity, validate_key_usage};
pub use filter::{GeoBounds, MessageFilter};
pub use listener::{DEFAULT_MAX_HANDSHAKES, OnHandshakeDuration, OnHandshakeError, TlsListener};
pub use quota::{DEFAULT_TENANT_KEY, QuotaConfig, TenantQuota, TenantQuotaTracker};
pub use repeater::EmergencyRepeater;
pub use replay::ReplayFilter;
pub use router::{
    ACCESS_LOG_TARGET, AuthzEvent, AuthzObserver, NORMAL_CHANNEL_CAPACITY,
    PRIORITY_CHANNEL_CAPACITY, PendingAudit, PendingDelivery, PositionReplayLimitConfig,
    RoutedMessage, Router, SessionHandle,
};
pub use rustgate_authz;
#[cfg(feature = "proto")]
pub use rustgate_proto::TakFrameCodec;
pub use rustgate_resilience::backpressure::{
    BackpressureGate, BackpressurePermit, DEFAULT_MAX_QUEUED_BYTES, OnBytesChanged, OnDeferred,
};
pub use rustls::server::ResolvesServerCert;
pub use rustls::server::danger::ClientCertVerifier;
pub use session::{AuthenticatedSession, SessionReader, SessionWriter};
pub use store_forward::{
    ClientQueue, DEFAULT_CLIENT_QUEUE_MAX_BYTES, QueueStats, StoreForwardError,
};
pub use throttle::{ClientThrottle, ThrottleConfig};
pub use verifier::{DynamicCertVerifier, RootStoreProvider};

pub mod pem;

pub mod quota;

mod plaintext;
pub mod udp;

pub use plaintext::{PlaintextIdentityConfig, PlaintextListener, PlaintextSession};
pub use udp::{CidrPrefix, UdpInput, UdpInputConfig};
