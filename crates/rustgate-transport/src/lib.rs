//! TLS transport, session management, and message routing for rustgate.

mod acl;
pub mod backpressure;
mod cache;
pub mod cert_reloader;
mod codec;
mod codecs;
mod config;
mod dedup;
mod extract;
mod filter;
mod listener;
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

pub use acl::{GroupAcl, GroupAclPolicy};
pub use backpressure::{
    BackpressureGate, BackpressurePermit, DEFAULT_MAX_QUEUED_BYTES, OnBytesChanged, OnDeferred,
};
pub use cache::PositionCache;
pub use cert_reloader::CertReloader;
#[cfg(feature = "ocsp")]
pub use client_ocsp::OcspStaplerFetcher;
pub use client_ocsp::{ClientOcspVerifier, FetchFuture, OcspFetcher, OnCacheHit, OnCacheMiss};
pub use codec::{FramedCodec, LengthPrefixedCodec, LineDelimitedCodec, XmlStreamCodec};
pub use codecs::{RawLengthPrefixedCodec, RawLineCodec, TakXmlCodec};
#[cfg(feature = "fips")]
pub use config::install_fips_provider;
pub use config::{
    TlsConfig, TlsMinVersion, check_crl_freshness, is_fips_provider_active, is_pq_provider_active,
};
#[cfg(feature = "post-quantum")]
pub use config::{install_pq_provider, install_provider_with_kx_groups};
pub use dedup::{
    DEFAULT_MAX_ENTRIES as DEFAULT_DEDUP_MAX_ENTRIES, DedupCache, OnDuplicate, OnInsert,
};
pub use extract::{ExpectedKeyUsage, extract_identity, validate_key_usage};
pub use filter::{GeoBounds, MessageFilter};
pub use listener::{DEFAULT_MAX_HANDSHAKES, OnHandshakeError, TlsListener};
pub use repeater::EmergencyRepeater;
pub use replay::ReplayFilter;
pub use router::{
    ACCESS_LOG_TARGET, NORMAL_CHANNEL_CAPACITY, PRIORITY_CHANNEL_CAPACITY, RoutedMessage, Router,
    SessionHandle,
};
#[cfg(feature = "proto")]
pub use rustgate_proto::TakFrameCodec;
pub use rustls::server::ResolvesServerCert;
pub use rustls::server::danger::ClientCertVerifier;
pub use session::{AuthenticatedSession, SessionReader, SessionWriter};
pub use store_forward::{
    ClientQueue, DEFAULT_CLIENT_QUEUE_MAX_BYTES, QueueStats, StoreForwardError,
};
pub use throttle::{ClientThrottle, ThrottleConfig};
pub use verifier::{DynamicCertVerifier, RootStoreProvider};

pub mod pem;

mod plaintext;
pub mod udp;

pub use plaintext::{PlaintextIdentityConfig, PlaintextListener, PlaintextSession};
pub use udp::{UdpInput, UdpInputConfig};
