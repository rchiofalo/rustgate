//! TLS transport, session management, and message routing for rustgate.

mod acl;
mod cache;
pub mod cert_reloader;
mod codec;
mod codecs;
mod config;
mod extract;
mod filter;
mod listener;
mod repeater;
mod replay;
mod router;
mod session;
mod throttle;
mod verifier;

pub use acl::{GroupAcl, GroupAclPolicy};
pub use cache::PositionCache;
pub use cert_reloader::CertReloader;
pub use codec::{FramedCodec, LengthPrefixedCodec, LineDelimitedCodec, XmlStreamCodec};
pub use codecs::{RawLengthPrefixedCodec, RawLineCodec, TakXmlCodec};
#[cfg(feature = "fips")]
pub use config::install_fips_provider;
pub use config::{
    TlsConfig, TlsMinVersion, check_crl_freshness, is_fips_provider_active, is_pq_provider_active,
};
#[cfg(feature = "post-quantum")]
pub use config::{install_pq_provider, install_provider_with_kx_groups};
pub use extract::{ExpectedKeyUsage, extract_identity, validate_key_usage};
pub use filter::{GeoBounds, MessageFilter};
pub use listener::{DEFAULT_MAX_HANDSHAKES, TlsListener};
pub use repeater::EmergencyRepeater;
pub use replay::ReplayFilter;
pub use router::{NORMAL_CHANNEL_CAPACITY, PRIORITY_CHANNEL_CAPACITY, Router, SessionHandle};
#[cfg(feature = "proto")]
pub use rustgate_proto::TakFrameCodec;
pub use session::{AuthenticatedSession, SessionReader, SessionWriter};
pub use throttle::{ClientThrottle, ThrottleConfig};
pub use verifier::{DynamicCertVerifier, RootStoreProvider};

pub mod pem;

mod plaintext;
pub mod udp;

pub use plaintext::{PlaintextIdentityConfig, PlaintextListener, PlaintextSession};
pub use udp::{UdpInput, UdpInputConfig};
