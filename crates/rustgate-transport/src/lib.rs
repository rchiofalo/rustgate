//! TLS transport, session management, and message routing for rustgate.

mod cache;
mod codec;
mod config;
mod encoder;
mod extract;
mod filter;
mod listener;
mod repeater;
mod replay;
mod router;
mod session;
mod throttle;
mod verifier;

pub use cache::PositionCache;
pub use codec::{FramedCodec, LengthPrefixedCodec, LineDelimitedCodec, XmlStreamCodec};
#[cfg(feature = "fips")]
pub use config::install_fips_provider;
pub use config::{TlsConfig, TlsMinVersion, check_crl_freshness, is_fips_provider_active};
pub use encoder::{CotEncoder, MessageEncoder, RawEncoder};
pub use extract::{ExpectedKeyUsage, extract_identity, validate_key_usage};
pub use filter::{GeoBounds, MessageFilter};
pub use listener::TlsListener;
pub use repeater::EmergencyRepeater;
pub use replay::ReplayFilter;
pub use router::{Router, SessionHandle};
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
