//! TLS transport, session management, and message routing for rustgate.

mod cache;
mod codec;
mod config;
mod encoder;
mod extract;
mod filter;
mod listener;
mod repeater;
mod router;
mod session;
mod throttle;

pub use cache::PositionCache;
pub use codec::{FramedCodec, LengthPrefixedCodec, LineDelimitedCodec, XmlStreamCodec};
pub use config::TlsConfig;
pub use encoder::{CotEncoder, MessageEncoder, RawEncoder};
pub use extract::extract_identity;
pub use filter::{GeoBounds, MessageFilter};
pub use listener::TlsListener;
pub use repeater::EmergencyRepeater;
pub use router::{Router, SessionHandle};
#[cfg(feature = "proto")]
pub use rustgate_proto::TakFrameCodec;
pub use session::{AuthenticatedSession, SessionReader, SessionWriter};
pub use throttle::{ClientThrottle, ThrottleConfig};
