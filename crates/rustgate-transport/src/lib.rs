//! TLS transport, session management, and message routing for rustgate.

mod cache;
mod codec;
mod config;
mod encoder;
mod extract;
mod listener;
mod router;
mod session;

pub use cache::PositionCache;
pub use codec::{FramedCodec, LengthPrefixedCodec, LineDelimitedCodec, XmlStreamCodec};
pub use config::TlsConfig;
pub use encoder::{CotEncoder, MessageEncoder, RawEncoder};
pub use extract::extract_identity;
pub use listener::TlsListener;
pub use router::{Router, SessionHandle};
#[cfg(feature = "proto")]
pub use rustgate_proto::TakFrameCodec;
pub use session::{AuthenticatedSession, SessionReader, SessionWriter};
