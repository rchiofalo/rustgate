//! V2 federation protocol: gRPC over mTLS.
//!
//! This is the standard TAK Server federation wire format using
//! the FederatedChannel gRPC service over HTTP/2 with mTLS.
//!
//! Requires the `v2` feature flag.

#[cfg(feature = "v2")]
pub mod client;
#[cfg(feature = "v2")]
pub mod convert;
#[cfg(feature = "v2")]
pub mod proto;
#[cfg(feature = "v2")]
pub mod server;
