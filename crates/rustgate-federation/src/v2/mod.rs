// Copyright © 2026 Roberto Chiofalo.

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
/// W3C Trace Context propagation across the V2 federation gRPC channel
/// (PR-B of issue #852). See [`traceparent`] for the inject / extract
/// helpers that move `traceparent` and `tracestate` headers across RPC
/// boundaries.
#[cfg(feature = "v2")]
pub mod traceparent;
