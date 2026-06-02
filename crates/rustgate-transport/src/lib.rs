// Copyright © 2026 Roberto Chiofalo.

//! Codec / framing primitives, hardware identity helpers, and UDP / multicast
//! ingress transports for rustgate.
//!
//! The routing engine — `Router`, `SessionHandle`, ACL evaluation, dedup,
//! store-and-forward, position cache, replay, throttling, tenant quota,
//! obligations, and egress — moved to `rustgate-router` in #888.
//!
//! TLS, certificate handling, OCSP, SPIFFE, and the TCP listeners
//! (`TlsListener`, `PlaintextListener`) live in `rustgate-tls` as of
//! #890.
//!
//! This crate now focuses on transport-layer plumbing that does not depend
//! on the full routing graph: byte-level codecs, hardware identity backends,
//! and UDP I/O.
//!
//! # Error handling
//!
//! Most fallible APIs in this crate return [`rustgate_core::error::Result`].
//! Specialised submodules expose typed error enums for matchable failure
//! modes (`codec::FramedCodecError`).

#![forbid(unsafe_code)]

/// Re-export of the relocated backpressure module for source-level
/// compatibility with callers that used `rustgate_transport::backpressure::*`.
/// The gate now lives in `rustgate_resilience::backpressure` so HTTP, NATS,
/// and federation publishers can share it without a transport dependency.
pub use rustgate_resilience::backpressure;

mod codec;
mod codecs;
pub mod hw_identity;

pub mod codec_ingress;
pub mod udp;
pub mod udp_common;
pub mod udp_multicast;

pub use codec::{
    FramedCodec, FramedCodecError, LengthPrefixedCodec, LineDelimitedCodec, XmlStreamCodec,
};
pub use codecs::{RawLengthPrefixedCodec, RawLineCodec, TakXmlCodec};
pub use hw_identity::{
    HardwareIdentity, HardwareIdentityError, HardwareIdentityResolver, Pkcs11StubBackend,
    SignatureAlgorithm as HardwareSignatureAlgorithm,
};
#[cfg(feature = "proto")]
pub use rustgate_proto::TakFrameCodec;
pub use rustgate_resilience::backpressure::{
    BackpressureGate, BackpressurePermit, DEFAULT_MAX_QUEUED_BYTES, OnBytesChanged, OnDeferred,
};
pub use rustls::server::ResolvesServerCert;
pub use rustls::server::danger::ClientCertVerifier;
pub use udp::{CidrPrefix, UdpInput, UdpInputConfig};
pub use udp_multicast::{
    DEFAULT_MAX_BPS as DEFAULT_MULTICAST_MAX_BPS, DEFAULT_MULTICAST_TTL, MulticastConfig,
    MulticastGroup, OnMulticastForward, SOURCE_UDP_MULTICAST,
};
