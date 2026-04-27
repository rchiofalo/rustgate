// Copyright © 2026 Roberto Chiofalo.

//! TAK protocol buffer translation for rustgate.
//!
//! Provides bidirectional conversion between CoT XML and TAK protobuf
//! wire format, plus the TakFrameCodec for the 0xBF+varint framing.
//!
//! # Canonical Format
//!
//! XML is the canonical payload format in RoutableMessage. This crate
//! translates at session edges:
//! - Inbound: protobuf -> XML (before routing)
//! - Outbound: XML -> protobuf (after routing)
//!
//! # Error handling
//!
//! This crate's error type is [`error::ProtoError`]; binary callers
//! propagate it via `?` and map it through `anyhow::Error` at the
//! orchestration layer. [`rustgate_core::error::RustgateError`] is the
//! boundary aggregator for the `rustgate-core` / `rustgate-transport`
//! slice and is not automatically constructed from [`error::ProtoError`].

// Varint decoding casts u64 -> usize. On 32-bit platforms this truncation
// could bypass frame size checks, so we require 64-bit.
#[cfg(not(target_pointer_width = "64"))]
compile_error!("rustgate-proto requires a 64-bit platform (varint decoding uses usize)");

pub mod codec;
pub mod convert;
pub mod error;
pub mod negotiate;
pub mod proto_codec;
pub mod xml_full;

/// Generated protobuf types from TAK `.proto` schemas.
pub mod tak_proto {
    include!(concat!(
        env!("OUT_DIR"),
        "/atakmap.commoncommo.protobuf.v1.rs"
    ));
}

pub use codec::TakFrameCodec;
pub use convert::{proto_to_xml, xml_to_proto};
pub use error::ProtoError;
pub use negotiate::{
    DEFAULT_NEGOTIATION_TIMEOUT, MAX_PROTO_VERSION, MIN_PROTO_VERSION,
    NEGOTIATION_TIMEOUT_DEFAULT_SECS, NegotiatedVersion, build_protocol_support_xml,
    build_tak_response, parse_tak_request, read_tak_request, read_tak_request_with_timeout,
};
pub use proto_codec::TakProtobufCodec;
pub use xml_full::{FullCotEvent, parse_full};
