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

pub mod codec;
pub mod convert;
pub mod encoder;
pub mod error;
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
pub use encoder::TakProtobufEncoder;
pub use error::ProtoError;
pub use xml_full::{parse_full, FullCotEvent};
