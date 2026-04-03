//! Pluggable protocol codec trait.
//!
//! The [`Codec`] trait unifies framing (message boundary detection) and
//! payload transformation (wire format ↔ canonical XML) into a single
//! abstraction. Each protocol gets one `Codec` implementation that knows
//! how to frame its wire format and convert payloads to/from the internal
//! [`RoutableMessage`](crate::message::RoutableMessage) representation.
//!
//! The router is codec-agnostic — it only sees `RoutableMessage` with
//! canonical XML payloads. Codecs handle translation at session edges.
//!
//! # WebSocket note
//!
//! The WebSocket transport (`rustgate-websocket`) handles framing via
//! tungstenite, not `FramedCodec`. It currently uses the legacy
//! [`MessageEncoder`](crate::encoder::MessageEncoder) trait and its own
//! `WsEncoding` enum for outbound encoding. Migrating WebSocket to use
//! `Codec` is tracked as a follow-up to the Phase 1 codec unification.
//!
//! # Legacy `Encoding` enum
//!
//! The `--encoding` CLI flag and its `Encoding` enum (`Raw`, `Cot`,
//! `TakProtobuf`) are preserved for backwards compatibility. The
//! `build_codec()` factory maps `(Framing, Encoding)` pairs to the
//! appropriate `Codec` implementation. Note that `Encoding::Cot` and
//! `Encoding::Raw` are functionally identical for TCP/TLS sessions since
//! the `CotEncoder` was always a passthrough — the distinction only
//! matters for the WebSocket path which still uses `MessageEncoder`.

use std::io;

use bytes::{Bytes, BytesMut};

use crate::message::RoutableMessage;
use crate::protocol::FramingStrategy;

/// Protocol codec for bidirectional message transformation.
///
/// Combines payload encoding (outbound) and decoding (inbound) for a
/// specific wire protocol. The framing layer (message boundary detection)
/// remains separate via [`FramingStrategy`] — the codec declares which
/// framing it needs, and the session layer constructs the appropriate
/// `FramedCodec` from it.
///
/// # Canonical format
///
/// The internal payload format in `RoutableMessage` is XML. Codecs that
/// use a different wire format (e.g., protobuf) must convert in both
/// directions: wire → XML on decode, XML → wire on encode.
pub trait Codec: Send + Sync + std::fmt::Debug {
    /// Human-readable protocol identifier (e.g., `"tak-xml"`, `"tak-protobuf"`).
    fn protocol_id(&self) -> &str;

    /// The framing strategy this codec uses for message boundary detection.
    ///
    /// The session layer uses this to construct the appropriate tokio-util
    /// `Decoder`/`Encoder` for the TCP stream.
    fn framing(&self) -> FramingStrategy;

    /// Transform raw framed bytes into canonical payload format (XML).
    ///
    /// Accepts `BytesMut` so passthrough codecs can call `frame.freeze()`
    /// for zero-copy conversion instead of allocating. Codecs that must
    /// transform the payload (e.g., protobuf → XML) will allocate
    /// regardless, so the owned buffer costs nothing extra.
    ///
    /// # Errors
    ///
    /// Returns an error if the frame cannot be decoded (e.g., malformed
    /// protobuf, invalid encoding).
    fn decode_payload(&self, frame: BytesMut) -> io::Result<Bytes>;

    /// Encode a [`RoutableMessage`]'s payload into wire-format bytes.
    ///
    /// For XML-native codecs, this passes through the payload. For protobuf
    /// codecs, this converts XML → protobuf.
    ///
    /// # Errors
    ///
    /// Returns an error if the message cannot be encoded for this protocol
    /// (e.g., XML that doesn't map to the target schema).
    fn encode_payload(&self, msg: &RoutableMessage) -> io::Result<Bytes>;

    /// Confidence score (0.0..=1.0) that the given prefix bytes belong to
    /// this protocol.
    ///
    /// Used for protocol auto-detection in future phases. Implementations
    /// should examine the first few bytes of a connection and return a
    /// confidence score. Returns 0.0 if the prefix does not match.
    fn detect(&self, prefix: &[u8]) -> f32;
}
