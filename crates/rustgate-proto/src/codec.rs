//! TAK protocol buffer frame codec.
//!
//! # Wire Format (TCP streaming)
//!
//! ```text
//! 0xBF | varint(payload_len) | protobuf_bytes
//! ```
//!
//! # Security
//!
//! Enforces MAX_FRAME_SIZE to prevent resource exhaustion from
//! malicious varint length claims.

use std::io;

use rustgate_core::constants::MAX_FRAME_SIZE;
use tokio_util::bytes::{Buf, BufMut, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

/// TAK protocol magic byte marking the start of a protobuf frame.
pub(crate) const MAGIC_BYTE: u8 = 0xBF;

/// Maximum varint bytes (5 bytes covers u32 range, sufficient for frame lengths).
const MAX_VARINT_BYTES: usize = 5;

/// Codec for the TAK protobuf streaming wire format.
///
/// Each frame is: magic byte (0xBF) + varint-encoded payload length + payload.
/// Handles partial reads with internal state tracking.
#[derive(Debug, Default)]
pub struct TakFrameCodec {
    /// Payload length parsed from the header, waiting for data.
    pending_len: Option<usize>,
}

impl TakFrameCodec {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Decoder for TakFrameCodec {
    type Item = BytesMut;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let payload_len = match self.pending_len {
            Some(len) => len,
            None => {
                if src.is_empty() {
                    return Ok(None);
                }

                if src[0] != MAGIC_BYTE {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("expected magic byte 0xBF, got 0x{:02X}", src[0]),
                    ));
                }

                // Need magic + at least 1 varint byte
                if src.len() < 2 {
                    return Ok(None);
                }

                match decode_varint(&src[1..]) {
                    Some((len, varint_bytes)) => {
                        if len > MAX_FRAME_SIZE {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!("TAK frame too large: {len} bytes (max {MAX_FRAME_SIZE})"),
                            ));
                        }
                        src.advance(1 + varint_bytes);
                        self.pending_len = Some(len);
                        len
                    }
                    None => {
                        // Varint incomplete — check if we've consumed too many bytes
                        if src.len() > MAX_VARINT_BYTES {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "invalid varint in TAK frame header",
                            ));
                        }
                        return Ok(None);
                    }
                }
            }
        };

        if src.len() < payload_len {
            src.reserve(payload_len - src.len());
            return Ok(None);
        }

        self.pending_len = None;
        Ok(Some(src.split_to(payload_len)))
    }
}

impl Encoder<BytesMut> for TakFrameCodec {
    type Error = io::Error;

    fn encode(&mut self, item: BytesMut, dst: &mut BytesMut) -> Result<(), Self::Error> {
        if item.len() > MAX_FRAME_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "TAK frame too large: {} bytes (max {MAX_FRAME_SIZE})",
                    item.len()
                ),
            ));
        }

        let varint_len = varint_encoded_len(item.len());
        dst.reserve(1 + varint_len + item.len());
        dst.put_u8(MAGIC_BYTE);
        encode_varint(item.len() as u64, dst);
        dst.extend_from_slice(&item);
        Ok(())
    }
}

/// Decode a protobuf-style varint from the buffer.
///
/// Returns `(value, bytes_consumed)` or `None` if the varint is incomplete.
pub(crate) fn decode_varint(buf: &[u8]) -> Option<(usize, usize)> {
    let mut result: u64 = 0;
    let mut shift = 0;
    for (i, &byte) in buf.iter().enumerate().take(MAX_VARINT_BYTES) {
        result |= u64::from(byte & 0x7F) << shift;
        if byte & 0x80 == 0 {
            return Some((result as usize, i + 1));
        }
        shift += 7;
    }
    None
}

/// Encode a value as a protobuf-style varint.
fn encode_varint(mut value: u64, dst: &mut BytesMut) {
    while value >= 0x80 {
        dst.put_u8((value as u8) | 0x80);
        value >>= 7;
    }
    dst.put_u8(value as u8);
}

/// Number of bytes needed to encode a value as a varint.
fn varint_encoded_len(value: usize) -> usize {
    let mut v = value as u64;
    let mut len = 1;
    while v >= 0x80 {
        v >>= 7;
        len += 1;
    }
    len
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_round_trip_small() {
        let mut buf = BytesMut::new();
        encode_varint(42, &mut buf);
        let (val, consumed) = decode_varint(&buf).expect("decode");
        assert_eq!(val, 42);
        assert_eq!(consumed, 1);
    }

    #[test]
    fn varint_round_trip_medium() {
        let mut buf = BytesMut::new();
        encode_varint(300, &mut buf);
        let (val, consumed) = decode_varint(&buf).expect("decode");
        assert_eq!(val, 300);
        assert_eq!(consumed, 2);
    }

    #[test]
    fn varint_round_trip_large() {
        let mut buf = BytesMut::new();
        encode_varint(16384, &mut buf);
        let (val, consumed) = decode_varint(&buf).expect("decode");
        assert_eq!(val, 16384);
        assert_eq!(consumed, 3);
    }

    #[test]
    fn varint_zero() {
        let mut buf = BytesMut::new();
        encode_varint(0, &mut buf);
        let (val, consumed) = decode_varint(&buf).expect("decode");
        assert_eq!(val, 0);
        assert_eq!(consumed, 1);
    }

    #[test]
    fn varint_boundary_127() {
        let mut buf = BytesMut::new();
        encode_varint(127, &mut buf);
        assert_eq!(buf.len(), 1);
        let (val, _) = decode_varint(&buf).expect("decode");
        assert_eq!(val, 127);
    }

    #[test]
    fn varint_boundary_128() {
        let mut buf = BytesMut::new();
        encode_varint(128, &mut buf);
        assert_eq!(buf.len(), 2);
        let (val, _) = decode_varint(&buf).expect("decode");
        assert_eq!(val, 128);
    }

    #[test]
    fn codec_round_trip_small() {
        let mut codec = TakFrameCodec::new();
        let payload = BytesMut::from(&b"hello protobuf"[..]);
        let mut buf = BytesMut::new();
        codec.encode(payload.clone(), &mut buf).expect("encode");

        let decoded = codec.decode(&mut buf).expect("decode").expect("frame");
        assert_eq!(decoded, payload);
    }

    #[test]
    fn codec_round_trip_multi_byte_varint() {
        let mut codec = TakFrameCodec::new();
        let payload = BytesMut::from(vec![0xABu8; 300].as_slice());
        let mut buf = BytesMut::new();
        codec.encode(payload.clone(), &mut buf).expect("encode");

        let decoded = codec.decode(&mut buf).expect("decode").expect("frame");
        assert_eq!(decoded, payload);
    }

    #[test]
    fn codec_round_trip_empty_payload() {
        let mut codec = TakFrameCodec::new();
        let payload = BytesMut::new();
        let mut buf = BytesMut::new();
        codec.encode(payload.clone(), &mut buf).expect("encode");

        let decoded = codec.decode(&mut buf).expect("decode").expect("frame");
        assert_eq!(decoded, payload);
    }

    #[test]
    fn codec_rejects_bad_magic() {
        let mut codec = TakFrameCodec::new();
        let mut buf = BytesMut::from(&[0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05][..]);
        let err = codec.decode(&mut buf).expect_err("should reject");
        assert!(err.to_string().contains("magic byte"), "got: {err}");
    }

    #[test]
    fn codec_rejects_oversized_frame() {
        let mut codec = TakFrameCodec::new();
        // Encode a varint claiming 32MB
        let mut buf = BytesMut::new();
        buf.put_u8(MAGIC_BYTE);
        encode_varint(32 * 1024 * 1024, &mut buf);
        let err = codec.decode(&mut buf).expect_err("should reject");
        assert!(err.to_string().contains("too large"), "got: {err}");
    }

    #[test]
    fn codec_partial_header_returns_none() {
        let mut codec = TakFrameCodec::new();
        let mut buf = BytesMut::from(&[MAGIC_BYTE][..]);
        assert!(codec.decode(&mut buf).expect("ok").is_none());
    }

    #[test]
    fn codec_partial_payload_returns_none() {
        let mut codec = TakFrameCodec::new();
        let mut buf = BytesMut::new();
        buf.put_u8(MAGIC_BYTE);
        encode_varint(10, &mut buf);
        buf.extend_from_slice(&[0u8; 5]); // only 5 of 10 bytes

        assert!(codec.decode(&mut buf).expect("ok").is_none());
        // Complete the payload
        buf.extend_from_slice(&[0u8; 5]);
        let decoded = codec.decode(&mut buf).expect("ok").expect("frame");
        assert_eq!(decoded.len(), 10);
    }

    #[test]
    fn codec_multiple_frames() {
        let mut codec = TakFrameCodec::new();
        let mut buf = BytesMut::new();

        let p1 = BytesMut::from(&b"first"[..]);
        let p2 = BytesMut::from(&b"second"[..]);
        codec.encode(p1.clone(), &mut buf).expect("encode1");
        codec.encode(p2.clone(), &mut buf).expect("encode2");

        let d1 = codec.decode(&mut buf).expect("ok").expect("frame1");
        let d2 = codec.decode(&mut buf).expect("ok").expect("frame2");
        assert_eq!(d1, p1);
        assert_eq!(d2, p2);
    }
}
