// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Bit-level utilities for composing schemas across non-byte-aligned
//! boundaries.
//!
//! The schema runtime ([`crate::codec::SchemaCodec`]) consumes a
//! byte slice whose first declared field starts at byte 0, bit 0.
//! That assumption fails for protocols where a fixed-shape body
//! follows a **variable-length bit-packed header** — VMF is the
//! canonical example. The VMF header is 38–94 bits depending on
//! which optional FPI-gated fields are present; the body that
//! follows is itself bit-packed but starts at whatever bit
//! position the header ended on.
//!
//! Rather than extending the schema runtime with a `start_bit`
//! parameter (the "v6 grammar" arc tracked in #1411 — bigger
//! surface area, more code to maintain), this module provides a
//! small bit-shift utility that lets a wrapper produce a
//! byte-aligned view of the remaining payload for the body
//! schema to consume.
//!
//! Wrapper pattern:
//!
//! ```ignore
//! // Decode side: hand-roll the header (already required because
//! // the header is variable-length bit-packed), then feed the
//! // remaining bytes to the body schema after byte-aligning.
//! let (header, header_end_bit) = decode_header_hand_rolled(payload)?;
//! let body_byte_offset = header_end_bit / 8;
//! let body_bit_offset  = header_end_bit % 8;
//! let body_bytes = bitstream::shift_left(
//!     &payload[body_byte_offset..],
//!     body_bit_offset as u8,
//! );
//! let entity = body_codec.to_entity(&body_bytes)?;
//!
//! // Encode side: hand-roll the header, then ask the body schema
//! // for its bytes, then merge them at the bit-cursor position.
//! let header_bytes = encode_header_hand_rolled(...)?;
//! let body_entity = project_to_entity(body_value);
//! let body_bytes = body_codec.from_entity(&body_entity)?;
//! let wire = bitstream::splice_at(
//!     &header_bytes,
//!     header_end_bit,
//!     &body_bytes,
//!     body_bit_count,
//! );
//! ```
//!
//! Cost: one allocation per encode/decode of the body slice.
//! For VMF K05.1 that's ~22 bytes — irrelevant in any tactical
//! workload. The benefit is **zero changes to `SchemaCodec`**:
//! the runtime keeps its "first field starts at byte 0 bit 0"
//! contract, which means every existing test and codec continues
//! to behave exactly as before.

/// Shift a byte slice **left by `bit_shift` bits**, producing a
/// new `Vec<u8>` whose first declared bit lands at byte 0 bit 0.
///
/// `bit_shift` must be in `[0, 7]`. A shift of 0 returns the input
/// verbatim. A shift of N drops the high N bits of byte 0 and
/// fills the low N bits of the last output byte with zero
/// (which is safe — the consumer of those trailing bits is
/// either past the declared schema size or has its own
/// bit-width-based truncation).
///
/// # Example
///
/// ```rust
/// use rustgate_codec_schema::bitstream::shift_left;
///
/// // Input: bits 0..=15 are 0xAB 0xCD (binary 1010_1011 1100_1101).
/// // Shift left by 4: byte 0 high nibble of output is the LOW
/// // nibble of input byte 0 (0xB), low nibble is the HIGH nibble
/// // of input byte 1 (0xC). Output: 0xBC.
/// // Byte 1 high nibble is LOW nibble of input byte 1 (0xD), low
/// // nibble is zero (no more input). Output: 0xD0.
/// assert_eq!(shift_left(&[0xAB, 0xCD], 4), vec![0xBC, 0xD0]);
/// ```
///
/// # Panics
///
/// Never. `bit_shift > 7` returns the input verbatim — the
/// caller's responsibility is to keep `bit_shift` in range; this
/// function tolerates out-of-range values for ergonomics.
#[must_use]
pub fn shift_left(input: &[u8], bit_shift: u8) -> Vec<u8> {
    if bit_shift == 0 || input.is_empty() {
        return input.to_vec();
    }
    let bit_shift = bit_shift.min(7) as usize;
    input
        .iter()
        .enumerate()
        .map(|(i, &b)| {
            // Take the low `(8 - bit_shift)` bits of byte i and put
            // them in the HIGH part of output byte i, then OR in
            // the high `bit_shift` bits of byte i+1 (if it exists)
            // into the LOW part. This is exactly "shift the whole
            // stream left by bit_shift bits".
            let high = b << bit_shift;
            let low = input
                .get(i + 1)
                .map(|&next| next >> (8 - bit_shift))
                .unwrap_or(0);
            high | low
        })
        .collect()
}

/// Splice a body byte stream into a header byte stream at a
/// non-byte-aligned bit position, returning the combined wire
/// bytes.
///
/// `header_bytes` carries the header at byte 0 bit 0 plus the
/// header's tail bits (the byte containing `header_end_bit` is
/// included with its low `8 - (header_end_bit % 8)` bits as part
/// of the header; the high `header_end_bit % 8` bits of that
/// same byte are NOT yet written and will be filled by the body's
/// first bits).
///
/// `body_bytes` carries the body starting at byte 0 bit 0.
///
/// `body_bit_count` is how many bits of `body_bytes` to splice
/// (the body may be shorter than `body_bytes.len() * 8` if it
/// ended mid-byte). The remaining bits of `body_bytes` are
/// discarded.
///
/// The output is `ceil((header_end_bit + body_bit_count) / 8)`
/// bytes.
///
/// # Example
///
/// ```rust
/// use rustgate_codec_schema::bitstream::splice_at;
///
/// // Header is 12 bits (1.5 bytes): 0xAB, then 0xC in the high
/// // nibble of byte 1. The low nibble of byte 1 is reserved for
/// // the body's first 4 bits.
/// let header_bytes = vec![0xAB, 0xC0];
/// let header_end_bit = 12;
/// // Body is 8 bits starting with 0xDE.
/// let body_bytes = vec![0xDE];
/// let body_bit_count = 8;
/// // Combined wire: 0xAB, then 0xC nibble from header + 0xD
/// // nibble from body = 0xCD, then 0xE nibble from body + 0x0
/// // pad = 0xE0.
/// assert_eq!(
///     splice_at(&header_bytes, header_end_bit, &body_bytes, body_bit_count),
///     vec![0xAB, 0xCD, 0xE0],
/// );
/// ```
#[must_use]
pub fn splice_at(
    header_bytes: &[u8],
    header_end_bit: usize,
    body_bytes: &[u8],
    body_bit_count: usize,
) -> Vec<u8> {
    let total_bits = header_end_bit + body_bit_count;
    let total_bytes = total_bits.div_ceil(8);
    let mut out = vec![0u8; total_bytes];

    // Copy the header bytes whole. The byte containing
    // `header_end_bit` is included; its high bits (above the
    // bit position) are the header's contribution and its low
    // bits (below `header_end_bit % 8`) are zero, waiting for
    // the body.
    let header_full_bytes = header_end_bit / 8;
    for (i, &b) in header_bytes
        .iter()
        .take(header_full_bytes.min(out.len()))
        .enumerate()
    {
        out[i] = b;
    }
    // If header ends mid-byte, copy that partial byte too.
    let header_tail_bit = header_end_bit % 8;
    if header_tail_bit > 0
        && header_full_bytes < out.len()
        && header_bytes.len() > header_full_bytes
    {
        let mask = 0xFFu8 << (8 - header_tail_bit);
        out[header_full_bytes] |= header_bytes[header_full_bytes] & mask;
    }

    // Write the body bits starting at bit position
    // `header_end_bit` of the output. Walk the body bytes,
    // splitting each into the part that goes into the current
    // output byte's low bits and the part that overflows into
    // the next output byte's high bits.
    let body_full_bytes = body_bit_count / 8;
    let body_tail_bits = body_bit_count % 8;
    let shift = header_tail_bit; // 0..=7

    for (i, &b) in body_bytes.iter().take(body_full_bytes).enumerate() {
        let out_byte = header_full_bytes + i;
        if shift == 0 {
            if out_byte < out.len() {
                out[out_byte] |= b;
            }
        } else {
            // Top `(8 - shift)` bits of the body byte go in the
            // bottom `(8 - shift)` bits of the current output
            // byte.
            if out_byte < out.len() {
                out[out_byte] |= b >> shift;
            }
            // Bottom `shift` bits go in the top `shift` bits of
            // the next output byte.
            if out_byte + 1 < out.len() {
                out[out_byte + 1] |= b << (8 - shift);
            }
        }
    }

    // Last partial body byte (if body_bit_count is not byte-
    // aligned). Same split logic but only emit the high
    // `body_tail_bits` of body_bytes[body_full_bytes].
    if body_tail_bits > 0 && body_bytes.len() > body_full_bytes {
        let b = body_bytes[body_full_bytes] & (0xFFu8 << (8 - body_tail_bits));
        let out_byte = header_full_bytes + body_full_bytes;
        if shift == 0 {
            if out_byte < out.len() {
                out[out_byte] |= b;
            }
        } else {
            if out_byte < out.len() {
                out[out_byte] |= b >> shift;
            }
            if out_byte + 1 < out.len() && (shift + body_tail_bits) > 8 {
                out[out_byte + 1] |= b << (8 - shift);
            }
        }
    }

    out
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    // ---------- shift_left ----------

    #[test]
    fn shift_left_zero_returns_input_verbatim() {
        assert_eq!(shift_left(&[0xAB, 0xCD], 0), vec![0xAB, 0xCD]);
    }

    #[test]
    fn shift_left_four_shifts_nibbles() {
        // The docstring example, exact.
        assert_eq!(shift_left(&[0xAB, 0xCD], 4), vec![0xBC, 0xD0]);
    }

    #[test]
    fn shift_left_one_shifts_single_bit() {
        // 0b1000_0000 << 1 = 0b0000_0000, but the high bit of
        // byte 1 (0b1000_0000) becomes the low bit of output 0.
        // Wait — let me recompute: input = [0x80, 0x80].
        // Shift left 1: byte 0 high bit drops, so out[0] high
        // part = 0x80 << 1 = 0x00. Out[0] low bit pulls in input
        // byte 1's high bit = 1. So out[0] = 0x01.
        // Out[1] = 0x80 << 1 = 0x00 (high), low is 0 (no more
        // input). So out[1] = 0x00.
        assert_eq!(shift_left(&[0x80, 0x80], 1), vec![0x01, 0x00]);
    }

    #[test]
    fn shift_left_seven_shifts_almost_full_byte() {
        // 0xFF, 0x80 shifted left 7:
        // out[0] high = 0xFF << 7 = 0x80. Low = 0x80 >> 1 = 0x40.
        // out[0] = 0xC0.
        // out[1] high = 0x80 << 7 = 0x00. Low = 0 (no more input).
        // out[1] = 0x00.
        assert_eq!(shift_left(&[0xFF, 0x80], 7), vec![0xC0, 0x00]);
    }

    #[test]
    fn shift_left_empty_input_returns_empty() {
        assert_eq!(shift_left(&[], 4), Vec::<u8>::new());
    }

    #[test]
    fn shift_left_single_byte_low_bits_zero_filled() {
        // [0xFF] shifted left 4: high nibble = 0xF, low nibble
        // is zero (no byte 1). Output = 0xF0.
        assert_eq!(shift_left(&[0xFF], 4), vec![0xF0]);
    }

    // ---------- splice_at ----------

    #[test]
    fn splice_at_byte_aligned_header_concatenates() {
        // Header ends on a byte boundary (16 bits = 2 full
        // bytes). Body is a full 8 bits. Result is concatenation.
        assert_eq!(
            splice_at(&[0xAB, 0xCD], 16, &[0xEF], 8),
            vec![0xAB, 0xCD, 0xEF],
        );
    }

    #[test]
    fn splice_at_mid_byte_header_splices_correctly() {
        // The docstring example: header is 12 bits (0xAB, 0xC in
        // high nibble of byte 1). Body is 8 bits (0xDE).
        // Combined: 0xAB, 0xCD, 0xE0.
        assert_eq!(
            splice_at(&[0xAB, 0xC0], 12, &[0xDE], 8),
            vec![0xAB, 0xCD, 0xE0],
        );
    }

    #[test]
    fn splice_at_one_bit_header_splices_correctly() {
        // Header is 1 bit (the high bit of byte 0): 0x80. Body
        // is 7 bits (0x7F << 1 = 0xFE, of which we use the top 7
        // bits = 0xFE high 7 = 0xFE >> 1 = 0x7F).
        // Wait let me think again. Body bytes = [0xFE], body_bit_count = 7.
        // The top 7 bits of 0xFE are 0xFE & 0xFE = 0xFE, then shifted
        // into position after the 1-bit header.
        // Output: bit 0 = 1 (header), bits 1..=7 = top 7 bits of 0xFE = 0b1111111 = 0x7F.
        // So output[0] = 0b1_1111111 = 0xFF.
        assert_eq!(splice_at(&[0x80], 1, &[0xFE], 7), vec![0xFF],);
    }

    #[test]
    fn splice_at_round_trips_through_shift_left() {
        // Property: splice_at(header_bytes, N, body_bytes, M)
        // followed by shift_left applied to the body region must
        // recover body_bytes for byte-aligned cases.
        //
        // Build: header = 12 bits (0xAB 0xC0), body = 16 bits
        // (0x12 0x34).
        let spliced = splice_at(&[0xAB, 0xC0], 12, &[0x12, 0x34], 16);
        // Expected: 0xAB, 0xC1, 0x23, 0x40.
        // Header byte 0 = 0xAB. Header byte 1 high nibble = 0xC.
        // Body high nibble of byte 0 (0x1) → low nibble of out[1] = 0x1.
        // Out[1] = 0xC1.
        // Body low nibble of byte 0 (0x2) → high nibble of out[2] = 0x2.
        // Body high nibble of byte 1 (0x3) → low nibble of out[2] = 0x3.
        // Out[2] = 0x23.
        // Body low nibble of byte 1 (0x4) → high nibble of out[3] = 0x4.
        // Pad with 0. Out[3] = 0x40.
        assert_eq!(spliced, vec![0xAB, 0xC1, 0x23, 0x40]);

        // Now extract the body region starting at bit 12 and
        // shift left to byte-align. The body region starts at
        // byte 1 (containing the tail-half of header + first-half
        // of body) and we shift left by 4.
        let body_view = shift_left(&spliced[1..], 4);
        // body_view[0] = (0xC1 << 4) | (0x23 >> 4) = 0x10 | 0x02 = 0x12.
        // body_view[1] = (0x23 << 4) | (0x40 >> 4) = 0x30 | 0x04 = 0x34.
        // body_view[2] = (0x40 << 4) | 0 = 0x00.
        assert_eq!(body_view, vec![0x12, 0x34, 0x00]);
        // First two bytes of body_view recover the body input.
        assert_eq!(&body_view[..2], &[0x12, 0x34]);
    }
}
