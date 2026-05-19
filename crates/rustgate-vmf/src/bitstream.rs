// Copyright © 2026 Roberto Chiofalo.

//! Minimal big-endian bit-level reader and writer used by the VMF codec.
//!
//! VMF (MIL-STD-6017) is **bit-oriented** — fields are packed end-to-end
//! across byte boundaries with no padding, and the wire ordering is
//! big-endian (most-significant bit first within each byte). The reader
//! and writer here implement exactly that: read up to 32 bits at a time
//! into a `u32`, write up to 32 bits from a `u32`. That matches every
//! field width present in the MIL-STD-2045-47001 application header and
//! the K05.1 Position Report (the MVP scope of issue #868).
//!
//! The implementation is deliberately tiny — about a hundred lines —
//! because the broader workspace prefers to keep crate dep trees minimal
//! (see `rustgate-asterix`, which only depends on `bytes` and
//! `thiserror`) and a third-party `bitstream-io` adds two compile units
//! and four version-pin lines for a wrapper this short. If a future
//! K-series message needs >32-bit single-field reads (UNIX-time
//! timestamps, large bitmaps), the reader's `read_bits_u64` extension
//! lands at that point.
//!
//! # Endianness
//!
//! Within each byte, bit 7 (the MSB) is read first. Across byte
//! boundaries the high-order field bits land in the earlier byte's low
//! positions and the low-order bits land in the later byte's high
//! positions — the standard big-endian bit order used by MIL-STD,
//! ASTERIX, and most ATC / tactical wire formats. Little-endian variants
//! (Bluetooth, MAVLink payload) are not supported here; those crates
//! roll their own helpers.

use crate::error::VmfError;

/// Bit-level reader over a borrowed byte slice.
///
/// Stateless across method calls except for the bit cursor; safe to
/// re-create per frame. Read methods return [`VmfError::Truncated`] on
/// short reads with a symbolic field name so the upstream session log
/// pinpoints which UAP bit ran out of bytes.
#[derive(Debug)]
pub struct BitReader<'a> {
    bytes: &'a [u8],
    /// Current read position in bits from the start of `bytes`. The
    /// MSB of `bytes[0]` is bit 0; the LSB is bit 7.
    pos: usize,
}

impl<'a> BitReader<'a> {
    /// Wrap a byte slice as a bit reader positioned at the first bit.
    #[must_use]
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    /// Bits remaining to be read.
    #[must_use]
    pub fn remaining_bits(&self) -> usize {
        self.bytes.len().saturating_mul(8).saturating_sub(self.pos)
    }

    /// Current read position in bits from the start of the slice.
    #[must_use]
    pub fn position_bits(&self) -> usize {
        self.pos
    }

    /// Borrow the underlying byte slice. Surface for callers that
    /// need to extract a sub-slice at the current bit cursor — the
    /// VMF K05.1 codec migration uses this to hand a byte-aligned
    /// view of the body to the `rustgate-codec-schema` runtime.
    #[must_use]
    pub fn payload(&self) -> &'a [u8] {
        self.bytes
    }

    /// Advance the bit cursor by `n` bits without reading. Used by
    /// callers that consumed bits through an alternate path (e.g.
    /// `SchemaCodec` decode operating on a byte-aligned slice
    /// produced via `bitstream::shift_left`) and need to mark those
    /// bits as consumed in the BitReader for any downstream code
    /// to pick up at the right position.
    pub fn advance_bits(&mut self, n: usize) -> Result<(), VmfError> {
        if self.remaining_bits() < n {
            return Err(VmfError::Truncated {
                field: "advance_bits",
                needed_bits: u32::try_from(n).unwrap_or(u32::MAX),
            });
        }
        self.pos += n;
        Ok(())
    }

    /// Read `n` bits (1..=32) and return them right-justified in a
    /// `u32`. Returns [`VmfError::Truncated`] when the stream runs out
    /// of bytes mid-read.
    ///
    /// `field` is a symbolic name surfaced in the truncation error so
    /// session-layer logs can pinpoint which UAP bit ran short — pass
    /// the same string the call site uses in error messages.
    pub fn read_bits(&mut self, n: u32, field: &'static str) -> Result<u32, VmfError> {
        // The implementation supports 1..=32. A zero-width read would
        // mask to zero anyway and a >32 read overflows the return type;
        // both surface as InvalidValue so the call site catches its own
        // bug rather than producing wrong wire values silently.
        if !(1..=32).contains(&n) {
            return Err(VmfError::InvalidValue {
                field,
                detail: format!("read_bits called with n={n}, must be 1..=32"),
            });
        }
        let needed = n as usize;
        if self.remaining_bits() < needed {
            return Err(VmfError::Truncated {
                field,
                needed_bits: n,
            });
        }
        let mut value: u64 = 0;
        let mut bits_read = 0;
        while bits_read < needed {
            let byte_idx = self.pos / 8;
            let bit_in_byte = self.pos % 8; // 0 = MSB, 7 = LSB
            let bits_left_in_byte = 8 - bit_in_byte;
            let take = bits_left_in_byte.min(needed - bits_read);
            // Extract the high `take` bits starting at `bit_in_byte` of
            // `bytes[byte_idx]`. Defensive `get`: bounds were already
            // checked above, but `?` keeps clippy happy and the function
            // panic-free if the invariant is ever broken in test paths.
            let byte = u64::from(*self.bytes.get(byte_idx).ok_or(VmfError::Truncated {
                field,
                needed_bits: n,
            })?);
            let shift_right = bits_left_in_byte - take;
            // Mask to `take` bits, then push to the right of `value`.
            let mask = (1u64 << take) - 1;
            let chunk = (byte >> shift_right) & mask;
            value = (value << take) | chunk;
            self.pos += take;
            bits_read += take;
        }
        // `value` holds at most 32 bits because `n <= 32`.
        Ok(value as u32)
    }

    /// Read a single bit.
    pub fn read_bit(&mut self, field: &'static str) -> Result<bool, VmfError> {
        Ok(self.read_bits(1, field)? != 0)
    }

    /// Read `n` bits as a signed two's-complement integer in i32.
    pub fn read_bits_signed(&mut self, n: u32, field: &'static str) -> Result<i32, VmfError> {
        if !(1..=32).contains(&n) {
            return Err(VmfError::InvalidValue {
                field,
                detail: format!("read_bits_signed called with n={n}, must be 1..=32"),
            });
        }
        let raw = self.read_bits(n, field)?;
        if n == 32 {
            // Already 32 bits; reinterpret the raw bits as signed.
            return Ok(raw as i32);
        }
        let sign_bit = 1u32 << (n - 1);
        if raw & sign_bit == 0 {
            // Positive — top bits are already zero; safe to convert.
            return Ok(raw as i32);
        }
        // Sign-extend. Compute the negative value by subtracting 2^n.
        // `as i64` keeps the arithmetic in range, `as i32` then
        // narrows to the return type. Since `n <= 31` the result fits.
        let extended = i64::from(raw) - (1i64 << n);
        Ok(extended as i32)
    }

    /// Read `n` bytes (byte-aligned). Returns [`VmfError::Truncated`]
    /// when the cursor is not on a byte boundary or when the stream
    /// runs short.
    pub fn read_bytes(&mut self, n: usize, field: &'static str) -> Result<&'a [u8], VmfError> {
        if !self.pos.is_multiple_of(8) {
            return Err(VmfError::InvalidValue {
                field,
                detail: format!("read_bytes called at non-byte-aligned bit {}", self.pos),
            });
        }
        let byte_idx = self.pos / 8;
        let end = byte_idx.checked_add(n).ok_or(VmfError::Truncated {
            field,
            needed_bits: u32::try_from(n.saturating_mul(8)).unwrap_or(u32::MAX),
        })?;
        if end > self.bytes.len() {
            return Err(VmfError::Truncated {
                field,
                needed_bits: u32::try_from(n.saturating_mul(8)).unwrap_or(u32::MAX),
            });
        }
        // Slice is bounds-checked above.
        let slice = self.bytes.get(byte_idx..end).ok_or(VmfError::Truncated {
            field,
            needed_bits: u32::try_from(n.saturating_mul(8)).unwrap_or(u32::MAX),
        })?;
        self.pos = end * 8;
        Ok(slice)
    }
}

/// Bit-level writer that accumulates into a `Vec<u8>`.
///
/// Pads the trailing partial byte with zeros on `into_bytes()` —
/// MIL-STD-6017 datagrams are byte-aligned at the network layer, so the
/// pad bits are discarded by the receiver as part of the application-
/// header length field.
#[derive(Debug, Default)]
pub struct BitWriter {
    bytes: Vec<u8>,
    /// Number of bits already written into `bytes`. The current write
    /// byte is `bytes.last_mut()` when `bits % 8 != 0`, otherwise a
    /// fresh byte is appended on the next write.
    bits: usize,
}

impl BitWriter {
    /// Construct an empty writer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct a writer with capacity reserved for `bytes` bytes of
    /// output.
    #[must_use]
    pub fn with_capacity(bytes: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(bytes),
            bits: 0,
        }
    }

    /// Number of complete bytes written so far (excluding any
    /// in-progress partial byte).
    #[must_use]
    pub fn byte_len(&self) -> usize {
        self.bits / 8
    }

    /// Total bits written.
    #[must_use]
    pub fn bit_len(&self) -> usize {
        self.bits
    }

    /// Append `n` bits (1..=32) from the low bits of `value`. Returns
    /// [`VmfError::EncodeOverflow`] if `value` does not fit in `n`
    /// bits.
    ///
    /// `field` is a symbolic field name surfaced in overflow errors so
    /// the call site can pinpoint which encoder produced an
    /// out-of-range value.
    pub fn write_bits(&mut self, value: u32, n: u32, field: &'static str) -> Result<(), VmfError> {
        if !(1..=32).contains(&n) {
            return Err(VmfError::EncodeOverflow {
                field,
                detail: format!("write_bits called with n={n}, must be 1..=32"),
            });
        }
        if n < 32 {
            let max = (1u32 << n).saturating_sub(1);
            if value > max {
                return Err(VmfError::EncodeOverflow {
                    field,
                    detail: format!("value 0x{value:X} does not fit in {n} bits"),
                });
            }
        }
        // Walk the bit count, packing into the trailing byte and
        // appending fresh bytes as needed.
        let mut remaining = n as usize;
        let mut value64 = u64::from(value);
        while remaining > 0 {
            if self.bits.is_multiple_of(8) {
                self.bytes.push(0);
            }
            let bit_in_byte = self.bits % 8;
            let bits_left_in_byte = 8 - bit_in_byte;
            let take = bits_left_in_byte.min(remaining);
            // Extract the top `take` bits from the remaining `remaining`
            // bits of `value64`.
            let shift_right = remaining - take;
            let chunk = ((value64 >> shift_right) & ((1u64 << take) - 1)) as u8;
            // Position chunk so its MSB lands at `bit_in_byte`.
            let placed = chunk << (bits_left_in_byte - take);
            // SAFETY-equivalent: we just pushed if needed, so last_mut() exists.
            if let Some(byte) = self.bytes.last_mut() {
                *byte |= placed;
            }
            self.bits += take;
            remaining -= take;
            value64 &= (1u64 << remaining).wrapping_sub(1);
        }
        Ok(())
    }

    /// Append a single bit.
    pub fn write_bit(&mut self, bit: bool, field: &'static str) -> Result<(), VmfError> {
        self.write_bits(u32::from(bit), 1, field)
    }

    /// Append `n` bits from a signed integer using two's-complement
    /// encoding.
    pub fn write_bits_signed(
        &mut self,
        value: i32,
        n: u32,
        field: &'static str,
    ) -> Result<(), VmfError> {
        if !(1..=32).contains(&n) {
            return Err(VmfError::EncodeOverflow {
                field,
                detail: format!("write_bits_signed called with n={n}, must be 1..=32"),
            });
        }
        if n < 32 {
            let max = (1i32 << (n - 1)) - 1;
            let min = -(1i32 << (n - 1));
            if value < min || value > max {
                return Err(VmfError::EncodeOverflow {
                    field,
                    detail: format!("value {value} does not fit in {n} signed bits"),
                });
            }
        }
        let mask = if n == 32 { u32::MAX } else { (1u32 << n) - 1 };
        let raw = (value as u32) & mask;
        self.write_bits(raw, n, field)
    }

    /// Append `data` byte-aligned. Pads the in-progress partial byte
    /// with zeros first if the cursor is not byte-aligned.
    pub fn write_bytes(&mut self, data: &[u8]) {
        // Pad to byte boundary first.
        let pad = (8 - (self.bits % 8)) % 8;
        if pad != 0 {
            self.bits += pad;
        }
        self.bytes.extend_from_slice(data);
        self.bits += data.len() * 8;
    }

    /// Finish, padding the trailing partial byte with zeros.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn read_bits_walks_byte_boundary() {
        // Two bytes 0b1010_1100 0b1111_0000
        // Read 4 bits → 0b1010 = 0xA
        // Read 6 bits → 0b1100_11 = 0x33
        // Read 6 bits → 0b11_0000 = 0x30
        let bytes = [0b1010_1100u8, 0b1111_0000u8];
        let mut r = BitReader::new(&bytes);
        assert_eq!(r.read_bits(4, "a").unwrap(), 0xA);
        assert_eq!(r.read_bits(6, "b").unwrap(), 0x33);
        assert_eq!(r.read_bits(6, "c").unwrap(), 0x30);
        assert_eq!(r.remaining_bits(), 0);
    }

    #[test]
    fn read_bits_truncates_at_eof() {
        let bytes = [0xFFu8];
        let mut r = BitReader::new(&bytes);
        assert_eq!(r.read_bits(8, "a").unwrap(), 0xFF);
        let err = r.read_bits(1, "b").unwrap_err();
        assert!(matches!(err, VmfError::Truncated { needed_bits: 1, .. }));
    }

    #[test]
    fn read_bits_signed_negative_extends_high_bits() {
        // 5-bit signed: 0b11111 = -1
        let bytes = [0b1111_1000u8];
        let mut r = BitReader::new(&bytes);
        assert_eq!(r.read_bits_signed(5, "x").unwrap(), -1);
    }

    #[test]
    fn read_bits_signed_positive_unchanged() {
        // 5-bit signed: 0b00111 = 7
        let bytes = [0b0011_1000u8];
        let mut r = BitReader::new(&bytes);
        assert_eq!(r.read_bits_signed(5, "x").unwrap(), 7);
    }

    #[test]
    fn read_bytes_requires_byte_alignment() {
        let bytes = [0xAAu8, 0xBBu8];
        let mut r = BitReader::new(&bytes);
        // Skip 4 bits to misalign.
        let _ = r.read_bits(4, "skip").unwrap();
        let err = r.read_bytes(1, "x").unwrap_err();
        assert!(matches!(err, VmfError::InvalidValue { .. }));
    }

    #[test]
    fn write_bits_round_trips() {
        let mut w = BitWriter::new();
        w.write_bits(0xA, 4, "a").unwrap();
        w.write_bits(0x33, 6, "b").unwrap();
        w.write_bits(0x30, 6, "c").unwrap();
        let bytes = w.into_bytes();
        assert_eq!(bytes, vec![0b1010_1100u8, 0b1111_0000u8]);
    }

    #[test]
    fn write_bits_overflow_detected() {
        let mut w = BitWriter::new();
        // 0x10 in 4 bits would overflow.
        let err = w.write_bits(0x10, 4, "x").unwrap_err();
        assert!(matches!(err, VmfError::EncodeOverflow { .. }));
    }

    #[test]
    fn write_bits_signed_round_trips() {
        let mut w = BitWriter::new();
        w.write_bits_signed(-1, 5, "a").unwrap(); // 0b11111
        w.write_bits_signed(3, 5, "b").unwrap(); // 0b00011
        w.write_bits_signed(0, 6, "c").unwrap(); // 0b000000
        // Total 16 bits = 2 bytes.
        let bytes = w.into_bytes();
        let mut r = BitReader::new(&bytes);
        assert_eq!(r.read_bits_signed(5, "a").unwrap(), -1);
        assert_eq!(r.read_bits_signed(5, "b").unwrap(), 3);
        assert_eq!(r.read_bits_signed(6, "c").unwrap(), 0);
    }

    #[test]
    fn write_bytes_pads_to_byte_boundary() {
        let mut w = BitWriter::new();
        w.write_bits(0b101, 3, "x").unwrap();
        w.write_bytes(&[0xAA, 0xBB]);
        let bytes = w.into_bytes();
        // 3 bits then byte-padded → first byte is 0b1010_0000
        // followed by 0xAA, 0xBB.
        assert_eq!(bytes, vec![0b1010_0000u8, 0xAA, 0xBB]);
    }

    #[test]
    fn read_writer_long_bit_field() {
        // 24-bit URN-style field round-trips.
        let mut w = BitWriter::new();
        w.write_bits(0x12_3456, 24, "urn").unwrap();
        let bytes = w.into_bytes();
        let mut r = BitReader::new(&bytes);
        assert_eq!(r.read_bits(24, "urn").unwrap(), 0x12_3456);
    }
}
