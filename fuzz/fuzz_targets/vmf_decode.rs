// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

#![no_main]
#![allow(clippy::panic, clippy::unwrap_used)]

//! Fuzz the VMF (Variable Message Format / MIL-STD-2045-47001D)
//! header + body decoder.
//!
//! `rustgate_vmf::decode_message` accepts an arbitrary byte slice
//! and returns `(VmfHeader, VmfMessage)` or a `VmfError`. VMF is
//! the highest-risk decoder in the workspace: the wire format is
//! **bit-aligned** (FPI / FRI / GPI flags govern whether each
//! subsequent field is present, with bit-precision boundaries), and
//! the implementation uses a hand-rolled `BitReader` over a borrowed
//! `&[u8]`. A regression in either the bit cursor or the FPI gating
//! is a credible source of slice-index panics on hostile input.
//!
//! # Why this surface earns a fuzzer
//!
//! - Every field in the VMF R/T header (originator URN, recipient
//!   URN, message identifier, classification, DTG) is gated by an
//!   FPI ("Field Presence Indicator") bit that may or may not
//!   precede it. The decoder must read the FPI first, then read N
//!   following bits **only if** the FPI was set. A flipped or
//!   missing FPI bit can cause the cursor to land on a different
//!   field downstream — any dispatch that subsequently does an
//!   unchecked `read_bits(width)` on a buffer with `<width` bits
//!   left will panic.
//! - The bit cursor crosses byte boundaries opaquely; reads of 1,
//!   3, 5, 13, 24, 32 bits are all common in the schema. A regression
//!   that wrote `cursor += width` without a remaining-bits guard
//!   would underflow on a truncated frame.
//! - K05.1 Position Reports use signed integer encodings with the
//!   sign bit at the top of a non-power-of-two-width field; an
//!   off-by-one on the sign-extension mask would silently corrupt
//!   the lat/lon. The fuzzer cannot detect silent corruption from
//!   arbitrary bytes (only the unit tests pin that), but a
//!   **panic** in the sign-extension path on truncated input is in
//!   scope.
//! - The `MessageId::is_k05_1` dispatch chooses between typed K05.1
//!   decode and the opaque `VmfMessage::Unknown` arm. A regression
//!   that selected K05.1 on a buffer too small to hold a K05.1 body
//!   would panic in the bit reader rather than fall through to
//!   `Unknown`.
//!
//! # Failure modes the fuzzer would catch
//!
//! - An FPI bit referring to a field whose width exceeds the
//!   remaining bit-buffer length (must surface as `VmfError`,
//!   never as a slice-index panic in `BitReader::read_bits`).
//! - A K05.1-discriminating header followed by a body that's bit-
//!   short of the full K05.1 layout (must return `Truncated`).
//! - A bit-cursor advance past the buffer end after the header
//!   parse, where the round-up-to-byte-boundary remainder slice
//!   is then taken via `&payload[byte_offset..]` (panic if
//!   `byte_offset > payload.len()`).
//!
//! The fuzz target is a single-shot decode and the `Result` is
//! dropped; only the absence of a panic / sanitiser complaint
//! matters.

use libfuzzer_sys::fuzz_target;
use rustgate_vmf::decode_message;

fuzz_target!(|data: &[u8]| {
    let _ = decode_message(data);
});
