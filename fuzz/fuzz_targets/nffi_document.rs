// Copyright © 2026 Roberto Chiofalo.

#![no_main]
#![allow(clippy::panic, clippy::unwrap_used)]

//! Fuzz the NFFI (NATO Friendly Force Information / STANAG 5527)
//! XML document decoder.
//!
//! `rustgate_nffi::decode_document` accepts an arbitrary byte slice
//! and returns a typed `NffiDocument` (a list of typed
//! [`NffiTrack`] records plus opaque `UnknownElement`s) or an
//! [`NffiError`]. NFFI flows over coalition tactical networks as
//! XML payloads; every coalition feed hits this parser, so a panic
//! here is a remote DoS reachable from any allied force in the
//! shared situational-awareness fabric.
//!
//! # Why this surface earns a fuzzer
//!
//! - The decoder is built on `quick-xml`, which is itself robust
//!   against the classic XML pitfalls (no entity expansion, no
//!   external DTD), but the **NFFI-specific dispatch on top of
//!   `quick-xml` events** is hand-rolled. The element-name stack,
//!   the dispatch on `<wgs84Position>` only inside
//!   `<positionalData>`, and the `UnknownElement` capture all sit
//!   above quick-xml and have their own failure modes.
//! - Attribute parsing for `lat`, `lon`, `alt`, `speed`, `course`
//!   uses `f64::from_str` on attacker-controlled bytes. NFC
//!   normalisation, locale-dependent decimal separators, and
//!   leading/trailing whitespace are all parser concerns; a
//!   regression in the stripping logic would surface as
//!   `InvalidFloat` (typed) on hostile input. The float
//!   range-check (`lat ∈ [-90, 90]`, `lon ∈ [-180, 180]`)
//!   surfaces as `OutOfRange` and uses `is_finite()` defensively
//!   — a NaN attribute that bypassed the finite check would
//!   propagate.
//! - The 15-character SIDC field (MIL-STD-2525 / STANAG-2019
//!   battle-symbol code) is parsed via the dedicated
//!   `AppSixA::parse` state machine; each character maps to an
//!   enum. Arbitrary characters must surface as a typed parse
//!   error, never a slice-index panic on a `< 15` character
//!   string.
//! - The 1 MiB `MAX_PAYLOAD_BYTES` cap is enforced before the
//!   parse loop; a regression that moved the check into the parse
//!   would let an attacker craft a deeply-nested XML payload that
//!   blew the call stack.
//!
//! # Failure modes the fuzzer would catch
//!
//! - A mismatched closing tag (`<a>...</b>`) not surfaced as
//!   `NffiError::Xml`. quick-xml's `check_end_names = true` mode
//!   handles this, but a regression that disabled the flag would
//!   accept silent corruption.
//! - A `<wgs84Position>` element with attributes that parse as
//!   `f64` but lie outside the WGS-84 envelope and aren't
//!   surfaced as `OutOfRange`.
//! - An NFC-normalisation regression that let a homoglyph
//!   element name through the dispatch table.
//!
//! The fuzz target is a single-shot decode; only the absence of a
//! panic / sanitiser complaint matters.

use libfuzzer_sys::fuzz_target;
use rustgate_nffi::decode_document;

fuzz_target!(|data: &[u8]| {
    let _ = decode_document(data);
});
