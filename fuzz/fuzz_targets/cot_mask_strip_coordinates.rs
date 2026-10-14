// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

#![no_main]
#![allow(clippy::panic, clippy::unwrap_used)]

//! Fuzz the CoT `<point>` coordinate masker.
//!
//! `rustgate_cot::mask::strip_coordinates` is on the per-recipient
//! delivery path when an authz policy returns the `MaskPoint` obligation.
//! Three traits make it worth fuzzing:
//!
//! - It walks every element with **quick_xml**, which has a history of
//!   resource-exhaustion issues on crafted input (deeply nested elements,
//!   pathological attribute lists, large CDATA).
//! - It must **fail closed** on XML-intent input that parses partially —
//!   a sender that emits `<event><point lat="…"…/>` and then truncates
//!   the document must NOT leak coordinates via pass-through recovery,
//!   because the `<point>` element was already copied to the writer
//!   buffer before the parse error triggered.
//! - Case-insensitive and namespace-stripped `<point>` matching is
//!   hand-rolled in [`is_point_tag`]; a regression there re-opens a
//!   documented bypass (`<Point>`, `<cot:point>`) that older revisions
//!   of the masker were vulnerable to.
//!
//! The fuzz target also exercises **idempotence**: masked output must
//! itself mask cleanly with equal bytes. A regression where the masker
//! emits XML the next pass can't parse (or masks a previously-masked
//! `<point>` differently) would be caught here.

use libfuzzer_sys::fuzz_target;
use rustgate_cot::mask::strip_coordinates;

fuzz_target!(|data: &[u8]| {
    let Ok(first) = strip_coordinates(data) else {
        // XML-intent payload that failed to parse, attribute-budget
        // trip, or writer I/O error. All are in scope for the masker's
        // documented error surface; the fuzzer's job is to make sure
        // they don't panic or read out-of-bounds on the way out.
        return;
    };
    // Second pass must succeed — `first` is either verbatim input (fast
    // path for non-XML) or quick_xml-serialised output of a successful
    // walk, both of which are valid inputs to `strip_coordinates`.
    let second = match strip_coordinates(&first) {
        Ok(s) => s,
        Err(e) => panic!("strip_coordinates regressed on its own output: {e}"),
    };
    // Idempotence: masked output is a fixed point of the masker. A second
    // pass must produce byte-identical output; any drift would indicate
    // a serialisation bug.
    assert_eq!(
        first, second,
        "strip_coordinates is not idempotent (first pass != second pass)"
    );
});
